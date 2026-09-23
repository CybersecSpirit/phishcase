import asyncio
import base64
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import dkim
import test_jobs as helpers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.investigation import connectivity
from backend.investigation.dkim_api import (
    BoundedDNS,
    VerificationUnavailableError,
    verify_original,
    worker_environment,
)
from backend.investigation.store import db

BASE = "/api/workspace"


class DKIMTests(unittest.TestCase):
    setUp = helpers.JobTests.setUp
    tearDown = helpers.JobTests.tearDown

    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        public = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cls.dns_key = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public)
        cls.signed = (
            dkim.sign(
                helpers.EMAIL,
                b"test",
                b"example.org",
                private,
                include_headers=[b"from", b"to", b"subject"],
            )
            + helpers.EMAIL
        )

    def upload(self, raw=None, filename="signed.eml"):
        response = self.client.post(
            BASE + "/analyses", files={"file": (filename, raw or self.signed)}
        )
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()["id"]

    def test_offline_missing_flag_and_tenant_policy_refuse_before_dns_or_persistence(
        self,
    ):
        identity = self.upload()
        with patch(
            "backend.investigation.dkim_api.resolve_txt",
            new=AsyncMock(side_effect=AssertionError("DNS must not be reached")),
        ) as dns:
            for mode, enabled in (
                ("offline", "true"),
                ("restricted", "false"),
                ("connected", "false"),
                ("invalid", "true"),
            ):
                with (
                    self.subTest(mode=mode, enabled=enabled),
                    patch.dict(
                        os.environ,
                        {"CONNECTIVITY_MODE": mode, "DKIM_LOOKUP_ENABLED": enabled},
                    ),
                ):
                    self.assertFalse(
                        self.client.get(BASE + "/integrations").json()["dkim"][
                            "allowed"
                        ]
                    )
                    self.assertEqual(
                        self.client.post(
                            BASE + f"/analyses/{identity}/dkim", json={"confirm": True}
                        ).status_code,
                        403,
                    )
            with patch.dict(
                os.environ,
                {"CONNECTIVITY_MODE": "connected", "DKIM_LOOKUP_ENABLED": "true"},
            ):
                ctx = connectivity.policy_factory.set(lambda: {"mode": "connected"})
                try:
                    self.assertFalse(connectivity.dkim_allowed())
                finally:
                    connectivity.policy_factory.reset(ctx)
            dns.assert_not_called()
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM enrichments").fetchone()[0], 0
            )

    def test_real_signature_verification_persists_and_idempotent_replay_uses_no_dns(
        self,
    ):
        identity = self.upload()
        path = BASE + f"/analyses/{identity}/dkim"
        resolver = AsyncMock(return_value=self.dns_key)
        with (
            patch.dict(
                os.environ,
                {"CONNECTIVITY_MODE": "restricted", "DKIM_LOOKUP_ENABLED": "true"},
            ),
            patch("backend.investigation.dkim_api.resolve_txt", new=resolver),
        ):
            self.assertEqual(
                self.client.post(path, json={"confirm": False}).status_code, 422
            )
            payload = {"confirm": True, "request_id": str(uuid4())}
            response = self.client.post(path, json=payload)
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["metadata"]["verification"], "valid")
            self.assertEqual(
                result["metadata"]["dns_queries"], ["test._domainkey.example.org"]
            )
            self.assertEqual(result["metadata"]["signing_domains"], ["example.org"])
            self.assertIsNone(result["malicious"])
            self.assertEqual(
                self.client.post(path, json=payload).json()["id"], result["id"]
            )
            resolver.assert_awaited_once_with("test._domainkey.example.org")
        history = self.client.get(BASE + f"/analyses/{identity}/enrichments").json()
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["items"][0]["provider"], "dkim")
        self.assertIn("source_sha256", history["items"][0]["metadata"])
        self.assertEqual(
            self.client.get(BASE + f"/analyses/{identity}/source").content, self.signed
        )

    def test_invalid_signature_unsigned_and_dns_error_are_distinct(self):
        async def check():
            resolver = AsyncMock(return_value=self.dns_key)
            invalid = await verify_original(
                self.signed.replace(b"harmless synthetic", b"changed synthetic"),
                resolver,
            )
            self.assertEqual(invalid["verification"], "invalid")
            unsigned = await verify_original(
                helpers.EMAIL,
                AsyncMock(side_effect=AssertionError("No DNS for unsigned")),
            )
            self.assertEqual(unsigned["verification"], "unsigned")
            absent = await verify_original(self.signed, AsyncMock(return_value=None))
            self.assertEqual(absent["verification"], "unavailable")
            self.assertEqual(absent["reason_code"], "dns_no_key")
            timeout = await verify_original(
                self.signed, AsyncMock(side_effect=TimeoutError)
            )
            self.assertEqual(timeout["reason_code"], "dns_timeout")

        asyncio.run(check())

    def test_crypto_subprocess_deadline_kills_and_reaps_without_blocking_http_loop(
        self,
    ):
        async def check():
            children = []
            spawn = asyncio.create_subprocess_exec

            async def record(*args, **kwargs):
                child = await spawn(*args, **kwargs)
                children.append(child)
                return child

            with (
                patch(
                    "backend.investigation.dkim_api.worker_command",
                    return_value=[sys.executable, "-c", "import time; time.sleep(30)"],
                ),
                patch("backend.investigation.dkim_api.VERIFICATION_TIMEOUT", 0.1),
                patch(
                    "backend.investigation.dkim_api.asyncio.create_subprocess_exec",
                    side_effect=record,
                ),
            ):
                began = time.monotonic()
                check_task = asyncio.create_task(verify_original(self.signed))
                await asyncio.sleep(0.01)
                self.assertFalse(
                    check_task.done()
                )  # The event loop remains responsive.
                result = await check_task
                self.assertEqual(result["reason_code"], "verification_timeout")
                self.assertLess(time.monotonic() - began, 3)
                self.assertLess(children[0].returncode, 0)
                with self.assertRaises(ProcessLookupError):
                    os.kill(children[0].pid, 0)

        asyncio.run(check())

    def test_cpu_limit_is_enforced_by_os_and_environment_has_no_secrets(self):
        async def check():
            command = [
                sys.executable,
                "-c",
                "from backend.investigation.dkim_task import limits; limits(); exec('while True: pass')",
            ]
            with patch(
                "backend.investigation.dkim_api.worker_command", return_value=command
            ):
                began = time.monotonic()
                result = await verify_original(self.signed)
                self.assertEqual(result["reason_code"], "verification_resource_limit")
                self.assertLess(time.monotonic() - began, 8)

        with patch.dict(
            os.environ,
            {
                "CLOUD_ENCRYPTION_KEY": "synthetic",
                "DATABASE_URL": "synthetic",
                "SMTP_PASSWORD": "synthetic",
                "VIRUSTOTAL_API_KEY": "synthetic",
                "CONNECTIVITY_MODE": "connected",
            },
        ):
            environment = worker_environment()
            for secret in (
                "CLOUD_ENCRYPTION_KEY",
                "DATABASE_URL",
                "SMTP_PASSWORD",
                "VIRUSTOTAL_API_KEY",
            ):
                self.assertNotIn(secret, environment)
            self.assertEqual(environment["CONNECTIVITY_MODE"], "offline")
            self.assertEqual(environment["PHISHCASE_DISABLE_DOTENV"], "true")
            asyncio.run(check())

    @unittest.skipUnless(sys.platform == "linux", "Production Linux enforces RLIMIT_AS")
    def test_linux_memory_limit_is_enforced_in_real_crypto_subprocess(self):
        command = [
            sys.executable,
            "-c",
            "from backend.investigation.dkim_task import limits; limits(); bytearray(512 * 1024 * 1024)",
        ]
        with patch(
            "backend.investigation.dkim_api.worker_command", return_value=command
        ):
            result = asyncio.run(verify_original(self.signed))
            self.assertEqual(result["reason_code"], "verification_resource_limit")

    def test_dns_query_size_signature_and_name_bounds(self):
        async def check():
            resolver = AsyncMock(return_value=b"x" * 4097)
            result = await verify_original(self.signed, resolver)
            self.assertEqual(result["reason_code"], "dns_response_limit")
            many = b"DKIM-Signature: malformed\r\n" * 6 + helpers.EMAIL
            dns = AsyncMock(side_effect=AssertionError("Signature limit before DNS"))
            self.assertEqual(
                (await verify_original(many, dns))["reason_code"], "signature_limit"
            )
            bounded = BoundedDNS(AsyncMock(return_value=self.dns_key))
            with self.assertRaises(VerificationUnavailableError):
                await bounded(b"https://evil.example/path")
            for index in range(5):
                await bounded(f"s{index}._domainkey.example.org".encode())
            with self.assertRaises(VerificationUnavailableError):
                await bounded(b"sixth._domainkey.example.org")

        asyncio.run(check())

    def test_viewer_csrf_modified_original_and_msg_never_trigger_dns(self):
        identity = self.upload()
        path = BASE + f"/analyses/{identity}/dkim"
        with (
            patch.dict(
                os.environ,
                {"CONNECTIVITY_MODE": "connected", "DKIM_LOOKUP_ENABLED": "true"},
            ),
            patch(
                "backend.investigation.dkim_api.resolve_txt",
                new=AsyncMock(side_effect=AssertionError("DNS not expected")),
            ) as dns,
        ):
            self.assertEqual(
                self.client.post(
                    path, json={"confirm": True}, headers={"X-Requested-With": ""}
                ).status_code,
                403,
            )
            with db() as conn:
                conn.execute("UPDATE users SET role='viewer' WHERE username='admin'")
            self.assertEqual(
                self.client.post(path, json={"confirm": True}).status_code, 403
            )
            with db() as conn:
                conn.execute("UPDATE users SET role='admin' WHERE username='admin'")
            msg = self.upload(self.signed, "container.msg")
            self.assertEqual(
                self.client.post(
                    BASE + f"/analyses/{msg}/dkim", json={"confirm": True}
                ).json()["metadata"]["reason_code"],
                "original_format_unsupported",
            )
            with patch(
                "backend.investigation.dkim_api.original",
                side_effect=ValueError("sensitive storage detail"),
            ):
                response = self.client.post(path, json={"confirm": True})
                self.assertEqual(response.status_code, 409)
                self.assertNotIn("sensitive", response.text)
            dns.assert_not_called()

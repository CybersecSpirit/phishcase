import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.investigation.api import router as workspace_router
from backend.investigation.enrichment import (
    EnrichmentResult,
    EnrichmentStatus,
)
from backend.investigation.enrichment_api import initialize_enrichments
from backend.investigation.evidence import storage
from backend.investigation.store import create_admin, db

PASSWORD = "Test-password-12345"
URL = "https://suspicious.example/invoice"
ATTACHMENT = b"innocuous-test-bytes"
HASH = hashlib.sha256(ATTACHMENT).hexdigest()


class FakeProvider:
    def __init__(self, name="virustotal"):
        self.name = name
        self.calls = []
        self.error = None

    async def lookup(self, target):
        self.calls.append(("lookup", target))
        if self.error:
            raise self.error
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.UNKNOWN,
            summary="No result; no submission",
        )

    async def submit(self, target, *, content=None, visibility=None):
        self.calls.append(("submit", target, content, visibility))
        if self.error:
            raise self.error
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.PENDING,
            external_id="job",
            metadata={"visibility": visibility} if self.name == "urlscan" else {},
        )

    async def poll(self, target, external_id):
        self.calls.append(("poll", target, external_id))
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.AVAILABLE,
            malicious=2,
            external_id=external_id,
        )

    async def healthcheck(self):
        self.calls.append(("health",))
        return {"status": "reachable", "detail": "benign check"}


class EnrichmentAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "INVESTIGATION_DB": str(Path(self.temp.name) / "db.sqlite3"),
                "COOKIE_SECURE": "false",
                "CONNECTIVITY_MODE": "offline",
                "VIRUSTOTAL_API_KEY": "TOP-SECRET-TEST-KEY",
                "URLSCAN_API_KEY": "TOP-SECRET-URLSCAN-KEY",
                "VIRUSTOTAL_ALLOW_FILE_SUBMISSION": "false",
                "VIRUSTOTAL_ALLOW_URL_SUBMISSION": "false",
                "URLSCAN_ALLOW_URL_SUBMISSION": "false",
                "VIRUSTOTAL_LOOKUP_ENABLED": "true",
                "URLSCAN_LOOKUP_ENABLED": "true",
            },
        )
        self.env.start()
        create_admin("admin", PASSWORD)
        self.app = FastAPI()
        self.app.include_router(workspace_router, prefix="/api/workspace")
        self.client = TestClient(self.app, headers={"X-Requested-With": "PhishCase"})
        self.client.post(
            "/api/workspace/auth/login",
            json={"username": "admin", "password": PASSWORD},
        )
        self.case_id = self.client.post(
            "/api/workspace/cases", json={"title": "Investigation"}
        ).json()["id"]
        self.analysis_id = str(uuid4())
        document = {
            "eml": {
                "bodies": [
                    {
                        "urls": [URL],
                        "domains": ["suspicious.example"],
                        "ip_addresses": ["192.0.2.6"],
                    }
                ],
                "attachments": [
                    {
                        "filename": "sample.bin",
                        "hash": {"sha256": HASH},
                        "raw": base64.b64encode(ATTACHMENT).decode(),
                    }
                ],
            }
        }
        with db() as conn:
            initialize_enrichments(conn)
            conn.execute(
                "INSERT INTO analyses (id,case_id,filename,sha256,status,result,created_by) VALUES (?,?,?,?,?,?,1)",
                (
                    self.analysis_id,
                    self.case_id,
                    "message.eml",
                    "b" * 64,
                    "completed",
                    json.dumps(document),
                ),
            )
        self.fake = FakeProvider()
        self.provider_patch = patch(
            "backend.investigation.enrichment_api.get_provider", return_value=self.fake
        )
        self.factory = self.provider_patch.start()
        self.prefix = f"/api/workspace/analyses/{self.analysis_id}/enrichments"

    def tearDown(self):
        self.provider_patch.stop()
        self.client.close()
        self.env.stop()
        self.temp.cleanup()

    def lookup(self, **kwargs):
        return self.client.post(
            self.prefix + "/lookup",
            json={"provider": "virustotal", "kind": "sha256", "value": HASH, **kwargs},
        )

    def submit(self, **kwargs):
        return self.client.post(
            self.prefix + "/submit",
            json={
                "provider": "virustotal",
                "kind": "file",
                "attachment_index": 0,
                "confirm": True,
                **kwargs,
            },
        )

    def connected(self):
        os.environ["CONNECTIVITY_MODE"] = "connected"
        os.environ["VIRUSTOTAL_ALLOW_FILE_SUBMISSION"] = "true"

    def test_offline_and_invalid_mode_call_no_provider(self):
        for mode in ("offline", "misspelled"):
            os.environ["CONNECTIVITY_MODE"] = mode
            self.assertEqual(self.lookup().status_code, 403)
            self.assertEqual(self.submit().status_code, 403)
            self.assertEqual(
                self.client.post(
                    "/api/workspace/integrations/virustotal/health"
                ).status_code,
                403,
            )
        self.factory.assert_not_called()
        self.assertEqual(self.fake.calls, [])

    def test_restricted_lookup_stores_unknown_without_upload(self):
        os.environ["CONNECTIVITY_MODE"] = "restricted"
        os.environ["VIRUSTOTAL_ALLOW_FILE_SUBMISSION"] = "true"
        response = self.lookup()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "unknown")
        self.assertEqual(self.submit().status_code, 403)
        items = self.client.get(self.prefix).json()
        self.assertEqual(items["total"], 1)
        self.assertEqual(items["items"][0]["target"], {"kind": "sha256", "value": HASH})
        self.assertEqual([v[0] for v in self.fake.calls], ["lookup"])

    def test_only_evidence_linked_targets_allowed(self):
        os.environ["CONNECTIVITY_MODE"] = "restricted"
        for kind, value in (
            ("sha256", "0" * 64),
            ("url", "https://unrelated.example"),
            ("ip", "127.0.0.1"),
            ("domain", "unrelated.example"),
        ):
            self.assertEqual(self.lookup(kind=kind, value=value).status_code, 422)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.lookup(kind="url", value=URL).status_code, 200)

    def test_connected_requires_key_flag_and_confirmation(self):
        os.environ["CONNECTIVITY_MODE"] = "connected"
        self.assertEqual(self.submit().status_code, 403)
        os.environ["VIRUSTOTAL_ALLOW_FILE_SUBMISSION"] = "true"
        os.environ["VIRUSTOTAL_API_KEY"] = ""
        self.assertEqual(self.submit().status_code, 409)
        os.environ["VIRUSTOTAL_API_KEY"] = "secret"
        self.assertEqual(self.submit(confirm=False).status_code, 422)
        self.assertEqual(self.submit(attachment_index=99).status_code, 422)
        self.assertEqual(self.fake.calls, [])
        response = self.submit()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.fake.calls[0][2], ATTACHMENT)
        self.assertEqual(self.fake.calls[0][1].value, HASH)

    def test_viewer_has_read_only_access_and_csrf_is_enforced(self):
        self.connected()
        response = self.client.post(
            "/api/workspace/users",
            json={"username": "viewer", "password": PASSWORD, "role": "viewer"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.client.post("/api/workspace/auth/logout")
        self.client.post(
            "/api/workspace/auth/login",
            json={"username": "viewer", "password": PASSWORD},
        )
        self.assertEqual(self.client.get(self.prefix).status_code, 200)
        caps = self.client.get("/api/workspace/integrations").json()
        self.assertFalse(caps["providers"][0]["lookup_allowed"])
        self.assertFalse(caps["providers"][0]["submission_allowed"]["file"])
        self.assertEqual(self.lookup().status_code, 403)
        self.assertEqual(self.submit().status_code, 403)
        self.assertEqual(
            self.client.post(
                "/api/workspace/integrations/virustotal/health"
            ).status_code,
            403,
        )
        self.assertEqual(self.fake.calls, [])
        self.client.post("/api/workspace/auth/logout")
        self.client.post(
            "/api/workspace/auth/login",
            json={"username": "admin", "password": PASSWORD},
        )
        response = self.client.post(
            self.prefix + "/submit",
            headers={"X-Requested-With": ""},
            json={
                "provider": "virustotal",
                "kind": "file",
                "attachment_index": 0,
                "confirm": True,
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_metadata_health_and_errors_never_disclose_keys(self):
        os.environ["CONNECTIVITY_MODE"] = "restricted"
        metadata = self.client.get("/api/workspace/integrations")
        self.assertNotIn("TOP-SECRET", metadata.text)
        self.assertTrue(metadata.json()["providers"][0]["configured"])
        health = self.client.post("/api/workspace/integrations/virustotal/health")
        self.assertEqual(health.status_code, 200)
        self.fake.error = RuntimeError("TOP-SECRET-TEST-KEY request URL with key")
        response = self.lookup()
        self.assertEqual(response.json()["status"], "error")
        self.assertNotIn("TOP-SECRET", response.text)
        self.assertNotIn("TOP-SECRET", self.client.get(self.prefix).text)
        with db() as conn:
            self.assertNotIn(
                "TOP-SECRET",
                json.dumps([dict(r) for r in conn.execute("SELECT * FROM events")]),
            )

    def test_submission_idempotency_and_pending_duplicate(self):
        self.connected()
        request_id = str(uuid4())
        first = self.submit(request_id=request_id)
        again = self.submit(request_id=request_id)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["id"], again.json()["id"])
        self.assertEqual(len(self.fake.calls), 1)
        self.assertEqual(self.submit().status_code, 409)
        self.assertEqual(
            self.submit(request_id=request_id, visibility="public").status_code, 409
        )
        self.assertEqual(len(self.fake.calls), 1)

    def test_poll_uses_persisted_job_policy_delay_and_same_analysis(self):
        self.connected()
        response = self.submit()
        identifier = response.json()["id"]
        endpoint = self.prefix + f"/{identifier}/poll"
        self.assertEqual(self.client.post(endpoint).status_code, 429)
        with db() as conn:
            conn.execute("UPDATE enrichments SET poll_after=0")
        os.environ["CONNECTIVITY_MODE"] = "offline"
        self.assertEqual(self.client.post(endpoint).status_code, 403)
        os.environ["CONNECTIVITY_MODE"] = "restricted"
        result = self.client.post(endpoint)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["malicious"], 2)
        self.assertEqual(self.fake.calls[-1][2], "job")
        self.assertEqual(self.client.post(endpoint).status_code, 409)
        self.assertEqual(
            self.client.post(self.prefix + "/unknown/poll").status_code, 404
        )

    def test_local_rate_limit_and_latest_results(self):
        os.environ["CONNECTIVITY_MODE"] = "restricted"
        for _ in range(4):
            self.assertEqual(self.lookup().status_code, 200)
        self.assertEqual(self.lookup().status_code, 429)
        self.assertEqual(len(self.fake.calls), 4)
        self.assertEqual(self.client.get(self.prefix).json()["total"], 4)
        self.assertEqual(
            self.client.get(self.prefix + "?latest=true").json()["total"], 1
        )
        self.assertEqual(
            len(self.client.get(self.prefix + "?limit=2&offset=1").json()["items"]), 2
        )

    def test_tampered_attachment_refused_before_provider(self):
        self.connected()
        with db() as conn:
            row = conn.execute(
                "SELECT result FROM analyses WHERE id=?", (self.analysis_id,)
            ).fetchone()
            document = json.loads(row["result"])
            document["eml"]["attachments"][0]["raw"] = base64.b64encode(
                b"changed"
            ).decode()
            conn.execute(
                "UPDATE analyses SET result=? WHERE id=?",
                (json.dumps(document), self.analysis_id),
            )
        self.assertEqual(self.submit().status_code, 409)
        self.assertEqual(self.fake.calls, [])

    def test_externalized_attachment_is_read_without_changing_original(self):
        self.connected()
        evidence = storage().put(ATTACHMENT)
        with db() as conn:
            document = json.loads(
                conn.execute(
                    "SELECT result FROM analyses WHERE id=?", (self.analysis_id,)
                ).fetchone()["result"]
            )
            document["eml"]["attachments"][0].pop("raw")
            conn.execute(
                "UPDATE analyses SET result=? WHERE id=?",
                (json.dumps(document), self.analysis_id),
            )
            conn.execute(
                "INSERT INTO evidence_attachments VALUES (?,?,?,?,?)",
                (self.analysis_id, 0, evidence.key, evidence.sha256, evidence.size),
            )
        response = self.submit()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.fake.calls[-1][2], ATTACHMENT)
        self.assertEqual(storage().read(evidence.key, evidence.sha256), ATTACHMENT)

    def test_urlscan_requires_specific_permission_and_defaults_private(self):
        self.connected()
        self.fake.name = "urlscan"
        payload = {"provider": "urlscan", "kind": "url", "value": URL, "confirm": True}
        self.assertEqual(
            self.client.post(self.prefix + "/submit", json=payload).status_code, 403
        )
        os.environ["URLSCAN_ALLOW_URL_SUBMISSION"] = "true"
        response = self.client.post(self.prefix + "/submit", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.fake.calls[0][3], "private")
        self.assertEqual(response.json()["metadata"]["requested_visibility"], "private")

    def test_missing_analysis_blocks_reads_and_provider_actions(self):
        os.environ["CONNECTIVITY_MODE"] = "restricted"
        self.prefix = "/api/workspace/analyses/unknown/enrichments"
        self.assertEqual(self.client.get(self.prefix).status_code, 404)
        self.assertEqual(self.lookup().status_code, 404)
        self.assertEqual(self.fake.calls, [])


if __name__ == "__main__":
    unittest.main()

import asyncio
import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.investigation import jobs
from backend.investigation.api import router
from backend.investigation.evidence import FileEvidenceStorage, original
from backend.investigation.store import create_admin, db, initialize

EMAIL = b"From: sender@example.org\r\nTo: analyst@example.net\r\nSubject: Queue test\r\n\r\nA harmless synthetic message.\r\n"
PASSWORD = "Test-password-12345"


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "INVESTIGATION_DB": str(Path(self.temp.name) / "test.db"),
                "COOKIE_SECURE": "false",
                "CONNECTIVITY_MODE": "offline",
                "JOB_MAX_ATTEMPTS": "2",
            },
        )
        self.env.start()
        create_admin("admin", PASSWORD)
        app = FastAPI()
        app.include_router(router, prefix="/api/workspace")
        self.client = TestClient(app, headers={"X-Requested-With": "PhishCase"})
        self.assertEqual(
            self.client.post(
                "/api/workspace/auth/login",
                json={"username": "admin", "password": PASSWORD},
            ).status_code,
            200,
        )

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.temp.cleanup()

    def upload(self, headers=None):
        response = self.client.post(
            "/api/workspace/analyses",
            files={"file": ("../../sample.eml", EMAIL)},
            headers=headers,
        )
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json()["status"], "queued")
        return response.json()

    def document(self, raw):
        return {
            "eml": {
                "header": {"subject": "Queue test"},
                "bodies": [],
                "attachments": [],
            },
            "verdicts": [],
        }

    def test_upload_returns_before_worker_and_original_survives_restart(self):
        item = self.upload()
        self.client.close()
        initialize()
        with db() as conn:
            self.assertEqual(original(conn, item["id"]), EMAIL)
            self.assertEqual(
                conn.execute("SELECT status FROM analyses").fetchone()[0], "queued"
            )
            self.assertIsNone(conn.execute("SELECT source FROM analyses").fetchone()[0])
        self.assertTrue(jobs.run_once(self.document))
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT status FROM analyses").fetchone()[0], "completed"
            )
            self.assertEqual(original(conn, item["id"]), EMAIL)

    def test_idempotency_and_payload_conflict(self):
        first = self.upload({"Idempotency-Key": "upload-1"})
        second = self.upload({"Idempotency-Key": "upload-1"})
        self.assertEqual(first["id"], second["id"])
        response = self.client.post(
            "/api/workspace/analyses",
            files={"file": ("other.eml", EMAIL + b"different")},
            headers={"Idempotency-Key": "upload-1"},
        )
        self.assertEqual(response.status_code, 409)
        with db() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)

    def test_upload_rate_limit_preserves_existing_jobs(self):
        for _ in range(20):
            self.upload()
        response = self.client.post(
            "/api/workspace/analyses", files={"file": ("qa.eml", EMAIL)}
        )
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM jobs").fetchone()[0], 20
            )

    def test_atomic_claim_expired_lease_and_stale_worker_fencing(self):
        self.upload()
        first = jobs.claim()
        self.assertIsNone(jobs.claim())
        with db() as conn:
            conn.execute("UPDATE jobs SET lease_until=?", (time.time() - 1,))
        second = jobs.claim()
        self.assertNotEqual(first["lease_token"], second["lease_token"])
        self.assertFalse(jobs.finish(first, document=self.document(EMAIL)))
        self.assertTrue(jobs.finish(second, document=self.document(EMAIL)))

    def test_bounded_retries_manual_retry_and_no_human_decision_overwrite(self):
        item = self.upload()
        for _ in range(2):
            claimed = jobs.claim()
            jobs.finish(claimed, error="Synthetic timeout")
            with db() as conn:
                conn.execute("UPDATE jobs SET available_at=0")
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT state FROM jobs").fetchone()[0], "failed"
            )
        self.assertIsNone(jobs.claim())
        self.assertEqual(
            self.client.post(f"/api/workspace/analyses/{item['id']}/retry").status_code,
            202,
        )
        self.assertTrue(jobs.run_once(self.document))
        self.assertEqual(
            self.client.post(f"/api/workspace/analyses/{item['id']}/retry").status_code,
            409,
        )

    def test_attachment_bytes_are_not_in_report_and_download_is_explicit(self):
        item = self.upload()
        content = b"<!doctype html><script>not executed</script>"
        document = self.document(EMAIL)
        document["eml"]["attachments"] = [
            {
                "filename": "../../danger.html",
                "raw": base64.b64encode(content).decode(),
                "hash": {"sha256": hashlib.sha256(content).hexdigest()},
            }
        ]
        jobs.run_once(lambda raw: document)
        report = self.client.get(f"/api/workspace/analyses/{item['id']}")
        self.assertNotIn('"raw"', report.text)
        download = self.client.get(
            f"/api/workspace/analyses/{item['id']}/attachments/0"
        )
        self.assertEqual(download.content, content)
        self.assertIn("attachment;", download.headers["content-disposition"])
        self.assertEqual(download.headers["x-content-type-options"], "nosniff")

    def test_storage_keys_traversal_symlinks_and_hash_verification(self):
        target = FileEvidenceStorage(Path(self.temp.name) / "isolated")
        value = target.put(EMAIL)
        self.assertEqual(target.read(value.key, value.sha256), EMAIL)
        with self.assertRaises(ValueError):
            target.read("../test.db")
        with self.assertRaises(ValueError):
            target.read(value.key, "0" * 64)
        link = target.path("a" * 32)
        link.symlink_to(Path(self.temp.name) / "test.db")
        with self.assertRaises(OSError):
            target.read("a" * 32)

    def test_real_isolated_eml_and_msg_parser_offline(self):
        for raw in [EMAIL, Path("tests/fixtures/complete.msg").read_bytes()]:
            document = jobs.analyze_isolated(raw)
            self.assertIn("header", document["eml"])
            self.assertIn("assessment", document)

    def test_offline_prevents_provider_and_dkim_calls(self):
        from backend.factories.response import parse, set_verdicts

        response = parse(EMAIL)
        with (
            patch(
                "backend.factories.response.get_dkim_verdict",
                side_effect=AssertionError("DNS egress"),
            ),
            patch(
                "backend.factories.response.get_vt_verdict",
                side_effect=AssertionError("VT egress"),
            ),
            patch(
                "backend.factories.response.get_urlscan_verdict",
                side_effect=AssertionError("urlscan egress"),
            ),
        ):
            asyncio.run(
                set_verdicts(
                    response,
                    eml_file=EMAIL,
                    optional_vt=object(),
                    optional_urlscan=object(),
                )
            )

    def test_api_tokens_hash_at_rest_revocation_and_source(self):
        token = self.client.post(
            "/api/workspace/auth/tokens", json={"name": "ingest"}
        ).json()
        self.assertIn("token", token)
        with db() as conn:
            self.assertNotIn(
                token["token"],
                json.dumps(dict(conn.execute("SELECT * FROM api_tokens").fetchone())),
            )
        self.client.cookies.clear()
        response = self.client.post(
            "/api/workspace/analyses",
            files={"file": ("sample.eml", EMAIL)},
            headers={
                "Authorization": "Bearer " + token["token"],
                "X-Requested-With": "",
            },
        )
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json()["ingestion_source"], "api")
        self.client.delete(
            "/api/workspace/auth/tokens/" + token["id"],
            headers={"Authorization": "Bearer " + token["token"]},
        )
        self.assertEqual(
            self.client.get(
                "/api/workspace/analyses",
                headers={"Authorization": "Bearer " + token["token"]},
            ).status_code,
            401,
        )

    def test_human_exports_escape_html_and_bundle_selection_is_explicit(self):
        import io
        import zipfile

        item = self.upload()
        document = self.document(EMAIL)
        document["eml"]["header"]["subject"] = "<script>alert(1)</script>"
        document["eml"]["attachments"] = [
            {
                "filename": "danger.html",
                "raw": base64.b64encode(b"synthetic payload").decode(),
                "hash": {},
            }
        ]
        jobs.run_once(lambda raw: document)
        base = f"/api/workspace/analyses/{item['id']}"
        rendered = self.client.get(base + "/export.html")
        self.assertEqual(rendered.status_code, 200, rendered.text)
        self.assertNotIn("<script>", rendered.text)
        self.assertIn("&lt;script&gt;", rendered.text)
        plain = self.client.get(base + "/export.json")
        self.assertNotIn('"raw"', plain.text)
        empty = zipfile.ZipFile(
            io.BytesIO(self.client.get(base + "/evidence.zip").content)
        )
        self.assertFalse(
            any(name.startswith("attachments/") for name in empty.namelist())
        )
        selected = zipfile.ZipFile(
            io.BytesIO(self.client.get(base + "/evidence.zip?attachments=0").content)
        )
        self.assertEqual(
            selected.read("attachments/attachment-1.bin"), b"synthetic payload"
        )
        manifest = json.loads(selected.read("manifest.json"))
        for name, metadata in manifest["files"].items():
            self.assertEqual(
                hashlib.sha256(selected.read(name)).hexdigest(), metadata["sha256"]
            )
        self.assertEqual(
            self.client.get(base + "/evidence.zip?attachments=-1").status_code, 422
        )

    def test_immutable_original_database_guard(self):
        import sqlite3

        self.upload()
        with self.assertRaises(sqlite3.IntegrityError), db() as conn:
            conn.execute("UPDATE analyses SET sha256=?", ("0" * 64,))

import asyncio
import os
import tempfile
import unittest
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.investigation.api import router
from backend.investigation.store import create_admin, initialize

HEADERS = {"X-Requested-With": "EML-Investigation"}
PASSWORD = "Test-password-12345"
EMAIL = b"""From: sender@example.org\r\nTo: analyst@example.net\r\nSubject: Invoice review\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlease review https://suspicious.example.org/invoice from 192.0.2.15\r\n"""


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "INVESTIGATION_DB": str(Path(self.temp.name) / "test.db"),
                "COOKIE_SECURE": "false",
                "JOB_MAX_ATTEMPTS": "1",
                "CONNECTIVITY_MODE": "offline",
            },
        )
        self.env.start()
        create_admin("admin", PASSWORD)
        self.app = FastAPI()
        self.app.include_router(router, prefix="/api/workspace")
        self.client = TestClient(self.app, headers=HEADERS)
        self.login()

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.temp.cleanup()

    def login(self, name="admin", password=PASSWORD, client=None):
        return (client or self.client).post(
            "/api/workspace/auth/login", json={"username": name, "password": password}
        )

    def upload(self, path, **kwargs):
        from backend.investigation.analyzer_task import analyze
        from backend.investigation.jobs import run_once

        response = self.client.post(path, **kwargs)
        if response.status_code != 202:
            return response
        self.assertEqual(response.json()["status"], "queued")
        run_once(lambda raw: asyncio.run(analyze(raw)))
        return self.client.get("/api/workspace/analyses/" + response.json()["id"])

    def case(self, title="Suspicious invoice"):
        r = self.client.post("/api/workspace/cases", json={"title": title})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["id"]

    def test_auth_csrf_logout(self):
        anonymous = TestClient(self.app)
        self.assertEqual(anonymous.get("/api/workspace/cases").status_code, 401)
        self.assertEqual(
            anonymous.post(
                "/api/workspace/auth/login",
                json={"username": "admin", "password": PASSWORD},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/workspace/cases",
                headers={"X-Requested-With": ""},
                json={"title": "Blocked"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post("/api/workspace/auth/logout").status_code, 200
        )
        self.assertEqual(self.client.get("/api/workspace/cases").status_code, 401)

    def test_roles_disable_and_session_revocation(self):
        for role in ("viewer", "analyst"):
            r = self.client.post(
                "/api/workspace/users",
                json={"username": role, "password": PASSWORD, "role": role},
            )
            self.assertEqual(r.status_code, 201)
        viewer = TestClient(self.app, headers=HEADERS)
        self.login("viewer", client=viewer)
        self.assertEqual(viewer.get("/api/workspace/dashboard").status_code, 200)
        self.assertEqual(
            viewer.post("/api/workspace/cases", json={"title": "Denied"}).status_code,
            403,
        )
        self.assertEqual(
            viewer.post(
                "/api/workspace/users", json={"username": "bad", "password": PASSWORD}
            ).status_code,
            403,
        )
        analyst = TestClient(self.app, headers=HEADERS)
        self.login("analyst", client=analyst)
        self.assertEqual(
            analyst.post("/api/workspace/cases", json={"title": "Allowed"}).status_code,
            201,
        )
        self.assertEqual(
            analyst.post(
                "/api/workspace/users", json={"username": "bad", "password": PASSWORD}
            ).status_code,
            403,
        )
        users = self.client.get("/api/workspace/users").json()
        target = next(u for u in users if u["username"] == "analyst")
        self.client.put(
            "/api/workspace/users/" + str(target["id"]),
            json={"role": "analyst", "active": False},
        )
        self.assertEqual(analyst.get("/api/workspace/cases").status_code, 401)
        self.assertEqual(
            self.client.put(
                "/api/workspace/users/1", json={"role": "viewer", "active": False}
            ).status_code,
            409,
        )

    def test_case_notes_and_persistence(self):
        case_id = self.case()
        path = f"/api/workspace/cases/{case_id}"
        self.assertEqual(
            self.client.put(
                path,
                json={
                    "title": "Confirmed invoice phishing",
                    "status": "investigating",
                    "priority": "high",
                    "assignee_id": 1,
                },
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                path + "/notes",
                json={"body": "Contacted recipient; no click reported."},
            ).status_code,
            201,
        )
        initialize()
        c = self.client.get(path).json()
        self.assertEqual(c["priority"], "high")
        self.assertEqual(len(c["notes"]), 1)
        self.assertEqual(len(c["events"]), 3)
        self.assertEqual(
            self.client.get("/api/workspace/cases?q=Confirmed").json()[0]["id"], case_id
        )
        self.assertEqual(
            self.client.put(
                path, json={"title": "Bad assignee", "assignee_id": 999}
            ).status_code,
            422,
        )
        self.assertEqual(self.client.get("/api/workspace/cases/999").status_code, 404)

    def test_real_email_pipeline_iocs_and_cross_case_correlation(self):
        for title in ("Campaign A", "Campaign B"):
            case_id = self.case(title)
            r = self.upload(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("sample.eml", EMAIL, "message/rfc822")},
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["status"], "completed", r.text)
            self.assertEqual(
                self.client.get(
                    "/api/workspace/analyses/" + r.json()["id"] + "/source"
                ).content,
                EMAIL,
            )
            self.assertEqual(
                r.json()["result"]["eml"]["header"]["subject"], "Invoice review"
            )
        indicators = self.client.get(
            "/api/workspace/iocs?q=suspicious.example.org"
        ).json()
        ips = self.client.get("/api/workspace/iocs?q=192.0.2.15").json()
        self.assertTrue(ips)
        self.assertEqual(ips[0]["kind"], "ip")
        self.assertTrue(indicators)
        self.assertTrue(all(i["case_count"] == 2 for i in indicators))
        ioc_id = indicators[0]["id"]
        self.assertEqual(
            self.client.put(
                f"/api/workspace/iocs/{ioc_id}", json={"verdict": "malicious"}
            ).status_code,
            200,
        )
        self.assertEqual(
            len(self.client.get(f"/api/workspace/iocs/{ioc_id}/occurrences").json()), 2
        )
        self.assertEqual(
            self.client.get("/api/workspace/dashboard").json()["analyses"], 2
        )

    def test_failed_analysis_and_limits(self):
        case_id = self.case()

        async def fail(*args, **kwargs):
            raise RuntimeError("do not disclose internal details")

        with patch("backend.api.endpoints.analyze._analyze", fail):
            r = self.upload(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("bad.eml", EMAIL)},
            )
        self.assertEqual(r.json()["status"], "failed")
        self.assertNotIn("internal", r.text)
        self.assertEqual(
            self.client.get("/api/workspace/dashboard").json()["failed_analyses"], 1
        )
        self.assertEqual(
            self.upload(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("empty.eml", b"")},
            ).status_code,
            422,
        )
        self.assertEqual(
            self.upload(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("big.eml", b"x" * (20 * 1024 * 1024 + 1))},
            ).status_code,
            413,
        )

    def test_direct_upload_creates_named_case_and_keeps_original(self):
        response = self.upload(
            "/api/workspace/analyses", files={"file": ("invoice.eml", EMAIL)}
        )
        self.assertEqual(response.status_code, 200, response.text)
        analysis = response.json()
        self.assertEqual(analysis["status"], "completed")
        self.assertEqual(analysis["assessment"]["level"], "inconclusive")
        case = self.client.get(
            "/api/workspace/cases/" + str(analysis["case_id"])
        ).json()
        self.assertEqual(
            case["title"], datetime.now(UTC).strftime("%Y-%m-%d") + " · Invoice review"
        )
        self.assertEqual(case["assignee_id"], 1)
        self.assertEqual(
            self.client.get(
                "/api/workspace/analyses/" + analysis["id"] + "/source"
            ).content,
            EMAIL,
        )
        self.assertEqual(
            self.client.get("/api/workspace/analyses/" + analysis["id"]).json()[
                "assessment"
            ],
            analysis["assessment"],
        )

    def test_direct_invalid_files_do_not_create_empty_cases(self):
        for name, content, expected in [
            ("empty.eml", b"", 422),
            ("bad.exe", EMAIL, 422),
            ("big.eml", b"x" * (20 * 1024 * 1024 + 1), 413),
        ]:
            r = self.upload("/api/workspace/analyses", files={"file": (name, content)})
            self.assertEqual(r.status_code, expected)
        self.assertEqual(self.client.get("/api/workspace/cases").json(), [])

    def test_direct_failure_is_saved_with_filename(self):
        async def fail(*args, **kwargs):
            raise RuntimeError("malformed")

        with patch("backend.api.endpoints.analyze._analyze", fail):
            r = self.upload(
                "/api/workspace/analyses", files={"file": ("broken.msg", EMAIL)}
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "failed")
        case = self.client.get(
            "/api/workspace/cases/" + str(r.json()["case_id"])
        ).json()
        self.assertTrue(case["title"].endswith(" · broken.msg"))
        self.assertEqual(
            self.client.get(
                "/api/workspace/analyses/" + r.json()["id"] + "/source"
            ).content,
            EMAIL,
        )

    def test_repeated_uploads_have_distinct_cases(self):
        results = [
            self.upload(
                "/api/workspace/analyses", files={"file": ("same.eml", EMAIL)}
            ).json()
            for _ in range(2)
        ]
        self.assertNotEqual(results[0]["case_id"], results[1]["case_id"])
        self.assertNotEqual(results[0]["id"], results[1]["id"])

    def test_msg_direct_upload(self):
        raw = Path("tests/fixtures/outer.msg").read_bytes()
        r = self.upload("/api/workspace/analyses", files={"file": ("outer.MSG", raw)})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "completed", r.text[:800])
        self.assertEqual(
            self.client.get(
                "/api/workspace/analyses/" + r.json()["id"] + "/source"
            ).content,
            raw,
        )

    def test_attachments_stay_in_same_case_and_download_as_attachment(self):
        message = EmailMessage()
        message["Subject"] = "Pièce jointe de test"
        message["From"] = "sender@example.org"
        message["To"] = "analyst@example.net"
        message.set_content("Document de test, ne pas exécuter.")
        payload = b'<script>alert("inert test")</script>'
        message.add_attachment(
            payload, maintype="text", subtype="html", filename="../rapport.html"
        )
        r = self.upload(
            "/api/workspace/analyses",
            files={"file": ("attachment.eml", message.as_bytes())},
        )
        self.assertEqual(r.status_code, 200)
        analysis = r.json()
        self.assertEqual(analysis["status"], "completed", r.text)
        self.assertEqual(len(self.client.get("/api/workspace/cases").json()), 1)
        self.assertEqual(len(analysis["result"]["eml"]["attachments"]), 1)
        path = "/api/workspace/analyses/" + analysis["id"] + "/attachments/0"
        download = self.client.get(path)
        self.assertEqual(download.content, payload)
        self.assertTrue(
            download.headers["content-disposition"].startswith("attachment;")
        )
        self.assertNotIn("../", download.headers["content-disposition"])
        self.assertEqual(download.headers["content-type"], "application/octet-stream")
        self.assertEqual(download.headers["x-content-type-options"], "nosniff")
        self.assertEqual(self.client.get(path[:-1] + "99").status_code, 404)
        self.assertEqual(self.client.get(path[:-1] + "-1").status_code, 404)
        self.assertEqual(TestClient(self.app).get(path).status_code, 401)
        self.assertTrue(
            self.client.get(
                "/api/workspace/iocs?q="
                + analysis["result"]["eml"]["attachments"][0]["hash"]["sha256"]
            ).json()
        )

    def test_viewer_cannot_use_direct_upload(self):
        self.client.post(
            "/api/workspace/users",
            json={"username": "viewer", "password": PASSWORD, "role": "viewer"},
        )
        viewer = TestClient(self.app, headers=HEADERS)
        self.login("viewer", client=viewer)
        self.assertEqual(
            viewer.post(
                "/api/workspace/analyses", files={"file": ("sample.eml", EMAIL)}
            ).status_code,
            403,
        )
        self.assertEqual(self.client.get("/api/workspace/cases").json(), [])

    def test_legacy_routes_are_unmounted_and_v1_requires_authentication(self):
        from backend.main import create_app

        client = TestClient(create_app(), headers=HEADERS)
        self.assertEqual(client.get("/api/cache/").status_code, 404)
        self.assertIn(
            client.post("/api/analyze/", json={"file": EMAIL.decode()}).status_code,
            (404, 405),
        )
        self.assertEqual(client.get("/api/v1/analyses").status_code, 401)
        self.assertEqual(
            client.post(
                "/api/v1/analyses", files={"file": ("test.eml", EMAIL)}
            ).status_code,
            401,
        )

    def test_login_throttling(self):
        self.client.post("/api/workspace/auth/logout")
        for _ in range(10):
            self.assertEqual(self.login(password="wrong").status_code, 401)
        self.assertEqual(self.login().status_code, 429)

    def test_password_reset_invalidates_session(self):
        self.assertEqual(
            self.client.put(
                "/api/workspace/users/1",
                json={
                    "role": "admin",
                    "active": True,
                    "password": "Different-password-123",
                },
            ).status_code,
            200,
        )
        self.assertEqual(self.client.get("/api/workspace/cases").status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(self.login(password="Different-password-123").status_code, 200)


if __name__ == "__main__":
    unittest.main()

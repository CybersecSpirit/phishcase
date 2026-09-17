import os
import tempfile
import unittest
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
            r = self.client.post(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("sample.eml", EMAIL, "message/rfc822")},
            )
            self.assertEqual(r.status_code, 201, r.text)
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

        with patch("backend.investigation.api._analyze", fail):
            r = self.client.post(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("bad.eml", EMAIL)},
            )
        self.assertEqual(r.json()["status"], "failed")
        self.assertNotIn("internal", r.text)
        self.assertEqual(
            self.client.get("/api/workspace/dashboard").json()["failed_analyses"], 1
        )
        self.assertEqual(
            self.client.post(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("empty.eml", b"")},
            ).status_code,
            422,
        )
        self.assertEqual(
            self.client.post(
                f"/api/workspace/cases/{case_id}/analyses",
                files={"file": ("big.eml", b"x" * (20 * 1024 * 1024 + 1))},
            ).status_code,
            413,
        )

    def test_legacy_routes_require_authentication(self):
        from backend.main import create_app

        client = TestClient(create_app(), headers=HEADERS)
        self.assertEqual(client.get("/api/cache/").status_code, 401)
        self.assertEqual(
            client.post("/api/analyze/", json={"file": EMAIL.decode()}).status_code, 401
        )
        self.client.post(
            "/api/workspace/users",
            json={"username": "viewer", "password": PASSWORD, "role": "viewer"},
        )
        client.post(
            "/api/workspace/auth/login",
            json={"username": "viewer", "password": PASSWORD},
        )
        self.assertEqual(
            client.post("/api/analyze/", json={"file": EMAIL.decode()}).status_code, 403
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

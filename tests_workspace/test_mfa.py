import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.investigation.api import router
from backend.investigation.store import create_admin, db, initialize

HEADERS = {"X-Requested-With": "EML-Investigation"}
PASSWORD = "Test-password-12345"
PREFIX = "/api/workspace/auth/mfa"


class MFATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "test.db")
        self.env = patch.dict(
            os.environ,
            INVESTIGATION_DB=self.path,
            COOKIE_SECURE="false",
            MFA_ENCRYPTION_KEY="",
        )
        self.env.start()
        self.now = int(time.time() / 30) * 30 + 5
        self.clock = patch(
            "backend.investigation.mfa.time.time", side_effect=lambda: self.now
        )
        self.clock.start()
        create_admin("admin", PASSWORD)
        self.app = FastAPI()
        self.app.include_router(router, prefix="/api/workspace")
        self.client = self.browser()
        self.login(self.client)

    def tearDown(self):
        self.client.close()
        self.clock.stop()
        self.env.stop()
        self.temp.cleanup()

    def browser(self):
        return TestClient(self.app, headers=HEADERS)

    def login(self, client, password=PASSWORD):
        return client.post(
            "/api/workspace/auth/login",
            json={"username": "admin", "password": password},
        )

    def post(self, suffix, data, client=None):
        return (client or self.client).post(PREFIX + suffix, json=data)

    def setup_mfa(self):
        response = self.post("/setup", {"password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        data = response.json()
        self.assertTrue(data["qr"].startswith("data:image/svg+xml;base64,"))
        return data["secret"]

    def enable_mfa(self):
        secret = self.setup_mfa()
        response = self.post("/enable", {"code": pyotp.TOTP(secret).at(self.now)})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        codes = response.json()["recovery_codes"]
        self.assertEqual(len(set(codes)), 10)
        return secret, codes

    def test_enrollment_requires_password_and_valid_code(self):
        self.assertEqual(self.post("/setup", {"password": "wrong"}).status_code, 400)
        self.assertEqual(self.client.get(PREFIX).json()["enabled"], False)
        secret = self.setup_mfa()
        self.assertEqual(self.post("/enable", {"code": "abcdef"}).status_code, 400)
        self.assertFalse(self.client.get(PREFIX).json()["enabled"])
        self.assertEqual(
            self.post("/enable", {"code": pyotp.TOTP(secret).at(self.now)}).status_code,
            200,
        )
        self.assertTrue(self.client.get(PREFIX).json()["enabled"])
        self.assertEqual(self.post("/setup", {"password": PASSWORD}).status_code, 409)

    def test_enrollment_bound_to_session_and_expires(self):
        second = self.browser()
        self.login(second)
        secret = self.setup_mfa()
        self.assertEqual(
            self.post(
                "/enable", {"code": pyotp.TOTP(secret).at(self.now)}, second
            ).status_code,
            400,
        )
        self.now += 601
        self.assertEqual(
            self.post("/enable", {"code": pyotp.TOTP(secret).at(self.now)}).status_code,
            400,
        )
        self.setup_mfa()
        self.assertEqual(self.post("/cancel", {}).status_code, 200)
        self.assertEqual(self.post("/enable", {"code": "123456"}).status_code, 400)

    def test_enabling_rotates_session_and_revokes_others(self):
        second = self.browser()
        self.login(second)
        original = self.client.cookies.get("eml_session")
        self.enable_mfa()
        self.assertNotEqual(original, self.client.cookies.get("eml_session"))
        self.assertEqual(self.client.get("/api/workspace/dashboard").status_code, 200)
        self.assertEqual(second.get("/api/workspace/dashboard").status_code, 401)

    def test_password_is_not_session_and_code_cannot_be_replayed(self):
        secret, _ = self.enable_mfa()
        browser = self.browser()
        response = self.login(browser)
        self.assertEqual(response.json(), {"mfa_required": True})
        self.assertIsNone(browser.cookies.get("eml_session"))
        self.assertEqual(browser.get("/api/workspace/cases").status_code, 401)
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now)}, browser
            ).status_code,
            400,
        )
        self.now += 30
        code = pyotp.TOTP(secret).at(self.now)
        self.assertEqual(self.post("/verify", {"code": code}, browser).status_code, 200)
        self.assertEqual(browser.get("/api/workspace/cases").status_code, 200)
        self.assertEqual(self.post("/verify", {"code": code}, browser).status_code, 401)
        self.login(browser)
        self.assertEqual(browser.get("/api/workspace/cases").status_code, 401)
        self.assertEqual(self.post("/verify", {"code": code}, browser).status_code, 400)

    def test_challenge_expiry_and_no_challenge_denied(self):
        secret, _ = self.enable_mfa()
        browser = self.browser()
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now)}, browser
            ).status_code,
            401,
        )
        self.login(browser)
        self.now += 301
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now)}, browser
            ).status_code,
            401,
        )

    def test_clock_tolerance_and_outside_window(self):
        secret, _ = self.enable_mfa()
        self.now += 120
        browser = self.browser()
        self.login(browser)
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now - 60)}, browser
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now - 30)}, browser
            ).status_code,
            200,
        )
        self.login(browser)
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now + 30)}, browser
            ).status_code,
            200,
        )

    def test_recovery_code_single_use_and_stored_hashed(self):
        secret, codes = self.enable_mfa()
        with db() as conn:
            stored = conn.execute("SELECT * FROM users").fetchone()
            self.assertNotEqual(stored["mfa_secret"], secret)
            self.assertNotIn(secret, stored["mfa_secret"])
            saved_codes = [
                r[0] for r in conn.execute("SELECT digest FROM mfa_recovery")
            ]
            self.assertNotIn(codes[0].replace("-", ""), saved_codes)
        self.assertEqual(Path(self.path + ".mfa.key").stat().st_mode & 0o777, 0o600)
        browser = self.browser()
        self.login(browser)
        self.assertEqual(
            self.post("/verify", {"code": codes[0].upper()}, browser).status_code, 200
        )
        self.assertEqual(browser.get(PREFIX).json()["recovery_remaining"], 9)
        self.login(browser)
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 400
        )
        for route in ("/api/workspace/auth/me", "/api/workspace/users", PREFIX):
            text = self.client.get(route).text
            self.assertNotIn(secret, text)
            self.assertNotIn(codes[1], text)
            self.assertNotIn("mfa_secret", text)

    def test_factor_throttling_survives_new_password_challenges(self):
        _, codes = self.enable_mfa()
        browser = self.browser()
        for _ in range(5):
            self.login(browser)
            self.assertEqual(
                self.post("/verify", {"code": "invalid"}, browser).status_code, 400
            )
        self.login(browser)
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 429
        )
        self.now += 901
        self.login(browser)
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 200
        )

    def test_setup_throttled_and_csrf_required(self):
        for _ in range(5):
            self.assertEqual(
                self.post("/setup", {"password": "wrong"}).status_code, 400
            )
        self.assertEqual(self.post("/setup", {"password": PASSWORD}).status_code, 429)
        for route in (
            "/verify",
            "/setup",
            "/enable",
            "/cancel",
            "/disable",
            "/recovery",
        ):
            self.assertEqual(
                self.client.post(
                    PREFIX + route,
                    headers={"X-Requested-With": ""},
                    json={"password": PASSWORD, "code": "123456"},
                ).status_code,
                403,
            )

    def test_disable_requires_both_factors(self):
        _, codes = self.enable_mfa()
        self.assertEqual(
            self.post("/disable", {"password": "wrong", "code": codes[0]}).status_code,
            400,
        )
        self.assertEqual(
            self.post("/disable", {"password": PASSWORD, "code": "wrong"}).status_code,
            400,
        )
        self.assertTrue(self.client.get(PREFIX).json()["enabled"])
        browser = self.browser()
        self.login(browser)
        self.assertEqual(
            self.post("/disable", {"password": PASSWORD, "code": codes[0]}).status_code,
            200,
        )
        self.assertFalse(self.client.get(PREFIX).json()["enabled"])
        self.assertEqual(
            self.post("/verify", {"code": codes[1]}, browser).status_code, 401
        )
        self.assertIn("id", self.login(browser).json())

    def test_regenerate_invalidates_old_codes_and_other_sessions(self):
        _, codes = self.enable_mfa()
        browser = self.browser()
        self.login(browser)
        self.post("/verify", {"code": codes[0]}, browser)
        response = self.post("/recovery", {"password": PASSWORD, "code": codes[1]})
        self.assertEqual(response.status_code, 200)
        new_codes = response.json()["recovery_codes"]
        self.assertEqual(browser.get("/api/workspace/cases").status_code, 401)
        self.login(browser)
        self.assertEqual(
            self.post("/verify", {"code": codes[2]}, browser).status_code, 400
        )
        self.assertEqual(
            self.post("/verify", {"code": new_codes[0]}, browser).status_code, 200
        )

    def test_admin_password_reset_revokes_challenges_but_keeps_mfa(self):
        _, codes = self.enable_mfa()
        browser = self.browser()
        self.login(browser)
        self.assertEqual(
            self.client.put(
                "/api/workspace/users/1",
                json={
                    "role": "admin",
                    "active": True,
                    "password": "Changed-password-12345",
                },
            ).status_code,
            200,
        )
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 401
        )
        self.assertEqual(self.login(browser).status_code, 401)
        self.assertEqual(
            self.login(browser, "Changed-password-12345").json(), {"mfa_required": True}
        )
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 200
        )

    def test_encrypted_seed_survives_restart_and_missing_key_fails_closed(self):
        secret, codes = self.enable_mfa()
        initialize()
        browser = self.browser()
        self.login(browser)
        self.now += 30
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now)}, browser
            ).status_code,
            200,
        )
        Path(self.path + ".mfa.key").unlink()
        self.login(browser)
        self.now += 30
        self.assertEqual(
            self.post(
                "/verify", {"code": pyotp.TOTP(secret).at(self.now)}, browser
            ).status_code,
            503,
        )
        self.assertFalse(Path(self.path + ".mfa.key").exists())
        self.assertEqual(browser.get("/api/workspace/cases").status_code, 401)
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 200
        )

    def test_encryption_key_override(self):
        with patch.dict(os.environ, MFA_ENCRYPTION_KEY=Fernet.generate_key().decode()):
            secret, _ = self.enable_mfa()
            self.assertFalse(Path(self.path + ".mfa.key").exists())
            browser = self.browser()
            self.login(browser)
            self.now += 30
            self.assertEqual(
                self.post(
                    "/verify", {"code": pyotp.TOTP(secret).at(self.now)}, browser
                ).status_code,
                200,
            )

    def test_schema_migration_preserves_accounts_and_sessions(self):
        # Simulate the pre-MFA users schema, then run startup migration twice.
        with db() as conn:
            conn.execute("ALTER TABLE users DROP COLUMN mfa_secret")
            conn.execute("ALTER TABLE users DROP COLUMN mfa_last_step")
        initialize()
        initialize()
        self.assertEqual(
            self.client.get("/api/workspace/auth/me").json()["username"], "admin"
        )
        self.assertFalse(self.client.get(PREFIX).json()["enabled"])

    def test_viewer_can_manage_own_mfa_but_not_accounts(self):
        created = self.client.post(
            "/api/workspace/users",
            json={"username": "reader", "password": PASSWORD, "role": "viewer"},
        )
        self.assertEqual(created.status_code, 201)
        reader = self.browser()
        reader.post(
            "/api/workspace/auth/login",
            json={"username": "reader", "password": PASSWORD},
        )
        result = self.post("/setup", {"password": PASSWORD}, reader)
        self.assertEqual(result.status_code, 200)
        secret = result.json()["secret"]
        self.assertEqual(
            self.post(
                "/enable", {"code": pyotp.TOTP(secret).at(self.now)}, reader
            ).status_code,
            200,
        )
        self.assertTrue(reader.get(PREFIX).json()["enabled"])
        self.assertFalse(self.client.get(PREFIX).json()["enabled"])
        self.assertEqual(
            reader.post(
                "/api/workspace/users",
                json={"username": "another", "password": PASSWORD},
            ).status_code,
            403,
        )

    def test_recovery_consumption_is_atomic(self):
        from concurrent.futures import ThreadPoolExecutor

        _, codes = self.enable_mfa()
        browser = self.browser()
        self.login(browser)
        challenge = browser.cookies.get("eml_mfa")

        def verify():
            other = self.browser()
            other.cookies.set("eml_mfa", challenge)
            return self.post("/verify", {"code": codes[0]}, other).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: verify(), range(2)))
        self.assertEqual(sorted(statuses), [200, 401])
        self.assertEqual(self.client.get(PREFIX).json()["recovery_remaining"], 9)

    def test_disabled_account_cannot_finish_pending_challenge(self):
        _, codes = self.enable_mfa()
        browser = self.browser()
        self.login(browser)
        with db() as conn:
            conn.execute("UPDATE users SET active=0 WHERE id=1")
        self.assertEqual(
            self.post("/verify", {"code": codes[0]}, browser).status_code, 401
        )

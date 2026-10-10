"""Real SQLite workflow persistence, roles, conflicts and explicit transmission."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.investigation.api import router
from backend.investigation.store import create_admin, db, initialize

P = "/api/workspace"
H = {"X-Requested-With": "EML-Investigation"}
PASSWORD = "Test-password-12345"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "INVESTIGATION_DB": str(Path(self.temp.name) / "case.db"),
                "COOKIE_SECURE": "false",
                "SMTP_HOST": "",
                "SMTP_FROM": "",
            },
        )
        self.env.start()
        create_admin("admin", PASSWORD)
        self.app = FastAPI()
        self.app.include_router(router, prefix=P)
        self.client = TestClient(self.app, headers=H)
        self.client.post(
            P + "/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.case = self.client.post(P + "/cases", json={"title": "Signalement"}).json()

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.temp.cleanup()

    def action(self):
        response = self.client.post(
            P + f"/cases/{self.case['id']}/actions",
            json={
                "title": "Révoquer la session",
                "owner_id": 1,
                "due_date": "2026-10-12",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def reply(self):
        response = self.client.post(
            P + f"/cases/{self.case['id']}/replies",
            json={
                "recipient": "reporter@example.org",
                "subject": "Votre signalement",
                "body": "<script>no execution</script>\nMerci.",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_actions_persist_and_migration_is_idempotent(self):
        action = self.action()
        initialize()
        items = self.client.get(P + f"/cases/{self.case['id']}/actions").json()
        self.assertEqual(items[0]["id"], action["id"])
        self.assertEqual(items[0]["due_date"], "2026-10-12")
        self.assertEqual(self.client.get(P + "/actions?scope=mine").json()["total"], 1)

    def test_action_proof_and_controlled_closure(self):
        action = self.action()
        self.assertEqual(
            self.client.put(
                P + f"/cases/{self.case['id']}", json={**self.case, "status": "closed"}
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.put(
                P + f"/actions/{action['id']}", json={**action, "status": "done"}
            ).status_code,
            422,
        )
        saved = self.client.put(
            P + f"/actions/{action['id']}",
            json={
                **action,
                "status": "done",
                "proof": "Session révoquée ; référence IT-123",
            },
        ).json()
        self.assertEqual(saved["revision"], 2)
        self.assertEqual(
            self.client.put(
                P + f"/cases/{self.case['id']}", json={**self.case, "status": "closed"}
            ).status_code,
            200,
        )

    def test_action_assignee_and_initial_terminal_states_are_validated(self):
        url = P + f"/cases/{self.case['id']}/actions"
        self.assertEqual(
            self.client.post(
                url, json={"title": "Invalid owner", "owner_id": 999}
            ).status_code,
            422,
        )
        for state in ("done", "cancelled"):
            self.assertEqual(
                self.client.post(
                    url, json={"title": "Document action", "status": state}
                ).status_code,
                422,
            )
        self.assertEqual(self.client.get(url).json(), [])
        self.assertEqual(
            self.client.post(
                url,
                json={
                    "title": "Cancel duplicate",
                    "status": "cancelled",
                    "proof": "Already tracked in IR-123",
                },
            ).status_code,
            201,
        )

    def test_conflicting_case_and_action_changes_do_not_overwrite(self):
        case_url = P + f"/cases/{self.case['id']}"
        self.assertEqual(
            self.client.put(
                case_url, json={**self.case, "title": "Analyste A"}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.put(
                case_url, json={**self.case, "title": "Analyste B"}
            ).status_code,
            409,
        )
        self.assertEqual(self.client.get(case_url).json()["title"], "Analyste A")
        action = self.action()
        self.assertEqual(
            self.client.put(
                P + f"/actions/{action['id']}",
                json={**action, "title": "Première version"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.put(
                P + f"/actions/{action['id']}",
                json={**action, "title": "Version obsolète"},
            ).status_code,
            409,
        )

    def test_viewer_can_read_but_cannot_write_or_send(self):
        self.client.post(
            P + "/users",
            json={"username": "viewer", "password": PASSWORD, "role": "viewer"},
        )
        reply = self.reply()
        with TestClient(self.app, headers=H) as viewer:
            viewer.post(
                P + "/auth/login", json={"username": "viewer", "password": PASSWORD}
            )
            self.assertEqual(
                viewer.get(P + f"/cases/{self.case['id']}/replies").status_code, 200
            )
            self.assertEqual(
                viewer.post(
                    P + f"/cases/{self.case['id']}/actions", json={"title": "Blocked"}
                ).status_code,
                403,
            )
            self.assertEqual(
                viewer.post(
                    P + f"/replies/{reply['id']}/send", json={"revision": 1}
                ).status_code,
                403,
            )
            self.assertEqual(
                viewer.post(
                    P + f"/replies/{reply['id']}/reconcile",
                    json={
                        "revision": 1,
                        "outcome": "accepted",
                        "proof": "Unauthorized",
                    },
                ).status_code,
                403,
            )

    def test_reply_preview_and_absent_transport_never_send(self):
        reply = self.reply()
        self.assertEqual(
            self.client.get(P + f"/replies/{reply['id']}/preview").json()["body"],
            reply["body"],
        )
        self.assertEqual(
            self.client.post(
                P + f"/replies/{reply['id']}/send", json={"revision": 1}
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.get(P + f"/cases/{self.case['id']}/replies").json()["items"][0][
                "status"
            ],
            "draft",
        )

    def test_explicit_send_is_once_and_acceptance_is_recorded(self):
        reply = self.reply()
        sender = Mock()
        with patch(
            "backend.investigation.workflows.reply_transport", return_value=sender
        ):
            response = self.client.post(
                P + f"/replies/{reply['id']}/send", json={"revision": 1}
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["status"], "accepted")
            self.assertEqual(
                self.client.post(
                    P + f"/replies/{reply['id']}/send", json={"revision": 2}
                ).status_code,
                409,
            )
        sender.assert_called_once_with(
            reply["recipient"], reply["subject"], reply["body"]
        )

    def test_uncertain_send_is_visible_and_cannot_be_repeated(self):
        reply = self.reply()
        sender = Mock(side_effect=TimeoutError("private transport detail"))
        with patch(
            "backend.investigation.workflows.reply_transport", return_value=sender
        ):
            response = self.client.post(
                P + f"/replies/{reply['id']}/send", json={"revision": 1}
            )
            self.assertEqual(response.json()["status"], "uncertain")
            self.assertNotIn("private transport detail", response.text)
            self.assertEqual(
                self.client.post(
                    P + f"/replies/{reply['id']}/send", json={"revision": 2}
                ).status_code,
                409,
            )
        sender.assert_called_once()

    def test_transport_reconciliation_records_proof_without_sending(self):
        reply = self.reply()
        sender = Mock(side_effect=TimeoutError())
        with patch(
            "backend.investigation.workflows.reply_transport", return_value=sender
        ):
            uncertain = self.client.post(
                P + f"/replies/{reply['id']}/send", json={"revision": 1}
            ).json()
            url = P + f"/replies/{reply['id']}/reconcile"
            data = {
                "revision": uncertain["revision"],
                "outcome": "failed",
                "proof": "SMTP log IR-123: rejected before acceptance",
            }
            self.assertEqual(
                self.client.post(url, json={**data, "proof": " "}).status_code, 422
            )
            self.assertEqual(
                self.client.post(url, json={**data, "revision": 1}).status_code, 409
            )
            failed = self.client.post(url, json=data)
            self.assertEqual(failed.status_code, 200, failed.text)
            self.assertEqual(failed.json()["status"], "failed")
            self.assertEqual(failed.json()["reconciliation_proof"], data["proof"])
            self.assertEqual(failed.json()["resolved_by"], 1)
            self.assertEqual(
                self.client.post(
                    P + f"/replies/{reply['id']}/send",
                    json={"revision": failed.json()["revision"]},
                ).status_code,
                409,
            )
            revised = self.client.put(P + f"/replies/{reply['id']}", json=failed.json())
            self.assertEqual(revised.status_code, 200, revised.text)
            self.assertEqual(revised.json()["status"], "draft")
        sender.assert_called_once()
        with db() as conn:
            event = conn.execute(
                "SELECT detail FROM events WHERE action='reply.reconciled'"
            ).fetchone()
            self.assertIn(data["proof"], event["detail"])

    def test_late_transport_failure_cannot_overwrite_verified_reconciliation(self):
        reply = self.reply()

        def late_failure(*args):
            result = self.client.post(
                P + f"/replies/{reply['id']}/reconcile",
                json={
                    "revision": 2,
                    "outcome": "failed",
                    "proof": "Transport rejection checked / IR-789",
                },
            )
            self.assertEqual(result.status_code, 200, result.text)
            raise TimeoutError()

        with patch(
            "backend.investigation.workflows.reply_transport", return_value=late_failure
        ):
            result = self.client.post(
                P + f"/replies/{reply['id']}/send", json={"revision": 1}
            )
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["status"], "failed")
        self.assertEqual(result.json()["revision"], 3)
        self.assertEqual(
            result.json()["reconciliation_proof"],
            "Transport rejection checked / IR-789",
        )
        with db() as conn:
            self.assertIsNotNone(
                conn.execute(
                    "SELECT id FROM events WHERE action='reply.transport_observed'"
                ).fetchone()
            )

    def test_crashed_sending_reconciles_acceptance_and_unblocks_closure(self):
        reply = self.reply()
        with db() as conn:
            conn.execute(
                "UPDATE reporter_replies SET status='sending',revision=2 WHERE id=?",
                (reply["id"],),
            )
        case_url = P + f"/cases/{self.case['id']}"
        self.assertEqual(
            self.client.put(
                case_url, json={**self.case, "status": "closed"}
            ).status_code,
            409,
        )
        result = self.client.post(
            P + f"/replies/{reply['id']}/reconcile",
            json={
                "revision": 2,
                "outcome": "accepted",
                "proof": "SMTP accepted message reference IR-456",
            },
        )
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["status"], "accepted")
        self.assertIsNotNone(result.json()["accepted_at"])
        self.assertEqual(
            self.client.put(
                case_url, json={**self.case, "status": "closed"}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                P + f"/replies/{reply['id']}/reconcile",
                json={"revision": 3, "outcome": "failed", "proof": "Change"},
            ).status_code,
            409,
        )

    def test_intelligence_is_sourced_and_human_confidence_is_bounded(self):
        data = {
            "case_id": self.case["id"],
            "title": "Fuite potentielle",
            "source": "Rapport interne / IR-42",
            "facts": "Adresse exposée observée dans une source datée",
            "counter_evidence": "Aucun lien temporel établi",
            "hypothesis": "Réemploi possible",
            "confidence": 40,
            "observed_at": "2026-10-10",
        }
        result = self.client.post(P + "/intelligence", json=data)
        self.assertEqual(result.status_code, 201, result.text)
        self.assertEqual(
            self.client.get(P + "/intelligence").json()["items"][0]["counter_evidence"],
            data["counter_evidence"],
        )
        self.assertEqual(
            self.client.post(
                P + "/intelligence", json={**data, "confidence": 101}
            ).status_code,
            422,
        )
        saved = result.json()
        self.assertEqual(
            self.client.put(
                P + f"/intelligence/{saved['id']}",
                json={**saved, "facts": "Faits révisés"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.put(P + f"/intelligence/{saved['id']}", json=saved).status_code,
            409,
        )

    def test_decision_conflict_and_unqualified_message_block_closure(self):
        with db() as conn:
            conn.execute(
                "INSERT INTO analyses(id,case_id,filename,sha256,status,created_by) VALUES ('a',?,'a.eml',?,'completed',1)",
                (self.case["id"], "a" * 64),
            )
        self.assertEqual(
            self.client.put(
                P + f"/cases/{self.case['id']}", json={**self.case, "status": "closed"}
            ).status_code,
            409,
        )
        decision = {
            "verdict": "inconclusive",
            "confidence": 20,
            "justification": "Éléments insuffisants",
            "expected_decision_id": 0,
        }
        self.assertEqual(
            self.client.put(P + "/analyses/a/decision", json=decision).status_code, 200
        )
        self.assertEqual(
            self.client.put(P + "/analyses/a/decision", json=decision).status_code, 409
        )

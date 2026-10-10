"""Email ownership, conservative legacy migration and campaign concurrency."""

import hashlib
import json
import sqlite3
import unittest
from pathlib import Path

import test_jobs as helpers

from backend.investigation import jobs
from backend.investigation.evidence import original
from backend.investigation.store import db, initialize

P = "/api/workspace"


class EmailCampaignTests(unittest.TestCase):
    setUp = helpers.JobTests.setUp
    tearDown = helpers.JobTests.tearDown
    upload = helpers.JobTests.upload
    document = helpers.JobTests.document

    def test_optional_multiple_campaigns_detach_preserves_decision_and_evidence(self):
        email = self.upload()
        self.assertIsNone(email["case_id"])
        jobs.run_once(self.document)
        decision = self.client.put(
            P + f"/analyses/{email['id']}/decision",
            json={
                "verdict": "legitimate",
                "confidence": 85,
                "justification": "Reviewed original",
            },
        )
        self.assertEqual(decision.status_code, 200, decision.text)
        first = self.client.post(
            P + "/campaigns",
            json={"name": "First", "analysis_ids": [email["id"]], "assignee_id": 1},
        ).json()
        second = self.client.post(
            P + "/campaigns", json={"name": "Second", "analysis_ids": [email["id"]]}
        ).json()
        self.assertEqual(
            len(self.client.get(P + f"/analyses/{email['id']}/campaigns").json()), 2
        )
        root = P + f"/campaigns/{first['id']}"
        changed = self.client.put(root, json={**first, "priority": "high"})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(self.client.put(root, json=first).status_code, 409)
        self.assertEqual(
            self.client.delete(
                root + f"/emails/{email['id']}?revision={first['revision']}"
            ).status_code,
            409,
        )
        revision = changed.json()["revision"]
        self.assertEqual(
            self.client.delete(
                root + f"/emails/{email['id']}?revision={revision}"
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(P + f"/analyses/{email['id']}/campaigns").json()[0]["id"],
            second["id"],
        )
        exported = self.client.get(P + f"/analyses/{email['id']}/export.json").json()
        self.assertEqual(exported["analyst_decisions"][0]["verdict"], "legitimate")
        self.assertEqual(
            self.client.get(P + f"/analyses/{email['id']}/source").content,
            helpers.EMAIL,
        )
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM cases").fetchone()[0], 0
            )

    def test_closed_campaign_pending_work_permissions_and_atomic_invalid_membership(
        self,
    ):
        email = self.upload()
        campaign = self.client.post(
            P + "/campaigns", json={"name": "Follow up", "analysis_ids": [email["id"]]}
        ).json()
        root = P + f"/campaigns/{campaign['id']}"
        self.assertEqual(
            self.client.put(root, json={**campaign, "status": "closed"}).status_code,
            409,
        )
        self.assertEqual(
            self.client.post(
                root + "/emails",
                json={
                    "analysis_ids": [email["id"], "absent"],
                    "revision": campaign["revision"],
                },
            ).status_code,
            404,
        )
        self.assertEqual(self.client.get(root).json()["revision"], campaign["revision"])
        jobs.run_once(self.document)
        self.client.put(
            P + f"/analyses/{email['id']}/decision",
            json={
                "verdict": "legitimate",
                "confidence": 80,
                "justification": "Reviewed",
            },
        )
        action = self.client.post(
            root + "/actions", json={"title": "Verify removal"}
        ).json()
        self.assertEqual(
            self.client.put(root, json={**campaign, "status": "closed"}).status_code,
            409,
        )
        done = self.client.put(
            P + f"/actions/{action['id']}",
            json={**action, "status": "done", "proof": "Removal verified"},
        )
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(
            self.client.put(root, json={**campaign, "status": "closed"}).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                root + "/actions", json={"title": "More work"}
            ).status_code,
            409,
        )
        self.client.post(
            P + "/users",
            json={"username": "reader", "password": helpers.PASSWORD, "role": "viewer"},
        )
        self.client.post(P + "/auth/logout")
        self.client.post(
            P + "/auth/login", json={"username": "reader", "password": helpers.PASSWORD}
        )
        self.assertEqual(self.client.get(root + "/emails").status_code, 200)
        self.assertEqual(
            self.client.post(root + "/notes", json={"body": "Forbidden"}).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(P + "/campaigns", json={"name": "Forbidden"}).status_code,
            403,
        )

    def test_migration_of_published_schema_preserves_every_context_and_is_idempotent(
        self,
    ):
        # Replace the disposable DB with a genuine published Folio schema.
        path = Path(self.temp.name) / "test.db"
        self.client.close()
        path.unlink()
        conn = sqlite3.connect(path)
        conn.executescript(
            (Path(__file__).parent / "fixtures/folio_legacy.sql").read_text()
        )
        conn.execute(
            "INSERT INTO users(id,username,password,role) VALUES(1,'admin','unused','admin')"
        )
        for identity, title, description in [
            (1, "2026-10-09 · Queue test", ""),
            (2, "2026-10-09 · Queue test", "Useful context"),
            (3, "Named investigation", ""),
        ]:
            conn.execute(
                "INSERT INTO cases(id,title,description,created_by,assignee_id,priority) VALUES(?,?,?,?,?,?)",
                (
                    identity,
                    title,
                    description,
                    1,
                    1,
                    "high" if identity == 3 else "medium",
                ),
            )
            document = json.dumps(self.document(helpers.EMAIL))
            conn.execute(
                "INSERT INTO analyses(id,case_id,filename,sha256,status,result,created_by,source,auto_title,created_at,subject) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(identity),
                    identity,
                    "sample.eml",
                    hashlib.sha256(helpers.EMAIL).hexdigest(),
                    "completed",
                    document,
                    1,
                    helpers.EMAIL,
                    "2026-10-09 · sample.eml",
                    "2026-10-09 11:00:00",
                    "Queue test",
                ),
            )
            conn.execute(
                "INSERT INTO events(actor_id,case_id,action,detail) VALUES(1,?,'analysis.completed',?)",
                (identity, str(identity)),
            )
        conn.execute(
            "INSERT INTO campaigns(id,name,created_by) VALUES(1,'Existing correlation',1)"
        )
        conn.execute("INSERT INTO campaign_cases VALUES(1,1)")
        conn.execute("INSERT INTO campaign_cases VALUES(1,2)")
        conn.execute(
            "INSERT INTO notes(case_id,author_id,body) VALUES(2,1,'Preserved note')"
        )
        conn.execute(
            "INSERT INTO case_actions(case_id,title,created_by) VALUES(2,'Preserved action',1)"
        )
        conn.execute(
            "INSERT INTO reporter_replies(case_id,recipient,subject,body,created_by) VALUES(2,'test@example.org','Subject','Preserved case reply',1)"
        )
        conn.execute(
            "INSERT INTO reporter_replies(case_id,analysis_id,recipient,subject,body,created_by) VALUES(1,'1','test@example.org','Subject','Preserved email reply',1)"
        )
        conn.execute(
            "INSERT INTO intelligence_links(case_id,title,source,facts,observed_at,created_by) VALUES(2,'Preserved lead','IR-123','Observed','2026-10-09',1)"
        )
        conn.execute(
            "INSERT INTO analyst_decisions(analysis_id,actor_id,verdict,confidence,justification,action) VALUES('1',1,'legitimate',90,'Preserved decision','decided')"
        )
        conn.commit()
        conn.close()
        initialize()
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM analyses").fetchone()[0], 3
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM campaigns").fetchone()[0], 3
            )
            self.assertIsNone(
                conn.execute(
                    "SELECT campaign_id FROM legacy_case_links WHERE case_id=1"
                ).fetchone()[0]
            )
            target = conn.execute(
                "SELECT campaign_id FROM legacy_case_links WHERE case_id=2"
            ).fetchone()[0]
            self.assertEqual(
                conn.execute(
                    "SELECT body FROM campaign_notes WHERE campaign_id=?", (target,)
                ).fetchone()[0],
                "Preserved note",
            )
            for table in ("case_actions", "intelligence_links"):
                self.assertEqual(
                    conn.execute(f"SELECT campaign_id FROM {table}").fetchone()[0],
                    target,
                )
            self.assertEqual(
                conn.execute(
                    "SELECT campaign_id FROM reporter_replies WHERE analysis_id IS NULL"
                ).fetchone()[0],
                target,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT analysis_id FROM reporter_replies WHERE analysis_id='1'"
                ).fetchone()[0],
                "1",
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM campaign_analyses WHERE campaign_id=1"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                conn.execute("SELECT verdict FROM analyst_decisions").fetchone()[0],
                "legitimate",
            )
            self.assertEqual(original(conn, "1"), helpers.EMAIL)
            self.assertFalse(conn.execute("PRAGMA foreign_key_check").fetchall())
            before = {
                t: [tuple(r) for r in conn.execute(f"SELECT * FROM {t}")]
                for t in (
                    "analyses",
                    "campaigns",
                    "campaign_analyses",
                    "campaign_notes",
                    "legacy_case_links",
                    "campaign_events",
                )
            }
        initialize()
        with db() as conn:
            for table, rows in before.items():
                self.assertEqual(
                    [tuple(r) for r in conn.execute(f"SELECT * FROM {table}")], rows
                )

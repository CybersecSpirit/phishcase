"""Exercise real SQLite queries and API pagination beyond the former 500-row cap."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from backend.investigation.api import router
from backend.investigation.investigations import (
    _legacy_or_page,
    index_analysis,
    initialize_investigations,
)
from backend.investigation.store import create_admin, db, initialize

PREFIX = "/api/workspace"
PASSWORD = "Test-password-12345"
HEADERS = {"X-Requested-With": "EML-Investigation"}


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "INVESTIGATION_DB": str(Path(self.temp.name) / "investigations.db"),
                "COOKIE_SECURE": "false",
            },
        )
        self.env.start()
        create_admin("admin", PASSWORD)
        with db() as conn:
            initialize_investigations(conn)
        app = FastAPI()
        app.include_router(router, prefix=PREFIX)
        self.app = app
        self.client = TestClient(app, headers=HEADERS)
        response = self.client.post(
            PREFIX + "/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.temp.cleanup()

    def get(self, path, **params):
        response = self.client.get(PREFIX + path, params=params)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def case(self, title="Invoice review"):
        response = self.client.post(PREFIX + "/cases", json={"title": title})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def analysis(
        self,
        case_id,
        identity="analysis-1",
        subject="Invoice review",
        sender="sender@example.org",
        reply_to="reply@example.net",
        attachment="statement.pdf",
        attachment_hash="a" * 64,
        body="A sufficiently long body to identify an identical email template. " * 3,
    ):
        original = b"Original immutable evidence: " + identity.encode()
        document = {
            "assessment": {"level": "inconclusive"},
            "eml": {
                "header": {
                    "subject": subject,
                    "from_": sender,
                    "message_id": f"<{identity}@example.org>",
                    "header": {"reply-to": [reply_to]},
                },
                "bodies": [{"content": body}],
                "attachments": [
                    {"filename": attachment, "hash": {"sha256": attachment_hash}}
                ],
            },
        }
        with db() as conn:
            conn.execute(
                """INSERT INTO analyses(id,case_id,filename,sha256,status,subject,result,source,created_by)
                VALUES (?,?,?,?,'completed',?,?,?,1)""",
                (
                    identity,
                    case_id,
                    identity + ".eml",
                    hashlib.sha256(original).hexdigest(),
                    subject,
                    json.dumps(document),
                    original,
                ),
            )
            index_analysis(conn, identity, document)
        return identity

    def seed_many(self, case_id, count=621):
        with db() as conn:
            conn.executemany(
                """INSERT INTO analyses(id,case_id,filename,sha256,status,subject,created_by,created_at)
                VALUES (?,?,?,?,?,?,1,?)""",
                [
                    (
                        f"bulk-{i:04d}",
                        case_id,
                        f"mail-{i:04d}.eml",
                        str(i).zfill(64),
                        "failed" if i % 2 else "completed",
                        f"Invoice {i:04d}",
                        f"2026-01-{i % 28 + 1:02d} 12:00:00",
                    )
                    for i in range(count)
                ],
            )

    def test_direct_case_and_global_pagination_over_500_without_gaps(self):
        old_case = self.case("Old but important")
        old = self.analysis(old_case, "old-analysis")
        recent_case = self.case("Bulk collection")
        self.seed_many(recent_case)
        with db() as conn:
            conn.execute(
                "UPDATE analyses SET created_at='2000-01-01 00:00:00' WHERE id=?",
                (old,),
            )
        self.assertEqual(self.get(f"/cases/{old_case}/analyses")["items"][0]["id"], old)
        self.assertEqual(self.get("/analyses", case_id=old_case, page=1)["total"], 1)
        found = []
        for page in range(1, 8):
            result = self.get("/analyses", page=page, page_size=100)
            self.assertEqual(result["total"], 622)
            self.assertEqual(result["pages"], 7)
            found.extend(item["id"] for item in result["items"])
        self.assertEqual(len(found), 622)
        self.assertEqual(len(set(found)), 622)
        self.assertIn(old, found)
        legacy = self.client.get(PREFIX + "/analyses")
        self.assertEqual(legacy.status_code, 422)
        self.assertIn("use pagination", legacy.json()["detail"])
        self.assertEqual(self.get("/analyses", page=99)["items"], [])

    def test_legacy_boundary_loads_at_most_501_rows_and_accepts_filtered_results(self):
        case_id = self.case()
        self.seed_many(case_id, 500)
        legacy = self.get("/analyses")
        self.assertEqual(len(legacy), 500)
        self.analysis(case_id, "overflow")
        legacy = self.client.get(PREFIX + "/analyses")
        self.assertEqual(legacy.status_code, 422)
        self.assertIn("page=1", legacy.json()["detail"])
        self.assertEqual(len(self.get("/analyses", q="overflow")), 1)
        self.assertEqual(self.get("/analyses", page=1)["total"], 501)
        self.analysis(case_id, "another-row")
        visited = []
        with db() as conn:
            # A real SQLite function counts row materialization. An unbounded
            # execute/fetch followed by slicing would visit all 502 rows.
            conn.create_function(
                "visited_row", 1, lambda value: visited.append(value) or value
            )
            with self.assertRaises(HTTPException) as error:
                _legacy_or_page(
                    conn,
                    "SELECT visited_row(id) AS id FROM analyses",
                    (),
                    None,
                    None,
                    None,
                )
            self.assertEqual(error.exception.status_code, 422)
        self.assertEqual(len(visited), 501)

    def test_analysis_filters_counts_page_size_and_limit_alias(self):
        case_id = self.case()
        self.seed_many(case_id)
        result = self.get(
            "/analyses",
            case_id=case_id,
            status="failed",
            q="Invoice 05",
            page=1,
            page_size=17,
        )
        self.assertEqual(result["total"], 50)
        self.assertEqual(len(result["items"]), 17)
        self.assertTrue(all(item["status"] == "failed" for item in result["items"]))
        self.assertEqual(self.get("/analyses", page=1, limit=7)["page_size"], 7)
        self.assertEqual(self.get("/analyses", page_size=11)["page"], 1)
        for params in (
            {"page": 0},
            {"page_size": 201},
            {"page_size": 0},
            {"limit": -1},
        ):
            self.assertEqual(
                self.client.get(PREFIX + "/analyses", params=params).status_code, 422
            )
        self.assertEqual(
            self.client.get(PREFIX + "/analyses?case_id=99999&page=1").status_code, 404
        )

    def test_cases_iocs_events_and_occurrences_are_exhaustively_paginated(self):
        case_id = self.case()
        self.seed_many(case_id)
        with db() as conn:
            conn.executemany(
                "INSERT INTO cases(title,created_by) VALUES (?,1)",
                [(f"Extra case {i}",) for i in range(520)],
            )
            conn.executemany(
                "INSERT INTO iocs(kind,value) VALUES ('domain',?)",
                [(f"signal-{i:04d}.example",) for i in range(1101)],
            )
            conn.executemany(
                "INSERT INTO analysis_iocs VALUES ('bulk-0000',?)",
                [(i,) for i in range(1, 1102)],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO analysis_iocs VALUES (?,1)",
                [(f"bulk-{i:04d}",) for i in range(621)],
            )
            conn.executemany(
                "INSERT INTO events(actor_id,case_id,action,detail) VALUES (1,?,'review.test',?)",
                [(case_id, f"Audit {i}") for i in range(620)],
            )
        for path in ("/cases", "/iocs", "/iocs/1/occurrences"):
            response = self.client.get(PREFIX + path)
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("use pagination", response.json()["detail"])
        self.assertEqual(self.get("/cases", page=6, page_size=100)["total"], 521)
        self.assertEqual(len(self.get("/cases", page=6, page_size=100)["items"]), 21)
        self.assertEqual(
            self.get("/iocs", page=12, page_size=100, kind="domain")["total"], 1101
        )
        self.assertEqual(len(self.get("/iocs", page=12, page_size=100)["items"]), 1)
        occurrences = self.get("/iocs/1/occurrences", page=7, page_size=100)
        self.assertEqual(occurrences["total"], 621)
        self.assertEqual(len(occurrences["items"]), 21)
        self.assertEqual(self.get("/iocs/1")["analysis_count"], 621)
        similarities = self.get(
            "/analyses/bulk-0000/similarities", page=7, page_size=100
        )
        self.assertEqual(similarities["total"], 620)
        self.assertEqual(len(similarities["items"]), 20)
        self.assertTrue(
            all(
                item["reasons"][0]["kind"] == "domain" for item in similarities["items"]
            )
        )
        self.assertEqual(
            self.get(
                f"/cases/{case_id}/events", page=7, page_size=100, action="review.test"
            )["total"],
            620,
        )
        self.assertEqual(
            len(
                self.get(
                    f"/cases/{case_id}/events",
                    page=7,
                    page_size=100,
                    action="review.test",
                )["items"]
            ),
            20,
        )

    def test_literal_search_does_not_treat_user_text_as_sql_wildcards(self):
        expected = self.case("Discount 100% _ special")
        self.case("Discount 1000 ordinary")
        self.assertEqual(self.get("/cases", q="% _", page=1)["total"], 1)
        self.assertEqual(
            self.get("/cases", q="% _", page=1)["items"][0]["id"], expected
        )
        self.assertEqual(self.get("/search", q="' OR 1=1 --")["total"], 0)

    def test_decision_history_reopen_and_evidence_are_separate(self):
        case_id = self.case()
        analysis_id = self.analysis(case_id)
        path = PREFIX + f"/analyses/{analysis_id}/decision"
        with db() as conn:
            before = dict(
                conn.execute(
                    "SELECT * FROM analyses WHERE id=?", (analysis_id,)
                ).fetchone()
            )
        self.assertIsNone(self.get(f"/analyses/{analysis_id}/decision")["current"])
        for verdict, confidence in [("phishing", 80), ("credential_phishing", 97)]:
            response = self.client.put(
                path,
                json={
                    "verdict": verdict,
                    "confidence": confidence,
                    "justification": "Verified landing page evidence locally",
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        state = self.get(f"/analyses/{analysis_id}/decision")
        self.assertEqual(state["current"]["verdict"], "credential_phishing")
        self.assertEqual(state["current"]["username"], "admin")
        self.assertEqual(len(state["history"]), 2)
        response = self.client.post(
            path + "/reopen", json={"justification": "New evidence requires review"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNone(response.json()["current"])
        self.assertEqual(response.json()["history"][0]["action"], "reopened")
        self.assertEqual(self.get(f"/cases/{case_id}")["status"], "investigating")
        self.assertEqual(
            self.client.post(
                path + "/reopen", json={"justification": "Again"}
            ).status_code,
            409,
        )
        history = self.get(
            f"/analyses/{analysis_id}/decision/history", page=2, page_size=2
        )
        self.assertEqual(history["total"], 3)
        self.assertEqual(history["items"][0]["verdict"], "phishing")
        with db() as conn:
            after = dict(
                conn.execute(
                    "SELECT * FROM analyses WHERE id=?", (analysis_id,)
                ).fetchone()
            )
        self.assertEqual(before, after)
        self.assertEqual(
            self.get(f"/cases/{case_id}/events", action="analysis.decided")["total"], 2
        )

    def test_decision_validation_and_viewer_cannot_mutate_workflows(self):
        analysis_id = self.analysis(self.case())
        path = PREFIX + f"/analyses/{analysis_id}/decision"
        for data in [
            {"verdict": "malicious", "confidence": 50, "justification": "Reason"},
            {"verdict": "phishing", "confidence": 101, "justification": "Reason"},
            {"verdict": "phishing", "confidence": 50, "justification": "  "},
        ]:
            self.assertEqual(self.client.put(path, json=data).status_code, 422)
        self.client.post(
            PREFIX + "/users",
            json={"username": "viewer", "password": PASSWORD, "role": "viewer"},
        )
        with TestClient(self.app, headers=HEADERS) as viewer:
            viewer.post(
                PREFIX + "/auth/login",
                json={"username": "viewer", "password": PASSWORD},
            )
            self.assertEqual(viewer.get(path).status_code, 200)
            self.assertEqual(
                viewer.put(
                    path,
                    json={
                        "verdict": "phishing",
                        "confidence": 80,
                        "justification": "Reason",
                    },
                ).status_code,
                403,
            )
            self.assertEqual(
                viewer.post(PREFIX + "/campaigns", json={"name": "Denied"}).status_code,
                403,
            )
        with TestClient(self.app) as anonymous:
            for path in (
                "/search",
                "/events",
                "/campaigns",
                f"/analyses/{analysis_id}/similarities",
            ):
                self.assertEqual(anonymous.get(PREFIX + path).status_code, 401)

    def test_campaign_crud_links_shared_iocs_and_timeline_preserve_evidence(self):
        first, second = self.case("Campaign one"), self.case("Campaign two")
        self.analysis(first, "first")
        self.analysis(second, "second")
        with db() as conn:
            conn.execute(
                "INSERT INTO iocs(kind,value) VALUES ('domain','shared.example')"
            )
            conn.execute(
                "INSERT INTO iocs(kind,value) VALUES ('domain','unique.example')"
            )
            conn.executemany(
                "INSERT INTO analysis_iocs VALUES (?,?)",
                [("first", 1), ("second", 1), ("first", 2)],
            )
        response = self.client.post(
            PREFIX + "/campaigns",
            json={
                "name": "Autumn invoices",
                "description": "Related invoices",
                "tags": [" Invoice ", "INVOICE", "fraud"],
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        campaign_id = response.json()["id"]
        root = f"/campaigns/{campaign_id}"
        self.assertEqual(response.json()["tags"], ["fraud", "invoice"])
        for case_id in (first, second):
            response = self.client.put(PREFIX + root + f"/cases/{case_id}")
            self.assertEqual(response.status_code, 200, response.text)
        self.client.put(PREFIX + root + f"/cases/{first}")  # Idempotent link.
        self.assertEqual(self.get(root)["case_count"], 2)
        self.assertEqual(self.get(root)["analysis_count"], 2)
        self.assertEqual(self.get(root + "/cases", page_size=1)["pages"], 2)
        self.assertEqual(self.get(root + "/iocs")["total"], 1)
        self.assertEqual(
            self.get(root + "/iocs")["items"][0]["value"], "shared.example"
        )
        self.assertEqual(
            self.get(root + "/events", action="campaign.case_attached")["total"], 2
        )
        self.assertEqual(self.get("/campaigns", tag="invoice")["total"], 1)
        self.assertEqual(self.get("/iocs/1")["campaigns"][0]["id"], campaign_id)
        self.client.put(
            PREFIX + root,
            json={
                "name": "Closed autumn invoices",
                "status": "closed",
                "tags": ["fraud"],
                "verdict": "phishing",
            },
        )
        self.assertEqual(self.get(root)["verdict"], "phishing")
        self.assertEqual(
            self.client.delete(PREFIX + root + f"/cases/{second}").status_code, 200
        )
        self.assertEqual(self.get(root + "/iocs")["total"], 0)
        self.assertEqual(
            self.get(root + "/events", action="campaign.case_detached")["total"], 1
        )
        self.assertEqual(self.client.delete(PREFIX + root).status_code, 200)
        self.assertEqual(self.client.get(PREFIX + root).status_code, 404)
        self.assertEqual(self.get("/campaigns")["total"], 0)
        self.assertEqual(self.get("/search", q="autumn", type="campaign")["total"], 0)
        self.assertEqual(self.get("/analyses", page=1)["total"], 2)
        self.assertEqual(self.get("/events", action="campaign.deleted")["total"], 1)

    def test_similarity_is_explained_and_does_not_merge_cases(self):
        first, second, unrelated = (
            self.case("First"),
            self.case("Second"),
            self.case("Other"),
        )
        self.analysis(first, "first", subject="Re: Fwd: Invoice    review")
        self.analysis(second, "second", subject="invoice review")
        self.analysis(
            unrelated,
            "third",
            subject="Different email",
            sender="different@other.example",
            reply_to="other@another.example",
            attachment="other.bin",
            attachment_hash="b" * 64,
            body="An entirely different message, with no shared body content. " * 3,
        )
        with db() as conn:
            conn.execute(
                "INSERT INTO iocs(kind,value) VALUES ('url','https://landing.example/login')"
            )
            conn.executemany(
                "INSERT INTO analysis_iocs VALUES (?,1)", [("first",), ("second",)]
            )
        results = self.get("/analyses/first/similarities")
        self.assertEqual(results["total"], 1)
        self.assertEqual(results["items"][0]["id"], "second")
        reasons = {reason["kind"]: reason for reason in results["items"][0]["reasons"]}
        self.assertEqual(reasons["subject"]["value"], "invoice review")
        self.assertEqual(reasons["reply_to"]["value"], "reply@example.net")
        self.assertEqual(reasons["url"]["label"], "Same URL")
        self.assertEqual(self.get("/cases", page=1)["total"], 3)

    def test_global_search_metadata_iocs_campaign_tags_and_pagination(self):
        case_id = self.case("Invoice investigation")
        self.analysis(
            case_id,
            "indexed",
            sender="Searchable <specific@sender.example>",
            reply_to="specific@reply.example",
            attachment="specific.xlsx",
        )
        self.seed_many(case_id)
        self.client.post(
            PREFIX + "/campaigns", json={"name": "Winter", "tags": ["specific-tag"]}
        )
        with db() as conn:
            conn.execute("INSERT INTO iocs(kind,value) VALUES ('ip','192.0.2.99')")
            conn.execute("INSERT INTO analysis_iocs VALUES ('indexed',1)")
        for query in (
            "specific@sender",
            "specific@reply",
            "specific.xlsx",
            "192.0.2.99",
        ):
            result = self.get("/search", q=query, type="analysis")
            self.assertEqual(result["total"], 1, query)
            self.assertEqual(result["items"][0]["url"], "/analyses/indexed")
        self.assertEqual(
            self.get("/search", q="specific-tag", type="campaign")["total"], 1
        )
        result = self.get(
            "/search", q="Invoice", type="analysis", page=7, page_size=100
        )
        self.assertEqual(result["total"], 622)
        self.assertEqual(len(result["items"]), 22)

    def test_migration_backfills_existing_analysis_and_is_idempotent(self):
        case_id = self.case()
        self.analysis(case_id, "legacy", reply_to="legacy@reply.example")
        with db() as conn:
            conn.execute("DELETE FROM analysis_signals")
            conn.execute("DELETE FROM analysis_indexed")
        initialize()
        initialize()
        self.assertEqual(
            self.get("/search", q="legacy@reply", type="analysis")["total"], 1
        )
        with db() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM analysis_indexed").fetchone()[0], 1
            )


if __name__ == "__main__":
    unittest.main()

import hashlib
import io
import json
import os
import unittest
import zipfile
from email.message import EmailMessage
from unittest.mock import patch

import test_jobs as helpers

from backend.factories.eml import EmlFactory
from backend.investigation import jobs
from backend.investigation.enrichment import EnrichmentResult, EnrichmentStatus, target
from backend.investigation.enrichment_api import analysis_record, reserve, save_result
from backend.investigation.evidence import storage
from backend.investigation.failures import AnalysisError
from backend.investigation.report_context import local_content
from backend.investigation.store import db

BASE = "/api/workspace"
URL = "https://destination.example/login"


class ReportContextTests(unittest.TestCase):
    setUp = helpers.JobTests.setUp
    tearDown = helpers.JobTests.tearDown
    upload = helpers.JobTests.upload

    def mail(self):
        mail = EmailMessage()
        mail["From"] = '"Finance trusted.example" <sender@actual.example>'
        mail["To"] = "analyst@example.test"
        mail["Reply-To"] = "support@reply.example"
        mail["Return-Path"] = "bounce@return.example"
        mail["Subject"] = "Context test"
        mail["Received"] = (
            "from relay.example [192.0.2.2] by final.example; Wed, 23 Sep 2026 08:02:00 +0000"
        )
        mail["Received"] = (
            "from source.example [192.0.2.1] by relay.example; Wed, 23 Sep 2026 08:01:00 +0000"
        )
        mail["Authentication-Results"] = (
            "untrusted.example; spf=pass smtp.mailfrom=actual.example; dkim=fail; dmarc=fail"
        )
        mail.set_content(
            f'<p>Hello analyst</p><script>forbidden()</script><a href="{URL}">https://trusted.example/login</a>',
            subtype="html",
        )
        mail.add_attachment(
            b"synthetic attachment",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.bin",
        )
        return mail.as_bytes()

    def completed(self, raw):
        response = self.client.post(
            BASE + "/analyses", files={"file": ("context.eml", raw)}
        )
        self.assertEqual(response.status_code, 202, response.text)
        item = response.json()
        document = {
            "eml": EmlFactory().call(raw).model_dump(mode="json"),
            "verdicts": [],
        }
        digest = document["eml"]["attachments"][0]["hash"]["sha256"]
        document["verdicts"] = [
            {
                "name": "oleid",
                "malicious": True,
                "details": [
                    {
                        "key": "macro",
                        "description": digest + " has a synthetic static finding",
                    }
                ],
            }
        ]
        self.assertTrue(jobs.run_once(lambda _: document))
        return item

    def test_real_parser_retains_display_name_chronology_html_text_and_declarations(
        self,
    ):
        document = {"eml": EmlFactory().call(self.mail()).model_dump(mode="json")}
        context = local_content(document)
        self.assertEqual(context["identity"]["display_name"], "Finance trusted.example")
        self.assertEqual(context["identity"]["address"], "sender@actual.example")
        self.assertIn("Finance trusted.example", context["identity"]["raw_from"])
        self.assertEqual(
            {item["code"] for item in context["identity"]["anomalies"]},
            {
                "display_name_domain_differs",
                "reply_to_domain_differs",
                "return_path_domain_differs",
            },
        )
        self.assertEqual(context["routing"]["order"], "oldest_first")
        hops = context["routing"]["hops"]
        self.assertIn("source.example", hops[0]["from_"])
        self.assertIn("final.example", hops[1]["by"])
        self.assertEqual(hops[1]["delay"], 60)
        self.assertIn("Hello analyst", context["bodies"][0]["text"])
        self.assertNotIn("forbidden", context["bodies"][0]["text"])
        self.assertIn("<script>", document["eml"]["bodies"][0]["content"])
        url = next(item for item in context["urls"] if item["value"] == URL)
        self.assertEqual(url["display_texts"], ["https://trusted.example/login"])
        self.assertTrue(url["destination_mismatch"])
        self.assertEqual(
            {item["mechanism"] for item in context["authentication"]["declared"]},
            {"spf", "dkim", "dmarc"},
        )
        self.assertTrue(
            all(
                item["confidence"] == "unverified"
                for item in context["authentication"]["declared"]
            )
        )

    def test_context_relates_actual_iocs_campaigns_and_persisted_enrichments_in_exports(
        self,
    ):
        raw = self.mail()
        first, second = self.completed(raw), self.completed(raw)
        campaign = self.client.post(
            BASE + "/campaigns", json={"name": "Context campaign"}
        ).json()
        for item in (first, second):
            self.assertEqual(
                self.client.put(
                    BASE + f"/campaigns/{campaign['id']}/cases/{item['case_id']}"
                ).status_code,
                200,
            )
        with db() as conn:
            analysis = analysis_record(conn, first["id"])
            before = analysis["result"]
            user = dict(
                conn.execute("SELECT * FROM users WHERE username='admin'").fetchone()
            )
            selected = target("url", URL)
            pending, _ = reserve(conn, analysis, user, "urlscan", selected, "lookup")
        save_result(
            pending["id"],
            EnrichmentResult(
                "urlscan",
                selected,
                EnrichmentStatus.AVAILABLE,
                malicious=1,
                summary="Synthetic provider observation",
                metadata={"domain": "destination.example", "redirect_chain": [URL]},
            ),
        )
        report = self.client.get(BASE + "/analyses/" + first["id"]).json()
        context = report["result"]["investigation"]
        url = next(item for item in context["urls"] if item["value"] == URL)
        self.assertEqual((url["analysis_count"], url["case_count"]), (2, 2))
        self.assertEqual(url["campaigns"][0]["id"], campaign["id"])
        self.assertEqual(
            url["enrichments"][0]["summary"], "Synthetic provider observation"
        )
        attachment = context["attachments"][0]
        self.assertEqual(attachment["analysis_count"], 2)
        self.assertTrue(attachment["static_findings"])
        base = BASE + "/analyses/" + first["id"]
        exported = self.client.get(base + "/export.json").json()
        self.assertEqual(exported["enrichments"][0]["id"], pending["id"])
        html = self.client.get(base + "/export.html").text
        self.assertIn("Synthetic provider observation", html)
        self.assertIn("Hello analyst", html)
        self.assertNotIn("<script>", html)
        package = zipfile.ZipFile(
            io.BytesIO(self.client.get(base + "/evidence.zip?attachments=0").content)
        )
        self.assertEqual(
            json.loads(package.read("report.json"))["enrichments"][0]["id"],
            pending["id"],
        )
        self.assertEqual(package.read("original.eml"), raw)
        with db() as conn:
            self.assertEqual(analysis_record(conn, first["id"])["result"], before)
        dashboard = self.client.get(BASE + "/dashboard").json()
        self.assertEqual(dashboard["pending_verdicts"], 2)
        self.assertEqual(dashboard["active_campaigns"], 1)
        self.assertEqual(dashboard["frequent_iocs"][0]["analysis_count"], 2)
        self.assertEqual(len(dashboard["recent_analyses"]), 2)
        self.client.put(
            base + "/decision",
            json={
                "verdict": "phishing",
                "confidence": 80,
                "justification": "Synthetic analyst review",
            },
        )
        self.assertEqual(
            self.client.get(BASE + "/dashboard").json()["pending_verdicts"], 1
        )
        self.client.post(
            base + "/decision/reopen", json={"justification": "Review again"}
        )
        self.assertEqual(
            self.client.get(BASE + "/dashboard").json()["pending_verdicts"], 2
        )

    def test_failures_have_finite_safe_codes_and_preserve_original(self):
        item = self.upload()

        def reject(_):
            raise ValueError("confidential-mail-body-and-token")

        jobs.run_once(reject)
        report = self.client.get(BASE + "/analyses/" + item["id"]).json()
        self.assertEqual(report["error_code"], "parser_rejected")
        self.assertNotIn("confidential", report["error"])
        with db() as conn:
            row = analysis_record(conn, item["id"])
            original = storage().read(row["source_ref"], row["sha256"])
            self.assertEqual(hashlib.sha256(original).hexdigest(), item["sha256"])
            conn.execute("UPDATE jobs SET available_at=0")
            path = storage().path(row["source_ref"])
            path.chmod(0o600)
            path.write_bytes(b"synthetic tamper")
        jobs.run_once(reject)
        self.assertEqual(
            self.client.get(BASE + "/analyses/" + item["id"]).json()["error_code"],
            "evidence_integrity",
        )

    def test_real_child_timeout_uses_bounded_failure_code(self):
        with (
            patch.dict(os.environ, {"JOB_TIMEOUT_SECONDS": "0"}),
            self.assertRaises(AnalysisError) as error,
        ):
            jobs.analyze_isolated(helpers.EMAIL)
        self.assertEqual(error.exception.code, "parser_timeout")

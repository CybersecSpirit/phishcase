"""The real parser is local regardless of global or tenant enrichment permissions."""

import asyncio
import os
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from backend.investigation.analyzer_task import analyze
from backend.investigation.connectivity import mode, policy_factory

EMAIL = b"""From: sender@example.org\r
To: analyst@example.net\r
Subject: Local parser boundary\r
DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=default; b=invalid\r
MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=boundary\r
\r
--boundary\r
Content-Type: text/plain\r
\r
Inspect https://example.org/review without fetching it.\r
--boundary\r
Content-Type: application/octet-stream\r
Content-Disposition: attachment; filename="sample.bin"\r
Content-Transfer-Encoding: base64\r
\r
U3ludGhldGljIGxvY2FsIGV2aWRlbmNl\r
--boundary--\r
"""


class AnalyzerPolicyTests(unittest.TestCase):
    def test_enrichment_flags_never_create_provider_clients_in_parser(self):
        for connectivity in ("offline", "restricted", "connected"):
            for enabled in (False, True):
                with (
                    self.subTest(mode=connectivity, enabled=enabled),
                    ExitStack() as stack,
                ):
                    stack.enter_context(
                        patch.dict(
                            os.environ,
                            {
                                "CONNECTIVITY_MODE": connectivity,
                                "VIRUSTOTAL_LOOKUP_ENABLED": str(enabled).lower(),
                                "URLSCAN_LOOKUP_ENABLED": str(enabled).lower(),
                            },
                        )
                    )
                    # Nonempty credentials make the former automatic path reachable.
                    for name in (
                        "VIRUSTOTAL_API_KEY",
                        "URLSCAN_API_KEY",
                        "EMAIL_REP_API_KEY",
                    ):
                        stack.enter_context(
                            patch("backend.settings." + name, "synthetic-test-key")
                        )
                    stack.enter_context(
                        patch(
                            "backend.settings.SPAMASSASSIN_HOST", "remote.example.org"
                        )
                    )
                    constructors = [
                        stack.enter_context(
                            patch(
                                "backend.clients." + name,
                                side_effect=AssertionError("Unexpected network client"),
                            )
                        )
                        for name in (
                            "VirusTotal",
                            "UrlScan",
                            "EmailRep",
                            "SpamAssassin",
                        )
                    ]
                    dns = stack.enter_context(
                        patch(
                            "backend.factories.response.get_dkim_verdict",
                            side_effect=AssertionError("Unexpected DNS lookup"),
                        )
                    )
                    existing_policy = {
                        "mode": connectivity,
                        "lookups": {"virustotal": enabled, "urlscan": enabled},
                        "submissions": {},
                    }
                    previous = policy_factory.set(lambda policy=existing_policy: policy)
                    try:
                        document = asyncio.run(analyze(EMAIL))
                        self.assertEqual(mode(), connectivity)
                    finally:
                        policy_factory.reset(previous)
                    self.assertEqual(
                        document["eml"]["header"]["subject"], "Local parser boundary"
                    )
                    self.assertEqual(len(document["eml"]["attachments"]), 1)
                    self.assertIn("assessment", document)
                    for constructor in constructors:
                        constructor.assert_not_called()
                    dns.assert_not_called()

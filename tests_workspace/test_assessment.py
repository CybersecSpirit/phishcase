import unittest

from backend.investigation.assessment import summarize


class AssessmentTests(unittest.TestCase):
    def test_dkim_failure_is_not_a_malware_detection(self):
        document = {
            "verdicts": [
                {
                    "name": "DKIM",
                    "malicious": True,
                    "details": [{"description": "Invalid signature"}],
                }
            ]
        }
        self.assertEqual(summarize(document)["level"], "suspicious")

    def test_reputation_detection_is_explained(self):
        document = {
            "verdicts": [
                {
                    "name": "VirusTotal",
                    "malicious": True,
                    "details": [{"description": "3 engines detected the attachment"}],
                }
            ]
        }
        assessment = summarize(document)
        self.assertEqual(assessment["level"], "malicious")
        self.assertIn("VirusTotal", assessment["reasons"][0])

    def test_missing_scanner_never_shows_no_signal(self):
        self.assertEqual(
            summarize({"verdicts": [{"name": "oleid", "malicious": False}]})["level"],
            "inconclusive",
        )

    def test_available_scans_without_flags_are_not_claimed_safe(self):
        assessment = summarize(
            {"verdicts": [{"name": "SpamAssassin", "malicious": False}]}
        )
        self.assertEqual(assessment["level"], "no_signal")
        self.assertIn("ne garantit pas", assessment["explanation"])

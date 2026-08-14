import json
import unittest
from pathlib import Path
from unittest import mock

import validator
from authorization_evidence_report import audit_authorization_evidence

FIXTURE = Path(__file__).parent / "fixtures" / "authorization_evidence_cases.json"


class AuthorizationEvidenceIntegrationTests(unittest.TestCase):
    def test_disabled_audit_is_explicitly_non_blocking(self):
        result = audit_authorization_evidence("", now_utc="2026-08-14T12:00:00Z")
        self.assertFalse(result["enabled"])
        self.assertFalse(result["blocking"])
        self.assertIsNone(result["passed"])
        self.assertEqual("not_configured", result["state"])

    def test_fixture_bundle_is_reported_under_stable_states(self):
        result = audit_authorization_evidence(str(FIXTURE), now_utc="2026-08-14T12:00:00Z")
        self.assertTrue(result["enabled"])
        self.assertFalse(result["blocking"])
        self.assertEqual(6, len(result["case_results"]))
        self.assertEqual(2, result["state_counts"]["structurally_invalid"])
        self.assertEqual(1, result["state_counts"]["valid_and_authorized"])
        self.assertEqual(1, result["state_counts"]["expired"])
        self.assertEqual(1, result["state_counts"]["revoked"])
        self.assertEqual(1, result["state_counts"]["structurally_valid_zero_authority"])

    def test_audit_error_remains_non_blocking(self):
        result = audit_authorization_evidence("missing-evidence.json", now_utc="2026-08-14T12:00:00Z")
        self.assertFalse(result["blocking"])
        self.assertFalse(result["passed"])
        self.assertEqual("structurally_invalid", result["state"])

    def test_report_only_result_cannot_change_endpoint_passed(self):
        passing_core = {
            "passed": True,
            "payment_required_passed": True,
            "probed_at_utc": "2026-08-14T12:00:00Z",
        }
        with mock.patch.object(validator, "check_reachability", return_value={"passed": True}), \
             mock.patch.object(validator, "_check_manifest_cached", return_value={"passed": True}), \
             mock.patch.object(validator, "check_402_body", return_value=passing_core), \
             mock.patch.object(validator, "check_p95", return_value={"passed": True}):
            result = validator.validate_endpoint(
                "https://example.test/resource",
                1000,
                authorization_evidence_path=str(FIXTURE),
            )
        self.assertTrue(result["passed"])
        self.assertFalse(result["checks"]["authorization_evidence"]["blocking"])
        self.assertEqual(6, len(result["checks"]["authorization_evidence"]["case_results"]))


if __name__ == "__main__":
    unittest.main()

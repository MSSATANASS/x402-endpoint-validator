import copy
import json
import unittest
from pathlib import Path

from authorization_evidence import classify_authorization_evidence, sha256_hex


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "authorization_evidence_cases.json"


class AuthorizationEvidenceFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_fixture_cases_classify_to_declared_states(self):
        now_utc = self.fixture["now_utc"]
        for case in self.fixture["cases"]:
            with self.subTest(case=case["name"]):
                result = classify_authorization_evidence(
                    case["evidence"],
                    case["consumed_text"].encode("utf-8"),
                    case["policy"],
                    now_utc,
                )
                self.assertEqual(case["expected_state"], result["state"])
                self.assertTrue(result["reasons"])

    def test_authority_is_a_consumer_policy_decision(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["name"] == "valid_but_zero_authority"
        )
        evidence = copy.deepcopy(case["evidence"])
        consumed_bytes = case["consumed_text"].encode("utf-8")

        untrusted = classify_authorization_evidence(
            evidence, consumed_bytes, case["policy"], self.fixture["now_utc"]
        )
        trusted_policy = copy.deepcopy(case["policy"])
        trusted_policy["authorized_keys"].append(evidence["verifier_key_ref"])
        trusted = classify_authorization_evidence(
            evidence, consumed_bytes, trusted_policy, self.fixture["now_utc"]
        )

        self.assertEqual("structurally_valid_zero_authority", untrusted["state"])
        self.assertEqual("valid_and_authorized", trusted["state"])
        self.assertEqual(evidence["authorization_sha256"], sha256_hex(consumed_bytes))

    def test_hash_binds_exact_consumed_bytes_not_reconstructed_json(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["name"] == "valid_and_authorized"
        )
        altered_bytes = b'{"decision":"D-1001", "approval":"fulfillment-approved"}'
        self.assertNotEqual(
            sha256_hex(case["consumed_text"].encode("utf-8")),
            sha256_hex(altered_bytes),
        )

        result = classify_authorization_evidence(
            case["evidence"], altered_bytes, case["policy"], self.fixture["now_utc"]
        )
        self.assertEqual("structurally_invalid", result["state"])
        self.assertIn("exact consumed bytes", result["reasons"][0])

    def test_missing_field_is_structurally_invalid(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["name"] == "valid_and_authorized"
        )
        evidence = copy.deepcopy(case["evidence"])
        del evidence["authorization_uri"]

        result = classify_authorization_evidence(
            evidence,
            case["consumed_text"].encode("utf-8"),
            case["policy"],
            self.fixture["now_utc"],
        )
        self.assertEqual("structurally_invalid", result["state"])
        self.assertIn("authorization_uri", result["reasons"][0])


if __name__ == "__main__":
    unittest.main()

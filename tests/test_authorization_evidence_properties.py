"""Deterministic property coverage for Authorization Lifecycle Audit phase 2.

The suite uses a fixed standard-library PRNG rather than a new test dependency.
It complements the named fixtures with reproducible mutation coverage while the
feature remains fully isolated from validator.py and CI exit behavior.
"""

from __future__ import annotations

import copy
import json
import random
import unittest
from pathlib import Path

from authorization_evidence import classify_authorization_evidence


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "authorization_evidence_cases.json"


class AuthorizationEvidencePropertyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.now_utc = fixture["now_utc"]
        cls.valid_case = next(
            item for item in fixture["cases"] if item["name"] == "valid_and_authorized"
        )

    def _valid_inputs(self):
        return (
            copy.deepcopy(self.valid_case["evidence"]),
            self.valid_case["consumed_text"].encode("utf-8"),
            copy.deepcopy(self.valid_case["policy"]),
        )

    def test_any_single_byte_mutation_breaks_authorization_integrity(self):
        evidence, consumed_bytes, policy = self._valid_inputs()
        prng = random.Random(4022026)

        for sample in range(64):
            with self.subTest(sample=sample):
                mutated = bytearray(consumed_bytes)
                index = prng.randrange(len(mutated))
                xor_mask = prng.randrange(1, 256)
                mutated[index] ^= xor_mask

                result = classify_authorization_evidence(
                    evidence, bytes(mutated), policy, self.now_utc
                )
                self.assertEqual("structurally_invalid", result["state"])
                self.assertIn("exact consumed bytes", result["reasons"][0])

    def test_revocation_is_terminal_even_when_policy_and_bytes_are_valid(self):
        evidence, consumed_bytes, policy = self._valid_inputs()
        evidence["status"] = "revoked"

        for variant in (policy, {}, {"accepted_schemes": [], "authorized_keys": []}):
            with self.subTest(policy=variant):
                result = classify_authorization_evidence(
                    evidence, consumed_bytes, variant, self.now_utc
                )
                self.assertEqual("revoked", result["state"])

    def test_expiration_is_terminal_even_when_policy_and_bytes_are_valid(self):
        evidence, consumed_bytes, policy = self._valid_inputs()
        evidence["valid_until"] = self.now_utc

        result = classify_authorization_evidence(
            evidence, consumed_bytes, policy, self.now_utc
        )
        self.assertEqual("expired", result["state"])

    def test_absent_or_partial_policy_never_grants_authority(self):
        evidence, consumed_bytes, policy = self._valid_inputs()
        policies = (
            {},
            {"accepted_schemes": policy["accepted_schemes"]},
            {"authorized_keys": policy["authorized_keys"]},
            {"accepted_schemes": [], "authorized_keys": []},
        )

        for variant in policies:
            with self.subTest(policy=variant):
                result = classify_authorization_evidence(
                    evidence, consumed_bytes, variant, self.now_utc
                )
                self.assertEqual("structurally_valid_zero_authority", result["state"])


if __name__ == "__main__":
    unittest.main()

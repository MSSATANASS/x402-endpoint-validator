"""Authorization Lifecycle Audit — phase-1 evidence classifier.

This module is deliberately not wired into ``validator.py`` yet.  It supplies a
small, deterministic contract for fixtures and local policy evaluation before
any report, CI, payment, or fulfillment behavior is changed.

The classifier keeps three questions separate:

* integrity: do the exact consumed bytes match ``authorization_sha256``?
* structural validity: does the evidence contain the required shape and did an
  upstream verifier report a valid signature?
* authority: does the consumer's local policy authorize ``verifier_key_ref``?

A signature result is passed in as a verifier outcome for this first phase; the
module neither downloads authorization URIs nor attempts cryptographic
verification.  Network retrieval and scheme-specific signature verification
are future adapters, not implicit behavior in a CI probe.
"""

from __future__ import annotations

import hashlib
from typing import Any

REQUIRED_EVIDENCE_FIELDS = (
    "decision_ref",
    "authorization_uri",
    "authorization_sha256",
    "scheme",
    "verifier_key_ref",
    "transport_hint",
    "signature_valid",
    "status",
    "valid_until",
)

VALID_TRANSPORT_HINTS = frozenset({"raw_url", "relay_event", "bundle", "other"})
VALID_STATUSES = frozenset({"active", "revoked"})
VALID_STATES = frozenset(
    {
        "structurally_invalid",
        "structurally_valid_zero_authority",
        "valid_and_authorized",
        "expired",
        "revoked",
    }
)


def sha256_hex(consumed_bytes: bytes) -> str:
    """Return the lowercase SHA-256 digest for the exact bytes consumed."""
    return hashlib.sha256(consumed_bytes).hexdigest()


def _result(state: str, reasons: list[str], **extra: Any) -> dict[str, Any]:
    """Build a stable report object for deterministic fixtures and future CI."""
    if state not in VALID_STATES:
        raise ValueError(f"unsupported authorization evidence state: {state}")
    return {"state": state, "reasons": reasons, **extra}


def classify_authorization_evidence(
    evidence: dict[str, Any],
    consumed_bytes: bytes,
    policy: dict[str, Any],
    now_utc: str,
) -> dict[str, Any]:
    """Classify evidence using exact bytes and the consumer's local policy.

    Parameters are intentionally explicit.  ``consumed_bytes`` is the byte
    sequence that a future adapter retrieved and verified; no JSON
    re-serialization is performed.  ``policy`` may contain ``authorized_keys``
    and ``accepted_schemes`` lists.  Missing policy lists mean no keys or
    schemes are trusted.

    ``valid_until`` and ``now_utc`` are compared as UTC ISO-8601 strings in
    canonical ``YYYY-MM-DDTHH:MM:SSZ`` form.  Phase 1 validates that shape by
    requiring the trailing ``Z`` and uses lexical comparison, which is safe for
    the prescribed fixed-width format.
    """
    if not isinstance(evidence, dict):
        return _result("structurally_invalid", ["evidence must be an object"])
    if not isinstance(policy, dict):
        return _result("structurally_invalid", ["policy must be an object"])
    if not isinstance(consumed_bytes, bytes):
        return _result("structurally_invalid", ["consumed_bytes must be bytes"])
    if not isinstance(now_utc, str) or not now_utc.endswith("Z"):
        return _result("structurally_invalid", ["now_utc must be a UTC ISO-8601 string"])

    missing = [field for field in REQUIRED_EVIDENCE_FIELDS if not evidence.get(field)]
    if missing:
        return _result("structurally_invalid", ["missing required fields: " + ", ".join(missing)])

    if evidence["transport_hint"] not in VALID_TRANSPORT_HINTS:
        return _result("structurally_invalid", ["unsupported transport_hint"])
    if evidence["status"] not in VALID_STATUSES:
        return _result("structurally_invalid", ["unsupported status"])
    if not isinstance(evidence["signature_valid"], bool) or not evidence["signature_valid"]:
        return _result("structurally_invalid", ["signature verification did not succeed"])
    if not isinstance(evidence["authorization_sha256"], str) or len(evidence["authorization_sha256"]) != 64:
        return _result("structurally_invalid", ["authorization_sha256 must be a 64-character hex digest"])
    if evidence["authorization_sha256"].lower() != sha256_hex(consumed_bytes):
        return _result(
            "structurally_invalid",
            ["authorization_sha256 does not match exact consumed bytes"],
            expected_sha256=evidence["authorization_sha256"].lower(),
            observed_sha256=sha256_hex(consumed_bytes),
        )

    valid_until = evidence["valid_until"]
    if not isinstance(valid_until, str) or not valid_until.endswith("Z"):
        return _result("structurally_invalid", ["valid_until must be a UTC ISO-8601 string"])

    # Revocation is represented as a safe terminal state only after the evidence
    # itself has passed integrity and structural checks.
    if evidence["status"] == "revoked":
        return _result("revoked", ["authorization evidence records a terminal revocation"])
    if valid_until <= now_utc:
        return _result("expired", ["authorization evidence is outside its validity window"])

    accepted_schemes = policy.get("accepted_schemes", [])
    authorized_keys = policy.get("authorized_keys", [])
    if not isinstance(accepted_schemes, list) or evidence["scheme"] not in accepted_schemes:
        return _result(
            "structurally_valid_zero_authority",
            ["consumer policy does not accept this authorization scheme"],
            verifier_key_ref=evidence["verifier_key_ref"],
        )
    if not isinstance(authorized_keys, list) or evidence["verifier_key_ref"] not in authorized_keys:
        return _result(
            "structurally_valid_zero_authority",
            ["consumer policy does not authorize verifier_key_ref"],
            verifier_key_ref=evidence["verifier_key_ref"],
        )

    return _result(
        "valid_and_authorized",
        ["integrity, structure, validity window, scheme, and local authority all passed"],
        verifier_key_ref=evidence["verifier_key_ref"],
    )

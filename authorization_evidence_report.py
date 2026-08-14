"""Report-only integration for Authorization Lifecycle Audit.

This adapter deliberately does not participate in the endpoint pass/fail
calculation. It loads a local JSON evidence bundle, classifies each case with
the pure phase-1 classifier, and exposes the findings under
``checks.authorization_evidence`` for observability.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from authorization_evidence import classify_authorization_evidence

NOT_CONFIGURED_STATE = "not_configured"


def _not_configured() -> dict[str, Any]:
    return {
        "enabled": False,
        "blocking": False,
        "passed": None,
        "state": NOT_CONFIGURED_STATE,
        "states": [],
        "state_counts": {},
        "source": None,
        "findings": [],
        "note": "authorization evidence audit is disabled; core validation is unchanged",
    }


def _error(source: str, message: str) -> dict[str, Any]:
    return {
        "enabled": True,
        "blocking": False,
        "passed": False,
        "state": "structurally_invalid",
        "states": ["structurally_invalid"],
        "state_counts": {"structurally_invalid": 1},
        "source": source,
        "findings": [message],
        "note": "report-only audit error; core validation is unchanged",
    }


def _load_bundle(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    if not isinstance(bundle, dict):
        raise ValueError("authorization evidence bundle must be a JSON object")
    if not isinstance(bundle.get("cases"), list):
        raise ValueError("authorization evidence bundle requires a cases array")
    return bundle


def audit_authorization_evidence(path: str, *, now_utc: str) -> dict[str, Any]:
    """Classify a local evidence bundle without affecting endpoint verdicts.

    Bundle cases contain ``consumed_text`` (the exact UTF-8 fixture bytes),
    ``evidence`` and ``policy``. The adapter never fetches ``authorization_uri``
    and never changes the validator's existing ``passed`` or exit-code logic.
    """
    raw_path = (path or "").strip()
    if not raw_path:
        return _not_configured()

    source = str(Path(raw_path))
    try:
        bundle = _load_bundle(Path(raw_path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _error(source, f"could not load authorization evidence bundle: {exc}")

    results: list[dict[str, Any]] = []
    for index, case in enumerate(bundle["cases"]):
        if not isinstance(case, dict):
            results.append({
                "case": str(index),
                "state": "structurally_invalid",
                "reasons": ["case must be an object"],
            })
            continue
        try:
            consumed_text = case.get("consumed_text")
            consumed_bytes = consumed_text.encode("utf-8") if isinstance(consumed_text, str) else consumed_text
            classified = classify_authorization_evidence(
                case.get("evidence"),
                consumed_bytes,
                case.get("policy"),
                bundle.get("now_utc", now_utc),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            classified = {
                "state": "structurally_invalid",
                "reasons": [f"case classification error: {exc}"],
            }
        result = {
            "case": str(case.get("name", index)),
            "state": classified.get("state", "structurally_invalid"),
            "reasons": classified.get("reasons", []),
        }
        for key in ("verifier_key_ref", "expected_sha256", "observed_sha256"):
            if key in classified:
                result[key] = classified[key]
        results.append(result)

    state_counts = dict(sorted(Counter(item["state"] for item in results).items()))
    states = [item["state"] for item in results]
    all_authorized = bool(results) and all(state == "valid_and_authorized" for state in states)
    return {
        "enabled": True,
        "blocking": False,
        "passed": all_authorized,
        "state": states[0] if len(set(states)) == 1 and states else None,
        "states": states,
        "state_counts": state_counts,
        "source": source,
        "case_results": results,
        "findings": [
            f"{name}: {count}"
            for name, count in state_counts.items()
            if name != "valid_and_authorized"
        ],
        "note": "report-only audit; authorization evidence does not change endpoint passed or CI exit codes",
    }


__all__ = ["NOT_CONFIGURED_STATE", "audit_authorization_evidence"]

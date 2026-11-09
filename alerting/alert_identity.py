"""
alerting/alert_identity.py

Phase 13.1: Canonical hashing and deterministic identities for alerting.

Every Phase 13 identity is the SHA-256 of one canonical encoding:

    canonical(tag, v1, ..., vn) =
        json.dumps([tag, v1, ..., vn], separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False)

encoded as UTF-8.  Because ensure_ascii=True, the text is pure ASCII and the
bytes do not depend on the platform.

Rules
-----
  - The first element is a fixed domain tag, so two kinds of identity can
    never collide even when their values are equal.
  - Values may be str, int, or None.  bool, float, datetime, bytes and every
    other type raise ValueError; nothing is coerced.
  - None encodes as JSON null and is distinct from the empty string.
  - Integers must be >= 0 and are written in base 10.
  - Strings are hashed by exact code point.  They are NOT Unicode-normalized:
    PostgreSQL compares these values bytewise, and normalizing would merge
    keys the database treats as different.
  - A string containing a lone surrogate raises ValueError.
  - No timestamp takes part in any identity.

Identities
----------
    decision_id = H("agentops.alert.decision.v1", investigation_id, policy_version)
    dedup_key   = H("agentops.alert.dedup.v1", anomaly_type, service_name,
                    operation_name)
    attempt_id  = H("agentops.alert.attempt.v1", decision_id, channel_name,
                    attempt_no)

Standard library only.  No database access, no I/O.

Public API:
    DECISION_TAG, DEDUP_TAG, ATTEMPT_TAG
    IDENTIFIER_PATTERN
    canonical_bytes()      — (tag, *values) -> canonical ASCII bytes
    canonical_sha256()     — (tag, *values) -> 64-char SHA-256 hex
    is_sha256_hex()        — True for exactly 64 lowercase hex characters
    validate_identifier()  — check a policy_version / channel name
    compute_decision_id()
    compute_dedup_key()
    compute_attempt_id()
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DECISION_TAG: str = "agentops.alert.decision.v1"
DEDUP_TAG: str = "agentops.alert.dedup.v1"
ATTEMPT_TAG: str = "agentops.alert.attempt.v1"

#: Identifiers supplied by the policy: policy_version and channel names.
IDENTIFIER_PATTERN: str = r"[A-Za-z0-9._-]{1,64}"

# fullmatch is used throughout: "$" would also match before a trailing newline.
_IDENTIFIER_RE = re.compile(IDENTIFIER_PATTERN)
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")

_SURROGATE_FIRST: int = 0xD800
_SURROGATE_LAST: int = 0xDFFF


# ---------------------------------------------------------------------------
# Canonical encoding
# ---------------------------------------------------------------------------

def _has_surrogate(value: str) -> bool:
    return any(_SURROGATE_FIRST <= ord(ch) <= _SURROGATE_LAST for ch in value)


def _checked_value(value: Any, position: int) -> Any:
    """Return value unchanged when it may be hashed; ValueError otherwise."""
    if value is None:
        return None
    # bool is a subclass of int in Python — must be rejected explicitly.
    if isinstance(value, bool):
        raise ValueError(f"canonical value {position} must not be bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(
                f"canonical value {position} must be >= 0, got {value}"
            )
        return value
    if isinstance(value, str):
        if _has_surrogate(value):
            raise ValueError(
                f"canonical value {position} contains a lone surrogate"
            )
        return value
    raise ValueError(
        f"canonical value {position} must be str, int or None, "
        f"got {type(value).__name__}"
    )


def canonical_bytes(tag: str, *values: Any) -> bytes:
    """
    Canonical encoding of a domain tag and its values.

    Raises:
        ValueError  if tag is not a non-empty str, or any value is not a str,
                    a non-negative int, or None, or a string holds a lone
                    surrogate.
    """
    if not isinstance(tag, str) or tag == "":
        raise ValueError("canonical tag must be a non-empty str")
    if _has_surrogate(tag):
        raise ValueError("canonical tag contains a lone surrogate")

    elements = [tag]
    for position, value in enumerate(values, start=1):
        elements.append(_checked_value(value, position))

    text = json.dumps(
        elements,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return text.encode("utf-8")


def canonical_sha256(tag: str, *values: Any) -> str:
    """64 lowercase hexadecimal characters: SHA-256 of canonical_bytes()."""
    return hashlib.sha256(canonical_bytes(tag, *values)).hexdigest()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def is_sha256_hex(value: Any) -> bool:
    """True when value is a str of exactly 64 lowercase hexadecimal characters."""
    return isinstance(value, str) and _SHA256_HEX_RE.fullmatch(value) is not None


def validate_identifier(value: Any, field: str) -> str:
    """
    Return value when it is a valid policy identifier.

    Raises:
        ValueError  if value is not a str matching IDENTIFIER_PATTERN in full.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be str, got {type(value).__name__}")
    if _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(
            f"{field} must match ^{IDENTIFIER_PATTERN}$, got {value!r}"
        )
    return value


def _require_sha256_hex(value: Any, field: str) -> str:
    if not is_sha256_hex(value):
        raise ValueError(
            f"{field} must be 64 lowercase hexadecimal characters"
        )
    return value


def _require_optional_str(value: Any, field: str) -> Optional[str]:
    if value is not None and not isinstance(value, str):
        raise ValueError(
            f"{field} must be str or None, got {type(value).__name__}"
        )
    return value


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------

def compute_decision_id(investigation_id: str, policy_version: str) -> str:
    """
    Identity of the decision for one investigation under one policy version.

    Raises:
        ValueError  if investigation_id is not a SHA-256 hex digest or
                    policy_version is not a valid identifier.
    """
    _require_sha256_hex(investigation_id, "investigation_id")
    validate_identifier(policy_version, "policy_version")
    return canonical_sha256(DECISION_TAG, investigation_id, policy_version)


def compute_dedup_key(
    anomaly_type: str,
    service_name: Optional[str],
    operation_name: Optional[str],
) -> str:
    """
    Deduplication key of one incident stream.

    service_name and operation_name may be None; None and "" give different
    keys.

    Raises:
        ValueError  if anomaly_type is not a non-empty str, or service_name or
                    operation_name is neither a str nor None.
    """
    if not isinstance(anomaly_type, str) or anomaly_type == "":
        raise ValueError("anomaly_type must be a non-empty str")
    _require_optional_str(service_name, "service_name")
    _require_optional_str(operation_name, "operation_name")
    return canonical_sha256(DEDUP_TAG, anomaly_type, service_name, operation_name)


def compute_attempt_id(decision_id: str, channel_name: str, attempt_no: int) -> str:
    """
    Identity of one delivery attempt.  It does not depend on the attempt's
    outcome.

    Raises:
        ValueError  if decision_id is not a SHA-256 hex digest, channel_name
                    is not a valid identifier, or attempt_no is not an int
                    >= 1.
    """
    _require_sha256_hex(decision_id, "decision_id")
    validate_identifier(channel_name, "channel_name")
    if isinstance(attempt_no, bool) or not isinstance(attempt_no, int):
        raise ValueError(
            f"attempt_no must be int, got {type(attempt_no).__name__}"
        )
    if attempt_no < 1:
        raise ValueError(f"attempt_no must be >= 1, got {attempt_no}")
    return canonical_sha256(ATTEMPT_TAG, decision_id, channel_name, attempt_no)

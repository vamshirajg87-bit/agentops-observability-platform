"""
alerting/alert_version.py

Phase 13.1: Authoritative contract versions for alerting.

This module is the ONE source of truth for:
  1. POLICY_SCHEMA_VERSION — the structure of the policy file accepted by
     alert_policy.py.  It is part of the policy hash, so a schema change can
     never be mistaken for the same policy.
  2. PAYLOAD_VERSION — the structure of the persisted notification payload.

Must never be derived from Git SHA, wall-clock time, or any runtime state.
"""

from __future__ import annotations

POLICY_SCHEMA_VERSION: str = "1.0.0"

PAYLOAD_VERSION: str = "1.0.0"

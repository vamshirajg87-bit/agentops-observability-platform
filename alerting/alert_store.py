"""
alerting/alert_store.py

Phase 13.4: Database access for alert evaluation.

This module holds every SQL statement of the alert evaluator.  It registers
a policy version, lists the investigations that have no decision under a
policy version, reads the alert history one evaluation needs, and writes one
row to public.alert_decisions.

Role
----
All statements run as the alert_evaluator role (migration 013) and use only
what that role is granted:

    public.rca_investigations  SELECT on ten columns
    public.alert_policies      INSERT, SELECT
    public.alert_decisions     INSERT, SELECT

Idempotency
-----------
policy rows:    ON CONFLICT (policy_version) DO NOTHING
decision rows:  ON CONFLICT (investigation_id, policy_version) DO NOTHING

First-write-wins: an existing row is never overwritten.  No UPDATE, no DELETE.

Transactions
------------
Functions here never commit or roll back.  The caller owns the transaction
and supplies an open connection, which it also closes.

SQL safety
----------
All values are %(name)s bound parameters.  No string interpolation.  Explicit
column lists.  No SELECT *.  Window bounds are computed by the caller and
bound as timestamps; no time arithmetic is done in SQL.

registered_at and decided_at are not supplied; the columns have DEFAULT NOW().

Alert history
-------------
fetch_alert_history() runs three statements and merges their rows by
decision_id.  Every statement reads ALERT decisions only, of every policy
version.  E is the event_time of the investigation being evaluated.

    duplicate   the same anomaly_id, with no time bound
    cooldown    the same dedup_key and  cooldown_start < event_time <= E
    storm       any dedup_key and       storm_start    < event_time <= E

The lower bound is exclusive and the upper bound inclusive.

Public API:
    fetch_policy_sha256()   — stored hash of a policy version, or None
    insert_policy()         — register a policy version; True if inserted
    fetch_candidates()      — investigations without a decision, in order
    fetch_alert_history()   — merged alert history for one evaluation
    insert_decision()       — insert one decision; True if inserted
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Optional

import psycopg
import psycopg.rows
from psycopg.types.json import Jsonb

from alert_models import AlertDecision


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_SQL_FETCH_POLICY_SHA256 = """\
SELECT
    policy_sha256
FROM public.alert_policies
WHERE policy_version = %(policy_version)s
"""

# registered_at is intentionally absent: the column has DEFAULT NOW().
_SQL_INSERT_POLICY = """\
INSERT INTO public.alert_policies (
    policy_version,
    policy_sha256,
    policy_json
) VALUES (
    %(policy_version)s,
    %(policy_sha256)s,
    %(policy_json)s
) ON CONFLICT (policy_version) DO NOTHING"""

# i = investigations, d = decisions already made under this policy version.
# No staleness or severity filter: every undecided investigation is returned
# and classified by the engine.
_SQL_FETCH_CANDIDATES = """\
SELECT
    i.investigation_id,
    i.anomaly_id,
    i.anomaly_type,
    i.service_name,
    i.operation_name,
    i.event_time,
    i.severity,
    i.confidence,
    i.limitations,
    i.summary
FROM public.rca_investigations AS i
WHERE NOT EXISTS (
    SELECT d.decision_id
    FROM public.alert_decisions AS d
    WHERE d.investigation_id = i.investigation_id
      AND d.policy_version = %(policy_version)s
)
ORDER BY i.event_time ASC, i.investigation_id ASC
"""

_SQL_FETCH_HISTORY_DUPLICATE = """\
SELECT
    decision_id,
    anomaly_id,
    dedup_key,
    event_time,
    severity,
    decision
FROM public.alert_decisions
WHERE decision = 'ALERT'
  AND anomaly_id = %(anomaly_id)s
"""

_SQL_FETCH_HISTORY_COOLDOWN = """\
SELECT
    decision_id,
    anomaly_id,
    dedup_key,
    event_time,
    severity,
    decision
FROM public.alert_decisions
WHERE decision = 'ALERT'
  AND dedup_key = %(dedup_key)s
  AND event_time > %(cooldown_start)s
  AND event_time <= %(event_time)s
"""

_SQL_FETCH_HISTORY_STORM = """\
SELECT
    decision_id,
    anomaly_id,
    dedup_key,
    event_time,
    severity,
    decision
FROM public.alert_decisions
WHERE decision = 'ALERT'
  AND event_time > %(storm_start)s
  AND event_time <= %(event_time)s
"""

# decided_at is intentionally absent: the column has DEFAULT NOW().
_SQL_INSERT_DECISION = """\
INSERT INTO public.alert_decisions (
    decision_id,
    investigation_id,
    policy_version,
    anomaly_id,
    anomaly_type,
    service_name,
    operation_name,
    event_time,
    severity,
    confidence,
    limitations,
    dedup_key,
    decision,
    reason_code,
    related_decision_id,
    evaluated_at,
    payload,
    summary,
    summary_truncated
) VALUES (
    %(decision_id)s,
    %(investigation_id)s,
    %(policy_version)s,
    %(anomaly_id)s,
    %(anomaly_type)s,
    %(service_name)s,
    %(operation_name)s,
    %(event_time)s,
    %(severity)s,
    %(confidence)s,
    %(limitations)s,
    %(dedup_key)s,
    %(decision)s,
    %(reason_code)s,
    %(related_decision_id)s,
    %(evaluated_at)s,
    %(payload)s,
    %(summary)s,
    %(summary_truncated)s
) ON CONFLICT (investigation_id, policy_version) DO NOTHING"""


# ---------------------------------------------------------------------------
# Parameter mapping (pure)
# ---------------------------------------------------------------------------

def _decision_params(decision: AlertDecision) -> dict[str, Any]:
    """
    Map an AlertDecision to the INSERT parameters for public.alert_decisions.

    payload stays None for a decision that has none, so the column is SQL
    NULL.  Wrapping None would store a JSON null, which is not NULL.
    """
    payload = None if decision.payload is None else Jsonb(dict(decision.payload))
    return {
        "decision_id": decision.decision_id,
        "investigation_id": decision.investigation_id,
        "policy_version": decision.policy_version,
        "anomaly_id": decision.anomaly_id,
        "anomaly_type": decision.anomaly_type,
        "service_name": decision.service_name,
        "operation_name": decision.operation_name,
        "event_time": decision.event_time,
        "severity": decision.severity.value,
        "confidence": decision.confidence.value,
        "limitations": list(decision.limitations),  # tuple → list for TEXT[]
        "dedup_key": decision.dedup_key,
        "decision": decision.decision.value,
        "reason_code": decision.reason_code.value,
        "related_decision_id": decision.related_decision_id,
        "evaluated_at": decision.evaluated_at,
        "payload": payload,
        "summary": decision.summary,
        "summary_truncated": decision.summary_truncated,
    }


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------

def fetch_policy_sha256(
    conn: psycopg.Connection,
    policy_version: str,
) -> Optional[str]:
    """
    Return the policy_sha256 stored for policy_version.

    Returns None if the policy version is not registered.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_POLICY_SHA256, {"policy_version": policy_version})
        row = cur.fetchone()

    if row is None:
        return None
    return row["policy_sha256"]


def insert_policy(
    conn: psycopg.Connection,
    *,
    policy_version: str,
    policy_sha256: str,
    policy_json: Mapping[str, Any],
) -> bool:
    """
    Register one policy version; first-write-wins.

    Returns True if the row was inserted, False if policy_version was already
    registered, in which case nothing is changed.

    Does not commit.

    Raises:
        psycopg.Error  on any database error.
    """
    params = {
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "policy_json": Jsonb(dict(policy_json)),
    }
    with conn.cursor() as cur:
        cur.execute(_SQL_INSERT_POLICY, params)
        return cur.rowcount == 1


# ---------------------------------------------------------------------------
# Candidate discovery
# ---------------------------------------------------------------------------

def fetch_candidates(
    conn: psycopg.Connection,
    policy_version: str,
) -> list[dict[str, Any]]:
    """
    List the investigations that have no decision under policy_version.

    Returns one dict per investigation with the keys investigation_id,
    anomaly_id, anomaly_type, service_name, operation_name, event_time,
    severity, confidence, limitations, summary, ordered event_time ASC, then
    investigation_id ASC.  A decision under another policy version does not
    exclude an investigation.  No staleness or severity filter is applied.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_CANDIDATES, {"policy_version": policy_version})
        rows = cur.fetchall()

    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Alert history
# ---------------------------------------------------------------------------

def fetch_alert_history(
    conn: psycopg.Connection,
    *,
    anomaly_id: str,
    dedup_key: str,
    event_time: datetime,
    cooldown_start: datetime,
    storm_start: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch the persisted ALERT decisions one evaluation needs.

    Runs the duplicate, cooldown and storm statements and merges their rows
    by decision_id, so a decision returned by more than one statement appears
    once.  Decisions of every policy version are included.

    Returns one dict per decision with the keys decision_id, anomaly_id,
    dedup_key, event_time, severity, decision, ordered decision_id ASC.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    statements = (
        (_SQL_FETCH_HISTORY_DUPLICATE, {"anomaly_id": anomaly_id}),
        (_SQL_FETCH_HISTORY_COOLDOWN, {
            "dedup_key": dedup_key,
            "cooldown_start": cooldown_start,
            "event_time": event_time,
        }),
        (_SQL_FETCH_HISTORY_STORM, {
            "storm_start": storm_start,
            "event_time": event_time,
        }),
    )

    merged: dict[Any, dict[str, Any]] = {}
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        for sql, params in statements:
            cur.execute(sql, params)
            for row in cur.fetchall():
                merged.setdefault(row["decision_id"], dict(row))

    return [merged[decision_id] for decision_id in sorted(merged)]


# ---------------------------------------------------------------------------
# Decision persistence
# ---------------------------------------------------------------------------

def insert_decision(
    conn: psycopg.Connection,
    decision: AlertDecision,
) -> bool:
    """
    Insert one decision row; first-write-wins.

    Returns True if the row was inserted, False if a decision for the same
    (investigation_id, policy_version) already existed, in which case nothing
    is changed.

    Does not commit.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor() as cur:
        cur.execute(_SQL_INSERT_DECISION, _decision_params(decision))
        return cur.rowcount == 1

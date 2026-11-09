"""
alerting/alert_delivery_store.py

Phase 13.5: Database access for alert notification.

This module holds every SQL statement of the alert notifier.  It reads the
persisted alert decisions, reads the delivery records of a decision, and
appends one row to public.alert_delivery_attempts or
public.alert_delivery_outcomes.

Role
----
All statements run as the alert_notifier role (migration 014) and use only
what that role is granted:

    public.alert_decisions          SELECT on eight columns
    public.alert_delivery_attempts  INSERT, SELECT
    public.alert_delivery_outcomes  INSERT, SELECT

Nothing is read from any RCA, anomaly, telemetry, embedding or policy table.

Discovery
---------
fetch_alert_decisions() returns every decision whose verdict is ALERT, of
every policy version and of any age, ordered evaluated_at ASC, then
decision_id ASC.  Whether an alert is still deliverable is decided from its
delivery state by the caller, not by this module.

Idempotency
-----------
attempt rows:  ON CONFLICT (decision_id, channel_name, attempt_no) DO NOTHING
outcome rows:  ON CONFLICT (attempt_id) DO NOTHING

An existing row is never overwritten.  No UPDATE, no DELETE.  A caller whose
attempt row was not inserted does not own that attempt and must not send.

Transactions
------------
Functions here never commit or roll back.  The caller owns the transaction
and supplies an open connection, which it also closes.

SQL safety
----------
All values are %(name)s bound parameters.  No string interpolation.  Explicit
column lists.  No SELECT *.

started_at and recorded_at are not supplied; the columns have DEFAULT NOW().

Public API:
    fetch_alert_decisions()         — every ALERT decision, oldest first
    fetch_recent_alert_decisions()  — the newest ALERT decisions
    fetch_decision()                — one decision of any verdict, or None
    fetch_delivery_history()        — delivery records of several decisions
    fetch_channel_history()         — delivery records of one decision on
                                      one channel
    insert_attempt()                — insert one attempt; True if inserted
    insert_outcome()                — insert one outcome; True if inserted
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

import psycopg
import psycopg.rows

from alert_channels import SendResult


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

# No policy_version filter, no age filter and no LIMIT: expiry is a delivery
# state and must stay visible.
_SQL_FETCH_ALERT_DECISIONS = """\
SELECT
    decision_id,
    decision,
    reason_code,
    policy_version,
    evaluated_at,
    payload,
    summary,
    summary_truncated
FROM public.alert_decisions
WHERE decision = 'ALERT'
ORDER BY evaluated_at ASC, decision_id ASC
"""

_SQL_FETCH_RECENT_ALERT_DECISIONS = """\
SELECT
    decision_id,
    decision,
    reason_code,
    policy_version,
    evaluated_at,
    payload,
    summary,
    summary_truncated
FROM public.alert_decisions
WHERE decision = 'ALERT'
ORDER BY evaluated_at DESC, decision_id ASC
LIMIT %(limit)s
"""

_SQL_FETCH_DECISION = """\
SELECT
    decision_id,
    decision,
    reason_code,
    policy_version,
    evaluated_at,
    payload,
    summary,
    summary_truncated
FROM public.alert_decisions
WHERE decision_id = %(decision_id)s
"""

# a = attempts, o = the outcome of an attempt, when one was recorded.
_SQL_FETCH_DELIVERY_HISTORY = """\
SELECT
    a.attempt_id,
    a.decision_id,
    a.channel_name,
    a.channel_type,
    a.attempt_no,
    a.trigger,
    a.summary_included,
    a.payload_sha256,
    a.started_at,
    o.outcome,
    o.detail,
    o.recorded_at
FROM public.alert_delivery_attempts AS a
LEFT JOIN public.alert_delivery_outcomes AS o
  ON o.attempt_id = a.attempt_id
WHERE a.decision_id = ANY(%(decision_ids)s)
ORDER BY a.decision_id ASC, a.channel_name ASC, a.attempt_no ASC
"""

_SQL_FETCH_CHANNEL_HISTORY = """\
SELECT
    a.attempt_id,
    a.decision_id,
    a.channel_name,
    a.channel_type,
    a.attempt_no,
    a.trigger,
    a.summary_included,
    a.payload_sha256,
    a.started_at,
    o.outcome,
    o.detail,
    o.recorded_at
FROM public.alert_delivery_attempts AS a
LEFT JOIN public.alert_delivery_outcomes AS o
  ON o.attempt_id = a.attempt_id
WHERE a.decision_id = %(decision_id)s
  AND a.channel_name = %(channel_name)s
ORDER BY a.attempt_no ASC
"""

# started_at is intentionally absent: the column has DEFAULT NOW().
_SQL_INSERT_ATTEMPT = """\
INSERT INTO public.alert_delivery_attempts (
    attempt_id,
    decision_id,
    channel_name,
    channel_type,
    attempt_no,
    trigger,
    summary_included,
    payload_sha256
) VALUES (
    %(attempt_id)s,
    %(decision_id)s,
    %(channel_name)s,
    %(channel_type)s,
    %(attempt_no)s,
    %(trigger)s,
    %(summary_included)s,
    %(payload_sha256)s
) ON CONFLICT (decision_id, channel_name, attempt_no) DO NOTHING"""

# recorded_at is intentionally absent: the column has DEFAULT NOW().
_SQL_INSERT_OUTCOME = """\
INSERT INTO public.alert_delivery_outcomes (
    attempt_id,
    outcome,
    detail
) VALUES (
    %(attempt_id)s,
    %(outcome)s,
    %(detail)s
) ON CONFLICT (attempt_id) DO NOTHING"""


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

def _fetch_all(
    conn: psycopg.Connection, sql: str, params: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return [dict(row) for row in rows]


def fetch_alert_decisions(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """
    List every ALERT decision, ordered evaluated_at ASC, then decision_id ASC.

    Returns one dict per decision with the keys decision_id, decision,
    reason_code, policy_version, evaluated_at, payload, summary,
    summary_truncated.  Decisions of every policy version and of any age are
    included.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    return _fetch_all(conn, _SQL_FETCH_ALERT_DECISIONS)


def fetch_recent_alert_decisions(
    conn: psycopg.Connection,
    limit: int,
) -> list[dict[str, Any]]:
    """
    List the newest ALERT decisions: evaluated_at DESC, then decision_id ASC,
    at most limit of them.  Same keys as fetch_alert_decisions().

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    return _fetch_all(conn, _SQL_FETCH_RECENT_ALERT_DECISIONS, {"limit": limit})


def fetch_decision(
    conn: psycopg.Connection,
    decision_id: str,
) -> Optional[dict[str, Any]]:
    """
    Fetch one decision by decision_id, whatever its verdict.

    Returns None if decision_id does not exist.  Same keys as
    fetch_alert_decisions(); the caller checks the verdict.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    rows = _fetch_all(conn, _SQL_FETCH_DECISION, {"decision_id": decision_id})
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Delivery history
# ---------------------------------------------------------------------------

def fetch_delivery_history(
    conn: psycopg.Connection,
    decision_ids: Sequence[str],
) -> list[dict[str, Any]]:
    """
    Fetch every attempt of several decisions, each with its outcome.

    Returns one dict per attempt with the keys attempt_id, decision_id,
    channel_name, channel_type, attempt_no, trigger, summary_included,
    payload_sha256, started_at, outcome, detail, recorded_at.  The last three
    are None for an attempt without an outcome.  Ordered decision_id,
    channel_name, attempt_no.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    if not decision_ids:
        return []
    return _fetch_all(
        conn, _SQL_FETCH_DELIVERY_HISTORY, {"decision_ids": list(decision_ids)},
    )


def fetch_channel_history(
    conn: psycopg.Connection,
    decision_id: str,
    channel_name: str,
) -> list[dict[str, Any]]:
    """
    Fetch every attempt of one decision on one channel, each with its
    outcome, ordered attempt_no ASC.  Same keys as fetch_delivery_history().

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    return _fetch_all(conn, _SQL_FETCH_CHANNEL_HISTORY, {
        "decision_id": decision_id,
        "channel_name": channel_name,
    })


# ---------------------------------------------------------------------------
# Delivery records
# ---------------------------------------------------------------------------

def insert_attempt(
    conn: psycopg.Connection,
    *,
    attempt_id: str,
    decision_id: str,
    channel_name: str,
    channel_type: str,
    attempt_no: int,
    trigger: str,
    summary_included: bool,
    payload_sha256: str,
) -> bool:
    """
    Insert one attempt row.

    Returns True if the row was inserted, False if an attempt with the same
    (decision_id, channel_name, attempt_no) already existed, in which case
    nothing is changed and the caller does not own the attempt.

    Does not commit.

    Raises:
        psycopg.Error  on any database error.
    """
    params = {
        "attempt_id": attempt_id,
        "decision_id": decision_id,
        "channel_name": channel_name,
        "channel_type": channel_type,
        "attempt_no": attempt_no,
        "trigger": trigger,
        "summary_included": summary_included,
        "payload_sha256": payload_sha256,
    }
    with conn.cursor() as cur:
        cur.execute(_SQL_INSERT_ATTEMPT, params)
        return cur.rowcount == 1


def insert_outcome(
    conn: psycopg.Connection,
    *,
    attempt_id: str,
    result: SendResult,
) -> bool:
    """
    Insert the outcome of one attempt.

    result must be a SendResult, so only an outcome and a detail code of the
    closed contract can be stored.

    Returns True if the row was inserted, False if the attempt already had an
    outcome, in which case nothing is changed.

    Does not commit.

    Raises:
        ValueError     if result is not a SendResult.  Raised before any SQL
                       is executed.
        psycopg.Error  on any database error.
    """
    if not isinstance(result, SendResult):
        raise ValueError(
            f"result must be SendResult, got {type(result).__name__}"
        )
    params = {
        "attempt_id": attempt_id,
        "outcome": result.outcome.value,
        "detail": result.detail,
    }
    with conn.cursor() as cur:
        cur.execute(_SQL_INSERT_OUTCOME, params)
        return cur.rowcount == 1

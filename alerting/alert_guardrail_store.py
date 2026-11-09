"""
alerting/alert_guardrail_store.py

Phase 13.6: Database access for the operational guardrails.

This module holds every SQL statement of the guardrails.  All four are
SELECT statements: the guardrails only observe and report, so nothing is ever
written, changed or removed.

Role
----
All statements run as the alert_evaluator role (migration 013) and use only
what that role is granted:

    public.anomaly_detector_runs    SELECT on signal_path, service_name,
                                    operation_name, updated_at
    public.anomaly_events           SELECT on anomaly_id, detected_at
    public.rca_investigations       SELECT on anomaly_id (and nine others)
    public.alert_decisions          SELECT
    public.alert_delivery_attempts  SELECT
    public.alert_delivery_outcomes  SELECT

No summary, limitation, payload, explanation or outcome detail is read, and
nothing from telemetry, evidence, embeddings or the analytics schema.

Statements
----------
    S1  every detector checkpoint
    S2  every anomaly that has no investigation, of any age
    S3  ALERT decisions evaluated at or after a point in time, or with an
        attempt started at or after it
    S4  the delivery attempts of given decisions on given channels, each
        with its outcome when one was recorded

No statement compares against the database clock.  Time bounds are computed
by the caller and bound as parameters; age thresholds are applied by the
caller, not in SQL.

Transactions
------------
Functions here never commit or roll back.  The caller owns the transaction
and supplies an open connection, which it also closes.

SQL safety
----------
All values are %(name)s bound parameters.  No string interpolation.  Explicit
column lists.  No SELECT *.

Public API:
    fetch_checkpoints()               — S1
    fetch_uninvestigated_anomalies()  — S2
    fetch_alert_decisions()           — S3
    fetch_delivery_history()          — S4
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Sequence

import psycopg
import psycopg.rows


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_SQL_FETCH_CHECKPOINTS = """\
SELECT
    signal_path,
    service_name,
    operation_name,
    updated_at
FROM public.anomaly_detector_runs
ORDER BY signal_path ASC, service_name ASC, operation_name ASC
"""

# e = anomalies, i = investigations of the same anomaly.
# No age predicate: the caller applies the threshold.
_SQL_FETCH_UNINVESTIGATED_ANOMALIES = """\
SELECT
    e.anomaly_id,
    e.detected_at
FROM public.anomaly_events AS e
WHERE NOT EXISTS (
    SELECT i.investigation_id
    FROM public.rca_investigations AS i
    WHERE i.anomaly_id = e.anomaly_id
)
ORDER BY e.detected_at ASC, e.anomaly_id ASC
"""

# d = decisions, a = attempts of the same decision.
# No policy_version filter and no LIMIT.
_SQL_FETCH_ALERT_DECISIONS = """\
SELECT
    d.decision_id,
    d.evaluated_at
FROM public.alert_decisions AS d
WHERE d.decision = 'ALERT'
  AND (
    d.evaluated_at >= %(lookback_start)s
    OR EXISTS (
        SELECT a.attempt_id
        FROM public.alert_delivery_attempts AS a
        WHERE a.decision_id = d.decision_id
          AND a.started_at >= %(lookback_start)s
    )
  )
ORDER BY d.evaluated_at ASC, d.decision_id ASC
"""

# a = attempts, o = the outcome of an attempt, when one was recorded.
# The outcome's detail text is not needed to derive a delivery state.
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
    o.recorded_at
FROM public.alert_delivery_attempts AS a
LEFT JOIN public.alert_delivery_outcomes AS o
  ON o.attempt_id = a.attempt_id
WHERE a.decision_id = ANY(%(decision_ids)s)
  AND a.channel_name = ANY(%(channel_names)s)
ORDER BY a.decision_id ASC, a.channel_name ASC, a.attempt_no ASC
"""


# ---------------------------------------------------------------------------
# Public query functions
# ---------------------------------------------------------------------------

def _fetch_all(
    conn: psycopg.Connection, sql: str, params: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return [dict(row) for row in rows]


def fetch_checkpoints(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """
    List every detector checkpoint.

    Returns one dict per detection group with the keys signal_path,
    service_name, operation_name, updated_at, ordered by the three key
    columns.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    return _fetch_all(conn, _SQL_FETCH_CHECKPOINTS)


def fetch_uninvestigated_anomalies(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """
    List every anomaly that has no investigation.

    Returns one dict per anomaly with the keys anomaly_id, detected_at,
    ordered detected_at ASC, then anomaly_id ASC.  An investigation of any
    confidence counts.  Anomalies of every age are returned; the caller
    decides which are overdue.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    return _fetch_all(conn, _SQL_FETCH_UNINVESTIGATED_ANOMALIES)


def fetch_alert_decisions(
    conn: psycopg.Connection,
    *,
    lookback_start: datetime,
) -> list[dict[str, Any]]:
    """
    List the ALERT decisions that may fall into the delivery lookback: those
    evaluated at or after lookback_start, and those with any attempt started
    at or after it.  Decisions of every policy version are included.

    Returns one dict per decision with the keys decision_id, evaluated_at,
    ordered evaluated_at ASC, then decision_id ASC.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    return _fetch_all(
        conn, _SQL_FETCH_ALERT_DECISIONS, {"lookback_start": lookback_start},
    )


def fetch_delivery_history(
    conn: psycopg.Connection,
    *,
    decision_ids: Sequence[str],
    channel_names: Sequence[str],
) -> list[dict[str, Any]]:
    """
    Fetch the attempts of the given decisions on the given channels, each
    with its outcome.

    Returns one dict per attempt with the keys attempt_id, decision_id,
    channel_name, channel_type, attempt_no, trigger, summary_included,
    payload_sha256, started_at, outcome, recorded_at.  The last two are None
    for an attempt without an outcome.  Ordered decision_id, channel_name,
    attempt_no.

    When either sequence is empty nothing can match, and no statement is
    executed.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    if not decision_ids or not channel_names:
        return []
    return _fetch_all(conn, _SQL_FETCH_DELIVERY_HISTORY, {
        "decision_ids": list(decision_ids),
        "channel_names": list(channel_names),
    })

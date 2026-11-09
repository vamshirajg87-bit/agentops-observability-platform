"""
trace-viewer/anomaly_queries.py

Read-only PostgreSQL data-access layer for anomalies and RCA investigations.

All functions accept a psycopg.Connection and use %(name)s parameter binding.
No filter value is interpolated into SQL; the only f-string pieces are the
fixed column lists and WHERE fragments defined in this module.

Tables read (SELECT only, granted to trace_viewer_reader by migration 015):
    public.anomaly_events
    public.rca_investigations
    public.rca_evidence

Public API:
    AnomalyListResult              — structured result of list_anomalies()
    list_anomalies()               → AnomalyListResult   paginated anomalies + total
    get_anomaly()                  → dict | None         one anomaly by ID
    get_rca_investigation()        → dict | None         investigation + ranked evidence
    get_latest_rca_for_anomaly()   → dict | None         newest investigation + evidence

ID formats (enforced by CHECK constraints on the tables):
    anomaly_id, investigation_id   64 lowercase hex characters
    trace_id                       32 lowercase hex characters (trace-viewer convention)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import psycopg
import psycopg.rows

SEVERITIES: tuple[str, ...] = ("INFO", "WARNING", "CRITICAL")

#: What is read from PostgreSQL is one more than the API returns (app.MAX_TEXT_CHARS
#: 2,000, MAX_EVIDENCE_ROWS 200, MAX_LIMITATIONS 50), so that "exactly the limit" is
#: told apart from "more".  The database does the shortening, so an oversized value
#: or list is never transferred.  Kept equal to the app's limits + 1 by a unit test.
TEXT_FETCH_CHARS: int = 2001
EVIDENCE_FETCH_ROWS: int = 201
LIMITATIONS_FETCH_ITEMS: int = 51

_ID64_RE = re.compile(r"^[0-9a-f]{64}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


@dataclass
class AnomalyListResult:
    """total — rows matching the filters before pagination; anomalies — this page."""
    total: int
    anomalies: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# SQL fragments
# ---------------------------------------------------------------------------

_ANOMALY_SELECT = f"""\
SELECT
    anomaly_id,
    anomaly_type,
    signal_name,
    detector_name,
    detector_version,
    trace_id,
    span_id,
    service_name,
    operation_name,
    observed_value,
    event_time,
    baseline_median,
    baseline_mad,
    baseline_n,
    baseline_window_start,
    baseline_window_end,
    anomaly_score,
    severity,
    left(explanation, {TEXT_FETCH_CHARS}) AS explanation,
    detected_at
FROM public.anomaly_events
"""

# Newest first; the primary key makes the order total (deterministic).
_ANOMALY_ORDER = "ORDER BY event_time DESC, anomaly_id ASC\n"

_INVESTIGATION_SELECT = f"""\
SELECT
    investigation_id,
    anomaly_id,
    analyzer_version,
    investigated_at,
    trace_id,
    subject_span_id,
    service_name,
    operation_name,
    event_time,
    trace_span_count,
    anomaly_type,
    observed_value,
    baseline_median,
    anomaly_score,
    severity,
    confidence,
    left(summary, {TEXT_FETCH_CHARS}) AS summary,
    ARRAY(
        SELECT left(item, {TEXT_FETCH_CHARS})
        FROM unnest(limitations[1:{LIMITATIONS_FETCH_ITEMS}]) WITH ORDINALITY AS u(item, ord)
        ORDER BY ord
    ) AS limitations
FROM public.rca_investigations
"""

_EVIDENCE_SQL = f"""\
SELECT
    span_id,
    parent_span_id,
    span_name,
    service_name,
    duration_ms,
    status_code,
    error_type,
    left(error_message, {TEXT_FETCH_CHARS}) AS error_message,
    tool_name,
    tool_status,
    agent_name,
    agent_operation,
    retrieval_result_count,
    retrieval_top_relevance_score,
    is_root_span,
    is_error_span,
    is_direct_subject,
    depth,
    trace_duration_fraction,
    evidence_type,
    evidence_score,
    left(evidence_score_breakdown, {TEXT_FETCH_CHARS}) AS evidence_score_breakdown,
    left(explanation, {TEXT_FETCH_CHARS}) AS explanation,
    rank_position,
    count(*) OVER () AS evidence_total
FROM public.rca_evidence
WHERE investigation_id = %(investigation_id)s
ORDER BY rank_position ASC, span_id ASC
LIMIT {EVIDENCE_FETCH_ROWS}
"""

# Newest investigation for an anomaly; investigation_id breaks timestamp ties.
_LATEST_INVESTIGATION_SQL = (
    _INVESTIGATION_SELECT
    + "WHERE anomaly_id = %(anomaly_id)s\n"
    + "ORDER BY investigated_at DESC, investigation_id ASC\n"
    + "LIMIT 1"
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_id64(value: str, name: str) -> None:
    if not _ID64_RE.match(value):
        raise ValueError(f"{name} must be 64 lowercase hex characters")


def _validate_trace_id(value: str) -> None:
    if not _TRACE_ID_RE.match(value):
        raise ValueError("trace_id must be 32 lowercase hex characters")


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def list_anomalies(
    conn: psycopg.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    service_name: str | None = None,
    trace_id: str | None = None,
) -> AnomalyListResult:
    """
    Return one page of anomalies from public.anomaly_events.

    Ordering: event_time DESC, anomaly_id ASC.

    Raises:
        ValueError     if limit < 1, offset < 0, severity is not a known value,
                       or trace_id is not 32 lowercase hex characters.
        psycopg.Error  on any database error.
    """
    if limit < 1:
        raise ValueError(f"limit must be >= 1, got {limit}")
    if offset < 0:
        raise ValueError(f"offset must be >= 0, got {offset}")
    if severity is not None and severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    if trace_id is not None:
        _validate_trace_id(trace_id)

    conditions: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if severity is not None:
        conditions.append("severity = %(severity)s")
        params["severity"] = severity
    if service_name is not None:
        conditions.append("service_name = %(service_name)s")
        params["service_name"] = service_name
    if trace_id is not None:
        conditions.append("trace_id = %(trace_id)s")
        params["trace_id"] = trace_id

    where = ("WHERE " + " AND ".join(conditions) + "\n") if conditions else ""
    count_sql = f"SELECT COUNT(*) FROM public.anomaly_events\n{where}"
    page_sql = f"{_ANOMALY_SELECT}{where}{_ANOMALY_ORDER}LIMIT %(limit)s OFFSET %(offset)s"

    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(count_sql, params)
        total = cur.fetchone()["count"]
        cur.execute(page_sql, params)
        rows = cur.fetchall()

    return AnomalyListResult(total=total, anomalies=rows)


def get_anomaly(conn: psycopg.Connection, anomaly_id: str) -> dict[str, Any] | None:
    """
    Return the anomaly with anomaly_id, or None if it does not exist.

    Raises:
        ValueError     if anomaly_id is not 64 lowercase hex characters.
        psycopg.Error  on any database error.
    """
    _validate_id64(anomaly_id, "anomaly_id")
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            f"{_ANOMALY_SELECT}WHERE anomaly_id = %(anomaly_id)s",
            {"anomaly_id": anomaly_id},
        )
        return cur.fetchone()


def _attach_evidence(cur: psycopg.Cursor, investigation: dict[str, Any]) -> dict[str, Any]:
    """
    Add "evidence" (at most EVIDENCE_FETCH_ROWS rows, strongest first) and
    "evidence_total" (how many evidence rows the investigation really has, from the
    same statement) to the investigation row.
    """
    cur.execute(_EVIDENCE_SQL, {"investigation_id": investigation["investigation_id"]})
    rows = cur.fetchall()
    total = rows[0].get("evidence_total", len(rows)) if rows else 0
    for row in rows:
        row.pop("evidence_total", None)
    investigation["evidence"] = rows
    investigation["evidence_total"] = total
    return investigation


def get_rca_investigation(
    conn: psycopg.Connection,
    investigation_id: str,
) -> dict[str, Any] | None:
    """
    Return the investigation with investigation_id plus its evidence, or None.

    The result is the investigation row with an extra "evidence" list ordered
    rank_position ASC, span_id ASC.

    Raises:
        ValueError     if investigation_id is not 64 lowercase hex characters.
        psycopg.Error  on any database error.
    """
    _validate_id64(investigation_id, "investigation_id")
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            f"{_INVESTIGATION_SELECT}WHERE investigation_id = %(investigation_id)s",
            {"investigation_id": investigation_id},
        )
        row = cur.fetchone()
        if row is None:
            return None
        return _attach_evidence(cur, row)


def get_latest_rca_for_anomaly(
    conn: psycopg.Connection,
    anomaly_id: str,
) -> dict[str, Any] | None:
    """
    Return the most recent investigation for anomaly_id plus its evidence, or
    None if the anomaly has no investigation (or does not exist).

    Raises:
        ValueError     if anomaly_id is not 64 lowercase hex characters.
        psycopg.Error  on any database error.
    """
    _validate_id64(anomaly_id, "anomaly_id")
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_LATEST_INVESTIGATION_SQL, {"anomaly_id": anomaly_id})
        row = cur.fetchone()
        if row is None:
            return None
        return _attach_evidence(cur, row)

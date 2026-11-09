"""
rca-analyzer/rca_source.py

Phase 11.3: Read-only source queries for the RCA analyzer.

Fetches data from public.anomaly_events and analytics.stg_telemetry_spans.
All SQL uses %(name)s parameter binding; no values are interpolated into
SQL strings. The caller supplies an open psycopg.Connection; this module
never opens a database connection of its own.

Public API:
    RcaAnomalyRecord  — typed snapshot of one public.anomaly_events row
    fetch_anomaly()   — fetch one anomaly by anomaly_id
    fetch_spans()     — fetch all spans for a trace_id

Column renames (DB column → Python field):
    anomaly_events.span_id      → RcaAnomalyRecord.subject_span_id
    anomaly_events.explanation  → RcaAnomalyRecord.detector_explanation
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import psycopg
import psycopg.rows

from rca_trace import SpanRecord


# ---------------------------------------------------------------------------
# Domain validation sets
# ---------------------------------------------------------------------------

_VALID_ANOMALY_TYPES = frozenset(
    {"latency", "retrieval_quality", "error_rate", "tool_failure"}
)
_VALID_SEVERITIES = frozenset({"INFO", "WARNING", "CRITICAL"})


# ---------------------------------------------------------------------------
# Typed anomaly model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RcaAnomalyRecord:
    """
    Typed snapshot of one row from public.anomaly_events.

    The DB column span_id is exposed as subject_span_id to avoid ambiguity
    with span-level span_id values used in trace reconstruction.  The DB
    column explanation is exposed as detector_explanation to match the RCA
    domain vocabulary.
    """

    anomaly_id: str
    anomaly_type: str           # "latency" | "retrieval_quality" | "error_rate" | "tool_failure"
    signal_name: str
    detector_name: str
    detector_version: str
    trace_id: Optional[str]
    subject_span_id: Optional[str]   # DB column: span_id; None for trace-level anomalies
    service_name: Optional[str]
    operation_name: Optional[str]
    observed_value: float
    event_time: datetime
    baseline_median: Optional[float]
    baseline_mad: Optional[float]
    baseline_n: Optional[int]
    anomaly_score: Optional[float]
    severity: str                    # "INFO" | "WARNING" | "CRITICAL"
    detector_explanation: str        # DB column: explanation


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_SQL_FETCH_ANOMALY = """\
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
    anomaly_score,
    severity,
    explanation
FROM public.anomaly_events
WHERE anomaly_id = %(anomaly_id)s
"""

_SQL_FETCH_SPANS = """\
SELECT
    trace_id,
    span_id,
    parent_span_id,
    span_name,
    span_kind,
    service_name,
    start_time,
    end_time,
    duration_ms,
    status_code,
    status_message,
    agent_name,
    agent_operation,
    tool_name,
    tool_status,
    retrieval_result_count,
    retrieval_top_relevance_score,
    error_type,
    error_message
FROM analytics.stg_telemetry_spans
WHERE trace_id = %(trace_id)s
ORDER BY start_time ASC, span_id ASC
"""


# ---------------------------------------------------------------------------
# Row mappers
# ---------------------------------------------------------------------------

def _row_to_anomaly_record(row: dict[str, Any]) -> RcaAnomalyRecord:
    """Map a psycopg dict_row from public.anomaly_events to RcaAnomalyRecord."""
    anomaly_type = row["anomaly_type"]
    if anomaly_type not in _VALID_ANOMALY_TYPES:
        raise ValueError(
            f"Unrecognised anomaly_type {anomaly_type!r} "
            f"in anomaly_id={row['anomaly_id']!r}"
        )
    severity = row["severity"]
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"Unrecognised severity {severity!r} "
            f"in anomaly_id={row['anomaly_id']!r}"
        )
    return RcaAnomalyRecord(
        anomaly_id=row["anomaly_id"],
        anomaly_type=anomaly_type,
        signal_name=row["signal_name"],
        detector_name=row["detector_name"],
        detector_version=row["detector_version"],
        trace_id=row["trace_id"],
        subject_span_id=row["span_id"],
        service_name=row["service_name"],
        operation_name=row["operation_name"],
        observed_value=row["observed_value"],
        event_time=row["event_time"],
        baseline_median=row["baseline_median"],
        baseline_mad=row["baseline_mad"],
        baseline_n=row["baseline_n"],
        anomaly_score=row["anomaly_score"],
        severity=severity,
        detector_explanation=row["explanation"],
    )


def _row_to_span_record(row: dict[str, Any]) -> SpanRecord:
    """Map a psycopg dict_row from analytics.stg_telemetry_spans to SpanRecord."""
    return SpanRecord(
        span_id=row["span_id"],
        parent_span_id=row["parent_span_id"],
        span_name=row["span_name"],
        service_name=row["service_name"],
        start_time=row["start_time"],
        end_time=row["end_time"],
        duration_ms=row["duration_ms"],
        status_code=row["status_code"],
        trace_id=row["trace_id"],
        span_kind=row.get("span_kind"),
        status_message=row.get("status_message"),
        agent_name=row.get("agent_name"),
        agent_operation=row.get("agent_operation"),
        tool_name=row.get("tool_name"),
        tool_status=row.get("tool_status"),
        retrieval_result_count=row.get("retrieval_result_count"),
        retrieval_top_relevance_score=row.get("retrieval_top_relevance_score"),
        error_type=row.get("error_type"),
        error_message=row.get("error_message"),
    )


# ---------------------------------------------------------------------------
# Public query functions
# ---------------------------------------------------------------------------

def fetch_anomaly(
    conn: psycopg.Connection,
    anomaly_id: str,
) -> Optional[RcaAnomalyRecord]:
    """
    Fetch one anomaly by anomaly_id from public.anomaly_events.

    Returns None if anomaly_id does not exist.

    Raises:
        ValueError           if the row contains an unrecognised anomaly_type
                             or severity.
        psycopg.Error        on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_ANOMALY, {"anomaly_id": anomaly_id})
        row = cur.fetchone()

    if row is None:
        return None
    return _row_to_anomaly_record(row)


def fetch_spans(
    conn: psycopg.Connection,
    trace_id: str,
) -> list[SpanRecord]:
    """
    Fetch all spans for trace_id from analytics.stg_telemetry_spans.

    Rows are ordered start_time ASC, span_id ASC for deterministic results.
    Returns an empty list if no spans exist for the given trace_id.

    Do not call this function when the anomaly carries no trace_id; check
    the anomaly record's trace_id before calling.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_SPANS, {"trace_id": trace_id})
        rows = cur.fetchall()

    return [_row_to_span_record(row) for row in rows]

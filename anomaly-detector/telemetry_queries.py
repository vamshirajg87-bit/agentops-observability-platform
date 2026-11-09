"""
anomaly-detector/telemetry_queries.py

PostgreSQL read-only data access layer for anomaly detector telemetry.

All functions accept a psycopg.Connection and return list[dict[str, Any]] rows
via the dict_row row factory.  All variable values use %(name)s parameter
binding; no values are interpolated into SQL strings.  Relation names are
fixed module-level constants.

Half-open interval convention: [window_start, window_end)
    event_time >= window_start
    event_time  < window_end

The caller (Phase 10.4E) is responsible for deriving exact window_start and
window_end from detector configuration.  This module executes the requested
bounds exactly — it does not add safety buffers or reinterpret detector config.

Public API:
    fetch_trace_latency_history()     — analytics.mart_trace_metrics
    fetch_agent_latency_history()     — analytics.mart_agent_metrics
    fetch_tool_latency_history()      — analytics.stg_telemetry_spans
    fetch_retrieval_history()         — analytics.mart_retrieval_metrics
    fetch_error_rate_history()        — analytics.stg_telemetry_spans
    fetch_tool_failure_history()      — analytics.stg_telemetry_spans
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import psycopg
import psycopg.rows

# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------
# Each constant selects only the columns required to build the corresponding
# Phase 10.3 record type.  Column names are kept as-is from the source
# relation; renaming is handled by record_mapper.py.
#
# Ordering convention: primary sort is the event-time column ASC; tie-breaker
# is trace_id ASC (and span_id ASC where the grain is span-level) to ensure
# stable, deterministic ordering across pages and replays.

_SQL_TRACE_LATENCY = """\
SELECT
    trace_id,
    trace_duration_ms,
    root_span_name,
    root_service_name,
    trace_start_time,
    has_error
FROM analytics.mart_trace_metrics
WHERE root_service_name = %(service_name)s
  AND root_span_name    = %(operation_name)s
  AND trace_start_time >= %(window_start)s
  AND trace_start_time  < %(window_end)s
ORDER BY trace_start_time ASC, trace_id ASC
"""

_SQL_AGENT_LATENCY = """\
SELECT
    trace_id,
    span_id,
    service_name,
    span_name,
    duration_ms,
    start_time,
    is_error_span
FROM analytics.mart_agent_metrics
WHERE service_name = %(service_name)s
  AND span_name    = %(operation_name)s
  AND start_time  >= %(window_start)s
  AND start_time   < %(window_end)s
ORDER BY start_time ASC, trace_id ASC, span_id ASC
"""

# Tool latency uses stg_telemetry_spans, NOT mart_tool_metrics.
# mart_tool_metrics filters to tool_name IS NOT NULL, which excludes error
# spans where tool_name is NULL.  stg_telemetry_spans preserves all
# tool.execute spans so error durations are included in the history.
_SQL_TOOL_LATENCY = """\
SELECT
    trace_id,
    span_id,
    service_name,
    span_name,
    duration_ms,
    start_time,
    is_error_span
FROM analytics.stg_telemetry_spans
WHERE span_name    = 'tool.execute'
  AND service_name = %(service_name)s
  AND start_time  >= %(window_start)s
  AND start_time   < %(window_end)s
ORDER BY start_time ASC, trace_id ASC, span_id ASC
"""

_SQL_RETRIEVAL = """\
SELECT
    trace_id,
    span_id,
    service_name,
    retrieval_top_relevance_score,
    retrieval_result_count,
    start_time,
    is_error_span
FROM analytics.mart_retrieval_metrics
WHERE service_name = %(service_name)s
  AND start_time  >= %(window_start)s
  AND start_time   < %(window_end)s
ORDER BY start_time ASC, trace_id ASC, span_id ASC
"""

# Error-rate history uses stg_telemetry_spans, NOT mart_error_events.
# ErrorRateDetector requires both error and non-error spans to compute
# rate denominators.  mart_error_events is ERROR-only and cannot supply
# the denominator.  No filter on is_error_span — both values are required.
_SQL_ERROR_RATE = """\
SELECT
    trace_id,
    span_id,
    service_name,
    span_name,
    is_error_span,
    error_type,
    start_time
FROM analytics.stg_telemetry_spans
WHERE service_name = %(service_name)s
  AND span_name    = %(operation_name)s
  AND start_time  >= %(window_start)s
  AND start_time   < %(window_end)s
ORDER BY start_time ASC, trace_id ASC, span_id ASC
"""

# Tool failure uses stg_telemetry_spans, NOT mart_tool_metrics.
# ToolFailureDetector needs both successful and failed tool.execute spans:
#   - successful spans provide the denominator for rate computation
#   - failed spans (is_error_span=True) are the numerator
# mart_tool_metrics excludes spans where tool_name IS NULL, which drops
# error spans.  No filter on is_error_span or tool_name.
_SQL_TOOL_FAILURE = """\
SELECT
    trace_id,
    span_id,
    service_name,
    is_error_span,
    error_type,
    start_time
FROM analytics.stg_telemetry_spans
WHERE span_name    = 'tool.execute'
  AND service_name = %(service_name)s
  AND start_time  >= %(window_start)s
  AND start_time   < %(window_end)s
ORDER BY start_time ASC, trace_id ASC, span_id ASC
"""


# ---------------------------------------------------------------------------
# Public query functions
# ---------------------------------------------------------------------------

def fetch_trace_latency_history(
    conn: psycopg.Connection,
    *,
    service_name: str,
    operation_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch trace-level latency history from analytics.mart_trace_metrics.

    Returns rows whose trace_start_time falls in [window_start, window_end).
    Filtered to (root_service_name, root_span_name) matching the supplied
    (service_name, operation_name) — the grouping LatencyDetector uses for
    trace-level observations.

    Rows ordered trace_start_time ASC, trace_id ASC.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            _SQL_TRACE_LATENCY,
            {
                "service_name": service_name,
                "operation_name": operation_name,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
        return cur.fetchall()


def fetch_agent_latency_history(
    conn: psycopg.Connection,
    *,
    service_name: str,
    operation_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch agent-span latency history from analytics.mart_agent_metrics.

    Returns rows whose start_time falls in [window_start, window_end).
    Filtered to (service_name, span_name) — the grouping LatencyDetector uses
    for agent-span observations.

    Rows ordered start_time ASC, trace_id ASC, span_id ASC.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            _SQL_AGENT_LATENCY,
            {
                "service_name": service_name,
                "operation_name": operation_name,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
        return cur.fetchall()


def fetch_tool_latency_history(
    conn: psycopg.Connection,
    *,
    service_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch tool-span latency history from analytics.stg_telemetry_spans.

    Filtered to span_name = 'tool.execute' and service_name.  Error spans
    (tool_name IS NULL) are preserved because LatencyDetector's exclude_errors
    flag handles them at detection time, not at query time.

    Rows ordered start_time ASC, trace_id ASC, span_id ASC.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            _SQL_TOOL_LATENCY,
            {
                "service_name": service_name,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
        return cur.fetchall()


def fetch_retrieval_history(
    conn: psycopg.Connection,
    *,
    service_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch retrieval-span history from analytics.mart_retrieval_metrics.

    Returns rows whose start_time falls in [window_start, window_end).
    Filtered to service_name — the sole grouping RetrievalQualityDetector uses.

    retrieval_result_count = 0 and retrieval_top_relevance_score = 0.0 are
    valid signal values and are preserved as-is by the dict_row row factory.

    Rows ordered start_time ASC, trace_id ASC, span_id ASC.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            _SQL_RETRIEVAL,
            {
                "service_name": service_name,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
        return cur.fetchall()


def fetch_error_rate_history(
    conn: psycopg.Connection,
    *,
    service_name: str,
    operation_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch error-rate observation history from analytics.stg_telemetry_spans.

    Returns ALL spans (error and non-error) for the (service_name, span_name)
    group whose start_time falls in [window_start, window_end).  ErrorRateDetector
    requires both error and non-error observations to compute rate denominators.

    Rows ordered start_time ASC, trace_id ASC, span_id ASC.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            _SQL_ERROR_RATE,
            {
                "service_name": service_name,
                "operation_name": operation_name,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
        return cur.fetchall()


def fetch_tool_failure_history(
    conn: psycopg.Connection,
    *,
    service_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[dict[str, Any]]:
    """
    Fetch tool-execution history from analytics.stg_telemetry_spans.

    Returns ALL tool.execute spans (success and failure) for service_name whose
    start_time falls in [window_start, window_end).  ToolFailureDetector requires
    both successful and failed spans for rate computation and persistence analysis.

    Rows ordered start_time ASC, trace_id ASC, span_id ASC.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            _SQL_TOOL_FAILURE,
            {
                "service_name": service_name,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
        return cur.fetchall()

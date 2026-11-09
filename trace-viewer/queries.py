"""
trace-viewer/queries.py

PostgreSQL data-access layer for the trace viewer.

All functions accept a psycopg.Connection and use %(name)s parameter binding.
No filter values are interpolated into SQL strings.

Public API:
    TraceListResult            — structured result of list_traces()
    list_traces()              → TraceListResult   paginated traces + total count
    fetch_trace_spans()        → list[SpanRecord]  all spans for one trace
    get_trace_reconstruction() → TraceReconstruction  full tree for one trace
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import psycopg
import psycopg.rows

from reconstruction import SpanRecord, TraceReconstruction, build_trace_tree

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class TraceListResult:
    """Structured result of list_traces().

    total  — number of traces matching the has_error filter before pagination.
    traces — rows for the current page, ordered trace_start_time DESC, trace_id ASC.
    """
    total: int
    traces: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# SQL fragments
# ---------------------------------------------------------------------------

# All 16 columns from analytics.int_trace_spans, plus the derived is_demo_data flag.
_LIST_TRACES_SELECT = """\
SELECT
    trace_id,
    trace_start_time,
    trace_end_time,
    trace_duration_ms,
    root_span_id,
    root_span_name,
    root_service_name,
    request_id,
    session_id,
    span_count,
    service_count,
    error_span_count,
    agent_span_count,
    tool_span_count,
    retrieval_span_count,
    has_error,
    EXISTS (
        SELECT 1 FROM analytics.stg_telemetry_spans AS demo_s
        WHERE demo_s.trace_id = int_trace_spans.trace_id
          AND demo_s.attributes ->> 'demo_seed' IS NOT NULL
    ) AS is_demo_data
FROM analytics.int_trace_spans
"""

# Fixed literal WHERE clause when has_error filter is active.
# The value is always bound as a psycopg parameter — never interpolated.
_LIST_TRACES_WHERE_HAS_ERROR = "WHERE has_error = %(has_error)s\n"

# Deterministic ordering: primary trace_start_time DESC, trace_id ASC as
# tie-breaker so pages are stable when multiple traces share a start time.
_LIST_TRACES_ORDER = "ORDER BY trace_start_time DESC, trace_id ASC\n"

#: Characters of each free-text span column read from PostgreSQL: one more than the
#: API's limit (app.MAX_TEXT_CHARS, 2,000) so that a value of exactly 2,000
#: characters is told apart from a longer one.  The database does the shortening
#: (left() counts characters, as Python's len() does), so a very long value is
#: never transferred.  Kept equal to app.MAX_TEXT_CHARS + 1 by a unit test.
TEXT_FETCH_CHARS: int = 2001

_FETCH_SPANS_SQL = f"""\
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
    left(status_message, {TEXT_FETCH_CHARS}) AS status_message,
    request_id,
    session_id,
    gen_ai_operation,
    agent_name,
    agent_operation,
    tool_name,
    tool_status,
    retrieval_result_count,
    retrieval_top_relevance_score,
    error_type,
    left(error_message, {TEXT_FETCH_CHARS}) AS error_message,
    (attributes ->> 'demo_seed' IS NOT NULL) AS is_demo_data
FROM analytics.stg_telemetry_spans
WHERE trace_id = %(trace_id)s
"""

# Appended to _FETCH_SPANS_SQL only when the caller limits the number of spans:
# a deterministic order, so the spans kept are always the earliest ones.
_FETCH_SPANS_LIMITED_TAIL = "ORDER BY start_time ASC, span_id ASC\nLIMIT %(limit)s"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _validate_trace_id(trace_id: str) -> None:
    """Raise ValueError if trace_id is not a 32-character lowercase hex string."""
    if not isinstance(trace_id, str) or not _TRACE_ID_RE.match(trace_id):
        raise ValueError(
            f"trace_id must be a 32-character lowercase hex string, got {trace_id!r}"
        )


# ---------------------------------------------------------------------------
# Row mapping
# ---------------------------------------------------------------------------

def _row_to_span_record(row: dict[str, Any]) -> SpanRecord:
    """Map a psycopg dict_row to a SpanRecord."""
    return SpanRecord(
        span_id=row["span_id"],
        parent_span_id=row["parent_span_id"],
        span_name=row["span_name"],
        start_time=row["start_time"],
        end_time=row["end_time"],
        duration_ms=row["duration_ms"],
        status_code=row["status_code"],
        trace_id=row.get("trace_id"),
        service_name=row.get("service_name"),
        span_kind=row.get("span_kind"),
        status_message=row.get("status_message"),
        request_id=row.get("request_id"),
        session_id=row.get("session_id"),
        gen_ai_operation=row.get("gen_ai_operation"),
        agent_name=row.get("agent_name"),
        agent_operation=row.get("agent_operation"),
        tool_name=row.get("tool_name"),
        tool_status=row.get("tool_status"),
        retrieval_result_count=row.get("retrieval_result_count"),
        retrieval_top_relevance_score=row.get("retrieval_top_relevance_score"),
        error_type=row.get("error_type"),
        error_message=row.get("error_message"),
        is_demo_data=bool(row.get("is_demo_data", False)),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_traces(
    conn: psycopg.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    has_error: bool | None = None,
    service_name: str | None = None,
    request_id: str | None = None,
    session_id: str | None = None,
    min_duration_ms: float | None = None,
    max_duration_ms: float | None = None,
    search: str | None = None,
) -> TraceListResult:
    """
    Return a paginated page of traces from analytics.int_trace_spans.

    Both the count (for pagination) and the page rows respect all active
    filters. Two SQL statements are executed on a single cursor within the
    same function call: a COUNT for the total and a paginated SELECT for
    the rows.

    Args:
        conn:             Open psycopg connection with SELECT on
                          analytics.int_trace_spans.
        limit:            Maximum number of rows to return. Must be >= 1.
        offset:           Number of rows to skip. Must be >= 0.
        has_error:        None → all; True → error traces; False → healthy.
        service_name:     Filter by root_service_name (exact match).
        request_id:       Filter by request_id (exact match).
        session_id:       Filter by session_id (exact match).
        min_duration_ms:  Filter to traces with duration >= this value.
        max_duration_ms:  Filter to traces with duration <= this value.
        search:           OR-match across trace_id, request_id, session_id.

    All filter values are always passed as bound parameters; none are
    interpolated into the SQL string.

    Returns:
        TraceListResult with:
            total  — total traces matching active filters (before pagination).
            traces — rows for this page, each a dict of all 16 int_trace_spans
                     columns with native Python types.
        Ordering: trace_start_time DESC, trace_id ASC.

    Raises:
        ValueError     if limit < 1 or offset < 0.
        psycopg.Error  on any database error.
    """
    if limit < 1:
        raise ValueError(f"limit must be >= 1, got {limit}")
    if offset < 0:
        raise ValueError(f"offset must be >= 0, got {offset}")

    conditions: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if has_error is not None:
        conditions.append("has_error = %(has_error)s")
        params["has_error"] = has_error
    if service_name is not None:
        conditions.append("root_service_name = %(service_name)s")
        params["service_name"] = service_name
    if request_id is not None:
        conditions.append("request_id = %(request_id)s")
        params["request_id"] = request_id
    if session_id is not None:
        conditions.append("session_id = %(session_id)s")
        params["session_id"] = session_id
    if min_duration_ms is not None:
        conditions.append("trace_duration_ms >= %(min_duration_ms)s")
        params["min_duration_ms"] = min_duration_ms
    if max_duration_ms is not None:
        conditions.append("trace_duration_ms <= %(max_duration_ms)s")
        params["max_duration_ms"] = max_duration_ms
    if search is not None:
        conditions.append(
            "(trace_id LIKE %(search)s OR request_id LIKE %(search)s OR session_id LIKE %(search)s)"
        )
        params["search"] = search + "%"

    where = ("WHERE " + " AND ".join(conditions) + "\n") if conditions else ""

    count_sql = f"SELECT COUNT(*) FROM analytics.int_trace_spans\n{where}"
    page_sql = (
        f"{_LIST_TRACES_SELECT}"
        f"{where}"
        f"{_LIST_TRACES_ORDER}"
        "LIMIT %(limit)s OFFSET %(offset)s"
    )

    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(count_sql, params)
        total = cur.fetchone()["count"]

        cur.execute(page_sql, params)
        traces = cur.fetchall()

    return TraceListResult(total=total, traces=traces)


def _validate_max_spans(max_spans: int) -> None:
    """Raise ValueError unless max_spans is an int >= 1 (a bool is not accepted)."""
    if isinstance(max_spans, bool) or not isinstance(max_spans, int) or max_spans < 1:
        raise ValueError(f"max_spans must be an integer >= 1, got {max_spans!r}")


def fetch_trace_spans(
    conn: psycopg.Connection,
    trace_id: str,
    *,
    max_spans: int | None = None,
) -> list[SpanRecord]:
    """
    Return the spans of trace_id from analytics.stg_telemetry_spans.

    Args:
        conn:      Open psycopg connection with SELECT on
                   analytics.stg_telemetry_spans.
        trace_id:  32-character lowercase hex string.
        max_spans: None (default) reads every span, exactly as before.  An
                   integer >= 1 reads at most max_spans + 1 spans, earliest
                   first (start_time ASC, span_id ASC): the one extra span lets
                   the caller tell "exactly max_spans" from "more than
                   max_spans" without a second query.

    Returns:
        List of SpanRecord objects. Empty list if trace_id is not found.

    Raises:
        ValueError     if trace_id or max_spans fails validation.
        psycopg.Error  on any database error.
    """
    _validate_trace_id(trace_id)

    if max_spans is None:
        sql, params = _FETCH_SPANS_SQL, {"trace_id": trace_id}
    else:
        _validate_max_spans(max_spans)
        sql = _FETCH_SPANS_SQL + _FETCH_SPANS_LIMITED_TAIL
        params = {"trace_id": trace_id, "limit": max_spans + 1}

    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    return [_row_to_span_record(row) for row in rows]


def get_trace_reconstruction(
    conn: psycopg.Connection,
    trace_id: str,
    *,
    max_spans: int | None = None,
) -> TraceReconstruction:
    """
    Fetch the spans for trace_id and reconstruct the trace tree.

    Args:
        conn:      Open psycopg connection with SELECT on
                   analytics.stg_telemetry_spans.
        trace_id:  32-character lowercase hex string.
        max_spans: None (default) reconstructs every span, exactly as before.
                   An integer >= 1 reconstructs at most the first max_spans
                   spans (earliest first) and sets TraceReconstruction.truncated
                   when the trace has more.  A span whose parent is cut off is
                   reported as an orphan by the reconstruction, as for any span
                   whose parent is absent.

    Returns:
        TraceReconstruction. span_count == 0 if trace_id is not found.

    Raises:
        ValueError     if trace_id or max_spans fails validation.
        psycopg.Error  on any database error.
    """
    spans = fetch_trace_spans(conn, trace_id, max_spans=max_spans)
    truncated = max_spans is not None and len(spans) > max_spans
    if truncated:
        spans = spans[:max_spans]
    result = build_trace_tree(spans)
    result.truncated = truncated
    return result

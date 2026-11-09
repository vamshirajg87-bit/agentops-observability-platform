"""
Tests for anomaly-detector/telemetry_queries.py

No live PostgreSQL is required.  SQL behaviour is verified by inspecting the
module-level SQL string constants; connection/cursor behaviour is verified with
a lightweight mock.

Coverage:
    1. Source relation: each query targets the correct analytics relation
    2. Prohibited relations: tool queries never reference mart_tool_metrics;
       error-rate query never references mart_error_events;
       no query touches public.telemetry_spans
    3. Half-open bounds: >= window_start AND < window_end (strict upper bound)
    4. Parameter binding: %(name)s style; no f-string or %-format injection
    5. Grouping filters: service_name and/or operation_name present
    6. Deterministic ordering: ORDER BY event-time ASC plus tie-breaker
    7. Completeness: error-rate and tool-failure queries include success + failure
       (no is_error_span filter; no tool_name IS NOT NULL)
    8. No hardcoded lookback constant (e.g. 8-day buffer)
    9. Function call behaviour: cursor receives correct SQL and params
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from telemetry_queries import (
    _SQL_AGENT_LATENCY,
    _SQL_ERROR_RATE,
    _SQL_RETRIEVAL,
    _SQL_TOOL_FAILURE,
    _SQL_TOOL_LATENCY,
    _SQL_TRACE_LATENCY,
    fetch_agent_latency_history,
    fetch_error_rate_history,
    fetch_retrieval_history,
    fetch_tool_failure_history,
    fetch_tool_latency_history,
    fetch_trace_latency_history,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_TS2 = datetime(2024, 6, 8, 12, 0, 0, tzinfo=timezone.utc)


def _make_conn(rows: list | None = None) -> MagicMock:
    """Return a mock psycopg connection whose cursor.fetchall() returns rows."""
    rows = rows or []
    cur = MagicMock()
    cur.fetchall.return_value = rows
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn


def _executed_sql(conn: MagicMock) -> str:
    """Return the SQL string passed to the first cursor.execute() call."""
    return conn.cursor.return_value.execute.call_args[0][0]


def _executed_params(conn: MagicMock) -> dict:
    """Return the params dict passed to the first cursor.execute() call."""
    return conn.cursor.return_value.execute.call_args[0][1]


# ---------------------------------------------------------------------------
# 1. Trace latency query
# ---------------------------------------------------------------------------

class TestTraceLatencySQL:

    def test_source_relation(self):
        assert "analytics.mart_trace_metrics" in _SQL_TRACE_LATENCY

    def test_does_not_reference_mart_tool_metrics(self):
        assert "mart_tool_metrics" not in _SQL_TRACE_LATENCY

    def test_does_not_reference_mart_error_events(self):
        assert "mart_error_events" not in _SQL_TRACE_LATENCY

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_TRACE_LATENCY

    def test_half_open_lower_bound(self):
        assert ">= %(window_start)s" in _SQL_TRACE_LATENCY

    def test_strict_upper_bound(self):
        assert "< %(window_end)s" in _SQL_TRACE_LATENCY

    def test_no_lte_upper_bound(self):
        assert "<= %(window_end)s" not in _SQL_TRACE_LATENCY

    def test_service_name_filter(self):
        assert "%(service_name)s" in _SQL_TRACE_LATENCY

    def test_operation_name_filter(self):
        assert "%(operation_name)s" in _SQL_TRACE_LATENCY

    def test_order_by_event_time_asc(self):
        assert re.search(r"ORDER BY\s+trace_start_time\s+ASC", _SQL_TRACE_LATENCY)

    def test_order_by_has_tie_breaker(self):
        assert "trace_id ASC" in _SQL_TRACE_LATENCY

    def test_no_arbitrary_day_constant(self):
        assert "8" not in re.findall(r"\b8\b", _SQL_TRACE_LATENCY)

    def test_parameter_binding_used(self):
        for param in ("%(service_name)s", "%(operation_name)s",
                      "%(window_start)s", "%(window_end)s"):
            assert param in _SQL_TRACE_LATENCY


class TestTraceLatencyFunction:

    def test_returns_rows_from_fetchall(self):
        expected = [{"trace_id": "a" * 32, "trace_duration_ms": 100.0}]
        conn = _make_conn(rows=expected)
        result = fetch_trace_latency_history(
            conn, service_name="svc", operation_name="op",
            window_start=_TS, window_end=_TS2,
        )
        assert result == expected

    def test_params_forwarded(self):
        conn = _make_conn()
        fetch_trace_latency_history(
            conn, service_name="my-svc", operation_name="my-op",
            window_start=_TS, window_end=_TS2,
        )
        params = _executed_params(conn)
        assert params["service_name"] == "my-svc"
        assert params["operation_name"] == "my-op"
        assert params["window_start"] == _TS
        assert params["window_end"] == _TS2


# ---------------------------------------------------------------------------
# 2. Agent latency query
# ---------------------------------------------------------------------------

class TestAgentLatencySQL:

    def test_source_relation(self):
        assert "analytics.mart_agent_metrics" in _SQL_AGENT_LATENCY

    def test_does_not_reference_mart_tool_metrics(self):
        assert "mart_tool_metrics" not in _SQL_AGENT_LATENCY

    def test_does_not_reference_mart_error_events(self):
        assert "mart_error_events" not in _SQL_AGENT_LATENCY

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_AGENT_LATENCY

    def test_half_open_lower_bound(self):
        assert ">= %(window_start)s" in _SQL_AGENT_LATENCY

    def test_strict_upper_bound(self):
        assert "< %(window_end)s" in _SQL_AGENT_LATENCY

    def test_no_lte_upper_bound(self):
        assert "<= %(window_end)s" not in _SQL_AGENT_LATENCY

    def test_service_name_filter(self):
        assert "%(service_name)s" in _SQL_AGENT_LATENCY

    def test_operation_name_filter(self):
        assert "%(operation_name)s" in _SQL_AGENT_LATENCY

    def test_order_by_event_time_asc(self):
        assert re.search(r"ORDER BY\s+start_time\s+ASC", _SQL_AGENT_LATENCY)

    def test_order_by_has_span_tie_breaker(self):
        assert "trace_id ASC" in _SQL_AGENT_LATENCY
        assert "span_id ASC" in _SQL_AGENT_LATENCY


# ---------------------------------------------------------------------------
# 3. Tool latency query
# ---------------------------------------------------------------------------

class TestToolLatencySQL:

    def test_source_relation(self):
        assert "analytics.stg_telemetry_spans" in _SQL_TOOL_LATENCY

    def test_does_not_reference_mart_tool_metrics(self):
        assert "mart_tool_metrics" not in _SQL_TOOL_LATENCY

    def test_does_not_reference_mart_error_events(self):
        assert "mart_error_events" not in _SQL_TOOL_LATENCY

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_TOOL_LATENCY

    def test_filters_on_tool_execute_span_name(self):
        assert "'tool.execute'" in _SQL_TOOL_LATENCY

    def test_no_tool_name_is_not_null(self):
        assert "tool_name IS NOT NULL" not in _SQL_TOOL_LATENCY
        assert "tool_name is not null" not in _SQL_TOOL_LATENCY.lower()

    def test_half_open_lower_bound(self):
        assert ">= %(window_start)s" in _SQL_TOOL_LATENCY

    def test_strict_upper_bound(self):
        assert "< %(window_end)s" in _SQL_TOOL_LATENCY

    def test_no_lte_upper_bound(self):
        assert "<= %(window_end)s" not in _SQL_TOOL_LATENCY

    def test_service_name_filter(self):
        assert "%(service_name)s" in _SQL_TOOL_LATENCY

    def test_order_by_event_time_asc(self):
        assert re.search(r"ORDER BY\s+start_time\s+ASC", _SQL_TOOL_LATENCY)

    def test_order_by_has_span_tie_breaker(self):
        assert "trace_id ASC" in _SQL_TOOL_LATENCY
        assert "span_id ASC" in _SQL_TOOL_LATENCY


# ---------------------------------------------------------------------------
# 4. Retrieval history query
# ---------------------------------------------------------------------------

class TestRetrievalSQL:

    def test_source_relation(self):
        assert "analytics.mart_retrieval_metrics" in _SQL_RETRIEVAL

    def test_does_not_reference_mart_tool_metrics(self):
        assert "mart_tool_metrics" not in _SQL_RETRIEVAL

    def test_does_not_reference_mart_error_events(self):
        assert "mart_error_events" not in _SQL_RETRIEVAL

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_RETRIEVAL

    def test_half_open_lower_bound(self):
        assert ">= %(window_start)s" in _SQL_RETRIEVAL

    def test_strict_upper_bound(self):
        assert "< %(window_end)s" in _SQL_RETRIEVAL

    def test_no_lte_upper_bound(self):
        assert "<= %(window_end)s" not in _SQL_RETRIEVAL

    def test_service_name_filter(self):
        assert "%(service_name)s" in _SQL_RETRIEVAL

    def test_order_by_event_time_asc(self):
        assert re.search(r"ORDER BY\s+start_time\s+ASC", _SQL_RETRIEVAL)

    def test_order_by_has_span_tie_breaker(self):
        assert "trace_id ASC" in _SQL_RETRIEVAL
        assert "span_id ASC" in _SQL_RETRIEVAL

    def test_selects_retrieval_result_count(self):
        assert "retrieval_result_count" in _SQL_RETRIEVAL

    def test_selects_retrieval_top_relevance_score(self):
        assert "retrieval_top_relevance_score" in _SQL_RETRIEVAL


# ---------------------------------------------------------------------------
# 5. Error-rate history query
# ---------------------------------------------------------------------------

class TestErrorRateSQL:

    def test_source_relation(self):
        assert "analytics.stg_telemetry_spans" in _SQL_ERROR_RATE

    def test_does_not_reference_mart_error_events(self):
        assert "mart_error_events" not in _SQL_ERROR_RATE

    def test_does_not_reference_mart_tool_metrics(self):
        assert "mart_tool_metrics" not in _SQL_ERROR_RATE

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_ERROR_RATE

    def test_no_is_error_span_filter(self):
        # The query must include both error and non-error rows.
        # A WHERE clause filtering on is_error_span would exclude success rows.
        # is_error_span may appear in SELECT — only flag if it appears in WHERE.
        where_clause = _SQL_ERROR_RATE.split("WHERE", 1)[1] if "WHERE" in _SQL_ERROR_RATE else ""
        order_removed = where_clause.split("ORDER BY")[0] if "ORDER BY" in where_clause else where_clause
        assert "is_error_span" not in order_removed

    def test_half_open_lower_bound(self):
        assert ">= %(window_start)s" in _SQL_ERROR_RATE

    def test_strict_upper_bound(self):
        assert "< %(window_end)s" in _SQL_ERROR_RATE

    def test_no_lte_upper_bound(self):
        assert "<= %(window_end)s" not in _SQL_ERROR_RATE

    def test_service_name_filter(self):
        assert "%(service_name)s" in _SQL_ERROR_RATE

    def test_operation_name_filter(self):
        assert "%(operation_name)s" in _SQL_ERROR_RATE

    def test_order_by_event_time_asc(self):
        assert re.search(r"ORDER BY\s+start_time\s+ASC", _SQL_ERROR_RATE)

    def test_order_by_has_span_tie_breaker(self):
        assert "trace_id ASC" in _SQL_ERROR_RATE
        assert "span_id ASC" in _SQL_ERROR_RATE

    def test_no_tool_name_is_not_null(self):
        assert "tool_name IS NOT NULL" not in _SQL_ERROR_RATE


# ---------------------------------------------------------------------------
# 6. Tool failure history query
# ---------------------------------------------------------------------------

class TestToolFailureSQL:

    def test_source_relation(self):
        assert "analytics.stg_telemetry_spans" in _SQL_TOOL_FAILURE

    def test_does_not_reference_mart_tool_metrics(self):
        assert "mart_tool_metrics" not in _SQL_TOOL_FAILURE

    def test_does_not_reference_mart_error_events(self):
        assert "mart_error_events" not in _SQL_TOOL_FAILURE

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_TOOL_FAILURE

    def test_filters_on_tool_execute_span_name(self):
        assert "'tool.execute'" in _SQL_TOOL_FAILURE

    def test_no_tool_name_is_not_null(self):
        assert "tool_name IS NOT NULL" not in _SQL_TOOL_FAILURE
        assert "tool_name is not null" not in _SQL_TOOL_FAILURE.lower()

    def test_no_is_error_span_filter(self):
        # Both success and failure tool.execute spans are needed.
        where_clause = _SQL_TOOL_FAILURE.split("WHERE", 1)[1] if "WHERE" in _SQL_TOOL_FAILURE else ""
        order_removed = where_clause.split("ORDER BY")[0] if "ORDER BY" in where_clause else where_clause
        assert "is_error_span" not in order_removed

    def test_half_open_lower_bound(self):
        assert ">= %(window_start)s" in _SQL_TOOL_FAILURE

    def test_strict_upper_bound(self):
        assert "< %(window_end)s" in _SQL_TOOL_FAILURE

    def test_no_lte_upper_bound(self):
        assert "<= %(window_end)s" not in _SQL_TOOL_FAILURE

    def test_service_name_filter(self):
        assert "%(service_name)s" in _SQL_TOOL_FAILURE

    def test_order_by_event_time_asc(self):
        assert re.search(r"ORDER BY\s+start_time\s+ASC", _SQL_TOOL_FAILURE)

    def test_order_by_has_span_tie_breaker(self):
        assert "trace_id ASC" in _SQL_TOOL_FAILURE
        assert "span_id ASC" in _SQL_TOOL_FAILURE


# ---------------------------------------------------------------------------
# 7. Cross-query safety invariants
# ---------------------------------------------------------------------------

class TestCrossQuerySafety:

    _ALL_SQL = [
        _SQL_TRACE_LATENCY,
        _SQL_AGENT_LATENCY,
        _SQL_TOOL_LATENCY,
        _SQL_RETRIEVAL,
        _SQL_ERROR_RATE,
        _SQL_TOOL_FAILURE,
    ]

    def test_no_query_references_public_telemetry_spans(self):
        for sql in self._ALL_SQL:
            assert "public.telemetry_spans" not in sql, (
                f"Query references public.telemetry_spans directly: {sql[:80]!r}"
            )

    def test_no_query_has_arbitrary_8_day_literal(self):
        # Ensure no query embeds a hardcoded lookback constant such as
        # INTERVAL '8 days' or similar.  Bounds come from caller parameters.
        for sql in self._ALL_SQL:
            assert "INTERVAL" not in sql.upper(), (
                f"Query contains INTERVAL (hardcoded window): {sql[:80]!r}"
            )

    def test_all_queries_use_parameter_binding(self):
        for sql in self._ALL_SQL:
            assert "%(window_start)s" in sql
            assert "%(window_end)s" in sql

    def test_no_query_uses_lte_upper_bound(self):
        for sql in self._ALL_SQL:
            assert "<= %(window_end)s" not in sql, (
                f"Query uses non-strict upper bound: {sql[:80]!r}"
            )


# ---------------------------------------------------------------------------
# 8. Function behaviour: params forwarded, fetchall called
# ---------------------------------------------------------------------------

class TestFunctionParamForwarding:

    def test_fetch_agent_latency_history_params(self):
        conn = _make_conn()
        fetch_agent_latency_history(
            conn, service_name="s", operation_name="op",
            window_start=_TS, window_end=_TS2,
        )
        p = _executed_params(conn)
        assert p == {"service_name": "s", "operation_name": "op",
                     "window_start": _TS, "window_end": _TS2}

    def test_fetch_tool_latency_history_params(self):
        conn = _make_conn()
        fetch_tool_latency_history(
            conn, service_name="s", window_start=_TS, window_end=_TS2,
        )
        p = _executed_params(conn)
        assert p == {"service_name": "s", "window_start": _TS, "window_end": _TS2}

    def test_fetch_retrieval_history_params(self):
        conn = _make_conn()
        fetch_retrieval_history(
            conn, service_name="svc-r", window_start=_TS, window_end=_TS2,
        )
        p = _executed_params(conn)
        assert p == {"service_name": "svc-r", "window_start": _TS, "window_end": _TS2}

    def test_fetch_error_rate_history_params(self):
        conn = _make_conn()
        fetch_error_rate_history(
            conn, service_name="svc-e", operation_name="span.op",
            window_start=_TS, window_end=_TS2,
        )
        p = _executed_params(conn)
        assert p == {"service_name": "svc-e", "operation_name": "span.op",
                     "window_start": _TS, "window_end": _TS2}

    def test_fetch_tool_failure_history_params(self):
        conn = _make_conn()
        fetch_tool_failure_history(
            conn, service_name="svc-tf", window_start=_TS, window_end=_TS2,
        )
        p = _executed_params(conn)
        assert p == {"service_name": "svc-tf", "window_start": _TS, "window_end": _TS2}

    def test_all_functions_return_list(self):
        rows = [{"col": "val"}]
        for fn, kwargs in [
            (fetch_trace_latency_history,
             {"service_name": "s", "operation_name": "o",
              "window_start": _TS, "window_end": _TS2}),
            (fetch_agent_latency_history,
             {"service_name": "s", "operation_name": "o",
              "window_start": _TS, "window_end": _TS2}),
            (fetch_tool_latency_history,
             {"service_name": "s", "window_start": _TS, "window_end": _TS2}),
            (fetch_retrieval_history,
             {"service_name": "s", "window_start": _TS, "window_end": _TS2}),
            (fetch_error_rate_history,
             {"service_name": "s", "operation_name": "o",
              "window_start": _TS, "window_end": _TS2}),
            (fetch_tool_failure_history,
             {"service_name": "s", "window_start": _TS, "window_end": _TS2}),
        ]:
            conn = _make_conn(rows=rows)
            result = fn(conn, **kwargs)
            assert result == rows

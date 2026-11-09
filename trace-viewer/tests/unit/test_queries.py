"""
trace-viewer/tests/unit/test_queries.py

Unit tests for queries.py.

All tests are offline — no live database connection required. The psycopg
Connection is replaced by a MagicMock whose cursor context manager returns
controlled row data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

from queries import (
    TraceListResult,
    _LIST_TRACES_ORDER,
    _LIST_TRACES_WHERE_HAS_ERROR,
    _row_to_span_record,
    _validate_trace_id,
    fetch_trace_spans,
    get_trace_reconstruction,
    list_traces,
)
from reconstruction import TraceReconstruction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_TRACE_ID = "a" * 32  # 32 lowercase hex chars


def _dt() -> datetime:
    return datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _minimal_span_row(
    span_id: str = "s1",
    parent_span_id: str | None = None,
    **extra,
) -> dict:
    """Minimal row dict with all required SpanRecord fields."""
    return {
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "span_name": "test.span",
        "start_time": _dt(),
        "end_time": _dt(),
        "duration_ms": 10.0,
        "status_code": "OK",
        **extra,
    }


class _MockCursor:
    """
    Simulates a psycopg cursor for testing list_traces(), which calls
    execute() twice on the same cursor:
        1. count_sql  → fetchone() returns {"count": count_value}
        2. page_sql   → fetchall() returns page_rows

    Also captures every (sql, params) pair passed to execute().
    """

    def __init__(self, count_value: int, page_rows: list[dict]) -> None:
        self._count_value = count_value
        self._page_rows = page_rows
        self.execute_calls: list[tuple[str, dict]] = []

    def execute(self, sql: str, params: dict) -> None:
        self.execute_calls.append((sql, params))

    def fetchone(self) -> dict:
        return {"count": self._count_value}

    def fetchall(self) -> list[dict]:
        return self._page_rows

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _make_conn_for_list(
    count_value: int = 0,
    page_rows: list[dict] | None = None,
) -> tuple[MagicMock, _MockCursor]:
    """Return (conn, cursor) wired for list_traces()."""
    cur = _MockCursor(count_value, page_rows or [])
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def _make_conn_for_fetch(rows: list[dict]) -> tuple[MagicMock, MagicMock]:
    """Return (conn, cursor) wired for fetch_trace_spans() / get_trace_reconstruction()."""
    cur = MagicMock()
    cur.fetchall.return_value = rows

    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=cur)
    ctx.__exit__ = MagicMock(return_value=False)

    conn = MagicMock()
    conn.cursor.return_value = ctx

    return conn, cur


# ---------------------------------------------------------------------------
# _validate_trace_id
# ---------------------------------------------------------------------------

class TestValidateTraceId:
    def test_valid_32_hex_lower(self):
        _validate_trace_id("0" * 32)
        _validate_trace_id("a" * 32)
        _validate_trace_id("f" * 32)
        _validate_trace_id("0123456789abcdef" * 2)

    def test_rejects_uppercase(self):
        with pytest.raises(ValueError):
            _validate_trace_id("A" * 32)

    def test_rejects_31_chars(self):
        with pytest.raises(ValueError):
            _validate_trace_id("a" * 31)

    def test_rejects_33_chars(self):
        with pytest.raises(ValueError):
            _validate_trace_id("a" * 33)

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError):
            _validate_trace_id("")

    def test_rejects_non_hex(self):
        with pytest.raises(ValueError):
            _validate_trace_id("g" * 32)

    def test_rejects_spaces(self):
        with pytest.raises(ValueError):
            _validate_trace_id(" " * 32)

    def test_rejects_non_string(self):
        with pytest.raises(ValueError):
            _validate_trace_id(None)  # type: ignore[arg-type]

    def test_rejects_int(self):
        with pytest.raises(ValueError):
            _validate_trace_id(12345678901234567890123456789012)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _row_to_span_record
# ---------------------------------------------------------------------------

class TestRowToSpanRecord:
    def test_required_fields_mapped(self):
        row = _minimal_span_row("sp1")
        span = _row_to_span_record(row)
        assert span.span_id == "sp1"
        assert span.parent_span_id is None
        assert span.span_name == "test.span"
        assert span.duration_ms == 10.0
        assert span.status_code == "OK"

    def test_optional_fields_none_when_absent(self):
        row = _minimal_span_row()
        span = _row_to_span_record(row)
        assert span.trace_id is None
        assert span.service_name is None
        assert span.span_kind is None
        assert span.agent_name is None
        assert span.tool_name is None
        assert span.retrieval_result_count is None
        assert span.retrieval_top_relevance_score is None
        assert span.error_type is None
        assert span.error_message is None

    def test_optional_fields_populated(self):
        row = _minimal_span_row(
            trace_id=_VALID_TRACE_ID,
            service_name="my-service",
            span_kind="INTERNAL",
            agent_name="agent1",
            tool_name="search",
            tool_status="success",
            retrieval_result_count=5,
            retrieval_top_relevance_score=0.95,
            error_type="TimeoutError",
            error_message="timed out",
        )
        span = _row_to_span_record(row)
        assert span.trace_id == _VALID_TRACE_ID
        assert span.service_name == "my-service"
        assert span.span_kind == "INTERNAL"
        assert span.agent_name == "agent1"
        assert span.tool_name == "search"
        assert span.tool_status == "success"
        assert span.retrieval_result_count == 5
        assert span.retrieval_top_relevance_score == 0.95
        assert span.error_type == "TimeoutError"
        assert span.error_message == "timed out"

    def test_parent_span_id_preserved(self):
        row = _minimal_span_row("child", parent_span_id="parent1")
        span = _row_to_span_record(row)
        assert span.parent_span_id == "parent1"

    def test_start_end_time_preserved(self):
        t = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        row = _minimal_span_row()
        row["start_time"] = t
        row["end_time"] = t
        span = _row_to_span_record(row)
        assert span.start_time == t
        assert span.end_time == t


# ---------------------------------------------------------------------------
# list_traces — return type and basic structure
# ---------------------------------------------------------------------------

class TestListTracesReturnType:
    def test_returns_trace_list_result(self):
        conn, _ = _make_conn_for_list(count_value=0, page_rows=[])
        result = list_traces(conn)
        assert isinstance(result, TraceListResult)

    def test_result_has_total_and_traces(self):
        page = [{"trace_id": _VALID_TRACE_ID}]
        conn, _ = _make_conn_for_list(count_value=1, page_rows=page)
        result = list_traces(conn)
        assert result.total == 1
        assert result.traces == page

    def test_empty_result(self):
        conn, _ = _make_conn_for_list(count_value=0, page_rows=[])
        result = list_traces(conn)
        assert result.total == 0
        assert result.traces == []


# ---------------------------------------------------------------------------
# list_traces — total reflects filter, not page size
# ---------------------------------------------------------------------------

class TestListTracesTotal:
    def test_total_mapped_from_count_query(self):
        conn, _ = _make_conn_for_list(count_value=42, page_rows=[])
        result = list_traces(conn)
        assert result.total == 42

    def test_total_can_exceed_page_size(self):
        # 100 total, but only 1 row on this page (limit=1, offset=50)
        conn, _ = _make_conn_for_list(count_value=100, page_rows=[{"x": 1}])
        result = list_traces(conn, limit=1, offset=50)
        assert result.total == 100
        assert len(result.traces) == 1


# ---------------------------------------------------------------------------
# list_traces — has_error filter
# ---------------------------------------------------------------------------

class TestListTracesHasErrorFilter:
    def test_no_filter_sends_no_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        count_sql, _ = cur.execute_calls[0]
        page_sql, _ = cur.execute_calls[1]
        assert "WHERE" not in count_sql
        # the demo-flag subquery has its own WHERE; the outer query must have none
        assert "WHERE" not in page_sql.split("FROM analytics.int_trace_spans")[-1]

    def test_has_error_true_sends_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, has_error=True)
        count_sql, count_params = cur.execute_calls[0]
        page_sql, page_params = cur.execute_calls[1]
        assert "WHERE" in count_sql
        assert "WHERE" in page_sql
        assert count_params["has_error"] is True
        assert page_params["has_error"] is True

    def test_has_error_false_sends_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, has_error=False)
        count_sql, count_params = cur.execute_calls[0]
        page_sql, page_params = cur.execute_calls[1]
        assert "WHERE" in count_sql
        assert "WHERE" in page_sql
        assert count_params["has_error"] is False
        assert page_params["has_error"] is False

    def test_has_error_value_is_bound_not_interpolated(self):
        # The WHERE fragment must use %(has_error)s, not a bare True/False
        assert "%(has_error)s" in _LIST_TRACES_WHERE_HAS_ERROR
        # No literal Python True/False in the SQL fragment
        assert "True" not in _LIST_TRACES_WHERE_HAS_ERROR
        assert "False" not in _LIST_TRACES_WHERE_HAS_ERROR

    def test_count_and_page_both_receive_has_error_param(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, has_error=True)
        assert len(cur.execute_calls) == 2
        _, count_params = cur.execute_calls[0]
        _, page_params = cur.execute_calls[1]
        assert "has_error" in count_params
        assert "has_error" in page_params

    def test_no_filter_has_error_not_in_params(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        _, count_params = cur.execute_calls[0]
        _, page_params = cur.execute_calls[1]
        assert "has_error" not in count_params
        assert "has_error" not in page_params


# ---------------------------------------------------------------------------
# list_traces — pagination parameter binding
# ---------------------------------------------------------------------------

class TestListTracesPagination:
    def test_default_limit_and_offset_bound(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        _, page_params = cur.execute_calls[1]
        assert page_params["limit"] == 50
        assert page_params["offset"] == 0

    def test_custom_limit_and_offset_bound(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, limit=10, offset=20)
        _, page_params = cur.execute_calls[1]
        assert page_params["limit"] == 10
        assert page_params["offset"] == 20

    def test_count_query_does_not_use_limit_offset(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, limit=5, offset=10)
        count_sql, _ = cur.execute_calls[0]
        assert "LIMIT" not in count_sql
        assert "OFFSET" not in count_sql

    def test_limit_zero_raises(self):
        conn, _ = _make_conn_for_list()
        with pytest.raises(ValueError, match="limit"):
            list_traces(conn, limit=0)

    def test_limit_negative_raises(self):
        conn, _ = _make_conn_for_list()
        with pytest.raises(ValueError, match="limit"):
            list_traces(conn, limit=-1)

    def test_offset_negative_raises(self):
        conn, _ = _make_conn_for_list()
        with pytest.raises(ValueError, match="offset"):
            list_traces(conn, offset=-1)


# ---------------------------------------------------------------------------
# list_traces — SQL contract assertions
# ---------------------------------------------------------------------------

class TestListTracesSqlContract:
    def test_count_query_targets_int_trace_spans(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        count_sql, _ = cur.execute_calls[0]
        assert "analytics.int_trace_spans" in count_sql

    def test_page_query_targets_int_trace_spans(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        _, page_sql = (cur.execute_calls[1][0], cur.execute_calls[1][0])
        page_sql = cur.execute_calls[1][0]
        assert "analytics.int_trace_spans" in page_sql

    def test_deterministic_ordering_in_page_sql(self):
        assert "trace_start_time DESC" in _LIST_TRACES_ORDER
        assert "trace_id ASC" in _LIST_TRACES_ORDER

    def test_two_execute_calls_per_list_traces(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        assert len(cur.execute_calls) == 2


# ---------------------------------------------------------------------------
# fetch_trace_spans
# ---------------------------------------------------------------------------

class TestFetchTraceSpans:
    def test_returns_span_records(self):
        rows = [_minimal_span_row("s1"), _minimal_span_row("s2")]
        conn, _ = _make_conn_for_fetch(rows)
        result = fetch_trace_spans(conn, _VALID_TRACE_ID)
        assert len(result) == 2
        assert result[0].span_id == "s1"
        assert result[1].span_id == "s2"

    def test_trace_id_passed_as_parameter(self):
        conn, cur = _make_conn_for_fetch([])
        fetch_trace_spans(conn, _VALID_TRACE_ID)
        args, _ = cur.execute.call_args
        params = args[1]
        assert params["trace_id"] == _VALID_TRACE_ID

    def test_empty_result_for_unknown_trace(self):
        conn, _ = _make_conn_for_fetch([])
        result = fetch_trace_spans(conn, _VALID_TRACE_ID)
        assert result == []

    def test_invalid_trace_id_raises_before_query(self):
        conn, cur = _make_conn_for_fetch([])
        with pytest.raises(ValueError):
            fetch_trace_spans(conn, "not-valid")
        cur.execute.assert_not_called()

    def test_uppercase_trace_id_raises(self):
        conn, cur = _make_conn_for_fetch([])
        with pytest.raises(ValueError):
            fetch_trace_spans(conn, "A" * 32)
        cur.execute.assert_not_called()

    def test_sql_uses_stg_telemetry_spans(self):
        from queries import _FETCH_SPANS_SQL
        assert "analytics.stg_telemetry_spans" in _FETCH_SPANS_SQL

    def test_sql_filters_by_trace_id_parameter(self):
        from queries import _FETCH_SPANS_SQL
        assert "%(trace_id)s" in _FETCH_SPANS_SQL
        assert "WHERE trace_id = %(trace_id)s" in _FETCH_SPANS_SQL

    def test_required_columns_in_sql(self):
        from queries import _FETCH_SPANS_SQL
        for col in ("span_id", "parent_span_id", "span_name", "start_time",
                    "end_time", "duration_ms", "status_code"):
            assert col in _FETCH_SPANS_SQL, f"Missing column: {col}"

    def test_optional_columns_in_sql(self):
        from queries import _FETCH_SPANS_SQL
        for col in ("trace_id", "service_name", "span_kind", "agent_name",
                    "tool_name", "error_type"):
            assert col in _FETCH_SPANS_SQL, f"Missing column: {col}"


# ---------------------------------------------------------------------------
# get_trace_reconstruction
# ---------------------------------------------------------------------------

class TestGetTraceReconstruction:
    def test_returns_trace_reconstruction(self):
        rows = [_minimal_span_row("root")]
        conn, _ = _make_conn_for_fetch(rows)
        result = get_trace_reconstruction(conn, _VALID_TRACE_ID)
        assert isinstance(result, TraceReconstruction)

    def test_span_count_matches_row_count(self):
        rows = [_minimal_span_row("s1"), _minimal_span_row("s2", parent_span_id="s1")]
        conn, _ = _make_conn_for_fetch(rows)
        result = get_trace_reconstruction(conn, _VALID_TRACE_ID)
        assert result.span_count == 2

    def test_empty_trace_returns_empty_reconstruction(self):
        conn, _ = _make_conn_for_fetch([])
        result = get_trace_reconstruction(conn, _VALID_TRACE_ID)
        assert result.span_count == 0
        assert result.roots == []
        assert result.orphans == []
        assert result.cycle_members == []
        assert result.has_cycle is False

    def test_root_span_placed_in_roots(self):
        rows = [_minimal_span_row("root", parent_span_id=None)]
        conn, _ = _make_conn_for_fetch(rows)
        result = get_trace_reconstruction(conn, _VALID_TRACE_ID)
        assert len(result.roots) == 1
        assert result.roots[0].span.span_id == "root"

    def test_parent_child_relationship_reconstructed(self):
        rows = [
            _minimal_span_row("parent", parent_span_id=None),
            _minimal_span_row("child", parent_span_id="parent"),
        ]
        conn, _ = _make_conn_for_fetch(rows)
        result = get_trace_reconstruction(conn, _VALID_TRACE_ID)
        assert len(result.roots) == 1
        assert len(result.roots[0].children) == 1
        assert result.roots[0].children[0].span.span_id == "child"

    def test_invalid_trace_id_raises_before_query(self):
        conn, cur = _make_conn_for_fetch([])
        with pytest.raises(ValueError):
            get_trace_reconstruction(conn, "bad")
        cur.execute.assert_not_called()

    def test_no_cycle_flag_for_clean_tree(self):
        rows = [
            _minimal_span_row("r", parent_span_id=None),
            _minimal_span_row("c", parent_span_id="r"),
        ]
        conn, _ = _make_conn_for_fetch(rows)
        result = get_trace_reconstruction(conn, _VALID_TRACE_ID)
        assert result.has_cycle is False


# ---------------------------------------------------------------------------
# Phase 9.7: list_traces — new filter params
# ---------------------------------------------------------------------------

class TestListTracesServiceFilter:
    def test_service_name_adds_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, service_name="my-svc")
        count_sql, count_params = cur.execute_calls[0]
        page_sql, page_params = cur.execute_calls[1]
        assert "WHERE" in count_sql
        assert "WHERE" in page_sql
        assert "root_service_name" in count_sql
        assert count_params["service_name"] == "my-svc"
        assert page_params["service_name"] == "my-svc"

    def test_service_name_uses_parameter_binding(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, service_name="svc")
        count_sql, _ = cur.execute_calls[0]
        assert "%(service_name)s" in count_sql

    def test_no_service_name_no_root_service_filter(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        count_sql, count_params = cur.execute_calls[0]
        assert "root_service_name" not in count_sql
        assert "service_name" not in count_params


class TestListTracesRequestIdFilter:
    def test_request_id_adds_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, request_id="req-1")
        count_sql, count_params = cur.execute_calls[0]
        assert "WHERE" in count_sql
        assert "request_id" in count_sql
        assert count_params["request_id"] == "req-1"

    def test_request_id_uses_parameter_binding(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, request_id="req-1")
        count_sql, _ = cur.execute_calls[0]
        assert "%(request_id)s" in count_sql


class TestListTracesSessionIdFilter:
    def test_session_id_adds_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, session_id="sess-1")
        count_sql, count_params = cur.execute_calls[0]
        assert "WHERE" in count_sql
        assert "session_id" in count_sql
        assert count_params["session_id"] == "sess-1"

    def test_session_id_uses_parameter_binding(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, session_id="sess-1")
        count_sql, _ = cur.execute_calls[0]
        assert "%(session_id)s" in count_sql


class TestListTracesMinDurationFilter:
    def test_min_duration_adds_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, min_duration_ms=100.0)
        count_sql, count_params = cur.execute_calls[0]
        assert "WHERE" in count_sql
        assert "trace_duration_ms" in count_sql
        assert ">=" in count_sql
        assert count_params["min_duration_ms"] == 100.0

    def test_min_duration_uses_parameter_binding(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, min_duration_ms=50.0)
        count_sql, _ = cur.execute_calls[0]
        assert "%(min_duration_ms)s" in count_sql

    def test_min_duration_zero_is_valid(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, min_duration_ms=0.0)
        _, count_params = cur.execute_calls[0]
        assert count_params["min_duration_ms"] == 0.0


class TestListTracesMaxDurationFilter:
    def test_max_duration_adds_where_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, max_duration_ms=5000.0)
        count_sql, count_params = cur.execute_calls[0]
        assert "WHERE" in count_sql
        assert "trace_duration_ms" in count_sql
        assert "<=" in count_sql
        assert count_params["max_duration_ms"] == 5000.0

    def test_max_duration_uses_parameter_binding(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, max_duration_ms=999.0)
        count_sql, _ = cur.execute_calls[0]
        assert "%(max_duration_ms)s" in count_sql


class TestListTracesDurationRange:
    def test_both_bounds_generate_two_conditions(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, min_duration_ms=10.0, max_duration_ms=500.0)
        count_sql, count_params = cur.execute_calls[0]
        assert "%(min_duration_ms)s" in count_sql
        assert "%(max_duration_ms)s" in count_sql
        assert count_params["min_duration_ms"] == 10.0
        assert count_params["max_duration_ms"] == 500.0

    def test_equal_min_max_is_accepted(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, min_duration_ms=100.0, max_duration_ms=100.0)
        _, count_params = cur.execute_calls[0]
        assert count_params["min_duration_ms"] == 100.0
        assert count_params["max_duration_ms"] == 100.0


class TestListTracesSearchFilter:
    def test_search_adds_like_or_clause(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, search="abc123")
        count_sql, count_params = cur.execute_calls[0]
        assert "WHERE" in count_sql
        assert "trace_id" in count_sql
        assert "request_id" in count_sql
        assert "session_id" in count_sql
        assert "OR" in count_sql
        assert "LIKE" in count_sql

    def test_search_appends_percent_to_bound_value(self):
        """The % wildcard is part of the bound parameter value, not the SQL template."""
        conn, cur = _make_conn_for_list()
        list_traces(conn, search="abc123")
        _, count_params = cur.execute_calls[0]
        assert count_params["search"] == "abc123%"

    def test_search_partial_prefix_bound(self):
        """Entering 8 hex chars produces a prefix-match bound value."""
        conn, cur = _make_conn_for_list()
        list_traces(conn, search="97a1b6fe")
        _, count_params = cur.execute_calls[0]
        assert count_params["search"] == "97a1b6fe%"

    def test_search_full_id_still_works(self):
        """A full 32-char trace_id produces a bound value of id + '%'."""
        conn, cur = _make_conn_for_list()
        list_traces(conn, search="a" * 32)
        _, count_params = cur.execute_calls[0]
        assert count_params["search"] == "a" * 32 + "%"

    def test_search_uses_parameter_binding(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, search="abc")
        count_sql, _ = cur.execute_calls[0]
        assert "%(search)s" in count_sql

    def test_search_not_in_params_when_none(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn)
        _, count_params = cur.execute_calls[0]
        assert "search" not in count_params

    def test_search_count_and_page_both_receive_param(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, search="prefix")
        _, count_params = cur.execute_calls[0]
        _, page_params  = cur.execute_calls[1]
        assert count_params["search"] == "prefix%"
        assert page_params["search"]  == "prefix%"


class TestListTracesFilteredTotal:
    def test_filtered_total_comes_from_count_query(self):
        conn, cur = _make_conn_for_list(count_value=7, page_rows=[])
        result = list_traces(conn, service_name="svc")
        assert result.total == 7

    def test_total_reflects_active_filter_not_page_size(self):
        conn, cur = _make_conn_for_list(count_value=200, page_rows=[{"x": 1}])
        result = list_traces(conn, min_duration_ms=100.0, limit=1, offset=0)
        assert result.total == 200
        assert len(result.traces) == 1


class TestListTracesCombinedFilters:
    def test_has_error_and_service_name_both_in_where(self):
        conn, cur = _make_conn_for_list()
        list_traces(conn, has_error=True, service_name="svc")
        count_sql, count_params = cur.execute_calls[0]
        assert "has_error" in count_sql
        assert "root_service_name" in count_sql
        assert "AND" in count_sql
        assert count_params["has_error"] is True
        assert count_params["service_name"] == "svc"

    def test_all_filters_combined_generates_and_clauses(self):
        conn, cur = _make_conn_for_list()
        list_traces(
            conn,
            has_error=False,
            service_name="svc",
            request_id="req",
            session_id="sess",
            min_duration_ms=10.0,
            max_duration_ms=1000.0,
            search="abc",
        )
        count_sql, count_params = cur.execute_calls[0]
        assert "WHERE" in count_sql
        assert "AND" in count_sql
        assert count_params["has_error"] is False
        assert count_params["service_name"] == "svc"
        assert count_params["request_id"] == "req"
        assert count_params["session_id"] == "sess"
        assert count_params["min_duration_ms"] == 10.0
        assert count_params["max_duration_ms"] == 1000.0
        assert count_params["search"] == "abc%"


# ===========================================================================
# Phase 14.6.1: bounded read of one trace (max_spans)
# ===========================================================================

import psycopg as _psycopg_14_6_1
from datetime import timedelta as _td_14_6_1


def _bounded_rows(n: int) -> list[dict]:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        {"trace_id": "a" * 32, "span_id": f"{i + 1:016x}", "parent_span_id": None if i == 0 else f"{i:016x}",
         "span_name": "s", "span_kind": None, "service_name": "svc", "start_time": base + _td_14_6_1(milliseconds=i),
         "end_time": base + _td_14_6_1(milliseconds=i + 1), "duration_ms": 1.0, "status_code": "OK",
         "status_message": None, "is_demo_data": False}
        for i in range(n)
    ]


def _conn_with(rows: list[dict]):
    cur = MagicMock()
    cur.fetchall.return_value = rows
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cur
    return conn, cur


class TestBoundedTraceRead:
    def test_default_read_is_exactly_the_old_unbounded_query(self):
        from queries import _FETCH_SPANS_SQL, fetch_trace_spans
        conn, cur = _conn_with(_bounded_rows(3))
        assert len(fetch_trace_spans(conn, "a" * 32)) == 3
        assert cur.execute.call_args.args == (_FETCH_SPANS_SQL, {"trace_id": "a" * 32})
        assert "LIMIT" not in _FETCH_SPANS_SQL

    def test_bounded_read_orders_deterministically_and_limits_with_a_bound_parameter(self):
        from queries import _FETCH_SPANS_SQL, fetch_trace_spans
        conn, cur = _conn_with(_bounded_rows(2))
        fetch_trace_spans(conn, "a" * 32, max_spans=10)
        sql, params = cur.execute.call_args.args
        assert sql.startswith(_FETCH_SPANS_SQL)
        assert sql.rstrip().endswith("ORDER BY start_time ASC, span_id ASC\nLIMIT %(limit)s")
        assert params == {"trace_id": "a" * 32, "limit": 11}           # one extra row detects "more than max"
        assert "10" not in sql and "11" not in sql                      # never interpolated

    def test_a_trace_within_the_limit_is_complete_and_not_truncated(self):
        from queries import get_trace_reconstruction
        conn, _ = _conn_with(_bounded_rows(5))
        result = get_trace_reconstruction(conn, "a" * 32, max_spans=5)
        assert result.span_count == 5 and result.truncated is False

    def test_a_trace_over_the_limit_keeps_the_first_spans_and_is_truncated(self):
        from queries import get_trace_reconstruction
        conn, _ = _conn_with(_bounded_rows(6))                         # the extra row came back
        result = get_trace_reconstruction(conn, "a" * 32, max_spans=5)
        assert result.span_count == 5 and result.truncated is True
        kept = {n.span.span_id for n in result.roots} | {c.span.span_id for n in result.roots for c in n.children}
        assert f"{6:016x}" not in kept                                  # the sixth span was dropped

    def test_default_reconstruction_is_unchanged_and_never_truncated(self):
        from queries import get_trace_reconstruction
        conn, cur = _conn_with(_bounded_rows(4))
        result = get_trace_reconstruction(conn, "a" * 32)
        assert result.span_count == 4 and result.truncated is False
        assert "limit" not in cur.execute.call_args.args[1]

    def test_unknown_trace_with_a_limit_is_empty_not_truncated(self):
        from queries import get_trace_reconstruction
        conn, _ = _conn_with([])
        result = get_trace_reconstruction(conn, "a" * 32, max_spans=5)
        assert result.span_count == 0 and result.truncated is False

    @pytest.mark.parametrize("bad", [0, -1, True, False, 1.5, "5"])
    def test_an_invalid_limit_never_reaches_the_database(self, bad):
        from queries import fetch_trace_spans
        conn, cur = _conn_with([])
        with pytest.raises(ValueError, match="max_spans"):
            fetch_trace_spans(conn, "a" * 32, max_spans=bad)
        cur.execute.assert_not_called()

    def test_an_invalid_trace_id_is_still_rejected_before_the_limit_is_considered(self):
        from queries import fetch_trace_spans
        conn, cur = _conn_with([])
        with pytest.raises(ValueError, match="trace_id"):
            fetch_trace_spans(conn, "nope", max_spans=5)
        cur.execute.assert_not_called()

    def test_a_database_error_still_propagates(self):
        from queries import get_trace_reconstruction
        conn, cur = _conn_with([])
        cur.execute.side_effect = _psycopg_14_6_1.OperationalError("boom")
        with pytest.raises(_psycopg_14_6_1.Error):
            get_trace_reconstruction(conn, "a" * 32, max_spans=5)


# ===========================================================================
# Phase 14.6.1 corrections (B3J-414): span free text is shortened by PostgreSQL
# ===========================================================================

import re as _re_414


class TestSpanTextBoundedInSql:
    def test_the_two_free_text_columns_are_read_through_left_with_the_same_names(self):
        import queries
        sql = queries._FETCH_SPANS_SQL
        assert "left(status_message, 2001) AS status_message" in sql
        assert "left(error_message, 2001) AS error_message" in sql
        assert queries.TEXT_FETCH_CHARS == 2001

    def test_only_the_two_message_columns_are_shortened(self):
        import queries
        shortened = _re_414.findall(r"left\((\w+), \d+\)", queries._FETCH_SPANS_SQL)
        assert shortened == ["status_message", "error_message"]

    def test_no_value_is_interpolated_and_the_only_parameters_are_unchanged(self):
        import queries
        sql = queries._FETCH_SPANS_SQL
        assert _re_414.findall(r"%\((\w+)\)s", sql) == ["trace_id"]
        assert "%s" not in sql
        conn, cur = _conn_with([])
        queries.fetch_trace_spans(conn, "a" * 32)
        assert cur.execute.call_args.args == (sql, {"trace_id": "a" * 32})
        queries.fetch_trace_spans(conn, "a" * 32, max_spans=7)
        bounded_sql, params = cur.execute.call_args.args
        assert bounded_sql == sql + queries._FETCH_SPANS_LIMITED_TAIL and params == {"trace_id": "a" * 32, "limit": 8}

    def test_the_select_list_is_otherwise_the_unbounded_original(self):
        # replacing each left(x, n) AS x by x gives back the column list read before this change
        import queries
        plain = _re_414.sub(r"left\((\w+), \d+\) AS \1", r"\1", queries._FETCH_SPANS_SQL)
        columns = [c.strip() for c in plain.split("FROM")[0].replace("SELECT", "").split(",\n")]
        assert columns == ["trace_id", "span_id", "parent_span_id", "span_name", "span_kind", "service_name", "start_time",
                           "end_time", "duration_ms", "status_code", "status_message", "request_id", "session_id",
                           "gen_ai_operation", "agent_name", "agent_operation", "tool_name", "tool_status",
                           "retrieval_result_count", "retrieval_top_relevance_score", "error_type", "error_message",
                           "(attributes ->> 'demo_seed' IS NOT NULL) AS is_demo_data"]
        assert "WHERE trace_id = %(trace_id)s" in plain and "FROM analytics.stg_telemetry_spans" in plain

    def test_a_row_shortened_by_the_database_maps_to_a_span_record_unchanged(self):
        import queries
        rows = _bounded_rows(1)
        rows[0]["status_message"] = "s" * 2001
        rows[0]["error_message"] = "e" * 2001
        conn, _ = _conn_with(rows)
        (span,) = queries.fetch_trace_spans(conn, "a" * 32)
        assert (len(span.status_message), len(span.error_message)) == (2001, 2001)    # the API layer reports and cuts at 2,000

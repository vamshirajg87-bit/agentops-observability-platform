"""
rca-analyzer/tests/unit/test_rca_source.py

Unit tests for rca_db.py and rca_source.py.

No live PostgreSQL required. SQL behaviour is verified by inspecting
module-level SQL string constants; connection/cursor behaviour is verified
with lightweight MagicMock objects.

Coverage:
    DB CONNECTION (TestRcaDbConnect):
        missing password → RuntimeError before any psycopg.connect call
        all env vars read and forwarded to psycopg.connect
        defaults applied when optional vars absent

    SQL CONSTANTS (TestFetchAnomalySQL, TestFetchSpansSQL):
        source relation; parameterized binding; no injection; ordering;
        required columns; no UPDATE/DELETE/INSERT; no stale relation names

    ROW MAPPING (TestRowToAnomalyRecord, TestRowToSpanRecord):
        all fields mapped correctly
        column renames: span_id → subject_span_id, explanation → detector_explanation
        no raw "span_id" or "explanation" attributes on the record
        valid anomaly_type values pass through; invalid → ValueError
        valid severity values pass through; invalid → ValueError
        None values preserved; 0.0 / zero int preserved
        RcaAnomalyRecord is immutable (frozen=True)

    FETCH FUNCTIONS (TestFetchAnomaly, TestFetchSpans):
        cursor called with dict_row row factory
        correct SQL constant and params forwarded to execute()
        None returned for missing anomaly_id
        empty list returned for missing trace_id
        multiple spans returned in query order
        caller connection not closed by either function
        no hidden psycopg.connect() call in rca_source module source
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import rca_source
from rca_source import (
    RcaAnomalyRecord,
    _SQL_FETCH_ANOMALY,
    _SQL_FETCH_SPANS,
    _row_to_anomaly_record,
    _row_to_span_record,
    fetch_anomaly,
    fetch_spans,
)
from rca_trace import SpanRecord


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TS = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_TS2 = datetime(2024, 6, 1, 12, 0, 1, tzinfo=timezone.utc)
_ANOMALY_ID = "a" * 64
_TRACE_ID = "f" * 32
_SPAN_ID = "b" * 32


def _anomaly_row(**overrides: object) -> dict:
    row: dict = {
        "anomaly_id": _ANOMALY_ID,
        "anomaly_type": "latency",
        "signal_name": "trace_latency_p95",
        "detector_name": "LatencyDetector",
        "detector_version": "1.0",
        "trace_id": _TRACE_ID,
        "span_id": None,
        "service_name": "orchestrator",
        "operation_name": "run_pipeline",
        "observed_value": 1500.0,
        "event_time": _TS,
        "baseline_median": 200.0,
        "baseline_mad": 30.0,
        "baseline_n": 100,
        "anomaly_score": 8.5,
        "severity": "WARNING",
        "explanation": "p95 exceeded 3× baseline",
    }
    row.update(overrides)
    return row


def _span_row(**overrides: object) -> dict:
    row: dict = {
        "trace_id": _TRACE_ID,
        "span_id": _SPAN_ID,
        "parent_span_id": None,
        "span_name": "run_pipeline",
        "span_kind": "INTERNAL",
        "service_name": "orchestrator",
        "start_time": _TS,
        "end_time": _TS2,
        "duration_ms": 1000.0,
        "status_code": "OK",
        "status_message": None,
        "agent_name": None,
        "agent_operation": None,
        "tool_name": None,
        "tool_status": None,
        "retrieval_result_count": None,
        "retrieval_top_relevance_score": None,
        "error_type": None,
        "error_message": None,
    }
    row.update(overrides)
    return row


def _make_conn_one(row: dict | None = None) -> MagicMock:
    """Mock connection whose cursor.fetchone() returns row."""
    cur = MagicMock()
    cur.fetchone.return_value = row
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn


def _make_conn_all(rows: list | None = None) -> MagicMock:
    """Mock connection whose cursor.fetchall() returns rows."""
    rows = rows or []
    cur = MagicMock()
    cur.fetchall.return_value = rows
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn


# ---------------------------------------------------------------------------
# DB connection factory
# ---------------------------------------------------------------------------

class TestRcaDbConnect:

    def test_missing_password_raises_runtime_error(self, monkeypatch):
        monkeypatch.delenv("RCA_ANALYZER_DB_PASSWORD", raising=False)
        import rca_db
        with pytest.raises(RuntimeError, match="RCA_ANALYZER_DB_PASSWORD"):
            rca_db.connect()

    def test_empty_password_raises_runtime_error(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "")
        import rca_db
        with pytest.raises(RuntimeError, match="RCA_ANALYZER_DB_PASSWORD"):
            rca_db.connect()

    def test_forwards_password_to_psycopg_connect(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "secret123")
        import rca_db
        with patch("rca_db.psycopg.connect") as mock_connect:
            mock_connect.return_value = MagicMock()
            rca_db.connect()
        kwargs = mock_connect.call_args[1]
        assert kwargs["password"] == "secret123"

    def test_default_host_is_localhost(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "pw")
        monkeypatch.delenv("RCA_ANALYZER_DB_HOST", raising=False)
        import rca_db
        with patch("rca_db.psycopg.connect") as mock_connect:
            mock_connect.return_value = MagicMock()
            rca_db.connect()
        kwargs = mock_connect.call_args[1]
        assert kwargs["host"] == "localhost"

    def test_default_port_is_5432(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "pw")
        monkeypatch.delenv("RCA_ANALYZER_DB_PORT", raising=False)
        import rca_db
        with patch("rca_db.psycopg.connect") as mock_connect:
            mock_connect.return_value = MagicMock()
            rca_db.connect()
        kwargs = mock_connect.call_args[1]
        assert kwargs["port"] == 5432

    def test_default_dbname_is_agentops(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "pw")
        monkeypatch.delenv("RCA_ANALYZER_DB_NAME", raising=False)
        import rca_db
        with patch("rca_db.psycopg.connect") as mock_connect:
            mock_connect.return_value = MagicMock()
            rca_db.connect()
        kwargs = mock_connect.call_args[1]
        assert kwargs["dbname"] == "agentops"

    def test_default_user_is_rca_analyzer(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "pw")
        monkeypatch.delenv("RCA_ANALYZER_DB_USER", raising=False)
        import rca_db
        with patch("rca_db.psycopg.connect") as mock_connect:
            mock_connect.return_value = MagicMock()
            rca_db.connect()
        kwargs = mock_connect.call_args[1]
        assert kwargs["user"] == "rca_analyzer"

    def test_env_overrides_applied(self, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "mypass")
        monkeypatch.setenv("RCA_ANALYZER_DB_HOST", "pghost.internal")
        monkeypatch.setenv("RCA_ANALYZER_DB_PORT", "5433")
        monkeypatch.setenv("RCA_ANALYZER_DB_NAME", "mydb")
        monkeypatch.setenv("RCA_ANALYZER_DB_USER", "myuser")
        import rca_db
        with patch("rca_db.psycopg.connect") as mock_connect:
            mock_connect.return_value = MagicMock()
            rca_db.connect()
        kwargs = mock_connect.call_args[1]
        assert kwargs["host"] == "pghost.internal"
        assert kwargs["port"] == 5433
        assert kwargs["dbname"] == "mydb"
        assert kwargs["user"] == "myuser"
        assert kwargs["password"] == "mypass"


# ---------------------------------------------------------------------------
# SQL: fetch_anomaly
# ---------------------------------------------------------------------------

class TestFetchAnomalySQL:

    def test_source_relation(self):
        assert "public.anomaly_events" in _SQL_FETCH_ANOMALY

    def test_parameterized_anomaly_id(self):
        assert "%(anomaly_id)s" in _SQL_FETCH_ANOMALY

    def test_no_raw_format_string_injection(self):
        # %(name)s is valid; a bare %s or %d would be injection risk
        assert re.search(r"%[^(]", _SQL_FETCH_ANOMALY) is None

    def test_selects_anomaly_id(self):
        assert "anomaly_id" in _SQL_FETCH_ANOMALY

    def test_selects_span_id(self):
        assert "span_id" in _SQL_FETCH_ANOMALY

    def test_selects_explanation(self):
        assert "explanation" in _SQL_FETCH_ANOMALY

    def test_selects_trace_id(self):
        assert "trace_id" in _SQL_FETCH_ANOMALY

    def test_selects_severity(self):
        assert "severity" in _SQL_FETCH_ANOMALY

    def test_selects_anomaly_type(self):
        assert "anomaly_type" in _SQL_FETCH_ANOMALY

    def test_no_update(self):
        assert "UPDATE" not in _SQL_FETCH_ANOMALY.upper()

    def test_no_delete(self):
        assert "DELETE" not in _SQL_FETCH_ANOMALY.upper()

    def test_no_insert(self):
        assert "INSERT" not in _SQL_FETCH_ANOMALY.upper()


# ---------------------------------------------------------------------------
# SQL: fetch_spans
# ---------------------------------------------------------------------------

class TestFetchSpansSQL:

    def test_source_relation(self):
        assert "analytics.stg_telemetry_spans" in _SQL_FETCH_SPANS

    def test_parameterized_trace_id(self):
        assert "%(trace_id)s" in _SQL_FETCH_SPANS

    def test_no_raw_format_string_injection(self):
        assert re.search(r"%[^(]", _SQL_FETCH_SPANS) is None

    def test_order_by_start_time_asc(self):
        upper = _SQL_FETCH_SPANS.upper()
        assert "ORDER BY" in upper
        assert "START_TIME ASC" in upper

    def test_order_by_span_id_asc(self):
        assert "SPAN_ID ASC" in _SQL_FETCH_SPANS.upper()

    def test_selects_span_id(self):
        assert "span_id" in _SQL_FETCH_SPANS

    def test_selects_parent_span_id(self):
        assert "parent_span_id" in _SQL_FETCH_SPANS

    def test_selects_service_name(self):
        assert "service_name" in _SQL_FETCH_SPANS

    def test_selects_start_time(self):
        assert "start_time" in _SQL_FETCH_SPANS

    def test_selects_end_time(self):
        assert "end_time" in _SQL_FETCH_SPANS

    def test_selects_duration_ms(self):
        assert "duration_ms" in _SQL_FETCH_SPANS

    def test_selects_status_code(self):
        assert "status_code" in _SQL_FETCH_SPANS

    def test_selects_error_type(self):
        assert "error_type" in _SQL_FETCH_SPANS

    def test_selects_tool_name(self):
        assert "tool_name" in _SQL_FETCH_SPANS

    def test_selects_agent_name(self):
        assert "agent_name" in _SQL_FETCH_SPANS

    def test_selects_retrieval_result_count(self):
        assert "retrieval_result_count" in _SQL_FETCH_SPANS

    def test_does_not_reference_public_telemetry_spans(self):
        assert "public.telemetry_spans" not in _SQL_FETCH_SPANS

    def test_no_update(self):
        assert "UPDATE" not in _SQL_FETCH_SPANS.upper()

    def test_no_delete(self):
        assert "DELETE" not in _SQL_FETCH_SPANS.upper()

    def test_no_insert(self):
        assert "INSERT" not in _SQL_FETCH_SPANS.upper()


# ---------------------------------------------------------------------------
# Row mapper: RcaAnomalyRecord
# ---------------------------------------------------------------------------

class TestRowToAnomalyRecord:

    def test_all_fields_mapped(self):
        rec = _row_to_anomaly_record(_anomaly_row())
        assert rec.anomaly_id == _ANOMALY_ID
        assert rec.anomaly_type == "latency"
        assert rec.signal_name == "trace_latency_p95"
        assert rec.detector_name == "LatencyDetector"
        assert rec.detector_version == "1.0"
        assert rec.trace_id == _TRACE_ID
        assert rec.subject_span_id is None
        assert rec.service_name == "orchestrator"
        assert rec.operation_name == "run_pipeline"
        assert rec.observed_value == 1500.0
        assert rec.event_time == _TS
        assert rec.baseline_median == 200.0
        assert rec.baseline_mad == 30.0
        assert rec.baseline_n == 100
        assert rec.anomaly_score == 8.5
        assert rec.severity == "WARNING"
        assert rec.detector_explanation == "p95 exceeded 3× baseline"

    def test_db_span_id_becomes_subject_span_id(self):
        sid = "c" * 32
        rec = _row_to_anomaly_record(_anomaly_row(span_id=sid))
        assert rec.subject_span_id == sid

    def test_no_raw_span_id_attribute(self):
        rec = _row_to_anomaly_record(_anomaly_row())
        assert not hasattr(rec, "span_id")

    def test_db_explanation_becomes_detector_explanation(self):
        rec = _row_to_anomaly_record(_anomaly_row(explanation="some text"))
        assert rec.detector_explanation == "some text"

    def test_no_raw_explanation_attribute(self):
        rec = _row_to_anomaly_record(_anomaly_row())
        assert not hasattr(rec, "explanation")

    def test_null_trace_id_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(trace_id=None))
        assert rec.trace_id is None

    def test_null_subject_span_id_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(span_id=None))
        assert rec.subject_span_id is None

    def test_null_service_name_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(service_name=None))
        assert rec.service_name is None

    def test_null_operation_name_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(operation_name=None))
        assert rec.operation_name is None

    def test_null_baseline_fields_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(
            baseline_median=None, baseline_mad=None,
            baseline_n=None, anomaly_score=None,
        ))
        assert rec.baseline_median is None
        assert rec.baseline_mad is None
        assert rec.baseline_n is None
        assert rec.anomaly_score is None

    def test_zero_observed_value_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(observed_value=0.0))
        assert rec.observed_value == 0.0

    def test_zero_baseline_n_preserved(self):
        rec = _row_to_anomaly_record(_anomaly_row(baseline_n=0))
        assert rec.baseline_n == 0

    def test_valid_anomaly_type_latency(self):
        rec = _row_to_anomaly_record(_anomaly_row(anomaly_type="latency"))
        assert rec.anomaly_type == "latency"

    def test_valid_anomaly_type_retrieval_quality(self):
        rec = _row_to_anomaly_record(_anomaly_row(anomaly_type="retrieval_quality"))
        assert rec.anomaly_type == "retrieval_quality"

    def test_valid_anomaly_type_error_rate(self):
        rec = _row_to_anomaly_record(_anomaly_row(anomaly_type="error_rate"))
        assert rec.anomaly_type == "error_rate"

    def test_valid_anomaly_type_tool_failure(self):
        rec = _row_to_anomaly_record(_anomaly_row(anomaly_type="tool_failure"))
        assert rec.anomaly_type == "tool_failure"

    def test_invalid_anomaly_type_raises_value_error(self):
        with pytest.raises(ValueError, match="anomaly_type"):
            _row_to_anomaly_record(_anomaly_row(anomaly_type="unknown_signal"))

    def test_invalid_anomaly_type_error_message_includes_anomaly_id(self):
        with pytest.raises(ValueError, match=_ANOMALY_ID):
            _row_to_anomaly_record(_anomaly_row(anomaly_type="bad_type"))

    def test_valid_severity_info(self):
        rec = _row_to_anomaly_record(_anomaly_row(severity="INFO"))
        assert rec.severity == "INFO"

    def test_valid_severity_warning(self):
        rec = _row_to_anomaly_record(_anomaly_row(severity="WARNING"))
        assert rec.severity == "WARNING"

    def test_valid_severity_critical(self):
        rec = _row_to_anomaly_record(_anomaly_row(severity="CRITICAL"))
        assert rec.severity == "CRITICAL"

    def test_invalid_severity_raises_value_error(self):
        with pytest.raises(ValueError, match="severity"):
            _row_to_anomaly_record(_anomaly_row(severity="EXTREME"))

    def test_is_frozen(self):
        rec = _row_to_anomaly_record(_anomaly_row())
        with pytest.raises((AttributeError, TypeError)):
            rec.anomaly_id = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Row mapper: SpanRecord
# ---------------------------------------------------------------------------

class TestRowToSpanRecord:

    def test_required_fields_mapped(self):
        rec = _row_to_span_record(_span_row())
        assert rec.span_id == _SPAN_ID
        assert rec.parent_span_id is None
        assert rec.span_name == "run_pipeline"
        assert rec.service_name == "orchestrator"
        assert rec.start_time == _TS
        assert rec.end_time == _TS2
        assert rec.duration_ms == 1000.0
        assert rec.status_code == "OK"
        assert rec.trace_id == _TRACE_ID

    def test_optional_fields_none_by_default(self):
        rec = _row_to_span_record(_span_row())
        assert rec.agent_name is None
        assert rec.agent_operation is None
        assert rec.tool_name is None
        assert rec.tool_status is None
        assert rec.retrieval_result_count is None
        assert rec.retrieval_top_relevance_score is None
        assert rec.error_type is None
        assert rec.error_message is None
        assert rec.status_message is None

    def test_agent_fields_populated(self):
        rec = _row_to_span_record(_span_row(
            agent_name="planner", agent_operation="plan",
        ))
        assert rec.agent_name == "planner"
        assert rec.agent_operation == "plan"

    def test_tool_fields_populated(self):
        rec = _row_to_span_record(_span_row(
            tool_name="web_search", tool_status="SUCCESS",
        ))
        assert rec.tool_name == "web_search"
        assert rec.tool_status == "SUCCESS"

    def test_retrieval_fields_populated(self):
        rec = _row_to_span_record(_span_row(
            retrieval_result_count=5, retrieval_top_relevance_score=0.92,
        ))
        assert rec.retrieval_result_count == 5
        assert rec.retrieval_top_relevance_score == 0.92

    def test_error_fields_populated(self):
        rec = _row_to_span_record(_span_row(
            error_type="TimeoutError", error_message="request timed out",
        ))
        assert rec.error_type == "TimeoutError"
        assert rec.error_message == "request timed out"

    def test_parent_span_id_non_null(self):
        parent = "d" * 32
        rec = _row_to_span_record(_span_row(parent_span_id=parent))
        assert rec.parent_span_id == parent

    def test_zero_retrieval_count_preserved(self):
        rec = _row_to_span_record(_span_row(retrieval_result_count=0))
        assert rec.retrieval_result_count == 0

    def test_zero_relevance_score_preserved(self):
        rec = _row_to_span_record(_span_row(retrieval_top_relevance_score=0.0))
        assert rec.retrieval_top_relevance_score == 0.0

    def test_returns_span_record_instance(self):
        rec = _row_to_span_record(_span_row())
        assert isinstance(rec, SpanRecord)


# ---------------------------------------------------------------------------
# fetch_anomaly behaviour
# ---------------------------------------------------------------------------

class TestFetchAnomaly:

    def test_returns_none_when_not_found(self):
        conn = _make_conn_one(row=None)
        result = fetch_anomaly(conn, _ANOMALY_ID)
        assert result is None

    def test_returns_record_when_found(self):
        conn = _make_conn_one(row=_anomaly_row())
        result = fetch_anomaly(conn, _ANOMALY_ID)
        assert isinstance(result, RcaAnomalyRecord)
        assert result.anomaly_id == _ANOMALY_ID

    def test_cursor_called_with_dict_row(self):
        import psycopg.rows
        conn = _make_conn_one(row=None)
        fetch_anomaly(conn, _ANOMALY_ID)
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_execute_receives_sql_constant(self):
        conn = _make_conn_one(row=None)
        fetch_anomaly(conn, _ANOMALY_ID)
        executed_sql = conn.cursor.return_value.execute.call_args[0][0]
        assert executed_sql is _SQL_FETCH_ANOMALY

    def test_execute_receives_correct_params(self):
        conn = _make_conn_one(row=None)
        fetch_anomaly(conn, _ANOMALY_ID)
        executed_params = conn.cursor.return_value.execute.call_args[0][1]
        assert executed_params == {"anomaly_id": _ANOMALY_ID}

    def test_caller_connection_not_closed(self):
        conn = _make_conn_one(row=None)
        fetch_anomaly(conn, _ANOMALY_ID)
        conn.close.assert_not_called()

    def test_no_hidden_psycopg_connect_in_source(self):
        source = Path(rca_source.__file__).read_text()
        assert "psycopg.connect" not in source


# ---------------------------------------------------------------------------
# fetch_spans behaviour
# ---------------------------------------------------------------------------

class TestFetchSpans:

    def test_returns_empty_list_when_no_spans(self):
        conn = _make_conn_all(rows=[])
        result = fetch_spans(conn, _TRACE_ID)
        assert result == []

    def test_returns_span_record_instances(self):
        conn = _make_conn_all(rows=[_span_row()])
        result = fetch_spans(conn, _TRACE_ID)
        assert len(result) == 1
        assert isinstance(result[0], SpanRecord)

    def test_span_id_mapped_correctly(self):
        conn = _make_conn_all(rows=[_span_row()])
        result = fetch_spans(conn, _TRACE_ID)
        assert result[0].span_id == _SPAN_ID

    def test_cursor_called_with_dict_row(self):
        import psycopg.rows
        conn = _make_conn_all(rows=[])
        fetch_spans(conn, _TRACE_ID)
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_execute_receives_sql_constant(self):
        conn = _make_conn_all(rows=[])
        fetch_spans(conn, _TRACE_ID)
        executed_sql = conn.cursor.return_value.execute.call_args[0][0]
        assert executed_sql is _SQL_FETCH_SPANS

    def test_execute_receives_correct_params(self):
        conn = _make_conn_all(rows=[])
        fetch_spans(conn, _TRACE_ID)
        executed_params = conn.cursor.return_value.execute.call_args[0][1]
        assert executed_params == {"trace_id": _TRACE_ID}

    def test_multiple_spans_returned_in_order(self):
        span_a = _span_row(span_id="a" * 32, start_time=_TS)
        span_b = _span_row(span_id="b" * 32, start_time=_TS2)
        conn = _make_conn_all(rows=[span_a, span_b])
        result = fetch_spans(conn, _TRACE_ID)
        assert len(result) == 2
        assert result[0].span_id == "a" * 32
        assert result[1].span_id == "b" * 32

    def test_caller_connection_not_closed(self):
        conn = _make_conn_all(rows=[])
        fetch_spans(conn, _TRACE_ID)
        conn.close.assert_not_called()

    def test_no_hidden_psycopg_connect_in_source(self):
        source = Path(rca_source.__file__).read_text()
        assert "psycopg.connect" not in source

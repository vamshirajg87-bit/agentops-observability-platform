"""
Tests for anomaly-detector/record_mapper.py

All tests are pure Python — no database connection required.
Row dicts are constructed inline; mappers are called directly.

Coverage:
    TRACE LATENCY:
        root_service_name -> service_name
        root_span_name    -> operation_name
        trace_duration_ms -> duration_ms
        trace_start_time  -> start_time
        has_error         -> is_error
        span_id is None (trace-grain records have no span_id)

    SPAN LATENCY (agent + tool — identical column layout):
        span_id           -> span_id  (not None)
        span_name         -> operation_name
        service_name      -> service_name
        duration_ms       -> duration_ms
        start_time        -> start_time
        is_error_span     -> is_error

    RETRIEVAL:
        retrieval_result_count = 0     remains 0   (not None)
        retrieval_result_count = None  remains None
        retrieval_top_relevance_score = 0.0   remains 0.0
        retrieval_top_relevance_score = None  remains None
        is_error_span     -> is_error

    ERROR:
        successful row: is_error=False, error_type=None
        failed row:     is_error=True,  error_type preserved
        span_name       -> operation_name

    TOOL:
        successful row: is_error=False, error_type=None
        failed row:     is_error=True,  error_type preserved

    ALL:
        timezone-aware datetime preserved exactly
        KeyError raised for required missing fields
        is_error_span bool preservation: True/False identity preserved (no bool() coercion)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from record_mapper import (
    row_to_error_record,
    row_to_retrieval_record,
    row_to_span_latency_record,
    row_to_tool_record,
    row_to_trace_latency_record,
)
from detector.anomaly_types import (
    ErrorRecord,
    LatencyRecord,
    RetrievalRecord,
    ToolRecord,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_TS = datetime(2024, 3, 15, 9, 30, 0, tzinfo=timezone.utc)
_TRACE = "a" * 32
_SPAN = "b" * 16


def _trace_row(**overrides) -> dict:
    base = {
        "trace_id": _TRACE,
        "trace_duration_ms": 250.0,
        "root_span_name": "agentops.request",
        "root_service_name": "research-service",
        "trace_start_time": _TS,
        "has_error": False,
    }
    base.update(overrides)
    return base


def _span_row(**overrides) -> dict:
    base = {
        "trace_id": _TRACE,
        "span_id": _SPAN,
        "service_name": "research-service",
        "span_name": "agent.run",
        "duration_ms": 120.5,
        "start_time": _TS,
        "is_error_span": False,
    }
    base.update(overrides)
    return base


def _retrieval_row(**overrides) -> dict:
    base = {
        "trace_id": _TRACE,
        "span_id": _SPAN,
        "service_name": "research-service",
        "retrieval_top_relevance_score": 0.85,
        "retrieval_result_count": 5,
        "start_time": _TS,
        "is_error_span": False,
    }
    base.update(overrides)
    return base


def _error_row(**overrides) -> dict:
    base = {
        "trace_id": _TRACE,
        "span_id": _SPAN,
        "service_name": "research-service",
        "span_name": "agent.run",
        "is_error_span": False,
        "error_type": None,
        "start_time": _TS,
    }
    base.update(overrides)
    return base


def _tool_row(**overrides) -> dict:
    base = {
        "trace_id": _TRACE,
        "span_id": _SPAN,
        "service_name": "research-service",
        "is_error_span": False,
        "error_type": None,
        "start_time": _TS,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Trace latency mapper
# ---------------------------------------------------------------------------

class TestRowToTraceLatencyRecord:

    def test_root_service_name_maps_to_service_name(self):
        rec = row_to_trace_latency_record(_trace_row(root_service_name="billing"))
        assert rec.service_name == "billing"

    def test_root_span_name_maps_to_operation_name(self):
        rec = row_to_trace_latency_record(_trace_row(root_span_name="my.op"))
        assert rec.operation_name == "my.op"

    def test_trace_duration_ms_maps_to_duration_ms(self):
        rec = row_to_trace_latency_record(_trace_row(trace_duration_ms=500.0))
        assert rec.duration_ms == 500.0

    def test_trace_duration_ms_float_preserved_directly(self):
        rec = row_to_trace_latency_record(_trace_row(trace_duration_ms=300.0))
        assert rec.duration_ms == 300.0
        assert isinstance(rec.duration_ms, float)

    def test_trace_start_time_maps_to_start_time(self):
        rec = row_to_trace_latency_record(_trace_row(trace_start_time=_TS))
        assert rec.start_time is _TS

    def test_has_error_true_maps_to_is_error_true(self):
        rec = row_to_trace_latency_record(_trace_row(has_error=True))
        assert rec.is_error is True

    def test_has_error_false_maps_to_is_error_false(self):
        rec = row_to_trace_latency_record(_trace_row(has_error=False))
        assert rec.is_error is False

    def test_span_id_is_none(self):
        rec = row_to_trace_latency_record(_trace_row())
        assert rec.span_id is None

    def test_trace_id_preserved(self):
        rec = row_to_trace_latency_record(_trace_row())
        assert rec.trace_id == _TRACE

    def test_returns_latency_record(self):
        rec = row_to_trace_latency_record(_trace_row())
        assert isinstance(rec, LatencyRecord)

    def test_missing_required_key_raises_key_error(self):
        row = _trace_row()
        del row["trace_duration_ms"]
        with pytest.raises(KeyError):
            row_to_trace_latency_record(row)

    def test_timezone_aware_datetime_preserved_exactly(self):
        rec = row_to_trace_latency_record(_trace_row(trace_start_time=_TS))
        assert rec.start_time.tzinfo is not None
        assert rec.start_time == _TS


# ---------------------------------------------------------------------------
# Span latency mapper (agent + tool)
# ---------------------------------------------------------------------------

class TestRowToSpanLatencyRecord:

    def test_span_id_preserved(self):
        rec = row_to_span_latency_record(_span_row(span_id="c" * 16))
        assert rec.span_id == "c" * 16

    def test_span_name_maps_to_operation_name(self):
        rec = row_to_span_latency_record(_span_row(span_name="tool.execute"))
        assert rec.operation_name == "tool.execute"

    def test_service_name_preserved(self):
        rec = row_to_span_latency_record(_span_row(service_name="my-svc"))
        assert rec.service_name == "my-svc"

    def test_duration_ms_preserved(self):
        rec = row_to_span_latency_record(_span_row(duration_ms=99.9))
        assert rec.duration_ms == 99.9

    def test_duration_ms_float_preserved_directly(self):
        rec = row_to_span_latency_record(_span_row(duration_ms=200.0))
        assert rec.duration_ms == 200.0
        assert isinstance(rec.duration_ms, float)

    def test_start_time_preserved(self):
        rec = row_to_span_latency_record(_span_row(start_time=_TS))
        assert rec.start_time is _TS

    def test_is_error_span_true_maps_to_is_error_true(self):
        rec = row_to_span_latency_record(_span_row(is_error_span=True))
        assert rec.is_error is True

    def test_is_error_span_false_maps_to_is_error_false(self):
        rec = row_to_span_latency_record(_span_row(is_error_span=False))
        assert rec.is_error is False

    def test_span_id_not_none(self):
        rec = row_to_span_latency_record(_span_row())
        assert rec.span_id is not None

    def test_returns_latency_record(self):
        assert isinstance(row_to_span_latency_record(_span_row()), LatencyRecord)

    def test_missing_required_key_raises_key_error(self):
        row = _span_row()
        del row["span_name"]
        with pytest.raises(KeyError):
            row_to_span_latency_record(row)

    def test_timezone_aware_datetime_preserved_exactly(self):
        rec = row_to_span_latency_record(_span_row(start_time=_TS))
        assert rec.start_time.tzinfo is not None
        assert rec.start_time == _TS



# ---------------------------------------------------------------------------
# Retrieval mapper
# ---------------------------------------------------------------------------

class TestRowToRetrievalRecord:

    def test_result_count_zero_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_result_count=0))
        assert rec.retrieval_result_count == 0
        assert rec.retrieval_result_count is not None

    def test_result_count_none_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_result_count=None))
        assert rec.retrieval_result_count is None

    def test_result_count_positive_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_result_count=7))
        assert rec.retrieval_result_count == 7

    def test_relevance_score_zero_float_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_top_relevance_score=0.0))
        assert rec.retrieval_top_relevance_score == 0.0
        assert rec.retrieval_top_relevance_score is not None

    def test_relevance_score_none_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_top_relevance_score=None))
        assert rec.retrieval_top_relevance_score is None

    def test_relevance_score_value_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_top_relevance_score=0.73))
        assert rec.retrieval_top_relevance_score == 0.73

    def test_is_error_span_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(is_error_span=True))
        assert rec.is_error is True

    def test_service_name_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row(service_name="retrieval-svc"))
        assert rec.service_name == "retrieval-svc"

    def test_trace_id_and_span_id_preserved(self):
        rec = row_to_retrieval_record(_retrieval_row())
        assert rec.trace_id == _TRACE
        assert rec.span_id == _SPAN

    def test_returns_retrieval_record(self):
        assert isinstance(row_to_retrieval_record(_retrieval_row()), RetrievalRecord)

    def test_missing_required_key_raises_key_error(self):
        row = _retrieval_row()
        del row["service_name"]
        with pytest.raises(KeyError):
            row_to_retrieval_record(row)

    def test_timezone_aware_datetime_preserved_exactly(self):
        rec = row_to_retrieval_record(_retrieval_row(start_time=_TS))
        assert rec.start_time.tzinfo is not None
        assert rec.start_time == _TS

    def test_retrieval_result_count_type_is_int(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_result_count=5))
        assert isinstance(rec.retrieval_result_count, int)

    def test_retrieval_top_relevance_score_type_is_float(self):
        rec = row_to_retrieval_record(_retrieval_row(retrieval_top_relevance_score=0.73))
        assert isinstance(rec.retrieval_top_relevance_score, float)


# ---------------------------------------------------------------------------
# Error record mapper
# ---------------------------------------------------------------------------

class TestRowToErrorRecord:

    def test_successful_span_maps_is_error_false(self):
        rec = row_to_error_record(_error_row(is_error_span=False))
        assert rec.is_error is False

    def test_successful_span_error_type_is_none(self):
        rec = row_to_error_record(_error_row(is_error_span=False, error_type=None))
        assert rec.error_type is None

    def test_failed_span_maps_is_error_true(self):
        rec = row_to_error_record(_error_row(is_error_span=True, error_type="TimeoutError"))
        assert rec.is_error is True

    def test_failed_span_error_type_preserved(self):
        rec = row_to_error_record(_error_row(is_error_span=True, error_type="ConnectionRefused"))
        assert rec.error_type == "ConnectionRefused"

    def test_error_type_none_is_not_stringified(self):
        rec = row_to_error_record(_error_row(error_type=None))
        assert rec.error_type is None
        assert rec.error_type != "None"
        assert rec.error_type != "unknown"

    def test_span_name_maps_to_operation_name(self):
        rec = row_to_error_record(_error_row(span_name="my.operation"))
        assert rec.operation_name == "my.operation"

    def test_service_name_preserved(self):
        rec = row_to_error_record(_error_row(service_name="error-svc"))
        assert rec.service_name == "error-svc"

    def test_returns_error_record(self):
        assert isinstance(row_to_error_record(_error_row()), ErrorRecord)

    def test_missing_required_key_raises_key_error(self):
        row = _error_row()
        del row["span_name"]
        with pytest.raises(KeyError):
            row_to_error_record(row)

    def test_timezone_aware_datetime_preserved_exactly(self):
        rec = row_to_error_record(_error_row(start_time=_TS))
        assert rec.start_time.tzinfo is not None
        assert rec.start_time == _TS


# ---------------------------------------------------------------------------
# Tool record mapper
# ---------------------------------------------------------------------------

class TestRowToToolRecord:

    def test_successful_tool_execute_is_error_false(self):
        rec = row_to_tool_record(_tool_row(is_error_span=False, error_type=None))
        assert rec.is_error is False

    def test_successful_tool_execute_error_type_none(self):
        rec = row_to_tool_record(_tool_row(is_error_span=False, error_type=None))
        assert rec.error_type is None

    def test_failed_tool_execute_is_error_true(self):
        rec = row_to_tool_record(_tool_row(is_error_span=True, error_type="ToolTimeout"))
        assert rec.is_error is True

    def test_failed_tool_execute_error_type_preserved(self):
        rec = row_to_tool_record(_tool_row(is_error_span=True, error_type="ToolTimeout"))
        assert rec.error_type == "ToolTimeout"

    def test_error_type_none_is_not_stringified(self):
        rec = row_to_tool_record(_tool_row(error_type=None))
        assert rec.error_type is None
        assert rec.error_type != "None"
        assert rec.error_type != "unknown"

    def test_service_name_preserved(self):
        rec = row_to_tool_record(_tool_row(service_name="tool-runner"))
        assert rec.service_name == "tool-runner"

    def test_trace_id_and_span_id_preserved(self):
        rec = row_to_tool_record(_tool_row())
        assert rec.trace_id == _TRACE
        assert rec.span_id == _SPAN

    def test_returns_tool_record(self):
        assert isinstance(row_to_tool_record(_tool_row()), ToolRecord)

    def test_missing_required_key_raises_key_error(self):
        row = _tool_row()
        del row["is_error_span"]
        with pytest.raises(KeyError):
            row_to_tool_record(row)

    def test_timezone_aware_datetime_preserved_exactly(self):
        rec = row_to_tool_record(_tool_row(start_time=_TS))
        assert rec.start_time.tzinfo is not None
        assert rec.start_time == _TS


# ---------------------------------------------------------------------------
# Source-level constraints
# ---------------------------------------------------------------------------

class TestMapperSourceConstraints:
    """Verify record_mapper.py contains no bool() or float() coercions."""

    def test_no_bool_coercion_in_source(self):
        import inspect
        import record_mapper
        source = inspect.getsource(record_mapper)
        assert "bool(" not in source, "mapper must not call bool() on psycopg rows"

    def test_no_float_coercion_in_source(self):
        import inspect
        import record_mapper
        source = inspect.getsource(record_mapper)
        assert "float(" not in source, "mapper must not call float() on psycopg rows"

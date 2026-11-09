"""
storage-consumer/tests/unit/test_repository.py

Unit tests for repository.py.

All tests use a mocked psycopg connection and cursor. No live PostgreSQL
is required.

Requires demo-app/ on PYTHONPATH so CanonicalSpanEvent can be imported:

    export PYTHONPATH="$PWD/demo-app"               # bash/zsh (repo root)
    $env:PYTHONPATH = "$PWD\\demo-app"              # PowerShell (repo root)
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from psycopg.types.json import Jsonb

from repository import SpanRepository


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TID = "a" * 32       # 32 hex chars — valid trace_id
SID = "b" * 16       # 16 hex chars — valid span_id
PSID = "c" * 16      # 16 hex chars — valid parent_span_id
TOPIC = "agentops.telemetry.spans"
PARTITION = 2
OFFSET = 99


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def make_event(**overrides):
    """Construct a minimal valid CanonicalSpanEvent with optional field overrides."""
    from schemas.telemetry import CanonicalSpanEvent
    now = _now()
    defaults = {
        "trace_id": TID,
        "span_id": SID,
        "span_name": "test.operation",
        "span_kind": "INTERNAL",
        "service_name": "agentops-test",
        "start_time": now,
        "end_time": now,
        "duration_ms": 0.0,
        "status_code": "OK",
    }
    defaults.update(overrides)
    return CanonicalSpanEvent(**defaults)


def make_conn(fetchone_result=(42,)):
    """
    Return (mock_conn, mock_cursor) with cursor.fetchone() pre-configured.

    fetchone_result=(42,) → new row inserted (True)
    fetchone_result=None  → conflict / DO NOTHING (False)
    """
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = fetchone_result

    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    return mock_conn, mock_cursor


def get_execute_args(mock_cursor):
    """Return (sql, params) from the single cursor.execute() call."""
    mock_cursor.execute.assert_called_once()
    return mock_cursor.execute.call_args[0]  # positional: (sql, params)


# ---------------------------------------------------------------------------
# insert_span — return value contract
# ---------------------------------------------------------------------------

class TestReturnValue:
    def test_returns_true_when_row_inserted(self):
        conn, _ = make_conn(fetchone_result=(42,))
        result = SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        assert result is True

    def test_returns_false_when_conflict_do_nothing(self):
        conn, _ = make_conn(fetchone_result=None)
        result = SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        assert result is False

    def test_different_row_id_still_returns_true(self):
        conn, _ = make_conn(fetchone_result=(9999,))
        result = SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        assert result is True


# ---------------------------------------------------------------------------
# Canonical field mapping
# ---------------------------------------------------------------------------

class TestCanonicalFieldMapping:
    """Each CanonicalSpanEvent field must appear in the params dict under its
    column name and carry the correct value."""

    def _params(self, event):
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(event, TOPIC, PARTITION, OFFSET)
        _, params = get_execute_args(cursor)
        return params

    def test_schema_version(self):
        event = make_event()
        assert self._params(event)["schema_version"] == event.schema_version

    def test_event_type(self):
        event = make_event()
        assert self._params(event)["event_type"] == event.event_type

    def test_trace_id(self):
        event = make_event()
        assert self._params(event)["trace_id"] == TID

    def test_span_id(self):
        event = make_event()
        assert self._params(event)["span_id"] == SID

    def test_parent_span_id_when_set(self):
        event = make_event(parent_span_id=PSID)
        assert self._params(event)["parent_span_id"] == PSID

    def test_parent_span_id_none_when_absent(self):
        event = make_event()
        assert self._params(event)["parent_span_id"] is None

    def test_span_name(self):
        event = make_event(span_name="my.span")
        assert self._params(event)["span_name"] == "my.span"

    def test_span_kind(self):
        event = make_event(span_kind="CLIENT")
        assert self._params(event)["span_kind"] == "CLIENT"

    def test_service_name(self):
        event = make_event(service_name="my-service")
        assert self._params(event)["service_name"] == "my-service"

    def test_start_time(self):
        event = make_event()
        assert self._params(event)["start_time"] == event.start_time

    def test_end_time(self):
        event = make_event()
        assert self._params(event)["end_time"] == event.end_time

    def test_duration_ms(self):
        event = make_event(duration_ms=250.5)
        assert self._params(event)["duration_ms"] == pytest.approx(250.5)

    def test_status_code(self):
        event = make_event(status_code="ERROR")
        assert self._params(event)["status_code"] == "ERROR"

    def test_status_message_when_set(self):
        event = make_event(status_message="connection refused")
        assert self._params(event)["status_message"] == "connection refused"

    def test_status_message_none_when_absent(self):
        event = make_event()
        assert self._params(event)["status_message"] is None

    def test_request_id_when_set(self):
        event = make_event(request_id="req-abc")
        assert self._params(event)["request_id"] == "req-abc"

    def test_session_id_when_set(self):
        event = make_event(session_id="sess-xyz")
        assert self._params(event)["session_id"] == "sess-xyz"

    def test_gen_ai_operation_when_set(self):
        event = make_event(gen_ai_operation="chat")
        assert self._params(event)["gen_ai_operation"] == "chat"

    def test_agent_name_when_set(self):
        event = make_event(agent_name="planner-agent")
        assert self._params(event)["agent_name"] == "planner-agent"

    def test_agent_operation_when_set(self):
        event = make_event(agent_operation="plan")
        assert self._params(event)["agent_operation"] == "plan"

    def test_tool_name_when_set(self):
        event = make_event(tool_name="web-search")
        assert self._params(event)["tool_name"] == "web-search"

    def test_tool_status_when_set(self):
        event = make_event(tool_status="success")
        assert self._params(event)["tool_status"] == "success"

    def test_retrieval_result_count_when_set(self):
        event = make_event(retrieval_result_count=5)
        assert self._params(event)["retrieval_result_count"] == 5

    def test_retrieval_result_count_none_when_absent(self):
        event = make_event()
        assert self._params(event)["retrieval_result_count"] is None

    def test_retrieval_top_relevance_score_when_set(self):
        event = make_event(retrieval_top_relevance_score=0.87)
        assert self._params(event)["retrieval_top_relevance_score"] == pytest.approx(0.87)

    def test_retrieval_top_relevance_score_none_when_absent(self):
        event = make_event()
        assert self._params(event)["retrieval_top_relevance_score"] is None

    def test_error_type_when_set(self):
        event = make_event(error_type="TimeoutError")
        assert self._params(event)["error_type"] == "TimeoutError"

    def test_error_message_when_set(self):
        event = make_event(error_message="request timed out after 30s")
        assert self._params(event)["error_message"] == "request timed out after 30s"

    def test_all_optional_fields_are_present_and_none_when_absent(self):
        """Every optional column must appear in params as None, never missing."""
        event = make_event()
        params = self._params(event)
        optional_columns = [
            "parent_span_id",
            "status_message",
            "request_id",
            "session_id",
            "gen_ai_operation",
            "agent_name",
            "agent_operation",
            "tool_name",
            "tool_status",
            "retrieval_result_count",
            "retrieval_top_relevance_score",
            "error_type",
            "error_message",
        ]
        for col in optional_columns:
            assert col in params, f"column {col!r} missing from params"
            assert params[col] is None, (
                f"expected None for absent optional {col!r}, got {params[col]!r}"
            )


# ---------------------------------------------------------------------------
# Kafka provenance mapping
# ---------------------------------------------------------------------------

class TestKafkaProvenanceMapping:
    def _params(self, topic, partition, offset):
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(make_event(), topic, partition, offset)
        _, params = get_execute_args(cursor)
        return params

    def test_kafka_topic_mapped(self):
        assert self._params("agentops.telemetry.spans", 0, 0)["kafka_topic"] == \
               "agentops.telemetry.spans"

    def test_kafka_partition_mapped(self):
        assert self._params(TOPIC, 2, 0)["kafka_partition"] == 2

    def test_kafka_offset_mapped(self):
        assert self._params(TOPIC, PARTITION, 999)["kafka_offset"] == 999

    def test_kafka_offset_large_value_preserved(self):
        large_offset = 2_200_000_000  # exceeds 32-bit INTEGER range
        assert self._params(TOPIC, PARTITION, large_offset)["kafka_offset"] == large_offset


# ---------------------------------------------------------------------------
# SQL content
# ---------------------------------------------------------------------------

class TestSQLContent:
    def _sql(self):
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        sql, _ = get_execute_args(cursor)
        return sql

    def test_targets_telemetry_spans_table(self):
        assert "telemetry_spans" in self._sql()

    def test_contains_on_conflict_clause(self):
        assert "ON CONFLICT ON CONSTRAINT" in self._sql()

    def test_contains_constraint_name(self):
        assert "uq_telemetry_spans_trace_span" in self._sql()

    def test_contains_do_nothing(self):
        assert "DO NOTHING" in self._sql()

    def test_contains_returning_id(self):
        assert "RETURNING id" in self._sql()


# ---------------------------------------------------------------------------
# DB-generated fields
# ---------------------------------------------------------------------------

class TestDBGeneratedFields:
    def _params(self):
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        _, params = get_execute_args(cursor)
        return params

    def test_id_not_supplied(self):
        assert "id" not in self._params()

    def test_ingested_at_not_supplied(self):
        assert "ingested_at" not in self._params()


# ---------------------------------------------------------------------------
# JSONB adaptation
# ---------------------------------------------------------------------------

class TestJsonbAdaptation:
    def _attributes_param(self, attrs):
        event = make_event(attributes=attrs)
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(event, TOPIC, PARTITION, OFFSET)
        _, params = get_execute_args(cursor)
        return params["attributes"]

    def test_attributes_is_jsonb_instance(self):
        assert isinstance(self._attributes_param({"key": "val"}), Jsonb)

    def test_attributes_jsonb_wraps_original_dict(self):
        attrs = {"model": "gpt-4", "tokens": 100}
        result = self._attributes_param(attrs)
        assert result.obj == attrs

    def test_empty_attributes_wrapped_in_jsonb(self):
        assert isinstance(self._attributes_param({}), Jsonb)

    def test_attributes_not_a_raw_dict(self):
        result = self._attributes_param({"x": 1})
        assert not isinstance(result, dict)


# ---------------------------------------------------------------------------
# Transaction behavior
# ---------------------------------------------------------------------------

class TestTransactionBehavior:
    def test_transaction_context_manager_entered(self):
        conn, _ = make_conn()
        SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        conn.transaction.assert_called_once()

    def test_cursor_execute_called_once(self):
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        cursor.execute.assert_called_once()

    def test_fetchone_called_to_detect_conflict(self):
        conn, cursor = make_conn()
        SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)
        cursor.fetchone.assert_called_once()


# ---------------------------------------------------------------------------
# Exception propagation
# ---------------------------------------------------------------------------

class TestExceptionPropagation:
    def test_execute_exception_propagates(self):
        conn, cursor = make_conn()
        cursor.execute.side_effect = Exception("SQL execution error")
        with pytest.raises(Exception, match="SQL execution error"):
            SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)

    def test_execute_exception_is_not_converted_to_false(self):
        conn, cursor = make_conn()
        cursor.execute.side_effect = Exception("SQL execution error")
        with pytest.raises(Exception):
            SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)

    def test_transaction_commit_exception_propagates(self):
        conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        conn.cursor.return_value.__enter__.return_value = mock_cursor

        # side_effect on the __exit__ MagicMock causes it to raise whenever
        # the context manager exits (simulating a commit failure).
        conn.transaction.return_value.__exit__.side_effect = Exception("commit failed")

        with pytest.raises(Exception, match="commit failed"):
            SpanRepository(conn).insert_span(make_event(), TOPIC, PARTITION, OFFSET)


# ---------------------------------------------------------------------------
# No Kafka dependency
# ---------------------------------------------------------------------------

class TestNoKafkaDependency:
    def test_repository_source_has_no_confluent_kafka_import(self):
        import repository
        source = inspect.getsource(repository)
        assert "confluent_kafka" not in source

    def test_repository_source_has_no_consumer_commit(self):
        import repository
        source = inspect.getsource(repository)
        assert "consumer.commit" not in source

    def test_insert_span_signature_has_no_consumer_param(self):
        sig = inspect.signature(SpanRepository.insert_span)
        assert "consumer" not in sig.parameters
        assert "kafka_consumer" not in sig.parameters

"""
storage-consumer/repository.py

PostgreSQL persistence boundary for CanonicalSpanEvent records.

SpanRepository has no Kafka knowledge and never commits Kafka offsets.
Transaction and Kafka offset semantics are entirely the caller's
responsibility.

The connection passed at construction must be in autocommit=True mode so
that conn.transaction() issues a bounded, explicit BEGIN/COMMIT for each
insert rather than nesting inside an implicit outer transaction.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    import psycopg
    from schemas.telemetry import CanonicalSpanEvent


_INSERT_SQL = """\
INSERT INTO telemetry_spans (
    schema_version,
    event_type,
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
    error_message,
    attributes,
    kafka_topic,
    kafka_partition,
    kafka_offset
) VALUES (
    %(schema_version)s,
    %(event_type)s,
    %(trace_id)s,
    %(span_id)s,
    %(parent_span_id)s,
    %(span_name)s,
    %(span_kind)s,
    %(service_name)s,
    %(start_time)s,
    %(end_time)s,
    %(duration_ms)s,
    %(status_code)s,
    %(status_message)s,
    %(request_id)s,
    %(session_id)s,
    %(gen_ai_operation)s,
    %(agent_name)s,
    %(agent_operation)s,
    %(tool_name)s,
    %(tool_status)s,
    %(retrieval_result_count)s,
    %(retrieval_top_relevance_score)s,
    %(error_type)s,
    %(error_message)s,
    %(attributes)s,
    %(kafka_topic)s,
    %(kafka_partition)s,
    %(kafka_offset)s
)
ON CONFLICT ON CONSTRAINT uq_telemetry_spans_trace_span
DO NOTHING
RETURNING id
"""


class SpanRepository:
    """
    Persists CanonicalSpanEvent records to the telemetry_spans table.

    Each insert_span() call runs within its own explicit psycopg transaction.
    """

    def __init__(self, connection: psycopg.Connection) -> None:
        self._connection = connection

    def insert_span(
        self,
        event: CanonicalSpanEvent,
        topic: str,
        partition: int,
        offset: int,
    ) -> bool:
        """
        Persist event to telemetry_spans within an explicit transaction.

        Returns:
            True  — a new row was inserted.
            False — span already existed; ON CONFLICT DO NOTHING skipped it.

        Raises:
            Any psycopg exception from cursor.execute() or transaction commit.
            False is returned ONLY for a unique-constraint conflict, never for
            any other database error.
        """
        params = {
            "schema_version": event.schema_version,
            "event_type": event.event_type,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "parent_span_id": event.parent_span_id,
            "span_name": event.span_name,
            "span_kind": event.span_kind,
            "service_name": event.service_name,
            "start_time": event.start_time,
            "end_time": event.end_time,
            "duration_ms": event.duration_ms,
            "status_code": event.status_code,
            "status_message": event.status_message,
            "request_id": event.request_id,
            "session_id": event.session_id,
            "gen_ai_operation": event.gen_ai_operation,
            "agent_name": event.agent_name,
            "agent_operation": event.agent_operation,
            "tool_name": event.tool_name,
            "tool_status": event.tool_status,
            "retrieval_result_count": event.retrieval_result_count,
            "retrieval_top_relevance_score": event.retrieval_top_relevance_score,
            "error_type": event.error_type,
            "error_message": event.error_message,
            "attributes": Jsonb(event.attributes),
            "kafka_topic": topic,
            "kafka_partition": partition,
            "kafka_offset": offset,
        }
        with self._connection.transaction():
            with self._connection.cursor() as cur:
                cur.execute(_INSERT_SQL, params)
                row = cur.fetchone()
        return row is not None

"""
anomaly-detector/record_mapper.py

Pure Python row mappers: DB-shaped dict → Phase 10.3 record dataclasses.

No database access.  No SQL.  No detector execution.
Each function accepts a Mapping[str, Any] (e.g. a psycopg dict_row result)
and returns the exact Phase 10.3 dataclass.

Mapping guarantees:
  - Values are passed through directly without type coercion.  psycopg3 maps
    PostgreSQL BOOLEAN to Python bool and DOUBLE PRECISION to Python float
    natively; no coercion wrappers of those types are applied here.
  - Applying bool to a non-bool string such as "false" gives True, not False —
    a known footgun.  The mapper avoids it by preserving psycopg's native
    delivery rather than re-coercing.
  - Timezone-aware datetime values are passed through exactly; no conversion.
  - None is preserved as None.  Integer 0 and float 0.0 are preserved as-is.
  - Required fields use direct key access (row["key"]) — a missing key raises
    KeyError immediately rather than silently substituting a default.
  - error_type None is never converted to a string ("None", "unknown", "").

Column-name mapping (DB column -> Phase 10.3 field):
  mart_trace_metrics:
    trace_id              -> LatencyRecord.trace_id
    (constant None)       -> LatencyRecord.span_id
    root_service_name     -> LatencyRecord.service_name
    root_span_name        -> LatencyRecord.operation_name
    trace_duration_ms     -> LatencyRecord.duration_ms
    trace_start_time      -> LatencyRecord.start_time
    has_error             -> LatencyRecord.is_error

  mart_agent_metrics / stg_telemetry_spans (span-grain):
    trace_id              -> LatencyRecord.trace_id
    span_id               -> LatencyRecord.span_id
    service_name          -> LatencyRecord.service_name
    span_name             -> LatencyRecord.operation_name
    duration_ms           -> LatencyRecord.duration_ms
    start_time            -> LatencyRecord.start_time
    is_error_span         -> LatencyRecord.is_error

  mart_retrieval_metrics:
    trace_id                       -> RetrievalRecord.trace_id
    span_id                        -> RetrievalRecord.span_id
    service_name                   -> RetrievalRecord.service_name
    retrieval_top_relevance_score  -> RetrievalRecord.retrieval_top_relevance_score
    retrieval_result_count         -> RetrievalRecord.retrieval_result_count
    start_time                     -> RetrievalRecord.start_time
    is_error_span                  -> RetrievalRecord.is_error

  stg_telemetry_spans (error-rate):
    trace_id              -> ErrorRecord.trace_id
    span_id               -> ErrorRecord.span_id
    service_name          -> ErrorRecord.service_name
    span_name             -> ErrorRecord.operation_name
    is_error_span         -> ErrorRecord.is_error
    error_type            -> ErrorRecord.error_type
    start_time            -> ErrorRecord.start_time

  stg_telemetry_spans (tool failure):
    trace_id              -> ToolRecord.trace_id
    span_id               -> ToolRecord.span_id
    service_name          -> ToolRecord.service_name
    is_error_span         -> ToolRecord.is_error
    error_type            -> ToolRecord.error_type
    start_time            -> ToolRecord.start_time

Public API:
    row_to_trace_latency_record()   — mart_trace_metrics row -> LatencyRecord
    row_to_span_latency_record()    — mart_agent_metrics / stg span row -> LatencyRecord
    row_to_retrieval_record()       — mart_retrieval_metrics row -> RetrievalRecord
    row_to_error_record()           — stg_telemetry_spans row -> ErrorRecord
    row_to_tool_record()            — stg_telemetry_spans row -> ToolRecord
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from detector.anomaly_types import (
    ErrorRecord,
    LatencyRecord,
    RetrievalRecord,
    ToolRecord,
)


def row_to_trace_latency_record(row: Mapping[str, Any]) -> LatencyRecord:
    """
    Map a mart_trace_metrics row to a LatencyRecord.

    span_id is always None for trace-level records.
    service_name comes from root_service_name; operation_name from root_span_name.
    """
    return LatencyRecord(
        trace_id=row["trace_id"],
        span_id=None,
        service_name=row["root_service_name"],
        operation_name=row["root_span_name"],
        duration_ms=row["trace_duration_ms"],
        start_time=row["trace_start_time"],
        is_error=row["has_error"],
    )


def row_to_span_latency_record(row: Mapping[str, Any]) -> LatencyRecord:
    """
    Map a span-grain row to a LatencyRecord.

    Used for both mart_agent_metrics and stg_telemetry_spans (tool.execute)
    rows, which share the same column layout for the required fields.
    operation_name comes from span_name.
    """
    return LatencyRecord(
        trace_id=row["trace_id"],
        span_id=row["span_id"],
        service_name=row["service_name"],
        operation_name=row["span_name"],
        duration_ms=row["duration_ms"],
        start_time=row["start_time"],
        is_error=row["is_error_span"],
    )


def row_to_retrieval_record(row: Mapping[str, Any]) -> RetrievalRecord:
    """
    Map a mart_retrieval_metrics row to a RetrievalRecord.

    retrieval_result_count = 0 and retrieval_top_relevance_score = 0.0 are
    valid signal values.  Direct key access is used so that 0 / 0.0 / None
    are all preserved exactly without the `value or None` anti-pattern.
    """
    return RetrievalRecord(
        trace_id=row["trace_id"],
        span_id=row["span_id"],
        service_name=row["service_name"],
        retrieval_top_relevance_score=row["retrieval_top_relevance_score"],
        retrieval_result_count=row["retrieval_result_count"],
        start_time=row["start_time"],
        is_error=row["is_error_span"],
    )


def row_to_error_record(row: Mapping[str, Any]) -> ErrorRecord:
    """
    Map a stg_telemetry_spans row to an ErrorRecord.

    Non-error spans have is_error=False and error_type=None.
    Both are required observations for ErrorRateDetector's rate computation.
    error_type is never converted to a string; None stays None.
    """
    return ErrorRecord(
        trace_id=row["trace_id"],
        span_id=row["span_id"],
        service_name=row["service_name"],
        operation_name=row["span_name"],
        is_error=row["is_error_span"],
        error_type=row["error_type"],
        start_time=row["start_time"],
    )


def row_to_tool_record(row: Mapping[str, Any]) -> ToolRecord:
    """
    Map a stg_telemetry_spans (span_name='tool.execute') row to a ToolRecord.

    Successful spans have is_error=False and error_type=None.
    Failed spans preserve the actual error_type value.
    error_type is never converted to a string; None stays None.
    """
    return ToolRecord(
        trace_id=row["trace_id"],
        span_id=row["span_id"],
        service_name=row["service_name"],
        is_error=row["is_error_span"],
        error_type=row["error_type"],
        start_time=row["start_time"],
    )

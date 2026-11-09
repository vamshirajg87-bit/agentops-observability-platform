"""
observability/normalization.py

Converts OpenTelemetry span data into the canonical AgentOps
CanonicalSpanEvent schema.

This module does not send telemetry anywhere. It only transforms
and validates span data.
"""

from typing import Any, Dict

from schemas.telemetry import CanonicalSpanEvent


def normalize_span(span_data: Dict[str, Any]) -> CanonicalSpanEvent:
    """
    Convert a normalized OpenTelemetry-like span dictionary into
    a validated CanonicalSpanEvent.
    """

    attributes = span_data.get("attributes") or {}

    start_time = span_data["start_time"]
    end_time = span_data["end_time"]

    duration_ms = (
        end_time - start_time
    ).total_seconds() * 1000.0

    return CanonicalSpanEvent(
        schema_version="1.0",
        event_type="span",

        trace_id=span_data["trace_id"],
        span_id=span_data["span_id"],
        parent_span_id=span_data.get("parent_span_id"),

        span_name=span_data["span_name"],
        span_kind=span_data["span_kind"],

        start_time=start_time,
        end_time=end_time,
        duration_ms=duration_ms,

        status_code=span_data["status_code"],
        status_message=span_data.get("status_message"),

        service_name=span_data["service_name"],

        request_id=attributes.get("agentops.request_id"),
        session_id=attributes.get("agentops.session_id"),

        gen_ai_operation=attributes.get("gen_ai.operation.name"),

        agent_name=attributes.get("agent.name"),
        agent_operation=attributes.get("agent.operation"),

        tool_name=attributes.get("tool.name"),
        tool_status=attributes.get("tool.status"),

        retrieval_result_count=attributes.get(
            "retrieval.result_count"
        ),
        retrieval_top_relevance_score=attributes.get(
            "retrieval.top_relevance_score"
        ),

        error_type=attributes.get("error.type"),
        error_message=attributes.get("error.message"),

        attributes=attributes,
    )

"""
schemas/telemetry.py

Canonical telemetry schema for AgentOps span events.

This schema is independent of Kafka, PostgreSQL, and the OpenTelemetry
export format. It represents the normalized span record that the
AgentOps platform will validate and process downstream.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class CanonicalSpanEvent(BaseModel):
    schema_version: str = "1.0"
    event_type: str = "span"

    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None

    span_name: str
    span_kind: str

    start_time: datetime
    end_time: datetime
    duration_ms: float = Field(..., ge=0.0)

    status_code: str
    status_message: Optional[str] = None

    service_name: str

    request_id: Optional[str] = None
    session_id: Optional[str] = None

    gen_ai_operation: Optional[str] = None

    agent_name: Optional[str] = None
    agent_operation: Optional[str] = None

    tool_name: Optional[str] = None
    tool_status: Optional[str] = None

    retrieval_result_count: Optional[int] = Field(
        default=None,
        ge=0,
    )
    retrieval_top_relevance_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    error_type: Optional[str] = None
    error_message: Optional[str] = None

    attributes: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("trace_id")
    @classmethod
    def validate_trace_id(cls, value: str) -> str:
        if len(value) != 32:
            raise ValueError("trace_id must contain exactly 32 hexadecimal characters")

        try:
            int(value, 16)
        except ValueError as exc:
            raise ValueError("trace_id must be hexadecimal") from exc

        return value.lower()

    @field_validator("span_id", "parent_span_id")
    @classmethod
    def validate_span_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value

        if len(value) != 16:
            raise ValueError(
                "span_id and parent_span_id must contain exactly "
                "16 hexadecimal characters"
            )

        try:
            int(value, 16)
        except ValueError as exc:
            raise ValueError(
                "span_id and parent_span_id must be hexadecimal"
            ) from exc

        return value.lower()

    @model_validator(mode="after")
    def validate_timestamps(self):
        if self.end_time < self.start_time:
            raise ValueError("end_time must be greater than or equal to start_time")

        return self
"""
stream-processor/dlq.py

DLQ event model and builder for the agentops stream processor.

DLQEvent is published to the agentops.telemetry.dlq Kafka topic when a
Kafka message cannot be processed due to a data-quality or poison-message
failure. Operational failures (broker unavailable, network errors, publish
timeouts) are NOT represented here — they are handled by the retry/backoff
logic in the publisher layer.

Privacy policy
--------------
No raw protobuf bytes are stored in DLQEvent. The source_topic /
source_partition / source_offset triple is the replay coordinate: a
consumer can seek back to the original message as long as the source topic's
retention covers that offset.

source_payload_sha256 is identification and debug metadata only. It cannot
reconstruct the original payload and does not change the privacy posture of
the DLQ topic.

Schema versioning
-----------------
schema_version and event_type are Pydantic Literal fields. A consumer that
deserializes a payload with an unexpected schema_version receives a
ValidationError before processing begins, making incompatible changes
detectable at the boundary rather than silently corrupting downstream state.
"""

from __future__ import annotations

import enum
import re
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

from canonicalizer import CanonicalizationError, CanonicalizationErrorType
from otlp_decoder import OTLPDecodeError

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_ERROR_MESSAGE_LEN = 2_048


class DLQReason(enum.Enum):
    """Data-quality failure categories for DLQ routing.

    OTLP_DECODE_FAILURE       — raw protobuf bytes could not be parsed;
                                no logical span identity is available.
    SCHEMA_VALIDATION_FAILURE — decoded span dict was rejected by the
                                CanonicalSpanEvent schema validators.
    CANONICALIZATION_FAILURE  — an unexpected error occurred during the
                                canonicalization step.
    """

    OTLP_DECODE_FAILURE = "OTLP_DECODE_FAILURE"
    SCHEMA_VALIDATION_FAILURE = "SCHEMA_VALIDATION_FAILURE"
    CANONICALIZATION_FAILURE = "CANONICALIZATION_FAILURE"


# Maps CanonicalizationErrorType values to the corresponding DLQReason.
# Kept private; callers use build_dlq_event() and never inspect this directly.
_CANON_ERROR_TYPE_TO_DLQ_REASON: dict[CanonicalizationErrorType, DLQReason] = {
    CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE: DLQReason.SCHEMA_VALIDATION_FAILURE,
    CanonicalizationErrorType.UNEXPECTED_FAILURE: DLQReason.CANONICALIZATION_FAILURE,
}


class DLQEvent(BaseModel):
    """
    Structured event published to agentops.telemetry.dlq.

    Immutable once constructed. Call model_dump(mode='json') to produce a
    JSON-serialisable dict suitable for a Kafka producer value payload.
    """

    # Contract versioning — both fields are Literal so Pydantic rejects
    # payloads with incompatible values before any field is consumed.
    schema_version: Literal["1.0"] = "1.0"
    event_type: Literal["agentops.dlq"] = "agentops.dlq"

    # Transport identity — the replay handle.
    # source_partition and source_offset must be non-negative integers.
    source_topic: str
    source_partition: Annotated[int, Field(ge=0)]
    source_offset: Annotated[int, Field(ge=0)]

    # When the failure was detected (must be UTC-aware).
    failed_at: datetime

    # Failure classification.
    reason: DLQReason
    # Stored at most _MAX_ERROR_MESSAGE_LEN characters (truncation applied
    # in the validator; see below).
    error_message: str

    # Logical identity — populated when OTLP decode succeeded and at least
    # one span was extracted before failure. None for OTLP_DECODE_FAILURE.
    trace_id: str | None = None
    span_id: str | None = None
    service_name: str | None = None

    # SHA-256 of the original raw Kafka message value (identification only).
    # The caller computes this before invoking otlp_decoder.decode() and
    # passes it here. It is NOT a replay mechanism — the hash cannot
    # reconstruct the source bytes.
    source_payload_sha256: str | None = None

    @field_validator("failed_at")
    @classmethod
    def _require_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("failed_at must be timezone-aware")
        offset = v.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ValueError("failed_at must be UTC (utcoffset == 0)")
        return v

    @field_validator("source_payload_sha256")
    @classmethod
    def _validate_sha256(cls, v: str | None) -> str | None:
        if v is not None and not _SHA256_RE.match(v):
            raise ValueError(
                "source_payload_sha256 must be exactly 64 lowercase "
                "hexadecimal characters"
            )
        return v

    @field_validator("error_message")
    @classmethod
    def _truncate_error_message(cls, v: str) -> str:
        return v[:_MAX_ERROR_MESSAGE_LEN]


def build_dlq_event(
    *,
    exc: OTLPDecodeError | CanonicalizationError,
    source_topic: str,
    source_partition: int,
    source_offset: int,
    trace_id: str | None = None,
    span_id: str | None = None,
    service_name: str | None = None,
    source_payload_sha256: str | None = None,
    failed_at: datetime | None = None,
) -> DLQEvent:
    """
    Build a DLQEvent from a processing failure.

    Args:
        exc: OTLPDecodeError (raised before any span identity is known) or
             CanonicalizationError (span identity is available from the
             decoded span dict).
        source_topic: Kafka topic from which the failed message was consumed.
        source_partition: Kafka partition (>= 0).
        source_offset: Kafka offset (>= 0).
        trace_id: Hex trace ID; None when exc is OTLPDecodeError.
        span_id: Hex span ID; None when exc is OTLPDecodeError.
        service_name: Service name from resource attributes; None when unknown.
        source_payload_sha256: SHA-256 hex digest of the raw Kafka message
            value, computed by the caller before decoding. Identification
            metadata only — not a replay mechanism.
        failed_at: Failure timestamp. Must be UTC-aware if provided; defaults
            to datetime.now(tz=timezone.utc).

    Returns:
        DLQEvent ready for model_dump(mode='json') and Kafka publish.

    Raises:
        TypeError: if exc is not OTLPDecodeError or CanonicalizationError.
    """
    if isinstance(exc, OTLPDecodeError):
        reason = DLQReason.OTLP_DECODE_FAILURE
    elif isinstance(exc, CanonicalizationError):
        reason = _CANON_ERROR_TYPE_TO_DLQ_REASON[exc.error_type]
    else:
        raise TypeError(
            f"build_dlq_event() requires OTLPDecodeError or "
            f"CanonicalizationError; got {type(exc)!r}"
        )

    return DLQEvent(
        source_topic=source_topic,
        source_partition=source_partition,
        source_offset=source_offset,
        failed_at=failed_at if failed_at is not None else datetime.now(tz=timezone.utc),
        reason=reason,
        error_message=str(exc),
        trace_id=trace_id,
        span_id=span_id,
        service_name=service_name,
        source_payload_sha256=source_payload_sha256,
    )

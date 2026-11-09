"""
tests/unit/test_dlq.py

Unit tests for dlq.py.

No demo-app/ on PYTHONPATH is required — dlq.py has no demo-app dependency.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pydantic
import pytest

from canonicalizer import CanonicalizationError, CanonicalizationErrorType
from dlq import DLQEvent, DLQReason, build_dlq_event
from otlp_decoder import OTLPDecodeError

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

TOPIC = "agentops.telemetry.otlp.traces"
PARTITION = 2
OFFSET = 42
TRACE_ID = "0102030405060708090a0b0c0d0e0f10"
SPAN_ID = "0102030405060708"
SERVICE = "test-service"
SHA256 = "a" * 64  # 64 lowercase hex chars

UTC_NOW = datetime.now(tz=timezone.utc)

_DECODE_EXC = OTLPDecodeError("truncated varint")
_SCHEMA_EXC = CanonicalizationError(
    CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE, "trace_id too short"
)
_UNEXPECTED_EXC = CanonicalizationError(
    CanonicalizationErrorType.UNEXPECTED_FAILURE, "runtime error"
)


# ---------------------------------------------------------------------------
# DLQReason mapping via build_dlq_event
# ---------------------------------------------------------------------------


class TestDLQReasonMapping:
    def test_otlp_decode_error_maps_to_otlp_decode_failure(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.reason == DLQReason.OTLP_DECODE_FAILURE

    def test_schema_validation_failure_maps_correctly(self):
        event = build_dlq_event(
            exc=_SCHEMA_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.reason == DLQReason.SCHEMA_VALIDATION_FAILURE

    def test_unexpected_failure_maps_to_canonicalization_failure(self):
        event = build_dlq_event(
            exc=_UNEXPECTED_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.reason == DLQReason.CANONICALIZATION_FAILURE

    def test_unsupported_exception_type_raises_type_error(self):
        with pytest.raises(TypeError):
            build_dlq_event(
                exc=ValueError("not supported"),  # type: ignore[arg-type]
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
            )


# ---------------------------------------------------------------------------
# Logical identity fields
# ---------------------------------------------------------------------------


class TestLogicalIdentity:
    def test_decode_failure_identity_fields_are_none(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.trace_id is None
        assert event.span_id is None
        assert event.service_name is None

    def test_canonicalization_failure_identity_fields_populated(self):
        event = build_dlq_event(
            exc=_SCHEMA_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            trace_id=TRACE_ID,
            span_id=SPAN_ID,
            service_name=SERVICE,
            failed_at=UTC_NOW,
        )
        assert event.trace_id == TRACE_ID
        assert event.span_id == SPAN_ID
        assert event.service_name == SERVICE


# ---------------------------------------------------------------------------
# Schema versioning (Literal enforcement)
# ---------------------------------------------------------------------------


class TestSchemaVersioning:
    def test_schema_version_default_is_1_0(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.schema_version == "1.0"

    def test_event_type_default_is_agentops_dlq(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.event_type == "agentops.dlq"

    def test_wrong_schema_version_raises_validation_error(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                schema_version="2.0",  # type: ignore[arg-type]
                event_type="agentops.dlq",
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
            )

    def test_wrong_event_type_raises_validation_error(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                schema_version="1.0",
                event_type="dlq.span",  # type: ignore[arg-type]  # old value
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
            )


# ---------------------------------------------------------------------------
# failed_at UTC enforcement
# ---------------------------------------------------------------------------


class TestFailedAt:
    def test_utc_aware_datetime_is_accepted(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.failed_at.tzinfo is not None

    def test_naive_datetime_raises_validation_error(self):
        with pytest.raises(pydantic.ValidationError, match="timezone-aware"):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=datetime.now(),  # naive — no tzinfo
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
            )

    def test_non_utc_aware_datetime_raises_validation_error(self):
        with pytest.raises(pydantic.ValidationError, match="UTC"):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=datetime.now(tz=timezone(timedelta(hours=5))),
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
            )

    def test_failed_at_defaults_to_utc_now_when_not_supplied(self):
        before = datetime.now(tz=timezone.utc)
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
        )
        after = datetime.now(tz=timezone.utc)
        assert before <= event.failed_at <= after
        assert event.failed_at.tzinfo is not None


# ---------------------------------------------------------------------------
# source_partition and source_offset bounds
# ---------------------------------------------------------------------------


class TestSourceCoordinates:
    def test_zero_partition_and_offset_accepted(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=0,
            source_offset=0,
            failed_at=UTC_NOW,
        )
        assert event.source_partition == 0
        assert event.source_offset == 0

    def test_negative_partition_raises_validation_error(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=-1,
                source_offset=0,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
            )

    def test_negative_offset_raises_validation_error(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=0,
                source_offset=-1,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
            )

    def test_source_coordinates_round_trip(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.source_topic == TOPIC
        assert event.source_partition == PARTITION
        assert event.source_offset == OFFSET


# ---------------------------------------------------------------------------
# error_message truncation
# ---------------------------------------------------------------------------


class TestErrorMessage:
    def test_short_error_message_preserved(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert event.error_message == str(_DECODE_EXC)

    def test_error_message_truncated_at_2048_chars(self):
        long_msg = "x" * 4_000
        exc = OTLPDecodeError(long_msg)
        event = build_dlq_event(
            exc=exc,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert len(event.error_message) == 2_048
        assert event.error_message == long_msg[:2_048]

    def test_error_message_exactly_2048_chars_not_truncated(self):
        msg = "y" * 2_048
        exc = OTLPDecodeError(msg)
        event = build_dlq_event(
            exc=exc,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert len(event.error_message) == 2_048


# ---------------------------------------------------------------------------
# source_payload_sha256 validation
# ---------------------------------------------------------------------------


class TestSHA256Field:
    def test_none_is_accepted(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
            source_payload_sha256=None,
        )
        assert event.source_payload_sha256 is None

    def test_valid_64_char_lowercase_hex_accepted(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
            source_payload_sha256=SHA256,
        )
        assert event.source_payload_sha256 == SHA256

    def test_uppercase_hex_rejected(self):
        with pytest.raises(pydantic.ValidationError, match="lowercase"):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
                source_payload_sha256="A" * 64,
            )

    def test_63_char_hex_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
                source_payload_sha256="a" * 63,
            )

    def test_65_char_hex_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
                source_payload_sha256="a" * 65,
            )

    def test_non_hex_chars_rejected(self):
        with pytest.raises(pydantic.ValidationError):
            DLQEvent(
                source_topic=TOPIC,
                source_partition=PARTITION,
                source_offset=OFFSET,
                failed_at=UTC_NOW,
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="test",
                source_payload_sha256="g" * 64,  # 'g' is not hex
            )


# ---------------------------------------------------------------------------
# Privacy policy: no raw_payload field
# ---------------------------------------------------------------------------


class TestPrivacyPolicy:
    def test_dlq_event_has_no_raw_payload_field(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        assert not hasattr(event, "raw_payload")

    def test_dlq_event_model_fields_do_not_include_raw_payload(self):
        assert "raw_payload" not in DLQEvent.model_fields


# ---------------------------------------------------------------------------
# JSON serialization for Kafka publish
# ---------------------------------------------------------------------------


class TestJSONSerialization:
    def test_model_dump_json_mode_is_serializable(self):
        event = build_dlq_event(
            exc=_SCHEMA_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            trace_id=TRACE_ID,
            span_id=SPAN_ID,
            service_name=SERVICE,
            source_payload_sha256=SHA256,
            failed_at=UTC_NOW,
        )
        payload = event.model_dump(mode="json")
        # Must be JSON-round-trippable without errors
        serialized = json.dumps(payload)
        recovered = json.loads(serialized)
        assert recovered["schema_version"] == "1.0"
        assert recovered["event_type"] == "agentops.dlq"
        assert recovered["reason"] == DLQReason.SCHEMA_VALIDATION_FAILURE.value
        assert recovered["trace_id"] == TRACE_ID
        assert recovered["source_payload_sha256"] == SHA256

    def test_model_dump_includes_all_required_keys(self):
        event = build_dlq_event(
            exc=_DECODE_EXC,
            source_topic=TOPIC,
            source_partition=PARTITION,
            source_offset=OFFSET,
            failed_at=UTC_NOW,
        )
        payload = event.model_dump(mode="json")
        required_keys = {
            "schema_version",
            "event_type",
            "source_topic",
            "source_partition",
            "source_offset",
            "failed_at",
            "reason",
            "error_message",
            "trace_id",
            "span_id",
            "service_name",
            "source_payload_sha256",
        }
        assert required_keys.issubset(payload.keys())

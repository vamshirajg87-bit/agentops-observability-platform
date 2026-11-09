"""
tests/unit/test_otlp_decoder.py

Unit tests for otlp_decoder.py.

All tests build real ExportTraceServiceRequest protobuf messages in memory.
No Kafka, Docker, or external services are required.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.common.v1.common_pb2 import (
    AnyValue,
    KeyValue,
)
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import (
    ResourceSpans,
    ScopeSpans,
    Span,
    Status,
)

from otlp_decoder import OTLPDecodeError, decode


# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

TRACE_ID_HEX = "0102030405060708090a0b0c0d0e0f10"
SPAN_ID_HEX = "0102030405060708"
PARENT_SPAN_ID_HEX = "0807060504030201"

TRACE_ID_BYTES = bytes.fromhex(TRACE_ID_HEX)
SPAN_ID_BYTES = bytes.fromhex(SPAN_ID_HEX)
PARENT_SPAN_ID_BYTES = bytes.fromhex(PARENT_SPAN_ID_HEX)

# 2023-11-14T22:13:20Z in nanoseconds
START_NS = 1_700_000_000_000_000_000
END_NS = 1_700_000_001_000_000_000  # +1 second


def _kv_str(key: str, value: str) -> KeyValue:
    return KeyValue(key=key, value=AnyValue(string_value=value))


def _make_span(
    name: str = "test.span",
    trace_id: bytes = TRACE_ID_BYTES,
    span_id: bytes = SPAN_ID_BYTES,
    parent_span_id: bytes = b"",
    kind: int = 1,  # INTERNAL
    start_ns: int = START_NS,
    end_ns: int = END_NS,
    status_code: int = 1,  # OK
    status_message: str = "",
    attributes: list | None = None,
) -> Span:
    return Span(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        name=name,
        kind=kind,
        start_time_unix_nano=start_ns,
        end_time_unix_nano=end_ns,
        status=Status(code=status_code, message=status_message),
        attributes=attributes or [],
    )


def _make_payload(
    service_name: str = "test-service",
    spans: list | None = None,
) -> bytes:
    """Serialize one ResourceSpans (one ScopeSpans) into an ExportTraceServiceRequest."""
    resource = Resource(attributes=[_kv_str("service.name", service_name)])
    scope_spans = ScopeSpans(spans=spans or [])
    resource_spans = ResourceSpans(resource=resource, scope_spans=[scope_spans])
    return ExportTraceServiceRequest(resource_spans=[resource_spans]).SerializeToString()


# ---------------------------------------------------------------------------
# Single-span decoding
# ---------------------------------------------------------------------------


class TestSingleSpan:
    def test_returns_one_span_dict(self):
        result = decode(_make_payload(spans=[_make_span()]))
        assert len(result) == 1

    def test_result_is_list_of_dicts(self):
        result = decode(_make_payload(spans=[_make_span()]))
        assert isinstance(result, list)
        assert isinstance(result[0], dict)

    def test_span_name(self):
        result = decode(_make_payload(spans=[_make_span(name="supervisor.start")]))
        assert result[0]["span_name"] == "supervisor.start"

    def test_service_name_from_resource(self):
        result = decode(_make_payload(service_name="agentops-demo-app", spans=[_make_span()]))
        assert result[0]["service_name"] == "agentops-demo-app"

    def test_service_name_default_when_absent(self):
        resource = Resource()  # no attributes
        rs = ResourceSpans(resource=resource, scope_spans=[ScopeSpans(spans=[_make_span()])])
        payload = ExportTraceServiceRequest(resource_spans=[rs]).SerializeToString()
        result = decode(payload)
        assert result[0]["service_name"] == "unknown-service"


# ---------------------------------------------------------------------------
# ID conversion
# ---------------------------------------------------------------------------


class TestIDConversion:
    def test_trace_id_is_32_hex_chars(self):
        result = decode(_make_payload(spans=[_make_span(trace_id=TRACE_ID_BYTES)]))
        assert result[0]["trace_id"] == TRACE_ID_HEX
        assert len(result[0]["trace_id"]) == 32

    def test_span_id_is_16_hex_chars(self):
        result = decode(_make_payload(spans=[_make_span(span_id=SPAN_ID_BYTES)]))
        assert result[0]["span_id"] == SPAN_ID_HEX
        assert len(result[0]["span_id"]) == 16

    def test_trace_id_is_lowercase(self):
        # Use bytes that have values > 9 to confirm lowercase output.
        trace_bytes = bytes.fromhex("aabbccddeeff00112233445566778899")
        result = decode(_make_payload(spans=[_make_span(trace_id=trace_bytes)]))
        assert result[0]["trace_id"] == "aabbccddeeff00112233445566778899"
        assert result[0]["trace_id"] == result[0]["trace_id"].lower()

    def test_span_id_is_lowercase(self):
        span_bytes = bytes.fromhex("aabbccddeeff0011")
        result = decode(_make_payload(spans=[_make_span(span_id=span_bytes)]))
        assert result[0]["span_id"] == "aabbccddeeff0011"


# ---------------------------------------------------------------------------
# Root span / parent span
# ---------------------------------------------------------------------------


class TestParentSpanID:
    def test_root_span_parent_is_none(self):
        result = decode(_make_payload(spans=[_make_span(parent_span_id=b"")]))
        assert result[0]["parent_span_id"] is None

    def test_child_span_parent_is_hex_string(self):
        result = decode(_make_payload(spans=[_make_span(parent_span_id=PARENT_SPAN_ID_BYTES)]))
        assert result[0]["parent_span_id"] == PARENT_SPAN_ID_HEX

    def test_child_span_parent_is_16_hex_chars(self):
        result = decode(_make_payload(spans=[_make_span(parent_span_id=PARENT_SPAN_ID_BYTES)]))
        assert len(result[0]["parent_span_id"]) == 16


# ---------------------------------------------------------------------------
# Span kind
# ---------------------------------------------------------------------------


class TestSpanKind:
    @pytest.mark.parametrize(
        "kind_int, expected_str",
        [
            (0, "UNSPECIFIED"),
            (1, "INTERNAL"),
            (2, "SERVER"),
            (3, "CLIENT"),
            (4, "PRODUCER"),
            (5, "CONSUMER"),
        ],
    )
    def test_span_kind_mapping(self, kind_int: int, expected_str: str):
        result = decode(_make_payload(spans=[_make_span(kind=kind_int)]))
        assert result[0]["span_kind"] == expected_str

    def test_unknown_kind_falls_back_to_unspecified(self):
        # Protobuf allows numeric values not in the enum for forward compat.
        span = _make_span()
        span.kind = 99  # Not a defined SpanKind value
        rs = ResourceSpans(
            resource=Resource(attributes=[_kv_str("service.name", "svc")]),
            scope_spans=[ScopeSpans(spans=[span])],
        )
        result = decode(ExportTraceServiceRequest(resource_spans=[rs]).SerializeToString())
        assert result[0]["span_kind"] == "UNSPECIFIED"


# ---------------------------------------------------------------------------
# Status code and message
# ---------------------------------------------------------------------------


class TestStatus:
    @pytest.mark.parametrize(
        "code_int, expected_str",
        [
            (0, "UNSET"),
            (1, "OK"),
            (2, "ERROR"),
        ],
    )
    def test_status_code_mapping(self, code_int: int, expected_str: str):
        result = decode(_make_payload(spans=[_make_span(status_code=code_int)]))
        assert result[0]["status_code"] == expected_str

    def test_status_message_populated(self):
        result = decode(_make_payload(spans=[_make_span(status_message="upstream timeout")]))
        assert result[0]["status_message"] == "upstream timeout"

    def test_empty_status_message_is_none(self):
        result = decode(_make_payload(spans=[_make_span(status_message="")]))
        assert result[0]["status_message"] is None


# ---------------------------------------------------------------------------
# Timestamp conversion
# ---------------------------------------------------------------------------


class TestTimestamps:
    def test_start_time_is_utc_datetime(self):
        result = decode(_make_payload(spans=[_make_span(start_ns=START_NS)]))
        assert isinstance(result[0]["start_time"], datetime)
        assert result[0]["start_time"].tzinfo == timezone.utc

    def test_end_time_is_utc_datetime(self):
        result = decode(_make_payload(spans=[_make_span(end_ns=END_NS)]))
        assert isinstance(result[0]["end_time"], datetime)
        assert result[0]["end_time"].tzinfo == timezone.utc

    def test_start_time_value(self):
        result = decode(_make_payload(spans=[_make_span(start_ns=START_NS)]))
        expected = datetime.fromtimestamp(START_NS / 1_000_000_000, tz=timezone.utc)
        assert result[0]["start_time"] == expected

    def test_end_time_value(self):
        result = decode(_make_payload(spans=[_make_span(end_ns=END_NS)]))
        expected = datetime.fromtimestamp(END_NS / 1_000_000_000, tz=timezone.utc)
        assert result[0]["end_time"] == expected

    def test_end_time_is_one_second_after_start(self):
        result = decode(_make_payload(spans=[_make_span(start_ns=START_NS, end_ns=END_NS)]))
        delta = result[0]["end_time"] - result[0]["start_time"]
        assert abs(delta.total_seconds() - 1.0) < 1e-6


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------


class TestAttributes:
    def test_no_attributes_returns_empty_dict(self):
        result = decode(_make_payload(spans=[_make_span(attributes=[])]))
        assert result[0]["attributes"] == {}

    def test_string_attribute(self):
        attrs = [_kv_str("agent.name", "supervisor")]
        result = decode(_make_payload(spans=[_make_span(attributes=attrs)]))
        assert result[0]["attributes"]["agent.name"] == "supervisor"

    def test_int_attribute(self):
        kv = KeyValue(key="retrieval.result_count", value=AnyValue(int_value=5))
        result = decode(_make_payload(spans=[_make_span(attributes=[kv])]))
        assert result[0]["attributes"]["retrieval.result_count"] == 5
        assert isinstance(result[0]["attributes"]["retrieval.result_count"], int)

    def test_double_attribute(self):
        kv = KeyValue(key="retrieval.top_relevance_score", value=AnyValue(double_value=0.87))
        result = decode(_make_payload(spans=[_make_span(attributes=[kv])]))
        assert abs(result[0]["attributes"]["retrieval.top_relevance_score"] - 0.87) < 1e-9

    def test_bool_attribute(self):
        kv = KeyValue(key="some.flag", value=AnyValue(bool_value=True))
        result = decode(_make_payload(spans=[_make_span(attributes=[kv])]))
        assert result[0]["attributes"]["some.flag"] is True

    def test_bytes_attribute_is_hex_string(self):
        kv = KeyValue(key="raw.bytes", value=AnyValue(bytes_value=b"\xde\xad\xbe\xef"))
        result = decode(_make_payload(spans=[_make_span(attributes=[kv])]))
        assert result[0]["attributes"]["raw.bytes"] == "deadbeef"

    def test_multiple_attributes(self):
        attrs = [
            _kv_str("agent.name", "research"),
            _kv_str("agent.operation", "plan"),
            KeyValue(key="retrieval.result_count", value=AnyValue(int_value=3)),
        ]
        result = decode(_make_payload(spans=[_make_span(attributes=attrs)]))
        a = result[0]["attributes"]
        assert a["agent.name"] == "research"
        assert a["agent.operation"] == "plan"
        assert a["retrieval.result_count"] == 3

    def test_agentops_request_id_attribute(self):
        attrs = [_kv_str("agentops.request_id", "req_abc123")]
        result = decode(_make_payload(spans=[_make_span(attributes=attrs)]))
        assert result[0]["attributes"]["agentops.request_id"] == "req_abc123"

    def test_agentops_session_id_attribute(self):
        attrs = [_kv_str("agentops.session_id", "sess_xyz789")]
        result = decode(_make_payload(spans=[_make_span(attributes=attrs)]))
        assert result[0]["attributes"]["agentops.session_id"] == "sess_xyz789"

    def test_gen_ai_operation_attribute(self):
        attrs = [_kv_str("gen_ai.operation.name", "retrieval")]
        result = decode(_make_payload(spans=[_make_span(attributes=attrs)]))
        assert result[0]["attributes"]["gen_ai.operation.name"] == "retrieval"


# ---------------------------------------------------------------------------
# Multiple spans per record
# ---------------------------------------------------------------------------


class TestMultipleSpans:
    def test_two_spans_in_one_scope(self):
        span_a = _make_span(name="supervisor.start", span_id=bytes.fromhex("0102030405060701"))
        span_b = _make_span(name="research.plan",    span_id=bytes.fromhex("0102030405060702"))
        result = decode(_make_payload(spans=[span_a, span_b]))
        assert len(result) == 2
        names = {s["span_name"] for s in result}
        assert names == {"supervisor.start", "research.plan"}

    def test_seven_spans_in_one_record(self):
        """Mirrors the demo-app's normal seven-span trace in one Kafka record."""
        span_names = [
            "agentops.request",
            "supervisor.start",
            "research.plan",
            "retrieval.search",
            "tool.execute",
            "research.synthesize",
            "supervisor.finalize",
        ]
        spans = [
            _make_span(name=n, span_id=bytes([i + 1] + [0] * 7))
            for i, n in enumerate(span_names)
        ]
        result = decode(_make_payload(spans=spans))
        assert len(result) == 7
        assert {s["span_name"] for s in result} == set(span_names)

    def test_spans_across_multiple_resource_spans(self):
        """Two ResourceSpans in one ExportTraceServiceRequest; each carries its own service."""
        rs_a = ResourceSpans(
            resource=Resource(attributes=[_kv_str("service.name", "service-a")]),
            scope_spans=[ScopeSpans(spans=[
                _make_span(name="span-a", span_id=bytes.fromhex("0102030405060701"))
            ])],
        )
        rs_b = ResourceSpans(
            resource=Resource(attributes=[_kv_str("service.name", "service-b")]),
            scope_spans=[ScopeSpans(spans=[
                _make_span(name="span-b", span_id=bytes.fromhex("0102030405060702"))
            ])],
        )
        payload = ExportTraceServiceRequest(resource_spans=[rs_a, rs_b]).SerializeToString()
        result = decode(payload)

        assert len(result) == 2
        by_name = {s["span_name"]: s for s in result}
        assert by_name["span-a"]["service_name"] == "service-a"
        assert by_name["span-b"]["service_name"] == "service-b"

    def test_spans_across_multiple_scope_spans(self):
        """Multiple ScopeSpans within one ResourceSpans."""
        rs = ResourceSpans(
            resource=Resource(attributes=[_kv_str("service.name", "svc")]),
            scope_spans=[
                ScopeSpans(spans=[_make_span(name="span-a", span_id=bytes.fromhex("0102030405060701"))]),
                ScopeSpans(spans=[_make_span(name="span-b", span_id=bytes.fromhex("0102030405060702"))]),
            ],
        )
        payload = ExportTraceServiceRequest(resource_spans=[rs]).SerializeToString()
        result = decode(payload)
        assert len(result) == 2

    def test_all_spans_get_service_name_from_their_resource(self):
        """Each span in a ResourceSpans group inherits that resource's service.name."""
        rs = ResourceSpans(
            resource=Resource(attributes=[_kv_str("service.name", "my-service")]),
            scope_spans=[ScopeSpans(spans=[
                _make_span(name="a", span_id=bytes.fromhex("0102030405060701")),
                _make_span(name="b", span_id=bytes.fromhex("0102030405060702")),
            ])],
        )
        payload = ExportTraceServiceRequest(resource_spans=[rs]).SerializeToString()
        result = decode(payload)
        assert all(s["service_name"] == "my-service" for s in result)

    def test_empty_request_returns_empty_list(self):
        payload = ExportTraceServiceRequest().SerializeToString()
        result = decode(payload)
        assert result == []

    def test_resource_spans_with_no_spans_returns_empty_list(self):
        rs = ResourceSpans(
            resource=Resource(attributes=[_kv_str("service.name", "svc")]),
            scope_spans=[ScopeSpans(spans=[])],
        )
        payload = ExportTraceServiceRequest(resource_spans=[rs]).SerializeToString()
        result = decode(payload)
        assert result == []


# ---------------------------------------------------------------------------
# Malformed protobuf
# ---------------------------------------------------------------------------


class TestMalformedProtobuf:
    def test_empty_bytes_returns_empty_list(self):
        # b"" is a valid protobuf encoding of a message with all-default
        # (absent) fields. ParseFromString succeeds and resource_spans is [].
        result = decode(b"")
        assert result == []

    def test_truncated_varint_raises_decode_error(self):
        # \x0a = field 1 (resource_spans), wire type 2 (length-delimited).
        # \xff = varint byte with continuation bit set but no following byte.
        # This is a definitively truncated varint that cannot be decoded.
        with pytest.raises(OTLPDecodeError):
            decode(b"\x0a\xff")

    def test_truncated_valid_proto_raises_decode_error(self):
        # Build a real proto and truncate it in the middle.
        payload = _make_payload(spans=[_make_span()])
        assert len(payload) > 4, "payload too short to truncate meaningfully"
        with pytest.raises(OTLPDecodeError):
            decode(payload[: len(payload) // 2])

    def test_decode_error_message_contains_context(self):
        with pytest.raises(OTLPDecodeError, match="Failed to parse OTLP protobuf payload"):
            decode(b"\x0a\xff")

    def test_decode_error_has_cause(self):
        with pytest.raises(OTLPDecodeError) as exc_info:
            decode(b"\x0a\xff")
        assert exc_info.value.__cause__ is not None


# ---------------------------------------------------------------------------
# Output contract shape
# ---------------------------------------------------------------------------


class TestOutputContract:
    """Verify every required key is present in the returned dict."""

    REQUIRED_KEYS = {
        "trace_id",
        "span_id",
        "parent_span_id",
        "span_name",
        "span_kind",
        "start_time",
        "end_time",
        "status_code",
        "status_message",
        "service_name",
        "attributes",
    }

    def test_all_required_keys_present(self):
        result = decode(_make_payload(spans=[_make_span()]))
        assert self.REQUIRED_KEYS.issubset(result[0].keys())

    def test_no_extra_keys(self):
        result = decode(_make_payload(spans=[_make_span()]))
        assert set(result[0].keys()) == self.REQUIRED_KEYS

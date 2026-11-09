"""
stream-processor/otlp_decoder.py

Decodes raw OTLP ExportTraceServiceRequest protobuf bytes (as produced
by the OpenTelemetry Collector Kafka exporter with encoding: otlp_proto)
into a flat list of span dicts.

One Kafka record may contain many spans across multiple ResourceSpans and
ScopeSpans containers. Callers must not assume a 1:1 record-to-span ratio.

Each returned dict satisfies the normalize_span() input contract defined
in demo-app/observability/normalization.py:

    trace_id        str   32 lowercase hex chars
    span_id         str   16 lowercase hex chars
    parent_span_id  str | None
    span_name       str
    span_kind       str   "INTERNAL" | "SERVER" | "CLIENT" |
                          "PRODUCER" | "CONSUMER" | "UNSPECIFIED"
    start_time      datetime  UTC-aware
    end_time        datetime  UTC-aware
    status_code     str   "UNSET" | "OK" | "ERROR"
    status_message  str | None
    service_name    str
    attributes      dict[str, Any]
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue


# Maps OTLP SpanKind integer values to the string names used by the
# OpenTelemetry SDK (span.kind.name) and therefore by normalize_span().
_SPAN_KIND_MAP: dict[int, str] = {
    0: "UNSPECIFIED",
    1: "INTERNAL",
    2: "SERVER",
    3: "CLIENT",
    4: "PRODUCER",
    5: "CONSUMER",
}

# Maps OTLP Status.code integer values to the string names used by the
# OpenTelemetry SDK (span.status.status_code.name).
_STATUS_CODE_MAP: dict[int, str] = {
    0: "UNSET",
    1: "OK",
    2: "ERROR",
}


class OTLPDecodeError(Exception):
    """Raised when an OTLP protobuf payload cannot be parsed."""


def _decode_any_value(value: AnyValue) -> Any:
    """Convert an OTLP AnyValue to a Python-native type."""
    kind = value.WhichOneof("value")
    if kind == "string_value":
        return value.string_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "int_value":
        return value.int_value
    if kind == "double_value":
        return value.double_value
    if kind == "array_value":
        return [_decode_any_value(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return {
            kv.key: _decode_any_value(kv.value)
            for kv in value.kvlist_value.values
        }
    if kind == "bytes_value":
        # Encode as hex to preserve the bytes safely as a JSON-serialisable
        # string. Raw bytes are not valid JSON and could contain sensitive data.
        return value.bytes_value.hex()
    return None


def _decode_attributes(key_values) -> dict[str, Any]:
    return {kv.key: _decode_any_value(kv.value) for kv in key_values}


def _nanos_to_datetime(nanos: int) -> datetime:
    return datetime.fromtimestamp(nanos / 1_000_000_000, tz=timezone.utc)


def decode(payload: bytes) -> list[dict[str, Any]]:
    """
    Parse raw Kafka message bytes as an ExportTraceServiceRequest and
    return a flat list of span dicts, one entry per OTLP Span.

    The full OTLP hierarchy is traversed:
        ExportTraceServiceRequest
          → ResourceSpans  (may be many per record)
            → ScopeSpans   (may be many per ResourceSpans)
              → Span        (may be many per ScopeSpans)

    Returns an empty list when the message contains zero spans.

    Raises:
        OTLPDecodeError: if the bytes cannot be parsed as a valid
            ExportTraceServiceRequest.
    """
    request = ExportTraceServiceRequest()
    try:
        request.ParseFromString(payload)
    except Exception as exc:
        raise OTLPDecodeError(
            f"Failed to parse OTLP protobuf payload: {exc}"
        ) from exc

    spans: list[dict[str, Any]] = []

    for resource_spans in request.resource_spans:
        resource_attrs = _decode_attributes(resource_spans.resource.attributes)
        service_name: str = resource_attrs.get("service.name", "unknown-service")

        for scope_spans in resource_spans.scope_spans:
            for span in scope_spans.spans:
                trace_id: str = span.trace_id.hex()
                span_id: str = span.span_id.hex()

                # parent_span_id is b"" (empty bytes) for root spans.
                parent_span_id: str | None = (
                    span.parent_span_id.hex() if span.parent_span_id else None
                )

                span_kind: str = _SPAN_KIND_MAP.get(span.kind, "UNSPECIFIED")
                status_code: str = _STATUS_CODE_MAP.get(
                    span.status.code, "UNSET"
                )
                # Protobuf default for string is ""; map to None to match
                # the normalize_span() contract (Optional[str]).
                status_message: str | None = span.status.message or None

                attributes = _decode_attributes(span.attributes)

                spans.append(
                    {
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "parent_span_id": parent_span_id,
                        "span_name": span.name,
                        "span_kind": span_kind,
                        "start_time": _nanos_to_datetime(
                            span.start_time_unix_nano
                        ),
                        "end_time": _nanos_to_datetime(
                            span.end_time_unix_nano
                        ),
                        "status_code": status_code,
                        "status_message": status_message,
                        "service_name": service_name,
                        "attributes": attributes,
                    }
                )

    return spans

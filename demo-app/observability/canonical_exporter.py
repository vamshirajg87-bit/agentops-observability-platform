"""
observability/canonical_exporter.py

Development exporter that converts finished OpenTelemetry spans
into the canonical AgentOps telemetry schema and publishes them to Kafka.

Kafka delivery failures are logged so observability outages do not
crash the demo application.
"""

import logging
from datetime import datetime, timezone

from opentelemetry.sdk.trace.export import (
    SpanExporter,
    SpanExportResult,
)

from observability.kafka_publisher import KafkaTelemetryPublisher
from observability.normalization import normalize_span


logger = logging.getLogger(__name__)


class CanonicalSpanExporter(SpanExporter):
    def __init__(self):
        self.publisher = KafkaTelemetryPublisher()

    def export(self, spans):
        for span in spans:
            context = span.get_span_context()

            trace_id = f"{context.trace_id:032x}"
            span_id = f"{context.span_id:016x}"

            parent_span_id = None

            if span.parent is not None:
                parent_span_id = f"{span.parent.span_id:016x}"

            start_time = datetime.fromtimestamp(
                span.start_time / 1_000_000_000,
                tz=timezone.utc,
            )

            end_time = datetime.fromtimestamp(
                span.end_time / 1_000_000_000,
                tz=timezone.utc,
            )

            service_name = span.resource.attributes.get(
                "service.name",
                "unknown-service",
            )

            status_code = span.status.status_code.name

            span_data = {
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": parent_span_id,
                "span_name": span.name,
                "span_kind": span.kind.name,
                "start_time": start_time,
                "end_time": end_time,
                "status_code": status_code,
                "status_message": span.status.description,
                "service_name": service_name,
                "attributes": dict(span.attributes or {}),
            }

            canonical_event = normalize_span(span_data)

            try:
                self.publisher.publish(canonical_event)
            except Exception as exc:
                logger.error(
                    "Failed to publish canonical telemetry to Kafka: %s",
                    exc,
                )

            print(canonical_event.model_dump_json())

        return SpanExportResult.SUCCESS

    def shutdown(self):
        remaining_messages = self.publisher.flush(timeout=5.0)

        if remaining_messages > 0:
            logger.warning(
            "Kafka producer shutdown completed with %s "
            "message(s) still pending",
            remaining_messages,
        )

    
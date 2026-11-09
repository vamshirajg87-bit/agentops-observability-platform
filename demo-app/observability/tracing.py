"""
observability/tracing.py

OpenTelemetry tracing foundation for the AgentOps demo-app.
"""

import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

from observability.canonical_exporter import CanonicalSpanExporter


SERVICE_NAME = "agentops-demo-app"

_tracing_configured = False


def configure_tracing() -> None:
    global _tracing_configured

    if _tracing_configured:
        return

    resource = Resource.create(
        {
            "service.name": SERVICE_NAME,
        }
    )

    provider = TracerProvider(resource=resource)

    # Development console output.
    provider.add_span_processor(
        SimpleSpanProcessor(ConsoleSpanExporter())
    )

    # Local canonical Kafka development path.
    # Controlled by AGENTOPS_DIRECT_EXPORT env var (default: disabled).
    # The direct canonical Kafka path is retained as an optional development
    # adapter and is enabled only when explicitly requested.
    if os.environ.get("AGENTOPS_DIRECT_EXPORT", "false").lower() == "true":
        provider.add_span_processor(
            SimpleSpanProcessor(CanonicalSpanExporter())
        )

    # Production-style OTLP path to OpenTelemetry Collector.
    provider.add_span_processor(
        SimpleSpanProcessor(
            OTLPSpanExporter(
                endpoint="http://localhost:4317",
                insecure=True,
            )
        )
    )

    trace.set_tracer_provider(provider)

    _tracing_configured = True


def get_tracer(name: str):
    return trace.get_tracer(name)
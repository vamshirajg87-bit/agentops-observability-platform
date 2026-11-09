"""
stream-processor/config.py

Configuration constants for the Phase 5 stream processor.

All values can be overridden via environment variables.
Defaults target the local Docker Compose development stack.

PYTHONPATH note: Phase 5.2+ (canonicalizer) requires demo-app/ on
PYTHONPATH so shared modules (schemas.telemetry, observability.normalization)
can be imported. The decoder (Phase 5.1) has no such dependency.
Set PYTHONPATH=/path/to/demo-app before running the full processor.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Kafka connectivity
# ---------------------------------------------------------------------------

KAFKA_BOOTSTRAP_SERVERS: str = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
)

# ---------------------------------------------------------------------------
# Topics
# ---------------------------------------------------------------------------

TOPIC_OTLP_TRACES: str = os.environ.get(
    "TOPIC_OTLP_TRACES", "agentops.telemetry.otlp.traces"
)

TOPIC_SPANS: str = os.environ.get(
    "TOPIC_SPANS", "agentops.telemetry.spans"
)

TOPIC_DLQ: str = os.environ.get(
    "TOPIC_DLQ", "agentops.telemetry.dlq"
)

# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------

CONSUMER_GROUP_ID: str = os.environ.get(
    "CONSUMER_GROUP_ID", "agentops-stream-processor"
)

# "earliest" ensures no messages are missed after a fresh deployment.
# Change to "latest" for development sessions where historical replay
# is not wanted.
CONSUMER_AUTO_OFFSET_RESET: str = os.environ.get(
    "CONSUMER_AUTO_OFFSET_RESET", "earliest"
)

# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------

# Maximum delivery attempts before routing a span to the DLQ.
PUBLISH_RETRIES: int = int(os.environ.get("PUBLISH_RETRIES", "3"))

# Seconds to wait for synchronous flush confirmation per record.
# NOTE: Phase 5 uses flush-per-record for correctness: a consumer offset
# is never committed until delivery of every span in the record is
# confirmed (trusted topic or DLQ). Batched / async delivery can be
# introduced in a later phase once the correctness baseline is established.
PUBLISH_TIMEOUT_SECONDS: float = float(
    os.environ.get("PUBLISH_TIMEOUT_SECONDS", "5.0")
)

# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

# Maximum number of trace_id:span_id keys held in the in-memory dedup set.
# When the limit is reached, the set is cleared and rebuilds from new spans.
# This is a best-effort within-process guard; it provides no durable
# exactly-once guarantee across restarts or consumer rebalances.
# Phase 6 PostgreSQL UNIQUE(trace_id, span_id) is the durable constraint.
DEDUP_MAX_SIZE: int = int(os.environ.get("DEDUP_MAX_SIZE", "100000"))

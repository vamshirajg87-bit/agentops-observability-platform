"""
storage-consumer/config.py

Configuration constants for the Phase 6 storage consumer.

All values can be overridden via environment variables.
Defaults target the local Docker Compose development stack accessed from
the Windows host (Kafka and PostgreSQL exposed on localhost).

PYTHONPATH note: The storage consumer deserializes CanonicalSpanEvent from
demo-app/schemas/telemetry.py. Set PYTHONPATH to include demo-app/ before
running the storage consumer:

    $env:PYTHONPATH = "$PWD\\demo-app"          # PowerShell
    export PYTHONPATH="$PWD/demo-app"            # bash/zsh

Consumer group isolation
------------------------
CONSUMER_GROUP_ID defaults to "agentops-storage-consumer", which is
intentionally distinct from the Phase 5 stream processor group
("agentops-stream-processor"). The two services consume agentops.telemetry.spans
independently, maintaining separate committed offsets on the broker.
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

# The trusted canonical spans topic produced by the Phase 5 stream processor.
TOPIC_SPANS: str = os.environ.get(
    "TOPIC_SPANS", "agentops.telemetry.spans"
)

# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------

# Must differ from the Phase 5 stream processor group ID so the storage
# consumer maintains its own independent offset position on TOPIC_SPANS.
CONSUMER_GROUP_ID: str = os.environ.get(
    "CONSUMER_GROUP_ID", "agentops-storage-consumer"
)

# "earliest" ensures no spans are missed after a fresh deployment or restart.
CONSUMER_AUTO_OFFSET_RESET: str = os.environ.get(
    "CONSUMER_AUTO_OFFSET_RESET", "earliest"
)

# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

PG_HOST: str = os.environ.get("PG_HOST", "localhost")
PG_PORT: int = int(os.environ.get("PG_PORT", "5432"))
PG_DATABASE: str = os.environ.get("PG_DATABASE", "agentops")
PG_USER: str = os.environ.get("PG_USER", "agentops")
# Required: there is no default.  The storage consumer connects as the owner
# role, so this is the PostgreSQL owner password (POSTGRES_PASSWORD in .env).
# Left unset, the connection is attempted without a password and PostgreSQL
# refuses it.
PG_PASSWORD: str = os.environ.get("PG_PASSWORD", "")

# ---------------------------------------------------------------------------
# Timing instrumentation (opt-in)
# ---------------------------------------------------------------------------

def _timing_interval(raw: str) -> float:
    """Seconds between timing summaries; 0 (the default) turns timing off."""
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(
            f"CONSUMER_TIMING_INTERVAL_SECONDS must be a number, got {raw!r}") from None
    if not 0.0 <= value < float("inf"):
        raise ValueError("CONSUMER_TIMING_INTERVAL_SECONDS must be 0 or a positive number")
    return value


# 0 = disabled (default): the consumer does no timing work.  A positive value
# enables per-stage timing and writes one aggregate summary line to stdout
# every that many seconds, and a final summary when the consumer stops.  It
# only measures; it changes no processing, transaction or offset behavior.
TIMING_INTERVAL_SECONDS: float = _timing_interval(
    os.environ.get("CONSUMER_TIMING_INTERVAL_SECONDS", "0")
)

# ---------------------------------------------------------------------------
# Kafka offset commits (opt-in batching)
# ---------------------------------------------------------------------------

def _commit_batch_messages(raw: str) -> int:
    """Messages per Kafka offset commit; 1 (the default) is the original behavior."""
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(
            f"CONSUMER_COMMIT_BATCH_MESSAGES must be a whole number, got {raw!r}") from None
    if not 1 <= value <= 1000:
        raise ValueError("CONSUMER_COMMIT_BATCH_MESSAGES must be between 1 and 1000")
    return value


def _commit_interval_seconds(raw: str) -> float:
    """Approximate longest wait before pending offsets are committed (batching only)."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(
            f"CONSUMER_COMMIT_INTERVAL_SECONDS must be a number, got {raw!r}") from None
    if not 0.05 <= value <= 30.0:
        raise ValueError("CONSUMER_COMMIT_INTERVAL_SECONDS must be between 0.05 and 30")
    return value


# 1 = the original behavior: one synchronous Kafka commit after every message, with
# no batching code at all.  A larger value commits the offsets of persisted
# messages in batches of up to that many messages (see consumer.OffsetBatcher).
COMMIT_BATCH_MESSAGES: int = _commit_batch_messages(
    os.environ.get("CONSUMER_COMMIT_BATCH_MESSAGES", "1")
)
# Used only when COMMIT_BATCH_MESSAGES > 1.  An approximate bound, not a hard
# real-time guarantee: it is checked after each message and when a poll returns
# without one, so a slow message or commit can extend it.
COMMIT_INTERVAL_SECONDS: float = _commit_interval_seconds(
    os.environ.get("CONSUMER_COMMIT_INTERVAL_SECONDS", "1.0")
)

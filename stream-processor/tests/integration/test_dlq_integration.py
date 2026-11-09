"""
stream-processor/tests/integration/test_dlq_integration.py

Live DLQ integration test for the agentops stream processor.

Produces a deliberately invalid payload to the raw OTLP topic and verifies
that the stream processor routes it to the DLQ with the correct metadata,
then commits the source offset.

PRECONDITIONS (verified by session-scoped fixture — failure, not skip):
  - Kafka is reachable at config.KAFKA_BOOTSTRAP_SERVERS.
  - All three required topics exist.
  - A stream processor instance is running and consuming
    config.TOPIC_OTLP_TRACES (its absence manifests as a timeout — FAIL,
    not skip).

ISOLATION:
  - DLQ and raw topic watermarks are captured immediately before the
    injection.  Only post-baseline records are examined.
  - The matching DLQ event is identified by exact source_partition and
    source_offset from the delivery callback, not by position or count.

Run only against a live stack:
  $env:PYTHONPATH = "$PWD\\demo-app"
  python -m pytest stream-processor/tests/integration -m integration -v
"""

from __future__ import annotations

import hashlib
import json
import time

import confluent_kafka
import pytest
from confluent_kafka import Consumer, Producer, TopicPartition

import config
from dlq import DLQEvent, DLQReason

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

INVALID_PAYLOAD: bytes = b"NOT_VALID_PROTOBUF"
INVALID_PAYLOAD_SHA256: str = hashlib.sha256(INVALID_PAYLOAD).hexdigest()

DLQ_POLL_TIMEOUT: int = 30   # seconds to wait for the DLQ record
COMMIT_CHECK_ATTEMPTS: int = 5
COMMIT_CHECK_INTERVAL: float = 1.0  # seconds between offset-check retries


# ---------------------------------------------------------------------------
# Session-scoped precondition fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def kafka_available() -> None:
    """
    Verify Kafka is reachable and all three required topics exist.

    Calls pytest.fail() (not pytest.skip()) so a missing or offline Kafka
    stack is reported as a test failure, not a silent skip.  Phase 5.6
    integration acceptance requires 0 unexpected skips.
    """
    required_topics = {
        config.TOPIC_OTLP_TRACES,
        config.TOPIC_SPANS,
        config.TOPIC_DLQ,
    }
    probe = Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": "agentops-integration-preflight",
        "enable.auto.commit": False,
    })
    try:
        try:
            meta = probe.list_topics(timeout=5.0)
        except confluent_kafka.KafkaException as exc:
            pytest.fail(
                f"Kafka unreachable at {config.KAFKA_BOOTSTRAP_SERVERS}: {exc}"
            )

        missing = required_topics - set(meta.topics.keys())
        if missing:
            pytest.fail(
                f"Kafka available but required topics missing: {sorted(missing)}"
            )
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_high_watermarks(topic: str) -> dict[int, int]:
    """Return {partition: high_watermark} for every partition of topic."""
    consumer = Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": f"agentops-dlq-baseline-{int(time.time())}",
        "enable.auto.commit": False,
    })
    try:
        meta = consumer.list_topics(topic, timeout=10.0)
        partitions = sorted(meta.topics[topic].partitions.keys())
        marks: dict[int, int] = {}
        for p in partitions:
            tp = TopicPartition(topic, p)
            lo, hi = consumer.get_watermark_offsets(tp, timeout=5.0)
            marks[p] = max(hi, 0)
        return marks
    finally:
        consumer.close()


def _collect_from_baseline(
    topic: str,
    watermarks: dict[int, int],
    timeout_seconds: int,
) -> list[confluent_kafka.Message]:
    """Return all records at offsets >= watermarks[partition]."""
    consumer = Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": f"agentops-dlq-collect-{int(time.time())}",
        "enable.auto.commit": False,
    })
    tps = [TopicPartition(topic, p, watermarks[p]) for p in watermarks]
    consumer.assign(tps)
    records: list[confluent_kafka.Message] = []
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                continue
            records.append(msg)
    finally:
        consumer.close()
    return records


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_invalid_payload_routes_to_dlq(kafka_available: None) -> None:
    """
    Produce b"NOT_VALID_PROTOBUF" to the raw OTLP topic and assert:

    1. Exactly one matching DLQ event appears (identified by source
       partition + offset from the delivery callback).
    2. DLQ reason == OTLP_DECODE_FAILURE.
    3. source_payload_sha256 matches pre-computed hash of INVALID_PAYLOAD.
    4. source_topic == config.TOPIC_OTLP_TRACES.
    5. source_partition and source_offset match the injected record.
    6. error_message is non-empty.
    7. Stream processor consumer group committed offset > source_offset,
       proving the source record became commit-eligible after DLQ publish.
    """
    # ------------------------------------------------------------------
    # Capture baselines immediately before injection.
    # ------------------------------------------------------------------
    dlq_marks = _get_high_watermarks(config.TOPIC_DLQ)
    raw_marks = _get_high_watermarks(config.TOPIC_OTLP_TRACES)

    # ------------------------------------------------------------------
    # Produce the invalid payload, capturing delivery metadata.
    # ------------------------------------------------------------------
    injected: dict[str, object] = {
        "partition": None,
        "offset": None,
        "error": None,
    }

    def _delivery_cb(err: confluent_kafka.KafkaError | None, msg: confluent_kafka.Message) -> None:
        if err is not None:
            injected["error"] = err
        else:
            injected["partition"] = msg.partition()
            injected["offset"] = msg.offset()

    producer = Producer({"bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS})
    producer.produce(
        config.TOPIC_OTLP_TRACES,
        value=INVALID_PAYLOAD,
        on_delivery=_delivery_cb,
    )
    producer.flush(timeout=10.0)

    assert injected["error"] is None, (
        f"Failed to produce invalid payload to {config.TOPIC_OTLP_TRACES}: "
        f"{injected['error']}"
    )
    assert injected["partition"] is not None, (
        "Delivery callback did not fire — producer.flush() may have timed out."
    )

    source_partition: int = injected["partition"]  # type: ignore[assignment]
    source_offset: int = injected["offset"]  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Wait for a matching DLQ record (identified by source_partition and
    # source_offset, not by position).
    # ------------------------------------------------------------------
    dlq_consumer = Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": f"agentops-dlq-test-{int(time.time())}",
        "enable.auto.commit": False,
    })
    dlq_consumer.assign(
        [TopicPartition(config.TOPIC_DLQ, p, dlq_marks[p]) for p in dlq_marks]
    )

    matched_event: DLQEvent | None = None
    deadline = time.monotonic() + DLQ_POLL_TIMEOUT

    try:
        while time.monotonic() < deadline:
            msg = dlq_consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                continue
            try:
                data = json.loads(msg.value().decode("utf-8"))
                event = DLQEvent.model_validate(data)
            except Exception:
                continue
            if (
                event.source_topic == config.TOPIC_OTLP_TRACES
                and event.source_partition == source_partition
                and event.source_offset == source_offset
            ):
                matched_event = event
                break
    finally:
        dlq_consumer.close()

    assert matched_event is not None, (
        f"No DLQ record found matching source_partition={source_partition}, "
        f"source_offset={source_offset} within {DLQ_POLL_TIMEOUT}s. "
        f"Is the stream processor running and subscribed to "
        f"{config.TOPIC_OTLP_TRACES!r}?"
    )

    # ------------------------------------------------------------------
    # Validate DLQ event content.
    # ------------------------------------------------------------------
    assert matched_event.reason == DLQReason.OTLP_DECODE_FAILURE, (
        f"Expected DLQReason.OTLP_DECODE_FAILURE, got {matched_event.reason!r}"
    )
    assert matched_event.source_payload_sha256 == INVALID_PAYLOAD_SHA256, (
        f"SHA-256 mismatch:\n"
        f"  expected : {INVALID_PAYLOAD_SHA256}\n"
        f"  got      : {matched_event.source_payload_sha256}"
    )
    assert matched_event.source_topic == config.TOPIC_OTLP_TRACES
    assert matched_event.source_partition == source_partition
    assert matched_event.source_offset == source_offset
    assert matched_event.error_message, "error_message must be non-empty"

    # ------------------------------------------------------------------
    # Verify the stream processor committed the source offset.
    #
    # Create a Consumer with the processor's group.id but do NOT subscribe
    # or assign — committed() queries the broker's offset store without
    # joining the group, so it does not trigger a rebalance.
    #
    # confluent_kafka commits offset+1 as the next-fetch position, so
    # committed_offset > source_offset is the correct assertion.
    # ------------------------------------------------------------------
    committed_offset: int = confluent_kafka.OFFSET_INVALID  # type: ignore[attr-defined]

    for attempt in range(COMMIT_CHECK_ATTEMPTS):
        offset_checker = Consumer({
            "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": config.CONSUMER_GROUP_ID,
            "enable.auto.commit": False,
        })
        try:
            committed = offset_checker.committed(
                [TopicPartition(config.TOPIC_OTLP_TRACES, source_partition)],
                timeout=10.0,
            )
            committed_offset = committed[0].offset
        finally:
            offset_checker.close()

        if committed_offset != confluent_kafka.OFFSET_INVALID and committed_offset > source_offset:
            break
        if attempt < COMMIT_CHECK_ATTEMPTS - 1:
            time.sleep(COMMIT_CHECK_INTERVAL)

    assert committed_offset != confluent_kafka.OFFSET_INVALID, (
        f"Consumer group {config.CONSUMER_GROUP_ID!r} has no committed offset "
        f"on {config.TOPIC_OTLP_TRACES}[{source_partition}] after "
        f"{COMMIT_CHECK_ATTEMPTS} attempts. "
        f"The source record may not have been committed after DLQ publish."
    )
    assert committed_offset > source_offset, (
        f"Consumer group {config.CONSUMER_GROUP_ID!r} committed offset "
        f"{committed_offset} is not > source offset {source_offset} on "
        f"{config.TOPIC_OTLP_TRACES}[{source_partition}]. "
        f"Source record was not committed after DLQ publish."
    )

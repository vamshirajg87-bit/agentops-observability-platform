"""
stream-processor/publisher.py

Kafka publishing layer for the agentops stream processor.

DELIVERY CONTRACT
-----------------
publish_span() and publish_dlq() return normally ONLY after the broker has
positively acknowledged delivery. produce() returning without error is NOT
delivery acknowledgement — it only means the message was accepted into the
local producer buffer. Acknowledgement requires a successful delivery
callback, confirmed via flush().

Any outcome without positive acknowledgement raises a PublishError subtype.
The caller must not commit the source Kafka offset in that case.

RETRY SEMANTICS
---------------
max_attempts = 1 + retries (PUBLISH_RETRIES in config)

Retriable broker errors (KafkaError.retriable() == True) and producer
queue-full (BufferError) are retried up to retries times with exponential
backoff (2, 4, 8, ... seconds). Non-retriable broker errors fail
immediately. Delivery timeouts are NOT retried — see TIMEOUT AMBIGUITY.

TIMEOUT AMBIGUITY
-----------------
A flush/delivery timeout does NOT prove Kafka failed to accept the record.
The publisher raises PublishTimeoutError immediately and does NOT re-produce
after a timeout. Re-producing would create a second queued copy and a second
outstanding delivery callback for the same logical message. The caller must
not commit the source offset; Phase 5.5/Kafka replay provides at-least-once
retry semantics. A duplicate may still arise if the original timed-out
message eventually reached Kafka; Phase 6 PostgreSQL
UNIQUE(trace_id, span_id) is the durable idempotency backstop.

OPERATIONAL vs. DATA ERRORS
----------------------------
PublishSerializationError: internal/data error — the event could not be
    serialized. Source offset must not be committed. For publish_span(),
    Phase 5.5 must surface this as a processing failure (not converted into
    a DLQ reason; the DLQ reason taxonomy is locked in Phase 5.2). For
    publish_dlq(), never attempt to DLQ-the-DLQ.

PublishBrokerError / PublishTimeoutError: operational errors — not
    converted into DLQ data-quality events.

FUTURE THROUGHPUT
-----------------
Phase 5.4 uses synchronous per-message acknowledgement (produce + flush per
call). A future optimization may require an evolved API (batch publishing,
futures, or explicit acknowledgement draining) — it cannot be transparently
substituted behind the current synchronous return contract.

THREAD SAFETY
-------------
KafkaPublisher is NOT thread-safe. Designed for single-threaded use.

DEPENDENCIES
------------
confluent_kafka (runtime), config, dlq. No demo-app/ dependency at runtime.
CanonicalSpanEvent is referenced for type-checking only.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any, Callable

import confluent_kafka

import config
from dlq import DLQEvent

if TYPE_CHECKING:
    from schemas.telemetry import CanonicalSpanEvent


class PublishError(Exception):
    """Base class for all publishing failures."""


class PublishTimeoutError(PublishError):
    """
    Flush/delivery timeout expired before broker acknowledgement.

    Delivery outcome is AMBIGUOUS: the message may or may not have reached
    the broker. A retry may produce a duplicate. Source offset must remain
    uncommitted until a subsequent attempt is positively acknowledged.
    Phase 6 PostgreSQL UNIQUE(trace_id, span_id) is the durable backstop.
    """


class PublishBrokerError(PublishError):
    """Broker rejected or could not deliver the message."""


class PublishSerializationError(PublishError):
    """Event could not be serialized to bytes for publishing."""


class KafkaPublisher:
    """
    Publishes CanonicalSpanEvent and DLQEvent to their respective Kafka topics.

    Uses a single long-lived confluent_kafka.Producer passed at construction.
    Do not construct a new KafkaPublisher per span.

    Usage:
        with KafkaPublisher(producer, retries=3, timeout_seconds=5.0) as pub:
            pub.publish_span(event)
            pub.publish_dlq(dlq_event)
    """

    def __init__(
        self,
        producer: confluent_kafka.Producer,
        retries: int,
        timeout_seconds: float,
        _sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """
        Args:
            producer: Long-lived confluent_kafka.Producer. Not constructed here.
            retries: Number of retries AFTER the initial attempt.
                     max_attempts = 1 + retries. Must be >= 0.
            timeout_seconds: Per-flush delivery timeout. Must be > 0.
            _sleep: Sleep function injected for testing; defaults to time.sleep.

        Raises:
            ValueError: if retries < 0 or timeout_seconds <= 0.
        """
        if retries < 0:
            raise ValueError(f"retries must be >= 0; got {retries}")
        if timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be > 0; got {timeout_seconds}")
        self._producer = producer
        self._retries = retries
        self._timeout_seconds = timeout_seconds
        self._sleep = _sleep
        self._closed = False

    def publish_span(self, event: CanonicalSpanEvent) -> None:
        """
        Publish a CanonicalSpanEvent to the trusted spans topic.

        Returns normally only after broker acknowledgement.

        Topic:  config.TOPIC_SPANS
        Key:    event.trace_id encoded UTF-8 (trace partition locality)
        Value:  JSON encoding of event.model_dump(mode='json')

        Raises:
            RuntimeError: if the publisher is closed.
            PublishSerializationError: if the event cannot be serialized.
                Phase 5.5 must surface this as a processing failure —
                do NOT convert to a DLQ reason (taxonomy locked in Phase 5.2).
            PublishBrokerError: on non-retriable or exhausted broker error.
            PublishTimeoutError: on delivery timeout after all attempts.
        """
        if self._closed:
            raise RuntimeError("KafkaPublisher is closed; cannot publish")
        try:
            value: bytes = json.dumps(event.model_dump(mode='json')).encode('utf-8')
        except Exception as exc:
            raise PublishSerializationError(
                f"failed to serialize CanonicalSpanEvent: {exc}"
            ) from exc
        key: bytes = event.trace_id.encode('utf-8')
        self._publish(config.TOPIC_SPANS, key, value)

    def publish_dlq(self, event: DLQEvent) -> None:
        """
        Publish a DLQEvent to the DLQ topic.

        Returns normally only after broker acknowledgement.
        On failure, never attempt to DLQ-the-DLQ.

        Topic:  config.TOPIC_DLQ
        Key:    source_topic/source_partition/source_offset encoded UTF-8
        Value:  JSON encoding of event.model_dump(mode='json')

        Raises:
            RuntimeError: if the publisher is closed.
            PublishSerializationError: if the event cannot be serialized.
            PublishBrokerError: on non-retriable or exhausted broker error.
            PublishTimeoutError: on delivery timeout after all attempts.
        """
        if self._closed:
            raise RuntimeError("KafkaPublisher is closed; cannot publish")
        try:
            value: bytes = json.dumps(event.model_dump(mode='json')).encode('utf-8')
        except Exception as exc:
            raise PublishSerializationError(
                f"failed to serialize DLQEvent: {exc}"
            ) from exc
        key: bytes = (
            f"{event.source_topic}/{event.source_partition}/{event.source_offset}"
        ).encode('utf-8')
        self._publish(config.TOPIC_DLQ, key, value)

    def _publish(self, topic: str, key: bytes, value: bytes) -> None:
        """
        Core publish loop: produce + flush with retry/backoff.

        max_attempts = 1 + self._retries.
        Backoff before each retry: 2^attempt seconds (2, 4, 8, ...).
        """
        last_exc: PublishError | None = None
        max_attempts = 1 + self._retries

        for attempt in range(max_attempts):
            if attempt > 0:
                self._sleep(2 ** attempt)

            delivery: dict[str, Any] = {'ok': False, 'error': None}

            def _on_delivery(err: Any, msg: Any, _d: dict = delivery) -> None:
                if err is None:
                    _d['ok'] = True
                else:
                    _d['error'] = err

            try:
                self._producer.produce(
                    topic, key=key, value=value, on_delivery=_on_delivery
                )
            except BufferError as exc:
                self._producer.poll(0)
                last_exc = PublishBrokerError(
                    f"producer queue full on attempt {attempt + 1}/{max_attempts}: {exc}"
                )
                continue

            remaining = self._producer.flush(timeout=self._timeout_seconds)

            if delivery['ok']:
                return  # broker positively acknowledged

            if delivery['error'] is not None:
                err = delivery['error']
                if hasattr(err, 'retriable') and err.retriable():
                    last_exc = PublishBrokerError(
                        f"retriable broker error on attempt "
                        f"{attempt + 1}/{max_attempts}: {err}"
                    )
                    continue
                raise PublishBrokerError(f"non-retriable broker error: {err}")

            if remaining > 0:
                # Timeout — delivery outcome ambiguous.
                # Do NOT re-produce: the message may still be in the producer
                # queue; re-producing creates a second copy and a second
                # outstanding delivery callback.
                # Caller must not commit the source offset.
                # Phase 5.5/Kafka replay provides at-least-once retry semantics.
                # A duplicate may still arise if the original timed-out message
                # eventually reached Kafka; Phase 6 PostgreSQL
                # UNIQUE(trace_id, span_id) is the durable idempotency backstop.
                raise PublishTimeoutError(
                    f"delivery timeout after {self._timeout_seconds}s on attempt "
                    f"{attempt + 1}/{max_attempts}; delivery outcome is ambiguous; "
                    "publisher does not re-produce after a timeout; "
                    "caller must not commit source offset; "
                    "replay may produce a duplicate if the original message reached Kafka; "
                    "Phase 6 PostgreSQL UNIQUE(trace_id, span_id) is the durable "
                    "idempotency backstop"
                )

            raise PublishBrokerError(
                "flush returned 0 but no delivery report was received; "
                "this indicates unexpected producer behaviour"
            )

        if last_exc is None:
            raise PublishBrokerError(
                "exhausted retry loop with no recorded error (unexpected)"
            )
        raise last_exc

    def close(self) -> None:
        """
        Flush remaining in-flight messages and mark the publisher closed.
        Idempotent — safe to call multiple times. _closed is set before the
        flush so a repeated call after a timeout is always a no-op.

        Raises:
            PublishTimeoutError: if the shutdown flush does not complete
                within timeout_seconds. The publisher is still marked closed;
                subsequent calls to close() are no-ops.
        """
        if not self._closed:
            self._closed = True
            remaining = self._producer.flush(timeout=self._timeout_seconds)
            if remaining > 0:
                raise PublishTimeoutError(
                    f"shutdown flush left {remaining} undelivered message(s) "
                    f"after {self._timeout_seconds}s; "
                    "source offset must not be committed for unacknowledged messages"
                )

    def __enter__(self) -> KafkaPublisher:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

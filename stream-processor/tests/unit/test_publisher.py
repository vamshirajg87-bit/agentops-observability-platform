"""
tests/unit/test_publisher.py

Unit tests for publisher.py.

No live Kafka broker required — confluent_kafka.Producer is fully mocked.
No demo-app/ on PYTHONPATH required — CanonicalSpanEvent is replaced by
MagicMock stubs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import confluent_kafka
import pytest

from dlq import DLQEvent, DLQReason
from publisher import (
    KafkaPublisher,
    PublishBrokerError,
    PublishSerializationError,
    PublishTimeoutError,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

TRACE_ID = "0102030405060708090a0b0c0d0e0f10"
SPAN_ID = "0102030405060708"
TOPIC = "agentops.telemetry.otlp.traces"
PARTITION = 2
OFFSET = 42
UTC_NOW = datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_span_stub(trace_id: str = TRACE_ID) -> MagicMock:
    stub = MagicMock()
    stub.trace_id = trace_id
    stub.model_dump.return_value = {"trace_id": trace_id, "span_id": SPAN_ID}
    return stub


def _make_dlq_event(**kwargs) -> DLQEvent:
    defaults = dict(
        source_topic=TOPIC,
        source_partition=PARTITION,
        source_offset=OFFSET,
        failed_at=UTC_NOW,
        reason=DLQReason.OTLP_DECODE_FAILURE,
        error_message="test error",
    )
    defaults.update(kwargs)
    return DLQEvent(**defaults)


def _make_publisher(
    producer: MagicMock,
    retries: int = 0,
    timeout: float = 1.0,
) -> tuple[KafkaPublisher, MagicMock]:
    no_sleep = MagicMock()
    pub = KafkaPublisher(
        producer, retries=retries, timeout_seconds=timeout, _sleep=no_sleep
    )
    return pub, no_sleep


def _mock_producer_success() -> MagicMock:
    """Producer that fires a success delivery callback synchronously."""
    producer = MagicMock()

    def produce_side(*args, **kwargs):
        on_delivery = kwargs.get("on_delivery")
        if on_delivery:
            on_delivery(None, MagicMock())

    producer.produce.side_effect = produce_side
    producer.flush.return_value = 0
    return producer


def _mock_producer_error(retriable: bool = False) -> MagicMock:
    """Producer that fires an error delivery callback synchronously."""
    producer = MagicMock()
    err = MagicMock()
    err.retriable.return_value = retriable

    def produce_side(*args, **kwargs):
        on_delivery = kwargs.get("on_delivery")
        if on_delivery:
            on_delivery(err, None)

    producer.produce.side_effect = produce_side
    producer.flush.return_value = 0
    return producer


def _mock_producer_timeout() -> MagicMock:
    """Producer where flush times out (returns >0) and no callback fires."""
    producer = MagicMock()
    producer.flush.return_value = 1  # >0 means timeout
    return producer


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_positive_retries_and_timeout_succeeds(self):
        producer = MagicMock()
        pub = KafkaPublisher(producer, retries=3, timeout_seconds=5.0)
        assert pub is not None

    def test_zero_retries_succeeds(self):
        producer = MagicMock()
        pub = KafkaPublisher(producer, retries=0, timeout_seconds=1.0)
        assert pub is not None

    def test_negative_retries_raises_value_error(self):
        producer = MagicMock()
        with pytest.raises(ValueError, match="retries"):
            KafkaPublisher(producer, retries=-1, timeout_seconds=1.0)

    def test_zero_timeout_raises_value_error(self):
        producer = MagicMock()
        with pytest.raises(ValueError, match="timeout_seconds"):
            KafkaPublisher(producer, retries=0, timeout_seconds=0.0)

    def test_negative_timeout_raises_value_error(self):
        producer = MagicMock()
        with pytest.raises(ValueError, match="timeout_seconds"):
            KafkaPublisher(producer, retries=0, timeout_seconds=-1.0)


# ---------------------------------------------------------------------------
# Delivery contract: produce() ≠ acknowledgement
# ---------------------------------------------------------------------------


class TestDeliveryContract:
    def test_produce_without_flush_is_not_acknowledgement(self):
        """
        A producer that never calls the delivery callback (no flush side-effect)
        must NOT be treated as success — the callback must fire with ok=True.
        Here we use a timeout producer (flush returns 1, no callback) to
        show that PublishTimeoutError is raised, not a silent success.
        """
        producer = _mock_producer_timeout()
        pub, _ = _make_publisher(producer, retries=0)
        span = _make_span_stub()
        with pytest.raises(PublishTimeoutError):
            pub.publish_span(span)


# ---------------------------------------------------------------------------
# publish_span — success path
# ---------------------------------------------------------------------------


class TestPublishSpanSuccess:
    def test_returns_normally_on_broker_ack(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        span = _make_span_stub()
        pub.publish_span(span)  # must not raise

    def test_produces_to_correct_topic(self):
        import config
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_span(_make_span_stub())
        _, kwargs = producer.produce.call_args
        assert kwargs["topic"] if "topic" in kwargs else producer.produce.call_args[0][0] == config.TOPIC_SPANS

    def test_produce_called_with_correct_topic(self):
        import config
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_span(_make_span_stub())
        args, kwargs = producer.produce.call_args
        topic = args[0] if args else kwargs.get("topic")
        assert topic == config.TOPIC_SPANS

    def test_value_is_valid_json_bytes(self):
        import json
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_span(_make_span_stub())
        _, kwargs = producer.produce.call_args
        value = kwargs["value"]
        assert isinstance(value, bytes)
        parsed = json.loads(value.decode("utf-8"))
        assert "trace_id" in parsed

    def test_flush_called_with_timeout(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer, timeout=2.5)
        pub.publish_span(_make_span_stub())
        producer.flush.assert_called_once_with(timeout=2.5)


# ---------------------------------------------------------------------------
# publish_span — serialization
# ---------------------------------------------------------------------------


class TestPublishSpanSerialization:
    def test_serialization_error_raises_publish_serialization_error(self):
        producer = MagicMock()
        pub, _ = _make_publisher(producer)
        span = MagicMock()
        span.trace_id = TRACE_ID
        span.model_dump.side_effect = RuntimeError("cannot serialize")
        with pytest.raises(PublishSerializationError):
            pub.publish_span(span)

    def test_produce_not_called_on_serialization_error(self):
        producer = MagicMock()
        pub, _ = _make_publisher(producer)
        span = MagicMock()
        span.trace_id = TRACE_ID
        span.model_dump.side_effect = RuntimeError("cannot serialize")
        with pytest.raises(PublishSerializationError):
            pub.publish_span(span)
        producer.produce.assert_not_called()


# ---------------------------------------------------------------------------
# publish_dlq — success path
# ---------------------------------------------------------------------------


class TestPublishDLQSuccess:
    def test_returns_normally_on_broker_ack(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        dlq_event = _make_dlq_event()
        pub.publish_dlq(dlq_event)  # must not raise

    def test_produce_called_with_correct_topic(self):
        import config
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_dlq(_make_dlq_event())
        args, kwargs = producer.produce.call_args
        topic = args[0] if args else kwargs.get("topic")
        assert topic == config.TOPIC_DLQ

    def test_value_is_valid_json_bytes(self):
        import json
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_dlq(_make_dlq_event())
        _, kwargs = producer.produce.call_args
        value = kwargs["value"]
        assert isinstance(value, bytes)
        parsed = json.loads(value.decode("utf-8"))
        assert "reason" in parsed


# ---------------------------------------------------------------------------
# publish_dlq — serialization
# ---------------------------------------------------------------------------


class TestPublishDLQSerialization:
    def test_serialization_error_raises_publish_serialization_error(self):
        producer = MagicMock()
        pub, _ = _make_publisher(producer)
        event = MagicMock(spec=DLQEvent)
        event.source_topic = TOPIC
        event.source_partition = PARTITION
        event.source_offset = OFFSET
        event.model_dump.side_effect = RuntimeError("bad serialization")
        with pytest.raises(PublishSerializationError):
            pub.publish_dlq(event)

    def test_produce_not_called_on_serialization_error(self):
        producer = MagicMock()
        pub, _ = _make_publisher(producer)
        event = MagicMock(spec=DLQEvent)
        event.source_topic = TOPIC
        event.source_partition = PARTITION
        event.source_offset = OFFSET
        event.model_dump.side_effect = RuntimeError("bad serialization")
        with pytest.raises(PublishSerializationError):
            pub.publish_dlq(event)
        producer.produce.assert_not_called()


# ---------------------------------------------------------------------------
# Trusted-span key
# ---------------------------------------------------------------------------


class TestTrustedKey:
    def test_span_key_is_trace_id_bytes(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_span(_make_span_stub(trace_id=TRACE_ID))
        _, kwargs = producer.produce.call_args
        assert kwargs["key"] == TRACE_ID.encode("utf-8")

    def test_span_key_preserves_trace_partition_locality(self):
        """Two spans with the same trace_id produce the same key."""
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_span(_make_span_stub(trace_id=TRACE_ID))
        key1 = producer.produce.call_args[1]["key"]

        producer2 = _mock_producer_success()
        pub2, _ = _make_publisher(producer2)
        pub2.publish_span(_make_span_stub(trace_id=TRACE_ID))
        key2 = producer2.produce.call_args[1]["key"]

        assert key1 == key2


# ---------------------------------------------------------------------------
# DLQ key
# ---------------------------------------------------------------------------


class TestDLQKey:
    def test_dlq_key_is_source_coordinates(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.publish_dlq(_make_dlq_event())
        _, kwargs = producer.produce.call_args
        expected_key = f"{TOPIC}/{PARTITION}/{OFFSET}".encode("utf-8")
        assert kwargs["key"] == expected_key

    def test_dlq_key_differs_for_different_source_coordinates(self):
        producer1 = _mock_producer_success()
        pub1, _ = _make_publisher(producer1)
        pub1.publish_dlq(_make_dlq_event(source_offset=1))
        key1 = producer1.produce.call_args[1]["key"]

        producer2 = _mock_producer_success()
        pub2, _ = _make_publisher(producer2)
        pub2.publish_dlq(_make_dlq_event(source_offset=2))
        key2 = producer2.produce.call_args[1]["key"]

        assert key1 != key2


# ---------------------------------------------------------------------------
# Broker delivery error — non-retriable
# ---------------------------------------------------------------------------


class TestBrokerDeliveryError:
    def test_non_retriable_error_raises_immediately(self):
        producer = _mock_producer_error(retriable=False)
        pub, _ = _make_publisher(producer, retries=3)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())

    def test_non_retriable_error_does_not_retry(self):
        producer = _mock_producer_error(retriable=False)
        pub, _ = _make_publisher(producer, retries=3)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())
        # Should have called produce exactly once (no retry)
        assert producer.produce.call_count == 1


# ---------------------------------------------------------------------------
# Retriable broker failure
# ---------------------------------------------------------------------------


class TestRetriableBrokerFailure:
    def test_retriable_exhausted_raises_publish_broker_error(self):
        producer = _mock_producer_error(retriable=True)
        pub, _ = _make_publisher(producer, retries=2)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())

    def test_retriable_then_success_returns_normally(self):
        producer = MagicMock()
        err = MagicMock()
        err.retriable.return_value = True
        call_count = {"n": 0}

        def produce_side(*args, **kwargs):
            on_delivery = kwargs.get("on_delivery")
            call_count["n"] += 1
            if on_delivery:
                if call_count["n"] == 1:
                    on_delivery(err, None)  # first call: retriable error
                else:
                    on_delivery(None, MagicMock())  # second call: success

        producer.produce.side_effect = produce_side
        producer.flush.return_value = 0

        pub, _ = _make_publisher(producer, retries=2)
        pub.publish_span(_make_span_stub())  # must not raise


# ---------------------------------------------------------------------------
# max_attempts
# ---------------------------------------------------------------------------


class TestMaxAttempts:
    def test_retries_3_means_4_produce_calls(self):
        producer = _mock_producer_error(retriable=True)
        pub, _ = _make_publisher(producer, retries=3)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())
        assert producer.produce.call_count == 4

    def test_retries_0_means_1_produce_call(self):
        producer = _mock_producer_error(retriable=True)
        pub, _ = _make_publisher(producer, retries=0)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())
        assert producer.produce.call_count == 1


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


class TestTimeout:
    def test_timeout_raises_publish_timeout_error(self):
        producer = _mock_producer_timeout()
        pub, _ = _make_publisher(producer, retries=0)
        with pytest.raises(PublishTimeoutError):
            pub.publish_span(_make_span_stub())

    def test_timeout_error_message_mentions_duplicate(self):
        producer = _mock_producer_timeout()
        pub, _ = _make_publisher(producer, retries=0)
        with pytest.raises(PublishTimeoutError, match="duplicate"):
            pub.publish_span(_make_span_stub())

    def test_timeout_performs_exactly_one_produce_call_even_with_retries(self):
        """Timeout must not re-produce; retries > 0 must not change that."""
        producer = _mock_producer_timeout()
        pub, _ = _make_publisher(producer, retries=3)
        with pytest.raises(PublishTimeoutError):
            pub.publish_span(_make_span_stub())
        assert producer.produce.call_count == 1


# ---------------------------------------------------------------------------
# BufferError
# ---------------------------------------------------------------------------


class TestBufferError:
    def test_buffer_error_triggers_poll_then_retry(self):
        producer = MagicMock()
        call_count = {"n": 0}

        def produce_side(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise BufferError("queue full")
            on_delivery = kwargs.get("on_delivery")
            if on_delivery:
                on_delivery(None, MagicMock())

        producer.produce.side_effect = produce_side
        producer.flush.return_value = 0

        pub, _ = _make_publisher(producer, retries=2)
        pub.publish_span(_make_span_stub())  # must not raise
        producer.poll.assert_called_with(0)

    def test_buffer_error_exhausted_raises_publish_broker_error(self):
        producer = MagicMock()
        producer.produce.side_effect = BufferError("always full")
        producer.flush.return_value = 0

        pub, _ = _make_publisher(producer, retries=2)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())

    def test_buffer_error_exhausted_attempts_equals_max_attempts(self):
        producer = MagicMock()
        producer.produce.side_effect = BufferError("always full")
        producer.flush.return_value = 0

        pub, _ = _make_publisher(producer, retries=2)
        with pytest.raises(PublishBrokerError):
            pub.publish_span(_make_span_stub())
        # retries=2 → max_attempts=3 → 3 produce calls
        assert producer.produce.call_count == 3


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_flushes_with_timeout(self):
        producer = MagicMock()
        producer.flush.return_value = 0
        pub, _ = _make_publisher(producer, timeout=3.0)
        pub.close()
        producer.flush.assert_called_with(timeout=3.0)

    def test_close_is_idempotent(self):
        """Double-close must flush only once."""
        producer = MagicMock()
        producer.flush.return_value = 0
        pub, _ = _make_publisher(producer)
        pub.close()
        flush_count_after_first = producer.flush.call_count
        pub.close()
        assert producer.flush.call_count == flush_count_after_first

    def test_post_close_publish_span_raises_runtime_error(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.close()
        with pytest.raises(RuntimeError, match="closed"):
            pub.publish_span(_make_span_stub())

    def test_post_close_publish_dlq_raises_runtime_error(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        pub.close()
        with pytest.raises(RuntimeError, match="closed"):
            pub.publish_dlq(_make_dlq_event())

    def test_close_flush_zero_succeeds(self):
        producer = MagicMock()
        producer.flush.return_value = 0
        pub, _ = _make_publisher(producer)
        pub.close()  # must not raise

    def test_close_flush_nonzero_raises_publish_timeout_error(self):
        producer = MagicMock()
        producer.flush.return_value = 1
        pub, _ = _make_publisher(producer)
        with pytest.raises(PublishTimeoutError):
            pub.close()

    def test_repeated_close_after_successful_close_is_harmless(self):
        producer = MagicMock()
        producer.flush.return_value = 0
        pub, _ = _make_publisher(producer)
        pub.close()
        pub.close()  # must not raise; flush called only once
        assert producer.flush.call_count == 1


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_enter_returns_publisher(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        result = pub.__enter__()
        assert result is pub

    def test_exit_calls_close(self):
        producer = MagicMock()
        producer.flush.return_value = 0
        pub, _ = _make_publisher(producer)
        pub.__exit__(None, None, None)
        producer.flush.assert_called_once()

    def test_context_manager_calls_close_on_exception(self):
        producer = _mock_producer_error(retriable=False)
        pub, _ = _make_publisher(producer)
        with pytest.raises(PublishBrokerError):
            with pub:
                pub.publish_span(_make_span_stub())
        # close() must have been called (flush called at least once for the close)
        assert producer.flush.call_count >= 1

    def test_with_block_normal_exit_closes_publisher(self):
        producer = _mock_producer_success()
        pub, _ = _make_publisher(producer)
        with pub:
            pub.publish_span(_make_span_stub())
        # After the with block, publisher is closed
        with pytest.raises(RuntimeError, match="closed"):
            pub.publish_span(_make_span_stub())

    def test_context_manager_propagates_close_timeout(self):
        """__exit__ must propagate PublishTimeoutError raised by close()."""
        producer = MagicMock()
        producer.flush.return_value = 1  # shutdown flush times out
        pub, _ = _make_publisher(producer)
        with pytest.raises(PublishTimeoutError):
            with pub:
                pass  # normal body exit triggers close()

"""
tests/unit/test_processor.py

Unit tests for processor.py.

All external dependencies (otlp_decoder.decode, canonicalizer.canonicalize,
confluent_kafka.Consumer, KafkaPublisher) are mocked. No live Kafka required.

Run with demo-app/ on PYTHONPATH:
    PYTHONPATH=/path/to/demo-app python -m pytest tests/unit/test_processor.py -v
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

import processor as _proc_module
from canonicalizer import CanonicalizationError, CanonicalizationErrorType
from deduplicator import SpanDeduplicator
from dlq import DLQReason
from otlp_decoder import OTLPDecodeError
from processor import process_message, run_consumer_loop
from publisher import PublishBrokerError, PublishSerializationError, PublishTimeoutError

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

TOPIC = "agentops.telemetry.otlp.traces"
PARTITION = 0
OFFSET = 42

TID_A = "aa" * 16  # 32 hex chars
TID_B = "bb" * 16
TID_C = "cc" * 16
SID_A = "11" * 8   # 16 hex chars
SID_B = "22" * 8
SID_C = "33" * 8

PAYLOAD = b"fake-otlp-bytes"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_msg(value=PAYLOAD, topic=TOPIC, partition=PARTITION, offset=OFFSET):
    msg = MagicMock()
    msg.value.return_value = value
    msg.topic.return_value = topic
    msg.partition.return_value = partition
    msg.offset.return_value = offset
    msg.error.return_value = None
    return msg


def make_span_event(trace_id=TID_A, span_id=SID_A):
    event = MagicMock()
    event.trace_id = trace_id
    event.span_id = span_id
    return event


def make_span_dict(trace_id=TID_A, span_id=SID_A, service_name="svc"):
    return {"trace_id": trace_id, "span_id": span_id, "service_name": service_name}


def make_publisher():
    pub = MagicMock()
    pub.publish_span.return_value = None
    pub.publish_dlq.return_value = None
    pub.close.return_value = None
    return pub


def make_dedup(max_size=100):
    return SpanDeduplicator(max_size=max_size)


def make_mock_dedup():
    d = MagicMock()
    d.contains.return_value = False
    d.mark.return_value = None
    return d


def canon_exc(kind=CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE, msg="bad span"):
    return CanonicalizationError(kind, msg)


def make_raise(exc):
    """Return a callable that raises exc when called with any argument."""
    def _raise(_):
        raise exc
    return _raise


# ---------------------------------------------------------------------------
# process_message — happy path
# ---------------------------------------------------------------------------

class TestProcessMessageHappyPath:
    def test_single_span_published_and_marked(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_span.assert_called_once_with(event)
        dedup.mark.assert_called_once_with(event.trace_id, event.span_id)

    def test_multi_span_all_published(self, monkeypatch):
        events = [make_span_event(TID_A, SID_A), make_span_event(TID_B, SID_B)]
        span_dicts = [make_span_dict(TID_A, SID_A), make_span_dict(TID_B, SID_B)]

        monkeypatch.setattr(_proc_module, "decode", lambda _: span_dicts)
        it = iter(events)
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: next(it))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        assert pub.publish_span.call_count == 2
        assert dedup.mark.call_count == 2

    def test_duplicate_skipped_no_publish_no_mark(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        dedup = make_mock_dedup()
        dedup.contains.return_value = True  # already seen

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_span.assert_not_called()
        dedup.mark.assert_not_called()

    def test_mixed_duplicate_and_new_in_batch(self, monkeypatch):
        ev_a = make_span_event(TID_A, SID_A)
        ev_b = make_span_event(TID_B, SID_B)
        span_dicts = [make_span_dict(TID_A, SID_A), make_span_dict(TID_B, SID_B)]

        monkeypatch.setattr(_proc_module, "decode", lambda _: span_dicts)
        events_iter = iter([ev_a, ev_b])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: next(events_iter))

        pub = make_publisher()
        dedup = make_mock_dedup()
        # A is duplicate, B is new
        dedup.contains.side_effect = lambda tid, sid: tid == TID_A

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_span.assert_called_once_with(ev_b)
        dedup.mark.assert_called_once_with(ev_b.trace_id, ev_b.span_id)

    def test_empty_decode_result_returns_normally(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_span.assert_not_called()
        pub.publish_dlq.assert_not_called()


# ---------------------------------------------------------------------------
# process_message — publish/mark ordering
# ---------------------------------------------------------------------------

class TestPublishMarkOrdering:
    def test_publish_occurs_before_mark(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        call_log: list[str] = []
        pub = make_publisher()
        pub.publish_span.side_effect = lambda e: call_log.append("publish_span")
        dedup = make_mock_dedup()
        dedup.mark.side_effect = lambda t, s: call_log.append("mark")

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        assert call_log == ["publish_span", "mark"]

    def test_mark_not_called_when_publish_span_raises(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        pub.publish_span.side_effect = PublishBrokerError("broker down")
        dedup = make_mock_dedup()

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        dedup.mark.assert_not_called()


# ---------------------------------------------------------------------------
# process_message — None payload
# ---------------------------------------------------------------------------

class TestNonePayload:
    def test_none_payload_publishes_otlp_decode_failure_dlq(self, monkeypatch):
        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=None), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_dlq.assert_called_once()
        evt = pub.publish_dlq.call_args[0][0]
        assert evt.reason == DLQReason.OTLP_DECODE_FAILURE
        assert evt.error_message == "Kafka message value is None"

    def test_none_payload_source_payload_sha256_is_none(self, monkeypatch):
        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=None), pub, dedup, TOPIC, PARTITION, OFFSET)

        evt = pub.publish_dlq.call_args[0][0]
        assert evt.source_payload_sha256 is None

    def test_none_payload_dlq_publish_failure_propagates(self, monkeypatch):
        pub = make_publisher()
        pub.publish_dlq.side_effect = PublishBrokerError("broker down")
        dedup = make_mock_dedup()

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(value=None), pub, dedup, TOPIC, PARTITION, OFFSET)

    def test_none_payload_does_not_call_decode(self, monkeypatch):
        decode_called = [False]

        def spy_decode(_):
            decode_called[0] = True
            return []

        monkeypatch.setattr(_proc_module, "decode", spy_decode)

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=None), pub, dedup, TOPIC, PARTITION, OFFSET)

        assert not decode_called[0]

    def test_none_payload_does_not_publish_trusted_span(self, monkeypatch):
        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=None), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_span.assert_not_called()

    def test_none_payload_dlq_source_coords_correct(self, monkeypatch):
        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=None), pub, dedup, TOPIC, 3, 99)

        evt = pub.publish_dlq.call_args[0][0]
        assert evt.source_topic == TOPIC
        assert evt.source_partition == 3
        assert evt.source_offset == 99


# ---------------------------------------------------------------------------
# process_message — empty bytes payload (b'')
# ---------------------------------------------------------------------------

class TestEmptyBytesPayload:
    def test_empty_bytes_decode_returns_empty_list_normal_return(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        pub = make_publisher()
        dedup = make_mock_dedup()

        # Must return normally (no exception)
        process_message(make_msg(value=b""), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_dlq.assert_not_called()
        pub.publish_span.assert_not_called()

    def test_empty_bytes_sha256_is_computed(self, monkeypatch):
        """b'' is a bytes payload; sha256 must be computed."""
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        sha_inputs: list[bytes] = []
        original = hashlib.sha256

        def recording_sha256(data):
            sha_inputs.append(data)
            return original(data)

        monkeypatch.setattr(hashlib, "sha256", recording_sha256)

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=b""), pub, dedup, TOPIC, PARTITION, OFFSET)

        assert sha_inputs == [b""]


# ---------------------------------------------------------------------------
# process_message — decode failure
# ---------------------------------------------------------------------------

class TestDecodeFailure:
    def test_decode_failure_publishes_exactly_one_dlq(self, monkeypatch):
        exc = OTLPDecodeError("bad proto")
        monkeypatch.setattr(_proc_module, "decode", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_dlq.assert_called_once()

    def test_decode_failure_dlq_reason_is_otlp_decode_failure(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", make_raise(OTLPDecodeError("bad")))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        evt = pub.publish_dlq.call_args[0][0]
        assert evt.reason == DLQReason.OTLP_DECODE_FAILURE

    def test_decode_failure_dlq_includes_sha256(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", make_raise(OTLPDecodeError("bad")))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=PAYLOAD), pub, dedup, TOPIC, PARTITION, OFFSET)

        evt = pub.publish_dlq.call_args[0][0]
        assert evt.source_payload_sha256 == hashlib.sha256(PAYLOAD).hexdigest()

    def test_decode_failure_dlq_publish_failure_propagates(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", make_raise(OTLPDecodeError("bad")))

        pub = make_publisher()
        pub.publish_dlq.side_effect = PublishBrokerError("broker down")
        dedup = make_mock_dedup()

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

    def test_decode_failure_returns_normally_after_dlq_ack(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", make_raise(OTLPDecodeError("bad")))

        pub = make_publisher()
        dedup = make_mock_dedup()

        # Must not raise
        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)


# ---------------------------------------------------------------------------
# process_message — canonicalization failure
# ---------------------------------------------------------------------------

class TestCanonicalizationFailure:
    def test_schema_validation_failure_dlqs_span(self, monkeypatch):
        exc = canon_exc(CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE)
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_dlq.assert_called_once()
        evt = pub.publish_dlq.call_args[0][0]
        assert evt.reason == DLQReason.SCHEMA_VALIDATION_FAILURE

    def test_unexpected_failure_maps_to_canonicalization_failure(self, monkeypatch):
        exc = canon_exc(CanonicalizationErrorType.UNEXPECTED_FAILURE)
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        evt = pub.publish_dlq.call_args[0][0]
        assert evt.reason == DLQReason.CANONICALIZATION_FAILURE

    def test_multiple_canonicalization_failures_reuse_same_sha(self, monkeypatch):
        exc = canon_exc()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [
            make_span_dict(TID_A, SID_A),
            make_span_dict(TID_B, SID_B),
        ])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=PAYLOAD), pub, dedup, TOPIC, PARTITION, OFFSET)

        assert pub.publish_dlq.call_count == 2
        expected_sha = hashlib.sha256(PAYLOAD).hexdigest()
        for c in pub.publish_dlq.call_args_list:
            assert c[0][0].source_payload_sha256 == expected_sha

    def test_canonicalization_failure_continues_to_next_span(self, monkeypatch):
        """A failed span does not abort processing of subsequent spans."""
        ev_b = make_span_event(TID_B, SID_B)
        call_count = [0]

        def canon_side(sd):
            call_count[0] += 1
            if sd["trace_id"] == TID_A:
                raise canon_exc()
            return ev_b

        monkeypatch.setattr(_proc_module, "decode", lambda _: [
            make_span_dict(TID_A, SID_A),
            make_span_dict(TID_B, SID_B),
        ])
        monkeypatch.setattr(_proc_module, "canonicalize", canon_side)

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_dlq.assert_called_once()  # only A failed
        pub.publish_span.assert_called_once_with(ev_b)

    def test_malformed_span_never_enters_dedupe(self, monkeypatch):
        exc = canon_exc()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        dedup.contains.assert_not_called()
        dedup.mark.assert_not_called()

    def test_canonicalization_dlq_publish_failure_propagates(self, monkeypatch):
        exc = canon_exc()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        pub.publish_dlq.side_effect = PublishBrokerError("broker down")
        dedup = make_mock_dedup()

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)


# ---------------------------------------------------------------------------
# process_message — publish_span failures
# ---------------------------------------------------------------------------

class TestPublishSpanFailures:
    def test_publish_broker_error_propagates(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        pub.publish_span.side_effect = PublishBrokerError("broker down")
        dedup = make_mock_dedup()

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

    def test_publish_timeout_error_propagates(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        pub.publish_span.side_effect = PublishTimeoutError("timeout")
        dedup = make_mock_dedup()

        with pytest.raises(PublishTimeoutError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

    def test_publish_serialization_error_propagates(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        pub.publish_span.side_effect = PublishSerializationError("bad event")
        dedup = make_mock_dedup()

        with pytest.raises(PublishSerializationError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

    def test_trusted_publish_failure_does_not_call_dlq(self, monkeypatch):
        event = make_span_event()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [make_span_dict()])
        monkeypatch.setattr(_proc_module, "canonicalize", lambda _: event)

        pub = make_publisher()
        pub.publish_span.side_effect = PublishBrokerError("broker down")
        dedup = make_mock_dedup()

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_dlq.assert_not_called()


# ---------------------------------------------------------------------------
# process_message — SHA-256 semantics
# ---------------------------------------------------------------------------

class TestSHA256Semantics:
    def test_sha256_computed_once_per_message(self, monkeypatch):
        """SHA-256 is computed once; all DLQ events share the same digest."""
        sha_inputs: list[bytes] = []
        original = hashlib.sha256

        def recording_sha256(data):
            sha_inputs.append(data)
            return original(data)

        monkeypatch.setattr(hashlib, "sha256", recording_sha256)

        exc = canon_exc()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [
            make_span_dict(TID_A, SID_A),
            make_span_dict(TID_B, SID_B),
            make_span_dict(TID_C, SID_C),
        ])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=PAYLOAD), pub, dedup, TOPIC, PARTITION, OFFSET)

        assert sha_inputs == [PAYLOAD]

    def test_sha256_reused_across_dlq_events(self, monkeypatch):
        exc = canon_exc()
        monkeypatch.setattr(_proc_module, "decode", lambda _: [
            make_span_dict(TID_A, SID_A),
            make_span_dict(TID_B, SID_B),
        ])
        monkeypatch.setattr(_proc_module, "canonicalize", make_raise(exc))

        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=PAYLOAD), pub, dedup, TOPIC, PARTITION, OFFSET)

        expected_sha = hashlib.sha256(PAYLOAD).hexdigest()
        for c in pub.publish_dlq.call_args_list:
            assert c[0][0].source_payload_sha256 == expected_sha

    def test_sha256_none_for_none_payload(self, monkeypatch):
        pub = make_publisher()
        dedup = make_mock_dedup()

        process_message(make_msg(value=None), pub, dedup, TOPIC, PARTITION, OFFSET)

        evt = pub.publish_dlq.call_args[0][0]
        assert evt.source_payload_sha256 is None


# ---------------------------------------------------------------------------
# process_message — same-process partial-failure replay
# ---------------------------------------------------------------------------

class TestPartialFailureReplay:
    def test_earlier_spans_skipped_failed_span_retried(self, monkeypatch):
        """
        Record with spans A, B, C:
        - A and B publish successfully → marked
        - C publish fails → process_message raises; source offset NOT committed

        On same-process retry:
        - A and B: contains() True → skipped (not re-published)
        - C: contains() False → publish_span called again
        """
        ev_a = make_span_event(TID_A, SID_A)
        ev_b = make_span_event(TID_B, SID_B)
        ev_c = make_span_event(TID_C, SID_C)

        span_dicts = [
            make_span_dict(TID_A, SID_A),
            make_span_dict(TID_B, SID_B),
            make_span_dict(TID_C, SID_C),
        ]
        events_map = {
            (TID_A, SID_A): ev_a,
            (TID_B, SID_B): ev_b,
            (TID_C, SID_C): ev_c,
        }

        def mock_canonicalize(sd):
            return events_map[(sd["trace_id"], sd["span_id"])]

        monkeypatch.setattr(_proc_module, "decode", lambda _: span_dicts)
        monkeypatch.setattr(_proc_module, "canonicalize", mock_canonicalize)

        dedup = make_dedup(max_size=10)
        pub = make_publisher()

        # First attempt: A and B succeed, C fails
        pub.publish_span.side_effect = [
            None,                          # A succeeds
            None,                          # B succeeds
            PublishBrokerError("C failed"), # C fails
        ]

        with pytest.raises(PublishBrokerError):
            process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        # A and B were marked; C was not
        assert dedup.contains(TID_A, SID_A) is True
        assert dedup.contains(TID_B, SID_B) is True
        assert dedup.contains(TID_C, SID_C) is False

        # Second attempt (replay): C should be re-tried; A and B skipped
        pub.publish_span.side_effect = None  # all succeed
        pub.publish_span.reset_mock()

        process_message(make_msg(), pub, dedup, TOPIC, PARTITION, OFFSET)

        pub.publish_span.assert_called_once_with(ev_c)


# ---------------------------------------------------------------------------
# run_consumer_loop — poll behavior
# ---------------------------------------------------------------------------

class TestRunConsumerLoopPoll:
    def test_none_poll_continues_without_commit(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        pub = make_publisher()
        consumer = MagicMock()
        shutdown = threading.Event()

        poll_count = [0]

        def poll_side(**_kwargs):
            poll_count[0] += 1
            if poll_count[0] >= 3:
                shutdown.set()
            return None

        consumer.poll.side_effect = poll_side

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.commit.assert_not_called()

    def test_pre_set_shutdown_exits_without_polling(self):
        pub = make_publisher()
        consumer = MagicMock()
        shutdown = threading.Event()
        shutdown.set()

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.poll.assert_not_called()
        consumer.commit.assert_not_called()


# ---------------------------------------------------------------------------
# run_consumer_loop — msg.error() handling
# ---------------------------------------------------------------------------

class TestRunConsumerLoopConsumerError:
    def _make_error_msg(self):
        msg = MagicMock()
        msg.error.return_value = MagicMock()  # non-None error
        return msg

    def test_consumer_error_halts_loop(self):
        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = self._make_error_msg()
        shutdown = threading.Event()

        with pytest.raises(RuntimeError, match="consumer error"):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

    def test_consumer_error_no_process_message_called(self, monkeypatch):
        pm_called = [False]

        def spy_pm(*args, **kwargs):
            pm_called[0] = True

        monkeypatch.setattr(_proc_module, "process_message", spy_pm)

        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = self._make_error_msg()
        shutdown = threading.Event()

        with pytest.raises(RuntimeError):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        assert not pm_called[0]

    def test_consumer_error_no_dlq_published(self):
        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = self._make_error_msg()
        shutdown = threading.Event()

        with pytest.raises(RuntimeError):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        pub.publish_dlq.assert_not_called()

    def test_consumer_error_no_commit(self):
        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = self._make_error_msg()
        shutdown = threading.Event()

        with pytest.raises(RuntimeError):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.commit.assert_not_called()


# ---------------------------------------------------------------------------
# run_consumer_loop — commit semantics
# ---------------------------------------------------------------------------

class TestRunConsumerLoopCommit:
    def _setup_single_message_loop(self, monkeypatch, msg=None):
        """Delivers one message then sets shutdown to exit cleanly."""
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        pub = make_publisher()
        consumer = MagicMock()
        shutdown = threading.Event()
        msg = msg or make_msg()

        call_count = [0]

        def poll_side(**_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return msg
            shutdown.set()
            return None

        consumer.poll.side_effect = poll_side
        consumer.commit.return_value = None
        return pub, consumer, shutdown, msg

    def test_successful_message_commits_offset(self, monkeypatch):
        pub, consumer, shutdown, msg = self._setup_single_message_loop(monkeypatch)

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.commit.assert_called_once_with(message=msg, asynchronous=False)

    def test_exact_msg_object_passed_to_commit(self, monkeypatch):
        pub, consumer, shutdown, msg = self._setup_single_message_loop(monkeypatch)

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        commit_call = consumer.commit.call_args
        assert commit_call.kwargs["message"] is msg

    def test_commit_uses_asynchronous_false(self, monkeypatch):
        pub, consumer, shutdown, msg = self._setup_single_message_loop(monkeypatch)

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        commit_call = consumer.commit.call_args
        assert commit_call.kwargs["asynchronous"] is False

    def test_process_message_exception_no_commit(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode",
                            make_raise(OTLPDecodeError("bad")))

        pub = make_publisher()
        pub.publish_dlq.side_effect = PublishBrokerError("dlq broker down")
        consumer = MagicMock()
        consumer.poll.return_value = make_msg()
        shutdown = threading.Event()

        with pytest.raises(PublishBrokerError):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.commit.assert_not_called()

    def test_commit_failure_propagates(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = make_msg()
        consumer.commit.side_effect = Exception("commit failed")
        shutdown = threading.Event()

        with pytest.raises(Exception, match="commit failed"):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

    def test_commit_failure_does_not_cause_second_commit(self, monkeypatch):
        monkeypatch.setattr(_proc_module, "decode", lambda _: [])

        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = make_msg()
        consumer.commit.side_effect = Exception("commit failed")
        shutdown = threading.Event()

        with pytest.raises(Exception):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.commit.assert_called_once()


# ---------------------------------------------------------------------------
# run_consumer_loop — cleanup guarantees
# ---------------------------------------------------------------------------

class TestRunConsumerLoopCleanup:
    def test_publisher_closed_on_normal_shutdown(self):
        pub = make_publisher()
        consumer = MagicMock()
        shutdown = threading.Event()
        shutdown.set()

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        pub.close.assert_called_once()

    def test_consumer_closed_on_normal_shutdown(self):
        pub = make_publisher()
        consumer = MagicMock()
        shutdown = threading.Event()
        shutdown.set()

        run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.close.assert_called_once()

    def test_publisher_closed_after_loop_exception(self):
        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = make_msg()
        consumer.commit.side_effect = Exception("commit failed")
        shutdown = threading.Event()

        with pytest.raises(Exception):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        pub.close.assert_called_once()

    def test_consumer_closed_after_loop_exception(self):
        pub = make_publisher()
        consumer = MagicMock()
        consumer.poll.return_value = make_msg()
        consumer.commit.side_effect = Exception("commit failed")
        shutdown = threading.Event()

        with pytest.raises(Exception):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.close.assert_called_once()

    def test_consumer_closed_even_if_publisher_close_raises(self):
        pub = make_publisher()
        pub.close.side_effect = PublishTimeoutError("shutdown flush timeout")
        consumer = MagicMock()
        shutdown = threading.Event()
        shutdown.set()

        with pytest.raises(PublishTimeoutError):
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)

        consumer.close.assert_called_once()

    def test_publisher_close_exception_propagates_after_consumer_close(self):
        pub = make_publisher()
        pub.close.side_effect = PublishTimeoutError("shutdown flush timeout")
        consumer = MagicMock()
        shutdown = threading.Event()
        shutdown.set()

        exc = None
        try:
            run_consumer_loop(consumer, pub, make_dedup(), shutdown)
        except PublishTimeoutError as e:
            exc = e

        assert exc is not None
        # consumer.close was still called before exception escaped
        consumer.close.assert_called_once()

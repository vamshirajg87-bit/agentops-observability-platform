"""
stream-processor/processor.py

Orchestration layer for the agentops stream processor.

Connects the OTLP decoder, canonicalizer, span deduplicator, and Kafka
publisher into a source-offset-correct consumer loop.

PROCESS_MESSAGE CONTRACT
------------------------
process_message() returns normally only when the complete source record is
commit-eligible: every span has been published to the trusted topic with
positive broker ack and marked in the deduplicator, sent to the DLQ with
positive broker ack, or skipped as a confirmed in-process duplicate.

Any propagated exception means the source record is NOT commit-eligible.
The caller must not commit the source offset. The consumer loop halts.

RUN_CONSUMER_LOOP CONTRACT
--------------------------
Source offsets are committed only via:
    consumer.commit(message=msg, asynchronous=False)
called after process_message() returns normally.

consumer.close() is guaranteed to execute even if publisher.close() raises,
via nested try/finally cleanup.

A cleanup failure (publisher.close() or consumer.close()) never replaces the
failure that stopped the loop: the original exception stays the one that
propagates, and each cleanup failure is reported on stderr. When the loop
ended without an error, the first cleanup failure (publisher before consumer)
propagates and a second one is reported on stderr.

A KeyboardInterrupt, SystemExit or other BaseException raised by cleanup is
never swallowed: it propagates and replaces whatever was propagating. Every
failure it displaces and that was not already reported is first written to
stderr, so the original failure is not lost.

PHASE BOUNDARY
--------------
Phase 5.5 ships orchestration and unit tests only.
The existing CanonicalSpanExporter direct Kafka write path is not modified.
Phase 5.6 proves end-to-end correctness and disables that path.
"""

from __future__ import annotations

import hashlib
import sys
import threading
from datetime import datetime, timezone

import confluent_kafka

from canonicalizer import CanonicalizationError, canonicalize
from deduplicator import SpanDeduplicator
from dlq import DLQEvent, DLQReason, build_dlq_event
from otlp_decoder import OTLPDecodeError, decode
from publisher import KafkaPublisher


def process_message(
    msg: confluent_kafka.Message,
    publisher: KafkaPublisher,
    deduplicator: SpanDeduplicator,
    source_topic: str,
    source_partition: int,
    source_offset: int,
) -> None:
    """
    Process a single Kafka message.

    Precondition: msg.error() has already been checked by the caller and is None.

    Returns normally when the complete source record is commit-eligible.
    Any propagated exception means the caller must not commit the source offset.

    Does not depend on confluent_kafka.Consumer.
    """
    raw_value = msg.value()

    if raw_value is None:
        publisher.publish_dlq(
            DLQEvent(
                source_topic=source_topic,
                source_partition=source_partition,
                source_offset=source_offset,
                failed_at=datetime.now(tz=timezone.utc),
                reason=DLQReason.OTLP_DECODE_FAILURE,
                error_message="Kafka message value is None",
                source_payload_sha256=None,
            )
        )
        return

    source_payload_sha256: str = hashlib.sha256(raw_value).hexdigest()

    try:
        spans = decode(raw_value)
    except OTLPDecodeError as exc:
        publisher.publish_dlq(
            build_dlq_event(
                exc=exc,
                source_topic=source_topic,
                source_partition=source_partition,
                source_offset=source_offset,
                source_payload_sha256=source_payload_sha256,
            )
        )
        return

    for span_dict in spans:
        try:
            event = canonicalize(span_dict)
        except CanonicalizationError as exc:
            publisher.publish_dlq(
                build_dlq_event(
                    exc=exc,
                    source_topic=source_topic,
                    source_partition=source_partition,
                    source_offset=source_offset,
                    trace_id=span_dict.get("trace_id"),
                    span_id=span_dict.get("span_id"),
                    service_name=span_dict.get("service_name"),
                    source_payload_sha256=source_payload_sha256,
                )
            )
            continue

        if deduplicator.contains(event.trace_id, event.span_id):
            continue

        publisher.publish_span(event)
        deduplicator.mark(event.trace_id, event.span_id)


def run_consumer_loop(
    consumer: confluent_kafka.Consumer,
    publisher: KafkaPublisher,
    deduplicator: SpanDeduplicator,
    shutdown_event: threading.Event,
    poll_timeout_seconds: float = 1.0,
) -> None:
    """
    Drive the consumer loop until shutdown_event is set or an error halts.

    consumer.close() is guaranteed to execute even if publisher.close() raises.
    Source offsets are committed only by consumer.commit() after successful
    process_message() completion.

    Cleanup closes the publisher, then the consumer, and attempts both. If the
    loop stopped on an exception, that exception is the one that propagates
    and any cleanup failure is written to stderr. Without a loop exception the
    first cleanup failure (publisher before consumer) propagates and the other
    is written to stderr. A BaseException raised by cleanup still propagates
    (it is never swallowed); the failures it displaces are written to stderr
    first.
    """
    error: BaseException | None = None
    try:
        while not shutdown_event.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)

            if msg is None:
                continue

            if msg.error() is not None:
                raise RuntimeError(f"consumer error: {msg.error()}")

            source_topic = msg.topic()
            source_partition = msg.partition()
            source_offset = msg.offset()

            process_message(
                msg,
                publisher,
                deduplicator,
                source_topic,
                source_partition,
                source_offset,
            )

            consumer.commit(message=msg, asynchronous=False)
    except BaseException as exc:
        error = exc
        raise
    finally:
        primary = _close_publisher_then_consumer(publisher, consumer, error)
        if primary is not None and primary is not error:
            raise primary


def _close_publisher_then_consumer(
    publisher: KafkaPublisher,
    consumer: confluent_kafka.Consumer,
    primary: BaseException | None,
) -> BaseException | None:
    """
    Close the publisher, then the consumer; both are always attempted.

    Returns the failure that must propagate: the loop's own failure if there
    was one, otherwise the first cleanup failure (publisher before consumer),
    otherwise None. Every other cleanup failure is written to stderr.

    A BaseException (KeyboardInterrupt, SystemExit, ...) raised by either close
    is not caught here: it propagates and replaces the failure in flight. The
    failures it displaces that were not yet reported are written to stderr
    before it propagates.
    """
    state = _CleanupState(primary)
    try:
        try:
            publisher.close()
        except Exception as exc:
            state.failed("publisher.close()", exc)
        except BaseException as exc:
            state.interrupted("publisher.close()", exc)
            raise
        finally:
            try:
                consumer.close()
            except Exception as exc:
                state.failed("consumer.close()", exc)
    except BaseException as interruption:
        state.displaced_by(interruption)
        raise
    return state.primary


class _CleanupState:
    """
    Which failure propagates, and which failures are still unreported, while
    the publisher and the consumer are closed.
    """

    def __init__(self, loop_error: BaseException | None) -> None:
        self.primary = loop_error
        self.interruption: BaseException | None = None
        self.unreported: list[tuple[str, BaseException]] = []
        if loop_error is not None:
            self.unreported.append(("loop failure", loop_error))

    def failed(self, operation: str, failure: Exception) -> None:
        """A close raised an ordinary exception: it propagates only if nothing else is."""
        handling = self.primary if self.primary is not None else self.interruption
        if handling is None:
            self.primary = failure
            self.unreported.append((f"{operation} failure", failure))
            return
        _report(
            f"stream processor: {operation} failed while handling "
            f"{_safe_repr(handling)}: {_safe_repr(failure)}"
        )

    def interrupted(self, operation: str, interruption: BaseException) -> None:
        """A close raised a BaseException; it is about to propagate."""
        self.interruption = interruption
        self.unreported.append((f"{operation} interruption", interruption))

    def displaced_by(self, interruption: BaseException) -> None:
        """interruption is propagating: report each unreported failure it replaces."""
        for label, failure in self.unreported:
            if failure is not interruption:
                _report(
                    f"stream processor: {label} was displaced by "
                    f"{_safe_repr(interruption)}: {_safe_repr(failure)}"
                )


def _safe_repr(failure: BaseException) -> str:
    try:
        return repr(failure)
    except Exception:
        return f"<{type(failure).__name__} (repr failed)>"


def _report(line: str) -> None:
    """Write a diagnostic to stderr; a failure to write must not replace the real error."""
    try:
        print(line, file=sys.stderr)
    except Exception:
        pass

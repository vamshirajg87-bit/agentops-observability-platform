"""
stream-processor/main.py

Runtime entry point for the agentops stream processor.

Constructs Consumer, Producer, KafkaPublisher, SpanDeduplicator, and
threading.Event, then delegates entirely to run_consumer_loop().

Contains no processing logic — all business logic lives in processor.py.

Graceful shutdown: the first SIGTERM or SIGINT sets the shutdown event. The
consumer loop finishes the message it is working on (publication, DLQ and
offset commit included), exits between messages and runs its normal cleanup;
the process then exits 0. A second signal raises KeyboardInterrupt, the
existing immediate-stop path. The handler only sets the event and writes one
line; it touches no Kafka client. An orchestrator that stops waiting and kills
the process loses nothing: offsets are committed only after acknowledged work,
so the next run replays instead.

Usage:
    PYTHONPATH=/path/to/repo/demo-app python stream-processor/main.py

    # Windows PowerShell:
    $env:PYTHONPATH = "$PWD\\demo-app"
    python stream-processor/main.py
"""

from __future__ import annotations

import os
import signal
import sys
import threading
from typing import Any, Callable

import confluent_kafka

import config
from deduplicator import SpanDeduplicator
from processor import run_consumer_loop
from publisher import KafkaPublisher


def _report_to_stderr(line: str) -> None:
    """
    Write one diagnostic line to stderr (file descriptor 2).

    Used from a signal handler, where print() could re-enter a half-finished
    write of the main thread; a single os.write cannot. A failure to write is
    ignored: a diagnostic must never raise out of a handler.
    """
    try:
        os.write(2, line.encode("utf-8", "replace"))
    except OSError:
        pass


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


def install_shutdown_handlers(
    shutdown_event: threading.Event,
    *,
    signal_module: Any = signal,
    report: Callable[[str], None] = _report_to_stderr,
) -> Callable[[], None]:
    """
    Make SIGTERM and SIGINT request a graceful stop; return a function that
    restores the handlers that were installed before.

    First signal: set shutdown_event and write one line. Second signal (the
    event is already set): raise KeyboardInterrupt, the immediate-stop path.

    A signal whose handler cannot be installed (not the main thread, or an
    unsupported platform) is skipped with one line and left as it was; the
    process then behaves as it did before this function existed for that
    signal. The handler does nothing else: no Kafka, database, network or
    blocking call.
    """

    def handle(signum: int, frame: Any) -> None:
        if shutdown_event.is_set():
            raise KeyboardInterrupt
        shutdown_event.set()
        report(
            f"stream processor: {_signal_name(signum)} received; finishing the "
            "current message, then shutting down. Send it again to stop immediately.\n"
        )

    previous: dict[int, Any] = {}
    for signum in (signal_module.SIGTERM, signal_module.SIGINT):
        try:
            before = signal_module.getsignal(signum)
            signal_module.signal(signum, handle)
        except (ValueError, OSError, RuntimeError) as exc:
            report(
                f"stream processor: cannot handle {_signal_name(signum)} "
                f"({exc}); it keeps its previous behavior\n"
            )
            continue
        previous[signum] = before

    def restore() -> None:
        for signum, handler in previous.items():
            try:
                signal_module.signal(
                    signum, handler if handler is not None else signal_module.SIG_DFL
                )
            except (ValueError, OSError, RuntimeError):
                pass
        previous.clear()

    return restore


def main() -> None:
    print("agentops stream processor starting")
    print(f"  bootstrap : {config.KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  group     : {config.CONSUMER_GROUP_ID}")
    print(f"  input     : {config.TOPIC_OTLP_TRACES}")
    print(f"  trusted   : {config.TOPIC_SPANS}")
    print(f"  dlq       : {config.TOPIC_DLQ}")
    print(f"  dedup size: {config.DEDUP_MAX_SIZE}")

    consumer = confluent_kafka.Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": config.CONSUMER_GROUP_ID,
        "auto.offset.reset": config.CONSUMER_AUTO_OFFSET_RESET,
        "enable.auto.commit": False,
    })
    consumer.subscribe([config.TOPIC_OTLP_TRACES])
    print(f"Subscribed to {config.TOPIC_OTLP_TRACES!r}. Press Ctrl+C to stop.")

    producer = confluent_kafka.Producer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "acks": "all",
        "enable.idempotence": True,
    })

    publisher = KafkaPublisher(
        producer=producer,
        retries=config.PUBLISH_RETRIES,
        timeout_seconds=config.PUBLISH_TIMEOUT_SECONDS,
    )

    deduplicator = SpanDeduplicator(max_size=config.DEDUP_MAX_SIZE)
    shutdown_event = threading.Event()
    restore_signal_handlers = install_shutdown_handlers(shutdown_event)

    try:
        run_consumer_loop(
            consumer=consumer,
            publisher=publisher,
            deduplicator=deduplicator,
            shutdown_event=shutdown_event,
        )
        # Returned normally: only the shutdown event ends the loop without an error.
        print("agentops stream processor stopped (shutdown requested).")
    except KeyboardInterrupt:
        # run_consumer_loop's finally block already closed publisher and consumer.
        print("\nagentops stream processor stopped.")
        sys.exit(0)
    except Exception as exc:
        print(f"\nagentops stream processor halted: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        restore_signal_handlers()


if __name__ == "__main__":
    main()

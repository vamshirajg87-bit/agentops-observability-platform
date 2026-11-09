"""
storage-consumer/main.py

Runtime entry point for the agentops storage consumer.

Constructs the Kafka Consumer, psycopg Connection, SpanRepository, and
threading.Event, then delegates entirely to run_consumer_loop().

Contains no processing logic — all business logic lives in consumer.py
and repository.py.

Graceful shutdown: the first SIGTERM or SIGINT sets the shutdown event. The
consumer loop finishes the message it is working on (the database insert
first, then its offset commit, or its record in the opt-in offset batcher),
exits between messages and runs its normal cleanup, which flushes only the
offsets of persisted messages; the process then exits 0. A second signal
raises KeyboardInterrupt, the existing immediate-stop path. The handler only
sets the event and writes one line; it touches no Kafka client and no
database connection. An orchestrator that stops waiting and kills the process
loses nothing: offsets are committed only after the database transaction, so
the next run replays into the unique key instead.

Usage:
    PYTHONPATH=/path/to/repo/demo-app python storage-consumer/main.py

    # Windows PowerShell:
    $env:PYTHONPATH = "$PWD\\demo-app"
    python storage-consumer/main.py
"""

from __future__ import annotations

import os
import signal
import sys
import threading
from typing import Any, Callable

import confluent_kafka
import psycopg

import config
from consumer import OffsetBatcher, run_consumer_loop
from repository import SpanRepository


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
            f"storage consumer: {_signal_name(signum)} received; finishing the "
            "current message, then shutting down. Send it again to stop immediately.\n"
        )

    previous: dict[int, Any] = {}
    for signum in (signal_module.SIGTERM, signal_module.SIGINT):
        try:
            before = signal_module.getsignal(signum)
            signal_module.signal(signum, handle)
        except (ValueError, OSError, RuntimeError) as exc:
            report(
                f"storage consumer: cannot handle {_signal_name(signum)} "
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
    print("agentops storage consumer starting")
    print(f"  bootstrap  : {config.KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  group      : {config.CONSUMER_GROUP_ID}")
    print(f"  topic      : {config.TOPIC_SPANS}")
    print(f"  pg host    : {config.PG_HOST}:{config.PG_PORT}")
    print(f"  pg database: {config.PG_DATABASE}")

    consumer = confluent_kafka.Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": config.CONSUMER_GROUP_ID,
        "auto.offset.reset": config.CONSUMER_AUTO_OFFSET_RESET,
        "enable.auto.commit": False,
    })
    batcher = None
    if config.COMMIT_BATCH_MESSAGES > 1:
        # Opt-in: offsets are committed in batches, with ownership tracked through the
        # rebalance callbacks.  With the default (1) none of this is created and the
        # subscription is exactly the original one.
        batcher = OffsetBatcher(consumer, config.COMMIT_BATCH_MESSAGES,
                                config.COMMIT_INTERVAL_SECONDS)
        consumer.subscribe([config.TOPIC_SPANS], on_assign=batcher.on_assign,
                           on_revoke=batcher.on_revoke, on_lost=batcher.on_lost)
        print(f"  commit     : batches of up to {config.COMMIT_BATCH_MESSAGES} messages, "
              f"about every {config.COMMIT_INTERVAL_SECONDS:g} s")
    else:
        consumer.subscribe([config.TOPIC_SPANS])
    print(f"Subscribed to {config.TOPIC_SPANS!r}. Press Ctrl+C to stop.")

    connection = psycopg.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DATABASE,
        user=config.PG_USER,
        password=config.PG_PASSWORD,
        autocommit=True,
    )
    repository = SpanRepository(connection)
    shutdown_event = threading.Event()
    timing = None
    if config.TIMING_INTERVAL_SECONDS > 0:
        # Imported only when enabled, so a deployment that never turns timing on
        # does not need timing.py (the pipeline image copies files by name).
        from timing import TimingRecorder
        timing = TimingRecorder(config.TIMING_INTERVAL_SECONDS)

    restore_signal_handlers = install_shutdown_handlers(shutdown_event)
    try:
        run_consumer_loop(
            consumer=consumer,
            repository=repository,
            shutdown_event=shutdown_event,
            timing=timing,
            **({"batcher": batcher} if batcher is not None else {}),
        )
        # Returned normally: only the shutdown event ends the loop without an error.
        print("agentops storage consumer stopped (shutdown requested).")
    except KeyboardInterrupt:
        print("\nagentops storage consumer stopped.")
        sys.exit(0)
    except Exception as exc:
        print(f"\nagentops storage consumer halted: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        restore_signal_handlers()
        connection.close()


if __name__ == "__main__":
    main()

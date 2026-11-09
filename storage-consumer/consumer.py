"""
storage-consumer/consumer.py

Orchestration layer for the agentops storage consumer.

Connects the Kafka message stream to the PostgreSQL span repository with
correct at-least-once offset semantics: the Kafka offset is committed only
after the database transaction commits.

PROCESS_MESSAGE CONTRACT
------------------------
process_message() returns normally only when the span record is
commit-eligible: it has been persisted (or already existed) in the database
and the transaction has committed.

Any propagated exception means the caller must not commit the source offset.
The consumer loop halts.

RUN_CONSUMER_LOOP CONTRACT
--------------------------
Source offsets are committed only via:
    consumer.commit(message=msg, asynchronous=False)
called after process_message() returns normally.

consumer.close() is guaranteed to execute via try/finally cleanup.

FAILURE POLICY
--------------
This is a trusted-topic consumer. Tombstone payloads, malformed JSON, or
CanonicalSpanEvent validation failures all halt the consumer rather than
routing to a DLQ. The operator must investigate and resolve the root cause.
"""

from __future__ import annotations

import json
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional

import confluent_kafka

from schemas.telemetry import CanonicalSpanEvent

if TYPE_CHECKING:
    from repository import SpanRepository
    from timing import TimingRecorder


def process_message(
    msg: confluent_kafka.Message,
    repository: SpanRepository,
    timing: TimingRecorder | None = None,
) -> None:
    """
    Process a single Kafka message from the trusted spans topic.

    Precondition: msg.error() has already been checked by the caller and is None.

    Steps:
        1. Reject tombstone (None value) — raises RuntimeError
        2. Decode UTF-8 bytes — UnicodeDecodeError propagates
        3. Parse JSON — JSONDecodeError propagates
        4. Validate as CanonicalSpanEvent — ValidationError propagates
        5. Persist via repository.insert_span() — any psycopg exception propagates

    Both True (new row) and False (ON CONFLICT DO NOTHING) from insert_span
    are treated as success: the message is commit-eligible.

    Never commits a Kafka offset.

    timing (optional, default None = no timing work): a TimingRecorder that is
    given the duration of steps 2-4 ("decode_validate") and of step 5
    ("insert_txn"), and whether the insert was new or a conflict.  It only
    observes; it changes no step, no result and no exception.
    """
    started = timing.clock() if timing is not None else 0.0
    raw_value = msg.value()

    if raw_value is None:
        raise RuntimeError(
            f"Tombstone message received on trusted topic "
            f"{msg.topic()!r} partition={msg.partition()} offset={msg.offset()}"
        )

    text = raw_value.decode("utf-8")
    event_dict = json.loads(text)
    event = CanonicalSpanEvent.model_validate(event_dict)

    if timing is None:
        repository.insert_span(
            event,
            topic=msg.topic(),
            partition=msg.partition(),
            offset=msg.offset(),
        )
        return

    validated = timing.clock()
    timing.record("decode_validate", validated - started)
    inserted = repository.insert_span(
        event,
        topic=msg.topic(),
        partition=msg.partition(),
        offset=msg.offset(),
    )
    timing.record("insert_txn", timing.clock() - validated)
    timing.count("conflicts" if inserted is False else "inserted")


def run_consumer_loop(
    consumer: confluent_kafka.Consumer,
    repository: SpanRepository,
    shutdown_event: threading.Event,
    poll_timeout_seconds: float = 1.0,
    timing: TimingRecorder | None = None,
    batcher: OffsetBatcher | None = None,
) -> None:
    """
    Drive the consumer loop until shutdown_event is set or an error halts.

    batcher (optional, default None = the original loop below, unchanged): an
    OffsetBatcher.  Only then are offsets committed in batches; see OffsetBatcher.

    consumer.close() is guaranteed to execute via finally block.
    Source offsets are committed only by consumer.commit() after successful
    process_message() completion.

    timing (optional, default None = no timing work) only observes: it adds no
    step, thread or retry, and a stage that raises is not recorded and its
    exception propagates exactly as without it.  The final summary is written
    in the finally block before the consumer is closed.
    """
    if batcher is not None:
        _run_batched_loop(consumer, repository, shutdown_event, poll_timeout_seconds,
                          timing, batcher)
        return
    try:
        while not shutdown_event.is_set():
            cycle_started = timing.clock() if timing is not None else 0.0
            msg = consumer.poll(timeout=poll_timeout_seconds)

            if msg is None:
                if timing is not None:
                    timing.count("idle_polls")
                    timing.maybe_emit()
                continue

            if msg.error() is not None:
                raise RuntimeError(f"consumer error: {msg.error()}")

            if timing is None:
                process_message(msg, repository)

                consumer.commit(message=msg, asynchronous=False)
                continue

            polled = timing.clock()
            timing.record("poll", polled - cycle_started)
            process_message(msg, repository, timing)

            commit_started = timing.clock()
            consumer.commit(message=msg, asynchronous=False)
            finished = timing.clock()
            timing.record("kafka_commit", finished - commit_started)
            timing.record("cycle", finished - cycle_started)
            timing.count("messages")
            timing.maybe_emit()
    finally:
        if timing is not None:
            timing.final()
        consumer.close()


# ---------------------------------------------------------------------------
# Opt-in batched offset commits
# ---------------------------------------------------------------------------

class CommitFailed(RuntimeError):
    """A Kafka offset commit failed (wholly or for some partitions); the loop halts."""


_Key = tuple  # (topic, partition)


class OffsetBatcher:
    """
    Bounded batching of Kafka offset commits, ownership-aware and per partition.

    It exists only when CONSUMER_COMMIT_BATCH_MESSAGES > 1; with 1 the original
    loop runs and none of this code is used.

    The loop is single-threaded and synchronous, so when poll() runs (and so when a
    rebalance callback fires) no message is in flight: everything recorded here has
    already been persisted by a committed PostgreSQL transaction.  An offset is
    recorded ONLY after process_message() returned normally.

    State, all per (topic, partition):
        owned    the partitions this consumer owns, kept by the rebalance callbacks
        _next    highest persisted offset + 1 (the offset Kafka expects to be committed)
        _count   messages persisted since that partition was last committed
        _first   monotonic time of that partition's first pending message
    The totals (messages pending, age of the oldest) are computed from these maps on
    demand, so a partial flush can never leave them inconsistent.

    Invariants:
        - a committed offset never exceeds 1 + the highest persisted offset
        - nothing is recorded or committed for a partition that is not owned
        - a partition leaves `owned` (and all its pending state) when it is revoked or
          lost, before anything else can run, so its offsets are never committed later
        - pending entries are removed only for partitions whose commit was confirmed
        - a failed commit, or an unexpected error in a callback, halts the loop
        - once the state is fatal, a commit has failed, or the consumer is closing, NOTHING
          is committed any more: not by the loop, not by a rebalance callback that
          consumer.close() fires.  Such a callback only releases ownership and drops the
          pending entries of its partitions (they are persisted, so they are redelivered)

    The time threshold is approximate, not a hard guarantee: it is checked after each
    message and when a poll returns without one, and a slow insert or commit extends it.
    Do not read the batch size as a universal bound on redelivery after a failure.
    """

    def __init__(
        self,
        consumer: Any,
        max_messages: int,
        max_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        timing: Any = None,
        log: Callable[[str], None] = print,
    ) -> None:
        if isinstance(max_messages, bool) or not isinstance(max_messages, int) or max_messages < 2:
            raise ValueError("an OffsetBatcher needs a batch of at least 2 messages")
        if not max_seconds > 0:
            raise ValueError("an OffsetBatcher needs a positive interval")
        self.consumer = consumer
        self.max_messages = max_messages
        self.max_seconds = float(max_seconds)
        self.clock = clock
        self.timing = timing
        self._log = log
        self.owned: set[_Key] = set()
        self._next: dict[_Key, int] = {}
        self._count: dict[_Key, int] = {}
        self._first: dict[_Key, float] = {}
        self.fatal: Optional[BaseException] = None
        self.commit_failed = False
        # Set (by the loop) after the final flush and before consumer.close(), so that
        # callbacks which close() fires cannot commit.
        self.closing = False
        self._in_flush = False
        # counters for tests and logs
        self.commits = 0
        self.revoke_commit_failures = 0
        self.dropped_on_lost = 0
        self.stale_assignments = 0
        self.blocked_revokes = 0

    # -- derived state ---------------------------------------------------------
    def pending_messages(self) -> int:
        return sum(self._count.values())

    def oldest_pending(self) -> Optional[float]:
        return min(self._first.values()) if self._first else None

    def pending_offsets(self) -> dict[_Key, int]:
        return dict(self._next)

    def check_invariants(self) -> None:
        """Raise AssertionError when the bookkeeping is inconsistent (used by tests)."""
        assert set(self._next) == set(self._count) == set(self._first)
        assert set(self._next) <= self.owned
        assert all(n > 0 for n in self._count.values())
        assert all(o > 0 for o in self._next.values())

    def poll_timeout(self, base: float) -> float:
        """The poll timeout to use: shorter while something is pending, so an idle
        poll flushes within about the interval."""
        return min(base, self.max_seconds) if self._next else base

    def commits_blocked(self) -> bool:
        """True when no offset may be committed: unsafe state, a failed commit, or closing."""
        return self.fatal is not None or self.commit_failed or self.closing

    # -- fatal state -----------------------------------------------------------
    def _set_fatal(self, message: str, exc: Optional[BaseException] = None) -> None:
        if self.fatal is None:
            self.fatal = exc if exc is not None else RuntimeError(message)
        self._log(f"storage consumer offset batching: {message}")

    def check_fatal(self) -> None:
        if self.fatal is not None:
            raise RuntimeError(
                f"offset batching state is unsafe: {self.fatal}") from self.fatal

    # -- recording -------------------------------------------------------------
    def record(self, msg: Any) -> None:
        """Record that msg has been persisted.  Call only after process_message()."""
        self.check_fatal()
        key = (msg.topic(), msg.partition())
        if key not in self.owned:
            self._set_fatal(f"a message arrived for a partition that is not owned: {key}")
            self.check_fatal()
        offset = msg.offset() + 1
        self._next[key] = max(self._next.get(key, 0), offset)
        self._count[key] = self._count.get(key, 0) + 1
        self._first.setdefault(key, self.clock())

    def due(self) -> bool:
        if self.pending_messages() >= self.max_messages:
            return True
        oldest = self.oldest_pending()
        return oldest is not None and self.clock() - oldest >= self.max_seconds

    def flush_if_due(self) -> None:
        if self.due():
            self.flush()

    def flush_pending(self) -> None:
        """Flush everything pending (idle poll)."""
        if self._next:
            self.flush()

    def _drop(self, keys: Iterable[_Key]) -> None:
        for key in list(keys):
            self._next.pop(key, None)
            self._count.pop(key, None)
            self._first.pop(key, None)

    # -- committing ------------------------------------------------------------
    def _commit(self, keys: list[_Key]) -> tuple[set[_Key], Optional[BaseException]]:
        """Commit the pending offsets of keys synchronously.  Returns the keys whose
        commit was confirmed and the exception, if the call raised.  The pending state
        of confirmed keys is removed; nothing else is touched."""
        if self.commits_blocked():
            # Defense in depth: every path that reaches here is also checked by its caller.
            return set(), CommitFailed("commits are blocked (unsafe state, failed commit or closing)")
        if self._in_flush:
            self._set_fatal("a flush was started inside a flush")
            self.check_fatal()
        self._in_flush = True
        try:
            sent = {key: self._next[key] for key in keys}
            offsets = [confluent_kafka.TopicPartition(topic, partition, offset)
                       for (topic, partition), offset in sent.items()]
            started = self.clock()
            try:
                result = self.consumer.commit(offsets=offsets, asynchronous=False)
            except Exception as exc:  # noqa: BLE001 - nothing is known to be committed
                return set(), exc
            confirmed: set[_Key] = set()
            if isinstance(result, (list, tuple)):
                for tp in result:
                    key = (getattr(tp, "topic", None), getattr(tp, "partition", None))
                    if (key in sent and getattr(tp, "error", None) is None
                            and getattr(tp, "offset", None) == sent[key]):
                        confirmed.add(key)
            for key in confirmed:
                if self._next.get(key) != sent[key]:
                    self._set_fatal(f"pending offset of {key} changed during its commit")
                    self.check_fatal()
                self._drop([key])
            if confirmed:
                self.commits += 1
                if self.timing is not None:
                    self.timing.record("kafka_commit", self.clock() - started)
            return confirmed, None
        finally:
            self._in_flush = False

    def flush(self, only: Optional[Iterable[_Key]] = None) -> None:
        """Commit the pending offsets (of `only`, if given) of owned partitions.
        Raises CommitFailed after recording the partitions that did succeed."""
        wanted = None if only is None else set(only)
        keys = [key for key in self._next
                if key in self.owned and (wanted is None or key in wanted)]
        if not keys:
            return
        confirmed, error = self._commit(keys)
        failed = [key for key in keys if key not in confirmed]
        if error is not None:
            self.commit_failed = True
            raise CommitFailed(f"Kafka offset commit failed: {error!r}") from error
        if failed:
            self.commit_failed = True
            raise CommitFailed(f"Kafka offset commit failed for {sorted(failed, key=str)}")

    def finish(self) -> None:
        """Best-effort final flush before close.  Never raises.  Skipped when the state is
        unsafe or a commit has already failed; everything pending is persisted data."""
        if self.fatal is not None or self.commit_failed:
            return
        try:
            self.flush()
        except Exception as exc:  # noqa: BLE001 - must not mask the original error
            self._log(f"storage consumer offset batching: final commit failed: {exc!r}")

    # -- rebalance callbacks (never raise) ---------------------------------------
    @staticmethod
    def _keys(partitions: Iterable[Any]) -> list[_Key]:
        return [(tp.topic, tp.partition) for tp in partitions]

    def on_assign(self, consumer: Any, partitions: Iterable[Any]) -> None:
        try:
            for key in self._keys(partitions):
                if key in self.owned or key in self._next:
                    self.stale_assignments += 1
                    self._log(f"storage consumer offset batching: stale state for {key} dropped")
                    self._drop([key])
                self.owned.add(key)
        except Exception as exc:  # noqa: BLE001
            self._set_fatal(f"on_assign failed: {exc!r}", exc)

    def on_revoke(self, consumer: Any, partitions: Iterable[Any]) -> None:
        try:
            keys = self._keys(partitions)
            pending = [key for key in keys if key in self._next and key in self.owned]
            try:
                if pending and self.commits_blocked():
                    # fatal, failed commit or closing: release ownership, commit nothing
                    self.blocked_revokes += 1
                    self._log("storage consumer offset batching: revoke while commits are "
                              "blocked; pending offsets dropped, they will be redelivered")
                elif pending:
                    confirmed, error = self._commit(pending)
                    if error is not None or len(confirmed) < len(pending):
                        self.revoke_commit_failures += 1
                        self._log("storage consumer offset batching: committing revoked "
                                  "partitions failed; they will be redelivered")
            finally:
                self._drop(keys)
                self.owned.difference_update(keys)
        except Exception as exc:  # noqa: BLE001
            self._set_fatal(f"on_revoke failed: {exc!r}", exc)

    def on_lost(self, consumer: Any, partitions: Iterable[Any]) -> None:
        try:
            keys = self._keys(partitions)
            self.dropped_on_lost += sum(1 for key in keys if key in self._next)
            self._drop(keys)
            self.owned.difference_update(keys)
        except Exception as exc:  # noqa: BLE001
            self._set_fatal(f"on_lost failed: {exc!r}", exc)


def _run_batched_loop(
    consumer: confluent_kafka.Consumer,
    repository: SpanRepository,
    shutdown_event: threading.Event,
    poll_timeout_seconds: float,
    timing: TimingRecorder | None,
    batcher: OffsetBatcher,
) -> None:
    """The loop of run_consumer_loop when offsets are committed in batches.  Same order
    as the original (poll, process, persist), then the offset is only RECORDED; the
    commit happens when the batch is due, on an idle poll, on a revoke and at shutdown.

    Timing: kafka_commit is recorded once per commit call (so its count is the number of
    commits and its mean is per commit, not per message); cycle runs from the start of a
    poll to the end of that message's handling and includes a flush that happens in it."""
    batcher.timing = timing
    error: BaseException | None = None
    try:
        while not shutdown_event.is_set():
            cycle_started = timing.clock() if timing is not None else 0.0
            msg = consumer.poll(timeout=batcher.poll_timeout(poll_timeout_seconds))
            batcher.check_fatal()

            if msg is None:
                if timing is not None:
                    timing.count("idle_polls")
                batcher.flush_pending()
                if timing is not None:
                    timing.maybe_emit()
                continue

            if msg.error() is not None:
                raise RuntimeError(f"consumer error: {msg.error()}")

            if timing is None:
                process_message(msg, repository)
                batcher.record(msg)
                batcher.flush_if_due()
                continue

            polled = timing.clock()
            timing.record("poll", polled - cycle_started)
            process_message(msg, repository, timing)
            batcher.record(msg)
            batcher.flush_if_due()
            timing.record("cycle", timing.clock() - cycle_started)
            timing.count("messages")
            timing.maybe_emit()
    except BaseException as exc:
        error = exc
        raise
    finally:
        try:
            batcher.finish()                  # the one permitted final flush
        finally:
            # From here no commit, and so no kafka_commit timing record, can happen: a
            # rebalance callback fired by close() can only release ownership.
            batcher.closing = True
            try:
                if timing is not None:
                    timing.final()
            finally:
                if error is None:
                    consumer.close()
                else:
                    try:
                        consumer.close()
                    except Exception:  # noqa: BLE001 - never replace the original error
                        pass

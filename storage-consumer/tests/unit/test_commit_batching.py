"""
storage-consumer/tests/unit/test_commit_batching.py

Unit tests for the opt-in batched Kafka offset commits (consumer.OffsetBatcher and the
batched loop).  No live Kafka or PostgreSQL: fake consumer, fake repository, fake clocks.

Proves:
  - batching is off by default and the original loop and subscription are untouched
  - an offset is recorded only after the database insert returned, and committed per
    partition as last persisted offset + 1, with explicit TopicPartition offsets
  - count, time, idle and shutdown flushes; partial commit success and failure
  - assign / revoke / lost callbacks and ownership: nothing is committed after a loss
  - unexpected callback or state errors halt instead of continuing
  - replay after a crash is idempotent; timing accounting; configuration validation
  - the bookkeeping stays consistent over randomized operation sequences

Real-broker behavior (callback propagation, commit inside on_revoke, close(), the way
a partial commit is reported) cannot be established here; see the B3J-233 design.
"""

from __future__ import annotations

import importlib
import json
import random
import threading
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import config
import consumer as consumer_mod
from consumer import CommitFailed, OffsetBatcher, process_message, run_consumer_loop
from timing import TimingRecorder

TOPIC = "agentops.telemetry.spans"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

def span_bytes(span_id: str) -> bytes:
    now = datetime.now(tz=timezone.utc).isoformat()
    return json.dumps({"trace_id": "a" * 32, "span_id": span_id, "span_name": "t.op",
                       "span_kind": "INTERNAL", "service_name": "svc", "start_time": now,
                       "end_time": now, "duration_ms": 0.0, "status_code": "OK"}).encode()


class FakeMsg:
    def __init__(self, partition, offset, value=None, error=None, topic=TOPIC):
        self._p, self._o, self._t, self._e = partition, offset, topic, error
        self._v = span_bytes(f"{partition:04x}{offset:012x}") if value is None else value

    def value(self):
        return self._v

    def topic(self):
        return self._t

    def partition(self):
        return self._p

    def offset(self):
        return self._o

    def error(self):
        return self._e


class FakeTP:
    def __init__(self, partition, offset=None, error=None, topic=TOPIC):
        self.topic, self.partition, self.offset, self.error = topic, partition, offset, error


class Clock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Tick:
    def __init__(self, step=0.001):
        self.now, self.step = 0.0, step

    def __call__(self):
        self.now += self.step
        return self.now


class FakeRepo:
    """Mimics ON CONFLICT DO NOTHING: True for a new row, False for a duplicate."""

    def __init__(self, log, rows=None, fail_on=()):
        self.log, self.rows, self.fail_on = log, set() if rows is None else rows, set(fail_on)

    def insert_span(self, event, topic, partition, offset):
        if (partition, offset) in self.fail_on:
            raise RuntimeError("database down")
        self.log.append(("insert", partition, offset))
        key = (event.trace_id, event.span_id)
        fresh = key not in self.rows
        self.rows.add(key)
        return fresh


class FakeConsumer:
    """poll() plays a script of FakeMsg / None / callable items, then ends the loop."""

    def __init__(self, script, shutdown, log):
        self.script, self.shutdown, self.log = list(script), shutdown, log
        self.poll_timeouts, self.commits, self.commit_plan = [], [], []
        self.closed, self.close_error = 0, None
        self.on_close = None            # called inside close(), like the callbacks the client fires

    def poll(self, timeout):
        self.poll_timeouts.append(timeout)
        if not self.script:
            self.shutdown.set()
            return None
        item = self.script.pop(0)
        if not self.script:
            self.shutdown.set()
        if not isinstance(item, FakeMsg) and callable(item):
            item = item()
        return item

    def commit(self, offsets=None, asynchronous=True, message=None):
        assert message is None and asynchronous is False
        self.commits.append([(tp.topic, tp.partition, tp.offset) for tp in offsets])
        self.log.append(("commit", tuple(sorted((tp.partition, tp.offset) for tp in offsets))))
        plan = self.commit_plan.pop(0) if self.commit_plan else None
        if plan is None:
            return [FakeTP(tp.partition, tp.offset, topic=tp.topic) for tp in offsets]
        return plan(offsets)

    def close(self):
        self.closed += 1
        self.log.append(("close",))
        if self.on_close is not None:
            self.on_close()
        if self.close_error is not None:
            raise self.close_error


def play(script, *, n=3, t=1.0, clock=None, repo=None, timing=None, partitions=(0,), fail_on=(), rows=None,
         setup=None):
    shutdown, log = threading.Event(), []
    consumer = FakeConsumer(script, shutdown, log)
    repo = repo or FakeRepo(log, rows=rows, fail_on=fail_on)
    batcher = OffsetBatcher(consumer, n, t, clock=clock or Tick(), log=lambda message: None)
    if partitions:
        batcher.on_assign(consumer, [FakeTP(p) for p in partitions])
    if setup:
        setup(consumer, batcher)
    error = None
    try:
        run_consumer_loop(consumer, repo, shutdown, timing=timing, batcher=batcher)
    except BaseException as exc:  # noqa: BLE001 - the tests inspect it
        error = exc
    return SimpleNamespace(consumer=consumer, repo=repo, batcher=batcher, log=log, error=error)


def only_errors_on(*bad):
    """A commit plan: partitions in `bad` come back with an error, the others succeed."""
    def plan(offsets):
        return [FakeTP(tp.partition, tp.offset, error=("boom" if tp.partition in bad else None), topic=tp.topic)
                for tp in offsets]
    return plan


# ---------------------------------------------------------------------------
# Off by default; the original path is unchanged
# ---------------------------------------------------------------------------

class TestOptIn:

    def test_defaults_are_n1_and_one_second(self, monkeypatch):
        monkeypatch.delenv("CONSUMER_COMMIT_BATCH_MESSAGES", raising=False)
        monkeypatch.delenv("CONSUMER_COMMIT_INTERVAL_SECONDS", raising=False)
        try:
            importlib.reload(config)
            assert config.COMMIT_BATCH_MESSAGES == 1 and config.COMMIT_INTERVAL_SECONDS == 1.0
        finally:
            monkeypatch.undo()
            importlib.reload(config)

    def test_environment_values_are_read(self, monkeypatch):
        monkeypatch.setenv("CONSUMER_COMMIT_BATCH_MESSAGES", "100")
        monkeypatch.setenv("CONSUMER_COMMIT_INTERVAL_SECONDS", "0.5")
        try:
            importlib.reload(config)
            assert (config.COMMIT_BATCH_MESSAGES, config.COMMIT_INTERVAL_SECONDS) == (100, 0.5)
        finally:
            monkeypatch.undo()
            importlib.reload(config)

    @pytest.mark.parametrize("raw", ["1", "2", "100", "1000", " 7 "])
    def test_batch_size_accepts_whole_numbers_1_to_1000(self, raw):
        assert config._commit_batch_messages(raw) == int(raw)

    @pytest.mark.parametrize("raw", ["0", "-1", "1001", "1.5", "abc", "", "nan", None])
    def test_batch_size_refuses_anything_else(self, raw):
        with pytest.raises(ValueError, match="CONSUMER_COMMIT_BATCH_MESSAGES"):
            config._commit_batch_messages(raw)

    @pytest.mark.parametrize("raw", ["0.05", "1", "1.0", "30", "0.5"])
    def test_interval_accepts_the_range(self, raw):
        assert config._commit_interval_seconds(raw) == float(raw)

    @pytest.mark.parametrize("raw", ["0", "0.04", "30.1", "-1", "abc", "", "nan", "inf", None])
    def test_interval_refuses_anything_else(self, raw):
        with pytest.raises(ValueError, match="CONSUMER_COMMIT_INTERVAL_SECONDS"):
            config._commit_interval_seconds(raw)

    def test_the_loop_takes_no_batcher_by_default(self):
        import inspect
        assert inspect.signature(run_consumer_loop).parameters["batcher"].default is None

    def test_without_a_batcher_the_original_commit_call_is_made(self):
        consumer = MagicMock()
        shutdown = threading.Event()
        msg = FakeMsg(1, 5)
        consumer.poll.side_effect = lambda timeout: (shutdown.set(), msg)[1]
        run_consumer_loop(consumer, MagicMock(), shutdown)
        consumer.commit.assert_called_once_with(message=msg, asynchronous=False)
        consumer.subscribe.assert_not_called()

    def test_main_n1_subscribes_exactly_as_before_and_passes_no_batcher(self, monkeypatch):
        import main as main_mod
        fake = MagicMock()
        monkeypatch.setattr(main_mod.confluent_kafka, "Consumer", lambda settings: fake)
        monkeypatch.setattr(main_mod.psycopg, "connect", lambda **kw: MagicMock())
        captured = {}
        monkeypatch.setattr(main_mod, "run_consumer_loop", lambda **kw: captured.update(kw))
        monkeypatch.setattr(config, "COMMIT_BATCH_MESSAGES", 1)
        main_mod.main()
        fake.subscribe.assert_called_once_with([config.TOPIC_SPANS])
        assert "batcher" not in captured

    def test_main_n_greater_than_1_registers_the_callbacks(self, monkeypatch):
        import main as main_mod
        fake = MagicMock()
        monkeypatch.setattr(main_mod.confluent_kafka, "Consumer", lambda settings: fake)
        monkeypatch.setattr(main_mod.psycopg, "connect", lambda **kw: MagicMock())
        captured = {}
        monkeypatch.setattr(main_mod, "run_consumer_loop", lambda **kw: captured.update(kw))
        monkeypatch.setattr(config, "COMMIT_BATCH_MESSAGES", 50)
        monkeypatch.setattr(config, "COMMIT_INTERVAL_SECONDS", 0.5)
        main_mod.main()
        batcher = captured["batcher"]
        assert isinstance(batcher, OffsetBatcher)
        assert (batcher.max_messages, batcher.max_seconds) == (50, 0.5)
        fake.subscribe.assert_called_once_with(
            [config.TOPIC_SPANS], on_assign=batcher.on_assign, on_revoke=batcher.on_revoke,
            on_lost=batcher.on_lost)

    def test_main_does_not_enable_batching_unless_configured(self):
        import inspect
        import main as main_mod
        assert "if config.COMMIT_BATCH_MESSAGES > 1" in inspect.getsource(main_mod.main)

    @pytest.mark.parametrize("n", [0, 1, -3, True, 2.5, "3"])
    def test_a_batcher_needs_at_least_two_messages(self, n):
        with pytest.raises(ValueError):
            OffsetBatcher(MagicMock(), n, 1.0)

    @pytest.mark.parametrize("t", [0, -1, float("nan")])
    def test_a_batcher_needs_a_positive_interval(self, t):
        with pytest.raises(ValueError):
            OffsetBatcher(MagicMock(), 3, t)


# ---------------------------------------------------------------------------
# Ordering, offsets and thresholds
# ---------------------------------------------------------------------------

class TestOffsetsAndOrdering:

    def test_the_database_insert_comes_before_the_commit_that_covers_it(self):
        run = play([FakeMsg(0, 10), FakeMsg(0, 11), FakeMsg(0, 12)], n=3)
        assert run.error is None
        assert run.log == [("insert", 0, 10), ("insert", 0, 11), ("insert", 0, 12),
                           ("commit", ((0, 13),)), ("close",)]

    def test_explicit_topic_partition_offsets_are_committed_synchronously(self):
        run = play([FakeMsg(2, 41), FakeMsg(2, 42)], n=2, partitions=(2,))
        assert run.consumer.commits == [[(TOPIC, 2, 43)]]        # last persisted + 1

    def test_interleaved_partitions_commit_one_offset_each(self):
        script = [FakeMsg(0, 5), FakeMsg(1, 9), FakeMsg(2, 2), FakeMsg(0, 6), FakeMsg(1, 10)]
        run = play(script, n=5, partitions=(0, 1, 2))
        assert run.consumer.commits == [[(TOPIC, 0, 7), (TOPIC, 1, 11), (TOPIC, 2, 3)]]
        assert run.batcher.pending_messages() == 0
        run.batcher.check_invariants()

    def test_a_lower_offset_never_moves_a_pending_offset_back(self):
        batcher = OffsetBatcher(MagicMock(), 5, 1.0, clock=Clock(), log=lambda m: None)
        batcher.on_assign(None, [FakeTP(0)])
        for offset in (10, 12, 11):
            batcher.record(FakeMsg(0, offset))
        assert batcher.pending_offsets() == {(TOPIC, 0): 13}
        assert batcher.pending_messages() == 3

    def test_count_threshold_commits_every_n_and_shutdown_commits_the_rest(self):
        run = play([FakeMsg(0, i) for i in range(7)], n=3)
        assert [c for c in run.consumer.commits] == [[(TOPIC, 0, 3)], [(TOPIC, 0, 6)], [(TOPIC, 0, 7)]]
        assert run.log[-2:] == [("commit", ((0, 7),)), ("close",)]

    def test_time_threshold_commits_when_the_oldest_pending_message_is_old_enough(self):
        clock = Clock()
        script = [FakeMsg(0, 0), lambda: (clock.advance(0.4), FakeMsg(0, 1))[1],
                  lambda: (clock.advance(0.7), FakeMsg(0, 2))[1], lambda: (clock.advance(0.1), FakeMsg(0, 3))[1]]
        run = play(script, n=100, t=1.0, clock=clock)
        # message 2 arrives 1.1 s after the first pending message: flush covers 0..2; 3 flushes at shutdown
        assert run.consumer.commits == [[(TOPIC, 0, 3)], [(TOPIC, 0, 4)]]

    def test_an_idle_poll_flushes_pending_offsets_and_commits_nothing_when_none_are_pending(self):
        run = play([FakeMsg(0, 0), None, None], n=100)
        assert run.consumer.commits == [[(TOPIC, 0, 1)]]              # the second idle poll has nothing to flush
        assert run.log.index(("commit", ((0, 1),))) < run.log.index(("close",))

    def test_the_poll_timeout_shortens_only_while_something_is_pending(self):
        run = play([FakeMsg(0, 0), None], n=100, t=0.3)
        assert run.consumer.poll_timeouts[0] == 1.0                    # nothing pending yet
        assert run.consumer.poll_timeouts[1] == 0.3                    # one message pending
        assert OffsetBatcher(MagicMock(), 3, 5.0, log=lambda m: None).poll_timeout(1.0) == 1.0

    def test_shutdown_commits_pending_offsets_before_close(self):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=100)
        assert run.log[-2:] == [("commit", ((0, 2),)), ("close",)]
        assert run.consumer.closed == 1


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------

class TestFailures:

    def test_a_database_failure_is_not_recorded_and_earlier_messages_are_still_committed(self):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1), FakeMsg(0, 2)], n=100, fail_on=[(0, 1)])
        assert isinstance(run.error, RuntimeError) and "database down" in str(run.error)
        assert run.consumer.commits == [[(TOPIC, 0, 1)]]              # only the persisted message
        assert run.log[-2:] == [("commit", ((0, 1),)), ("close",)]

    @staticmethod
    def _tombstone():
        msg = FakeMsg(0, 1)
        msg._v = None
        return msg

    @pytest.mark.parametrize("make", [
        lambda: TestFailures._tombstone(),                                  # tombstone
        lambda: FakeMsg(0, 1, value=bytes([0xFF, 0xFE])),                   # not UTF-8
        lambda: FakeMsg(0, 1, value=b"not json"),                           # not JSON
        lambda: FakeMsg(0, 1, value=b'{"trace_id": "x"}')])                 # fails validation
    def test_a_decode_or_validation_failure_commits_nothing_for_that_message(self, make):
        run = play([FakeMsg(0, 0), make()], n=100)
        assert run.error is not None
        assert run.consumer.commits == [[(TOPIC, 0, 1)]]

    def test_a_kafka_message_error_halts_and_commits_only_persisted_messages(self):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1, error="broker down")], n=100)
        assert isinstance(run.error, RuntimeError) and "consumer error" in str(run.error)
        assert run.consumer.commits == [[(TOPIC, 0, 1)]]

    def test_a_commit_exception_halts_keeps_pending_and_is_not_retried(self):
        def boom(offsets):
            raise RuntimeError("commit exploded")
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, setup=lambda c, b: c.commit_plan.append(boom))
        assert isinstance(run.error, CommitFailed)
        assert run.batcher.commit_failed and run.batcher.pending_messages() == 2
        assert len(run.consumer.commits) == 1                          # no retry in the final flush
        assert run.consumer.closed == 1

    def test_partial_success_keeps_the_acknowledged_partitions_and_the_failed_one_stays_pending(self):
        script = [FakeMsg(0, 1), FakeMsg(1, 2), FakeMsg(2, 3)]
        run = play(script, n=3, partitions=(0, 1, 2), setup=lambda c, b: c.commit_plan.append(only_errors_on(1)))
        assert isinstance(run.error, CommitFailed)
        assert run.batcher.pending_offsets() == {(TOPIC, 1): 3}        # only partition 1 is still pending
        assert run.batcher.pending_messages() == 1
        assert run.batcher.oldest_pending() is not None
        run.batcher.check_invariants()
        assert len(run.consumer.commits) == 1                          # no second attempt after a failure
        assert run.consumer.closed == 1

    @pytest.mark.parametrize("make", [
        lambda offsets: None,                                                                        # no result
        lambda offsets: [],                                                                          # nothing confirmed
        lambda offsets: [FakeTP(tp.partition, tp.offset + 1, topic=tp.topic) for tp in offsets],     # other offset
        lambda offsets: [FakeTP(tp.partition, tp.offset, topic="other.topic") for tp in offsets],    # other topic
        lambda offsets: "committed",                                                                 # not a list
    ])
    def test_a_result_that_does_not_confirm_a_partition_counts_as_failed(self, make):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, setup=lambda c, b: c.commit_plan.append(make))
        assert isinstance(run.error, CommitFailed)
        assert run.batcher.pending_offsets() == {(TOPIC, 0): 2}

    def test_the_error_field_is_what_marks_a_failed_partition_not_an_err_attribute(self):
        tp = FakeTP(0, 5)
        assert not hasattr(tp, "err")
        plan = lambda offsets: [FakeTP(0, 2, error=None)]                  # the offset that was sent
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, setup=lambda c, b: c.commit_plan.append(plan))
        assert run.error is None and run.batcher.pending_messages() == 0

    def test_close_errors_never_replace_the_original_error(self):
        def setup(consumer, batcher):
            consumer.close_error = RuntimeError("close failed")
        run = play([FakeMsg(0, 0)], n=100, fail_on=[(0, 0)], setup=setup)
        assert "database down" in str(run.error)

    def test_a_close_error_without_another_error_propagates_as_before(self):
        def setup(consumer, batcher):
            consumer.close_error = RuntimeError("close failed")
        run = play([FakeMsg(0, 0)], n=100, setup=setup)
        assert "close failed" in str(run.error)

    def test_keyboard_interrupt_flushes_pending_offsets_and_closes(self):
        def interrupt():
            raise KeyboardInterrupt
        run = play([FakeMsg(0, 0), FakeMsg(0, 1), interrupt], n=100)
        assert isinstance(run.error, KeyboardInterrupt)
        assert run.consumer.commits == [[(TOPIC, 0, 2)]] and run.consumer.closed == 1

    def test_flushing_inside_a_commit_is_refused(self):
        holder = {}

        def reenter(offsets):
            holder["batcher"].flush()
        batcher = OffsetBatcher(MagicMock(), 2, 1.0, clock=Clock(), log=lambda m: None)
        holder["batcher"] = batcher
        batcher.consumer.commit.side_effect = lambda **kw: reenter(None)
        batcher.on_assign(None, [FakeTP(0)])
        batcher.record(FakeMsg(0, 0))
        with pytest.raises(CommitFailed):
            batcher.flush()
        assert batcher.fatal is not None


# ---------------------------------------------------------------------------
# Rebalance callbacks and ownership
# ---------------------------------------------------------------------------

def owned_batcher(partitions=(0, 1, 2), n=100, t=1.0, consumer=None, clock=None):
    consumer = consumer or FakeConsumer([], threading.Event(), [])
    batcher = OffsetBatcher(consumer, n, t, clock=clock or Clock(), log=lambda message: None)
    batcher.on_assign(consumer, [FakeTP(p) for p in partitions])
    return consumer, batcher


class TestRebalance:

    def test_a_partition_is_owned_only_after_it_was_assigned(self):
        batcher = OffsetBatcher(MagicMock(), 3, 1.0, log=lambda m: None)
        with pytest.raises(RuntimeError, match="not owned"):
            batcher.record(FakeMsg(0, 0))
        assert batcher.fatal is not None
        with pytest.raises(RuntimeError, match="unsafe"):
            batcher.record(FakeMsg(0, 1))                                # everything is refused afterwards

    def test_revoke_commits_only_the_revoked_partitions_and_releases_them(self):
        consumer, batcher = owned_batcher()
        for p, o in ((0, 4), (1, 8), (2, 1)):
            batcher.record(FakeMsg(p, o))
        batcher.on_revoke(consumer, [FakeTP(1)])                         # a cooperative revoke of one partition
        assert consumer.commits == [[(TOPIC, 1, 9)]]
        assert batcher.owned == {(TOPIC, 0), (TOPIC, 2)}
        assert batcher.pending_offsets() == {(TOPIC, 0): 5, (TOPIC, 2): 2}
        batcher.check_invariants()

    def test_revoke_of_every_partition_leaves_nothing_pending_or_owned(self):
        consumer, batcher = owned_batcher()
        for p in (0, 1, 2):
            batcher.record(FakeMsg(p, 3))
        batcher.on_revoke(consumer, [FakeTP(p) for p in (0, 1, 2)])
        assert consumer.commits == [[(TOPIC, 0, 4), (TOPIC, 1, 4), (TOPIC, 2, 4)]]
        assert batcher.owned == set() and batcher.pending_messages() == 0 and batcher.oldest_pending() is None

    @pytest.mark.parametrize("plan", [only_errors_on(0, 1), lambda offsets: (_ for _ in ()).throw(RuntimeError("x")),
                                      lambda offsets: None])
    def test_a_failed_revoke_commit_drops_the_offsets_and_does_not_halt(self, plan):
        consumer, batcher = owned_batcher(partitions=(0, 1))
        consumer.commit_plan.append(plan)
        batcher.record(FakeMsg(0, 3))
        batcher.record(FakeMsg(1, 3))
        batcher.on_revoke(consumer, [FakeTP(0), FakeTP(1)])               # must not raise
        assert batcher.fatal is None and not batcher.commit_failed
        assert batcher.revoke_commit_failures == 1
        assert batcher.owned == set() and batcher.pending_messages() == 0

    def test_a_partial_revoke_failure_still_acknowledges_the_successful_partition(self):
        consumer, batcher = owned_batcher(partitions=(0, 1))
        consumer.commit_plan.append(only_errors_on(1))
        batcher.record(FakeMsg(0, 3))
        batcher.record(FakeMsg(1, 3))
        batcher.on_revoke(consumer, [FakeTP(0), FakeTP(1)])
        assert batcher.revoke_commit_failures == 1 and batcher.fatal is None
        assert batcher.pending_messages() == 0 and batcher.owned == set()

    def test_lost_partitions_are_dropped_without_any_commit_and_never_committed_later(self):
        consumer, batcher = owned_batcher()
        batcher.record(FakeMsg(0, 3))
        batcher.record(FakeMsg(1, 3))
        batcher.on_lost(consumer, [FakeTP(0)])
        assert consumer.commits == [] and batcher.dropped_on_lost == 1
        assert batcher.owned == {(TOPIC, 1), (TOPIC, 2)}
        batcher.flush()                                                   # a later flush ...
        assert consumer.commits == [[(TOPIC, 1, 4)]]                      # ... never includes the lost partition
        with pytest.raises(RuntimeError, match="not owned"):
            batcher.record(FakeMsg(0, 4))                                 # a message for it without a new assignment halts

    def test_a_reassigned_partition_starts_clean(self):
        consumer, batcher = owned_batcher(partitions=(0,))
        batcher.record(FakeMsg(0, 3))
        batcher.on_lost(consumer, [FakeTP(0)])
        batcher.on_assign(consumer, [FakeTP(0)])
        assert batcher.pending_messages() == 0
        batcher.record(FakeMsg(0, 50))
        batcher.flush()
        assert consumer.commits == [[(TOPIC, 0, 51)]]

    def test_assign_of_an_already_owned_partition_drops_its_stale_state(self):
        consumer, batcher = owned_batcher(partitions=(0,))
        batcher.record(FakeMsg(0, 3))
        batcher.on_assign(consumer, [FakeTP(0)])                          # a missed revoke
        assert batcher.stale_assignments == 1 and batcher.pending_messages() == 0
        assert batcher.owned == {(TOPIC, 0)}

    def test_revoking_a_partition_that_has_nothing_pending_commits_nothing(self):
        consumer, batcher = owned_batcher()
        batcher.on_revoke(consumer, [FakeTP(0)])
        assert consumer.commits == [] and batcher.owned == {(TOPIC, 1), (TOPIC, 2)}

    def test_callbacks_never_raise_and_an_internal_error_makes_the_state_fatal(self):
        batcher = OffsetBatcher(MagicMock(), 3, 1.0, log=lambda m: None)
        for callback in (batcher.on_assign, batcher.on_revoke, batcher.on_lost):
            callback(None, [object()])                                    # malformed partitions: must not raise
        assert batcher.fatal is not None
        with pytest.raises(RuntimeError, match="unsafe"):
            batcher.check_fatal()

    def test_after_a_fatal_callback_error_the_loop_halts_before_processing_or_committing(self):
        def poisoned_poll():
            batcher_ref["b"].on_revoke(None, [object()])                  # the callback fires inside poll()
            return FakeMsg(0, 1)
        batcher_ref = {}

        def setup(consumer, batcher):
            batcher_ref["b"] = batcher
        run = play([FakeMsg(0, 0), poisoned_poll, FakeMsg(0, 2)], n=100, setup=setup)
        assert isinstance(run.error, RuntimeError) and "unsafe" in str(run.error)
        assert run.log == [("insert", 0, 0), ("close",)]                  # message 1 never processed; nothing committed
        assert run.consumer.commits == []

    def test_a_callback_fired_during_poll_commits_before_the_next_message_is_processed(self):
        def rebalance():
            batcher_ref["b"].on_revoke(None, [FakeTP(0), FakeTP(1)])
            batcher_ref["b"].on_assign(None, [FakeTP(0)])
            return FakeMsg(0, 7)
        batcher_ref = {}

        def setup(consumer, batcher):
            batcher_ref["b"] = batcher
        run = play([FakeMsg(0, 5), FakeMsg(1, 9), rebalance], n=100, partitions=(0, 1), setup=setup)
        assert run.error is None
        assert run.log == [("insert", 0, 5), ("insert", 1, 9), ("commit", ((0, 6), (1, 10))),
                           ("insert", 0, 7), ("commit", ((0, 8),)), ("close",)]

    def test_a_message_from_a_partition_that_the_rebalance_removed_halts(self):
        def rebalance():
            batcher_ref["b"].on_revoke(None, [FakeTP(0), FakeTP(1)])
            batcher_ref["b"].on_assign(None, [FakeTP(0)])
            return FakeMsg(1, 11)                                          # partition 1 is no longer owned
        batcher_ref = {}

        def setup(consumer, batcher):
            batcher_ref["b"] = batcher
        run = play([FakeMsg(0, 5), rebalance], n=100, partitions=(0, 1), setup=setup)
        assert isinstance(run.error, RuntimeError) and "not owned" in str(run.error)
        assert all(offsets != [(TOPIC, 1, 12)] for offsets in run.consumer.commits)

    def test_close_is_followed_by_no_unsafe_final_commit_after_a_fatal_state(self):
        def poisoned():
            batcher_ref["b"].on_lost(None, [object()])
            return FakeMsg(0, 1)
        batcher_ref = {}

        def setup(consumer, batcher):
            batcher_ref["b"] = batcher
        run = play([FakeMsg(0, 0), poisoned], n=100, setup=setup)
        assert run.consumer.commits == [] and run.consumer.closed == 1


# ---------------------------------------------------------------------------
# Bookkeeping after partial flushes
# ---------------------------------------------------------------------------

class TestBookkeeping:

    def test_counts_and_oldest_time_follow_the_remaining_partitions_after_a_partial_flush(self):
        clock = Clock()
        consumer, batcher = owned_batcher(partitions=(0, 1, 2), clock=clock)
        batcher.record(FakeMsg(0, 1)); clock.advance(2.0)
        batcher.record(FakeMsg(1, 1)); batcher.record(FakeMsg(1, 2)); clock.advance(3.0)
        batcher.record(FakeMsg(2, 1))
        assert batcher.pending_messages() == 4 and batcher.oldest_pending() == 0.0
        consumer.commit_plan.append(only_errors_on(1))
        with pytest.raises(CommitFailed):
            batcher.flush()
        assert batcher.pending_offsets() == {(TOPIC, 1): 3}
        assert batcher.pending_messages() == 2 and batcher.oldest_pending() == 2.0
        batcher.check_invariants()

    def test_after_a_full_flush_nothing_is_pending_and_the_age_restarts(self):
        clock = Clock()
        consumer, batcher = owned_batcher(partitions=(0,), clock=clock, n=100)
        batcher.record(FakeMsg(0, 1))
        clock.advance(5.0)
        batcher.flush()
        assert batcher.pending_messages() == 0 and batcher.oldest_pending() is None and not batcher.due()
        batcher.record(FakeMsg(0, 2))
        assert batcher.oldest_pending() == 5.0

    def test_flushing_with_nothing_pending_makes_no_commit(self):
        consumer, batcher = owned_batcher()
        batcher.flush()
        batcher.flush_pending()
        batcher.finish()
        assert consumer.commits == []

    def test_finish_is_skipped_after_a_commit_failure_or_a_fatal_state(self):
        consumer, batcher = owned_batcher(partitions=(0,))
        batcher.record(FakeMsg(0, 1))
        batcher.commit_failed = True
        batcher.finish()
        assert consumer.commits == []
        consumer2, batcher2 = owned_batcher(partitions=(0,))
        batcher2.record(FakeMsg(0, 1))
        batcher2.on_assign(None, [object()])
        batcher2.finish()
        assert consumer2.commits == []

    def test_finish_swallows_a_commit_failure(self):
        consumer, batcher = owned_batcher(partitions=(0,))
        consumer.commit_plan.append(only_errors_on(0))
        batcher.record(FakeMsg(0, 1))
        batcher.finish()                                                  # must not raise
        assert batcher.commit_failed

    @pytest.mark.parametrize("seed", range(150))
    def test_randomized_operations_keep_the_bookkeeping_consistent(self, seed):
        rng = random.Random(seed)
        consumer = FakeConsumer([], threading.Event(), [])
        clock = Clock()
        batcher = OffsetBatcher(consumer, 40, 5.0, clock=clock, log=lambda m: None)
        owned, persisted, committed = set(), {}, {}
        pending, counts = {}, {}
        next_offset = {p: rng.randrange(0, 50) for p in range(4)}
        confirmed_by_plan = {}

        def plan_for(kind):
            def plan(offsets):
                confirmed_by_plan.clear()
                if kind == "raise":
                    raise RuntimeError("commit exploded")
                out = []
                for tp in offsets:
                    bad = kind == "some" and rng.random() < 0.5
                    out.append(FakeTP(tp.partition, tp.offset, error="x" if bad else None))
                    if not bad:
                        confirmed_by_plan[(tp.topic, tp.partition)] = tp.offset
                return out
            return plan

        for _ in range(60):
            op = rng.choice(["assign", "record", "record", "record", "flush", "revoke", "lost", "tick"])
            free = [p for p in range(4) if (TOPIC, p) not in owned]
            mine = [p for p in range(4) if (TOPIC, p) in owned]
            if op == "assign" and free:
                p = rng.choice(free)
                batcher.on_assign(consumer, [FakeTP(p)])
                owned.add((TOPIC, p))
                pending.pop((TOPIC, p), None); counts.pop((TOPIC, p), None)
            elif op == "record" and mine:
                p = rng.choice(mine)
                offset = next_offset[p] + rng.randrange(0, 3)
                next_offset[p] = offset + 1
                batcher.record(FakeMsg(p, offset))
                key = (TOPIC, p)
                pending[key] = max(pending.get(key, 0), offset + 1)
                counts[key] = counts.get(key, 0) + 1
                persisted[key] = max(persisted.get(key, 0), offset + 1)
            elif op == "flush" and pending:
                kind = rng.choice(["all", "some", "raise"])
                consumer.commit_plan.append(plan_for(kind))
                before = dict(pending)
                try:
                    batcher.flush()
                except CommitFailed:
                    pass
                for key, offset in confirmed_by_plan.items():
                    assert key in owned and offset == before[key] <= persisted[key]
                    assert offset >= committed.get(key, 0)
                    committed[key] = offset
                    pending.pop(key); counts.pop(key)
                confirmed_by_plan.clear()
            elif op in ("revoke", "lost") and mine:
                chosen = rng.sample(mine, rng.randrange(1, len(mine) + 1))
                keys = [(TOPIC, p) for p in chosen]
                if op == "revoke":
                    consumer.commit_plan.append(plan_for(rng.choice(["all", "some", "raise"])))
                    before = dict(pending)
                    batcher.on_revoke(consumer, [FakeTP(p) for p in chosen])
                    for key, offset in confirmed_by_plan.items():
                        assert key in owned and offset == before[key] <= persisted[key]
                        assert offset >= committed.get(key, 0)
                        committed[key] = offset
                    confirmed_by_plan.clear()
                else:
                    batcher.on_lost(consumer, [FakeTP(p) for p in chosen])
                for key in keys:
                    owned.discard(key); pending.pop(key, None); counts.pop(key, None)
            elif op == "tick":
                clock.advance(rng.random())
            # invariants after every operation
            batcher.check_invariants()
            assert batcher.fatal is None
            assert batcher.owned == owned
            assert batcher.pending_offsets() == pending
            assert batcher.pending_messages() == sum(counts.values())
            assert (batcher.oldest_pending() is None) == (not pending)
        # nothing committed ever exceeded a persisted offset, and no commit was for an unowned partition at that time
        for sent in consumer.commits:
            for topic, partition, offset in sent:
                assert offset <= persisted[(topic, partition)]


# ---------------------------------------------------------------------------
# Crash and replay
# ---------------------------------------------------------------------------

class TestCrashAndReplay:

    def test_replaying_uncommitted_messages_changes_no_rows_and_counts_conflicts(self):
        messages = [FakeMsg(0, i) for i in range(8)]
        rows, log = set(), []
        # first run: all 8 messages are persisted, but only the first 6 are committed before the crash
        first_consumer = FakeConsumer([], threading.Event(), log)
        repo = FakeRepo(log, rows=rows)
        first = OffsetBatcher(first_consumer, 6, 1.0, clock=Clock(), log=lambda m: None)
        first.on_assign(first_consumer, [FakeTP(0)])
        for msg in messages:
            process_message(msg, repo)
            first.record(msg)
            first.flush_if_due()
        assert first_consumer.commits == [[(TOPIC, 0, 6)]]
        assert first.pending_messages() == 2                       # persisted, offsets not committed: "crash" here
        rows_after_crash = set(rows)
        # restart: Kafka redelivers from the committed offset (6)
        replay = [m for m in messages if m.offset() >= 6]
        second = play(list(replay), n=2, rows=rows)
        assert second.error is None
        assert rows == rows_after_crash and len(rows) == 8          # same rows
        assert second.consumer.commits == [[(TOPIC, 0, 8)]]
        # the redelivered messages hit the unique constraint: the repository reported "already there"
        assert [e for e in second.log if e[0] == "insert"] == [("insert", 0, 6), ("insert", 0, 7)]

    def test_a_conflict_is_still_a_persisted_message_for_offset_purposes(self):
        rows = {("a" * 32, f"{0:04x}{3:012x}")}                      # the span of offset 3 already exists
        run = play([FakeMsg(0, 3)], n=100, rows=rows)
        assert run.error is None and run.consumer.commits == [[(TOPIC, 0, 4)]]


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

def recorder_():
    emitted = []
    return TimingRecorder(60.0, clock=Tick(), emit=emitted.append), emitted


class TestTiming:

    @staticmethod
    def _final(emitted):
        parsed = [json.loads(line[len("storage-consumer timing "):]) for line in emitted]
        return parsed[-1]

    def test_the_same_consumer_and_repository_calls_are_made_with_and_without_timing(self):
        script = lambda: [FakeMsg(0, i) for i in range(7)] + [None]
        without = play(script(), n=3)
        recorder, _ = recorder_()
        with_timing = play(script(), n=3, timing=recorder)
        assert without.log == with_timing.log
        assert without.consumer.commits == with_timing.consumer.commits

    def test_commit_timing_is_per_commit_not_per_message(self):
        recorder, emitted = recorder_()
        run = play([FakeMsg(0, i) for i in range(7)], n=3, timing=recorder)
        final = self._final(emitted)
        assert final["kind"] == "final"
        commits = len(run.consumer.commits)
        assert commits == 3 and final["stages"]["kafka_commit"]["count"] == commits
        assert final["counters"]["messages"] == 7 and final["stages"]["cycle"]["count"] == 7
        assert final["stages"]["poll"]["count"] == 7 and final["stages"]["insert_txn"]["count"] == 7
        assert final["counters"]["inserted"] == 7 and final["counters"]["conflicts"] == 0
        assert round(final["counters"]["messages"] / final["stages"]["kafka_commit"]["count"], 2) == 2.33

    def test_idle_polls_are_counted_and_a_failed_commit_is_not_recorded(self):
        recorder, emitted = recorder_()
        play([FakeMsg(0, 0), None, None], n=100, timing=recorder)
        final = self._final(emitted)
        assert final["counters"]["idle_polls"] >= 1 and final["stages"]["kafka_commit"]["count"] == 1
        recorder2, emitted2 = recorder_()
        play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, timing=recorder2,
             setup=lambda c, b: c.commit_plan.append(only_errors_on(0)))
        assert self._final(emitted2)["stages"]["kafka_commit"]["count"] == 0

    def test_a_timing_failure_does_not_change_what_is_committed(self):
        recorder, _ = recorder_()
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, timing=recorder)
        assert run.error is None and run.consumer.commits == [[(TOPIC, 0, 2)]]


# ---------------------------------------------------------------------------
# Source-level guarantees
# ---------------------------------------------------------------------------

class TestSourceGuarantees:

    def test_process_message_still_never_commits(self):
        import inspect
        assert ".commit(" not in inspect.getsource(process_message)

    def test_the_batcher_commits_with_explicit_offsets_and_synchronously_only(self):
        import inspect
        source = inspect.getsource(OffsetBatcher)
        assert "offsets=offsets, asynchronous=False" in source
        assert "asynchronous=True" not in source
        assert ".err " not in source and ".err)" not in source and ".err," not in source

    def test_the_batcher_is_not_enabled_in_the_default_or_by_the_loop_signature(self):
        assert not hasattr(consumer_mod, "TimingRecorder")
        import main as main_mod
        import inspect
        assert "OffsetBatcher(" in inspect.getsource(main_mod.main)
        assert "COMMIT_BATCH_MESSAGES > 1" in inspect.getsource(main_mod.main)


# ---------------------------------------------------------------------------
# Callbacks fired by close() (B3J-236): they may release ownership but never commit
# ---------------------------------------------------------------------------

def fire_on_close(consumer, batcher, partitions=(0,), lost=False):
    """Make close() behave like the client: it invokes the rebalance callbacks."""
    def callbacks():
        parts = [FakeTP(p) for p in partitions]
        batcher.on_revoke(consumer, parts)
        if lost:
            batcher.on_lost(consumer, parts)
    consumer.on_close = callbacks


def commits_after_close(run):
    index = run.log.index(("close",))
    return [event for event in run.log[index:] if event[0] == "commit"]


class StrictRecorder(TimingRecorder):
    """Notes every stage record or count that arrives after the final summary."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_final, self.after_final = False, []

    def final(self):
        super().final()
        self.is_final = True

    def record(self, stage, seconds):
        if self.is_final:
            self.after_final.append(stage)
        super().record(stage, seconds)

    def count(self, name):
        if self.is_final:
            self.after_final.append(name)
        super().count(name)


def poisoned_poll(holder):
    """A poll item: an internal failure inside a callback (fatal), then a message."""
    def item():
        holder["b"].on_revoke(None, [object()])
        return FakeMsg(0, 1)
    return item


class TestCloseCallbacksNeverCommit:

    def test_normal_shutdown_flushes_once_before_close_and_the_close_callback_commits_nothing(self):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=100, setup=lambda c, b: fire_on_close(c, b))
        assert run.error is None
        assert run.consumer.commits == [[(TOPIC, 0, 2)]]               # exactly the one final flush
        assert run.log == [("insert", 0, 0), ("insert", 0, 1), ("commit", ((0, 2),)), ("close",)]
        assert commits_after_close(run) == []
        assert run.batcher.closing and run.batcher.owned == set() and run.batcher.pending_messages() == 0
        assert run.batcher.revoke_commit_failures == 0 and run.batcher.blocked_revokes == 0
        run.batcher.check_invariants()

    def test_a_close_callback_with_nothing_pending_does_nothing(self):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, setup=lambda c, b: fire_on_close(c, b))
        assert run.consumer.commits == [[(TOPIC, 0, 2)]] and run.batcher.blocked_revokes == 0

    def test_after_a_kafka_commit_failure_close_does_not_try_again_and_the_original_error_survives(self):
        def boom(offsets):
            raise RuntimeError("commit exploded")

        def setup(consumer, batcher):
            consumer.commit_plan.append(boom)
            fire_on_close(consumer, batcher)
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, setup=setup)
        assert isinstance(run.error, CommitFailed)
        assert [e for e in run.log if e[0] == "commit"] == [("commit", ((0, 2),))]      # the failed attempt only
        assert commits_after_close(run) == []
        assert run.batcher.blocked_revokes == 1
        assert run.batcher.owned == set() and run.batcher.pending_messages() == 0       # released and dropped

    def test_after_a_partial_commit_failure_close_does_not_commit_the_failed_partition(self):
        def setup(consumer, batcher):
            consumer.commit_plan.append(only_errors_on(1))
            fire_on_close(consumer, batcher, partitions=(0, 1, 2))
        run = play([FakeMsg(0, 1), FakeMsg(1, 2), FakeMsg(2, 3)], n=3, partitions=(0, 1, 2), setup=setup)
        assert isinstance(run.error, CommitFailed)
        assert len(run.consumer.commits) == 1 and commits_after_close(run) == []
        assert run.batcher.owned == set() and run.batcher.pending_messages() == 0
        run.batcher.check_invariants()

    def test_after_a_fatal_state_close_commits_nothing(self):
        holder = {}

        def setup(consumer, batcher):
            holder["b"] = batcher
            fire_on_close(consumer, batcher)
        run = play([FakeMsg(0, 0), poisoned_poll(holder), FakeMsg(0, 2)], n=100, setup=setup)
        assert isinstance(run.error, RuntimeError) and "unsafe" in str(run.error)
        assert run.consumer.commits == [] and commits_after_close(run) == []
        assert run.batcher.owned == set() and run.batcher.pending_messages() == 0
        assert run.batcher.blocked_revokes == 1

    def test_a_failed_final_flush_is_not_retried_by_the_close_callback(self):
        def setup(consumer, batcher):
            consumer.commit_plan.append(only_errors_on(0))
            fire_on_close(consumer, batcher)
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=100, setup=setup)
        assert run.error is None                                          # finish() swallowed the failure
        assert run.batcher.commit_failed
        assert len(run.consumer.commits) == 1 and commits_after_close(run) == []
        assert run.batcher.blocked_revokes == 1 and run.batcher.pending_messages() == 0

    def test_a_close_callback_for_lost_partitions_commits_nothing_either(self):
        run = play([FakeMsg(0, 0)], n=100, setup=lambda c, b: fire_on_close(c, b, lost=True))
        assert run.consumer.commits == [[(TOPIC, 0, 1)]] and commits_after_close(run) == []
        assert run.batcher.owned == set()

    def test_a_database_failure_keeps_its_exception_and_close_commits_nothing(self):
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=100, fail_on=[(0, 1)],
                   setup=lambda c, b: fire_on_close(c, b))
        assert isinstance(run.error, RuntimeError) and "database down" in str(run.error)
        assert run.consumer.commits == [[(TOPIC, 0, 1)]]                    # the persisted message, before close
        assert commits_after_close(run) == []

    def test_keyboard_interrupt_still_flushes_before_close_and_close_commits_nothing(self):
        def interrupt():
            raise KeyboardInterrupt
        run = play([FakeMsg(0, 0), interrupt], n=100, setup=lambda c, b: fire_on_close(c, b))
        assert isinstance(run.error, KeyboardInterrupt)
        assert run.consumer.commits == [[(TOPIC, 0, 1)]] and commits_after_close(run) == []

    def test_no_commit_is_possible_once_closing_is_set(self):
        consumer, batcher = owned_batcher(partitions=(0, 1))
        batcher.record(FakeMsg(0, 3))
        batcher.record(FakeMsg(1, 3))
        batcher.closing = True
        with pytest.raises(CommitFailed):
            batcher.flush()
        batcher.finish()
        batcher.on_revoke(consumer, [FakeTP(0)])
        assert consumer.commits == []                                      # nothing reached the client
        assert batcher.blocked_revokes == 1 and batcher.revoke_commit_failures == 0
        assert batcher.owned == {(TOPIC, 1)}                                # ownership of the revoked partition released
        assert batcher.pending_offsets() == {(TOPIC, 1): 4}                 # the other partition's entry untouched
        batcher.check_invariants()

    @pytest.mark.parametrize("flag", ["commit_failed", "fatal"])
    def test_a_revoke_in_a_halted_state_releases_ownership_without_committing(self, flag):
        consumer, batcher = owned_batcher(partitions=(0, 1))
        batcher.record(FakeMsg(0, 3))
        setattr(batcher, flag, True if flag == "commit_failed" else RuntimeError("bad"))
        batcher.on_revoke(consumer, [FakeTP(0), FakeTP(1)])
        assert consumer.commits == [] and batcher.owned == set() and batcher.pending_messages() == 0
        assert batcher.blocked_revokes == 1

    def test_during_normal_operation_a_failed_revoke_commit_is_still_recoverable(self):
        consumer, batcher = owned_batcher(partitions=(0,))
        consumer.commit_plan.append(only_errors_on(0))
        batcher.record(FakeMsg(0, 3))
        assert not batcher.commits_blocked()
        batcher.on_revoke(consumer, [FakeTP(0)])
        assert len(consumer.commits) == 1 and batcher.revoke_commit_failures == 1
        assert batcher.fatal is None and not batcher.commit_failed and batcher.blocked_revokes == 0

    def test_no_timing_record_arrives_after_the_final_summary(self):
        emitted = []
        recorder = StrictRecorder(60.0, clock=Tick(), emit=emitted.append)
        run = play([FakeMsg(0, i) for i in range(5)], n=3, timing=recorder,
                   setup=lambda c, b: fire_on_close(c, b))
        assert run.error is None and recorder.is_final and recorder.after_final == []
        final = json.loads(emitted[-1][len("storage-consumer timing "):])
        assert final["kind"] == "final" and final["stages"]["kafka_commit"]["count"] == len(run.consumer.commits) == 2

    def test_no_timing_record_arrives_after_the_final_summary_when_a_commit_failed(self):
        emitted = []
        recorder = StrictRecorder(60.0, clock=Tick(), emit=emitted.append)

        def setup(consumer, batcher):
            consumer.commit_plan.append(only_errors_on(0))
            fire_on_close(consumer, batcher)
        run = play([FakeMsg(0, 0), FakeMsg(0, 1)], n=2, timing=recorder, setup=setup)
        assert isinstance(run.error, CommitFailed) and recorder.after_final == []
        assert json.loads(emitted[-1][len("storage-consumer timing "):])["stages"]["kafka_commit"]["count"] == 0

    def test_the_final_flush_precedes_the_closing_flag_and_close(self):
        seen = {}

        def setup(consumer, batcher):
            consumer.on_close = lambda: seen.update(closing_at_close=batcher.closing)
        run = play([FakeMsg(0, 0)], n=100, setup=setup)
        assert seen["closing_at_close"] is True
        assert run.log.index(("commit", ((0, 1),))) < run.log.index(("close",))

    def test_the_original_loop_has_no_closing_state_and_still_commits_per_message(self):
        consumer, shutdown = MagicMock(), threading.Event()
        msgs = [FakeMsg(0, 0), FakeMsg(0, 1)]
        script = list(msgs)

        def poll(timeout):
            message = script.pop(0)
            if not script:
                shutdown.set()
            return message
        consumer.poll.side_effect = poll
        run_consumer_loop(consumer, MagicMock(), shutdown)
        assert [c.kwargs for c in consumer.commit.call_args_list] == [
            {"message": msgs[0], "asynchronous": False}, {"message": msgs[1], "asynchronous": False}]
        consumer.close.assert_called_once()

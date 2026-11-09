"""
storage-consumer/tests/unit/test_failure_recovery.py

Offline restart-convergence tests for the storage consumer (Phase 14.5, first scenario).

The other unit tests prove, one fault at a time, that a failure leaves the Kafka offset uncommitted.
These tests add the next step: after a fault the loop halts, a supervisor starts it again, the new
consumer begins at the last COMMITTED offset, and the run converges on the right final state.

What is real: consumer.run_consumer_loop, consumer.process_message, consumer.OffsetBatcher (the
batched mode as main.py configures it) and the CanonicalSpanEvent validation.
What is fake, and in memory only: the Kafka log and its committed offset, the poll/commit calls,
and the PostgreSQL repository, which emulates the UNIQUE(trace_id, span_id) constraint with
ON CONFLICT DO NOTHING (insert_span returns True for a new row and False for a duplicate).
No socket, no Docker, no Kafka, no PostgreSQL, no process is touched.

What this proves, and what it does not
  - It proves that the Python orchestration contracts converge under a single injected fault (and
    under two in a row): final rows == unique input spans, no duplicate rows, no offset committed
    past an unpersisted message, the faulted run halts, restart begins at the committed offset.
  - It does NOT prove exactly-once Kafka delivery: replays happen, and the unique constraint (here
    emulated) is what keeps them harmless.
  - It does NOT prove Kafka or PostgreSQL behavior: the real unique constraint, real transactions
    and the real client's commit semantics are covered only by the live integration cases.
  - A "simulated interruption" is NOT an operating-system process kill.  The fake raises a
    BaseException at the chosen point and, from then on, refuses every call the dying run makes (so
    nothing it does afterwards has any effect), which models "the process stopped there".  Python's
    finally blocks still run in the test process, which a real kill would not do; the real forced
    kill of the real consumer is the live integration case C07b.

Uncovered crash windows are listed at the end of the module docstring of the last test class.
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import confluent_kafka
import pytest

from consumer import OffsetBatcher, process_message, run_consumer_loop

TOPIC = "agentops.telemetry.spans"
TRACE = "a" * 32
N = 5                       # messages in the default scenarios
BATCH = 3                   # batch size of the batched scenarios
N_BATCHED = 7               # offsets 0..6: batches commit 3, 6, then the idle flush commits 7


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class SimulatedInterruption(BaseException):
    """The process 'stopped' here.  Not an OS kill; see the module docstring."""


def span_bytes(index: int) -> bytes:
    return json.dumps({
        "trace_id": TRACE, "span_id": f"{index:016x}", "span_name": "t.op", "span_kind": "INTERNAL",
        "service_name": "svc", "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": "2026-01-01T00:00:00+00:00", "duration_ms": 0.0, "status_code": "OK"}).encode()


def build_log(count: int, duplicates: dict[int, int] | None = None) -> list[bytes]:
    """count messages; duplicates maps an offset to the offset whose span it repeats."""
    duplicates = duplicates or {}
    return [span_bytes(duplicates.get(offset, offset)) for offset in range(count)]


def unique_keys(log: list[bytes]) -> set[tuple[str, str]]:
    return {(json.loads(value)["trace_id"], json.loads(value)["span_id"]) for value in log}


class FakeMsg:
    def __init__(self, offset, value):
        self._offset, self._value = offset, value

    def value(self):
        return self._value

    def topic(self):
        return TOPIC

    def partition(self):
        return 0

    def offset(self):
        return self._offset

    def error(self):
        return None


DB_FAULTS = ("db_insert_error", "db_txn_commit_error", "db_commit_ack_lost", "interrupt_during_db_transaction")
COMMIT_FAULTS = ("kafka_commit_error", "kafka_commit_ack_lost", "interrupt_before_kafka_commit")


class FakeBroker:
    """An ordered single-partition log with a committed offset, one-shot faults and an event trace."""

    def __init__(self, log, faults=()):
        self.log = list(log)
        self.committed = None                     # None: nothing committed yet, so a new consumer starts at 0
        self.faults = [dict(kind=kind, at=at) for kind, at in faults]
        self.events: list[tuple] = []
        self.violations: list[str] = []
        self.commit_calls = 0
        self.run = 0
        self.dead: set[int] = set()
        self.repo: FakeRepository | None = None

    # -- runs --------------------------------------------------------------------
    def start_run(self) -> int:
        self.run += 1
        return self.run

    def start_offset(self) -> int:
        return 0 if self.committed is None else self.committed

    def kill(self, run):
        self.dead.add(run)

    def check_alive(self, run):
        if run in self.dead:
            raise SimulatedInterruption("this run was already interrupted; the call has no effect")

    # -- faults --------------------------------------------------------------------
    def take(self, kinds, at):
        for fault in self.faults:
            if fault["kind"] in kinds and fault["at"] == at:
                self.faults.remove(fault)         # one-shot
                self.events.append(("fault", self.run, fault["kind"], at))
                return fault["kind"]
        return None

    # -- the invariant: nothing is committed past an unpersisted message --------------
    def check_commit(self, new_offset):
        for offset in range(new_offset):
            key = (json.loads(self.log[offset])["trace_id"], json.loads(self.log[offset])["span_id"])
            if self.repo is None or key not in self.repo.keys:
                self.violations.append(f"offset {new_offset} committed but offset {offset} is not persisted")
        if self.committed is not None and new_offset < self.committed:
            self.violations.append(f"committed offset moved back from {self.committed} to {new_offset}")


class FakeRepository:
    """Emulates telemetry_spans: UNIQUE(trace_id, span_id) with ON CONFLICT DO NOTHING, and one
    transaction per insert.  True = a new row, False = already there."""

    def __init__(self, broker):
        self.broker = broker
        broker.repo = self
        self.rows: list[tuple[str, str]] = []     # committed rows in commit order
        self.keys: set[tuple[str, str]] = set()
        self.results: list[tuple[int, int, bool]] = []      # (run, offset, was_new) as returned to the caller

    def insert_span(self, event, topic, partition, offset):
        run = self.broker.run
        self.broker.check_alive(run)
        fault = self.broker.take(DB_FAULTS, offset)
        key = (event.trace_id, event.span_id)
        if fault == "db_insert_error":
            raise RuntimeError("injected: the insert failed before anything was persisted")
        if fault == "db_txn_commit_error":
            raise RuntimeError("injected: the transaction failed at commit and was rolled back")
        if fault == "interrupt_during_db_transaction":
            self.broker.kill(run)                 # killed mid-transaction: rolled back, nothing persisted
            raise SimulatedInterruption("interrupted inside the database transaction")
        is_new = key not in self.keys
        if is_new:
            self.rows.append(key)
            self.keys.add(key)
        self.broker.events.append(("insert", run, offset, is_new))
        if fault == "db_commit_ack_lost":
            raise RuntimeError("injected: the connection was lost after the commit; the caller never learns")
        self.results.append((run, offset, is_new))
        return is_new


class FakeConsumer:
    """The consumer one run uses: starts at the broker's committed offset, polls in order."""

    def __init__(self, broker, run, shutdown):
        self.broker, self.run, self.shutdown = broker, run, shutdown
        self.position = broker.start_offset()
        self.start = self.position
        self.closed = 0

    def poll(self, timeout=None):
        self.broker.check_alive(self.run)
        if self.position >= len(self.broker.log):
            self.shutdown.set()
            return None
        msg = FakeMsg(self.position, self.broker.log[self.position])
        self.broker.events.append(("poll", self.run, self.position))
        self.position += 1
        return msg

    def commit(self, message=None, offsets=None, asynchronous=True):
        assert asynchronous is False, "the consumer must commit synchronously"
        self.broker.check_alive(self.run)
        if message is not None:
            new_offset, reply = message.offset() + 1, None
        else:
            assert len(offsets) == 1 and offsets[0].partition == 0
            new_offset = offsets[0].offset
            reply = [confluent_kafka.TopicPartition(offsets[0].topic, 0, new_offset)]
        call = self.broker.commit_calls
        self.broker.commit_calls += 1
        fault = self.broker.take(COMMIT_FAULTS, call)
        if fault == "kafka_commit_error":
            raise RuntimeError("injected: the offset commit failed; nothing was committed")
        if fault == "interrupt_before_kafka_commit":
            self.broker.kill(self.run)
            raise SimulatedInterruption("interrupted after the database commit, before the offset commit")
        self.broker.check_commit(new_offset)
        self.broker.committed = new_offset
        self.broker.events.append(("commit", self.run, new_offset))
        if fault == "kafka_commit_ack_lost":
            raise RuntimeError("injected: the commit was applied by the broker but the reply was lost")
        return reply

    def close(self):
        if self.run in self.broker.dead:
            return                                # a dead process closes nothing
        self.closed += 1
        self.broker.events.append(("close", self.run))


# ---------------------------------------------------------------------------
# The supervisor: run the real loop, restart it from the committed offset until it ends cleanly
# ---------------------------------------------------------------------------

def supervise(log, faults=(), *, batch=None, max_runs=6):
    broker = FakeBroker(log, faults)
    repo = FakeRepository(broker)
    runs = []
    while True:
        run_id = broker.start_run()
        shutdown = threading.Event()
        consumer = FakeConsumer(broker, run_id, shutdown)
        batcher = None
        if batch is not None:
            # as main.py wires it for CONSUMER_COMMIT_BATCH_MESSAGES > 1: the real OffsetBatcher with the
            # assignment callback the broker would fire; the clock is frozen, so only the count threshold,
            # the idle-poll flush and the final flush commit
            batcher = OffsetBatcher(consumer, batch, 30.0, clock=lambda: 0.0, log=lambda message: None)
            batcher.on_assign(consumer, [confluent_kafka.TopicPartition(TOPIC, 0)])
        first_event = len(broker.events)
        error = None
        try:
            run_consumer_loop(consumer, repo, shutdown, poll_timeout_seconds=0.01, batcher=batcher)
        except BaseException as exc:  # noqa: BLE001 - the supervisor inspects the halt
            error = exc
        events = broker.events[first_event:]
        runs.append(SimpleNamespace(
            id=run_id, start=consumer.start, error=error, committed_after=broker.committed, events=events,
            polled=[e[2] for e in events if e[0] == "poll"],
            inserted_new={e[2] for e in events if e[0] == "insert" and e[3]},
            conflicts={e[2] for e in events if e[0] == "insert" and not e[3]},
            closed=consumer.closed))
        if error is None:
            break
        assert len(runs) < max_runs, "the supervisor did not converge"
    return SimpleNamespace(broker=broker, repo=repo, runs=runs, log=log)


def assert_converged(result, *, expected_runs):
    log, broker, repo = result.log, result.broker, result.repo
    assert len(result.runs) == expected_runs
    assert result.runs[-1].error is None                       # the last run ended cleanly
    assert all(run.error is not None for run in result.runs[:-1])    # every earlier run halted on its fault
    assert set(repo.rows) == unique_keys(log)                  # final persisted unique spans == unique input spans
    assert len(repo.rows) == len(set(repo.rows)) == len(unique_keys(log))    # no duplicate rows
    assert broker.violations == []                             # nothing committed past an unpersisted message
    assert broker.committed == len(log)                        # the recovery run reached the final committed offset
    assert broker.faults == []                                 # every injected fault actually fired
    starts, committed = [], None
    for run in result.runs:                                    # every run began at the offset committed before it
        starts.append(run.start)
        assert run.start == (0 if committed is None else committed)
        committed = run.committed_after if run.committed_after is not None else committed
    for run in result.runs[:-1]:                               # a faulted run halted: no poll after its fault
        fault_index = next(i for i, e in enumerate(run.events) if e[0] == "fault")
        assert not [e for e in run.events[fault_index:] if e[0] == "poll"]


# ---------------------------------------------------------------------------
# Expected state after the first (faulted) run, derived from the contract, not from the code
# ---------------------------------------------------------------------------

def expected_default(kind, k):
    """(committed offset after the faulted run, replayed offset that must hit the unique constraint or None)."""
    return {
        "db_insert_error": (k, None),
        "db_txn_commit_error": (k, None),
        "interrupt_during_db_transaction": (k, None),
        "db_commit_ack_lost": (k, k),                  # the row is there, so the replay of k is a conflict
        "kafka_commit_error": (k, k),                  # persisted k, commit k+1 failed, so k is replayed
        "interrupt_before_kafka_commit": (k, k),
        "kafka_commit_ack_lost": (k + 1, None),        # the broker applied it: no replay
    }[kind]


def expected_batched(kind, k):
    """Batched mode, BATCH=3, 7 messages: commit calls 0, 1, 2 carry offsets 3, 6, 7.  For a database fault
    k is the message offset; for a commit fault k is the commit call."""
    boundaries = [3, 6, 7]
    if kind in DB_FAULTS:
        done = max([b for b in (3, 6) if b <= k], default=None)        # batches already committed
        if kind == "interrupt_during_db_transaction":
            return (done, None)                         # killed: no final flush
        return (k if k > 0 else None, k if kind == "db_commit_ack_lost" else None)   # the final flush commits the persisted rest
    before = None if k == 0 else boundaries[k - 1]
    target = boundaries[k]
    if kind == "kafka_commit_ack_lost":
        return (target, None)
    return (before, None)


# ===========================================================================
# Default loop: one fault at every step of every message
# ===========================================================================

LOGS = {"plain": build_log(N), "duplicate": build_log(N, {3: 1})}     # in "duplicate", offset 3 repeats offset 1's span


class TestSingleFaultConvergence:
    @pytest.mark.parametrize("log_name", sorted(LOGS))
    @pytest.mark.parametrize("kind", DB_FAULTS)
    @pytest.mark.parametrize("offset", range(N))
    def test_a_database_fault_halts_and_the_restart_converges(self, kind, offset, log_name):
        log = LOGS[log_name]
        result = supervise(log, [(kind, offset)])
        assert_converged(result, expected_runs=2)
        first, second = result.runs
        committed, replayed = expected_default(kind, offset)
        assert first.committed_after == (committed if committed > 0 else None)
        assert second.start == committed
        if replayed is not None and log_name == "plain":
            assert second.conflicts == {replayed}                 # the replay hit the unique constraint
        assert first.closed == (0 if isinstance(first.error, SimulatedInterruption) else 1)

    @pytest.mark.parametrize("log_name", sorted(LOGS))
    @pytest.mark.parametrize("kind", COMMIT_FAULTS)
    @pytest.mark.parametrize("call", range(N))
    def test_an_offset_commit_fault_halts_and_the_restart_converges(self, kind, call, log_name):
        log = LOGS[log_name]
        result = supervise(log, [(kind, call)])
        assert_converged(result, expected_runs=2)
        first, second = result.runs
        committed, replayed = expected_default(kind, call)
        assert first.committed_after == (committed if committed > 0 else None)
        assert second.start == committed
        if replayed is not None and log_name == "plain":
            assert second.conflicts == {replayed}
        assert first.polled[-1] == call                           # the fault came on the message it was injected for

    def test_a_clean_run_needs_no_restart_and_commits_every_offset_in_order(self):
        result = supervise(LOGS["plain"])
        assert_converged(result, expected_runs=1)
        assert [e[2] for e in result.runs[0].events if e[0] == "commit"] == list(range(1, N + 1))
        assert result.runs[0].inserted_new == set(range(N)) and result.runs[0].conflicts == set()


class TestFaultSemantics:
    """The most important schedules, spelled out."""

    def test_a_failed_insert_leaves_the_message_uncommitted_and_it_is_persisted_after_the_restart(self):
        result = supervise(LOGS["plain"], [("db_insert_error", 2)])
        first, second = result.runs
        assert isinstance(first.error, RuntimeError) and first.polled == [0, 1, 2]
        assert first.inserted_new == {0, 1} and first.committed_after == 2
        assert second.start == 2 and second.inserted_new == {2, 3, 4} and second.conflicts == set()

    def test_a_failed_transaction_commit_persists_nothing_and_the_message_is_retried(self):
        result = supervise(LOGS["plain"], [("db_txn_commit_error", 2)])
        first, second = result.runs
        assert first.inserted_new == {0, 1} and (TRACE, f"{2:016x}") not in set(result.repo.rows[:2])
        assert second.start == 2 and 2 in second.inserted_new and second.conflicts == set()

    def test_a_commit_failure_after_persistence_replays_the_message_as_a_conflict(self):
        result = supervise(LOGS["plain"], [("kafka_commit_error", 2)])
        first, second = result.runs
        assert first.inserted_new == {0, 1, 2} and first.committed_after == 2     # persisted 2, but the commit of 3 failed
        assert second.start == 2 and second.conflicts == {2} and second.inserted_new == {3, 4}
        assert len(result.repo.rows) == N                                         # no duplicate row

    def test_an_interruption_between_persistence_and_the_offset_commit_replays_idempotently(self):
        result = supervise(LOGS["plain"], [("interrupt_before_kafka_commit", 2)])
        first, second = result.runs
        assert isinstance(first.error, SimulatedInterruption)
        assert first.inserted_new == {0, 1, 2} and first.committed_after == 2
        assert first.closed == 0                                                  # the interrupted run closed nothing
        assert second.start == 2 and second.conflicts == {2} and second.inserted_new == {3, 4}

    def test_an_interruption_inside_the_database_transaction_persists_nothing_for_that_message(self):
        result = supervise(LOGS["plain"], [("interrupt_during_db_transaction", 3)])
        first, second = result.runs
        assert first.inserted_new == {0, 1, 2} and first.committed_after == 3
        assert second.start == 3 and second.conflicts == set() and second.inserted_new == {3, 4}

    def test_a_lost_database_acknowledgement_means_persisted_but_uncommitted_then_a_conflict(self):
        result = supervise(LOGS["plain"], [("db_commit_ack_lost", 1)])
        first, second = result.runs
        assert (TRACE, f"{1:016x}") in set(result.repo.rows) and first.committed_after == 1
        assert second.start == 1 and second.conflicts == {1}

    def test_a_lost_commit_reply_halts_the_run_even_though_the_broker_applied_the_commit(self):
        result = supervise(LOGS["plain"], [("kafka_commit_ack_lost", 1)])
        first, second = result.runs
        assert isinstance(first.error, RuntimeError) and first.committed_after == 2   # applied
        assert second.start == 2 and second.conflicts == set() and second.inserted_new == {2, 3, 4}

    def test_a_replayed_span_in_the_log_is_a_conflict_that_still_advances_the_offset(self):
        result = supervise(LOGS["duplicate"])
        assert_converged(result, expected_runs=1)
        assert result.runs[0].conflicts == {3} and result.runs[0].inserted_new == {0, 1, 2, 4}
        assert len(result.repo.rows) == N - 1 and result.broker.committed == N

    def test_two_faults_in_a_row_still_converge(self):
        result = supervise(LOGS["plain"], [("db_insert_error", 1), ("kafka_commit_error", 3)])
        assert_converged(result, expected_runs=3)
        assert [run.start for run in result.runs] == [0, 1, 3]
        assert result.runs[2].conflicts == {3}

    def test_the_same_message_failing_twice_is_retried_until_it_succeeds(self):
        result = supervise(LOGS["plain"], [("db_insert_error", 2), ("db_txn_commit_error", 2)])
        assert_converged(result, expected_runs=3)
        assert [run.start for run in result.runs] == [0, 2, 2]

    def test_a_halted_run_closes_its_consumer_without_committing(self):
        result = supervise(LOGS["plain"], [("db_insert_error", 2)])
        assert result.runs[0].closed == 1 and not [e for e in result.runs[0].events if e[0] == "commit" and e[2] > 2]


# ===========================================================================
# Batched mode: the real OffsetBatcher, batches of 3 over 7 messages
# ===========================================================================

LOG_BATCHED = build_log(N_BATCHED)


class TestBatchedConvergence:
    def test_a_clean_batched_run_commits_in_batches_and_flushes_the_rest_at_the_end(self):
        result = supervise(LOG_BATCHED, batch=BATCH)
        assert_converged(result, expected_runs=1)
        assert [e[2] for e in result.runs[0].events if e[0] == "commit"] == [3, 6, 7]

    @pytest.mark.parametrize("kind", DB_FAULTS)
    @pytest.mark.parametrize("offset", range(N_BATCHED))
    def test_a_database_fault_in_a_batch_halts_and_the_restart_converges(self, kind, offset):
        result = supervise(LOG_BATCHED, [(kind, offset)], batch=BATCH)
        assert_converged(result, expected_runs=2)
        first, second = result.runs
        committed, replayed = expected_batched(kind, offset)
        assert first.committed_after == committed
        assert second.start == (committed or 0)
        if replayed is not None:
            assert replayed in second.conflicts

    @pytest.mark.parametrize("kind", COMMIT_FAULTS)
    @pytest.mark.parametrize("call", range(3))
    def test_a_batch_commit_fault_halts_and_the_restart_converges(self, kind, call):
        result = supervise(LOG_BATCHED, [(kind, call)], batch=BATCH)
        assert_converged(result, expected_runs=2)
        first, second = result.runs
        committed, _ = expected_batched(kind, call)
        assert first.committed_after == committed
        assert second.start == (committed or 0)

    def test_an_interruption_before_the_first_batch_commit_replays_the_whole_batch_as_conflicts(self):
        result = supervise(LOG_BATCHED, [("interrupt_before_kafka_commit", 0)], batch=BATCH)
        first, second = result.runs
        assert first.inserted_new == {0, 1, 2} and first.committed_after is None      # persisted, never committed
        assert second.start == 0 and second.conflicts == {0, 1, 2}
        assert result.broker.committed == N_BATCHED and len(result.repo.rows) == N_BATCHED

    def test_a_database_failure_mid_batch_commits_the_persisted_messages_in_the_final_flush(self):
        # offsets 0-2 are committed with the first batch; 3 is persisted; 4 fails.  The loop's final flush
        # commits 3 (persisted) and never 4.
        result = supervise(LOG_BATCHED, [("db_insert_error", 4)], batch=BATCH)
        first, second = result.runs
        assert first.inserted_new == {0, 1, 2, 3} and first.committed_after == 4
        assert [e[2] for e in first.events if e[0] == "commit"] == [3, 4]
        assert second.start == 4 and second.conflicts == set()

    def test_a_failed_batch_commit_is_not_retried_and_nothing_further_is_committed(self):
        result = supervise(LOG_BATCHED, [("kafka_commit_error", 1)], batch=BATCH)
        first, _ = result.runs
        assert first.committed_after == 3                                             # the second batch (6) failed
        assert [e[2] for e in first.events if e[0] == "commit"] == [3]
        assert first.polled[-1] == 5                                                  # halted on that message's flush

    def test_two_faults_in_batched_mode_still_converge(self):
        # run 1: offset 1 fails, and the loop's final flush commits offset 1 (commit call 0).  Run 2 starts at 1
        # and is interrupted before its first batch commit (call 1), so run 3 starts at 1 again.
        result = supervise(LOG_BATCHED, [("db_insert_error", 1), ("interrupt_before_kafka_commit", 1)], batch=BATCH)
        assert_converged(result, expected_runs=3)
        assert [run.start for run in result.runs] == [0, 1, 1]
        assert result.runs[2].conflicts == {1, 2, 3}

    def test_a_commit_fault_can_hit_the_final_flush_of_a_run_that_already_halted(self):
        # the commit-call index counts every commit, including the best-effort flush after a failure: here
        # that flush is interrupted, so nothing is committed and the restart replays the persisted message
        result = supervise(LOG_BATCHED, [("db_insert_error", 1), ("interrupt_before_kafka_commit", 0)], batch=BATCH)
        assert_converged(result, expected_runs=2)
        first, second = result.runs
        assert isinstance(first.error, SimulatedInterruption) and first.committed_after is None
        assert second.start == 0 and second.conflicts == {0}


# ===========================================================================
# The fakes and the invariant checker must not be vacuous
# ===========================================================================

class TestTheHarnessItself:
    def test_a_new_consumer_starts_at_the_last_committed_offset_not_at_zero(self):
        broker = FakeBroker(LOGS["plain"])
        FakeRepository(broker)
        broker.committed = 3
        assert FakeConsumer(broker, broker.start_run(), threading.Event()).start == 3

    def test_a_fault_fires_exactly_once(self):
        broker = FakeBroker(LOGS["plain"], [("db_insert_error", 1)])
        assert broker.take(DB_FAULTS, 1) == "db_insert_error" and broker.take(DB_FAULTS, 1) is None

    def test_an_interrupted_run_can_no_longer_change_anything(self):
        broker = FakeBroker(LOGS["plain"], [("interrupt_before_kafka_commit", 0)])
        repo = FakeRepository(broker)
        run = broker.start_run()
        consumer = FakeConsumer(broker, run, threading.Event())
        msg = consumer.poll()
        process_message(msg, repo)
        with pytest.raises(SimulatedInterruption):
            consumer.commit(message=msg, asynchronous=False)
        with pytest.raises(SimulatedInterruption):
            consumer.commit(message=msg, asynchronous=False)          # the dead run's later calls have no effect
        with pytest.raises(SimulatedInterruption):
            repo.insert_span(None, TOPIC, 0, 1)
        consumer.close()
        assert broker.committed is None and consumer.closed == 0

    def test_the_repository_emulates_the_unique_constraint(self):
        broker = FakeBroker(build_log(2, {1: 0}))
        repo = FakeRepository(broker)
        run = broker.start_run()
        consumer = FakeConsumer(broker, run, threading.Event())
        assert repo.insert_span(_event(consumer.poll()), TOPIC, 0, 0) is True
        assert repo.insert_span(_event(consumer.poll()), TOPIC, 0, 1) is False
        assert len(repo.rows) == 1

    def test_the_checker_catches_a_loop_that_commits_before_persisting(self):
        # A deliberately WRONG loop (commit first, then persist), on the same fakes: with a failing
        # insert it commits past an unpersisted message, and the invariant check must flag it.
        broker = FakeBroker(LOGS["plain"], [("db_insert_error", 2)])
        repo = FakeRepository(broker)
        run = broker.start_run()
        consumer = FakeConsumer(broker, run, threading.Event())
        with pytest.raises(RuntimeError):
            while True:
                msg = consumer.poll()
                consumer.commit(message=msg, asynchronous=False)       # wrong order
                process_message(msg, repo)
        assert broker.violations and "not persisted" in broker.violations[0]

    def test_the_checker_catches_an_offset_that_moves_backwards(self):
        broker = FakeBroker(LOGS["plain"])
        repo = FakeRepository(broker)
        for index in range(3):
            repo.keys.add((TRACE, f"{index:016x}"))
        broker.committed = 3
        broker.check_commit(2)
        assert broker.violations == ["committed offset moved back from 3 to 2"]

    def test_supervise_refuses_to_report_success_when_a_fault_never_fired(self):
        result = supervise(LOGS["plain"], [("db_insert_error", 99)])
        with pytest.raises(AssertionError):
            assert_converged(result, expected_runs=1)                  # the fault is still pending

    def test_the_real_orchestration_functions_are_the_ones_under_test(self):
        import consumer as consumer_mod
        assert run_consumer_loop is consumer_mod.run_consumer_loop
        assert process_message is consumer_mod.process_message and OffsetBatcher is consumer_mod.OffsetBatcher


def _event(msg):
    from schemas.telemetry import CanonicalSpanEvent
    return CanonicalSpanEvent.model_validate(json.loads(msg.value()))


class TestUncoveredWindows:
    """Not covered here, on purpose (see the module docstring for what the covered cases prove):

      - a real operating-system kill (finally blocks would not run); live case C07b covers it
      - rebalances, lost ownership and several partitions or members; live cases C03-C06
      - the real Kafka client's commit semantics and the real PostgreSQL unique constraint
      - connection loss with no restart, and a restart policy: this consumer does not reconnect
      - a poison message (malformed JSON, tombstone, invalid event): it halts, and a supervisor would
        loop on the same offset, which is a design question, not something these tests settle
      - the time-based flush of the batched mode (the clock is frozen here), and signal handling
    """

    def test_the_list_of_uncovered_windows_is_documented(self):
        assert "real operating-system kill" in TestUncoveredWindows.__doc__

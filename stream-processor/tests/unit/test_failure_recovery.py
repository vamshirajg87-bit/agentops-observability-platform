"""
tests/unit/test_failure_recovery.py

Offline restart-convergence tests for the stream processor (Phase 14.5, second scenario).

The other unit tests prove, one fault at a time, that a failure leaves the source offset
uncommitted.  These tests add the next step: after a fault the loop halts, a supervisor starts it
again with a NEW consumer, publisher and deduplicator, the new consumer begins at the last
COMMITTED offset, and the run converges on the right final state.

What is real: processor.run_consumer_loop, processor.process_message, publisher.KafkaPublisher
(its retry, backoff, timeout and close logic), deduplicator.SpanDeduplicator, and the DLQEvent
model with build_dlq_event.
What is fake, and in memory only: the Kafka input log and its committed offset, the poll/commit
calls, the producer and its delivery reports, the broker log the producer writes to, and the
supervisor.  processor.decode and processor.canonicalize are replaced by table lookups (the same
approach test_processor.py takes), so demo-app is not needed.  No socket, no Docker, no Kafka,
no PostgreSQL, no process is touched.

Delivery acknowledgement and broker persistence are modelled SEPARATELY.  A message can be
persisted without the publisher ever seeing a delivery report (timeout_persisted), can be lost
(timeout_lost), or can reach the broker only later (timeout_late: it is delivered by the next
flush, which is the shutdown flush in publisher.close()).  The publisher cannot tell these apart,
and neither can the processor; the tests assert exactly that.

What this proves, and what it does not
  - It proves that the Python orchestration contracts converge under injected faults: the set of
    distinct trusted spans and DLQ events on the output side equals what the input log requires,
    no offset is committed before its required publications were positively acknowledged, a
    faulted run halts, and the restart begins at the committed offset.
  - It does NOT prove exactly-once delivery.  Replays DO produce duplicate trusted spans and
    duplicate DLQ events; the tests count them and bound them.  The in-memory deduplicator
    suppresses duplicates only inside one process, and not at all for DLQ events.
  - It does NOT prove Kafka behaviour.  Whether a real broker can report a retriable error after
    persisting a record (error_retriable_persisted) is an ASSUMPTION modelled as a variant, and
    committing message N is modelled as committing N+1 (the usual client semantics).
  - A "simulated interruption" is NOT an operating-system process kill.  The fake raises a
    BaseException at the chosen point and treats the producer as dead afterwards (queued records
    are discarded).  Python's finally blocks still run in the test process, which a real kill
    would not do.
  - The restart supervisor is a test construct; the repository has none.

Run from the stream-processor directory (kept separate from the storage-consumer tests):
    python -m pytest tests/unit/test_failure_recovery.py
"""

from __future__ import annotations

import json
import random
import sys
import threading
from collections import Counter, defaultdict

from unittest.mock import MagicMock

import pytest

import config
import processor as proc
from canonicalizer import CanonicalizationError, CanonicalizationErrorType
from deduplicator import SpanDeduplicator
from otlp_decoder import OTLPDecodeError
from processor import run_consumer_loop
from publisher import (
    KafkaPublisher,
    PublishBrokerError,
    PublishSerializationError,
    PublishTimeoutError,
)

SOURCE_TOPIC = "agentops.telemetry.otlp.traces"
TRACE = "aa" * 16
RETRIES = 3

PRODUCE_FAULTS = frozenset({
    "buffer_error", "error_nonretriable", "error_retriable", "error_retriable_persisted",
    "timeout_persisted", "timeout_lost", "timeout_late",
    "interrupt_in_produce", "interrupt_after_persist",
})
COMMIT_FAULTS = frozenset({"commit_error", "commit_ack_lost", "interrupt_before_commit"})
POLL_FAULTS = frozenset({"consumer_error"})
FLUSH_FAULTS = frozenset({"flush_remaining"})

# Fault kinds that end the run in which they fire (the loop must halt at once).
TERMINAL = frozenset({
    "error_nonretriable", "timeout_persisted", "timeout_lost", "timeout_late",
    "interrupt_in_produce", "interrupt_after_persist",
    "commit_error", "commit_ack_lost", "interrupt_before_commit",
    "consumer_error", "serialization_error",
})
# Kinds the publisher's retry loop absorbs when retries remain.
ABSORBED = frozenset({"buffer_error", "error_retriable", "error_retriable_persisted"})

SWEEP_KINDS = sorted(PRODUCE_FAULTS | COMMIT_FAULTS | POLL_FAULTS)
SITE_OF = {**{k: "produce" for k in PRODUCE_FAULTS}, **{k: "commit" for k in COMMIT_FAULTS},
           **{k: "poll" for k in POLL_FAULTS}, **{k: "flush" for k in FLUSH_FAULTS}}


# ---------------------------------------------------------------------------
# Input log: records, with expectations derived from the records alone
# ---------------------------------------------------------------------------

def S(i, *, bad=False, unserializable=False):
    """A decoded span dict.  bad: canonicalization rejects it.  unserializable: model_dump fails."""
    return {"trace_id": TRACE, "span_id": f"{i:016x}", "service_name": "svc",
            "bad": bad, "unserializable": unserializable}


def MSG(*spans):
    return {"kind": "spans", "spans": list(spans)}


DECODE_FAIL = {"kind": "decode_fail"}
NONE_VALUE = {"kind": "none"}


def key(i):
    return (TRACE, f"{i:016x}")


def requirements(record, offset):
    """(trusted keys, DLQ coordinates) that must be positively acknowledged before this record's
    offset may be committed.  Derived from the record only."""
    trusted, dlq = set(), set()
    if record["kind"] in ("decode_fail", "none"):
        dlq.add((offset, None, None, "OTLP_DECODE_FAILURE"))
    else:
        for span in record["spans"]:
            if span["bad"]:
                dlq.add((offset, span["trace_id"], span["span_id"], "SCHEMA_VALIDATION_FAILURE"))
            else:
                trusted.add((span["trace_id"], span["span_id"]))
    return trusted, dlq


def expected_trusted(log):
    return set().union(*(requirements(r, o)[0] for o, r in enumerate(log)))


def expected_dlq(log):
    return set().union(*(requirements(r, o)[1] for o, r in enumerate(log)))


def all_span_keys(log):
    return {(s["trace_id"], s["span_id"]) for r in log if r["kind"] == "spans" for s in r["spans"]}


PLAIN = [MSG(S(i)) for i in range(5)]
MULTI_SPAN = [MSG(S(0), S(1), S(2)), MSG(S(3)), MSG(S(4), S(5)), MSG(S(6), S(7), S(8)), MSG(S(9))]
# produce order without faults: S0, DLQ(1), DLQ(2), DLQ(3,S3), S4, S5, DLQ(4,S6), S7
DLQ_MIX = [MSG(S(0)), DECODE_FAIL, NONE_VALUE, MSG(S(3, bad=True), S(4)),
           MSG(S(5), S(6, bad=True), S(7))]
CROSS_DUPLICATES = [MSG(S(0)), MSG(S(1)), MSG(S(0)), MSG(S(2), S(1)), MSG(S(0))]
LOGS = {"plain": PLAIN, "multi_span": MULTI_SPAN, "dlq_mix": DLQ_MIX,
        "cross_duplicates": CROSS_DUPLICATES}


def F(kind, at, run=1):
    return (kind, run, at)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class SimulatedInterruption(BaseException):
    """The process 'stopped' here.  Not an OS kill; see the module docstring."""


class CommitFailure(Exception):
    pass


class FakeKafkaError:
    def __init__(self, retriable):
        self._retriable = retriable

    def retriable(self):
        return self._retriable

    def __str__(self):
        return "fake kafka error (retriable)" if self._retriable else "fake kafka error (fatal)"


class FakeMsg:
    def __init__(self, offset, value, error=None):
        self._offset, self._value, self._error = offset, value, error

    def value(self):
        return self._value

    def topic(self):
        return SOURCE_TOPIC

    def partition(self):
        return 0

    def offset(self):
        return self._offset

    def error(self):
        return self._error


class FakeEvent:
    """Stands in for CanonicalSpanEvent: only what the publisher and processor touch."""

    def __init__(self, world, span):
        self.world = world
        self.trace_id = span["trace_id"]
        self.span_id = span["span_id"]
        self.unserializable = span["unserializable"]

    def model_dump(self, mode="json"):
        if self.unserializable:
            self.world.fire("serialization_error")
            raise ValueError("cannot serialize this span")
        return {"trace_id": self.trace_id, "span_id": self.span_id}


class World:
    """The in-memory universe: input log, committed offset, output broker log, fault schedule,
    event trace, and everything the checkers need.  One World spans all restarts."""

    def __init__(self, log, faults):
        self.log = list(log)
        self.faults = [{"kind": k, "run": r, "at": a, "used": False} for k, r, a in faults]
        self.run = 0
        self.committed = 0
        self.committed_end = {}
        self.events = []
        self.problems = []               # violations observed live, at the moment they happen
        self.sleeps = []
        self.counters = defaultdict(int)
        self.persisted_trusted = []      # (run, key)  -- present on the broker, acked or not
        self.persisted_dlq = []          # (run, coordinate)
        self.acked_trusted = set()       # positive delivery reports ever seen
        self.acked_dlq = set()
        self.acked_in_run = defaultdict(set)
        self.fired = []                  # (run, kind)

    # -- schedule ----------------------------------------------------------------
    def tick(self, site):
        idx = self.counters[(self.run, site)]
        self.counters[(self.run, site)] += 1
        return idx

    def take(self, kinds, index):
        for f in self.faults:
            if (not f["used"] and f["run"] == self.run and f["at"] == index
                    and f["kind"] in kinds):
                f["used"] = True
                return f["kind"]
        return None

    def fire(self, kind):
        self.fired.append((self.run, kind))
        self.events.append(("fire", self.run, kind))

    # -- patched pipeline stages -------------------------------------------------
    def message(self, offset):
        record = self.log[offset]
        return FakeMsg(offset, None if record["kind"] == "none" else f"rec-{offset}".encode())

    def decode(self, payload):
        record = self.log[int(payload.split(b"-")[1])]
        if record["kind"] == "decode_fail":
            raise OTLPDecodeError("payload is not a valid OTLP request")
        return [dict(s) for s in record["spans"]]

    def canonicalize(self, span):
        if span["bad"]:
            raise CanonicalizationError(
                CanonicalizationErrorType.SCHEMA_VALIDATION_FAILURE, "span rejected")
        return FakeEvent(self, span)

    # -- bookkeeping -------------------------------------------------------------
    @staticmethod
    def identify(topic, value):
        body = json.loads(value)
        if topic == config.TOPIC_DLQ:
            return (body["source_offset"], body["trace_id"], body["span_id"], body["reason"])
        return (body["trace_id"], body["span_id"])

    def persist(self, entry):
        ident = self.identify(entry["topic"], entry["value"])
        if entry["topic"] == config.TOPIC_DLQ:
            self.persisted_dlq.append((self.run, ident))
        else:
            self.persisted_trusted.append((self.run, ident))
        self.events.append(("persist", self.run, entry["topic"], ident))

    def ack(self, entry):
        entry["cb"](None, None)
        ident = self.identify(entry["topic"], entry["value"])
        if entry["topic"] == config.TOPIC_DLQ:
            self.acked_dlq.add(ident)
        else:
            self.acked_trusted.add(ident)
            self.acked_in_run[self.run].add(ident)

    def check_commit(self, message, asynchronous):
        if asynchronous is not False:
            self.problems.append(f"run {self.run}: commit is not synchronous ({asynchronous!r})")
        if message is None:
            self.problems.append(f"run {self.run}: commit without an explicit message")
            return
        offset = message.offset()
        trusted, dlq = requirements(self.log[offset], offset)
        missing_t = sorted(trusted - self.acked_trusted)
        missing_d = sorted(dlq - self.acked_dlq, key=repr)
        if missing_t or missing_d:
            self.problems.append(
                f"run {self.run}: commit past unacked publications at offset {offset}: "
                f"trusted={missing_t} dlq={missing_d}")


class FakeProducer:
    """confluent_kafka.Producer stand-in: produce / poll / flush with a delivery queue."""

    def __init__(self, world):
        self.world = world
        self.queue = []
        self.dead = False

    def produce(self, topic, key=None, value=None, on_delivery=None):
        w = self.world
        idx = w.tick("produce")
        w.events.append(("produce", w.run, idx, topic, w.identify(topic, value)))
        kind = w.take(PRODUCE_FAULTS, idx)
        if kind == "buffer_error":
            w.fire(kind)
            raise BufferError("local queue full")
        if kind == "interrupt_in_produce":
            w.fire(kind)
            self.dead = True
            raise SimulatedInterruption()
        self.queue.append({"topic": topic, "key": key, "value": value, "cb": on_delivery,
                           "mode": kind or "ok", "deferred": False})

    def poll(self, timeout=0):
        return 0

    def flush(self, timeout=None):
        w = self.world
        idx = w.tick("flush")
        w.events.append(("flush", w.run, idx))
        if self.dead:
            self.queue.clear()
            return 0
        remaining = 0
        for entry in list(self.queue):
            mode = entry["mode"]
            if mode == "ok":
                w.persist(entry)
                w.ack(entry)
                self.queue.remove(entry)
            elif mode in ("error_nonretriable", "error_retriable", "error_retriable_persisted"):
                w.fire(mode)
                if mode == "error_retriable_persisted":
                    w.persist(entry)
                entry["cb"](FakeKafkaError(mode != "error_nonretriable"), None)
                self.queue.remove(entry)
            elif mode == "timeout_persisted":
                w.fire(mode)
                w.persist(entry)
                self.queue.remove(entry)
                remaining += 1
            elif mode == "timeout_lost":
                w.fire(mode)
                self.queue.remove(entry)
                remaining += 1
            elif mode == "timeout_late":
                if entry["deferred"]:
                    w.persist(entry)
                    w.ack(entry)
                    self.queue.remove(entry)
                else:
                    w.fire(mode)
                    entry["deferred"] = True
                    remaining += 1
            elif mode == "interrupt_after_persist":
                w.persist(entry)
                w.fire(mode)
                self.dead = True
                self.queue.clear()
                raise SimulatedInterruption()
        if w.take(FLUSH_FAULTS, idx):
            w.fire("flush_remaining")
            remaining += 1
        return remaining


class FakeConsumer:
    """Starts at the last committed offset; ends the loop when the log is exhausted."""

    def __init__(self, world, shutdown):
        self.world = world
        self.shutdown = shutdown
        self.position = world.committed
        self.closed = False

    def poll(self, timeout=None):
        w = self.world
        idx = w.tick("poll")
        if w.take(POLL_FAULTS, idx):
            w.events.append(("poll", w.run, idx, None))
            w.fire("consumer_error")
            return FakeMsg(None, None, error="broker transport failure")
        if self.position >= len(w.log):
            w.events.append(("poll", w.run, idx, None))
            self.shutdown.set()
            return None
        msg = w.message(self.position)
        self.position += 1
        w.events.append(("poll", w.run, idx, msg.offset()))
        return msg

    def commit(self, message=None, asynchronous=True):
        w = self.world
        idx = w.tick("commit")
        w.check_commit(message, asynchronous)
        w.events.append(("commit", w.run, message.offset() if message else None))
        kind = w.take(COMMIT_FAULTS, idx)
        if kind == "commit_error":
            w.fire(kind)
            raise CommitFailure("commit failed")
        if kind == "interrupt_before_commit":
            w.fire(kind)
            raise SimulatedInterruption()
        w.committed = message.offset() + 1
        w.events.append(("committed", w.run, w.committed))
        if kind == "commit_ack_lost":
            w.fire(kind)
            raise CommitFailure("commit acknowledgement lost")

    def close(self):
        self.closed = True
        self.world.events.append(("consumer_close", self.world.run))


# ---------------------------------------------------------------------------
# Restart supervisor
# ---------------------------------------------------------------------------

class Run:
    def __init__(self, number, world, dedup_size, retries):
        self.number = number
        self.shutdown = threading.Event()
        self.dedup = SpanDeduplicator(max_size=dedup_size)
        self.producer = FakeProducer(world)
        self.publisher = KafkaPublisher(
            self.producer, retries=retries, timeout_seconds=1.0, _sleep=world.sleeps.append)
        self.consumer = FakeConsumer(world, self.shutdown)
        self.exc = None
        self.marked_at_start = {k for k in all_span_keys(world.log) if self.dedup.contains(*k)}


class Outcome:
    def __init__(self, world, runs):
        self.world, self.runs = world, runs


def install(world, monkeypatch):
    monkeypatch.setattr(proc, "decode", world.decode)
    monkeypatch.setattr(proc, "canonicalize", world.canonicalize)


def run_scenario(monkeypatch, log, faults=(), *, retries=RETRIES, loop=None, max_runs=8,
                 dedup_size=1000):
    """Run the loop under a fresh stack until it finishes cleanly (or max_runs is reached)."""
    world = World(log, faults)
    install(world, monkeypatch)
    loop = loop or run_consumer_loop
    runs = []
    while True:
        world.run += 1
        world.events.append(("start", world.run, world.committed))
        run = Run(world.run, world, dedup_size, retries)
        runs.append(run)
        try:
            loop(run.consumer, run.publisher, run.dedup, run.shutdown, poll_timeout_seconds=0.0)
        except (Exception, SimulatedInterruption) as exc:
            run.exc = exc
        world.committed_end[world.run] = world.committed
        if run.exc is None or len(runs) >= max_runs:
            return Outcome(world, runs)


def make_stack(monkeypatch, log, faults=(), retries=RETRIES, dedup_size=1000):
    """One run's stack for tests that drive process_message directly (same-process replay)."""
    world = World(log, faults)
    install(world, monkeypatch)
    world.run = 1
    run = Run(1, world, dedup_size, retries)
    return world, run


@pytest.fixture
def run(monkeypatch):
    def _run(log, faults=(), **kwargs):
        return run_scenario(monkeypatch, log, faults, **kwargs)
    return _run


# ---------------------------------------------------------------------------
# Observations and invariant checkers
# ---------------------------------------------------------------------------

def copies(o):
    return Counter(k for _, k in o.world.persisted_trusted)


def dlq_copies(o):
    return Counter(c for _, c in o.world.persisted_dlq)


def produce_calls(o, ident, run_number=None):
    return sum(1 for e in o.world.events if e[0] == "produce" and e[4] == ident
               and (run_number is None or e[1] == run_number))


def polled_offsets(o, run_number):
    return [e[3] for e in o.world.events
            if e[0] == "poll" and e[1] == run_number and e[3] is not None]


def marked(run, indexes=range(5)):
    return [run.dedup.contains(*key(i)) for i in indexes]


def live_problems(o):
    """Invariants that must hold at every step, converged or not."""
    w = o.world
    problems = list(w.problems)
    # a terminal fault halts the run: nothing is polled, produced or committed afterwards
    for run in o.runs:
        halted = False
        for e in w.events:
            if e[1] != run.number:
                continue
            if e[0] == "fire" and e[2] in TERMINAL:
                halted = True
            elif halted and e[0] in ("poll", "produce", "commit"):
                problems.append(f"run {run.number}: {e[0]} after a terminal fault")
        if not run.consumer.closed:
            problems.append(f"run {run.number}: consumer was not closed")
    # failed publications are never marked in the deduplicator
    for run in o.runs:
        for k in all_span_keys(w.log):
            if run.dedup.contains(*k) and k not in w.acked_in_run[run.number]:
                problems.append(f"run {run.number}: {k[1]} marked in dedup without a positive ack")
    # restart resumes from the last committed offset, derived from the event history alone
    committed = 0
    for run in o.runs:
        offsets = polled_offsets(o, run.number)
        if offsets and offsets[0] != committed:
            problems.append(
                f"run {run.number}: first polled offset {offsets[0]} != committed {committed}")
        for e in w.events:
            if e[0] == "committed" and e[1] == run.number:
                committed = e[2]
    return problems


def convergence_problems(o, allow_cache_misses=False):
    w = o.world
    problems = []
    if o.runs[-1].exc is not None:
        problems.append(f"did not converge: last run raised {o.runs[-1].exc!r}")
    if w.committed != len(w.log):
        problems.append(f"final committed offset {w.committed} != {len(w.log)}")
    got = {k for _, k in w.persisted_trusted}
    for name, want, have in (("trusted", expected_trusted(w.log), got),
                             ("dlq", expected_dlq(w.log), {c for _, c in w.persisted_dlq})):
        if want - have:
            problems.append(f"missing {name}: {sorted(want - have, key=repr)}")
        if have - want:
            problems.append(f"unexpected {name}: {sorted(have - want, key=repr)}")
    if not allow_cache_misses:
        persisted_retries = Counter(r for r, kind in w.fired if kind == "error_retriable_persisted")
        total_allowance = len(o.runs) + sum(persisted_retries.values())
        for label, counter in (("trusted", copies(o)), ("dlq", dlq_copies(o))):
            for ident, n in counter.items():
                if n > total_allowance:
                    problems.append(f"{label} {ident} published {n}x > bound {total_allowance}")
        per_run = Counter()
        for label, items in (("trusted", w.persisted_trusted), ("dlq", w.persisted_dlq)):
            for r, ident in items:
                per_run[(label, r, ident)] += 1
        for (label, r, ident), n in per_run.items():
            if n > 1 + persisted_retries[r]:
                problems.append(f"run {r}: {label} {ident} published {n}x inside one process")
    return problems


def assert_converged(o, allow_cache_misses=False):
    problems = live_problems(o) + convergence_problems(o, allow_cache_misses)
    assert not problems, "\n".join(problems)


# ---------------------------------------------------------------------------
# Single-fault sweep
# ---------------------------------------------------------------------------

EXPECTED_EXCEPTION = {
    "error_nonretriable": PublishBrokerError, "timeout_persisted": PublishTimeoutError,
    "timeout_lost": PublishTimeoutError, "timeout_late": PublishTimeoutError,
    "interrupt_in_produce": SimulatedInterruption, "interrupt_after_persist": SimulatedInterruption,
    "commit_error": CommitFailure, "commit_ack_lost": CommitFailure,
    "interrupt_before_commit": SimulatedInterruption, "consumer_error": RuntimeError,
}
AT_VALUES = (0, 1, 2, 4, 7, 12)


class TestSingleFaultConvergence:
    """Every fault kind, at several positions, on logs of different shapes."""

    @pytest.mark.parametrize("log_name", sorted(LOGS))
    @pytest.mark.parametrize("kind", SWEEP_KINDS)
    @pytest.mark.parametrize("at", AT_VALUES)
    def test_converges_after_one_fault(self, run, log_name, kind, at):
        log = LOGS[log_name]
        baseline = run(log)
        assert_converged(baseline)
        calls = baseline.world.counters[(1, SITE_OF[kind])]

        o = run(log, [F(kind, at)])

        fired = [k for r, k in o.world.fired if k == kind]
        assert bool(fired) == (at < calls), "the fault must fire exactly when the site is reached"
        assert_converged(o)
        if fired and kind in TERMINAL:
            assert len(o.runs) == 2
            assert type(o.runs[0].exc) is EXPECTED_EXCEPTION[kind]
        else:
            assert len(o.runs) == 1 and o.runs[0].exc is None


class TestSequentialFaults:
    def test_three_runs_each_hit_by_a_different_fault(self, run):
        # run1: S0 persisted but unacked (timeout).  run2: S0 acked, commit fails.
        # run3: S0 published again and committed, then the DLQ publish of offset 1 fails.
        o = run(DLQ_MIX, [F("timeout_persisted", 0, 1), F("commit_error", 0, 2),
                          F("error_nonretriable", 1, 3)])
        assert_converged(o)
        assert len(o.runs) == 4
        assert copies(o)[key(0)] == 3            # runs 1, 2 and 3 each put S0 on the broker
        assert [o.world.committed_end[n] for n in (1, 2, 3, 4)] == [0, 0, 1, 5]
        assert dlq_copies(o)[(1, None, None, "OTLP_DECODE_FAILURE")] == 1

    def test_ack_lost_then_consumer_error_then_interrupt_after_persist(self, run):
        o = run(PLAIN, [F("commit_ack_lost", 0, 1), F("consumer_error", 0, 2),
                        F("interrupt_after_persist", 1, 3)])
        assert_converged(o)
        assert len(o.runs) == 4
        assert [o.world.committed_end[n] for n in (1, 2, 3, 4)] == [1, 1, 2, 5]
        assert copies(o) == {key(0): 1, key(1): 1, key(2): 2, key(3): 1, key(4): 1}

    @pytest.mark.parametrize("log_name", ["multi_span", "dlq_mix"])
    @pytest.mark.parametrize("seed", range(50))
    def test_random_schedules_converge(self, run, log_name, seed):
        rng = random.Random(seed)
        faults = [F(rng.choice(SWEEP_KINDS), rng.randint(0, 6), rng.randint(1, 3))
                  for _ in range(rng.randint(2, 4))]
        o = run(LOGS[log_name], faults)
        assert_converged(o)
        assert len(o.runs) <= 1 + len([f for f in o.world.fired if f[1] in TERMINAL])


# ---------------------------------------------------------------------------
# Publisher semantics under the real processor
# ---------------------------------------------------------------------------

class TestPublishFailures:
    def test_nonretriable_failure_halts_without_retry_and_replays_from_the_failed_record(self, run):
        o = run(PLAIN, [F("error_nonretriable", 2)])
        r1, r2 = o.runs
        assert isinstance(r1.exc, PublishBrokerError) and "non-retriable" in str(r1.exc)
        assert o.world.committed_end[1] == 2
        assert marked(r1) == [True, True, False, False, False]
        assert o.world.sleeps == []
        assert polled_offsets(o, 1) == [0, 1, 2]           # the loop did not look at offset 3
        assert polled_offsets(o, 2)[0] == 2
        assert copies(o) == {key(i): 1 for i in range(5)}
        assert_converged(o)

    def test_retriable_failure_then_success_needs_no_restart(self, run):
        o = run(PLAIN, [F("error_retriable", 2)])
        assert len(o.runs) == 1 and o.runs[0].exc is None
        assert o.world.sleeps == [2]
        assert produce_calls(o, key(2)) == 2
        assert copies(o) == {key(i): 1 for i in range(5)}        # the failed attempt persisted nothing
        assert_converged(o)

    def test_retriable_error_after_broker_persisted_duplicates_without_a_restart(self, run):
        # Assumption modelled as a variant: the broker persisted the record and still reported
        # a retriable error.  The retry then publishes a second copy inside one process.
        o = run(PLAIN, [F("error_retriable_persisted", 2)])
        assert len(o.runs) == 1
        assert copies(o)[key(2)] == 2 and all(copies(o)[key(i)] == 1 for i in (0, 1, 3, 4))
        assert_converged(o)

    @pytest.mark.parametrize("retries", [0, 1, 3])
    def test_retry_exhaustion_halts_and_replay_converges(self, run, retries):
        faults = [F("error_retriable", 2 + n) for n in range(retries + 1)]
        o = run(PLAIN, faults, retries=retries)
        r1 = o.runs[0]
        assert isinstance(r1.exc, PublishBrokerError) and "retriable" in str(r1.exc)
        assert produce_calls(o, key(2), 1) == retries + 1
        assert o.world.sleeps == [2 ** a for a in range(1, retries + 1)]
        assert o.world.committed_end[1] == 2
        assert marked(r1)[2] is False
        assert len(o.runs) == 2
        assert copies(o)[key(2)] == 1
        assert_converged(o)

    @pytest.mark.parametrize("retries", [1, 3])
    def test_success_on_the_last_allowed_attempt_needs_no_restart(self, run, retries):
        faults = [F("error_retriable", 2 + n) for n in range(retries)]
        o = run(PLAIN, faults, retries=retries)
        assert len(o.runs) == 1 and o.runs[0].exc is None
        assert o.world.sleeps == [2 ** a for a in range(1, retries + 1)]
        assert produce_calls(o, key(2)) == retries + 1
        assert_converged(o)

    def test_buffer_error_is_retried(self, run):
        o = run(PLAIN, [F("buffer_error", 2)])
        assert len(o.runs) == 1 and o.world.sleeps == [2]
        assert produce_calls(o, key(2)) == 2
        assert copies(o) == {key(i): 1 for i in range(5)}
        assert_converged(o)

    def test_buffer_error_exhaustion_halts_and_replay_converges(self, run):
        o = run(PLAIN, [F("buffer_error", 2 + n) for n in range(RETRIES + 1)])
        assert isinstance(o.runs[0].exc, PublishBrokerError) and "queue full" in str(o.runs[0].exc)
        assert o.world.sleeps == [2, 4, 8]
        assert o.world.committed_end[1] == 2 and len(o.runs) == 2
        assert copies(o)[key(2)] == 1
        assert_converged(o)


class TestAmbiguousDeliveryTimeout:
    """A timeout proves nothing about whether the broker persisted the record."""

    EXPECTED_COPIES = {"timeout_persisted": 2, "timeout_lost": 1, "timeout_late": 2}

    @pytest.mark.parametrize("mode", sorted(EXPECTED_COPIES))
    def test_copies_on_the_broker_depend_on_what_the_broker_did(self, run, mode):
        o = run(PLAIN, [F(mode, 2)])
        r1 = o.runs[0]
        assert isinstance(r1.exc, PublishTimeoutError) and "ambiguous" in str(r1.exc)
        assert o.world.sleeps == []                          # a timeout is not retried
        assert produce_calls(o, key(2), 1) == 1              # and not re-produced
        # The publisher never saw an ack.  Only a late delivery is acked by the broker side, and
        # only during the shutdown flush, after the exception was already raised.
        assert (key(2) in o.world.acked_in_run[1]) == (mode == "timeout_late")
        assert marked(r1)[2] is False
        assert copies(o)[key(2)] == self.EXPECTED_COPIES[mode]
        assert all(copies(o)[key(i)] == 1 for i in (0, 1, 3, 4))
        assert o.world.committed_end[1] == 2
        assert_converged(o)

    def test_the_three_outcomes_look_identical_to_the_processor(self, run):
        def observable(mode):
            o = run(PLAIN, [F(mode, 2)])
            r1 = o.runs[0]
            return (type(r1.exc), str(r1.exc), o.world.committed_end[1], tuple(marked(r1)),
                    produce_calls(o, key(2), 1))
        views = {mode: observable(mode) for mode in self.EXPECTED_COPIES}
        assert views["timeout_persisted"] == views["timeout_lost"] == views["timeout_late"]

    def test_a_late_delivery_comes_from_the_shutdown_flush_and_does_not_mask_the_timeout(self, run):
        o = run(PLAIN, [F("timeout_late", 2)])
        assert type(o.runs[0].exc) is PublishTimeoutError
        assert (1, key(2)) in o.world.persisted_trusted     # persisted during run 1's cleanup


class TestKafkaCommitFailures:
    def test_commit_failure_after_a_successful_publish_replays_the_record(self, run):
        o = run(PLAIN, [F("commit_error", 2)])
        r1 = o.runs[0]
        assert isinstance(r1.exc, CommitFailure)
        assert marked(r1) == [True, True, True, False, False]       # span 2 was acked and marked
        assert o.world.committed_end[1] == 2
        assert polled_offsets(o, 2)[0] == 2
        assert copies(o) == {key(0): 1, key(1): 1, key(2): 2, key(3): 1, key(4): 1}
        assert_converged(o)

    def test_lost_commit_ack_advances_the_offset_and_does_not_replay(self, run):
        o = run(PLAIN, [F("commit_ack_lost", 2)])
        assert isinstance(o.runs[0].exc, CommitFailure)
        assert o.world.committed_end[1] == 3                # the broker did record the commit
        assert polled_offsets(o, 2)[0] == 3
        assert copies(o) == {key(i): 1 for i in range(5)}
        assert_converged(o)

    def test_interruption_before_the_commit_replays_the_record(self, run):
        o = run(PLAIN, [F("interrupt_before_commit", 2)])
        assert isinstance(o.runs[0].exc, SimulatedInterruption)
        assert o.world.committed_end[1] == 2
        assert copies(o)[key(2)] == 2
        assert_converged(o)


class TestMultiSpanPartialPublication:
    LOG = [MSG(S(0), S(1), S(2)), MSG(S(3))]

    def test_restart_republishes_the_whole_message_because_the_dedup_is_lost(self, run):
        o = run(self.LOG, [F("error_nonretriable", 2)])
        r1, r2 = o.runs
        assert marked(r1, range(4)) == [True, True, False, False]
        assert o.world.committed_end[1] == 0
        assert polled_offsets(o, 2)[0] == 0
        assert r2.marked_at_start == set()
        assert copies(o) == {key(0): 2, key(1): 2, key(2): 1, key(3): 1}
        assert_converged(o)

    def test_replay_inside_one_process_skips_the_spans_already_published(self, monkeypatch):
        world, run1 = make_stack(monkeypatch, self.LOG, [F("error_nonretriable", 2)])
        msg = world.message(0)
        with pytest.raises(PublishBrokerError):
            proc.process_message(msg, run1.publisher, run1.dedup, SOURCE_TOPIC, 0, 0)
        proc.process_message(msg, run1.publisher, run1.dedup, SOURCE_TOPIC, 0, 0)
        o = Outcome(world, [run1])
        assert copies(o) == {key(0): 1, key(1): 1, key(2): 1}
        assert produce_calls(o, key(0)) == 1


class TestDeduplication:
    def test_same_process_duplicates_across_messages_are_suppressed(self, run):
        o = run([MSG(S(0)), MSG(S(0))])
        assert copies(o) == {key(0): 1} and produce_calls(o, key(0)) == 1
        assert o.world.committed == 2
        assert_converged(o)

    def test_restart_with_an_empty_cache_republishes_but_later_duplicates_are_still_suppressed(self, run):
        o = run([MSG(S(0)), MSG(S(0)), MSG(S(1))], [F("commit_error", 0)])
        r1, r2 = o.runs
        assert r1.dedup.contains(*key(0)) and r2.marked_at_start == set()
        assert copies(o) == {key(0): 2, key(1): 1}
        assert produce_calls(o, key(0), 2) == 1               # the dup at offset 1 was skipped in run 2
        assert_converged(o)

    def test_a_bounded_cache_forgets_and_the_span_is_published_again(self, run):
        o = run([MSG(S(0)), MSG(S(1)), MSG(S(0))], dedup_size=1)
        assert copies(o) == {key(0): 2, key(1): 1}
        assert_converged(o, allow_cache_misses=True)

    def test_a_disabled_cache_never_suppresses(self, run):
        o = run([MSG(S(0)), MSG(S(0))], dedup_size=0)
        assert copies(o) == {key(0): 2}
        assert_converged(o, allow_cache_misses=True)


class TestDLQFailuresAndReplay:
    DECODE_DLQ = (1, None, None, "OTLP_DECODE_FAILURE")
    NONE_DLQ = (2, None, None, "OTLP_DECODE_FAILURE")
    BAD_DLQ = (3, TRACE, f"{3:016x}", "SCHEMA_VALIDATION_FAILURE")

    def test_dlq_publish_failure_blocks_the_commit_and_replays(self, run):
        o = run(DLQ_MIX, [F("error_nonretriable", 1)])        # DLQ for the undecodable record
        r1 = o.runs[0]
        assert isinstance(r1.exc, PublishBrokerError)
        assert o.world.committed_end[1] == 1
        assert not any(r == 1 for r, _ in o.world.persisted_dlq)
        assert dlq_copies(o) == {c: 1 for c in expected_dlq(DLQ_MIX)}
        assert_converged(o)

    def test_failed_dlq_for_a_bad_span_stops_the_good_span_behind_it(self, run):
        o = run(DLQ_MIX, [F("error_nonretriable", 3)])        # DLQ for the bad span of offset 3
        assert not any(r == 1 and k == key(4) for r, k in o.world.persisted_trusted)
        assert o.world.committed_end[1] == 3
        assert copies(o)[key(4)] == 1
        assert_converged(o)

    def test_replay_duplicates_the_dlq_event_after_a_later_span_failed(self, run):
        o = run(DLQ_MIX, [F("error_nonretriable", 4)])        # S4 fails after DLQ(3) was acked
        assert dlq_copies(o)[self.BAD_DLQ] == 2
        assert copies(o)[key(4)] == 1
        assert o.world.committed_end[1] == 3
        assert_converged(o)

    def test_dlq_events_are_not_deduplicated_even_inside_one_process(self, monkeypatch):
        # produce calls here start at 0: DLQ(3) is call 0, S4 is call 1
        world, run1 = make_stack(monkeypatch, DLQ_MIX, [F("error_nonretriable", 1)])
        msg = world.message(3)
        with pytest.raises(PublishBrokerError):
            proc.process_message(msg, run1.publisher, run1.dedup, SOURCE_TOPIC, 0, 3)
        proc.process_message(msg, run1.publisher, run1.dedup, SOURCE_TOPIC, 0, 3)
        o = Outcome(world, [run1])
        assert dlq_copies(o)[self.BAD_DLQ] == 2              # characterization, see the report
        assert copies(o)[key(4)] == 1
        assert run1.dedup.contains(*key(3)) is False         # a rejected span never enters the cache

    @pytest.mark.parametrize("mode", ["timeout_persisted", "timeout_lost"])
    def test_ambiguous_dlq_timeout(self, run, mode):
        o = run(DLQ_MIX, [F(mode, 1)])
        assert isinstance(o.runs[0].exc, PublishTimeoutError)
        assert dlq_copies(o)[self.DECODE_DLQ] == (2 if mode == "timeout_persisted" else 1)
        assert_converged(o)

    def test_all_dlq_reasons_are_present_after_a_fault_free_run(self, run):
        o = run(DLQ_MIX)
        assert set(dlq_copies(o)) == {self.DECODE_DLQ, self.NONE_DLQ, self.BAD_DLQ,
                                      (4, TRACE, f"{6:016x}", "SCHEMA_VALIDATION_FAILURE")}
        assert_converged(o)


class TestSerializationAndConsumerErrors:
    def test_a_span_that_cannot_be_serialized_halts_every_run_and_is_never_dlqed(self, run):
        log = [MSG(S(0)), MSG(S(1)), MSG(S(2), S(3, unserializable=True)), MSG(S(4))]
        o = run(log, max_runs=3)
        assert len(o.runs) == 3
        assert all(isinstance(r.exc, PublishSerializationError) for r in o.runs)
        assert [o.world.committed_end[n] for n in (1, 2, 3)] == [2, 2, 2]
        assert o.world.persisted_dlq == []                    # not converted into a DLQ event
        assert key(4) not in copies(o) and key(3) not in copies(o)
        assert copies(o)[key(0)] == 1 and copies(o)[key(1)] == 1      # committed, never replayed
        assert copies(o)[key(2)] == 3                         # replayed by every restart
        assert live_problems(o) == []
        assert "did not converge" in " ".join(convergence_problems(o))

    def test_consumer_error_halts_before_any_processing_and_converges_after_restart(self, run):
        o = run(PLAIN, [F("consumer_error", 2)])
        assert isinstance(o.runs[0].exc, RuntimeError) and "consumer error" in str(o.runs[0].exc)
        assert polled_offsets(o, 1) == [0, 1]
        assert o.world.committed_end[1] == 2
        assert copies(o) == {key(i): 1 for i in range(5)}     # nothing was replayed
        assert o.world.persisted_dlq == []
        assert_converged(o)


class TestCleanupFailures:
    """run_consumer_loop closes the publisher, then the consumer, and attempts both.  A cleanup failure must
    never replace the failure that stopped the loop; without a loop failure the first cleanup failure
    (publisher before consumer) propagates; every other one is written to stderr.  Before B3J-326 a
    publisher.close() error replaced the processing error, and before B3J-328 a consumer.close() error did."""

    # -- through the restart harness: the real publisher, the real flush --------------------------
    def test_processing_failure_only_propagates_unchanged_and_reports_nothing(self, run, capsys):
        o = run(PLAIN, [F("error_nonretriable", 2)])
        exc = o.runs[0].exc
        assert type(exc) is PublishBrokerError and exc.__context__ is None
        assert o.runs[0].consumer.closed
        assert "publisher.close() failed" not in capsys.readouterr().err
        assert_converged(o)

    def test_publisher_close_failure_only_still_propagates_and_loses_nothing(self, run, capsys):
        o = run(PLAIN, [F("flush_remaining", 5)])             # flush #5 is the close() flush
        assert type(o.runs[0].exc) is PublishTimeoutError and "shutdown flush" in str(o.runs[0].exc)
        assert o.runs[0].consumer.closed
        assert o.world.committed_end[1] == 5
        assert len(o.runs) == 2 and polled_offsets(o, 2) == []
        assert copies(o) == {key(i): 1 for i in range(5)}
        assert "publisher.close() failed" not in capsys.readouterr().err     # propagated, not just printed
        assert_converged(o)

    def test_both_failures_keep_the_processing_error_primary_and_report_the_close_error(self, run, capsys):
        o = run(PLAIN, [F("error_nonretriable", 2), F("flush_remaining", 3)])
        exc = o.runs[0].exc
        assert type(exc) is PublishBrokerError and "non-retriable" in str(exc)
        assert exc.__context__ is None                        # not chained to the cleanup failure
        err = capsys.readouterr().err
        assert "publisher.close() failed" in err
        assert "PublishBrokerError" in err and "PublishTimeoutError" in err and "shutdown flush" in err
        assert o.runs[0].consumer.closed
        with pytest.raises(RuntimeError):                     # the publisher is closed regardless
            o.runs[0].publisher.publish_span(FakeEvent(o.world, S(9)))
        assert o.world.committed_end[1] == 2
        assert_converged(o)

    def test_successful_processing_and_cleanup_is_unchanged(self, run, capsys):
        o = run(PLAIN)
        assert len(o.runs) == 1 and o.runs[0].exc is None
        assert capsys.readouterr().err == ""
        assert_converged(o)

    # -- directly, with mocks: every combination of the three failures ------------------------------
    @staticmethod
    def _loop(processing=None, publisher_close=None, consumer_close=None):
        """A loop whose consumer.poll raises `processing`, whose publisher.close raises `publisher_close`
        and whose consumer.close raises `consumer_close`; records the order of the two closes.  The
        exceptions are raised from named functions (poll_raiser, close_publisher, close_consumer) so a
        test can see them in the traceback."""
        consumer, publisher, order = MagicMock(), MagicMock(), []

        def poll_raiser(timeout=None):
            raise processing

        def close_publisher():
            order.append("publisher.close")
            if publisher_close is not None:
                raise publisher_close

        def close_consumer():
            order.append("consumer.close")
            if consumer_close is not None:
                raise consumer_close
        publisher.close.side_effect = close_publisher
        consumer.close.side_effect = close_consumer
        shutdown = threading.Event()
        if processing is not None:
            consumer.poll.side_effect = poll_raiser
        else:
            shutdown.set()

        def call():
            return run_consumer_loop(consumer, publisher, SpanDeduplicator(10), shutdown,
                                     poll_timeout_seconds=0.0)
        return call, order

    @pytest.mark.parametrize("processing_fails", [False, True])
    @pytest.mark.parametrize("publisher_fails", [False, True])
    @pytest.mark.parametrize("consumer_fails", [False, True])
    def test_the_first_failure_in_processing_publisher_consumer_order_is_the_one_raised(
            self, capsys, processing_fails, publisher_fails, consumer_fails):
        processing = RuntimeError("poll blew up") if processing_fails else None
        publisher_close = PublishTimeoutError("shutdown flush left 1 message") if publisher_fails else None
        consumer_close = OSError("consumer close failed") if consumer_fails else None
        call, order = self._loop(processing, publisher_close, consumer_close)

        failures = [f for f in (processing, publisher_close, consumer_close) if f is not None]
        if failures:
            with pytest.raises(BaseException) as caught:
                call()
            assert caught.value is failures[0]                  # the very object, not a copy or a wrapper
            assert caught.value.__context__ is None             # and not chained to a cleanup failure
        else:
            call()
        assert order == ["publisher.close", "consumer.close"]    # both attempted, publisher first

        err = capsys.readouterr().err
        for secondary in failures[1:]:                           # each other failure is visible, with type and message
            assert repr(secondary) in err
            assert type(secondary).__name__ in err and str(secondary) in err
        if len(failures) <= 1:
            assert err == ""                                     # a lone failure is raised, not also printed

    def test_each_cleanup_failure_names_the_operation_that_failed(self, capsys):
        call, _ = self._loop(RuntimeError("boom"), PublishTimeoutError("flush"), OSError("close"))
        with pytest.raises(RuntimeError):
            call()
        lines = capsys.readouterr().err.splitlines()
        assert len(lines) == 2
        assert lines[0].startswith("stream processor: publisher.close() failed") and "PublishTimeoutError" in lines[0]
        assert lines[1].startswith("stream processor: consumer.close() failed") and "OSError" in lines[1]

    @pytest.mark.parametrize("publisher_fails, consumer_fails", [(False, False), (True, False), (False, True), (True, True)])
    def test_an_interruption_is_preserved_over_every_cleanup_failure(self, capsys, publisher_fails, consumer_fails):
        publisher_close = PublishTimeoutError("shutdown flush") if publisher_fails else None
        consumer_close = OSError("consumer close failed") if consumer_fails else None
        call, order = self._loop(KeyboardInterrupt(), publisher_close, consumer_close)
        with pytest.raises(KeyboardInterrupt):
            call()
        assert order == ["publisher.close", "consumer.close"]
        err = capsys.readouterr().err
        assert ("publisher.close() failed" in err) == publisher_fails
        assert ("consumer.close() failed" in err) == consumer_fails

    def test_the_consumer_is_still_closed_when_publisher_close_is_interrupted(self):
        call, order = self._loop(None, KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            call()
        assert order == ["publisher.close", "consumer.close"]

    def test_a_consumer_close_failure_alone_propagates_through_the_real_loop(self, monkeypatch, capsys):
        # real publisher and real flush; only the fake consumer's close raises, after a clean drain
        world, stack = make_stack(monkeypatch, PLAIN)

        def failing_close():
            raise OSError("consumer close failed")
        stack.consumer.close = failing_close
        with pytest.raises(OSError, match="consumer close failed"):
            run_consumer_loop(stack.consumer, stack.publisher, stack.dedup, stack.shutdown,
                              poll_timeout_seconds=0.0)
        assert world.committed == 5
        assert capsys.readouterr().err == ""


# What the three places can raise.  Every message is distinct so a report line can be matched to the
# failure it is about.
LOOP_FAILURES = {"none": None, "error": lambda: RuntimeError("loop"),
                 "interrupt": lambda: KeyboardInterrupt("loop")}
PUBLISHER_FAILURES = {"none": None, "error": lambda: PublishTimeoutError("publisher"),
                      "interrupt": lambda: KeyboardInterrupt("publisher"), "exit": lambda: SystemExit(3)}
CONSUMER_FAILURES = {"none": None, "error": lambda: OSError("consumer"),
                     "interrupt": lambda: KeyboardInterrupt("consumer"), "exit": lambda: SystemExit(4)}
CLEANUP_MATRIX = [(lo, pu, co) for lo in LOOP_FAILURES for pu in PUBLISHER_FAILURES for co in CONSUMER_FAILURES]


def _build(loop, publisher, consumer):
    return tuple(None if table[key] is None else table[key]()
                 for table, key in ((LOOP_FAILURES, loop), (PUBLISHER_FAILURES, publisher),
                                    (CONSUMER_FAILURES, consumer)))


def expected_propagation(loop, publisher, consumer):
    """What propagates, derived from the policy alone: an interruption raised by cleanup always wins (the
    consumer's replaces the publisher's); otherwise the first of loop, publisher, consumer."""
    interruptions = [f for f in (publisher, consumer) if f is not None and not isinstance(f, Exception)]
    if interruptions:
        return interruptions[-1]
    return next((f for f in (loop, publisher, consumer) if f is not None), None)


def _frames(exc):
    import traceback
    return [frame.name for frame in traceback.extract_tb(exc.__traceback__)]


class TestCleanupInterruptions:
    """A KeyboardInterrupt / SystemExit raised by cleanup is never swallowed and still wins, exactly as
    before B3J-331; what changed is that the failures it displaces are written to stderr first.  Synthetic
    exceptions and mocks only: no real signal is sent."""

    @pytest.mark.parametrize("loop, publisher, consumer", CLEANUP_MATRIX)
    def test_precedence_identity_traceback_and_order_are_unchanged(self, capsys, loop, publisher, consumer):
        failures = _build(loop, publisher, consumer)
        call, order = TestCleanupFailures._loop(*failures)
        expected = expected_propagation(*failures)

        if expected is None:
            call()
        else:
            with pytest.raises(BaseException) as caught:
                call()
            assert caught.value is expected                     # the very object: same type, args and exit code
            origin = {id(failures[0]): "poll_raiser", id(failures[1]): "close_publisher",
                      id(failures[2]): "close_consumer"}[id(expected)]
            assert origin in _frames(caught.value)              # and its original traceback
        assert order == ["publisher.close", "consumer.close"]    # both attempted, publisher first, once each

    @pytest.mark.parametrize("loop, publisher, consumer", CLEANUP_MATRIX)
    def test_every_failure_that_does_not_propagate_is_reported_exactly_once(
            self, capsys, loop, publisher, consumer):
        failures = _build(loop, publisher, consumer)
        call, _ = TestCleanupFailures._loop(*failures)
        expected = expected_propagation(*failures)
        if expected is None:
            call()
        else:
            with pytest.raises(BaseException):
                call()
        lines = capsys.readouterr().err.splitlines()

        others = [f for f in failures if f is not None and f is not expected]
        assert len(lines) == len(others)                         # nothing extra, nothing twice
        for failure in others:                                   # each is the subject of exactly one line
            assert sum(1 for line in lines if line.endswith(repr(failure))) == 1
        if expected is not None:                                 # the propagating one is not a subject
            assert not any(line.endswith(repr(expected)) for line in lines)
        assert all(line.startswith("stream processor: ") for line in lines)

    def test_a_publisher_interruption_over_a_loop_error_reports_the_loop_error(self, capsys):
        loop, interruption = RuntimeError("loop"), KeyboardInterrupt("publisher")
        call, order = TestCleanupFailures._loop(loop, interruption)
        with pytest.raises(KeyboardInterrupt) as caught:
            call()
        assert caught.value is interruption and caught.value.__context__ is loop     # Python's chaining
        assert capsys.readouterr().err == (
            "stream processor: loop failure was displaced by KeyboardInterrupt('publisher'): "
            "RuntimeError('loop')\n")
        assert order == ["publisher.close", "consumer.close"]

    def test_the_consumer_is_still_closed_and_its_ordinary_error_reported_after_a_publisher_interruption(
            self, capsys):
        call, order = TestCleanupFailures._loop(None, SystemExit(3), OSError("consumer"))
        with pytest.raises(SystemExit) as caught:
            call()
        assert caught.value.code == 3 and order == ["publisher.close", "consumer.close"]
        assert capsys.readouterr().err == (
            "stream processor: consumer.close() failed while handling SystemExit(3): OSError('consumer')\n")

    def test_a_consumer_interruption_reports_the_publisher_error_that_would_otherwise_be_lost(self, capsys):
        call, _ = TestCleanupFailures._loop(None, PublishTimeoutError("publisher"), KeyboardInterrupt("consumer"))
        with pytest.raises(KeyboardInterrupt):
            call()
        assert capsys.readouterr().err == (
            "stream processor: publisher.close() failure was displaced by KeyboardInterrupt('consumer'): "
            "PublishTimeoutError('publisher')\n")

    def test_a_failure_already_reported_is_not_reported_again_when_an_interruption_follows(self, capsys):
        # loop error + publisher error (reported when it happened) + consumer interruption
        call, _ = TestCleanupFailures._loop(RuntimeError("loop"), PublishTimeoutError("publisher"),
                                            KeyboardInterrupt("consumer"))
        with pytest.raises(KeyboardInterrupt):
            call()
        lines = capsys.readouterr().err.splitlines()
        assert lines == [
            "stream processor: publisher.close() failed while handling RuntimeError('loop'): "
            "PublishTimeoutError('publisher')",
            "stream processor: loop failure was displaced by KeyboardInterrupt('consumer'): "
            "RuntimeError('loop')"]

    def test_a_failure_to_write_diagnostics_never_replaces_the_real_error(self, monkeypatch):
        class BrokenStderr:
            def write(self, _):
                raise OSError("stderr is closed")

            def flush(self):
                raise OSError("stderr is closed")
        monkeypatch.setattr(sys, "stderr", BrokenStderr())
        loop = RuntimeError("loop")
        call, order = TestCleanupFailures._loop(loop, PublishTimeoutError("publisher"), OSError("consumer"))
        with pytest.raises(RuntimeError) as caught:
            call()
        assert caught.value is loop and order == ["publisher.close", "consumer.close"]

    def test_an_exception_whose_repr_fails_is_still_reported(self, capsys):
        class BadRepr(Exception):
            def __repr__(self):
                raise ValueError("repr is broken")
        loop = BadRepr("loop")
        call, _ = TestCleanupFailures._loop(loop, PublishTimeoutError("publisher"))
        with pytest.raises(BadRepr) as caught:
            call()
        assert caught.value is loop
        err = capsys.readouterr().err
        assert "BadRepr (repr failed)" in err and "PublishTimeoutError('publisher')" in err


# ---------------------------------------------------------------------------
# The harness itself: the checker must reject wrong implementations
# ---------------------------------------------------------------------------

def commit_before_process_loop(consumer, publisher, deduplicator, shutdown, poll_timeout_seconds=1.0):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            if msg.error() is not None:
                raise RuntimeError("consumer error")
            consumer.commit(message=msg, asynchronous=False)
            proc.process_message(msg, publisher, deduplicator, msg.topic(), msg.partition(),
                                 msg.offset())
    finally:
        try:
            publisher.close()
        finally:
            consumer.close()


def swallow_and_continue_loop(consumer, publisher, deduplicator, shutdown, poll_timeout_seconds=1.0):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            if msg.error() is not None:
                raise RuntimeError("consumer error")
            try:
                proc.process_message(msg, publisher, deduplicator, msg.topic(), msg.partition(),
                                     msg.offset())
            except Exception:
                pass
            consumer.commit(message=msg, asynchronous=False)
    finally:
        try:
            publisher.close()
        finally:
            consumer.close()


def never_commits_loop(consumer, publisher, deduplicator, shutdown, poll_timeout_seconds=1.0):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            proc.process_message(msg, publisher, deduplicator, msg.topic(), msg.partition(),
                                 msg.offset())
    finally:
        try:
            publisher.close()
        finally:
            consumer.close()


def async_commit_loop(consumer, publisher, deduplicator, shutdown, poll_timeout_seconds=1.0):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            proc.process_message(msg, publisher, deduplicator, msg.topic(), msg.partition(),
                                 msg.offset())
            consumer.commit(message=msg, asynchronous=True)
    finally:
        try:
            publisher.close()
        finally:
            consumer.close()


def mark_before_publish(msg, publisher, deduplicator, source_topic, source_partition, source_offset):
    for span in proc.decode(msg.value()):
        event = proc.canonicalize(span)
        if deduplicator.contains(event.trace_id, event.span_id):
            continue
        deduplicator.mark(event.trace_id, event.span_id)       # wrong: before the broker ack
        publisher.publish_span(event)


def all_problems(o):
    return live_problems(o) + convergence_problems(o)


class TestTheHarnessItself:
    def test_a_fault_free_run_is_clean_and_has_the_expected_shape(self, run):
        o = run(PLAIN)
        assert all_problems(o) == []
        w = o.world
        assert (len(o.runs), w.counters[(1, "produce")], w.counters[(1, "commit")],
                w.counters[(1, "poll")]) == (1, 5, 5, 6)
        assert copies(o) == {key(i): 1 for i in range(5)}

    def test_a_fault_beyond_the_reached_sites_never_fires(self, run):
        o = run(PLAIN, [F("error_nonretriable", 99), F("commit_error", 0, 5)])
        assert o.world.fired == [] and len(o.runs) == 1
        assert all_problems(o) == []

    def test_expectations_come_from_the_log_alone(self):
        assert expected_trusted(DLQ_MIX) == {key(i) for i in (0, 4, 5, 7)}
        assert expected_dlq(DLQ_MIX) == {
            (1, None, None, "OTLP_DECODE_FAILURE"), (2, None, None, "OTLP_DECODE_FAILURE"),
            (3, TRACE, key(3)[1], "SCHEMA_VALIDATION_FAILURE"),
            (4, TRACE, key(6)[1], "SCHEMA_VALIDATION_FAILURE")}

    def test_missing_and_unexpected_output_is_reported(self, run):
        o = run(PLAIN)
        o.world.persisted_trusted.remove((1, key(2)))
        o.world.persisted_trusted.append((1, key(99)))
        text = " ".join(all_problems(o))
        assert "missing trusted" in text and "unexpected trusted" in text

    def test_a_too_many_copies_is_reported(self, run):
        o = run(PLAIN)
        o.world.persisted_trusted += [(1, key(0))] * 3
        assert any("inside one process" in p for p in all_problems(o))

    @pytest.mark.parametrize("at", range(5))
    def test_commit_before_publish_is_rejected(self, run, at):
        o = run(PLAIN, [F("error_nonretriable", at)], loop=commit_before_process_loop)
        problems = all_problems(o)
        assert any("commit past unacked" in p for p in problems)
        assert any("missing trusted" in p for p in problems)      # and the span is really lost

    @pytest.mark.parametrize("at", range(5))
    def test_swallowing_the_failure_is_rejected(self, run, at):
        o = run(PLAIN, [F("error_nonretriable", at)], loop=swallow_and_continue_loop)
        problems = all_problems(o)
        assert any("commit past unacked" in p for p in problems)
        assert any("after a terminal fault" in p for p in problems)

    @pytest.mark.parametrize("at", range(5))
    def test_marking_before_the_ack_is_rejected(self, run, monkeypatch, at):
        monkeypatch.setattr(proc, "process_message", mark_before_publish)
        o = run(PLAIN, [F("error_nonretriable", at)])
        assert any("marked in dedup without a positive ack" in p for p in live_problems(o))

    def test_a_loop_that_never_commits_is_rejected(self, run):
        o = run(PLAIN, loop=never_commits_loop)
        assert any("final committed offset 0 != 5" in p for p in all_problems(o))

    def test_an_asynchronous_commit_is_rejected(self, run):
        o = run(PLAIN, loop=async_commit_loop)
        assert any("not synchronous" in p for p in live_problems(o))

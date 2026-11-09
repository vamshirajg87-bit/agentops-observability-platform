"""
tests/cross_component/test_replay_convergence.py

Offline replay-convergence tests across BOTH pipeline components (Phase 14.5, third scenario):

    OTLP protobuf  ->  stream processor  ->  trusted Kafka topic  ->  storage consumer  ->  repository

What is real: stream-processor processor.run_consumer_loop / process_message, publisher.KafkaPublisher
(retry, backoff, timeout and close logic), deduplicator.SpanDeduplicator, otlp_decoder.decode (real OTLP
protobuf bytes), canonicalizer.canonicalize (real normalize_span), the DLQ model, the real
CanonicalSpanEvent, and storage-consumer consumer.run_consumer_loop / process_message (decode, JSON parse,
CanonicalSpanEvent validation).
What is fake, and in memory only: the Kafka source log and both committed offsets, both consumers' poll and
commit calls, the producer with its delivery reports, the broker log it writes (the shared trusted topic),
the repository (it emulates UNIQUE(trace_id, span_id) with ON CONFLICT DO NOTHING and a transaction per
insert), and the restart supervisor.  Only the poison-message tests that need a span the real decoder can
never produce wrap canonicalize, and they say so.
No socket, no Docker, no Kafka, no PostgreSQL, no process is touched.

Each component is restarted independently by a bounded, sequential round scheduler: one run of a component
drains its input or halts, then the other component runs.  A restart builds a NEW consumer, publisher and
deduplicator and starts at that component's own committed offset.  There is no threading, so truly
concurrent interleavings are not exercised.

Delivery acknowledgement and broker persistence are modelled separately (see timeout_persisted,
timeout_lost, timeout_late, error_retriable_persisted).  A database commit whose reply is lost
(db_ack_lost) is a committed row with an exception at the caller.

What this proves, and what it does not
  - It proves the Python orchestration contracts compose: whatever the injected faults, once both components
    drain, the repository holds exactly one row per distinct valid span, no offset moved past work that was
    not acknowledged / persisted, restarts resumed at the right offsets, and poison input stays an explicit,
    non-converging halt.
  - It does NOT prove exactly-once delivery or any distributed transaction.  Replays DO publish duplicate
    trusted spans and duplicate DLQ events; the tests count them.  Only the (emulated) unique key keeps the
    replays from becoming duplicate rows.
  - It does NOT prove Kafka or PostgreSQL behaviour: the real unique constraint, real transactions, real
    client commit semantics (committing N commits N+1 is assumed) and Jsonb storage are covered only by the
    integration tests, which were not run.
  - A "simulated interruption" is NOT an operating-system process kill: it is a BaseException raised at the
    chosen point after which the producer is treated as dead.  Python finally blocks still run.
  - Rebalancing, several partitions and the opt-in OffsetBatcher are not modelled.

Import isolation: the stream-processor and storage-consumer both have flat modules named config and main, and
both have a conftest and a tests package.  This file lives outside both packages, puts the stream-processor
directory first on sys.path and the storage-consumer directory last, and uses only storage's consumer module
(which never imports config).  It never imports the storage config, repository or main.

Run from the repository root, apart from the two package suites:
    python -m pytest tests/cross_component -p no:cacheprovider
"""

from __future__ import annotations

import json
import random
import sys
import threading
from collections import Counter, defaultdict
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SP_DIR = _ROOT / "stream-processor"
_ST_DIR = _ROOT / "storage-consumer"
for _path in (_ROOT / "demo-app", _SP_DIR):          # stream-processor ends up first
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
if str(_ST_DIR) not in sys.path:
    sys.path.append(str(_ST_DIR))                    # storage-consumer last: only consumer.py is used

import config as sp_config                           # noqa: E402  (the stream-processor config)
import consumer as st_consumer                       # noqa: E402  (the storage-consumer loop)
import processor as sp_proc                          # noqa: E402
from canonicalizer import canonicalize               # noqa: E402
from deduplicator import SpanDeduplicator           # noqa: E402
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest  # noqa: E402
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue  # noqa: E402
from opentelemetry.proto.resource.v1.resource_pb2 import Resource  # noqa: E402
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span, Status  # noqa: E402
from otlp_decoder import decode                      # noqa: E402
from publisher import KafkaPublisher, PublishBrokerError, PublishSerializationError, PublishTimeoutError  # noqa: E402
from pydantic import ValidationError                 # noqa: E402
from schemas.telemetry import CanonicalSpanEvent     # noqa: E402

for _module, _directory in ((sp_config, _SP_DIR), (sp_proc, _SP_DIR), (st_consumer, _ST_DIR)):
    if Path(_module.__file__).resolve().parent != _directory:
        raise ImportError(
            f"{_module.__name__} was imported from {_module.__file__}, not {_directory}; "
            "run this module on its own, apart from the package test suites")

TRACE = "0a" * 16
RETRIES = 3
TOPIC = sp_config.TOPIC_SPANS
START_NS = 1_700_000_000_000_000_000
END_NS = 1_700_000_001_000_000_000


# ---------------------------------------------------------------------------
# Source records: real OTLP protobuf, with expectations derived from the specs alone
# ---------------------------------------------------------------------------

def P(i, *, bad=False, rejected=False, trace=TRACE, attrs=()):
    """A span spec.  bad: end before start.  rejected: the attributes make the canonical schema reject it.
    Either way the span is expected to go to the DLQ and never reach the trusted topic."""
    return {"i": i, "bad": bad or rejected, "swap": bad, "trace": trace, "attrs": tuple(attrs)}


def span_id(i):
    return f"{i:016x}"


def ident_of(spec):
    return (spec["trace"], span_id(spec["i"]))


def _kv(key, kind, value):
    return KeyValue(key=key, value=AnyValue(**{{"s": "string_value", "d": "double_value",
                                                "i": "int_value"}[kind]: value}))


def _span_pb(spec):
    start, end = (END_NS, START_NS) if spec["swap"] else (START_NS, END_NS)
    return Span(trace_id=bytes.fromhex(spec["trace"]), span_id=spec["i"].to_bytes(8, "big"),
                name=f"op.{spec['i']}", kind=1, start_time_unix_nano=start, end_time_unix_nano=end,
                status=Status(code=1), attributes=[_kv(*a) for a in spec["attrs"]])


def REC(*specs, service="svc"):
    resource = Resource(attributes=[_kv("service.name", "s", service)])
    request = ExportTraceServiceRequest(resource_spans=[
        ResourceSpans(resource=resource, scope_spans=[ScopeSpans(spans=[_span_pb(s) for s in specs])])])
    return {"kind": "spans", "value": request.SerializeToString(), "specs": list(specs)}


GARBAGE = {"kind": "decode_fail", "value": b"garbage-not-protobuf", "specs": []}
TOMBSTONE = {"kind": "none", "value": None, "specs": []}


def requirements(record, offset):
    """(trusted idents, DLQ coordinates) that must be acknowledged before this source offset is committed."""
    if record["kind"] in ("decode_fail", "none"):
        return set(), {(offset, None, None, "OTLP_DECODE_FAILURE")}
    trusted, dlq = set(), set()
    for spec in record["specs"]:
        if spec["bad"]:
            dlq.add((offset, spec["trace"], span_id(spec["i"]), "SCHEMA_VALIDATION_FAILURE"))
        else:
            trusted.add(ident_of(spec))
    return trusted, dlq


def expected_trusted(source):
    return set().union(*(requirements(r, o)[0] for o, r in enumerate(source)))


def expected_dlq(source):
    return set().union(*(requirements(r, o)[1] for o, r in enumerate(source)))


def all_idents(source):
    return {ident_of(s) for r in source for s in r["specs"]}


def canonical_entry(i, *, trace=TRACE, attrs=()):
    """A trusted-topic entry built exactly as the stream processor builds it (real decode, canonicalize
    and the publisher's serialization), for tests that seed the topic."""
    record = REC(P(i, trace=trace, attrs=attrs))
    event = canonicalize(decode(record["value"])[0])
    return {"key": event.trace_id.encode(), "value": json.dumps(event.model_dump(mode="json")).encode(),
            "poison": False, "ident": (event.trace_id, event.span_id), "run": None}


def poison_entry(raw):
    return {"key": b"poison", "value": raw, "poison": True, "ident": None, "run": None}


PLAIN = [REC(P(i)) for i in range(5)]
MULTI = [REC(P(0), P(1), P(2)), REC(P(3)), REC(P(4), P(5)), REC(P(6), P(7), P(8)), REC(P(9))]
# SP produce order without faults: S0, DLQ(1), DLQ(2), DLQ(3,S3), S4, S5, DLQ(4,S6), S7
MIXED = [REC(P(0)), GARBAGE, TOMBSTONE, REC(P(3, bad=True), P(4)), REC(P(5), P(6, bad=True), P(7))]
DUP = [REC(P(0)), REC(P(1)), REC(P(0)), REC(P(2), P(1))]
SOURCES = {"plain": PLAIN, "multi": MULTI, "mixed": MIXED, "dup": DUP}


# ---------------------------------------------------------------------------
# Faults
# ---------------------------------------------------------------------------

class SimulatedInterruption(BaseException):
    """The process 'stopped' here.  Not an OS kill; see the module docstring."""


class CommitFailure(Exception):
    pass


SP_PRODUCE = frozenset({"buffer_error", "error_nonretriable", "error_retriable", "error_retriable_persisted",
                        "timeout_persisted", "timeout_lost", "timeout_late",
                        "interrupt_in_produce", "interrupt_after_persist"})
SP_COMMIT = frozenset({"commit_error", "commit_ack_lost", "interrupt_before_commit"})
SP_POLL = frozenset({"consumer_error"})
SP_FLUSH = frozenset({"flush_remaining"})
ST_DB = frozenset({"db_error", "db_ack_lost", "db_interrupt"})
ST_COMMIT = frozenset({"commit_error", "commit_ack_lost", "interrupt_before_commit"})
ST_POLL = frozenset({"consumer_error"})

SP_KINDS = sorted(SP_PRODUCE | SP_COMMIT | SP_POLL)
ST_KINDS = sorted(ST_DB | ST_COMMIT | ST_POLL)
SP_SITE = {**{k: "produce" for k in SP_PRODUCE}, **{k: "commit" for k in SP_COMMIT},
           **{k: "poll" for k in SP_POLL}, **{k: "flush" for k in SP_FLUSH}}
ST_SITE = {**{k: "db" for k in ST_DB}, **{k: "commit" for k in ST_COMMIT}, **{k: "poll" for k in ST_POLL}}
TERMINAL = {
    "sp": frozenset({"error_nonretriable", "timeout_persisted", "timeout_lost", "timeout_late",
                     "interrupt_in_produce", "interrupt_after_persist", "commit_error", "commit_ack_lost",
                     "interrupt_before_commit", "consumer_error", "serialization_error"}),
    "st": ST_DB | ST_COMMIT | ST_POLL,
}
EXPECTED_SP_EXCEPTION = {
    "error_nonretriable": PublishBrokerError, "timeout_persisted": PublishTimeoutError,
    "timeout_lost": PublishTimeoutError, "timeout_late": PublishTimeoutError,
    "interrupt_in_produce": SimulatedInterruption, "interrupt_after_persist": SimulatedInterruption,
    "commit_error": CommitFailure, "commit_ack_lost": CommitFailure,
    "interrupt_before_commit": SimulatedInterruption, "consumer_error": RuntimeError,
}
EXPECTED_ST_EXCEPTION = {
    "db_error": RuntimeError, "db_ack_lost": RuntimeError, "db_interrupt": SimulatedInterruption,
    "commit_error": CommitFailure, "commit_ack_lost": CommitFailure,
    "interrupt_before_commit": SimulatedInterruption, "consumer_error": RuntimeError,
}


def SPF(kind, at, run=1):
    return ("sp", kind, run, at)


def STF(kind, at, run=1):
    return ("st", kind, run, at)


# ---------------------------------------------------------------------------
# The in-memory universe
# ---------------------------------------------------------------------------

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
        return TOPIC

    def partition(self):
        return 0

    def offset(self):
        return self._offset

    def error(self):
        return self._error


class World:
    """Everything both components share, across all restarts."""

    def __init__(self, source, faults=(), *, topic_seed=(), unique=True):
        self.source = list(source)
        self.topic = [dict(e) for e in topic_seed]       # the trusted topic: SP writes it, ST reads it
        self.faults = [{"comp": c, "kind": k, "run": r, "at": a, "used": False} for c, k, r, a in faults]
        self.unique = unique
        self.committed = {"sp": 0, "st": 0}
        self.run = {"sp": 0, "st": 0}
        self.runs = {"sp": [], "st": []}
        self.committed_end = {"sp": {}, "st": {}}
        self.counters = defaultdict(int)
        self.events = []
        self.problems = []
        self.sleeps = []
        self.fired = []                                  # (comp, run, kind)
        self.rows = []                                   # the physical table: dicts, in commit order
        self.insert_log = []                             # (run, topic offset, ident, outcome)
        self.persisted_dlq = []                          # (run, coordinate)
        self.acked_trusted = set()
        self.acked_dlq = set()
        self.acked_in_run = defaultdict(set)
        self.converged = False

    # -- schedule ----------------------------------------------------------------
    def begin(self, comp):
        self.run[comp] += 1
        self.events.append(("start", comp, self.run[comp], self.committed[comp]))
        return self.run[comp]

    def tick(self, comp, site):
        idx = self.counters[(comp, self.run[comp], site)]
        self.counters[(comp, self.run[comp], site)] += 1
        return idx

    def take(self, comp, kinds, index):
        for f in self.faults:
            if (not f["used"] and f["comp"] == comp and f["run"] == self.run[comp]
                    and f["at"] == index and f["kind"] in kinds):
                f["used"] = True
                return f["kind"]
        return None

    def fire(self, comp, kind):
        self.fired.append((comp, self.run[comp], kind))
        self.events.append(("fire", comp, self.run[comp], kind))

    # -- observations ------------------------------------------------------------
    @staticmethod
    def identify(topic, value):
        body = json.loads(value)
        if topic == sp_config.TOPIC_DLQ:
            return (body["source_offset"], body["trace_id"], body["span_id"], body["reason"])
        return (body["trace_id"], body["span_id"])

    def first_row(self, ident):
        return next((r for r in self.rows if r["ident"] == ident), None)

    def persist(self, entry):
        run = self.run["sp"]
        ident = self.identify(entry["topic"], entry["value"])
        if entry["topic"] == sp_config.TOPIC_DLQ:
            self.persisted_dlq.append((run, ident))
        else:
            self.topic.append({"key": entry["key"], "value": entry["value"], "poison": False,
                               "ident": ident, "run": run})
        self.events.append(("persist", "sp", run, entry["topic"], ident))

    def ack(self, entry):
        entry["cb"](None, None)
        ident = self.identify(entry["topic"], entry["value"])
        if entry["topic"] == sp_config.TOPIC_DLQ:
            self.acked_dlq.add(ident)
        else:
            self.acked_trusted.add(ident)
            self.acked_in_run[self.run["sp"]].add(ident)

    # -- the invariants checked at the moment of each commit ----------------------
    def check_sp_commit(self, message, asynchronous):
        if asynchronous is not False:
            self.problems.append(f"sp run {self.run['sp']}: commit is not synchronous ({asynchronous!r})")
        offset = message.offset()
        trusted, dlq = requirements(self.source[offset], offset)
        missing_t, missing_d = sorted(trusted - self.acked_trusted), sorted(dlq - self.acked_dlq, key=repr)
        if missing_t or missing_d:
            self.problems.append(
                f"sp run {self.run['sp']}: source commit past unacknowledged publications at offset {offset}: "
                f"trusted={missing_t} dlq={missing_d}")

    def check_st_commit(self, message, asynchronous):
        if asynchronous is not False:
            self.problems.append(f"st run {self.run['st']}: commit is not synchronous ({asynchronous!r})")
        for offset in range(message.offset() + 1):
            entry = self.topic[offset]
            if entry["poison"]:
                self.problems.append(f"st run {self.run['st']}: destination commit past poison message at topic offset {offset}")
            elif self.first_row(entry["ident"]) is None:
                self.problems.append(
                    f"st run {self.run['st']}: destination commit past unpersisted topic offset {offset}")


# ---------------------------------------------------------------------------
# Stream-processor fakes
# ---------------------------------------------------------------------------

class SpProducer:
    def __init__(self, world):
        self.world, self.queue, self.dead = world, [], False

    def produce(self, topic, key=None, value=None, on_delivery=None):
        w = self.world
        idx = w.tick("sp", "produce")
        w.events.append(("produce", "sp", w.run["sp"], idx, topic, w.identify(topic, value)))
        kind = w.take("sp", SP_PRODUCE, idx)
        if kind == "buffer_error":
            w.fire("sp", kind)
            raise BufferError("local queue full")
        if kind == "interrupt_in_produce":
            w.fire("sp", kind)
            self.dead = True
            raise SimulatedInterruption()
        self.queue.append({"topic": topic, "key": key, "value": value, "cb": on_delivery,
                           "mode": kind or "ok", "deferred": False})

    def poll(self, timeout=0):
        return 0

    def flush(self, timeout=None):
        w = self.world
        idx = w.tick("sp", "flush")
        w.events.append(("flush", "sp", w.run["sp"], idx))
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
                w.fire("sp", mode)
                if mode == "error_retriable_persisted":
                    w.persist(entry)
                entry["cb"](FakeKafkaError(mode != "error_nonretriable"), None)
                self.queue.remove(entry)
            elif mode == "timeout_persisted":
                w.fire("sp", mode)
                w.persist(entry)
                self.queue.remove(entry)
                remaining += 1
            elif mode == "timeout_lost":
                w.fire("sp", mode)
                self.queue.remove(entry)
                remaining += 1
            elif mode == "timeout_late":
                if entry["deferred"]:
                    w.persist(entry)
                    w.ack(entry)
                    self.queue.remove(entry)
                else:
                    w.fire("sp", mode)
                    entry["deferred"] = True
                    remaining += 1
            elif mode == "interrupt_after_persist":
                w.persist(entry)
                w.fire("sp", mode)
                self.dead = True
                self.queue.clear()
                raise SimulatedInterruption()
        if w.take("sp", SP_FLUSH, idx):
            w.fire("sp", "flush_remaining")
            remaining += 1
        return remaining


class SpConsumer:
    def __init__(self, world, shutdown):
        self.world, self.shutdown = world, shutdown
        self.position = world.committed["sp"]
        self.closed = False

    def poll(self, timeout=None):
        w = self.world
        run = w.run["sp"]
        idx = w.tick("sp", "poll")
        if w.take("sp", SP_POLL, idx):
            w.events.append(("poll", "sp", run, idx, None))
            w.fire("sp", "consumer_error")
            return FakeMsg(None, None, error="broker transport failure")
        if self.position >= len(w.source):
            w.events.append(("poll", "sp", run, idx, None))
            self.shutdown.set()
            return None
        record = w.source[self.position]
        msg = FakeMsg(self.position, record["value"])
        self.position += 1
        w.events.append(("poll", "sp", run, idx, msg.offset()))
        return msg

    def commit(self, message=None, asynchronous=True):
        w = self.world
        run = w.run["sp"]
        idx = w.tick("sp", "commit")
        w.check_sp_commit(message, asynchronous)
        w.events.append(("commit", "sp", run, message.offset()))
        kind = w.take("sp", SP_COMMIT, idx)
        if kind == "commit_error":
            w.fire("sp", kind)
            raise CommitFailure("source commit failed")
        if kind == "interrupt_before_commit":
            w.fire("sp", kind)
            raise SimulatedInterruption()
        w.committed["sp"] = message.offset() + 1
        w.events.append(("committed", "sp", run, w.committed["sp"]))
        if kind == "commit_ack_lost":
            w.fire("sp", kind)
            raise CommitFailure("source commit acknowledgement lost")

    def close(self):
        self.closed = True


class SpRun:
    def __init__(self, world, dedup_size, retries):
        self.number = world.begin("sp")
        self.shutdown = threading.Event()
        self.dedup = SpanDeduplicator(max_size=dedup_size)
        self.producer = SpProducer(world)
        self.publisher = KafkaPublisher(self.producer, retries=retries, timeout_seconds=1.0,
                                        _sleep=world.sleeps.append)
        self.consumer = SpConsumer(world, self.shutdown)
        self.marked_at_start = {i for i in all_idents(world.source) if self.dedup.contains(*i)}
        self.exc = None


# ---------------------------------------------------------------------------
# Storage-consumer fakes
# ---------------------------------------------------------------------------

class StConsumer:
    """Reads the shared trusted topic from this component's own committed offset."""

    def __init__(self, world, shutdown):
        self.world, self.shutdown = world, shutdown
        self.position = world.committed["st"]
        self.closed = False

    def poll(self, timeout=None):
        w = self.world
        run = w.run["st"]
        idx = w.tick("st", "poll")
        if w.take("st", ST_POLL, idx):
            w.events.append(("poll", "st", run, idx, None))
            w.fire("st", "consumer_error")
            return FakeMsg(None, None, error="broker transport failure")
        if self.position >= len(w.topic):
            w.events.append(("poll", "st", run, idx, None))
            self.shutdown.set()
            return None
        msg = FakeMsg(self.position, w.topic[self.position]["value"])
        self.position += 1
        w.events.append(("poll", "st", run, idx, msg.offset()))
        return msg

    def commit(self, message=None, offsets=None, asynchronous=True):
        w = self.world
        run = w.run["st"]
        idx = w.tick("st", "commit")
        w.check_st_commit(message, asynchronous)
        w.events.append(("commit", "st", run, message.offset()))
        kind = w.take("st", ST_COMMIT, idx)
        if kind == "commit_error":
            w.fire("st", kind)
            raise CommitFailure("destination commit failed")
        if kind == "interrupt_before_commit":
            w.fire("st", kind)
            raise SimulatedInterruption()
        w.committed["st"] = message.offset() + 1
        w.events.append(("committed", "st", run, w.committed["st"]))
        if kind == "commit_ack_lost":
            w.fire("st", kind)
            raise CommitFailure("destination commit acknowledgement lost")

    def close(self):
        self.closed = True


class StRepository:
    """telemetry_spans: UNIQUE(trace_id, span_id) with ON CONFLICT DO NOTHING, one transaction per insert.
    True = a new row, False = already there.  unique=False removes the constraint (a negative control)."""

    def __init__(self, world):
        self.world = world

    def insert_span(self, event, topic, partition, offset):
        w = self.world
        run = w.run["st"]
        idx = w.tick("st", "db")
        w.events.append(("insert", "st", run, offset))
        kind = w.take("st", ST_DB, idx)
        if kind == "db_error":
            w.fire("st", kind)
            raise RuntimeError("injected: the insert failed before anything was persisted")
        if kind == "db_interrupt":
            w.fire("st", kind)
            raise SimulatedInterruption()
        ident = (event.trace_id, event.span_id)
        is_new = (not w.unique) or w.first_row(ident) is None
        if is_new:
            w.rows.append({"ident": ident, "topic": topic, "partition": partition, "offset": offset,
                           "event": event, "run": run})
        w.insert_log.append((run, offset, ident, "new" if is_new else "conflict"))
        if kind == "db_ack_lost":
            w.fire("st", kind)
            raise RuntimeError("injected: the connection was lost after the commit; the caller never learns")
        return is_new


class StRun:
    def __init__(self, world):
        self.number = world.begin("st")
        self.shutdown = threading.Event()
        self.consumer = StConsumer(world, self.shutdown)
        self.repository = StRepository(world)
        self.exc = None


# ---------------------------------------------------------------------------
# Restart supervision: a bounded, sequential round scheduler
# ---------------------------------------------------------------------------

def run_sp(world, *, loop=None, retries=RETRIES, dedup_size=1000):
    run = SpRun(world, dedup_size, retries)
    world.runs["sp"].append(run)
    try:
        (loop or sp_proc.run_consumer_loop)(run.consumer, run.publisher, run.dedup, run.shutdown,
                                            poll_timeout_seconds=0.0)
    except (Exception, SimulatedInterruption) as exc:
        run.exc = exc
    world.committed_end["sp"][run.number] = world.committed["sp"]
    return run


def run_st(world, *, loop=None):
    run = StRun(world)
    world.runs["st"].append(run)
    try:
        (loop or st_consumer.run_consumer_loop)(run.consumer, run.repository, run.shutdown,
                                                poll_timeout_seconds=0.0)
    except (Exception, SimulatedInterruption) as exc:
        run.exc = exc
    world.committed_end["st"][run.number] = world.committed["st"]
    return run


def _sp_done(w):
    runs = w.runs["sp"]
    return bool(runs) and runs[-1].exc is None and w.committed["sp"] == len(w.source)


def _st_done(w):
    runs = w.runs["st"]
    return bool(runs) and runs[-1].exc is None and w.committed["st"] == len(w.topic)


def converge(world, schedule=(), *, max_pairs=8, sp_loop=None, st_loop=None, retries=RETRIES,
             dedup_size=1000):
    """Run the explicit schedule ('SP' / 'ST'), then alternate SP and ST until both have drained cleanly
    or max_pairs rounds are spent.  world.converged says which."""
    for comp in schedule:
        if comp == "SP":
            run_sp(world, loop=sp_loop, retries=retries, dedup_size=dedup_size)
        else:
            run_st(world, loop=st_loop)
    pairs = 0
    while not (_sp_done(world) and _st_done(world)) and pairs < max_pairs:
        if not _sp_done(world):
            run_sp(world, loop=sp_loop, retries=retries, dedup_size=dedup_size)
        if not _st_done(world):
            run_st(world, loop=st_loop)
        pairs += 1
    world.converged = _sp_done(world) and _st_done(world)
    return world


@pytest.fixture
def make_world():
    def _make(source, faults=(), **kwargs):
        return World(source, faults, **kwargs)
    return _make


# ---------------------------------------------------------------------------
# Observations and invariant checkers
# ---------------------------------------------------------------------------

def topic_copies(w):
    return Counter(e["ident"] for e in w.topic if not e["poison"])


def dlq_copies(w):
    return Counter(c for _, c in w.persisted_dlq)


def rows_by_ident(w):
    return Counter(r["ident"] for r in w.rows)


def inserts(w, ident=None, outcome=None):
    return [e for e in w.insert_log if (ident is None or e[2] == ident) and (outcome is None or e[3] == outcome)]


def produce_calls(w, ident, run=None):
    return sum(1 for e in w.events if e[0] == "produce" and e[5] == ident and (run is None or e[2] == run))


def polled(w, comp, run):
    return [e[4] for e in w.events if e[0] == "poll" and e[1] == comp and e[2] == run and e[4] is not None]


def live_problems(w):
    """Invariants that must hold at every step, converged or not."""
    problems = list(w.problems)
    for comp in ("sp", "st"):
        committed = 0
        for run in w.runs[comp]:
            halted = False
            for e in w.events:
                if e[1] != comp or e[2] != run.number:
                    continue
                if e[0] == "fire" and e[3] in TERMINAL[comp]:
                    halted = True
                elif halted and e[0] in ("poll", "produce", "commit", "insert"):
                    problems.append(f"{comp} run {run.number}: {e[0]} after a terminal fault")
            if not run.consumer.closed:
                problems.append(f"{comp} run {run.number}: consumer was not closed")
            offsets = polled(w, comp, run.number)
            if offsets and offsets[0] != committed:
                problems.append(f"{comp} run {run.number}: first polled offset {offsets[0]} != committed {committed}")
            for e in w.events:
                if e[0] == "committed" and e[1] == comp and e[2] == run.number:
                    committed = e[3]
    for run in w.runs["sp"]:             # a failed publication is never marked in the deduplicator
        for ident in all_idents(w.source):
            if run.dedup.contains(*ident) and ident not in w.acked_in_run[run.number]:
                problems.append(f"sp run {run.number}: {ident[1]} marked in dedup without a positive ack")
    first_offset = {}
    for offset, entry in enumerate(w.topic):          # the stored offset belongs to the first copy
        if entry["ident"] is not None:
            first_offset.setdefault(entry["ident"], offset)
    for row in w.rows:
        if w.unique and row["offset"] != first_offset.get(row["ident"]):
            problems.append(f"row {row['ident'][1]} stored offset {row['offset']} != first copy "
                            f"{first_offset.get(row['ident'])}")
    return problems


def convergence_problems(w):
    problems = []
    if not w.converged:
        problems.append("did not converge: the components did not both drain cleanly")
    if w.committed["sp"] != len(w.source):
        problems.append(f"final source committed offset {w.committed['sp']} != {len(w.source)}")
    if w.committed["st"] != len(w.topic):
        problems.append(f"final destination committed offset {w.committed['st']} != {len(w.topic)}")
    want, have = expected_trusted(w.source), set(rows_by_ident(w))
    if want - have:
        problems.append(f"missing rows: {sorted(want - have)}")
    if have - want:
        problems.append(f"unexpected rows: {sorted(have - want)}")
    duplicated = sorted(i for i, n in rows_by_ident(w).items() if n > 1)
    if duplicated:
        problems.append(f"duplicate rows for {duplicated}")
    want_dlq, have_dlq = expected_dlq(w.source), {c for _, c in w.persisted_dlq}
    if want_dlq - have_dlq:
        problems.append(f"missing dlq: {sorted(want_dlq - have_dlq, key=repr)}")
    if have_dlq - want_dlq:
        problems.append(f"unexpected dlq: {sorted(have_dlq - want_dlq, key=repr)}")
    retried = sum(1 for c, _, k in w.fired if c == "sp" and k == "error_retriable_persisted")
    bound = len(w.runs["sp"]) + retried
    for ident, n in topic_copies(w).items():
        if n > bound:
            problems.append(f"{ident[1]} published {n}x > bound {bound}")
        reached = len(inserts(w, ident))
        if reached < n:
            problems.append(f"{ident[1]}: {n} topic copies but only {reached} repository attempts")
        if reached > n + len(w.runs["st"]):
            problems.append(f"{ident[1]}: {reached} repository attempts for {n} copies")
        if len(inserts(w, ident, "new")) != 1:
            problems.append(f"{ident[1]}: {len(inserts(w, ident, 'new'))} successful first inserts")
    per_run = Counter((r, c) for r, c in w.persisted_dlq)
    for (r, c), n in per_run.items():
        if n > 1 + sum(1 for comp, run, k in w.fired if comp == "sp" and run == r and k == "error_retriable_persisted"):
            problems.append(f"sp run {r}: dlq {c} published {n}x inside one process")
    return problems


def assert_converged(w):
    problems = live_problems(w) + convergence_problems(w)
    assert not problems, "\n".join(problems)


def exc_of(w, comp, number):
    return w.runs[comp][number - 1].exc


def row_offset(w, i, trace=TRACE):
    return w.first_row((trace, span_id(i)))["offset"]


# ===========================================================================
# 1. The primary, fully real round trip
# ===========================================================================

class TestPrimaryRoundTrip:
    ATTRS = (("agentops.request_id", "s", "req-1"), ("agentops.session_id", "s", "sess-1"),
             ("agent.name", "s", "planner"), ("tool.name", "s", "search"), ("retrieval.result_count", "i", 3),
             ("retrieval.top_relevance_score", "d", 0.5))

    def test_otlp_input_reaches_the_repository_through_the_real_stack(self, make_world):
        source = [REC(P(0, attrs=self.ATTRS), P(1)), REC(P(2))]
        w = converge(make_world(source))

        assert_converged(w)
        assert (len(w.runs["sp"]), len(w.runs["st"])) == (1, 1)
        assert [e["ident"] for e in w.topic] == [(TRACE, span_id(i)) for i in range(3)]
        assert all(e["key"] == TRACE.encode() for e in w.topic)          # keyed by trace id, as published
        assert set(rows_by_ident(w)) == expected_trusted(source) and len(w.rows) == 3
        for offset, row in enumerate(w.rows):
            assert (row["topic"], row["partition"], row["offset"]) == (TOPIC, 0, offset)
        assert w.persisted_dlq == []

    def test_the_stored_event_equals_an_independent_canonicalization_of_the_input(self, make_world):
        source = [REC(P(0, attrs=self.ATTRS))]
        w = converge(make_world(source))
        independent = canonicalize(decode(source[0]["value"])[0])        # computed here, not by the pipeline
        stored = w.rows[0]["event"]
        assert isinstance(stored, CanonicalSpanEvent)
        assert stored.model_dump(mode="json") == independent.model_dump(mode="json")
        assert (stored.request_id, stored.session_id, stored.agent_name, stored.tool_name) == (
            "req-1", "sess-1", "planner", "search")
        assert (stored.retrieval_result_count, stored.retrieval_top_relevance_score) == (3, 0.5)
        assert stored.service_name == "svc" and stored.duration_ms == 1000.0

    def test_the_topic_message_is_what_the_storage_consumer_validates(self, make_world):
        w = converge(make_world([REC(P(0))]))
        body = json.loads(w.topic[0]["value"])
        assert CanonicalSpanEvent.model_validate(body).model_dump(mode="json") == body
        assert body["trace_id"] == TRACE and body["span_id"] == span_id(0)


# ===========================================================================
# 2. Single-fault sweeps
# ===========================================================================

AT_SP = (0, 1, 3, 6)
AT_ST = (0, 1, 2, 4, 7)


class TestStreamProcessorFaultSweep:
    @pytest.mark.parametrize("source_name", sorted(SOURCES))
    @pytest.mark.parametrize("kind", SP_KINDS)
    @pytest.mark.parametrize("at", AT_SP)
    def test_converges_after_one_stream_processor_fault(self, make_world, source_name, kind, at):
        source = SOURCES[source_name]
        baseline = converge(make_world(source))
        assert_converged(baseline)
        calls = baseline.counters[("sp", 1, SP_SITE[kind])]

        w = converge(make_world(source, [SPF(kind, at)]), ("SP", "ST"))

        fired = [f for f in w.fired if f[0] == "sp"]
        assert bool(fired) == (at < calls)
        assert_converged(w)
        if fired and kind in TERMINAL["sp"]:
            assert len(w.runs["sp"]) == 2
            assert type(exc_of(w, "sp", 1)) is EXPECTED_SP_EXCEPTION[kind]
        else:
            assert len(w.runs["sp"]) == 1


class TestStorageFaultSweep:
    @pytest.mark.parametrize("source_name", ["plain", "multi"])
    @pytest.mark.parametrize("kind", ST_KINDS)
    @pytest.mark.parametrize("at", AT_ST)
    def test_converges_after_one_storage_fault(self, make_world, source_name, kind, at):
        source = SOURCES[source_name]
        baseline = converge(make_world(source))
        calls = baseline.counters[("st", 1, ST_SITE[kind])]

        w = converge(make_world(source, [STF(kind, at)]))

        assert bool(w.fired) == (at < calls)
        assert_converged(w)
        if w.fired:
            assert len(w.runs["st"]) == 2 and len(w.runs["sp"]) == 1
            assert type(exc_of(w, "st", 1)) is EXPECTED_ST_EXCEPTION[kind]
            assert topic_copies(w) == topic_copies(baseline)          # a storage fault never touches the topic


# ===========================================================================
# 3. Stream-processor failures, observed through the storage consumer
# ===========================================================================

class TestStreamProcessorFailures:
    def test_failure_before_publication_leaves_a_consistent_prefix_that_storage_persists(self, make_world):
        w = make_world(PLAIN, [SPF("error_nonretriable", 2)])
        run_sp(w)
        assert isinstance(exc_of(w, "sp", 1), PublishBrokerError)
        assert [e["ident"][1] for e in w.topic] == [span_id(0), span_id(1)]       # nothing from record 2
        assert w.committed["sp"] == 2
        run_st(w)
        assert set(rows_by_ident(w)) == {(TRACE, span_id(0)), (TRACE, span_id(1))} and w.committed["st"] == 2
        converge(w)
        assert_converged(w)
        assert (len(w.runs["sp"]), len(w.runs["st"])) == (2, 2)
        assert topic_copies(w) == {(TRACE, span_id(i)): 1 for i in range(5)}
        assert inserts(w, outcome="conflict") == []

    def test_partial_multi_span_publication_republishes_the_prefix_and_storage_rejects_the_repeats(self, make_world):
        w = make_world(MULTI, [SPF("error_nonretriable", 2)])       # third span of the first message
        run_sp(w)
        assert [e["ident"][1] for e in w.topic] == [span_id(0), span_id(1)]
        assert w.committed["sp"] == 0
        run_st(w)                                                    # storage persists the partial output
        converge(w)
        assert_converged(w)
        copies = topic_copies(w)
        assert copies[(TRACE, span_id(0))] == 2 and copies[(TRACE, span_id(1))] == 2
        assert copies[(TRACE, span_id(2))] == 1
        for i in (0, 1):                                             # the repeat hits the unique key
            ident = (TRACE, span_id(i))
            assert [o for _, _, _, o in inserts(w, ident)] == ["new", "conflict"]
            assert row_offset(w, i) == i                             # first copy's offset is kept
        assert len(w.rows) == len(expected_trusted(MULTI))

    def test_publish_acknowledged_but_source_commit_failed(self, make_world):
        w = converge(make_world(PLAIN, [SPF("commit_error", 2)]), ("SP", "ST"))
        assert_converged(w)
        assert w.committed_end["sp"][1] == 2 and polled(w, "sp", 2)[0] == 2
        assert topic_copies(w)[(TRACE, span_id(2))] == 2
        assert [o for _, _, _, o in inserts(w, (TRACE, span_id(2)))] == ["new", "conflict"]
        assert row_offset(w, 2) == 2

    def test_lost_source_commit_acknowledgement_does_not_replay(self, make_world):
        w = converge(make_world(PLAIN, [SPF("commit_ack_lost", 2)]), ("SP", "ST"))
        assert_converged(w)
        assert w.committed_end["sp"][1] == 3
        assert polled(w, "sp", 2) == [3, 4]                          # record 2 is not read again
        assert topic_copies(w) == {(TRACE, span_id(i)): 1 for i in range(5)}
        assert inserts(w, outcome="conflict") == []

    @pytest.mark.parametrize("mode, copies_of_s2", [("timeout_persisted", 2), ("timeout_lost", 1),
                                                     ("timeout_late", 2)])
    def test_ambiguous_canonical_publication(self, make_world, mode, copies_of_s2):
        w = make_world(PLAIN, [SPF(mode, 2)])
        run_sp(w)
        ident = (TRACE, span_id(2))
        assert isinstance(exc_of(w, "sp", 1), PublishTimeoutError)
        assert ident not in w.acked_in_run[1] or mode == "timeout_late"     # late: acked only during cleanup
        assert w.committed["sp"] == 2 and produce_calls(w, ident, 1) == 1    # no retry, no re-produce
        on_broker = any(e["ident"] == ident for e in w.topic)
        assert on_broker == (mode != "timeout_lost")
        run_st(w)                      # storage may persist what the publisher never saw acknowledged
        assert (w.first_row(ident) is not None) == on_broker
        converge(w)
        assert_converged(w)
        assert topic_copies(w)[ident] == copies_of_s2
        assert len([r for r in w.rows if r["ident"] == ident]) == 1


# ===========================================================================
# 4. Storage failures
# ===========================================================================

class TestStorageFailures:
    def test_transaction_failure_before_persistence_replays_the_message(self, make_world):
        w = converge(make_world(PLAIN, [STF("db_error", 2)]))
        assert_converged(w)
        assert isinstance(exc_of(w, "st", 1), RuntimeError) and w.committed_end["st"][1] == 2
        assert [r["ident"][1] for r in w.rows if r["run"] == 1] == [span_id(0), span_id(1)]
        assert len(w.runs["sp"]) == 1 and topic_copies(w) == {(TRACE, span_id(i)): 1 for i in range(5)}
        assert inserts(w, (TRACE, span_id(2)), "new")[0][0] == 2          # persisted by the second run

    def test_transaction_committed_but_the_caller_sees_an_exception(self, make_world):
        w = converge(make_world(PLAIN, [STF("db_ack_lost", 2)]))
        assert_converged(w)
        ident = (TRACE, span_id(2))
        assert w.first_row(ident)["run"] == 1                              # the row was there after run 1
        assert w.committed_end["st"][1] == 2                               # but the offset was not committed
        assert [(r, o) for r, _, _, o in inserts(w, ident)] == [(1, "new"), (2, "conflict")]
        assert row_offset(w, 2) == 2

    def test_destination_offset_commit_failure_replays_into_the_unique_key(self, make_world):
        w = converge(make_world(PLAIN, [STF("commit_error", 2)]))
        assert_converged(w)
        assert w.committed_end["st"][1] == 2 and polled(w, "st", 2)[0] == 2
        assert [o for _, _, _, o in inserts(w, (TRACE, span_id(2)))] == ["new", "conflict"]
        assert topic_copies(w) == {(TRACE, span_id(i)): 1 for i in range(5)}      # the topic is untouched
        assert len(w.rows) == 5

    def test_lost_destination_commit_acknowledgement_does_not_replay(self, make_world):
        w = converge(make_world(PLAIN, [STF("commit_ack_lost", 2)]))
        assert_converged(w)
        assert w.committed_end["st"][1] == 3
        assert polled(w, "st", 2) == [3, 4]                          # topic offset 2 is not read again
        assert inserts(w, outcome="conflict") == [] and len(inserts(w)) == 5

    def test_interruption_inside_the_transaction_persists_nothing(self, make_world):
        w = converge(make_world(PLAIN, [STF("db_interrupt", 2)]))
        assert_converged(w)
        assert isinstance(exc_of(w, "st", 1), SimulatedInterruption)
        assert w.first_row((TRACE, span_id(2)))["run"] == 2


# ===========================================================================
# 5. Restarts and upstream replay
# ===========================================================================

class TestRestartsAndReplays:
    def test_both_components_restart_with_cleared_state(self, make_world):
        w = make_world(PLAIN, [SPF("interrupt_after_persist", 3), STF("interrupt_before_commit", 1)])
        for comp in ("SP", "ST", "SP", "ST"):
            (run_sp if comp == "SP" else run_st)(w)
        converge(w)
        assert_converged(w)
        sp2 = w.runs["sp"][1]
        assert sp2.marked_at_start == set() and sp2.dedup is not w.runs["sp"][0].dedup
        assert w.committed_end["sp"][1] == 3                       # the interrupted record was not committed
        assert topic_copies(w)[(TRACE, span_id(3))] == 2           # persisted unacked, then replayed
        assert polled(w, "st", 2)[0] == w.committed_end["st"][1]   # storage resumed at its own offset
        assert w.committed_end["st"][1] == 1

    def test_duplicates_from_upstream_replay_never_become_rows(self, make_world):
        # DUP repeats S0 in a later record; a stream-processor restart empties its dedup, so S0 is
        # published twice while the same-process repeat is still suppressed.
        w = converge(make_world(DUP, [SPF("commit_error", 0)]), ("SP", "ST"))
        assert_converged(w)
        ident = (TRACE, span_id(0))
        assert topic_copies(w)[ident] == 2
        assert produce_calls(w, ident, 2) == 1                     # the repeat at record 2 skipped in run 2
        assert [o for _, _, _, o in inserts(w, ident)] == ["new", "conflict"]
        assert len([r for r in w.rows if r["ident"] == ident]) == 1

    def test_the_topic_may_carry_many_copies_and_the_first_one_wins(self, make_world):
        seed = [canonical_entry(0), canonical_entry(1), canonical_entry(0), canonical_entry(0)]
        w = converge(make_world([], topic_seed=seed))
        assert_storage_converged(w, {(TRACE, span_id(0)), (TRACE, span_id(1))})
        assert [o for _, _, _, o in inserts(w, (TRACE, span_id(0)))] == ["new", "conflict", "conflict"]
        assert row_offset(w, 0) == 0 and row_offset(w, 1) == 1 and len(w.rows) == 2


def assert_storage_converged(w, expected_idents):
    """For worlds seeded with a topic and no source: the expectations are the idents the seed carries."""
    ignored = ("missing rows", "unexpected rows", "published")
    problems = live_problems(w) + [p for p in convergence_problems(w) if not any(t in p for t in ignored)]
    assert not problems, "\n".join(problems)
    assert set(rows_by_ident(w)) == set(expected_idents)


# ===========================================================================
# 6. Sequential faults across both components
# ===========================================================================

class TestSequentialFaults:
    def test_a_hand_derived_schedule_across_both_components(self, make_world):
        # SP run1: S2 persisted but unacknowledged.  ST run1 persists S0..S2 then fails its commit of S1.
        w = make_world(PLAIN, [SPF("timeout_persisted", 2), STF("commit_error", 1)])
        run_sp(w)
        run_st(w)
        assert w.committed_end["sp"][1] == 2 and w.committed_end["st"][1] == 1
        assert [r["ident"][1] for r in w.rows] == [span_id(0), span_id(1)]        # then halted at commit 1
        converge(w)
        assert_converged(w)
        assert topic_copies(w)[(TRACE, span_id(2))] == 2
        assert [o for _, _, _, o in inserts(w, (TRACE, span_id(1)))] == ["new", "conflict"]
        assert (len(w.runs["sp"]), len(w.runs["st"])) == (2, 2)      # ST run 2 drains the replayed copy too

    @pytest.mark.parametrize("source_name", ["multi", "mixed"])
    @pytest.mark.parametrize("seed", range(40))
    def test_random_schedules_across_both_components_converge(self, make_world, source_name, seed):
        rng = random.Random(seed)
        faults = []
        for _ in range(rng.randint(2, 5)):
            comp = rng.choice(["sp", "st"])
            kind = rng.choice(SP_KINDS if comp == "sp" else ST_KINDS)
            faults.append((comp, kind, rng.randint(1, 3), rng.randint(0, 6)))
        schedule = rng.choice([(), ("SP", "ST"), ("ST", "SP", "ST"), ("SP", "ST", "SP", "ST")])
        w = converge(make_world(SOURCES[source_name], faults), schedule, max_pairs=14)
        assert_converged(w)


# ===========================================================================
# 7. DLQ failures
# ===========================================================================

class TestDlqFailures:
    BAD3 = (3, TRACE, span_id(3), "SCHEMA_VALIDATION_FAILURE")
    DECODE1 = (1, None, None, "OTLP_DECODE_FAILURE")

    def test_dlq_publish_failure_blocks_the_source_commit_and_leaves_storage_untouched(self, make_world):
        w = make_world(MIXED, [SPF("error_nonretriable", 1)])      # DLQ for the undecodable record
        run_sp(w)
        assert isinstance(exc_of(w, "sp", 1), PublishBrokerError) and w.committed["sp"] == 1
        assert w.persisted_dlq == []
        converge(w)
        assert_converged(w)
        assert dlq_copies(w) == {c: 1 for c in expected_dlq(MIXED)}
        assert set(rows_by_ident(w)) == expected_trusted(MIXED)        # DLQ events never reach storage

    def test_replay_duplicates_a_dlq_event_but_not_a_row(self, make_world):
        w = converge(make_world(MIXED, [SPF("error_nonretriable", 4)]), ("SP", "ST"))     # S4 fails after DLQ(3)
        assert_converged(w)
        assert dlq_copies(w)[self.BAD3] == 2
        assert topic_copies(w)[(TRACE, span_id(4))] == 1
        assert len(w.rows) == len(expected_trusted(MIXED))

    def test_ambiguous_dlq_timeout_duplicates_the_dlq_event(self, make_world):
        w = converge(make_world(MIXED, [SPF("timeout_persisted", 1)]), ("SP", "ST"))
        assert_converged(w)
        assert dlq_copies(w)[self.DECODE1] == 2

    def test_the_trusted_topic_carries_nothing_for_dlq_records(self, make_world):
        w = converge(make_world(MIXED))
        assert {e["ident"] for e in w.topic} == expected_trusted(MIXED)
        assert dlq_copies(w) == {c: 1 for c in expected_dlq(MIXED)}


# ===========================================================================
# 8. Poison messages: explicit, non-converging halts
# ===========================================================================

def _nan_duration_entry():
    body = json.loads(canonical_entry(7)["value"])
    return poison_entry(json.dumps(body).replace('"duration_ms": 1000.0', '"duration_ms": NaN').encode())


def _short_trace_entry():
    body = json.loads(canonical_entry(7)["value"])
    body["trace_id"] = "abc"
    return poison_entry(json.dumps(body).encode())


POISON = {
    "tombstone": (poison_entry(None), RuntimeError),
    "malformed_json": (poison_entry(b"{not json"), json.JSONDecodeError),
    "invalid_utf8": (poison_entry(b"\xff\xfe\xfd"), UnicodeDecodeError),
    "schema_invalid": (_short_trace_entry(), ValidationError),
    "nan_duration": (_nan_duration_entry(), ValidationError),
}


class TestPoisonMessages:
    @pytest.mark.parametrize("name", sorted(POISON))
    def test_a_poison_message_halts_storage_on_every_restart_and_nothing_behind_it_is_processed(
            self, make_world, name):
        entry, exc_type = POISON[name]
        seed = [canonical_entry(0), entry, canonical_entry(1)]
        w = converge(make_world([], topic_seed=seed), max_pairs=4)

        assert not w.converged
        assert len(w.runs["st"]) == 4
        assert all(type(r.exc) is exc_type or isinstance(r.exc, exc_type) for r in w.runs["st"])
        assert w.committed["st"] == 1                          # stuck on the poison offset
        assert set(rows_by_ident(w)) == {(TRACE, span_id(0))}  # the record behind it was never inserted
        assert not any(e[0] == "insert" and e[3] == 2 for e in w.events)
        assert polled(w, "st", 4) == [1]                       # every restart looks at the poison and stops
        assert live_problems(w) == []                          # and nothing was committed past it
        assert "did not converge" in " ".join(convergence_problems(w))

    def test_a_span_that_cannot_be_serialized_stops_the_stream_processor_and_never_reaches_the_topic(
            self, make_world, monkeypatch):
        poisoned = (TRACE, span_id(2))
        real = sp_proc.canonicalize

        def wrapped(span_dict):                   # a span the real decoder can never produce
            event = real(span_dict)
            if (event.trace_id, event.span_id) == poisoned:
                return CanonicalSpanEvent(**{**event.model_dump(), "attributes": {"o": object()}})
            return event

        monkeypatch.setattr(sp_proc, "canonicalize", wrapped)
        source = [REC(P(0)), REC(P(1)), REC(P(3), P(2)), REC(P(4))]
        w = converge(make_world(source), ("SP", "ST"), max_pairs=3)

        assert not w.converged
        assert len(w.runs["sp"]) == 4          # the scheduled run plus three rounds
        assert all(isinstance(r.exc, PublishSerializationError) for r in w.runs["sp"])
        assert w.committed["sp"] == 2 and w.persisted_dlq == []        # not converted into a DLQ event
        assert poisoned not in topic_copies(w) and (TRACE, span_id(4)) not in topic_copies(w)
        assert topic_copies(w)[(TRACE, span_id(3))] == 4               # the span ahead of it repeats on every restart
        assert set(rows_by_ident(w)) == {(TRACE, span_id(i)) for i in (0, 1, 3)}      # and is stored once
        assert live_problems(w) == []


# ===========================================================================
# 9. Schema boundary checks
# ===========================================================================

class TestSchemaBoundary:
    def test_valid_events_with_optional_fields_round_trip_losslessly(self, make_world):
        attrs = (("agentops.request_id", "s", "r"), ("error.type", "s", "Timeout"), ("x.count", "i", 7))
        w = converge(make_world([REC(P(0, attrs=attrs))]))
        assert_converged(w)
        event = w.rows[0]["event"]
        assert (event.request_id, event.error_type) == ("r", "Timeout")
        assert event.attributes == {"agentops.request_id": "r", "error.type": "Timeout", "x.count": 7}

    def test_non_finite_attribute_values_are_silently_turned_into_null(self, make_world):
        # Confirmed behaviour, not a crash: pydantic's JSON mode writes NaN / Infinity as null, so the
        # trusted topic is strict JSON, but the original value is lost.  A policy question, not a defect.
        attrs = (("x.nan", "d", float("nan")), ("x.inf", "d", float("inf")), ("x.ok", "d", 1.5))
        w = converge(make_world([REC(P(0, attrs=attrs))]))
        assert_converged(w)
        text = w.topic[0]["value"].decode()
        assert "NaN" not in text and "Infinity" not in text
        assert w.rows[0]["event"].attributes == {"x.nan": None, "x.inf": None, "x.ok": 1.5}

    def test_a_span_rejected_by_the_schema_goes_to_the_dlq_not_the_topic(self, make_world):
        for bad_attrs in ((("retrieval.result_count", "s", "many"),), (("retrieval.top_relevance_score", "d", 7.0),)):
            w = converge(make_world([REC(P(0, rejected=True, attrs=bad_attrs))]))
            assert_converged(w)
            assert w.topic == [] and len(w.rows) == 0
            assert dlq_copies(w) == {(0, TRACE, span_id(0), "SCHEMA_VALIDATION_FAILURE"): 1}

    def test_a_non_json_safe_attribute_is_a_serialization_failure_that_otlp_cannot_produce(self):
        # Invalid test input rather than a pipeline defect: the OTLP decoder only yields JSON-safe values
        # (bytes become hex).  Built directly to pin what the publisher does if it ever happened.
        event = canonicalize(decode(REC(P(0))["value"])[0])
        bad = CanonicalSpanEvent(**{**event.model_dump(), "attributes": {"o": object()}})
        world = World([])
        world.run["sp"] = 1
        publisher = KafkaPublisher(SpProducer(world), retries=0, timeout_seconds=1.0)
        with pytest.raises(PublishSerializationError):
            publisher.publish_span(bad)

    def test_ids_are_normalized_and_case_variants_collide_in_the_unique_key(self, make_world):
        lower = canonical_entry(5)
        upper_body = json.loads(lower["value"])
        upper_body["trace_id"], upper_body["span_id"] = TRACE.upper(), span_id(5).upper()
        upper = {**lower, "value": json.dumps(upper_body).encode()}
        w = converge(make_world([], topic_seed=[lower, upper]))
        assert_storage_converged(w, {(TRACE, span_id(5))})
        assert len(w.rows) == 1 and w.rows[0]["ident"] == (TRACE, span_id(5))
        assert [o for _, _, _, o in w.insert_log] == ["new", "conflict"]

    def test_a_nan_duration_is_rejected_and_an_infinite_one_is_accepted(self, make_world):
        # NaN is invalid input (poison, see above).  Infinity passes the schema's >= 0 check; whether the
        # database accepts it is not testable offline.  OTLP cannot produce either: duration is derived
        # from two datetimes.
        body = json.loads(canonical_entry(7)["value"])
        inf = poison_entry(json.dumps(body).replace('"duration_ms": 1000.0', '"duration_ms": Infinity').encode())
        inf["poison"], inf["ident"] = False, (body["trace_id"], body["span_id"])
        w = converge(make_world([], topic_seed=[inf]))
        assert w.converged and w.rows[0]["event"].duration_ms == float("inf")
        with pytest.raises(ValidationError):
            CanonicalSpanEvent.model_validate(json.loads(POISON["nan_duration"][0]["value"]))


# ===========================================================================
# 10. The harness itself: the checker must reject wrong implementations
# ===========================================================================

def sp_commit_before_process_loop(consumer, publisher, deduplicator, shutdown, poll_timeout_seconds=1.0):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            if msg.error() is not None:
                raise RuntimeError("consumer error")
            consumer.commit(message=msg, asynchronous=False)
            sp_proc.process_message(msg, publisher, deduplicator, msg.topic(), msg.partition(), msg.offset())
    finally:
        try:
            publisher.close()
        finally:
            consumer.close()


def st_commit_before_insert_loop(consumer, repository, shutdown, poll_timeout_seconds=1.0, **_):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            consumer.commit(message=msg, asynchronous=False)
            st_consumer.process_message(msg, repository)
    finally:
        consumer.close()


def st_swallow_and_continue_loop(consumer, repository, shutdown, poll_timeout_seconds=1.0, **_):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            try:
                st_consumer.process_message(msg, repository)
            except Exception:
                pass
            consumer.commit(message=msg, asynchronous=False)
    finally:
        consumer.close()


def st_never_commits_loop(consumer, repository, shutdown, poll_timeout_seconds=1.0, **_):
    try:
        while not shutdown.is_set():
            msg = consumer.poll(timeout=poll_timeout_seconds)
            if msg is None:
                continue
            st_consumer.process_message(msg, repository)
    finally:
        consumer.close()


def all_problems(w):
    return live_problems(w) + convergence_problems(w)


class TestTheHarnessItself:
    def test_a_fault_free_run_is_clean_and_has_the_expected_shape(self, make_world):
        w = converge(make_world(PLAIN))
        assert all_problems(w) == []
        assert (len(w.runs["sp"]), len(w.runs["st"])) == (1, 1)
        assert w.counters[("sp", 1, "produce")] == 5 and w.counters[("st", 1, "db")] == 5
        assert w.counters[("sp", 1, "commit")] == 5 and w.counters[("st", 1, "commit")] == 5

    def test_a_fault_beyond_the_reached_sites_never_fires(self, make_world):
        w = converge(make_world(PLAIN, [SPF("error_nonretriable", 99), STF("commit_error", 0, 5)]))
        assert w.fired == [] and all_problems(w) == []

    def test_expectations_come_from_the_specs_alone(self):
        assert expected_trusted(MIXED) == {(TRACE, span_id(i)) for i in (0, 4, 5, 7)}
        assert expected_dlq(MIXED) == {
            (1, None, None, "OTLP_DECODE_FAILURE"), (2, None, None, "OTLP_DECODE_FAILURE"),
            (3, TRACE, span_id(3), "SCHEMA_VALIDATION_FAILURE"),
            (4, TRACE, span_id(6), "SCHEMA_VALIDATION_FAILURE")}

    def test_tampered_output_is_reported(self, make_world):
        w = converge(make_world(PLAIN))
        w.rows.pop(2)
        w.rows.append({**w.rows[0], "offset": 99})
        text = " ".join(all_problems(w))
        assert "missing rows" in text and "duplicate rows" in text

    @pytest.mark.parametrize("at", range(5))
    def test_source_commit_before_publication_is_rejected(self, make_world, at):
        w = converge(make_world(PLAIN, [SPF("error_nonretriable", at)]), sp_loop=sp_commit_before_process_loop)
        problems = all_problems(w)
        assert any("source commit past unacknowledged" in p for p in problems)
        assert any("missing rows" in p for p in problems)             # and the span is really lost

    @pytest.mark.parametrize("at", range(5))
    def test_destination_commit_before_persistence_is_rejected(self, make_world, at):
        w = converge(make_world(PLAIN, [STF("db_error", at)]), st_loop=st_commit_before_insert_loop)
        problems = all_problems(w)
        assert any("destination commit past unpersisted" in p for p in problems)
        assert any("missing rows" in p for p in problems)

    @pytest.mark.parametrize("at", range(3))
    def test_skipping_a_poison_message_is_rejected(self, make_world, at):
        seed = [canonical_entry(0), poison_entry(b"{not json"), canonical_entry(1)]
        w = converge(make_world([], topic_seed=seed), st_loop=st_swallow_and_continue_loop)
        problems = all_problems(w)
        assert any("past poison" in p for p in problems)

    def test_duplicate_persistence_is_rejected(self, make_world):
        seed = [canonical_entry(0), canonical_entry(0)]
        w = converge(make_world([], topic_seed=seed, unique=False))
        assert len(w.rows) == 2
        assert any("duplicate rows" in p for p in convergence_problems(w))
        assert any("successful first inserts" in p for p in convergence_problems(w))

    def test_a_storage_loop_that_never_commits_is_rejected(self, make_world):
        w = converge(make_world(PLAIN), st_loop=st_never_commits_loop, max_pairs=2)
        assert any("final destination committed offset 0 != 5" in p for p in all_problems(w))

"""
workload-generator/run_shutdown_it.py

Validation harness for the graceful shutdown of the two containerized processing services
(stream processor and storage consumer; B3J-335 and B3J-337), on a separate, disposable
Compose project:

    host producer step -> Kafka raw topic -> stream processor (container)
        -> Kafka canonical topic -> storage consumer (container) -> PostgreSQL

It is INERT unless it is invoked, and it does nothing live unless it is invoked with both
--execute and the confirmation phrase.  This file was written and tested offline (B3J-339);
no live case has been run.

    python workload-generator/run_shutdown_it.py                      # prints the plan; touches nothing
    python workload-generator/run_shutdown_it.py --preflight --expect-head <40 hex>
                                                                       # read-only checks; no mutation
    python workload-generator/run_shutdown_it.py --execute --expect-head <40 hex> \
        --confirm CONFIRM-DISPOSABLE-SHUTDOWN-VALIDATION-<first 12 hex of the head>

What it validates (cases S1 to S4 are graceful stops; S5 and S6 are the destructive cases, opt-in via --cases)
    S1  idle graceful stop of both services: exit code, stop duration, restart count, the one
        shutdown diagnostic per service
    S2  stop of the stream processor while it is processing a known batch: no source offset is
        committed past a message whose spans are not all on the canonical topic; after a
        restart every expected canonical span is present
    S3  stop of the storage consumer while it is persisting a known backlog: no destination
        offset is committed past a canonical message whose row is not in PostgreSQL; after a
        restart every expected row is present, once
    S4  as S3 with the opt-in offset batching enabled (CONSUMER_COMMIT_BATCH_MESSAGES); it PASSes only if the
        effective batching configuration, the startup line and deferred-then-advancing commits were observed

    S5  forced termination: SIGKILL of the disposable project's storage consumer (batching on, restart policy "no")
        while it holds durable-but-uncommitted records; the frozen PostgreSQL and Kafka state predicts the replay
        per partition, and the restarted consumer's own counters (messages, conflicts, inserted) must match it

    S6  forced termination of the STREAM PROCESSOR (restart policy "no") while it holds published-but-uncommitted
        spans; the frozen state predicts the republication per source message, the canonical topic must then show
        exactly those identities twice (once before and once after the freeze), and the storage consumer (stopped until
        the end) must absorb exactly those duplicates through the unique key

Not here, deliberately: any other kill, repeated signals, broker stalls or any other fault
injection.  S5 is not part of the default case list.  A case whose stop (or kill) could not be issued
while the service was still working is INCONCLUSIVE, never PASS, and nothing is retried.

Isolation (the same conventions as run_pipeline_it.py and run_commit_batching_it.py)
    - exact branch, exact HEAD, empty index; a clean working tree except this file and its test
    - a unique project "agentops-shutdown-it-<8 hex>", never one that any Docker object carries
    - run_smoke's override unchanged (no fixed container names, loopback-only ports 19092 and
      15432), the pipeline overlay unchanged, and ONE extra override written to a temporary
      directory outside the repository: stop_grace_period 30s, consumer groups of this project
      and, for S4 only, the batching variables.  No production Compose file is modified.
    - throw-away random passwords in that temporary directory
    - refuses to start while a benchmark marker or process, a benchmark / pipeline / batching
      Docker object or an earlier unverified cleanup of this harness is present
    - the MVP containers and the legacy PostgreSQL are snapshotted before and compared after
    - fails closed when a gate cannot be measured

Cleanup is "compose down --volumes --remove-orphans" for this project only, without --rmi:
its own images are removed one by one by exact name when they carry its Compose label.
Nothing is pruned, and the inventory comparison only REPORTS (it never chooses deletions).
When cleanup cannot be verified, a blocking marker is written and the diagnostics are kept.

Test-data contract (source: stream-processor/processor.py, otlp_decoder.py, collector config)
    topic     agentops.telemetry.otlp.traces
    key       the 16 trace-id bytes (the collector's partition_traces_by_id)
    value     a serialized ExportTraceServiceRequest, one trace per message, no headers
    ids       deterministic, see IDS_SOURCE: trace = batch + message index, span = index + k
The producer runs inside the project's own stream-processor image (it has confluent_kafka and
opentelemetry-proto), so the host needs neither.  Duplicates and replays are told apart from
missing data by comparing canonical copies per (trace, span) with the expected set.

Evidence (schema "run_shutdown_it.evidence/1")
    Two structured JSON files per live run, written outside the repository and outside the benchmark
    evidence directories (default: <system temp>/agentops-shutdown-it-evidence/), never overwritten, each
    with a unique timestamped name and with every credential masked:
      ...-pre-cleanup.json  written BEFORE the disposable containers are removed: the project, the git head,
                            the selected cases, the grace period, and for every stopped service its exit code,
                            status, restart counts, OOM flag, stop timing, diagnostic counts, the relevant log
                            lines, every assertion and any missing observation
      ...-final.json        written after cleanup: the same results plus the cleanup verification, the
                            before/after inventory fingerprints, the protected-resource comparison, the
                            overall verdict, and the name and SHA-256 of the pre-cleanup file
    A run whose evidence cannot be written is never reported as PASS.

    When a run aborts, the evidence also holds "diagnostics": the failed tool reads (purpose, exit status,
    poll attempts, elapsed time, classification, bounded redacted stdout/stderr excerpts) and a read-only
    snapshot of the stream processor (container state, bounded redacted log tail), taken before the teardown.
    A description of a consumer group is classified as committed-offsets, formed-no-committed-offsets,
    group-absent, cli-failure, no-rows, partitions-incomplete or malformed; an uncommitted offset is None and
    is never presented as an observed 0.

Exit codes: 0 only when every selected case PASSED, cleanup was verified and the evidence was written; 1
otherwise; 2 for a refused invocation.  Standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_commit_batching_it as batching  # noqa: E402 - gates and protected-resource guards, unchanged
import run_pipeline_it as pipeline  # noqa: E402 - safe_cleanup and power helpers, unchanged
import run_smoke as smoke  # noqa: E402
from run_smoke import SmokeFailure, say, section  # noqa: E402

PROJECT_PREFIX: str = "agentops-shutdown-it-"
_PROJECT_RE = re.compile(re.escape(PROJECT_PREFIX) + r"[0-9a-f]{8}")
EXPECTED_BRANCH: str = "claude/compassionate-noether-7peel4"
OWN_FILES: tuple[str, ...] = (
    "workload-generator/run_shutdown_it.py",
    "workload-generator/tests/unit/test_shutdown_it.py",
)
OVERLAY_FILE: str = "docker/compose.pipeline.yml"
STOP_GRACE: str = "30s"
APP_SERVICES: tuple[str, ...] = ("stream-processor", "storage-consumer")
INFRA_SERVICES: tuple[str, ...] = ("kafka", "kafka-init", "postgres", "db-bootstrap")
CASES: tuple[str, ...] = ("S1", "S2", "S3", "S4")                 # the graceful cases; the default selection
ALL_CASES: tuple[str, ...] = (*CASES, "S5", "S6")                 # S5 and S6 (forced termination) must be asked for by name

#: Containers and name prefixes that must be left exactly as they are.
PROTECTED_CONTAINERS: tuple[str, ...] = (*batching.MVP_CONTAINERS, batching.LEGACY_POSTGRES)
PROTECTED_TOKENS: tuple[str, ...] = (
    "agentops-mvp", batching.LEGACY_POSTGRES, batching.BENCHMARK_PROJECT,
    batching.PIPELINE_IT_PREFIX, "agentops-batching-it-",
)

MIN_HOST_MEMORY_MIB: int = 4096
MIN_ENGINE_BYTES: int = batching.MIN_ENGINE_BYTES            # 3.5 GiB
MIN_DISK_GIB: int = batching.MIN_DISK_GIB                    # 10 GiB
PORTS: tuple[int, ...] = (smoke.KAFKA_PORT, smoke.POSTGRES_PORT)

CONFIRM_PREFIX: str = "CONFIRM-DISPOSABLE-SHUTDOWN-VALIDATION-"
_LABEL_PROJECT = "com.docker.compose.project"

# ---------------------------------------------------------------------------
# The source-topic contract
# ---------------------------------------------------------------------------

SOURCE_TOPIC: str = smoke.TOPIC_RAW
CANONICAL_TOPIC: str = smoke.TOPIC_SPANS
BROKER: str = smoke.BROKER_INTERNAL
SPANS_PER_MESSAGE: int = 3
CASE_BATCH: Mapping[str, int] = {"S2": 1, "S3": 2, "S4": 3, "S5": 4, "S6": 5}

#: The S4 batching configuration: the override file is written from these, and the effective container
#: environment and the startup line are verified against the same values.
BATCH_ENV_NAME: str = "CONSUMER_COMMIT_BATCH_MESSAGES"
INTERVAL_ENV_NAME: str = "CONSUMER_COMMIT_INTERVAL_SECONDS"
BATCH_INTERVAL_SECONDS: str = "30"
#: What storage-consumer/main.py prints when OffsetBatcher is active.
BATCHING_STARTUP_RE = re.compile(r"^\s*commit\s*:\s*batches of up to (\d+) messages, about every ([0-9]+(?:\.[0-9]+)?) s\s*$")
#: The existing opt-in timing instrumentation (storage-consumer/timing.py), enabled only in the disposable S4
#: override.  Its summary lines carry the consumer's own message and commit counts.
TIMING_ENV_NAME: str = "CONSUMER_TIMING_INTERVAL_SECONDS"
TIMING_INTERVAL_SECONDS: str = "30"
TIMING_LINE_PREFIX: str = "storage-consumer timing "         # timing.LINE_PREFIX (a test compares the two)
TIMING_LINE_LIMIT: int = 20000
#: A batching consumer must show at least this fraction of the batch size as messages per commit call.  Every
#: count-triggered commit covers at least one full batch, so a quarter leaves ample room for the commits that are
#: not count-triggered; a per-message consumer shows exactly 1.
BATCH_EFFICIENCY_MIN_FRACTION: float = 0.25
EVIDENCE_SAMPLE_LIMIT: int = 200

#: The single definition of the deterministic identifiers.  The host executes it for its own
#: expectations and the producer script embeds the same text, so the two cannot drift apart.
IDS_SOURCE: str = '''\
def trace_hex(batch, index):
    return format(batch, "04x") + format(index, "028x")


def span_hex(index, k):
    return format(index, "012x") + format(k + 1, "04x")
'''
_ids: dict[str, Any] = {}
exec(IDS_SOURCE, _ids)                                       # noqa: S102 - our own constant
trace_hex: Callable[[int, int], str] = _ids["trace_hex"]
span_hex: Callable[[int, int], str] = _ids["span_hex"]

#: Run inside the project's stream-processor image as:  python -c <PRODUCER_SOURCE> batch count spans
PRODUCER_SOURCE: str = IDS_SOURCE + '''
import json
import sys

from confluent_kafka import Producer
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span, Status

batch, count, spans = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
START, END = 1700000000000000000, 1700000001000000000
producer = Producer({"bootstrap.servers": "''' + BROKER + '''", "acks": "all", "enable.idempotence": True})
acks, errors = {}, []


def delivered(err, msg):
    if err is not None:
        errors.append(str(err))
    else:
        acks[int(msg.key().hex()[4:], 16)] = [msg.partition(), msg.offset()]


for index in range(count):
    trace = bytes.fromhex(trace_hex(batch, index))
    items = [Span(trace_id=trace, span_id=bytes.fromhex(span_hex(index, k)), name="shutdown.it", kind=1,
                  start_time_unix_nano=START, end_time_unix_nano=END, status=Status(code=1))
             for k in range(spans)]
    resource = Resource(attributes=[KeyValue(key="service.name", value=AnyValue(string_value="shutdown-it"))])
    request = ExportTraceServiceRequest(resource_spans=[
        ResourceSpans(resource=resource, scope_spans=[ScopeSpans(spans=items)])])
    while True:
        try:
            producer.produce("''' + SOURCE_TOPIC + '''", key=trace, value=request.SerializeToString(),
                             on_delivery=delivered)
            break
        except BufferError:
            producer.poll(0.2)
    producer.poll(0)
remaining = producer.flush(60)
print(json.dumps({"acks": acks, "errors": errors, "unflushed": remaining}))
sys.exit(1 if errors or remaining else 0)
'''


#: The message-size limits the harness relies on (nothing in Compose or in the topic creation overrides them): the
#: producer's `message.max.bytes` default and the broker's/topic's default `message.max.bytes`/`max.message.bytes`.
PRODUCER_MESSAGE_MAX_BYTES: int = 1_000_000
BROKER_MESSAGE_MAX_BYTES: int = 1_048_588
#: One produced span is at most this many bytes on the wire (trace id 18, span id 10, name 13, kind 2, two fixed64 times
#: 18, status 4, plus its own tag and length = 67), with a margin; a message adds a small fixed envelope.
SPAN_WIRE_BYTES_MAX: int = 70
MESSAGE_ENVELOPE_BYTES_MAX: int = 128


def source_message_size_bound(spans: int) -> int:
    """An upper bound of the serialized OTLP request the producer step sends for one message of `spans` spans."""
    return spans * SPAN_WIRE_BYTES_MAX + MESSAGE_ENVELOPE_BYTES_MAX


def source_message_fits(spans: int) -> bool:
    return source_message_size_bound(spans) < min(PRODUCER_MESSAGE_MAX_BYTES, BROKER_MESSAGE_MAX_BYTES)


def expected_spans(batch: int, count: int, spans: int = SPANS_PER_MESSAGE) -> set[tuple[str, str]]:
    return {(trace_hex(batch, i), span_hex(i, k)) for i in range(count) for k in range(spans)}


@dataclasses.dataclass(frozen=True)
class Produced:
    """One batch of source messages and where each landed."""
    batch: int
    count: int
    spans: int
    acks: Mapping[int, tuple[int, int]]            # message index -> (partition, offset)

    def expected(self) -> set[tuple[str, str]]:
        return expected_spans(self.batch, self.count, self.spans)

    def message_spans(self, index: int) -> set[tuple[str, str]]:
        return {(trace_hex(self.batch, index), span_hex(index, k)) for k in range(self.spans)}


def parse_producer_output(text: str, batch: int, count: int, spans: int) -> Produced:
    """Fails closed: every message must be acknowledged exactly once, with no error."""
    line = next((l for l in reversed(text.strip().splitlines()) if l.lstrip().startswith("{")), "")
    try:
        body = json.loads(line)
        acks = {int(k): (int(v[0]), int(v[1])) for k, v in body["acks"].items()}
        errors, unflushed = body["errors"], body["unflushed"]
    except (ValueError, KeyError, TypeError, IndexError):
        raise SmokeFailure("the producer step printed no usable result") from None
    if errors or unflushed:
        raise SmokeFailure(f"the producer step reported errors={errors!r} unflushed={unflushed!r}")
    if set(acks) != set(range(count)):
        raise SmokeFailure(f"the producer acknowledged {len(acks)} of {count} messages")
    return Produced(batch, count, spans, acks)


# ---------------------------------------------------------------------------
# Parsers of the tools' output (all fail closed)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class GroupPartition:
    current: Optional[int]
    log_end: Optional[int]


#: What one description of a consumer group can turn out to be.  Only the first two are usable.
GROUP_COMMITTED = "committed-offsets"                    # all partitions listed, at least one offset committed
GROUP_FORMED_NO_COMMIT = "formed-no-committed-offsets"   # all partitions listed, nothing committed yet
GROUP_ABSENT = "group-absent"                            # the tool says the group does not exist (not yet formed)
GROUP_CLI_FAILURE = "cli-failure"                        # the tool exited non-zero and listed nothing usable
GROUP_NO_ROWS = "no-rows"                                # exit 0, but no row of this group on this topic
GROUP_INCOMPLETE = "partitions-incomplete"               # some, not all, partitions listed (e.g. a rebalance)
GROUP_MALFORMED = "malformed"                            # a row of this group that cannot be read, or too many rows
GROUP_NO_ACTIVE_MEMBERS = "no-active-members"            # the tool says so: only partitions with a commit are listed
USABLE_GROUP_CLASSES = (GROUP_COMMITTED, GROUP_FORMED_NO_COMMIT)


def listed_rows(stdout: str, group: str, topic: str) -> tuple[dict[int, "GroupPartition"], bool]:
    """The rows of this group on this topic exactly as printed, and whether any row of the group could not
    be read.  '-' (nothing committed) is kept as None, never as 0."""
    header: Optional[list[str]] = None
    rows: dict[int, GroupPartition] = {}
    malformed = False

    def number(value: str) -> Optional[int]:
        return None if value == "-" else int(value)
    for line in stdout.splitlines():
        cells = line.split()
        if cells[:1] == ["GROUP"]:
            header = cells
        elif header and cells and cells[0] == group:
            if len(cells) != len(header):
                malformed = True
                continue
            row = dict(zip(header, cells))
            if row.get("TOPIC") != topic:
                continue
            try:
                rows[int(row["PARTITION"])] = GroupPartition(number(row["CURRENT-OFFSET"]), number(row["LOG-END-OFFSET"]))
            except (KeyError, ValueError):
                malformed = True
    return rows, malformed


def classify_group_output(stdout: str, stderr: str, returncode: Optional[int], group: str, topic: str,
                          partitions: int = smoke.PARTITIONS) -> tuple[str, Optional[dict[int, "GroupPartition"]]]:
    """Classifies ONE kafka-consumer-groups --describe result.  Returns (classification, rows); rows are
    returned only for a usable classification.  '-' (nothing committed) is kept as None, never as 0.
    'no-active-members' (the tool's own message, with some partitions not listed) is NOT usable here: a
    partition missing from such a listing is not, by itself, known to be uncommitted."""
    rows, malformed = listed_rows(stdout, group, topic)
    if malformed or len(rows) > partitions:
        return GROUP_MALFORMED, None
    if len(rows) == partitions:
        return (GROUP_FORMED_NO_COMMIT if all(r.current is None for r in rows.values()) else GROUP_COMMITTED), rows
    if "does not exist" in stdout + stderr:
        return GROUP_ABSENT, None
    if "has no active members" in stdout + stderr and returncode in (0, None):
        return GROUP_NO_ACTIVE_MEMBERS, None
    if returncode not in (0, None):
        return GROUP_CLI_FAILURE, None
    return (GROUP_INCOMPLETE if rows else GROUP_NO_ROWS), None


def parse_group_offsets(text: str, group: str, topic: str,
                        partitions: int = smoke.PARTITIONS) -> Optional[dict[int, "GroupPartition"]]:
    """Per-partition committed and log-end offsets from kafka-consumer-groups --describe, or None
    when the group has no stable description yet.  '-' (nothing committed) becomes None."""
    classification, rows = classify_group_output(text, "", 0, group, topic, partitions)
    return rows if classification in USABLE_GROUP_CLASSES else None


def partitions_without_commit(groups: Mapping[int, "GroupPartition"]) -> list[int]:
    """The partitions whose committed offset is unknown/absent.  The progress arithmetic counts these as
    'no progress'; this makes that choice visible in the evidence instead of silent."""
    return sorted(partition for partition, row in groups.items() if row.current is None)


def bounded_excerpt(text: str, limit: int = 400) -> str:
    """Redacted and bounded: the start and the end are kept, the middle is replaced by a count."""
    text = redact_text((text or "").strip())
    if len(text) <= limit:
        return text
    head, tail = text[: limit * 2 // 3], text[-(limit // 3):]
    return f"{head} ...[{len(text) - len(head) - len(tail)} chars omitted]... {tail}"


@dataclasses.dataclass
class ToolRead:
    """What a failed read of a Kafka tool looked like (no credentials, bounded)."""
    purpose: str
    attempts: int
    elapsed_seconds: float
    returncode: Optional[int]
    classification: str
    group_state: str                                     # 'absent', 'present' or 'unknown'
    stdout_excerpt: str
    stderr_excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class GroupReadError(SmokeFailure):
    """The consumer-group description never became usable; .read says what the tool printed."""

    def __init__(self, message: str, read: ToolRead) -> None:
        super().__init__(message)
        self.read = read


# ---------------------------------------------------------------------------
# After a stop: committed offsets from Kafka's own per-partition answer
# ---------------------------------------------------------------------------
#
# While a consumer runs, the strict description above (every partition listed) is right.  Once it has stopped,
# the group has no active members and kafka-consumer-groups lists ONLY the partitions that have a committed
# offset; a partition missing from that listing is not, by the CLI alone, known to be uncommitted (it might
# also be a partition the tool failed to list).  So after a stop the committed offsets are asked of Kafka for
# each partition of the topic by name (OffsetFetch through Consumer.committed), which answers a number, "no
# commit" (OFFSET_INVALID) or an error per partition, and the CLI listing is only a cross-check that must agree.

OFFSET_INVALID: int = -1001                              # librdkafka: this partition has no committed offset

#: Run inside the project's stream-processor image as:  python -c <COMMITTED_SOURCE> group topic
#: It subscribes to nothing, assigns nothing and commits nothing: it asks, then closes.
COMMITTED_SOURCE: str = '''
import json
import sys

from confluent_kafka import Consumer, TopicPartition

group, topic = sys.argv[1], sys.argv[2]
consumer = Consumer({"bootstrap.servers": "''' + BROKER + '''", "group.id": group, "enable.auto.commit": False,
                     "enable.auto.offset.store": False})
out = {"group": group, "topic": topic, "partitions": {}, "errors": []}
try:
    entry = consumer.list_topics(topic, timeout=20).topics.get(topic)
    if entry is None or entry.error is not None:
        out["errors"].append("topic metadata unavailable: %r" % (entry.error if entry is not None else "absent"))
    else:
        wanted = [TopicPartition(topic, p) for p in sorted(entry.partitions)]
        for answer in consumer.committed(wanted, timeout=20):
            low, high = consumer.get_watermark_offsets(TopicPartition(topic, answer.partition), timeout=20, cached=False)
            out["partitions"][str(answer.partition)] = {
                "offset": answer.offset, "error": str(answer.error) if answer.error is not None else None,
                "low": low, "high": high}
except Exception as exc:
    out["errors"].append("%s: %s" % (type(exc).__name__, exc))
finally:
    consumer.close()
print(json.dumps(out))
sys.exit(1 if out["errors"] else 0)
'''


class PostStopError(SmokeFailure):
    """The committed offsets after a stop could not be established; nothing is guessed."""

    def __init__(self, message: str, detail: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.detail = dict(detail or {})


class PostStopConflict(PostStopError):
    """Kafka's per-partition answer and the CLI listing disagree."""


@dataclasses.dataclass(frozen=True)
class PartitionCommit:
    state: str                    # 'committed' (a number) or 'uncommitted' (Kafka says there is none)
    offset: Optional[int]         # the committed offset, None when uncommitted
    low: int
    high: int                     # the end offset of the topic partition (never a committed offset)


@dataclasses.dataclass
class PostStopOffsets:
    """The committed offsets after a stop, with how they were established."""
    groups: dict[int, "GroupPartition"]
    commits: dict[int, PartitionCommit]
    corroboration: dict[str, Any]
    source: str = "Consumer.committed() per partition"

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "corroboration": self.corroboration,
                "partitions": {str(p): dataclasses.asdict(c) for p, c in sorted(self.commits.items())}}


def parse_committed_output(text: str, expected_partitions: int = smoke.PARTITIONS) -> dict[int, PartitionCommit]:
    """Strict reader of COMMITTED_SOURCE's output.  Anything that is not an exact, consistent answer for every
    partition of the topic raises PostStopError: an error, a different partition set, an ambiguous offset
    code, a commit beyond the end of the partition, unreadable JSON."""
    line = next((l for l in reversed((text or "").strip().splitlines()) if l.lstrip().startswith("{")), "")
    try:
        body = json.loads(line)
        errors, rows = body["errors"], body["partitions"]
    except (ValueError, KeyError, TypeError):
        raise PostStopError("the committed-offset step printed no usable result",
                            {"stdout": bounded_excerpt(text)}) from None
    if errors:
        raise PostStopError("the committed-offset step reported errors: " + bounded_excerpt("; ".join(map(str, errors)), 300))
    try:
        found = {int(key): value for key, value in rows.items()}
    except (ValueError, AttributeError):
        raise PostStopError("the committed-offset step listed unreadable partition numbers") from None
    if set(found) != set(range(expected_partitions)):
        raise PostStopError(f"topic partition-set mismatch: Kafka reports {sorted(found)}, expected "
                            f"{list(range(expected_partitions))}")
    commits: dict[int, PartitionCommit] = {}
    for partition, row in sorted(found.items()):
        try:
            offset, low, high, error = row["offset"], row["low"], row["high"], row.get("error")
        except (KeyError, AttributeError, TypeError):
            raise PostStopError(f"partition {partition}: unreadable answer") from None
        if error is not None:
            raise PostStopError(f"partition {partition}: Kafka returned an error instead of an offset: "
                                + bounded_excerpt(str(error), 200))
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (offset, low, high)) or high < low:
            raise PostStopError(f"partition {partition}: inconsistent offsets offset={offset!r} low={low!r} high={high!r}")
        if offset == OFFSET_INVALID:
            commits[partition] = PartitionCommit("uncommitted", None, low, high)
        elif offset >= 0:
            if offset > high:
                raise PostStopError(f"partition {partition}: committed offset {offset} is beyond the end offset {high}")
            commits[partition] = PartitionCommit("committed", offset, low, high)
        else:
            raise PostStopError(f"partition {partition}: ambiguous offset code {offset}")
    return commits


def corroborate_with_cli(stdout: str, stderr: str, returncode: Optional[int], group: str, topic: str,
                         commits: Mapping[int, PartitionCommit]) -> dict[str, Any]:
    """Compares the CLI listing with Kafka's per-partition answers.  A listed row must agree with the answer; a
    partition the CLI does not list must be one Kafka says is uncommitted.  Any disagreement raises
    PostStopConflict.  A CLI result that cannot be read is recorded as 'unavailable', not as agreement."""
    classification, _ = classify_group_output(stdout, stderr, returncode, group, topic, len(commits))
    rows, malformed = listed_rows(stdout, group, topic)
    summary: dict[str, Any] = {"cli_classification": classification, "listed_partitions": sorted(rows),
                               "unlisted_partitions": sorted(set(commits) - set(rows)), "exit_status": returncode}
    if malformed or classification in (GROUP_CLI_FAILURE, GROUP_MALFORMED):
        summary["agreement"] = "unavailable"
        summary["cli_stdout"], summary["cli_stderr"] = bounded_excerpt(stdout), bounded_excerpt(stderr)
        return summary
    problems = []
    for partition, row in sorted(rows.items()):
        known = commits.get(partition)
        if known is None:
            problems.append(f"the CLI lists partition {partition}, which Kafka does not report for the topic")
        elif row.current != known.offset:
            problems.append(f"partition {partition}: CLI shows {row.current!r}, Kafka answers {known.offset!r}")
    for partition in sorted(set(commits) - set(rows)):
        if commits[partition].state == "committed":
            problems.append(f"partition {partition}: Kafka answers committed offset {commits[partition].offset}, "
                            "but the CLI does not list it")
    if problems:
        raise PostStopConflict("the CLI listing and Kafka's per-partition answers disagree: " + "; ".join(problems), summary)
    summary["agreement"] = "agreed"
    return summary


@dataclasses.dataclass(frozen=True)
class Canonical:
    partition: int
    offset: int
    trace: str
    span: str


_CANONICAL_LINE = re.compile(r"^Partition:(\d+)\s+Offset:(\d+)\s+(\{.*\})\s*$")


def parse_canonical_records(text: str) -> list[Canonical]:
    """kafka-console-consumer output with print.partition and print.offset.  A line that is neither a
    record nor the tool's own summary is an error: the harness never guesses."""
    records = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("Processed a total of"):
            continue
        match = _CANONICAL_LINE.match(line)
        if not match:
            raise SmokeFailure(f"unparsable canonical-topic line: {line[:120]!r}")
        try:
            body = json.loads(match.group(3))
            records.append(Canonical(int(match.group(1)), int(match.group(2)),
                                     str(body["trace_id"]), str(body["span_id"])))
        except (ValueError, KeyError):
            raise SmokeFailure(f"unusable canonical record: {line[:120]!r}") from None
    return records


@dataclasses.dataclass(frozen=True)
class Row:
    trace: str
    span: str
    partition: int
    offset: int


def parse_rows(text: str) -> list[Row]:
    """psql -At output of: trace_id|span_id|kafka_partition|kafka_offset."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        cells = line.strip().split("|")
        if len(cells) != 4:
            raise SmokeFailure(f"unparsable row: {line[:120]!r}")
        try:
            rows.append(Row(cells[0], cells[1], int(cells[2]), int(cells[3])))
        except ValueError:
            raise SmokeFailure(f"unparsable row: {line[:120]!r}") from None
    return rows


@dataclasses.dataclass(frozen=True)
class Inspect:
    status: str
    exit_code: int
    restarts: int
    oom_killed: bool


def parse_inspect(text: str) -> Inspect:
    cells = text.strip().split("|")
    if len(cells) != 4:
        raise SmokeFailure(f"unparsable docker inspect output: {text.strip()[:120]!r}")
    try:
        return Inspect(cells[0], int(cells[1]), int(cells[2]), cells[3].strip().lower() == "true")
    except ValueError:
        raise SmokeFailure(f"unparsable docker inspect output: {text.strip()[:120]!r}") from None


INSPECT_FORMAT: str = "{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}|{{.State.OOMKilled}}"
FIRST_SIGNAL_MARKER: str = "received; finishing the current message, then shutting down"
GRACEFUL_MARKER: str = "stopped (shutdown requested)"


def diagnostic_counts(logs: str) -> tuple[int, int]:
    """(first-signal diagnostics, graceful-stop lines) in a service log."""
    return (sum(1 for line in logs.splitlines() if FIRST_SIGNAL_MARKER in line),
            sum(1 for line in logs.splitlines() if GRACEFUL_MARKER in line))


# ---------------------------------------------------------------------------
# Safety assertions: offsets versus durability, and replay accounting
# ---------------------------------------------------------------------------

def committed_offsets(groups: Mapping[int, GroupPartition]) -> dict[int, Optional[int]]:
    return {partition: row.current for partition, row in groups.items()}


def committed_total(groups: Mapping[int, GroupPartition]) -> int:
    return sum(row.current or 0 for row in groups.values())


def log_end_total(groups: Mapping[int, GroupPartition]) -> int:
    return sum(row.log_end or 0 for row in groups.values())


def source_commit_problems(batch: Produced, committed: Mapping[int, Optional[int]],
                           canonical: Sequence[Canonical]) -> list[str]:
    """A source offset may be committed only past messages whose spans are ALL on the canonical topic."""
    present = {(record.trace, record.span) for record in canonical}
    problems = []
    for index in sorted(batch.acks):
        partition, offset = batch.acks[index]
        limit = committed.get(partition)
        if limit is not None and offset < limit:
            missing = sorted(batch.message_spans(index) - present)
            if missing:
                problems.append(f"source partition {partition} is committed to {limit}, past message "
                                f"{index} (offset {offset}) whose {len(missing)} span(s) are not on the "
                                "canonical topic")
    return problems


def storage_commit_problems(canonical: Sequence[Canonical], committed: Mapping[int, Optional[int]],
                            rows: Sequence[Row]) -> list[str]:
    """A destination offset may be committed only past canonical messages whose row is in PostgreSQL."""
    persisted = {(row.trace, row.span) for row in rows}
    problems = []
    for record in canonical:
        limit = committed.get(record.partition)
        if limit is not None and record.offset < limit and (record.trace, record.span) not in persisted:
            problems.append(f"canonical partition {record.partition} is committed to {limit}, past offset "
                            f"{record.offset} whose span {record.span} has no row")
    return problems


@dataclasses.dataclass(frozen=True)
class Accounting:
    missing: int                 # expected and absent
    unexpected: int              # present and not expected
    duplicate_copies: int        # extra copies beyond the first, per (trace, span)
    detail: tuple[str, ...]


def account_canonical(expected: set[tuple[str, str]], canonical: Sequence[Canonical]) -> Accounting:
    """Replay (duplicates) versus loss (missing) on the canonical topic."""
    copies = Counter((record.trace, record.span) for record in canonical)
    missing = expected - set(copies)
    unexpected = set(copies) - expected
    duplicates = sum(n - 1 for ident, n in copies.items() if ident in expected and n > 1)
    detail = tuple(sorted(f"missing {t}/{s}" for t, s in missing)[:5])
    return Accounting(len(missing), len(unexpected), duplicates, detail)


def account_rows(expected: set[tuple[str, str]], rows: Sequence[Row]) -> Accounting:
    """Rows must be exactly the expected set, each once: the unique key makes duplicates impossible,
    so any duplicate here means the constraint is not the one assumed."""
    copies = Counter((row.trace, row.span) for row in rows)
    missing = expected - set(copies)
    unexpected = set(copies) - expected
    duplicates = sum(n - 1 for n in copies.values() if n > 1)
    detail = tuple(sorted(f"missing {t}/{s}" for t, s in missing)[:5])
    return Accounting(len(missing), len(unexpected), duplicates, detail)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Case:
    name: str
    verdict: str                                  # PASS, FAIL or INCONCLUSIVE
    problems: list[str] = dataclasses.field(default_factory=list)
    metrics: dict[str, Any] = dataclasses.field(default_factory=dict)
    stops: list["ServiceStop"] = dataclasses.field(default_factory=list)
    observations: dict[str, Any] = dataclasses.field(default_factory=dict)   # only what was actually collected
    partial: bool = False                                                     # the case was aborted by an exception

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "verdict": self.verdict, "problems": list(self.problems),
                "metrics": dict(self.metrics), "stops": [stop.to_dict() for stop in self.stops],
                "observations": dict(self.observations), "partial": self.partial}


def begin_case(env: Any, name: str) -> Case:
    """A new case, also published on the environment so that, if the case is aborted by an exception, what it
    had already observed (its stop results, its window, its offsets) can still be reported."""
    case = Case(name, "PASS")
    env.current_case = case
    return case


def overall_verdict(cases: Sequence[Case], *, cleanup_verified: bool, selected: Sequence[str]) -> str:
    """PASS only if every selected case ran and passed and cleanup was verified.  Any FAIL, or a
    cleanup that could not be verified, is FAIL; otherwise anything missing or inconclusive is HOLD."""
    by_name = {case.name: case for case in cases}
    if any(case.verdict == "FAIL" for case in cases) or not cleanup_verified:
        return "FAIL"
    if any(name not in by_name or by_name[name].verdict != "PASS" for name in selected):
        return "HOLD"
    return "PASS"


@dataclasses.dataclass(frozen=True)
class Config:
    messages: int = 2000
    spans: int = SPANS_PER_MESSAGE
    batch_messages: int = 50
    window: tuple[float, float] = (0.10, 0.70)
    idle_stop_max: float = 10.0
    graceful_stop_max: float = 25.0               # below the 30 s grace: reaching it means a kill
    drain_timeout: float = 300.0
    window_timeout: float = 240.0
    idle_seconds: float = 10.0
    #: duplicates tolerated on the canonical topic per graceful stop of the stream processor: the
    #: message in hand is finished before the stop, so the expectation is zero; one message of
    #: replay would still be at-least-once-correct and is reported, not failed.
    duplicate_tolerance_messages: int = 1
    #: S4 only: how long the batching startup line may take to appear after the container is running.
    config_wait: float = 30.0
    #: S5 only: the batch size (larger than S4's, so the replay is unmistakable; the 30 s interval stays inert), how
    #: long the restarted consumer may take to drain (it includes the group rebalance after a killed member), and how
    #: long the killed container may take to be reported exited.
    crash_batch_messages: int = 500
    restart_wait: float = 240.0
    termination_wait: float = 15.0
    #: S6 only: the deterministic input.  Each message is published span by span (one acknowledged produce per span) and
    #: committed only after its last span, so the published-but-uncommitted interval is almost the whole processing
    #: cycle of one message; 500 spans make that cycle long compared with the harness's own latency (about 33.5 kB per
    #: message, far below the 1,000,000-byte producer limit and the broker's 1,048,588-byte default).
    crash_messages: int = 60
    crash_spans: int = 500


def window_state(progress: float, window: tuple[float, float]) -> str:
    """'before' (not started enough), 'inside' (stop now) or 'after' (finished too early)."""
    low, high = window
    if progress < low:
        return "before"
    return "inside" if progress <= high else "after"


# ---------------------------------------------------------------------------
# The environment the cases run against (a fake in the tests, LiveEnv for a live run)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class StopResult:
    seconds: float
    returncode: int
    requested_monotonic: float = 0.0              # the harness clock when the stop was requested
    requested_utc: str = ""                       # the wall-clock time of the request


class Env:
    """What a case may do.  Every method of LiveEnv is project-scoped."""
    stream_group: str = ""
    storage_group: str = ""
    project: str = ""
    protected_ids: frozenset = frozenset()
    produced: list  # Produced batches, in order; every implementation sets it in __init__
    current_case: Optional["Case"] = None

    def expected(self) -> set[tuple[str, str]]:
        """Every span the harness has put on the source topic so far."""
        return set().union(*(batch.expected() for batch in self.produced)) if self.produced else set()

    def inspect(self, service: str) -> Inspect: raise NotImplementedError
    def logs(self, service: str) -> str: raise NotImplementedError
    def start(self, service: str) -> None: raise NotImplementedError
    def stop(self, services: Sequence[str]) -> StopResult: raise NotImplementedError
    def wait_running(self, service: str) -> None: raise NotImplementedError
    def produce(self, batch: int, count: int, spans: int) -> Produced: raise NotImplementedError
    def group(self, group: str, topic: str) -> dict[int, GroupPartition]: raise NotImplementedError
    def group_after_stop(self, group: str, topic: str, service: str) -> "PostStopOffsets": raise NotImplementedError
    def canonical(self) -> list[Canonical]: raise NotImplementedError
    def rows(self) -> list[Row]: raise NotImplementedError
    def wait_drained(self, group: str, topic: str, timeout: float) -> bool: raise NotImplementedError
    def set_storage_batching(self, messages: Optional[int], *, no_restart: bool = False) -> None: raise NotImplementedError
    def restart_policy(self, service: str) -> str: raise NotImplementedError
    def kill_target(self, service: str) -> "KillTarget": raise NotImplementedError
    def container_id(self, service: str) -> str: raise NotImplementedError
    def recheck_containers(self, ids: Sequence[str]) -> dict[str, "ContainerFacts"]: raise NotImplementedError
    def kill(self, service: str, container_id: str, case: str = "S5") -> "KillResult": raise NotImplementedError
    def write_override(self, *, batching_messages: Optional[int] = None, no_restart: bool = False,
                       stream_no_restart: bool = False, storage_timing: bool = False) -> None: raise NotImplementedError
    def termination_facts(self, service: str) -> "TerminationFacts": raise NotImplementedError
    def container_env(self, service: str, names: Sequence[str]) -> dict[str, Optional[str]]: raise NotImplementedError
    def sleep(self, seconds: float) -> None: raise NotImplementedError
    def clock(self) -> float: raise NotImplementedError


_SECRET_NAME = re.compile(r"""(?i)\b([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY)[A-Z0-9_]*)=[^\s"',;)\]}]+""")


def redact_text(text: str) -> str:
    """Masks the generated credentials of this run and anything that looks like NAME_PASSWORD=value."""
    return _SECRET_NAME.sub(r"\1=<redacted>", smoke.redact(text))


def redact_structure(value: Any) -> Any:
    """redact_text applied to every string of a JSON-like structure.  Redacting the values BEFORE they are
    serialized keeps the document valid whatever the strings contain."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {key: redact_structure(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value]
    return value


def credential_leaks(text: str) -> int:
    """How many times a generated credential of this run appears in text."""
    return sum(text.count(value) for value in smoke.RUN.generated.values() if value)


@dataclasses.dataclass
class ServiceStop:
    """What was observed when one service was stopped.  None means 'not observed'."""
    service: str
    stop_requested_monotonic: Optional[float]
    stop_requested_utc: str
    stop_command_services: list[str]              # the services that one `compose stop` command covered
    stop_seconds: Optional[float]                 # of that command, so shared by those services
    stop_returncode: Optional[int]
    exit_code: Optional[int] = None
    status: Optional[str] = None
    restarts_before: Optional[int] = None
    restarts_after: Optional[int] = None
    oom_killed: Optional[bool] = None
    first_signal_diagnostics: Optional[int] = None   # new since the stop was requested
    graceful_stop_lines: Optional[int] = None        # new since the stop was requested
    shutdown_log_lines: list[str] = dataclasses.field(default_factory=list)
    assertions: dict[str, Optional[bool]] = dataclasses.field(default_factory=dict)
    missing_observations: list[str] = dataclasses.field(default_factory=list)
    all_passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def observe_stop(env: Env, service: str, before: Inspect, logs_before: tuple[int, int], stop: StopResult,
                 limit: float, stopped_with: Sequence[str] = ()) -> tuple[ServiceStop, list[str]]:
    """The observations and checks every stop shares: exit code, state, restart count, OOM, duration and the
    one-time diagnostics.  A missing or malformed observation is recorded and is itself a problem, never a
    pass.  Reads exactly what the earlier version read (one inspect, one log)."""
    observation = ServiceStop(
        service=service, stop_requested_monotonic=stop.requested_monotonic, stop_requested_utc=stop.requested_utc,
        stop_command_services=list(stopped_with) or [service], stop_seconds=stop.seconds,
        stop_returncode=stop.returncode, restarts_before=before.restarts)
    problems: list[str] = []
    if not stop.requested_utc:
        observation.missing_observations.append("stop request time")
        problems.append(f"{service}: observation missing: stop request time")
    try:
        now: Optional[Inspect] = env.inspect(service)
    except SmokeFailure as failure:
        now = None
        observation.missing_observations.append(f"container state: {str(failure)[:160]}")
        problems.append(f"{service}: observation missing: container state")
    if now is not None:
        observation.exit_code, observation.status = now.exit_code, now.status
        observation.restarts_after, observation.oom_killed = now.restarts, now.oom_killed
        if now.exit_code == 137:
            problems.append(f"{service}: exit code 137, killed after the grace period")
        elif now.exit_code != 0:
            problems.append(f"{service}: exit code {now.exit_code}")
        if now.status != "exited":
            problems.append(f"{service}: status {now.status!r}, not 'exited'")
        if now.restarts != before.restarts:
            problems.append(f"{service}: restart count {before.restarts} -> {now.restarts}")
        if now.oom_killed:
            problems.append(f"{service}: OOM killed")
    if stop.returncode != 0:
        problems.append(f"{service}: compose stop returned {stop.returncode}")
    if stop.seconds > limit:
        problems.append(f"{service}: stop took {stop.seconds:.1f}s, above {limit:.0f}s")
    try:
        logs: Optional[str] = env.logs(service)
    except SmokeFailure as failure:
        logs = None
        observation.missing_observations.append(f"service log: {str(failure)[:160]}")
        problems.append(f"{service}: observation missing: service log")
    if logs is not None:
        first, graceful = diagnostic_counts(logs)
        observation.first_signal_diagnostics, observation.graceful_stop_lines = first - logs_before[0], graceful - logs_before[1]
        observation.shutdown_log_lines = [
            redact_text(line)[:300] for line in logs.splitlines()
            if FIRST_SIGNAL_MARKER in line or GRACEFUL_MARKER in line][-10:]
        if observation.first_signal_diagnostics != 1:
            problems.append(f"{service}: {observation.first_signal_diagnostics} first-signal diagnostics, expected 1")
        if observation.graceful_stop_lines != 1:
            problems.append(f"{service}: {observation.graceful_stop_lines} graceful-stop lines, expected 1")
    observation.assertions = {
        "exit_code_0": None if now is None else now.exit_code == 0,
        "status_exited": None if now is None else now.status == "exited",
        "restart_count_unchanged": None if now is None else now.restarts == before.restarts,
        "not_oom_killed": None if now is None else not now.oom_killed,
        "compose_stop_ok": stop.returncode == 0,
        "stop_within_limit": stop.seconds <= limit,
        "one_first_signal_diagnostic": None if logs is None else observation.first_signal_diagnostics == 1,
        "one_graceful_stop_line": None if logs is None else observation.graceful_stop_lines == 1,
    }
    observation.all_passed = (all(value is True for value in observation.assertions.values())
                              and not observation.missing_observations)
    return observation, problems


def check_stop(env: Env, service: str, before: Inspect, logs_before: tuple[int, int], stop: StopResult,
               limit: float) -> list[str]:
    """The problems of one stop (see observe_stop)."""
    return observe_stop(env, service, before, logs_before, stop, limit)[1]


def restart(env: Env, services: Sequence[str]) -> None:
    for service in services:
        env.start(service)
        env.wait_running(service)


def wait_window(env: Env, group: str, topic: str, baseline: int, total: int, cfg: Config,
                samples: Optional[list] = None, started: float = 0.0) -> str:
    """Polls the group's progress until it is inside the window ('inside'), already beyond it
    ('after'), or the timeout passes ('timeout').  The first poll inside the window ends the wait, so the stop
    is requested at once.  When `samples` is given (S4) every poll is also recorded there, for information."""
    deadline = env.clock() + cfg.window_timeout
    while True:
        groups = env.group(group, topic)
        done = committed_total(groups) - baseline
        if samples is not None:
            samples.append({"t": round(env.clock() - started, 2), "utc": utc_now_iso(),
                            "committed": {str(p): row.current for p, row in sorted(groups.items())},
                            "committed_progress": done})
        state = window_state(done / total if total else 1.0, cfg.window)
        if state != "before":
            return state
        if env.clock() >= deadline:
            return "timeout"
        env.sleep(0.5)


def case_s1(env: Env, cfg: Config) -> Case:
    case = begin_case(env, "S1")
    for service in APP_SERVICES:
        env.wait_running(service)
    env.sleep(cfg.idle_seconds)
    before = {s: env.inspect(s) for s in APP_SERVICES}
    logs_before = {s: diagnostic_counts(env.logs(s)) for s in APP_SERVICES}
    stop = env.stop(APP_SERVICES)
    for service in APP_SERVICES:
        observation, problems = observe_stop(env, service, before[service], logs_before[service], stop,
                                             cfg.idle_stop_max, APP_SERVICES)
        case.stops.append(observation)
        case.problems += problems
    case.metrics = {"stop_seconds": round(stop.seconds, 2)}
    restart(env, APP_SERVICES)
    case.verdict = "FAIL" if case.problems else "PASS"
    return case


def _prepare_backlog(env: Env, cfg: Config, batch: int) -> Produced:
    """Storage stopped, stream processor running: produce a batch and let the stream processor
    publish all of it to the canonical topic."""
    env.stop(["storage-consumer"])
    env.wait_running("stream-processor")
    produced = env.produce(batch, cfg.messages, cfg.spans)
    if not env.wait_drained(env.stream_group, SOURCE_TOPIC, cfg.drain_timeout):
        raise SmokeFailure("the stream processor did not drain the batch in time")
    return produced


def case_s2(env: Env, cfg: Config) -> Case:
    case = begin_case(env, "S2")
    batch = CASE_BATCH["S2"]
    env.stop(["storage-consumer"])
    env.wait_running("stream-processor")
    baseline_groups = env.group(env.stream_group, SOURCE_TOPIC)
    baseline = committed_total(baseline_groups)
    case.metrics["uncommitted_partitions_at_baseline"] = partitions_without_commit(baseline_groups)
    produced = env.produce(batch, cfg.messages, cfg.spans)
    case.observations["workload"] = {"batch": batch, "messages": cfg.messages, "spans_per_message": cfg.spans,
                                     "baseline_committed_total": baseline}
    state = wait_window(env, env.stream_group, SOURCE_TOPIC, baseline, cfg.messages, cfg)
    case.observations["window"] = {"state": state, "required_range": list(cfg.window)}
    if state != "inside":
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the stream processor was not inside its processing window when the stop "
                             f"could be issued ({state})")
        return case
    before, logs_before = env.inspect("stream-processor"), diagnostic_counts(env.logs("stream-processor"))
    stop = env.stop(["stream-processor"])
    observation, problems = observe_stop(env, "stream-processor", before, logs_before, stop, cfg.graceful_stop_max,
                                         ["stream-processor"])
    case.stops.append(observation)
    case.problems += problems
    post_stop = env.group_after_stop(env.stream_group, SOURCE_TOPIC, "stream-processor")
    committed = committed_offsets(post_stop.groups)
    case.observations["post_stop_offsets"] = post_stop.to_dict()
    canonical_after_stop = env.canonical()
    case.observations["canonical_records_after_stop"] = len(canonical_after_stop)
    case.problems += source_commit_problems(produced, committed, canonical_after_stop)
    restart(env, ["stream-processor"])
    if not env.wait_drained(env.stream_group, SOURCE_TOPIC, cfg.drain_timeout):
        case.problems.append("the restarted stream processor did not drain the source topic in time")
    accounting = account_canonical(env.expected(), env.canonical())
    if accounting.missing or accounting.unexpected:
        case.problems.append(f"canonical topic: {accounting.missing} missing, {accounting.unexpected} "
                             f"unexpected {list(accounting.detail)}")
    if accounting.duplicate_copies > cfg.duplicate_tolerance_messages * cfg.spans:
        case.problems.append(f"canonical topic: {accounting.duplicate_copies} duplicate copies, above the "
                             f"{cfg.duplicate_tolerance_messages}-message tolerance")
    case.metrics.update({"stop_seconds": round(stop.seconds, 2),
                         "committed_at_stop": sum(c or 0 for c in committed.values()),
                         "duplicate_copies": accounting.duplicate_copies})
    case.verdict = "FAIL" if case.problems else "PASS"
    return case


def progress_baseline(groups: Mapping[int, GroupPartition]) -> tuple[int, int, list[int]]:
    """(committed progress, backlog, partitions counted as 0) of a group, for the progress arithmetic ONLY.
    An uncommitted partition (None) contributes 0 to the SUM here; the authoritative offsets are never changed
    and are recorded as they were read."""
    zero_counted = partitions_without_commit(groups)
    committed = committed_total(groups)
    return committed, log_end_total(groups) - committed, zero_counted


def require_zero_low_baseline(post_stop: "PostStopOffsets", what: str = "S3/S4 baseline") -> None:
    """The progress arithmetic of S3/S4 (backlog = sum of end offsets - sum of committed offsets, an uncommitted
    partition counting as 0) is right only if every partition starts at offset 0 and no commit lies below its
    start.  That holds for the disposable topics (fresh, nothing deletes records) but is CHECKED here from the
    authoritative per-partition record, never assumed.  Raises PostStopError, with nothing clamped or replaced,
    if any low watermark is missing, malformed or not 0, if a numeric committed offset is below its low
    watermark, or if the per-partition records do not cover the same partitions."""
    problems = []
    if set(post_stop.commits) != set(post_stop.groups):
        problems.append(f"the per-partition records {sorted(post_stop.commits)} do not match the offsets "
                        f"{sorted(post_stop.groups)}")
    for partition, commit in sorted(post_stop.commits.items()):
        low = commit.low
        if not isinstance(low, int) or isinstance(low, bool):
            problems.append(f"partition {partition}: low watermark {low!r} is missing or malformed")
            continue
        if low != 0:
            problems.append(f"partition {partition}: low watermark {low} is not 0")
        if commit.state == "committed":
            if not isinstance(commit.offset, int) or isinstance(commit.offset, bool):
                problems.append(f"partition {partition}: committed offset {commit.offset!r} is not a number")
            elif commit.offset < low:
                problems.append(f"partition {partition}: committed offset {commit.offset} is below the low watermark {low}")
        elif commit.state != "uncommitted" or commit.offset is not None:
            problems.append(f"partition {partition}: ambiguous state {commit.state!r} / offset {commit.offset!r}")
    if problems:
        raise PostStopError(f"the {what} cannot be trusted: " + bounded_excerpt("; ".join(problems), 400),
                            {"partitions": {str(p): dataclasses.asdict(c) for p, c in sorted(post_stop.commits.items())}})


# ---------------------------------------------------------------------------
# S4: proof that batching was configured, active and exercised
# ---------------------------------------------------------------------------
#
# The proof of batching is the consumer's OWN count of messages and of Kafka commit calls (the existing opt-in
# timing instrumentation, enabled only in the disposable S4 override).  It does not depend on how fast or in
# which order two outside tools are read.  The group-offset samples taken while waiting for the window are
# recorded as information only.

@dataclasses.dataclass
class BatchingConfigCheck:
    """What was established about the storage consumer's effective batching configuration.
    status: 'verified', 'mismatch' (a value or the startup line is wrong or absent) or 'unverifiable'
    (a read failed).  Only the named batching variables are ever read out of the container environment."""
    status: str
    expected: dict[str, str]
    observed_env: dict[str, Optional[str]] = dataclasses.field(default_factory=dict)
    startup_line: Optional[str] = None
    waited_seconds: float = 0.0
    log_tail: list[str] = dataclasses.field(default_factory=list)      # only when the startup line is not found
    problems: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def verify_batching_configuration(env: Env, service: str, messages: int, cfg: Config) -> BatchingConfigCheck:
    """The container's environment must hold exactly the batching values (and the timing interval that makes the
    proof possible), and the process must have printed the OffsetBatcher startup line with the same numbers.  A
    wrong or absent value is a mismatch; a read that failed leaves the configuration unverifiable.  Neither is
    ever a pass."""
    expected = {BATCH_ENV_NAME: str(int(messages)), INTERVAL_ENV_NAME: BATCH_INTERVAL_SECONDS,
                TIMING_ENV_NAME: TIMING_INTERVAL_SECONDS}
    check = BatchingConfigCheck("verified", expected)
    try:
        observed = env.container_env(service, tuple(expected))
    except SmokeFailure as failure:
        check.status = "unverifiable"
        check.problems.append("the effective container environment could not be read: " + bounded_excerpt(str(failure), 200))
        return check
    check.observed_env = {name: observed.get(name) for name in expected}
    for name, want in expected.items():
        if check.observed_env[name] != want:
            check.problems.append(f"{name} is {check.observed_env[name]!r} in the container, expected {want!r}")
    if check.problems:
        check.status = "mismatch"
        return check
    started = env.clock()
    while True:
        try:
            logs = env.logs(service)
        except SmokeFailure as failure:
            check.status = "unverifiable"
            check.problems.append("the service log could not be read: " + bounded_excerpt(str(failure), 200))
            return check
        lines = logs.splitlines()
        found = [match for match in (BATCHING_STARTUP_RE.match(line) for line in lines) if match]
        if found:
            last = found[-1]
            check.startup_line = redact_text(last.group(0).strip())[:200]
            if int(last.group(1)) != int(messages) or float(last.group(2)) != float(BATCH_INTERVAL_SECONDS):
                check.status = "mismatch"
                check.problems.append(f"the startup line reports batches of {last.group(1)} every {last.group(2)} s, "
                                      f"expected {messages} every {BATCH_INTERVAL_SECONDS} s")
            check.waited_seconds = round(env.clock() - started, 2)
            return check
        if env.clock() - started >= cfg.config_wait:
            check.status = "mismatch"
            check.waited_seconds = round(env.clock() - started, 2)
            check.log_tail = [redact_text(line)[:200] for line in lines[-5:]]
            check.problems.append("the batching startup line (\"commit : batches of up to N messages\") never appeared: "
                                  "the offset batcher is not shown to be active")
            return check
        env.sleep(1.0)


@dataclasses.dataclass
class TimingEvidence:
    """The consumer's own final timing summary for the S4 process, and what it shows about batching.

    status: 'valid', 'missing' (no final summary), 'malformed' (a summary line or field cannot be read),
    'ambiguous' (more than one final summary, or counters that contradict each other) or 'unreadable'.
    Only 'valid' can support a batching PASS, and then only when efficient is True."""
    status: str
    messages: Optional[int] = None
    commits: Optional[int] = None
    inserted: Optional[int] = None
    conflicts: Optional[int] = None
    final_summaries: int = 0
    summary_lines: int = 0
    messages_per_commit: Optional[float] = None
    required_messages_per_commit: Optional[float] = None
    efficient: bool = False
    reasons: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _count(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def parse_timing_evidence(logs: str, batch_messages: int) -> TimingEvidence:
    """Reads the 'final' timing summary of the consumer process whose log this is (the harness reads it right
    after the S4 stop and before any restart, so the log holds that one process only).

    Semantics, from storage-consumer/consumer.py and timing.py:
      counters.messages          one per message that was persisted (process_message returned) and recorded; counted
                                 after any flush that message triggered; a message that raised is not counted
      stages.kafka_commit.count  one per Kafka commit CALL whose commit was confirmed (the batcher records it only
                                 when at least one partition was confirmed); in the original loop one per message
      counters.inserted/conflicts  split of messages (a replay conflict is still a persisted message)
    A batching consumer therefore shows about messages / batch commits, a per-message consumer shows as many commits
    as messages.  Every count-triggered commit covers at least batch_messages messages, so the efficiency bar
    (BATCH_EFFICIENCY_MIN_FRACTION of the batch per commit) leaves room for the few commits that are not
    count-triggered (an idle poll, a rebalance, the final flush).  Anything missing, malformed or contradictory is
    never efficient."""
    evidence = TimingEvidence("missing")
    payloads = []
    for raw in (logs or "").splitlines():
        line = raw.strip()
        if not line.startswith(TIMING_LINE_PREFIX):
            continue
        evidence.summary_lines += 1
        body = line[len(TIMING_LINE_PREFIX):]
        try:
            payload = json.loads(body) if len(body) <= TIMING_LINE_LIMIT else None
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            evidence.status = "malformed"
            evidence.reasons.append("a timing summary line could not be read")
            return evidence
        payloads.append(payload)
    finals = [p for p in payloads if p.get("kind") == "final"]
    evidence.final_summaries = len(finals)
    if not finals:
        evidence.reasons.append("no final timing summary was found: the consumer did not print one at its stop")
        return evidence
    if len(finals) > 1:
        evidence.status = "ambiguous"
        evidence.reasons.append(f"{len(finals)} final timing summaries were found; they cannot be told apart")
        return evidence
    final = finals[0]
    try:
        counters, stages = final["counters"], final["stages"]
        evidence.messages = _count(counters["messages"])
        evidence.inserted = _count(counters["inserted"])
        evidence.conflicts = _count(counters["conflicts"])
        evidence.commits = _count(stages["kafka_commit"]["count"])
    except (KeyError, TypeError):
        evidence.status = "malformed"
        evidence.reasons.append("the final timing summary lacks the expected counters")
        return evidence
    if None in (evidence.messages, evidence.inserted, evidence.conflicts, evidence.commits):
        evidence.status = "malformed"
        evidence.reasons.append("a timing counter is not a non-negative whole number")
        return evidence
    if evidence.inserted + evidence.conflicts != evidence.messages:
        evidence.status = "ambiguous"
        evidence.reasons.append("inserted + conflicts does not equal messages")
        return evidence
    if evidence.commits > evidence.messages:
        evidence.status = "ambiguous"
        evidence.reasons.append("more commit calls than messages")
        return evidence
    evidence.status = "valid"
    if evidence.messages < batch_messages:
        evidence.reasons.append(f"only {evidence.messages} message(s) were processed, fewer than one batch of {batch_messages}")
        return evidence
    if evidence.commits < 1:
        evidence.reasons.append("no Kafka commit was recorded")
        return evidence
    evidence.messages_per_commit = round(evidence.messages / evidence.commits, 2)
    evidence.required_messages_per_commit = round(batch_messages * BATCH_EFFICIENCY_MIN_FRACTION, 2)
    evidence.efficient = evidence.messages_per_commit >= evidence.required_messages_per_commit
    if not evidence.efficient:
        evidence.reasons.append(f"{evidence.commits} commit call(s) for {evidence.messages} messages "
                                f"({evidence.messages_per_commit} per commit) is below the "
                                f"{evidence.required_messages_per_commit} a batching consumer shows")
    return evidence


def summarize_commit_samples(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """INFORMATION ONLY: the committed offsets seen while waiting for the window, and the changes between
    consecutive samples (never required to be a multiple of the batch size; a commit between two samples may have
    been missed).  This is not evidence of batching."""
    changes: list[dict[str, Any]] = []
    largest = 0
    for before, now in zip(samples, samples[1:]):
        moved = {}
        for partition, value in now["committed"].items():
            old = before["committed"].get(partition)
            if value != old:
                moved[partition] = [old, value]
                if isinstance(value, int) and not isinstance(value, bool):
                    largest = max(largest, value - (old or 0))
        if moved:
            changes.append({"t": now["t"], "partitions": moved})
    return {"samples_taken": len(samples), "samples_with_commit_change": len(changes), "commit_changes": changes[:50],
            "largest_partition_step": largest,
            "commit_progress_observed": any(s["committed_progress"] > 0 for s in samples),
            "informational": "not evidence of batching; see timing_evidence"}


def bounded_samples(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    kept = list(samples) if len(samples) <= EVIDENCE_SAMPLE_LIMIT else \
        [*samples[:EVIDENCE_SAMPLE_LIMIT // 2], *samples[-(EVIDENCE_SAMPLE_LIMIT // 2):]]
    return {"samples": kept, "samples_total": len(samples), "truncated": len(kept) < len(samples)}


def partition_evidence(post_stop: "PostStopOffsets", baseline: Mapping[int, GroupPartition],
                       canonical: Sequence[Canonical], rows: Sequence[Row]) -> dict[str, Any]:
    """Per partition at the stop: the committed offset (None if uncommitted), how many canonical records and
    durable rows the partition holds and its durable frontier (the first canonical offset without a row, else
    the end).  Counts are cumulative over the project's cases.  Observation only: the pass/fail checks stay
    storage_commit_problems and the final accounting."""
    persisted = {(row.trace, row.span) for row in rows}
    out: dict[str, Any] = {}
    progressed = []
    for partition in sorted(post_stop.groups):
        committed = post_stop.groups[partition].current
        start = baseline[partition].current if partition in baseline else None
        records = [r for r in canonical if r.partition == partition]
        missing = sorted(r.offset for r in records if (r.trace, r.span) not in persisted)
        frontier = missing[0] if missing else max((r.offset for r in records), default=-1) + 1
        moved = (committed or 0) > (start or 0)
        if moved:
            progressed.append(partition)
        out[str(partition)] = {
            "committed": committed, "baseline_committed": start, "canonical_records": len(records),
            "durable_rows": sum(1 for row in rows if row.partition == partition), "durable_frontier": frontier,
            "committed_within_frontier": committed is None or committed <= frontier, "progressed": moved}
    return {"partitions": out, "partitions_progressed": progressed, "partitions_progressed_count": len(progressed)}


def identity_mismatches(canonical: Sequence[Canonical], rows: Sequence[Row]) -> list[str]:
    """A stored row's kafka_partition/kafka_offset must be one of the places its (trace, span) sits on the
    canonical topic (a replayed canonical record has several, and only the first is stored)."""
    places: dict[tuple[str, str], set[tuple[int, int]]] = {}
    for record in canonical:
        places.setdefault((record.trace, record.span), set()).add((record.partition, record.offset))
    found = []
    for row in rows:
        known = places.get((row.trace, row.span))
        if known is None:
            found.append(f"row {row.trace}/{row.span} (partition {row.partition}, offset {row.offset}) has no canonical record")
        elif (row.partition, row.offset) not in known:
            found.append(f"row {row.trace}/{row.span} stores partition {row.partition}, offset {row.offset}; "
                         f"the canonical topic has {sorted(known)[:3]}")
    return found


def _storage_case(env: Env, cfg: Config, name: str, *, batching_messages: Optional[int]) -> Case:
    case = begin_case(env, name)
    batch = CASE_BATCH[name]
    observe = batching_messages is not None             # S4: configuration and batched commits must be shown
    produced = _prepare_backlog(env, cfg, batch)
    env.set_storage_batching(batching_messages)
    # The storage consumer is STOPPED here, so its group has no active members and the CLI lists only the
    # partitions that have a commit (none, on a first run).  The strict reader cannot describe that group; the
    # authoritative stopped-group reader can, and it refuses unless the container is exited.
    pre_start = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    try:
        require_zero_low_baseline(pre_start)            # before any arithmetic, window polling or restart
    except PostStopError:
        case.observations["baseline_rejected"] = {"offsets": pre_start.to_dict()}
        raise
    groups = pre_start.groups
    baseline, total, zero_counted = progress_baseline(groups)
    case.metrics["uncommitted_partitions_at_baseline"] = partitions_without_commit(groups)
    case.observations["baseline"] = {"offsets": pre_start.to_dict(), "progress_baseline": baseline,
                                     "backlog_records": total, "counted_as_zero_in_progress_sum_only": zero_counted}
    env.start("storage-consumer")
    env.wait_running("storage-consumer")
    case.observations["workload"] = {"batch": batch, "messages": cfg.messages, "spans_per_message": cfg.spans,
                                     "baseline_committed_total": baseline, "backlog_records": total}
    samples: list[dict[str, Any]] = []
    if observe:
        check = verify_batching_configuration(env, "storage-consumer", batching_messages, cfg)
        case.observations["batching_configuration"] = check.to_dict()
        if check.status != "verified":
            case.verdict = "INCONCLUSIVE" if check.status == "unverifiable" else "FAIL"
            case.problems += check.problems
            return case
        case.observations["commit_observations"] = {"samples": samples}      # live list: kept if the case is aborted
        state = wait_window(env, env.storage_group, CANONICAL_TOPIC, baseline, total, cfg, samples, env.clock())
        case.observations["commit_observations"] = {**bounded_samples(samples), "summary": summarize_commit_samples(samples)}
    else:
        state = wait_window(env, env.storage_group, CANONICAL_TOPIC, baseline, total, cfg)
    case.observations["window"] = {"state": state, "required_range": list(cfg.window)}
    if state != "inside":
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the storage consumer was not inside its persistence window when the stop "
                             f"could be issued ({state})")
        return case
    before, logs_before = env.inspect("storage-consumer"), diagnostic_counts(env.logs("storage-consumer"))
    stop = env.stop(["storage-consumer"])
    observation, problems = observe_stop(env, "storage-consumer", before, logs_before, stop, cfg.graceful_stop_max,
                                         ["storage-consumer"])
    case.stops.append(observation)
    case.problems += problems
    timing = None
    if observe:
        # Read right after the stop and before any restart: the log of this container holds this one process only.
        try:
            timing = parse_timing_evidence(env.logs("storage-consumer"), batching_messages)
        except SmokeFailure as failure:
            timing = TimingEvidence("unreadable", reasons=["the service log could not be read after the stop: "
                                                           + bounded_excerpt(str(failure), 200)])
        case.observations["timing_evidence"] = timing.to_dict()
    post_stop = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    committed = committed_offsets(post_stop.groups)
    case.observations["post_stop_offsets"] = post_stop.to_dict()
    canonical, rows = env.canonical(), env.rows()
    case.observations["records_after_stop"] = {"canonical": len(canonical), "rows": len(rows)}
    case.observations["partition_evidence_at_stop"] = partition_evidence(post_stop, groups, canonical, rows)
    case.problems += storage_commit_problems(canonical, committed, rows)
    mismatches = identity_mismatches(canonical, rows)
    case.observations["row_identity_at_stop"] = {"mismatches": len(mismatches), "examples": mismatches[:3]}
    if observe and mismatches:
        case.problems.append(f"stored row metadata disagrees with the canonical topic for {len(mismatches)} row(s): {mismatches[0]}")
    persisted = {(row.trace, row.span) for row in rows}
    persisted_uncommitted = sum(
        1 for record in canonical
        if (committed.get(record.partition) is None or record.offset >= committed[record.partition])
        and (record.trace, record.span) in persisted)
    restart(env, ["storage-consumer"])
    if not env.wait_drained(env.storage_group, CANONICAL_TOPIC, cfg.drain_timeout):
        case.problems.append("the restarted storage consumer did not drain the canonical topic in time")
    final_rows = env.rows()
    final = account_rows(env.expected(), final_rows)
    final_mismatches = identity_mismatches(canonical, final_rows)       # every record was canonical before the start
    case.observations["final_rows"] = {
        "rows": len(final_rows), "expected": len(env.expected()), "missing": final.missing,
        "unexpected": final.unexpected, "duplicate_copies": final.duplicate_copies,
        "identity_mismatches": len(final_mismatches)}
    if observe and final_mismatches:
        case.problems.append(f"stored row metadata disagrees with the canonical topic after the drain for "
                             f"{len(final_mismatches)} row(s): {final_mismatches[0]}")
    if final.missing or final.unexpected or final.duplicate_copies:
        case.problems.append(f"rows: {final.missing} missing, {final.unexpected} unexpected, "
                             f"{final.duplicate_copies} duplicated {list(final.detail)}")
    case.metrics.update({"stop_seconds": round(stop.seconds, 2), "persisted_but_uncommitted": persisted_uncommitted,
                         "batching_messages": batching_messages})
    if observe:
        case.metrics["batching_exercised"] = bool(timing is not None and timing.status == "valid" and timing.efficient)
    if case.problems:
        case.verdict = "FAIL"
    elif observe and not case.metrics["batching_exercised"]:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("batching was configured and verified but is not shown to have been exercised by the "
                             f"consumer's own counters ({timing.status if timing else 'none'}): "
                             + "; ".join(timing.reasons if timing and timing.reasons else ["no evidence"]))
    else:
        case.verdict = "PASS"
    return case


def case_s3(env: Env, cfg: Config) -> Case:
    return _storage_case(env, cfg, "S3", batching_messages=None)


def case_s4(env: Env, cfg: Config) -> Case:
    try:
        return _storage_case(env, cfg, "S4", batching_messages=cfg.batch_messages)
    finally:
        env.set_storage_batching(None)


# ---------------------------------------------------------------------------
# S5: forced termination of the storage consumer, and the replay that follows
# ---------------------------------------------------------------------------
#
# The only destructive case.  It sends SIGKILL to ONE container, the disposable project's storage consumer, after
# that container has been identified three ways (Compose, `docker inspect`, its labels) and proved to be neither a
# protected container nor anything outside this project.  Nothing else is ever signalled.
#
# Once the process is dead the state is frozen: the PostgreSQL rows and the committed offsets can no longer move,
# so they are read exactly (no sampling skew) and the replay that must follow is PREDICTED per partition.  The
# restarted consumer's own final timing summary (messages, inserted, conflicts) is then compared with the
# prediction.  A correct final row count alone is not evidence of replay.

KILL_ARGUMENTS: tuple[str, ...] = ("kill", "-s", "SIGKILL", "storage-consumer")
KILL_SERVICE: str = "storage-consumer"
KILL_EXIT_CODE: int = 137
KILL_REQUIRED_RUNNING: tuple[str, ...] = ("kafka", "postgres", "stream-processor")


#: The ONLY kills this harness may issue: one service per destructive case, nothing else, nobody else.
KILL_TARGETS: Mapping[str, str] = {"S5": "storage-consumer", "S6": "stream-processor"}


def kill_arguments(case: str) -> tuple[str, ...]:
    if case not in KILL_TARGETS:
        raise SmokeFailure(f"case {case!r} may not kill anything")
    return ("kill", "-s", "SIGKILL", KILL_TARGETS[case])


def kill_arguments_allowed(args: Sequence[str], case: str = "S5") -> bool:
    """True only for exactly `kill -s SIGKILL <the one service the case may kill>`."""
    return case in KILL_TARGETS and tuple(args) == kill_arguments(case)


@dataclasses.dataclass(frozen=True)
class KillTarget:
    """What Compose and Docker say about the one container that may be killed."""
    container_id: str            # from `compose ps`
    inspected_id: str            # from `docker inspect` of that id
    project_label: str
    service_label: str
    name: str
    status: str
    restart_policy: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ContainerFacts:
    """What one `docker inspect` of a full container id says (the revalidation just before a kill)."""
    container_id: str
    project_label: str
    service_label: str
    name: str
    status: str
    restart_policy: str


@dataclasses.dataclass(frozen=True)
class KillResult:
    returncode: int
    seconds: float


@dataclasses.dataclass(frozen=True)
class TerminationFacts:
    container_id: str
    status: str
    exit_code: int
    oom_killed: bool
    restarts: int
    error: str
    finished_at: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


_HEX64 = re.compile(r"[0-9a-f]{64}")


def target_problems(env: "Env", target: KillTarget, service: str) -> list[str]:
    """The requirements on the one container that may be killed (identity, labels, name, protection, state, policy)."""
    problems = []
    project = env.project
    if project == "agentops" or not _PROJECT_RE.fullmatch(project or ""):
        problems.append(f"the project {project!r} is not a disposable shutdown-validation project")
    if not (_HEX64.fullmatch(target.container_id) and _HEX64.fullmatch(target.inspected_id)):
        problems.append("a full 64-hex container id is required from both Compose and Docker")
    if target.container_id != target.inspected_id:
        problems.append("Compose and `docker inspect` disagree about the container id")
    if target.project_label != project:
        problems.append(f"the container's project label is {target.project_label!r}, not {project!r}")
    if target.service_label != service:
        problems.append(f"the container's service label is {target.service_label!r}, not {service!r}")
    name = target.name.lstrip("/")
    if name in PROTECTED_CONTAINERS or any(token in name for token in PROTECTED_TOKENS):
        problems.append(f"the container name {name!r} is, or looks like, a protected container")
    if not name.startswith(f"{project}-{service}"):
        problems.append(f"the container name {name!r} is not this project's {service}")
    if target.container_id in env.protected_ids or target.inspected_id in env.protected_ids:
        problems.append("the container id matches a protected container")
    if target.status != "running":
        problems.append(f"the container is {target.status!r}, not running")
    if target.restart_policy != "no":
        problems.append(f"the restart policy is {target.restart_policy!r}, not 'no'")
    return problems


def verify_kill_target(env: "Env", target: KillTarget, service: str = KILL_SERVICE,
                       neighbours: Optional[Mapping[str, str]] = None) -> list[str]:
    """Why the kill must NOT be issued (empty = every requirement holds).  `service` is the one container the case may
    kill; `neighbours` the state each other disposable service must be in (default: running)."""
    problems = target_problems(env, target, service)
    wanted = dict(neighbours) if neighbours is not None else {name_: "running" for name_ in KILL_REQUIRED_RUNNING}
    for other, want in wanted.items():
        try:
            state = env.inspect(other).status
        except SmokeFailure as failure:
            problems.append(f"{other} could not be inspected: {bounded_excerpt(str(failure), 120)}")
            continue
        if state != want:
            problems.append(f"{other} is {state!r}, not {want}" if want == "running" else f"{other} is {state!r}, expected {want!r}")
    return problems


def revalidate_kill(env: "Env", target: KillTarget, service: str, neighbour_ids: Mapping[str, str],
                    neighbours: Mapping[str, str]) -> list[str]:
    """The last look before the one kill, from ONE `docker inspect` of the full ids that were verified earlier (the kill
    target and each neighbour).  Empty = the container is still exactly the verified one and every requirement of
    `verify_kill_target` still holds; anything else, including a result that cannot be read, refuses the kill."""
    ids = [target.container_id, *(neighbour_ids[name] for name in neighbours)]
    try:
        facts = env.recheck_containers(ids)
    except SmokeFailure as failure:
        return [f"the containers could not be re-inspected at the moment of the kill: {bounded_excerpt(str(failure), 160)}"]
    if sorted(facts) != sorted(set(ids)):
        return ["the re-inspection did not describe exactly the verified containers"]
    seen = facts[target.container_id]
    problems = []
    if seen.container_id != target.container_id:
        problems.append("the container id changed since it was verified")
    current = KillTarget(target.container_id, seen.container_id, seen.project_label, seen.service_label, seen.name,
                         seen.status, seen.restart_policy)
    problems += target_problems(env, current, service)
    for name, want in neighbours.items():
        other = facts[neighbour_ids[name]]
        if other.container_id != neighbour_ids[name]:
            problems.append(f"{name}'s container id changed since it was verified")
        if other.project_label != env.project or other.service_label != name:
            problems.append(f"{name} is no longer this project's {name}")
        if other.status != want:
            problems.append(f"{name} is {other.status!r}, not {want}" if want == "running" else f"{name} is {other.status!r}, expected {want!r}")
    return problems


def attribute_termination(kill: KillResult, target: KillTarget, facts: TerminationFacts, logs_delta: tuple[int, int],
                          final_summaries: int, restarts_before: int) -> tuple[list[str], dict[str, Any]]:
    """Whether the death of the container can be attributed to the authorized SIGKILL, from what was observed (the
    exit code is one observation among several, never the proof).  Returns (reasons it cannot be, the record)."""
    reasons = []
    if kill.returncode != 0:
        reasons.append(f"the kill command returned {kill.returncode}")
    if facts.container_id != target.container_id:
        reasons.append("the container id changed")
    if facts.status != "exited":
        reasons.append(f"the container is {facts.status!r}, not exited")
    if facts.exit_code != KILL_EXIT_CODE:
        reasons.append(f"exit code {facts.exit_code}, not {KILL_EXIT_CODE} (SIGKILL)")
    if facts.oom_killed:
        reasons.append("the container was OOM-killed")
    if facts.restarts != restarts_before:
        reasons.append(f"restart count {restarts_before} -> {facts.restarts}")
    first, graceful = logs_delta
    if first or graceful:
        reasons.append(f"graceful-shutdown diagnostics appeared ({first} first-signal, {graceful} graceful-stop line(s))")
    if final_summaries:
        reasons.append(f"{final_summaries} final timing summary(ies) exist: the process stopped by itself")
    record = {"kill_returncode": kill.returncode, "kill_seconds": round(kill.seconds, 2), "facts": facts.to_dict(),
              "first_signal_diagnostics": first, "graceful_stop_lines": graceful, "final_timing_summaries": final_summaries,
              "restarts_before": restarts_before, "attributed_to_sigkill": not reasons, "reasons": list(reasons)}
    return reasons, record


class StateNotStable(SmokeFailure):
    """The PostgreSQL rows kept changing after the consumer was dead."""


def stable_rows(env: "Env", attempts: int = 5) -> list["Row"]:
    """The rows, read until two reads (a second apart) agree; the process is dead, so they must."""
    previous = env.rows()
    for _ in range(attempts):
        env.sleep(1.0)
        current = env.rows()
        if sorted(dataclasses.astuple(r) for r in current) == sorted(dataclasses.astuple(r) for r in previous):
            return current
        previous = current
    raise StateNotStable(f"the PostgreSQL rows were still changing after {attempts} reads of the stopped consumer")


@dataclasses.dataclass
class ReplayPrediction:
    """What the restarted consumer must report, from the frozen state."""
    messages: int                      # every canonical record from the restart positions to the end
    conflicts: int                     # of those, already durable
    inserted: int                      # of those, not yet durable
    replay_total: int                  # durable but uncommitted: conflicts predicted from the frozen interval
    ambiguous: bool                    # canonical duplicates make the split unpredictable
    partitions: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class FrozenState:
    prediction: ReplayPrediction
    fail_problems: list[str]
    inconclusive: list[str]
    committed: dict[int, Optional[int]]


def analyse_frozen_state(post: "PostStopOffsets", canonical: Sequence[Canonical], rows: Sequence[Row]) -> FrozenState:
    """Per partition: the restart position (the committed offset, or the VERIFIED low watermark when nothing is
    committed), the durable frontier (first canonical offset without a row), the replay interval between them, and
    the counters the restarted consumer must show.  Safety problems (a commit past a durable row, a durable row
    beyond a gap) are FAIL material; a missing interval or an ambiguous prediction is not."""
    committed = committed_offsets(post.groups)
    fail = list(storage_commit_problems(canonical, committed, rows))
    persisted = {(row.trace, row.span) for row in rows}
    identity_count = Counter((record.trace, record.span) for record in canonical)
    ambiguous = any(n > 1 for n in identity_count.values())
    partitions: dict[str, Any] = {}
    messages = conflicts = replay_total = 0
    for partition in sorted(post.commits):
        commit = post.commits[partition]
        start = commit.offset if commit.state == "committed" else commit.low
        records = sorted((r for r in canonical if r.partition == partition), key=lambda r: r.offset)
        frontier = next((r.offset for r in records if (r.trace, r.span) not in persisted),
                        (records[-1].offset + 1) if records else commit.low)
        beyond = sorted(r.offset for r in rows if r.partition == partition and r.offset > frontier)
        if beyond:
            fail.append(f"partition {partition}: durable row(s) at offset(s) {beyond[:3]} lie beyond the first "
                        f"missing offset {frontier}: the durable offsets are not contiguous")
        replay_range = [r for r in records if start <= r.offset < frontier]
        redelivered = [r for r in records if r.offset >= start]
        partitions[str(partition)] = {
            "low": commit.low, "committed": commit.offset if commit.state == "committed" else None,
            "restart_position": start, "durable_frontier": frontier, "durable_rows": sum(1 for r in rows if r.partition == partition),
            "replay_interval": [start, frontier], "replay_records": len(replay_range),
            "redelivered_records": len(redelivered), "committed_within_frontier": start <= frontier}
        messages += len(redelivered)
        conflicts += sum(1 for r in redelivered if (r.trace, r.span) in persisted)
        replay_total += len(replay_range)
    prediction = ReplayPrediction(messages, conflicts, messages - conflicts, replay_total, ambiguous, partitions)
    inconclusive = []
    if ambiguous:
        inconclusive.append("the canonical topic holds duplicate identities, so the restart counters cannot be predicted exactly")
    if replay_total <= 0 and not fail:
        inconclusive.append("no durable-but-uncommitted interval exists at the moment of termination: there is nothing to replay")
    return FrozenState(prediction, fail, inconclusive, committed)


def _wait_exited(env: "Env", service: str, cfg: Config) -> None:
    deadline = env.clock() + cfg.termination_wait
    while env.inspect(service).status == "running" and env.clock() < deadline:
        env.sleep(0.5)


def _crash_case(env: "Env", cfg: Config, case: Case) -> Case:
    batch = CASE_BATCH["S5"]
    produced = _prepare_backlog(env, cfg, batch)
    env.set_storage_batching(cfg.crash_batch_messages, no_restart=True)
    pre_start = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    try:
        require_zero_low_baseline(pre_start, what="S5 baseline")
    except PostStopError:
        case.observations["baseline_rejected"] = {"offsets": pre_start.to_dict()}
        raise
    groups = pre_start.groups
    baseline, total, zero_counted = progress_baseline(groups)
    case.metrics["uncommitted_partitions_at_baseline"] = partitions_without_commit(groups)
    case.observations["baseline"] = {"offsets": pre_start.to_dict(), "progress_baseline": baseline,
                                     "backlog_records": total, "counted_as_zero_in_progress_sum_only": zero_counted}
    env.start("storage-consumer")
    env.wait_running("storage-consumer")
    case.observations["workload"] = {"batch": batch, "messages": cfg.messages, "spans_per_message": cfg.spans,
                                     "baseline_committed_total": baseline, "backlog_records": total}
    check = verify_batching_configuration(env, "storage-consumer", cfg.crash_batch_messages, cfg)
    case.observations["batching_configuration"] = check.to_dict()
    if check.status != "verified":
        case.verdict = "INCONCLUSIVE" if check.status == "unverifiable" else "FAIL"
        case.problems += check.problems
        return case
    try:
        policy = env.restart_policy("storage-consumer")
    except SmokeFailure as failure:
        policy = f"unreadable: {bounded_excerpt(str(failure), 120)}"
    case.observations["restart_policy"] = {"observed": policy, "required": "no"}
    if policy != "no":
        case.verdict = "INCONCLUSIVE"
        case.problems.append(f"the storage consumer's restart policy is {policy!r}, not 'no': it would restart itself "
                             "after a kill, so nothing was killed")
        return case
    samples: list[dict[str, Any]] = []
    case.observations["commit_observations"] = {"samples": samples}
    state = wait_window(env, env.storage_group, CANONICAL_TOPIC, baseline, total, cfg, samples, env.clock())
    case.observations["commit_observations"] = {**bounded_samples(samples), "summary": summarize_commit_samples(samples)}
    case.observations["window"] = {"state": state, "required_range": list(cfg.window)}
    if state != "inside":
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the storage consumer was not inside its persistence window when the kill could be "
                             f"issued ({state}); nothing was killed")
        return case
    # --- the one destructive step: identify, verify, and only then kill --------------------------------------
    try:
        target = env.kill_target("storage-consumer")
    except SmokeFailure as failure:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the kill target could not be identified: " + bounded_excerpt(str(failure), 200))
        return case
    refusal = verify_kill_target(env, target)
    case.observations["kill_target"] = {**target.to_dict(), "verified": not refusal, "refusals": refusal}
    if refusal:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the kill was refused, nothing was killed: " + "; ".join(refusal))
        return case
    before = env.inspect("storage-consumer")
    logs_before = diagnostic_counts(env.logs("storage-consumer"))
    kill = env.kill("storage-consumer", target.container_id)
    try:
        _wait_exited(env, "storage-consumer", cfg)
        facts = env.termination_facts("storage-consumer")
        logs_after = env.logs("storage-consumer")
    except SmokeFailure as failure:
        case.observations["termination"] = {"unreadable": bounded_excerpt(str(failure), 200)}
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the state after the kill could not be read: " + bounded_excerpt(str(failure), 200))
        return case
    first_after, graceful_after = diagnostic_counts(logs_after)
    finals = sum(1 for line in logs_after.splitlines()
                 if line.strip().startswith(TIMING_LINE_PREFIX) and '"kind":"final"' in line.replace(" ", ""))
    reasons, record = attribute_termination(kill, target, facts, (first_after - logs_before[0], graceful_after - logs_before[1]),
                                            finals, before.restarts)
    case.observations["termination"] = record
    if reasons:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the termination cannot be attributed to the authorized SIGKILL: " + "; ".join(reasons))
        return case
    # --- the frozen state: nothing can change any more ---------------------------------------------------------
    post = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    require_zero_low_baseline(post, what="S5 frozen state")
    case.observations["post_kill_offsets"] = post.to_dict()
    canonical = env.canonical()
    try:
        rows = stable_rows(env)
    except StateNotStable as failure:
        case.verdict = "INCONCLUSIVE"
        case.problems.append(str(failure))
        return case
    case.observations["records_after_kill"] = {"canonical": len(canonical), "rows": len(rows)}
    frozen = analyse_frozen_state(post, canonical, rows)
    case.observations["frozen_state"] = {"partitions": frozen.prediction.partitions,
                                         "replay_interval_records": frozen.prediction.replay_total}
    case.observations["replay_prediction"] = {
        "expected_messages": frozen.prediction.messages, "expected_conflicts": frozen.prediction.conflicts,
        "expected_inserted": frozen.prediction.inserted, "ambiguous": frozen.prediction.ambiguous,
        "replay_ranges": {p: v["replay_interval"] for p, v in frozen.prediction.partitions.items()}}
    case.metrics["persisted_but_uncommitted"] = frozen.prediction.replay_total
    if frozen.fail_problems:
        case.problems += frozen.fail_problems
        case.verdict = "FAIL"
        return case
    if frozen.inconclusive:
        case.verdict = "INCONCLUSIVE"
        case.problems += frozen.inconclusive
        return case
    # --- restart and replay ------------------------------------------------------------------------------------
    recheck = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    if committed_offsets(recheck.groups) != frozen.committed:
        case.observations["committed_moved_before_restart"] = {"before": frozen.committed, "after": committed_offsets(recheck.groups)}
        case.verdict = "FAIL"
        case.problems.append("the committed offsets moved while the consumer was dead")
        return case
    restart(env, ["storage-consumer"])
    if not env.wait_drained(env.storage_group, CANONICAL_TOPIC, cfg.restart_wait):
        case.verdict = "INCONCLUSIVE"
        case.problems.append(f"the restarted consumer did not drain within {cfg.restart_wait:.0f}s: the group rebalance after "
                             "the killed member, or the consumer itself, was too slow; replay is attempted but not observed")
        return case
    before2, logs_before2 = env.inspect("storage-consumer"), diagnostic_counts(env.logs("storage-consumer"))
    stop = env.stop(["storage-consumer"])
    observation, problems = observe_stop(env, "storage-consumer", before2, logs_before2, stop, cfg.graceful_stop_max,
                                         ["storage-consumer"])
    case.stops.append(observation)
    case.problems += problems
    try:
        timing = parse_timing_evidence(env.logs("storage-consumer"), cfg.crash_batch_messages)
    except SmokeFailure as failure:
        timing = TimingEvidence("unreadable", reasons=["the service log could not be read after the stop: "
                                                       + bounded_excerpt(str(failure), 200)])
    case.observations["restarted_timing"] = timing.to_dict()
    final_post = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    case.observations["final_offsets"] = final_post.to_dict()
    behind = [p for p, row in sorted(final_post.groups.items()) if row.current != row.log_end]
    if behind:
        case.problems.append(f"the final committed offsets did not reach the end offsets on partition(s) {behind}")
    final_rows = env.rows()
    final = account_rows(env.expected(), final_rows)
    mismatches = identity_mismatches(canonical, final_rows)
    case.observations["final_rows"] = {
        "rows": len(final_rows), "expected": len(env.expected()), "missing": final.missing, "unexpected": final.unexpected,
        "duplicate_copies": final.duplicate_copies, "identity_mismatches": len(mismatches)}
    if final.missing or final.unexpected or final.duplicate_copies:
        case.problems.append(f"rows: {final.missing} missing, {final.unexpected} unexpected, "
                             f"{final.duplicate_copies} duplicated {list(final.detail)}")
    if mismatches:
        case.problems.append(f"stored row metadata disagrees with the canonical topic for {len(mismatches)} row(s): {mismatches[0]}")
    replay_problems = []
    if timing.status == "valid":
        for label, got, want in (("messages", timing.messages, frozen.prediction.messages),
                                 ("conflicts", timing.conflicts, frozen.prediction.conflicts),
                                 ("inserted", timing.inserted, frozen.prediction.inserted)):
            if got != want:
                replay_problems.append(f"the restarted consumer reports {got} {label}, the frozen state predicts {want}")
    case.problems += replay_problems
    case.metrics.update({"stop_seconds": round(stop.seconds, 2), "replay_conflicts": timing.conflicts,
                         "replay_predicted": frozen.prediction.conflicts, "batching_messages": cfg.crash_batch_messages})
    if case.problems:
        case.verdict = "FAIL"
    elif timing.status != "valid":
        case.verdict = "INCONCLUSIVE"
        case.problems.append(f"replay was attempted but is not observed: the restarted consumer's counters are {timing.status}: "
                             + "; ".join(timing.reasons or ["no evidence"]))
    else:
        case.verdict = "PASS"
    return case


def case_s5(env: "Env", cfg: Config) -> Case:
    case = begin_case(env, "S5")
    try:
        return _crash_case(env, cfg, case)
    finally:
        env.set_storage_batching(None)


# ---------------------------------------------------------------------------
# S6: forced termination of the stream processor, and the republication that must follow
# ---------------------------------------------------------------------------
#
# A source record is committed only after EVERY span of it was published with a positive acknowledgement, so a kill
# between the first acknowledged span and the commit leaves published spans whose source offset is uncommitted.  The
# restarted processor (an empty in-process deduplicator, a new producer id) republishes the whole record.  The
# deterministic identities encode the source message, so every canonical record can be traced back to its raw
# partition and offset, and the republication can be predicted from the FROZEN state after the kill and then observed
# as identities that appear once before and once after the frozen end of their canonical partition.  The storage
# consumer stays stopped until the end, so the downstream unique key is shown to absorb exactly those duplicates.

S6_SERVICE: str = "stream-processor"
S6_NEIGHBOURS: Mapping[str, str] = {"kafka": "running", "postgres": "running", "storage-consumer": "exited"}


@dataclasses.dataclass(frozen=True)
class SourceIdentity:
    batch: int
    index: int
    k: int


def decode_identity(trace: str, span: str) -> Optional[SourceIdentity]:
    """The (batch, source message, span number) a deterministic identity encodes, or None if it is not one."""
    if not isinstance(trace, str) or not isinstance(span, str) or len(trace) != 32 or len(span) != 16:
        return None
    try:
        batch, index = int(trace[:4], 16), int(trace[4:], 16)
        span_index, k = int(span[:12], 16), int(span[12:], 16) - 1
    except ValueError:
        return None
    if span_index != index or k < 0:
        return None
    return SourceIdentity(batch, index, k)


@dataclasses.dataclass
class StreamFreeze:
    fail_problems: list[str]
    inconclusive: list[str]
    committed: dict[int, Optional[int]]
    ends: dict[int, int]                      # canonical end offset per canonical partition at the freeze
    frozen_records: int                       # canonical records of this case's batch at the freeze
    published_uncommitted: int                # spans on the canonical topic whose source message is uncommitted
    replay_messages: int                      # source messages the restarted processor must read again
    predicted_growth: int                     # canonical records the restarted processor must publish
    partial_messages: int                     # uncommitted messages with only some of their spans published
    partitions: dict[str, Any]


def analyse_stream_freeze(produced: Produced, post: "PostStopOffsets", canonical: Sequence[Canonical],
                          batch: int) -> StreamFreeze:
    """From the frozen state (processor dead, nothing can change): per source partition the restart position
    (the committed offset, or the VERIFIED low watermark when nothing is committed), which source messages are read
    again, how many of their spans are already on the canonical topic, and so what the restart must publish.
    Safety problems (a commit past a message whose spans are not all published) are FAIL material; a missing
    published-but-uncommitted span, a fixture that cannot be mapped or a duplicate already present are not."""
    committed = committed_offsets(post.groups)
    fail = list(source_commit_problems(produced, committed, canonical))
    inconclusive: list[str] = []
    positions = {p: (c.offset if c.state == "committed" else c.low) for p, c in post.commits.items()}
    per_message: dict[int, list[Canonical]] = {}
    seen: Counter = Counter()
    ends: dict[int, int] = {}
    unmapped = outside = 0
    for record in canonical:
        ends[record.partition] = max(ends.get(record.partition, 0), record.offset + 1)
        ident = decode_identity(record.trace, record.span)
        if ident is None:
            unmapped += 1
            continue
        if ident.batch != batch:
            continue                                           # another case's record: not ours, not ambiguous
        if not (0 <= ident.index < produced.count and ident.k < produced.spans):
            outside += 1
            continue
        per_message.setdefault(ident.index, []).append(record)
        seen[(ident.index, ident.k)] += 1
    if unmapped or outside:
        inconclusive.append(f"{unmapped} canonical record(s) have no deterministic identity and {outside} lie outside "
                            "the fixture: the fixture-to-source mapping is ambiguous")
    if any(n > 1 for n in seen.values()):
        inconclusive.append("a span identity is already duplicated on the canonical topic at the freeze, so the "
                            "replay cannot be separated from an earlier duplicate")
    published = replay_messages = partial = 0
    parts: dict[str, Any] = {}
    for index, (partition, offset) in sorted(produced.acks.items()):
        start = positions.get(partition)
        if start is None:
            inconclusive.append(f"source partition {partition} has no verified restart position")
            continue
        info = parts.setdefault(str(partition), {"restart_position": start, "committed": committed.get(partition),
                                                 "replayed_messages": 0, "published_uncommitted_spans": 0,
                                                 "partial_messages": 0})
        if offset >= start:
            spans_there = len(per_message.get(index, []))
            replay_messages += 1
            published += spans_there
            info["replayed_messages"] += 1
            info["published_uncommitted_spans"] += spans_there
            if 0 < spans_there < produced.spans:
                partial += 1
                info["partial_messages"] += 1
    if published <= 0 and not fail:
        inconclusive.append("no span of an uncommitted source message is on the canonical topic at the moment of "
                            "termination: there is nothing to republish")
    frozen = sum(len(v) for v in per_message.values())
    return StreamFreeze(fail, inconclusive, committed, ends, frozen, published, replay_messages,
                        replay_messages * produced.spans, partial, parts)


@dataclasses.dataclass
class Republication:
    growth: int
    missing: int
    unexpected: int
    duplicate_copies: int
    straddling: int                  # one copy before the frozen end of its canonical partition, one after
    same_phase: int                  # extra copies on the same side: not explained by a source replay
    fail_problems: list[str]
    inconclusive: list[str]
    sample: list[dict[str, Any]]


def analyse_republication(produced: Produced, batch: int, freeze: StreamFreeze,
                          canonical_after: Sequence[Canonical]) -> Republication:
    """After the restart and the drain: which identities are missing or unexpected, how many records were added, and
    which duplicated identities are a SOURCE replay (one copy below and one at or above the frozen end of their
    canonical partition) and which are not (extra copies on one side only)."""
    copies: dict[tuple[int, int], list[Canonical]] = {}
    unexpected = 0
    ambiguous = 0
    for record in canonical_after:
        ident = decode_identity(record.trace, record.span)
        if ident is None:
            ambiguous += 1
            continue
        if ident.batch != batch:
            continue
        if not (0 <= ident.index < produced.count and ident.k < produced.spans):
            unexpected += 1
            continue
        copies.setdefault((ident.index, ident.k), []).append(record)
    present = len(copies)
    expected = produced.count * produced.spans
    total = sum(len(v) for v in copies.values())
    growth = total - freeze.frozen_records
    straddling = same_phase = duplicates = 0
    sample: list[dict[str, Any]] = []
    for identity, records in sorted(copies.items()):
        if len(records) < 2:
            continue
        duplicates += len(records) - 1
        before = [r for r in records if r.offset < freeze.ends.get(r.partition, 0)]
        after = [r for r in records if r.offset >= freeze.ends.get(r.partition, 0)]
        if before and after:
            straddling += 1
        same_phase += max(len(before) - 1, 0) + max(len(after) - 1, 0)
        if len(sample) < 5:
            sample.append({"source_message": identity[0], "span": identity[1],
                           "raw": list(produced.acks.get(identity[0], ())),
                           "canonical_copies": [[r.partition, r.offset] for r in records]})
    fail: list[str] = []
    inconclusive: list[str] = []
    missing = expected - present
    if ambiguous:
        inconclusive.append(f"{ambiguous} canonical record(s) have no deterministic identity")
    if missing:
        fail.append(f"canonical topic: {missing} expected span identity(ies) are missing after the drain")
    if unexpected:
        fail.append(f"canonical topic: {unexpected} record(s) of this batch lie outside the fixture")
    if growth < freeze.predicted_growth:
        fail.append(f"the restarted processor published {growth} record(s), fewer than the {freeze.predicted_growth} its "
                    "committed source offsets require")
    elif growth > freeze.predicted_growth:
        inconclusive.append(f"{growth - freeze.predicted_growth} more record(s) were published after the restart than "
                            "the replay predicts: not explained by the source replay")
    if same_phase:
        inconclusive.append(f"{same_phase} extra copy(ies) of an identity lie on the same side of the freeze: "
                            "not a source replay")
    if (not fail and not inconclusive and straddling != freeze.published_uncommitted):
        inconclusive.append(f"{straddling} identity(ies) were republished across the freeze, the prediction is "
                            f"{freeze.published_uncommitted}: the duplicate accounting is inconsistent")
    return Republication(growth, missing, unexpected, duplicates, straddling, same_phase, fail, inconclusive, sample)


def expected_storage_counters(canonical_after: Sequence[Canonical], start: "PostStopOffsets",
                              rows_before: Sequence[Row]) -> tuple[int, int, int]:
    """(messages, inserted, conflicts) the storage consumer must report when it reads every canonical record from
    its committed positions: an identity not yet in PostgreSQL is inserted once, every other record is a conflict."""
    positions = {p: (c.offset if c.state == "committed" else c.low) for p, c in start.commits.items()}
    records = [r for r in canonical_after if r.offset >= positions.get(r.partition, 0)]
    persisted = {(row.trace, row.span) for row in rows_before}
    fresh = {(r.trace, r.span) for r in records} - persisted
    return len(records), len(fresh), len(records) - len(fresh)


def stable_canonical(env: "Env", attempts: int = 4) -> list[Canonical]:
    """The canonical topic, read until two reads agree (the producer is dead or stopped, so they must)."""
    previous = env.canonical()
    for _ in range(attempts):
        env.sleep(1.0)
        current = env.canonical()
        if sorted(dataclasses.astuple(r) for r in current) == sorted(dataclasses.astuple(r) for r in previous):
            return current
        previous = current
    raise StateNotStable(f"the canonical topic was still changing after {attempts} reads of the stopped processor")


def _stream_crash_case(env: "Env", cfg: Config, case: Case) -> Case:
    batch = CASE_BATCH["S6"]
    messages, spans = cfg.crash_messages, cfg.crash_spans
    if not source_message_fits(spans) or not (0 < spans <= 0xFFFF):
        case.verdict = "INCONCLUSIVE"
        case.problems.append(f"{spans} spans per message do not provably fit the {PRODUCER_MESSAGE_MAX_BYTES}-byte producer "
                             f"and {BROKER_MESSAGE_MAX_BYTES}-byte broker message limits (bound "
                             f"{source_message_size_bound(spans)} bytes): nothing was started or produced")
        return case
    env.stop(["storage-consumer"])                                  # it stays stopped: the duplicates must accumulate
    env.write_override(stream_no_restart=True, storage_timing=True)
    env.start("stream-processor")                                   # recreated with the restart policy "no"
    env.wait_running("stream-processor")
    try:
        policy = env.restart_policy("stream-processor")
    except SmokeFailure as failure:
        policy = f"unreadable: {bounded_excerpt(str(failure), 120)}"
    try:
        group_env = env.container_env("stream-processor", ("CONSUMER_GROUP_ID",))["CONSUMER_GROUP_ID"]
    except SmokeFailure as failure:
        group_env = f"unreadable: {bounded_excerpt(str(failure), 120)}"
    case.observations["stream_processor_configuration"] = {
        "restart_policy": policy, "required_restart_policy": "no", "consumer_group": group_env,
        "required_consumer_group": env.stream_group}
    if policy != "no" or group_env != env.stream_group:
        case.verdict = "INCONCLUSIVE"
        case.problems.append(f"the stream processor's restart policy is {policy!r} and its group {group_env!r}; both must be "
                             "'no' and this project's group before anything is killed: nothing was killed")
        return case
    # --- the kill target is identified and fully verified NOW, before anything is produced and before the progress wait:
    # the slow lookups must not sit between the last progress reading and the kill ---------------------------------
    try:
        target = env.kill_target(S6_SERVICE)
    except SmokeFailure as failure:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the kill target could not be identified: " + bounded_excerpt(str(failure), 200)
                             + "; nothing was killed")
        return case
    refusal = verify_kill_target(env, target, S6_SERVICE, S6_NEIGHBOURS)
    case.observations["kill_target"] = {**target.to_dict(), "verified": not refusal, "refusals": refusal}
    if refusal:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the kill was refused, nothing was killed: " + "; ".join(refusal))
        return case
    try:
        neighbour_ids = {name: env.container_id(name) for name in S6_NEIGHBOURS}
        before = env.inspect(S6_SERVICE)
        logs_before = diagnostic_counts(env.logs(S6_SERVICE))
    except SmokeFailure as failure:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the kill preconditions could not be read: " + bounded_excerpt(str(failure), 200)
                             + "; nothing was killed")
        return case
    case.observations["kill_target"]["neighbour_container_ids"] = dict(neighbour_ids)
    baseline_groups = env.group(env.stream_group, SOURCE_TOPIC)
    baseline = committed_total(baseline_groups)
    case.metrics["uncommitted_partitions_at_baseline"] = partitions_without_commit(baseline_groups)
    produced = env.produce(batch, messages, spans)
    case.observations["workload"] = {"batch": batch, "messages": messages, "spans_per_message": spans,
                                     "expected_identities": messages * spans, "baseline_committed_total": baseline}
    samples: list[dict[str, Any]] = []
    case.observations["commit_observations"] = {"samples": samples}
    window_started = env.clock()
    state = wait_window(env, env.stream_group, SOURCE_TOPIC, baseline, messages, cfg, samples, window_started)
    case.observations["commit_observations"] = {**bounded_samples(samples), "summary": summarize_commit_samples(samples)}
    case.observations["window"] = {"state": state, "required_range": list(cfg.window)}
    if state != "inside":
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the stream processor was not inside its processing window when the kill could be issued "
                             f"({state}); nothing was killed")
        return case
    # --- the one destructive step: re-validate the verified ids in ONE inspect, then kill -------------------------
    # (the full verification happened before the wait; this is the last look, and `env.kill` re-resolves the container
    # once more).  Anything that cannot be established refuses the kill.
    revalidation_started = env.clock()
    refusal = revalidate_kill(env, target, S6_SERVICE, neighbour_ids, S6_NEIGHBOURS)
    last_poll = samples[-1]["t"] if samples else 0.0
    case.observations["kill_revalidation"] = {
        "checked_container_ids": [target.container_id, *neighbour_ids.values()], "refusals": refusal,
        "revalidation_seconds": round(env.clock() - revalidation_started, 2),
        "seconds_from_last_progress_reading_to_kill_request": round(env.clock() - (window_started + last_poll), 2)}
    if refusal:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the kill was refused at the moment of the kill, nothing was killed: " + "; ".join(refusal))
        return case
    kill = env.kill(S6_SERVICE, target.container_id, "S6")
    try:
        _wait_exited(env, S6_SERVICE, cfg)
        facts = env.termination_facts(S6_SERVICE)
        logs_after = env.logs(S6_SERVICE)
    except SmokeFailure as failure:
        case.observations["termination"] = {"unreadable": bounded_excerpt(str(failure), 200)}
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the state after the kill could not be read: " + bounded_excerpt(str(failure), 200))
        return case
    first_after, graceful_after = diagnostic_counts(logs_after)
    reasons, record = attribute_termination(kill, target, facts, (first_after - logs_before[0], graceful_after - logs_before[1]),
                                            0, before.restarts)
    case.observations["termination"] = record
    if reasons:
        case.verdict = "INCONCLUSIVE"
        case.problems.append("the termination cannot be attributed to the authorized SIGKILL: " + "; ".join(reasons))
        return case
    # --- the frozen state ----------------------------------------------------------------------------------------
    post = env.group_after_stop(env.stream_group, SOURCE_TOPIC, S6_SERVICE)
    require_zero_low_baseline(post, what="S6 frozen source state")
    case.observations["post_kill_offsets"] = post.to_dict()
    try:
        frozen_canonical = stable_canonical(env)
    except StateNotStable as failure:
        case.verdict = "INCONCLUSIVE"
        case.problems.append(str(failure))
        return case
    freeze = analyse_stream_freeze(produced, post, frozen_canonical, batch)
    case.observations["frozen_source"] = {"committed": {str(p): v for p, v in sorted(freeze.committed.items())},
                                          "partitions": freeze.partitions}
    case.observations["frozen_canonical"] = {"records_of_this_case": freeze.frozen_records,
                                             "total_records": len(frozen_canonical),
                                             "ends": {str(p): v for p, v in sorted(freeze.ends.items())}}
    case.observations["replay_prediction"] = {
        "published_uncommitted_spans": freeze.published_uncommitted, "replayed_messages": freeze.replay_messages,
        "predicted_growth": freeze.predicted_growth, "predicted_straddling_duplicates": freeze.published_uncommitted,
        "partially_published_messages": freeze.partial_messages}
    case.metrics["published_but_uncommitted"] = freeze.published_uncommitted
    if freeze.fail_problems:
        case.problems += freeze.fail_problems
        case.verdict = "FAIL"
        return case
    if freeze.inconclusive:
        case.verdict = "INCONCLUSIVE"
        case.problems += freeze.inconclusive
        return case
    # --- restart and republication -------------------------------------------------------------------------------
    recheck = env.group_after_stop(env.stream_group, SOURCE_TOPIC, S6_SERVICE)
    if committed_offsets(recheck.groups) != freeze.committed:
        case.observations["committed_moved_before_restart"] = {"before": freeze.committed,
                                                               "after": committed_offsets(recheck.groups)}
        case.verdict = "FAIL"
        case.problems.append("the committed source offsets moved while the processor was dead")
        return case
    restart(env, [S6_SERVICE])
    if not env.wait_drained(env.stream_group, SOURCE_TOPIC, cfg.restart_wait):
        case.verdict = "INCONCLUSIVE"
        case.problems.append(f"the restarted stream processor did not drain the source topic within {cfg.restart_wait:.0f}s: "
                             "the group rebalance after the killed member, or the processor itself, was too slow; "
                             "republication is attempted but not observed")
        return case
    before2, logs_before2 = env.inspect(S6_SERVICE), diagnostic_counts(env.logs(S6_SERVICE))
    stop = env.stop([S6_SERVICE])
    observation, problems = observe_stop(env, S6_SERVICE, before2, logs_before2, stop, cfg.graceful_stop_max, [S6_SERVICE])
    case.stops.append(observation)
    case.problems += problems
    try:
        canonical_after = stable_canonical(env)
    except StateNotStable as failure:
        case.verdict = "INCONCLUSIVE"
        case.problems.append(str(failure))
        return case
    final_source = env.group_after_stop(env.stream_group, SOURCE_TOPIC, S6_SERVICE)
    case.observations["final_source_offsets"] = final_source.to_dict()
    behind = [p for p, row in sorted(final_source.groups.items()) if row.current != row.log_end]
    if behind:
        case.problems.append(f"the final committed source offsets did not reach the end offsets on partition(s) {behind}")
    rep = analyse_republication(produced, batch, freeze, canonical_after)
    case.observations["republication"] = {
        "observed_growth": rep.growth, "predicted_growth": freeze.predicted_growth, "missing_identities": rep.missing,
        "unexpected_identities": rep.unexpected, "duplicate_copies": rep.duplicate_copies,
        "straddling_duplicates": rep.straddling, "predicted_straddling_duplicates": freeze.published_uncommitted,
        "same_phase_extra_copies": rep.same_phase, "sample": rep.sample}
    case.problems += rep.fail_problems
    # --- downstream: the storage consumer reads the whole canonical topic once ------------------------------------
    storage_start = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
    require_zero_low_baseline(storage_start, what="S6 storage baseline")
    rows_before = env.rows()
    exp_messages, exp_inserted, exp_conflicts = expected_storage_counters(canonical_after, storage_start, rows_before)
    case.observations["storage_prediction"] = {"messages": exp_messages, "inserted": exp_inserted, "conflicts": exp_conflicts}
    restart(env, ["storage-consumer"])
    drained = env.wait_drained(env.storage_group, CANONICAL_TOPIC, cfg.drain_timeout)
    storage_timing = TimingEvidence("unreadable", reasons=["the storage consumer did not drain in time"])
    if drained:
        before3, logs_before3 = env.inspect("storage-consumer"), diagnostic_counts(env.logs("storage-consumer"))
        stop3 = env.stop(["storage-consumer"])
        observation3, problems3 = observe_stop(env, "storage-consumer", before3, logs_before3, stop3, cfg.graceful_stop_max,
                                               ["storage-consumer"])
        case.stops.append(observation3)
        case.problems += problems3
        try:
            storage_timing = parse_timing_evidence(env.logs("storage-consumer"), 1)
        except SmokeFailure as failure:
            storage_timing = TimingEvidence("unreadable", reasons=["the storage log could not be read: "
                                                                   + bounded_excerpt(str(failure), 200)])
        final_storage = env.group_after_stop(env.storage_group, CANONICAL_TOPIC, "storage-consumer")
        case.observations["final_storage_offsets"] = final_storage.to_dict()
        behind2 = [p for p, row in sorted(final_storage.groups.items()) if row.current != row.log_end]
        if behind2:
            case.problems.append(f"the final committed storage offsets did not reach the end offsets on partition(s) {behind2}")
    case.observations["storage_timing"] = storage_timing.to_dict()
    final_rows = env.rows()
    final = account_rows(env.expected(), final_rows)
    mismatches = identity_mismatches(canonical_after, final_rows)
    case.observations["final_rows"] = {
        "rows": len(final_rows), "expected": len(env.expected()), "missing": final.missing, "unexpected": final.unexpected,
        "duplicate_copies": final.duplicate_copies, "identity_mismatches": len(mismatches)}
    if drained and (final.missing or final.unexpected or final.duplicate_copies):
        case.problems.append(f"rows: {final.missing} missing, {final.unexpected} unexpected, "
                             f"{final.duplicate_copies} duplicated {list(final.detail)}")
    if drained and mismatches:
        case.problems.append(f"stored row metadata disagrees with the canonical topic for {len(mismatches)} row(s): {mismatches[0]}")
    if storage_timing.status == "valid":
        for label, got, want in (("messages", storage_timing.messages, exp_messages),
                                 ("inserted", storage_timing.inserted, exp_inserted),
                                 ("conflicts", storage_timing.conflicts, exp_conflicts)):
            if got != want:
                case.problems.append(f"the storage consumer reports {got} {label}, the canonical topic predicts {want}")
    case.metrics.update({"republished_duplicates": rep.straddling, "predicted_duplicates": freeze.published_uncommitted,
                         "canonical_growth": rep.growth, "predicted_growth": freeze.predicted_growth,
                         "storage_conflicts": storage_timing.conflicts})
    if case.problems:
        case.verdict = "FAIL"
    elif rep.inconclusive or not drained or storage_timing.status != "valid":
        case.verdict = "INCONCLUSIVE"
        case.problems += rep.inconclusive
        if not drained:
            case.problems.append("the storage consumer did not drain the canonical topic in time")
        elif storage_timing.status != "valid":
            case.problems.append(f"republication was observed but the downstream absorption is not: the storage consumer's "
                                 f"counters are {storage_timing.status}: " + "; ".join(storage_timing.reasons or ["no evidence"]))
    else:
        case.verdict = "PASS"
    return case


def case_s6(env: "Env", cfg: Config) -> Case:
    case = begin_case(env, "S6")
    try:
        return _stream_crash_case(env, cfg, case)
    finally:
        env.write_override()


CASE_FUNCTIONS: Mapping[str, Callable[[Env, Config], Case]] = {
    "S1": case_s1, "S2": case_s2, "S3": case_s3, "S4": case_s4, "S5": case_s5, "S6": case_s6}


def run_cases(env: Env, cfg: Config, selected: Sequence[str]) -> list[Case]:
    """In order; the first FAIL stops the run (nothing is retried and nothing further is started)."""
    results = []
    for name in ALL_CASES:
        if name not in selected:
            continue
        env.current_case = None
        try:
            case = CASE_FUNCTIONS[name](env, cfg)
        except BaseException as exc:
            # The case was aborted.  What it had already observed is kept as a partial, FAILED case and handed
            # to the caller on the exception itself; the exception is re-raised unchanged.
            partial = env.current_case if env.current_case is not None and env.current_case.name == name else Case(name, "FAIL")
            partial.verdict, partial.partial = "FAIL", True
            partial.problems.append(f"case aborted by {type(exc).__name__}: {bounded_excerpt(str(exc), 300)}")
            partial.observations["aborted"] = {"after_a_recorded_stop": bool(partial.stops),
                                               "exception": type(exc).__name__}
            try:
                exc.partial_cases = [*results, partial]
            except Exception:  # noqa: BLE001 - an exception that refuses attributes still propagates
                pass
            raise
        results.append(case)
        if case.verdict == "FAIL":
            break
    return results


# ---------------------------------------------------------------------------
# Names, override and credentials
# ---------------------------------------------------------------------------

def new_project_name() -> str:
    return PROJECT_PREFIX + uuid.uuid4().hex[:8]


def project_resource_names(project: str) -> tuple[str, ...]:
    """What Compose derives from the project name."""
    return (f"{project}-", f"{project}_")


def validate_project_name(name: str, docker_lines: Sequence[str]) -> None:
    if name == "agentops":
        raise SmokeFailure("the project name must never be the default 'agentops'")
    if not _PROJECT_RE.fullmatch(name):
        raise SmokeFailure(f"project name {name!r} is not {PROJECT_PREFIX}<8 hex>")
    for token in PROTECTED_TOKENS:
        if name.startswith(token) or token.startswith(name):
            raise SmokeFailure(f"project name {name!r} overlaps the protected name {token!r}")
    taken = [line for line in docker_lines if name in line]
    if taken:
        raise SmokeFailure("Docker objects of this project name already exist:\n" + "\n".join(taken[:6]))


def group_ids(project: str) -> tuple[str, str]:
    return f"{project}-stream", f"{project}-storage"


def test_override_text(project: str, *, batching_messages: Optional[int] = None, no_restart: bool = False,
                       stream_no_restart: bool = False, storage_timing: bool = False) -> str:
    """The one extra Compose file: written to the temporary directory, never to the repository."""
    stream, storage = group_ids(project)
    lines = [
        "# Written by run_shutdown_it.py into its temporary directory; never in the repository.",
        "services:",
        "  stream-processor:",
        f"    stop_grace_period: {STOP_GRACE}",
        *(['    restart: "no"'] if stream_no_restart else []),
        "    environment:",
        f"      CONSUMER_GROUP_ID: \"{stream}\"",
        "  storage-consumer:",
        f"    stop_grace_period: {STOP_GRACE}",
        *(['    restart: "no"'] if no_restart else []),
        "    environment:",
        f"      CONSUMER_GROUP_ID: \"{storage}\"",
    ]
    if batching_messages is not None:
        lines += [f"      {BATCH_ENV_NAME}: \"{int(batching_messages)}\"",
                  f"      {INTERVAL_ENV_NAME}: \"{BATCH_INTERVAL_SECONDS}\"",
                  f"      {TIMING_ENV_NAME}: \"{TIMING_INTERVAL_SECONDS}\""]
    elif storage_timing:
        lines += [f"      {TIMING_ENV_NAME}: \"{TIMING_INTERVAL_SECONDS}\""]
    return "\n".join(lines) + "\n"


def compose_files(override: Path) -> list[str]:
    return [smoke.COMPOSE_FILE, smoke.OVERRIDE_FILE, OVERLAY_FILE, str(override)]


def compose_command(project: str, override: Path, env_file: Path, *args: str) -> list[str]:
    if project == "agentops" or not _PROJECT_RE.fullmatch(project):
        raise SmokeFailure(f"refusing a Compose command for the project {project!r}")
    command = ["docker", "compose", "-p", project]
    for path in compose_files(override):
        command += ["-f", path]
    return [*command, "--env-file", str(env_file), *args]


def generate_credentials() -> dict[str, str]:
    return {name: secrets.token_urlsafe(24) for name in smoke.PASSWORD_VARIABLES}


def env_file_text(credentials: Mapping[str, str]) -> str:
    return "".join(f"{name}={value}\n" for name, value in credentials.items())


# ---------------------------------------------------------------------------
# Gates and preflight
# ---------------------------------------------------------------------------

def confirmation_phrase(expect_head: str) -> str:
    return CONFIRM_PREFIX + expect_head[:12]


def check_confirmation(given: Optional[str], expect_head: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expect_head or ""):
        raise SmokeFailure("--expect-head needs a full 40-character commit")
    if given != confirmation_phrase(expect_head):
        raise SmokeFailure("live execution needs --confirm " + confirmation_phrase(expect_head))


Shell = Callable[..., "subprocess.CompletedProcess"]


def git_state(sh: Shell, repo: Path, expect_head: str, *, branch: str = EXPECTED_BRANCH,
              own_files: Sequence[str] = OWN_FILES) -> str:
    """'development' (this harness and its test untracked, nothing else) or 'committed' (clean tree, both
    tracked); SmokeFailure otherwise.  Read-only."""
    def out(*args: str) -> str:
        result = sh(["git", "-C", str(repo), *args], timeout=60, what="git " + args[0])
        if result.returncode != 0:
            raise SmokeFailure(f"git {' '.join(args[:2])}: exit {result.returncode}")
        return result.stdout.strip()

    if not re.fullmatch(r"[0-9a-f]{40}", expect_head or ""):
        raise SmokeFailure("--expect-head needs a full 40-character commit")
    current = out("rev-parse", "--abbrev-ref", "HEAD")
    if current != branch:
        raise SmokeFailure(f"the branch is {current!r}, not {branch!r}")
    head = out("rev-parse", "HEAD")
    if head != expect_head:
        raise SmokeFailure(f"HEAD is {head}, not the expected commit {expect_head}")
    if out("diff", "--cached", "--name-only"):
        raise SmokeFailure("the index is not empty")
    status = {line for line in out("status", "--porcelain", "--untracked-files=all").splitlines() if line.strip()}
    if not status:
        return "committed"
    if status == {f"?? {path}" for path in own_files}:
        return "development"
    raise SmokeFailure("the working tree is neither clean nor exactly this harness and its test: "
                       + ", ".join(sorted(status)[:6]))


@dataclasses.dataclass
class Readings:
    """What the host and the engine report; None means 'could not be measured'."""
    power_source: Optional[str] = None
    battery_percent: Optional[int] = None
    available_mib: Optional[float] = None
    engine_bytes: Optional[int] = None
    free_disk_bytes: Optional[float] = None
    ports_in_use: Mapping[int, Optional[bool]] = dataclasses.field(default_factory=dict)


def host_gate_problems(readings: Readings) -> list[str]:
    """The gates that need no Docker: power, host memory, disk and ports.  An unmeasurable reading
    is an unmet gate."""
    problems = []
    if readings.power_source is None:
        problems.append("the power source could not be read")
    elif readings.power_source != "AC":
        problems.append(f"the machine is on {readings.power_source}, not AC power")
    mib = readings.available_mib
    if mib is None or isinstance(mib, bool) or not isinstance(mib, (int, float)) or math.isnan(mib):
        problems.append("available host memory could not be read")
    elif mib < MIN_HOST_MEMORY_MIB:
        problems.append(f"available host memory {mib:.0f} MiB is below {MIN_HOST_MEMORY_MIB} MiB")
    disk = batching.disk_gate(readings.free_disk_bytes)
    if not disk.ok:
        problems.append(disk.message)
    for port in PORTS:
        state = readings.ports_in_use.get(port)
        if state is None:
            problems.append(f"port {port} could not be checked")
        elif state:
            problems.append(f"port {port} is in use")
    return problems


def engine_problem(engine_bytes: Any) -> Optional[str]:
    """The Docker engine's memory gate; None when it is met."""
    gate = batching.engine_gate(engine_bytes) if isinstance(engine_bytes, int) and not isinstance(engine_bytes, bool) \
        else batching.Gate(False, False, "the Docker engine memory could not be read")
    return None if gate.ok else gate.message


def evaluate_gates(readings: Readings) -> list[str]:
    """Every unmet gate, host and engine."""
    problems = host_gate_problems(readings)
    engine = engine_problem(readings.engine_bytes)
    return problems + ([engine] if engine else [])


def find_blockers(*, benchmark_markers: Sequence[str], own_markers: Sequence[str],
                  docker_lines: Sequence[str], processes: Sequence[str]) -> list[str]:
    blockers = [f"benchmark marker {name}" for name in benchmark_markers]
    blockers += [f"unverified cleanup marker {name}" for name in own_markers]
    for line in docker_lines:
        for needle, what in ((batching.BENCHMARK_PROJECT, "benchmark"),
                             (batching.PIPELINE_IT_PREFIX, "pipeline test"),
                             ("agentops-batching-it-", "batching validation"),
                             (PROJECT_PREFIX, "earlier shutdown validation")):
            if needle in line:
                blockers.append(f"{what} Docker object: {line.strip()[:120]}")
                break
    blockers += [f"process {pid}" for pid in processes if str(pid).strip()]
    return blockers


def marker_path(root: Optional[Path] = None) -> Path:
    return (Path(tempfile.gettempdir()) / "agentops-shutdown-it" if root is None else Path(root)) / "CLEANUP_UNVERIFIED"


def own_markers(root: Optional[Path] = None) -> list[str]:
    return ["CLEANUP_UNVERIFIED"] if marker_path(root).exists() else []


def write_marker(reason: str, root: Optional[Path] = None) -> Path:
    path = marker_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(reason[:2000] + "\n", encoding="utf-8")
    return path


def protected_lines(fingerprint: Mapping[str, Sequence[str]]) -> list[str]:
    """The inventory lines that belong to the MVP, legacy, benchmark or sibling-validation resources."""
    needles = (*PROTECTED_TOKENS, *PROTECTED_CONTAINERS)
    return sorted(line for kind in fingerprint.values() for line in kind if any(n in line for n in needles))


def protected_inventory_problems(before: Mapping[str, Sequence[str]], after: Mapping[str, Sequence[str]]) -> list[str]:
    old, new = set(protected_lines(before)), set(protected_lines(after))
    return ([f"protected object missing or changed: {line}" for line in sorted(old - new)]
            + [f"protected object appeared: {line}" for line in sorted(new - old)])


def free_port_probe(port: int) -> Optional[bool]:
    """True when something listens on or holds 127.0.0.1:port; False when it is free; None if unknown."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True


def default_docker_data_dir() -> Optional[Path]:
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "Docker" if base else None


@dataclasses.dataclass
class Preflight:
    project: str
    git_state: str
    before: dict[str, list[str]]
    protected_before: dict[str, Optional[str]]
    readings: Readings


def run_preflight(sh: Shell, repo: Path, expect_head: str, *, docker_data_dir: Optional[Path],
                  power: Callable[[], tuple[str, int]] = pipeline.power_state,
                  memory: Callable[[], float] = batching.available_memory_mib,
                  disk: Callable[[Path], float] = lambda p: shutil.disk_usage(str(p)).free,
                  port_probe: Callable[[int], Optional[bool]] = free_port_probe,
                  markers: Callable[[], list[str]] = batching.benchmark_markers,
                  processes: Callable[[], list[str]] = batching.competing_processes,
                  own: Callable[[], list[str]] = own_markers,
                  inventory: Optional[Callable[[], dict[str, list[str]]]] = None,
                  snapshot: Optional[Callable[[], dict[str, Optional[str]]]] = None,
                  name: Optional[str] = None) -> Preflight:
    """Everything that must hold before a live run.  Read-only.  The order matters: nothing that
    needs Docker is touched until the git state and every host gate have passed."""
    state = git_state(sh, repo, expect_head)

    readings = Readings(ports_in_use={port: port_probe(port) for port in PORTS})
    try:
        readings.power_source, readings.battery_percent = power()
    except Exception:  # noqa: BLE001 - unmeasurable is a failed gate
        pass
    try:
        readings.available_mib = memory()
    except Exception:  # noqa: BLE001
        pass
    try:
        readings.free_disk_bytes = disk(docker_data_dir) if docker_data_dir and Path(docker_data_dir).exists() else None
    except Exception:  # noqa: BLE001
        pass
    host_problems = host_gate_problems(readings)
    early = find_blockers(benchmark_markers=markers(), own_markers=own(), docker_lines=[], processes=processes())
    if host_problems or early:
        raise SmokeFailure("preflight failed before any Docker command:\n" + "\n".join([*host_problems, *early]))

    # From here on Docker is only read.
    info = json.loads(_checked(sh, ["docker", "info", "--format", "{{json .}}"], what="docker info"))
    readings.engine_bytes = info.get("MemTotal") if isinstance(info.get("MemTotal"), int) else None
    engine = engine_problem(readings.engine_bytes)
    if engine:
        raise SmokeFailure(engine)
    before = inventory() if inventory else _inventory(sh)
    lines = [line for kind in before.values() for line in kind]
    blockers = find_blockers(benchmark_markers=[], own_markers=[], docker_lines=lines, processes=[])
    if blockers:
        raise SmokeFailure("preflight blockers:\n" + "\n".join(blockers))
    protected = (snapshot or (lambda: _protected_snapshot(sh)))()
    legacy = batching.legacy_problem(protected.get(batching.LEGACY_POSTGRES))
    if legacy:
        raise SmokeFailure(legacy)
    project = name or new_project_name()
    validate_project_name(project, lines)
    return Preflight(project, state, before, protected, readings)


def _checked(sh: Shell, command: Sequence[str], *, what: str, timeout: float = smoke.T_COMMAND) -> str:
    result = sh(list(command), timeout=timeout, what=what)
    if result.returncode != 0:
        raise SmokeFailure(f"{what}: exit {result.returncode}\n" + "\n".join((result.stdout + result.stderr).strip().splitlines()[-8:]))
    return result.stdout


def _lines(sh: Shell, *args: str) -> list[str]:
    return sorted(line for line in _checked(sh, ["docker", *args], what="docker " + args[0]).splitlines() if line.strip())


def _inventory(sh: Shell) -> dict[str, list[str]]:
    return {
        "containers": _lines(sh, "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}} {{.State}}"),
        "volumes": _lines(sh, "volume", "ls", "--format", "{{.Name}}"),
        "networks": _lines(sh, "network", "ls", "--no-trunc", "--format", "{{.ID}} {{.Name}}"),
        "images": _lines(sh, "images", "--no-trunc", "--format", "{{.Repository}}:{{.Tag}} {{.ID}}"),
    }


def _protected_snapshot(sh: Shell) -> dict[str, Optional[str]]:
    snapshot: dict[str, Optional[str]] = {}
    for name in PROTECTED_CONTAINERS:
        result = sh(["docker", "inspect", "-f",
                     "{{.Id}} {{.State.Status}} {{.State.StartedAt}} {{.State.FinishedAt}} {{.RestartCount}}"
                     " nets={{range $k, $v := .NetworkSettings.Networks}}{{$k}}:{{$v.NetworkID}},{{end}}"
                     " mounts={{range .Mounts}}{{.Type}}:{{.Name}}:{{.Destination}}:{{.RW}},{{end}}", name],
                    timeout=smoke.T_COMMAND, what="docker inspect")
        snapshot[name] = result.stdout.strip() if result.returncode == 0 else None
    return snapshot


# ---------------------------------------------------------------------------
# The live environment
# ---------------------------------------------------------------------------

class LiveEnv(Env):
    """Every command names the project, the four Compose files and the temporary environment file."""

    def __init__(self, project: str, override: Path, env_file: Path, sh: Shell,
                 clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
                 utc: Callable[[], str] = lambda: utc_now_iso()) -> None:
        self.project, self.override, self.env_file = project, override, env_file
        self.sh, self._clock, self._sleep, self._utc = sh, clock, sleeper, utc
        self.stream_group, self.storage_group = group_ids(project)
        self.produced = []
        self.protected_ids: frozenset = frozenset()    # set by execute() from the protected-container snapshot
        self.tool_reads: list[ToolRead] = []           # failed or fallback reads, the last few
        smoke.RUN.compose_used = True

    def cmd(self, *args: str) -> list[str]:
        return compose_command(self.project, self.override, self.env_file, *args)

    def compose(self, *args: str, timeout: float = smoke.T_COMMAND, what: str = "") -> str:
        return _checked(self.sh, self.cmd(*args), what=what or "compose " + args[0], timeout=timeout)

    def sleep(self, seconds: float) -> None:
        self._sleep(seconds)

    def clock(self) -> float:
        return self._clock()

    def _container(self, service: str) -> str:
        found = self.compose("ps", "-a", "-q", service).split()
        if len(found) != 1:
            raise SmokeFailure(f"{service}: expected one container, found {len(found)}")
        return found[0]

    def inspect(self, service: str) -> Inspect:
        return parse_inspect(_checked(self.sh, ["docker", "inspect", "-f", INSPECT_FORMAT, self._container(service)],
                                      what="docker inspect"))

    def logs(self, service: str) -> str:
        return self.compose("logs", "--no-color", "--no-log-prefix", service, what=f"logs {service}")

    def start(self, service: str) -> None:
        self.compose("up", "-d", "--no-deps", "--no-build", service, timeout=smoke.T_BOOTSTRAP, what=f"up {service}")

    def stop(self, services: Sequence[str]) -> StopResult:
        # No -t: the stop period under test is the configured stop_grace_period.
        requested_utc = self._utc()
        started = self._clock()
        result = self.sh(self.cmd("stop", *services), timeout=120.0, what="compose stop")
        return StopResult(self._clock() - started, result.returncode, started, requested_utc)

    def wait_running(self, service: str) -> None:
        def probe() -> Optional[bool]:
            state = self.inspect(service)
            probe.detail = f"{service} is {state.status}"  # type: ignore[attr-defined]
            return True if state.status == "running" else None
        smoke.wait_for(f"{service} to be running", smoke.T_HOST_SERVICE, probe, interval=1.0)

    def produce(self, batch: int, count: int, spans: int) -> Produced:
        output = self.compose("run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "stream-processor",
                              "-c", PRODUCER_SOURCE, str(batch), str(count), str(spans),
                              timeout=600.0, what="producer step")
        produced = parse_producer_output(output, batch, count, spans)
        self.produced.append(produced)
        return produced

    def _kafka(self, tool: str, *args: str, timeout: float = smoke.T_COMMAND) -> subprocess.CompletedProcess:
        return self.sh(self.cmd("exec", "-T", "kafka", f"{smoke.KAFKA_BIN}/{tool}", "--bootstrap-server", BROKER, *args),
                       timeout=timeout, what=tool)

    def end_offsets(self, topic: str) -> dict[int, GroupPartition]:
        result = self._kafka("kafka-get-offsets.sh", "--topic", topic)
        found = {}
        for token in result.stdout.split():
            parts = token.rsplit(":", 2)
            if len(parts) == 3 and parts[0] == topic and parts[1].isdigit() and parts[2].isdigit():
                found[int(parts[1])] = GroupPartition(None, int(parts[2]))
        if len(found) != smoke.PARTITIONS:
            raise SmokeFailure(f"unexpected end offsets for {topic}: {result.stdout.strip()[:120]!r}")
        return found

    def group(self, group: str, topic: str) -> dict[int, GroupPartition]:
        """The group's description, polled briefly while it settles (the same 30 s as before).  A group the
        tool reports as absent has committed nothing: its committed offsets are None and the log ends come
        from the topic.  Every attempt is classified; when the poll ends unusable, the error carries what the
        tool printed (bounded, redacted), the attempt count and the elapsed time."""
        purpose = f"kafka-consumer-groups --describe --group {group} (topic {topic})"
        started = self._clock()
        deadline = started + 30.0
        attempts = 0
        while True:
            attempts += 1
            result = self._kafka("kafka-consumer-groups.sh", "--describe", "--group", group)
            classification, parsed = classify_group_output(result.stdout, result.stderr, result.returncode, group, topic)
            if classification in USABLE_GROUP_CLASSES and parsed is not None:
                return parsed
            now = self._clock()
            read = ToolRead(purpose, attempts, now - started, result.returncode, classification,
                            "absent" if classification == GROUP_ABSENT else
                            ("present" if classification in (GROUP_INCOMPLETE, GROUP_MALFORMED, GROUP_NO_ACTIVE_MEMBERS) else "unknown"),
                            bounded_excerpt(result.stdout), bounded_excerpt(result.stderr))
            if classification == GROUP_ABSENT:
                self._remember(read)
                return self.end_offsets(topic)
            if now >= deadline:
                self._remember(read)
                raise GroupReadError(
                    f"no stable description of group {group} on {topic} after {attempts} attempt(s) in "
                    f"{read.elapsed_seconds:.0f}s; last classification: {classification}; exit {result.returncode}; "
                    f"stdout: {read.stdout_excerpt!r}; stderr: {read.stderr_excerpt!r}", read)
            self._sleep(1.0)

    def _remember(self, read: ToolRead) -> None:
        self.tool_reads = [*self.tool_reads, read][-5:]

    def group_after_stop(self, group: str, topic: str, service: str) -> PostStopOffsets:
        """The committed offsets of a group whose consumer has stopped (see the note above COMMITTED_SOURCE).
        Refuses unless the service's container is exited; asks Kafka for each partition by name; cross-checks the
        CLI listing; never turns an unknown into 0 and never uses an end offset as a committed offset."""
        state = self.inspect(service)
        if state.status != "exited":
            raise PostStopError(f"{service} is {state.status!r}, not stopped: the post-stop inspection is refused",
                                {"service_status": state.status})
        result = self.sh(self.cmd("run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "stream-processor", "-c",
                                  COMMITTED_SOURCE, group, topic), timeout=120.0, what="committed-offset step")
        try:
            commits = parse_committed_output(result.stdout)
        except PostStopError as failure:
            failure.detail.update({"exit_status": result.returncode, "stderr": bounded_excerpt(result.stderr)})
            raise
        if result.returncode != 0:
            raise PostStopError(f"the committed-offset step exited {result.returncode}",
                                {"stdout": bounded_excerpt(result.stdout), "stderr": bounded_excerpt(result.stderr)})
        listing = self._kafka("kafka-consumer-groups.sh", "--describe", "--group", group)
        corroboration = corroborate_with_cli(listing.stdout, listing.stderr, listing.returncode, group, topic, commits)
        groups = {partition: GroupPartition(commit.offset, commit.high) for partition, commit in commits.items()}
        return PostStopOffsets(groups, commits, corroboration)

    def canonical(self) -> list[Canonical]:
        result = self._kafka("kafka-console-consumer.sh", "--topic", CANONICAL_TOPIC, "--from-beginning",
                             "--timeout-ms", "20000", "--property", "print.partition=true",
                             "--property", "print.offset=true", timeout=300.0)
        if result.returncode != 0:
            raise SmokeFailure("reading the canonical topic failed:\n" + result.stderr[-400:])
        return parse_canonical_records(result.stdout)

    def rows(self) -> list[Row]:
        return parse_rows(self.compose(
            "exec", "-T", "postgres", "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-U", "agentops", "-d", "agentops",
            "-c", "SELECT trace_id, span_id, kafka_partition, kafka_offset FROM telemetry_spans ORDER BY id",
            timeout=120.0, what="psql"))

    def wait_drained(self, group: str, topic: str, timeout: float) -> bool:
        deadline = self._clock() + timeout
        while True:
            groups = self.group(group, topic)
            if all((row.current or 0) >= (row.log_end or 0) for row in groups.values()):
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(1.0)

    def container_env(self, service: str, names: Sequence[str]) -> dict[str, Optional[str]]:
        """The effective value (None if absent) of exactly the named variables in the service's container.
        Read-only `docker inspect` of this project's container; no other variable is ever read out."""
        raw = _checked(self.sh, ["docker", "inspect", "-f", "{{json .Config.Env}}", self._container(service)],
                       what="docker inspect environment")
        try:
            items = json.loads(raw)
        except ValueError:
            raise SmokeFailure("the container environment was not readable JSON") from None
        if items is None:
            items = []
        if not isinstance(items, list):
            raise SmokeFailure("the container environment was not a list")
        found: dict[str, Optional[str]] = {name: None for name in names}
        for item in items:
            key, sep, value = item.partition("=") if isinstance(item, str) else ("", "", "")
            if sep and key in found:
                found[key] = value
        return found

    def set_storage_batching(self, messages: Optional[int], *, no_restart: bool = False) -> None:
        self.override.write_text(test_override_text(self.project, batching_messages=messages, no_restart=no_restart),
                                 encoding="utf-8")

    def write_override(self, *, batching_messages: Optional[int] = None, no_restart: bool = False,
                       stream_no_restart: bool = False, storage_timing: bool = False) -> None:
        self.override.write_text(test_override_text(self.project, batching_messages=batching_messages, no_restart=no_restart,
                                                    stream_no_restart=stream_no_restart, storage_timing=storage_timing),
                                 encoding="utf-8")

    def restart_policy(self, service: str) -> str:
        return _checked(self.sh, ["docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", self._container(service)],
                        what="docker inspect restart policy").strip()

    def kill_target(self, service: str) -> KillTarget:
        """What Compose and Docker say about the service's container (read-only)."""
        container = self._container(service)
        fields = _checked(self.sh, ["docker", "inspect", "-f",
                                    "{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
                                    "{{index .Config.Labels \"com.docker.compose.service\"}}|{{.Name}}|{{.State.Status}}|"
                                    "{{.HostConfig.RestartPolicy.Name}}", container], what="docker inspect kill target").strip().split("|")
        if len(fields) != 6:
            raise SmokeFailure("the kill target inspection was not readable")
        return KillTarget(container, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5])

    def container_id(self, service: str) -> str:
        """The one container Compose knows for this project's service (read-only)."""
        return self._container(service)

    def recheck_containers(self, ids: Sequence[str]) -> dict[str, ContainerFacts]:
        """ONE `docker inspect` of these full ids (read-only); a container that is gone, or an output that does not
        describe exactly these ids in order, raises."""
        ids = list(dict.fromkeys(ids))
        if not ids or not all(_HEX64.fullmatch(one) for one in ids):
            raise SmokeFailure("a full 64-hex container id is required for every re-inspected container")
        lines = _checked(self.sh, ["docker", "inspect", "-f",
                                   "{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
                                   "{{index .Config.Labels \"com.docker.compose.service\"}}|{{.Name}}|{{.State.Status}}|"
                                   "{{.HostConfig.RestartPolicy.Name}}", *ids], what="docker inspect re-check").strip().splitlines()
        rows = [line.strip().split("|") for line in lines]
        if len(rows) != len(ids) or any(len(row) != 6 for row in rows):
            raise SmokeFailure("the re-inspection was not readable")
        return {requested: ContainerFacts(*row) for requested, row in zip(ids, rows)}

    def kill(self, service: str, container_id: str, case: str = "S5") -> KillResult:
        """The only kill in this harness: `compose kill -s SIGKILL <service>` of this project, where the service is the
        one the case may kill (S5: storage-consumer, S6: stream-processor), and only if the container is still exactly
        the one that was verified.  Never a bare name, never the host, never the engine."""
        if case not in KILL_TARGETS or service != KILL_TARGETS[case] or not kill_arguments_allowed(
                ("kill", "-s", "SIGKILL", service), case):
            raise SmokeFailure(f"refusing to kill {service!r} for case {case!r}")
        if self._container(service) != container_id:
            raise SmokeFailure("refusing to kill: the container is no longer the one that was verified")
        started = self._clock()
        result = self.sh(self.cmd(*kill_arguments(case)), timeout=60.0, what="compose kill")
        return KillResult(result.returncode, self._clock() - started)

    def termination_facts(self, service: str) -> TerminationFacts:
        fields = _checked(self.sh, ["docker", "inspect", "-f",
                                    "{{.Id}}|{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.RestartCount}}|"
                                    "{{.State.Error}}|{{.State.FinishedAt}}", self._container(service)],
                          what="docker inspect termination").strip().split("|", 6)
        if len(fields) != 7:
            raise SmokeFailure("the termination inspection was not readable")
        try:
            return TerminationFacts(fields[0], fields[1], int(fields[2]), fields[3].strip().lower() == "true",
                                    int(fields[4]), fields[5], fields[6])
        except ValueError:
            raise SmokeFailure("the termination inspection had unreadable numbers") from None


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Docker networks: the protected user-defined networks and the default bridge
# ---------------------------------------------------------------------------
#
# Docker may recreate its own default bridge (a new ID) while a Compose project starts.  That alone is not a
# change to anything this harness protects, so a POSITIVELY VERIFIED default bridge is compared by a fixed token
# instead of its ID, in this harness's own cleanup comparison only (pipeline.safe_cleanup is not changed).
# Everything else stays strict: both AgentOps user-defined networks must be identical before and after, and any
# bridge that cannot be verified, any missing or ambiguous inspection and any other difference fails closed.

USER_NETWORKS: tuple[str, ...] = ("agentops-mvp_mvp-net", "agentops_agentops-net")
DEFAULT_BRIDGE_NAME: str = "bridge"
DEFAULT_BRIDGE_OPTION: str = "com.docker.network.bridge.default_bridge"
BRIDGE_TOKEN: str = "<verified-default-bridge>"


@dataclasses.dataclass(frozen=True)
class NetworkFacts:
    """Everything read from one `docker network inspect`; frozen so that equality means every field is equal."""
    id: str
    name: str
    driver: str
    scope: str
    internal: bool
    created: str
    labels: tuple[tuple[str, str], ...]
    options: tuple[tuple[str, str], ...]
    attached: tuple[str, ...]            # running containers only: "<container id>:<name>"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "driver": self.driver, "scope": self.scope,
                "internal": self.internal, "created": self.created, "labels": dict(self.labels),
                "options": dict(self.options), "attached": list(self.attached)}


def parse_network(text: str) -> NetworkFacts:
    """Strict reader of `docker network inspect <one network>`; anything else raises SmokeFailure."""
    try:
        body = json.loads(text)
    except ValueError:
        raise SmokeFailure("the network inspection was not readable JSON") from None
    if not isinstance(body, list) or len(body) != 1 or not isinstance(body[0], dict):
        raise SmokeFailure("the network inspection did not describe exactly one network")
    item = body[0]
    try:
        facts = {key: item[key] for key in ("Id", "Name", "Driver", "Scope", "Created")}
    except KeyError as missing:
        raise SmokeFailure(f"the network inspection lacks {missing}") from None
    internal = item.get("Internal")
    labels, options, containers = item.get("Labels") or {}, item.get("Options") or {}, item.get("Containers") or {}
    if (not all(isinstance(v, str) and v for v in facts.values()) or not isinstance(internal, bool)
            or not all(isinstance(m, dict) for m in (labels, options, containers))):
        raise SmokeFailure("the network inspection has unexpected field types")
    attached = []
    for cid, info in containers.items():
        name = info.get("Name") if isinstance(info, dict) else None
        if not isinstance(name, str):
            raise SmokeFailure("the network inspection lists an attachment without a name")
        attached.append(f"{cid}:{name}")
    return NetworkFacts(facts["Id"], facts["Name"], facts["Driver"], facts["Scope"], internal, facts["Created"],
                        tuple(sorted((str(k), str(v)) for k, v in labels.items())),
                        tuple(sorted((str(k), str(v)) for k, v in options.items())), tuple(sorted(attached)))


def read_network(sh: Shell, reference: str, *, by_id: bool = False) -> Optional[NetworkFacts]:
    """None only when Docker says the network does not exist; any other failure or mismatch raises."""
    result = sh(["docker", "network", "inspect", reference], timeout=smoke.T_COMMAND, what="docker network inspect")
    if result.returncode != 0:
        text = (result.stdout + result.stderr).lower()
        if "not found" in text or "no such network" in text:
            return None
        raise SmokeFailure(f"docker network inspect {reference[:20]}: exit {result.returncode}")
    facts = parse_network(result.stdout)
    if (facts.id if by_id else facts.name) != reference:
        raise SmokeFailure(f"docker network inspect {reference[:20]} described a different network")
    return facts


def bridge_problems(facts: NetworkFacts) -> list[str]:
    """Why this is NOT the Docker-managed default bridge (empty = positively verified)."""
    problems = []
    if facts.name != DEFAULT_BRIDGE_NAME:
        problems.append(f"name {facts.name!r}")
    if facts.driver != "bridge":
        problems.append(f"driver {facts.driver!r}")
    if facts.scope != "local":
        problems.append(f"scope {facts.scope!r}")
    if facts.internal:
        problems.append("internal")
    if facts.labels:
        problems.append("it has labels")
    if dict(facts.options).get(DEFAULT_BRIDGE_OPTION) != "true":
        problems.append("it is not marked as the default bridge")
    if facts.attached:
        problems.append(f"{len(facts.attached)} attached container(s)")
    return problems


@dataclasses.dataclass
class NetworkSnapshot:
    bridge: Optional[NetworkFacts]
    bridge_problems: list[str]
    users: dict[str, Optional[NetworkFacts]]

    @property
    def bridge_verified(self) -> bool:
        return self.bridge is not None and not self.bridge_problems


def read_network_snapshot(sh: Shell) -> NetworkSnapshot:
    """The default bridge (exactly one network of that name, verified) and both protected user-defined networks."""
    listed = _lines(sh, "network", "ls", "--no-trunc", "--format", "{{.ID}} {{.Name}}")
    candidates = [line.split(None, 1) for line in listed]
    bridges = [cells[0] for cells in candidates if len(cells) == 2 and cells[1] == DEFAULT_BRIDGE_NAME]
    bridge: Optional[NetworkFacts] = None
    problems: list[str] = []
    if len(bridges) != 1:
        problems.append(f"{len(bridges)} networks named {DEFAULT_BRIDGE_NAME!r} were listed, expected exactly one")
    else:
        bridge = read_network(sh, bridges[0], by_id=True)
        if bridge is None:
            problems.append("the default bridge could not be inspected")
        else:
            problems.extend(bridge_problems(bridge))
    return NetworkSnapshot(bridge, problems, {name: read_network(sh, name) for name in USER_NETWORKS})


def normalise_bridge(inventory: Mapping[str, Sequence[str]], snapshot: NetworkSnapshot) -> dict[str, list[str]]:
    """The inventory with the verified default bridge's line compared by token instead of by ID.  Exactly one
    matching line is replaced; anything else leaves the inventory as it was (so a difference still shows)."""
    result = {kind: list(lines) for kind, lines in inventory.items()}
    if snapshot.bridge_verified and snapshot.bridge is not None:
        line = f"{snapshot.bridge.id} {DEFAULT_BRIDGE_NAME}"
        if result.get("networks", []).count(line) == 1:
            result["networks"] = sorted(BRIDGE_TOKEN + " " + DEFAULT_BRIDGE_NAME if entry == line else entry
                                        for entry in result["networks"])
    return result


def compare_networks(before: NetworkSnapshot, after: NetworkSnapshot) -> dict[str, Any]:
    """The before/after comparison kept as data.  The default bridge is informational only when verified at both
    ends; the two protected networks must be identical in every field, including their attachments."""
    problems: list[str] = []
    users: dict[str, Any] = {}
    for name in USER_NETWORKS:
        was, now = before.users.get(name), after.users.get(name)
        users[name] = {"before": was.to_dict() if was else None, "after": now.to_dict() if now else None,
                       "identical": was is not None and was == now}
        if was is None or now is None:
            problems.append(f"protected network {name} was not found {'before' if was is None else 'after'} the run")
        elif was != now:
            fields = [f.name for f in dataclasses.fields(NetworkFacts) if getattr(was, f.name) != getattr(now, f.name)]
            problems.append(f"protected network {name} changed: {', '.join(fields)}")
    for label, snap in (("before", before), ("after", after)):
        if not snap.bridge_verified:
            problems.append(f"the default bridge could not be verified {label} the run: "
                            + ("; ".join(snap.bridge_problems) or "no inspection"))
    recreated = bool(before.bridge and after.bridge and before.bridge.id != after.bridge.id)
    bridge = {"before": before.bridge.to_dict() if before.bridge else None,
              "after": after.bridge.to_dict() if after.bridge else None,
              "verified_before": before.bridge_verified, "verified_after": after.bridge_verified,
              "recreated": recreated,
              "treated_as": "informational" if before.bridge_verified and after.bridge_verified else "problem"}
    return {"default_bridge": bridge, "user_defined": users, "problems": problems}


class ShutdownOps:
    """What cleanup touches, scoped by the project name; the interface pipeline.safe_cleanup uses.
    Unlike the sibling harnesses it never passes --rmi: its own images are removed one by one by exact
    name, and only when they carry its Compose label."""

    def __init__(self, project: str, override: Optional[Path], env_file: Optional[Path], sh: Shell,
                 temp: Optional[Path], status_before: Optional[Sequence[str]] = None,
                 protected_before: Optional[Mapping[str, Optional[str]]] = None,
                 networks_before: Optional[NetworkSnapshot] = None) -> None:
        if project == "agentops" or not _PROJECT_RE.fullmatch(project):
            raise SmokeFailure(f"cleanup refuses the project name {project!r}")
        self.project, self.override, self.env_file, self.sh, self.temp = project, override, env_file, sh, temp
        self.status_before, self.protected_before = status_before, protected_before
        self.networks_before: Optional[NetworkSnapshot] = networks_before
        self.networks_after: Optional[NetworkSnapshot] = None
        self.log: list[str] = []
        self.down_command: list[str] = []

    def can_down(self) -> bool:
        return bool(self.override is not None and self.env_file is not None and Path(self.env_file).is_file())

    def down(self) -> tuple[int, str]:
        self.down_command = compose_command(self.project, self.override, self.env_file,  # type: ignore[arg-type]
                                            "down", "--volumes", "--remove-orphans")
        result = self.sh(self.down_command, timeout=smoke.T_DOWN, what="compose down")
        tail = smoke.redact(result.stderr.strip()[-300:])
        self.log.append(f"compose down (project {self.project}): exit {result.returncode}\n{tail}")
        return result.returncode, tail

    def project_objects(self, kind: str) -> list[str]:
        label = f"label={_LABEL_PROJECT}={self.project}"
        command = {"containers": ["ps", "-a", "-q", "--filter", label],
                   "networks": ["network", "ls", "-q", "--filter", label],
                   "volumes": ["volume", "ls", "-q", "--filter", label],
                   "images": ["images", "-q", "--filter", label]}[kind]
        return _lines(self.sh, *command)

    def owned_images(self) -> list[str]:
        listed = _lines(self.sh, "images", "--filter", f"label={_LABEL_PROJECT}={self.project}",
                        "--format", "{{.Repository}}:{{.Tag}}")
        return [ref for ref in listed if ref.startswith(self.project + "-") and "<none>" not in ref]

    def remove_image(self, reference: str) -> bool:
        if not reference.startswith(self.project + "-"):
            raise SmokeFailure(f"refusing to remove {reference!r}: not named after the project")
        result = self.sh(["docker", "image", "remove", reference], timeout=smoke.T_COMMAND, what="docker image remove")
        self.log.append(f"image remove {reference}: exit {result.returncode}")
        return result.returncode == 0

    def fingerprint(self) -> dict[str, list[str]]:
        """The inventory; with the network snapshots on hand, a positively verified default bridge is compared by
        token (see normalise_bridge).  Without them (no snapshot was taken) it is the raw inventory."""
        raw = _inventory(self.sh)
        if self.networks_before is None:
            return raw
        self.networks_after = read_network_snapshot(self.sh)
        return normalise_bridge(raw, self.networks_after)

    def leaked(self) -> int:
        count = smoke.RUN.masked_in_logs
        if self.temp is not None and Path(self.temp).exists():
            for path in Path(self.temp).glob("*"):
                if path.is_file() and path.name != "shutdown.env":
                    text = path.read_text(encoding="utf-8", errors="replace")
                    count += sum(text.count(v) for v in smoke.RUN.generated.values())
        return count

    def remove_temp(self) -> bool:
        if self.temp is None:
            return True
        resolved = Path(self.temp).resolve()
        root = Path(tempfile.gettempdir()).resolve()
        if resolved == smoke.REPO or smoke.REPO in resolved.parents or root not in resolved.parents:
            raise SmokeFailure(f"refusing to delete {resolved}: not a temporary directory")
        return smoke._remove_tree(resolved)

    def repository_problems(self) -> list[str]:
        problems = []
        try:
            now = sorted(line for line in _checked(
                self.sh, ["git", "-C", str(smoke.REPO), "status", "--porcelain", "--untracked-files=all"],
                what="git status").splitlines() if line.strip())
            if self.status_before is not None and now != sorted(self.status_before):
                problems.append("the repository changed during the run: " + ", ".join(sorted(set(now) ^ set(self.status_before))))
        except SmokeFailure as failure:
            problems.append(str(failure))
        return problems

    def normal_stack_problem(self) -> Optional[str]:
        if self.protected_before is None:
            return None
        problems = batching.protected_changes(self.protected_before, _protected_snapshot(self.sh))
        return "; ".join(problems) if problems else None


@dataclasses.dataclass
class CleanupResult:
    problems: list[str]
    inventory_before: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    inventory_after: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    protected_inventory_problems: list[str] = dataclasses.field(default_factory=list)
    protected_before: Optional[dict[str, Optional[str]]] = None
    protected_after: Optional[dict[str, Optional[str]]] = None
    protected_changes: list[str] = dataclasses.field(default_factory=list)
    network_report: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return not self.problems


def fingerprint_summary(fingerprint: Mapping[str, Sequence[str]]) -> dict[str, dict[str, Any]]:
    return {kind: {"count": len(lines), "fingerprint": smoke.short_hash(lines)} for kind, lines in fingerprint.items()}


def cleanup_detailed(ops: ShutdownOps, before: Optional[dict[str, list[str]]],
                     report: Callable[[str], None] = say) -> CleanupResult:
    """cleanup() with the comparison kept as data for the evidence.  The same commands, in the same order."""
    result = CleanupResult(problems=[])

    def honest(text: str) -> None:
        report(text.replace("compose down --volumes --rmi local --remove-orphans",
                            "compose down --volumes --remove-orphans (no --rmi: own images are removed by exact name)"))
    networks_before = getattr(ops, "networks_before", None)
    # The shared comparison is given the inventory with the verified bridge compared by token (when it can be).
    compared = normalise_bridge(before, networks_before) if before is not None and networks_before is not None else before
    try:
        result.problems.extend(pipeline.safe_cleanup(ops.project, compared, ops, honest))
        if before is not None:
            after = ops.fingerprint()
            result.inventory_before, result.inventory_after = fingerprint_summary(compared), fingerprint_summary(after)
            result.protected_inventory_problems = protected_inventory_problems(compared, after)
            result.problems.extend(result.protected_inventory_problems)
        if networks_before is not None:
            networks_after = getattr(ops, "networks_after", None) or read_network_snapshot(ops.sh)
            result.network_report = compare_networks(networks_before, networks_after)
            result.problems.extend(result.network_report["problems"])
        if ops.protected_before is not None:
            result.protected_before = dict(ops.protected_before)
            result.protected_after = _protected_snapshot(ops.sh)
            result.protected_changes = batching.protected_changes(result.protected_before, result.protected_after)
    except Exception as exc:  # noqa: BLE001
        result.problems.append(f"cleanup could not be completed: {type(exc).__name__}: {exc}")
    return result


def cleanup(ops: ShutdownOps, before: Optional[dict[str, list[str]]], report: Callable[[str], None] = say) -> list[str]:
    """pipeline.safe_cleanup plus the protected-inventory comparison; the problems it returns decide
    whether cleanup is 'verified'.  An exception anywhere is itself a problem, never a silent success."""
    return cleanup_detailed(ops, before, report).problems


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

EVIDENCE_SCHEMA: str = "run_shutdown_it.evidence/1"


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def utc_stamp(iso: str) -> str:
    """'2026-10-18T01:02:03.123456+00:00' -> '20261018T010203123456Z' (sortable, filename-safe)."""
    return re.sub(r"[^0-9T]", "", iso.split("+")[0].rstrip("Z")) + "Z"


def default_evidence_dir() -> Path:
    return Path(tempfile.gettempdir()) / "agentops-shutdown-it-evidence"


def evidence_dir_problem(directory: Path, repo: Optional[Path] = None) -> Optional[str]:
    """Why this directory may not hold evidence: inside the repository, in the benchmark evidence
    area, or in the cleanup-marker directory.  None when it may."""
    repo = smoke.REPO if repo is None else repo
    resolved = Path(directory).resolve()
    if resolved == repo or repo in resolved.parents:
        return f"{resolved} is inside the repository"
    benchmarks = (Path(tempfile.gettempdir()) / "agentops-benchmarks").resolve()
    if resolved == benchmarks or benchmarks in resolved.parents or "agentops-benchmarks" in resolved.parts:
        return f"{resolved} is inside the benchmark evidence area"
    markers = marker_path().parent.resolve()
    if resolved == markers or markers in resolved.parents:
        return f"{resolved} is inside the cleanup-marker directory"
    return None


def evidence_filename(project: str, kind: str, stamp: str, attempt: int = 0) -> str:
    return f"shutdown-it-{stamp}-{project}-{kind}" + (f"-{attempt}" if attempt else "") + ".json"


def collect_snapshot(env: Any, service: str = "stream-processor", tail: int = 40) -> dict[str, Any]:
    """A read-only picture of one disposable service for an aborted run: its container state and a bounded,
    redacted log tail.  Never starts, stops or changes anything, and never raises: whatever cannot be
    collected is recorded in 'errors' so that it cannot mask the original failure or block cleanup."""
    snapshot: dict[str, Any] = {"service": service, "state": None, "log_lines_total": None, "log_tail": [], "errors": []}
    try:
        snapshot["state"] = dataclasses.asdict(env.inspect(service))
    except Exception as exc:  # noqa: BLE001
        snapshot["errors"].append(f"state: {type(exc).__name__}: {bounded_excerpt(str(exc), 160)}")
    try:
        lines = env.logs(service).splitlines()
        snapshot["log_lines_total"] = len(lines)
        snapshot["log_tail"] = [bounded_excerpt(line, 300) for line in lines[-tail:]]
    except Exception as exc:  # noqa: BLE001
        snapshot["errors"].append(f"log: {type(exc).__name__}: {bounded_excerpt(str(exc), 160)}")
    return snapshot


#: The service each case is about; an unknown or missing case is snapshotted on both.
CASE_SNAPSHOT_SERVICE: Mapping[str, str] = {
    "S1": "stream-processor", "S2": "stream-processor", "S3": "storage-consumer", "S4": "storage-consumer"}


def aborted_case_services(env: Any) -> list[str]:
    """The service(s) whose state and log tail belong to the case that was aborted."""
    try:
        name = getattr(getattr(env, "current_case", None), "name", None)
        service = CASE_SNAPSHOT_SERVICE.get(name) if isinstance(name, str) else None
    except Exception:  # noqa: BLE001 - never let the choice of service mask the failure
        service = None
    return [service] if service else ["stream-processor", "storage-consumer"]


def failure_diagnostics(env: Any, read: Optional[ToolRead] = None) -> dict[str, Any]:
    """Everything worth keeping when a run aborted: the failed tool reads and a read-only snapshot of the
    service the aborted case is about ('aborted_case_snapshot'); when the case is unknown, of both services
    ('aborted_case_snapshot' is then the stream processor, 'aborted_case_snapshots' lists both)."""
    reads = [item.to_dict() for item in getattr(env, "tool_reads", [])]
    if read is not None and read.to_dict() not in reads:
        reads.append(read.to_dict())
    services = aborted_case_services(env)
    snapshots = [collect_snapshot(env, service) for service in services]
    result: dict[str, Any] = {"tool_reads": reads, "aborted_case_snapshot": snapshots[0]}
    if len(snapshots) > 1:
        result["aborted_case_snapshots"] = snapshots
    return result


def case_summary(results: Sequence[Case]) -> list[dict[str, Any]]:
    return [case.to_dict() for case in results]


def build_evidence(*, kind: str, project: str, git_head: str, git_state: str, selected: Sequence[str],
                   results: Sequence[Case], failure: str, verdict: str, started_utc: str, finished_utc: str,
                   evidence_problems: Sequence[str] = (), cleanup: Optional[CleanupResult] = None,
                   precleanup: Optional[Mapping[str, str]] = None,
                   diagnostics: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA, "kind": kind, "project": project, "git_head": git_head,
        "git_state": git_state, "selected_cases": list(selected), "stop_grace_period": STOP_GRACE,
        "started_utc": started_utc, "finished_utc": finished_utc, "failure": redact_text(failure)[:2000],
        "verdict": verdict,
        "verdict_note": ("provisional: cleanup had not yet been performed" if kind == "pre-cleanup"
                         else "final: after cleanup and evidence writing"),
        "evidence_problems": list(evidence_problems), "cases": case_summary(results),
    }
    if cleanup is not None:
        record["cleanup"] = {
            "verified": cleanup.verified, "problems": [redact_text(p) for p in cleanup.problems],
            "inventory_before": cleanup.inventory_before, "inventory_after": cleanup.inventory_after,
            "protected_inventory_problems": cleanup.protected_inventory_problems,
            "protected_containers_before": cleanup.protected_before, "protected_containers_after": cleanup.protected_after,
            "protected_container_changes": cleanup.protected_changes,
        }
        if cleanup.network_report:
            record["cleanup"]["networks"] = cleanup.network_report
    if precleanup is not None:
        record["pre_cleanup_file"] = dict(precleanup)
    if diagnostics:
        record["diagnostics"] = dict(diagnostics)
    return record


def serialize_evidence(record: Mapping[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=True, default=str) + "\n"


def write_evidence(directory: Path, project: str, kind: str, record: Mapping[str, Any], stamp: str) -> tuple[Path, str]:
    """Writes one new evidence file and returns (path, sha256).  Never overwrites; refuses a directory that
    is inside the repository or the benchmark area; refuses to write text holding a generated credential;
    reads the file back and compares its hash.  Raises SmokeFailure (or OSError) when anything is wrong."""
    problem = evidence_dir_problem(directory)
    if problem:
        raise SmokeFailure("evidence directory refused: " + problem)
    text = smoke.redact(serialize_evidence(redact_structure(record)))      # values first; then the exact credentials
    if credential_leaks(text):
        raise SmokeFailure("evidence refused: a generated credential would have been written")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    for attempt in range(10):
        path = directory / evidence_filename(project, kind, stamp, attempt)
        try:
            with open(path, "xb") as handle:
                handle.write(data)
        except FileExistsError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SmokeFailure(f"evidence file {path} did not read back as written")
        return path, digest
    raise SmokeFailure("no unique evidence filename was available")


def final_verdict(results: Sequence[Case], *, selected: Sequence[str], cleanup_verified: bool, failure: str,
                  evidence_problems: Sequence[str]) -> str:
    """overall_verdict, plus: a failure or an evidence problem is FAIL, and a PASS needs every recorded
    per-service assertion to hold.  Never turns FAIL, HOLD or INCONCLUSIVE into PASS."""
    if failure or evidence_problems:
        return "FAIL"
    base = overall_verdict(results, cleanup_verified=cleanup_verified, selected=selected)
    if base == "PASS" and any(not stop.all_passed for case in results for stop in case.stops):
        return "FAIL"
    return base


def verdict_consistency_problems(verdict: str, results: Sequence[Case], *, selected: Sequence[str],
                                 cleanup_verified: bool, failure: str, evidence_problems: Sequence[str]) -> list[str]:
    """What would make the stated verdict untrue; empty when it is consistent with the recorded facts."""
    problems = []
    if verdict not in ("PASS", "FAIL", "HOLD"):
        problems.append(f"unknown verdict {verdict!r}")
    if verdict == "PASS":
        if failure:
            problems.append("PASS with a recorded failure")
        if evidence_problems:
            problems.append("PASS with an evidence problem")
        if not cleanup_verified:
            problems.append("PASS without verified cleanup")
        by_name = {case.name: case for case in results}
        for name in selected:
            if name not in by_name or by_name[name].verdict != "PASS":
                problems.append(f"PASS but case {name} did not pass")
        if any(not stop.all_passed for case in results for stop in case.stops):
            problems.append("PASS with a failed per-service assertion")
    if verdict != "FAIL" and any(case.verdict == "FAIL" for case in results):
        problems.append(f"{verdict} with a failed case")
    return problems


# ---------------------------------------------------------------------------
# Plan and command line
# ---------------------------------------------------------------------------

def plan_text(project: str, expect_head: Optional[str], cases: Sequence[str], cfg: Config) -> str:
    phrase = confirmation_phrase(expect_head) if expect_head else CONFIRM_PREFIX + "<first 12 hex of the head>"
    return "\n".join([
        "run_shutdown_it: PLAN ONLY.  Nothing was read, started or changed.",
        f"project (illustrative; a fresh one is generated at run time): {project}",
        f"compose files: {', '.join(compose_files(Path('<temporary>/override.yml')))}",
        f"extra override: stop_grace_period {STOP_GRACE} on {', '.join(APP_SERVICES)}; groups of this project",
        f"cases: {', '.join(cases)}   source batch: {cfg.messages} messages x {cfg.spans} spans",
        *(["S5 SIGKILLs the disposable storage consumer (and only that container); it must be named in --cases"]
          if "S5" in cases else []),
        *(["S6 SIGKILLs the disposable stream processor (and only that container); it must be named in --cases; "
           f"it uses its own input of {cfg.crash_messages} messages x {cfg.crash_spans} spans"] if "S6" in cases else []),
        f"gates: AC power; host memory >= {MIN_HOST_MEMORY_MIB} MiB; Docker memory >= "
        f"{MIN_ENGINE_BYTES // 1024 ** 2} MiB; free disk >= {MIN_DISK_GIB} GiB; ports {PORTS} free; "
        "exact HEAD, clean tree; no benchmark activity; no earlier unverified cleanup",
        f"ports: 127.0.0.1 only ({', '.join(str(p) for p in PORTS)})",
        "preflight:  --preflight --expect-head <commit>",
        f"live run:   --execute --expect-head <commit> --confirm {phrase}",
    ])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_shutdown_it",
        description="Graceful-shutdown validation of the containerized processing services on a disposable "
                    "Compose project.  Prints a plan unless --preflight or --execute is given.")
    parser.add_argument("--expect-head", metavar="COMMIT")
    parser.add_argument("--preflight", action="store_true", help="read-only checks; nothing is created")
    parser.add_argument("--execute", action="store_true", help="the live run; needs --confirm")
    parser.add_argument("--confirm", metavar="PHRASE")
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--messages", type=int, default=Config.messages)
    parser.add_argument("--docker-data-dir", type=Path, default=None)
    return parser


def parse_cases(text: str) -> list[str]:
    names = [part.strip().upper() for part in text.split(",") if part.strip()]
    if not names or any(name not in ALL_CASES for name in names) or len(set(names)) != len(names):
        raise SmokeFailure(f"--cases must be a list of distinct names from {', '.join(ALL_CASES)}")
    return names


def _default_shell(command: Sequence[str], *, timeout: float, what: str = "") -> "subprocess.CompletedProcess":
    return smoke.run(command, timeout=timeout, what=what)


def execute(args: argparse.Namespace, cases: Sequence[str], cfg: Config, sh: Shell = _default_shell,
            preflight: Callable[..., Preflight] = run_preflight,
            sleeper: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.monotonic,
            evidence_dir: Optional[Path] = None,
            utc: Callable[[], str] = utc_now_iso) -> int:
    """The live run.  Only reached with --execute and a matching --confirm."""
    check_confirmation(args.confirm, args.expect_head)
    started_utc = utc()
    evidence_directory = Path(evidence_dir) if evidence_dir is not None else default_evidence_dir()
    data_dir = args.docker_data_dir or default_docker_data_dir()
    pre = preflight(sh, smoke.REPO, args.expect_head, docker_data_dir=data_dir)
    project = pre.project
    networks_before = read_network_snapshot(sh)                    # reads only; nothing exists yet to clean up
    network_start_problems = [*(["the default bridge is not verified: " + "; ".join(networks_before.bridge_problems)]
                                if not networks_before.bridge_verified else []),
                              *(f"protected network {name} was not found" for name, facts in networks_before.users.items()
                                if facts is None)]
    if network_start_problems:
        raise SmokeFailure("network preflight failed before any Docker change:\n" + "\n".join(network_start_problems))
    section(f"disposable project {project} (git state: {pre.git_state})")
    status_before = sorted(line for line in _checked(
        sh, ["git", "-C", str(smoke.REPO), "status", "--porcelain", "--untracked-files=all"],
        what="git status").splitlines() if line.strip())
    temp = Path(tempfile.mkdtemp(prefix="shutdown-it-")).resolve()
    try:
        smoke.register_workspace(temp)           # without this record smoke._remove_tree refuses to delete it
    except (OSError, SmokeFailure) as exc:
        raise SmokeFailure(f"could not record ownership of the temporary directory: {exc}") from exc
    credentials = generate_credentials()
    smoke.RUN.temp, smoke.RUN.generated = temp, dict(credentials)
    env_file = temp / "shutdown.env"
    env_file.write_text(env_file_text(credentials), encoding="utf-8")
    override = temp / "override.yml"
    override.write_text(test_override_text(project), encoding="utf-8")
    smoke.RUN.env_file = env_file
    ops = ShutdownOps(project, override, env_file, sh, temp, status_before, pre.protected_before, networks_before)
    results: list[Case] = []
    failure = ""
    env: Optional[LiveEnv] = None
    failure_read: Optional[ToolRead] = None
    interrupted = False
    aborted: Optional[BaseException] = None
    try:
        env = LiveEnv(project, override, env_file, sh, clock=clock, sleeper=sleeper, utc=utc)
        env.protected_ids = frozenset(value.split()[0] for value in (pre.protected_before or {}).values() if value)
        env.compose("build", "postgres", "db-bootstrap", *APP_SERVICES, timeout=smoke.T_BUILD, what="compose build")
        env.compose("up", "-d", "kafka", timeout=smoke.T_BROKER, what="up kafka")
        env.compose("up", "-d", "--no-build", "kafka-init", "postgres", "db-bootstrap",
                    timeout=smoke.T_BOOTSTRAP, what="up infrastructure")
        smoke.wait_for("kafka-init to finish", smoke.T_KAFKA_INIT,
                       lambda: True if env.inspect("kafka-init").status == "exited" else None)
        smoke.wait_for("db-bootstrap to finish", smoke.T_BOOTSTRAP,
                       lambda: True if env.inspect("db-bootstrap").status == "exited" else None, interval=3.0)
        if env.inspect("kafka-init").exit_code != 0 or env.inspect("db-bootstrap").exit_code != 0:
            raise SmokeFailure("the topic initialisation or the database bootstrap failed")
        restart(env, APP_SERVICES)
        results = run_cases(env, cfg, cases)
    except SmokeFailure as exc:
        failure = str(exc)
        failure_read = getattr(exc, "read", None)
        aborted = exc
        say(f"FAILURE: {failure}")
    except KeyboardInterrupt as exc:
        failure = "interrupted"
        interrupted = True
        aborted = exc
        say("FAILURE: interrupted")
    except Exception as exc:  # noqa: BLE001 - anything unforeseen is a failure, and is cleaned up too
        failure = f"{type(exc).__name__}: {exc}"
        aborted = exc
        say(f"FAILURE: {failure}")
    partial_cases = getattr(aborted, "partial_cases", None) if aborted is not None else None
    if partial_cases:
        results = list(partial_cases)
    # An aborted run keeps a bounded, read-only picture of the stream processor and of what the tools printed.
    diagnostics: dict[str, Any] = {}
    if failure and env is not None and not interrupted:
        try:
            diagnostics = failure_diagnostics(env, failure_read)
            snapshot = diagnostics["aborted_case_snapshot"]
            say(f"DIAGNOSTICS: {len(diagnostics['tool_reads'])} failed tool read(s); {snapshot['service']} state "
                f"{(snapshot['state'] or {}).get('status')}, {snapshot['log_lines_total']} log line(s), "
                f"{len(snapshot['errors'])} collection error(s)")
        except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the failure or block cleanup
            say(f"DIAGNOSTICS could not be collected: {type(exc).__name__}")
    # The per-service results are made durable BEFORE the disposable containers are removed.
    evidence_problems: list[str] = []
    precleanup: dict[str, str] = {}
    provisional = "FAIL" if failure else overall_verdict(results, cleanup_verified=True, selected=cases)
    try:
        path, digest = write_evidence(
            evidence_directory, project, "pre-cleanup",
            build_evidence(kind="pre-cleanup", project=project, git_head=args.expect_head, git_state=pre.git_state,
                           selected=cases, results=results, failure=failure, verdict=provisional,
                           started_utc=started_utc, finished_utc=utc(), diagnostics=diagnostics),
            utc_stamp(utc()))
        precleanup = {"name": path.name, "sha256": digest}
        say(f"evidence (pre-cleanup): {path}  sha256 {digest}")
    except (SmokeFailure, OSError) as exc:
        evidence_problems.append(f"the pre-cleanup evidence could not be written: {exc}")
        say(f"EVIDENCE PROBLEM: {evidence_problems[-1]}")
    section("project teardown")
    cleaned = cleanup_detailed(ops, pre.before)
    problems = cleaned.problems
    for problem in problems:
        say(f"CLEANUP PROBLEM: {problem}")
    if problems:
        write_marker("; ".join(problems))
    verdict = final_verdict(results, selected=cases, cleanup_verified=not problems, failure=failure,
                            evidence_problems=evidence_problems)
    inconsistent = verdict_consistency_problems(verdict, results, selected=cases, cleanup_verified=not problems,
                                                failure=failure, evidence_problems=evidence_problems)
    if inconsistent:
        evidence_problems.extend(inconsistent)
        verdict = "FAIL"
    try:
        path, digest = write_evidence(
            evidence_directory, project, "final",
            build_evidence(kind="final", project=project, git_head=args.expect_head, git_state=pre.git_state,
                           selected=cases, results=results, failure=failure, verdict=verdict,
                           started_utc=started_utc, finished_utc=utc(), evidence_problems=evidence_problems,
                           cleanup=cleaned, precleanup=precleanup or None, diagnostics=diagnostics),
            utc_stamp(utc()))
        say(f"evidence (final): {path}  sha256 {digest}")
    except (SmokeFailure, OSError) as exc:
        evidence_problems.append(f"the final evidence could not be written: {exc}")
        say(f"EVIDENCE PROBLEM: {evidence_problems[-1]}")
        verdict = "FAIL"                      # never a PASS without its evidence
    section("result")
    for case in results:
        say(f"  {case.name}: {case.verdict}  {case.metrics}")
        for stop in case.stops:
            say(f"      {stop.service}: exit {stop.exit_code}, status {stop.status}, restarts "
                f"{stop.restarts_before}->{stop.restarts_after}, oom {stop.oom_killed}, first-signal "
                f"{stop.first_signal_diagnostics}, graceful {stop.graceful_stop_lines}, stop "
                f"{'n/a' if stop.stop_seconds is None else format(stop.stop_seconds, '.2f')}s, "
                f"assertions {'all passed' if stop.all_passed else 'NOT all passed'}")
        for problem in case.problems:
            say(f"      {problem}")
    say(f"overall: {verdict}")
    say(f"cleanup verified: {'yes' if not problems else 'NO'}")
    say(f"evidence written: {'yes' if not evidence_problems else 'NO'}")
    return 0 if verdict == "PASS" else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cases = parse_cases(args.cases)
    except SmokeFailure as failure:
        print(str(failure), file=sys.stderr)
        return 2
    cfg = Config(messages=args.messages)
    if not args.preflight and not args.execute:
        print(plan_text(new_project_name(), args.expect_head, cases, cfg))
        return 0
    try:
        if args.execute:
            check_confirmation(args.confirm, args.expect_head)
        elif not re.fullmatch(r"[0-9a-f]{40}", args.expect_head or ""):
            raise SmokeFailure("--expect-head needs a full 40-character commit")
    except SmokeFailure as failure:
        print(str(failure), file=sys.stderr)
        return 2
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")
    if args.preflight and not args.execute:
        try:
            pre = run_preflight(_default_shell, smoke.REPO, args.expect_head,
                                docker_data_dir=args.docker_data_dir or default_docker_data_dir())
        except SmokeFailure as failure:
            say(f"PREFLIGHT FAILED: {failure}")
            return 1
        say(f"preflight passed (git state {pre.git_state}); candidate project {pre.project}; nothing was created")
        return 0
    pipeline.keep_awake()
    try:
        return execute(args, cases, cfg)
    except SmokeFailure as failure:
        say(f"REFUSED: {failure}")
        return 1
    finally:
        pipeline.release_awake()


if __name__ == "__main__":
    sys.exit(main())

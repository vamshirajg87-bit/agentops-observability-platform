"""
scripts/e2e_verify.py

End-to-end verification for the agentops stream processor path.

Captures per-partition high-watermarks on all three topics before the demo
request, waits for the user to run exactly one demo invocation, then
collects and validates the post-baseline records.

Usage:
    # PowerShell — Stage A (direct exporter suppressed):
    $env:PYTHONPATH = "$PWD\\demo-app"
    $env:AGENTOPS_DIRECT_EXPORT = "false"   # set in the DEMO shell, not here
    python scripts/e2e_verify.py --timeout 30

    # Linux/macOS:
    PYTHONPATH=/path/to/repo/demo-app python scripts/e2e_verify.py --timeout 30

Exit codes:
    0 — OVERALL PASS
    1 — OVERALL FAIL (check individual lines for details)
    2 — Precondition failure (Kafka unreachable, topic missing, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# Path setup: make stream-processor modules and demo-app schemas importable.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_REPO_ROOT, "stream-processor"))
sys.path.insert(0, os.path.join(_REPO_ROOT, "demo-app"))

import confluent_kafka
from confluent_kafka import Consumer, TopicPartition

import config
from schemas.telemetry import CanonicalSpanEvent

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPECTED_SPAN_NAMES: frozenset[str] = frozenset({
    "agentops.request",
    "supervisor.start",
    "research.plan",
    "retrieval.search",
    "tool.execute",
    "research.synthesize",
    "supervisor.finalize",
})

ROOT_SPAN_NAME = "agentops.request"


# ---------------------------------------------------------------------------
# Kafka helpers
# ---------------------------------------------------------------------------

def _make_consumer(suffix: str) -> Consumer:
    group_id = f"agentops-e2e-verify-{suffix}-{uuid.uuid4().hex[:8]}"
    return Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP_SERVERS,
        "group.id": group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "latest",
    })


def get_topic_partitions(consumer: Consumer, topic: str) -> list[int]:
    """Return sorted partition IDs discovered from broker metadata."""
    try:
        meta = consumer.list_topics(topic, timeout=10.0)
    except confluent_kafka.KafkaException as exc:
        print(f"PRECONDITION FAIL: cannot reach broker: {exc}", file=sys.stderr)
        sys.exit(2)
    if topic not in meta.topics:
        print(f"PRECONDITION FAIL: topic {topic!r} not found", file=sys.stderr)
        sys.exit(2)
    err = meta.topics[topic].error
    if err is not None:
        print(f"PRECONDITION FAIL: topic {topic!r} error: {err}", file=sys.stderr)
        sys.exit(2)
    return sorted(meta.topics[topic].partitions.keys())


def capture_watermarks(
    consumer: Consumer,
    topic: str,
    partitions: list[int],
) -> dict[int, int]:
    """Return {partition: high_watermark} using broker metadata query."""
    marks: dict[int, int] = {}
    for p in partitions:
        tp = TopicPartition(topic, p)
        try:
            lo, hi = consumer.get_watermark_offsets(tp, timeout=5.0)
        except confluent_kafka.KafkaException as exc:
            print(
                f"PRECONDITION FAIL: cannot get watermarks for "
                f"{topic}[{p}]: {exc}",
                file=sys.stderr,
            )
            sys.exit(2)
        # hi == -1001 (OFFSET_INVALID) when partition has no committed data
        marks[p] = max(hi, 0)
    return marks


def collect_post_baseline(
    topic: str,
    watermarks: dict[int, int],
    timeout_seconds: int,
    settling_seconds: int = 4,
) -> list[confluent_kafka.Message]:
    """
    Assign a consumer to each partition at the baseline offset and collect
    all records that arrive within timeout_seconds.  Stops early if no new
    record arrives within settling_seconds after the last one.
    """
    consumer = _make_consumer(f"collect-{topic.replace('.', '-')}")
    tps = [TopicPartition(topic, p, watermarks[p]) for p in watermarks]
    consumer.assign(tps)

    records: list[confluent_kafka.Message] = []
    deadline = time.monotonic() + timeout_seconds
    last_new = time.monotonic()

    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            msg = consumer.poll(timeout=min(1.0, remaining))
            if msg is None:
                if time.monotonic() - last_new >= settling_seconds and records:
                    break
                continue
            if msg.error():
                continue
            records.append(msg)
            last_new = time.monotonic()
    finally:
        consumer.close()

    return records


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def deserialize_trusted(
    messages: list[confluent_kafka.Message],
) -> tuple[list[CanonicalSpanEvent], list[str]]:
    """
    Deserialize trusted-topic messages as CanonicalSpanEvent.
    Returns (valid_events, error_descriptions).
    """
    events: list[CanonicalSpanEvent] = []
    errors: list[str] = []
    for msg in messages:
        try:
            data = json.loads(msg.value().decode("utf-8"))
            event = CanonicalSpanEvent.model_validate(data)
            events.append(event)
        except Exception as exc:
            errors.append(f"partition={msg.partition()} offset={msg.offset()}: {exc}")
    return events, errors


def _result(label: str, passed: bool, detail: str = "") -> bool:
    status = "PASS" if passed else "FAIL"
    suffix = f"  ({detail})" if detail else ""
    print(f"{label}: {status}{suffix}")
    return passed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="E2E verification for the agentops stream processor path."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to wait for post-baseline trusted records (default: 30).",
    )
    parser.add_argument(
        "--settling",
        type=int,
        default=4,
        help="Seconds of inactivity before stopping collection (default: 4).",
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # 1. Capture baselines for all three topics.
    # ------------------------------------------------------------------
    probe = _make_consumer("probe")

    raw_partitions = get_topic_partitions(probe, config.TOPIC_OTLP_TRACES)
    trusted_partitions = get_topic_partitions(probe, config.TOPIC_SPANS)
    dlq_partitions = get_topic_partitions(probe, config.TOPIC_DLQ)

    raw_marks = capture_watermarks(probe, config.TOPIC_OTLP_TRACES, raw_partitions)
    trusted_marks = capture_watermarks(probe, config.TOPIC_SPANS, trusted_partitions)
    dlq_marks = capture_watermarks(probe, config.TOPIC_DLQ, dlq_partitions)
    probe.close()

    print("Baselines captured:")
    print(f"  {config.TOPIC_OTLP_TRACES}: {raw_marks}")
    print(f"  {config.TOPIC_SPANS}:       {trusted_marks}")
    print(f"  {config.TOPIC_DLQ}:         {dlq_marks}")
    print()

    # ------------------------------------------------------------------
    # 2. Wait for user to run exactly one demo request.
    # ------------------------------------------------------------------
    print(">>> Baselines captured.")
    print(">>> Ensure AGENTOPS_DIRECT_EXPORT=false is set in the demo-app shell.")
    print(">>> Run exactly ONE demo request now, then press Enter. <<<")
    input()
    print()
    print(f"Collecting post-baseline records (timeout={args.timeout}s, "
          f"settling={args.settling}s)...")

    # ------------------------------------------------------------------
    # 3. Gather post-baseline records (trusted first — longest wait).
    # ------------------------------------------------------------------
    trusted_msgs = collect_post_baseline(
        config.TOPIC_SPANS, trusted_marks, args.timeout, args.settling
    )
    raw_msgs = collect_post_baseline(
        config.TOPIC_OTLP_TRACES, raw_marks, 5, 2
    )
    dlq_msgs = collect_post_baseline(
        config.TOPIC_DLQ, dlq_marks, 5, 2
    )

    print(f"Post-baseline counts — raw: {len(raw_msgs)}, "
          f"trusted: {len(trusted_msgs)}, dlq: {len(dlq_msgs)}")
    print()

    # ------------------------------------------------------------------
    # 4. Deserialize trusted records.
    # ------------------------------------------------------------------
    all_events, deser_errors = deserialize_trusted(trusted_msgs)

    # ------------------------------------------------------------------
    # 4a. Identify test trace root candidate.
    # ------------------------------------------------------------------
    root_candidates = [
        e for e in all_events
        if e.span_name == ROOT_SPAN_NAME and e.parent_span_id is None
    ]

    test_trace_id: str | None = None
    if len(root_candidates) == 1:
        test_trace_id = root_candidates[0].trace_id
    # Zero or >1 root candidates → test_trace_id stays None (FAIL below).

    test_spans = (
        [e for e in all_events if e.trace_id == test_trace_id]
        if test_trace_id
        else []
    )
    unrelated = [e for e in all_events if e.trace_id != test_trace_id]
    unrelated_trace_ids = sorted({e.trace_id for e in unrelated})

    root = root_candidates[0] if len(root_candidates) == 1 else None
    children = [s for s in test_spans if s.span_id != root.span_id] if root else []

    # ------------------------------------------------------------------
    # 5–9. Validate and report.
    # ------------------------------------------------------------------
    print("=" * 60)
    results: list[bool] = []

    # RAW_TOPIC_ADVANCED
    results.append(_result(
        "RAW_TOPIC_ADVANCED",
        len(raw_msgs) >= 1,
        f"post-baseline raw records: {len(raw_msgs)}",
    ))

    # TEST_TRACE_IDENTIFIED
    if len(root_candidates) == 0:
        id_detail = "no agentops.request root span found"
    elif len(root_candidates) > 1:
        ids = ", ".join(c.trace_id for c in root_candidates)
        id_detail = f"ambiguous: {len(root_candidates)} root spans ({ids})"
    else:
        id_detail = f"trace_id={test_trace_id}"
    results.append(_result(
        "TEST_TRACE_IDENTIFIED",
        len(root_candidates) == 1,
        id_detail,
    ))

    # TRUSTED_SPAN_COUNT
    results.append(_result(
        "TRUSTED_SPAN_COUNT",
        len(test_spans) == 7,
        f"got {len(test_spans)}, expected 7",
    ))

    # UNIQUE_SPAN_IDS
    unique_ids = {s.span_id for s in test_spans}
    results.append(_result(
        "UNIQUE_SPAN_IDS",
        len(unique_ids) == len(test_spans),
        f"unique={len(unique_ids)} total={len(test_spans)}",
    ))

    # SPAN_NAMES
    actual_names = {s.span_name for s in test_spans}
    missing = EXPECTED_SPAN_NAMES - actual_names
    extra = actual_names - EXPECTED_SPAN_NAMES
    names_ok = (not missing) and (not extra)
    name_detail = ""
    if missing:
        name_detail += f"missing={sorted(missing)} "
    if extra:
        name_detail += f"extra={sorted(extra)}"
    results.append(_result("SPAN_NAMES", names_ok, name_detail.strip()))

    # PARENT_RELATIONSHIPS
    if root and children:
        root_ok = root.parent_span_id is None
        children_ok = all(s.parent_span_id == root.span_id for s in children)
        child_count_ok = len(children) == 6
        parents_ok = root_ok and children_ok and child_count_ok
        parent_detail = (
            f"root.parent_span_id={root.parent_span_id!r}, "
            f"children={len(children)}, "
            f"all_children_correct={children_ok}"
        )
    else:
        parents_ok = False
        parent_detail = "cannot check — root or test spans not identified"
    results.append(_result("PARENT_RELATIONSHIPS", parents_ok, parent_detail))

    # CANONICAL_VALIDATION
    results.append(_result(
        "CANONICAL_VALIDATION",
        len(deser_errors) == 0,
        f"{len(deser_errors)} error(s)" if deser_errors else "all valid",
    ))
    for err in deser_errors:
        print(f"  deserialization error: {err}")

    # DLQ_ZERO
    results.append(_result(
        "DLQ_ZERO",
        len(dlq_msgs) == 0,
        f"post-baseline DLQ records: {len(dlq_msgs)}",
    ))

    # UNRELATED_TRACES (informational — not a PASS/FAIL gate in Stage A)
    print(f"UNRELATED_TRACES: {len(unrelated_trace_ids)}")
    for tid in unrelated_trace_ids:
        print(f"  - {tid}")

    print("=" * 60)
    overall = all(results)
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")

    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())

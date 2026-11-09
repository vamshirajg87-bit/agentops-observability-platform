"""
storage-consumer/tests/integration/test_persistence_e2e.py

Phase 6.5 — Durable Persistence Integration Proof

Part A (automated, in this file): publishes 7 synthetic CanonicalSpanEvent
spans directly to the trusted agentops.telemetry.spans Kafka topic, polls
PostgreSQL until all 7 spans appear, then asserts the full persistence
contract — every column, promoted field, Kafka provenance, idempotency
guarantee, and single-partition routing.

Part B (manual, Windows PowerShell): see the "PART B — FULL PIPELINE SMOKE
PROOF" section at the bottom of this file.

Infrastructure prerequisites
-----------------------------
  docker compose up -d

Run this test
-------------
  # From the repository root:
  $env:PYTHONPATH = "$PWD\\storage-consumer;$PWD\\demo-app"  # PowerShell
  export PYTHONPATH="$PWD/storage-consumer:$PWD/demo-app"    # bash/zsh

  # The storage consumer must be running so it consumes from Kafka and
  # persists to PostgreSQL:
  python storage-consumer/main.py                             # in a separate terminal

  pytest storage-consumer/tests/integration/ -v -m integration
"""

import time
import threading
import uuid
from datetime import datetime, timezone

import psycopg
import psycopg.rows
import pytest
from confluent_kafka import Producer

from repository import SpanRepository
from schemas.telemetry import CanonicalSpanEvent


KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "agentops.telemetry.spans"

PG_DSN = (
    "host=localhost port=5432 dbname=agentops "
    "user=agentops password=agentops_dev"
)

POLL_INTERVAL_SECONDS = 0.5
POLL_TIMEOUT_SECONDS = 60.0

SERVICE_NAME = "agentops-demo-app"

EXPECTED_SPAN_NAMES = {
    "agentops.request",
    "supervisor.start",
    "research.plan",
    "retrieval.search",
    "tool.execute",
    "research.synthesize",
    "supervisor.finalize",
}


# ─── session fixtures ────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def kafka_producer():
    """Verify Kafka is reachable and the target topic exists; return producer."""
    producer = Producer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "message.timeout.ms": 5000,
            "socket.timeout.ms": 5000,
        }
    )
    try:
        cluster_meta = producer.list_topics(timeout=10)
    except Exception as exc:
        pytest.fail(
            f"Kafka broker not reachable at {KAFKA_BOOTSTRAP!r}: {exc}. "
            "Start docker-compose services before running integration tests."
        )
    if KAFKA_TOPIC not in cluster_meta.topics:
        pytest.fail(
            f"Required topic {KAFKA_TOPIC!r} not found on broker. "
            "Run kafka-init or docker compose up before integration tests."
        )
    return producer


@pytest.fixture(scope="session")
def pg_conn():
    """Open a psycopg3 autocommit dict-row connection; fail if unreachable."""
    try:
        conn = psycopg.connect(
            PG_DSN,
            autocommit=True,
            row_factory=psycopg.rows.dict_row,
        )
    except Exception as exc:
        pytest.fail(
            f"PostgreSQL not reachable: {exc}. "
            "Start docker-compose services before running integration tests."
        )
    yield conn
    conn.close()


# ─── helpers ─────────────────────────────────────────────────────────────────


def _build_test_spans(
    trace_id: str,
    root_span_id: str,
    child_span_ids: list,
) -> list:
    """Return 7 CanonicalSpanEvent objects matching the demo-app span topology."""
    now = datetime.now(tz=timezone.utc)

    def make(name, span_id, parent_span_id=None, **kw):
        attrs = {}
        for attr_key, field_key in (
            ("agent.name", "agent_name"),
            ("agent.operation", "agent_operation"),
            ("gen_ai.operation.name", "gen_ai_operation"),
            ("tool.name", "tool_name"),
            ("tool.status", "tool_status"),
        ):
            if kw.get(field_key) is not None:
                attrs[attr_key] = kw[field_key]
        if kw.get("retrieval_result_count") is not None:
            attrs["retrieval.result_count"] = kw["retrieval_result_count"]
        if kw.get("retrieval_top_relevance_score") is not None:
            attrs["retrieval.top_relevance_score"] = kw["retrieval_top_relevance_score"]

        return CanonicalSpanEvent(
            schema_version="1.0",
            event_type="span",
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            span_name=name,
            span_kind="INTERNAL",
            service_name=SERVICE_NAME,
            start_time=now,
            end_time=now,
            duration_ms=0.0,
            status_code="OK",
            agent_name=kw.get("agent_name"),
            agent_operation=kw.get("agent_operation"),
            gen_ai_operation=kw.get("gen_ai_operation"),
            tool_name=kw.get("tool_name"),
            tool_status=kw.get("tool_status"),
            retrieval_result_count=kw.get("retrieval_result_count"),
            retrieval_top_relevance_score=kw.get("retrieval_top_relevance_score"),
            attributes=attrs,
        )

    c = child_span_ids
    return [
        make("agentops.request", root_span_id),
        make("supervisor.start",    c[0], parent_span_id=root_span_id,
             agent_name="supervisor",  agent_operation="start"),
        make("research.plan",       c[1], parent_span_id=root_span_id,
             agent_name="research",    agent_operation="plan"),
        make("retrieval.search",    c[2], parent_span_id=root_span_id,
             agent_name="retrieval",   agent_operation="search",
             gen_ai_operation="retrieval",
             retrieval_result_count=3, retrieval_top_relevance_score=0.92),
        make("tool.execute",        c[3], parent_span_id=root_span_id,
             agent_name="tool_agent",  agent_operation="execute",
             gen_ai_operation="execute_tool",
             tool_name="web_search",   tool_status="success"),
        make("research.synthesize", c[4], parent_span_id=root_span_id,
             agent_name="research",    agent_operation="synthesize"),
        make("supervisor.finalize", c[5], parent_span_id=root_span_id,
             agent_name="supervisor",  agent_operation="finalize"),
    ]


def _publish_spans(producer: Producer, spans: list) -> None:
    """Publish all spans to Kafka and wait for acknowledged delivery."""
    errors: list = []
    lock = threading.Lock()

    def on_delivery(err, msg):
        if err is not None:
            with lock:
                errors.append(err)

    for event in spans:
        producer.produce(
            topic=KAFKA_TOPIC,
            key=event.trace_id.encode("utf-8"),
            value=event.model_dump_json(),
            on_delivery=on_delivery,
        )

    undelivered = producer.flush(timeout=30)
    if undelivered > 0:
        pytest.fail(
            f"{undelivered} Kafka message(s) not delivered within 30 s."
        )
    if errors:
        pytest.fail(f"Kafka delivery error(s): {errors}")


def _poll_postgres(
    conn: psycopg.Connection,
    trace_id: str,
    expected_count: int = 7,
    timeout: float = POLL_TIMEOUT_SECONDS,
) -> list:
    """Poll PostgreSQL until expected_count rows appear; pytest.fail on timeout."""
    rows: list = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM telemetry_spans WHERE trace_id = %s",
                (trace_id,),
            )
            rows = cur.fetchall()
        if len(rows) >= expected_count:
            return rows
        time.sleep(POLL_INTERVAL_SECONDS)
    pytest.fail(
        f"Timed out after {timeout:.0f}s waiting for {expected_count} spans "
        f"with trace_id={trace_id!r}. Found {len(rows)}."
    )


# ─── Part A — automated storage integration test ──────────────────────────────


@pytest.mark.integration
class TestPersistenceE2E:
    """
    Publishes 7 synthetic spans to agentops.telemetry.spans, waits for the
    running storage consumer to persist them, then asserts the full
    persistence contract and idempotency guarantee.
    """

    def test_spans_persisted_end_to_end(self, kafka_producer, pg_conn):
        # ── build unique trace identity ───────────────────────────────────────
        trace_id = uuid.uuid4().hex           # 32 lowercase hex chars
        root_span_id = uuid.uuid4().hex[:16]  # 16 hex chars
        child_span_ids = [uuid.uuid4().hex[:16] for _ in range(6)]
        all_span_ids = [root_span_id] + child_span_ids

        spans = _build_test_spans(trace_id, root_span_id, child_span_ids)

        # ── publish to trusted Kafka topic ────────────────────────────────────
        _publish_spans(kafka_producer, spans)

        # ── wait for storage consumer to persist all 7 spans ─────────────────
        rows = _poll_postgres(pg_conn, trace_id, expected_count=7)

        # ── A1: count ─────────────────────────────────────────────────────────
        assert len(rows) == 7, f"Expected 7 rows, got {len(rows)}"

        # ── A2: all span_ids distinct ─────────────────────────────────────────
        persisted_span_ids = {r["span_id"].strip() for r in rows}
        assert len(persisted_span_ids) == 7, (
            f"span_ids not all distinct: {persisted_span_ids}"
        )

        # ── A3: span name set matches expected topology ───────────────────────
        persisted_names = {r["span_name"] for r in rows}
        assert persisted_names == EXPECTED_SPAN_NAMES, (
            f"Missing: {EXPECTED_SPAN_NAMES - persisted_names}. "
            f"Extra: {persisted_names - EXPECTED_SPAN_NAMES}."
        )

        # ── A4: root span has NULL parent_span_id ─────────────────────────────
        root_rows = [r for r in rows if r["span_name"] == "agentops.request"]
        assert len(root_rows) == 1
        assert root_rows[0]["parent_span_id"] is None, (
            f"Root span parent_span_id should be NULL, "
            f"got {root_rows[0]['parent_span_id']!r}"
        )

        # ── A5: all child spans point to root span ────────────────────────────
        child_rows = [r for r in rows if r["span_name"] != "agentops.request"]
        assert len(child_rows) == 6
        for row in child_rows:
            assert row["parent_span_id"] is not None
            assert row["parent_span_id"].strip() == root_span_id, (
                f"{row['span_name']!r} parent_span_id mismatch: "
                f"expected {root_span_id!r}, got {row['parent_span_id']!r}"
            )

        # ── A6: schema_version = '1.0' ────────────────────────────────────────
        for row in rows:
            assert row["schema_version"] == "1.0", (
                f"schema_version={row['schema_version']!r} for {row['span_name']!r}"
            )

        # ── A7: event_type = 'span' ───────────────────────────────────────────
        for row in rows:
            assert row["event_type"] == "span", (
                f"event_type={row['event_type']!r} for {row['span_name']!r}"
            )

        # ── A8: trace_id round-trips correctly ────────────────────────────────
        for row in rows:
            assert row["trace_id"].strip() == trace_id, (
                f"trace_id mismatch: {row['trace_id']!r}"
            )

        # ── A9: span_kind = 'INTERNAL' ────────────────────────────────────────
        for row in rows:
            assert row["span_kind"] == "INTERNAL", (
                f"span_kind={row['span_kind']!r} for {row['span_name']!r}"
            )

        # ── A10: service_name ─────────────────────────────────────────────────
        for row in rows:
            assert row["service_name"] == SERVICE_NAME, (
                f"service_name={row['service_name']!r} for {row['span_name']!r}"
            )

        # ── A11: start_time and end_time not null ─────────────────────────────
        for row in rows:
            assert row["start_time"] is not None, (
                f"start_time NULL for {row['span_name']!r}"
            )
            assert row["end_time"] is not None, (
                f"end_time NULL for {row['span_name']!r}"
            )

        # ── A12: duration_ms >= 0 ─────────────────────────────────────────────
        for row in rows:
            assert float(row["duration_ms"]) >= 0.0, (
                f"duration_ms={row['duration_ms']} for {row['span_name']!r}"
            )

        # ── A13: status_code = 'OK' ───────────────────────────────────────────
        for row in rows:
            assert row["status_code"] == "OK", (
                f"status_code={row['status_code']!r} for {row['span_name']!r}"
            )

        # ── A14: attributes JSONB not null ────────────────────────────────────
        for row in rows:
            assert row["attributes"] is not None, (
                f"attributes NULL for {row['span_name']!r}"
            )

        # ── A15: retrieval.search promoted fields ─────────────────────────────
        (rr,) = [r for r in rows if r["span_name"] == "retrieval.search"]
        assert rr["gen_ai_operation"] == "retrieval"
        assert rr["agent_name"] == "retrieval"
        assert rr["agent_operation"] == "search"
        assert rr["retrieval_result_count"] == 3
        assert abs(float(rr["retrieval_top_relevance_score"]) - 0.92) < 1e-6

        # ── A16: tool.execute promoted fields ─────────────────────────────────
        (tr,) = [r for r in rows if r["span_name"] == "tool.execute"]
        assert tr["gen_ai_operation"] == "execute_tool"
        assert tr["agent_name"] == "tool_agent"
        assert tr["agent_operation"] == "execute"
        assert tr["tool_name"] == "web_search"
        assert tr["tool_status"] == "success"

        # ── A17: kafka_topic matches the trusted topic ────────────────────────
        for row in rows:
            assert row["kafka_topic"] == KAFKA_TOPIC, (
                f"kafka_topic={row['kafka_topic']!r} for {row['span_name']!r}"
            )

        # ── A18: kafka_partition not null ─────────────────────────────────────
        for row in rows:
            assert row["kafka_partition"] is not None, (
                f"kafka_partition NULL for {row['span_name']!r}"
            )

        # ── A19: kafka_offset not null ────────────────────────────────────────
        for row in rows:
            assert row["kafka_offset"] is not None, (
                f"kafka_offset NULL for {row['span_name']!r}"
            )

        # ── A20: ingested_at not null ─────────────────────────────────────────
        for row in rows:
            assert row["ingested_at"] is not None, (
                f"ingested_at NULL for {row['span_name']!r}"
            )

        # ── A21: all spans share one Kafka partition (hash of trace_id key) ───
        partitions = {r["kafka_partition"] for r in rows}
        assert len(partitions) == 1, (
            f"All 7 spans should land on one partition (same trace_id key). "
            f"Got partitions: {partitions}"
        )

        # ── A22: supervisor.start promoted fields ─────────────────────────────
        (ssr,) = [r for r in rows if r["span_name"] == "supervisor.start"]
        assert ssr["agent_name"] == "supervisor"
        assert ssr["agent_operation"] == "start"

        # ── A23: COUNT(*) re-query returns exactly 7 (no silent duplicates) ───
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM telemetry_spans WHERE trace_id = %s",
                (trace_id,),
            )
            cnt_row = cur.fetchone()
        assert cnt_row["cnt"] == 7, (
            f"Duplicate-check COUNT(*) expected 7, got {cnt_row['cnt']}"
        )

        # ════════════════════════════════════════════════════════════════════════
        # DATABASE IDEMPOTENCY SUB-PROOF
        #
        # Re-call SpanRepository.insert_span() for each of the 7 spans with
        # fabricated Kafka provenance (partition=99, offset=99_999_999+i).
        # The UNIQUE(trace_id, span_id) constraint must absorb every replay.
        # Original Kafka provenance must remain unchanged in PostgreSQL.
        # ════════════════════════════════════════════════════════════════════════

        replay_conn = psycopg.connect(PG_DSN, autocommit=True)
        repo = SpanRepository(replay_conn)

        replay_results = []
        try:
            for i, event in enumerate(spans):
                result = repo.insert_span(
                    event,
                    topic=KAFKA_TOPIC,
                    partition=99,
                    offset=99_999_999 + i,
                )
                replay_results.append(result)
        finally:
            replay_conn.close()

        # I1: all 7 replay inserts returned False (ON CONFLICT DO NOTHING)
        assert all(r is False for r in replay_results), (
            f"Expected all False from idempotency replay, got: {replay_results}"
        )

        # I2: row count still 7 after replay
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM telemetry_spans WHERE trace_id = %s",
                (trace_id,),
            )
            cnt_row = cur.fetchone()
        assert cnt_row["cnt"] == 7, (
            f"Row count after idempotency replay must still be 7, "
            f"got {cnt_row['cnt']}"
        )

        # I3: original kafka_partition not overwritten (no row has partition=99)
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT kafka_partition FROM telemetry_spans WHERE trace_id = %s",
                (trace_id,),
            )
            partition_rows = cur.fetchall()
        for pr in partition_rows:
            assert pr["kafka_partition"] != 99, (
                "Idempotency replay with partition=99 must not overwrite "
                "original kafka_partition"
            )

        # I4: original kafka_offset not overwritten (no row has offset >= 99_999_999)
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT kafka_offset FROM telemetry_spans WHERE trace_id = %s",
                (trace_id,),
            )
            offset_rows = cur.fetchall()
        for orw in offset_rows:
            assert orw["kafka_offset"] < 99_999_999, (
                f"Idempotency replay must not overwrite original kafka_offset; "
                f"got {orw['kafka_offset']}"
            )


# ════════════════════════════════════════════════════════════════════════════════
# PART B — FULL PIPELINE SMOKE PROOF (manual, Windows PowerShell)
#
# Objective: prove the complete path
#   demo-app (OTel SDK) → OTLP Collector → agentops.telemetry.otlp.traces
#   → stream-processor → agentops.telemetry.spans → storage-consumer → PostgreSQL
#
# Prerequisites
# -------------
#   1. docker compose up -d            (Kafka, Collector, PostgreSQL, kafka-init)
#   2. All three Python services running in separate PowerShell terminals:
#
#      # Terminal 1 — stream processor
#      $env:PYTHONPATH = "$PWD\stream-processor;$PWD\demo-app"
#      python stream-processor/main.py
#
#      # Terminal 2 — storage consumer
#      $env:PYTHONPATH = "$PWD\storage-consumer;$PWD\demo-app"
#      python storage-consumer/main.py
#
#      # Terminal 3 — demo app (one-shot run)
#      $env:PYTHONPATH = "$PWD\demo-app"
#      python demo-app/main.py
#
# Step 1 — capture a pre-run row count baseline
# -----------------------------------------------
#   $env:PGPASSWORD = "agentops_dev"
#   $baseline = psql -h localhost -U agentops -d agentops `
#       -t -c "SELECT COUNT(*) FROM telemetry_spans;" | ForEach-Object { $_.Trim() }
#   Write-Host "Baseline row count: $baseline"
#
# Step 2 — run the demo app
# --------------------------
#   $env:PYTHONPATH = "$PWD\demo-app"
#   python demo-app/main.py
#   # Wait for it to complete (should take a few seconds; no LLM API key required —
#   # the demo uses deterministic stubs).
#
# Step 3 — wait for pipeline to drain (≈ 5 s)
# ---------------------------------------------
#   Start-Sleep -Seconds 5
#
# Step 4 — verify new rows in PostgreSQL
# ----------------------------------------
#   $env:PGPASSWORD = "agentops_dev"
#   $after = psql -h localhost -U agentops -d agentops `
#       -t -c "SELECT COUNT(*) FROM telemetry_spans;" | ForEach-Object { $_.Trim() }
#   Write-Host "After row count: $after"
#   Write-Host "New rows persisted: $([int]$after - [int]$baseline)"
#
# Step 5 — inspect the most-recent spans
# ----------------------------------------
#   $env:PGPASSWORD = "agentops_dev"
#   psql -h localhost -U agentops -d agentops -c `
#       "SELECT span_name, span_kind, service_name, status_code,
#               agent_name, agent_operation, gen_ai_operation,
#               kafka_topic, kafka_partition, kafka_offset, ingested_at
#          FROM telemetry_spans
#         ORDER BY ingested_at DESC
#         LIMIT 10;"
#
# Step 6 — expected outcome
# --------------------------
#   • ([int]$after - [int]$baseline) >= 6   (supervisor.start, research.plan,
#     retrieval.search, tool.execute, research.synthesize, supervisor.finalize,
#     and possibly agentops.request if the root span is emitted)
#   • kafka_topic = 'agentops.telemetry.spans' for all new rows
#   • service_name = 'agentops-demo-app' for all new rows
#   • All rows have non-null ingested_at, kafka_partition, kafka_offset
#   • No errors in the stream-processor or storage-consumer terminal output
#
# This manual smoke proof establishes that the full OTLP pipeline — from OTel
# SDK instrumentation through the Collector, stream processor, and storage
# consumer — terminates in durable PostgreSQL persistence with the correct
# at-least-once + idempotent semantics.
# ════════════════════════════════════════════════════════════════════════════════

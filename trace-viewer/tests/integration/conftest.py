"""
trace-viewer/tests/integration/conftest.py

Opt-in guard, target description and deterministic fixtures for the trace-viewer
PostgreSQL integration tests (test_viewer_sql_live.py).

These tests need a real PostgreSQL.  They are written to run ONLY against the
disposable database that workload-generator/run_viewer_sql_it.py creates, and every
one of them is SKIPPED unless that orchestrator (or someone following its contract)
supplies all four settings below.  A stray or half-set environment skips; it can
never point the tests at another database.

    AGENTOPS_VIEWER_IT_DSN              postgresql://agentops:<password>@127.0.0.1:<port>/agentops
    AGENTOPS_VIEWER_IT_VIEWER_PASSWORD  the password of the role trace_viewer_reader in that database
    AGENTOPS_VIEWER_IT_PROJECT          agentops-viewer-it-<8 hex>
    AGENTOPS_VIEWER_IT_APPROVAL         disposable-loopback:<project>:<port>

The guard accepts only: a literal loopback address; a port from 1024 up that is not
one of the ports of the normal stack, the MVP viewer, Grafana or the sibling harnesses;
the owner role "agentops" and the database "agentops" (the names the bootstrap
creates); a project name of the exact form above; and an approval string that names
that same project and port.  Nothing here connects to anything.

The fixture builders below are pure: no database, no clock, no randomness.  The same
call always returns the same rows, so a test can state exact expectations.

Run only by the orchestrator, once, when separately authorized.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlsplit

import pytest

ENV_DSN = "AGENTOPS_VIEWER_IT_DSN"
ENV_VIEWER_PASSWORD = "AGENTOPS_VIEWER_IT_VIEWER_PASSWORD"
ENV_PROJECT = "AGENTOPS_VIEWER_IT_PROJECT"
ENV_APPROVAL = "AGENTOPS_VIEWER_IT_APPROVAL"

PROJECT_RE = re.compile(r"agentops-viewer-it-[0-9a-f]{8}")
#: The normal stack (Kafka 9092, PostgreSQL 5432, collector 4317 and 4318), the MVP viewer (8000),
#: Grafana (3000), and the fixed ports of the sibling harnesses (collector 14317, Kafka 19092,
#: PostgreSQL 15432).
PROHIBITED_PORTS = frozenset({3000, 4317, 4318, 5432, 8000, 9092, 14317, 15432, 19092})
OWNER_ROLE = "agentops"
DATABASE = "agentops"
LOOPBACK_LITERALS = ("127.0.0.1", "::1")


def approval_token(project: str, port: int) -> str:
    return f"disposable-loopback:{project}:{port}"


@dataclasses.dataclass(frozen=True)
class Target:
    host: str
    port: int
    project: str
    admin_dsn: str
    viewer_password: str


def check_target(dsn: Optional[str], viewer_password: Optional[str], project: Optional[str],
                 approval: Optional[str]) -> tuple[Optional[Target], str]:
    """(target, "") when every condition holds; (None, why not) otherwise.  Pure; connects to nothing."""
    if not dsn or not viewer_password or not project or not approval:
        missing = [name for name, value in ((ENV_DSN, dsn), (ENV_VIEWER_PASSWORD, viewer_password),
                                            (ENV_PROJECT, project), (ENV_APPROVAL, approval)) if not value]
        return None, "not approved: " + ", ".join(missing) + " not set"
    if not PROJECT_RE.fullmatch(project):
        return None, "the project is not a disposable agentops-viewer-it-<8 hex> project"
    try:
        parts = urlsplit(dsn)
        port = parts.port
        host = parts.hostname
    except ValueError:
        return None, "the DSN could not be read"
    if parts.scheme not in ("postgresql", "postgres"):
        return None, "the DSN is not a postgresql:// URL"
    if host is None or port is None:
        return None, "the DSN has no explicit host and port"
    try:
        loopback = ipaddress.ip_address(host).is_loopback and host in LOOPBACK_LITERALS
    except ValueError:
        loopback = False
    if not loopback:
        return None, "the host is not a literal loopback address (127.0.0.1 or ::1)"
    if port < 1024 or port > 65535 or port in PROHIBITED_PORTS:
        return None, f"port {port} is protected or not usable"
    if unquote(parts.username or "") != OWNER_ROLE or parts.path.lstrip("/") != DATABASE or not parts.password:
        return None, "the DSN does not name the bootstrap owner role and database with a password"
    if parts.query or parts.fragment:
        return None, "the DSN must carry no options"
    if approval != approval_token(project, port):
        return None, "the approval does not name this project and port"
    return Target(host, port, project, dsn, viewer_password), ""


def target_from_environment(environ: Optional[dict[str, str]] = None) -> tuple[Optional[Target], str]:
    env = os.environ if environ is None else environ
    return check_target(env.get(ENV_DSN), env.get(ENV_VIEWER_PASSWORD), env.get(ENV_PROJECT), env.get(ENV_APPROVAL))


def pytest_configure(config: pytest.Config) -> None:
    for name, text in (("sql_level", "a statement run directly against PostgreSQL"),
                       ("query_level", "a trace-viewer query function against PostgreSQL"),
                       ("endpoint_level", "a FastAPI endpoint (in-process client) against PostgreSQL"),
                       ("connection_level", "connection behaviour of db.connect()")):
        config.addinivalue_line("markers", f"{name}: {text}")


@pytest.fixture(scope="session")
def live_target() -> Target:
    target, reason = target_from_environment()
    if target is None:
        pytest.skip(reason)
    return target


@pytest.fixture(scope="session")
def support() -> Any:
    """This module, so that a test can reach the fixture builders without importing a conftest by name."""
    return sys.modules[__name__]


@pytest.fixture(autouse=True)
def _every_test_needs_an_approved_target(live_target: Target) -> Target:
    """Every test in this directory depends on the approved target, so every test is skipped without one."""
    return live_target


# ---------------------------------------------------------------------------
# Deterministic fixtures
# ---------------------------------------------------------------------------

LABEL = "b3j-417"
KAFKA_TOPIC = "agentops.viewer.it.b3j417"
BASE_TIME = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)

#: stored lengths of an ASCII message and the multi-byte cases
ASCII_LENGTHS = (1, 1999, 2000, 2001, 2002, 5000)
UNICODE_CASES = (("bmp", "é"), ("astral", "\U0001F600"))      # 2 bytes and 4 bytes in UTF-8, one character each
UNICODE_LENGTHS = (2000, 2001)
LIMITATION_COUNTS = (0, 1, 50, 51, 500)
EVIDENCE_COUNTS = (0, 1, 200, 201, 230, 1000)
BIG_TRACE_SIZES = (1000, 1001)

TABLES = ("telemetry_spans", "anomaly_events", "rca_investigations", "rca_evidence")


def digest(label: str, length: int = 64) -> str:
    return hashlib.sha256(f"{LABEL}|{label}".encode("utf-8")).hexdigest()[:length]


@dataclasses.dataclass(frozen=True)
class TextCase:
    label: str
    char: str
    length: int

    @property
    def text(self) -> str:
        return self.char * self.length


def text_cases() -> tuple[TextCase, ...]:
    cases = [TextCase(f"ascii-{n}", "x", n) for n in ASCII_LENGTHS]
    cases += [TextCase(f"{kind}-{n}", char, n) for kind, char in UNICODE_CASES for n in UNICODE_LENGTHS]
    return tuple(cases)


@dataclasses.dataclass(frozen=True)
class Fixtures:
    rows: dict[str, list[dict[str, Any]]]                       # every row to insert, parents first
    text_trace_id: str
    span_cases: tuple[tuple[TextCase, str], ...]                # (case, span_id)
    big_traces: dict[int, str]                                  # size -> trace_id
    anomaly_cases: tuple[tuple[TextCase, str], ...]             # (case, anomaly_id)
    summary_cases: tuple[tuple[TextCase, str], ...]             # (case, investigation_id): summary, limitation, evidence text
    limitation_cases: tuple[tuple[int, str], ...]               # (count, investigation_id)
    long_limitation_investigation: str
    null_limitation_investigation: str
    evidence_cases: tuple[tuple[int, str], ...]                 # (count, investigation_id)
    anomaly_without_investigation: str


def _scripts_on_path() -> None:
    scripts = str(Path(__file__).resolve().parents[3] / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)


def demo_templates():
    """The deterministic MVP demo seed (scripts/agentops_mvp_demo.py): realistic rows that satisfy every constraint."""
    _scripts_on_path()
    import agentops_mvp_demo as demo
    return demo.build_manifest()


def _anomaly(template: dict[str, Any], key: str, explanation: str, index: int) -> dict[str, Any]:
    row = dict(template)
    row.update(anomaly_id=digest(f"anomaly|{key}"), explanation=explanation, operation_name=f"viewer-it-{key}",
               event_time=BASE_TIME + timedelta(seconds=index), detected_at=BASE_TIME + timedelta(seconds=index, milliseconds=5))
    return row


def _investigation(template: dict[str, Any], key: str, anomaly: dict[str, Any], *, summary: str,
                   limitations: list[Optional[str]]) -> dict[str, Any]:
    row = dict(template)
    row.update(investigation_id=digest(f"investigation|{key}"), anomaly_id=anomaly["anomaly_id"],
               analyzer_version=f"viewer-it-{key}", event_time=anomaly["event_time"], summary=summary,
               limitations=limitations, investigated_at=anomaly["detected_at"] + timedelta(seconds=1))
    return row


def _evidence(template: dict[str, Any], investigation_id: str, ordinal: int, rank: int, *, error_message: Optional[str],
              explanation: str, breakdown: str) -> dict[str, Any]:
    row = dict(template)
    row.update(investigation_id=investigation_id, span_id=digest(f"evidence|{investigation_id}|{ordinal}", 16),
               rank_position=rank, error_message=error_message, explanation=explanation, evidence_score_breakdown=breakdown)
    return row


def _span(template: dict[str, Any], trace_id: str, ordinal: int, parent: Optional[str], offset: int, **overrides: Any) -> dict[str, Any]:
    row = dict(template)
    row.update(trace_id=trace_id, span_id=digest(f"span|{trace_id}|{ordinal}", 16), parent_span_id=parent,
               span_name=f"viewer-it.span.{ordinal}", start_time=BASE_TIME + timedelta(milliseconds=ordinal),
               end_time=BASE_TIME + timedelta(milliseconds=ordinal + 1), duration_ms=1.0, status_code="ERROR",
               status_message=None, error_type=None, error_message=None, request_id=None, session_id=None,
               kafka_topic=KAFKA_TOPIC, kafka_partition=0, kafka_offset=offset,
               attributes={"viewer_it": LABEL}, ingested_at=BASE_TIME + timedelta(seconds=5))
    row.update(overrides)
    return row


def build_fixtures() -> Fixtures:
    """Everything the live tests insert: the demo seed plus boundary rows.  Pure and deterministic."""
    demo = demo_templates()
    span_t, anomaly_t, inv_t, ev_t = (demo.rows(t)[0] for t in TABLES)
    rows: dict[str, list[dict[str, Any]]] = {t: [dict(r) for r in demo.rows(t)] for t in TABLES}
    offset = 1_000_000

    def next_offset() -> int:
        nonlocal offset
        offset += 1
        return offset

    # --- spans with over-long and boundary-length messages, in one trace -------------------------------------
    text_trace = digest("trace|text", 32)
    root = _span(span_t, text_trace, 0, None, next_offset(), span_name="viewer-it.root")
    rows["telemetry_spans"].append(root)
    span_cases = []
    for i, case in enumerate(text_cases(), start=1):
        row = _span(span_t, text_trace, i, root["span_id"], next_offset(), status_message=case.text, error_message=case.text)
        rows["telemetry_spans"].append(row)
        span_cases.append((case, row["span_id"]))

    # --- traces of exactly 1,000 and 1,001 spans --------------------------------------------------------------
    big: dict[int, str] = {}
    for size in BIG_TRACE_SIZES:
        trace = digest(f"trace|big|{size}", 32)
        big[size] = trace
        first = _span(span_t, trace, 0, None, next_offset(), span_name="viewer-it.big-root")
        rows["telemetry_spans"].append(first)
        for i in range(1, size):
            rows["telemetry_spans"].append(_span(span_t, trace, i, first["span_id"], next_offset()))

    # --- anomalies with boundary-length explanations ----------------------------------------------------------
    index = 0
    anomaly_cases = []
    for case in text_cases():
        index += 1
        row = _anomaly(anomaly_t, f"text-{case.label}", case.text, index)
        rows["anomaly_events"].append(row)
        anomaly_cases.append((case, row["anomaly_id"]))

    # --- investigations whose summary, one limitation and one evidence row have boundary-length text ---------
    summary_cases = []
    for case in text_cases():
        index += 1
        parent = _anomaly(anomaly_t, f"summary-{case.label}", "x", index)
        rows["anomaly_events"].append(parent)
        investigation = _investigation(inv_t, f"summary-{case.label}", parent, summary=case.text, limitations=[case.text])
        rows["rca_investigations"].append(investigation)
        rows["rca_evidence"].append(_evidence(ev_t, investigation["investigation_id"], 1, 1, error_message=case.text,
                                              explanation=case.text, breakdown=case.text))
        summary_cases.append((case, investigation["investigation_id"]))

    # --- limitation arrays of 0, 1, 50, 51 and 500 entries ----------------------------------------------------
    limitation_cases = []
    for count in LIMITATION_COUNTS:
        index += 1
        parent = _anomaly(anomaly_t, f"limitations-{count}", "x", index)
        rows["anomaly_events"].append(parent)
        investigation = _investigation(inv_t, f"limitations-{count}", parent, summary="limitations",
                                       limitations=[f"limitation {i:04d}" for i in range(count)])
        rows["rca_investigations"].append(investigation)
        limitation_cases.append((count, investigation["investigation_id"]))
    index += 1
    parent = _anomaly(anomaly_t, "limitations-long", "x", index)
    rows["anomaly_events"].append(parent)
    long_inv = _investigation(inv_t, "limitations-long", parent, summary="long limitations",
                              limitations=["l" * 2001, "m" * 5000, "short"])
    rows["rca_investigations"].append(long_inv)
    index += 1
    parent = _anomaly(anomaly_t, "limitations-null", "x", index)
    rows["anomaly_events"].append(parent)
    null_inv = _investigation(inv_t, "limitations-null", parent, summary="a NULL limitation entry",
                              limitations=["first", None, "third"])
    rows["rca_investigations"].append(null_inv)

    # --- evidence of 0, 1, 200, 201, 230 and 1,000 rows, with ties in rank_position -----------------------------
    evidence_cases = []
    for count in EVIDENCE_COUNTS:
        index += 1
        parent = _anomaly(anomaly_t, f"evidence-{count}", "x", index)
        rows["anomaly_events"].append(parent)
        investigation = _investigation(inv_t, f"evidence-{count}", parent, summary="evidence", limitations=[])
        rows["rca_investigations"].append(investigation)
        for ordinal in range(count):
            rank = ordinal // 2 + 1                          # pairs share a rank: the order must break the tie by span_id
            rows["rca_evidence"].append(_evidence(ev_t, investigation["investigation_id"], ordinal, rank,
                                                  error_message=None, explanation="evidence", breakdown="a=1"))
        evidence_cases.append((count, investigation["investigation_id"]))

    index += 1
    lonely = _anomaly(anomaly_t, "no-investigation", "an anomaly nothing investigated", index)
    rows["anomaly_events"].append(lonely)
    return Fixtures(rows, text_trace, tuple(span_cases), big, tuple(anomaly_cases), tuple(summary_cases),
                    tuple(limitation_cases), long_inv["investigation_id"], null_inv["investigation_id"],
                    tuple(evidence_cases), lonely["anomaly_id"])


def insert_rows(conn: Any, table: str, rows: list[dict[str, Any]], batch: int = 500) -> None:
    """Parameterized INSERT of the given rows (columns of the demo seed).  Used only by the admin connection."""
    from psycopg.types.json import Jsonb

    _scripts_on_path()
    import agentops_mvp_demo as demo

    columns = demo.COLUMNS[table]
    sql = f"INSERT INTO public.{table} ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))})"
    with conn.cursor() as cur:
        for start in range(0, len(rows), batch):
            cur.executemany(sql, [tuple(Jsonb(row[c]) if isinstance(row[c], dict) else row[c] for c in columns)
                                  for row in rows[start:start + batch]])

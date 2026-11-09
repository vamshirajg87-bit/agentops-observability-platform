"""
scripts/tests/test_agentops_mvp_demo.py

Offline tests for scripts/agentops_mvp_demo.py (the deterministic demo dataset) and the guarded
`seed-demo` command of scripts/agentops_mvp.py.

Nothing real is ever run: a fake engine answers every Docker call and a fake database holds the
rows.  Where the repository has the real implementation (the anomaly detectors, the RCA analyzer,
the bootstrap plan, the migrations) the manifest is compared with it, field by field.

    D01  The dataset: shape, identifiers, timestamps, markers
    D02  Conformance with the table definitions in the migrations
    D03  Agreement with the repository implementations
    D04  SQL text
    D05  Row comparison
    D06  The seed-demo command
    D07  Scope
"""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agentops_mvp as mvp  # noqa: E402
import agentops_mvp_demo as demo  # noqa: E402
import agentops_mvp_lifecycle as lc  # noqa: E402
import test_agentops_mvp_config as cfg  # noqa: E402
import test_agentops_mvp_lifecycle as lt  # noqa: E402

_REPO = Path(mvp.__file__).resolve().parents[1]
_DOCKER = "/usr/bin/docker"
_CANARY = "LEAK-CANARY-a1b2c3d4e5f6-0123456789"
MANIFEST = demo.build_manifest()


def _by_name(rows, name):
    return [r for r in rows if r["span_name"] == name]


# ---------------------------------------------------------------------------
# D01  The dataset
# ---------------------------------------------------------------------------

class TestDataset:

    def test_exact_row_counts(self):
        assert MANIFEST.counts() == {"telemetry_spans": 96, "anomaly_events": 2, "rca_investigations": 2,
                                     "rca_evidence": 12}
        assert demo.EXPECTED_COUNTS == MANIFEST.counts()

    def test_thirteen_traces_of_seven_spans_and_a_failed_trace_of_five(self):
        by_trace: dict[str, list] = {}
        for row in MANIFEST.telemetry_spans:
            by_trace.setdefault(row["trace_id"], []).append(row)
        failed_id = demo.trace_id_for(demo.FAILED_TRACE_NUMBER)
        assert len(by_trace) == 14 and all(len(v) == 7 for k, v in by_trace.items() if k != failed_id)
        assert len(by_trace[failed_id]) == 5
        for trace_id, rows in by_trace.items():
            expected = demo.SPAN_NAMES[:5] if trace_id == failed_id else demo.SPAN_NAMES
            assert [r["span_name"] for r in rows] == list(expected)
            if trace_id == failed_id:       # the exception stops the graph after tool.execute
                assert rows[-1]["span_name"] == "tool.execute"
                assert {"research.synthesize", "supervisor.finalize"}.isdisjoint(r["span_name"] for r in rows)
                assert [r["status_code"] for r in rows] == ["ERROR", "UNSET", "UNSET", "UNSET", "ERROR"]
            roots = [r for r in rows if r["parent_span_id"] is None]
            assert len(roots) == 1 and roots[0]["span_name"] == "agentops.request"
            assert all(r["parent_span_id"] == roots[0]["span_id"] for r in rows if r is not roots[0])
            assert roots[0]["request_id"] and roots[0]["session_id"]
            assert all(r["request_id"] is None and r["session_id"] is None for r in rows if r is not roots[0])
            for r in rows:
                assert roots[0]["start_time"] <= r["start_time"] <= r["end_time"] <= roots[0]["end_time"]

    def test_twelve_normal_one_slow_one_failed(self):
        tools = _by_name(MANIFEST.telemetry_spans, "tool.execute")
        assert len(tools) == 14
        failed = [t for t in tools if t["status_code"] == "ERROR"]
        slow = [t for t in tools if t["duration_ms"] > 1000]
        normal = [t for t in tools if t["status_code"] == "UNSET" and t["duration_ms"] < 200]
        assert (len(failed), len(slow), len(normal)) == (1, 1, 12)
        assert slow[0]["duration_ms"] == 2350.0 and slow[0]["tool_name"] == demo.TOOL_NAME
        f = failed[0]
        assert (f["error_type"], f["tool_name"], f["tool_status"]) == ("ToolExecutionError", None, None)
        assert f["error_message"] == demo.ERROR_MESSAGE
        assert all(t["tool_name"] == demo.TOOL_NAME and t["tool_status"] == "success" for t in normal + slow)

    def test_the_failed_trace_root_is_error_as_in_the_repository(self):
        roots = _by_name(MANIFEST.telemetry_spans, "agentops.request")
        failed_root = next(r for r in roots if r["trace_id"] == demo.trace_id_for(demo.FAILED_TRACE_NUMBER))
        assert failed_root["status_code"] == "ERROR" and failed_root["error_type"] is None
        assert [r["status_code"] for r in roots if r is not failed_root] == ["UNSET"] * 13
        # the demo app's graph raises out of the request span, which OpenTelemetry marks ERROR
        source = (_REPO / "demo-app" / "observability" / "instrumentation.py").read_text(encoding="utf-8")
        assert "span.set_status(StatusCode.ERROR" in source and "raise" in source

    def test_identifiers_are_stable_unique_and_well_formed(self):
        spans = MANIFEST.telemetry_spans
        assert len({(r["trace_id"], r["span_id"]) for r in spans}) == 96
        assert all(re.fullmatch(r"[0-9a-f]{32}", r["trace_id"]) and re.fullmatch(r"[0-9a-f]{16}", r["span_id"]) for r in spans)
        assert [r["kafka_offset"] for r in spans] == list(range(96))
        assert {r["kafka_topic"] for r in spans} == {demo.KAFKA_TOPIC} and {r["kafka_partition"] for r in spans} == {0}
        assert demo.trace_id_for(1) == demo.trace_id_for(1) != demo.trace_id_for(2)
        assert demo.trace_id_for(1) == demo.trace_id_for(1) and re.fullmatch(r"[0-9a-f]{32}", demo.trace_id_for(1))

    def test_building_twice_gives_identical_rows(self):
        demo._CACHE.clear()
        again = demo.build_manifest()
        demo._CACHE.clear()
        demo._CACHE.append(MANIFEST)
        assert again.telemetry_spans == MANIFEST.telemetry_spans and again.rca_evidence == MANIFEST.rca_evidence

    def test_timestamps_are_explicit_utc(self):
        for table in demo.TABLES:
            for row in MANIFEST.rows(table):
                for column in demo.TIMESTAMP_COLUMNS & set(demo.COLUMNS[table]):
                    value = row[column]
                    if value is not None:
                        assert value.tzinfo is not None and value.utcoffset() == timedelta(0), (table, column)
        assert demo.BASE_TIME == datetime(2026, 10, 15, 9, 0, 0, tzinfo=timezone.utc)
        starts = sorted({r["start_time"] for r in _by_name(MANIFEST.telemetry_spans, "agentops.request")})
        assert starts[0] == demo.BASE_TIME and starts[-1] == demo.BASE_TIME + timedelta(minutes=65)
        assert all(b - a == timedelta(minutes=5) for a, b in zip(starts, starts[1:]))

    def test_the_visible_demo_markers(self):
        for anomaly in MANIFEST.anomaly_events:
            assert anomaly["explanation"].startswith("[DEMO SEED] ")
        for investigation in MANIFEST.rca_investigations:
            assert investigation["limitations"][-1].startswith("[DEMO SEED] ")
        assert all(r["attributes"]["demo_seed"] == "b3j-176" for r in MANIFEST.telemetry_spans)

    def test_the_two_anomalies_are_linked_to_their_traces_and_spans(self):
        latency, failure = MANIFEST.anomaly_events
        assert (latency["anomaly_type"], failure["anomaly_type"]) == ("latency", "tool_failure")
        spans = {(r["trace_id"], r["span_id"]): r for r in MANIFEST.telemetry_spans}
        for anomaly in (latency, failure):
            assert spans[(anomaly["trace_id"], anomaly["span_id"])]["span_name"] == "tool.execute"
            assert anomaly["event_time"] == spans[(anomaly["trace_id"], anomaly["span_id"])]["start_time"]
            assert re.fullmatch(r"[0-9a-f]{64}", anomaly["anomaly_id"])
        assert latency["baseline_n"] == 12 and latency["baseline_median"] == 120.5 and latency["baseline_mad"] == 2.0
        assert latency["anomaly_score"] == 751.898875 and latency["severity"] == "INFO"
        assert failure["operation_name"] == "tool.execute/ToolExecutionError" and failure["observed_value"] == 1.0

    def test_the_investigations_and_their_evidence(self):
        for inv in MANIFEST.rca_investigations:
            rows = [e for e in MANIFEST.rca_evidence if e["investigation_id"] == inv["investigation_id"]]
            size = 5 if inv is MANIFEST.rca_investigations[1] else 7
            assert len(rows) == size and inv["trace_span_count"] == size and inv["analyzer_version"] == "1.0.0"
            assert [e["rank_position"] for e in rows] == list(range(1, size + 1))
            scores = [e["evidence_score"] for e in rows]
            assert scores == sorted(scores, reverse=True)
            assert rows[0]["span_name"] == "tool.execute" and rows[0]["is_direct_subject"] is True
            assert sum(e["is_direct_subject"] for e in rows) == 1 and sum(e["is_root_span"] for e in rows) == 1
            assert inv["confidence"] == "HIGH" and inv["subject_span_id"] == rows[0]["span_id"]
        slow, failed = MANIFEST.rca_investigations
        assert "tool_name_absent" in failed["limitations"] and "tool_name_absent" not in slow["limitations"]

    def test_no_secret_looking_content(self):
        text = json.dumps([MANIFEST.telemetry_spans, MANIFEST.anomaly_events, MANIFEST.rca_investigations,
                           MANIFEST.rca_evidence], default=str).lower()
        for word in ("password", "secret", "token", "credential", "postgres_", "api_key"):
            assert word not in text, word


# ---------------------------------------------------------------------------
# D02  Conformance with the migrations
# ---------------------------------------------------------------------------

_MIGRATIONS = {"telemetry_spans": "001_create_telemetry_spans.sql", "anomaly_events": "004_create_anomaly_events.sql",
               "rca_investigations": "007_create_rca_tables.sql", "rca_evidence": "007_create_rca_tables.sql"}


def _table_definition(table: str):
    text = (_REPO / "storage-consumer" / "migrations" / _MIGRATIONS[table]).read_text(encoding="utf-8")
    text = "\n".join(line.split("--")[0] for line in text.splitlines())
    match = re.search(rf"CREATE TABLE (?:public\.)?{table}\s*\((.*?)\n\);", text, re.S)
    assert match, table
    columns, required = [], []
    for line in match.group(1).splitlines():
        line = line.strip().rstrip(",")
        if not line or line.upper().startswith(("CONSTRAINT", "PRIMARY", "FOREIGN", "CHECK", "UNIQUE", "REFERENCES", "(",
                                                "'", "ARRAY", ")")) or not re.match(r"[a-z_]+\s+[A-Za-z]", line):
            continue
        name = line.split()[0]
        columns.append(name)
        if "NOT NULL" in line and "DEFAULT" not in line.upper().replace("NOT NULL", "") and "PRIMARY KEY" not in line:
            required.append(name)
    return columns, required


class TestConformance:

    @pytest.mark.parametrize("table", demo.TABLES)
    def test_columns_exist_and_every_required_column_is_supplied(self, table):
        columns, required = _table_definition(table)
        assert set(demo.COLUMNS[table]) <= set(columns), set(demo.COLUMNS[table]) - set(columns)
        assert set(required) <= set(demo.COLUMNS[table]), set(required) - set(demo.COLUMNS[table])
        for row in MANIFEST.rows(table):
            assert set(row) >= set(demo.COLUMNS[table])
            for column in required:
                assert row[column] is not None, (table, column)

    def test_check_constraints(self):
        for r in MANIFEST.telemetry_spans:
            assert r["duration_ms"] >= 0 and r["kafka_partition"] >= 0 and r["kafka_offset"] >= 0
            assert r["retrieval_result_count"] is None or r["retrieval_result_count"] >= 0
            assert abs((r["end_time"] - r["start_time"]).total_seconds() * 1000 - r["duration_ms"]) < 1e-6
        for a in MANIFEST.anomaly_events:
            assert re.fullmatch(r"[0-9a-f]{64}", a["anomaly_id"])
            assert a["anomaly_type"] in ("latency", "retrieval_quality", "error_rate", "tool_failure")
            assert a["severity"] in ("INFO", "WARNING", "CRITICAL")
            assert a["baseline_n"] is None or a["baseline_n"] >= 0
        ids = {a["anomaly_id"] for a in MANIFEST.anomaly_events}
        for i in MANIFEST.rca_investigations:
            assert re.fullmatch(r"[0-9a-f]{64}", i["investigation_id"]) and i["anomaly_id"] in ids
            assert i["confidence"] in ("HIGH", "MEDIUM", "LOW", "INSUFFICIENT_DATA") and i["trace_span_count"] >= 0
        investigations = {i["investigation_id"] for i in MANIFEST.rca_investigations}
        pairs = set()
        for e in MANIFEST.rca_evidence:
            assert e["investigation_id"] in investigations
            assert 0.0 <= e["evidence_score"] <= 1.0 and e["rank_position"] > 0 and e["depth"] >= 0
            assert e["duration_ms"] >= 0 and (e["trace_duration_fraction"] is None or e["trace_duration_fraction"] >= 0)
            pairs.add((e["investigation_id"], e["span_id"]))
        assert len(pairs) == 12                                   # unique (investigation_id, span_id)

    def test_foreign_keys_and_trace_membership(self):
        span_ids = {(r["trace_id"], r["span_id"]) for r in MANIFEST.telemetry_spans}
        for a in MANIFEST.anomaly_events:
            assert (a["trace_id"], a["span_id"]) in span_ids
        for i in MANIFEST.rca_investigations:
            for e in (x for x in MANIFEST.rca_evidence if x["investigation_id"] == i["investigation_id"]):
                assert (i["trace_id"], e["span_id"]) in span_ids

    def test_the_views_the_apis_read_would_see_one_root_per_trace(self):
        by_trace = {}
        for r in MANIFEST.telemetry_spans:
            by_trace.setdefault(r["trace_id"], []).append(r)
        for rows in by_trace.values():
            assert sum(r["parent_span_id"] is None for r in rows) == 1
            assert sum(r["status_code"] == "ERROR" for r in rows) in (0, 2)


# ---------------------------------------------------------------------------
# D03  Agreement with the repository implementations
# ---------------------------------------------------------------------------

def _stub_psycopg():
    """The repository modules only import psycopg to name connection types; the functions compared
    here are pure.  Where the package (or its libpq) is not installed, a stand-in lets them import."""
    import types

    try:
        import psycopg  # noqa: F401
        import psycopg.rows  # noqa: F401
        return
    except Exception:  # noqa: BLE001 - ImportError, or a missing libpq
        for name in [n for n in sys.modules if n == "psycopg" or n.startswith("psycopg.")]:
            del sys.modules[name]
    stub = types.ModuleType("psycopg")
    for name in ("Connection", "Cursor", "Error", "OperationalError"):
        setattr(stub, name, type(name, (Exception,), {}))
    rows = types.ModuleType("psycopg.rows")
    rows.dict_row = None
    stub.rows = rows
    sys.modules["psycopg"], sys.modules["psycopg.rows"] = stub, rows


def _repo_modules():
    _stub_psycopg()
    for name in ("anomaly-detector", "rca-analyzer", "db-bootstrap"):
        path = str(_REPO / name)
        if path not in sys.path:
            sys.path.append(path)


class TestAgreementWithTheRepository:

    def test_the_hashes_match_the_real_implementations(self):
        _repo_modules()
        import anomaly_repository as ar
        import rca_persist as rp
        from detector.anomaly_types import AnomalyEvent
        for a in MANIFEST.anomaly_events:
            event = AnomalyEvent(
                anomaly_type=a["anomaly_type"], signal_name=a["signal_name"], detector_name=a["detector_name"],
                detector_version=a["detector_version"], trace_id=a["trace_id"], span_id=a["span_id"],
                service_name=a["service_name"], operation_name=a["operation_name"],
                observed_value=a["observed_value"], observed_at=a["event_time"], baseline_median=None,
                baseline_mad=None, baseline_n=None, baseline_window_start=None, baseline_window_end=None,
                anomaly_score=None, severity=lc.STATE_FRESH and "INFO", explanation="x")
            assert ar.compute_anomaly_id(event) == a["anomaly_id"]
        for i in MANIFEST.rca_investigations:
            assert rp.compute_investigation_id(i["anomaly_id"], rp.RCA_ANALYZER_VERSION if hasattr(rp, "RCA_ANALYZER_VERSION")
                                               else "1.0.0") == i["investigation_id"]
        import rca_version
        assert rca_version.RCA_ANALYZER_VERSION == demo.ANALYZER_VERSION

    def test_the_anomalies_equal_what_the_real_detectors_produce(self):
        _repo_modules()
        from detector.anomaly_types import LatencyRecord, ToolRecord
        from detector.latency_detector import LatencyDetector
        from detector.tool_failure_detector import ToolFailureDetector
        spans = MANIFEST.telemetry_spans
        tools = _by_name(spans, "tool.execute")
        latency_records = [LatencyRecord(trace_id=t["trace_id"], span_id=t["span_id"], service_name=t["service_name"],
                                         operation_name="tool.execute", duration_ms=t["duration_ms"],
                                         start_time=t["start_time"], is_error=t["status_code"] == "ERROR")
                           for t in tools]
        slow = next(r for r in latency_records if r.duration_ms == 2350.0)
        (event,) = LatencyDetector().detect(slow, [r for r in latency_records if r is not slow and not r.is_error])
        expected = MANIFEST.anomaly_events[0]
        assert expected["explanation"] == "[DEMO SEED] " + event.explanation
        for field in ("anomaly_type", "signal_name", "detector_name", "detector_version", "trace_id", "span_id",
                      "service_name", "operation_name", "observed_value", "baseline_median", "baseline_mad", "baseline_n",
                      "baseline_window_start", "baseline_window_end"):
            assert expected[field] == getattr(event, field), field
        assert expected["event_time"] == event.observed_at
        assert expected["anomaly_score"] == pytest.approx(event.anomaly_score, abs=1e-6)
        assert expected["severity"] == event.severity.value
        tool_records = [ToolRecord(trace_id=t["trace_id"], span_id=t["span_id"], service_name=t["service_name"],
                                   is_error=t["status_code"] == "ERROR", error_type=t["error_type"],
                                   start_time=t["start_time"]) for t in tools]
        current = next(r for r in tool_records if r.is_error)
        (failure,) = ToolFailureDetector().detect(current, tool_records)
        expected = MANIFEST.anomaly_events[1]
        assert expected["explanation"] == "[DEMO SEED] " + failure.explanation
        for field in ("anomaly_type", "signal_name", "detector_name", "trace_id", "span_id", "operation_name",
                      "observed_value", "anomaly_score"):
            assert expected[field] == getattr(failure, field), field
        assert expected["severity"] == failure.severity.value

    def test_the_rca_rows_equal_what_the_real_analyzer_computes(self):
        _repo_modules()
        from rca_confidence import assess_confidence, derive_signal
        from rca_evidence import extract_evidence
        from rca_orchestrator import _build_summary, _derive_limitations
        from rca_ranker import score_and_rank
        from rca_source import RcaAnomalyRecord
        from rca_trace import SpanRecord, build_trace_tree
        for anomaly, investigation in zip(MANIFEST.anomaly_events, MANIFEST.rca_investigations):
            spans = [SpanRecord(**{k: s[k] for k in (
                "span_id", "parent_span_id", "span_name", "service_name", "start_time", "end_time", "duration_ms",
                "status_code", "trace_id", "span_kind", "status_message", "request_id", "session_id",
                "gen_ai_operation", "agent_name", "agent_operation", "tool_name", "tool_status",
                "retrieval_result_count", "retrieval_top_relevance_score", "error_type", "error_message")})
                for s in MANIFEST.telemetry_spans if s["trace_id"] == anomaly["trace_id"]]
            record = RcaAnomalyRecord(
                anomaly_id=anomaly["anomaly_id"], anomaly_type=anomaly["anomaly_type"],
                signal_name=anomaly["signal_name"], detector_name=anomaly["detector_name"],
                detector_version=anomaly["detector_version"], trace_id=anomaly["trace_id"],
                subject_span_id=anomaly["span_id"], service_name=anomaly["service_name"],
                operation_name=anomaly["operation_name"], observed_value=anomaly["observed_value"],
                event_time=anomaly["event_time"], baseline_median=anomaly["baseline_median"],
                baseline_mad=anomaly["baseline_mad"], baseline_n=anomaly["baseline_n"],
                anomaly_score=anomaly["anomaly_score"], severity=anomaly["severity"],
                detector_explanation=anomaly["explanation"])
            reconstruction = build_trace_tree(spans)
            ranked = score_and_rank(record, extract_evidence(record, reconstruction))
            confidence = assess_confidence(record, ranked, reconstruction)
            rows = [e for e in MANIFEST.rca_evidence if e["investigation_id"] == investigation["investigation_id"]]
            assert len(ranked) == len(rows) == (5 if anomaly["anomaly_type"] == "tool_failure" else 7)
            for position, (real, row) in enumerate(zip(ranked, rows), start=1):
                assert row["rank_position"] == position
                for field in ("span_id", "parent_span_id", "span_name", "service_name", "duration_ms", "status_code",
                              "error_type", "error_message", "tool_name", "tool_status", "agent_name", "agent_operation",
                              "retrieval_result_count", "retrieval_top_relevance_score", "is_root_span",
                              "is_error_span", "is_direct_subject", "depth", "evidence_type",
                              "evidence_score_breakdown", "explanation"):
                    assert row[field] == getattr(real, field), (position, field)
                assert row["evidence_score"] == pytest.approx(real.evidence_score, abs=1e-12)
                assert row["trace_duration_fraction"] == pytest.approx(real.trace_duration_fraction, abs=1e-12)
            assert investigation["confidence"] == confidence
            assert investigation["summary"] == _build_summary(confidence, record, reconstruction, ranked)
            limitations = _derive_limitations(record, reconstruction, ranked, derive_signal(record), confidence)
            assert investigation["limitations"][:-1] == list(limitations)

    def test_the_expected_ledger_is_the_real_bootstrap_plan(self):
        _repo_modules()
        import bootstrap
        plan = bootstrap.build_plan(_REPO / "storage-consumer" / "migrations", _REPO / "db-bootstrap" / "post_dbt_grants.sql")
        assert tuple(step.name for step in plan) == demo.EXPECTED_LEDGER_STEPS and len(plan) == 18


# ---------------------------------------------------------------------------
# D04  SQL text
# ---------------------------------------------------------------------------

def _split_values(text: str) -> list[str]:
    """Top-level comma split of one VALUES tuple body, honouring quotes and brackets."""
    parts, depth, current, quote = [], 0, [], False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            current.append(ch)
            if ch == "'":
                if text[i + 1:i + 2] == "'":
                    current.append("'")
                    i += 1
                else:
                    quote = False
        elif ch == "'":
            quote = True
            current.append(ch)
        elif ch in "([":
            depth += 1
            current.append(ch)
        elif ch in ")]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current).strip())
    return parts


class TestSql:
    SQL = demo.seed_sql()

    def test_the_script_shape(self):
        lines = self.SQL.splitlines()
        assert lines[0].startswith("-- [DEMO SEED] b3j-176")
        assert lines[1].startswith("SET LOCAL lock_timeout") and lines[2].startswith("SET LOCAL statement_timeout")
        assert lines[3] == ("LOCK TABLE public.telemetry_spans, public.anomaly_events, public.rca_investigations, "
                            "public.rca_evidence IN EXCLUSIVE MODE;")
        assert lines[4].startswith("DO $seed$ BEGIN IF") and "are not empty" in lines[4] and lines[4].count("count(*)") == 4
        assert lines[-1].startswith("DO $verify$") and "96" in lines[-1] and "unexpected row counts" in lines[-1]
        assert "BEGIN;" not in self.SQL and "COMMIT" not in self.SQL.upper()          # psql --single-transaction owns it

    def test_inserts_go_only_to_the_four_tables_once_each_in_order(self):
        targets = re.findall(r"^INSERT INTO public\.([a-z_]+) ", self.SQL, re.M)
        assert targets == list(demo.TABLES)
        for word in ("delete", "update ", "truncate", "drop ", "alter ", "create ", "grant ", "revoke ", "copy ",
                     "agentops_bootstrap", "analytics", "ledger", "set role", "\\", "pg_", "vacuum", "reindex",
                     "insert into public.analytics", "begin;", "commit", "rollback"):
            assert word not in self.SQL.lower(), word

    def test_every_statement_line_is_one_of_the_known_forms(self):
        for line in self.SQL.splitlines():
            assert (line.startswith(("--", "SET LOCAL ", "LOCK TABLE ", "DO $seed$", "DO $verify$", "INSERT INTO public.",
                                     "  ("))), line

    def test_the_value_tuples_match_the_column_lists(self):
        for table in demo.TABLES:
            block = re.search(rf"INSERT INTO public\.{table} \(([^)]*)\) VALUES\n(.*?);\n", self.SQL, re.S)
            columns = [c.strip() for c in block.group(1).split(",")]
            assert columns == list(demo.COLUMNS[table])
            tuples = [ln.strip().rstrip(",") for ln in block.group(2).splitlines()]
            assert len(tuples) == demo.EXPECTED_COUNTS[table]
            for t in tuples:
                assert t.startswith("(") and t.endswith(")")
                assert len(_split_values(t[1:-1])) == len(columns), (table, t[:80])

    def test_literal_rendering(self):
        f = demo.sql_literal
        assert f("c", None) == "NULL" and f("c", True) == "TRUE" and f("c", False) == "FALSE" and f("c", 7) == "7"
        assert f("c", 2350.0) == "2350.0" and f("c", 0.1) == "0.1"
        assert f("c", "it's") == "'it''s'" and f("c", "a\nb") == "'a\nb'"
        assert f("c", datetime(2026, 10, 15, 9, 0, 0, 5000, tzinfo=timezone.utc)) == "'2026-10-15T09:00:00.005000+00'::timestamptz"
        assert f("c", {"b": 1, "a": "x'y"}) == "'{\"a\":\"x''y\",\"b\":1}'::jsonb"
        assert f("c", ["a", "b'c"]) == "ARRAY['a', 'b''c']::text[]"
        for bad in (float("nan"), float("inf")):
            with pytest.raises(ValueError):
                f("c", bad)
        with pytest.raises(ValueError):
            f("c", "x\x00y")
        with pytest.raises(TypeError):
            f("c", object())

    def test_the_script_is_deterministic_and_secret_free(self):
        assert demo.seed_sql() == self.SQL == demo.seed_sql(MANIFEST)
        for word in ("password", "secret", "token", "credential"):
            assert word not in self.SQL.lower()
        assert self.SQL.isprintable() or "\n" in self.SQL

    def test_the_fixed_read_queries(self):
        assert demo.COUNTS_SQL.count("count(*)") == 4 and "agentops_bootstrap" not in demo.COUNTS_SQL
        assert demo.LEDGER_SQL == "SELECT position || '|' || step FROM agentops_bootstrap.ledger ORDER BY position"
        for table in demo.TABLES:
            sql = demo.rows_sql(table)
            assert sql.startswith("SELECT row_to_json(t) FROM (SELECT ") and f"FROM public.{table} ORDER BY " in sql
            assert not re.search(r"(?i)\b(insert|update|delete|drop|alter|truncate|grant)\b", sql)
        with pytest.raises(ValueError):
            demo.rows_sql("telemetry_spans; DROP TABLE x")


# ---------------------------------------------------------------------------
# D05  Row comparison and ledger parsing
# ---------------------------------------------------------------------------

def _json_row(row):
    def conv(value):
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()
        return value

    return {k: conv(v) for k, v in row.items() if k in demo.COLUMNS_ALL}


demo.COLUMNS_ALL = {c for cols in demo.COLUMNS.values() for c in cols}


def _lines(table, rows=None):
    rows = MANIFEST.rows(table) if rows is None else rows
    key = demo.ORDER_BY[table].split(", ")
    ordered = sorted(rows, key=lambda r: tuple(r[k] if k == "rank_position" else str(r[k]) for k in key))
    return "\n".join(json.dumps({c: (r[c].astimezone(timezone.utc).isoformat() if isinstance(r[c], datetime) else r[c])
                                 for c in demo.COLUMNS[table]}) for r in ordered)


class TestComparison:

    @pytest.mark.parametrize("table", demo.TABLES)
    def test_the_manifest_matches_itself(self, table):
        assert demo.compare_rows(table, _lines(table)) == []

    def test_a_changed_value_a_missing_row_and_extra_rows_are_reported(self):
        rows = [dict(r) for r in MANIFEST.telemetry_spans]
        rows[3]["duration_ms"] += 1
        problems = demo.compare_rows("telemetry_spans", _lines("telemetry_spans", rows))
        assert problems and "differs in duration_ms" in problems[0]
        assert demo.compare_rows("telemetry_spans", _lines("telemetry_spans", rows[:-1]))[0].endswith("95 rows found, 96 expected")
        assert "97 rows found" in demo.compare_rows("telemetry_spans", _lines("telemetry_spans") + "\n" + _lines("telemetry_spans").splitlines()[0])[0]
        assert demo.compare_rows("telemetry_spans", "not json")[0].endswith("could not be read")

    def test_a_changed_timestamp_attribute_and_null_are_reported(self):
        for column, value in (("start_time", "2026-10-15T09:00:00.001+00:00"), ("attributes", {"x": 1}),
                              ("status_message", "changed"), ("parent_span_id", None)):
            lines = _lines("telemetry_spans").splitlines()
            doc = json.loads(lines[10])
            doc[column] = value
            lines[10] = json.dumps(doc)
            problems = demo.compare_rows("telemetry_spans", "\n".join(lines))
            assert problems and f"differs in {column}" in problems[0], column

    def test_timestamp_representations_are_equivalent(self):
        lines = _lines("anomaly_events").splitlines()
        doc = json.loads(lines[0])
        doc["event_time"] = doc["event_time"].replace("+00:00", "Z")
        lines[0] = json.dumps(doc)
        assert demo.compare_rows("anomaly_events", "\n".join(lines)) == []

    def test_ledger_parsing_and_matching(self):
        text = "\n".join(f"{i + 1}|{s}" for i, s in enumerate(demo.EXPECTED_LEDGER_STEPS))
        assert demo.ledger_matches(demo.parse_ledger(text))
        assert not demo.ledger_matches(demo.parse_ledger("\n".join(text.splitlines()[:17])))
        swapped = text.splitlines()
        swapped[1], swapped[2] = "2|002_create_grafana_reader.sql", "3|dbt_run"
        assert not demo.ledger_matches(demo.parse_ledger("\n".join(swapped)))
        assert not demo.ledger_matches(demo.parse_ledger(text + "\n19|extra"))
        for bad in ("x|y", "1|", "no separator"):
            with pytest.raises(ValueError):
                demo.parse_ledger(bad)

    def test_count_parsing(self):
        assert demo.parse_counts("96|2|2|12\n") == demo.EXPECTED_COUNTS
        for bad in ("", "1|2|3", "a|b|c|d", "1|2|3|4|5", "-1|0|0|0"):
            assert demo.parse_counts(bad) is None


# ---------------------------------------------------------------------------
# D06  The seed-demo command (fake engine, fake database)
# ---------------------------------------------------------------------------

GOOD_FACTS = f"agentops-mvp|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{{}}"


def _to_json_rows(table):
    return [{c: (r[c].astimezone(timezone.utc).isoformat() if isinstance(r[c], datetime) else r[c])
             for c in demo.COLUMNS[table]} for r in MANIFEST.rows(table)]


class SeedDocker(lt.BuildDocker):
    """The fake engine plus a fake PostgreSQL behind `docker exec`."""

    def __init__(self, world=None, *, facts=GOOD_FACTS, ledger=None, tables=None, seed_plan="ok", fail_reads=(),
                 **kwargs):
        super().__init__(world if world is not None else lt.complete_world(), **kwargs)
        self.facts = facts
        self.ledger = list(ledger) if ledger is not None else list(demo.EXPECTED_LEDGER_STEPS)
        self.tables = {t: [] for t in demo.TABLES} if tables is None else tables
        self.seed_plan = seed_plan
        self.fail_reads = set(fail_reads)
        self.reads: list[str] = []
        self.writes: list[tuple[list[str], dict, bytes]] = []
        self.write_hook = None

    def __call__(self, argv, env):
        if argv[1:2] == ["inspect"] and argv[-1] == mvp.POSTGRES_CONTAINER:
            self.calls.append((list(argv), dict(env)))
            return lc.DockerResult(0, (self.facts + "\n").encode())
        if argv[1:2] == ["exec"]:
            self.calls.append((list(argv), dict(env)))
            sql = argv[-1]
            self.reads.append(sql)
            if sql in self.fail_reads:
                return lc.DockerResult(1, b"")
            if sql == demo.LEDGER_SQL:
                return lc.DockerResult(0, ("\n".join(f"{i + 1}|{s}" for i, s in enumerate(self.ledger)) + "\n").encode())
            if sql == demo.COUNTS_SQL:
                return lc.DockerResult(0, ("|".join(str(len(self.tables[t])) for t in demo.TABLES) + "\n").encode())
            for table in demo.TABLES:
                if sql == demo.rows_sql(table):
                    key = demo.ORDER_BY[table].split(", ")
                    rows = sorted(self.tables[table], key=lambda r: tuple(r[k] if k == "rank_position" else str(r[k]) for k in key))
                    return lc.DockerResult(0, ("\n".join(json.dumps(r) for r in rows) + "\n").encode())
            raise AssertionError("unexpected SQL: " + sql[:80])
        return super().__call__(argv, env)

    def seed(self, argv, env, input_bytes):
        self.writes.append((list(argv), dict(env), input_bytes))
        if self.write_hook:
            self.write_hook()
        plan = self.seed_plan
        if plan == "interrupt":
            raise KeyboardInterrupt
        if plan == "timeout":
            raise subprocess.TimeoutExpired(argv, 120)
        if plan == "crash":
            raise RuntimeError("boom " + _CANARY)
        if plan == "runner-error":
            raise mvp.CredentialError("the container tool could not be run", mvp.EXIT_FAILED)
        if plan == "sql-error":
            return lc.DockerResult(3, (f"psql: ERROR:  seed refused: the target tables are not empty\n"
                                       f"POSTGRES_PASSWORD={_CANARY}\npassword: hunter2\n").encode())
        assert input_bytes == demo.seed_sql().encode("utf-8")
        self.tables = {t: deepcopy(_to_json_rows(t)) for t in demo.TABLES}
        if plan == "corrupt-commit":
            self.tables["anomaly_events"][0]["severity"] = "CRITICAL"
        if plan == "interrupt-after-commit":
            raise KeyboardInterrupt
        return lc.DockerResult(0, b"")


def _seed_cli(tmp_path, docker=None, *, prepared=None, host=None, no_file=False, seed_runner=None):
    docker = docker if docker is not None else SeedDocker()
    target, runner, platform = prepared if prepared else lt._prepare(tmp_path)
    if no_file:
        target = target.parent / "missing" / mvp.FILE_NAME
    environ = {"SystemRoot": r"C:\Windows", "PATH": "/usr/bin", "DOCKER_CONFIG": "/home/x/.docker"}
    environ.update(host or {})
    out, err = io.StringIO(), io.StringIO()
    code = mvp.main(["seed-demo", "--credentials-file", str(target)], environ=environ, platform_name=platform,
                    runner=runner, compose_runner=docker, seed_runner=seed_runner or docker.seed, docker=_DOCKER,
                    repo_root=_REPO, out=out, err=err)
    return lt._Run(code, out.getvalue(), err.getvalue(), target, docker)


def _flat(docker):
    return " ".join(" ".join(a) for a, _ in docker.calls).split()


class TestSeedCommand:

    def test_a_successful_seed_writes_once_and_verifies_row_by_row(self, tmp_path):
        run = _seed_cli(tmp_path)
        assert run.code == 0, run.err
        assert run.out.startswith("demo data seeded: 96 telemetry_spans, 2 anomaly_events, 2 rca_investigations, 12 rca_evidence")
        assert "bootstrap ledger and the analytics schema were not changed" in run.out
        assert len(run.docker.writes) == 1
        argv, env, script = run.docker.writes[0]
        assert argv == [_DOCKER, "exec", "-i", "agentops-mvp-postgres-1", "psql", "-U", "agentops", "-d", "agentops",
                        "-X", "-q", "--single-transaction", "-v", "ON_ERROR_STOP=1", "-f", "-"]
        assert script == demo.seed_sql().encode("utf-8")
        assert {t: len(r) for t, r in run.docker.tables.items()} == demo.EXPECTED_COUNTS

    def test_the_read_commands_are_fixed_and_read_only(self, tmp_path):
        run = _seed_cli(tmp_path)
        execs = [a for a, _ in run.docker.calls if a[1:2] == ["exec"]]
        assert execs
        for argv in execs:
            if "-i" in argv:
                continue
            assert argv[:6] == [_DOCKER, "exec", "-e", "PGOPTIONS=-cdefault_transaction_read_only=on",
                                "agentops-mvp-postgres-1", "psql"]
            assert argv[-2] == "-c" and argv[-1] in {demo.LEDGER_SQL, demo.COUNTS_SQL, *(demo.rows_sql(t) for t in demo.TABLES)}
        assert [r for r in run.docker.reads][:2] == [demo.LEDGER_SQL, demo.COUNTS_SQL]

    def test_only_expected_docker_commands_and_no_forbidden_option(self, tmp_path):
        run = _seed_cli(tmp_path)
        kinds = set()
        for argv, _env in run.docker.calls:
            tail = argv[1:]
            if tail[0] == "compose":
                kinds.add("compose config")
            else:
                kinds.add(" ".join(tail[:2]) if tail[0] in ("context", "network", "volume", "image") else tail[0])
        assert kinds <= {"compose config", "context inspect", "info", "ps", "inspect", "exec", "network ls",
                         "network inspect", "volume ls", "volume inspect", "image ls"}
        # for `docker exec`, only what comes before the psql program is a Docker option (psql's own -v is a variable)
        flat = []
        for argv, _env in run.docker.calls:
            flat += argv[:argv.index("psql")] if "psql" in argv else argv
        for forbidden in ("up", "down", "build", "run", "start", "stop", "kill", "rm", "create", "pull", "push", "prune",
                          "restart", "cp", "--volumes", "-v", "--env-file", "--privileged", "-u", "--user", "-it"):
            assert forbidden not in flat, forbidden
        assert not any("DELETE" in a or "TRUNCATE" in a or "DROP" in a for argv, _ in run.docker.calls for a in argv)

    def test_the_legacy_stack_and_the_database_port_are_never_involved(self, tmp_path):
        run = _seed_cli(tmp_path)
        flat = " ".join(" ".join(a) for a, _ in run.docker.calls) + " ".join(str(c) for c in run.docker.writes[0][0])
        for word in lt.LEGACY_WORDS + ("5432", "agentops-postgres "):
            assert word not in flat

    def test_no_credential_is_read_printed_or_passed(self, tmp_path):
        real = set(cfg._values().values())
        run = _seed_cli(tmp_path, host={"POSTGRES_PASSWORD": _CANARY, "COMPOSE_PROFILES": "x"})
        assert run.code == 0
        for argv, env in run.docker.calls + [(w[0], w[1]) for w in run.docker.writes]:
            assert not any(v in " ".join(argv) for v in real | {_CANARY})
            assert not any(v in env.values() for v in real | {_CANARY})
            assert not {k.upper() for k in env} & {n.upper() for n in mvp.CREDENTIAL_VARIABLES}
            assert not any(k.upper().startswith("COMPOSE_") for k in env)
        assert not any(v in run.text for v in real | {_CANARY})

    def test_the_lock_is_held_while_it_works_and_released_after(self, tmp_path):
        prepared = lt._prepare(tmp_path)
        lock_path = str(prepared[0].parent / "lifecycle.lock")
        observed = []

        def probe():
            try:
                lc.ExclusiveLock(lock_path).acquire()
                observed.append("free")
            except lc.LockHeldError:
                observed.append("held")

        docker = SeedDocker()
        docker.write_hook = probe
        assert _seed_cli(tmp_path, docker, prepared=prepared).code == 0
        assert observed == ["held"]
        lc.ExclusiveLock(lock_path).acquire().release()

    def test_a_concurrent_lifecycle_command_is_refused(self, tmp_path):
        prepared = lt._prepare(tmp_path)
        with lc.ExclusiveLock(str(prepared[0].parent / "lifecycle.lock")):
            run = _seed_cli(tmp_path, prepared=prepared)
        assert run.code == mvp.EXIT_REFUSED and "another lifecycle command is running" in run.err
        assert run.docker.writes == []

    # -- refusals: nothing is written -------------------------------------------------------------

    def _refused(self, run, fragment, code=mvp.EXIT_REFUSED):
        assert run.code == code, (run.code, run.err)
        assert fragment in run.err, run.err
        assert run.docker.writes == [] and run.out == ""

    def test_missing_credentials_and_non_local_engine(self, tmp_path):
        run = _seed_cli(tmp_path / "a", no_file=True)
        assert run.code != 0 and run.docker.calls == [] and run.docker.writes == []
        self._refused(_seed_cli(tmp_path / "b", SeedDocker(endpoint="tcp://10.1.2.3:2375")), "not a local endpoint")

    @pytest.mark.parametrize("label,world", [
        ("fresh", lt.World()), ("images only", lt.World(images=list(lt._ALL_IMAGES))),
        ("bootstrap failed", lt.World(containers=[lt._container("db-bootstrap", state="exited", exit_code=6, health="none")],
                                      images=list(lt._ALL_IMAGES))),
        ("stopped", None), ("unlabelled volume", None),
    ])
    def test_the_stack_must_be_complete(self, tmp_path, label, world):
        if label == "stopped":
            world = lt.complete_world()
            for c in world.containers:
                if c["project"] == "agentops-mvp" and c["service"] == "postgres":
                    c.update(state="exited", running="false", health="none")
        if label == "unlabelled volume":
            world = lt.complete_world()
            world.volumes["agentops-mvp-postgres-data"] = {}
        self._refused(_seed_cli(tmp_path, SeedDocker(world)), "not COMPLETE")

    def test_an_uninspectable_stack_is_refused(self, tmp_path):
        self._refused(_seed_cli(tmp_path, SeedDocker(fail={"volume ls"})), "not COMPLETE")

    @pytest.mark.parametrize("label,facts", [
        ("wrong volume", "agentops-mvp|postgres|true|volume:agentops_postgres-data:/var/lib/postgresql/data;|{}"),
        ("bind mount", "agentops-mvp|postgres|true|bind::/var/lib/postgresql/data;|{}"),
        ("extra mount", "agentops-mvp|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;volume:x:/y;|{}"),
        ("wrong destination", "agentops-mvp|postgres|true|volume:agentops-mvp-postgres-data:/data;|{}"),
        ("foreign project", "agentops|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{}"),
        ("wrong service", "agentops-mvp|viewer|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{}"),
        ("not running", "agentops-mvp|postgres|false|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{}"),
        ("published port", 'agentops-mvp|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5432"}]}'),
        ("garbage", "nonsense"), ("empty", ""),
    ])
    def test_the_container_must_be_the_isolated_mvp_database(self, tmp_path, label, facts):
        self._refused(_seed_cli(tmp_path, SeedDocker(facts=facts)), "not the isolated MVP database")

    def test_an_unreadable_container_inspection_is_a_failure(self, tmp_path):
        class NoInspect(SeedDocker):
            def __call__(self, argv, env):
                if argv[1:2] == ["inspect"] and argv[-1] == mvp.POSTGRES_CONTAINER:
                    return lc.DockerResult(1, b"")
                return super().__call__(argv, env)

        self._refused(_seed_cli(tmp_path, NoInspect()), "could not be read", mvp.EXIT_FAILED)

    @pytest.mark.parametrize("label,ledger", [
        ("17 steps", list(demo.EXPECTED_LEDGER_STEPS[:17])), ("empty", []),
        ("extra step", list(demo.EXPECTED_LEDGER_STEPS) + ["016_extra.sql"]),
        ("wrong order", [demo.EXPECTED_LEDGER_STEPS[1], demo.EXPECTED_LEDGER_STEPS[0]] + list(demo.EXPECTED_LEDGER_STEPS[2:])),
        ("renamed", list(demo.EXPECTED_LEDGER_STEPS[:-1]) + ["015_other.sql"]),
        ("missing complete marker", [s for s in demo.EXPECTED_LEDGER_STEPS if s != "complete"]),
    ])
    def test_the_ledger_must_be_exactly_the_eighteen_steps(self, tmp_path, label, ledger):
        self._refused(_seed_cli(tmp_path, SeedDocker(ledger=ledger)), "bootstrap ledger is not the expected 18 steps")

    def test_an_unreadable_ledger_or_count_is_a_failure(self, tmp_path):
        self._refused(_seed_cli(tmp_path / "a", SeedDocker(fail_reads={demo.LEDGER_SQL})), "bootstrap ledger could not be read", mvp.EXIT_FAILED)
        self._refused(_seed_cli(tmp_path / "b", SeedDocker(fail_reads={demo.COUNTS_SQL})), "row counts could not be read", mvp.EXIT_FAILED)

    @pytest.mark.parametrize("table", demo.TABLES)
    def test_any_existing_row_in_any_target_table_is_refused(self, tmp_path, table):
        tables = {t: [] for t in demo.TABLES}
        tables[table] = deepcopy(_to_json_rows(table))[:1]
        docker = SeedDocker(tables=tables)
        self._refused(_seed_cli(tmp_path, docker), "already hold data that is not the demo dataset")
        assert len(docker.tables[table]) == 1                         # untouched

    def test_counts_equal_to_the_manifest_but_different_content_is_refused(self, tmp_path):
        tables = {t: deepcopy(_to_json_rows(t)) for t in demo.TABLES}
        tables["rca_evidence"][5]["explanation"] = "tampered"
        self._refused(_seed_cli(tmp_path, SeedDocker(tables=tables)), "differs from the demo dataset")

    def test_identical_existing_data_is_a_no_write_success_and_a_second_run_is_the_same(self, tmp_path):
        docker = SeedDocker()
        first = _seed_cli(tmp_path / "a", docker)
        assert first.code == 0 and len(docker.writes) == 1
        second = _seed_cli(tmp_path / "b", docker)
        assert second.code == 0 and second.out.startswith("demo data already present") and "nothing was written" in second.out
        assert len(docker.writes) == 1                                # duplicate execution wrote nothing
        assert {t: len(r) for t, r in docker.tables.items()} == demo.EXPECTED_COUNTS

    # -- failures: atomic, preserved ------------------------------------------------------------------------

    def test_an_sql_failure_rolls_back_reports_state_and_redacts(self, tmp_path):
        docker = SeedDocker(seed_plan="sql-error")
        run = _seed_cli(tmp_path, docker, host={"POSTGRES_PASSWORD": _CANARY})
        assert run.code == mvp.EXIT_FAILED
        assert "the seed failed (exit code 3) and was rolled back; nothing was removed" in run.err
        assert "the tables now hold 0 telemetry_spans, 0 anomaly_events, 0 rca_investigations, 0 rca_evidence" in run.err
        assert "seed refused" in run.err and _CANARY not in run.text and "hunter2" not in run.text and "***" in run.err
        assert len(docker.writes) == 1                                # no retry
        assert all(len(r) == 0 for r in docker.tables.values())

    def test_an_interrupted_seed_reports_the_state_and_keeps_everything(self, tmp_path):
        prepared = lt._prepare(tmp_path)
        docker = SeedDocker(seed_plan="interrupt")
        run = _seed_cli(tmp_path, docker, prepared=prepared)
        assert run.code == mvp.EXIT_FAILED and "the seed was interrupted" in run.err and "may still be finishing" in run.err
        assert "the tables now hold 0 telemetry_spans" in run.err and len(docker.writes) == 1
        lc.ExclusiveLock(str(prepared[0].parent / "lifecycle.lock")).acquire().release()
        # the interrupted transaction did commit: the report says so and a rerun does not write again
        committed = SeedDocker(seed_plan="interrupt-after-commit")
        run = _seed_cli(tmp_path / "c", committed)
        assert run.code == mvp.EXIT_FAILED and "the tables now hold 96 telemetry_spans, 2 anomaly_events" in run.err
        rerun = _seed_cli(tmp_path / "d", committed)
        assert rerun.code == 0 and "already present" in rerun.out and len(committed.writes) == 1

    def test_a_timeout_and_a_runner_error_and_a_crash(self, tmp_path):
        run = _seed_cli(tmp_path / "a", SeedDocker(seed_plan="timeout"))
        assert run.code == mvp.EXIT_FAILED and "the seed timed out; nothing was removed" in run.err
        run = _seed_cli(tmp_path / "b", SeedDocker(seed_plan="runner-error"))
        assert run.code == mvp.EXIT_FAILED and "the seed did not complete (the container tool could not be run)" in run.err
        run = _seed_cli(tmp_path / "c", SeedDocker(seed_plan="crash"))
        assert run.code == mvp.EXIT_FAILED and "could not be run" in run.err and _CANARY not in run.text and "boom" not in run.text

    def test_a_committed_result_that_differs_is_reported_and_not_removed(self, tmp_path):
        docker = SeedDocker(seed_plan="corrupt-commit")
        run = _seed_cli(tmp_path, docker)
        assert run.code == mvp.EXIT_FAILED and "committed but verification failed" in run.err
        assert "differs in severity" in run.err and "nothing was removed" in run.err
        assert len(docker.tables["telemetry_spans"]) == 96 and len(docker.writes) == 1

    def test_an_unreadable_row_listing_after_the_write_is_a_failure(self, tmp_path):
        docker = SeedDocker(fail_reads={demo.rows_sql("rca_evidence")})
        run = _seed_cli(tmp_path, docker)
        assert run.code == mvp.EXIT_FAILED and "rca_evidence rows could not be read" in run.err

    # -- the runners and the argument builders -----------------------------------------------------------------

    def test_the_default_seed_runner_sends_the_script_on_stdin_only_and_is_bounded(self, monkeypatch):
        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(kwargs)
            seen["argv"] = list(argv)
            return subprocess.CompletedProcess(argv, 0, b"x" * 9000, None)

        monkeypatch.setattr(mvp.subprocess, "run", fake_run)
        result = mvp.default_seed_runner(["docker", "exec"], {"A": "b"}, b"SELECT 1;")
        assert seen["input"] == b"SELECT 1;" and seen["timeout"] == mvp.SEED_TIMEOUT_SECONDS == 120
        assert seen["shell"] is False and seen["stderr"] == subprocess.STDOUT and seen["env"] == {"A": "b"}
        assert len(result.stdout) == mvp._BUILD_OUTPUT_TAIL
        assert "SELECT" not in " ".join(seen["argv"])

    def test_the_other_runners_do_not_pass_stdin(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(mvp.subprocess, "run", lambda argv, **kw: seen.update(kw) or subprocess.CompletedProcess(argv, 0, b"", None))
        mvp.default_build_runner(["docker"], {})
        assert "input" not in seen

    def test_production_wiring_uses_the_seed_runner_only_for_the_write(self, tmp_path, monkeypatch):
        docker = SeedDocker()
        used = {"reads": 0, "writes": []}
        monkeypatch.setattr(mvp, "default_compose_runner", lambda argv, env: used.__setitem__("reads", used["reads"] + 1) or docker(argv, env))
        monkeypatch.setattr(mvp, "default_seed_runner", lambda argv, env, data: used["writes"].append(list(argv)) or docker.seed(argv, env, data))
        target, runner, platform = lt._prepare(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        code = mvp.main(["seed-demo", "--credentials-file", str(target)], environ={"SystemRoot": r"C:\Windows"},
                        platform_name=platform, runner=runner, docker=_DOCKER, repo_root=_REPO, out=out, err=err)
        assert code == 0, err.getvalue()
        assert used["reads"] > 5 and len(used["writes"]) == 1 and "-i" in used["writes"][0]

    def test_the_argument_builders_are_fixed(self):
        assert mvp.container_facts_argv(_DOCKER)[:5] == [_DOCKER, "inspect", "--type", "container", "--format"]
        assert mvp.container_facts_argv(_DOCKER)[-1] == "agentops-mvp-postgres-1"
        fmt = mvp.container_facts_argv(_DOCKER)[5]
        for forbidden in (".Config.Env", ".Config.Cmd", "Password", ".Args", ".Config}"):
            assert forbidden not in fmt
        for bad in ("SELECT 1", "DELETE FROM public.anomaly_events", demo.LEDGER_SQL + "; DROP TABLE x", ""):
            with pytest.raises(mvp.CredentialError):
                mvp.psql_read_argv(_DOCKER, bad)
        assert mvp.psql_read_argv(_DOCKER, demo.COUNTS_SQL)[-1] == demo.COUNTS_SQL

    def test_existing_commands_are_unaffected(self, tmp_path):
        assert lt._status(tmp_path / "s", lt.World())[0] == 0
        assert lt._build_cli(tmp_path / "b").code == 0
        assert lt._up_cli(tmp_path / "u").code == 0
        assert cfg._check_config(tmp_path / "c", cfg.FakeEngine())[0] == mvp.EXIT_OK


# ---------------------------------------------------------------------------
# D07  Scope
# ---------------------------------------------------------------------------

class TestScope:
    DEMO_SOURCE = Path(demo.__file__).read_text(encoding="utf-8")
    MVP_SOURCE = Path(mvp.__file__).read_text(encoding="utf-8")

    def test_the_demo_module_is_pure(self):
        tree = ast.parse(self.DEMO_SOURCE)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add((node.module or "").split(".")[0])
        assert imported <= {"__future__", "hashlib", "json", "math", "re", "dataclasses", "datetime", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                assert name not in {"open", "exec", "eval", "system", "Popen", "run", "connect", "now", "today", "utcnow",
                                    "random", "randint", "uuid4", "urandom"}, name
        assert "datetime.now" not in self.DEMO_SOURCE and "import random" not in self.DEMO_SOURCE

    def test_the_seed_functions_use_no_modifying_container_verb(self):
        functions = {n.name: n for n in ast.walk(ast.parse(self.MVP_SOURCE)) if isinstance(n, ast.FunctionDef)}
        forbidden = {"up", "down", "build", "run", "start", "stop", "kill", "rm", "create", "pull", "push", "prune",
                     "restart", "cp", "--volumes", "-v", "--env-file", "--privileged", "-u", "--user", "system"}
        for name in ("container_facts_argv", "psql_read_argv", "psql_write_argv", "_seed_command", "_seed_locked",
                     "_query", "_compare_all", "_seed_evidence", "default_seed_runner"):
            constants = {n.value for n in ast.walk(functions[name]) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            allowed_psql_flag = {"-v"} if name in ("psql_read_argv", "psql_write_argv") else set()   # psql -v NAME=value
            assert not constants & (forbidden - allowed_psql_flag), (name, constants & forbidden)
        assert "DELETE FROM" not in self.MVP_SOURCE and "TRUNCATE" not in self.MVP_SOURCE and "DROP TABLE" not in self.MVP_SOURCE

    def test_exec_appears_only_in_the_two_fixed_builders(self):
        functions = {n.name: n for n in ast.walk(ast.parse(self.MVP_SOURCE)) if isinstance(n, ast.FunctionDef)}
        holders = [name for name, fn in functions.items()
                   if any(isinstance(n, ast.Constant) and n.value == "exec" for n in ast.walk(fn))]
        assert sorted(holders) == ["psql_read_argv", "psql_write_argv"]

    def test_the_seed_never_touches_the_credential_values_or_the_ledger_for_writing(self):
        functions = {n.name: n for n in ast.walk(ast.parse(self.MVP_SOURCE)) if isinstance(n, ast.FunctionDef)}
        for name in ("_seed_command", "_seed_locked"):
            text = ast.get_source_segment(self.MVP_SOURCE, functions[name])
            assert "parse_file" not in text and "_read_bytes" not in text and "values" not in text.replace("values()", "")
        assert "agentops_bootstrap" not in self.MVP_SOURCE.replace("agentops_bootstrap.ledger", "")

    def test_the_seed_sql_never_references_the_ledger_or_analytics(self):
        sql = demo.seed_sql().lower()
        assert "agentops_bootstrap" not in sql and "analytics" not in sql and "ledger" not in sql

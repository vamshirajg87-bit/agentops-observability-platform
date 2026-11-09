"""
scripts/tests/test_agentops_mvp_demo_spans_only.py

Offline tests for the spans-only generator of scripts/agentops_mvp_demo.py (B3J-419).

Nothing real is ever run: no database, no Docker, no process.  The generator is pure, so the tests
call it and read the rows and the SQL text.  The real detector classes (pure code, no database) are
run on the generated rows to show which signals the data really produces.

    S01  Determinism and the shape of the dataset
    S02  Timestamps
    S03  Arguments
    S04  SQL text: only telemetry_spans, one transaction, safe quoting
    S05  The real detectors on the generated rows
    S06  The existing seed is unchanged
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentops_mvp_demo as demo  # noqa: E402

_REPO = Path(demo.__file__).resolve().parents[1]
BASE = datetime(2026, 10, 26, 6, 0, 0, tzinfo=timezone.utc)
ROWS = demo.spans_only_rows(BASE)
SQL = demo.spans_only_sql(BASE)

#: sha256 of demo.seed_sql() as it was before the spans-only generator was added (B3J-419)
SEED_SQL_SHA256 = "3b3e72b2f03676239ce01c370b9fd610a2a945eb229e2d8fca354cf3cb08e5f9"


def _by_trace(rows):
    out: dict[str, list] = {}
    for row in rows:
        out.setdefault(row["trace_id"], []).append(row)
    return out


# ---------------------------------------------------------------------------
# S01  Determinism and shape
# ---------------------------------------------------------------------------

class TestShape:

    def test_same_arguments_give_the_same_rows_and_the_same_sql(self):
        assert demo.spans_only_rows(BASE) == ROWS
        assert demo.spans_only_sql(BASE) == SQL

    def test_row_count_is_the_documented_one(self):
        assert len(ROWS) == demo.spans_only_expected_count() == (36 + 1) * 7 + 5 == 264
        assert len(demo.spans_only_rows(BASE, normal_traces=30)) == demo.spans_only_expected_count(30)

    def test_traces_are_seven_spans_each_and_one_failed_trace_of_five(self):
        traces = _by_trace(ROWS)
        sizes = sorted(len(v) for v in traces.values())
        assert len(traces) == 38 and sizes.count(5) == 1 and sizes.count(7) == 37

    def test_the_baseline_is_at_least_the_detectors_minimum(self):
        normal = [r for r in ROWS if r["span_name"] == "tool.execute" and r["status_code"] != "ERROR"
                  and r["duration_ms"] < 1000]
        assert len(normal) >= demo.SPANS_ONLY_MIN_NORMAL_TRACES == 30

    def test_one_slow_tool_span_and_one_failed_tool_span(self):
        tools = [r for r in ROWS if r["span_name"] == "tool.execute"]
        slow = [r for r in tools if r["duration_ms"] == demo.SLOW_TOOL_MS]
        failed = [r for r in tools if r["status_code"] == "ERROR"]
        assert len(slow) == 1 and len(failed) == 1
        assert failed[0]["error_type"] == demo.ERROR_TYPE and failed[0]["tool_name"] is None
        assert slow[0]["tool_status"] == "success"

    def test_identifiers_do_not_overlap_the_seed_demo(self):
        seed_traces = {r["trace_id"] for r in demo.build_manifest().telemetry_spans}
        seed_spans = {(r["trace_id"], r["span_id"]) for r in demo.build_manifest().telemetry_spans}
        assert not seed_traces & {r["trace_id"] for r in ROWS}
        assert not seed_spans & {(r["trace_id"], r["span_id"]) for r in ROWS}

    def test_identifiers_are_unique_and_well_formed(self):
        assert len({(r["trace_id"], r["span_id"]) for r in ROWS}) == len(ROWS)
        assert all(re.fullmatch(r"[0-9a-f]{32}", r["trace_id"]) and re.fullmatch(r"[0-9a-f]{16}", r["span_id"]) for r in ROWS)
        assert len({(r["kafka_topic"], r["kafka_partition"], r["kafka_offset"]) for r in ROWS}) == len(ROWS)

    def test_every_row_is_marked_as_demonstration_data(self):
        assert all(r["attributes"]["demo_seed"] == demo.SPANS_ONLY_LABEL for r in ROWS)
        assert {r["kafka_topic"] for r in ROWS} == {"agentops.demo.seed.b3j419"}

    def test_every_row_has_exactly_the_table_columns(self):
        assert all(set(r) == set(demo.COLUMNS["telemetry_spans"]) for r in ROWS)

    def test_the_start_time_does_not_change_the_identifiers(self):
        later = demo.spans_only_rows(BASE + timedelta(hours=3))
        assert [(r["trace_id"], r["span_id"]) for r in later] == [(r["trace_id"], r["span_id"]) for r in ROWS]

    def test_another_label_gives_other_identifiers(self):
        other = demo.spans_only_rows(BASE, label="b3j-420")
        assert not {r["trace_id"] for r in other} & {r["trace_id"] for r in ROWS}
        assert {r["kafka_topic"] for r in other} == {"agentops.demo.seed.b3j420"}


# ---------------------------------------------------------------------------
# S02  Timestamps
# ---------------------------------------------------------------------------

class TestTimestamps:

    def test_the_first_span_starts_at_the_base_time(self):
        first, last = demo.spans_only_extent(BASE)
        assert first == BASE
        assert last == max(r["end_time"] for r in ROWS)

    def test_traces_are_five_minutes_apart_and_the_anomalies_come_last(self):
        starts = sorted(r["start_time"] for r in ROWS if r["span_name"] == "agentops.request")
        assert [b - a for a, b in zip(starts, starts[1:])] == [timedelta(minutes=5)] * 37
        slow = next(r for r in ROWS if r["span_name"] == "tool.execute" and r["duration_ms"] == demo.SLOW_TOOL_MS)
        failed = next(r for r in ROWS if r["span_name"] == "tool.execute" and r["status_code"] == "ERROR")
        normal_last = max(r["start_time"] for r in ROWS if r["span_name"] == "tool.execute"
                          and r["duration_ms"] < 1000 and r["status_code"] != "ERROR")
        assert normal_last < slow["start_time"] < failed["start_time"]

    def test_moving_the_base_time_moves_every_timestamp_by_the_same_amount(self):
        delta = timedelta(hours=7, minutes=13)
        moved = demo.spans_only_rows(BASE + delta)
        for a, b in zip(ROWS, moved):
            assert b["start_time"] - a["start_time"] == delta
            assert b["end_time"] - a["end_time"] == delta
            assert b["ingested_at"] - a["ingested_at"] == delta
            assert b["duration_ms"] == a["duration_ms"]

    def test_a_non_utc_base_time_is_the_same_instant(self):
        plus_two = timezone(timedelta(hours=2))
        assert demo.spans_only_rows(BASE.astimezone(plus_two)) == ROWS
        assert demo.spans_only_sql(BASE.astimezone(plus_two)) == SQL

    def test_the_dataset_fits_inside_a_twenty_four_hour_lookback_when_started_recently(self):
        now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
        first, last = demo.spans_only_extent(now - timedelta(hours=6))
        assert now - timedelta(hours=24) <= first and last <= now
        assert last - first < timedelta(hours=4)

    def test_timestamps_are_rendered_as_utc_timestamptz_literals(self):
        assert "'2026-10-26T06:00:00.000000+00'::timestamptz" in SQL

    def test_end_is_never_before_start(self):
        assert all(r["end_time"] >= r["start_time"] for r in ROWS)


# ---------------------------------------------------------------------------
# S03  Arguments
# ---------------------------------------------------------------------------

class TestArguments:

    def test_a_naive_base_time_is_refused(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            demo.spans_only_rows(datetime(2026, 10, 26, 6, 0))

    @pytest.mark.parametrize("value", ["2026-10-26T06:00:00+00:00", None, 0, 1.5])
    def test_a_base_time_that_is_not_a_datetime_is_refused(self, value):
        with pytest.raises(ValueError):
            demo.spans_only_sql(value)

    @pytest.mark.parametrize("count", [0, 1, 29, 501, -1, True, 36.0, "36", None])
    def test_the_number_of_normal_traces_is_bounded(self, count):
        with pytest.raises(ValueError, match="normal_traces"):
            demo.spans_only_rows(BASE, normal_traces=count)

    @pytest.mark.parametrize("count", [30, 31, 500])
    def test_the_limits_themselves_are_accepted(self, count):
        assert len(demo.spans_only_rows(BASE, normal_traces=count)) == demo.spans_only_expected_count(count)

    @pytest.mark.parametrize("label", ["", "B3J-419", "b3j 419", "b3j;419", "b3j'419", "b3j\n419", "-b3j", "x" * 33,
                                       "b3j-176", "b3j_419", "label\x00"])
    def test_an_unsafe_or_conflicting_label_is_refused(self, label):
        with pytest.raises(ValueError, match="label"):
            demo.spans_only_sql(BASE, label=label)

    def test_a_label_that_is_not_text_is_refused(self):
        with pytest.raises(ValueError):
            demo.spans_only_rows(BASE, label=None)


# ---------------------------------------------------------------------------
# S04  SQL text
# ---------------------------------------------------------------------------

class TestSql:

    def test_only_the_telemetry_spans_table_is_named(self):
        assert set(re.findall(r"public\.(\w+)", SQL)) == {"telemetry_spans"}

    @pytest.mark.parametrize("table", ["anomaly_events", "rca_investigations", "rca_evidence", "anomaly_detector_runs",
                                       "rca_investigation_embeddings", "agentops_bootstrap", "analytics"])
    def test_no_other_table_or_schema_is_mentioned(self, table):
        assert table not in SQL

    def test_only_insert_into_telemetry_spans_modifies_data(self):
        statements = [s.strip() for s in re.split(r";\s*\n", SQL) if s.strip() and not s.strip().startswith("--")]
        verbs = {s.split()[0].upper() for s in statements}
        assert verbs <= {"SET", "LOCK", "DO", "INSERT"}
        for forbidden in ("DELETE", "UPDATE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE", "COPY"):
            assert not re.search(rf"\b{forbidden}\b", SQL), forbidden
        assert SQL.count("INSERT INTO public.telemetry_spans (") == 1

    def test_the_script_locks_checks_emptiness_inserts_and_counts(self):
        order = [SQL.index(piece) for piece in (
            "SET LOCAL lock_timeout", "SET LOCAL statement_timeout", "LOCK TABLE public.telemetry_spans IN EXCLUSIVE MODE",
            "spans-only seed refused", "INSERT INTO public.telemetry_spans", "spans-only seed verification failed")]
        assert order == sorted(order)
        assert f"<> {len(ROWS)} THEN" in SQL
        assert "BEGIN;" not in SQL and "COMMIT" not in SQL        # psql --single-transaction owns the transaction

    def test_the_insert_has_one_value_tuple_per_row(self):
        insert = SQL[SQL.index("INSERT INTO"):SQL.index("DO $verify$")]
        assert insert.count("\n  (") == len(ROWS)

    def test_the_sql_is_plain_printable_text(self):
        assert "\x00" not in SQL and SQL.isascii()
        assert all(ch in "\n" or ch.isprintable() for ch in SQL)

    def test_single_quotes_are_balanced(self):
        assert SQL.replace("''", "").count("'") % 2 == 0

    def test_values_are_escaped_with_the_existing_quoting_function(self):
        assert demo.quote_text("it's") == "'it''s'"
        row = dict(ROWS[0], span_name="evil'); DROP TABLE x; --")
        statement = demo.insert_statement("telemetry_spans", [row])
        assert "'evil''); DROP TABLE x; --'" in statement
        assert statement.endswith(";") and statement.count("INSERT INTO") == 1

    def test_the_header_names_the_label_and_the_scope(self):
        assert SQL.startswith(f"-- {demo.DEMO_MARKER} {demo.SPANS_ONLY_LABEL}: demonstration spans only")


# ---------------------------------------------------------------------------
# S05  The real detectors on the generated rows
# ---------------------------------------------------------------------------

def _detector_modules():
    path = str(_REPO / "anomaly-detector")
    if path not in sys.path:
        sys.path.append(path)
    from detector.anomaly_types import LatencyRecord, ToolRecord
    from detector.latency_detector import LatencyDetector
    from detector.tool_failure_detector import ToolFailureDetector
    return LatencyRecord, ToolRecord, LatencyDetector, ToolFailureDetector


class TestRealDetectors:

    def _tools(self):
        return [r for r in ROWS if r["span_name"] == "tool.execute"]

    def test_the_latency_detector_flags_exactly_the_slow_tool_span(self):
        LatencyRecord, _, LatencyDetector, _ = _detector_modules()
        records = [LatencyRecord(trace_id=t["trace_id"], span_id=t["span_id"], service_name=t["service_name"],
                                 operation_name="tool.execute", duration_ms=t["duration_ms"], start_time=t["start_time"],
                                 is_error=t["status_code"] == "ERROR") for t in self._tools()]
        flagged = []
        for record in records:
            earlier = [r for r in records if r.start_time < record.start_time]
            flagged += [(record, e) for e in LatencyDetector().detect(record, earlier)]
        assert len(flagged) == 1
        record, event = flagged[0]
        assert record.duration_ms == demo.SLOW_TOOL_MS
        assert event.anomaly_type == "latency" and event.baseline_n == 36 >= 30
        assert event.severity.value in ("WARNING", "CRITICAL")      # a full baseline: the severity is not capped at INFO

    def test_the_tool_failure_detector_flags_exactly_the_failed_tool_span(self):
        _, ToolRecord, _, ToolFailureDetector = _detector_modules()
        records = [ToolRecord(trace_id=t["trace_id"], span_id=t["span_id"], service_name=t["service_name"],
                              is_error=t["status_code"] == "ERROR", error_type=t["error_type"], start_time=t["start_time"])
                   for t in self._tools()]
        events = []
        for record in records:
            events += ToolFailureDetector().detect(record, records) if record.is_error else []
        assert len(events) == 1
        assert events[0].anomaly_type == "tool_failure" and events[0].operation_name == f"tool.execute/{demo.ERROR_TYPE}"
        assert "is_first_occurrence=True" in events[0].explanation

    def test_the_normal_traces_alone_raise_no_latency_anomaly(self):
        LatencyRecord, _, LatencyDetector, _ = _detector_modules()
        normal = [t for t in self._tools() if t["status_code"] != "ERROR" and t["duration_ms"] < 1000]
        records = [LatencyRecord(t["trace_id"], t["span_id"], t["service_name"], "tool.execute", t["duration_ms"],
                                 t["start_time"], False) for t in normal]
        for record in records:
            assert LatencyDetector().detect(record, [r for r in records if r.start_time < record.start_time]) == []

    def test_the_rows_use_the_service_and_operation_names_of_the_default_detector_config(self):
        assert {r["service_name"] for r in ROWS} == {"agentops-demo-app"}
        assert {r["span_name"] for r in ROWS} >= {"tool.execute", "agentops.request"}


# ---------------------------------------------------------------------------
# S06  The existing seed is unchanged
# ---------------------------------------------------------------------------

class TestExistingSeedUnchanged:

    def test_seed_sql_is_byte_for_byte_what_it_was(self):
        assert hashlib.sha256(demo.seed_sql().encode("utf-8")).hexdigest() == SEED_SQL_SHA256

    def test_the_seed_manifest_counts_and_identifiers_are_unchanged(self):
        manifest = demo.build_manifest()
        assert manifest.counts() == demo.EXPECTED_COUNTS
        assert demo.trace_id_for(1) == demo.trace_id_for(1, demo.SEED_LABEL)
        assert manifest.telemetry_spans[0]["trace_id"] == demo.trace_id_for(1)
        assert {r["attributes"]["demo_seed"] for r in manifest.telemetry_spans} == {demo.SEED_LABEL}
        assert {r["kafka_topic"] for r in manifest.telemetry_spans} == {demo.KAFKA_TOPIC}

    def test_the_module_is_still_pure(self):
        tree = ast.parse(Path(demo.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add((node.module or "").split(".")[0])
        assert imported <= {"__future__", "hashlib", "json", "math", "re", "dataclasses", "datetime", "typing"}

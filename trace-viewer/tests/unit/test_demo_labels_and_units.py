"""
trace-viewer/tests/unit/test_demo_labels_and_units.py

B3J-185 presentation changes:
    1  Synthetic demo labelling: derived from the demo_seed attribute, absent for real data
    2  Anomaly observed values carry a unit; raw API values are untouched
    3  Span timestamps show milliseconds in UTC

The SQL and the API are checked with fakes; the JavaScript formatting functions are run
under node (skipped when node is unavailable).  Nothing connects to a database.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import queries
from app import TraceDetailResponse, TraceSummary, app
from queries import _row_to_span_record, fetch_trace_spans, list_traces
from reconstruction import SpanRecord, TraceNode, TraceReconstruction, build_trace_tree

_STATIC = os.path.join(os.path.dirname(__file__), "..", "..", "static")
_DT = datetime(2026, 10, 15, 9, 0, 0, 123000, tzinfo=timezone.utc)
_TRACE_ID = "a" * 32
client = TestClient(app, base_url="http://127.0.0.1")


def _read(name: str) -> str:
    with open(os.path.join(_STATIC, name), encoding="utf-8") as f:
        return f.read()


JS, HTML, CSS = _read("app.js"), _read("index.html"), _read("styles.css")
JS_CODE = "\n".join(re.sub(r"^\s*//.*$", "", line) for line in JS.splitlines())   # comments cannot fake a match


def _span(span_id="s1", parent=None, demo=False) -> SpanRecord:
    return SpanRecord(span_id=span_id, parent_span_id=parent, span_name="x", start_time=_DT, end_time=_DT,
                      duration_ms=1.0, status_code="UNSET", is_demo_data=demo)


def _conn_with(rows=None, count=0):
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchone.return_value = {"count": count}
    cur.fetchall.return_value = rows or []
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


# ---------------------------------------------------------------------------
# 1  Demo labelling: SQL, rows, API
# ---------------------------------------------------------------------------

class TestDemoFlagQueries:

    def test_both_queries_derive_the_flag_from_the_demo_seed_attribute(self):
        for sql in (queries._LIST_TRACES_SELECT, queries._FETCH_SPANS_SQL):
            assert "attributes ->> 'demo_seed' IS NOT NULL" in sql
            assert "AS is_demo_data" in sql

    def test_the_new_sql_is_read_only_and_adds_no_parameters(self):
        for sql in (queries._LIST_TRACES_SELECT, queries._FETCH_SPANS_SQL):
            assert sql.lstrip().upper().startswith("SELECT")
            assert not re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT)\b", sql, re.I)
            assert "%(" not in sql.replace("%(trace_id)s", "")
        assert "analytics.stg_telemetry_spans" in queries._LIST_TRACES_SELECT      # a view the role may read

    def test_the_list_query_still_orders_and_filters_as_before(self):
        conn, cur = _conn_with()
        list_traces(conn, has_error=True)
        page_sql = cur.execute.call_args_list[1][0][0]
        assert "WHERE has_error = %(has_error)s" in page_sql
        assert "ORDER BY trace_start_time DESC, trace_id ASC" in page_sql

    def test_a_row_without_the_flag_maps_to_false(self):
        row = {"span_id": "s", "parent_span_id": None, "span_name": "n", "start_time": _DT, "end_time": _DT,
               "duration_ms": 1.0, "status_code": "UNSET"}
        assert _row_to_span_record(row).is_demo_data is False
        assert _row_to_span_record({**row, "is_demo_data": True}).is_demo_data is True
        assert _row_to_span_record({**row, "is_demo_data": None}).is_demo_data is False

    def test_fetch_returns_the_flag_per_span(self):
        rows = [{"span_id": f"r{flag}", "parent_span_id": None, "span_name": "n", "start_time": _DT, "end_time": _DT,
                 "duration_ms": 1.0, "status_code": "UNSET", "is_demo_data": flag} for flag in (True, False)]
        conn, _ = _conn_with(rows)
        assert [s.is_demo_data for s in fetch_trace_spans(conn, _TRACE_ID)] == [True, False]


class TestDemoFlagApi:

    @staticmethod
    def _summary(**extra):
        base = dict(trace_id=_TRACE_ID, trace_start_time=_DT, trace_end_time=_DT, trace_duration_ms=1.0,
                    root_span_id="r", root_span_name="agentops.request", root_service_name="svc", request_id=None,
                    session_id=None, span_count=1, service_count=1, error_span_count=0, agent_span_count=0,
                    tool_span_count=0, retrieval_span_count=0, has_error=False)
        base.update(extra)
        return base

    def test_trace_summary_defaults_to_not_demo_and_accepts_the_flag(self):
        assert TraceSummary.model_validate(self._summary()).is_demo_data is False
        assert TraceSummary.model_validate(self._summary(is_demo_data=True)).is_demo_data is True

    def test_list_endpoint_exposes_the_flag_for_demo_and_real_traces(self):
        result = MagicMock(total=2, traces=[self._summary(is_demo_data=True), self._summary(trace_id="b" * 32)])
        with patch("app.connect", return_value=MagicMock()), patch("app.list_traces", return_value=result):
            body = client.get("/api/traces").json()
        assert [t["is_demo_data"] for t in body["traces"]] == [True, False]

    @pytest.mark.parametrize("flags,expected", [((True, True), True), ((False, False), False), ((False, True), True)])
    def test_detail_flag_is_true_when_any_span_is_demo_data(self, flags, expected):
        spans = [_span("root", demo=flags[0]), _span("child", parent="root", demo=flags[1])]
        response = TraceDetailResponse.from_reconstruction(_TRACE_ID, build_trace_tree(spans))
        assert response.is_demo_data is expected

    def test_detail_endpoint_exposes_the_flag_on_the_trace_and_the_spans(self):
        for demo, expected in ((True, True), (False, False)):
            result = build_trace_tree([_span("root", demo=demo)])
            with patch("app.connect", return_value=MagicMock()), patch("app.get_trace_reconstruction", return_value=result):
                body = client.get(f"/api/traces/{_TRACE_ID}").json()
            assert body["is_demo_data"] is expected and body["roots"][0]["span"]["is_demo_data"] is expected

    def test_an_empty_trace_is_not_demo_and_an_orphan_is_counted(self):
        empty = TraceReconstruction(roots=[], orphans=[], cycle_members=[], has_cycle=False, span_count=0)
        assert TraceDetailResponse.from_reconstruction(_TRACE_ID, empty).is_demo_data is False
        orphan = TraceReconstruction(roots=[], orphans=[TraceNode(span=_span("o", parent="gone", demo=True))],
                                     cycle_members=[], has_cycle=False, span_count=1)
        assert TraceDetailResponse.from_reconstruction(_TRACE_ID, orphan).is_demo_data is True

    def test_the_raw_attribute_bag_is_still_not_exposed(self):
        with patch("app.connect", return_value=MagicMock()), \
             patch("app.get_trace_reconstruction", return_value=build_trace_tree([_span("root", demo=True)])):
            text = client.get(f"/api/traces/{_TRACE_ID}").text
        assert "attributes" not in text and "demo_seed" not in text


class TestDemoBadgeInTheStaticFiles:

    def test_the_detail_badge_exists_hidden_by_default_and_is_styled(self):
        match = re.search(r'<span id="detail-demo-badge" class="demo-badge hidden">Synthetic Demo Data</span>', HTML)
        assert match
        assert ".demo-badge.hidden" in CSS and ".demo-badge {" in CSS

    def test_the_label_text_is_only_ever_written_as_text(self):
        assert "const DEMO_BADGE_TEXT = 'Synthetic Demo Data'" in JS
        assert "b.textContent = DEMO_BADGE_TEXT" in JS
        assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", JS_CODE)

    def test_the_badge_is_driven_only_by_the_api_flag(self):
        assert "if (t.is_demo_data === true) opTd.appendChild(makeDemoBadge())" in JS
        assert "detailDemoBadge.classList.toggle('hidden', data.is_demo_data !== true)" in JS
        assert "demo_seed" not in JS_CODE


# ---------------------------------------------------------------------------
# 2 and 3  Formatting functions, run under node
# ---------------------------------------------------------------------------

def _function_source(name: str) -> str:
    match = re.search(rf"^function {name}\(.*?^}}$", JS, re.S | re.M)
    assert match, name
    return match.group(0)


def _run(expression: str):
    """Evaluate a JS expression using the shipped formatting functions."""
    source = "\n".join(_function_source(n) for n in ("anomNumber", "formatObserved", "formatTimestampMs", "formatTimestamp"))
    script = source + f"\nprocess.stdout.write(JSON.stringify({expression}));"
    result = subprocess.run(["node", "-e", script], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout.decode("utf-8"))


needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@needs_node
class TestObservedValueUnits:

    def test_latency_is_shown_in_milliseconds(self):
        assert _run("formatObserved({anomaly_type:'latency',signal_name:'duration_ms',observed_value:2350})") == "2350 ms"
        assert _run("formatObserved({anomaly_type:'latency',signal_name:'duration_ms',observed_value:2350.4567})") == "2350.457 ms"

    def test_tool_failure_is_labelled_as_an_error_rate(self):
        assert _run("formatObserved({anomaly_type:'tool_failure',signal_name:'tool_error_rate',observed_value:1})") == "1 (error rate)"
        assert _run("formatObserved({anomaly_type:'error_rate',signal_name:'error_rate',observed_value:0.25})") == "0.25 (error rate)"

    def test_other_signals_and_missing_values_are_unchanged(self):
        assert _run("formatObserved({anomaly_type:'retrieval_quality',signal_name:'top_score',observed_value:0.5})") == "0.5"
        assert _run("formatObserved({anomaly_type:'latency',signal_name:'duration_ms',observed_value:null})") == "—"
        assert _run("formatObserved({anomaly_type:'x',signal_name:null,observed_value:3})") == "3"

    def test_raw_values_and_scores_are_not_modified(self):
        assert _run("(()=>{const a={anomaly_type:'latency',signal_name:'duration_ms',observed_value:2350};"
                    "formatObserved(a);return a.observed_value})()") == 2350
        assert "formatObserved(a)" in JS and "anomNumber(a.anomaly_score)" in JS      # the score keeps its plain format


@needs_node
class TestTimestampPrecision:

    def test_span_timestamps_show_milliseconds_in_utc(self):
        assert _run("formatTimestampMs('2026-10-15T09:00:00.123+00:00')") == "2026-10-15 09:00:00.123 UTC"
        assert _run("formatTimestampMs('2026-10-15T09:00:00+00:00')") == "2026-10-15 09:00:00.000 UTC"
        assert _run("formatTimestampMs('2026-10-15T09:00:00.007Z')") == "2026-10-15 09:00:00.007 UTC"

    def test_a_non_utc_offset_is_converted_to_utc(self):
        assert _run("formatTimestampMs('2026-10-15T11:00:00.250+02:00')") == "2026-10-15 09:00:00.250 UTC"

    def test_the_existing_second_precision_format_is_unchanged(self):
        assert _run("formatTimestamp('2026-10-15T09:00:00.999+00:00')") == "2026-10-15 09:00:00 UTC"

    def test_only_the_span_panel_uses_the_millisecond_format(self):
        assert "addField('Start',    formatTimestampMs(span.start_time))" in JS
        assert "addField('End',      formatTimestampMs(span.end_time))" in JS
        assert len(re.findall(r"formatTimestampMs\(", JS)) == 3         # definition + two uses
        assert "formatTimestamp(t.trace_start_time)" in JS and "return v ? formatTimestamp(v)" in JS

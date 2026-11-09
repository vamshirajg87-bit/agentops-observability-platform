"""
workload-generator/tests/unit/test_report.py

Unit tests for report.py.

Test inventory:
    WR01  Arithmetic of the plan report
    WR02  Determinism and the plan digest
    WR03  JSON output
    WR04  The report claims nothing that was not planned
    WR05  Text summary
    WR06  Writing the report file
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from workload_generator import __version__, report as report_module
from workload_generator.personas import Persona
from workload_generator.plan import Plan, PlanConfig, build_plan
from workload_generator.report import (
    OUTCOMES,
    RUN_STATUSES,
    SAMPLE_SIZE,
    ExecutionReport,
    build_report,
    combined_dict,
    format_execution,
    format_summary,
    plan_digest,
    request_row,
    write_report,
)
from workload_generator.scenarios import Scenario


def _plan(**overrides) -> Plan:
    values = dict(
        seed=42, run_id="unit-test-run", scenario=Scenario.MIXED_PRODUCTION, traces=600,
        rate=5.0,
    )
    values.update(overrides)
    return build_plan(PlanConfig(**values))


def _report(plan: Plan, concurrency: int = 4, max_duration_seconds: float = 900.0):
    return build_report(
        plan, concurrency=concurrency, max_duration_seconds=max_duration_seconds,
    )


# ---------------------------------------------------------------------------
# WR01  Arithmetic
# ---------------------------------------------------------------------------

class TestArithmetic:

    @pytest.mark.parametrize("scenario", list(Scenario))
    def test_counts_add_up(self, scenario):
        plan = _plan(scenario=scenario)
        report = _report(plan)
        assert report.requested_traces == report.planned_requests == 600
        assert sum(report.scenario_distribution.values()) == 600
        assert sum(report.persona_distribution.values()) == 600
        assert report.planned_retries == sum(len(r.retries) for r in plan.requests)
        assert report.planned_submissions == 600 + report.planned_retries

    def test_scenario_distribution_matches_the_plan(self):
        plan = _plan()
        report = _report(plan)
        for name, count in report.scenario_distribution.items():
            assert count == sum(r.scenario.value == name for r in plan.requests)
        assert "mixed-production" not in report.scenario_distribution

    def test_persona_distribution_matches_the_plan(self):
        plan = _plan()
        report = _report(plan)
        for name, count in report.persona_distribution.items():
            assert count == sum(r.persona.value == name for r in plan.requests)

    def test_distributions_are_in_vocabulary_order_without_zeros(self):
        report = _report(_plan(scenario=Scenario.API_500, persona=Persona.OFF_TOPIC_USER))
        assert list(report.scenario_distribution) == ["normal", "api-500"]
        assert list(report.persona_distribution) == ["off-topic-user"]
        assert all(report.scenario_distribution.values())

    def test_fault_distribution_counts_first_submissions_and_retries(self):
        plan = _plan(scenario=Scenario.RETRY_STORM)
        report = _report(plan)
        first = sum(r.fault is not None for r in plan.requests)
        retried = sum(x.fault is not None for r in plan.requests for x in r.retries)
        assert report.planned_fault_distribution == {"UpstreamServerError": first + retried}
        assert retried > 0

    def test_no_fault_no_fault_distribution(self):
        assert _report(_plan(scenario=Scenario.NORMAL)).planned_fault_distribution == {}
        assert _report(_plan(scenario=Scenario.SLOW_TOOL)).planned_fault_distribution == {}

    def test_duration_is_the_last_arrival(self):
        plan = _plan()
        report = _report(plan)
        assert report.planned_duration_seconds == plan.requests[-1].arrival_offset_seconds
        assert report.planned_duration_seconds == pytest.approx(599 / 5.0, rel=1e-6)

    def test_sessions_and_settings_are_carried_over(self):
        plan = _plan(rate=7)
        report = _report(plan, concurrency=9, max_duration_seconds=120.0)
        assert report.sessions == plan.session_count
        assert (report.requested_rate, report.concurrency) == (7.0, 9)
        assert report.max_duration_seconds == 120.0
        assert (report.run_id, report.seed, report.mode) == ("unit-test-run", 42, "real")
        assert (report.scenario, report.persona) == ("mixed-production", "mix")

    def test_persona_selection_is_named(self):
        report = _report(_plan(persona=Persona.RESEARCH_SESSION))
        assert report.persona == "research-session"

    def test_episode_rows(self):
        plan = _plan(scenario=Scenario.API_500, traces=1000)
        (row,) = _report(plan).episodes
        assert row["episode_id"] == "ep01-api-500" and row["scenario"] == "api-500"
        assert (row["start_index"], row["end_index"], row["requests"]) == (500, 800, 300)
        assert row["affected_requests"] == sum(
            r.scenario is Scenario.API_500 for r in plan.requests
        )
        assert 200 < row["affected_requests"] < 300

    def test_mixed_episode_rows_cover_every_abnormal_request(self):
        plan = _plan(traces=5000, rate=50.0)
        report = _report(plan)
        assert sum(row["affected_requests"] for row in report.episodes) == 250
        assert report.scenario_distribution["normal"] == 4750


# ---------------------------------------------------------------------------
# WR02  Determinism and digest
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_same_plan_same_report(self):
        assert _report(_plan()) == _report(_plan())
        assert _report(_plan()).to_json() == _report(_plan()).to_json()

    def test_digest_is_sha256_hex(self):
        digest = plan_digest(_plan())
        assert len(digest) == 64 and int(digest, 16) >= 0

    def test_digest_is_the_same_for_the_same_plan(self):
        assert plan_digest(_plan()) == plan_digest(_plan())

    @pytest.mark.parametrize("overrides", [
        {"seed": 43}, {"run_id": "another-run"}, {"scenario": Scenario.NORMAL},
        {"traces": 601}, {"rate": 6.0}, {"persona": Persona.AUTOMATION_CLIENT},
    ])
    def test_digest_changes_with_anything_that_changes_the_plan(self, overrides):
        assert plan_digest(_plan(**overrides)) != plan_digest(_plan())

    def test_digest_does_not_change_with_what_does_not_change_the_plan(self):
        plan = _plan()
        assert plan_digest(_plan(mode="synthetic")) == plan_digest(plan)
        assert _report(plan, concurrency=1).plan_digest == _report(plan, 64).plan_digest

    def test_digest_covers_every_field_of_a_request(self):
        import dataclasses
        plan = _plan(traces=3)
        base = plan_digest(plan)
        first = plan.requests[0]
        for change in (
            {"query": first.query + "?"},
            {"arrival_offset_seconds": first.arrival_offset_seconds + 0.001},
            {"session_id": "sess_" + "0" * 32},
            {"episode_id": "ep99-x"},
            {"latency": dataclasses.replace(first.latency, tool_ms=1.0)},
        ):
            changed = dataclasses.replace(
                plan, requests=(dataclasses.replace(first, **change), *plan.requests[1:]),
            )
            assert plan_digest(changed) != base

    def test_request_row_keys_are_fixed(self):
        for request in _plan(scenario=Scenario.RETRY_STORM).requests:
            row = request_row(request)
            assert list(row) == [
                "request_index", "request_id", "session_id", "persona", "scenario",
                "query", "arrival_offset_seconds", "latency_ms", "fault", "retries",
                "episode_id", "retrieval_effect",
            ]
            assert list(row["latency_ms"]) == ["tool", "retrieval", "synthesis"]
            assert row["retrieval_effect"] is None
            json.dumps(row)                              # plain data only

    def test_request_row_names_the_retrieval_effect(self):
        plan = _plan(scenario=Scenario.RETRIEVAL_QUALITY)
        rows = [request_row(request) for request in plan.requests]
        values = {row["retrieval_effect"] for row in rows}
        assert values == {None, "drop-best-match"}
        for row, request in zip(rows, plan.requests):
            assert (row["retrieval_effect"] is not None) == (
                request.scenario is Scenario.RETRIEVAL_QUALITY
            )

    def test_digest_covers_the_retrieval_effect(self):
        import dataclasses
        from workload_generator.scenarios import RetrievalEffect
        plan = _plan(traces=3, scenario=Scenario.NORMAL)
        changed = dataclasses.replace(plan, requests=(
            dataclasses.replace(
                plan.requests[0], retrieval_effect=RetrievalEffect.DROP_BEST_MATCH,
            ),
            *plan.requests[1:],
        ))
        assert plan_digest(changed) != plan_digest(plan)

    def test_sample_line_shows_the_retrieval_effect(self):
        plan = _plan(scenario=Scenario.RETRIEVAL_QUALITY)
        degraded = next(r for r in plan.requests if r.retrieval_effect is not None)
        healthy = next(r for r in plan.requests if r.retrieval_effect is None)
        text = format_summary(_report(plan), [degraded, healthy])
        first, second = [l for l in text.splitlines() if l.startswith("  #")]
        assert first.endswith("retrieval=drop-best-match")
        assert "retrieval=" not in second
        # The question shown is the user's own.
        assert degraded.query[:40] in first


# ---------------------------------------------------------------------------
# WR03  JSON
# ---------------------------------------------------------------------------

class TestJson:

    def test_json_is_valid_and_round_trips(self):
        report = _report(_plan(scenario=Scenario.RETRY_STORM))
        loaded = json.loads(report.to_json())
        assert loaded == report.to_dict()
        assert report.to_json().endswith("}\n")

    def test_keys_of_the_report(self):
        assert list(_report(_plan()).to_dict()) == [
            "report", "report_version", "generator_version", "executed",
            "run_id", "seed", "mode", "scenario", "persona",
            "requested_traces", "planned_requests", "planned_retries",
            "planned_submissions", "planned_duration_seconds", "requested_rate",
            "concurrency", "max_duration_seconds", "sessions",
            "scenario_distribution", "persona_distribution",
            "planned_fault_distribution", "episodes", "plan_digest",
        ]

    def test_header_values(self):
        data = _report(_plan()).to_dict()
        assert data["report"] == "workload-plan"
        assert data["report_version"] == 1
        assert data["generator_version"] == __version__
        assert data["executed"] is False

    def test_required_plan_metrics_are_present(self):
        data = _report(_plan()).to_dict()
        for key in (
            "run_id", "seed", "mode", "requested_traces", "planned_requests",
            "scenario_distribution", "persona_distribution", "planned_retries",
            "planned_duration_seconds", "requested_rate", "concurrency",
        ):
            assert key in data

    def test_json_holds_no_planned_request(self):
        # A report is a summary: its size does not grow with the plan.
        small = len(_report(_plan(traces=100, scenario=Scenario.NORMAL)).to_json())
        large = len(_report(_plan(traces=5000, rate=50.0, scenario=Scenario.NORMAL)).to_json())
        assert large < small + 200


# ---------------------------------------------------------------------------
# WR04  Nothing is claimed that was not planned
# ---------------------------------------------------------------------------

_EXECUTION_WORDS = (
    "completed", "succeeded", "failed_traces", "spans", "span_count", "exported",
    "export", "throughput", "actual", "achieved", "elapsed", "measured", "p50", "p95",
    "p99", "percentile", "latency",
)


class TestNoExecutionClaims:

    @pytest.mark.parametrize("scenario", list(Scenario))
    def test_no_key_of_the_report_is_an_execution_metric(self, scenario):
        # The report's own field names; the keys inside a distribution are
        # scenario, persona and error-type names and are not checked here.
        data = _report(_plan(scenario=scenario)).to_dict()
        names = list(data) + [key for row in data["episodes"] for key in row]
        for key in names:
            for word in _EXECUTION_WORDS:
                assert word not in key.lower(), key

    def test_report_says_it_was_not_executed(self):
        assert _report(_plan()).to_dict()["executed"] is False
        assert "executed" not in [
            name for name in report_module.PlanReport.__dataclass_fields__
        ]

    def test_counted_values_are_named_planned_or_requested(self):
        data = _report(_plan()).to_dict()
        for key, value in data.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                assert key.startswith(("planned_", "requested_")) or key in (
                    "report_version", "seed", "concurrency", "max_duration_seconds",
                    "sessions",
                ), key

    def test_summary_opens_by_saying_nothing_was_sent(self):
        text = format_summary(_report(_plan()))
        assert text.splitlines()[0] == (
            "PLAN ONLY - nothing was executed and nothing was sent."
        )

    def test_summary_claims_no_result(self):
        text = format_summary(_report(_plan(scenario=Scenario.RETRY_STORM))).lower()
        for word in ("completed", "succeeded", "exported", "throughput", "spans"):
            assert word not in text


# ---------------------------------------------------------------------------
# WR05  Text summary
# ---------------------------------------------------------------------------

class TestSummary:

    def test_summary_shows_every_required_item(self):
        plan = _plan(scenario=Scenario.RETRY_STORM)
        report = _report(plan)
        text = format_summary(report, plan.requests[:SAMPLE_SIZE])
        for label, value in (
            ("run id", "unit-test-run"),
            ("seed", "42"),
            ("mode", "real"),
            ("scenario", "retry-storm"),
            ("persona", "mix"),
            ("requested traces", "600"),
            ("rate", "5 requests/second"),
            ("concurrency", "4"),
            ("planned duration", f"{report.planned_duration_seconds:.3f} seconds"),
            ("planned retries", str(report.planned_retries)),
        ):
            (line,) = [
                l for l in text.splitlines()
                if l.startswith(label + " ") and not l.endswith(":")
            ]
            assert value in line, label
        assert "scenario distribution:" in text and "persona distribution:" in text
        assert report.plan_digest in text

    def test_summary_length_does_not_grow_with_the_plan(self):
        small = _plan(traces=100, scenario=Scenario.API_500)
        large = _plan(traces=5000, rate=50.0, scenario=Scenario.API_500)
        lines = lambda plan: len(format_summary(
            _report(plan), plan.requests[:SAMPLE_SIZE],
        ).splitlines())
        # At most a persona or an error type more; never a line per request.
        assert lines(small) < 45 and lines(large) < 45
        assert abs(lines(large) - lines(small)) <= 4

    def test_sample_is_small_and_optional(self):
        plan = _plan()
        assert SAMPLE_SIZE == 5
        without = format_summary(_report(plan))
        assert "planned requests:" not in without.split("episodes:")[1]
        with_sample = format_summary(_report(plan), plan.requests[:SAMPLE_SIZE])
        assert "first 5 planned requests:" in with_sample
        assert len([l for l in with_sample.splitlines() if l.startswith("  #")]) == 5

    def test_sample_line_shows_fault_and_retries(self):
        plan = _plan(scenario=Scenario.RETRY_STORM)
        failing = next(r for r in plan.requests if r.retries)
        (line,) = [
            l for l in format_summary(_report(plan), [failing]).splitlines()
            if l.startswith("  #")
        ]
        assert "fault=UpstreamServerError" in line
        assert f"retries={len(failing.retries)}" in line

    def test_empty_request_is_shown_as_such(self):
        plan = _plan(persona=Persona.AUTOMATION_CLIENT, traces=2000, rate=50.0)
        empty = next(r for r in plan.requests if r.query == "")
        assert "(empty request)" in format_summary(_report(plan), [empty])

    def test_long_queries_are_cut(self):
        import dataclasses
        plan = _plan(traces=3)
        long = dataclasses.replace(plan.requests[0], query="word " * 40)
        (line,) = [
            l for l in format_summary(_report(plan), [long]).splitlines()
            if l.startswith("  #")
        ]
        assert line.rstrip().endswith("...") and len(line) < 140

    def test_shares_are_percentages_of_planned_requests(self):
        text = format_summary(_report(_plan(traces=5000, rate=50.0)))
        (normal,) = [l for l in text.splitlines() if l.startswith("  normal ")]
        assert normal.split() == ["normal", "4750", "95.0%"]

    def test_summary_is_ascii(self):
        plan = _plan()
        assert format_summary(_report(plan), plan.requests[:5]).isascii()


# ---------------------------------------------------------------------------
# WR06  Writing the file
# ---------------------------------------------------------------------------

class TestWriteReport:

    def test_writes_valid_json_to_a_new_file(self, tmp_path):
        report = _report(_plan())
        path = write_report(report, tmp_path / "plan.json")
        assert path == tmp_path / "plan.json"
        assert json.loads(path.read_text(encoding="utf-8")) == report.to_dict()
        assert b"\r" not in path.read_bytes()

    def test_refuses_to_overwrite(self, tmp_path):
        target = tmp_path / "plan.json"
        target.write_text("keep me", encoding="utf-8")
        with pytest.raises(FileExistsError):
            write_report(_report(_plan()), target)
        assert target.read_text(encoding="utf-8") == "keep me"

    def test_does_not_create_directories(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            write_report(_report(_plan()), tmp_path / "missing" / "plan.json")
        assert not (tmp_path / "missing").exists()

    def test_accepts_a_string_path(self, tmp_path):
        path = write_report(_report(_plan()), str(tmp_path / "plan.json"))
        assert isinstance(path, Path) and path.is_file()

    def test_only_the_named_file_is_created(self, tmp_path):
        write_report(_report(_plan()), tmp_path / "plan.json")
        assert [p.name for p in tmp_path.iterdir()] == ["plan.json"]


# ---------------------------------------------------------------------------
# WR07  Execution report
# ---------------------------------------------------------------------------

def _execution(**overrides) -> ExecutionReport:
    values = dict(
        endpoint="http://localhost:14317", started="2026-10-06T12:00:00+00:00",
        finished="2026-10-06T12:02:00+00:00", elapsed_seconds=119.8,
        planned_requests=600, planned_retries=40, planned_submissions=640,
        started_requests=600, not_started_requests=0,
        attempts={**{name: 0 for name in OUTCOMES}, "expected_success": 520,
                  "expected_failure": 120},
        executed_attempts=640, executed_retries=40, late_starts=3,
        max_start_lag_seconds=0.412, mean_start_lag_seconds=0.021,
        achieved_submission_rate=5.342, spans_ended=4240,
        spans_exported_successfully=4240, export_failures=0, flush_ok=True,
        run_status="completed",
    )
    values.update(overrides)
    return ExecutionReport(**values)


class TestExecutionReport:

    def test_outcome_and_status_vocabularies(self):
        assert OUTCOMES == (
            "expected_success", "expected_failure", "unexpected_failure",
            "missing_failure", "reach_failure", "not_started",
        )
        assert RUN_STATUSES == (
            "completed", "stopped_integrity", "deadline_reached", "export_failed",
        )

    def test_keys_of_the_execution_report(self):
        assert list(_execution().to_dict()) == [
            "executed", "endpoint", "started", "finished", "elapsed_seconds",
            "planned_requests", "planned_retries", "planned_submissions",
            "started_requests", "not_started_requests", "attempts", "executed_attempts",
            "executed_retries", "late_starts", "max_start_lag_seconds",
            "mean_start_lag_seconds", "achieved_submission_rate", "spans_ended",
            "spans_exported_successfully", "export_failures", "flush_ok", "run_status",
            "problems", "start_lags",
        ]

    def test_values_round_trip_through_json(self):
        execution = _execution(problems=("request 3 attempt 0 (req_x): reach_failure: y",))
        data = json.loads(json.dumps(execution.to_dict()))
        assert data["executed"] is True
        assert data["attempts"] == dict(execution.attempts)
        assert list(data["attempts"]) == list(OUTCOMES)
        assert data["problems"] == list(execution.problems)
        assert data["flush_ok"] is True and data["run_status"] == "completed"

    def test_start_lags_default_to_none(self):
        assert _execution().start_lags is None
        assert _execution().to_dict()["start_lags"] is None

    def test_start_lags_serialize_and_round_trip(self):
        lags = {"limit": 10000, "expected": 2, "recorded": 2, "complete": True,
                "truncated_reason": None,
                "entries": [(0, 0.0, 0.001234), (1, 0.25, 0.150001)]}
        data = json.loads(json.dumps(_execution(start_lags=lags).to_dict()))
        assert data["start_lags"] == {**lags, "entries": [[0, 0.0, 0.001234],
                                                          [1, 0.25, 0.150001]]}

    def test_start_lags_do_not_change_the_other_fields(self):
        lags = {"limit": 10000, "expected": 0, "recorded": 0, "complete": True,
                "truncated_reason": None, "entries": []}
        with_lags = _execution(start_lags=lags).to_dict()
        without = _execution().to_dict()
        assert {k: v for k, v in with_lags.items() if k != "start_lags"} == {
            k: v for k, v in without.items() if k != "start_lags"}

    @pytest.mark.parametrize("status", ["finished", "ok", "", "COMPLETED"])
    def test_an_unknown_run_status_is_rejected(self, status):
        with pytest.raises(ValueError):
            _execution(run_status=status)

    @pytest.mark.parametrize("attempts", [
        {}, {"expected_success": 1},
        {name: 0 for name in reversed(OUTCOMES)},
        {**{name: 0 for name in OUTCOMES}, "persisted": 1},
    ])
    def test_attempts_must_hold_exactly_the_known_outcomes(self, attempts):
        with pytest.raises(ValueError):
            _execution(attempts=attempts)

    @pytest.mark.parametrize("word", [
        "collector", "accepted", "received", "delivered", "persisted", "stored", "kafka",
        "rows", "ingested", "detected", "anomal",
    ])
    def test_no_field_claims_anything_downstream_of_the_exporter(self, word):
        for key in _execution().to_dict():
            assert word not in key.lower(), key

    def test_export_fields_use_the_precise_names(self):
        keys = set(_execution().to_dict())
        assert {"spans_ended", "spans_exported_successfully", "export_failures",
                "flush_ok"} <= keys
        assert not {"spans_sent", "spans_delivered", "spans_accepted"} & keys

    def test_summary_text_states_its_own_limits(self):
        text = format_execution(_execution())
        lines = text.splitlines()
        assert lines[0].startswith("EXECUTION - what this driver did.")
        assert "Nothing here says what a collector" in lines[0]
        assert "did with the telemetry afterwards." in lines[1]
        (exported,) = [l for l in lines if l.startswith("spans exported")]
        assert exported.split()[2] == "4240"
        assert "(local exporter reported success)" in exported
        for phrase in ("collector accepted", "delivered", "persisted", "stored"):
            assert phrase not in text.lower()

    def test_summary_text_shows_every_reported_value(self):
        text = format_execution(_execution())
        value = lambda label: next(
            l[len(label):].strip() for l in text.splitlines() if l.startswith(label + " ")
        )
        assert value("run status") == "completed"
        assert value("endpoint") == "http://localhost:14317"
        assert value("elapsed") == "119.800 seconds"
        assert value("planned submissions") == "640 (600 requests + 40 retries)"
        assert value("started requests") == "600"
        assert value("not started") == "0 requests"
        assert value("executed attempts") == "640 (of which client retries: 40)"
        assert value("late starts") == "3 (max lag 0.412 s, mean lag 0.021 s)"
        assert value("achieved rate") == "5.342 attempts/second"
        assert value("spans ended") == "4240"
        assert value("export failures") == "0"
        assert value("flush ok") == "yes"
        for name in OUTCOMES:
            (line,) = [l for l in text.splitlines() if l.startswith(f"  {name} ")]
            assert int(line.split()[1]) == _execution().attempts[name]

    def test_a_failed_flush_is_conspicuous(self):
        text = format_execution(_execution(flush_ok=False, run_status="export_failed"))
        assert "flush ok            NO" in text
        assert "run status          export_failed" in text

    def test_integrity_problems_are_listed_only_when_there_are_some(self):
        assert "integrity problems" not in format_execution(_execution())
        text = format_execution(_execution(
            run_status="stopped_integrity",
            problems=("request 7 attempt 0 (req_a): missing_failure: planned X",),
        ))
        assert text.splitlines()[-2] == "integrity problems (first ones):"
        assert text.splitlines()[-1] == (
            "  request 7 attempt 0 (req_a): missing_failure: planned X"
        )

    def test_summary_is_ascii_and_bounded(self):
        text = format_execution(_execution(problems=tuple(f"p{i}" for i in range(10))))
        assert text.isascii() and len(text.splitlines()) < 45

    def test_combined_report_keeps_the_plan_and_adds_the_execution(self):
        plan = _plan()
        report = _report(plan)
        combined = combined_dict(report, _execution())
        assert list(combined)[:-1] == list(report.to_dict())
        assert list(combined)[-1] == "execution"
        assert combined["executed"] is True
        assert combined["execution"] == _execution().to_dict()
        for key, value in report.to_dict().items():
            if key != "executed":
                assert combined[key] == value
        # The plan report on its own is unchanged and still says "not executed".
        assert report.to_dict()["executed"] is False

    def test_report_file_with_execution(self, tmp_path):
        report = _report(_plan())
        path = write_report(report, tmp_path / "run.json", _execution())
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == combined_dict(report, _execution())
        assert b"\r" not in path.read_bytes()

    def test_report_file_with_execution_never_overwrites(self, tmp_path):
        target = tmp_path / "run.json"
        target.write_text("keep me", encoding="utf-8")
        with pytest.raises(FileExistsError):
            write_report(_report(_plan()), target, _execution())
        assert target.read_text(encoding="utf-8") == "keep me"

    def test_the_report_module_does_not_know_the_driver(self):
        source = Path(report_module.__file__).read_text(encoding="utf-8")
        assert "real_driver" not in source and "opentelemetry" not in source

    def test_plan_summary_heading_depends_on_what_follows(self):
        plan = _plan()
        report = _report(plan)
        assert format_summary(report).splitlines()[0] == (
            "PLAN ONLY - nothing was executed and nothing was sent."
        )
        executing = format_summary(report, plan_only=False)
        assert executing.splitlines()[0] == (
            "PLAN - about to be executed; the execution report follows."
        )
        assert "PLAN ONLY" not in executing
        # Apart from the heading and the mode note the two are the same.
        strip = lambda text: [
            l for l in text.splitlines()[1:] if not l.startswith("mode ")
        ]
        assert strip(executing) == strip(format_summary(report))

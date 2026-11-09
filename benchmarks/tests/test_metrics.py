"""
benchmarks/tests/test_metrics.py

Offline tests of the benchmark arithmetic, rules, result schema and the
orchestrator's offline paths.  Nothing here starts a process, opens a
socket, touches Docker or a database, or sends telemetry; several tests
prove that.
"""

from __future__ import annotations

import copy
import importlib.abc
import importlib.util
import io
import json
import math
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1]
_REPO = _BENCH.parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import metrics as M  # noqa: E402
import run_benchmark as RB  # noqa: E402

LADDER = json.loads((_BENCH / "ladder.json").read_text(encoding="utf-8"))
STOPS = LADDER["stop_limits"]


# ---------------------------------------------------------------------------
# Fail-closed isolation: whatever LIVE_ENABLED says, no test can reach the
# real harness, a process, a socket or Docker.
# ---------------------------------------------------------------------------

_HARNESS_MODULES = ("run_smoke", "run_e2e")
#: The real cell body, for tests that drive it with an injected fake harness.
REAL_EXECUTE_CELL = RB.execute_cell


class _BlockHarness(importlib.abc.MetaPathFinder):
    """Refuses to import the D3/E2E harness modules during the tests."""

    def find_spec(self, name, path=None, target=None):
        if name in _HARNESS_MODULES:
            raise ImportError(f"{name} is blocked in the benchmark tests")
        return None


class LiveAccessAttempt(AssertionError):
    """A test reached something live."""


@pytest.fixture(autouse=True)
def fail_closed(monkeypatch):
    def refuse(what):
        def call(*args, **kwargs):
            raise LiveAccessAttempt(f"{what} attempted: {args[:1]}")
        return call

    for name in _HARNESS_MODULES:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(sys, "meta_path", [_BlockHarness(), *sys.meta_path])
    monkeypatch.setattr(RB, "execute_cell", refuse("the real execute_cell"))
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    monkeypatch.setattr(os, "system", refuse("os.system"))
    monkeypatch.setattr(socket, "create_connection", refuse("a network connection"))
    monkeypatch.setattr(socket.socket, "connect", refuse("a socket connection"))


def _metric(**overrides):
    base = {"value": 1.0, "unit": "ms", "kind": "MEASURED", "source": "s", "method": "m",
            "window": None, "n": 1, "reason": None}
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Percentiles
# ---------------------------------------------------------------------------

class TestPercentile:
    def test_empty_sample_has_no_percentile(self):
        with pytest.raises(M.MetricError, match="empty"):
            M.percentile([], 50)
        with pytest.raises(M.MetricError):
            M.percentiles([])

    @pytest.mark.parametrize("q", [0, 50, 95, 99, 100])
    def test_single_value_is_every_percentile(self, q):
        assert M.percentile([7.5], q) == 7.5

    def test_linear_interpolation(self):
        values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        assert M.percentile(values, 50) == pytest.approx(5.5)
        assert M.percentile(values, 95) == pytest.approx(9.55)
        assert M.percentile(values, 99) == pytest.approx(9.91)
        assert M.percentile(values, 0) == 1 and M.percentile(values, 100) == 10

    def test_order_does_not_matter(self):
        assert M.percentiles([5, 1, 4, 2, 3]) == M.percentiles([1, 2, 3, 4, 5])

    def test_two_values(self):
        assert M.percentile([10, 20], 50) == 15

    def test_matches_known_nearest_rank_boundaries(self):
        values = list(range(101))
        assert M.percentiles(values) == {"p50": 50.0, "p95": 95.0, "p99": 99.0}

    @pytest.mark.parametrize("q", [-0.1, 100.1, float("nan"), float("inf")])
    def test_q_out_of_range(self, q):
        with pytest.raises(M.MetricError):
            M.percentile([1, 2], q)

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), "3", None, True])
    def test_non_finite_or_non_numeric_values_rejected(self, bad):
        with pytest.raises(M.MetricError):
            M.percentile([1.0, bad], 50)


# ---------------------------------------------------------------------------
# Rates
# ---------------------------------------------------------------------------

class TestRate:
    def test_basic(self):
        assert M.rate(700, 10.0) == 70.0
        assert M.rate(0, 5) == 0.0

    @pytest.mark.parametrize("seconds", [0, 0.0, -1, float("nan"), float("inf")])
    def test_zero_or_bad_duration_rejected(self, seconds):
        with pytest.raises(M.MetricError):
            M.rate(10, seconds)

    @pytest.mark.parametrize("count", [-1, 1.5, True, None])
    def test_bad_count_rejected(self, count):
        with pytest.raises(M.MetricError):
            M.rate(count, 1.0)


# ---------------------------------------------------------------------------
# Metrics and NOT_MEASURED
# ---------------------------------------------------------------------------

class TestMetric:
    def test_kinds_are_exactly_four(self):
        assert M.KINDS == ("MEASURED", "DERIVED", "OBSERVATION", "NOT_MEASURED")

    def test_not_measured_has_reason_and_no_value(self):
        metric = M.not_measured("ms", "src", "because").to_dict()
        assert metric["value"] is None and metric["n"] is None and metric["reason"] == "because"
        M.check_metric(metric, "x")

    def test_not_measured_never_zero(self):
        with pytest.raises(M.MetricError, match="no value"):
            M.check_metric(_metric(kind="NOT_MEASURED", value=0, n=None, reason="r"), "x")

    def test_not_measured_needs_reason(self):
        with pytest.raises(M.MetricError, match="reason"):
            M.check_metric(_metric(kind="NOT_MEASURED", value=None, n=None, reason=" "), "x")

    def test_measured_needs_value(self):
        with pytest.raises(M.MetricError, match="NOT_MEASURED instead"):
            M.check_metric(_metric(value=None), "x")

    def test_measured_value_zero_is_allowed(self):
        M.check_metric(_metric(value=0, n=5), "x")

    def test_only_not_measured_has_reason(self):
        with pytest.raises(M.MetricError, match="reason"):
            M.check_metric(_metric(reason="why"), "x")

    @pytest.mark.parametrize("kind", ["measured", "ESTIMATED", "", None])
    def test_unsupported_kind_rejected(self, kind):
        with pytest.raises(M.MetricError, match="kind"):
            M.check_metric(_metric(kind=kind), "x")

    def test_missing_or_extra_keys_rejected(self):
        bad = _metric()
        del bad["n"]
        with pytest.raises(M.MetricError, match="keys"):
            M.check_metric(bad, "x")
        with pytest.raises(M.MetricError, match="keys"):
            M.check_metric({**_metric(), "extra": 1}, "x")

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), "1", [], [1, "x"]])
    def test_bad_values_rejected(self, value):
        with pytest.raises(M.MetricError):
            M.check_metric(_metric(value=value), "x")

    def test_bad_window_rejected(self):
        with pytest.raises(M.MetricError, match="window"):
            M.check_metric(_metric(window={"start": "a"}), "x")
        M.check_metric(_metric(window={"start": "a", "end": "b", "clock": "database"}), "x")

    def test_negative_n_rejected(self):
        with pytest.raises(M.MetricError):
            M.check_metric(_metric(n=-1), "x")

    def test_latency_metrics_empty_is_not_measured(self):
        found = M.latency_metrics([], unit="ms", kind="MEASURED", source="s", method="m",
                                  window=None, reason_if_empty="nothing")
        assert sorted(found) == ["p50", "p95", "p99"]
        assert all(m.kind == "NOT_MEASURED" and m.value is None for m in found.values())

    def test_latency_metrics_values(self):
        found = M.latency_metrics([1, 2, 3], unit="ms", kind="MEASURED", source="s",
                                  method="m", window=None, reason_if_empty="x")
        assert found["p50"].value == 2 and found["p50"].n == 3


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

def _rec(**overrides):
    values = dict(planned_spans=700, spans_ended=700, spans_exported=700,
                  canonical_records=700, rows_stored=700, distinct_span_keys=700, dlq_records=0)
    values.update(overrides)
    return M.reconcile(**values)


class TestReconcile:
    def test_success(self):
        result = _rec()
        assert result.ok and result.missing == 0 and result.duplicates == 0
        assert all(check[3] for check in result.checks)

    def test_missing_spans(self):
        result = _rec(canonical_records=690, rows_stored=690, distinct_span_keys=690)
        assert not result.ok and result.missing == 10 and result.duplicates == 0

    def test_duplicate_canonical_records(self):
        result = _rec(canonical_records=705)
        assert not result.ok and result.duplicates == 5

    def test_duplicate_rows(self):
        result = _rec(canonical_records=702, rows_stored=702, distinct_span_keys=700)
        assert not result.ok and result.duplicates == 4

    def test_export_shortfall(self):
        assert not _rec(spans_exported=699).ok

    def test_dlq_fails(self):
        result = _rec(dlq_records=1)
        assert not result.ok
        assert ("DLQ records", 1, 0, False) in result.checks

    def test_fewer_ended_than_planned(self):
        assert not _rec(spans_ended=693).ok

    @pytest.mark.parametrize("name", ["rows_stored", "dlq_records"])
    def test_bad_inputs(self, name):
        with pytest.raises(M.MetricError):
            _rec(**{name: -1})

    def test_serializable(self):
        json.dumps(_rec(dlq_records=2).to_dict())


# ---------------------------------------------------------------------------
# Clock skew
# ---------------------------------------------------------------------------

def _sample(skew_ms, half_width_ms, at=1000.0):
    half = half_width_ms / 1000.0
    return M.ClockSample(at - half, at + skew_ms / 1000.0, at + half)


class TestClock:
    def test_skew_and_uncertainty(self):
        sample = _sample(3.0, 2.0)
        assert sample.skew_ms == pytest.approx(3.0)
        assert sample.uncertainty_ms == pytest.approx(2.0)

    def test_valid(self):
        check = M.clock_check([_sample(3, 1)], [_sample(5, 2)])
        assert check.valid and check.drift_ms == pytest.approx(2.0)
        assert check.skew_ms == pytest.approx(4.0)

    def test_uncertainty_at_limit_is_valid(self):
        assert M.clock_check([_sample(0, 10)], [_sample(0, 10)]).valid

    def test_uncertainty_over_limit_is_invalid(self):
        check = M.clock_check([_sample(0, 10.5)], [_sample(0, 1)])
        assert not check.valid and "uncertainty" in check.reasons[0]

    def test_drift_at_limit_is_valid(self):
        assert M.clock_check([_sample(0, 1)], [_sample(5, 1)]).valid

    def test_drift_over_limit_is_invalid(self):
        check = M.clock_check([_sample(0, 1)], [_sample(5.5, 1)])
        assert not check.valid and "drift" in check.reasons[0]

    def test_best_sample_is_narrowest(self):
        best = M.best_sample([_sample(9, 8), _sample(1, 0.5), _sample(4, 3)])
        assert best.skew_ms == pytest.approx(1.0)

    def test_no_samples(self):
        with pytest.raises(M.MetricError):
            M.clock_check([], [_sample(0, 1)])

    def test_reversed_bracket_rejected(self):
        with pytest.raises(M.MetricError):
            M.ClockSample(10.0, 10.0, 9.0)


# ---------------------------------------------------------------------------
# Generator-bound
# ---------------------------------------------------------------------------

class TestGeneratorBound:
    """O1: only the scheduler's own evidence makes a run GENERATOR_BOUND."""

    def test_on_time_scheduler_is_not_bound(self):
        assert M.generator_bound(late_starts=5, started_requests=100) == (False, ())

    def test_late_starts_exactly_5_percent_is_not_bound(self):
        assert not M.generator_bound(late_starts=5, started_requests=100)[0]

    def test_late_starts_over_5_percent_is_bound(self):
        bound, reasons = M.generator_bound(late_starts=6, started_requests=100)
        assert bound and "late" in reasons[0]

    def test_growing_start_lag_is_bound(self):
        bound, reasons = M.generator_bound(
            late_starts=0, started_requests=100,
            start_lag_series=[0.01, 0.02, 0.05, 0.09, 0.2, 0.4])
        assert bound and "start lag grew" in reasons[0]

    def test_start_lag_that_does_not_keep_growing_is_not_bound(self):
        assert not M.generator_bound(
            late_starts=0, started_requests=100,
            start_lag_series=[0.01, 0.02, 0.05, 0.09, 0.2, 0.1, 0.3])[0]
        assert not M.generator_bound(late_starts=0, started_requests=100,
                                     start_lag_series=[0.01, 0.02, 0.05, 0.09, 0.2])[0]

    def test_requests_never_started_or_deadline_is_bound(self):
        assert M.generator_bound(late_starts=0, started_requests=90,
                                 not_started_requests=10)[0]
        assert M.generator_bound(late_starts=0, started_requests=100,
                                 deadline_reached=True)[0]

    def test_throughput_is_not_an_input(self):
        """Low achieved throughput from run, export or flush overhead alone
        cannot make a run GENERATOR_BOUND: the rule has no throughput input."""
        with pytest.raises(TypeError):
            M.generator_bound(late_starts=0, started_requests=100, requested_rate=5,
                              achieved_rate=1)

    def test_several_reasons(self):
        assert len(M.generator_bound(late_starts=50, started_requests=90,
                                     not_started_requests=10, deadline_reached=True)[1]) == 3

    @pytest.mark.parametrize("kwargs", [
        dict(late_starts=0, started_requests=0),
        dict(late_starts=3, started_requests=2),
        dict(late_starts=-1, started_requests=2),
        dict(late_starts=0, started_requests=2, deadline_reached="yes"),
        dict(late_starts=0, started_requests=2, start_lag_series=[0.1, float("nan")]),
        dict(late_starts=0, started_requests=2, lag_growth_samples=1),
    ])
    def test_unjudgeable_inputs(self, kwargs):
        with pytest.raises(M.MetricError):
            M.generator_bound(**kwargs)


# ---------------------------------------------------------------------------
# Lag growth
# ---------------------------------------------------------------------------

class TestLagGrowth:
    def test_six_increasing_samples_stop(self):
        assert M.lag_growing([1, 2, 3, 4, 5, 6])

    def test_five_increasing_samples_do_not(self):
        assert not M.lag_growing([1, 2, 3, 4, 5])

    def test_plateau_breaks_the_run(self):
        assert not M.lag_growing([1, 2, 3, 3, 4, 5, 6, 7])
        assert M.lag_growing([1, 2, 3, 3, 4, 5, 6, 7, 8])

    def test_unknown_sample_breaks_the_run(self):
        assert not M.lag_growing([1, 2, 3, None, 4, 5, 6, 7])

    def test_drop_breaks_the_run(self):
        assert not M.lag_growing([5, 6, 7, 1, 2, 3, 4])

    def test_zero_lag_never_stops(self):
        assert not M.lag_growing([0] * 20)

    def test_custom_run(self):
        assert M.lag_growing([1, 2, 3], run=3)
        with pytest.raises(M.MetricError):
            M.lag_growing([1, 2], run=1)

    def test_negative_sample_rejected(self):
        with pytest.raises(M.MetricError):
            M.lag_growing([1, -2])


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

GB = 1024 ** 3


class TestResourceStops:
    def test_nothing_wrong(self):
        assert M.resource_stops(memory=[M.MemorySample("kafka", 50, 100)],
                                disk_free_bytes=100 * GB, projected_need_bytes=GB,
                                cpu_percent=[(0, 50), (60, 60)]) == ()

    def test_memory_at_90_percent_is_fine_above_stops(self):
        assert M.resource_stops(memory=[M.MemorySample("kafka", 90, 100)]) == ()
        assert "kafka memory" in M.resource_stops(memory=[M.MemorySample("kafka", 91, 100)])[0]

    def test_zero_memory_limit_rejected(self):
        with pytest.raises(M.MetricError):
            M.resource_stops(memory=[M.MemorySample("x", 1, 0)])

    def test_disk_floor(self):
        assert M.resource_stops(disk_free_bytes=10 * GB) == ()
        assert M.resource_stops(disk_free_bytes=10 * GB - 1)

    def test_disk_projection(self):
        assert M.resource_stops(disk_free_bytes=30 * GB, projected_need_bytes=15 * GB) == ()
        assert M.resource_stops(disk_free_bytes=30 * GB, projected_need_bytes=16 * GB)

    def test_cpu_saturation_needs_sixty_seconds(self):
        saturated = [(t, 100.0) for t in range(0, 61, 10)]
        assert M.resource_stops(cpu_percent=saturated[:-1]) == ()
        assert "CPU" in M.resource_stops(cpu_percent=saturated)[0]

    def test_cpu_dip_resets(self):
        samples = [(0, 100), (30, 100), (40, 50), (50, 100), (100, 100)]
        assert M.resource_stops(cpu_percent=samples) == ()

    def test_cpu_samples_must_be_ordered(self):
        with pytest.raises(M.MetricError):
            M.resource_stops(cpu_percent=[(10, 1), (5, 1)])

    def test_thresholds_from_ladder(self):
        reasons = M.resource_stops(memory=[M.MemorySample("pg", 81, 100)],
                                   memory_fraction=0.8)
        assert reasons


# ---------------------------------------------------------------------------
# Verdicts and claims
# ---------------------------------------------------------------------------

class TestVerdict:
    @pytest.mark.parametrize("integrity, stops, bound, expected", [
        (True, [], False, "VALID"),
        (True, [], True, "GENERATOR_BOUND"),
        (True, ["lag"], True, "STOPPED"),
        (False, ["lag"], True, "INVALID"),
        (False, [], False, "INVALID"),
        (None, ["timeout"], False, "STOPPED"),
        (None, [], False, "INVALID"),
        (None, [], True, "INVALID"),
    ])
    def test_precedence(self, integrity, stops, bound, expected):
        assert M.verdict(integrity_ok=integrity, stop_reasons=stops,
                         generator_bound_run=bound) == expected

    def test_claims_follow_verdict(self):
        valid = M.claim_eligibility("VALID", True)
        assert all(valid[k] for k in ("platform_throughput", "span_volume_handled",
                                      "persistence_latency", "no_loss_for_this_run"))
        assert not valid["load_source_limit_only"]
        assert not M.claim_eligibility("VALID", False)["persistence_latency"]
        assert not M.claim_eligibility("VALID", None)["persistence_latency"]
        bound = M.claim_eligibility("GENERATOR_BOUND", True)
        assert bound["load_source_limit_only"] and not bound["platform_throughput"]
        for value in ("INVALID", "STOPPED"):
            assert not any(M.claim_eligibility(value, True).values())

    def test_unknown_verdict(self):
        with pytest.raises(M.MetricError):
            M.claim_eligibility("GREAT", True)


# ---------------------------------------------------------------------------
# Ladder: targets only
# ---------------------------------------------------------------------------

class TestLadder:
    def test_shipped_ladder_is_valid(self):
        M.check_ladder(LADDER)

    def test_levels_and_targets(self):
        assert [(lv["name"], lv["target_requests"], lv["target_spans"])
                for lv in LADDER["levels"]] == [
            ("SMOKE", 100, 700), ("SMALL", 1000, 7000), ("MEDIUM", 10000, 70000),
            ("LARGE", 100000, 700000), ("STRESS", 500000, 3500000)]

    def test_ladder_is_targets_not_results(self):
        assert LADDER["kind"] == "TARGETS"

        def keys(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield key
                    yield from keys(value)
            elif isinstance(node, list):
                for value in node:
                    yield from keys(value)

        for key in keys(LADDER):
            assert not any(word in key.lower() for word in (
                "achieved", "result", "measured_rate", "p50", "p95", "p99", "throughput",
                "latency"))

    def test_only_smoke_and_small_live(self):
        assert [lv["name"] for lv in LADDER["levels"] if lv["live_allowed"]] == ["SMOKE", "SMALL"]

    def test_results_keys_rejected(self):
        bad = copy.deepcopy(LADDER)
        bad["achieved"] = {}
        with pytest.raises(M.MetricError):
            M.check_ladder(bad)
        bad = copy.deepcopy(LADDER)
        bad["levels"][0]["achieved_rate"] = 3
        with pytest.raises(M.MetricError):
            M.check_ladder(bad)

    @pytest.mark.parametrize("mutate", [
        lambda d: d.__setitem__("kind", "RESULTS"),
        lambda d: d["levels"][3].__setitem__("live_allowed", True),
        lambda d: d["levels"][4].__setitem__("refresh_and_detector", True),
        lambda d: d["levels"][0].__setitem__("target_spans", 701),
        lambda d: d["levels"][1].__setitem__("rates", [50, 10]),
        lambda d: d["levels"][0].__setitem__("rates", [100]),
        lambda d: d["defaults"].__setitem__("concurrency", 65),
        lambda d: d["defaults"].__setitem__("scenario", "api-500"),
        lambda d: d["stop_limits"].__setitem__("memory_fraction", 1.5),
        lambda d: d["levels"].reverse(),
    ])
    def test_inconsistent_ladders_rejected(self, mutate):
        bad = copy.deepcopy(LADDER)
        mutate(bad)
        with pytest.raises(M.MetricError):
            M.check_ladder(bad)


# ---------------------------------------------------------------------------
# Cells and ids
# ---------------------------------------------------------------------------

class TestCells:
    def test_smoke_plan(self):
        cells = RB.plan_cells(LADDER, "SMOKE")
        assert [(c.rate, c.repetition) for c in cells] == [(5, 1), (5, 2), (5, 3),
                                                           (10, 1), (10, 2), (10, 3)]
        first = cells[0]
        assert first.benchmark_id == "bm-smoke-r0005-c32-rep1"
        assert first.warmup_run_id == "b-smoke-r0005-c32-w1"
        assert first.measured_run_id == "b-smoke-r0005-c32-m1"
        assert first.measured_seconds == 20 and first.planned_spans == 700
        assert first.warmup_requests == 150

    def test_ids_are_unique_and_valid(self):
        cells = [c for name, _ in M.LEVELS for c in RB.plan_cells(LADDER, name)]
        ids = [c.benchmark_id for c in cells]
        runs = [r for c in cells for r in (c.warmup_run_id, c.measured_run_id)]
        assert len(set(ids)) == len(ids) and len(set(runs)) == len(runs)
        assert all(RB.RUN_ID_RE.fullmatch(r) for r in runs)

    def test_target_holds_no_result(self):
        target = RB.plan_cells(LADDER, "SMALL")[0].target()
        assert not any(k.startswith(("achieved", "p9", "result")) for k in target)

    @pytest.mark.parametrize("kwargs", [dict(rates=[7]), dict(repetitions=0),
                                        dict(concurrency=0), dict(concurrency=65)])
    def test_bad_selection(self, kwargs):
        with pytest.raises(RB.BenchmarkError):
            RB.plan_cells(LADDER, "SMOKE", **kwargs)

    def test_unknown_level(self):
        with pytest.raises(RB.BenchmarkError):
            RB.plan_cells(LADDER, "HUGE")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

class TestParsers:
    def test_sizes(self):
        assert RB.parse_size("512MiB") == 512 * 1024 ** 2
        assert RB.parse_size("1.5GiB") == int(1.5 * 1024 ** 3)
        assert RB.parse_size("12kB") == 12000
        with pytest.raises(RB.BenchmarkError):
            RB.parse_size("lots")

    def test_docker_stats(self):
        rows = RB.parse_docker_stats("pg|12.50%|100MiB / 7.6GiB\nkafka|3.0%|1GiB / 8GiB\n\n")
        assert rows[0] == {"name": "pg", "cpu_percent": 12.5,
                           "memory_used_bytes": 100 * 1024 ** 2,
                           "memory_limit_bytes": int(round(7.6 * 1024 ** 3))}
        with pytest.raises(RB.BenchmarkError):
            RB.parse_docker_stats("bad line")

    @pytest.mark.parametrize("text, seconds", [
        ("Finished running 9 view models in 0 hours 0 minutes and 2.31 seconds (2.31s).", 2.31),
        ("Finished running 5 table models in 1 minutes and 3.5 seconds", 63.5),
        ("Finished running 3 models in 12.0 seconds", 12.0),
        ("nothing here", None),
    ])
    def test_dbt_seconds(self, text, seconds):
        assert RB.parse_dbt_seconds(text) == seconds

    def test_detector_durations(self):
        log = ("x INFO    [tool_latency / agentops-demo-app / ]\n"
               "x INFO      duration_ms         : 12.5\n"
               "x INFO    [trace_latency / agentops-demo-app / agentops.request]\n"
               "x INFO      duration_ms         : 7.0\n")
        assert RB.parse_detector_durations(log) == {"tool_latency/": 12.5,
                                                    "trace_latency/agentops.request": 7.0}

    def test_clock_samples(self):
        samples = RB.parse_clock_samples("[[1.0, 1.0005, 1.001]]")
        assert samples[0].uncertainty_ms == pytest.approx(0.5)
        for bad in ("", "[]", "[[1, 2]]", "[[2, 1, 1]]"):
            with pytest.raises(RB.BenchmarkError):
                RB.parse_clock_samples(bad)

    def test_clock_probe_code_has_no_credentials(self):
        code = RB.clock_probe_code(5)
        compile(code, "probe", "exec")
        assert "os.environ['PGPASSWORD']" in code and "range(5)" in code
        with pytest.raises(RB.BenchmarkError):
            RB.clock_probe_code(0)

    def test_run_metrics_sql_refuses_bad_run_id(self):
        assert "b-smoke-r0005-c32-m1" in RB.run_metrics_sql("b-smoke-r0005-c32-m1")
        with pytest.raises(RB.BenchmarkError):
            RB.run_metrics_sql("x'; DROP TABLE telemetry_spans; --")

    def test_machine_baseline_records_failures_as_not_measured(self):
        def run(command):
            if command[:2] == ["docker", "info"]:
                return json.dumps({"ServerVersion": "29", "NCPU": 8, "MemTotal": 1, "Secret": "x"})
            raise OSError("no such tool")

        machine = RB.collect_machine_baseline(run, platform_info={"os": "test"})
        assert machine["os"] == "test" and machine["docker"]["NCPU"] == 8
        assert "Secret" not in machine["docker"]
        assert machine["images"]["kind"] == "NOT_MEASURED" and "OSError" in machine["images"]["reason"]


class TestSampler:
    def test_samples_and_errors_kept_never_zero(self):
        calls = iter([1, ValueError("boom"), 3])

        def sample():
            value = next(calls, 9)
            if isinstance(value, Exception):
                raise value
            return value

        sampler = RB.PeriodicSampler(sample, 0.001)
        sampler.start()
        import time
        deadline = time.monotonic() + 5
        while len(sampler.samples) < 3 and time.monotonic() < deadline:
            time.sleep(0.005)
        sampler.stop()
        values = [v for _, v in sampler.samples[:3]]
        assert values == [1, None, 3] and sampler.errors[0][1].startswith("ValueError")

    def test_bad_interval(self):
        with pytest.raises(RB.BenchmarkError):
            RB.PeriodicSampler(lambda: 1, 0)


# ---------------------------------------------------------------------------
# Result assembly, schema, serialization
# ---------------------------------------------------------------------------

SHA = "a" * 40


def _driver(**overrides):
    base = {"started": "2026-01-01T00:00:00+00:00", "finished": "2026-01-01T00:00:20+00:00",
            "elapsed_seconds": 20.0, "executed_attempts": 100, "started_requests": 100,
            "spans_ended": 700, "spans_exported_successfully": 700, "export_failures": 0,
            "flush_ok": True, "run_status": "completed", "problems": [],
            "achieved_submission_rate": 5.0, "late_starts": 0}
    base.update(overrides)
    return base


def _db(rows=700, **overrides):
    base = {"rows": rows, "distinct_spans": rows, "roots": 100, "first_ingested": 1000.0,
            "last_ingested": 1020.0, "request_ms": [200.0 + i for i in range(100)],
            "persistence_ms": [30.0 + i % 10 for i in range(rows)], "per_second": [35] * 20}
    base.update(overrides)
    return base


def _evidence(**overrides):
    cell = RB.plan_cells(LADDER, "SMOKE", rates=[5], repetitions=1)[0]
    values = dict(cell=cell, git_sha=SHA, git_dirty=False, started=1000.0, finished=1100.0,
                  machine={"os": "test"}, driver=_driver(), canonical_records=700,
                  raw_records=140, dlq_records=0, database=_db(),
                  clock_before=[_sample(2, 0.5)], clock_after=[_sample(3, 0.5)],
                  lag_samples=[(0, {"raw": 0, "canonical": 1}), (10, {"raw": 0, "canonical": 0})],
                  resource_samples=[(0, [{"name": "pg", "cpu_percent": 1.0,
                                          "memory_used_bytes": 10, "memory_limit_bytes": 100}])],
                  drain_seconds=4.0, refresh_seconds=2.3,
                  detector_ms={"trace_latency/agentops.request": 5.0})
    values.update(overrides)
    return RB.CellEvidence(**values)


class TestAssembleResult:
    def test_valid_run(self):
        result = RB.assemble_result(_evidence(), STOPS)
        assert result["verdict"] == "VALID" and result["integrity"]["ok"] is True
        assert result["claims"]["platform_throughput"] and result["claims"]["persistence_latency"]
        tp = result["metrics"]["throughput"]
        assert tp["spans_persisted_per_second"]["value"] == pytest.approx(699 / 20.0)
        assert tp["spans_persisted_per_second"]["kind"] == "DERIVED"
        assert tp["spans_generated_per_second"]["kind"] == "DERIVED"
        assert result["metrics"]["latency"]["request_ms"]["p50"]["value"] == pytest.approx(249.5)
        assert result["metrics"]["latency"]["persistence_ms"]["p95"]["kind"] == "DERIVED"
        assert result["metrics"]["lag"]["canonical_max"]["kind"] == "OBSERVATION"
        assert result["metrics"]["analytics"]["detection_latency"]["kind"] == "NOT_MEASURED"
        assert set(result) == (M.RESULT_KEYS | M.RESULT_OPTIONAL_KEYS) - {"host"}     # no host evidence in this fixture
        M.validate_result(result)

    def test_target_and_achieved_are_separate(self):
        result = RB.assemble_result(_evidence(), STOPS)
        assert set(result["workload"]) == {"target"}
        assert result["workload"]["target"]["rate_per_second"] == 5
        assert "spans_ended" in result["counts"]

    def test_missing_evidence_is_not_measured_and_invalid(self):
        result = RB.assemble_result(_evidence(driver=None, database=None, canonical_records=None,
                                              clock_before=[], lag_samples=[],
                                              resource_samples=[], drain_seconds=None,
                                              failure="RuntimeError: x"), STOPS)
        assert result["verdict"] == "INVALID" and result["integrity"]["ok"] is None
        assert result["counts"]["spans_ended"]["kind"] == "NOT_MEASURED"
        assert result["counts"]["rows_stored"]["kind"] == "NOT_MEASURED"
        tp = result["metrics"]["throughput"]
        assert tp["spans_persisted_per_second"]["value"] is None
        assert result["clock"]["kind"] == "NOT_MEASURED"
        assert not any(result["claims"].values())

    def test_empty_database_mapping_is_not_counted_as_zero(self):
        result = RB.assemble_result(_evidence(database={}), STOPS)
        assert result["counts"]["rows_stored"]["kind"] == "NOT_MEASURED"
        assert result["verdict"] == "INVALID"

    def test_integrity_failure(self):
        result = RB.assemble_result(_evidence(dlq_records=1), STOPS)
        assert result["verdict"] == "INVALID" and result["integrity"]["ok"] is False
        assert any(g["name"] == "DLQ records" and not g["ok"] for g in result["integrity"]["gates"])

    def test_duplicates_fail(self):
        result = RB.assemble_result(_evidence(canonical_records=705), STOPS)
        assert result["verdict"] == "INVALID"

    def test_generator_bound_from_late_starts(self):
        result = RB.assemble_result(_evidence(driver=_driver(late_starts=6)), STOPS)
        assert result["verdict"] == "GENERATOR_BOUND"
        assert result["claims"]["load_source_limit_only"]
        assert not result["claims"]["platform_throughput"]
        assert any("load source" in item for item in result["limitations"])

    def test_low_achieved_throughput_alone_is_not_generator_bound(self):
        """Overhead (last request, export, flush) lowers executed / elapsed;
        with the scheduler on time the run stays VALID, and the low
        throughput is still reported as it was."""
        result = RB.assemble_result(_evidence(driver=_driver(
            achieved_submission_rate=1.0, elapsed_seconds=100.0, late_starts=0)), STOPS)
        assert result["verdict"] == "VALID" and not result["stop"]["generator_bound"]
        assert result["metrics"]["throughput"]["requests_per_second"]["value"] == pytest.approx(1.0)

    def test_lag_growth_stops(self):
        lags = [(i * 10, {"raw": i, "canonical": 0}) for i in range(1, 8)]
        result = RB.assemble_result(_evidence(lag_samples=lags), STOPS)
        assert result["verdict"] == "STOPPED" and "raw lag" in result["stop"]["reasons"][0]

    def test_stop_reason_from_harness(self):
        result = RB.assemble_result(_evidence(stop_reasons=["cleanup not verified"]), STOPS)
        assert result["verdict"] == "STOPPED"

    def test_invalid_clock_blocks_persistence_latency(self):
        result = RB.assemble_result(_evidence(clock_after=[_sample(30, 0.5)]), STOPS)
        assert result["verdict"] == "VALID" and result["clock"]["valid"] is False
        assert result["metrics"]["latency"]["persistence_ms"]["p50"]["kind"] == "NOT_MEASURED"
        assert "drift" in result["metrics"]["latency"]["persistence_ms"]["p50"]["reason"]
        assert not result["claims"]["persistence_latency"]

    def test_level_without_detector(self):
        evidence = _evidence()
        evidence.cell = RB.plan_cells(LADDER, "LARGE", rates=[100], repetitions=1)[0]
        result = RB.assemble_result(evidence, STOPS)
        assert result["metrics"]["analytics"]["detector_ms"]["kind"] == "NOT_MEASURED"

    def test_serialization_round_trip(self, tmp_path):
        result = RB.assemble_result(_evidence(), STOPS)
        path = RB.write_result(result, tmp_path)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded == json.loads(json.dumps(result))
        M.validate_result(loaded)
        with pytest.raises(FileExistsError):
            RB.write_result(result, tmp_path)

    def test_results_never_written_inside_repository(self):
        result = RB.assemble_result(_evidence(), STOPS)
        with pytest.raises(RB.BenchmarkError):
            RB.write_result(result, _REPO / "benchmarks" / "results")
        assert not (_REPO / "benchmarks" / "results").exists()


class TestValidateResult:
    def _valid(self):
        return json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))

    @pytest.mark.parametrize("mutate, message", [
        (lambda r: r.pop("limitations"), "missing keys"),
        (lambda r: r.__setitem__("bonus", 1), "unexpected keys"),
        (lambda r: r.__setitem__("benchmark_id", "x"), "benchmark_id"),
        (lambda r: r.__setitem__("git_sha", "abc"), "git_sha"),
        (lambda r: r.__setitem__("git_dirty", "no"), "git_dirty"),
        (lambda r: r["timestamps"].__setitem__("started", "yesterday"), "timestamps"),
        (lambda r: r["workload"].__setitem__("achieved", {}), "targets only"),
        (lambda r: r["counts"].__setitem__("rows_stored", -1), "counts.rows_stored"),
        (lambda r: r["counts"].__setitem__("rows_stored", 1.5), "counts.rows_stored"),
        (lambda r: r["metrics"]["throughput"]["spans_persisted_per_second"].__setitem__(
            "kind", "GUESSED"), "kind"),
        (lambda r: r["metrics"]["throughput"]["spans_persisted_per_second"].__setitem__(
            "value", None), "NOT_MEASURED instead"),
        (lambda r: r["metrics"].__setitem__("empty", {}), "nested mappings"),
        (lambda r: r.__setitem__("verdict", "EXCELLENT"), "verdict"),
        (lambda r: r.__setitem__("verdict", "INVALID"), "contradicts"),
        (lambda r: r["claims"].__setitem__("platform_throughput", False), "claims"),
        (lambda r: r["integrity"]["gates"][0].__setitem__("ok", False), "gate did not pass"),
        (lambda r: r.__setitem__("clock", {"skew_ms": 1}), "clock"),
        (lambda r: r.__setitem__("limitations", [""]), "limitations"),
    ])
    def test_malformed_results_rejected(self, mutate, message):
        result = self._valid()
        mutate(result)
        with pytest.raises(M.MetricError, match=message):
            M.validate_result(result)

    def test_generator_bound_cannot_claim_capacity(self):
        result = json.loads(json.dumps(RB.assemble_result(
            _evidence(driver=_driver(late_starts=50)), STOPS)))
        result["verdict"] = "VALID"
        with pytest.raises(M.MetricError, match="contradicts"):
            M.validate_result(result)

    def test_not_a_mapping(self):
        with pytest.raises(M.MetricError):
            M.validate_result([])


# ---------------------------------------------------------------------------
# Command line and safety boundaries
# ---------------------------------------------------------------------------

@pytest.fixture
def no_live_access(monkeypatch):
    """Any attempt to open a connection or start a process fails the test."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"live access attempted: {args[:1]}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(os, "system", refuse)


def _fresh_import(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up while it loads
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


class TestSafety:
    def test_import_has_no_live_side_effects(self, no_live_access):
        before = set(sys.modules)
        _fresh_import("metrics_probe", _BENCH / "metrics.py")
        module = _fresh_import("run_benchmark_probe", _BENCH / "run_benchmark.py")
        loaded = set(sys.modules) - before
        for forbidden in ("run_smoke", "run_e2e", "psycopg", "confluent_kafka", "opentelemetry",
                          "grpc", "docker", "workload_generator"):
            assert not any(m == forbidden or m.startswith(forbidden + ".") for m in loaded)
        # Importing has no live side effect whatever the gate's value.
        assert isinstance(module.LIVE_ENABLED, bool)

    def test_metrics_module_has_no_io_imports(self):
        text = (_BENCH / "metrics.py").read_text(encoding="utf-8")
        # "Docker" appears in names and comments since B3J-287 (the container resource rules); what is
        # forbidden is any way to reach it, so the check names the import and the client entry points.
        for word in ("import socket", "import subprocess", "import os", "open(", "psycopg",
                     "import docker", "from docker", "docker.from_env", "urllib", "import json"):
            assert word not in text.split('"""', 2)[2]

    def test_plan_mode_touches_nothing(self, no_live_access, tmp_path):
        out = io.StringIO()
        code = RB.main(["--level", "SMOKE", "--output-dir", str(tmp_path / "out")], stdout=out)
        text = out.getvalue()
        assert code == 0 and text.startswith("PLAN ONLY")
        assert "bm-smoke-r0005-c32-rep1" in text and "b-smoke-r0010-c32-m3" in text
        assert not (tmp_path / "out").exists()

    def test_live_is_refused_before_anything_starts(self, no_live_access, tmp_path, capsys,
                                                    monkeypatch):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        code = RB.main(["--level", "SMOKE", "--live", "--output-dir", str(tmp_path)])
        assert code == 2 and "not enabled" in capsys.readouterr().err
        assert "run_smoke" not in sys.modules

    def test_run_cell_is_unreachable(self, no_live_access, tmp_path, monkeypatch):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        cell = RB.plan_cells(LADDER, "SMOKE", rates=[5], repetitions=1)[0]
        with pytest.raises(RB.LiveDisabled):
            RB.run_cell(cell, LADDER, expect_head=None, output_dir=tmp_path)
        assert "run_smoke" not in sys.modules

    def test_output_inside_repository_refused(self, no_live_access):
        with pytest.raises(SystemExit):
            RB.main(["--level", "SMOKE", "--output-dir", str(_REPO / "benchmarks")])

    def test_default_output_is_outside_repository(self):
        assert _REPO not in RB.DEFAULT_OUTPUT.resolve().parents

    def test_offline_validation_does_no_live_access(self, no_live_access, tmp_path):
        result = RB.assemble_result(_evidence(), STOPS)
        M.validate_result(result)
        RB.write_result(result, tmp_path)
        M.check_ladder(RB.load_ladder(_BENCH / "ladder.json"))

    def test_unknown_level_and_rate_rejected(self, no_live_access):
        with pytest.raises(SystemExit):
            RB.main(["--level", "HUGE"])
        with pytest.raises(SystemExit):
            RB.main(["--level", "SMOKE", "--rate", "7"])

    def test_no_synthetic_mode(self):
        text = (_BENCH / "run_benchmark.py").read_text(encoding="utf-8").lower()
        assert "--mode synthetic" not in text and "synthetic_driver" not in text


def test_math_is_finite_everywhere():
    result = RB.assemble_result(_evidence(), STOPS)

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, float):
            assert math.isfinite(node)

    walk(result)


# ---------------------------------------------------------------------------
# B3J-257: the optional `consumer` block of a result
# ---------------------------------------------------------------------------

def _consumer(**over):
    block = {"commit_batching": {"enabled": False, "batch_messages": 1, "interval_seconds": None},
             "timing_diagnostic_interval_seconds": 0.0}
    block.update(over)
    return block


_BATCHED = {"enabled": True, "batch_messages": 100, "interval_seconds": 1.0}
_OBSERVED = {"windows": 5, "window_seconds": 10.0, "messages": 700, "commit_calls": 10,
             "mean_messages_per_commit": 70.0, "mean_seconds_between_commits": 1.0, "mean_commit_ms": 8.5}


class TestConsumerBlock:
    def _valid(self):
        return json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))

    def test_assembled_results_carry_the_block_and_validate(self):
        result = self._valid()
        assert result["consumer"] == _consumer()
        M.validate_result(result)

    def test_a_historical_result_without_the_block_is_still_valid(self):
        result = self._valid()
        del result["consumer"]
        M.validate_result(result)
        assert "consumer" in M.RESULT_OPTIONAL_KEYS and "consumer" not in M.RESULT_KEYS

    @pytest.mark.parametrize("block", [
        _consumer(),
        _consumer(commit_batching=dict(_BATCHED)),
        _consumer(commit_batching=dict(_BATCHED), timing_diagnostic_interval_seconds=5.0, observed=dict(_OBSERVED)),
        _consumer(timing_diagnostic_interval_seconds=5, observed={**_OBSERVED, "commit_calls": 0,
                                                                    "mean_messages_per_commit": None,
                                                                    "mean_seconds_between_commits": None,
                                                                    "mean_commit_ms": None}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 2, "interval_seconds": 0.05}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 1000, "interval_seconds": 30}),
    ])
    def test_well_formed_blocks_are_accepted(self, block):
        assert M.consumer_block_problems(block) == []

    @pytest.mark.parametrize("block", [
        None, [], "text", {}, {"commit_batching": dict(_BATCHED)}, _consumer(extra=1),
        _consumer(commit_batching={"enabled": True, "batch_messages": 100}),
        _consumer(commit_batching={**_BATCHED, "extra": 1}),
        _consumer(commit_batching={"enabled": 1, "batch_messages": 100, "interval_seconds": 1.0}),
        _consumer(commit_batching={"enabled": True, "batch_messages": True, "interval_seconds": 1.0}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 1, "interval_seconds": 1.0}),
        _consumer(commit_batching={"enabled": False, "batch_messages": 100, "interval_seconds": None}),
        _consumer(commit_batching={"enabled": False, "batch_messages": 1, "interval_seconds": 1.0}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 100, "interval_seconds": None}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 100, "interval_seconds": 0.01}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 100, "interval_seconds": 31}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 100, "interval_seconds": float("nan")}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 1001, "interval_seconds": 1.0}),
        _consumer(commit_batching={"enabled": True, "batch_messages": 0, "interval_seconds": 1.0}),
        _consumer(timing_diagnostic_interval_seconds=-1), _consumer(timing_diagnostic_interval_seconds=True),
        _consumer(timing_diagnostic_interval_seconds="5"),
        _consumer(observed={}), _consumer(observed={**_OBSERVED, "extra": 1}),
        _consumer(observed={**_OBSERVED, "windows": 0}), _consumer(observed={**_OBSERVED, "commit_calls": 701}),
        _consumer(observed={**_OBSERVED, "messages": -1}), _consumer(observed={**_OBSERVED, "windows": True}),
        _consumer(observed={**_OBSERVED, "mean_commit_ms": -1}),
        _consumer(observed={**_OBSERVED, "mean_commit_ms": "8"}),
        _consumer(observed={**_OBSERVED, "commit_calls": 0}),
        _consumer(observed={**_OBSERVED, "mean_messages_per_commit": None}),
        _consumer(observed={**_OBSERVED, "window_seconds": float("inf")}),
    ])
    def test_malformed_or_inconsistent_blocks_are_rejected(self, block):
        assert M.consumer_block_problems(block)

    def test_validate_result_rejects_a_bad_block_and_names_it(self):
        result = self._valid()
        result["consumer"]["commit_batching"]["batch_messages"] = 100
        with pytest.raises(M.MetricError, match="consumer"):
            M.validate_result(result)

    def test_write_result_refuses_a_bad_block(self, tmp_path):
        result = self._valid()
        result["consumer"] = {"commit_batching": {}}
        with pytest.raises(M.MetricError):
            RB.write_result(result, tmp_path)
        assert not list(tmp_path.glob("*.json"))

    def test_configured_and_measured_values_are_kept_apart(self):
        evidence = _evidence(consumer_batch_messages=100, consumer_commit_interval_seconds=1.0,
                             consumer_timing_interval_seconds=5.0, consumer_observed=dict(_OBSERVED))
        block = RB.assemble_result(evidence, STOPS)["consumer"]
        assert block["commit_batching"] == _BATCHED and block["observed"] == _OBSERVED
        assert block["timing_diagnostic_interval_seconds"] == 5.0
        without = RB.assemble_result(_evidence(consumer_batch_messages=100, consumer_commit_interval_seconds=1.0), STOPS)["consumer"]
        assert "observed" not in without

    def test_an_interval_is_dropped_when_batching_is_off(self):
        block = RB.consumer_evidence(_evidence(consumer_batch_messages=1, consumer_commit_interval_seconds=1.0))
        assert block["commit_batching"] == {"enabled": False, "batch_messages": 1, "interval_seconds": None}


# ---------------------------------------------------------------------------
# B3J-275: the optional `host` block of a result
# ---------------------------------------------------------------------------

def _host(**over):
    block = {
        "platform": "windows",
        "keep_awake": {"acquisition": "acquired", "readback": "consistent"},
        "session": {"start": {"flags": 1, "locked": False, "idle_seconds": 3.0},
                    "end": {"flags": 0, "locked": True, "idle_seconds": 700.5}},
        "window": {"start_utc": "2026-10-16T18:00:00.000000Z", "end_utc": "2026-10-16T18:10:00.000000Z"},
        "power_events": {"status": "ok", "error": None, "query_seconds": 1.2, "truncated": False,
                        "events": [], "episodes": []},
        "host_interruption_suspected": False,
    }
    block.update(over)
    return block


_ENTRY = {"time_utc": "2026-10-16T18:03:00.500000Z", "id": 506, "reason": 12}
_EXIT = {"time_utc": "2026-10-16T18:05:06.000000Z", "id": 507, "reason": None}


def _with_events(events, episodes, flag=True, **power):
    block = _host()
    block["power_events"] = {**block["power_events"], "events": events, "episodes": episodes, **power}
    block["host_interruption_suspected"] = flag
    return block


class TestHostBlock:
    def _valid(self):
        return json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))

    def test_host_is_optional_and_historical_results_without_it_stay_valid(self):
        result = self._valid()
        result.pop("host", None)
        M.validate_result(result)
        assert "host" in M.RESULT_OPTIONAL_KEYS and "host" not in M.RESULT_KEYS

    @pytest.mark.parametrize("block", [
        _host(),
        _with_events([_ENTRY, _EXIT], [{"entered_utc": _ENTRY["time_utc"], "exited_utc": _EXIT["time_utc"], "seconds": 125.5}]),
        _with_events([_ENTRY], [{"entered_utc": _ENTRY["time_utc"], "exited_utc": None, "seconds": None}]),
        _with_events([_EXIT], [{"entered_utc": None, "exited_utc": _EXIT["time_utc"], "seconds": None}]),
        _with_events([], [], flag=None, status="failed", error="timeout"),
        _host(session={"start": None, "end": None}),
        _host(session={"start": {"flags": None, "locked": None, "idle_seconds": None}, "end": None}),
        _host(keep_awake={"acquisition": "unknown", "readback": "unknown"}),
        _with_events([], [], flag=False, truncated=True),
    ])
    def test_well_formed_blocks_are_accepted(self, block):
        assert M.host_block_problems(block) == []

    @pytest.mark.parametrize("mutate", [
        lambda b: b.pop("window"), lambda b: b.__setitem__("extra", 1), lambda b: b.__setitem__("platform", "linux"),
        lambda b: b["keep_awake"].__setitem__("acquisition", "held"),
        lambda b: b["keep_awake"].__setitem__("readback", "maybe"),
        lambda b: b["keep_awake"].pop("readback"),
        lambda b: b["session"]["start"].__setitem__("locked", True),               # locked must follow flags
        lambda b: b["session"]["start"].__setitem__("flags", 2),
        lambda b: b["session"]["start"].__setitem__("flags", True),
        lambda b: b["session"]["end"].__setitem__("locked", False),
        lambda b: b["session"]["start"].__setitem__("idle_seconds", -1),
        lambda b: b["session"]["start"].__setitem__("idle_seconds", "3"),
        lambda b: b["session"]["start"].__setitem__("extra", 1),
        lambda b: b["window"].__setitem__("start_utc", "2026-10-16 18:00:00"),
        lambda b: b["window"].__setitem__("end_utc", "2026-10-16T17:00:00.000000Z"),   # ends before it starts
        lambda b: b["power_events"].__setitem__("status", "maybe"),
        lambda b: b["power_events"].__setitem__("error", "boom"),                       # error with a successful query
        lambda b: b["power_events"].__setitem__("truncated", "no"),
        lambda b: b["power_events"].__setitem__("query_seconds", -0.1),
        lambda b: b["power_events"].pop("episodes"),
        lambda b: b["power_events"].__setitem__("events", [dict(_ENTRY, id=505)]),
        lambda b: b["power_events"].__setitem__("events", [dict(_ENTRY, time_utc="yesterday")]),
        lambda b: b["power_events"].__setitem__("events", [dict(_ENTRY, time_utc="2026-10-16T19:00:00.000000Z")]),  # outside
        lambda b: b["power_events"].__setitem__("events", [_EXIT, _ENTRY]),             # out of order
        lambda b: b["power_events"].__setitem__("events", [dict(_ENTRY, reason="12")]),
        lambda b: b["power_events"].__setitem__("events", [_ENTRY] * 51),
        lambda b: b["power_events"].__setitem__("episodes", [{"entered_utc": None, "exited_utc": None, "seconds": None}]),
        lambda b: b["power_events"].__setitem__("episodes", [{"entered_utc": _ENTRY["time_utc"], "exited_utc": None, "seconds": 5}]),
        lambda b: b["power_events"].__setitem__("episodes", [{"entered_utc": _ENTRY["time_utc"], "exited_utc": _EXIT["time_utc"], "seconds": None}]),
        lambda b: b.__setitem__("host_interruption_suspected", "no"),
    ])
    def test_malformed_or_inconsistent_blocks_are_rejected(self, mutate):
        block = _host()
        mutate(block)
        assert M.host_block_problems(block)

    def test_a_non_mapping_is_rejected(self):
        for value in (None, [], "windows", 3):
            assert M.host_block_problems(value)

    @pytest.mark.parametrize("build", [
        lambda: _host(host_interruption_suspected=True),                                  # no events must not read as an interruption
        lambda: _with_events([_ENTRY], [], flag=False),                                   # events must not read as clean
        lambda: _with_events([], [], flag=False, status="failed", error="timeout"),       # a failed query is never "false"
        lambda: _with_events([], [], flag=True, status="failed", error="timeout"),        # nor a confirmed interruption
        lambda: _host(host_interruption_suspected=None),                                  # a successful empty query is not "unknown"
    ])
    def test_the_indicator_must_follow_the_query_status_and_the_events(self, build):
        assert M.host_block_problems(build())

    def test_a_failed_query_is_distinct_from_zero_events(self):
        failed = _with_events([], [], flag=None, status="failed", error="timeout")
        none = _host()
        assert M.host_block_problems(failed) == [] and M.host_block_problems(none) == []
        assert failed["host_interruption_suspected"] is None and none["host_interruption_suspected"] is False
        failed["power_events"]["error"] = None
        assert M.host_block_problems(failed)                                    # a failure needs its error text
        failed["power_events"]["error"] = "x" * 121
        assert M.host_block_problems(failed)                                    # and it is bounded

    def test_validate_result_checks_the_block_and_names_it(self):
        result = self._valid()
        result["host"] = _host(platform="linux")
        with pytest.raises(M.MetricError, match="host"):
            M.validate_result(result)
        result["host"] = _host()
        M.validate_result(result)

    def test_claims_withdraw_the_timing_claims_only_when_an_interruption_is_suspected(self):
        clean = M.claim_eligibility("VALID", True)
        assert clean == M.claim_eligibility("VALID", True, False)
        broken = M.claim_eligibility("VALID", True, True)
        assert broken["platform_throughput"] is False and broken["persistence_latency"] is False
        assert broken["span_volume_handled"] is True and broken["no_loss_for_this_run"] is True
        assert M.claim_eligibility("GENERATOR_BOUND", True, True) == M.claim_eligibility("GENERATOR_BOUND", True, False)

    def test_the_validator_requires_claims_that_follow_the_host_indicator(self):
        result = self._valid()
        interrupted = _with_events([_ENTRY], [{"entered_utc": _ENTRY["time_utc"], "exited_utc": None, "seconds": None}])
        result["host"] = interrupted
        with pytest.raises(M.MetricError, match="claims"):
            M.validate_result(result)                          # the claims still say VALID throughput
        result["claims"] = M.claim_eligibility(result["verdict"], result["clock"]["valid"], True)
        M.validate_result(result)

    def test_the_host_block_does_not_change_the_verdict_rules(self):
        result = self._valid()
        verdict_before = result["verdict"]
        result["host"] = _host()
        M.validate_result(result)
        assert result["verdict"] == verdict_before


# ---------------------------------------------------------------------------
# B3J-283: the optional host-resource observations under metrics.resources
# ---------------------------------------------------------------------------

def _hr_row(cpu, ws=80_000_000, peak=90_000_000, status="ok"):
    return {"status": status, "cpu_percent": cpu, "working_set_bytes": ws, "peak_working_set_bytes": peak}


def _hr_snapshot(cpu, host_cpu, memory, disk):
    return {"processes": {"storage-consumer": _hr_row(cpu),
                          "storage-consumer:launcher": _hr_row(0.0 if cpu is not None else None, 5_000_000, 6_000_000)},
            "host_cpu_percent": host_cpu, "memory_available_bytes": memory, "memory_total_bytes": 16_000_000_000,
            "disk_free_bytes": disk, "errors": []}


_HR_SAMPLES = [(0.0, _hr_snapshot(None, None, 5_000, 300)), (10.0, _hr_snapshot(40.0, 12.5, 3_000, 250)),
               (20.0, _hr_snapshot(60.0, 20.0, 4_000, 280))]
_HR_INFO = {"interval": 10.0, "disk_volume": "C:\\", "keys": ["storage-consumer", "storage-consumer:launcher"],
            "errors": {}, "unattributed": 0, "stop_problem": None}


def _hr_result(samples=None, info=None, **overrides):
    evidence = _evidence(host_resource_samples=copy.deepcopy(_HR_SAMPLES if samples is None else samples),
                         host_resource_info=copy.deepcopy(_HR_INFO if info is None else info), **overrides)
    return json.loads(json.dumps(RB.assemble_result(evidence, STOPS)))


class TestHostResourceObservations:
    def test_a_result_with_observations_validates_and_holds_the_expected_values(self):
        result = _hr_result()
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        assert resources["host_process_cpu_percent_series"]["storage-consumer"]["value"] == [40.0, 60.0]
        assert resources["host_process_cpu_percent_max"]["storage-consumer"]["value"] == 60.0
        assert resources["host_process_cpu_percent_series_times_s"]["storage-consumer"]["value"] == [10.0, 20.0]
        assert resources["host_process_working_set_bytes_series"]["storage-consumer"]["value"] == [80_000_000] * 3
        assert resources["host_process_peak_working_set_bytes"]["storage-consumer:launcher"]["value"] == 6_000_000
        assert resources["host_memory_available_bytes_series"]["host"]["value"] == [5_000, 3_000, 4_000]
        assert resources["host_memory_available_bytes_min"]["host"]["value"] == 3_000
        assert resources["host_cpu_percent_series"]["host"]["value"] == [12.5, 20.0]
        assert resources["disk_free_bytes_min"]["C:\\"]["value"] == 250
        for name, leaf in ((n, l) for n, group in resources.items() if n.startswith(("host_", "disk_free"))
                           for l in ([group] if "kind" in group else group.values())):
            if "kind" in leaf:
                assert leaf["kind"] in ("OBSERVATION", "NOT_MEASURED"), name

    def test_every_observation_is_labelled_observation_with_its_unit_and_source(self):
        resources = _hr_result()["metrics"]["resources"]
        cpu = resources["host_process_cpu_percent_series"]["storage-consumer"]
        assert (cpu["kind"], cpu["unit"], cpu["source"]) == ("OBSERVATION", "%", "Windows GetProcessTimes / K32GetProcessMemoryInfo")
        assert "first sample has no value" in resources["host_process_cpu_percent_max"]["storage-consumer"]["method"]
        assert resources["host_memory_available_bytes_min"]["host"]["unit"] == "bytes"
        assert resources["host_cpu_percent_series"]["host"]["source"] == "Windows GetSystemTimes"

    def test_the_docker_resource_metrics_are_untouched_by_the_additions(self):
        plain = RB.assemble_result(_evidence(), STOPS)["metrics"]["resources"]
        added = _hr_result()["metrics"]["resources"]
        for name, value in plain.items():
            assert added[name] == json.loads(json.dumps(value)), name
        assert not [n for n in plain if n.startswith(("host_", "disk_free_bytes"))]

    def test_a_result_without_the_observations_has_exactly_the_old_resources_and_validates(self):
        result = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        assert sorted(result["metrics"]["resources"]) == ["cpu_percent_max", "cpu_percent_series",
                                                           "cpu_percent_series_times_s", "memory_peak_bytes"]
        M.validate_result(result)

    def test_no_samples_is_not_measured_with_a_reason_and_zero_coverage(self):
        result = _hr_result(samples=[])
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        assert resources["host_cpu_percent_series"]["all"]["kind"] == "NOT_MEASURED"
        assert resources["host_cpu_percent_series"]["all"]["reason"] == "no host resource samples"
        assert resources["host_memory_available_bytes_min"]["all"]["value"] is None
        coverage = resources["host_sampling_coverage"]
        assert coverage["samples_attempted"]["value"] == 0 and coverage["first_sample_s"]["kind"] == "NOT_MEASURED"

    def test_unusable_values_are_omitted_never_recorded_as_zero(self):
        bad = _hr_snapshot(float("nan"), float("inf"), -5, True)
        bad["processes"]["storage-consumer"]["working_set_bytes"] = -1
        bad["processes"]["storage-consumer:launcher"]["working_set_bytes"] = True
        result = _hr_result(samples=[(0.0, bad), (10.0, _hr_snapshot(30.0, 10.0, 4_000, 250))])
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        assert resources["host_process_cpu_percent_series"]["storage-consumer"]["value"] == [30.0]
        assert resources["host_cpu_percent_series"]["host"]["value"] == [10.0]
        assert resources["host_memory_available_bytes_series"]["host"]["value"] == [4_000]
        assert resources["disk_free_bytes_series"]["C:\\"]["value"] == [250]
        coverage = resources["host_sampling_coverage"]
        assert coverage["process_samples_unavailable"]["storage-consumer"]["value"] == 1
        assert coverage["process_samples_available"]["storage-consumer"]["value"] == 1

    def test_failed_samples_and_malformed_entries_are_counted_as_failures(self):
        samples = [(0.0, None), ("x", _hr_snapshot(1.0, 1.0, 1, 1)), (float("nan"), _hr_snapshot(1.0, 1.0, 1, 1)),
                   (10.0, _hr_snapshot(40.0, 12.5, 3_000, 250)), (20.0, "not a snapshot")]
        result = _hr_result(samples=samples)
        M.validate_result(result)
        coverage = result["metrics"]["resources"]["host_sampling_coverage"]
        assert coverage["samples_attempted"]["value"] == 5 and coverage["samples_failed"]["value"] == 4
        assert (coverage["first_sample_s"]["value"], coverage["last_sample_s"]["value"]) == (0.0, 20.0)

    def test_the_exited_and_unavailable_counts_are_per_process(self):
        samples = [(0.0, _hr_snapshot(None, None, 5_000, 300)), (10.0, _hr_snapshot(40.0, 12.5, 3_000, 250))]
        samples[1][1]["processes"]["storage-consumer"] = _hr_row(None, None, None, status="exited")
        result = _hr_result(samples=samples)
        M.validate_result(result)
        coverage = result["metrics"]["resources"]["host_sampling_coverage"]
        assert coverage["process_samples_exited"]["storage-consumer"]["value"] == 1
        assert coverage["process_samples_available"]["storage-consumer"]["value"] == 1
        assert coverage["process_samples_exited"]["storage-consumer:launcher"]["value"] == 0

    def test_a_broken_info_block_costs_only_the_observations_and_says_so(self):
        evidence = _evidence(host_resource_samples=list(_HR_SAMPLES), host_resource_info={"keys": 5})
        result = json.loads(json.dumps(RB.assemble_result(evidence, STOPS)))
        M.validate_result(result)
        assert not [n for n in result["metrics"]["resources"] if n.startswith("host_")]
        assert any(t.startswith("diagnostic host resources not recorded") for t in result["limitations"])
        assert result["verdict"] == RB.assemble_result(_evidence(), STOPS)["verdict"]

    def test_the_verdict_claims_and_stop_reasons_ignore_the_observations(self):
        plain = RB.assemble_result(_evidence(), STOPS)
        hosted = _hr_result()
        starved = _hr_result(samples=[(0.0, _hr_snapshot(99999.0, 100.0, 1, 1)), (10.0, _hr_snapshot(99999.0, 100.0, 1, 1))])
        for result in (hosted, starved):
            assert result["verdict"] == plain["verdict"] and result["claims"] == plain["claims"]
            assert result.get("stop") == plain.get("stop")

    def test_the_limitation_lines_describe_the_added_coverage_and_the_bounded_errors(self):
        evidence = _evidence(host_resource_samples=list(_HR_SAMPLES), host_resource_info={
            **_HR_INFO, "errors": {"memory:OSError": 2, "other": 1}, "stop_problem": "BenchmarkError: did not stop"})
        lines = RB.host_resource_limitations(evidence)
        assert len(lines) == 3 and "recorded Docker resources only" in lines[0]
        assert "3 failed reads (memory:OSError x2, other x1)" in lines[1]
        assert lines[2] == "host resource sampler stop problem: BenchmarkError: did not stop"
        assert RB.host_resource_limitations(_evidence()) == []


class TestHostResourceValidation:
    def _valid(self):
        return _hr_result()

    @pytest.mark.parametrize("mutate, message", [
        (lambda r: r.pop("host_process_cpu_percent_series_times_s"), "incomplete"),
        (lambda r: r.pop("host_sampling_coverage"), "host_sampling_coverage is required"),
        (lambda r: r.__setitem__("host_gpu_percent_max", r["host_cpu_percent_max"]), "not a host resource observation"),
        (lambda r: r["host_process_cpu_percent_max"]["storage-consumer"].__setitem__("value", 1.0), "not the maximum"),
        (lambda r: r["host_memory_available_bytes_min"]["host"].__setitem__("value", 9_999), "not the minimum"),
        (lambda r: r["disk_free_bytes_min"]["C:\\"].__setitem__("value", 1), "not the minimum"),
        (lambda r: r["host_process_cpu_percent_series_times_s"]["storage-consumer"].__setitem__("value", [10.0]), "one time per value"),
        (lambda r: r["host_process_cpu_percent_series_times_s"]["storage-consumer"].__setitem__("value", [20.0, 10.0]), "in order"),
        (lambda r: r["host_process_cpu_percent_series_times_s"]["storage-consumer"].__setitem__("value", [-1.0, 5.0]), "in order"),
        (lambda r: r["host_process_cpu_percent_series"]["storage-consumer"].__setitem__("value", [40.0, -1.0]), "non-negative"),
        (lambda r: r["host_process_cpu_percent_series"]["storage-consumer"].__setitem__("n", 5), "n must equal"),
        (lambda r: r["host_cpu_percent_series"]["host"].__setitem__("value", [12.5, 100.5]), "at most 100"),
        (lambda r: r["host_cpu_percent_max"]["host"].__setitem__("unit", "bytes"), "unit must be"),
        (lambda r: r["host_memory_available_bytes_series"]["host"].__setitem__("unit", "%"), "unit must be"),
        (lambda r: r["host_memory_available_bytes_series"]["host"].__setitem__("kind", "MEASURED"), "OBSERVATION"),
        (lambda r: r["host_process_cpu_percent_series"].__setitem__("extra", r["host_process_cpu_percent_series"]["storage-consumer"]), "different keys"),
        (lambda r: r["host_process_peak_working_set_bytes"]["storage-consumer"].__setitem__("value", -1), "byte count"),
        (lambda r: r["host_process_peak_working_set_bytes"]["storage-consumer"].__setitem__("unit", "%"), "byte count"),
        (lambda r: r["host_sampling_coverage"]["samples_failed"].__setitem__("value", 99), "more than the samples attempted"),
        (lambda r: r["host_sampling_coverage"]["samples_attempted"].__setitem__("value", 2.5), "whole number"),
        (lambda r: r["host_sampling_coverage"]["interval_seconds"].__setitem__("value", 0), "positive"),
        (lambda r: r["host_sampling_coverage"]["first_sample_s"].__setitem__("value", 99.0), "first sample is after"),
        (lambda r: r["host_sampling_coverage"]["host_cpu_samples_available"].__setitem__("value", 3), "differs from the length"),
        (lambda r: r["host_sampling_coverage"]["host_memory_samples_available"].__setitem__("value", 1), "differs from the length"),
        (lambda r: r["host_sampling_coverage"]["disk_samples_available"].__setitem__("value", 1), "differs from the length"),
        (lambda r: r["host_sampling_coverage"]["process_samples_available"]["storage-consumer"].__setitem__("value", 1), "differs from the length"),
        (lambda r: r["host_sampling_coverage"]["process_samples_exited"]["storage-consumer"].__setitem__("value", 99), "more samples than were attempted"),
        (lambda r: r["host_sampling_coverage"].__setitem__("bonus", r["host_sampling_coverage"]["samples_failed"]), "not a coverage entry"),
        (lambda r: r["host_sampling_coverage"].pop("collection_errors"), "missing"),
        (lambda r: r["host_sampling_coverage"]["process_samples_available"].__setitem__("storage-consumer", {"value": 3}), "metric"),
    ])
    def test_a_malformed_observation_is_refused(self, mutate, message):
        result = self._valid()
        mutate(result["metrics"]["resources"])
        with pytest.raises(M.MetricError, match=message):
            M.validate_result(result)

    def test_the_unmutated_result_is_accepted(self):
        M.validate_result(self._valid())

    def test_only_resource_names_with_a_host_prefix_are_policed(self):
        result = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        result["metrics"]["resources"]["some_future_metric"] = result["metrics"]["resources"]["memory_peak_bytes"]
        M.validate_result(result)                                    # not a host name: left alone

    @pytest.mark.parametrize("resources", [None, [], "x", {}, {"cpu_percent_max": {}}])
    def test_inputs_without_host_names_have_no_problems(self, resources):
        assert M.host_resource_problems(resources) == []

    def test_not_measured_entries_are_accepted_alongside_measured_ones(self):
        result = _hr_result(samples=[_HR_SAMPLES[0], _HR_SAMPLES[1]])
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        resources["host_cpu_percent_series"] = {"all": M.not_measured("%", "x", "none").to_dict()}
        resources["host_cpu_percent_max"] = {"all": M.not_measured("%", "x", "none").to_dict()}
        resources["host_cpu_percent_series_times_s"] = {"all": M.not_measured("s", "x", "none").to_dict()}
        coverage = resources["host_sampling_coverage"]
        coverage["host_cpu_samples_available"]["value"] = 0
        M.validate_result(result)

    def test_a_result_written_before_the_observations_validates_whatever_the_new_checks_are(self):
        result = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        for name in [n for n in result["metrics"]["resources"] if n.startswith(("host_", "disk_free_bytes"))]:
            del result["metrics"]["resources"][name]
        M.validate_result(result)
        assert M.RESULT_KEYS | M.RESULT_OPTIONAL_KEYS == {
            "benchmark_id", "git_sha", "git_dirty", "timestamps", "machine", "workload", "counts", "metrics",
            "clock", "integrity", "verdict", "limitations", "verdict_reasons", "stop", "claims", "consumer", "host"}

    def test_the_resource_stop_function_and_its_thresholds_are_unchanged(self):
        assert (M.MEMORY_FRACTION_MAX, M.CPU_SATURATION_PERCENT, M.CPU_SATURATION_SECONDS,
                M.DISK_PROJECTION_FACTOR) == (0.90, 99.5, 60.0, 2.0)
        assert M.resource_stops(cpu_percent=[(0, 100.0), (30, 100.0), (61, 100.0)]) \
            == ("CPU at or above 99.5% for 61 s",)
        assert M.LAG_GROWTH_SAMPLES == 6 and M.LATE_START_FRACTION == 0.05


# ---------------------------------------------------------------------------
# B3J-287: Docker container CPU and memory rules, coverage, and the new integrity gate
# ---------------------------------------------------------------------------

DK_VM = 8 * 1024 ** 3


def _dk_row(name, cpu, used, limit=DK_VM):
    return {"name": name, "cpu_percent": cpu, "memory_used_bytes": used, "memory_limit_bytes": limit}


def _dk_rows(kafka_cpu=100.0, pg_cpu=20.0, kafka_mem=1_000_000_000, pg_mem=100_000_000):
    return [_dk_row("proj-kafka-1", kafka_cpu, kafka_mem), _dk_row("proj-pg-1", pg_cpu, pg_mem)]


def _dk_samples(times, **kwargs):
    return [(float(t), _dk_rows(**kwargs)) for t in times]


_DK_ADEQUATE = [10.0 * i for i in range(13)]                        # 0 .. 120 s
_DK_WINDOW = {"stop_s": 125.0, "interval_s": 10.0, "expected_containers": 2}
_DK_MACHINE = {"os": "test", "docker": {"NCPU": 4, "MemTotal": DK_VM}}


def _dk_result(samples=None, window=None, machine=None, **overrides):
    evidence = _evidence(resource_samples=_dk_samples(_DK_ADEQUATE) if samples is None else samples,
                         resource_window=dict(_DK_WINDOW) if window is None else window,
                         machine=copy.deepcopy(_DK_MACHINE) if machine is None else machine, **overrides)
    return json.loads(json.dumps(RB.assemble_result(evidence, STOPS)))


def _gate(result, name="docker resource coverage"):
    found = [g for g in result["integrity"]["gates"] if g["name"] == name]
    return found[0] if found else None


class TestDockerCpuSeries:
    def test_the_cpu_of_the_containers_is_added_per_tick_and_divided_by_the_recorded_ncpu(self):
        series = M.docker_vm_cpu_series(_dk_samples([0, 10], kafka_cpu=200.0, pg_cpu=100.0),
                                        expected_containers=2, ncpu=4)
        assert series == [(0.0, 75.0), (10.0, 75.0)]
        assert M.docker_vm_cpu_series(_dk_samples([0], kafka_cpu=200.0, pg_cpu=100.0),
                                      expected_containers=2, ncpu=8)[0][1] == 37.5      # the denominator is NCPU
        assert M.docker_vm_cpu_series(_dk_samples([0], kafka_cpu=396.0, pg_cpu=3.0),
                                      expected_containers=2, ncpu=4)[0][1] == pytest.approx(99.75)

    @pytest.mark.parametrize("ncpu", [None, 0, -4, True, 4.0, "4"])
    def test_an_unusable_ncpu_gives_no_value_never_a_guess(self, ncpu):
        assert M.docker_vm_cpu_series(_dk_samples([0, 10]), expected_containers=2, ncpu=ncpu) == [(0.0, None), (10.0, None)]

    @pytest.mark.parametrize("rows", [
        None, "x", [],
        [_dk_row("a", 1.0, 1)],                                                        # a container missing
        [_dk_row("a", 1.0, 1), _dk_row("b", 1.0, 1), _dk_row("c", 1.0, 1)],            # an unexpected extra
        [_dk_row("a", 1.0, 1), _dk_row("a", 1.0, 1)],                                  # duplicate name
        [_dk_row("a", 1.0, 1), _dk_row("", 1.0, 1)],                                   # no name
        [_dk_row("a", 1.0, 1), _dk_row("b", float("nan"), 1)],
        [_dk_row("a", 1.0, 1), _dk_row("b", float("inf"), 1)],
        [_dk_row("a", 1.0, 1), _dk_row("b", -1.0, 1)],
        [_dk_row("a", 1.0, 1), _dk_row("b", True, 1)],
        [_dk_row("a", 1.0, 1), {"name": "b"}],
        [_dk_row("a", 1.0, 1), "not a row"],
    ])
    def test_an_incomplete_or_malformed_tick_is_no_value_and_never_zero(self, rows):
        assert M.docker_vm_cpu_series([(0.0, rows)], expected_containers=2, ncpu=4) == [(0.0, None)]

    def test_samples_must_be_in_order_and_well_formed(self):
        with pytest.raises(M.MetricError, match="time order"):
            M.docker_vm_cpu_series(_dk_samples([10, 0]), expected_containers=2, ncpu=4)
        with pytest.raises(M.MetricError):
            M.docker_vm_cpu_series([(0.0,)], expected_containers=2, ncpu=4)
        with pytest.raises(M.MetricError):
            M.docker_vm_cpu_series([(float("nan"), _dk_rows())], expected_containers=2, ncpu=4)


class TestSustainedCpuSaturation:
    def _series(self, times, value=100.0):
        return [(float(t), value) for t in times]

    def test_exactly_sixty_seconds_at_the_threshold_is_saturation(self):
        assert M.sustained_cpu_saturation(self._series(range(0, 61, 10)), percent=99.5, seconds=60,
                                          max_gap_seconds=20) == 60.0

    def test_one_tick_short_of_sixty_seconds_is_not(self):
        assert M.sustained_cpu_saturation(self._series(range(0, 60, 10)), percent=99.5, seconds=60,
                                          max_gap_seconds=20) is None

    def test_the_threshold_is_at_or_above_99_5(self):
        kwargs = dict(percent=99.5, seconds=60, max_gap_seconds=20)
        assert M.sustained_cpu_saturation(self._series(range(0, 61, 10), 99.5), **kwargs) == 60.0
        assert M.sustained_cpu_saturation(self._series(range(0, 61, 10), 99.499), **kwargs) is None

    def test_the_real_cadence_of_about_twelve_seconds_needs_six_ticks(self):
        kwargs = dict(percent=99.5, seconds=60, max_gap_seconds=20)
        assert M.sustained_cpu_saturation(self._series([0, 12, 24, 36, 48, 60]), **kwargs) == 60.0
        assert M.sustained_cpu_saturation(self._series([0, 12, 24, 36, 48]), **kwargs) is None

    def test_a_dip_below_the_threshold_resets_the_run(self):
        series = self._series([0, 10, 20, 30]) + [(40.0, 50.0)] + self._series([50, 60, 70, 80, 90])
        assert M.sustained_cpu_saturation(series, percent=99.5, seconds=60, max_gap_seconds=20) is None
        series += self._series([100, 110])
        assert M.sustained_cpu_saturation(series, percent=99.5, seconds=60, max_gap_seconds=20) == 60.0

    def test_a_failed_or_incomplete_tick_breaks_the_run(self):
        series = [(float(t), None if t == 30 else 100.0) for t in range(0, 71, 10)]
        assert M.sustained_cpu_saturation(series, percent=99.5, seconds=60, max_gap_seconds=20) is None

    def test_a_missing_intermediate_tick_is_a_gap_that_breaks_the_run(self):
        # ticks at 0,10,20 then 45 (a 25 s gap) then 55,65,75: neither side lasts 60 s
        assert M.sustained_cpu_saturation(self._series([0, 10, 20, 45, 55, 65, 75]), percent=99.5, seconds=60,
                                          max_gap_seconds=20) is None
        # the same ticks with no gap larger than allowed do last
        assert M.sustained_cpu_saturation(self._series([0, 10, 20, 40, 60]), percent=99.5, seconds=60,
                                          max_gap_seconds=20) == 60.0

    def test_a_gap_of_exactly_twice_the_interval_still_continues_and_a_hair_more_does_not(self):
        assert M.sustained_cpu_saturation(self._series([0, 20, 40, 60]), percent=99.5, seconds=60, max_gap_seconds=20) == 60.0
        assert M.sustained_cpu_saturation(self._series([0, 20.01, 40.02, 60.03]), percent=99.5, seconds=60,
                                          max_gap_seconds=20) is None

    def test_a_long_gap_resets_even_between_two_saturated_ticks(self):
        assert M.sustained_cpu_saturation(self._series([0, 100, 160]), percent=99.5, seconds=60, max_gap_seconds=20) is None

    def test_ticks_must_be_in_order(self):
        with pytest.raises(M.MetricError, match="time order"):
            M.sustained_cpu_saturation(self._series([10, 0]), percent=99.5, seconds=60, max_gap_seconds=20)

    def test_resource_stops_is_unchanged_for_historical_callers(self):
        saturated = [(t, 100.0) for t in range(0, 61, 10)]
        assert M.resource_stops(cpu_percent=saturated[:-1]) == ()
        assert M.resource_stops(cpu_percent=saturated) == ("CPU at or above 99.5% for 60 s",)
        assert M.resource_stops(cpu_percent=[(0, 100), (10, 100), (500, 100)]) == \
            ("CPU at or above 99.5% for 500 s",)                     # the old function never looked at gaps


class TestDockerMemoryAggregation:
    def test_a_complete_tick_is_summed_at_one_moment_and_peaks_are_never_added(self):
        samples = [(0.0, _dk_rows(kafka_mem=900, pg_mem=10)), (10.0, _dk_rows(kafka_mem=10, pg_mem=900))]
        ticks = M.docker_memory_ticks(samples, expected_containers=2)
        assert ticks == [(0.0, 910, 910), (10.0, 910, 910)]
        assert max(a for _, a, _ in ticks) == 910 != 900 + 900               # not the sum of the two peaks

    def test_an_incomplete_tick_gives_only_a_lower_bound(self):
        rows = [_dk_row("a", 1.0, 700)]
        assert M.docker_memory_ticks([(0.0, rows)], expected_containers=2) == [(0.0, None, 700)]

    def test_a_failed_sample_or_no_valid_row_gives_nothing(self):
        bad = [_dk_row("a", 1.0, -1), _dk_row("b", 1.0, True), {"name": "c", "memory_used_bytes": 1.5}, "x"]
        assert M.docker_memory_ticks([(0.0, None), (1.0, "x"), (2.0, bad)], expected_containers=2) == [
            (0.0, None, None), (1.0, None, None), (2.0, None, None)]

    def test_duplicate_names_and_extras_are_not_a_complete_tick(self):
        dup = [_dk_row("a", 1.0, 5), _dk_row("a", 1.0, 7)]
        assert M.docker_memory_ticks([(0.0, dup)], expected_containers=2) == [(0.0, None, 5)]
        extra = [_dk_row("a", 1.0, 5), _dk_row("b", 1.0, 6), _dk_row("c", 1.0, 7)]
        assert M.docker_memory_ticks([(0.0, extra)], expected_containers=2) == [(0.0, None, 18)]

    def test_the_threshold_is_ninety_percent_of_the_recorded_vm_and_exactly_ninety_is_allowed(self):
        vm = 1000
        at = lambda used: [(0.0, used, used)]                         # noqa: E731
        assert M.docker_memory_stops(at(900), vm_bytes=vm) == ()
        reason, = M.docker_memory_stops(at(901), vm_bytes=vm)
        assert "90.1%" in reason and "1000 bytes" in reason and "> 90%" in reason and "lower bound" not in reason

    def test_a_lower_bound_above_the_threshold_is_conclusive_and_one_below_proves_nothing(self):
        vm = 1000
        reason, = M.docker_memory_stops([(0.0, None, 950)], vm_bytes=vm)
        assert "lower bound" in reason
        assert M.docker_memory_stops([(0.0, None, 500), (10.0, None, None)], vm_bytes=vm) == ()

    def test_the_largest_share_is_reported_once(self):
        reasons = M.docker_memory_stops([(0.0, 910, 910), (10.0, 960, 960), (20.0, 920, 920)], vm_bytes=1000)
        assert len(reasons) == 1 and "96.0%" in reasons[0]

    @pytest.mark.parametrize("vm", [None, 0, -1, True, 5.0e9, "8"])
    def test_without_a_usable_vm_size_nothing_is_judged(self, vm):
        assert M.docker_memory_stops([(0.0, 10 ** 12, 10 ** 12)], vm_bytes=vm) == ()

    def test_the_existing_per_container_check_still_sees_what_it_always_saw(self):
        assert M.resource_stops(memory=[M.MemorySample("c", 95, 100)]) == ("c memory 95.0% of its limit > 90%",)


class TestUsableCoverage:
    def _cov(self, times, window=125.0, interval=10.0, **kw):
        return M.usable_coverage(times, window_seconds=window, interval=interval, **kw)

    def test_an_adequate_run_has_no_problems_and_reports_its_numbers(self):
        cov = self._cov(_DK_ADEQUATE)
        assert cov.problems == () and cov.usable == 13 and (cov.first, cov.last) == (0.0, 120.0)
        assert cov.max_gap == 10.0 and cov.fraction == pytest.approx(0.96)

    def test_the_rep8_pattern_is_adequate(self):
        times = [0.001, 11.567, 23.64, 35.736, 47.852, 59.599, 71.658, 83.787, 95.849, 107.938, 119.735]
        assert self._cov(times, window=124.6).problems == ()

    def test_at_least_five_usable_ticks(self):
        assert not [p for p in self._cov([0, 30, 60, 90, 120], window=120).problems if "usable ticks, fewer" in p]
        assert any("4 usable ticks, fewer than 5" in p for p in self._cov([0, 30, 60, 90], window=90).problems)
        assert any("0 usable ticks" in p for p in self._cov([]).problems)

    def test_eighty_percent_of_the_window_is_the_line(self):
        assert not [p for p in self._cov([0, 20, 40, 60, 80], window=100).problems if "of the window" in p]
        assert any("79%" in p for p in self._cov([0, 19.75, 39.5, 59.25, 79.0], window=100).problems)

    def test_the_first_and_last_ticks_must_be_near_the_window_edges(self):
        times = [20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]
        assert not [p for p in self._cov(times, window=140).problems if "window start" in p or "window end" in p]
        assert any("window start" in p for p in self._cov([20.1, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120], window=140).problems)
        assert any("window end" in p for p in self._cov([5, 15, 25, 35, 45, 55, 65, 75, 85, 95, 105], window=125.1).problems)

    def test_the_largest_gap_is_three_intervals(self):
        assert not [p for p in self._cov([0, 30, 31, 32, 33, 60, 90], window=90).problems if "gap" in p]
        assert any("gap of 30.5 s" in p for p in self._cov([0, 30.5, 31, 32, 33, 60, 90], window=90).problems)

    @pytest.mark.parametrize("window, interval", [(None, 10.0), (0, 10.0), (-5, 10.0), (True, 10.0),
                                                  (float("nan"), 10.0), (100.0, None), (100.0, 0), (100.0, True)])
    def test_an_unknown_window_or_interval_is_a_problem_not_a_guess(self, window, interval):
        assert self._cov(_DK_ADEQUATE, window=window, interval=interval).problems


class TestDockerResourceAssembly:
    def test_an_adequately_sampled_run_is_valid_and_records_the_observations(self):
        result = _dk_result()
        M.validate_result(result)
        assert result["verdict"] == "VALID" and result["integrity"]["ok"] is True
        gate = _gate(result)
        assert gate["ok"] is True and "13 usable ticks" in gate["evidence"]
        resources = result["metrics"]["resources"]
        cpu = resources["docker_vm_cpu_percent_series"]["benchmark-containers"]
        assert cpu["value"] == [30.0] * 13 and cpu["unit"] == "%" and cpu["kind"] == "OBSERVATION"
        assert resources["docker_vm_cpu_percent_max"]["benchmark-containers"]["value"] == 30.0
        assert resources["docker_vm_cpu_percent_series_times_s"]["benchmark-containers"]["value"][:3] == [0.0, 10.0, 20.0]
        assert resources["docker_memory_aggregate_bytes_max"]["benchmark-containers"]["value"] == 1_100_000_000
        fraction = resources["docker_memory_aggregate_fraction_max"]["benchmark-containers"]
        assert fraction["value"] == pytest.approx(1_100_000_000 / DK_VM) and fraction["unit"] == "fraction"
        coverage = resources["docker_resource_coverage"]
        assert coverage["ticks_attempted"]["value"] == 13 and coverage["cpu_ticks_usable"]["value"] == 13
        assert coverage["ncpu"]["value"] == 4 and coverage["vm_memory_bytes"]["value"] == DK_VM
        assert coverage["window_seconds"]["value"] == 125.0 and coverage["cpu_max_gap_s"]["value"] == 10.0
        assert coverage["cpu_window_fraction"]["value"] == pytest.approx(0.96)

    def test_the_limitations_describe_the_new_semantics_and_the_sampling_uncertainty(self):
        text = _dk_result()["limitations"]
        assert any("differ from SMALL-10 repetition 8 and every earlier cell" in t for t in text)
        assert any("not necessarily the exact physical memory" in t and "cannot see a spike" in t for t in text)
        assert any("judged only after the measured run" in t for t in text)

    def test_evidence_without_a_sampler_window_keeps_exactly_the_old_behaviour(self):
        evidence = _evidence()
        result = json.loads(json.dumps(RB.assemble_result(evidence, STOPS)))
        assert _gate(result) is None and len(result["integrity"]["gates"]) == 12
        assert not [n for n in result["metrics"]["resources"] if n.startswith("docker_")]
        assert not [t for t in result["limitations"] if "differ from SMALL-10 repetition 8" in t]
        M.validate_result(result)

    def test_too_few_ticks_make_the_run_invalid_with_every_claim_withdrawn(self):
        result = _dk_result(samples=_dk_samples([0, 10, 20, 30]))
        M.validate_result(result)
        assert result["verdict"] == "INVALID" and result["integrity"]["ok"] is False
        assert _gate(result)["ok"] is False and "fewer than 5" in _gate(result)["evidence"]
        assert result["claims"] == {k: False for k in result["claims"]}
        assert result["stop"]["reasons"] == []

    def test_a_complete_sampler_failure_is_invalid_and_not_zero(self):
        result = _dk_result(samples=[(float(t), None) for t in _DK_ADEQUATE])
        M.validate_result(result)
        assert result["verdict"] == "INVALID"
        resources = result["metrics"]["resources"]
        assert resources["docker_vm_cpu_percent_series"]["all"]["kind"] == "NOT_MEASURED"
        assert resources["docker_memory_aggregate_bytes_max"]["all"]["value"] is None
        assert resources["docker_resource_coverage"]["ticks_failed"]["value"] == 13
        assert resources["docker_resource_coverage"]["cpu_first_usable_s"]["kind"] == "NOT_MEASURED"

    def test_early_sampler_termination_is_invalid(self):
        result = _dk_result(samples=_dk_samples([0, 10, 20, 30, 40, 50, 60]))     # window runs to 125 s
        assert result["verdict"] == "INVALID"
        assert "window end" in _gate(result)["evidence"] or "of the window" in _gate(result)["evidence"]

    def test_a_missing_cpu_field_costs_only_the_cpu_observation(self):
        samples = [(t, [{**r, "cpu_percent": None} if r["name"] == "proj-pg-1" else r for r in rows])
                   for t, rows in _dk_samples(_DK_ADEQUATE)]
        result = _dk_result(samples=samples)
        assert result["verdict"] == "INVALID"
        assert "cpu: 0 usable ticks" in _gate(result)["evidence"] and "memory:" not in _gate(result)["evidence"]
        resources = result["metrics"]["resources"]
        assert resources["docker_vm_cpu_percent_series"]["all"]["kind"] == "NOT_MEASURED"
        assert resources["docker_memory_aggregate_bytes_series"]["benchmark-containers"]["kind"] == "OBSERVATION"

    def test_intermittent_failures_within_the_tolerance_stay_valid(self):
        samples = _dk_samples(_DK_ADEQUATE)
        samples[4] = (40.0, None)                                    # one failed docker stats call
        result = _dk_result(samples=samples)
        assert result["verdict"] == "VALID" and _gate(result)["ok"] is True
        assert result["metrics"]["resources"]["docker_resource_coverage"]["ticks_failed"]["value"] == 1
        assert len(result["metrics"]["resources"]["docker_vm_cpu_percent_series"]["benchmark-containers"]["value"]) == 12

    def test_two_failed_ticks_in_a_row_open_a_gap_above_three_intervals(self):
        samples = _dk_samples(_DK_ADEQUATE)
        samples[4] = (40.0, None)
        samples[5] = (50.0, None)
        samples[6] = (60.0, None)                                    # 30 -> 70: 40 s without a usable tick
        assert _dk_result(samples=samples)["verdict"] == "INVALID"

    def test_sustained_docker_cpu_saturation_is_stopped_with_its_reason(self):
        times = [10.0 * i for i in range(13)]
        result = _dk_result(samples=_dk_samples(times, kafka_cpu=300.0, pg_cpu=99.0))     # 399 / 4 = 99.75 %
        M.validate_result(result)
        assert result["verdict"] == "STOPPED" and _gate(result)["ok"] is True
        assert result["stop"]["reasons"] == ["Docker container CPU at or above 99.5% of 4 CPUs for 60 s"]
        assert result["claims"]["platform_throughput"] is False

    def test_a_saturation_shorter_than_sixty_seconds_is_not_a_stop(self):
        samples = [(t, _dk_rows(kafka_cpu=300.0, pg_cpu=99.0) if 20 <= t <= 70 else _dk_rows())
                   for t in _DK_ADEQUATE]                             # 50 s
        assert _dk_result(samples=samples)["verdict"] == "VALID"

    def test_one_failed_tick_inside_a_saturation_means_no_stop(self):
        samples = _dk_samples(_DK_ADEQUATE, kafka_cpu=300.0, pg_cpu=99.0)
        samples[6] = (60.0, None)
        result = _dk_result(samples=samples)
        assert result["stop"]["reasons"] == [] and result["verdict"] == "VALID"

    def test_host_cpu_never_counts_toward_the_docker_denominator(self):
        result = _dk_result(host_resource_samples=[(0.0, {"host_cpu_percent": 100.0, "processes": {}})],
                            host_resource_info={"interval": 10.0, "disk_volume": "C:\\", "keys": [], "errors": {},
                                                "unattributed": 0, "stop_problem": None})
        assert result["verdict"] == "VALID"
        assert result["metrics"]["resources"]["docker_vm_cpu_percent_max"]["benchmark-containers"]["value"] == 30.0

    def test_aggregate_memory_over_ninety_percent_of_the_vm_is_stopped_although_no_container_is(self):
        samples = _dk_samples(_DK_ADEQUATE, kafka_mem=int(0.46 * DK_VM), pg_mem=int(0.46 * DK_VM))
        samples = [(t, [{**r, "memory_limit_bytes": 100 * DK_VM} for r in rows]) for t, rows in samples]
        result = _dk_result(samples=samples)
        assert result["verdict"] == "STOPPED"
        assert len(result["stop"]["reasons"]) == 1 and result["stop"]["reasons"][0].startswith(
            "Docker containers memory 92.0% of the Docker VM's")

    def test_a_conclusive_lower_bound_stops_even_when_the_tick_is_incomplete(self):
        samples = _dk_samples(_DK_ADEQUATE)
        samples[3] = (30.0, [_dk_row("proj-kafka-1", 100.0, int(0.95 * DK_VM), 100 * DK_VM)])   # pg missing from this tick
        result = _dk_result(samples=samples)
        assert result["verdict"] == "STOPPED" and len(result["stop"]["reasons"]) == 1
        assert "(a measured lower bound)" in result["stop"]["reasons"][0]
        assert result["metrics"]["resources"]["docker_resource_coverage"]["memory_ticks_lower_bound_only"]["value"] == 1

    def test_an_incomplete_tick_below_the_limit_is_unavailable_not_an_aggregate(self):
        samples = _dk_samples(_DK_ADEQUATE)
        samples[3] = (30.0, [_dk_row("proj-kafka-1", 100.0, 5_000_000_000)])
        result = _dk_result(samples=samples)
        assert result["verdict"] == "VALID"
        series = result["metrics"]["resources"]["docker_memory_aggregate_bytes_series"]["benchmark-containers"]["value"]
        assert len(series) == 12 and 5_000_000_000 not in series

    def test_the_existing_per_container_memory_stop_still_applies_alongside(self):
        samples = [(t, [{**r, "memory_limit_bytes": 1_050_000_000} for r in rows]) for t, rows in _dk_samples(_DK_ADEQUATE)]
        result = _dk_result(samples=samples)
        assert result["verdict"] == "STOPPED"
        assert any("proj-kafka-1 memory" in r and "of its limit" in r for r in result["stop"]["reasons"])

    def test_verdict_precedence_invalid_outranks_stopped_and_the_reasons_are_kept(self):
        samples = _dk_samples(_DK_ADEQUATE, kafka_cpu=300.0, pg_cpu=99.0)
        result = _dk_result(samples=samples, machine={"os": "test", "docker": {"NCPU": 4}})    # MemTotal not recorded
        assert result["verdict"] == "INVALID" and "MemTotal was not recorded" in _gate(result)["evidence"]
        assert result["stop"]["reasons"] == ["Docker container CPU at or above 99.5% of 4 CPUs for 60 s"]

    def test_stopped_stays_stopped_when_the_coverage_is_adequate(self):
        assert _dk_result(samples=_dk_samples(_DK_ADEQUATE, kafka_cpu=300.0, pg_cpu=99.0))["verdict"] == "STOPPED"

    @pytest.mark.parametrize("machine, fragment", [
        ({"os": "test"}, "NCPU was not recorded"),
        ({"os": "test", "docker": {"NCPU": 4}}, "MemTotal was not recorded"),
        ({"os": "test", "docker": {"NCPU": 0, "MemTotal": DK_VM}}, "NCPU was not recorded"),
        ({"os": "test", "docker": {"NCPU": 4, "MemTotal": "8"}}, "MemTotal was not recorded"),
    ])
    def test_unrecorded_docker_capacity_is_invalid(self, machine, fragment):
        result = _dk_result(machine=machine)
        assert result["verdict"] == "INVALID" and fragment in _gate(result)["evidence"]

    def test_an_unknown_container_count_is_invalid(self):
        result = _dk_result(window={"stop_s": 125.0, "interval_s": 10.0, "expected_containers": 0})
        assert result["verdict"] == "INVALID" and "number of benchmark containers" in _gate(result)["evidence"]

    def test_malformed_samples_fail_closed_without_raising(self):
        samples = _dk_samples([10, 0, 20, 30, 40, 50, 60])
        result = _dk_result(samples=samples)
        assert result["verdict"] == "INVALID" and "could not be evaluated" in _gate(result)["evidence"]
        assert not [n for n in result["metrics"]["resources"] if n.startswith("docker_")]

    def test_the_sampling_window_is_the_samplers_not_the_sample_endpoints(self):
        near = _dk_result(window={"stop_s": 125.0, "interval_s": 10.0, "expected_containers": 2})
        far = _dk_result(window={"stop_s": 400.0, "interval_s": 10.0, "expected_containers": 2})
        assert near["verdict"] == "VALID" and far["verdict"] == "INVALID"

    def test_other_gates_and_verdict_rules_are_untouched_by_an_adequate_run(self):
        plain = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        hosted = _dk_result()
        assert [g for g in hosted["integrity"]["gates"] if g["name"] != "docker resource coverage"] == plain["integrity"]["gates"]
        assert hosted["claims"] == plain["claims"] and hosted["verdict"] == plain["verdict"]


# rep8's recorded Docker CPU series (the three containers share one tick time) and memory peaks
_REP8_TIMES = [0.001, 11.567, 23.64, 35.736, 47.852, 59.599, 71.658, 83.787, 95.849, 107.938, 119.735]
_REP8_CPU = {
    "agentops-workload-smoke-kafka-1": [172.78, 8.26, 2.99, 22.67, 15.95, 8.92, 111.37, 182.85, 76.23, 107.08, 85.75],
    "agentops-workload-smoke-otel-collector-1": [0.0, 0.42, 0.71, 2.39, 1.26, 1.05, 0.95, 0.1, 0.29, 0.0, 0.0],
    "agentops-workload-smoke-postgres-1": [1.29, 2.06, 3.84, 8.24, 3.55, 7.43, 5.35, 0.95, 3.36, 3.93, 0.03],
}
_REP8_MEMORY_PEAKS = {"agentops-workload-smoke-kafka-1": 656303718,
                      "agentops-workload-smoke-otel-collector-1": 51160023,
                      "agentops-workload-smoke-postgres-1": 49943675}
_REP8_MEMTOTAL = 5157535744


class TestRep8UnderTheNewRules:
    def _samples(self):
        names = sorted(_REP8_CPU)
        return [(at, [_dk_row(n, _REP8_CPU[n][i], _REP8_MEMORY_PEAKS[n], _REP8_MEMTOTAL) for n in names])
                for i, at in enumerate(_REP8_TIMES)]

    def _result(self):
        return _dk_result(samples=self._samples(), window={"stop_s": 124.6, "interval_s": 10.0, "expected_containers": 3},
                          machine={"os": "test", "docker": {"NCPU": 4, "MemTotal": _REP8_MEMTOTAL}})

    def test_the_embedded_values_are_rep8s_recorded_series_when_the_evidence_is_present(self):
        import glob
        files = glob.glob(os.path.join(os.environ.get("TEMP", ""), "agentops-benchmarks", "bm-small-r0010-c32-rep8-2*.json"))
        if not files:
            pytest.skip("the rep8 result is not on this machine")
        resources = json.loads(Path(files[0]).read_text(encoding="utf-8"))["metrics"]["resources"]
        for name, values in _REP8_CPU.items():
            assert resources["cpu_percent_series"][name]["value"] == values
            assert resources["cpu_percent_series_times_s"][name]["value"] == _REP8_TIMES
            assert resources["memory_peak_bytes"][name]["value"] == _REP8_MEMORY_PEAKS[name]

    def test_rep8_would_have_been_valid_with_adequate_coverage_and_no_stop(self):
        result = self._result()
        M.validate_result(result)
        assert result["verdict"] == "VALID" and result["stop"]["reasons"] == []
        assert _gate(result)["ok"] is True and "11 usable ticks" in _gate(result)["evidence"]

    def test_rep8_normalized_cpu_peaks_at_about_46_percent_of_the_four_cpus(self):
        cpu = self._result()["metrics"]["resources"]["docker_vm_cpu_percent_series"]["benchmark-containers"]["value"]
        assert len(cpu) == 11 and max(cpu) == pytest.approx(45.975, abs=1e-3) and min(cpu) == pytest.approx(1.885, abs=1e-3)
        assert not any(value >= 99.5 for value in cpu)

    def test_rep8_memory_is_bounded_by_the_sum_of_its_peaks_at_about_fifteen_percent(self):
        resources = self._result()["metrics"]["resources"]
        fraction = resources["docker_memory_aggregate_fraction_max"]["benchmark-containers"]["value"]
        assert resources["docker_memory_aggregate_bytes_max"]["benchmark-containers"]["value"] == 757407416
        assert fraction == pytest.approx(0.1469, abs=1e-4)

    def test_rep8_coverage_numbers(self):
        coverage = self._result()["metrics"]["resources"]["docker_resource_coverage"]
        assert coverage["cpu_max_gap_s"]["value"] == pytest.approx(12.129, abs=1e-3)
        assert coverage["cpu_window_fraction"]["value"] == pytest.approx((119.735 - 0.001) / 124.6, abs=1e-3)
        assert coverage["ticks_attempted"]["value"] == 11


class TestPeriodicSamplerWindow:
    def test_the_window_is_the_samplers_start_to_its_first_stop(self):
        ticks = iter([100.0, 107.5, 130.0])

        class Quiet(RB.PeriodicSampler):
            def start(self):
                self._started_at = self._clock()

        sampler = Quiet(lambda: 1, 10.0, clock=lambda: next(ticks))
        assert sampler.window is None
        sampler.start()
        sampler.stop()
        assert sampler.window == (0.0, 7.5)
        sampler.stop()                                                # a second stop does not move the window
        assert sampler.window == (0.0, 7.5)

    def test_a_sampler_that_never_started_has_no_window(self):
        sampler = RB.PeriodicSampler(lambda: 1, 10.0)
        sampler.stop()
        assert sampler.window is None


class TestDockerResourceValidation:
    def _valid(self):
        return _dk_result()

    @pytest.mark.parametrize("mutate, message", [
        (lambda r: r.pop("docker_vm_cpu_percent_series_times_s"), "incomplete"),
        (lambda r: r.pop("docker_resource_coverage"), "docker_resource_coverage is required"),
        (lambda r: r.__setitem__("docker_gpu_percent_max", r["docker_vm_cpu_percent_max"]), "not a Docker resource observation"),
        (lambda r: r["docker_vm_cpu_percent_max"]["benchmark-containers"].__setitem__("value", 99.0), "not the maximum"),
        (lambda r: r["docker_memory_aggregate_bytes_max"]["benchmark-containers"].__setitem__("value", 1), "not the maximum"),
        (lambda r: r["docker_vm_cpu_percent_series"]["benchmark-containers"].__setitem__("value", [30.0] * 12 + [-1.0]), "non-negative"),
        (lambda r: r["docker_vm_cpu_percent_series"]["benchmark-containers"].__setitem__("value", [30.0] * 12 + [151.0]), "at most 150"),
        (lambda r: r["docker_vm_cpu_percent_series_times_s"]["benchmark-containers"].__setitem__("value", [0.0]), "one time per value"),
        (lambda r: r["docker_vm_cpu_percent_series"]["benchmark-containers"].__setitem__("unit", "bytes"), "unit must be"),
        (lambda r: r["docker_vm_cpu_percent_series"]["benchmark-containers"].__setitem__("kind", "MEASURED"), "OBSERVATION"),
        (lambda r: r["docker_memory_aggregate_fraction_max"]["benchmark-containers"].__setitem__("value", 0.9), "not the peak over"),
        (lambda r: r["docker_memory_aggregate_fraction_max"]["benchmark-containers"].__setitem__("unit", "%"), "non-negative fraction"),
        (lambda r: r["docker_resource_coverage"]["ticks_failed"].__setitem__("value", 99), "more than the ticks attempted"),
        (lambda r: r["docker_resource_coverage"]["cpu_ticks_usable"].__setitem__("value", 5), "differs from the length"),
        (lambda r: r["docker_resource_coverage"]["memory_ticks_usable"].__setitem__("value", 5), "differs from the length"),
        (lambda r: r["docker_resource_coverage"]["window_seconds"].__setitem__("value", 0), "must be positive"),
        (lambda r: r["docker_resource_coverage"]["interval_seconds"].__setitem__("value", 0), "must be positive"),
        (lambda r: r["docker_resource_coverage"]["cpu_first_usable_s"].__setitem__("value", 999.0), "first cpu tick is after"),
        (lambda r: r["docker_resource_coverage"]["cpu_window_fraction"].__setitem__("value", 1.5), "more than 1"),
        (lambda r: r["docker_resource_coverage"]["ncpu"].__setitem__("value", 2.5), "whole number"),
        (lambda r: r["docker_resource_coverage"].__setitem__("bonus", r["docker_resource_coverage"]["ncpu"]), "not a coverage entry"),
        (lambda r: r["docker_resource_coverage"].pop("ticks_attempted"), "missing"),
    ])
    def test_a_malformed_docker_observation_is_refused(self, mutate, message):
        result = self._valid()
        mutate(result["metrics"]["resources"])
        with pytest.raises(M.MetricError, match=message):
            M.validate_result(result)

    def test_the_unmutated_result_and_the_not_measured_forms_are_accepted(self):
        M.validate_result(self._valid())
        M.validate_result(_dk_result(samples=[(float(t), None) for t in _DK_ADEQUATE]))

    def test_results_without_docker_observations_validate_and_other_names_are_left_alone(self):
        result = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        M.validate_result(result)
        assert M.docker_resource_problems(result["metrics"]["resources"]) == []
        assert M.docker_resource_problems(None) == [] and M.docker_resource_problems({"cpu_percent_max": {}}) == []

    def test_the_host_validation_still_works_after_sharing_its_family_check(self):
        result = _hr_result()
        M.validate_result(result)
        result["metrics"]["resources"]["host_cpu_percent_max"]["host"]["value"] = 1.0
        with pytest.raises(M.MetricError, match="not the maximum"):
            M.validate_result(result)

    def test_the_new_constants_and_the_unchanged_thresholds(self):
        assert (M.DOCKER_COVERAGE_MIN_TICKS, M.DOCKER_COVERAGE_MIN_FRACTION, M.DOCKER_COVERAGE_EDGE_FACTOR,
                M.DOCKER_COVERAGE_GAP_FACTOR, M.DOCKER_CPU_GAP_FACTOR) == (5, 0.80, 2.0, 3.0, 2.0)
        assert (M.CPU_SATURATION_PERCENT, M.CPU_SATURATION_SECONDS, M.MEMORY_FRACTION_MAX) == (99.5, 60.0, 0.90)
        assert (STOPS["cpu_saturation_percent"], STOPS["cpu_saturation_seconds"], STOPS["memory_fraction"]) == (99.5, 60, 0.90)


# ---------------------------------------------------------------------------
# B3J-299: the optional host-memory checkpoint group under metrics.resources
# ---------------------------------------------------------------------------

CP_MIB = 1024 ** 2
CP_THRESHOLD = 2048 * CP_MIB


def _cp_outcome(readings, status=None, threshold=CP_THRESHOLD):
    valid = [r for r in readings if r is not None]
    if len(valid) != len(readings):
        derived, minimum = "unavailable", None
    else:
        minimum = min(valid)
        derived = "below_threshold" if minimum < threshold else "ok"
    return {"readings": list(readings), "minimum": minimum, "threshold": threshold, "status": status or derived}


def _cp_result(readings=(3000 * CP_MIB, 3100 * CP_MIB, 3200 * CP_MIB), observed=None, **overrides):
    observed = {"before_startup": 4000 * CP_MIB, "stack_ready": 3900 * CP_MIB} if observed is None else observed
    outcome = None if readings is None else _cp_outcome(list(readings))
    if outcome is not None and "stop_reasons" not in overrides:         # a failed checkpoint always stops the cell
        reason = RB.host_memory_checkpoint_stop_reason(outcome)
        overrides["stop_reasons"] = [reason] if reason else []
    evidence = _evidence(host_memory_checkpoint=outcome, host_memory_observations=dict(observed), **overrides)
    return json.loads(json.dumps(RB.assemble_result(evidence, STOPS)))


class TestHostMemoryCheckpointEvidence:
    def test_a_passing_checkpoint_validates_and_holds_every_reading(self):
        result = _cp_result()
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        points = resources["host_memory_checkpoint_bytes"]
        assert points["before_startup"]["value"] == 4000 * CP_MIB and points["stack_ready"]["value"] == 3900 * CP_MIB
        assert points["after_warmup"]["value"] == [3000 * CP_MIB, 3100 * CP_MIB, 3200 * CP_MIB]
        assert points["after_warmup"]["n"] == 3 and points["after_warmup"]["unit"] == "bytes"
        assert resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["value"] == 3000 * CP_MIB
        assert resources["host_memory_checkpoint_threshold_bytes"]["after_warmup"]["value"] == CP_THRESHOLD
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == 0
        assert all(leaf["kind"] == "OBSERVATION" for leaf in points.values())

    def test_a_result_without_the_group_has_no_such_names_and_validates(self):
        result = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        assert not [n for n in result["metrics"]["resources"] if n.startswith("host_memory_checkpoint")]
        M.validate_result(result)
        assert M.host_memory_checkpoint_problems(result["metrics"]["resources"]) == []

    def test_the_checkpoint_needs_neither_the_host_sampler_families_nor_its_coverage(self):
        result = _cp_result()
        assert not [n for n in result["metrics"]["resources"] if n in ("host_sampling_coverage", "host_cpu_percent_max")]
        assert M.host_resource_problems(result["metrics"]["resources"]) == []
        M.validate_result(result)

    def test_the_checkpoint_and_the_host_sampler_fields_validate_together(self):
        result = _cp_result(host_resource_samples=copy.deepcopy(_HR_SAMPLES), host_resource_info=copy.deepcopy(_HR_INFO))
        M.validate_result(result)
        assert "host_sampling_coverage" in result["metrics"]["resources"]

    def test_observation_readings_alone_validate(self):
        result = _cp_result(readings=None)
        M.validate_result(result)
        assert list(result["metrics"]["resources"]["host_memory_checkpoint_bytes"]) == ["before_startup", "stack_ready"]
        assert "host_memory_checkpoint_minimum_bytes" not in result["metrics"]["resources"]

    def test_a_stopped_checkpoint_validates_with_the_readings_it_has(self):
        result = _cp_result(readings=(1000 * CP_MIB, 3000 * CP_MIB, 2900 * CP_MIB))
        M.validate_result(result)
        assert result["metrics"]["resources"]["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["value"] == 1000 * CP_MIB

    def test_one_unavailable_reading_keeps_the_valid_ones_and_has_no_minimum(self):
        result = _cp_result(readings=(3000 * CP_MIB, None, 3200 * CP_MIB))
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        assert resources["host_memory_checkpoint_bytes"]["after_warmup"]["value"] == [3000 * CP_MIB, 3200 * CP_MIB]
        assert resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["kind"] == "NOT_MEASURED"
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == 1

    def test_all_unavailable_is_not_measured_and_never_zero(self):
        result = _cp_result(readings=(None, None, None), observed={"before_startup": None, "stack_ready": 5})
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        assert resources["host_memory_checkpoint_bytes"]["after_warmup"]["kind"] == "NOT_MEASURED"
        assert resources["host_memory_checkpoint_bytes"]["before_startup"]["kind"] == "NOT_MEASURED"
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == 3

    def test_the_checkpoint_never_changes_the_verdict_claims_or_gates_of_a_complete_run(self):
        plain = json.loads(json.dumps(RB.assemble_result(_evidence(), STOPS)))
        with_cp = _cp_result()
        assert (with_cp["verdict"], with_cp["claims"], with_cp["integrity"]) == (plain["verdict"], plain["claims"], plain["integrity"])


class TestHostMemoryCheckpointValidation:
    def _valid(self):
        return _cp_result()

    @pytest.mark.parametrize("mutate, message", [
        (lambda r: r.__setitem__("host_memory_checkpoint_extra", r["host_memory_checkpoint_bytes"]), "not a host-memory checkpoint observation"),
        (lambda r: r["host_memory_checkpoint_bytes"].__setitem__("somewhere", r["host_memory_checkpoint_bytes"]["stack_ready"]), "not a known reading point"),
        (lambda r: r["host_memory_checkpoint_bytes"]["after_warmup"].__setitem__("value", [1, 2, 3, 4]), "3 or fewer"),
        (lambda r: r["host_memory_checkpoint_bytes"]["after_warmup"].__setitem__("value", [1, -2, 3]), "non-negative byte counts"),
        (lambda r: r["host_memory_checkpoint_bytes"]["after_warmup"].__setitem__("value", [1, True, 3]), "non-negative byte counts"),
        (lambda r: r["host_memory_checkpoint_bytes"]["after_warmup"].__setitem__("value", [1.5, 2, 3]), "non-negative byte counts"),
        (lambda r: r["host_memory_checkpoint_bytes"]["before_startup"].__setitem__("value", [1, 2]), "1 or fewer"),
        (lambda r: r["host_memory_checkpoint_bytes"]["before_startup"].__setitem__("unit", "%"), "byte counts"),
        (lambda r: r["host_memory_checkpoint_bytes"]["stack_ready"].__setitem__("kind", "MEASURED"), "byte counts"),
        (lambda r: r["host_memory_checkpoint_bytes"]["after_warmup"].__setitem__("n", 2), "n must equal"),
        (lambda r: r["host_memory_checkpoint_minimum_bytes"]["after_warmup"].__setitem__("value", 1), "not the smallest reading"),
        (lambda r: r["host_memory_checkpoint_minimum_bytes"]["after_warmup"].__setitem__("unit", "%"), "non-negative byte count"),
        (lambda r: r["host_memory_checkpoint_threshold_bytes"]["after_warmup"].__setitem__("value", 0), "positive byte count"),
        (lambda r: r["host_memory_checkpoint_threshold_bytes"]["after_warmup"].__setitem__("value", 2.5), "positive byte count"),
        (lambda r: r["host_memory_checkpoint_unavailable_readings"]["after_warmup"].__setitem__("value", 4), "0 to 3 readings"),
        (lambda r: r["host_memory_checkpoint_unavailable_readings"]["after_warmup"].__setitem__("value", 1), "do not add up"),
        (lambda r: r["host_memory_checkpoint_unavailable_readings"]["after_warmup"].__setitem__("value", 1), "present although a reading failed"),
        (lambda r: r.pop("host_memory_checkpoint_threshold_bytes"), "required with the after_warmup"),
        (lambda r: r.pop("host_memory_checkpoint_minimum_bytes"), "required with the after_warmup"),
        (lambda r: r.pop("host_memory_checkpoint_unavailable_readings"), "required with the after_warmup"),
        (lambda r: r.__setitem__("host_memory_checkpoint_bytes", [1, 2]), "must map a label"),
    ])
    def test_a_malformed_checkpoint_group_is_refused(self, mutate, message):
        result = self._valid()
        mutate(result["metrics"]["resources"])
        with pytest.raises(M.MetricError, match=message):
            M.validate_result(result)

    def test_the_minimum_must_be_missing_when_a_reading_failed_and_present_when_none_did(self):
        result = _cp_result(readings=(3000 * CP_MIB, None, 3200 * CP_MIB))
        result["metrics"]["resources"]["host_memory_checkpoint_minimum_bytes"]["after_warmup"] = \
            M.Metric(3000 * CP_MIB, "bytes", "OBSERVATION", "x", "y", None, 2).to_dict()
        with pytest.raises(M.MetricError, match="present although a reading failed"):
            M.validate_result(result)
        result = self._valid()
        result["metrics"]["resources"]["host_memory_checkpoint_minimum_bytes"]["after_warmup"] = \
            M.not_measured("bytes", "x", "none").to_dict()
        with pytest.raises(M.MetricError, match="missing although every reading was valid"):
            M.validate_result(result)

    @pytest.mark.parametrize("resources", [None, [], "x", {}, {"cpu_percent_max": {}}])
    def test_inputs_without_checkpoint_names_have_no_problems(self, resources):
        assert M.host_memory_checkpoint_problems(resources) == []

    def test_the_other_host_name_rules_still_hold_around_the_checkpoint_group(self):
        result = _cp_result(host_resource_samples=copy.deepcopy(_HR_SAMPLES), host_resource_info=copy.deepcopy(_HR_INFO))
        result["metrics"]["resources"]["host_gpu_percent_max"] = result["metrics"]["resources"]["host_cpu_percent_max"]
        with pytest.raises(M.MetricError, match="not a host resource observation"):
            M.validate_result(result)

    def test_the_recorded_rep8_and_rep9_results_still_validate_when_present(self):
        import glob
        base = os.path.join(os.environ.get("TEMP", ""), "agentops-benchmarks")
        found = sorted(glob.glob(os.path.join(base, "bm-small-r0010-c32-rep[89]-2*.json")))
        if len(found) < 2:
            pytest.skip("the rep8 and rep9 results are not on this machine")
        for path in found:
            result = json.loads(Path(path).read_text(encoding="utf-8"))
            assert "host_memory_checkpoint_bytes" not in result["metrics"]["resources"]
            M.validate_result(result)

    def test_the_resource_rules_and_thresholds_are_unchanged(self):
        assert (M.MEMORY_FRACTION_MAX, M.CPU_SATURATION_PERCENT, M.CPU_SATURATION_SECONDS) == (0.90, 99.5, 60.0)
        assert (M.DOCKER_COVERAGE_MIN_TICKS, M.DOCKER_COVERAGE_MIN_FRACTION) == (5, 0.80)
        assert M.HOST_MEMORY_CHECKPOINT_READINGS == RB.HOST_MEMORY_CHECKPOINT_READINGS == 3
        assert M.HOST_MEMORY_OBSERVATION_KEYS == RB.HOST_MEMORY_OBSERVATION_LABELS


# ---------------------------------------------------------------------------
# B3J-301: the checkpoint evidence against the verdict and the stop reasons; companions; partial readings
# ---------------------------------------------------------------------------

CP_BELOW = (1000 * CP_MIB, 3000 * CP_MIB, 3200 * CP_MIB)
CP_PARTIAL = (3000 * CP_MIB, None, 3200 * CP_MIB)
CP_ALL_GOOD = (3000 * CP_MIB, 3100 * CP_MIB, 3200 * CP_MIB)


def _reason_for(readings):
    return RB.host_memory_checkpoint_stop_reason(_cp_outcome(list(readings)))


def _validate_with(result, verdict=None, reasons=None):
    """result with its verdict / stop reasons replaced (claims and generator_bound kept consistent)."""
    result = copy.deepcopy(result)
    if reasons is not None:
        result.setdefault("stop", {"generator_bound": False})["reasons"] = list(reasons)
    if verdict is not None:
        result["verdict"] = verdict
        result["claims"] = M.claim_eligibility(verdict, result["clock"]["valid"], False)
    return result


class TestCheckpointVerdictConsistency:
    """assemble_result validates what it builds, so a contradictory result can only be made by changing a
    consistent one; each test starts from a valid result and alters its verdict, stop reasons or evidence."""

    @pytest.mark.parametrize("readings", [CP_BELOW, CP_PARTIAL, (None, None, None)])
    def test_a_failing_checkpoint_with_its_reason_and_a_stopped_verdict_validates(self, readings):
        result = _cp_result(readings=readings)
        assert result["verdict"] == "STOPPED" and result["stop"]["reasons"] == [_reason_for(readings)]
        M.validate_result(result)

    def test_assemble_result_itself_refuses_a_failing_checkpoint_without_its_reason(self):
        with pytest.raises(M.MetricError, match="no matching checkpoint stop reason is recorded"):
            _cp_result(readings=CP_BELOW, stop_reasons=[])

    @pytest.mark.parametrize("readings", [CP_BELOW, CP_PARTIAL])
    @pytest.mark.parametrize("verdict", ["VALID", "GENERATOR_BOUND"])
    def test_a_failing_checkpoint_cannot_coexist_with_a_valid_or_generator_bound_verdict(self, readings, verdict):
        forced = _validate_with(_cp_result(readings=readings), verdict=verdict, reasons=[])
        with pytest.raises(M.MetricError, match=f"the host-memory checkpoint failed but the verdict is {verdict}"):
            M.validate_result(forced)

    @pytest.mark.parametrize("readings", [CP_BELOW, CP_PARTIAL])
    def test_a_failing_checkpoint_without_its_stop_reason_is_refused_whatever_else_is_recorded(self, readings):
        forced = _validate_with(_cp_result(readings=readings), reasons=["some other reason"])
        with pytest.raises(M.MetricError, match="no matching checkpoint stop reason is recorded"):
            M.validate_result(forced)

    def test_a_failing_checkpoint_with_no_stop_reason_at_all_is_refused(self):
        forced = _validate_with(_cp_result(readings=CP_BELOW), verdict="VALID", reasons=[])
        problems = []
        try:
            M.validate_result(forced)
        except M.MetricError as exc:
            problems = str(exc)
        assert "failed but the verdict is VALID" in problems and "no matching checkpoint stop reason" in problems

    def test_a_reason_of_the_wrong_kind_is_refused(self):
        for readings, wrong in ((CP_BELOW, CP_PARTIAL), (CP_PARTIAL, CP_BELOW)):
            forced = _validate_with(_cp_result(readings=readings), reasons=[_reason_for(wrong)])
            with pytest.raises(M.MetricError, match="names a failure the checkpoint evidence does not show"):
                M.validate_result(forced)

    def test_both_kinds_of_reason_recorded_for_one_failure_are_refused(self):
        forced = _validate_with(_cp_result(readings=CP_BELOW), reasons=[_reason_for(CP_BELOW), _reason_for(CP_PARTIAL)])
        with pytest.raises(M.MetricError, match="names a failure the checkpoint evidence does not show"):
            M.validate_result(forced)

    @pytest.mark.parametrize("failure", [CP_BELOW, CP_PARTIAL])
    def test_a_successful_checkpoint_with_a_checkpoint_stop_reason_is_refused(self, failure):
        good = _cp_result(readings=CP_ALL_GOOD)
        assert good["verdict"] == "VALID"
        forced = _validate_with(good, verdict="STOPPED", reasons=[_reason_for(failure)])
        with pytest.raises(M.MetricError, match="checkpoint evidence shows no failure"):
            M.validate_result(forced)

    def test_a_spurious_checkpoint_reason_without_any_checkpoint_evidence_is_refused(self):
        base = json.loads(json.dumps(RB.assemble_result(_evidence(stop_reasons=["cell budget of 2 s exceeded before x"]), STOPS)))
        forced = _validate_with(base, reasons=[_reason_for(CP_BELOW)])
        with pytest.raises(M.MetricError, match="checkpoint evidence shows no failure"):
            M.validate_result(forced)

    def test_an_unrecognised_checkpoint_reason_is_refused(self):
        forced = _validate_with(_cp_result(readings=CP_BELOW), reasons=[_reason_for(CP_BELOW), "host memory checkpoint: odd"])
        with pytest.raises(M.MetricError, match="unrecognised checkpoint stop reason"):
            M.validate_result(forced)

    def test_evidence_edited_to_hide_a_failure_is_caught_by_the_reason(self):
        forced = _cp_result(readings=CP_BELOW)
        resources = forced["metrics"]["resources"]
        resources["host_memory_checkpoint_bytes"]["after_warmup"]["value"] = list(CP_ALL_GOOD)
        resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["value"] = min(CP_ALL_GOOD)
        with pytest.raises(M.MetricError, match="checkpoint evidence shows no failure"):
            M.validate_result(forced)

    def test_a_passing_checkpoint_with_no_reason_validates_and_other_stop_reasons_are_none_of_its_business(self):
        result = _cp_result(readings=CP_ALL_GOOD)
        M.validate_result(result)
        assert result["verdict"] == "VALID"
        other = _cp_result(readings=CP_ALL_GOOD, stop_reasons=["cell budget of 2 s exceeded before the measured run"])
        assert other["verdict"] == "STOPPED"
        M.validate_result(other)

    def test_other_stop_reasons_alongside_a_checkpoint_failure_are_fine(self):
        result = _cp_result(readings=CP_BELOW, stop_reasons=["cell budget of 2 s exceeded before x", _reason_for(CP_BELOW)])
        M.validate_result(result)

    def test_invalid_may_carry_a_failing_checkpoint(self):
        forced = _validate_with(_cp_result(readings=CP_BELOW), verdict="INVALID")
        forced["integrity"]["ok"] = False
        forced["integrity"]["gates"] = [{"name": "x", "ok": False, "evidence": "e"}]
        M.validate_result(forced)                            # INVALID outranks STOPPED; the reason is kept

    def test_historical_results_without_checkpoint_evidence_or_reason_are_untouched(self):
        for evidence in (_evidence(), _evidence(stop_reasons=["cell budget of 2 s exceeded before x"])):
            M.validate_result(json.loads(json.dumps(RB.assemble_result(evidence, STOPS))))
        assert M.host_memory_checkpoint_consistency_problems(None, [], "VALID") == []
        assert M.host_memory_checkpoint_consistency_problems({}, ["other"], "STOPPED") == []
        assert M.host_memory_checkpoint_consistency_problems({"cpu_percent_max": {}}, None, "VALID") == []

    def test_observation_only_evidence_neither_fails_nor_needs_a_reason(self):
        result = _cp_result(readings=None)
        M.validate_result(result)
        assert M.host_memory_checkpoint_consistency_problems(result["metrics"]["resources"], [], "VALID") == []

    def test_the_older_verdict_rules_and_their_precedence_are_unchanged(self):
        assert M.verdict(integrity_ok=None, stop_reasons=["x"], generator_bound_run=False) == "STOPPED"
        assert M.verdict(integrity_ok=False, stop_reasons=["x"], generator_bound_run=True) == "INVALID"
        assert M.verdict(integrity_ok=True, stop_reasons=[], generator_bound_run=True) == "GENERATOR_BOUND"
        assert M.verdict(integrity_ok=True, stop_reasons=[], generator_bound_run=False) == "VALID"


class TestCheckpointCompanions:
    def _valid(self):
        return _cp_result(readings=CP_ALL_GOOD)

    @pytest.mark.parametrize("name", ["host_memory_checkpoint_minimum_bytes", "host_memory_checkpoint_threshold_bytes",
                                      "host_memory_checkpoint_unavailable_readings"])
    def test_every_companion_is_required_with_the_after_warmup_reading(self, name):
        result = self._valid()
        del result["metrics"]["resources"][name]
        with pytest.raises(M.MetricError, match=f"{name}: required with the after_warmup"):
            M.validate_result(result)

    @pytest.mark.parametrize("present", ["host_memory_checkpoint_minimum_bytes", "host_memory_checkpoint_threshold_bytes",
                                         "host_memory_checkpoint_unavailable_readings"])
    def test_a_companion_without_the_after_warmup_reading_is_refused(self, present):
        result = self._valid()
        resources = result["metrics"]["resources"]
        del resources["host_memory_checkpoint_bytes"]["after_warmup"]
        for name in M.HOST_MEMORY_CHECKPOINT_COMPANIONS:
            if name != present:
                del resources[name]
        problems = M.host_memory_checkpoint_problems(resources)
        assert any("companion metrics without the after_warmup reading" in p for p in problems)

    def test_companions_without_any_reading_group_are_refused(self):
        result = self._valid()
        del result["metrics"]["resources"]["host_memory_checkpoint_bytes"]
        with pytest.raises(M.MetricError, match="companion metrics without the after_warmup reading"):
            M.validate_result(result)

    def test_all_companions_deleted_but_the_reading_kept_is_refused(self):
        result = self._valid()
        for name in M.HOST_MEMORY_CHECKPOINT_COMPANIONS:
            del result["metrics"]["resources"][name]
        problems = M.host_memory_checkpoint_problems(result["metrics"]["resources"])
        assert len([p for p in problems if "required with the after_warmup" in p]) == 3

    @pytest.mark.parametrize("name", ["host_memory_checkpoint_minimum_bytes", "host_memory_checkpoint_threshold_bytes",
                                      "host_memory_checkpoint_unavailable_readings"])
    @pytest.mark.parametrize("broken", [[], "x", {}, {"other": 1}])
    def test_a_companion_that_does_not_map_after_warmup_is_refused(self, name, broken):
        result = self._valid()
        result["metrics"]["resources"][name] = broken
        with pytest.raises(M.MetricError, match=f"{name}: must map after_warmup"):
            M.validate_result(result)

    def test_a_not_measured_threshold_or_count_is_refused_but_a_not_measured_minimum_is_allowed_when_one_failed(self):
        result = _cp_result(readings=CP_PARTIAL)
        M.validate_result(result)                            # the minimum is NOT_MEASURED here
        result["metrics"]["resources"]["host_memory_checkpoint_threshold_bytes"]["after_warmup"] = \
            M.not_measured("bytes", "x", "none").to_dict()
        with pytest.raises(M.MetricError, match="threshold_bytes: a positive byte count"):
            M.validate_result(result)
        result = _cp_result(readings=CP_PARTIAL)
        result["metrics"]["resources"]["host_memory_checkpoint_unavailable_readings"]["after_warmup"] = \
            M.not_measured("readings", "x", "none").to_dict()
        with pytest.raises(M.MetricError, match="a count is measured, not NOT_MEASURED"):
            M.validate_result(result)

    def test_a_missing_minimum_with_every_reading_valid_is_refused(self):
        result = self._valid()
        result["metrics"]["resources"]["host_memory_checkpoint_minimum_bytes"]["after_warmup"] = \
            M.not_measured("bytes", "x", "none").to_dict()
        with pytest.raises(M.MetricError, match="missing although every reading was valid"):
            M.validate_result(result)

    def test_a_minimum_inconsistent_with_the_readings_is_refused(self):
        result = self._valid()
        result["metrics"]["resources"]["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["value"] = 3100 * CP_MIB
        with pytest.raises(M.MetricError, match="not the smallest reading"):
            M.validate_result(result)

    @pytest.mark.parametrize("readings, valid_count, unavailable", [
        (CP_PARTIAL, 2, 1), ((None, 3000 * CP_MIB, None), 1, 2), ((None, None, None), 0, 3)])
    def test_partial_and_total_unavailability_are_represented_and_add_up(self, readings, valid_count, unavailable):
        result = _cp_result(readings=readings)
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        leaf = resources["host_memory_checkpoint_bytes"]["after_warmup"]
        assert (leaf["n"] if leaf["kind"] != "NOT_MEASURED" else 0) == valid_count
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == unavailable
        assert resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["kind"] == "NOT_MEASURED"

    @pytest.mark.parametrize("count", [0, 1, 2, 3])
    def test_contradictory_reading_counts_are_refused(self, count):
        result = _cp_result(readings=CP_PARTIAL)                    # two valid readings, one unavailable
        result["metrics"]["resources"]["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] = count
        if count == 1:
            M.validate_result(result)
        else:
            with pytest.raises(M.MetricError):
                M.validate_result(result)

    def test_an_unknown_checkpoint_name_is_still_refused(self):
        result = self._valid()
        result["metrics"]["resources"]["host_memory_checkpoint_status"] = result["metrics"]["resources"]["host_memory_checkpoint_bytes"]
        with pytest.raises(M.MetricError, match="not a host-memory checkpoint observation"):
            M.validate_result(result)

"""
benchmarks/tests/test_run_cell.py

Offline tests of one benchmark cell, driven end to end with a fake D3
harness and fake E2E helpers.  No process, socket, container, database or
telemetry is used: the `no_live_access` fixture makes any attempt fail.
"""

from __future__ import annotations

import dataclasses
import importlib.abc
import os
import json
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

_BENCH = Path(__file__).resolve().parents[1]
_REPO = _BENCH.parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import metrics as M  # noqa: E402
import run_benchmark as RB  # noqa: E402

LADDER = json.loads((_BENCH / "ladder.json").read_text(encoding="utf-8"))
SHA = "b" * 40
GB = 1024 ** 3


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


@pytest.fixture(autouse=True)
def no_live_access(monkeypatch):
    def refuse(*args, **kwargs):
        raise LiveAccessAttempt(f"live access attempted: {args[:1]}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(RB, "local_platform_info", lambda: {"os": "test"})


#: The real pre-claim checks (B3J-103), for tests that exercise them; every other test
#: runs with them replaced, as it runs with a fake harness: they would otherwise look at
#: the real repository and the real canonical output directory.
REAL_CHECK_LIVE_OUTPUT_DIR = RB.check_live_output_dir
REAL_VERIFY_REPOSITORY = RB.verify_repository_readonly


@pytest.fixture(autouse=True)
def pre_claim_checks_replaced(monkeypatch):
    monkeypatch.setattr(RB, "check_live_output_dir", lambda output_dir: Path(output_dir).resolve())
    monkeypatch.setattr(RB, "verify_repository_readonly",
                        lambda expect_head, **kw: {"head": expect_head, "branch": "test-branch"})


class Boom(RuntimeError):
    pass


def timed_series_payload(seconds=22, rows=700, start=4999, **changes):
    """What run_series_sql returns for a run of `rows` spans: 35 a second ended in
    seconds 0-19 and ingested one second later (offsets 1-20), 40 ms each."""
    ended = [35 if 0 <= i < 20 else 0 for i in range(seconds)]
    ingested = [35 if 1 <= i <= 20 else 0 for i in range(seconds)]
    offsets = [i for i, c in enumerate(ingested) if c]
    payload = {"start_epoch_s": start, "end_epoch_s": start + seconds - 1, "rows": rows,
               "cap_seconds": RB.MAX_TIMED_SERIES_SECONDS, "ended": ended, "ingested": ingested,
               "latency_offsets": offsets, "latency_mean_ms": [40.0] * len(offsets),
               "latency_max_ms": [45.5] * len(offsets)}
    payload.update(changes)
    return payload


def gap_series_payload(seconds=22, rows=700, start=4999, **changes):
    """What run_gap_sql returns for the same run as timed_series_payload: 35 rows a
    second ingested in seconds 1-20, three partitions (12 + 12 + 11 a second), each gap
    between 5 and 30 ms.  The first row (in second 1) has no gap."""
    ingested = [35 if 1 <= i <= 20 else 0 for i in range(seconds)]
    offsets = [i for i, c in enumerate(ingested) if c]
    payload = {
        "start_epoch_s": start, "end_epoch_s": start + seconds - 1, "rows": rows,
        "cap_seconds": RB.MAX_TIMED_SERIES_SECONDS, "stall_ms": RB.STALL_GAP_MS,
        "partition_limit": RB.MAX_GAP_PARTITIONS, "first_row_offset": 1,
        "gap_count": rows - 1, "gap_p50_ms": 14.0, "gap_p90_ms": 20.0, "gap_p99_ms": 28.0,
        "gap_max_ms": 30.0, "stall_gaps": 0, "ingested": ingested,
        "gap_offsets": offsets, "gap_counts": [34] + [35] * (len(offsets) - 1),
        "gap_median_ms": [14.0] * len(offsets), "gap_max_by_second_ms": [30.0] * len(offsets),
        "gap_stall_counts": [0] * len(offsets),
        "partitions": [
            {"partition": 0, "rows": 240, "min_offset": 0, "max_offset": 239,
             "distinct_offsets": 240, "per_second": [12 if 1 <= i <= 20 else 0 for i in range(seconds)]},
            {"partition": 1, "rows": 240, "min_offset": 0, "max_offset": 239,
             "distinct_offsets": 240, "per_second": [12 if 1 <= i <= 20 else 0 for i in range(seconds)]},
            {"partition": 2, "rows": 220, "min_offset": 0, "max_offset": 219,
             "distinct_offsets": 220, "per_second": [11 if 1 <= i <= 20 else 0 for i in range(seconds)]}]}
    payload.update(changes)
    return payload


class FakeSmoke:
    """Records every call; `fail` names the step that raises."""

    GROUP_STREAM, GROUP_STORAGE = "d3-stream-processor", "d3-storage-consumer"
    TOPIC_RAW, TOPIC_SPANS, TOPIC_DLQ = "raw", "spans", "dlq"
    POSTGRES_PORT, T_COMMAND = 15432, 60.0

    def __init__(self, tmp: Path, *, fail: str = "", cleanup_ok: bool = True,
                 stats: str = "proj-kafka-1|5.0%|100MiB / 1GiB\nproj-pg-1|1.0%|50MiB / 1GiB",
                 lag=0, clock=(1000.0, 1000.001, 1000.002), late_starts=0, dlq=0,
                 series=None, gap=None):
        self.calls: list[str] = []
        self.fail, self.cleanup_ok, self.stats, self.lag = fail, cleanup_ok, stats, lag
        self.clock_sample, self.late_starts, self.dlq = clock, late_starts, dlq
        self.series = series if series is not None else timed_series_payload()
        self.gap = gap if gap is not None else gap_series_payload()
        self.RATE = self.SEED = self.CONCURRENCY = None
        self.T_DRAIN = self.SETTLE_SECONDS = None
        self.RUN = SimpleNamespace(temp=tmp, python=Path("python"),
                                   generated={"POSTGRES_PASSWORD": "never-printed"})
        self.stage_ids: list[str] = []
        self.psql_sql: list[str] = []
        self.commands: list[list[str]] = []
        self.offsets = {"raw": 0, "spans": 0, "dlq": 0}

    def _step(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise Boom(f"{name} failed")

    # -- stack ----------------------------------------------------------------
    def git(self, *args):
        return SHA + "\n"

    def repository_state(self):
        return []

    def __getattr__(self, name):
        if name in ("check_repository", "check_ports", "record_docker_state", "create_workspace",
                    "create_virtual_environment", "check_render", "start_kafka", "create_topics",
                    "start_postgres", "run_bootstrap", "start_collector", "start_host_services",
                    "check_host_processes", "stop_host_processes"):
            return lambda *args, **kwargs: self._step(name)
        raise AttributeError(name)

    def host_environment(self, **extra):
        return {"PATH": "x", **extra}

    def check_normal_stack(self, when):
        self._step("check_normal_stack")

    def check_baseline(self):
        self._step("check_baseline")
        return dict(self.offsets)

    def Stage(self, **kwargs):
        return SimpleNamespace(**kwargs)

    def planned_facts(self, stage):
        return {"digest": "d" * 64}

    def run_stage(self, stage, offsets):
        warm = stage.run_id.split("-")[-1].startswith("w")
        self._step("run_stage_warmup" if warm else "run_stage_measured")
        self.stage_ids.append(stage.run_id)
        self.offsets = {"raw": offsets["raw"] + stage.traces,
                        "spans": offsets["spans"] + stage.spans,
                        "dlq": offsets["dlq"] + (0 if warm else self.dlq)}
        finished = datetime.fromtimestamp(5000.0, tz=timezone.utc).isoformat()
        report = {"execution": {
            "started": datetime.fromtimestamp(4980.0, tz=timezone.utc).isoformat(),
            "finished": finished, "elapsed_seconds": 20.0,
            "executed_attempts": stage.traces, "started_requests": stage.traces,
            "not_started_requests": 0, "spans_ended": stage.spans,
            "spans_exported_successfully": stage.spans, "export_failures": 0,
            "flush_ok": True, "run_status": "completed", "problems": [],
            "achieved_submission_rate": stage.traces / 20.0,
            "late_starts": self.late_starts}}
        (self.RUN.temp / f"{stage.run_id}.json").write_text(json.dumps(report), encoding="utf-8")
        return dict(self.offsets)

    def compose(self, *args, **kwargs):
        self._step("compose_" + args[0])
        return "id-kafka\nid-pg\n"

    def group_lag(self, group, topic):
        if isinstance(self.lag, Exception):
            raise self.lag
        return self.lag

    def checked(self, command, *, timeout, what, env=None, **kwargs):
        self.commands.append(list(command))
        if command[:2] == ["docker", "stats"]:
            self._step("docker_stats")
            return self.stats
        if len(command) > 1 and command[1] == "-c":
            self._step("clock_probe")
            assert env and "PGPASSWORD" in env
            return json.dumps([list(self.clock_sample)])
        if command[:2] == ["docker", "info"]:
            return json.dumps({"ServerVersion": "29", "NCPU": 8, "MemTotal": 8 * GB})
        return "ok"

    def psql(self, sql):
        self._step("psql")
        self.psql_sql.append(sql)
        if "gap_ms" in sql:                                # the optional ingest-gap query
            return json.dumps(self.gap)
        if "generate_series" in sql:                       # the optional per-second query
            return json.dumps(self.series)
        rows = 700
        return json.dumps({
            "rows": rows, "distinct_spans": rows, "roots": 100,
            "first_ingested": 5000.0, "last_ingested": 5020.0,
            "request_ms": [250.0] * 100, "persistence_ms": [40.0] * rows,
            "per_second": [35] * 20})

    def run(self, command, *, timeout, what, **kwargs):
        self._step("refresh_run")
        self.commands.append(list(command))
        code = 3 if self.fail == "refresh_exit" else 0
        return subprocess.CompletedProcess(
            command, code, "Finished running 9 view models in 0 hours 0 minutes and 2.5 "
            "seconds", "")

    def cleanup(self):
        self.calls.append("cleanup")
        if self.fail == "cleanup_raises":
            raise Boom("cleanup")
        return self.cleanup_ok


class FakeE2E:
    REFRESH_SERVICE = "analytics-refresh"

    def __init__(self, smoke: FakeSmoke, *, ledger_changes: bool = False):
        self.smoke, self.ledger_changes, self.ledger_reads = smoke, ledger_changes, 0

    def build_refresh_image(self):
        self.smoke._step("build_refresh_image")

    def refresh_command(self, *args):
        return ["docker", "compose", "--profile", "analytics-refresh", *args]

    def ledger_fingerprint(self):
        self.ledger_reads += 1
        return "18 steps, x" if not (self.ledger_changes and self.ledger_reads > 1) else "18"

    def run_detector(self, label):
        self.smoke._step("run_detector")
        return ([{"signal_path": "trace_latency", "operation_name": "agentops.request",
                  "duration_ms": "12.5", "candidates": "1300", "emitted": "22",
                  "inserted": "22", "duplicate": "0"},
                 {"signal_path": "tool_failure", "operation_name": "", "duration_ms": "3",
                  "candidates": "1300", "emitted": "0", "inserted": "0", "duplicate": "0"}], {})

    def remove_profile_resources(self):
        self.smoke.calls.append("remove_profile_resources")


class FakeSampler:
    """Samples once at start and once at stop, synchronously, like the real
    one: a sample that raises is kept as None."""

    instances: list["FakeSampler"] = []

    def __init__(self, sample, interval):
        self.sample, self.samples, self.errors, self.stops = sample, [], [], 0
        FakeSampler.instances.append(self)

    def _take(self, at):
        try:
            self.samples.append((at, self.sample()))
        except Exception as exc:
            self.samples.append((at, None))
            self.errors.append((at, str(exc)))

    def start(self):
        self._take(0.0)

    def stop(self):
        self.stops += 1
        if self.stops == 1:
            self._take(10.0)


def _cell(level="SMOKE", **changes):
    cell = RB.plan_cells(LADDER, level, rates=[5 if level == "SMOKE" else
                                             LADDER["levels"][[n for n, _ in M.LEVELS]
                                                              .index(level)]["rates"][0]],
                         repetitions=1)[0]
    return dataclasses.replace(cell, **changes) if changes else cell


def _run(tmp_path, *, smoke=None, e2e=None, cell=None, disk=500 * GB, clock=None, ladder=None,
         out=None):
    smoke = smoke or FakeSmoke(tmp_path)
    e2e = e2e or FakeE2E(smoke)
    ticks = iter(range(10 ** 6))
    result, path, clean = REAL_EXECUTE_CELL(
        cell or _cell(), ladder or LADDER, smoke=smoke, e2e=e2e, expect_head=None,
        output_dir=out or (tmp_path / "results"), disk_free=lambda: disk,
        clock=clock or (lambda: float(next(ticks))),
        wall=lambda: 5003.0, sampler_factory=FakeSampler)
    return result, path, clean, smoke


ORDER = ["check_repository", "check_ports", "record_docker_state", "create_workspace",
         "create_virtual_environment", "check_render", "start_kafka", "create_topics",
         "start_postgres", "run_bootstrap", "build_refresh_image", "start_collector",
         "start_host_services", "check_baseline", "run_stage_warmup", "clock_probe",
         "compose_ps", "docker_stats", "run_stage_measured", "docker_stats", "psql",
         "clock_probe", "psql", "psql", "check_host_processes", "refresh_run", "run_detector",
         "check_normal_stack", "stop_host_processes", "remove_profile_resources", "cleanup"]


class TestSuccess:
    def test_full_cell_is_valid(self, tmp_path):
        result, path, clean, smoke = _run(tmp_path)
        assert clean and result["verdict"] == "VALID"
        assert smoke.calls == ORDER
        assert path.parent == (tmp_path / "results").resolve() and path.is_file()
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))
        assert (smoke.RATE, smoke.SEED, smoke.CONCURRENCY) == (5, 42, 32)
        assert smoke.T_DRAIN == 120.0 and smoke.SETTLE_SECONDS == 6.0

    def test_warmup_is_excluded_from_measured_counts(self, tmp_path):
        result, _, _, smoke = _run(tmp_path)
        cell = _cell()
        assert smoke.stage_ids == [cell.warmup_run_id, cell.measured_run_id]
        assert result["counts"]["canonical_records"] == 700        # not 700 + warm-up
        assert result["counts"]["raw_records"] == 100
        assert len(smoke.psql_sql) == 3            # the required query and two optional ones
        for sql in smoke.psql_sql:
            assert cell.measured_run_id in sql
            assert cell.warmup_run_id not in sql

    def test_timing_kinds(self, tmp_path):
        analytics = _run(tmp_path)[0]["metrics"]["analytics"]
        assert analytics["refresh_seconds"]["kind"] == "OBSERVATION"
        assert analytics["refresh_dbt_seconds"] == {**analytics["refresh_dbt_seconds"],
                                                   "kind": "MEASURED", "value": 2.5}
        detector = analytics["detector_ms"]
        assert detector["trace_latency/agentops.request"]["kind"] == "MEASURED"
        assert detector["trace_latency/agentops.request"]["value"] == 12.5
        (tmp_path / "b").mkdir()
        lag = _run(tmp_path / "b")[0]["metrics"]["lag"]
        assert lag["stage_tail_seconds"]["kind"] == "OBSERVATION"
        assert lag["stage_tail_seconds"]["value"] == 3
        assert lag["drain_seconds"]["kind"] == "NOT_MEASURED"

    def test_resource_sampling_is_limited_to_project_containers(self, tmp_path):
        _, _, _, smoke = _run(tmp_path)
        stats = [c for c in smoke.commands if c[:2] == ["docker", "stats"]]
        assert stats and all(c[-2:] == ["id-kafka", "id-pg"] for c in stats)
        assert all("--no-stream" in c for c in stats)

    def test_dbt_duration_missing_is_not_measured(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        smoke.run = lambda command, **kw: (smoke.calls.append("refresh_run") or
                                           subprocess.CompletedProcess(command, 0, "done", ""))
        analytics = _run(tmp_path, smoke=smoke)[0]["metrics"]["analytics"]
        assert analytics["refresh_dbt_seconds"]["kind"] == "NOT_MEASURED"
        assert analytics["refresh_seconds"]["kind"] == "OBSERVATION"

    def test_level_without_refresh_or_detector(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path, cell=_cell(refresh_and_detector=False))
        assert clean and result["verdict"] == "VALID"
        for step in ("build_refresh_image", "refresh_run", "run_detector",
                     "remove_profile_resources"):
            assert step not in smoke.calls
        analytics = result["metrics"]["analytics"]
        assert analytics["refresh_seconds"]["kind"] == "NOT_MEASURED"
        assert analytics["detector_ms"]["kind"] == "NOT_MEASURED"


STEPS = [s for s in ORDER if s not in ("stop_host_processes", "remove_profile_resources",
                                       "cleanup", "docker_stats")]


class TestFailures:
    @pytest.mark.parametrize("step", STEPS)
    def test_failure_at_each_step_is_invalid_and_cleaned_up(self, tmp_path, step):
        smoke = FakeSmoke(tmp_path, fail=step)
        result, path, clean, smoke = _run(tmp_path, smoke=smoke)
        assert result["verdict"] == "INVALID" and path.is_file()
        assert "Boom" in " ".join(g["evidence"] for g in result["integrity"]["gates"])
        tail = smoke.calls[smoke.calls.index(step) + 1:]
        assert tail[-1] == "cleanup" and "stop_host_processes" in tail
        built = "build_refresh_image" in smoke.calls
        assert ("remove_profile_resources" in tail) == built
        assert not any(c in tail for c in ("run_stage_measured", "run_detector")
                       if c != step and ORDER.index(c) < ORDER.index(step))

    def test_failed_refresh_exit_is_invalid(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="refresh_exit"))[0]
        assert result["verdict"] == "INVALID"

    def test_refresh_that_changes_the_ledger_is_invalid(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        result = _run(tmp_path, smoke=smoke, e2e=FakeE2E(smoke, ledger_changes=True))[0]
        assert result["verdict"] == "INVALID"
        assert "ledger" in " ".join(g["evidence"] for g in result["integrity"]["gates"])

    def test_integrity_failure_is_invalid(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, dlq=1))[0]
        assert result["verdict"] == "INVALID" and result["integrity"]["ok"] is False

    def test_lag_sampling_failure_stays_unknown(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, lag=Boom("jvm")))[0]
        lag = result["metrics"]["lag"]
        assert lag["raw_max"]["kind"] == "NOT_MEASURED" and lag["raw_max"]["value"] is None
        assert result["verdict"] == "VALID"

    def test_unknown_lag_value_is_not_zero(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, lag=None))[0]
        assert result["metrics"]["lag"]["canonical_max"]["kind"] == "NOT_MEASURED"

    def test_generator_bound_from_scheduler(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, late_starts=6))[0]
        assert result["verdict"] == "GENERATOR_BOUND"


class TestStops:
    def test_disk_preflight_stops_before_the_stack(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path, disk=5 * GB)
        assert result["verdict"] == "STOPPED" and clean
        assert "preflight" in result["stop"]["reasons"][0]
        assert "start_kafka" not in smoke.calls and smoke.calls[-1] == "cleanup"

    def test_disk_projection_scales_with_level(self):
        assert RB.projected_need_bytes(_cell("SMALL")) > RB.projected_need_bytes(_cell())

    def test_memory_stop(self, tmp_path):
        smoke = FakeSmoke(tmp_path, stats="proj-pg-1|1.0%|950MiB / 1000MiB")
        result = _run(tmp_path, smoke=smoke)[0]
        assert result["verdict"] == "STOPPED"
        assert any("memory" in reason for reason in result["stop"]["reasons"])

    def test_cell_budget_stop(self, tmp_path):
        ladder = json.loads(json.dumps(LADDER))
        ladder["defaults"]["cell_budget_seconds"] = 2  # the fake clock ticks once per read
        result, _, clean, smoke = _run(tmp_path, ladder=ladder)
        assert result["verdict"] == "STOPPED" and clean
        assert "budget" in result["stop"]["reasons"][0]
        assert "run_stage_measured" not in smoke.calls and smoke.calls[-1] == "cleanup"

    def test_invalid_clock_blocks_persistence_latency_only(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, clock=(1000.0, 1000.0, 1000.05)))[0]
        assert result["verdict"] == "VALID" and result["clock"]["valid"] is False
        assert result["metrics"]["latency"]["persistence_ms"]["p95"]["kind"] == "NOT_MEASURED"
        assert not result["claims"]["persistence_latency"]

    def test_valid_clock_allows_persistence_latency(self, tmp_path):
        result = _run(tmp_path)[0]
        assert result["clock"]["valid"] is True
        assert result["metrics"]["latency"]["persistence_ms"]["p95"]["value"] == 40.0


class TestCleanup:
    def test_unverified_cleanup_stops_and_blocks(self, tmp_path):
        result, path, clean, smoke = _run(tmp_path, smoke=FakeSmoke(tmp_path, cleanup_ok=False))
        assert not clean and result["verdict"] == "STOPPED"
        assert "cleanup not verified" in result["stop"]["reasons"]
        assert (path.parent / RB.CLEANUP_MARKER).is_file()

    def test_cleanup_that_raises_is_unverified(self, tmp_path):
        result, _, clean, _ = _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="cleanup_raises"))
        assert not clean and result["verdict"] == "STOPPED"

    def test_failing_cleanup_step_still_runs_the_rest(self, tmp_path):
        smoke = FakeSmoke(tmp_path, fail="stop_host_processes")
        result, _, clean, smoke = _run(tmp_path, smoke=smoke)
        assert not clean and smoke.calls[-2:] == ["remove_profile_resources", "cleanup"]
        assert result["verdict"] == "STOPPED"

    def test_samplers_are_stopped_even_on_failure(self, tmp_path):
        FakeSampler.instances.clear()
        _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="run_stage_measured"))
        assert FakeSampler.instances and all(s.stops >= 1 for s in FakeSampler.instances)

    def test_result_never_written_inside_repository(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        with pytest.raises(RB.BenchmarkError):
            _run(tmp_path, smoke=smoke, out=_REPO / "benchmarks" / "results")
        assert smoke.calls[-1] == "cleanup"
        assert not (_REPO / "benchmarks" / "results").exists()

    def test_marker_never_inside_repository(self):
        with pytest.raises(RB.BenchmarkError):
            RB._mark_cleanup_unverified(_REPO / "benchmarks", _cell())


class TestLiveStaysDisabled:
    def test_gate_is_a_boolean(self):
        assert isinstance(RB.LIVE_ENABLED, bool)

    def test_run_cell_refuses_before_importing_the_harness(self, tmp_path, monkeypatch):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        monkeypatch.setattr(RB, "execute_cell", lambda *a, **k: pytest.fail("reached"))
        for name in ("run_smoke", "run_e2e"):
            monkeypatch.delitem(sys.modules, name, raising=False)
        with pytest.raises(RB.LiveDisabled):
            RB.run_cell(_cell(), LADDER, expect_head=None, output_dir=tmp_path)
        assert "run_smoke" not in sys.modules and "run_e2e" not in sys.modules

    def test_cli_live_refused(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        assert RB.main(["--level", "SMOKE", "--live", "--output-dir", str(tmp_path)]) == 2
        assert "not enabled" in capsys.readouterr().err

    def test_plan_mode_warns_about_cleanup_marker(self, tmp_path):
        import io
        (tmp_path / RB.CLEANUP_MARKER).write_text("x", encoding="utf-8")
        out = io.StringIO()
        assert RB.main(["--level", "SMOKE", "--output-dir", str(tmp_path)], stdout=out) == 0
        assert "live runs are blocked" in out.getvalue()

    def test_plan_mode_has_no_side_effects(self, tmp_path):
        import io
        out = io.StringIO()
        assert RB.main(["--level", "SMALL", "--output-dir", str(tmp_path / "o")], stdout=out) == 0
        assert out.getvalue().startswith("PLAN ONLY") and not (tmp_path / "o").exists()


# ---------------------------------------------------------------------------
# Exact-cell live authorization (Phase 14.4B3)
# ---------------------------------------------------------------------------

HEAD = "8" * 40
APPROVED = ["--level", "SMOKE", "--rate", "5", "--repetition", "2", "--concurrency", "32",
            "--warmup-requests", "25"]


def _approved_cells(level="SMOKE", **overrides):
    kwargs = dict(rates=[5], repetition=2, concurrency=32, warmup_requests=25)
    if "repetitions" in overrides:
        kwargs.pop("repetition")
    kwargs.update(overrides)
    return RB.plan_cells(LADDER, level, **kwargs)


def _authorize(cells, authorize="bm-smoke-r0005-c32-rep2", expect_head=HEAD,
               warmup_requests=25, repetition=2):
    return RB.check_live_authorization(cells, authorize=authorize, expect_head=expect_head,
                                       warmup_requests=warmup_requests, repetition=repetition)


class TestLiveAuthorization:
    def test_exact_approved_cell(self):
        cell = _authorize(_approved_cells())
        assert (cell.benchmark_id, cell.requests, cell.rate, cell.concurrency,
                cell.repetition, cell.warmup_requests) == (
            "bm-smoke-r0005-c32-rep2", 100, 5, 32, 2, 25)
        cell = _authorize(_approved_cells(repetition=3), authorize="bm-smoke-r0005-c32-rep3",
                          repetition=3)
        assert (cell.benchmark_id, cell.repetition) == ("bm-smoke-r0005-c32-rep3", 3)

    @pytest.mark.parametrize("authorize", [None, "", "bm-smoke-r0010-c32-rep2",
                                           "bm-small-r0005-c32-rep2",
                                           "bm-smoke-r0005-c32-rep1",
                                           "bm-smoke-r0005-c32-rep6"])
    def test_missing_or_wrong_authorization(self, authorize):
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize(_approved_cells(), authorize=authorize)

    @pytest.mark.parametrize("head", [None, "", "812ff80", "Z" * 40, HEAD + "0"])
    def test_missing_or_malformed_head(self, head):
        with pytest.raises(RB.BenchmarkError, match="expect-head"):
            _authorize(_approved_cells(), expect_head=head)

    @pytest.mark.parametrize("warmup", [None, 24, 26, 150])
    def test_wrong_warmup_argument(self, warmup):
        with pytest.raises(RB.BenchmarkError, match="warmup-requests 25"):
            _authorize(_approved_cells(), warmup_requests=warmup)

    def test_planned_warmup_must_match_too(self):
        with pytest.raises(RB.BenchmarkError, match="warmup_requests"):
            _authorize(_approved_cells(warmup_requests=30))

    @pytest.mark.parametrize("overrides", [
        dict(rates=[10]), dict(concurrency=16), dict(rates=[10], level="SMALL"),
        dict(repetition=3),
    ])
    def test_wrong_cell_is_not_the_authorized_one(self, overrides):
        # rate, concurrency, level and repetition are all part of the id.
        with pytest.raises(RB.BenchmarkError, match="is not bm-smoke-r0005-c32-rep2"):
            _authorize(_approved_cells(**overrides))

    @pytest.mark.parametrize("repetition", [None, 1, 3])
    def test_repetition_must_be_selected_and_match(self, repetition):
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize(_approved_cells(), repetition=repetition)

    def test_rep1_is_refused_with_otherwise_correct_parameters(self):
        rep1 = _approved_cells(repetition=1)
        with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
            _authorize(rep1, authorize="bm-smoke-r0005-c32-rep1", repetition=1)
        assert not RB.is_approved_live_cell(rep1[0])

    @pytest.mark.parametrize("overrides", [dict(repetitions=2), dict(rates=[5, 10])])
    def test_multiple_planned_cells(self, overrides):
        with pytest.raises(RB.BenchmarkError, match="exactly one cell"):
            _authorize(_approved_cells(**overrides))

    def test_warmup_override_validation_and_default(self):
        assert RB.plan_cells(LADDER, "SMOKE", rates=[5], repetitions=1)[0].warmup_requests == 150
        assert _approved_cells()[0].warmup_requests == 25
        for bad in (0, -1, RB.MAX_WARMUP_REQUESTS + 1, True, 2.5):
            with pytest.raises(RB.BenchmarkError, match="warm-up"):
                RB.plan_cells(LADDER, "SMOKE", warmup_requests=bad)


class TestLiveCli:
    """The CLI with the gate opened in memory only, and run_cell replaced:
    nothing is imported or started."""

    @pytest.fixture
    def gate_open(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)

        def fake_run_cell(cell, ladder, **kw):
            calls.append((cell.benchmark_id, kw["expect_head"]))
            path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
            path.write_text("{}", encoding="utf-8")
            return {"verdict": "VALID"}, path, True

        monkeypatch.setattr(RB, "run_cell", fake_run_cell)
        for name in ("run_smoke", "run_e2e"):
            monkeypatch.delitem(sys.modules, name, raising=False)
        return calls

    def _main(self, tmp_path, *extra):
        return RB.main([*APPROVED, "--live", "--output-dir", str(tmp_path / "out"), *extra],
                       stdout=__import__("io").StringIO())

    def test_exact_cell_reaches_run_cell_once(self, gate_open, tmp_path):
        code = self._main(tmp_path, "--authorize", "bm-smoke-r0005-c32-rep2",
                          "--expect-head", HEAD)
        assert code == 0 and gate_open == [("bm-smoke-r0005-c32-rep2", HEAD)]

    @pytest.mark.parametrize("extra", [
        [],
        ["--authorize", "bm-smoke-r0005-c32-rep2"],
        ["--expect-head", HEAD],
        ["--authorize", "bm-smoke-r0010-c32-rep1", "--expect-head", HEAD],
        ["--authorize", "bm-smoke-r0005-c32-rep2", "--expect-head", HEAD, "--rate", "10"],
        ["--authorize", "bm-smoke-r0005-c32-rep3", "--expect-head", HEAD],
        ["--authorize", "bm-smoke-r0005-c32-rep1", "--expect-head", HEAD],
        ["--authorize", "bm-smoke-r0005-c32-rep2", "--expect-head", HEAD,
         "--concurrency", "16"],
        ["--authorize", "bm-smoke-r0005-c32-rep2", "--expect-head", HEAD,
         "--warmup-requests", "26"],
    ])
    def test_everything_else_refused_before_anything_starts(self, gate_open, tmp_path, extra,
                                                           capsys):
        assert self._main(tmp_path, *extra) == 2
        assert gate_open == [] and "nothing was started" in capsys.readouterr().err
        assert "run_smoke" not in sys.modules and "run_e2e" not in sys.modules

    def test_wrong_level_refused(self, gate_open, tmp_path, capsys):
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "2",
                        "--concurrency", "32", "--warmup-requests", "25", "--live",
                        "--authorize", "bm-smoke-r0005-c32-rep2", "--expect-head", HEAD,
                        "--output-dir", str(tmp_path)])
        assert code == 2 and gate_open == []

    def test_cleanup_marker_still_blocks(self, gate_open, tmp_path, capsys):
        (tmp_path / "out").mkdir()
        (tmp_path / "out" / RB.CLEANUP_MARKER).write_text("x", encoding="utf-8")
        code = self._main(tmp_path, "--authorize", "bm-smoke-r0005-c32-rep2",
                          "--expect-head", HEAD)
        assert code == 2 and gate_open == [] and "cleanup" in capsys.readouterr().err

    def test_run_cell_refuses_other_cells_before_imports(self, monkeypatch, tmp_path):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "execute_cell", lambda *a, **k: pytest.fail("reached"))
        for name in ("run_smoke", "run_e2e"):
            monkeypatch.delitem(sys.modules, name, raising=False)
        for cell in (_approved_cells(warmup_requests=150)[0], _approved_cells(rates=[10])[0],
                     _approved_cells(repetition=1)[0], _approved_cells(repetition=6)[0]):
            with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
                RB.run_cell(cell, LADDER, expect_head=HEAD, output_dir=tmp_path)
        assert "run_smoke" not in sys.modules and "run_e2e" not in sys.modules


class TestGateClosed:
    """The gate's refusal, tested with the gate forced closed in memory."""

    @pytest.fixture(autouse=True)
    def closed(self, monkeypatch):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)

    def test_exact_cell_is_still_refused_by_the_gate(self, tmp_path, capsys):
        code = RB.main([*APPROVED, "--live", "--authorize", "bm-smoke-r0005-c32-rep2",
                        "--expect-head", HEAD, "--output-dir", str(tmp_path)])
        assert code == 2 and "not enabled" in capsys.readouterr().err
        assert "run_smoke" not in sys.modules

    def test_plan_mode_with_override_has_no_side_effects(self, tmp_path):
        import io
        out = io.StringIO()
        assert RB.main([*APPROVED, "--output-dir", str(tmp_path / "o")], stdout=out) == 0
        text = out.getvalue()
        assert "warm-up 25 requests" in text and text.count("bm-") == 1
        assert not (tmp_path / "o").exists()

    def test_authorize_without_live_is_rejected(self):
        with pytest.raises(SystemExit):
            RB.main([*APPROVED, "--authorize", "bm-smoke-r0005-c32-rep2"])

# ---------------------------------------------------------------------------
# Both gate states, in memory only: nothing reaches the real harness
# ---------------------------------------------------------------------------

EXACT = [*APPROVED, "--authorize", "bm-smoke-r0005-c32-rep2", "--expect-head", HEAD]


@pytest.fixture(params=[False, True], ids=["gate-closed", "gate-open"])
def gate(request, monkeypatch):
    monkeypatch.setattr(RB, "LIVE_ENABLED", request.param)
    return request.param


class TestIsolationGuards:
    def test_guards_are_active(self, tmp_path):
        with pytest.raises(LiveAccessAttempt):
            subprocess.run(["docker", "ps"])
        with pytest.raises(LiveAccessAttempt):
            subprocess.Popen(["git", "status"])
        with pytest.raises(LiveAccessAttempt):
            subprocess.check_output(["docker", "info"])
        with pytest.raises(LiveAccessAttempt):
            os.system("docker ps")
        with pytest.raises(LiveAccessAttempt):
            socket.create_connection(("127.0.0.1", 15432))
        with pytest.raises(LiveAccessAttempt):
            RB.execute_cell(_cell(), LADDER, smoke=None, e2e=None, expect_head=HEAD,
                            output_dir=tmp_path, disk_free=lambda: 0)
        for name in ("run_smoke", "run_e2e"):
            with pytest.raises(ImportError, match="blocked"):
                __import__(name)

    def test_fake_harness_path_is_explicit(self):
        assert REAL_EXECUTE_CELL is not RB.execute_cell


class TestBothGateStates:
    def test_real_run_cell_never_reaches_the_harness(self, gate, tmp_path):
        cell = _approved_cells()[0]
        expected = ImportError if gate else RB.LiveDisabled
        with pytest.raises(expected):
            RB.run_cell(cell, LADDER, expect_head=HEAD, output_dir=tmp_path)
        assert "run_smoke" not in sys.modules and "run_e2e" not in sys.modules

    def test_exact_command_never_reaches_infrastructure(self, gate, tmp_path, capsys):
        args = [*EXACT, "--live", "--output-dir", str(tmp_path / "out")]
        out = tmp_path / "out"
        if gate:
            # Authorized and open: ownership and the ledger entry are taken,
            # then the real run_cell stops at the blocked harness import,
            # before any process or container.  The records stay.
            with pytest.raises(ImportError, match="blocked"):
                RB.main(args)
            assert (out / RB.OWNER_FILE).is_file()
            assert (out / "ledger" / "bm-smoke-r0005-c32-rep2.started").is_file()
            assert not (out / "ledger" / "bm-smoke-r0005-c32-rep2.done").exists()
            assert not list(out.glob("bm-*.json"))
        else:
            assert RB.main(args) == 2 and "not enabled" in capsys.readouterr().err
            assert not out.exists()

    @pytest.mark.parametrize("extra", [
        [],
        ["--authorize", "bm-smoke-r0005-c32-rep2"],
        ["--expect-head", HEAD],
        ["--authorize", "bm-smoke-r0010-c32-rep1", "--expect-head", HEAD],
    ])
    def test_authorization_is_still_required(self, gate, tmp_path, capsys, extra):
        code = RB.main([*APPROVED, "--live", "--output-dir", str(tmp_path), *extra])
        err = capsys.readouterr().err
        assert code == 2 and "nothing was started" in err
        assert ("not enabled" in err) is (not gate)

    def test_other_cells_refused_by_run_cell_when_open(self, gate, tmp_path):
        cell = _approved_cells(rates=[10])[0]
        expected = RB.BenchmarkError if gate else RB.LiveDisabled
        with pytest.raises(expected):
            RB.run_cell(cell, LADDER, expect_head=HEAD, output_dir=tmp_path)

    def test_plan_mode_is_identical(self, gate, tmp_path):
        import io
        out = io.StringIO()
        assert RB.main([*APPROVED, "--output-dir", str(tmp_path / "o")], stdout=out) == 0
        assert out.getvalue().startswith("PLAN ONLY") and not (tmp_path / "o").exists()

    def test_fake_harness_cell_still_runs_offline(self, gate, tmp_path):
        result, path, clean, smoke = _run(tmp_path)
        assert clean and result["verdict"] == "VALID" and path.is_file()
        assert smoke.calls[-1] == "cleanup"

# ---------------------------------------------------------------------------
# Phase 14.4B3F measurement corrections
# ---------------------------------------------------------------------------

def _assembled(driver_overrides=None, db_overrides=None, drop=(), **evidence):
    smoke_driver = {"started": "2026-01-01T00:00:00+00:00",
                    "finished": "2026-01-01T00:00:20+00:00", "elapsed_seconds": 20.0,
                    "executed_attempts": 100, "started_requests": 100,
                    "not_started_requests": 0, "spans_ended": 700,
                    "spans_exported_successfully": 700, "export_failures": 0,
                    "flush_ok": True, "run_status": "completed", "problems": [],
                    "achieved_submission_rate": 5.0, "late_starts": 0,
                    "max_start_lag_seconds": 0.04, "mean_start_lag_seconds": 0.01}
    smoke_driver.update(driver_overrides or {})
    for name in drop:
        smoke_driver.pop(name)
    database = {"rows": 700, "distinct_spans": 700, "roots": 100, "first_ingested": 5000.0,
                "last_ingested": 5020.0, "request_ms": [250.0] * 100,
                "persistence_ms": [40.0] * 700, "per_second": [35] * 20}
    database.update(db_overrides or {})
    values = dict(cell=_cell(), git_sha=SHA, git_dirty=False, started=1000.0, finished=1100.0,
                  driver=smoke_driver, canonical_records=700, raw_records=140, dlq_records=0,
                  database=database, clock_before=[M.ClockSample(1000.0, 1000.001, 1000.002)],
                  clock_after=[M.ClockSample(1001.0, 1001.001, 1001.002)],
                  stage_tail_seconds=37.9)
    values.update(evidence)
    result = RB.assemble_result(RB.CellEvidence(**values), LADDER["stop_limits"])
    M.validate_result(result)
    return result


class TestStageTail:
    def test_stage_tail_is_an_observation_with_the_exact_method(self):
        tail = _assembled()["metrics"]["lag"]["stage_tail_seconds"]
        assert tail["kind"] == "OBSERVATION" and tail["value"] == 37.9
        assert tail["method"] == ("Driver finished -> run_stage returned; includes consumer "
                                  "drain, settle period and reconciliation.")

    def test_pure_drain_is_not_measured_and_never_estimated(self):
        drain = _assembled()["metrics"]["lag"]["drain_seconds"]
        assert drain["kind"] == "NOT_MEASURED" and drain["value"] is None
        assert "does not expose an isolated drain duration" in drain["reason"]

    def test_older_field_name_is_read_as_the_stage_tail(self):
        result = _assembled(stage_tail_seconds=None, drain_seconds=12.0)
        assert result["metrics"]["lag"]["stage_tail_seconds"]["value"] == 12.0
        assert result["metrics"]["lag"]["drain_seconds"]["kind"] == "NOT_MEASURED"

    def test_missing_tail_is_not_measured(self):
        tail = _assembled(stage_tail_seconds=None)["metrics"]["lag"]["stage_tail_seconds"]
        assert tail["kind"] == "NOT_MEASURED" and tail["value"] is None

    def test_live_cell_records_the_tail(self, tmp_path):
        result = _run(tmp_path)[0]
        assert result["metrics"]["lag"]["stage_tail_seconds"]["value"] == 3


class TestPersistedRate:
    def test_formula_is_n_minus_one_over_span(self):
        rate = _assembled()["metrics"]["throughput"]["spans_persisted_per_second"]
        assert rate["kind"] == "DERIVED" and rate["value"] == pytest.approx(699 / 20.0)
        assert rate["n"] == 700 and "(rows - 1)" in rate["method"]
        assert rate["window"]["clock"] == "database"

    def test_two_rows(self):
        result = _assembled(db_overrides={"rows": 2, "distinct_spans": 2,
                                          "last_ingested": 5000.5})
        value = result["metrics"]["throughput"]["spans_persisted_per_second"]
        assert value["value"] == pytest.approx(2.0)

    @pytest.mark.parametrize("overrides, reason", [
        ({"rows": 1, "distinct_spans": 1}, "at least 2"),
        ({"rows": 0, "distinct_spans": 0}, "at least 2"),
        ({"last_ingested": 5000.0}, "one instant"),
        ({"last_ingested": 4999.0}, "one instant"),
        ({"first_ingested": None}, "not read"),
    ])
    def test_edge_cases_are_not_measured(self, overrides, reason):
        rate = _assembled(db_overrides=overrides)["metrics"]["throughput"][
            "spans_persisted_per_second"]
        assert rate["kind"] == "NOT_MEASURED" and rate["value"] is None
        assert reason in rate["reason"]

    def test_generated_and_request_rates_unchanged(self):
        tp = _assembled()["metrics"]["throughput"]
        assert tp["spans_generated_per_second"]["kind"] == "DERIVED"
        assert tp["spans_generated_per_second"]["value"] == 35.0
        assert tp["requests_per_second"]["value"] == 5.0


class TestScheduler:
    def test_values_copied_from_the_driver(self):
        sched = _assembled(driver_overrides={"late_starts": 3, "started_requests": 98,
                                             "not_started_requests": 2,
                                             "max_start_lag_seconds": 0.4,
                                             "mean_start_lag_seconds": 0.05})["metrics"][
            "scheduler"]
        fields = ("late_starts", "started_requests", "not_started_requests",
                  "max_start_lag_seconds", "mean_start_lag_seconds")
        assert {k: sched[k]["value"] for k in fields} == {
            "late_starts": 3, "started_requests": 98, "not_started_requests": 2,
            "max_start_lag_seconds": 0.4, "mean_start_lag_seconds": 0.05}
        assert {sched[k]["kind"] for k in fields} == {"MEASURED"}

    def test_genuine_zero_stays_zero(self):
        late = _assembled()["metrics"]["scheduler"]["late_starts"]
        assert late["kind"] == "MEASURED" and late["value"] == 0

    @pytest.mark.parametrize("field", ["late_starts", "not_started_requests",
                                       "max_start_lag_seconds", "mean_start_lag_seconds"])
    def test_missing_field_is_not_measured_not_zero(self, field):
        result = _assembled(drop=(field,))
        metric = result["metrics"]["scheduler"][field]
        assert metric["kind"] == "NOT_MEASURED" and metric["value"] is None
        evidence = result["stop"]["generator_bound_evidence"]
        assert evidence[field] is None and field in evidence["missing"]

    def test_missing_late_starts_means_not_evaluated(self):
        result = _assembled(drop=("late_starts",))
        evidence = result["stop"]["generator_bound_evidence"]
        assert evidence["evaluated"] is False and result["stop"]["generator_bound"] is False
        assert any("not evaluated" in item for item in result["limitations"])

    def test_no_driver_report(self):
        result = _assembled(driver=None, canonical_records=None)
        assert all(m["kind"] == "NOT_MEASURED" for m in result["metrics"]["scheduler"].values())
        assert result["stop"]["generator_bound_evidence"]["evaluated"] is False

    def test_run_status_and_no_series_recorded(self):
        evidence = _assembled(driver_overrides={"run_status": "deadline_reached"})[
            "stop"]["generator_bound_evidence"]
        assert evidence["run_status"] == "deadline_reached"
        assert evidence["start_lag_series"] is None

    @pytest.mark.parametrize("overrides, bound, verdict", [
        ({}, False, "VALID"),
        ({"late_starts": 5}, False, "VALID"),
        ({"late_starts": 6}, True, "GENERATOR_BOUND"),
        ({"not_started_requests": 1}, True, "GENERATOR_BOUND"),
        # Also fails the driver-status integrity gate: INVALID takes precedence.
        ({"run_status": "deadline_reached"}, True, "INVALID"),
    ])
    def test_decision_reproducible_from_the_json(self, overrides, bound, verdict):
        result = json.loads(json.dumps(_assembled(driver_overrides=overrides)))
        evidence = result["stop"]["generator_bound_evidence"]
        again, reasons = RB.generator_bound_from_evidence(
            evidence, late_fraction=evidence["late_fraction"],
            lag_growth_samples=evidence["lag_growth_samples"])
        assert again == result["stop"]["generator_bound"] == evidence["generator_bound"] == bound
        assert list(reasons) == [r for r in result["verdict_reasons"]
                                 if r not in result["stop"]["reasons"]]
        assert result["verdict"] == verdict == M.verdict(
            integrity_ok=result["integrity"]["ok"], stop_reasons=result["stop"]["reasons"],
            generator_bound_run=again)


class TestHistoricalCompatibility:
    def _historical(self):
        """A result shaped as written before 14.4B3F: drain_seconds as an
        OBSERVATION, persisted rate MEASURED, no scheduler section and no
        generator-bound evidence."""
        result = json.loads(json.dumps(_assembled()))
        lag = result["metrics"]["lag"]
        lag["drain_seconds"] = {**lag.pop("stage_tail_seconds"),
                                "method": "end of driver run -> lag 0 and counts stable"}
        rate = result["metrics"]["throughput"]["spans_persisted_per_second"]
        rate.update(kind="MEASURED", value=700 / 20.0,
                    method="rows / (last - first ingested_at)")
        del result["metrics"]["scheduler"]
        del result["stop"]["generator_bound_evidence"]
        return result

    def test_older_results_still_validate(self):
        M.validate_result(self._historical())

    def test_validation_does_not_rewrite_older_results(self):
        older = self._historical()
        snapshot = json.dumps(older, sort_keys=True)
        M.validate_result(older)
        assert json.dumps(older, sort_keys=True) == snapshot


class TestCorrectionsKeepSafety:
    def test_authorization_and_isolation_unchanged(self, tmp_path, monkeypatch, capsys):
        assert sorted(RB.APPROVED_LIVE_CELLS) == ["bm-small-r0010-c32-rep1",
                                                 "bm-small-r0010-c32-rep2",
                                                 "bm-small-r0010-c32-rep3",
                                                 "bm-small-r0010-c32-rep4",
                                                 "bm-small-r0010-c32-rep5",
                                                 "bm-small-r0010-c32-rep6",
                                                 "bm-small-r0010-c32-rep7",
                                                 "bm-small-r0010-c32-rep8",
                                                 "bm-small-r0010-c32-rep9",
                                                 "bm-smoke-r0005-c32-rep2",
                                                 "bm-smoke-r0005-c32-rep3",
                                                 "bm-smoke-r0005-c32-rep4",
                                                 "bm-smoke-r0005-c32-rep5"]
        assert [c["repetition"] for c in RB.APPROVED_LIVE_CELLS.values()] == [
            2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        with pytest.raises(LiveAccessAttempt):
            subprocess.run(["docker", "ps"])
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        assert RB.main([*EXACT, "--live", "--output-dir", str(tmp_path)]) == 2
        assert "not enabled" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Phase 14.4B3H2 repetition selection, run ledger and ownership
# ---------------------------------------------------------------------------

HISTORICAL_RESULT = (Path(tempfile.gettempdir()) / "agentops-benchmarks"
                     / "bm-smoke-r0005-c32-rep1-20261008T174815.json")
HISTORICAL_SHA256_PREFIX = "e2f98781f555d31c"


def _rep_args(n, *extra):
    return ["--level", "SMOKE", "--rate", "5", "--repetition", str(n), "--concurrency", "32",
            "--warmup-requests", "25", "--live", "--authorize", f"bm-smoke-r0005-c32-rep{n}",
            "--expect-head", HEAD, *extra]


class TestRepetitionSelector:
    @pytest.mark.parametrize("n", [2, 3])
    def test_one_repetition_planned_alone(self, n):
        cells = RB.plan_cells(LADDER, "SMOKE", rates=[5], repetition=n, concurrency=32,
                              warmup_requests=25)
        assert [(c.benchmark_id, c.warmup_run_id, c.measured_run_id) for c in cells] == [
            (f"bm-smoke-r0005-c32-rep{n}", f"b-smoke-r0005-c32-w{n}",
             f"b-smoke-r0005-c32-m{n}")]

    @pytest.mark.parametrize("bad", [0, 11, -1, True, 2.0])
    def test_bounds(self, bad):
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            RB.plan_cells(LADDER, "SMOKE", repetition=bad)

    def test_conflicts_with_repetitions(self):
        with pytest.raises(RB.BenchmarkError, match="exclude each other"):
            RB.plan_cells(LADDER, "SMOKE", repetition=2, repetitions=3)
        with pytest.raises(SystemExit):
            RB.main(["--level", "SMOKE", "--repetition", "2", "--repetitions", "3"])

    def test_plan_mode_without_selector_unchanged(self):
        import io
        out = io.StringIO()
        assert RB.main(["--level", "SMOKE", "--rate", "5", "--output-dir",
                        str(Path(__import__("tempfile").gettempdir()) / "unused-bm")],
                       stdout=out) == 0
        assert out.getvalue().count("bm-smoke-r0005-c32-rep") == 3

    def test_plan_mode_with_selector(self, tmp_path):
        import io
        out = io.StringIO()
        assert RB.main(["--level", "SMOKE", "--rate", "5", "--repetition", "3",
                        "--output-dir", str(tmp_path / "o")], stdout=out) == 0
        assert out.getvalue().count("bm-") == 1 and "rep3" in out.getvalue()
        assert not (tmp_path / "o").exists()


def _claim(tmp_path, n=2, **kw):
    cell = _approved_cells(repetition=n)[0]
    return cell, RB.claim_run(tmp_path, cell, head=HEAD, arguments={"repetition": n},
                              now=lambda: 1_800_000_000.0, pid=lambda: 4242, **kw)


class TestLedger:
    def test_claim_records_owner_and_started(self, tmp_path):
        cell, started = _claim(tmp_path)
        owner = json.loads((tmp_path / RB.OWNER_FILE).read_text(encoding="utf-8"))
        record = json.loads(started.read_text(encoding="utf-8"))
        assert started == tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.started"
        assert owner == record
        assert record["benchmark_id"] == cell.benchmark_id and record["git_head"] == HEAD
        assert record["pid"] == 4242 and record["started_utc"].startswith("2027-01-15T")
        assert record["arguments"] == {"repetition": 2}

    def test_duplicate_started_refused(self, tmp_path):
        cell, started = _claim(tmp_path)
        (tmp_path / RB.OWNER_FILE).unlink()      # as after a released run
        with pytest.raises(RB.BenchmarkError, match="was started before"):
            _claim(tmp_path)
        assert started.is_file()                 # never deleted
        assert not (tmp_path / RB.OWNER_FILE).exists()  # the refused claim released its own

    def test_existing_result_refused(self, tmp_path):
        (tmp_path / "bm-smoke-r0005-c32-rep2-20261009T000000.json").write_text("{}")
        with pytest.raises(RB.BenchmarkError, match="already exists"):
            _claim(tmp_path)
        assert not (tmp_path / "ledger").exists() and not (tmp_path / RB.OWNER_FILE).exists()

    def test_creation_failure_blocks(self, tmp_path, monkeypatch):
        real = RB._exclusive_json

        def failing(path, payload):
            if path.name.endswith(".started"):
                raise PermissionError("denied")
            return real(path, payload)

        monkeypatch.setattr(RB, "_exclusive_json", failing)
        with pytest.raises(RB.BenchmarkError, match="cannot create"):
            _claim(tmp_path)
        assert not (tmp_path / RB.OWNER_FILE).exists()

    def test_owner_creation_failure_blocks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(RB, "_exclusive_json",
                            lambda path, payload: (_ for _ in ()).throw(OSError("disk")))
        with pytest.raises(RB.BenchmarkError, match="cannot create"):
            _claim(tmp_path)

    def test_simultaneous_ownership_conflict(self, tmp_path):
        _claim(tmp_path, n=2)
        with pytest.raises(RB.BenchmarkError, match="owns this output directory"):
            _claim(tmp_path, n=3)
        assert not (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep3.started").exists()

    def test_ledger_never_inside_repository(self):
        with pytest.raises(RB.BenchmarkError, match="never written inside the repository"):
            _claim(_REPO / "benchmarks")
        assert not (_REPO / "benchmarks" / RB.OWNER_FILE).exists()


class TestFinish:
    def _result_file(self, tmp_path, verdict="VALID"):
        path = tmp_path / "bm-smoke-r0005-c32-rep2-x.json"
        path.write_text(json.dumps({"verdict": verdict}), encoding="utf-8")
        return path

    def test_done_records_hash_and_intended_status(self, tmp_path):
        cell, _ = _claim(tmp_path)
        path = self._result_file(tmp_path)
        released = RB.finish_run(tmp_path, cell, result={"verdict": "VALID"}, result_path=path,
                                 cleanup_verified=True, intended_status=0)
        done = json.loads((tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.done").read_text())
        import hashlib
        assert done["result_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert done["verdict"] == "VALID" and done["cleanup_verified"] is True
        assert done["intended_return_status"] == 0
        assert "not here" in done["intended_return_status_note"]
        assert not any("exit_code" in key for key in done)   # no OS exit code invented
        assert released and not (tmp_path / RB.OWNER_FILE).exists()
        assert (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.started").is_file()

    def test_cleanup_uncertainty_keeps_ownership(self, tmp_path):
        cell, _ = _claim(tmp_path)
        path = self._result_file(tmp_path, "STOPPED")
        released = RB.finish_run(tmp_path, cell, result={"verdict": "STOPPED"},
                                 result_path=path, cleanup_verified=False, intended_status=1)
        assert not released and (tmp_path / RB.OWNER_FILE).is_file()
        done = json.loads((tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.done").read_text())
        assert done["cleanup_verified"] is False and done["intended_return_status"] == 1

    def test_recording_failure_keeps_ownership(self, tmp_path):
        cell, _ = _claim(tmp_path)
        with pytest.raises(OSError):
            RB.finish_run(tmp_path, cell, result={"verdict": "VALID"},
                          result_path=tmp_path / "missing.json", cleanup_verified=True,
                          intended_status=0)
        assert (tmp_path / RB.OWNER_FILE).is_file()
        assert not (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.done").exists()

    def test_done_cannot_be_written_twice(self, tmp_path):
        cell, _ = _claim(tmp_path)
        path = self._result_file(tmp_path)
        RB.finish_run(tmp_path, cell, result={"verdict": "VALID"}, result_path=path,
                      cleanup_verified=False, intended_status=1)
        with pytest.raises(FileExistsError):
            RB.finish_run(tmp_path, cell, result={"verdict": "VALID"}, result_path=path,
                          cleanup_verified=True, intended_status=0)


class TestLiveFlowWithLedger:
    """main() with the gate open in memory and run_cell replaced."""

    @pytest.fixture
    def open_gate(self, monkeypatch):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        state = {"calls": [], "clean": True, "verdict": "VALID", "raise": None}

        def fake_run_cell(cell, ladder, **kw):
            state["calls"].append(cell.benchmark_id)
            if state["raise"]:
                raise state["raise"]
            path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
            path.write_text(json.dumps({"verdict": state["verdict"]}), encoding="utf-8")
            return {"verdict": state["verdict"]}, path, state["clean"]

        monkeypatch.setattr(RB, "run_cell", fake_run_cell)
        return state

    def _main(self, tmp_path, n):
        import io
        out = io.StringIO()
        return RB.main(_rep_args(n, "--output-dir", str(tmp_path)), stdout=out), out.getvalue()

    @pytest.mark.parametrize("n", [2, 3])
    def test_each_approved_repetition_runs_once(self, open_gate, tmp_path, n):
        code, text = self._main(tmp_path, n)
        assert code == 0 and open_gate["calls"] == [f"bm-smoke-r0005-c32-rep{n}"]
        assert (tmp_path / "ledger" / f"bm-smoke-r0005-c32-rep{n}.done").is_file()
        assert not (tmp_path / RB.OWNER_FILE).exists()
        code, _ = self._main(tmp_path, n)        # the same repetition again
        assert code == 2 and open_gate["calls"] == [f"bm-smoke-r0005-c32-rep{n}"]

    def test_rep2_then_rep3_sequentially(self, open_gate, tmp_path):
        assert self._main(tmp_path, 2)[0] == 0 and self._main(tmp_path, 3)[0] == 0
        assert open_gate["calls"] == ["bm-smoke-r0005-c32-rep2", "bm-smoke-r0005-c32-rep3"]

    @pytest.mark.parametrize("n", [1, 6])
    def test_rep1_and_rep6_refused(self, open_gate, tmp_path, n, capsys):
        import io
        assert RB.main(_rep_args(n, "--output-dir", str(tmp_path)), stdout=io.StringIO()) == 2
        assert open_gate["calls"] == [] and "nothing was started" in capsys.readouterr().err
        assert not (tmp_path / RB.OWNER_FILE).exists()

    def test_crash_leaves_blocking_evidence(self, open_gate, tmp_path):
        open_gate["raise"] = RuntimeError("process died")
        with pytest.raises(RuntimeError):
            self._main(tmp_path, 2)
        assert (tmp_path / RB.OWNER_FILE).is_file()
        assert (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.started").is_file()
        assert not (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.done").exists()
        open_gate["raise"] = None
        assert self._main(tmp_path, 3)[0] == 2           # ownership still held
        assert open_gate["calls"] == ["bm-smoke-r0005-c32-rep2"]

    def test_unverified_cleanup_keeps_ownership_and_blocks(self, open_gate, tmp_path):
        open_gate.update(clean=False, verdict="STOPPED")
        code, text = self._main(tmp_path, 2)
        assert code == 1 and "ownership is kept" in text
        assert (tmp_path / RB.OWNER_FILE).is_file()
        open_gate.update(clean=True, verdict="VALID")
        assert self._main(tmp_path, 3)[0] == 2

    def test_not_valid_but_clean_releases(self, open_gate, tmp_path):
        open_gate.update(verdict="INVALID")
        code, _ = self._main(tmp_path, 2)
        done = json.loads((tmp_path / "ledger" / "bm-smoke-r0005-c32-rep2.done").read_text())
        assert code == 1 and done["intended_return_status"] == 1
        assert not (tmp_path / RB.OWNER_FILE).exists()

    def test_existing_marker_blocks_before_claim(self, open_gate, tmp_path):
        (tmp_path / RB.CLEANUP_MARKER).write_text("x", encoding="utf-8")
        assert self._main(tmp_path, 2)[0] == 2
        assert not (tmp_path / RB.OWNER_FILE).exists() and open_gate["calls"] == []

    def test_claim_happens_before_harness_import(self, monkeypatch, tmp_path):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        with pytest.raises(ImportError, match="blocked"):
            RB.main(_rep_args(2, "--output-dir", str(tmp_path)))
        assert (tmp_path / RB.OWNER_FILE).is_file()
        assert "run_smoke" not in sys.modules


class TestHistoricalRep1:
    def test_historical_result_unchanged_if_present(self):
        if not HISTORICAL_RESULT.exists():
            pytest.skip("historical result not on this machine")
        import hashlib
        digest = hashlib.sha256(HISTORICAL_RESULT.read_bytes()).hexdigest()
        assert digest.startswith(HISTORICAL_SHA256_PREFIX)


# ---------------------------------------------------------------------------
# Phase 14.4B3I-5 start-lag diagnostic (observational only)
# ---------------------------------------------------------------------------

def _diag(entries=None, **overrides):
    entries = [[i, round(0.2 * i, 6), lag] for i, lag in enumerate(
        [0.001, 0.12, 0.0, 0.25, 0.05, 0.101])] if entries is None else entries
    value = {"limit": 10000, "expected": len(entries), "recorded": len(entries),
             "complete": True, "truncated_reason": None, "entries": entries}
    value.update(overrides)
    return value


def _with_diag(diag, **driver_overrides):
    return _assembled(driver_overrides={"start_lags": diag, **driver_overrides})


class TestStartLagDiagnosticInResults:
    def test_complete_diagnostic_gives_measured_percentiles(self):
        result = _with_diag(_diag())
        sched = result["metrics"]["scheduler"]
        lags = [0.001, 0.12, 0.0, 0.25, 0.05, 0.101]
        for q in (50, 95, 99):
            assert sched[f"start_lag_p{q}"]["kind"] == "MEASURED"
            assert sched[f"start_lag_p{q}"]["value"] == pytest.approx(M.percentile(lags, q))
            assert sched[f"start_lag_p{q}"]["n"] == 6

    def test_late_indices_use_the_driver_threshold_strictly(self):
        evidence = _with_diag(_diag())["stop"]["generator_bound_evidence"]
        diag = evidence["start_lag_diagnostic"]
        assert diag["late_request_indices"] == [1, 3, 5]      # 0.12, 0.25, 0.101 > 0.1
        assert diag["late_threshold_seconds"] == 0.1 and diag["usable"] is True

    def test_threshold_matches_the_driver(self):
        sys.path.insert(0, str(_REPO / "workload-generator"))
        try:
            from workload_generator import real_driver
        finally:
            sys.path.remove(str(_REPO / "workload-generator"))
        assert RB.DRIVER_LATE_START_SECONDS == real_driver.LATE_START_SECONDS

    @pytest.mark.parametrize("diag, reason", [
        (_diag(complete=False, truncated_reason="limit"), "limit"),
        (_diag(complete=False, truncated_reason="missing or invalid start lag"),
         "missing or invalid start lag"),
        (_diag(recorded=5), "recorded does not equal the number of entries"),
        (_diag(expected=7), "recorded does not equal expected"),
        (_diag(entries=[[0, 0.0, 0.1], [0, 0.2, 0.1]]), "not strictly increasing"),
        (_diag(entries=[[0, 0.0, -0.1]]), "non-finite or negative"),
        (_diag(entries=[[0, 0.0, float("nan")]]), "non-finite or negative"),
        (_diag(entries=[[0, 0.0]]), "malformed entry"),
        ({"entries": []}, "malformed diagnostic object"),
    ])
    def test_unusable_diagnostic_suppresses_percentiles(self, diag, reason):
        result = _with_diag(diag)
        sched = result["metrics"]["scheduler"]
        for q in (50, 95, 99):
            assert sched[f"start_lag_p{q}"]["kind"] == "NOT_MEASURED"
            assert sched[f"start_lag_p{q}"]["value"] is None
            assert reason in sched[f"start_lag_p{q}"]["reason"]
        stored = result["stop"]["generator_bound_evidence"]["start_lag_diagnostic"]
        assert stored["usable"] is False and stored["late_request_indices"] is None

    def test_absent_diagnostic_is_not_measured(self):
        result = _assembled()                                  # no start_lags key
        sched = result["metrics"]["scheduler"]
        assert sched["start_lag_p95"]["kind"] == "NOT_MEASURED"
        assert "no start-lag diagnostic" in sched["start_lag_p95"]["reason"]
        assert result["stop"]["generator_bound_evidence"]["start_lag_diagnostic"] is None

    def test_series_key_stays_null(self):
        for diag in (_diag(), _diag(complete=False, truncated_reason="limit"), None):
            evidence = _with_diag(diag)["stop"]["generator_bound_evidence"]
            assert evidence["start_lag_series"] is None

    def test_diagnostic_is_never_passed_to_a_decision(self, monkeypatch):
        bound_calls, growing_calls = [], []
        real_bound, real_growing = M.generator_bound, M.lag_growing

        def spy_bound(**kwargs):
            bound_calls.append(kwargs)
            return real_bound(**kwargs)

        def spy_growing(series, **kwargs):
            growing_calls.append(list(series))
            return real_growing(series, **kwargs)

        monkeypatch.setattr(M, "generator_bound", spy_bound)
        monkeypatch.setattr(M, "lag_growing", spy_growing)
        _with_diag(_diag())
        assert len(bound_calls) == 1
        assert "start_lag_series" not in bound_calls[0]       # the default () is used
        # The only lag_growing inputs are the Kafka lag samples (none here).
        assert growing_calls == [[], []]

    @pytest.mark.parametrize("late", [0, 5, 6, 10])
    def test_verdict_invariant_across_diagnostic_states(self, late):
        verdicts = set()
        for diag in (_diag(), _diag(complete=False, truncated_reason="limit"),
                     _diag(entries=[[0, 0.0, 0.5]] * 2), None):
            result = _with_diag(diag, late_starts=late)
            verdicts.add((result["verdict"], result["stop"]["generator_bound"],
                          tuple(result["verdict_reasons"])))
        assert len(verdicts) == 1
        expected = "GENERATOR_BOUND" if late > 5 else "VALID"
        assert next(iter(verdicts))[0] == expected

    def test_reproduction_from_json_ignores_the_diagnostic(self):
        result = json.loads(json.dumps(_with_diag(_diag(), late_starts=6)))
        evidence = result["stop"]["generator_bound_evidence"]
        bound, _ = RB.generator_bound_from_evidence(
            evidence, late_fraction=evidence["late_fraction"],
            lag_growth_samples=evidence["lag_growth_samples"])
        assert bound is True and result["verdict"] == "GENERATOR_BOUND"

    def test_old_result_shape_without_diagnostic_validates(self):
        older = json.loads(json.dumps(_assembled()))
        evidence = older["stop"]["generator_bound_evidence"]
        del evidence["start_lag_diagnostic"]
        for q in (50, 95, 99):
            del older["metrics"]["scheduler"][f"start_lag_p{q}"]
        M.validate_result(older)

    def test_historical_results_unchanged_if_present(self):
        import hashlib
        expected = {"bm-smoke-r0005-c32-rep1-20261008T174815.json": "e2f98781f555d31c",
                    "bm-smoke-r0005-c32-rep2-20261008T190552.json": "088c501ca0db9acb"}
        base = HISTORICAL_RESULT.parent
        for name, prefix in expected.items():
            path = base / name
            if path.exists():
                assert hashlib.sha256(path.read_bytes()).hexdigest().startswith(prefix)


# ---------------------------------------------------------------------------
# B3J-48d: SMOKE repetitions 4 and 5 are approved cells (nothing is run)
# ---------------------------------------------------------------------------

SMOKE_REPEAT_FIELDS = {"level": "SMOKE", "requests": 100, "rate": 5, "concurrency": 32,
                       "warmup_requests": 25}


class TestSmokeRepetitionsFourAndFive:
    @pytest.mark.parametrize("n", [4, 5])
    def test_recognised_as_approved_with_the_smoke_configuration(self, n):
        cell = _approved_cells(repetition=n)[0]
        bid = f"bm-smoke-r0005-c32-rep{n}"
        assert cell.benchmark_id == bid and RB.is_approved_live_cell(cell)
        assert dict(RB.APPROVED_LIVE_CELLS[bid]) == {**SMOKE_REPEAT_FIELDS, "repetition": n}
        assert (cell.level, cell.requests, cell.rate, cell.concurrency, cell.repetition,
                cell.warmup_requests) == ("SMOKE", 100, 5, 32, n, 25)
        checked = _authorize(_approved_cells(repetition=n), authorize=bid, repetition=n)
        assert checked == cell

    def test_exactly_the_four_smoke_cells_are_approved(self):
        smoke = {k: v for k, v in RB.APPROVED_LIVE_CELLS.items() if k.startswith("bm-smoke-")}
        assert sorted(smoke) == [f"bm-smoke-r0005-c32-rep{n}" for n in (2, 3, 4, 5)]
        assert [c["repetition"] for _, c in sorted(smoke.items())] == [2, 3, 4, 5]
        for approved in smoke.values():
            assert {k: v for k, v in approved.items() if k != "repetition"} == SMOKE_REPEAT_FIELDS
        assert len(RB.APPROVED_LIVE_CELLS) == 13     # four SMOKE cells plus SMALL-10 rep1-rep9

    def test_planned_ids_and_run_ids_are_distinct_across_all_repetitions(self):
        cells = [_approved_cells(repetition=n)[0] for n in (2, 3, 4, 5)]
        for attribute in ("benchmark_id", "warmup_run_id", "measured_run_id"):
            values = [getattr(c, attribute) for c in cells]
            assert len(set(values)) == 4, attribute
        assert [(c.benchmark_id, c.warmup_run_id, c.measured_run_id) for c in cells[2:]] == [
            ("bm-smoke-r0005-c32-rep4", "b-smoke-r0005-c32-w4", "b-smoke-r0005-c32-m4"),
            ("bm-smoke-r0005-c32-rep5", "b-smoke-r0005-c32-w5", "b-smoke-r0005-c32-m5")]
        for cell in cells:
            assert RB.RUN_ID_RE.fullmatch(cell.warmup_run_id)
            assert RB.RUN_ID_RE.fullmatch(cell.measured_run_id)

    @pytest.mark.parametrize("n", [4, 5])
    @pytest.mark.parametrize("overrides", [dict(rates=[10]), dict(concurrency=16),
                                           dict(warmup_requests=30)])
    def test_incorrect_parameters_are_refused(self, n, overrides):
        with pytest.raises(RB.BenchmarkError):
            _authorize(_approved_cells(repetition=n, **overrides),
                       authorize=f"bm-smoke-r0005-c32-rep{n}", repetition=n)

    @pytest.mark.parametrize("n", [4, 5])
    def test_wrong_selection_or_warmup_is_refused(self, n):
        bid = f"bm-smoke-r0005-c32-rep{n}"
        for repetition in (None, 2, 3, 6, n + 1 if n == 4 else 4):
            with pytest.raises(RB.BenchmarkError, match="repetition"):
                _authorize(_approved_cells(repetition=n), authorize=bid, repetition=repetition)
        for warmup in (None, 24, 26):
            with pytest.raises(RB.BenchmarkError, match="warmup-requests 25"):
                _authorize(_approved_cells(repetition=n), authorize=bid, repetition=n,
                           warmup_requests=warmup)
        with pytest.raises(RB.BenchmarkError, match="is not bm-smoke-r0005-c32-rep%d" % n):
            _authorize(_approved_cells(repetition=9 - n), authorize=bid, repetition=n)

    @pytest.mark.parametrize("authorize", ["bm-smoke-r0005-c32-rep6", "bm-smoke-r0005-c32-rep10",
                                           "bm-smoke-r0005-c32-rep1",
                                           "bm-small-r0005-c32-rep4",
                                           "bm-smoke-r0010-c32-rep4"])
    def test_rep6_rep1_and_small_cells_stay_refused(self, authorize):
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize(_approved_cells(repetition=4), authorize=authorize, repetition=4)
        for cell in (_approved_cells(repetition=6)[0], _approved_cells(repetition=1)[0],
                     RB.plan_cells(LADDER, "SMALL", rates=[10], repetition=1,
                                   concurrency=32, warmup_requests=25)[0]):
            assert not RB.is_approved_live_cell(cell), cell.benchmark_id

    def test_cell_fields_must_match_the_approved_ones_exactly(self):
        base = _approved_cells(repetition=4)[0]
        for change in (dict(requests=101), dict(rate=10), dict(concurrency=31),
                       dict(warmup_requests=26), dict(repetition=6), dict(level="SMALL")):
            assert not RB.is_approved_live_cell(dataclasses.replace(base, **change)), change

    @pytest.mark.parametrize("n", [4, 5])
    def test_main_with_the_gate_closed_refuses_before_anything(self, n, monkeypatch, tmp_path,
                                                               capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMOKE", "--rate", "5", "--repetition", str(n),
                        "--concurrency", "32", "--warmup-requests", "25", "--live",
                        "--authorize", f"bm-smoke-r0005-c32-rep{n}", "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "not enabled" in capsys.readouterr().err
        assert not out.exists()

    @pytest.mark.parametrize("n", [4, 5])
    def test_main_in_plan_mode_touches_nothing(self, n, tmp_path):
        import io
        out = io.StringIO()
        target = tmp_path / "plan-only"
        assert RB.main(["--level", "SMOKE", "--rate", "5", "--repetition", str(n),
                        "--concurrency", "32", "--warmup-requests", "25",
                        "--output-dir", str(target)], stdout=out) == 0
        assert f"bm-smoke-r0005-c32-rep{n}" in out.getvalue() and "PLAN ONLY" in out.getvalue()
        assert not target.exists()

    @pytest.mark.parametrize("n", [4, 5])
    def test_a_new_claim_leaves_existing_rep2_and_rep3_records_unchanged(self, n, tmp_path):
        ledger = tmp_path / "ledger"
        ledger.mkdir()
        existing = {}
        for old in (2, 3):
            for suffix, body in ((".started", "started-%d\n"), (".done", "done-%d\n")):
                path = ledger / f"bm-smoke-r0005-c32-rep{old}{suffix}"
                path.write_text(body % old, encoding="utf-8", newline="")
                existing[path] = path.read_bytes()
        result = tmp_path / "bm-smoke-r0005-c32-rep2-20261008T190552.json"
        result.write_text("{}", encoding="utf-8")
        existing[result] = result.read_bytes()
        cell, started = _claim(tmp_path, n=n)
        assert started == ledger / f"bm-smoke-r0005-c32-rep{n}.started" and started.is_file()
        for path, content in existing.items():
            assert path.read_bytes() == content, path.name
        assert sorted(p.name for p in ledger.iterdir()) == sorted(
            [f"bm-smoke-r0005-c32-rep{k}{s}" for k in (2, 3) for s in (".started", ".done")]
            + [f"bm-smoke-r0005-c32-rep{n}.started"])

    @pytest.mark.parametrize("n", [2, 3])
    def test_consumed_cells_stay_blocked_by_their_ledger_records(self, n, tmp_path):
        cell, started = _claim(tmp_path, n=n)
        (tmp_path / RB.OWNER_FILE).unlink()          # as after a released run
        with pytest.raises(RB.BenchmarkError, match="was started before"):
            _claim(tmp_path, n=n)
        assert started.is_file()

    def test_rep4_and_rep5_cannot_be_claimed_together(self, tmp_path):
        _claim(tmp_path, n=4)
        with pytest.raises(RB.BenchmarkError, match="owns this output directory"):
            _claim(tmp_path, n=5)
        assert not (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep5.started").exists()

    def test_the_gates_and_measurement_inputs_are_untouched(self):
        assert RB.LIVE_ENABLED is True            # unchanged by this step
        assert RB.MAX_WARMUP_REQUESTS == 10000
        assert dict(RB._SMOKE_REPEAT) == {**SMOKE_REPEAT_FIELDS}


# ---------------------------------------------------------------------------
# B3J-54: the first exploratory SMALL cell, SMALL-10 (nothing is run)
# ---------------------------------------------------------------------------

SMALL10_ID = "bm-small-r0010-c32-rep1"
SMALL10_FIELDS = {"level": "SMALL", "requests": 1000, "rate": 10, "concurrency": 32,
                  "warmup_requests": 300, "repetition": 1}


def _small(level="SMALL", rate=10, repetition=1, concurrency=32, warmup=300):
    return RB.plan_cells(LADDER, level, rates=[rate], repetition=repetition,
                         concurrency=concurrency, warmup_requests=warmup)[0]


def _authorize_small(cell, *, authorize=SMALL10_ID, expect_head=HEAD, warmup=300, repetition=1):
    return RB.check_live_authorization([cell], authorize=authorize, expect_head=expect_head,
                                       warmup_requests=warmup, repetition=repetition)


class TestSmallTenFirstCell:
    def test_exact_fields_ids_and_authorization(self):
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_ID]) == SMALL10_FIELDS
        cell = _small()
        assert cell.benchmark_id == SMALL10_ID
        assert (cell.warmup_run_id, cell.measured_run_id) == ("b-small-r0010-c32-w1",
                                                              "b-small-r0010-c32-m1")
        assert (cell.level, cell.requests, cell.rate, cell.concurrency, cell.repetition,
                cell.warmup_requests) == ("SMALL", 1000, 10, 32, 1, 300)
        assert cell.planned_spans == 7000 and cell.measured_seconds == 100.0
        assert cell.live_allowed is True and cell.refresh_and_detector is True
        assert RB.RUN_ID_RE.fullmatch(cell.warmup_run_id)
        assert RB.RUN_ID_RE.fullmatch(cell.measured_run_id)
        assert RB.is_approved_live_cell(cell)
        assert _authorize_small(cell) == cell

    def test_the_default_warmup_of_the_ladder_is_the_approved_one(self):
        default = RB.plan_cells(LADDER, "SMALL", rates=[10], repetition=1, concurrency=32)[0]
        assert default.warmup_requests == 300 and RB.is_approved_live_cell(default)

    def test_exactly_ten_cells_and_the_smoke_cells_unchanged(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == [
            SMALL10_ID, "bm-small-r0010-c32-rep2", "bm-small-r0010-c32-rep3",
            "bm-small-r0010-c32-rep4", "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9",
            "bm-smoke-r0005-c32-rep2",
            "bm-smoke-r0005-c32-rep3", "bm-smoke-r0005-c32-rep4", "bm-smoke-r0005-c32-rep5"]
        assert len(RB.APPROVED_LIVE_CELLS) == 13
        assert [k for k in RB.APPROVED_LIVE_CELLS if "small" in k] == [
            SMALL10_ID, "bm-small-r0010-c32-rep2", "bm-small-r0010-c32-rep3",
            "bm-small-r0010-c32-rep4", "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"]
        for n in (2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-smoke-r0005-c32-rep{n}"]) == {
                **SMOKE_REPEAT_FIELDS, "repetition": n}

    @pytest.mark.parametrize("warmup", [25, 150, 299, 301, 1000])
    def test_wrong_warmup_is_refused(self, warmup):
        cell = _small(warmup=warmup)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="warmup-requests 300"):
            _authorize_small(cell, warmup=warmup)

    @pytest.mark.parametrize("warmup", [None, 0, 299, 25])
    def test_wrong_warmup_argument_is_refused(self, warmup):
        with pytest.raises(RB.BenchmarkError, match="warmup-requests 300"):
            _authorize_small(_small(), warmup=warmup)

    @pytest.mark.parametrize("change", [dict(requests=999), dict(requests=1001),
                                        dict(requests=100), dict(rate=5), dict(rate=25),
                                        dict(concurrency=16), dict(concurrency=31),
                                        dict(concurrency=33), dict(repetition=10),
                                        dict(level="SMOKE"),
                                        dict(level="MEDIUM")])
    def test_any_changed_field_is_refused(self, change):
        assert not RB.is_approved_live_cell(dataclasses.replace(_small(), **change)), change

    @pytest.mark.parametrize("rate", [25, 50, 100])
    def test_other_small_rates_are_refused(self, rate):
        cell = _small(rate=rate)
        assert not RB.is_approved_live_cell(cell)
        bid = f"bm-small-r{rate:04d}-c32-rep1"
        assert cell.benchmark_id == bid
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=bid)
        with pytest.raises(RB.BenchmarkError, match="is not bm-small-r0010-c32-rep1"):
            _authorize_small(cell)

    @pytest.mark.parametrize("repetition", [10])
    def test_other_small_repetitions_are_refused(self, repetition):
        cell = _small(repetition=repetition)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r0010-c32-rep{repetition}",
                             repetition=repetition)
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize_small(cell, repetition=repetition)

    @pytest.mark.parametrize("level", ["MEDIUM", "LARGE", "STRESS"])
    def test_every_other_level_is_refused(self, level):
        spec = [lv for lv in LADDER["levels"] if lv["name"] == level][0]
        cell = _small(level=level, rate=spec["rates"][0])
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=cell.benchmark_id)

    @pytest.mark.parametrize("authorize", [None, "", " ", SMALL10_ID + " ", SMALL10_ID.upper(),
                                           "bm-small-r0010-c32-rep0",
                                           "bm-small-r0025-c32-rep1", "bm-small-r0010-c16-rep1",
                                           "bm-small-r0010-c32", "bm-smoke-r0010-c32-rep1",
                                           "bm-medium-r0050-c32-rep1"])
    def test_wrong_authorization_selectors_are_refused(self, authorize):
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(_small(), authorize=authorize)

    @pytest.mark.parametrize("repetition", [None, 0, 2, 5])
    def test_the_repetition_selector_must_be_one(self, repetition):
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize_small(_small(), repetition=repetition)

    @pytest.mark.parametrize("head", [None, "", "812ff80", "Z" * 40, HEAD + "0", "B" * 40])
    def test_the_expected_head_must_be_a_full_lowercase_commit(self, head):
        with pytest.raises(RB.BenchmarkError, match="expect-head"):
            _authorize_small(_small(), expect_head=head)

    def test_smoke_authorizations_cannot_run_the_small_cell(self):
        for n in (2, 3, 4, 5):
            with pytest.raises(RB.BenchmarkError):
                _authorize_small(_small(), authorize=f"bm-smoke-r0005-c32-rep{n}",
                                 repetition=n)
            with pytest.raises(RB.BenchmarkError, match="is not bm-smoke"):
                RB.check_live_authorization(
                    [_small()], authorize=f"bm-smoke-r0005-c32-rep{n}", expect_head=HEAD,
                    warmup_requests=25, repetition=n)

    def test_more_than_one_planned_cell_is_refused(self):
        cells = RB.plan_cells(LADDER, "SMALL", rates=[10, 25], repetition=1, concurrency=32,
                              warmup_requests=300)
        with pytest.raises(RB.BenchmarkError, match="exactly one cell"):
            RB.check_live_authorization(cells, authorize=SMALL10_ID, expect_head=HEAD,
                                        warmup_requests=300, repetition=1)

    def test_plan_only_mode_writes_nothing(self, tmp_path):
        import io
        out, target = io.StringIO(), tmp_path / "plan-only"
        assert RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "1",
                        "--concurrency", "32", "--warmup-requests", "300",
                        "--output-dir", str(target)], stdout=out) == 0
        text = out.getvalue()
        assert "PLAN ONLY" in text and SMALL10_ID in text
        assert "b-small-r0010-c32-w1" in text and "b-small-r0010-c32-m1" in text
        assert not target.exists() and list(tmp_path.iterdir()) == []

    def test_gate_closed_cli_refuses_before_anything(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "1",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "not enabled" in capsys.readouterr().err
        assert not out.exists()

    @pytest.mark.parametrize("extra", [
        ["--rate", "25"], ["--rate", "50"], ["--rate", "100"], ["--concurrency", "16"],
        ["--warmup-requests", "25"], ["--warmup-requests", "301"], ["--repetition", "2"],
    ])
    def test_cli_refuses_wrong_arguments_before_anything_starts(self, extra, monkeypatch,
                                                                tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", lambda *a, **k: pytest.fail("reached run_cell"))
        args = {"--level": "SMALL", "--rate": "10", "--repetition": "1", "--concurrency": "32",
                "--warmup-requests": "300"}
        for key, value in zip(extra[::2], extra[1::2]):
            args[key] = value
        argv = [item for pair in args.items() for item in pair]
        out = tmp_path / "out"
        code = RB.main([*argv, "--live", "--authorize", SMALL10_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "nothing was started" in capsys.readouterr().err
        assert not out.exists()

    def test_the_cli_reaches_run_cell_once_for_the_exact_cell(self, monkeypatch, tmp_path):
        import io
        calls = []

        def fake_run_cell(cell, ladder, **kw):
            calls.append((cell.benchmark_id, kw["expect_head"]))
            path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
            path.write_text("{}", encoding="utf-8")
            return {"verdict": "VALID"}, path, True

        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", fake_run_cell)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "1",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)], stdout=io.StringIO())
        assert code == 0 and calls == [(SMALL10_ID, HEAD)]
        assert (out / "ledger" / f"{SMALL10_ID}.started").is_file()
        assert (out / "ledger" / f"{SMALL10_ID}.done").is_file()
        assert not (out / RB.OWNER_FILE).exists()                 # released after a clean run

    def test_a_small_claim_leaves_the_smoke_records_untouched(self, tmp_path):
        ledger = tmp_path / "ledger"
        ledger.mkdir()
        before = {}
        for n in (2, 3, 4, 5):
            for suffix in (".started", ".done"):
                path = ledger / f"bm-smoke-r0005-c32-rep{n}{suffix}"
                path.write_text(f"smoke-{n}{suffix}\n", encoding="utf-8", newline="")
                before[path] = path.read_bytes()
        result = tmp_path / "bm-smoke-r0005-c32-rep5-20261011T143111.json"
        result.write_text("{}", encoding="utf-8")
        before[result] = result.read_bytes()
        started = RB.claim_run(tmp_path, _small(), head=HEAD, arguments={"repetition": 1},
                               now=lambda: 1_800_000_000.0, pid=lambda: 4242)
        assert started == ledger / f"{SMALL10_ID}.started" and started.is_file()
        for path, content in before.items():
            assert path.read_bytes() == content, path.name
        assert sorted(p.name for p in ledger.iterdir()) == sorted(
            [f"bm-smoke-r0005-c32-rep{n}{s}" for n in (2, 3, 4, 5) for s in (".started", ".done")]
            + [f"{SMALL10_ID}.started"])

    def test_the_small_cell_cannot_run_twice(self, tmp_path):
        started = RB.claim_run(tmp_path, _small(), head=HEAD, arguments={},
                               now=lambda: 1_800_000_000.0, pid=lambda: 4242)
        (tmp_path / RB.OWNER_FILE).unlink()          # as after a released run
        with pytest.raises(RB.BenchmarkError, match="was started before"):
            RB.claim_run(tmp_path, _small(), head=HEAD, arguments={})
        assert started.is_file()
        (tmp_path / "bm-small-r0010-c32-rep1-20261011T150000.json").write_text("{}")
        (tmp_path / "ledger" / f"{SMALL10_ID}.started").unlink()
        with pytest.raises(RB.BenchmarkError, match="already exists"):
            RB.claim_run(tmp_path, _small(), head=HEAD, arguments={})

    def test_the_small_and_smoke_cells_cannot_be_claimed_together(self, tmp_path):
        RB.claim_run(tmp_path, _small(), head=HEAD, arguments={})
        with pytest.raises(RB.BenchmarkError, match="owns this output directory"):
            _claim(tmp_path, n=4)
        assert not (tmp_path / "ledger" / "bm-smoke-r0005-c32-rep4.started").exists()

    def test_the_gates_ladder_and_thresholds_are_untouched(self):
        assert RB.LIVE_ENABLED is True and RB.MAX_WARMUP_REQUESTS == 10000
        spec = [lv for lv in LADDER["levels"] if lv["name"] == "SMALL"][0]
        assert (spec["target_requests"], spec["target_spans"], spec["rates"],
                spec["live_allowed"], spec["refresh_and_detector"]) == (
            1000, 7000, [10, 25, 50, 100], True, True)
        assert LADDER["defaults"]["cell_budget_seconds"] == 3600
        assert LADDER["defaults"]["drain_limit_seconds"] == 120
        assert LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert dict(RB._SMALL10_FIRST) == {k: v for k, v in SMALL10_FIELDS.items()
                                           if k != "repetition"}
        assert RB.projected_need_bytes(_small()) > RB.projected_need_bytes(_cell())


# ---------------------------------------------------------------------------
# B3J-59: optional diagnostics preserved in the result (nothing is run)
# ---------------------------------------------------------------------------

NEW_LEAVES = (("lag", "raw_series_records"), ("lag", "raw_series_times_s"),
              ("lag", "canonical_series_records"), ("lag", "canonical_series_times_s"),
              ("lag", "samples_taken"), ("lag", "sampler_started_epoch_s"),
              ("throughput", "persisted_per_second_series"),
              ("latency", "persistence_ms_max"), ("analytics", "detector_counts"),
              # B3J-68
              ("throughput", "timed_series_start_epoch_s"),
              ("throughput", "timed_ended_per_second_series"),
              ("throughput", "timed_ingested_per_second_series"),
              ("latency", "timed_persistence_ms_mean_series"),
              ("latency", "timed_persistence_ms_max_series"),
              ("latency", "timed_persistence_ms_series_offsets_s"),
              ("resources", "cpu_percent_max"), ("resources", "cpu_percent_series"),
              ("resources", "cpu_percent_series_times_s"),
              # B3J-84
              ("latency", "ingest_gap_ms_p50"), ("latency", "ingest_gap_ms_p90"),
              ("latency", "ingest_gap_ms_p99"), ("latency", "ingest_gap_ms_max"),
              ("latency", "ingest_gap_stalls"), ("latency", "ingest_gap_series_start_epoch_s"),
              ("latency", "ingest_gap_ms_median_by_second"),
              ("latency", "ingest_gap_ms_max_by_second"),
              ("latency", "ingest_gap_stalls_by_second"),
              ("latency", "ingest_gap_series_offsets_s"),
              ("throughput", "partition_rows"), ("throughput", "partition_offset_min"),
              ("throughput", "partition_offset_max"),
              ("throughput", "partition_distinct_offsets"),
              ("throughput", "partition_ingested_per_second_series"))
RISING_LAG = [(float(10 * i), {"raw": i, "canonical": 10 * i + 1}) for i in range(8)]


def _without_new_leaves(result):
    stripped = json.loads(json.dumps(result))
    for section, name in NEW_LEAVES:
        stripped["metrics"][section].pop(name, None)
    return stripped


def _baseline(monkeypatch, **evidence):
    """The same evidence assembled with the diagnostics switched off."""
    monkeypatch.setattr(RB, "_add_diagnostics", lambda *args, **kwargs: None)
    return _assembled(**evidence)


class TestDiagnosticCapture:
    def test_lag_series_and_times_are_preserved(self):
        samples = [(0.0, {"raw": 0, "canonical": 0}), (10.02, {"raw": 3, "canonical": 120}),
                   (20.0, {"raw": 2, "canonical": 277}), (30.0449, {"raw": 0, "canonical": 10})]
        lag = _assembled(lag_samples=samples)["metrics"]["lag"]
        assert lag["raw_series_records"]["value"] == [0, 3, 2, 0]
        assert lag["canonical_series_records"]["value"] == [0, 120, 277, 10]
        assert lag["raw_series_times_s"]["value"] == [0.0, 10.02, 20.0, 30.045]
        assert lag["canonical_series_times_s"]["value"] == [0.0, 10.02, 20.0, 30.045]
        for name in ("raw_series_records", "canonical_series_records", "raw_series_times_s",
                     "canonical_series_times_s"):
            assert lag[name]["kind"] == "OBSERVATION" and lag[name]["n"] == 4
        assert lag["samples_taken"]["value"] == 4 and lag["samples_taken"]["kind"] == "OBSERVATION"
        assert max(lag["canonical_series_records"]["value"]) == lag["canonical_max"]["value"] == 277
        assert max(lag["raw_series_records"]["value"]) == lag["raw_max"]["value"] == 3

    def test_failed_samples_are_omitted_and_never_zero(self):
        samples = [(0.0, {"raw": 1, "canonical": 5}), (10.0, None),
                   (20.0, {"raw": None, "canonical": 9}), (30.0, {"raw": 4, "canonical": None})]
        lag = _assembled(lag_samples=samples)["metrics"]["lag"]
        assert lag["raw_series_records"]["value"] == [1, 4]
        assert lag["raw_series_times_s"]["value"] == [0.0, 30.0]
        assert lag["canonical_series_records"]["value"] == [5, 9]
        assert lag["canonical_series_times_s"]["value"] == [0.0, 20.0]
        assert lag["samples_taken"]["value"] == 4                 # attempted, failed ones included
        assert lag["raw_series_records"]["n"] == lag["raw_series_times_s"]["n"] == 2
        assert 0 not in lag["canonical_series_records"]["value"]

    def test_no_samples_or_only_failed_samples_are_not_measured(self):
        lag = _assembled()["metrics"]["lag"]                      # no samples at all
        for name in ("raw_series_records", "raw_series_times_s", "canonical_series_records",
                     "canonical_series_times_s", "samples_taken"):
            assert lag[name]["kind"] == "NOT_MEASURED" and lag[name]["value"] is None, name
        assert "no lag samples" in lag["raw_series_records"]["reason"]
        failed = _assembled(lag_samples=[(0.0, None), (10.0, None)])["metrics"]["lag"]
        assert failed["raw_series_records"]["kind"] == "NOT_MEASURED"
        assert failed["raw_series_records"]["reason"] == "every sample failed"
        assert failed["samples_taken"]["value"] == 2

    def test_sampler_start_is_optional(self):
        assert "sampler_started_epoch_s" not in _assembled()["metrics"]["lag"]
        leaf = _assembled(sampler_started=5000.5)["metrics"]["lag"]["sampler_started_epoch_s"]
        assert leaf["value"] == 5000.5 and leaf["kind"] == "OBSERVATION" and leaf["n"] == 1
        assert leaf["window"] == {"start": RB._iso(5000.5), "end": RB._iso(5000.5),
                                  "clock": "host"}
        assert "after this instant" in leaf["method"]

    def test_ingestion_histogram_is_preserved_with_its_limits_stated(self):
        counts = [41, 69, 71, 70, 68]
        result = _assembled(db_overrides={"per_second": counts})
        leaf = result["metrics"]["throughput"]["persisted_per_second_series"]
        assert leaf["value"] == counts and leaf["n"] == 5 and leaf["kind"] == "OBSERVATION"
        assert leaf["window"] == {"start": RB._iso(5000.0), "end": RB._iso(5020.0),
                                  "clock": "database"}
        for phrase in ("counts only", "seconds with no rows are omitted",
                       "no bucket carries a timestamp", "gaps are not represented"):
            assert phrase in leaf["method"], phrase
        assert len(leaf["value"]) == len(counts)          # nothing was padded for missing seconds

    @pytest.mark.parametrize("db_overrides", [{"per_second": []}, {"per_second": None}])
    def test_missing_or_empty_histogram_is_not_measured(self, db_overrides):
        leaf = _assembled(db_overrides=db_overrides)["metrics"]["throughput"][
            "persisted_per_second_series"]
        assert leaf["kind"] == "NOT_MEASURED" and leaf["value"] is None
        assert "no per-second counts" in leaf["reason"]

    def test_no_database_result_is_handled(self):
        result = _assembled(database=None)
        leaf = result["metrics"]["throughput"]["persisted_per_second_series"]
        assert leaf["kind"] == "NOT_MEASURED" and leaf["reason"] == "no database result"
        assert result["metrics"]["latency"]["persistence_ms_max"]["kind"] == "NOT_MEASURED"

    def test_persistence_maximum_with_a_valid_clock(self):
        values = [10.0, 20.0, 4120.7, 30.0]
        leaf = _assembled(db_overrides={"persistence_ms": values})["metrics"]["latency"][
            "persistence_ms_max"]
        assert leaf["value"] == 4120.7 and leaf["kind"] == "DERIVED" and leaf["n"] == 4
        assert leaf["window"]["clock"] == "database"

    def test_persistence_maximum_is_not_reported_with_an_invalid_clock(self, tmp_path):
        result = _run(tmp_path, smoke=FakeSmoke(tmp_path, clock=(1000.0, 1000.0, 1000.05)))[0]
        assert result["clock"]["valid"] is False
        leaf = result["metrics"]["latency"]["persistence_ms_max"]
        assert leaf["kind"] == "NOT_MEASURED" and leaf["value"] is None
        assert "clock skew outside its limits" in leaf["reason"]

    def test_persistence_maximum_without_clock_samples_or_spans(self):
        no_clock = _assembled(clock_before=[], clock_after=[])["metrics"]["latency"]
        assert no_clock["persistence_ms_max"]["reason"] == "clock skew not measured"
        empty = _assembled(db_overrides={"persistence_ms": []})["metrics"]["latency"]
        assert empty["persistence_ms_max"]["kind"] == "NOT_MEASURED"
        assert empty["persistence_ms_max"]["reason"] == "no spans read"

    def test_detector_counts_by_signal_through_the_cell(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path)
        counts = result["metrics"]["analytics"]["detector_counts"]
        assert clean and sorted(counts) == sorted(result["metrics"]["analytics"]["detector_ms"])
        trace = counts["trace_latency/agentops.request"]
        assert {k: v["value"] for k, v in trace.items()} == {
            "candidates": 1300, "emitted": 22, "inserted": 22, "duplicate": 0}
        assert all(v["kind"] == "OBSERVATION" and v["n"] == 1 for v in trace.values())
        assert counts["tool_failure/"]["emitted"]["value"] == 0

    def test_only_the_four_counts_are_read_and_there_is_no_severity(self, tmp_path):
        groups = [{"signal_path": "trace_latency", "operation_name": "x", "candidates": "10",
                   "emitted": "2", "inserted": "2", "duplicate": "0", "duration_ms": "5",
                   "severity": "WARNING", "severity_counts": "INFO=1"}]
        assert RB.detector_counts_from_groups(groups) == {
            "trace_latency/x": {"candidates": 10, "emitted": 2, "inserted": 2, "duplicate": 0}}
        result = _run(tmp_path)[0]
        assert "severity" not in json.dumps(result).lower()
        import inspect
        for function in (RB.detector_counts_from_groups, RB._diag_detector_counts,
                         RB._add_diagnostics):
            assert "severity" not in inspect.getsource(function).replace("No severity", "")

    @pytest.mark.parametrize("groups", [None, 5, [], [{}], [{"signal_path": "a"}],
                                        [{"signal_path": "a", "operation_name": "b",
                                          "emitted": "x"}], ["not a mapping"]])
    def test_detector_count_parsing_never_raises(self, groups):
        assert RB.detector_counts_from_groups(groups) is None

    def test_detector_counts_without_the_detector(self):
        cell = dataclasses.replace(_cell(), refresh_and_detector=False)
        leaf = _assembled(cell=cell)["metrics"]["analytics"]["detector_counts"]
        assert leaf["kind"] == "NOT_MEASURED" and "not run at level" in leaf["reason"]
        unread = _assembled()["metrics"]["analytics"]["detector_counts"]
        assert unread["kind"] == "NOT_MEASURED" and unread["reason"] == "detector counts not read"

    def test_diagnostic_failure_keeps_the_required_result(self, monkeypatch):
        samples = [(float("nan"), {"raw": 1, "canonical": 2}), (10.0, {"raw": 1, "canonical": 3})]
        broken = _assembled(lag_samples=samples, sampler_started=5000.5)
        baseline = _baseline(monkeypatch, lag_samples=samples)
        assert any(text.startswith("diagnostic lag series not recorded")
                   for text in broken["limitations"])
        assert "raw_series_records" not in broken["metrics"]["lag"]
        assert "samples_taken" not in broken["metrics"]["lag"]          # atomic: all or none
        assert "sampler_started_epoch_s" in broken["metrics"]["lag"]    # the others survive
        stripped = _without_new_leaves(broken)
        stripped["limitations"] = [t for t in stripped["limitations"]
                                   if not t.startswith("diagnostic ")]
        assert stripped == baseline
        M.validate_result(broken)

    @pytest.mark.parametrize("builder", ["_diag_lag_series", "_diag_sampler_start",
                                         "_diag_ingest_series", "_diag_persistence_max",
                                         "_diag_detector_counts"])
    def test_any_failing_builder_is_isolated(self, monkeypatch, builder):
        def boom(*args, **kwargs):
            raise RuntimeError("builder failed")

        monkeypatch.setattr(RB, builder, boom)
        result = _assembled(lag_samples=RISING_LAG[:3], sampler_started=1.0)
        assert sum(t.startswith("diagnostic ") and t.endswith("RuntimeError")
                   for t in result["limitations"]) == 1
        assert result["verdict"] == "VALID" and result["integrity"]["ok"] is True
        assert result["metrics"]["latency"]["persistence_ms"]["p95"]["value"] == 40.0
        M.validate_result(result)

    def test_an_existing_metric_is_never_replaced(self):
        metrics = {"lag": {"samples_taken": {"kept": True}}}
        limitations = []
        RB._add_diagnostics(metrics, limitations, (
            ("lag series", lambda: {("lag", "samples_taken"): M.Metric(
                3, "samples", "OBSERVATION", "harness", "x", None, 3).to_dict()}),))
        assert metrics["lag"]["samples_taken"] == {"kept": True}
        assert limitations == ["diagnostic lag series not recorded: BenchmarkError"]

    def test_existing_results_are_unchanged_apart_from_the_new_leaves(self, monkeypatch):
        evidence = dict(lag_samples=RISING_LAG, sampler_started=5000.5,
                        db_overrides={"per_second": [30, 40, 50]})
        with_diagnostics = _assembled(**evidence)
        baseline = _baseline(monkeypatch, **evidence)
        assert _without_new_leaves(with_diagnostics) == baseline
        assert with_diagnostics["verdict"] == baseline["verdict"] == "STOPPED"   # lag grew
        assert with_diagnostics["stop"] == baseline["stop"]
        assert with_diagnostics["integrity"] == baseline["integrity"]
        assert with_diagnostics["claims"] == baseline["claims"]
        assert with_diagnostics["limitations"] == baseline["limitations"]

    def test_the_cell_records_the_sampler_start_and_keeps_its_call_order(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path)
        assert clean and smoke.calls == ORDER                  # the one post-run query of B3J-68
        leaf = result["metrics"]["lag"]["sampler_started_epoch_s"]
        assert leaf["value"] == 5003.0                         # the injected wall clock
        assert result["metrics"]["lag"]["samples_taken"]["value"] >= 1
        assert smoke.calls.count("psql") == 3

    def test_older_results_without_the_new_leaves_still_validate(self):
        M.validate_result(_without_new_leaves(_assembled(lag_samples=RISING_LAG)))
        older = _without_new_leaves(TestHistoricalCompatibility()._historical())
        assert not any(name in older["metrics"][section] for section, name in NEW_LEAVES)
        M.validate_result(older)                          # the pre-B3J-59 shape stays valid

    def test_serialization_validation_and_size(self, tmp_path, monkeypatch):
        evidence = dict(lag_samples=[(10.0 * i, {"raw": i, "canonical": 30 * i}) for i in range(12)],
                        sampler_started=5000.5, db_overrides={"per_second": list(range(100, 200))})
        result = _assembled(**evidence)
        path = RB.write_result(result, tmp_path / "out")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded == json.loads(json.dumps(result))
        M.validate_result(loaded)
        plain = json.dumps(_baseline(monkeypatch, **evidence), sort_keys=True)
        # B3J-59 allowed 6,000 bytes; B3J-68 and B3J-84 add 9 and 15 not-measured leaves
        # (about 250 bytes each) when no evidence exists.  A full-length result is bounded
        # separately in TestIngestGapLeaves.
        assert len(json.dumps(result, sort_keys=True)) - len(plain) < 14000

    def test_no_new_leaf_is_inside_the_percentile_mappings(self):
        latency = _assembled()["metrics"]["latency"]
        assert sorted(latency["persistence_ms"]) == ["p50", "p95", "p99"]
        assert sorted(latency["request_ms"]) == ["p50", "p95", "p99"]


# ---------------------------------------------------------------------------
# B3J-62: the SMALL-10 repeat, rep2 (nothing is run)
# ---------------------------------------------------------------------------

SMALL10_REP2_ID = "bm-small-r0010-c32-rep2"
SMALL10_REP2_FIELDS = {**SMALL10_FIELDS, "repetition": 2}


class TestSmallTenSecondRepetition:
    def test_rep2_is_approved_with_the_exact_specification(self):
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_REP2_ID]) == SMALL10_REP2_FIELDS
        cell = _small(repetition=2)
        assert cell.benchmark_id == SMALL10_REP2_ID and RB.is_approved_live_cell(cell)
        assert (cell.level, cell.rate, cell.requests, cell.warmup_requests, cell.concurrency,
                cell.seed, cell.repetition) == ("SMALL", 10, 1000, 300, 32, 42, 2)
        assert cell.target()["scenario"] == "normal"
        assert cell.planned_spans == 7000 and cell.measured_seconds == 100.0
        assert cell.live_allowed is True and cell.refresh_and_detector is True
        assert (cell.warmup_run_id, cell.measured_run_id) == ("b-small-r0010-c32-w2",
                                                              "b-small-r0010-c32-m2")
        assert RB.RUN_ID_RE.fullmatch(cell.warmup_run_id)
        assert RB.RUN_ID_RE.fullmatch(cell.measured_run_id)
        assert _authorize_small(cell, authorize=SMALL10_REP2_ID, repetition=2) == cell

    def test_rep1_and_rep2_differ_only_in_repetition_and_run_ids(self):
        first, second = _small(repetition=1).target(), _small(repetition=2).target()
        assert {k for k in first if first[k] != second[k]} == {
            "repetition", "warmup_run_id", "measured_run_id"}
        assert (first["repetition"], second["repetition"]) == (1, 2)
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_ID]) | {"repetition": 2} == dict(
            RB.APPROVED_LIVE_CELLS[SMALL10_REP2_ID])
        assert RB.REFRESH_TIMEOUT_SECONDS == 600.0 and LADDER["defaults"]["seed"] == 42

    def test_exactly_six_small_cells_and_four_smoke_cells(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == [
            SMALL10_ID, SMALL10_REP2_ID, "bm-small-r0010-c32-rep3", "bm-small-r0010-c32-rep4",
            "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9",
            "bm-smoke-r0005-c32-rep2",
            "bm-smoke-r0005-c32-rep3",
            "bm-smoke-r0005-c32-rep4", "bm-smoke-r0005-c32-rep5"]
        assert len(RB.APPROVED_LIVE_CELLS) == 13
        assert [k for k in RB.APPROVED_LIVE_CELLS if "small" in k] == [
            SMALL10_ID, SMALL10_REP2_ID, "bm-small-r0010-c32-rep3", "bm-small-r0010-c32-rep4",
            "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"]
        for n in (2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-smoke-r0005-c32-rep{n}"]) == {
                **SMOKE_REPEAT_FIELDS, "repetition": n}

    @pytest.mark.parametrize("repetition", [10])
    def test_rep9_and_higher_stay_refused(self, repetition):
        cell = _small(repetition=repetition)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r0010-c32-rep{repetition}",
                             repetition=repetition)
        for authorize, selector in ((SMALL10_ID, 1), (SMALL10_REP2_ID, 2),
                                    ("bm-small-r0010-c32-rep3", 3),
                                    ("bm-small-r0010-c32-rep4", 4),
                                    ("bm-small-r0010-c32-rep5", 5),
                                    ("bm-small-r0010-c32-rep6", 6)):
            with pytest.raises(RB.BenchmarkError):
                _authorize_small(cell, authorize=authorize, repetition=selector)

    def test_rep1_and_rep2_authorizations_cannot_be_interchanged(self):
        rep1, rep2 = _small(repetition=1), _small(repetition=2)
        assert _authorize_small(rep1) == rep1
        assert _authorize_small(rep2, authorize=SMALL10_REP2_ID, repetition=2) == rep2
        with pytest.raises(RB.BenchmarkError, match="is not bm-small-r0010-c32-rep1"):
            _authorize_small(rep2, authorize=SMALL10_ID, repetition=1)        # token 1, cell 2
        with pytest.raises(RB.BenchmarkError, match="is not bm-small-r0010-c32-rep2"):
            _authorize_small(rep1, authorize=SMALL10_REP2_ID, repetition=2)   # token 2, cell 1
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize_small(rep2, authorize=SMALL10_ID, repetition=2)        # wrong selector
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize_small(rep1, authorize=SMALL10_REP2_ID, repetition=1)

    @pytest.mark.parametrize("warmup", [None, 0, 25, 299, 301])
    def test_rep2_needs_the_exact_warmup_argument(self, warmup):
        with pytest.raises(RB.BenchmarkError, match="warmup-requests 300"):
            _authorize_small(_small(repetition=2), authorize=SMALL10_REP2_ID, repetition=2,
                             warmup=warmup)

    @pytest.mark.parametrize("change", [dict(requests=999), dict(rate=5), dict(rate=25),
                                        dict(concurrency=16), dict(concurrency=33),
                                        dict(warmup_requests=299), dict(level="SMOKE"),
                                        dict(repetition=1), dict(repetition=10)])
    def test_a_changed_rep2_field_is_not_the_approved_cell(self, change):
        cell = dataclasses.replace(_small(repetition=2), **change)
        approved = RB.APPROVED_LIVE_CELLS.get(cell.benchmark_id)
        assert approved is None or RB._cell_fields(cell) != dict(approved) or \
            cell.benchmark_id in (SMALL10_ID,) and change == dict(repetition=1)
        if change not in (dict(repetition=1),):
            assert not RB.is_approved_live_cell(cell), change

    @pytest.mark.parametrize("rate", [25, 50, 100])
    def test_other_small_rates_stay_refused_at_rep2(self, rate):
        cell = _small(rate=rate, repetition=2)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r{rate:04d}-c32-rep2", repetition=2)

    def test_a_rep2_claim_is_isolated_from_rep1_and_smoke(self, tmp_path):
        ledger = tmp_path / "ledger"
        ledger.mkdir()
        before = {}
        names = [f"{cid}{suffix}" for cid in (SMALL10_ID, "bm-smoke-r0005-c32-rep2",
                                              "bm-smoke-r0005-c32-rep5")
                 for suffix in (".started", ".done")]
        for name in names:
            path = ledger / name
            path.write_text(f"record {name}\n", encoding="utf-8", newline="")
            before[path] = path.read_bytes()
        for result in ("bm-small-r0010-c32-rep1-20261011T155919.json",
                       "bm-smoke-r0005-c32-rep5-20261011T143111.json"):
            path = tmp_path / result
            path.write_text("{}", encoding="utf-8")
            before[path] = path.read_bytes()
        started = RB.claim_run(tmp_path, _small(repetition=2), head=HEAD, arguments={},
                               now=lambda: 1_800_000_000.0, pid=lambda: 4242)
        assert started == ledger / f"{SMALL10_REP2_ID}.started" and started.is_file()
        for path, content in before.items():
            assert path.read_bytes() == content, path.name
        assert sorted(p.name for p in ledger.iterdir()) == sorted(names + [started.name])
        assert not list(tmp_path.glob(f"{SMALL10_REP2_ID}-*.json"))

    def test_rep2_cannot_run_twice_nor_alongside_rep1(self, tmp_path):
        started = RB.claim_run(tmp_path, _small(repetition=2), head=HEAD, arguments={})
        with pytest.raises(RB.BenchmarkError, match="owns this output directory"):
            RB.claim_run(tmp_path, _small(repetition=1), head=HEAD, arguments={})
        assert not (tmp_path / "ledger" / f"{SMALL10_ID}.started").exists()
        (tmp_path / RB.OWNER_FILE).unlink()          # as after a released run
        with pytest.raises(RB.BenchmarkError, match="was started before"):
            RB.claim_run(tmp_path, _small(repetition=2), head=HEAD, arguments={})
        assert started.is_file()

    def test_the_cli_reaches_run_cell_once_for_an_authorized_rep2(self, monkeypatch, tmp_path):
        import io
        calls = []

        def fake_run_cell(cell, ladder, **kw):
            calls.append((cell.benchmark_id, kw["expect_head"]))
            path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
            path.write_text("{}", encoding="utf-8")
            return {"verdict": "VALID"}, path, True

        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", fake_run_cell)
        out = tmp_path / "out"
        (out / "ledger").mkdir(parents=True)
        rep1_record = out / "ledger" / f"{SMALL10_ID}.done"
        rep1_record.write_text("rep1", encoding="utf-8")
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "2",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_REP2_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)], stdout=io.StringIO())
        assert code == 0 and calls == [(SMALL10_REP2_ID, HEAD)]
        assert (out / "ledger" / f"{SMALL10_REP2_ID}.started").is_file()
        assert (out / "ledger" / f"{SMALL10_REP2_ID}.done").is_file()
        assert rep1_record.read_text(encoding="utf-8") == "rep1"
        assert not (out / RB.OWNER_FILE).exists()

    def test_gate_closed_cli_refuses_rep2_before_anything(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "2",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_REP2_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "not enabled" in capsys.readouterr().err
        assert not out.exists()

    @pytest.mark.parametrize("extra", [
        ["--rate", "25"], ["--rate", "50"], ["--rate", "100"], ["--concurrency", "16"],
        ["--warmup-requests", "25"], ["--warmup-requests", "301"], ["--repetition", "1"],
        ["--repetition", "3"],
    ])
    def test_cli_refuses_wrong_rep2_arguments_before_anything_starts(
            self, extra, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", lambda *a, **k: pytest.fail("reached run_cell"))
        args = {"--level": "SMALL", "--rate": "10", "--repetition": "2", "--concurrency": "32",
                "--warmup-requests": "300"}
        for key, value in zip(extra[::2], extra[1::2]):
            args[key] = value
        argv = [item for pair in args.items() for item in pair]
        out = tmp_path / "out"
        code = RB.main([*argv, "--live", "--authorize", SMALL10_REP2_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "nothing was started" in capsys.readouterr().err
        assert not out.exists()

    def test_plan_only_mode_for_rep2_writes_nothing(self, tmp_path):
        import io
        out, target = io.StringIO(), tmp_path / "plan-only"
        assert RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "2",
                        "--concurrency", "32", "--warmup-requests", "300",
                        "--output-dir", str(target)], stdout=out) == 0
        assert "PLAN ONLY" in out.getvalue() and SMALL10_REP2_ID in out.getvalue()
        assert "b-small-r0010-c32-w2" in out.getvalue() and "b-small-r0010-c32-m2" in out.getvalue()
        assert not target.exists() and list(tmp_path.iterdir()) == []

    def test_a_rep2_result_still_carries_the_diagnostics_and_validates(self):
        result = _assembled(cell=_small(repetition=2), lag_samples=RISING_LAG[:4],
                            sampler_started=5000.5)
        assert result["benchmark_id"] == SMALL10_REP2_ID
        for section, name in NEW_LEAVES:
            assert name in result["metrics"][section], name
        M.validate_result(result)     # the SMOKE-sized fixture is not a SMALL run: no verdict claim

    def test_the_gates_and_thresholds_are_untouched_by_rep2(self):
        assert RB.LIVE_ENABLED is True and RB.MAX_WARMUP_REQUESTS == 10000
        assert dict(RB._SMALL10_FIRST) == {k: v for k, v in SMALL10_FIELDS.items()
                                           if k != "repetition"}
        assert LADDER["defaults"]["cell_budget_seconds"] == 3600
        assert LADDER["defaults"]["drain_limit_seconds"] == 120
        assert LADDER["stop_limits"]["late_start_fraction"] == 0.05


# ---------------------------------------------------------------------------
# B3J-68: time-aligned series and retained CPU samples (nothing is run)
# ---------------------------------------------------------------------------

TIMED_LEAVES = (("throughput", "timed_series_start_epoch_s"),
                ("throughput", "timed_ended_per_second_series"),
                ("throughput", "timed_ingested_per_second_series"),
                ("latency", "timed_persistence_ms_mean_series"),
                ("latency", "timed_persistence_ms_max_series"),
                ("latency", "timed_persistence_ms_series_offsets_s"))
CPU_LEAVES = (("resources", "cpu_percent_max"), ("resources", "cpu_percent_series"),
              ("resources", "cpu_percent_series_times_s"))
STATS = [(0.0, [{"name": "kafka", "cpu_percent": 5.0, "memory_used_bytes": 100,
                 "memory_limit_bytes": 1000},
                {"name": "pg", "cpu_percent": 0.0, "memory_used_bytes": 50,
                 "memory_limit_bytes": 1000}]),
         (14.2, [{"name": "kafka", "cpu_percent": 180.5, "memory_used_bytes": 110,
                  "memory_limit_bytes": 1000},
                 {"name": "pg", "cpu_percent": 12.25, "memory_used_bytes": 55,
                  "memory_limit_bytes": 1000}])]
INVALID_CLOCK = dict(clock_before=[M.ClockSample(1000.0, 1000.0, 1000.05)],
                     clock_after=[M.ClockSample(1001.0, 1001.0, 1001.05)])


def _timed(**changes):
    return _assembled(timed_series=timed_series_payload(**changes))["metrics"]


class TestTimedSeries:
    def test_the_sql_is_read_only_bounded_and_scoped_to_the_run(self):
        import re
        sql = RB.run_series_sql("b-small-r0010-c32-m2")
        words = set(re.findall(r"[a-z_]+", sql.lower()))
        assert sql.lstrip().upper().startswith("WITH") and ";" not in sql
        assert not words & {"insert", "update", "delete", "drop", "alter", "create", "truncate",
                            "grant", "revoke", "copy", "vacuum", "set"}
        assert sql.count("'b-small-r0010-c32-m2'") == 1
        assert "agentops.workload.run_id' = 'b-small-r0010-c32-m2'" in sql
        assert "parent_span_id IS NULL" in sql and "trace_id IN (SELECT trace_id FROM roots)" in sql
        assert str(RB.MAX_TIMED_SERIES_SECONDS) in sql and RB.MAX_TIMED_SERIES_SECONDS == 1800
        assert "CASE WHEN t1 >= t0 AND t1 - t0 <" in sql        # bounded in SQL, never truncated
        assert sql == RB.run_series_sql("b-small-r0010-c32-m2")      # deterministic
        assert "w2" not in sql

    @pytest.mark.parametrize("run_id", ["", "x'; DROP TABLE telemetry_spans; --", "B-SMALL",
                                        "b-small' OR '1'='1", "b-small\n-m2", None])
    def test_a_bad_run_id_is_refused(self, run_id):
        with pytest.raises((RB.BenchmarkError, TypeError)):
            RB.run_series_sql(run_id)

    def test_persistence_uses_the_same_expression_and_clocks_as_the_required_query(self):
        expression = "extract(epoch from (ingested_at - end_time)) * 1000.0"
        assert expression in RB.run_metrics_sql("b-small-r0010-c32-m2")
        assert expression in RB.run_series_sql("b-small-r0010-c32-m2")
        leaf = _timed()["latency"]["timed_persistence_ms_max_series"]
        assert leaf["source"] == "ingested_at (database clock) - end_time (host clock)"
        assert leaf["kind"] == "DERIVED" and leaf["unit"] == "ms"

    def test_the_required_query_is_untouched(self):
        import hashlib
        text = RB.run_metrics_sql("b-small-r0010-c32-m2")
        assert hashlib.sha256(text.encode()).hexdigest() == (
            "4d4154095e38f1f58e7ca4018e92379d8b5082ff0d027b37d42c064b4af3a936")
        assert "generate_series" not in text and "per_second" in text

    def test_the_axis_is_explicit_deterministic_and_aligned(self):
        first, second = _timed(), _timed()
        assert first["throughput"] == second["throughput"] and first["latency"] == second["latency"]
        start = first["throughput"]["timed_series_start_epoch_s"]
        assert start["value"] == 4999 and start["unit"] == "s" and start["kind"] == "OBSERVATION"
        assert start["window"] == {"start": RB._iso(4999), "end": RB._iso(5021), "clock": "host"}
        ended = first["throughput"]["timed_ended_per_second_series"]
        ingested = first["throughput"]["timed_ingested_per_second_series"]
        assert len(ended["value"]) == len(ingested["value"]) == ended["n"] == 22
        assert sum(ended["value"]) == sum(ingested["value"]) == 700
        assert "epoch" in start["method"] and "index i" in start["method"]
        offsets = first["latency"]["timed_persistence_ms_series_offsets_s"]["value"]
        assert offsets == list(range(1, 21))
        assert all(ingested["value"][i] > 0 for i in offsets)
        for name in ("timed_persistence_ms_mean_series", "timed_persistence_ms_max_series"):
            assert first["latency"][name]["n"] == len(offsets) == len(first["latency"][name]["value"])
        assert first["latency"]["timed_persistence_ms_mean_series"]["value"][0] == 40.0
        assert first["latency"]["timed_persistence_ms_max_series"]["value"][0] == 45.5
        assert ingested["source"].endswith("(database clock)")
        assert ended["source"].endswith("(host clock)")

    def test_zero_seconds_are_observed_zeros_and_latency_has_no_value_for_them(self):
        metrics = _timed()
        ended = metrics["throughput"]["timed_ended_per_second_series"]["value"]
        ingested = metrics["throughput"]["timed_ingested_per_second_series"]["value"]
        assert ended[:2] == [35, 35] and ended[20:] == [0, 0] and ingested[0] == 0
        assert ingested[21] == 0 and ingested.count(0) == 2
        latency = metrics["latency"]["timed_persistence_ms_mean_series"]["value"]
        assert len(latency) == 20 and 0 not in latency            # 2 empty seconds, no value

    def test_a_series_that_is_all_zeros_but_one_second_validates(self):
        payload = timed_series_payload(
            seconds=3, rows=7, start=100, ended=[7, 0, 0], ingested=[0, 0, 7],
            latency_offsets=[2], latency_mean_ms=[2000.0], latency_max_ms=[2000.0])
        metrics = _assembled(timed_series=payload, db_overrides={"rows": 7, "distinct_spans": 7,
                                                                  "roots": 100})["metrics"]
        assert metrics["throughput"]["timed_ingested_per_second_series"]["value"] == [0, 0, 7]

    def test_missing_measurements_are_not_measured_never_zero(self):
        for result in (_assembled(), _assembled(timed_series=None)):
            for section, name in TIMED_LEAVES:
                leaf = result["metrics"][section][name]
                assert leaf["kind"] == "NOT_MEASURED" and leaf["value"] is None, name
                assert leaf["reason"] == "the optional per-second query did not run or failed"
        no_clock = _assembled(timed_series=timed_series_payload(), clock_before=[],
                              clock_after=[])["metrics"]
        invalid = _assembled(timed_series=timed_series_payload(), **INVALID_CLOCK)["metrics"]
        for metrics, reason in ((no_clock, "clock skew not measured"),
                                (invalid, "clock skew outside its limits")):
            for section, name in TIMED_LEAVES:
                leaf = metrics[section][name]
                assert leaf["kind"] == "NOT_MEASURED" and leaf["value"] is None
                assert leaf["reason"].startswith(reason), (name, leaf["reason"])

    def test_a_run_with_no_spans_is_not_measured(self):
        empty = {"start_epoch_s": None, "end_epoch_s": None, "rows": 0, "cap_seconds": 1800,
                 "ended": None, "ingested": None, "latency_offsets": None,
                 "latency_mean_ms": None, "latency_max_ms": None}
        leaf = _assembled(timed_series=empty)["metrics"]["throughput"][
            "timed_ended_per_second_series"]
        assert leaf["kind"] == "NOT_MEASURED" and "no spans" in leaf["reason"]

    def test_the_series_length_bound_is_enforced(self):
        cap = RB.MAX_TIMED_SERIES_SECONDS
        at_cap = timed_series_payload(
            seconds=cap, ended=[0] * (cap - 1) + [700],
            ingested=[700] + [0] * (cap - 1), latency_offsets=[0],
            latency_mean_ms=[1.0], latency_max_ms=[1.0])
        metrics = _assembled(timed_series=at_cap)["metrics"]
        assert len(metrics["throughput"]["timed_ended_per_second_series"]["value"]) == cap
        over = timed_series_payload(
            seconds=cap + 1, ended=[0] * cap + [700], ingested=[700] + [0] * cap,
            latency_offsets=[0], latency_mean_ms=[1.0], latency_max_ms=[1.0])
        leaf = _assembled(timed_series=over)["metrics"]["throughput"][
            "timed_ended_per_second_series"]
        assert leaf["kind"] == "NOT_MEASURED" and "exceeds the bound of 1800 s" in leaf["reason"]

    @pytest.mark.parametrize("changes, why", [
        (dict(ended=[35] * 21), "one count per second"),
        (dict(ingested=[1.5] + [0] * 21), "not a count"),
        (dict(ingested=[True] + [0] * 21), "not a count"),
        (dict(ended=[-35] + [35] * 19 + [0, 0]), "not a count"),
        (dict(ended=[36] + [35] * 19 + [0, 0]), "counts 701 spans, not 700"),
        (dict(rows=699), "699 rows, the required query 700"),
        (dict(latency_offsets=[2, 1] + list(range(3, 21)) ), "latency offsets are not increasing"),
        (dict(latency_offsets=list(range(1, 20)) + [22]), "latency offsets are not increasing"),
        (dict(latency_mean_ms=[40.0] * 19), "latency arrays do not match"),
        (dict(latency_mean_ms=[float("nan")] + [40.0] * 19), "not a finite number"),
        (dict(latency_mean_ms=[50.0] * 20), "mean latency exceeds its maximum"),
        (dict(latency_offsets=list(range(0, 20))), "no ingested span"),
        (dict(latency_offsets=list(range(1, 20)), latency_mean_ms=[40.0] * 19,
              latency_max_ms=[45.0] * 19), "missing for seconds"),
        (dict(end_epoch_s=4990), "before the first span end"),
        (dict(start_epoch_s="4999"), "not a whole number"),
    ])
    def test_an_inconsistent_series_is_not_measured_and_changes_nothing(self, changes, why):
        baseline = _assembled()
        result = _assembled(timed_series=timed_series_payload(**changes))
        leaf = result["metrics"]["throughput"]["timed_ended_per_second_series"]
        assert leaf["kind"] == "NOT_MEASURED" and why in leaf["reason"], leaf["reason"]
        assert result["verdict"] == baseline["verdict"] == "VALID"
        assert result["integrity"] == baseline["integrity"]
        assert result["stop"] == baseline["stop"] and result["claims"] == baseline["claims"]

    def test_the_required_metrics_are_identical_with_and_without_the_series(self, monkeypatch):
        evidence = dict(timed_series=timed_series_payload(), resource_samples=STATS)
        with_series = _assembled(**evidence)
        baseline = _baseline(monkeypatch, **evidence)
        stripped = json.loads(json.dumps(with_series))
        for section, name in NEW_LEAVES + TIMED_LEAVES + CPU_LEAVES:
            stripped["metrics"][section].pop(name, None)
        assert stripped == baseline
        assert with_series["verdict"] == baseline["verdict"] == "VALID"

    def test_the_builder_failing_is_isolated(self, monkeypatch):
        monkeypatch.setattr(RB, "_diag_timed_series",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        result = _assembled(timed_series=timed_series_payload())
        assert "diagnostic timed series not recorded: RuntimeError" in result["limitations"]
        assert "timed_ended_per_second_series" not in result["metrics"]["throughput"]
        assert result["verdict"] == "VALID" and result["integrity"]["ok"] is True
        M.validate_result(result)

    def test_older_results_without_any_new_leaf_still_validate(self):
        result = _assembled(timed_series=timed_series_payload(), resource_samples=STATS)
        older = json.loads(json.dumps(result))
        for section, name in NEW_LEAVES + TIMED_LEAVES + CPU_LEAVES:
            older["metrics"][section].pop(name, None)
        M.validate_result(older)
        assert older["metrics"]["resources"] == {
            "memory_peak_bytes": result["metrics"]["resources"]["memory_peak_bytes"]}


class TestTimedSeriesInTheCell:
    def test_one_post_run_query_after_the_measured_stage_and_clock_check(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path)
        assert clean and result["verdict"] == "VALID"
        assert smoke.calls == ORDER and smoke.calls.count("psql") == 3
        measured = smoke.calls.index("run_stage_measured")
        assert smoke.calls.index("psql") > measured
        assert smoke.calls[smoke.calls.index("psql") + 1] == "clock_probe"
        assert smoke.calls[smoke.calls.index("clock_probe", measured) + 1] == "psql"
        first, second, _gap = smoke.psql_sql
        assert "distinct_spans" in first and "generate_series" not in first
        assert "generate_series" in second and "distinct_spans" not in second
        cell = _cell()
        assert cell.measured_run_id in second and cell.warmup_run_id not in second
        assert first == RB.run_metrics_sql(cell.measured_run_id)
        assert second == RB.run_series_sql(cell.measured_run_id)

    def test_the_cell_records_the_series_next_to_the_required_metrics(self, tmp_path):
        result = _run(tmp_path)[0]
        series = result["metrics"]["throughput"]["timed_ended_per_second_series"]
        assert series["kind"] == "OBSERVATION" and sum(series["value"]) == 700
        assert result["metrics"]["throughput"]["persisted_per_second_series"]["n"] == 20
        for section, name in TIMED_LEAVES + CPU_LEAVES:
            assert name in result["metrics"][section]

    @pytest.mark.parametrize("how", ["raises", "not_json", "wrong_shape"])
    def test_an_optional_query_failure_never_changes_the_verdict(self, tmp_path, monkeypatch, how):
        (tmp_path / "good").mkdir()
        (tmp_path / "bad").mkdir()
        good = _run(tmp_path / "good")
        smoke = FakeSmoke(tmp_path / "bad")
        original = smoke.psql

        def psql(sql):
            if "generate_series" not in sql:
                return original(sql)
            smoke._step("psql")
            smoke.psql_sql.append(sql)
            if how == "raises":
                raise Boom("series query failed")
            return "not json {" if how == "not_json" else "[1, 2, 3]"

        smoke.psql = psql
        result, path, clean, _ = _run(tmp_path / "bad", smoke=smoke)
        assert clean and result["verdict"] == good[0]["verdict"] == "VALID"
        for key in ("integrity", "stop", "claims", "counts", "clock"):
            assert result[key] == good[0][key], key
        if how == "wrong_shape":
            leaf = result["metrics"]["throughput"]["timed_ended_per_second_series"]
            assert leaf["kind"] == "NOT_MEASURED"
        else:
            assert any(t.startswith("diagnostic timed series query not recorded")
                       for t in result["limitations"])
            assert result["metrics"]["throughput"]["timed_ended_per_second_series"][
                "kind"] == "NOT_MEASURED"
        assert result["metrics"]["latency"]["persistence_ms"] == good[0]["metrics"]["latency"][
            "persistence_ms"]
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    def test_a_failure_of_the_required_query_still_fails_the_cell_as_before(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="psql"))
        assert result["verdict"] != "VALID"
        assert smoke.calls.count("psql") == 1          # the optional query never ran


class TestRetainedCpu:
    def test_cpu_is_kept_per_container_from_the_existing_samples(self):
        resources = _assembled(resource_samples=STATS)["metrics"]["resources"]
        assert resources["cpu_percent_max"]["kafka"]["value"] == 180.5
        assert resources["cpu_percent_max"]["pg"]["value"] == 12.25
        assert resources["cpu_percent_series"]["kafka"]["value"] == [5.0, 180.5]
        assert resources["cpu_percent_series"]["pg"]["value"] == [0.0, 12.25]   # a real 0.0 stays
        assert resources["cpu_percent_series_times_s"]["pg"]["value"] == [0.0, 14.2]
        for name in ("cpu_percent_max", "cpu_percent_series"):
            assert resources[name]["kafka"]["unit"] == "%" and resources[name]["kafka"]["n"] == 2
            assert "host processes" in resources[name]["kafka"]["method"]
        assert resources["memory_peak_bytes"]["kafka"]["value"] == 110      # unchanged

    def test_no_samples_is_not_measured(self):
        resources = _assembled()["metrics"]["resources"]
        for name in ("cpu_percent_max", "cpu_percent_series", "cpu_percent_series_times_s"):
            leaf = resources[name]["all"]
            assert leaf["kind"] == "NOT_MEASURED" and leaf["reason"] == "no resource samples"

    @pytest.mark.parametrize("bad", [None, "5.0%", "", True, False, float("nan"),
                                     float("inf"), -1.0, [5.0], {"x": 1}])
    def test_a_malformed_value_is_skipped_never_zero(self, bad):
        samples = [(0.0, [{"name": "kafka", "cpu_percent": 1.5, "memory_used_bytes": 1,
                           "memory_limit_bytes": 10}]),
                   (10.0, [{"name": "kafka", "cpu_percent": bad, "memory_used_bytes": 1,
                            "memory_limit_bytes": 10}]),
                   (20.0, [{"name": "kafka", "memory_used_bytes": 1,
                            "memory_limit_bytes": 10}])]
        resources = _assembled(resource_samples=samples)["metrics"]["resources"]
        assert resources["cpu_percent_series"]["kafka"]["value"] == [1.5]
        assert resources["cpu_percent_series_times_s"]["kafka"]["value"] == [0.0]
        assert resources["cpu_percent_max"]["kafka"]["n"] == 1

    def test_every_malformed_shape_is_skipped_by_the_builder(self):
        evidence = SimpleNamespace(resource_samples=[
            None, 5, (1.0,), ("late", []), (float("nan"), [{"name": "a", "cpu_percent": 1.0}]),
            (1.0, None), (1.0, "rows"), (2.0, [None, 3, "row", {"cpu_percent": 4.0},
                                                {"name": 7, "cpu_percent": 4.0},
                                                {"name": "ok", "cpu_percent": 7.5}]),
            (3.0, [{"name": "ok", "cpu_percent": 0}])])
        added = RB._diag_cpu(evidence)
        assert added[("resources", "cpu_percent_series")]["ok"]["value"] == [7.5, 0.0]
        assert added[("resources", "cpu_percent_series_times_s")]["ok"]["value"] == [2.0, 3.0]
        assert set(added[("resources", "cpu_percent_max")]) == {"ok"}
        none = RB._diag_cpu(SimpleNamespace(resource_samples=[(1.0, [{"name": "a"}])]))
        leaf = none[("resources", "cpu_percent_max")]["all"]
        assert leaf["kind"] == "NOT_MEASURED" and "no sample held a usable cpu_percent" in leaf[
            "reason"]

    def test_no_new_sampling_and_the_same_sampler_interval(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path)
        assert clean and smoke.calls.count("docker_stats") == 2     # as in ORDER, before B3J-68
        assert smoke.calls == ORDER
        assert LADDER["defaults"]["sample_interval_seconds"] == 10
        resources = result["metrics"]["resources"]
        assert resources["cpu_percent_max"]["proj-kafka-1"]["value"] == 5.0

    def test_cpu_values_never_reach_the_stop_rules_or_the_verdict(self, monkeypatch):
        seen = []
        real = M.resource_stops

        def spy(**kwargs):
            seen.append(sorted(kwargs))
            return real(**kwargs)

        monkeypatch.setattr(M, "resource_stops", spy)
        hot = [(at, [dict(row, cpu_percent=100000.0) for row in rows]) for at, rows in STATS]
        quiet = [(at, [dict(row, cpu_percent=0.0) for row in rows]) for at, rows in STATS]
        loud, calm = _assembled(resource_samples=hot), _assembled(resource_samples=quiet)
        assert loud["verdict"] == calm["verdict"] == "VALID"
        assert loud["stop"] == calm["stop"] and loud["integrity"] == calm["integrity"]
        assert seen and all("cpu_percent" not in names for names in seen)
        assert loud["metrics"]["resources"]["memory_peak_bytes"] == calm["metrics"]["resources"][
            "memory_peak_bytes"]


class TestB3J68DidNotChangeSafetyOrTheAllowlist:
    def test_gates_thresholds_and_the_allowlist_after_the_rep4_patch(self):
        assert RB.LIVE_ENABLED is True and RB.MAX_WARMUP_REQUESTS == 10000
        assert sorted(RB.APPROVED_LIVE_CELLS) == [
            "bm-small-r0010-c32-rep1", "bm-small-r0010-c32-rep2", "bm-small-r0010-c32-rep3",
            "bm-small-r0010-c32-rep4", "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9",
            "bm-smoke-r0005-c32-rep2",
            "bm-smoke-r0005-c32-rep3", "bm-smoke-r0005-c32-rep4", "bm-smoke-r0005-c32-rep5"]
        assert len(RB.APPROVED_LIVE_CELLS) == 13
        assert "bm-small-r0010-c32-rep7" in RB.APPROVED_LIVE_CELLS
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6
        assert LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert LADDER["stop_limits"]["memory_fraction"] == 0.90
        assert LADDER["defaults"]["cell_budget_seconds"] == 3600


# ---------------------------------------------------------------------------
# B3J-71: the SMALL-10 rep3 (nothing is run)
# ---------------------------------------------------------------------------

SMALL10_REP3_ID = "bm-small-r0010-c32-rep3"
SMALL10_REP3_FIELDS = {**SMALL10_FIELDS, "repetition": 3}
SMALL10_TOKENS = {1: SMALL10_ID, 2: SMALL10_REP2_ID, 3: SMALL10_REP3_ID}
ALLOWLISTED_CELLS = [SMALL10_ID, SMALL10_REP2_ID, SMALL10_REP3_ID,
                     "bm-small-r0010-c32-rep4", "bm-small-r0010-c32-rep5",
                     "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9",
                     "bm-smoke-r0005-c32-rep2",
                     "bm-smoke-r0005-c32-rep3", "bm-smoke-r0005-c32-rep4",
                     "bm-smoke-r0005-c32-rep5"]


class TestSmallTenThirdRepetition:
    def test_rep3_is_approved_with_the_exact_specification(self):
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_REP3_ID]) == SMALL10_REP3_FIELDS
        cell = _small(repetition=3)
        assert cell.benchmark_id == SMALL10_REP3_ID and RB.is_approved_live_cell(cell)
        assert (cell.level, cell.rate, cell.requests, cell.warmup_requests, cell.concurrency,
                cell.seed, cell.repetition) == ("SMALL", 10, 1000, 300, 32, 42, 3)
        assert cell.target()["scenario"] == "normal"
        assert cell.planned_spans == 7000 and cell.measured_seconds == 100.0
        assert cell.live_allowed is True and cell.refresh_and_detector is True
        assert (cell.warmup_run_id, cell.measured_run_id) == ("b-small-r0010-c32-w3",
                                                              "b-small-r0010-c32-m3")
        assert RB.RUN_ID_RE.fullmatch(cell.warmup_run_id)
        assert RB.RUN_ID_RE.fullmatch(cell.measured_run_id)
        assert _authorize_small(cell, authorize=SMALL10_REP3_ID, repetition=3) == cell

    def test_the_three_small_cells_differ_only_in_repetition_and_run_ids(self):
        targets = {n: _small(repetition=n).target() for n in (1, 2, 3)}
        for a, b in ((1, 2), (1, 3), (2, 3)):
            changed = {k for k in targets[a] if targets[a][k] != targets[b][k]}
            assert changed == {"repetition", "warmup_run_id", "measured_run_id"}, (a, b)
        ids = [f"{p}{n}" for n in (1, 2, 3) for p in ("w", "m")]
        found = [targets[n][key] for n in (1, 2, 3)
                 for key in ("warmup_run_id", "measured_run_id")]
        assert [i[-2:] for i in found] == ids and len(set(found)) == 6
        for n in (2, 3):
            assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_TOKENS[n]]) == {
                **dict(RB.APPROVED_LIVE_CELLS[SMALL10_ID]), "repetition": n}

    def test_exactly_ten_cells_and_the_earlier_cells_unchanged(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == ALLOWLISTED_CELLS
        assert len(RB.APPROVED_LIVE_CELLS) == 13
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_ID]) == SMALL10_FIELDS
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_REP2_ID]) == SMALL10_REP2_FIELDS
        for n in (2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-smoke-r0005-c32-rep{n}"]) == {
                **SMOKE_REPEAT_FIELDS, "repetition": n}
        assert [k for k in RB.APPROVED_LIVE_CELLS if "small" in k] == [
            SMALL10_ID, SMALL10_REP2_ID, SMALL10_REP3_ID, "bm-small-r0010-c32-rep4",
            "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"]

    @pytest.mark.parametrize("repetition", [10])
    def test_rep9_and_later_stay_refused(self, repetition):
        cell = _small(repetition=repetition)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r0010-c32-rep{repetition}",
                             repetition=repetition)
        for selector, token in SMALL10_TOKENS.items():
            with pytest.raises(RB.BenchmarkError):
                _authorize_small(cell, authorize=token, repetition=selector)

    @pytest.mark.parametrize("rate", [25, 50, 100])
    def test_other_small_rates_stay_refused_at_rep3(self, rate):
        cell = _small(rate=rate, repetition=3)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r{rate:04d}-c32-rep3", repetition=3)

    @pytest.mark.parametrize("claimed, actual", [(1, 2), (1, 3), (2, 1), (2, 3), (3, 1), (3, 2)])
    def test_the_three_authorization_tokens_cannot_be_interchanged(self, claimed, actual):
        cell = _small(repetition=actual)
        assert _authorize_small(cell, authorize=SMALL10_TOKENS[actual], repetition=actual) == cell
        with pytest.raises(RB.BenchmarkError, match="is not " + SMALL10_TOKENS[claimed]):
            _authorize_small(cell, authorize=SMALL10_TOKENS[claimed], repetition=claimed)
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize_small(cell, authorize=SMALL10_TOKENS[actual], repetition=claimed)

    @pytest.mark.parametrize("warmup", [None, 0, 25, 299, 301])
    def test_rep3_needs_the_exact_warmup_argument(self, warmup):
        with pytest.raises(RB.BenchmarkError, match="warmup-requests 300"):
            _authorize_small(_small(repetition=3), authorize=SMALL10_REP3_ID, repetition=3,
                             warmup=warmup)

    @pytest.mark.parametrize("change", [dict(requests=999), dict(requests=1001), dict(rate=5),
                                        dict(rate=25), dict(concurrency=16),
                                        dict(concurrency=33), dict(warmup_requests=299),
                                        dict(level="SMOKE"), dict(level="MEDIUM"),
                                        dict(repetition=10)])
    def test_a_changed_rep3_field_is_not_an_approved_cell(self, change):
        cell = dataclasses.replace(_small(repetition=3), **change)
        assert not RB.is_approved_live_cell(cell), change

    def test_the_run_ids_come_from_the_repetition_and_cannot_be_chosen(self, capsys):
        cell = _small(repetition=3)
        assert dataclasses.replace(cell, repetition=2).measured_run_id == "b-small-r0010-c32-m2"
        assert "w3" not in _small(repetition=2).warmup_run_id
        assert "m3" not in _small(repetition=1).measured_run_id
        with pytest.raises(SystemExit):
            RB.main(["--help"])
        flags = {word for word in capsys.readouterr().out.split() if word.startswith("--")}
        assert not flags & {"--seed", "--scenario", "--run-id", "--warmup-run-id",
                            "--measured-run-id"}

    def test_a_rep3_claim_is_isolated_and_single_use(self, tmp_path):
        ledger = tmp_path / "ledger"
        ledger.mkdir()
        existing = {}
        for name in (f"{SMALL10_ID}.started", f"{SMALL10_ID}.done", f"{SMALL10_REP2_ID}.started",
                     f"{SMALL10_REP2_ID}.done"):
            (ledger / name).write_text(f"record {name}\n", encoding="utf-8", newline="")
            existing[name] = (ledger / name).read_bytes()
        started = RB.claim_run(tmp_path, _small(repetition=3), head=HEAD, arguments={})
        assert started == ledger / f"{SMALL10_REP3_ID}.started" and started.is_file()
        for name, content in existing.items():
            assert (ledger / name).read_bytes() == content, name
        with pytest.raises(RB.BenchmarkError, match="owns this output directory"):
            RB.claim_run(tmp_path, _small(repetition=2), head=HEAD, arguments={})
        (tmp_path / RB.OWNER_FILE).unlink()
        with pytest.raises(RB.BenchmarkError, match="was started before"):
            RB.claim_run(tmp_path, _small(repetition=3), head=HEAD, arguments={})

    def test_the_cli_reaches_run_cell_once_for_an_authorized_rep3(self, monkeypatch, tmp_path):
        import io
        calls = []

        def fake_run_cell(cell, ladder, **kw):
            calls.append((cell.benchmark_id, kw["expect_head"]))
            path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
            path.write_text("{}", encoding="utf-8")
            return {"verdict": "VALID"}, path, True

        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", fake_run_cell)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "3",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_REP3_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)], stdout=io.StringIO())
        assert code == 0 and calls == [(SMALL10_REP3_ID, HEAD)]
        assert (out / "ledger" / f"{SMALL10_REP3_ID}.started").is_file()
        assert (out / "ledger" / f"{SMALL10_REP3_ID}.done").is_file()
        assert not (out / RB.OWNER_FILE).exists()

    @pytest.mark.parametrize("argv_changes", [
        {"--rate": "25"}, {"--concurrency": "16"}, {"--warmup-requests": "299"},
        {"--repetition": "4"}, {"--repetition": "2"}])
    def test_wrong_arguments_are_refused_before_anything_starts(
            self, argv_changes, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", lambda *a, **k: pytest.fail("reached run_cell"))
        args = {"--level": "SMALL", "--rate": "10", "--repetition": "3", "--concurrency": "32",
                "--warmup-requests": "300", **argv_changes}
        out = tmp_path / "out"
        code = RB.main([*[x for pair in args.items() for x in pair], "--live", "--authorize",
                        SMALL10_REP3_ID, "--expect-head", HEAD, "--output-dir", str(out)])
        assert code == 2 and "nothing was started" in capsys.readouterr().err
        assert not out.exists()

    def test_the_gate_closed_refuses_rep3(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "3",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_REP3_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "not enabled" in capsys.readouterr().err and not out.exists()

    def test_the_b3j68_diagnostics_stay_valid_for_a_rep3_result(self):
        result = _assembled(cell=_small(repetition=3), lag_samples=RISING_LAG[:4],
                            sampler_started=5000.5, timed_series=timed_series_payload(),
                            resource_samples=STATS)
        assert result["benchmark_id"] == SMALL10_REP3_ID
        for section, name in NEW_LEAVES:
            assert name in result["metrics"][section], name
        assert result["metrics"]["throughput"]["timed_ended_per_second_series"][
            "kind"] == "OBSERVATION"
        M.validate_result(result)

    def test_the_cell_run_for_rep3_uses_its_own_run_ids_in_both_queries(self, tmp_path):
        cell = _small(repetition=3)
        smoke = FakeSmoke(tmp_path)
        _run(tmp_path, smoke=smoke, cell=cell)
        assert smoke.stage_ids == ["b-small-r0010-c32-w3", "b-small-r0010-c32-m3"]
        for sql in smoke.psql_sql:
            assert "b-small-r0010-c32-m3" in sql
            assert "-m2" not in sql and "-m1" not in sql and "-w3" not in sql

    def test_verdicts_gates_and_thresholds_are_unchanged(self):
        assert RB.LIVE_ENABLED is True and RB.MAX_WARMUP_REQUESTS == 10000
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6
        assert LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert LADDER["stop_limits"]["memory_fraction"] == 0.90
        assert LADDER["defaults"]["cell_budget_seconds"] == 3600
        assert LADDER["defaults"]["drain_limit_seconds"] == 120
        assert dict(RB._SMALL10_FIRST) == {k: v for k, v in SMALL10_FIELDS.items()
                                           if k != "repetition"}


# ---------------------------------------------------------------------------
# B3J-84: gaps between consecutive ingests and per-partition progress (nothing is run)
# ---------------------------------------------------------------------------

GAP_LEAVES = (("latency", "ingest_gap_ms_p50"), ("latency", "ingest_gap_ms_p90"),
              ("latency", "ingest_gap_ms_p99"), ("latency", "ingest_gap_ms_max"),
              ("latency", "ingest_gap_stalls"),
              ("latency", "ingest_gap_series_start_epoch_s"),
              ("latency", "ingest_gap_ms_median_by_second"),
              ("latency", "ingest_gap_ms_max_by_second"),
              ("latency", "ingest_gap_stalls_by_second"),
              ("latency", "ingest_gap_series_offsets_s"),
              ("throughput", "partition_rows"), ("throughput", "partition_offset_min"),
              ("throughput", "partition_offset_max"), ("throughput", "partition_distinct_offsets"),
              ("throughput", "partition_ingested_per_second_series"))
GAP_OVERALL = GAP_LEAVES[:5]
GAP_SECONDS = GAP_LEAVES[5:10] + GAP_LEAVES[14:]
GAP_PARTITIONS = GAP_LEAVES[10:14]


def _gaps(**changes):
    return _assembled(timed_series=timed_series_payload(),
                      gap_series=gap_series_payload(**changes))["metrics"]


def _is_not_measured(metrics, spec):
    out = {}
    for section, name in spec:
        leaf = metrics[section][name]
        if "kind" not in leaf:                      # a tree: one leaf per partition, or "all"
            leaf = leaf["all"] if "all" in leaf else next(iter(leaf.values()))
        out[name] = (leaf["kind"] == "NOT_MEASURED" and leaf["value"] is None, leaf["reason"])
    return out


class TestIngestGapQuery:
    def test_the_sql_is_read_only_single_and_scoped_to_the_run(self):
        import re
        sql = RB.run_gap_sql("b-small-r0010-c32-m3")
        words = set(re.findall(r"[a-z_]+", sql.lower()))
        assert sql.lstrip().upper().startswith("WITH") and ";" not in sql and "--" not in sql
        assert not words & {"insert", "update", "delete", "drop", "alter", "create", "truncate",
                            "grant", "revoke", "copy", "vacuum", "set"}
        assert sql.count("'b-small-r0010-c32-m3'") == 1
        assert "agentops.workload.run_id' = 'b-small-r0010-c32-m3'" in sql
        assert "parent_span_id IS NULL" in sql and "trace_id IN (SELECT trace_id FROM roots)" in sql
        assert "w3" not in sql and sql == RB.run_gap_sql("b-small-r0010-c32-m3")

    @pytest.mark.parametrize("run_id", ["", "x'; DROP TABLE telemetry_spans; --", "B-SMALL",
                                        "b-small' OR '1'='1", "b-small\n-m2", None])
    def test_a_bad_run_id_is_refused(self, run_id):
        with pytest.raises((RB.BenchmarkError, TypeError)):
            RB.run_gap_sql(run_id)

    def test_the_order_is_deterministic_and_the_first_row_has_no_gap(self):
        sql = RB.run_gap_sql("b-small-r0010-c32-m3")
        assert "lag(s.ingested_at) OVER (ORDER BY s.ingested_at, s.id)" in sql
        assert "ORDER BY ingested_at, id LIMIT 1" in sql        # which row is first
        assert "coalesce(gap" not in sql.lower() and "gap_ms IS NOT NULL" in sql
        assert "* 1000.0" in sql and "ingested_at - end_time" not in sql   # a gap, not persistence

    def test_the_window_partitions_and_stall_are_bounded_in_sql(self):
        sql = RB.run_gap_sql("b-small-r0010-c32-m3")
        assert str(RB.MAX_TIMED_SERIES_SECONDS) in sql and RB.MAX_TIMED_SERIES_SECONDS == 1800
        assert "CASE WHEN t1 >= t0 AND t1 - t0 <" in sql
        assert f"LIMIT {RB.MAX_GAP_PARTITIONS}" in sql and RB.MAX_GAP_PARTITIONS == 16
        assert f"gap_ms > {RB.STALL_GAP_MS}" in sql and RB.STALL_GAP_MS == 100.0

    def test_the_existing_queries_are_untouched(self):
        import hashlib
        assert hashlib.sha256(RB.run_metrics_sql("b-small-r0010-c32-m3").encode()).hexdigest() == (
            "900ec6a02e15d892a75c62f4f853173f7d72cc484ec5f8de16f727b3fec065ec")
        assert hashlib.sha256(RB.run_series_sql("b-small-r0010-c32-m3").encode()).hexdigest() == (
            "98d52bd80b409e2551804633d3571ea228a5380f015dfe3a4a767bbc1308885a")
        assert "lag(" not in RB.run_series_sql("b-small-r0010-c32-m3")


class TestIngestGapLeaves:
    def test_overall_gap_statistics_are_recorded_with_their_counts(self):
        latency = _gaps()["latency"]
        for name, value in (("p50", 14.0), ("p90", 20.0), ("p99", 28.0), ("max", 30.0)):
            leaf = latency[f"ingest_gap_ms_{name}"]
            assert leaf["value"] == value and leaf["unit"] == "ms" and leaf["n"] == 699
            assert leaf["kind"] == "DERIVED" and leaf["source"].endswith("(database clock)")
            assert "first span has no gap" in leaf["method"]
        stalls = latency["ingest_gap_stalls"]
        assert stalls["value"] == 0 and stalls["kind"] == "OBSERVATION" and stalls["n"] == 699
        assert "100.0 ms" in stalls["method"]

    def test_per_second_values_are_sparse_aligned_and_never_zero_filled(self):
        latency = _gaps()["latency"]
        start = latency["ingest_gap_series_start_epoch_s"]
        assert start["value"] == 4999 == timed_series_payload()["start_epoch_s"]
        offsets = latency["ingest_gap_series_offsets_s"]["value"]
        assert offsets == list(range(1, 21))
        for name in ("ingest_gap_ms_median_by_second", "ingest_gap_ms_max_by_second",
                     "ingest_gap_stalls_by_second"):
            assert latency[name]["n"] == len(offsets) == len(latency[name]["value"])
            assert latency[name]["window"]["clock"] == "host"
        assert latency["ingest_gap_ms_median_by_second"]["value"][0] == 14.0
        assert latency["ingest_gap_ms_max_by_second"]["value"] == [30.0] * 20
        assert "never 0" in latency["ingest_gap_ms_median_by_second"]["method"]

    def test_partitions_are_reported_by_counts_and_bounds(self):
        throughput = _gaps()["throughput"]
        assert sorted(throughput["partition_rows"]) == ["p0", "p1", "p2"]
        assert [throughput["partition_rows"][p]["value"] for p in ("p0", "p1", "p2")] == [
            240, 240, 220]
        assert throughput["partition_offset_min"]["p2"]["value"] == 0
        assert throughput["partition_offset_max"]["p2"]["value"] == 219
        assert throughput["partition_distinct_offsets"]["p1"]["value"] == 240
        per_second = throughput["partition_ingested_per_second_series"]
        assert all(len(per_second[p]["value"]) == 22 for p in per_second)
        assert [sum(per_second[p]["value"]) for p in ("p0", "p1", "p2")] == [240, 240, 220]
        assert throughput["partition_rows"]["p0"]["n"] == 240

    def test_offsets_are_never_assumed_contiguous(self):
        parts = gap_series_payload()["partitions"]
        parts[0] = {**parts[0], "distinct_offsets": 200, "max_offset": 299}   # holes are real
        throughput = _gaps(partitions=parts)["throughput"]
        assert throughput["partition_distinct_offsets"]["p0"]["value"] == 200
        assert throughput["partition_offset_max"]["p0"]["value"] == 299
        assert throughput["partition_rows"]["p0"]["value"] == 240
        too_many = [dict(parts[0], distinct_offsets=241, max_offset=239)] + parts[1:]
        broken = _gaps(partitions=too_many)["throughput"]["partition_rows"]
        assert broken["all"]["kind"] == "NOT_MEASURED"        # more distinct offsets than fit

    def test_stalls_are_counted_per_second_and_overall(self):
        payload = gap_series_payload(
            gap_p99_ms=250.0, gap_max_ms=900.0, stall_gaps=3,
            gap_max_by_second_ms=[900.0, 150.0] + [30.0] * 18,
            gap_stall_counts=[2, 1] + [0] * 18)
        latency = _assembled(timed_series=timed_series_payload(),
                             gap_series=payload)["metrics"]["latency"]
        assert latency["ingest_gap_stalls"]["value"] == 3
        assert latency["ingest_gap_stalls_by_second"]["value"][:2] == [2, 1]
        assert latency["ingest_gap_ms_max"]["value"] == 900.0

    def test_unavailable_diagnostics_are_not_measured_never_zero(self):
        for result in (_assembled(), _assembled(timed_series=timed_series_payload())):
            for section, name in GAP_LEAVES:
                leaf = result["metrics"][section][name]
                leaf = leaf["all"] if name.startswith("partition_") else leaf
                assert leaf["kind"] == "NOT_MEASURED" and leaf["value"] is None, name
                assert leaf["reason"] == "the optional ingest-gap query did not run or failed"

    def test_an_invalid_or_missing_clock_keeps_only_the_database_clock_values(self):
        for evidence, reason in (
                (dict(clock_before=[], clock_after=[]), "clock skew not measured"),
                (INVALID_CLOCK, "clock skew outside its limits")):
            metrics = _assembled(timed_series=timed_series_payload(),
                                 gap_series=gap_series_payload(), **evidence)["metrics"]
            for name, (missing, why) in _is_not_measured(metrics, GAP_SECONDS).items():
                assert missing and why.startswith(reason), (name, why)
            for name, (missing, why) in _is_not_measured(metrics, GAP_OVERALL).items():
                assert not missing, name                 # database timestamps only
            for name, (missing, why) in _is_not_measured(metrics, GAP_PARTITIONS).items():
                assert not missing, name
            assert metrics["latency"]["ingest_gap_ms_p99"]["value"] == 28.0

    def test_the_window_bound_loses_only_the_per_second_values(self):
        cap = RB.MAX_TIMED_SERIES_SECONDS
        payload = gap_series_payload(end_epoch_s=4999 + cap)            # cap + 1 seconds
        metrics = _assembled(timed_series=timed_series_payload(),
                             gap_series=payload)["metrics"]
        for name, (missing, why) in _is_not_measured(metrics, GAP_SECONDS).items():
            assert missing and "exceeds the bound of 1800 s" in why, (name, why)
        assert not any(m for m, _ in _is_not_measured(metrics, GAP_OVERALL).values())
        assert not any(m for m, _ in _is_not_measured(metrics, GAP_PARTITIONS).values())

    def test_a_series_exactly_at_the_bound_is_accepted(self):
        cap = RB.MAX_TIMED_SERIES_SECONDS
        ingested = [700] + [0] * (cap - 1)
        parts = [{"partition": 0, "rows": 700, "min_offset": 0, "max_offset": 699,
                  "distinct_offsets": 700, "per_second": [700] + [0] * (cap - 1)}]
        payload = gap_series_payload(
            seconds=cap, ingested=ingested, first_row_offset=0, gap_offsets=[0],
            gap_counts=[699], gap_median_ms=[1.0], gap_max_by_second_ms=[30.0],
            gap_stall_counts=[0], partitions=parts)
        metrics = _assembled(timed_series=timed_series_payload(),
                             gap_series=payload)["metrics"]
        assert len(metrics["throughput"]["partition_ingested_per_second_series"]["p0"]["value"]) == cap
        assert not any(m for m, _ in _is_not_measured(metrics, GAP_SECONDS).values())

    @pytest.mark.parametrize("changes, where, why", [
        (dict(gap_count=700), "overall", "700 gaps for 700 rows"),                  # first row as 0
        (dict(gap_count=698), "overall", "698 gaps for 700 rows"),
        (dict(rows=699), "overall", "699 rows, the required query 700"),
        (dict(rows=0), "overall", "no spans"),
        (dict(stall_ms=50.0), "overall", "not the documented one"),
        (dict(gap_p50_ms=float("nan")), "overall", "finite non-negative"),
        (dict(gap_p50_ms=-1.0), "overall", "finite non-negative"),
        (dict(gap_p90_ms=True), "overall", "finite non-negative"),
        (dict(gap_p50_ms=25.0), "overall", "not ordered"),
        (dict(stall_gaps=700), "overall", "outside 0..gap count"),
        (dict(gap_max_ms=None), "overall", "finite non-negative"),
        (dict(partitions=[]), "partitions", "no partition"),
        (dict(partitions=None), "partitions", "no partition"),
        (dict(partitions="x"), "partitions", "no partition"),
        (dict(first_row_offset=21), "seconds", "first ingested row is outside"),
        (dict(first_row_offset=5), "seconds", "does not match its ingested rows"),
        (dict(ingested=[35] * 22), "seconds", "counts 770 spans"),
        (dict(ingested=[35] * 21), "seconds", "one count per second"),
        (dict(gap_offsets=[1, 1] + list(range(3, 21))), "seconds", "not increasing"),
        (dict(gap_counts=[35] * 20), "seconds", "does not match its ingested rows"),
        (dict(gap_median_ms=[40.0] * 20), "seconds", "gap statistics are inconsistent"),
        (dict(gap_max_by_second_ms=[31.0] * 20), "seconds", "inconsistent"),
        (dict(stall_gaps=2, gap_max_ms=900.0, gap_max_by_second_ms=[900.0] + [30.0] * 19,
              gap_stall_counts=[1] + [0] * 19), "seconds", "do not add up to the totals"),
        (dict(gap_max_by_second_ms=[29.0] * 20), "seconds", "overall maximum"),
        (dict(gap_offsets=list(range(1, 20)), gap_counts=[34] + [35] * 18,
              gap_median_ms=[14.0] * 19, gap_max_by_second_ms=[30.0] * 19,
              gap_stall_counts=[0] * 19), "seconds", "do not add up"),
        (dict(gap_median_ms=[14.0] * 19), "seconds", "arrays do not match"),
    ])
    def test_inconsistent_results_are_not_measured_and_change_nothing(self, changes, where, why):
        baseline = _assembled()
        result = _assembled(timed_series=timed_series_payload(),
                            gap_series=gap_series_payload(**changes))
        groups = {"overall": GAP_OVERALL, "partitions": GAP_PARTITIONS, "seconds": GAP_SECONDS}
        reasons = _is_not_measured(result["metrics"], groups[where])
        assert all(missing for missing, _ in reasons.values()), reasons
        assert any(why in reason for _, reason in reasons.values()), (why, reasons)
        assert result["verdict"] == baseline["verdict"] == "VALID"
        assert result["integrity"] == baseline["integrity"]
        assert result["stop"] == baseline["stop"] and result["claims"] == baseline["claims"]

    def test_a_partition_that_does_not_add_up_is_caught_in_both_forms(self):
        parts = gap_series_payload()["partitions"]
        short = [dict(parts[0], rows=239, distinct_offsets=239, max_offset=238)] + parts[1:]
        metrics = _gaps(partitions=short)
        assert "do not add up to the rows" in _is_not_measured(metrics, GAP_PARTITIONS)[
            "partition_rows"][1]
        uneven = [dict(parts[0], per_second=[12] * 22)] + parts[1:]
        reasons = _is_not_measured(_gaps(partitions=uneven), GAP_SECONDS)
        assert all(missing for missing, _ in reasons.values())
        assert any("add up" in why for _, why in reasons.values())
        assert not _is_not_measured(_gaps(partitions=uneven), GAP_OVERALL)[
            "ingest_gap_ms_p50"][0]

    def test_a_single_row_has_no_gap(self):
        payload = gap_series_payload(
            rows=1, gap_count=0, ingested=[0, 1] + [0] * 20, first_row_offset=1, gap_offsets=[],
            gap_counts=[], gap_median_ms=[], gap_max_by_second_ms=[], gap_stall_counts=[],
            gap_p50_ms=None, gap_p90_ms=None, gap_p99_ms=None, gap_max_ms=None, stall_gaps=0,
            partitions=[dict(gap_series_payload()["partitions"][0], rows=1, min_offset=5,
                             max_offset=5, distinct_offsets=1, per_second=[0, 1] + [0] * 20)])
        result = _assembled(timed_series=None, gap_series=payload,
                            db_overrides={"rows": 1, "distinct_spans": 1, "roots": 100})
        leaf = result["metrics"]["latency"]["ingest_gap_ms_p50"]
        assert leaf["kind"] == "NOT_MEASURED" and "fewer than two rows" in leaf["reason"]

    def test_nothing_required_changes_with_or_without_the_gap_data(self, monkeypatch):
        evidence = dict(timed_series=timed_series_payload(), gap_series=gap_series_payload(),
                        resource_samples=STATS)
        with_gaps = _assembled(**evidence)
        baseline = _baseline(monkeypatch, **evidence)
        stripped = json.loads(json.dumps(with_gaps))
        for section, name in NEW_LEAVES:
            stripped["metrics"][section].pop(name, None)
        assert stripped == baseline
        assert with_gaps["verdict"] == baseline["verdict"] == "VALID"

    def test_a_failing_builder_is_isolated(self, monkeypatch):
        monkeypatch.setattr(RB, "_diag_ingest_gaps",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        result = _assembled(gap_series=gap_series_payload())
        assert "diagnostic ingest gaps not recorded: RuntimeError" in result["limitations"]
        assert "ingest_gap_ms_p50" not in result["metrics"]["latency"]
        assert result["verdict"] == "VALID" and result["integrity"]["ok"] is True
        M.validate_result(result)

    def test_older_results_without_the_gap_leaves_still_validate(self):
        result = _assembled(timed_series=timed_series_payload(), gap_series=gap_series_payload())
        older = json.loads(json.dumps(result))
        for section, name in GAP_LEAVES:
            older["metrics"][section].pop(name, None)
        M.validate_result(older)
        assert "timed_ended_per_second_series" in older["metrics"]["throughput"]
        M.validate_result(json.loads(json.dumps(result)))

    def test_a_full_length_result_stays_small_enough(self, tmp_path):
        """The densest result the diagnostics allow: every supported partition, the whole
        supported window, every second populated in the gap series and the timed series.
        Measured when it was written: 239,338 bytes compact (763,322 as the pretty-printed
        file).  The limit is that plus about 15 percent; the floor shows the result is dense."""
        cap, n = RB.MAX_TIMED_SERIES_SECONDS, RB.MAX_GAP_PARTITIONS
        rows = cap * n
        base = [round(10.0 + (i % 97) * 0.731, 3) for i in range(cap)]       # 3-decimal values
        highs = [round(v + 10.0, 3) for v in base]
        highs[0] = round(max(highs) + 1.0, 3)                                   # below 100 ms
        parts = [{"partition": p, "rows": cap, "min_offset": 1000 * p,
                  "max_offset": 1000 * p + cap - 1, "distinct_offsets": cap,
                  "per_second": [1] * cap} for p in range(n)]
        gap = gap_series_payload(
            seconds=cap, rows=rows, ingested=[n] * cap, first_row_offset=0, gap_count=rows - 1,
            gap_p50_ms=max(base), gap_p90_ms=max(base) + 1, gap_p99_ms=max(base) + 2,
            gap_max_ms=max(highs), gap_offsets=list(range(cap)),
            gap_counts=[n - 1] + [n] * (cap - 1), gap_median_ms=base, gap_max_by_second_ms=highs,
            gap_stall_counts=[0] * cap, partitions=parts)
        latency = [round(1000.0 + (i % 997) * 0.731, 3) for i in range(cap)]
        series = timed_series_payload(
            seconds=cap, rows=rows, ended=[n] * cap, ingested=[n] * cap,
            latency_offsets=list(range(cap)), latency_mean_ms=latency,
            latency_max_ms=[round(v + 100.123, 3) for v in latency])
        result = _assembled(timed_series=series, gap_series=gap, resource_samples=STATS,
                            lag_samples=RISING_LAG, db_overrides={
                                "rows": rows, "distinct_spans": rows, "roots": 100})
        for section, name in TIMED_LEAVES + GAP_LEAVES:       # every diagnostic is really there
            leaf = result["metrics"][section][name]
            leaf = next(iter(leaf.values())) if "kind" not in leaf else leaf
            assert leaf["kind"] != "NOT_MEASURED", (section, name, leaf.get("reason"))
        assert len(result["metrics"]["throughput"]["partition_ingested_per_second_series"]) == n
        size = len(json.dumps(result, sort_keys=True))
        assert 200_000 < size < 275_000, size
        path = RB.write_result(result, tmp_path / "out")
        assert path.stat().st_size < 880_000                  # the pretty-printed file
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))


class TestStallAndEchoConsistency:
    @staticmethod
    def _consistent(maximum, stalls):
        """An overall maximum and stall count that agree, with one second holding the maximum."""
        return dict(gap_max_ms=maximum, gap_p99_ms=min(28.0, maximum), stall_gaps=stalls,
                    gap_max_by_second_ms=[maximum] + [min(30.0, maximum)] * 19,
                    gap_stall_counts=[stalls] + [0] * 19)

    @pytest.mark.parametrize("maximum, stalls", [(30.0, 0), (99.999, 0), (100.0, 0),
                                                 (100.001, 1), (900.0, 5)])
    def test_the_strict_threshold_accepts_matching_maximum_and_stalls(self, maximum, stalls):
        metrics = _gaps(**self._consistent(maximum, stalls))
        for name, (missing, why) in _is_not_measured(metrics, GAP_OVERALL).items():
            assert not missing, (name, why)
        for name, (missing, why) in _is_not_measured(metrics, GAP_SECONDS).items():
            assert not missing, (name, why)
        assert metrics["latency"]["ingest_gap_stalls"]["value"] == stalls

    @pytest.mark.parametrize("maximum, stalls", [(100.001, 0), (900.0, 0), (30.0, 1),
                                                 (99.999, 1), (100.0, 1)])
    def test_a_mismatch_between_the_maximum_and_the_stall_count_is_not_measured(
            self, maximum, stalls):
        baseline = _assembled()
        result = _assembled(timed_series=timed_series_payload(),
                            gap_series=gap_series_payload(**self._consistent(maximum, stalls)))
        reasons = _is_not_measured(result["metrics"], GAP_OVERALL)
        assert all(missing for missing, _ in reasons.values())
        assert all("stall count does not match the maximum gap against 100.0 ms" in why
                   for _, why in reasons.values()), reasons
        assert result["verdict"] == baseline["verdict"] == "VALID"
        assert result["integrity"] == baseline["integrity"]
        assert result["stop"] == baseline["stop"] and result["claims"] == baseline["claims"]

    @pytest.mark.parametrize("seconds_max, seconds_stalls", [
        ([900.0, 150.0] + [30.0] * 18, [1, 0] + [0] * 18),      # 150 ms second without a stall
        ([900.0, 30.0] + [30.0] * 18, [1, 1] + [0] * 18),       # a stall in a 30 ms second
        ([900.0, 100.0] + [30.0] * 18, [1, 1] + [0] * 18),      # exactly 100 ms is no stall
        ([900.0, 100.001] + [30.0] * 18, [1, 0] + [0] * 18),    # just over the threshold
        ([900.0, 99.999] + [30.0] * 18, [1, 1] + [0] * 18)])    # just under the threshold
    def test_a_second_whose_stalls_do_not_match_its_maximum_is_not_measured(
            self, seconds_max, seconds_stalls):
        overall_stalls = sum(seconds_stalls)
        result = _assembled(timed_series=timed_series_payload(), gap_series=gap_series_payload(
            gap_max_ms=900.0, gap_p99_ms=28.0, stall_gaps=overall_stalls,
            gap_max_by_second_ms=seconds_max, gap_stall_counts=seconds_stalls))
        reasons = _is_not_measured(result["metrics"], GAP_SECONDS)
        assert all(missing for missing, _ in reasons.values()), reasons
        assert all("a second's stall count does not match its maximum gap" in why
                   for _, why in reasons.values()), reasons
        assert not any(m for m, _ in _is_not_measured(result["metrics"], GAP_OVERALL).values())
        assert result["verdict"] == "VALID"

    @pytest.mark.parametrize("changes, why", [
        (dict(cap_seconds=5), "window bound is not this version's"),
        (dict(cap_seconds=RB.MAX_TIMED_SERIES_SECONDS + 1), "window bound is not this version's"),
        (dict(cap_seconds="1800"), "cap_seconds is not a whole number"),
        (dict(cap_seconds=None), "cap_seconds is not a whole number"),
        (dict(cap_seconds=True), "cap_seconds is not a whole number"),
        (dict(partition_limit=99), "partition limit is not this version's"),
        (dict(partition_limit=RB.MAX_GAP_PARTITIONS - 1), "partition limit is not this version's"),
        (dict(partition_limit=None), "partition_limit is not a whole number"),
        (dict(partition_limit=16.0), "partition_limit is not a whole number")])
    def test_a_mismatched_configuration_echo_makes_the_diagnostic_not_measured(self, changes, why):
        baseline = _assembled()
        result = _assembled(timed_series=timed_series_payload(),
                            gap_series=gap_series_payload(**changes))
        for group in (GAP_OVERALL, GAP_PARTITIONS, GAP_SECONDS):
            assert all(missing for missing, _ in _is_not_measured(result["metrics"], group).values())
        assert any(why in reason for _, reason in
                   _is_not_measured(result["metrics"], GAP_OVERALL).values())
        assert result["verdict"] == baseline["verdict"] == "VALID"
        assert result["integrity"] == baseline["integrity"]

    def test_a_payload_that_echoes_the_current_constants_is_accepted(self):
        payload = gap_series_payload()
        assert (payload["cap_seconds"], payload["partition_limit"]) == (
            RB.MAX_TIMED_SERIES_SECONDS, RB.MAX_GAP_PARTITIONS) == (1800, 16)
        assert not any(m for m, _ in _is_not_measured(_gaps(), GAP_OVERALL).values())


class TestIngestGapInTheCell:
    def test_one_more_post_run_query_after_the_series_and_clock_check(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path)
        assert clean and result["verdict"] == "VALID"
        assert smoke.calls == ORDER and smoke.calls.count("psql") == 3
        measured = smoke.calls.index("run_stage_measured")
        probe = smoke.calls.index("clock_probe", measured)
        assert smoke.calls[probe + 1:probe + 3] == ["psql", "psql"]
        assert smoke.calls.index("psql") > measured and smoke.calls.index("psql") < probe
        required, series, gaps = smoke.psql_sql
        cell = _cell()
        assert required == RB.run_metrics_sql(cell.measured_run_id)
        assert series == RB.run_series_sql(cell.measured_run_id)
        assert gaps == RB.run_gap_sql(cell.measured_run_id)
        assert cell.warmup_run_id not in gaps and cell.measured_run_id in gaps

    def test_the_cell_records_the_gaps_next_to_the_required_metrics(self, tmp_path):
        result = _run(tmp_path)[0]
        latency = result["metrics"]["latency"]
        assert latency["ingest_gap_ms_p99"]["value"] == 28.0
        assert result["metrics"]["throughput"]["partition_rows"]["p0"]["value"] == 240
        assert latency["persistence_ms"]["p95"]["kind"] == "DERIVED"          # untouched
        assert result["metrics"]["throughput"]["persisted_per_second_series"]["n"] == 20

    @pytest.mark.parametrize("how", ["raises", "not_json", "wrong_shape"])
    def test_a_failure_of_only_the_gap_query_never_changes_the_verdict(
            self, tmp_path, how):
        (tmp_path / "good").mkdir()
        (tmp_path / "bad").mkdir()
        good = _run(tmp_path / "good")
        smoke = FakeSmoke(tmp_path / "bad")
        original = smoke.psql

        def psql(sql):
            if "gap_ms" not in sql:
                return original(sql)
            smoke._step("psql")
            smoke.psql_sql.append(sql)
            if how == "raises":
                raise Boom("gap query failed")
            return "not json {" if how == "not_json" else "[1, 2, 3]"

        smoke.psql = psql
        result, path, clean, _ = _run(tmp_path / "bad", smoke=smoke)
        assert clean and result["verdict"] == good[0]["verdict"] == "VALID"
        for key in ("integrity", "stop", "claims", "counts", "clock"):
            assert result[key] == good[0][key], key
        assert good[0]["metrics"]["throughput"]["timed_ended_per_second_series"][
            "kind"] == "OBSERVATION"
        assert result["metrics"]["throughput"]["timed_ended_per_second_series"] == good[0][
            "metrics"]["throughput"]["timed_ended_per_second_series"]       # the series survives
        leaf = result["metrics"]["latency"]["ingest_gap_ms_p50"]
        assert leaf["kind"] == "NOT_MEASURED"
        if how != "wrong_shape":
            assert any(t.startswith("diagnostic ingest gap query not recorded")
                       for t in result["limitations"])
        assert result["metrics"]["latency"]["persistence_ms"] == good[0]["metrics"]["latency"][
            "persistence_ms"]
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    def test_a_failing_series_query_leaves_the_gap_query_alone(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        original = smoke.psql

        def psql(sql):
            if "gap_ms" not in sql and "generate_series" in sql:
                smoke._step("psql")
                smoke.psql_sql.append(sql)
                raise Boom("series query failed")
            return original(sql)

        smoke.psql = psql
        result, _, clean, _ = _run(tmp_path, smoke=smoke)
        assert clean and result["verdict"] == "VALID"
        assert result["metrics"]["latency"]["ingest_gap_ms_p99"]["value"] == 28.0
        assert result["metrics"]["throughput"]["timed_ended_per_second_series"][
            "kind"] == "NOT_MEASURED"

    def test_the_required_query_failing_still_fails_the_cell_before_any_optional_query(
            self, tmp_path):
        result, _, clean, smoke = _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="psql"))
        assert result["verdict"] != "VALID" and smoke.calls.count("psql") == 1


class TestB3J84DidNotChangeSafetyOrTheAllowlist:
    def test_gates_thresholds_ladder_and_the_allowlist_are_unchanged(self):
        import hashlib
        assert RB.LIVE_ENABLED is True and RB.MAX_WARMUP_REQUESTS == 10000
        assert len(RB.APPROVED_LIVE_CELLS) == 13
        assert sorted(RB.APPROVED_LIVE_CELLS) == ALLOWLISTED_CELLS
        assert "bm-small-r0010-c32-rep7" in RB.APPROVED_LIVE_CELLS
        assert hashlib.sha256((Path(_BENCH) / "ladder.json").read_bytes()).hexdigest() == (
            "571138bb0c10e15547345aca5f15422742ffb03d998e88127c2d7aadc8b2c71f")
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6
        assert LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert LADDER["defaults"]["sample_interval_seconds"] == 10
        assert LADDER["defaults"]["cell_budget_seconds"] == 3600


# ---------------------------------------------------------------------------
# B3J-89: the SMALL-10 rep4 (nothing is run)
# ---------------------------------------------------------------------------

SMALL10_REP4_ID = "bm-small-r0010-c32-rep4"
SMALL10_REP4_FIELDS = {**SMALL10_FIELDS, "repetition": 4}
ALL_TOKENS = {**SMALL10_TOKENS, 4: SMALL10_REP4_ID}


class TestSmallTenFourthRepetition:
    def test_rep4_is_approved_with_the_exact_specification(self):
        assert dict(RB.APPROVED_LIVE_CELLS[SMALL10_REP4_ID]) == SMALL10_REP4_FIELDS
        cell = _small(repetition=4)
        assert cell.benchmark_id == SMALL10_REP4_ID and RB.is_approved_live_cell(cell)
        assert (cell.level, cell.rate, cell.requests, cell.warmup_requests, cell.concurrency,
                cell.seed, cell.repetition) == ("SMALL", 10, 1000, 300, 32, 42, 4)
        assert cell.target()["scenario"] == "normal"
        assert cell.planned_spans == 7000 and cell.measured_seconds == 100.0
        assert cell.live_allowed is True and cell.refresh_and_detector is True
        assert (cell.warmup_run_id, cell.measured_run_id) == ("b-small-r0010-c32-w4",
                                                              "b-small-r0010-c32-m4")
        assert RB.RUN_ID_RE.fullmatch(cell.warmup_run_id)
        assert RB.RUN_ID_RE.fullmatch(cell.measured_run_id)
        assert _authorize_small(cell, authorize=SMALL10_REP4_ID, repetition=4) == cell

    def test_exactly_ten_cells_and_the_existing_eight_unchanged_and_accepted(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == ALLOWLISTED_CELLS
        assert len(RB.APPROVED_LIVE_CELLS) == 13
        for n in (1, 2, 3, 4):
            assert dict(RB.APPROVED_LIVE_CELLS[ALL_TOKENS[n]]) == {
                **SMALL10_FIELDS, "repetition": n}
            cell = _small(repetition=n)
            assert RB.is_approved_live_cell(cell) and cell.benchmark_id == ALL_TOKENS[n]
        for n in (2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-smoke-r0005-c32-rep{n}"]) == {
                **SMOKE_REPEAT_FIELDS, "repetition": n}
            assert RB.is_approved_live_cell(_approved_cells(repetition=n)[0])

    def test_the_four_small_cells_differ_only_in_repetition_and_run_ids(self):
        targets = {n: _small(repetition=n).target() for n in (1, 2, 3, 4)}
        for a in (1, 2, 3):
            for b in range(a + 1, 5):
                changed = {k for k in targets[a] if targets[a][k] != targets[b][k]}
                assert changed == {"repetition", "warmup_run_id", "measured_run_id"}, (a, b)
        ids = [targets[n][key] for n in (1, 2, 3, 4) for key in ("warmup_run_id", "measured_run_id")]
        assert len(set(ids)) == 8

    @pytest.mark.parametrize("change", [dict(rate=5), dict(rate=25), dict(rate=50), dict(rate=100),
                                        dict(repetition=1), dict(repetition=2), dict(repetition=3),
                                        dict(repetition=10), dict(concurrency=16),
                                        dict(concurrency=31), dict(concurrency=33),
                                        dict(concurrency=64)])
    def test_a_wrong_rate_repetition_or_concurrency_is_not_the_approved_cell(self, change):
        cell = dataclasses.replace(_small(repetition=4), **change)
        if change == dict(repetition=1) or change in (dict(repetition=2), dict(repetition=3)):
            assert cell.benchmark_id == ALL_TOKENS[change["repetition"]]   # another approved cell
            assert RB.is_approved_live_cell(cell)
            with pytest.raises(RB.BenchmarkError, match="is not " + SMALL10_REP4_ID):
                _authorize_small(cell, authorize=SMALL10_REP4_ID, repetition=4)
        else:
            assert not RB.is_approved_live_cell(cell), change

    @pytest.mark.parametrize("warmup", [None, 0, 25, 150, 299, 301, 1000])
    def test_a_wrong_warmup_count_is_refused(self, warmup):
        with pytest.raises(RB.BenchmarkError, match="warmup-requests 300"):
            _authorize_small(_small(repetition=4), authorize=SMALL10_REP4_ID, repetition=4,
                             warmup=warmup)
        if warmup:
            cell = dataclasses.replace(_small(repetition=4), warmup_requests=warmup)
            assert not RB.is_approved_live_cell(cell)

    @pytest.mark.parametrize("requests", [1, 100, 999, 1001, 5000])
    def test_a_wrong_measured_request_count_is_refused(self, requests):
        cell = dataclasses.replace(_small(repetition=4), requests=requests)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="differs from the approved one in requests"):
            _authorize_small(cell, authorize=SMALL10_REP4_ID, repetition=4)

    def test_the_scenario_is_fixed_and_the_seed_comes_from_the_pinned_ladder(self):
        import hashlib
        ladder_path = RB.DEFAULT_CONFIG
        assert hashlib.sha256(Path(ladder_path).read_bytes()).hexdigest() == (
            "571138bb0c10e15547345aca5f15422742ffb03d998e88127c2d7aadc8b2c71f")
        loaded = RB.load_ladder(ladder_path)
        assert loaded["defaults"]["seed"] == 42 and loaded["defaults"]["scenario"] == "normal"
        cell = RB.plan_cells(loaded, "SMALL", rates=[10], repetition=4, concurrency=32,
                             warmup_requests=300)[0]
        assert cell.seed == 42 and cell.target()["scenario"] == "normal"
        bad = json.loads(json.dumps(loaded))
        bad["defaults"]["scenario"] = "slow"
        with pytest.raises(M.MetricError, match="normal scenario only"):
            M.check_ladder(bad)                      # another scenario cannot even be planned
        # What this does not do: the allowlist compares level, requests, rate, concurrency,
        # repetition and warm-up.  The seed is held by the ladder file, whose hash is checked
        # before a live run (see the B3J-72 review).

    @pytest.mark.parametrize("repetition", [10])
    def test_rep9_and_later_stay_refused(self, repetition):
        cell = _small(repetition=repetition)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r0010-c32-rep{repetition}",
                             repetition=repetition)
        for selector, token in ALL_TOKENS.items():
            with pytest.raises(RB.BenchmarkError):
                _authorize_small(cell, authorize=token, repetition=selector)

    @pytest.mark.parametrize("rate", [25, 50, 100])
    @pytest.mark.parametrize("repetition", [1, 4, 5])
    def test_other_small_rates_stay_refused(self, rate, repetition):
        cell = _small(rate=rate, repetition=repetition)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="authorize"):
            _authorize_small(cell, authorize=f"bm-small-r{rate:04d}-c32-rep{repetition}",
                             repetition=repetition)

    @pytest.mark.parametrize("claimed", [1, 2, 3])
    def test_rep4_and_the_earlier_authorization_tokens_cannot_be_interchanged(self, claimed):
        rep4, other = _small(repetition=4), _small(repetition=claimed)
        for cell, own in ((rep4, 4), (other, claimed)):
            assert _authorize_small(cell, authorize=ALL_TOKENS[own], repetition=own) == cell
        with pytest.raises(RB.BenchmarkError, match="is not " + ALL_TOKENS[claimed]):
            _authorize_small(rep4, authorize=ALL_TOKENS[claimed], repetition=claimed)
        with pytest.raises(RB.BenchmarkError, match="is not " + SMALL10_REP4_ID):
            _authorize_small(other, authorize=SMALL10_REP4_ID, repetition=4)
        with pytest.raises(RB.BenchmarkError, match="repetition"):
            _authorize_small(rep4, authorize=SMALL10_REP4_ID, repetition=claimed)

    def test_a_rep4_claim_is_isolated_and_single_use(self, tmp_path):
        ledger = tmp_path / "ledger"
        ledger.mkdir()
        existing = {}
        for n in (1, 2, 3):
            for suffix in (".started", ".done"):
                path = ledger / f"{ALL_TOKENS[n]}{suffix}"
                path.write_text(f"record {path.name}\n", encoding="utf-8", newline="")
                existing[path] = path.read_bytes()
        started = RB.claim_run(tmp_path, _small(repetition=4), head=HEAD, arguments={})
        assert started == ledger / f"{SMALL10_REP4_ID}.started" and started.is_file()
        for path, content in existing.items():
            assert path.read_bytes() == content, path.name
        with pytest.raises(RB.BenchmarkError, match="owns this output directory"):
            RB.claim_run(tmp_path, _small(repetition=3), head=HEAD, arguments={})
        (tmp_path / RB.OWNER_FILE).unlink()
        with pytest.raises(RB.BenchmarkError, match="was started before"):
            RB.claim_run(tmp_path, _small(repetition=4), head=HEAD, arguments={})

    def test_the_cli_reaches_run_cell_once_for_an_authorized_rep4(self, monkeypatch, tmp_path):
        import io
        calls = []

        def fake_run_cell(cell, ladder, **kw):
            calls.append((cell.benchmark_id, kw["expect_head"]))
            path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
            path.write_text("{}", encoding="utf-8")
            return {"verdict": "VALID"}, path, True

        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", fake_run_cell)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "4",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_REP4_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)], stdout=io.StringIO())
        assert code == 0 and calls == [(SMALL10_REP4_ID, HEAD)]
        assert (out / "ledger" / f"{SMALL10_REP4_ID}.started").is_file()
        assert (out / "ledger" / f"{SMALL10_REP4_ID}.done").is_file()
        assert not (out / RB.OWNER_FILE).exists()

    @pytest.mark.parametrize("argv_changes", [
        {"--rate": "25"}, {"--concurrency": "16"}, {"--warmup-requests": "299"},
        {"--repetition": "5"}, {"--repetition": "3"}])
    def test_wrong_arguments_are_refused_before_anything_starts(
            self, argv_changes, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "run_cell", lambda *a, **k: pytest.fail("reached run_cell"))
        args = {"--level": "SMALL", "--rate": "10", "--repetition": "4", "--concurrency": "32",
                "--warmup-requests": "300", **argv_changes}
        out = tmp_path / "out"
        code = RB.main([*[x for pair in args.items() for x in pair], "--live", "--authorize",
                        SMALL10_REP4_ID, "--expect-head", HEAD, "--output-dir", str(out)])
        assert code == 2 and "nothing was started" in capsys.readouterr().err
        assert not out.exists()

    def test_the_gate_closed_refuses_rep4(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        out = tmp_path / "out"
        code = RB.main(["--level", "SMALL", "--rate", "10", "--repetition", "4",
                        "--concurrency", "32", "--warmup-requests", "300", "--live",
                        "--authorize", SMALL10_REP4_ID, "--expect-head", HEAD,
                        "--output-dir", str(out)])
        assert code == 2 and "not enabled" in capsys.readouterr().err and not out.exists()

    def test_the_cell_run_for_rep4_uses_its_own_run_ids_in_all_three_queries(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        _run(tmp_path, smoke=smoke, cell=_small(repetition=4))
        assert smoke.stage_ids == ["b-small-r0010-c32-w4", "b-small-r0010-c32-m4"]
        assert len(smoke.psql_sql) == 3
        for sql in smoke.psql_sql:
            assert "b-small-r0010-c32-m4" in sql
            assert not any(other in sql for other in ("-m1", "-m2", "-m3", "-w4"))

    def test_the_diagnostic_sql_gates_and_thresholds_are_unchanged(self):
        import hashlib
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        run_id = "b-small-r0010-c32-m4"
        assert digest(RB.run_metrics_sql(run_id)) == (
            "c883fac812a62628e6411d88dbd0de2062e4171d744512ea18384d75fdcbe736")
        assert digest(RB.run_series_sql(run_id)) == (
            "79251ad7f0c2aa7d74e50653797334efef83a3461d5699dabd1f5e9aa6d2bad2")
        assert digest(RB.run_gap_sql(run_id)) == (
            "b5af5c8dc43b1dfed6c2c7c1b20ccb4b8b44ff50d136a3851fea5bc0999de3c1")
        assert RB.LIVE_ENABLED is True and RB.MAX_WARMUP_REQUESTS == 10000
        assert RB.MAX_TIMED_SERIES_SECONDS == 1800 and RB.STALL_GAP_MS == 100.0
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6
        assert LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert LADDER["stop_limits"]["memory_fraction"] == 0.90
        assert LADDER["defaults"]["sample_interval_seconds"] == 10
        assert LADDER["defaults"]["cell_budget_seconds"] == 3600
        assert LADDER["defaults"]["drain_limit_seconds"] == 120

    def test_a_rep4_result_still_validates_with_all_diagnostics(self):
        result = _assembled(cell=_small(repetition=4), lag_samples=RISING_LAG[:4],
                            sampler_started=5000.5, timed_series=timed_series_payload(),
                            gap_series=gap_series_payload(), resource_samples=STATS)
        assert result["benchmark_id"] == SMALL10_REP4_ID
        for section, name in NEW_LEAVES:
            assert name in result["metrics"][section], name
        M.validate_result(result)


# ---------------------------------------------------------------------------
# B3J-103: configuration integrity, marker binding, single use, validation order
# ---------------------------------------------------------------------------

import copy  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import threading  # noqa: E402

LADDER_BYTES = (_BENCH / "ladder.json").read_bytes()
APPROVED_ARGS = [*APPROVED, "--live", "--authorize", "bm-smoke-r0005-c32-rep2",
                 "--expect-head", HEAD]
SMOKE2 = "bm-smoke-r0005-c32-rep2"
OTHER_OWNER = "another run owns this"
MUTATIONS = {
    "seed": lambda d: d["defaults"].__setitem__("seed", 7),
    "detector off": lambda d: d["levels"][0].__setitem__("refresh_and_detector", False),
    "drain": lambda d: d["defaults"].__setitem__("drain_limit_seconds", 5),
    "settle": lambda d: d["defaults"].__setitem__("settle_seconds", 1),
    "budget": lambda d: d["defaults"].__setitem__("cell_budget_seconds", 99999),
    "sample interval": lambda d: d["defaults"].__setitem__("sample_interval_seconds", 1),
    "memory stop": lambda d: d["stop_limits"].__setitem__("memory_fraction", 1.0),
    "disk stop": lambda d: d["stop_limits"].__setitem__("disk_free_min_gb", 0.001),
    "lag stop": lambda d: d["stop_limits"].__setitem__("lag_growth_samples", 1000),
}


def _altered(name):
    data = copy.deepcopy(LADDER)
    MUTATIONS[name](data)
    M.check_ladder(data)                      # structurally valid: only the pin can refuse it
    return data


class FakeExecutionState:
    """Stands in for SetThreadExecutionState and the aggregate state read-back.  Nothing here
    touches Windows."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.state = 0                         # the aggregate state other requesters would add to
        self.refuse_acquire = False            # SetThreadExecutionState returns 0 for the keep-awake flags
        self.refuse_release = False
        self.raise_on_acquire = False
        self.readback = "follow"               # 'follow' (the aggregate), 'none', 'raise' or an int
        self.outstanding = 0
        # the host diagnostics (B3J-275): lock state, idle time and the event-log query, all fake
        self.session_flags = 1                 # 1 = unlocked, 0 = locked, None/raise = unreadable
        self.idle_seconds = 12.5
        self.query_calls: list[tuple] = []
        self.query_result = None               # None = a successful query with no events; or a callable
        self.query_events: list[tuple] = []    # (iso time, id, reason) rows for a successful query

    def read_flags(self):
        self.calls.append(("flags",))
        if self.session_flags == "raise":
            raise OSError("no session api")
        return self.session_flags

    def read_idle(self):
        self.calls.append(("idle",))
        return self.idle_seconds

    def run_query(self, script, timeout):
        self.query_calls.append((script, timeout))
        if callable(self.query_result):
            return self.query_result(script, timeout)
        rows = [{"t": when, "id": identifier, "r": reason} for when, identifier, reason in self.query_events]
        return SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "events": rows}), stderr="")

    def set(self, flags):
        self.calls.append(("set", flags))
        if flags == RB.ES_CONTINUOUS:
            if self.refuse_release:
                return 0
            self.outstanding = max(0, self.outstanding - 1)
            self.state = 0
            return RB.KEEP_AWAKE_FLAGS
        if self.raise_on_acquire:
            raise OSError("no power api")
        if self.refuse_acquire:
            return 0
        self.outstanding += 1
        self.state = flags & 0x7FFFFFFF
        return 0x80000000

    def read(self):
        self.calls.append(("read",))
        if self.readback == "raise":
            raise OSError("cannot read")
        if self.readback == "none":
            return None
        if isinstance(self.readback, int):
            return self.readback
        return self.state


_REAL_POWER_FUNCTIONS = (RB._windows_set_execution_state, RB._windows_read_execution_state,
                         RB._windows_session_flags, RB._windows_idle_seconds, RB._run_event_query)


@pytest.fixture(autouse=True)
def _power(monkeypatch):
    """No test may reach a real Windows power API: for EVERY test the module's two Windows
    functions are replaced by one FakeExecutionState (which the `live` fixture and the guard
    tests then use), and Windows is assumed so the guard runs on any platform."""
    fake = FakeExecutionState()
    monkeypatch.setattr(RB, "_is_windows", lambda: True)
    monkeypatch.setattr(RB, "_windows_set_execution_state", fake.set)
    monkeypatch.setattr(RB, "_windows_read_execution_state", fake.read)
    monkeypatch.setattr(RB, "_windows_session_flags", fake.read_flags)
    monkeypatch.setattr(RB, "_windows_idle_seconds", fake.read_idle)
    monkeypatch.setattr(RB, "_run_event_query", fake.run_query)
    return fake


@pytest.fixture
def live(monkeypatch, tmp_path, _power):
    """The CLI with the gate open in memory, the real pre-claim checks and the real claim,
    run_cell replaced, a canonical output directory inside tmp_path, a fake read-only git, and
    a fake Windows execution-state API (the keep-awake guard runs for real against it)."""
    canonical = tmp_path / "canonical"
    git = {"head": HEAD, "branch": "work", "status": [], "staged": []}
    awake = _power
    seen = SimpleNamespace(runs=[], canonical=canonical, git=git, started_during_run=None, awake=awake,
                           held_during_run=None)
    monkeypatch.setattr(RB, "LIVE_ENABLED", True)
    monkeypatch.setattr(RB, "DEFAULT_OUTPUT", canonical)
    monkeypatch.setattr(RB, "check_live_output_dir", REAL_CHECK_LIVE_OUTPUT_DIR)
    monkeypatch.setattr(RB, "verify_repository_readonly",
                        lambda expect_head, **kw: REAL_VERIFY_REPOSITORY(
                            expect_head, read=lambda: dict(git)))

    def fake_run_cell(cell, ladder, **kw):
        seen.runs.append(cell.benchmark_id)
        seen.held_during_run = awake.outstanding
        started = kw["output_dir"] / "ledger" / f"{cell.benchmark_id}.started"
        seen.started_during_run = json.loads(started.read_text(encoding="utf-8"))
        path = kw["output_dir"] / f"{cell.benchmark_id}-fake.json"
        path.write_text("{}", encoding="utf-8")
        return {"verdict": "VALID"}, path, True

    monkeypatch.setattr(RB, "run_cell", fake_run_cell)
    return seen


def _live(args=None, *extra):
    return RB.main([*(APPROVED_ARGS if args is None else args), *extra], stdout=io.StringIO())


def _nothing_created(seen):
    c = seen.canonical
    return seen.runs == [] and (not c.exists() or not any(c.rglob("*")))


class TestB1ConfigurationIntegrity:
    def test_the_pin_is_the_real_ladders_hash(self):
        assert RB.APPROVED_LADDER_SHA256 == hashlib.sha256(LADDER_BYTES).hexdigest() == (
            "571138bb0c10e15547345aca5f15422742ffb03d998e88127c2d7aadc8b2c71f")
        data, digest = RB.read_ladder(RB.DEFAULT_CONFIG)
        assert digest == RB.APPROVED_LADDER_SHA256 and data == LADDER

    def test_the_hash_and_the_parse_come_from_the_same_bytes(self, tmp_path, monkeypatch):
        altered = json.dumps(_altered("seed")).encode("utf-8")
        path = tmp_path / "x.json"
        path.write_bytes(LADDER_BYTES)
        reads = []

        def once(self):
            reads.append(self)
            return altered

        monkeypatch.setattr(Path, "read_bytes", once)
        data, digest = RB.read_ladder(path)
        assert reads == [path]                                   # read once
        assert digest == hashlib.sha256(altered).hexdigest() and data["defaults"]["seed"] == 7

    @pytest.mark.parametrize("name", sorted(MUTATIONS))
    def test_every_altered_value_is_refused_by_the_effective_check(self, name):
        altered = _altered(name)
        cells = RB.plan_cells(altered, "SMOKE", rates=[5], repetition=2, concurrency=32,
                              warmup_requests=25)
        with pytest.raises(RB.BenchmarkError, match="effective configuration differs"):
            RB.check_effective_config(cells[0], altered)
        assert RB.check_effective_config(_approved_cells()[0], LADDER)["seed"] == 42

    @pytest.mark.parametrize("name", sorted(MUTATIONS))
    def test_an_altered_configuration_is_refused_before_anything_is_created(
            self, live, tmp_path, name, capsys):
        config = tmp_path / "alt.json"
        config.write_text(json.dumps(_altered(name), indent=2), encoding="utf-8")
        assert _live(None, "--config", str(config)) == 2
        assert "nothing was started" in capsys.readouterr().err and _nothing_created(live)

    def test_an_identical_content_configuration_at_another_path_is_accepted(self, live, tmp_path):
        config = tmp_path / "elsewhere" / "copy-of-the-ladder.json"
        config.parent.mkdir()
        config.write_bytes(LADDER_BYTES)
        assert _live(None, "--config", str(config)) == 0 and live.runs == [SMOKE2]

    def test_a_different_content_but_valid_configuration_is_refused_live_only(
            self, live, tmp_path, capsys):
        config = tmp_path / "reformatted.json"
        config.write_text(json.dumps(LADDER, indent=4), encoding="utf-8")   # same values
        assert _live(None, "--config", str(config)) == 2
        assert "SHA-256" in capsys.readouterr().err and _nothing_created(live)
        out = io.StringIO()                       # planning still takes any valid configuration
        assert RB.main(["--level", "SMOKE", "--config", str(config), "--output-dir",
                        str(tmp_path / "plan")], stdout=out) == 0
        assert out.getvalue().startswith("PLAN ONLY")
        assert not (tmp_path / "plan").exists()

    def test_run_cell_checks_the_effective_values_too(self, monkeypatch, tmp_path):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "execute_cell", lambda *a, **k: pytest.fail("reached"))
        altered = _altered("seed")
        cell = RB.plan_cells(altered, "SMOKE", rates=[5], repetition=2, concurrency=32,
                             warmup_requests=25)[0]
        assert RB.is_approved_live_cell(cell)                    # the old check alone passed it
        with pytest.raises(RB.BenchmarkError, match="effective configuration differs"):
            RB.run_cell(cell, altered, expect_head=HEAD, output_dir=tmp_path)


class TestB3CanonicalOutputDirectory:
    def test_another_directory_is_refused_for_live(self, live, tmp_path, capsys):
        other = tmp_path / "somewhere-else"
        assert _live(None, "--output-dir", str(other)) == 2
        assert "canonical output directory" in capsys.readouterr().err
        assert not other.exists() and _nothing_created(live)

    def test_the_canonical_directory_is_accepted(self, live):
        assert _live(None, "--output-dir", str(live.canonical)) == 0
        assert live.runs == [SMOKE2]

    def test_a_used_cell_cannot_be_rerun_by_naming_another_directory(self, live, tmp_path):
        assert _live(None, "--output-dir", str(live.canonical)) == 0
        assert _live(None, "--output-dir", str(tmp_path / "fresh")) == 2
        assert _live(None, "--output-dir", str(live.canonical)) == 2
        assert live.runs == [SMOKE2]

    @pytest.mark.parametrize("make", ["started", "done", "result", "owner"])
    def test_existing_evidence_blocks_reuse_and_is_left_alone(self, live, make, capsys):
        c = live.canonical
        (c / "ledger").mkdir(parents=True)
        paths = {"started": c / "ledger" / f"{SMOKE2}.started",
                 "done": c / "ledger" / f"{SMOKE2}.done",
                 "result": c / f"{SMOKE2}-20261011T000000.json", "owner": c / RB.OWNER_FILE}
        paths[make].write_text("historical", encoding="utf-8")
        before = sorted(str(p.relative_to(c)) for p in c.rglob("*"))
        assert _live() == 2 and live.runs == []
        assert sorted(str(p.relative_to(c)) for p in c.rglob("*")) == before
        assert paths[make].read_text(encoding="utf-8") == "historical"
        assert "existing records block" in capsys.readouterr().err


class TestB4ValidationBeforeClaim:
    @pytest.mark.parametrize("change", [
        dict(head="9" * 40), dict(status=[" M benchmarks/run_benchmark.py"]),
        dict(status=["?? stray.txt"]), dict(staged=["a.py"]), dict(branch="HEAD")])
    def test_wrong_head_dirty_tree_or_staged_change_creates_nothing(
            self, live, change, capsys):
        live.git.update(change)
        assert _live() == 2 and "nothing was started" in capsys.readouterr().err
        assert _nothing_created(live)

    def test_the_order_of_the_checks_and_the_claim(self, live, monkeypatch):
        order = []
        for name in ("check_live_authorization", "check_effective_config",
                     "check_live_output_dir", "check_no_prior_evidence",
                     "verify_repository_readonly", "claim_run", "run_cell"):
            real = getattr(RB, name)

            def wrapped(*a, _n=name, _r=real, **k):
                order.append(_n)
                return _r(*a, **k)

            monkeypatch.setattr(RB, name, wrapped)
        assert _live() == 0
        assert order == ["check_live_authorization", "check_effective_config",
                         "check_live_output_dir", "check_no_prior_evidence",
                         "verify_repository_readonly", "claim_run", "run_cell"]

    def test_a_failure_before_the_claim_leaves_no_state_whatever_it_is(self, live, tmp_path):
        for argv in (["--authorize", "bm-smoke-r0005-c32-rep3"],
                     ["--output-dir", str(tmp_path / "x")]):
            assert _live(None, *argv) == 2
        live.git["head"] = "1" * 40
        assert _live() == 2 and _nothing_created(live)


def _good_binding():
    cell = _approved_cells()[0]
    return cell, {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256,
                  "config_path": "c.json", "effective_config": RB.effective_config(cell, LADDER)}


class TestB2MarkerBinding:
    def test_started_records_the_verified_configuration_and_run_identity(self, live):
        assert _live() == 0
        record = live.started_during_run
        cell = _approved_cells()[0]
        assert record["schema"] == 4 and record["benchmark_id"] == SMOKE2
        assert record["verified_head"] == record["git_head"] == HEAD
        assert record["branch"] == "work" and record["ladder_sha256"] == RB.APPROVED_LADDER_SHA256
        assert record["output_dir"] == str(live.canonical.resolve())
        assert record["config_path"] == str(RB.DEFAULT_CONFIG.resolve())
        effective = record["effective_config"]
        assert effective["seed"] == 42 and effective["scenario"] == "normal"
        assert effective["refresh_and_detector"] is True and effective["live_allowed"] is True
        assert effective["consumer_timing_interval_seconds"] == 0.0
        assert effective["consumer_commit_batch_messages"] == 1
        assert effective["consumer_commit_interval_seconds"] is None
        assert (effective["drain_limit_seconds"], effective["settle_seconds"],
                effective["cell_budget_seconds"]) == (120, 6, 3600)
        assert effective["stop_limits"] == LADDER["stop_limits"]
        assert effective["target"] == cell.target()
        assert effective["target"]["warmup_run_id"] == "b-smoke-r0005-c32-w2"
        assert effective["target"]["measured_run_id"] == "b-smoke-r0005-c32-m2"
        assert RB.validate_marker(record, cell, live.canonical) == []
        assert record["arguments"]["authorize"] == SMOKE2 and record["arguments"]["live"] is True

    @pytest.mark.parametrize("field,value", [
        ("benchmark_id", "bm-smoke-r0005-c32-rep3"), ("verified_head", "7" * 40),
        ("git_head", "7" * 40), ("branch", "HEAD"), ("ladder_sha256", "0" * 64),
        ("output_dir", "/elsewhere"), ("nonce", ""), ("schema", 1),
        ("effective_config", {}), ("unexpected", 1)])
    def test_inconsistent_fields_are_reported(self, tmp_path, field, value):
        cell, binding = _good_binding()
        RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        record = json.loads((tmp_path / "ledger" / f"{SMOKE2}.started").read_text())
        assert RB.validate_marker(record, cell, tmp_path) == []
        record[field] = value
        assert RB.validate_marker(record, cell, tmp_path)

    def test_a_changed_effective_value_or_run_id_is_reported(self, tmp_path):
        cell, binding = _good_binding()
        RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        record = json.loads((tmp_path / "ledger" / f"{SMOKE2}.started").read_text())
        for edit in (lambda r: r["effective_config"].__setitem__("seed", 7),
                     lambda r: r["effective_config"]["stop_limits"].__setitem__(
                         "memory_fraction", 1.0),
                     lambda r: r["effective_config"].__setitem__("refresh_and_detector", False),
                     lambda r: r["effective_config"]["target"].__setitem__(
                         "measured_run_id", "b-other-m2")):
            broken = copy.deepcopy(record)
            edit(broken)
            assert RB.validate_marker(broken, cell, tmp_path)

    @pytest.mark.parametrize("bad", ["ladder", "seed", "head"])
    def test_claim_run_refuses_an_inconsistent_binding_and_creates_nothing(self, tmp_path, bad):
        cell, binding = _good_binding()
        head = HEAD
        if bad == "ladder":
            binding["ladder_sha256"] = "0" * 64
        elif bad == "seed":
            binding["effective_config"]["seed"] = 7
        else:
            head = "short"
        with pytest.raises(RB.BenchmarkError, match="inconsistent"):
            RB.claim_run(tmp_path, cell, head=head, arguments={}, binding=binding)
        assert not any(tmp_path.rglob("*"))

    def test_a_stored_record_that_differs_from_the_written_one_is_kept_for_review(
            self, tmp_path, monkeypatch):
        cell, binding = _good_binding()
        real = RB._exclusive_json

        def corrupting(path, payload):
            if path.name.endswith(".started"):
                payload = {**payload, "arguments": {"tampered": True}}
            return real(path, payload)

        monkeypatch.setattr(RB, "_exclusive_json", corrupting)
        # the in-memory record and the stored one differ: refused, nothing deleted
        with pytest.raises(RB.BenchmarkError, match="kept for review"):
            RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        assert (tmp_path / "ledger" / f"{SMOKE2}.started").is_file()
        assert (tmp_path / RB.OWNER_FILE).is_file()

    def test_the_historical_format_is_unchanged(self, tmp_path):
        cell = _approved_cells()[0]
        started = RB.claim_run(tmp_path, cell, head=HEAD, arguments={"repetition": 2})
        record = json.loads(started.read_text(encoding="utf-8"))
        assert set(record) == {"benchmark_id", "git_head", "pid", "started_utc", "arguments"}
        assert RB.validate_marker(record, cell, tmp_path)        # not a schema-2 record


class TestAtomicClaim:
    def test_concurrent_claims_for_the_same_cell_cannot_both_succeed(self, tmp_path):
        cell, binding = _good_binding()
        gate, results = threading.Barrier(8), []

        def attempt():
            gate.wait()
            try:
                results.append(("ok", RB.claim_run(tmp_path, cell, head=HEAD, arguments={},
                                                    binding=binding)))
            except RB.BenchmarkError as exc:
                results.append(("refused", str(exc)))

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert [r[0] for r in results].count("ok") == 1 and len(results) == 8
        assert sorted(p.name for p in (tmp_path / "ledger").iterdir()) == [f"{SMOKE2}.started"]
        assert (tmp_path / RB.OWNER_FILE).is_file()

    def test_concurrent_claims_for_different_cells_in_one_directory_serialize(self, tmp_path):
        gate, results = threading.Barrier(2), []
        cells = [_approved_cells(repetition=n)[0] for n in (2, 3)]

        def attempt(cell):
            gate.wait()
            try:
                RB.claim_run(tmp_path, cell, head=HEAD, arguments={})
                results.append("ok")
            except RB.BenchmarkError:
                results.append("refused")

        threads = [threading.Thread(target=attempt, args=(c,)) for c in cells]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == ["ok", "refused"]
        assert len(list((tmp_path / "ledger").iterdir())) == 1

    def test_a_failure_while_writing_the_record_leaves_no_partial_started(
            self, tmp_path, monkeypatch):
        cell, binding = _good_binding()
        real_fsync, calls = os.fsync, []

        def failing_fsync(fd):
            calls.append(fd)
            if len(calls) == 2:                     # the owner file was fine; the record fails
                raise OSError("disk")
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", failing_fsync)
        with pytest.raises(RB.BenchmarkError, match="cannot create"):
            RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        assert not (tmp_path / "ledger" / f"{SMOKE2}.started").exists()
        assert not (tmp_path / RB.OWNER_FILE).exists()           # its own ownership released
        assert [p.name for p in (tmp_path / "ledger").iterdir()] == []   # no temporary left

    def test_another_owners_claim_is_never_removed(self, tmp_path, monkeypatch):
        cell, binding = _good_binding()
        real = RB._exclusive_json

        def raced(path, payload):
            if path.name.endswith(".started"):
                (tmp_path / RB.OWNER_FILE).write_text(OTHER_OWNER, encoding="utf-8")
                raise OSError("disk")
            return real(path, payload)

        monkeypatch.setattr(RB, "_exclusive_json", raced)
        with pytest.raises(RB.BenchmarkError, match="cannot create"):
            RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        assert (tmp_path / RB.OWNER_FILE).read_text(encoding="utf-8") == OTHER_OWNER
        assert not (tmp_path / "ledger" / f"{SMOKE2}.started").exists()

    def test_an_existing_record_is_never_replaced(self, tmp_path):
        target = tmp_path / "ledger" / "x.started"
        RB._exclusive_json(target, {"a": 1})
        with pytest.raises(FileExistsError):
            RB._exclusive_json(target, {"a": 2})
        assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
        assert [p.name for p in target.parent.iterdir()] == ["x.started"]


# ---------------------------------------------------------------------------
# B3J-106: the real Git-state reader and the canonical output directory
# ---------------------------------------------------------------------------
#
# The autouse fail_closed fixture makes subprocess.run refuse everything.  The Git tests
# below put the REAL subprocess.run back, for read-only git commands against a temporary
# repository only (RB.REPO is pointed at it); nothing here touches the AgentOps repository.

import shutil  # noqa: E402

# subprocess.run is replaced by autouse fixtures only inside tests; at import time it is real.
REAL_SUBPROCESS_RUN = subprocess.run
REAL_POPEN = subprocess.Popen          # subprocess.run calls Popen

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _git_in(repo, *args):
    result = REAL_SUBPROCESS_RUN(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", *args],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout.strip()


@pytest.fixture
def temp_repo(tmp_path, monkeypatch):
    """A temporary repository with one commit on branch `work`; the real subprocess.run is
    restored and RB.REPO points at it.  Returns (repo, head)."""
    monkeypatch.setattr(subprocess, "Popen", REAL_POPEN)
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_in(repo, "init", "-q", "-b", "work")
    (repo / "tracked.txt").write_text("one\n", encoding="utf-8", newline="\n")
    _git_in(repo, "add", "-A")
    _git_in(repo, "commit", "-q", "-m", "base")
    monkeypatch.setattr(subprocess, "run", REAL_SUBPROCESS_RUN)
    monkeypatch.setattr(RB, "REPO", repo)
    return repo, _git_in(repo, "rev-parse", "HEAD")


def _damage(repo, kind):
    if kind == "dirty tracked file":
        (repo / "tracked.txt").write_text("changed\n", encoding="utf-8", newline="\n")
    elif kind == "staged change":
        (repo / "staged.txt").write_text("x\n", encoding="utf-8", newline="\n")
        _git_in(repo, "add", "staged.txt")
    elif kind == "untracked file":
        (repo / "stray.txt").write_text("x\n", encoding="utf-8", newline="\n")
    elif kind == "detached head":
        _git_in(repo, "checkout", "-q", "--detach")
    elif kind == "staged deletion":
        _git_in(repo, "rm", "-q", "tracked.txt")
    else:
        raise AssertionError(kind)


DAMAGE = ["dirty tracked file", "staged change", "untracked file", "detached head",
          "staged deletion"]


@needs_git
class TestRealGitStateReader:
    def test_a_clean_repository_is_read_correctly(self, temp_repo):
        repo, head = temp_repo
        state = RB.read_git_state()
        assert state == {"head": head, "branch": "work", "status": [], "staged": []}
        assert RB.read_git_state(repo) == state
        assert REAL_VERIFY_REPOSITORY(head) == {"head": head, "branch": "work"}

    def test_a_dirty_tracked_file_is_reported(self, temp_repo):
        _damage(temp_repo[0], "dirty tracked file")
        state = RB.read_git_state()
        assert state["status"] == [" M tracked.txt"] and state["staged"] == []

    def test_a_staged_change_is_reported_in_both_lists(self, temp_repo):
        _damage(temp_repo[0], "staged change")
        state = RB.read_git_state()
        assert state["staged"] == ["staged.txt"] and state["status"] == ["A  staged.txt"]

    def test_an_untracked_file_is_reported(self, temp_repo):
        _damage(temp_repo[0], "untracked file")
        state = RB.read_git_state()
        assert state["status"] == ["?? stray.txt"] and state["staged"] == []

    def test_a_detached_head_reads_as_head_not_a_branch(self, temp_repo):
        repo, head = temp_repo
        _damage(repo, "detached head")
        state = RB.read_git_state()
        assert state["branch"] == "HEAD" and state["head"] == head

    def test_a_nested_untracked_file_is_listed_individually(self, temp_repo):
        repo, _ = temp_repo
        (repo / "dir").mkdir()
        (repo / "dir" / "a.txt").write_text("x\n", encoding="utf-8")
        assert RB.read_git_state()["status"] == ["?? dir/a.txt"]    # --untracked-files=all

    @pytest.mark.parametrize("kind", DAMAGE)
    def test_verify_rejects_every_invalid_state(self, temp_repo, kind):
        repo, head = temp_repo
        _damage(repo, kind)
        with pytest.raises(RB.BenchmarkError):
            REAL_VERIFY_REPOSITORY(head)

    def test_verify_rejects_a_wrong_expected_head(self, temp_repo):
        with pytest.raises(RB.BenchmarkError, match="not the expected commit"):
            REAL_VERIFY_REPOSITORY("1" * 40)

    def test_reading_never_changes_the_repository(self, temp_repo):
        repo, _ = temp_repo
        _damage(repo, "untracked file")
        _damage(repo, "dirty tracked file")
        before = (sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*")
                         if ".git" not in p.parts), _git_in(repo, "status", "--porcelain"),
                  (repo / ".git" / "index").read_bytes())
        for _ in range(3):
            RB.read_git_state()
        after = (sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*")
                        if ".git" not in p.parts), _git_in(repo, "status", "--porcelain"),
                 (repo / ".git" / "index").read_bytes())
        assert before == after
        assert not (repo / ".git" / "index.lock").exists()

    def test_a_repository_without_commits_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(subprocess, "Popen", REAL_POPEN)
        empty = tmp_path / "empty"
        empty.mkdir()
        _git_in(empty, "init", "-q", "-b", "work")
        monkeypatch.setattr(subprocess, "run", REAL_SUBPROCESS_RUN)
        with pytest.raises(RB.BenchmarkError, match=r"git rev-parse: exit \d+"):
            RB.read_git_state(empty)

    def test_a_directory_that_is_not_a_repository_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(subprocess, "run", REAL_SUBPROCESS_RUN)
        monkeypatch.setattr(subprocess, "Popen", REAL_POPEN)
        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        with pytest.raises(RB.BenchmarkError, match=r"git rev-parse: exit \d+"):
            RB.read_git_state(plain)


class TestGitCommandFailures:
    """The reader's handling of a failing or odd git, with controlled subprocess results."""

    @staticmethod
    def _script(monkeypatch, results):
        issued = []

        def fake(command, **kwargs):
            issued.append(list(command))
            step = results[len(issued) - 1]
            if isinstance(step, BaseException):
                raise step
            code, out = step
            return subprocess.CompletedProcess(command, code, out, "")

        monkeypatch.setattr(subprocess, "run", fake)
        return issued

    GOOD = [(0, "a" * 40 + "\n"), (0, "work\n"), (0, ""), (0, "")]

    def test_the_four_commands_are_the_read_only_ones(self, monkeypatch):
        issued = self._script(monkeypatch, self.GOOD)
        assert RB.read_git_state(Path("somewhere")) == {
            "head": "a" * 40, "branch": "work", "status": [], "staged": []}
        assert [c[c.index("-C") + 2:] for c in issued] == [
            ["rev-parse", "HEAD"], ["rev-parse", "--abbrev-ref", "HEAD"],
            ["status", "--porcelain", "--untracked-files=all"],
            ["diff", "--cached", "--name-only"]]
        assert all(c[:3] == ["git", "--no-optional-locks", "-C"] for c in issued)

    @pytest.mark.parametrize("failing", [0, 1, 2, 3])
    def test_a_nonzero_exit_of_any_command_fails_closed(self, monkeypatch, failing):
        results = list(self.GOOD)
        results[failing] = (128, "")
        self._script(monkeypatch, results)
        with pytest.raises(RB.BenchmarkError, match="exit 128"):
            RB.read_git_state(Path("somewhere"))

    @pytest.mark.parametrize("error", [FileNotFoundError("git"), PermissionError("x"),
                                       subprocess.TimeoutExpired("git", 60)])
    def test_a_missing_git_or_a_timeout_fails_closed(self, monkeypatch, error):
        self._script(monkeypatch, [error])
        with pytest.raises(RB.BenchmarkError, match="git rev-parse"):
            RB.read_git_state(Path("somewhere"))

    @pytest.mark.parametrize("results", [
        [(0, ""), (0, "work\n"), (0, ""), (0, "")],                    # empty HEAD
        [(0, "garbage\n"), (0, "work\n"), (0, ""), (0, "")],           # not a commit id
        [(0, "a" * 40 + "\n"), (0, ""), (0, ""), (0, "")],             # no branch name
        [(0, "a" * 40 + "\n"), (0, "work\n"), (0, "\n\n  \n"), (0, "\n")],  # blank lines only
    ])
    def test_malformed_output_never_verifies_a_state(self, monkeypatch, results):
        self._script(monkeypatch, results)
        state = RB.read_git_state(Path("somewhere"))
        if state["head"] == "a" * 40 and state["branch"] == "work":
            assert state["status"] == [] and state["staged"] == []     # blank lines are ignored
            return
        with pytest.raises(RB.BenchmarkError):
            REAL_VERIFY_REPOSITORY("a" * 40, read=lambda: state)

    def test_output_without_a_proper_head_is_refused_even_when_expected(self, monkeypatch):
        self._script(monkeypatch, [(0, "garbage\n"), (0, "work\n"), (0, ""), (0, "")])
        state = RB.read_git_state(Path("somewhere"))
        assert state["head"] == "garbage"
        with pytest.raises(RB.BenchmarkError):                         # expect-head is validated
            RB.check_live_authorization(_approved_cells(), authorize=SMOKE2,
                                        expect_head=state["head"], warmup_requests=25,
                                        repetition=2)


@needs_git
class TestInvalidGitStateCreatesNoClaim:
    """main with the REAL verify_repository_readonly and the REAL read_git_state on a
    temporary repository: an invalid state is refused before any claim exists."""

    @pytest.fixture
    def real_git(self, live, temp_repo, monkeypatch):
        repo, head = temp_repo
        monkeypatch.setattr(RB, "verify_repository_readonly", REAL_VERIFY_REPOSITORY)
        args = [*APPROVED, "--live", "--authorize", SMOKE2, "--expect-head", head]
        live.repo, live.head, live.args = repo, head, args
        return live

    def test_the_stubs_are_not_in_force(self, real_git):
        assert RB.verify_repository_readonly is REAL_VERIFY_REPOSITORY
        assert RB.check_live_output_dir is REAL_CHECK_LIVE_OUTPUT_DIR
        assert RB.read_git_state.__module__ == "run_benchmark"

    def test_a_valid_state_is_claimed_with_the_real_head_and_branch(self, real_git):
        assert _live(real_git.args) == 0 and real_git.runs == [SMOKE2]
        record = real_git.started_during_run
        assert record["verified_head"] == real_git.head and record["branch"] == "work"

    @pytest.mark.parametrize("kind", DAMAGE)
    def test_every_invalid_state_is_refused_with_nothing_created(self, real_git, kind, capsys):
        _damage(real_git.repo, kind)
        assert _live(real_git.args) == 2
        assert "nothing was started" in capsys.readouterr().err
        assert _nothing_created(real_git)

    def test_a_wrong_expected_head_is_refused_with_nothing_created(self, real_git):
        assert _live(real_git.args[:-1] + ["2" * 40]) == 2 and _nothing_created(real_git)


@pytest.fixture
def canonical_dir(tmp_path, monkeypatch):
    canonical = tmp_path / "canonical"
    monkeypatch.setattr(RB, "DEFAULT_OUTPUT", canonical)
    monkeypatch.setattr(RB, "check_live_output_dir", REAL_CHECK_LIVE_OUTPUT_DIR)
    return canonical


class TestCanonicalOutputDirectory:
    def test_the_exact_path_is_accepted_whether_or_not_it_exists(self, canonical_dir):
        assert RB.check_live_output_dir(canonical_dir) == canonical_dir.resolve()
        assert not canonical_dir.exists()                      # checking creates nothing
        canonical_dir.mkdir()
        assert RB.check_live_output_dir(canonical_dir) == canonical_dir.resolve()

    @pytest.mark.parametrize("spelling", [
        lambda c: c / "sub" / "..",
        lambda c: c.parent / "elsewhere" / ".." / c.name,
        lambda c: Path(str(c) + os.sep),
        lambda c: Path(str(c) + os.sep + "." + os.sep),
        lambda c: c.parent / "." / c.name,
    ], ids=["dotdot-below", "dotdot-sibling", "trailing-sep", "trailing-dot", "dot-segment"])
    def test_equivalent_spellings_resolve_to_the_canonical_location(self, canonical_dir, spelling):
        canonical_dir.mkdir()
        assert RB.check_live_output_dir(spelling(canonical_dir)) == canonical_dir.resolve()

    @pytest.mark.skipif(os.name != "nt", reason="case-insensitive paths are a Windows rule")
    def test_case_differences_are_the_same_directory_on_windows(self, canonical_dir):
        canonical_dir.mkdir()
        shouted = canonical_dir.parent / canonical_dir.name.upper()
        assert RB.check_live_output_dir(shouted) == shouted.resolve()
        assert os.path.normcase(str(shouted.resolve())) == os.path.normcase(
            str(canonical_dir.resolve()))

    @pytest.mark.skipif(os.name == "nt", reason="case-sensitive paths are a POSIX rule")
    def test_case_differences_are_another_directory_on_posix(self, canonical_dir):
        with pytest.raises(RB.BenchmarkError, match="canonical output directory"):
            RB.check_live_output_dir(canonical_dir.parent / canonical_dir.name.upper())

    @pytest.mark.parametrize("other", [
        lambda c: c.parent / "another",
        lambda c: c.parent / (c.name + "2"),                   # shares the prefix
        lambda c: c / "child",                                 # inside the canonical one
        lambda c: c.parent,                                    # its parent
        lambda c: c.parent / "x" / c.name,                     # same name, another place
    ], ids=["sibling", "prefix", "child", "parent", "same-name-elsewhere"])
    def test_a_different_directory_is_rejected(self, canonical_dir, other):
        canonical_dir.mkdir()
        with pytest.raises(RB.BenchmarkError, match="canonical output directory"):
            RB.check_live_output_dir(other(canonical_dir))

    def test_a_symlink_alias_is_the_canonical_directory(self, canonical_dir, tmp_path):
        canonical_dir.mkdir()
        alias = tmp_path / "alias"
        try:
            os.symlink(canonical_dir, alias, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available to this user")
        assert RB.check_live_output_dir(alias) == canonical_dir.resolve()
        with pytest.raises(RB.BenchmarkError):                 # ".." leaves the link's parent
            RB.check_live_output_dir(alias / "..")

    @pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows feature")
    def test_a_junction_alias_is_the_canonical_directory(self, canonical_dir, tmp_path,
                                                         monkeypatch):
        monkeypatch.setattr(subprocess, "Popen", REAL_POPEN)
        canonical_dir.mkdir()
        junction = tmp_path / "junction"
        made = REAL_SUBPROCESS_RUN(["cmd", "/c", "mklink", "/J", str(junction), str(canonical_dir)],
                                   capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                   timeout=30)
        if made.returncode != 0 or not junction.exists():
            pytest.skip("a junction could not be created here")
        assert RB.check_live_output_dir(junction) == canonical_dir.resolve()

    def test_an_alias_to_a_different_directory_is_rejected(self, canonical_dir, tmp_path):
        other = tmp_path / "other"
        other.mkdir()
        alias = tmp_path / "alias-to-other"
        try:
            os.symlink(other, alias, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available to this user")
        with pytest.raises(RB.BenchmarkError, match="canonical output directory"):
            RB.check_live_output_dir(alias)

    def test_the_default_is_a_directory_outside_the_repository(self):
        default = RB.DEFAULT_OUTPUT.resolve()
        assert default.name == "agentops-benchmarks" and _REPO not in default.parents

    def test_the_real_check_is_in_force_in_the_live_fixture(self, live):
        assert RB.check_live_output_dir is REAL_CHECK_LIVE_OUTPUT_DIR
        assert RB.verify_repository_readonly is not REAL_VERIFY_REPOSITORY   # injected reader

    def test_an_equivalent_spelling_shares_one_ledger_through_main(self, live, tmp_path):
        spelled = live.canonical / "sub" / ".."
        assert _live(None, "--output-dir", str(spelled)) == 0 and live.runs == [SMOKE2]
        assert _live(None, "--output-dir", str(live.canonical)) == 2          # same ledger
        assert _live(None, "--output-dir", str(Path(str(live.canonical) + os.sep))) == 2
        assert live.runs == [SMOKE2]
        assert sorted(p.name for p in (live.canonical / "ledger").iterdir()) == [
            f"{SMOKE2}.done", f"{SMOKE2}.started"]
        assert not (tmp_path / "sub").exists()

    def test_every_other_test_still_runs_with_the_stubs(self, monkeypatch):
        # outside the live fixture, the autouse stubs are in force (documented, not hidden)
        assert RB.check_live_output_dir is not REAL_CHECK_LIVE_OUTPUT_DIR
        assert RB.verify_repository_readonly is not REAL_VERIFY_REPOSITORY


# ---------------------------------------------------------------------------
# B3J-119: diagnostic capture of the storage consumer timing summaries
# ---------------------------------------------------------------------------

import importlib.util  # noqa: E402

PREFIX = RB.CONSUMER_TIMING_PREFIX
_STAGE_NAMES = ("poll", "decode_validate", "insert_txn", "kafka_commit", "cycle")


def timing_line(kind="window", start=1_791_780_140.0, end=1_791_780_145.0, **extra):
    """A valid timing summary line, as storage-consumer/timing.py writes it."""
    stage = {"count": 3, "total_ms": 30.0, "mean_ms": 10.0, "max_ms": 14.0,
             "hist": [0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0]}
    payload = {"kind": kind, "elapsed_s": 5.0, "start_epoch_s": start, "end_epoch_s": end,
               "bounds_ms": [0.5, 1.0, 2.0], "stages": {n: dict(stage) for n in _STAGE_NAMES},
               "counters": {"messages": 3, "idle_polls": 1, "inserted": 3, "conflicts": 0}}
    payload.update(extra)
    return PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":"))


class TimedSmoke(FakeSmoke):
    """A fake harness whose storage consumer log is `log_text` (or raises `log_error`)."""

    def __init__(self, tmp, *, log_text="", log_error=None, **kw):
        super().__init__(tmp, **kw)
        self.log_text, self.log_error = log_text, log_error

    def read_log(self, name):
        self.calls.append("read_log")
        assert name == "storage-consumer"
        if self.log_error is not None:
            raise self.log_error
        return self.log_text


def _diagnostic(monkeypatch, cell=None):
    cell = cell or _cell()
    monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({cell.benchmark_id}))
    return cell


def _sidecar(tmp_path, cell=None):
    return (tmp_path / "results").resolve() / f"{(cell or _cell()).benchmark_id}-consumer-timing.jsonl"


def _timing_limitations(result):
    return [x for x in result["limitations"] if "consumer timing sidecar" in x]


def _diagnostic_notes(result):
    return [x for x in result["limitations"] if x.startswith("diagnostic cell: storage consumer")]


GOOD_LOG = "\n".join([
    "agentops storage consumer starting", "  pg host    : 127.0.0.1:15432",
    timing_line(start=100.0, end=105.0), "noise in between", timing_line(start=105.0, end=110.0),
    ""])


class TestTimingIsDisabledByDefault:
    def test_only_rep5_and_rep6_are_diagnostic_and_every_other_cell_has_timing_off(self):
        rep5, rep6 = "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6"
        assert RB.DIAGNOSTIC_TIMING_CELLS == frozenset({rep5, rep6, "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"})
        assert dict(RB.APPROVED_DIAGNOSTIC_INTERVALS) == {rep5: 5.0, rep6: 5.0, "bm-small-r0010-c32-rep7": 5.0, "bm-small-r0010-c32-rep8": 5.0, "bm-small-r0010-c32-rep9": 5.0}
        assert RB.DIAGNOSTIC_TIMING_INTERVAL_SECONDS == 5.0
        assert RB.DIAGNOSTIC_TIMING_CELLS <= set(RB.APPROVED_LIVE_CELLS)
        assert RB.LIVE_ENABLED is True and len(RB.APPROVED_LIVE_CELLS) == 13
        for cell_id in RB.APPROVED_LIVE_CELLS:
            assert RB.timing_interval_for(cell_id) == (5.0 if cell_id in (rep5, rep6, "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9") else 0.0), cell_id

    def test_an_ordinary_cell_runs_with_timing_off_and_does_nothing_extra(self, tmp_path):
        result, path, clean, smoke = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG))
        assert smoke.CONSUMER_TIMING_INTERVAL == 0.0
        assert smoke.calls == ORDER and "read_log" not in smoke.calls
        assert clean and result["verdict"] == "VALID"
        assert _timing_limitations(result) == []
        assert not list((tmp_path / "results").glob("*consumer-timing*"))

    def test_the_setting_is_reset_for_every_cell(self, tmp_path, monkeypatch):
        smoke = TimedSmoke(tmp_path, log_text=GOOD_LOG)
        _diagnostic(monkeypatch)
        _run(tmp_path, smoke=smoke)
        assert smoke.CONSUMER_TIMING_INTERVAL == 5.0
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset())
        _run(tmp_path / "again", smoke=smoke, out=tmp_path / "again-results")
        assert smoke.CONSUMER_TIMING_INTERVAL == 0.0

    def test_being_diagnostic_does_not_authorize_a_cell(self, monkeypatch, tmp_path):
        unapproved = dataclasses.replace(_approved_cells(repetition=2)[0], repetition=10)
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({unapproved.benchmark_id}))
        assert not RB.is_approved_live_cell(unapproved)
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
            RB.run_cell(unapproved, LADDER, expect_head=HEAD, output_dir=tmp_path)
        with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
            _authorize([unapproved], authorize=unapproved.benchmark_id)


class TestDiagnosticCapture:
    def test_a_diagnostic_cell_enables_timing_and_writes_the_sidecar(self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        result, path, clean, smoke = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG),
                                          cell=cell)
        assert smoke.CONSUMER_TIMING_INTERVAL == 5.0 and clean
        sidecar = _sidecar(tmp_path, cell)
        lines = sidecar.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2 and all(line.startswith(PREFIX) for line in lines)
        assert [json.loads(l[len(PREFIX):])["start_epoch_s"] for l in lines] == [100.0, 105.0]
        (note,) = _timing_limitations(result)
        assert "written" in note and "2 summaries (2 windows)" in note and "lost" in note
        assert sidecar.name == f"{cell.benchmark_id}-consumer-timing.jsonl"
        assert sidecar.parent == path.parent
        assert not sidecar.name.endswith(".json")            # never matches the result glob

    def test_the_result_is_unchanged_apart_from_one_limitation(self, tmp_path, monkeypatch):
        for name in ("a", "b"):
            (tmp_path / name).mkdir()
        plain, _, _, _ = _run(tmp_path / "a", smoke=TimedSmoke(tmp_path / "a", log_text=GOOD_LOG))
        cell = _diagnostic(monkeypatch)
        timed, _, _, _ = _run(tmp_path / "b", smoke=TimedSmoke(tmp_path / "b", log_text=GOOD_LOG),
                              cell=cell)
        assert {k: v for k, v in plain.items() if k not in ("limitations", "consumer")} == {
            k: v for k, v in timed.items() if k not in ("limitations", "consumer")}
        # the consumer block differs only by the configured timing interval and the measured windows
        assert plain["consumer"]["timing_diagnostic_interval_seconds"] == 0.0 and "observed" not in plain["consumer"]
        assert timed["consumer"]["timing_diagnostic_interval_seconds"] == 5.0 and "observed" in timed["consumer"]
        assert plain["consumer"]["commit_batching"] == timed["consumer"]["commit_batching"]
        assert timed["verdict"] == plain["verdict"] == "VALID"
        assert [x for x in timed["limitations"] if x not in _timing_limitations(timed)
                and x not in _diagnostic_notes(timed)] == plain["limitations"]
        assert len(_diagnostic_notes(timed)) == 1 and _diagnostic_notes(plain) == []
        M.validate_result(timed)

    def test_the_capture_runs_after_the_consumer_stops_and_before_the_logs_go(
            self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        _, _, _, smoke = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG), cell=cell)
        calls = smoke.calls
        assert calls.index("stop_host_processes") < calls.index("read_log") < calls.index("cleanup")
        assert calls.count("read_log") == 1

    @pytest.mark.parametrize("step", ["run_stage_measured", "start_host_services", "run_detector"])
    def test_a_failed_cell_still_captures_the_windows_it_has(self, tmp_path, monkeypatch, step):
        cell = _diagnostic(monkeypatch)
        smoke = TimedSmoke(tmp_path, log_text=GOOD_LOG, fail=step)
        result, _, clean, smoke = _run(tmp_path, smoke=smoke, cell=cell)
        assert result["verdict"] != "VALID" and clean
        assert "read_log" in smoke.calls and smoke.calls[-1] == "cleanup"
        assert _sidecar(tmp_path, cell).is_file()
        assert "written" in _timing_limitations(result)[0]

    def test_a_cell_that_failed_before_the_consumer_started_says_so(self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        smoke = TimedSmoke(tmp_path, log_error=KeyError("storage-consumer"), fail="start_kafka")
        result, _, clean, _ = _run(tmp_path, smoke=smoke, cell=cell)
        assert clean and result["verdict"] != "VALID"
        assert "NOT captured: the consumer log was not available" in _timing_limitations(result)[0]
        assert not _sidecar(tmp_path, cell).exists()


class TestTimingLineFiltering:
    def test_only_exact_prefix_valid_summaries_are_kept(self):
        good = timing_line()
        log = "\n".join([
            good,
            "  " + timing_line(),                                  # indented: not the prefix
            "note: " + timing_line(),                              # prefix not at the start
            "storage-consumer timing{}",                           # no separating space
            "storage-consumer  timing " + "{}",
            "Traceback (most recent call last):",
            "  pg host    : 127.0.0.1:15432",
            timing_line("final"),
        ])
        kept, malformed = RB.consumer_timing_lines(log)
        assert kept == [good, timing_line("final")] and malformed == 0

    @pytest.mark.parametrize("bad", [
        PREFIX + "{not json", PREFIX + "[]", PREFIX + "null", PREFIX + "",
        PREFIX + json.dumps({"kind": "window"}),
        timing_line(kind="surprise"),
        timing_line(elapsed_s="five"),
        timing_line(extra_key=1),                                   # an unknown field
        timing_line(trace_id="a" * 32),
        timing_line(counters={"messages": 1}),
        timing_line(counters={"messages": -1, "idle_polls": 0, "inserted": 0, "conflicts": 0}),
        timing_line(stages={"poll": {}}),
        timing_line(bounds_ms=list(range(100))),
        PREFIX + '{"kind":"window","elapsed_s":NaN}',
    ])
    def test_malformed_lines_are_skipped_and_counted(self, bad):
        kept, malformed = RB.consumer_timing_lines("\n".join([timing_line(), bad]))
        assert kept == [timing_line()] and malformed == 1

    def test_nothing_but_numbers_and_known_names_survives(self):
        poisoned = json.loads(timing_line()[len(PREFIX):])
        poisoned["stages"]["poll"]["note"] = "password=hunter2"
        kept, malformed = RB.consumer_timing_lines(PREFIX + json.dumps(poisoned))
        assert kept == [] and malformed == 1

    def test_the_number_of_lines_is_bounded(self, monkeypatch):
        monkeypatch.setattr(RB, "MAX_TIMING_LINES", 3)
        kept, malformed = RB.consumer_timing_lines("\n".join([timing_line()] * 5))
        assert len(kept) == 3 and malformed == 2

    def test_what_the_real_recorder_writes_is_accepted_unchanged(self):
        path = _REPO / "storage-consumer" / "timing.py"
        spec = importlib.util.spec_from_file_location("consumer_timing_contract", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.LINE_PREFIX == PREFIX
        out, tick = [], iter(x * 0.003 for x in range(1, 1000))
        recorder = module.TimingRecorder(0.001, clock=lambda: next(tick), emit=out.append,
                                         wall=lambda: 1_791_780_140.5)
        for stage in module.STAGES:
            recorder.record(stage, 0.004)
        recorder.count("messages")
        recorder.count("idle_polls")
        recorder.maybe_emit()
        recorder.final()
        assert [json.loads(l[len(PREFIX):])["kind"] for l in out] == ["window", "final"]
        kept, malformed = RB.consumer_timing_lines("\n".join(out))
        assert kept == out and malformed == 0

    def test_the_sidecar_holds_no_other_log_output_or_credentials(self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        log = "\n".join(["PG_PASSWORD=never-printed", "postgresql://u:never-printed@host/db",
                         timing_line(), "Traceback: never-printed"])
        _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=log), cell=cell)
        text = _sidecar(tmp_path, cell).read_text(encoding="utf-8")
        assert text.count("\n") == 1 and "never-printed" not in text
        assert "postgresql" not in text and "Traceback" not in text and "pg host" not in text


class TestCaptureNeverHarmsTheCell:
    @pytest.mark.parametrize("log", ["", "no timing here\nonly start-up lines\n",
                                     PREFIX + "{broken\n"])
    def test_an_empty_or_useless_log_is_reported_not_claimed(self, tmp_path, monkeypatch, log):
        cell = _diagnostic(monkeypatch)
        result, _, clean, _ = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=log), cell=cell)
        assert clean and result["verdict"] == "VALID"
        (note,) = _timing_limitations(result)
        assert "NOT captured" in note and "no timing summary" in note
        assert not _sidecar(tmp_path, cell).exists()

    def test_malformed_lines_are_reported_when_some_are_kept(self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        log = "\n".join([timing_line(), PREFIX + "{bad", PREFIX + "[]"])
        result, _, _, _ = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=log), cell=cell)
        assert "2 malformed timing line(s) skipped" in _timing_limitations(result)[0]
        assert _sidecar(tmp_path, cell).read_text(encoding="utf-8").count("\n") == 1

    @pytest.mark.parametrize("error", [KeyError("storage-consumer"), FileNotFoundError("gone"),
                                       PermissionError("denied"), RuntimeError("odd")])
    def test_an_unreadable_log_is_reported_and_changes_nothing(self, tmp_path, monkeypatch, error):
        cell = _diagnostic(monkeypatch)
        result, _, clean, smoke = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_error=error),
                                       cell=cell)
        assert clean and result["verdict"] == "VALID" and smoke.calls[-1] == "cleanup"
        assert "NOT captured" in _timing_limitations(result)[0]
        assert not _sidecar(tmp_path, cell).exists()

    def test_an_existing_sidecar_is_never_overwritten(self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        existing = _sidecar(tmp_path, cell)
        existing.parent.mkdir(parents=True)
        existing.write_text("historical evidence\n", encoding="utf-8")
        result, _, clean, _ = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG),
                                   cell=cell)
        assert clean and result["verdict"] == "VALID"
        assert existing.read_text(encoding="utf-8") == "historical evidence\n"
        assert "NOT written" in _timing_limitations(result)[0]
        assert [p.name for p in existing.parent.iterdir() if p.name.startswith(".")] == []

    def test_a_write_failure_changes_neither_the_verdict_nor_the_cleanup(
            self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)

        def broken(path, text):
            raise OSError("disk full")

        monkeypatch.setattr(RB, "_exclusive_text", broken)
        result, _, clean, smoke = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG),
                                       cell=cell)
        assert clean and result["verdict"] == "VALID" and smoke.calls[-1] == "cleanup"
        assert "NOT captured: OSError" in _timing_limitations(result)[0]
        assert not _sidecar(tmp_path, cell).exists()

    def test_a_failure_in_the_cell_is_not_masked_by_a_failure_in_the_capture(
            self, tmp_path, monkeypatch):
        cell = _diagnostic(monkeypatch)
        smoke = TimedSmoke(tmp_path, log_error=RuntimeError("log"), fail="run_stage_measured")
        result, _, clean, smoke = _run(tmp_path, smoke=smoke, cell=cell)
        assert result["verdict"] != "VALID" and clean and smoke.calls[-1] == "cleanup"
        assert "run_stage_measured failed" in json.dumps(result)

    def test_the_sidecar_is_whole_or_absent(self, tmp_path):
        target = tmp_path / "x-consumer-timing.jsonl"
        RB._exclusive_text(target, "one\ntwo\n")
        with pytest.raises(FileExistsError):
            RB._exclusive_text(target, "other\n")
        assert target.read_text(encoding="utf-8") == "one\ntwo\n"
        assert [p.name for p in tmp_path.iterdir()] == [target.name]

    def test_cleanup_without_a_capture_is_as_before(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        evidence = SimpleNamespace(limitations=[])
        assert RB._cleanup(smoke, FakeE2E(smoke), [], False, evidence) is True
        assert smoke.calls == ["stop_host_processes", "cleanup"] and evidence.limitations == []

    def test_a_capture_that_somehow_raised_still_lets_the_stack_come_down(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        evidence = SimpleNamespace(limitations=[])

        def raising():
            raise RuntimeError("unexpected")

        assert RB._cleanup(smoke, FakeE2E(smoke), [], False, evidence, raising) is False
        assert smoke.calls == ["stop_host_processes", "cleanup"]
        assert any("consumer timing capture failed" in x for x in evidence.limitations)


# ---------------------------------------------------------------------------
# B3J-122: SMALL-10 rep5, the one timing-enabled diagnostic cell (nothing is run)
# ---------------------------------------------------------------------------

REP5 = "bm-small-r0010-c32-rep5"
REP6 = "bm-small-r0010-c32-rep6"
REP5_FIELDS = {**SMALL10_FIELDS, "repetition": 5}
REP5_ARGS = ["--level", "SMALL", "--rate", "10", "--repetition", "5", "--concurrency", "32",
             "--warmup-requests", "300", "--live", "--authorize", REP5, "--expect-head", HEAD]


class TestRep5Authorization:
    def test_rep5_is_approved_with_exactly_the_small_ten_specification(self):
        assert dict(RB.APPROVED_LIVE_CELLS[REP5]) == REP5_FIELDS
        assert dict(RB.APPROVED_LIVE_CELLS[REP5]) == {
            **dict(RB.APPROVED_LIVE_CELLS["bm-small-r0010-c32-rep4"]), "repetition": 5}
        cell = _small(repetition=5)
        assert (cell.benchmark_id, cell.level, cell.requests, cell.rate, cell.concurrency,
                cell.repetition, cell.warmup_requests, cell.seed) == (
            REP5, "SMALL", 1000, 10, 32, 5, 300, 42)
        assert (cell.warmup_run_id, cell.measured_run_id) == (
            "b-small-r0010-c32-w5", "b-small-r0010-c32-m5")
        assert cell.target()["scenario"] == "normal" and cell.refresh_and_detector is True
        assert RB.RUN_ID_RE.fullmatch(cell.warmup_run_id) and RB.RUN_ID_RE.fullmatch(cell.measured_run_id)
        assert RB.is_approved_live_cell(cell)
        assert _authorize_small(cell, authorize=REP5, repetition=5) == cell

    @pytest.mark.parametrize("change", [
        dict(requests=999), dict(rate=5), dict(rate=25), dict(concurrency=16),
        dict(concurrency=33), dict(warmup_requests=299), dict(level="SMOKE"),
        dict(repetition=4), dict(repetition=10)])
    def test_a_changed_rep5_field_is_not_the_approved_cell(self, change):
        cell = dataclasses.replace(_small(repetition=5), **change)
        if change == dict(repetition=4):
            assert cell.benchmark_id == "bm-small-r0010-c32-rep4"       # another approved cell
            with pytest.raises(RB.BenchmarkError, match="is not " + REP5):
                _authorize_small(cell, authorize=REP5, repetition=5)
        else:
            assert not RB.is_approved_live_cell(cell), change

    @pytest.mark.parametrize("authorize,repetition,warmup", [
        (REP5, 4, 300), (REP5, 6, 300), (REP5, None, 300), (REP5, 5, 299), (REP5, 5, None),
        ("bm-small-r0010-c32-rep6", 6, 300), ("bm-small-r0025-c32-rep5", 5, 300)])
    def test_wrong_selectors_are_refused(self, authorize, repetition, warmup):
        with pytest.raises(RB.BenchmarkError):
            _authorize_small(_small(repetition=5), authorize=authorize, repetition=repetition,
                             warmup=warmup)

    def test_no_other_new_cell_is_approved(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == sorted(ALLOWLISTED_CELLS)
        for n in (10,):
            assert not RB.is_approved_live_cell(_small(repetition=n))
        for rate in (25, 50, 100):
            assert not RB.is_approved_live_cell(_small(rate=rate, repetition=5))

    def test_the_other_approved_cells_are_unchanged(self):
        for n in (1, 2, 3, 4):
            assert dict(RB.APPROVED_LIVE_CELLS[ALL_TOKENS[n]]) == {**SMALL10_FIELDS, "repetition": n}
        for n in (2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-smoke-r0005-c32-rep{n}"]) == {
                **SMOKE_REPEAT_FIELDS, "repetition": n}

    def test_the_ladder_and_its_pin_are_untouched(self):
        import hashlib
        pinned = "571138bb0c10e15547345aca5f15422742ffb03d998e88127c2d7aadc8b2c71f"
        assert hashlib.sha256((Path(_BENCH) / "ladder.json").read_bytes()).hexdigest() == pinned
        assert RB.APPROVED_LADDER_SHA256 == pinned


class TestTimingIsFailClosed:
    def test_rep5_runs_with_timing_at_five_seconds_and_the_others_with_none(self):
        rep5 = RB.check_effective_config(_small(repetition=5), LADDER)
        assert rep5["consumer_timing_interval_seconds"] == 5.0
        assert type(rep5["consumer_timing_interval_seconds"]) is float
        for cell_id in RB.APPROVED_LIVE_CELLS:
            assert RB.timing_interval_for(cell_id) == (5.0 if cell_id in (REP5, REP6, "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9") else 0.0)
        for n in (1, 2, 3, 4):
            assert RB.check_effective_config(_small(repetition=n), LADDER)[
                "consumer_timing_interval_seconds"] == 0.0
        for n in (2, 3, 4, 5):
            assert RB.check_effective_config(_approved_cells(repetition=n)[0], LADDER)[
                "consumer_timing_interval_seconds"] == 0.0

    def test_the_harness_gets_five_seconds_for_rep5_only(self, tmp_path):
        smoke = TimedSmoke(tmp_path, log_text=GOOD_LOG)
        _run(tmp_path, smoke=smoke, cell=_small(repetition=5))
        assert smoke.CONSUMER_TIMING_INTERVAL == 5.0
        smoke = TimedSmoke(tmp_path, log_text=GOOD_LOG)
        _run(tmp_path, smoke=smoke, cell=_small(repetition=4), out=tmp_path / "other")
        assert smoke.CONSUMER_TIMING_INTERVAL == 0.0
        smoke = TimedSmoke(tmp_path, log_text=GOOD_LOG)
        _run(tmp_path, smoke=smoke, out=tmp_path / "smoke-results")
        assert smoke.CONSUMER_TIMING_INTERVAL == 0.0

    def test_rep5_with_timing_disabled_is_refused_before_a_claim(self, live, monkeypatch, capsys):
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset())
        assert _live(REP5_ARGS) == 2
        assert "diagnostic timing configuration" in capsys.readouterr().err
        assert _nothing_created(live)

    @pytest.mark.parametrize("interval", [1.0, 4.999, 10.0, 0.0, 5])
    def test_rep5_with_another_interval_is_refused_before_a_claim(
            self, live, monkeypatch, capsys, interval):
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_INTERVAL_SECONDS", interval)
        assert _live(REP5_ARGS) == 2
        assert "nothing was started" in capsys.readouterr().err
        assert _nothing_created(live)

    def test_an_unapproved_diagnostic_activation_is_refused_before_a_claim(
            self, live, monkeypatch, capsys):
        ordinary = "bm-smoke-r0005-c32-rep2"
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({REP5, ordinary}))
        for argv in (REP5_ARGS, APPROVED_ARGS):               # neither the new nor the old cell runs
            assert _live(argv) == 2
            assert "diagnostic timing configuration" in capsys.readouterr().err
        assert _nothing_created(live)

    def test_an_ordinary_cell_alone_in_the_diagnostic_set_is_refused(self, live, monkeypatch):
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({"bm-smoke-r0005-c32-rep2"}))
        assert _live(APPROVED_ARGS) == 2 and _live(REP5_ARGS) == 2
        assert _nothing_created(live)

    def test_the_independent_literal_must_agree_with_the_constant(self, live, monkeypatch):
        monkeypatch.setattr(RB, "APPROVED_DIAGNOSTIC_INTERVALS", {REP5: 7.0})
        assert _live(REP5_ARGS) == 2 and _nothing_created(live)
        monkeypatch.setattr(RB, "APPROVED_DIAGNOSTIC_INTERVALS", {})
        assert _live(REP5_ARGS) == 2 and _live(APPROVED_ARGS) == 2 and _nothing_created(live)

    def test_run_cell_refuses_the_same_mismatches(self, monkeypatch, tmp_path):
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        monkeypatch.setattr(RB, "execute_cell", lambda *a, **k: pytest.fail("reached"))
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset())
        with pytest.raises(RB.BenchmarkError, match="diagnostic timing configuration"):
            RB.run_cell(_small(repetition=5), LADDER, expect_head=HEAD, output_dir=tmp_path)

    def test_no_ambient_environment_enables_it(self, monkeypatch):
        monkeypatch.setenv("CONSUMER_TIMING_INTERVAL_SECONDS", "5")
        assert RB.timing_interval_for("bm-smoke-r0005-c32-rep2") == 0.0
        assert RB.timing_interval_for("bm-small-r0010-c32-rep4") == 0.0
        assert RB.check_effective_config(_small(repetition=4), LADDER)[
            "consumer_timing_interval_seconds"] == 0.0


class TestRep5CliAndClaim:
    def test_the_exact_rep5_run_is_claimed_with_timing_bound_into_the_claim(self, live):
        assert _live(REP5_ARGS) == 0 and live.runs == [REP5]
        record = live.started_during_run
        assert record["schema"] == 4 and record["benchmark_id"] == REP5
        assert record["verified_head"] == HEAD and record["ladder_sha256"] == RB.APPROVED_LADDER_SHA256
        effective = record["effective_config"]
        assert effective["consumer_timing_interval_seconds"] == 5.0
        assert effective["target"] == _small(repetition=5).target()
        assert effective["seed"] == 42 and effective["scenario"] == "normal"
        assert effective["refresh_and_detector"] is True
        assert effective["stop_limits"] == LADDER["stop_limits"]
        assert RB.validate_marker(record, _small(repetition=5), live.canonical) == []

    def test_an_ordinary_cell_records_timing_off(self, live):
        assert _live() == 0 and live.runs == ["bm-smoke-r0005-c32-rep2"]
        assert live.started_during_run["effective_config"]["consumer_timing_interval_seconds"] == 0.0

    @pytest.mark.parametrize("change", [("--warmup-requests", "299"), ("--concurrency", "16"),
                                        ("--rate", "25"), ("--repetition", "6"),
                                        ("--level", "SMOKE")])
    def test_a_wrong_workload_is_refused_before_a_claim(self, live, change):
        argv = list(REP5_ARGS)
        argv[argv.index(change[0]) + 1] = change[1]
        assert _live(argv) == 2 and _nothing_created(live)

    def test_a_wrong_head_is_refused_before_a_claim(self, live, capsys):
        live.git["head"] = "9" * 40
        assert _live(REP5_ARGS) == 2 and _nothing_created(live)
        live.git["head"] = HEAD
        assert _live(REP5_ARGS[:-1] + ["short"]) == 2 and _nothing_created(live)
        live.git["status"] = [" M benchmarks/run_benchmark.py"]
        assert _live(REP5_ARGS) == 2 and _nothing_created(live)

    def test_the_cell_can_be_used_once(self, live, tmp_path):
        assert _live(REP5_ARGS) == 0
        assert _live(REP5_ARGS) == 2                       # same directory: evidence exists
        assert _live(REP5_ARGS, "--output-dir", str(tmp_path / "elsewhere")) == 2
        assert live.runs == [REP5]
        ledger = sorted(p.name for p in (live.canonical / "ledger").iterdir())
        assert ledger == [f"{REP5}.done", f"{REP5}.started"]

    def test_existing_rep5_records_block_a_rerun_and_are_left_alone(self, live):
        (live.canonical / "ledger").mkdir(parents=True)
        started = live.canonical / "ledger" / f"{REP5}.started"
        started.write_text("kept", encoding="utf-8")
        assert _live(REP5_ARGS) == 2 and live.runs == []
        assert started.read_text(encoding="utf-8") == "kept"

    def test_the_order_of_checks_is_unchanged(self, live, monkeypatch):
        order = []
        for name in ("check_live_authorization", "check_effective_config",
                     "check_live_output_dir", "check_no_prior_evidence",
                     "verify_repository_readonly", "claim_run", "run_cell"):
            real = getattr(RB, name)

            def wrapped(*a, _n=name, _r=real, **k):
                order.append(_n)
                return _r(*a, **k)

            monkeypatch.setattr(RB, name, wrapped)
        assert _live(REP5_ARGS) == 0
        assert order == ["check_live_authorization", "check_effective_config",
                         "check_live_output_dir", "check_no_prior_evidence",
                         "verify_repository_readonly", "claim_run", "run_cell"]


class TestSchemaThreeMarker:
    @staticmethod
    def _claim(tmp_path, cell):
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256,
                   "config_path": "c.json", "effective_config": RB.effective_config(cell, LADDER)}
        started = RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        return json.loads(started.read_text(encoding="utf-8"))

    def test_a_schema_three_record_validates_for_its_own_cell(self, tmp_path):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        assert record["schema"] == RB.MARKER_SCHEMA == 4
        assert record["effective_config"]["consumer_timing_interval_seconds"] == 5.0
        assert RB.validate_marker(record, cell, tmp_path) == []

    @pytest.mark.parametrize("value", [0.0, 4.0, 10.0, 5, "5", None, True])
    def test_a_tampered_timing_value_on_rep5_is_refused(self, tmp_path, value):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        record["effective_config"]["consumer_timing_interval_seconds"] = value
        assert any("consumer_timing_interval_seconds" in p
                   for p in RB.validate_marker(record, cell, tmp_path))

    @pytest.mark.parametrize("value", [5.0, 1.0, 0, False])
    def test_a_timing_value_on_an_ordinary_cell_is_refused(self, tmp_path, value):
        cell = _small(repetition=4)
        record = self._claim(tmp_path, cell)
        assert RB.validate_marker(record, cell, tmp_path) == []
        record["effective_config"]["consumer_timing_interval_seconds"] = value
        assert RB.validate_marker(record, cell, tmp_path)

    def test_a_missing_or_extra_effective_field_is_refused(self, tmp_path):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        missing = json.loads(json.dumps(record))
        del missing["effective_config"]["consumer_timing_interval_seconds"]
        extra = json.loads(json.dumps(record))
        extra["effective_config"]["something_else"] = 1
        assert RB.validate_marker(missing, cell, tmp_path) and RB.validate_marker(extra, cell, tmp_path)

    def test_a_schema_two_record_is_not_valid_for_a_new_claim(self, tmp_path):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        record["schema"] = 2
        assert "unsupported schema" in RB.validate_marker(record, cell, tmp_path)

    def test_claim_run_refuses_a_binding_with_the_wrong_timing_and_creates_nothing(self, tmp_path):
        cell = _small(repetition=5)
        effective = RB.effective_config(cell, LADDER)
        effective["consumer_timing_interval_seconds"] = 0.0
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256,
                   "config_path": "c.json", "effective_config": effective}
        with pytest.raises(RB.BenchmarkError, match="inconsistent"):
            RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        assert not any(tmp_path.rglob("*"))


class TestRep5ResultAndCapture:
    def test_the_diagnostic_limitation_is_recorded_whatever_happens_to_the_sidecar(
            self, tmp_path):
        cases = [dict(log_text=GOOD_LOG), dict(log_text=""), dict(log_error=KeyError("x")),
                 dict(log_error=RuntimeError("odd")), dict(log_text=GOOD_LOG, fail="run_stage_measured")]
        for index, kw in enumerate(cases):
            out = tmp_path / f"r{index}"
            out.mkdir()
            result, _, clean, smoke = _run(out, smoke=TimedSmoke(out, **kw), cell=_small(repetition=5))
            (note,) = _diagnostic_notes(result)
            assert note == ("diagnostic cell: storage consumer timing was enabled at 5 seconds; "
                            "the consumer ran with timing instrumentation")
            assert clean and smoke.calls[-1] == "cleanup"

    def test_an_ordinary_cell_has_no_diagnostic_limitation(self, tmp_path):
        for cell in (_small(repetition=4), _approved_cells()[0]):
            out = tmp_path / cell.benchmark_id
            out.mkdir()
            result, _, _, smoke = _run(out, smoke=TimedSmoke(out, log_text=GOOD_LOG), cell=cell)
            assert _diagnostic_notes(result) == [] and _timing_limitations(result) == []
            assert smoke.CONSUMER_TIMING_INTERVAL == 0.0 and "read_log" not in smoke.calls

    def test_the_verdict_is_the_same_with_and_without_timing(self, tmp_path, monkeypatch):
        # The fake harness is built for SMOKE-sized data, so a SMALL cell is judged the same
        # way with or without timing: what matters is that timing changes nothing about it.
        for name in ("on", "off"):
            (tmp_path / name).mkdir()
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({REP5}))
        timed, _, clean_on, _ = _run(tmp_path / "on", smoke=TimedSmoke(tmp_path / "on",
                                                                        log_text=GOOD_LOG),
                                     cell=_small(repetition=5))
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset())
        plain, _, clean_off, _ = _run(tmp_path / "off", smoke=TimedSmoke(tmp_path / "off",
                                                                         log_text=GOOD_LOG),
                                      cell=_small(repetition=5))
        assert clean_on and clean_off
        assert timed["verdict"] == plain["verdict"]
        assert timed["verdict_reasons"] == plain["verdict_reasons"]
        assert timed["counts"] == plain["counts"] and timed["integrity"] == plain["integrity"]
        assert timed["stop"] == plain["stop"] and timed["metrics"] == plain["metrics"]
        assert len(_diagnostic_notes(timed)) == 1 and _diagnostic_notes(plain) == []
        M.validate_result(timed)

    def test_a_capture_failure_cannot_change_the_verdict_or_stop_the_cleanup(
            self, tmp_path, monkeypatch):
        (tmp_path / "ok").mkdir()
        (tmp_path / "bad").mkdir()
        good, _, clean_ok, _ = _run(tmp_path / "ok", smoke=TimedSmoke(tmp_path / "ok",
                                                                      log_text=GOOD_LOG),
                                    cell=_small(repetition=5))

        def broken(path, text):
            raise OSError("disk full")

        monkeypatch.setattr(RB, "_exclusive_text", broken)
        bad, _, clean_bad, smoke = _run(tmp_path / "bad", smoke=TimedSmoke(tmp_path / "bad",
                                                                           log_text=GOOD_LOG),
                                        cell=_small(repetition=5))
        assert clean_ok and clean_bad and smoke.calls[-1] == "cleanup"
        assert bad["verdict"] == good["verdict"] and bad["metrics"] == good["metrics"]
        assert "NOT captured" in _timing_limitations(bad)[0]
        assert "written" in _timing_limitations(good)[0]
        assert len(_diagnostic_notes(bad)) == len(_diagnostic_notes(good)) == 1


# ---------------------------------------------------------------------------
# B3J-213: the normal database container may be absent, running healthy, or deliberately stopped
# ---------------------------------------------------------------------------

_LEGACY_ID = "b2b3d05e5c31e10963ecd134675cb6d8acc39a88877c431a34a0557e111f3e85"
_STARTED = "2026-10-11T05:09:40.642119878Z"
_FINISHED = "2026-10-12T05:30:29.794074111Z"
_NEVER = "0001-01-01T00:00:00Z"
_READ_ONLY_DOCKER = {"ps", "volume", "network", "images", "inspect"}


def _state(status, health="", started=_STARTED, finished=_FINISHED, ident=_LEGACY_ID):
    """The string normal_postgres() builds from `docker inspect`."""
    return f"{ident} {status} {health} {started} {finished}"


@pytest.fixture()
def guarded_smoke(monkeypatch):
    """A private copy of the real run_smoke module, with every docker call answered by a
    fake.  It is registered under its own name, so the real name never enters sys.modules."""
    path = _REPO / "workload-generator" / "run_smoke.py"
    name = "run_smoke_b3j213_under_test"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    module.docker_calls = []
    module.container = {"state": None}          # None: the container does not exist

    def fake_run(command, *, timeout, cwd=None, env=None, what=""):
        assert command[0] == "docker"
        module.docker_calls.append(list(command))
        if command[1] == "inspect":
            assert command[-1] == module.NORMAL_POSTGRES_CONTAINER
            state = module.container["state"]
            return subprocess.CompletedProcess(command, 0 if state else 1, (state or "") + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(module, "run", fake_run)
    assert "run_smoke" not in sys.modules
    return module


class TestNormalDatabaseBaseline:

    @pytest.mark.parametrize("state", [
        None,
        _state("running", "healthy"),
        _state("exited", "unhealthy"),                      # the real legacy container today
        _state("exited", "healthy"),
        _state("exited", ""),
    ])
    def test_accepted_baselines(self, guarded_smoke, state):
        smoke = guarded_smoke
        smoke.container["state"] = state
        smoke.record_docker_state()
        assert smoke.RUN.normal_postgres == state

    @pytest.mark.parametrize("state", [
        _state("running", "unhealthy"),
        _state("running", "starting"),
        _state("running", ""),                              # running, no health information
        _state("paused", "healthy"),
        _state("restarting", ""),
        _state("dead", ""),
        _state("created", ""),
        _state("removing", ""),
        "not even a state",
    ])
    def test_every_other_baseline_is_refused(self, guarded_smoke, state):
        smoke = guarded_smoke
        smoke.container["state"] = state
        with pytest.raises(smoke.SmokeFailure, match="neither running healthy nor exited"):
            smoke.record_docker_state()

    def test_the_predicate_itself(self, guarded_smoke):
        ok = guarded_smoke.normal_postgres_baseline_ok
        assert ok(None) and ok(_state("running", "healthy")) and ok(_state("exited", "unhealthy"))
        assert not ok(_state("running", "unhealthy")) and not ok(_state("dead")) and not ok("")

    def test_the_inspect_includes_the_lifecycle_timestamps(self, guarded_smoke):
        smoke = guarded_smoke
        smoke.container["state"] = _state("exited", "unhealthy")
        assert smoke.normal_postgres() == _state("exited", "unhealthy")
        inspect = [c for c in smoke.docker_calls if c[1] == "inspect"][-1]
        assert "{{.State.StartedAt}}" in inspect[3] and "{{.State.FinishedAt}}" in inspect[3]
        assert "{{.Id}}" in inspect[3] and "{{.State.Status}}" in inspect[3] and "Health" in inspect[3]


class TestNormalDatabaseChangeDetection:

    @staticmethod
    def _baseline(smoke, state):
        smoke.container["state"] = state
        smoke.record_docker_state()

    @pytest.mark.parametrize("baseline, later", [
        (_state("exited", "unhealthy"), _state("running", "healthy", finished=_NEVER)),    # started
        (_state("exited", "unhealthy"), _state("running", "starting")),                    # starting up
        (_state("exited", "unhealthy"), _state("exited", "unhealthy", started="2026-10-15T20:00:00Z")),
        (_state("exited", "unhealthy"), _state("exited", "unhealthy", finished="2026-10-15T20:01:00Z")),
        (_state("exited", "unhealthy"), _state("exited", "healthy")),                      # health flipped
        (_state("exited", "unhealthy"), _state("exited", "unhealthy", ident="f" * 64)),    # recreated
        (_state("exited", "unhealthy"), None),                                             # removed
        (_state("running", "healthy"), _state("exited", "healthy")),                       # stopped mid-run
        (_state("running", "healthy"), _state("running", "unhealthy")),
        (_state("running", "healthy"), None),
        (None, _state("exited", "")),                                                      # appeared
    ])
    def test_any_change_is_detected(self, guarded_smoke, baseline, later):
        smoke = guarded_smoke
        self._baseline(smoke, baseline)
        smoke.container["state"] = later
        with pytest.raises(smoke.SmokeFailure, match="changed"):
            smoke.check_normal_stack("test")

    @pytest.mark.parametrize("state", [None, _state("running", "healthy"), _state("exited", "unhealthy")])
    def test_an_unchanged_container_passes_every_check(self, guarded_smoke, state):
        smoke = guarded_smoke
        self._baseline(smoke, state)
        smoke.check_normal_stack("before any telemetry")
        smoke.check_normal_stack("after the first stage")
        smoke.check_normal_stack("after the cell")

    def test_the_final_comparison_uses_the_same_string(self):
        text = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        assert "now = normal_postgres()" in text and "if now != RUN.normal_postgres:" in text
        assert 'problems.append(f"{NORMAL_POSTGRES_CONTAINER} changed")' in text


class TestNormalDatabaseIsOnlyInspected:

    def test_the_baseline_check_issues_only_read_only_docker_commands(self, guarded_smoke):
        smoke = guarded_smoke
        smoke.container["state"] = _state("exited", "unhealthy")
        smoke.record_docker_state()
        smoke.check_normal_stack("test")
        assert smoke.docker_calls
        assert {call[1] for call in smoke.docker_calls} <= _READ_ONLY_DOCKER

    def test_the_container_name_never_appears_with_a_lifecycle_verb(self):
        text = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if "NORMAL_POSTGRES_CONTAINER" in line or "agentops-postgres" in line:
                for verb in ('"start"', '"stop"', '"restart"', '"kill"', '"rm"', '"rename"', '"exec"'):
                    assert verb not in line, (number, verb)

    def test_the_docker_fingerprint_still_covers_containers_volumes_networks_and_images(self, guarded_smoke):
        fingerprint = guarded_smoke.docker_fingerprint()
        assert set(fingerprint) == {"containers", "volumes", "networks", "images"}
        text = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        assert '"docker", "image", "rm", image_id' in text            # new images are removed by exact id
        assert "--force" not in text


# ---------------------------------------------------------------------------
# B3J-216: SMALL-10 rep5 states that it is diagnostic only and not comparable when the Docker
# engine allocation differs from the one reps 1-4 recorded
# ---------------------------------------------------------------------------

_REP5 = "bm-small-r0010-c32-rep5"
_REP6 = "bm-small-r0010-c32-rep6"
_REF_NCPU, _REF_MEM = 22, 8_168_574_976
_NOW_NCPU, _NOW_MEM = 4, 5_157_535_744


def _rep5_cell():
    cell = _approved_cells("SMALL", rates=[10], repetition=5, concurrency=32, warmup_requests=300)[0]
    assert cell.benchmark_id == _REP5
    return cell


def _machine(ncpu, mem):
    return {"docker": {"ServerVersion": "29.7.2", "NCPU": ncpu, "MemTotal": mem}}


def _comparability(result):
    return [x for x in result["limitations"] if x.startswith("comparability:")]


class AllocatedSmoke(TimedSmoke):
    """A timed fake harness whose Docker engine reports a chosen allocation (or fails)."""

    def __init__(self, tmp, *, ncpu=_NOW_NCPU, mem=_NOW_MEM, info_error=None, **kw):
        super().__init__(tmp, log_text=GOOD_LOG, **kw)
        self.ncpu, self.mem, self.info_error = ncpu, mem, info_error

    def checked(self, command, **kwargs):
        if list(command[:2]) == ["docker", "info"]:
            if self.info_error is not None:
                raise self.info_error
            self.commands.append(list(command))
            return json.dumps({"ServerVersion": "29.7.2", "NCPU": self.ncpu, "MemTotal": self.mem})
        return super().checked(command, **kwargs)


class TestComparabilityLimitation:

    def test_the_reference_is_the_recorded_allocation_of_this_one_cell(self):
        one = {"against": "SMALL-10 repetitions 1-4", "NCPU": _REF_NCPU, "MemTotal": _REF_MEM}
        assert dict(RB.COMPARABILITY_REFERENCES) == {_REP5: one, _REP6: one, "bm-small-r0010-c32-rep7": one, "bm-small-r0010-c32-rep8": one, "bm-small-r0010-c32-rep9": one}
        assert set(RB.COMPARABILITY_REFERENCES) <= RB.DIAGNOSTIC_TIMING_CELLS
        assert set(RB.COMPARABILITY_REFERENCES) <= set(RB.APPROVED_LIVE_CELLS)

    def test_a_different_allocation_gives_an_explicit_limitation(self):
        note = RB.comparability_limitation(_REP5, _machine(_NOW_NCPU, _NOW_MEM))
        assert note.startswith("comparability: diagnostic only")
        assert "not directly comparable with SMALL-10 repetitions 1-4" in note
        assert "throughput and latency" in note
        assert "NCPU 4 vs 22" in note and "MemTotal 5157535744 vs 8168574976 bytes" in note

    @pytest.mark.parametrize("ncpu, mem", [(_NOW_NCPU, _REF_MEM), (_REF_NCPU, _NOW_MEM), (8, 8 * GB), (64, 1)])
    def test_either_difference_alone_is_enough(self, ncpu, mem):
        note = RB.comparability_limitation(_REP5, _machine(ncpu, mem))
        assert note and "not directly comparable" in note

    def test_the_reference_allocation_needs_no_limitation(self):
        assert RB.comparability_limitation(_REP5, _machine(_REF_NCPU, _REF_MEM)) is None

    @pytest.mark.parametrize("machine", [
        {}, {"docker": None}, {"docker": {"kind": "NOT_MEASURED", "reason": "boom"}},
        {"docker": {"NCPU": 4}}, {"docker": {"MemTotal": 1}}, {"docker": {"NCPU": True, "MemTotal": True}},
        {"docker": {"NCPU": "4", "MemTotal": "5157535744"}}, {"docker": {"NCPU": 4.0, "MemTotal": 5.0e9}},
        None, "text", [],
    ])
    def test_an_unmeasured_allocation_is_never_silently_omitted(self, machine):
        note = RB.comparability_limitation(_REP5, machine)
        assert note and "could not be verified" in note and "not comparable" in note

    def test_no_other_cell_gets_the_limitation(self):
        for cell_id in RB.APPROVED_LIVE_CELLS:
            if cell_id not in (_REP5, _REP6, "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"):
                assert RB.comparability_limitation(cell_id, _machine(_NOW_NCPU, _NOW_MEM)) is None, cell_id
                assert RB.comparability_limitation(cell_id, {}) is None
        assert RB.comparability_limitation("bm-unknown", _machine(1, 1)) is None

    def test_the_function_does_not_change_its_input(self):
        machine = _machine(_NOW_NCPU, _NOW_MEM)
        before = json.dumps(machine, sort_keys=True)
        RB.comparability_limitation(_REP5, machine)
        assert json.dumps(machine, sort_keys=True) == before


class TestComparabilityInTheResult:

    def test_a_rep5_run_with_the_current_allocation_records_the_limitation_once(self, tmp_path):
        result, path, clean, smoke = _run(tmp_path, smoke=AllocatedSmoke(tmp_path), cell=_rep5_cell())
        assert clean and smoke.CONSUMER_TIMING_INTERVAL == 5.0
        (note,) = _comparability(result)
        assert "NCPU 4 vs 22" in note and "not directly comparable" in note
        assert not note.startswith("diagnostic cell: storage consumer")      # the other note is untouched
        assert len(_diagnostic_notes(result)) == 1
        assert result["machine"]["docker"]["NCPU"] == 4              # the measured allocation stays in the result
        M.validate_result(result)

    def test_it_does_not_change_the_verdict_or_any_measurement(self, tmp_path):
        for name in ("differs", "same"):
            (tmp_path / name).mkdir()
        differs, _, _, _ = _run(tmp_path / "differs", smoke=AllocatedSmoke(tmp_path / "differs"), cell=_rep5_cell())
        same, _, _, _ = _run(tmp_path / "same", cell=_rep5_cell(),
                             smoke=AllocatedSmoke(tmp_path / "same", ncpu=_REF_NCPU, mem=_REF_MEM))
        assert differs["verdict"] == same["verdict"]       # whatever the fake data earns, the note changes nothing
        assert differs["verdict_reasons"] == same["verdict_reasons"]
        assert differs["metrics"] == same["metrics"] and differs["claims"] == same["claims"]
        assert differs["integrity"] == same["integrity"] and differs["stop"] == same["stop"]
        assert len(_comparability(differs)) == 1 and _comparability(same) == []
        assert [x for x in differs["limitations"] if not x.startswith("comparability:")] == [
            x for x in same["limitations"]]
        M.validate_result(differs)
        M.validate_result(same)

    def test_the_reference_allocation_adds_nothing(self, tmp_path):
        result, _, _, _ = _run(tmp_path, cell=_rep5_cell(),
                               smoke=AllocatedSmoke(tmp_path, ncpu=_REF_NCPU, mem=_REF_MEM))
        assert _comparability(result) == []

    def test_a_failed_docker_info_still_records_a_limitation(self, tmp_path):
        smoke = AllocatedSmoke(tmp_path, info_error=RuntimeError("docker info failed"))
        result, _, clean, _ = _run(tmp_path, smoke=smoke, cell=_rep5_cell())
        assert clean
        (note,) = _comparability(result)
        assert "could not be verified" in note
        M.validate_result(result)

    def test_another_cell_never_carries_it_even_when_its_allocation_differs(self, tmp_path):
        result, _, _, smoke = _run(tmp_path)                    # an ordinary SMOKE cell; the fake engine has 8 CPUs
        assert _comparability(result) == []
        assert smoke.CONSUMER_TIMING_INTERVAL == 0.0

    def test_the_cell_body_cannot_skip_the_check(self):
        text = (_REPO / "benchmarks" / "run_benchmark.py").read_text(encoding="utf-8")
        assert text.count("comparability_limitation(cell.benchmark_id, evidence.machine)") == 1
        call = text.index("comparability_limitation(cell.benchmark_id, evidence.machine)")
        assert text.index("evidence.machine = collect_machine_baseline(") < call
        assert call < text.index("smoke.create_workspace()", call)       # recorded before the stack is built


# ---------------------------------------------------------------------------
# B3J-220: the harness's idea of a finished bootstrap ledger is the real bootstrap plan
# (B3J-219 failed live because it still expected 17 steps ending in "complete")
# ---------------------------------------------------------------------------

def _real_bootstrap_plan_names():
    """The ordered step names of db-bootstrap's own plan on the real migration files."""
    path = _REPO / "db-bootstrap" / "bootstrap.py"
    spec = importlib.util.spec_from_file_location("bootstrap_plan_b3j220", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bootstrap_plan_b3j220"] = module
    try:
        spec.loader.exec_module(module)
        plan = module.build_plan(_REPO / "storage-consumer" / "migrations",
                                 _REPO / "db-bootstrap" / "post_dbt_grants.sql")
    finally:
        sys.modules.pop("bootstrap_plan_b3j220", None)
    return tuple(step.name for step in plan), module.STEP_COMPLETE


def _ledger_text(names):
    """What the harness's ledger query returns for a ledger holding these steps."""
    return f"{len(names)}|{','.join(names)}"


class TestLedgerMatchesTheRealBootstrapPlan:

    def test_the_expected_steps_are_exactly_the_real_plan(self, guarded_smoke):
        names, complete = _real_bootstrap_plan_names()
        assert guarded_smoke.LEDGER_PLAN == names
        assert guarded_smoke.LEDGER_STEPS == len(names) == 18
        # the upgrades follow the "complete" marker, so "complete" is not the last step
        assert names.index(complete) == 16 and names[-1] == "015_grant_trace_viewer_anomaly_rca_read.sql"
        assert names[-1] != complete

    def test_every_migration_file_is_in_the_expected_steps(self, guarded_smoke):
        files = sorted(p.name for p in (_REPO / "storage-consumer" / "migrations").glob("*.sql"))
        assert files and all(name in guarded_smoke.LEDGER_PLAN for name in files)

    def test_the_ledger_a_real_bootstrap_writes_is_accepted(self, guarded_smoke):
        names, _ = _real_bootstrap_plan_names()          # built from the plan, not from the harness constant
        assert guarded_smoke.ledger_problem(_ledger_text(names)) is None

    def test_the_ledger_that_failed_in_b3j219_is_accepted_now(self, guarded_smoke):
        # 18 steps recorded, last step '015_grant_trace_viewer_anomaly_rca_read.sql'
        names, _ = _real_bootstrap_plan_names()
        assert names[-1] == "015_grant_trace_viewer_anomaly_rca_read.sql"
        assert guarded_smoke.ledger_problem(f"18|{','.join(names)}") is None

    def test_the_run_e2e_ledger_step_count_follows_the_same_source(self):
        text = (_REPO / "workload-generator" / "run_e2e.py").read_text(encoding="utf-8")
        assert 'str(smoke.LEDGER_STEPS)' in text
        names, _ = _real_bootstrap_plan_names()
        assert len(names) == 18

    def test_no_hardcoded_17_step_text_remains(self):
        text = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        assert "17 steps" not in text and "LEDGER_STEPS: int = 17" not in text


class TestLedgerProblem:

    @pytest.mark.parametrize("mutate, expect", [
        (lambda n: n[:17], "missing"),                                  # the old ledger, up to "complete"
        (lambda n: n[:16], "missing"),                                  # no "complete" marker yet
        (lambda n: n[:-1], "missing"),
        (lambda n: n + ("016_future_upgrade.sql",), "unexpected"),
        (lambda n: (n[1], n[0]) + n[2:], "order"),
        (lambda n: tuple(x for x in n if x != "complete"), "missing"),
        (lambda n: n[:-1] + ("015_other.sql",), "unexpected"),
        (lambda n: (), "missing"),
    ])
    def test_a_ledger_that_is_not_the_plan_is_refused(self, guarded_smoke, mutate, expect):
        names, _ = _real_bootstrap_plan_names()
        problem = guarded_smoke.ledger_problem(_ledger_text(mutate(names)))
        assert problem and "not COMPLETE" in problem and expect in problem
        assert "18 steps" in problem or "the 18 steps" in problem

    def test_a_count_that_disagrees_with_the_names_is_refused(self, guarded_smoke):
        names, _ = _real_bootstrap_plan_names()
        assert guarded_smoke.ledger_problem(f"17|{','.join(names)}")
        assert guarded_smoke.ledger_problem("") and guarded_smoke.ledger_problem("0|")

    def test_the_refusal_names_the_old_failure_mode(self, guarded_smoke):
        names, _ = _real_bootstrap_plan_names()
        problem = guarded_smoke.ledger_problem(_ledger_text(names[:17]))
        assert "last 'complete'" in problem and "015_grant_trace_viewer_anomaly_rca_read.sql" in problem


class TestBootstrapLedgerCheckInTheHarness:

    def test_the_real_plan_passes_the_harness_check(self, guarded_smoke, monkeypatch):
        names, _ = _real_bootstrap_plan_names()
        asked = []
        monkeypatch.setattr(guarded_smoke, "psql", lambda sql: asked.append(sql) or _ledger_text(names))
        guarded_smoke.check_bootstrap_ledger()
        assert len(asked) == 1 and asked[0].startswith("SELECT ") and "agentops_bootstrap.ledger" in asked[0]
        assert "ORDER BY position" in asked[0] and "INSERT" not in asked[0].upper()

    def test_a_seventeen_step_ledger_fails_the_harness_check_with_a_clear_message(self, guarded_smoke, monkeypatch):
        names, _ = _real_bootstrap_plan_names()
        monkeypatch.setattr(guarded_smoke, "psql", lambda sql: _ledger_text(names[:17]))
        with pytest.raises(guarded_smoke.SmokeFailure, match="not COMPLETE.*015_grant_trace_viewer"):
            guarded_smoke.check_bootstrap_ledger()

    def test_run_bootstrap_uses_the_check(self):
        text = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        body = text[text.index("def run_bootstrap()"):text.index("def ledger_problem(")]
        assert "check_bootstrap_ledger()" in body and 'raise SmokeFailure("the bootstrap failed")' in body


# ---------------------------------------------------------------------------
# B3J-223: SMALL-10 rep6, the replacement diagnostic cell (nothing is run).  rep5's claim and its
# INVALID evidence (B3J-219) are permanent: rep6 is a different cell and never touches them.
# ---------------------------------------------------------------------------

import re  # noqa: E402

REP6_FIELDS = {**SMALL10_FIELDS, "repetition": 6}
REP6_ARGS = ["--level", "SMALL", "--rate", "10", "--repetition", "6", "--concurrency", "32",
             "--warmup-requests", "300", "--live", "--authorize", REP6, "--expect-head", HEAD]
_REF_ONE = {"against": "SMALL-10 repetitions 1-4", "NCPU": 22, "MemTotal": 8_168_574_976}


def _rep6_cell():
    cell = _approved_cells("SMALL", rates=[10], repetition=6, concurrency=32, warmup_requests=300)[0]
    assert cell.benchmark_id == REP6
    return cell


class TestRep6Authorization:

    def test_rep6_is_approved_with_exactly_the_small_ten_specification(self):
        assert dict(RB.APPROVED_LIVE_CELLS[REP6]) == REP6_FIELDS
        assert dict(RB.APPROVED_LIVE_CELLS[REP6]) == {
            "level": "SMALL", "requests": 1000, "rate": 10, "concurrency": 32,
            "warmup_requests": 300, "repetition": 6}
        cell = _small(repetition=6)
        assert cell.benchmark_id == REP6 and RB.is_approved_live_cell(cell)
        assert (cell.warmup_run_id, cell.measured_run_id) == ("b-small-r0010-c32-w6", "b-small-r0010-c32-m6")
        assert _authorize_small(cell, authorize=REP6, repetition=6) == cell

    @pytest.mark.parametrize("change", [
        dict(requests=999), dict(requests=1001), dict(rate=5), dict(rate=25), dict(concurrency=16),
        dict(concurrency=33), dict(warmup_requests=299), dict(level="SMOKE")])
    def test_a_changed_rep6_field_is_not_the_approved_cell(self, change):
        assert not RB.is_approved_live_cell(dataclasses.replace(_small(repetition=6), **change)), change

    @pytest.mark.parametrize("authorize, repetition, cell_repetition", [
        (REP6, 5, 5), (REP5, 6, 6), (REP6, 5, 6), (REP5, 5, 6), (REP6, 6, 5), (REP5, 6, 5), (REP6, None, 6)])
    def test_rep5_and_rep6_authorizations_cannot_be_interchanged(self, authorize, repetition, cell_repetition):
        with pytest.raises(RB.BenchmarkError):
            _authorize_small(_small(repetition=cell_repetition), authorize=authorize, repetition=repetition)

    @pytest.mark.parametrize("authorize, repetition, warmup", [
        (REP6, 6, 299), (REP6, 6, None), ("bm-small-r0010-c32-rep7", 7, 300), ("bm-small-r0025-c32-rep6", 6, 300)])
    def test_wrong_selectors_are_refused(self, authorize, repetition, warmup):
        with pytest.raises(RB.BenchmarkError):
            _authorize_small(_small(repetition=6), authorize=authorize, repetition=repetition, warmup=warmup)

    def test_repetitions_nine_and_ten_stay_unauthorized_in_the_rep6_series(self):
        for n in (10,):
            assert not RB.is_approved_live_cell(_small(repetition=n))
            with pytest.raises(RB.BenchmarkError, match="authorize"):
                _authorize_small(_small(repetition=n), authorize=f"bm-small-r0010-c32-rep{n}", repetition=n)
        for rate in (25, 50, 100):
            assert not RB.is_approved_live_cell(_small(rate=rate, repetition=6))
        assert RB.is_approved_live_cell(_small(repetition=5)) and len(RB.APPROVED_LIVE_CELLS) == 13

    def test_the_earlier_cells_are_unchanged(self):
        for n in (1, 2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-small-r0010-c32-rep{n}"]) == {**SMALL10_FIELDS, "repetition": n}
        for n in (2, 3, 4, 5):
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-smoke-r0005-c32-rep{n}"]) == {**SMOKE_REPEAT_FIELDS, "repetition": n}


class TestRep6DiagnosticTables:

    def test_the_three_tables_agree_and_keep_rep5(self):
        both = {REP5, REP6, "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"}
        assert RB.DIAGNOSTIC_TIMING_CELLS == frozenset(both)
        assert dict(RB.APPROVED_DIAGNOSTIC_INTERVALS) == {REP5: 5.0, REP6: 5.0, "bm-small-r0010-c32-rep7": 5.0, "bm-small-r0010-c32-rep8": 5.0, "bm-small-r0010-c32-rep9": 5.0}
        assert set(RB.COMPARABILITY_REFERENCES) == both
        assert both <= set(RB.APPROVED_LIVE_CELLS)
        assert RB.DIAGNOSTIC_TIMING_INTERVAL_SECONDS == 5.0
        assert {RB.timing_interval_for(c) for c in both} == {5.0}

    def test_every_other_cell_runs_with_timing_off(self):
        for cell_id in RB.APPROVED_LIVE_CELLS:
            assert RB.timing_interval_for(cell_id) == (5.0 if cell_id in (REP5, REP6, "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9") else 0.0), cell_id

    def test_rep6_runs_with_timing_at_five_seconds_as_a_float(self):
        effective = RB.check_effective_config(_small(repetition=6), LADDER)
        assert effective["consumer_timing_interval_seconds"] == 5.0
        assert type(effective["consumer_timing_interval_seconds"]) is float
        assert effective["target"] == _small(repetition=6).target()

    def test_the_harness_gets_five_seconds_for_rep6(self, tmp_path):
        smoke = TimedSmoke(tmp_path, log_text=GOOD_LOG)
        _run(tmp_path, smoke=smoke, cell=_rep6_cell())
        assert smoke.CONSUMER_TIMING_INTERVAL == 5.0

    def test_the_references_are_the_reps_1_to_4_allocation_for_both(self):
        assert dict(RB.COMPARABILITY_REFERENCES) == {REP5: _REF_ONE, REP6: _REF_ONE, "bm-small-r0010-c32-rep7": _REF_ONE, "bm-small-r0010-c32-rep8": _REF_ONE, "bm-small-r0010-c32-rep9": _REF_ONE}

    @pytest.mark.parametrize("change", [lambda: RB.DIAGNOSTIC_TIMING_CELLS - {REP6},
                                        lambda: RB.DIAGNOSTIC_TIMING_CELLS | {"bm-smoke-r0005-c32-rep2"}])
    def test_a_disagreeing_timing_table_is_refused_for_rep6(self, change, monkeypatch):
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset(change()))
        with pytest.raises(RB.BenchmarkError, match="diagnostic timing configuration"):
            RB.check_effective_config(_small(repetition=6), LADDER)

    @pytest.mark.parametrize("table", [{REP5: 5.0}, {REP5: 5.0, REP6: 7.0}, {}])
    def test_a_wrong_interval_table_is_refused_for_rep6(self, table, monkeypatch):
        monkeypatch.setattr(RB, "APPROVED_DIAGNOSTIC_INTERVALS", table)
        with pytest.raises(RB.BenchmarkError):
            RB.check_effective_config(_small(repetition=6), LADDER)


class TestRep6ComparabilityLimitation:

    def test_rep6_under_the_current_allocation_is_labelled(self):
        note = RB.comparability_limitation(REP6, {"docker": {"NCPU": 4, "MemTotal": 5_157_535_744}})
        assert note.startswith("comparability: diagnostic only")
        assert "not directly comparable with SMALL-10 repetitions 1-4" in note
        assert "NCPU 4 vs 22" in note and "MemTotal 5157535744 vs 8168574976 bytes" in note

    def test_rep6_with_the_reference_allocation_needs_none(self):
        assert RB.comparability_limitation(REP6, {"docker": {"NCPU": 22, "MemTotal": 8_168_574_976}}) is None

    @pytest.mark.parametrize("machine", [{}, {"docker": None}, {"docker": {"kind": "NOT_MEASURED"}},
                                         {"docker": {"NCPU": "4", "MemTotal": "5"}}, None])
    def test_an_unmeasured_allocation_is_never_silently_omitted_for_rep6(self, machine):
        note = RB.comparability_limitation(REP6, machine)
        assert note and "could not be verified" in note

    def test_a_rep6_run_records_the_limitation_once(self, tmp_path):
        result, _, clean, smoke = _run(tmp_path, smoke=AllocatedSmoke(tmp_path), cell=_rep6_cell())
        assert clean and smoke.CONSUMER_TIMING_INTERVAL == 5.0
        (note,) = _comparability(result)
        assert "NCPU 4 vs 22" in note
        assert len(_diagnostic_notes(result)) == 1
        M.validate_result(result)

    def test_a_rep6_run_with_a_failed_docker_info_records_the_conservative_note(self, tmp_path):
        smoke = AllocatedSmoke(tmp_path, info_error=RuntimeError("docker info failed"))
        result, _, _, _ = _run(tmp_path, smoke=smoke, cell=_rep6_cell())
        (note,) = _comparability(result)
        assert "could not be verified" in note


class TestRep6ClaimAndRep5Evidence:

    def test_the_exact_rep6_run_is_claimed_with_timing_bound_into_the_claim(self, live):
        assert _live(REP6_ARGS) == 0 and live.runs == [REP6]
        record = live.started_during_run
        assert record["benchmark_id"] == REP6 and record["verified_head"] == HEAD
        assert record["effective_config"]["consumer_timing_interval_seconds"] == 5.0
        assert record["effective_config"]["target"] == _small(repetition=6).target()
        assert RB.validate_marker(record, _small(repetition=6), live.canonical) == []

    def test_rep6_can_be_used_once(self, live, tmp_path):
        assert _live(REP6_ARGS) == 0
        assert _live(REP6_ARGS) == 2 and _live(REP6_ARGS, "--output-dir", str(tmp_path / "else")) == 2
        assert live.runs == [REP6]
        assert sorted(p.name for p in (live.canonical / "ledger").iterdir()) == [f"{REP6}.done", f"{REP6}.started"]

    def _seed_rep5_evidence(self, live):
        ledger = live.canonical / "ledger"
        ledger.mkdir(parents=True)
        files = {ledger / f"{REP5}.started": '{"benchmark_id": "rep5 started"}\n',
                 ledger / f"{REP5}.done": '{"benchmark_id": "rep5 done", "verdict": "INVALID"}\n',
                 live.canonical / f"{REP5}-20261015T204049.json": '{"verdict": "INVALID"}\n'}
        for path, text in files.items():
            path.write_text(text, encoding="utf-8", newline="\n")
        return {path: path.read_bytes() for path in files}

    def test_rep5_evidence_does_not_block_rep6_and_is_left_byte_identical(self, live):
        before = self._seed_rep5_evidence(live)
        assert _live(REP6_ARGS) == 0 and live.runs == [REP6]
        assert {path: path.read_bytes() for path in before} == before          # not modified, removed or renamed
        names = sorted(p.name for p in (live.canonical / "ledger").iterdir())
        assert names == [f"{REP5}.done", f"{REP5}.started", f"{REP6}.done", f"{REP6}.started"]

    def test_rep5_stays_blocked_by_its_historical_claim(self, live):
        before = self._seed_rep5_evidence(live)
        assert _live(REP5_ARGS) == 2 and live.runs == []
        assert {path: path.read_bytes() for path in before} == before
        assert not (live.canonical / RB.OWNER_FILE).exists()

    def test_rep6_evidence_never_matches_the_rep5_glob_or_ledger_names(self):
        assert not "bm-small-r0010-c32-rep6-20261016T000000.json".startswith(REP5 + "-")
        assert not f"{REP6}.started".startswith(REP5)

    def test_the_claim_function_refuses_rep6_when_its_own_evidence_exists_but_not_for_rep5s(self, tmp_path):
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.effective_config(_small(repetition=6), LADDER)}
        (tmp_path / "ledger").mkdir()
        (tmp_path / "ledger" / f"{REP5}.started").write_text("kept", encoding="utf-8")
        started = RB.claim_run(tmp_path, _small(repetition=6), head=HEAD, arguments={}, binding=binding)
        assert started.name == f"{REP6}.started"
        assert (tmp_path / "ledger" / f"{REP5}.started").read_text(encoding="utf-8") == "kept"
        (tmp_path / RB.OWNER_FILE).unlink()
        with pytest.raises(RB.BenchmarkError, match="started before"):
            RB.claim_run(tmp_path, _small(repetition=6), head=HEAD, arguments={}, binding=binding)


# ---------------------------------------------------------------------------
# B3J-223: offline contracts between the harness and the files it drives, so that a wiring
# mismatch is found here and not in a live attempt (the B3J-219 failure was of this kind)
# ---------------------------------------------------------------------------

def _compose_services(path):
    names, inside = set(), False
    for line in (_REPO / path).read_text(encoding="utf-8").splitlines():
        if re.match(r"^services:\s*$", line):
            inside = True
        elif inside and re.match(r"^\S", line):
            inside = False
        elif inside:
            match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if match:
                names.add(match.group(1))
    return names


class TestHarnessWiringContracts:

    def test_the_consumer_timing_variable_is_the_one_the_storage_consumer_reads(self):
        harness = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        consumer = (_REPO / "storage-consumer" / "config.py").read_text(encoding="utf-8")
        name = "CONSUMER_TIMING_INTERVAL_SECONDS"
        assert f'storage_environment["{name}"]' in harness
        assert f'os.environ.get("{name}"' in consumer

    def test_every_service_the_harness_starts_exists_in_the_compose_files(self):
        main = _compose_services("docker-compose.yml")
        override = _compose_services("workload-generator/compose.smoke.override.yml")
        sys.path.insert(0, str(_REPO / "workload-generator"))
        try:
            text = (_REPO / "workload-generator" / "run_smoke.py").read_text(encoding="utf-8")
        finally:
            sys.path.remove(str(_REPO / "workload-generator"))
        harness = set(re.findall(r'"([a-z0-9-]+)"', re.search(r"SERVICES: tuple\[str, \.\.\.\] = \((.*?)\)", text).group(1)))
        assert harness == {"kafka", "kafka-init", "postgres", "db-bootstrap", "otel-collector"}
        assert harness <= main, harness - main
        assert override <= main, override - main                 # the override only adjusts services that exist

    def test_the_refresh_service_run_e2e_uses_exists_with_its_profile(self):
        text = (_REPO / "workload-generator" / "run_e2e.py").read_text(encoding="utf-8")
        service = re.search(r'^REFRESH_SERVICE: str = "([^"]+)"', text, re.M).group(1)
        profile = re.search(r'^REFRESH_PROFILE: str = "([^"]+)"', text, re.M).group(1)
        assert service in _compose_services("docker-compose.yml")
        compose = (_REPO / "docker-compose.yml").read_text(encoding="utf-8")
        block = compose[compose.index(f"\n  {service}:"):]
        block = block[:block.index("\n  grafana:")] if "\n  grafana:" in block else block
        assert f'profiles: ["{profile}"]' in block or f"- {profile}" in block

    def test_the_ledger_plan_agreement_is_covered_by_the_bootstrap_contract_tests(self, guarded_smoke):
        # not repeated here: TestLedgerMatchesTheRealBootstrapPlan compares LEDGER_PLAN with build_plan
        assert guarded_smoke.LEDGER_STEPS == len(guarded_smoke.LEDGER_PLAN) == 18


# ---------------------------------------------------------------------------
# B3J-257: opt-in commit batching of the storage consumer (nothing is approved yet)
# ---------------------------------------------------------------------------

REP7_LIKE = "bm-small-r0010-c32-rep7"
REP8_LIKE = "bm-small-r0010-c32-rep8"
REP9_LIKE = "bm-small-r0010-c32-rep9"
REP9_LIMITATION = (
    "SMALL-10 repetition 9 uses the same workload, rate, concurrency, warm-up and offset-commit batching "
    "(100 messages or 1.0 s, consumer timing every 5 s) as repetition 8, which ended VALID under its "
    "original rules and is not reclassified. Repetition 9 differs in instrumentation and rules: it also "
    "records host-side resource observations (storage consumer and stream processor CPU and working set, "
    "host available memory, whole-host CPU and free disk space), it judges Docker container CPU and memory "
    "as aggregates per sampling tick against the recorded Docker NCPU and MemTotal, and inadequate "
    "resource-sampling coverage makes a run INVALID, which repetition 8 did not require. Throughput and "
    "latency may be compared with repetition 8 only with these differences in mind. Repetition 6 ended "
    "STOPPED and repetition 7 ended GENERATOR_BOUND after a Windows Modern Standby transition; neither is a "
    "validated performance baseline.")
APPROVED_IDS = ["bm-smoke-r0005-c32-rep2", "bm-smoke-r0005-c32-rep3", "bm-smoke-r0005-c32-rep4",
                "bm-smoke-r0005-c32-rep5", "bm-small-r0010-c32-rep1", "bm-small-r0010-c32-rep2",
                "bm-small-r0010-c32-rep3", "bm-small-r0010-c32-rep4", "bm-small-r0010-c32-rep5",
                "bm-small-r0010-c32-rep6", "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9"]


@pytest.fixture
def batching_cell(monkeypatch):
    """A cell that a TEST-LOCAL change makes approved for batching; nothing real is registered."""
    cell = _small(repetition=7)
    monkeypatch.setattr(RB, "APPROVED_LIVE_CELLS",
                        {**RB.APPROVED_LIVE_CELLS, cell.benchmark_id: dict(RB._cell_fields(cell))})
    monkeypatch.setattr(RB, "APPROVED_COMMIT_BATCHING", {cell.benchmark_id: (100, 1.0)})
    monkeypatch.setattr(RB, "COMMIT_BATCHING_CELLS", frozenset({cell.benchmark_id}))
    return cell


class TestBatchingIsApprovedOnlyForRep7AndRep8:      # and, since B3J-291, rep9
    def test_the_approval_tables_agree_and_list_only_rep7_rep8_and_rep9(self):
        assert dict(RB.APPROVED_COMMIT_BATCHING) == {REP7_LIKE: (100, 1.0), REP8_LIKE: (100, 1.0),
                                                    REP9_LIKE: (100, 1.0)}
        assert RB.COMMIT_BATCHING_CELLS == frozenset({REP7_LIKE, REP8_LIKE, REP9_LIKE})
        assert (RB.COMMIT_BATCH_MESSAGES, RB.COMMIT_INTERVAL_SECONDS) == (100, 1.0)
        assert RB.DEFAULT_COMMIT_BATCHING == (1, None)
        assert set(RB.APPROVED_COMMIT_BATCHING) <= set(RB.APPROVED_LIVE_CELLS)

    def test_rep7_is_the_only_cell_that_batches(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == sorted(APPROVED_IDS)
        for benchmark_id in APPROVED_IDS:
            expected = (100, 1.0) if benchmark_id in (REP7_LIKE, REP8_LIKE, REP9_LIKE) else (1, None)
            assert RB.commit_batching_for(benchmark_id) == expected, benchmark_id
        assert RB.commit_batching_for("bm-small-r0010-c32-rep10") == (1, None)

    def test_rep7_is_a_timing_diagnostic_and_reps_one_to_six_are_unchanged(self):
        assert RB.DIAGNOSTIC_TIMING_CELLS == frozenset({"bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6",
                                                       REP7_LIKE, REP8_LIKE, REP9_LIKE})
        assert dict(RB.APPROVED_DIAGNOSTIC_INTERVALS) == {"bm-small-r0010-c32-rep5": 5.0, "bm-small-r0010-c32-rep6": 5.0,
                                                          REP7_LIKE: 5.0, REP8_LIKE: 5.0, REP9_LIKE: 5.0}
        assert sorted(RB.COMPARABILITY_REFERENCES) == ["bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6",
                                                       REP7_LIKE, REP8_LIKE, REP9_LIKE]
        assert RB.timing_interval_for(REP7_LIKE) == 5.0
        for n in range(1, 7):
            effective = RB.check_effective_config(_small(repetition=n), LADDER)
            assert effective["consumer_commit_batch_messages"] == 1
            assert effective["consumer_commit_interval_seconds"] is None

    def test_rep7_has_exactly_the_rep6_workload_and_only_the_run_ids_differ(self):
        six, seven = _small(repetition=6), _small(repetition=7)
        assert RB._cell_fields(seven) == {**RB._cell_fields(six), "repetition": 7}
        diff = {k for k, v in six.target().items() if seven.target()[k] != v}
        assert diff == {"repetition", "warmup_run_id", "measured_run_id"}
        assert (seven.requests, seven.rate, seven.concurrency, seven.warmup_requests) == (1000, 10, 32, 300)
        assert seven.target()["planned_spans"] == 7000 and seven.target()["seed"] == 42
        assert dict(RB.APPROVED_LIVE_CELLS[REP7_LIKE]) == {**dict(RB.APPROVED_LIVE_CELLS["bm-small-r0010-c32-rep6"]),
                                                          "repetition": 7}

    def test_rep7_selects_n_100_t_1_and_the_five_second_timing_in_its_effective_config(self):
        effective = RB.check_effective_config(_small(repetition=7), LADDER)
        assert effective["consumer_commit_batch_messages"] == 100 and type(effective["consumer_commit_batch_messages"]) is int
        assert effective["consumer_commit_interval_seconds"] == 1.0 and type(effective["consumer_commit_interval_seconds"]) is float
        assert effective["consumer_timing_interval_seconds"] == 5.0
        rep6 = RB.check_effective_config(_small(repetition=6), LADDER)
        assert {k: (rep6[k], effective[k]) for k in effective if effective[k] != rep6[k]} == {
            "target": (rep6["target"], effective["target"]),
            "consumer_commit_batch_messages": (1, 100), "consumer_commit_interval_seconds": (None, 1.0)}

    def test_rep7_is_authorized_only_with_its_exact_fields(self):
        cell = _small(repetition=7)
        assert RB.is_approved_live_cell(cell)
        assert _authorize_small(cell, authorize=REP7_LIKE, repetition=7) == cell
        for change in (dict(requests=999), dict(rate=5), dict(concurrency=16), dict(warmup_requests=299),
                       dict(level="SMOKE")):
            assert not RB.is_approved_live_cell(dataclasses.replace(cell, **change)), change
        with pytest.raises(RB.BenchmarkError):
            _authorize_small(cell, authorize=REP7_LIKE, repetition=6)
        with pytest.raises(RB.BenchmarkError):
            _authorize_small(cell, authorize="bm-small-r0010-c32-rep6", repetition=7)

    def test_repetitions_nine_and_ten_stay_unapproved(self):
        for n in (10,):
            assert not RB.is_approved_live_cell(_small(repetition=n))
            with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
                RB.check_live_authorization([_small(repetition=n)], authorize=f"bm-small-r0010-c32-rep{n}",
                                            expect_head=HEAD, warmup_requests=300, repetition=n)

    def test_the_cell_specific_limitations_belong_to_rep7_rep8_and_rep9_only(self):
        assert dict(RB.CELL_LIMITATIONS) == {
            REP7_LIKE: ("SMALL-10 repetition 6 used single-message commits on the same nominal 4-CPU configuration "
                        "and ended STOPPED; it is diagnostic context, not a validated performance baseline."),
            REP8_LIKE: ("SMALL-10 repetition 6 used single-message commits and ended STOPPED; repetition 7 used "
                        "batched commits, was interrupted by a Windows Modern Standby transition mid-run and ended "
                        "GENERATOR_BOUND; neither is a validated performance baseline."),
            REP9_LIKE: REP9_LIMITATION}


class TestEffectiveConfigAndApproval:
    def test_a_batching_cell_reports_exactly_the_approved_values(self, batching_cell):
        effective = RB.check_effective_config(batching_cell, LADDER)
        assert effective["consumer_commit_batch_messages"] == 100 and type(effective["consumer_commit_batch_messages"]) is int
        assert effective["consumer_commit_interval_seconds"] == 1.0 and type(effective["consumer_commit_interval_seconds"]) is float

    @pytest.mark.parametrize("approved,derived", [
        ({}, True), ({REP7_LIKE: (100, 1.0)}, False), ({REP7_LIKE: (50, 1.0)}, True),
        ({REP7_LIKE: (100, 2.0)}, True), ({REP7_LIKE: (100, 1)}, True), ({REP7_LIKE: (True, 1.0)}, True)])
    def test_the_independent_literal_and_the_derived_set_must_agree_or_nothing_runs(self, monkeypatch, approved, derived):
        cell = _small(repetition=7)
        monkeypatch.setattr(RB, "APPROVED_LIVE_CELLS", {**RB.APPROVED_LIVE_CELLS, REP7_LIKE: dict(RB._cell_fields(cell))})
        monkeypatch.setattr(RB, "APPROVED_COMMIT_BATCHING", approved)
        monkeypatch.setattr(RB, "COMMIT_BATCHING_CELLS", frozenset({REP7_LIKE}) if derived else frozenset())
        with pytest.raises(RB.BenchmarkError, match="commit batching configuration differs"):
            RB.check_effective_config(cell, LADDER)

    def test_a_batching_literal_for_a_cell_that_is_not_approved_live_is_refused(self, monkeypatch):
        not_approved = "bm-small-r0010-c32-rep10"
        monkeypatch.setattr(RB, "APPROVED_COMMIT_BATCHING", {not_approved: (100, 1.0)})
        monkeypatch.setattr(RB, "COMMIT_BATCHING_CELLS", frozenset({not_approved}))
        with pytest.raises(RB.BenchmarkError, match="commit batching configuration differs"):
            RB.check_effective_config(_small(repetition=6), LADDER)

    def test_changing_the_constants_alone_is_refused(self, batching_cell, monkeypatch):
        monkeypatch.setattr(RB, "COMMIT_BATCH_MESSAGES", 200)
        with pytest.raises(RB.BenchmarkError, match="commit batching configuration differs"):
            RB.check_effective_config(batching_cell, LADDER)

    def test_a_cell_with_the_wrong_effective_values_is_named(self, monkeypatch):
        cell = _small(repetition=6)
        monkeypatch.setattr(RB, "commit_batching_for", lambda benchmark_id: (100, 1.0))
        with pytest.raises(RB.BenchmarkError, match="consumer_commit_batch_messages"):
            RB.check_effective_config(cell, LADDER)

    @pytest.mark.parametrize("batch,interval", [(1, 1.0), (True, None), (1.0, None), (100, None)])
    def test_type_exactness_for_an_ordinary_cell(self, batch, interval):
        effective = RB.effective_config(_small(repetition=6), LADDER)
        effective.update(consumer_commit_batch_messages=batch, consumer_commit_interval_seconds=interval)
        assert RB._commit_batching_problems(effective, "bm-small-r0010-c32-rep6")


class TestMarkerSchemaFour:
    @staticmethod
    def _claim(tmp_path, cell):
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256,
                   "config_path": "c.json", "effective_config": RB.effective_config(cell, LADDER)}
        return json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))

    def test_new_claims_are_schema_four_with_the_batching_fields(self, tmp_path):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        assert record["schema"] == RB.MARKER_SCHEMA == 4
        assert record["effective_config"]["consumer_commit_batch_messages"] == 1
        assert record["effective_config"]["consumer_commit_interval_seconds"] is None
        assert RB.validate_marker(record, cell, tmp_path) == []

    def test_a_batching_cell_is_claimed_with_its_approved_values(self, tmp_path, batching_cell):
        record = self._claim(tmp_path, batching_cell)
        assert record["effective_config"]["consumer_commit_batch_messages"] == 100
        assert record["effective_config"]["consumer_commit_interval_seconds"] == 1.0
        assert RB.validate_marker(record, batching_cell, tmp_path) == []

    @pytest.mark.parametrize("field", ["consumer_commit_batch_messages", "consumer_commit_interval_seconds"])
    def test_a_missing_or_extra_batching_field_is_refused(self, tmp_path, field):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        missing = json.loads(json.dumps(record))
        del missing["effective_config"][field]
        extra = json.loads(json.dumps(record))
        extra["effective_config"]["consumer_commit_extra"] = 1
        assert "effective_config has the wrong fields" in RB.validate_marker(missing, cell, tmp_path)
        assert "effective_config has the wrong fields" in RB.validate_marker(extra, cell, tmp_path)

    @pytest.mark.parametrize("batch,interval", [(100, 1.0), (2, None), (1, 1.0), (True, None), (0, None)])
    def test_a_tampered_value_on_an_ordinary_cell_is_refused(self, tmp_path, batch, interval):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        record["effective_config"].update(consumer_commit_batch_messages=batch, consumer_commit_interval_seconds=interval)
        assert any("consumer_commit" in p for p in RB.validate_marker(record, cell, tmp_path))

    @pytest.mark.parametrize("batch,interval", [(1, None), (50, 1.0), (100, 2.0), (100, 1), (100, None)])
    def test_a_batching_cell_with_other_values_is_refused(self, tmp_path, batching_cell, batch, interval):
        record = self._claim(tmp_path, batching_cell)
        record["effective_config"].update(consumer_commit_batch_messages=batch, consumer_commit_interval_seconds=interval)
        assert any("consumer_commit" in p for p in RB.validate_marker(record, batching_cell, tmp_path))

    def test_claim_run_refuses_a_binding_with_unapproved_batching_and_creates_nothing(self, tmp_path):
        cell = _small(repetition=6)
        effective = RB.effective_config(cell, LADDER)
        effective["consumer_commit_batch_messages"] = 100
        effective["consumer_commit_interval_seconds"] = 1.0
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256,
                   "config_path": "c.json", "effective_config": effective}
        with pytest.raises(RB.BenchmarkError, match="inconsistent"):
            RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        assert not any(tmp_path.rglob("*"))

    @pytest.mark.parametrize("schema", [0, 1, 2, 5, "4", None])
    def test_other_schemas_are_unsupported(self, tmp_path, schema):
        cell = _small(repetition=5)
        record = self._claim(tmp_path, cell)
        record["schema"] = schema
        assert "unsupported schema" in RB.validate_marker(record, cell, tmp_path)


class TestHistoricalSchemaThreeRecords:
    def _legacy(self, tmp_path, cell):
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256,
                   "config_path": "c.json", "effective_config": RB.effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        record["schema"] = 3
        del record["effective_config"]["consumer_commit_batch_messages"]
        del record["effective_config"]["consumer_commit_interval_seconds"]
        return record

    @pytest.mark.parametrize("repetition", [1, 4, 5, 6])
    def test_a_historical_schema_three_record_still_validates_for_its_cell(self, tmp_path, repetition):
        cell = _small(repetition=repetition)
        assert RB.validate_marker(self._legacy(tmp_path, cell), cell, tmp_path) == []
        assert RB.LEGACY_MARKER_SCHEMAS == (3,)

    def test_a_schema_three_record_with_the_new_fields_is_refused(self, tmp_path):
        cell = _small(repetition=5)
        record = self._legacy(tmp_path, cell)
        record["effective_config"]["consumer_commit_batch_messages"] = 1
        assert "effective_config has the wrong fields" in RB.validate_marker(record, cell, tmp_path)

    def test_a_schema_three_record_cannot_describe_a_batching_cell(self, tmp_path, batching_cell):
        record = self._legacy(tmp_path, batching_cell)
        assert any("legacy-schema" in p for p in RB.validate_marker(record, batching_cell, tmp_path))

    def test_validation_never_rewrites_a_record(self, tmp_path):
        cell = _small(repetition=5)
        record = self._legacy(tmp_path, cell)
        before = json.dumps(record, sort_keys=True)
        RB.validate_marker(record, cell, tmp_path)
        assert json.dumps(record, sort_keys=True) == before


class TestExecuteCellConsumerConfiguration:
    def test_an_ordinary_cell_sets_the_globals_explicitly_to_n_equals_one(self, tmp_path):
        smoke = FakeSmoke(tmp_path)
        smoke.CONSUMER_COMMIT_BATCH_MESSAGES, smoke.CONSUMER_COMMIT_INTERVAL_SECONDS = 77, 9.0   # left by an earlier cell
        result, _, clean, _ = _run(tmp_path, smoke=smoke)
        assert clean and smoke.CONSUMER_COMMIT_BATCH_MESSAGES == 1 and smoke.CONSUMER_COMMIT_INTERVAL_SECONDS == 1.0
        assert result["consumer"] == {"commit_batching": {"enabled": False, "batch_messages": 1, "interval_seconds": None},
                                      "timing_diagnostic_interval_seconds": 0.0}
        assert not [x for x in result["limitations"] if "offset commits were batched" in x]

    def test_the_globals_are_reset_between_cells(self, tmp_path, batching_cell):
        smoke = FakeSmoke(tmp_path)
        _run(tmp_path, smoke=smoke, cell=batching_cell)
        assert (smoke.CONSUMER_COMMIT_BATCH_MESSAGES, smoke.CONSUMER_COMMIT_INTERVAL_SECONDS) == (100, 1.0)
        (tmp_path / "next").mkdir()
        _run(tmp_path / "next", smoke=smoke)
        assert (smoke.CONSUMER_COMMIT_BATCH_MESSAGES, smoke.CONSUMER_COMMIT_INTERVAL_SECONDS) == (1, 1.0)

    def test_a_batching_cell_records_its_configured_values_and_the_limitation(self, tmp_path, batching_cell):
        result, _, clean, _ = _run(tmp_path, cell=batching_cell)
        assert clean
        assert result["consumer"]["commit_batching"] == {"enabled": True, "batch_messages": 100, "interval_seconds": 1.0}
        assert "observed" not in result["consumer"]                     # no timing windows: nothing is invented
        assert [x for x in result["limitations"] if "offset commits were batched" in x and "100 messages" in x]
        M.validate_result(result)

    def test_measured_commit_behavior_appears_only_when_timing_windows_were_captured(self, tmp_path, monkeypatch, batching_cell):
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({batching_cell.benchmark_id}))
        result, _, _, _ = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG), cell=batching_cell)
        observed = result["consumer"]["observed"]
        assert observed["windows"] == 2 and observed["commit_calls"] == observed["messages"] > 0
        assert result["consumer"]["timing_diagnostic_interval_seconds"] == 5.0
        assert result["consumer"]["commit_batching"]["batch_messages"] == 100          # configured is not measured
        M.validate_result(result)

    def test_a_timing_cell_whose_log_has_no_windows_has_no_observed_block(self, tmp_path, monkeypatch, batching_cell):
        monkeypatch.setattr(RB, "DIAGNOSTIC_TIMING_CELLS", frozenset({batching_cell.benchmark_id}))
        result, _, _, _ = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text="nothing useful\n"), cell=batching_cell)
        assert "observed" not in result["consumer"]


class TestObservedCommitBehavior:
    @staticmethod
    def _window(messages, commits, elapsed=2.0, commit_ms=10.0, kind="window"):
        return "storage-consumer timing " + json.dumps({
            "kind": kind, "elapsed_s": elapsed, "counters": {"messages": messages, "idle_polls": 0, "inserted": messages, "conflicts": 0},
            "stages": {"kafka_commit": {"count": commits, "total_ms": commit_ms, "mean_ms": 0, "max_ms": 0, "hist": []}}})

    def test_totals_and_means_come_from_the_windows(self):
        observed = RB.observed_commit_behavior([self._window(140, 2, commit_ms=20.0), self._window(70, 1, commit_ms=10.0)])
        assert observed == {"windows": 2, "window_seconds": 4.0, "messages": 210, "commit_calls": 3,
                            "mean_messages_per_commit": 70.0, "mean_seconds_between_commits": 1.3333,
                            "mean_commit_ms": 10.0}
        M.consumer_block_problems({"commit_batching": {"enabled": True, "batch_messages": 100, "interval_seconds": 1.0},
                                   "timing_diagnostic_interval_seconds": 5.0, "observed": observed}) == []

    def test_nothing_to_measure_gives_none_and_a_final_summary_is_not_counted(self):
        assert RB.observed_commit_behavior([]) is None
        assert RB.observed_commit_behavior([self._window(99, 9, kind="final")]) is None

    def test_malformed_windows_are_skipped_not_guessed(self):
        lines = ["storage-consumer timing {broken", self._window(10, 1), "storage-consumer timing []",
                 "storage-consumer timing " + json.dumps({"kind": "window", "elapsed_s": 1})]
        assert RB.observed_commit_behavior(lines)["windows"] == 1

    def test_zero_commits_leave_the_means_null(self):
        observed = RB.observed_commit_behavior([self._window(0, 0)])
        assert observed["commit_calls"] == 0 and observed["mean_messages_per_commit"] is None


class TestReconciliationIsNotWeakened:
    def test_forced_termination_comes_after_every_reconciliation_step(self, tmp_path, batching_cell):
        _, _, clean, smoke = _run(tmp_path, cell=batching_cell)
        calls = smoke.calls
        assert clean
        stop = calls.index("stop_host_processes")
        assert calls.index("run_stage_measured") < calls.index("check_host_processes") < stop
        assert max(i for i, name in enumerate(calls) if name == "psql") < stop
        assert calls.index("check_normal_stack") < stop

    def test_a_failed_measured_stage_is_a_failure_with_batching_too(self, tmp_path, batching_cell):
        result, _, clean, smoke = _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="run_stage_measured"), cell=batching_cell)
        assert result["verdict"] != "VALID" and clean
        assert "stop_host_processes" in smoke.calls and result["consumer"]["commit_batching"]["enabled"] is True

    def test_a_nonzero_final_lag_is_not_reconciled_by_the_forced_stop(self, tmp_path, batching_cell):
        result, _, _, smoke = _run(tmp_path, smoke=FakeSmoke(tmp_path, lag=250), cell=batching_cell)
        assert result["verdict"] != "VALID"
        gate = [g for g in result["integrity"]["gates"] if not g["ok"]]
        assert gate or result["stop"]["reasons"] or result["integrity"]["ok"] is not True

    def test_the_lag_growth_rule_and_its_limit_are_unchanged(self):
        assert M.LAG_GROWTH_SAMPLES == 6 and LADDER["stop_limits"]["lag_growth_samples"] == 6
        assert M.lag_growing([1, 2, 3, 4, 5, 6]) is True
        assert M.lag_growing([5, 90, 40, 170, 20, 100]) is False        # a commit sawtooth is not growth
        assert M.lag_growing([1, 2, 3, 4, 5, None, 7]) is False


class TestRep7Evidence:
    def test_the_result_carries_the_rep7_limitation_and_the_configured_batching(self, tmp_path):
        cell = _small(repetition=7)
        result, _, clean, _ = _run(tmp_path, cell=cell)
        assert clean
        assert result["consumer"]["commit_batching"] == {"enabled": True, "batch_messages": 100, "interval_seconds": 1.0}
        assert result["consumer"]["timing_diagnostic_interval_seconds"] == 5.0
        assert RB.CELL_LIMITATIONS[REP7_LIKE] in result["limitations"]
        assert result["limitations"].count(RB.CELL_LIMITATIONS[REP7_LIKE]) == 1
        assert [x for x in result["limitations"] if "offset commits were batched" in x and "100 messages" in x]
        assert [x for x in result["limitations"] if x.startswith("comparability: diagnostic only")]
        M.validate_result(result)

    def test_observed_commit_behavior_needs_real_timing_windows(self, tmp_path):
        result, _, _, _ = _run(tmp_path, smoke=TimedSmoke(tmp_path, log_text=GOOD_LOG), cell=_small(repetition=7))
        assert result["consumer"]["observed"]["windows"] == 2
        (tmp_path / "again").mkdir()
        bare, _, _, _ = _run(tmp_path / "again", smoke=TimedSmoke(tmp_path / "again", log_text="no windows\n"),
                             cell=_small(repetition=7))
        assert "observed" not in bare["consumer"]

    @pytest.mark.parametrize("repetition", [1, 2, 3, 4, 5, 6])
    def test_no_other_cell_carries_the_limitation_or_batches(self, tmp_path, repetition):
        cell = _small(repetition=repetition)
        result, _, _, _ = _run(tmp_path, cell=cell)
        assert RB.CELL_LIMITATIONS[REP7_LIKE] not in result["limitations"]
        assert result["consumer"]["commit_batching"]["enabled"] is False

    def test_the_marker_for_rep7_is_schema_four_with_the_exact_configuration(self, tmp_path):
        cell = _small(repetition=7)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.check_effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        assert record["schema"] == 4 and record["benchmark_id"] == REP7_LIKE
        effective = record["effective_config"]
        assert (effective["consumer_commit_batch_messages"], effective["consumer_commit_interval_seconds"],
                effective["consumer_timing_interval_seconds"]) == (100, 1.0, 5.0)
        assert effective["target"] == cell.target() and RB.validate_marker(record, cell, tmp_path) == []

    @pytest.mark.parametrize("batch,interval", [(1, None), (50, 1.0), (100, 2.0), (100, None), (True, 1.0)])
    def test_a_marker_with_other_batching_values_is_refused_for_rep7(self, tmp_path, batch, interval):
        cell = _small(repetition=7)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        record["effective_config"].update(consumer_commit_batch_messages=batch, consumer_commit_interval_seconds=interval)
        assert any("consumer_commit" in p for p in RB.validate_marker(record, cell, tmp_path))

    def test_the_lag_growth_rule_is_still_six_samples(self):
        assert M.LAG_GROWTH_SAMPLES == 6 and LADDER["stop_limits"]["lag_growth_samples"] == 6
        assert M.lag_growing([1, 2, 3, 4, 5, 6]) is True and M.lag_growing([1, 2, 3, 4, 5, 5]) is False

    def test_offline_checks_of_the_registration_write_no_marker_or_file(self, tmp_path):
        before = sorted(p.name for p in RB.DEFAULT_OUTPUT.glob("*")) if RB.DEFAULT_OUTPUT.exists() else []
        RB.check_effective_config(_small(repetition=7), LADDER)
        RB.is_approved_live_cell(_small(repetition=7))
        after = sorted(p.name for p in RB.DEFAULT_OUTPUT.glob("*")) if RB.DEFAULT_OUTPUT.exists() else []
        assert before == after and not any(tmp_path.rglob("*"))


# ---------------------------------------------------------------------------
# B3J-267: the Windows keep-awake guard of the live path (fakes only, no real power API)
# ---------------------------------------------------------------------------

def _guard(fake=None, *, windows=True, thread=lambda: 1, reports=None):
    fake = fake or FakeExecutionState()
    sink = [] if reports is None else reports
    return RB.KeepAwake(is_windows=lambda: windows, set_state=fake.set, read_state=fake.read,
                        thread_id=thread, report=sink.append), fake, sink


class TestKeepAwakeGuard:
    def test_the_flags_are_exactly_continuous_system_and_display(self):
        assert (RB.ES_CONTINUOUS, RB.ES_SYSTEM_REQUIRED, RB.ES_DISPLAY_REQUIRED) == (0x80000000, 0x1, 0x2)
        assert RB.KEEP_AWAKE_FLAGS == 0x80000003 and RB.SYSTEM_EXECUTION_STATE_LEVEL == 16

    def test_acquire_and_release_use_the_exact_flags_in_order(self):
        guard, fake, reports = _guard()
        guard.acquire()
        assert guard.held and guard.acquisition == "acquired" and guard.readback == "consistent" and guard.owner == 1
        assert guard.release() is True and not guard.held and reports == []
        assert fake.calls == [("set", 0x80000003), ("read",), ("set", 0x80000000)]
        assert fake.outstanding == 0 and guard.release() is True and len(fake.calls) == 3      # idempotent

    def test_a_zero_return_is_a_failure_whatever_the_aggregate_state_says(self):
        fake = FakeExecutionState()
        fake.refuse_acquire, fake.readback = True, 0x3                    # a consistent aggregate does not rescue it
        guard, _, _ = _guard(fake)
        with pytest.raises(RB.BenchmarkError, match="refused"):
            guard.acquire()
        assert guard.acquisition == "failed" and not guard.held and fake.calls == [("set", 0x80000003)]
        assert guard.release() is True and len(fake.calls) == 1             # nothing held, nothing released

    def test_an_exception_from_the_api_is_a_failure(self):
        fake = FakeExecutionState()
        fake.raise_on_acquire = True
        guard, _, _ = _guard(fake)
        with pytest.raises(RB.BenchmarkError, match="could not be asked"):
            guard.acquire()
        assert guard.acquisition == "failed" and not guard.held

    @pytest.mark.parametrize("state", [0x3, 0x7, 0x43, 0x80000003])
    def test_a_readback_showing_both_bits_is_only_supporting_evidence(self, state):
        fake = FakeExecutionState()
        fake.readback = state
        guard, _, _ = _guard(fake)
        guard.acquire()
        assert guard.readback == "consistent" and guard.acquisition == "acquired"
        assert "cannot attribute" in RB.KeepAwake.__doc__ and "supports, but does" in RB.KeepAwake.__doc__

    @pytest.mark.parametrize("state", [0x0, 0x1, 0x2, 0x40])
    def test_a_readable_state_that_contradicts_the_call_fails_closed_and_releases(self, state):
        fake = FakeExecutionState()
        fake.readback = state
        guard, _, _ = _guard(fake)
        with pytest.raises(RB.BenchmarkError, match="does not show the keep-awake request"):
            guard.acquire()
        assert guard.readback == "inconsistent" and not guard.held and fake.outstanding == 0
        assert fake.calls[-1] == ("set", 0x80000000)

    @pytest.mark.parametrize("mode", ["none", "raise"])
    def test_an_unavailable_readback_is_reported_not_claimed_as_verification(self, mode):
        fake = FakeExecutionState()
        fake.readback = mode
        guard, _, _ = _guard(fake)
        guard.acquire()
        assert guard.acquisition == "acquired" and guard.readback == "unavailable" and guard.held
        assert "read-back unavailable" in guard.describe()

    def test_release_must_come_from_the_acquiring_thread(self):
        current, reports = [1], []
        guard, fake, _ = _guard(thread=lambda: current[0], reports=reports)
        guard.acquire()
        current[0] = 2
        assert guard.release() is False and guard.held and len(fake.calls) == 2           # no call from the wrong thread
        assert reports and "another thread" in reports[0]
        current[0] = 1
        assert guard.release() is True and not guard.held

    def test_a_real_second_thread_cannot_release_the_request(self):
        import threading
        guard = RB.KeepAwake(is_windows=lambda: True, set_state=FakeExecutionState().set,
                             read_state=lambda: 3, report=lambda text: reports.append(text))
        reports: list[str] = []
        guard.acquire()
        outcome = []
        worker = threading.Thread(target=lambda: outcome.append(guard.release()))
        worker.start()
        worker.join()
        assert outcome == [False] and guard.held and guard.owner == threading.get_ident()
        assert guard.release() is True

    @pytest.mark.parametrize("how", ["raises", "zero"])
    def test_a_release_failure_is_reported_and_never_raised(self, how):
        fake = FakeExecutionState()
        guard, _, reports = _guard(fake)
        guard.acquire()
        if how == "zero":
            fake.refuse_release = True
        else:
            fake.set = lambda flags, original=fake.set: (_ for _ in ()).throw(OSError("x")) if flags == RB.ES_CONTINUOUS else original(flags)
            guard._set_state = fake.set
        assert guard.release() is False and guard.held and reports

    def test_acquiring_twice_is_refused(self):
        guard, _, _ = _guard()
        guard.acquire()
        with pytest.raises(RB.BenchmarkError, match="already held"):
            guard.acquire()

    def test_off_windows_nothing_is_called_and_nothing_is_held(self):
        guard, fake, _ = _guard(windows=False)
        guard.acquire()
        assert guard.acquisition == "not_applicable" and guard.readback == "skipped" and not guard.held
        assert guard.release() is True and fake.calls == [] and "not applicable" in guard.describe()

    def test_the_default_guard_uses_the_module_functions_present_when_it_is_built(self, monkeypatch):
        fake = FakeExecutionState()
        monkeypatch.setattr(RB, "_is_windows", lambda: True)
        monkeypatch.setattr(RB, "_windows_set_execution_state", fake.set)
        monkeypatch.setattr(RB, "_windows_read_execution_state", fake.read)
        guard = RB.KeepAwake()
        guard.acquire()
        assert guard.release() is True and fake.calls[0] == ("set", RB.KEEP_AWAKE_FLAGS)

    def test_every_test_runs_with_the_real_power_functions_replaced(self, _power):
        real_set, real_read = _REAL_POWER_FUNCTIONS[:2]
        assert RB._windows_set_execution_state is not real_set and RB._windows_read_execution_state is not real_read
        assert (RB._windows_session_flags, RB._windows_idle_seconds, RB._run_event_query) != _REAL_POWER_FUNCTIONS[2:]
        assert RB._windows_set_execution_state == _power.set and RB._windows_read_execution_state == _power.read
        guard = RB.KeepAwake()
        guard.acquire()
        assert guard.release() is True and _power.calls[0] == ("set", 0x80000003)


class TestKeepAwakeInTheLivePath:
    def test_the_request_is_held_before_the_claim_and_through_the_run(self, live, monkeypatch):
        order = []
        real_claim = RB.claim_run
        monkeypatch.setattr(RB, "claim_run", lambda *a, **k: (order.append(("claim", live.awake.outstanding)),
                                                              real_claim(*a, **k))[1])
        stdout = io.StringIO()
        assert RB.main(list(APPROVED_ARGS), stdout=stdout) == 0
        assert order == [("claim", 1)] and live.held_during_run == 1 and live.awake.outstanding == 0
        assert live.awake.calls == [("set", 0x80000003), ("read",), ("set", 0x80000000)]
        assert "keep-awake: acquired (system and display required); read-back consistent" in stdout.getvalue()

    def test_a_refused_request_stops_everything_before_the_claim(self, live, capsys):
        live.awake.refuse_acquire = True
        assert _live() == 2
        assert "nothing was started" in capsys.readouterr().err and _nothing_created(live)
        assert live.awake.calls == [("set", 0x80000003)] and live.awake.outstanding == 0

    def test_an_api_exception_also_stops_before_the_claim(self, live, capsys):
        live.awake.raise_on_acquire = True
        assert _live() == 2
        assert "nothing was started" in capsys.readouterr().err and _nothing_created(live)

    def test_a_contradicting_readback_stops_before_the_claim_and_leaves_nothing_held(self, live, capsys):
        live.awake.readback = 0
        assert _live() == 2
        assert "nothing was started" in capsys.readouterr().err and _nothing_created(live)
        assert live.awake.outstanding == 0 and live.awake.calls[-1] == ("set", 0x80000000)

    def test_an_unavailable_readback_is_reported_and_the_run_proceeds(self, live):
        live.awake.readback = "none"
        stdout = io.StringIO()
        assert RB.main(list(APPROVED_ARGS), stdout=stdout) == 0 and live.runs == [SMOKE2]
        assert "read-back unavailable" in stdout.getvalue() and live.awake.outstanding == 0

    def test_an_exception_in_the_cell_still_releases_and_keeps_the_ledger(self, live, monkeypatch):
        def broken(cell, ladder, **kw):
            raise RuntimeError("the cell failed")
        monkeypatch.setattr(RB, "run_cell", broken)
        with pytest.raises(RuntimeError, match="the cell failed"):
            _live()
        assert live.awake.outstanding == 0 and live.awake.calls[-1] == ("set", 0x80000000)
        assert (live.canonical / "ledger" / f"{SMOKE2}.started").exists() and (live.canonical / "ACTIVE_RUN").exists()

    def test_a_keyboard_interrupt_releases(self, live, monkeypatch):
        def interrupted(cell, ladder, **kw):
            raise KeyboardInterrupt
        monkeypatch.setattr(RB, "run_cell", interrupted)
        with pytest.raises(KeyboardInterrupt):
            _live()
        assert live.awake.outstanding == 0

    def test_a_failure_to_record_completion_still_releases_and_keeps_its_status(self, live, monkeypatch, capsys):
        monkeypatch.setattr(RB, "finish_run", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
        assert _live() == 1
        assert "could not record completion" in capsys.readouterr().err and live.awake.outstanding == 0

    def test_a_claim_failure_inside_the_guard_releases_it(self, live, monkeypatch, capsys):
        monkeypatch.setattr(RB, "claim_run", lambda *a, **k: (_ for _ in ()).throw(RB.BenchmarkError("no")))
        assert _live() == 2
        assert "nothing was started" in capsys.readouterr().err and live.awake.outstanding == 0
        assert live.awake.calls == [("set", 0x80000003), ("read",), ("set", 0x80000000)]

    def test_a_release_failure_does_not_mask_the_original_exception(self, live, monkeypatch, capsys):
        live.awake.refuse_release = True

        def broken(cell, ladder, **kw):
            raise RuntimeError("the cell failed")
        monkeypatch.setattr(RB, "run_cell", broken)
        with pytest.raises(RuntimeError, match="the cell failed"):
            _live()
        assert "release was refused" in capsys.readouterr().err

    def test_a_release_failure_does_not_change_the_status(self, live, capsys):
        live.awake.refuse_release = True
        assert _live() == 0 and live.runs == [SMOKE2]
        assert "release was refused" in capsys.readouterr().err

    def test_a_second_invocation_is_refused_before_the_guard_and_nothing_leaks(self, live):
        assert _live() == 0 and live.awake.outstanding == 0
        before = list(live.awake.calls)
        assert _live() == 2                                              # prior evidence, refused before any request
        assert live.awake.calls == before and live.awake.outstanding == 0

    def test_pre_authorization_refusals_never_acquire(self, live, monkeypatch, capsys):
        assert _live(["--level", "SMOKE", "--rate", "5", "--repetition", "2", "--warmup-requests", "25",
                      "--live", "--authorize", "bm-smoke-r0005-c32-rep9",
                      "--expect-head", HEAD]) == 2
        monkeypatch.setattr(RB, "LIVE_ENABLED", False)
        assert _live() == 2
        live.git["head"] = "1" * 40
        monkeypatch.setattr(RB, "LIVE_ENABLED", True)
        assert _live() == 2
        assert live.awake.calls == [] and _nothing_created(live)

    def test_plan_only_never_acquires(self, live):
        out = io.StringIO()
        assert RB.main(["--level", "SMOKE", "--rate", "5", "--repetition", "2", "--warmup-requests", "25"],
                       stdout=out) == 0
        assert "PLAN ONLY" in out.getvalue() and live.awake.calls == []

    def test_off_windows_the_live_path_is_unchanged(self, live, monkeypatch):
        monkeypatch.setattr(RB, "_is_windows", lambda: False)
        stdout = io.StringIO()
        assert RB.main(list(APPROVED_ARGS), stdout=stdout) == 0 and live.runs == [SMOKE2]
        assert live.awake.calls == [] and "keep-awake: not applicable (not Windows)" in stdout.getvalue()

    def test_the_guard_changes_neither_the_claim_nor_the_schemas(self, live):
        assert _live() == 0
        record = live.started_during_run
        assert RB.MARKER_SCHEMA == 4 and set(record) == RB._MARKER_KEYS and "keep" not in json.dumps(record)
        assert M.RESULT_KEYS == frozenset({"benchmark_id", "git_sha", "git_dirty", "timestamps", "machine",
                                           "workload", "counts", "metrics", "clock", "integrity", "verdict",
                                           "limitations"})
        assert M.RESULT_OPTIONAL_KEYS == frozenset({"verdict_reasons", "stop", "claims", "consumer", "host"})

    def test_thresholds_are_untouched(self):
        assert M.LAG_GROWTH_SAMPLES == 6 and M.LATE_START_FRACTION == 0.05
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6 and LADDER["stop_limits"]["late_start_fraction"] == 0.05

    def test_repetition_ten_is_still_unregistered(self):
        ten = "bm-small-r0010-c32-rep10"
        assert ten not in RB.APPROVED_LIVE_CELLS and ten not in RB.COMMIT_BATCHING_CELLS
        assert ten not in RB.APPROVED_COMMIT_BATCHING and ten not in RB.DIAGNOSTIC_TIMING_CELLS
        assert ten not in RB.COMPARABILITY_REFERENCES and not RB.is_approved_live_cell(_small(repetition=10))


# ---------------------------------------------------------------------------
# B3J-275: host-interruption diagnostics (fakes only: no real power API, session API or event log)
# ---------------------------------------------------------------------------

from datetime import datetime as _dt, timezone as _tz  # noqa: E402


def _iso7(epoch, fraction="0000000"):
    """An event time as PowerShell's 'o' format writes it: UTC with seven fractional digits."""
    return _dt.fromtimestamp(epoch, tz=_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.") + fraction + "Z"


def _utc(epoch):
    return _dt.fromtimestamp(epoch, tz=_tz.utc)


def _proc(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _events_json(rows, ok=True):
    return json.dumps({"ok": ok, "events": [{"t": t, "id": i, "r": r} for t, i, r in rows]})


class TestSessionState:
    @pytest.mark.parametrize("flags,locked", [(1, False), (0, True)])
    def test_flags_are_read_with_zero_locked_and_one_unlocked(self, flags, locked):
        state = RB.session_state(read_flags=lambda: flags, read_idle=lambda: 7.26)
        assert state == {"flags": flags, "locked": locked, "idle_seconds": 7.26}

    @pytest.mark.parametrize("flags", [None, 2, -1, True, "1", 1.5])
    def test_anything_else_is_unknown_not_a_guess(self, flags):
        state = RB.session_state(read_flags=lambda: flags, read_idle=lambda: 1.0)
        assert state["flags"] is None and state["locked"] is None

    def test_failures_never_raise(self):
        def broken():
            raise OSError("no api")
        assert RB.session_state(read_flags=broken, read_idle=broken) == {"flags": None, "locked": None, "idle_seconds": None}

    @pytest.mark.parametrize("idle", [-1, float("nan"), float("inf"), True, "5"])
    def test_an_implausible_idle_time_is_unknown(self, idle):
        assert RB.session_state(read_flags=lambda: 1, read_idle=lambda: idle)["idle_seconds"] is None

    def test_the_real_reader_uses_the_corrected_offset(self):
        import inspect
        source = inspect.getsource(_REAL_POWER_FUNCTIONS[2])               # the real function, not the test's fake
        assert "unpack_from(\"<i\", raw_bytes, 16)" in source and "level == 1" in source
        assert "offset 16" in source and "SessionState" in source


class TestParsePowerEvents:
    START, END = 1_000_000.0, 1_000_600.0

    def _parse(self, rows, **kw):
        return RB.parse_power_events(_events_json(rows), _utc(self.START), _utc(self.END), **kw)

    def test_events_are_kept_sorted_with_microsecond_utc_times(self):
        events, truncated = self._parse([(_iso7(self.START + 300, "1234567"), 507, "44"), (_iso7(self.START + 10, "5000000"), 506, 12)])
        assert truncated is False
        assert [(e["id"], e["reason"]) for e in events] == [(506, 12), (507, 44)]
        assert events[0]["time_utc"].endswith("Z") and len(events[0]["time_utc"].split(".")[1]) == 7      # 6 digits + Z
        assert events[1]["time_utc"] == _utc(self.START + 300).strftime("%Y-%m-%dT%H:%M:%S.123456Z")

    def test_the_window_is_inclusive_at_both_ends_and_excludes_the_rest(self):
        rows = [(_iso7(self.START - 1), 506, 1), (_iso7(self.START), 506, 2),
                (_iso7(self.END), 507, 3), (_iso7(self.END + 1), 507, 4), (_iso7(self.START - 100), 507, 5)]
        events, _ = self._parse(rows)
        assert [e["reason"] for e in events] == [2, 3]

    def test_the_times_are_utc_whatever_the_local_zone(self, monkeypatch):
        import os
        import time as _time
        monkeypatch.setenv("TZ", "America/Toronto")
        if hasattr(_time, "tzset"):
            _time.tzset()
        events, _ = self._parse([(_iso7(self.START + 5), 506, 12)])
        assert events[0]["time_utc"].startswith(_utc(self.START + 5).strftime("%Y-%m-%dT%H:%M:%S"))

    def test_reason_may_be_missing_or_text(self):
        events, _ = self._parse([(_iso7(self.START + 1), 506, None), (_iso7(self.START + 2), 507, "abc"), (_iso7(self.START + 3), 506, "16777220")])
        assert [e["reason"] for e in events] == [None, None, 16777220]

    def test_a_single_object_is_accepted_as_one_event(self):
        text = json.dumps({"ok": True, "events": {"t": _iso7(self.START + 1), "id": 506, "r": 12}})
        assert RB.parse_power_events(text, _utc(self.START), _utc(self.END))[0][0]["id"] == 506

    def test_no_events_is_a_valid_answer(self):
        assert RB.parse_power_events('{"ok":true,"events":[]}', _utc(self.START), _utc(self.END)) == ([], False)

    def test_events_are_bounded_and_truncation_is_reported(self):
        rows = [(_iso7(self.START + n), 506 if n % 2 == 0 else 507, 1) for n in range(1, 61)]
        events, truncated = self._parse(rows)
        assert len(events) == RB.HOST_MAX_EVENTS == 50 and truncated is True
        assert events[0]["time_utc"] < events[-1]["time_utc"]

    @pytest.mark.parametrize("text", [
        "", "   \n", "not json", "[]", '{"ok":false,"events":[]}', '{"events":[]}', '{"ok":true}',
        '{"ok":true,"events":"x"}', '{"ok":true,"events":[1]}',
        json.dumps({"ok": True, "events": [{"t": "2026-10-16", "id": 506, "r": 1}]}),
        json.dumps({"ok": True, "events": [{"t": "2026-10-16T18:00:00Z", "id": 41, "r": 1}]}),
        json.dumps({"ok": True, "events": [{"t": "2026-10-16T18:00:00Z", "id": True, "r": 1}]}),
        json.dumps({"ok": True, "events": [{"id": 506}]})])
    def test_malformed_output_is_an_error(self, text):
        with pytest.raises(ValueError):
            RB.parse_power_events(text, _utc(self.START), _utc(self.END))

    def test_the_last_line_counts_so_warnings_before_it_are_ignored(self):
        text = "WARNING: something\n" + '{"ok":true,"events":[]}\n'
        assert RB.parse_power_events(text, _utc(self.START), _utc(self.END)) == ([], False)


class TestStandbyEpisodes:
    def _events(self, *rows):
        return [{"time_utc": RB._host_iso(1_000_000.0 + at), "id": identifier, "reason": None} for at, identifier in rows]

    def test_a_matched_entry_and_exit_is_one_episode_with_its_duration(self):
        episodes = RB.pair_standby_episodes(self._events((10, 506), (136.25, 507)))
        assert len(episodes) == 1 and episodes[0]["seconds"] == 126.25
        assert episodes[0]["entered_utc"] and episodes[0]["exited_utc"]

    def test_an_entry_without_an_exit_is_kept_as_a_possible_interruption(self):
        episodes = RB.pair_standby_episodes(self._events((10, 506)))
        assert episodes == [{"entered_utc": RB._host_iso(1_000_010.0), "exited_utc": None, "seconds": None}]

    def test_an_exit_without_an_entry_in_the_window_is_kept(self):
        episodes = RB.pair_standby_episodes(self._events((10, 507)))
        assert episodes == [{"entered_utc": None, "exited_utc": RB._host_iso(1_000_010.0), "seconds": None}]

    def test_two_entries_in_a_row_leave_the_first_unclosed(self):
        episodes = RB.pair_standby_episodes(self._events((10, 506), (20, 506), (50, 507)))
        assert [(e["exited_utc"] is None, e["seconds"]) for e in episodes] == [(True, None), (False, 30.0)]

    def test_several_episodes_stay_in_order(self):
        episodes = RB.pair_standby_episodes(self._events((1, 506), (2, 507), (10, 506), (12, 507), (20, 506)))
        assert [e["seconds"] for e in episodes] == [1.0, 2.0, None]

    def test_no_events_no_episodes(self):
        assert RB.pair_standby_episodes([]) == []


class TestQueryPowerEvents:
    START, END = 1_000_000.0, 1_000_600.0

    def _query(self, run, **kw):
        ticks = iter([0.0, 1.5, 3.0, 4.5])
        return RB.query_power_events(self.START, self.END, run=run, monotonic=lambda: next(ticks), **kw)

    def test_success_without_events_is_ok_and_empty(self):
        block = self._query(lambda script, timeout: _proc('{"ok":true,"events":[]}'))
        assert block["status"] == "ok" and block["error"] is None and block["events"] == [] and block["episodes"] == []
        assert block["query_seconds"] == 1.5 and block["truncated"] is False

    def test_success_with_an_entry_and_an_exit_reports_both_and_the_episode(self):
        rows = [(_iso7(self.START + 100), 506, 12), (_iso7(self.START + 226), 507, 44)]
        block = self._query(lambda script, timeout: _proc(_events_json(rows)))
        assert [e["id"] for e in block["events"]] == [506, 507] and block["episodes"][0]["seconds"] == 126.0
        assert M.host_block_problems({
            "platform": "windows", "keep_awake": {"acquisition": "acquired", "readback": "consistent"},
            "session": {"start": None, "end": None},
            "window": {"start_utc": RB._host_iso(self.START), "end_utc": RB._host_iso(self.END)},
            "power_events": block, "host_interruption_suspected": True}) == []

    def test_an_unmatched_entry_is_still_reported(self):
        block = self._query(lambda script, timeout: _proc(_events_json([(_iso7(self.START + 100), 506, 12)])))
        assert block["status"] == "ok" and block["episodes"] == [
            {"entered_utc": block["events"][0]["time_utc"], "exited_utc": None, "seconds": None}]

    def test_the_script_asks_for_the_utc_window_the_two_ids_and_the_system_log(self):
        seen = []
        self._query(lambda script, timeout: seen.append((script, timeout)) or _proc('{"ok":true,"events":[]}'))
        script, timeout = seen[0]
        assert RB._host_iso(self.START) in script and RB._host_iso(self.END) in script
        assert "Id=506,507" in script and "LogName='System'" in script and "Microsoft-Windows-Kernel-Power" in script
        assert "-MaxEvents 51" in script and "NoMatchingEventsFound" in script and timeout == RB.HOST_QUERY_TIMEOUT_SECONDS
        assert "__" not in script                                              # every placeholder was replaced

    def test_a_timeout_is_a_failed_query_not_an_empty_one(self):
        def slow(script, timeout):
            raise subprocess.TimeoutExpired("powershell", timeout)
        block = self._query(slow)
        assert (block["status"], block["error"], block["events"]) == ("failed", "timeout", [])

    def test_a_missing_executable_is_a_failed_query(self):
        def missing(script, timeout):
            raise FileNotFoundError("powershell")
        assert self._query(missing)["error"] == "tool_missing"

    def test_an_access_failure_is_a_failed_query_with_a_bounded_message(self):
        block = self._query(lambda script, timeout: _proc("", returncode=1, stderr="Get-WinEvent : Attempted to perform an unauthorized operation.\n" + "x" * 500))
        assert block["status"] == "failed" and block["error"].startswith("nonzero_exit:1: Get-WinEvent")
        assert len(block["error"]) <= RB.HOST_ERROR_LIMIT and "\n" not in block["error"]

    @pytest.mark.parametrize("text", ["", "garbage", '{"ok":false}', '{"ok":true,"events":[{"t":"bad","id":506}]}'])
    def test_malformed_output_is_a_failed_query(self, text):
        block = self._query(lambda script, timeout: _proc(text))
        assert block["status"] == "failed" and block["error"].startswith("malformed_output") and block["events"] == []

    def test_oversized_output_is_a_failed_query(self):
        block = self._query(lambda script, timeout: _proc("x" * (RB.HOST_OUTPUT_LIMIT + 1)))
        assert block["error"] == "output_too_large"

    def test_an_unexpected_exception_is_a_failed_query(self):
        def broken(script, timeout):
            raise RuntimeError("boom")
        assert self._query(broken)["error"] == "unexpected:RuntimeError"

    def test_the_default_runner_is_the_module_function_resolved_at_call_time(self, _power):
        block = RB.query_power_events(self.START, self.END)
        assert block["status"] == "ok" and len(_power.query_calls) == 1

    def test_an_end_before_the_start_is_clamped_to_an_empty_window(self):
        seen = []
        RB.query_power_events(self.END, self.START, run=lambda script, timeout: seen.append(script) or _proc('{"ok":true,"events":[]}'))
        assert RB._host_iso(self.END) in seen[0] and RB._host_iso(self.START) not in seen[0]


class TestCollectHostEvidence:
    def _collect(self, **kw):
        defaults = dict(started=1_000_000.0, finished=1_000_600.0, keep_awake={"acquisition": "acquired", "readback": "consistent"},
                        session_start={"flags": 1, "locked": False, "idle_seconds": 4.0})
        defaults.update(kw)
        return RB.collect_host_evidence(**defaults)

    def test_the_block_is_complete_and_valid(self, _power):
        block = self._collect()
        assert M.host_block_problems(block) == []
        assert block["platform"] == "windows" and block["keep_awake"] == {"acquisition": "acquired", "readback": "consistent"}
        assert block["session"]["start"]["locked"] is False and block["session"]["end"] == {"flags": 1, "locked": False, "idle_seconds": 12.5}
        assert block["window"] == {"start_utc": RB._host_iso(1_000_000.0), "end_utc": RB._host_iso(1_000_600.0)}
        assert block["power_events"]["status"] == "ok" and block["host_interruption_suspected"] is False

    def test_off_windows_there_is_no_block_and_nothing_is_read(self, _power, monkeypatch):
        monkeypatch.setattr(RB, "_is_windows", lambda: False)
        before = list(_power.calls)
        assert self._collect() is None and _power.calls == before and _power.query_calls == []

    def test_events_set_the_indicator_true(self, _power):
        _power.query_events = [(_iso7(1_000_100), 506, 12)]
        block = self._collect()
        assert block["host_interruption_suspected"] is True and M.host_block_problems(block) == []

    def test_a_failed_query_sets_the_indicator_to_unknown_not_false(self, _power):
        _power.query_result = lambda script, timeout: _proc("", returncode=1, stderr="denied")
        block = self._collect()
        assert block["power_events"]["status"] == "failed" and block["host_interruption_suspected"] is None
        assert M.host_block_problems(block) == []

    def test_a_query_function_that_raises_is_a_failed_query(self):
        def broken(*args, **kwargs):
            raise RuntimeError("x")
        block = self._collect(query=broken)
        assert block["power_events"]["error"] == "unexpected:RuntimeError" and block["host_interruption_suspected"] is None

    @pytest.mark.parametrize("keep", [None, {}, {"acquisition": "weird", "readback": 5}])
    def test_an_unknown_keep_awake_status_is_recorded_as_unknown(self, keep):
        block = self._collect(keep_awake=keep)
        assert block["keep_awake"] == {"acquisition": "unknown", "readback": "unknown"} and M.host_block_problems(block) == []

    def test_session_end_failures_are_unknown_values(self, _power):
        _power.session_flags = "raise"
        block = self._collect()
        assert block["session"]["end"]["flags"] is None and M.host_block_problems(block) == []

    def test_a_locked_session_is_recorded_as_locked(self, _power):
        _power.session_flags = 0
        assert self._collect()["session"]["end"]["locked"] is True

    def test_finish_before_start_gives_a_zero_length_window(self):
        block = self._collect(started=1_000_100.0, finished=1_000_000.0)
        assert block["window"]["start_utc"] == block["window"]["end_utc"]


class TestHostLimitations:
    def test_none_without_a_block_or_events(self, _power):
        assert RB.host_limitations(None) == []
        assert RB.host_limitations(RB.collect_host_evidence(started=1.0, finished=2.0, keep_awake=None, session_start=None)) == []

    def test_events_give_one_factual_sentence_that_denies_clean_capacity_evidence(self, _power):
        _power.query_events = [(_iso7(1.5), 506, 12), (_iso7(1.9), 507, 44)]
        host = RB.collect_host_evidence(started=1.0, finished=2.0, keep_awake=None, session_start=None)
        text, = RB.host_limitations(host)
        assert "host interruption suspected" in text and "1 Modern Standby entry and 1 exit" in text
        assert "Kernel-Power 506/507" in text and "not clean platform capacity evidence" in text

    def test_a_failed_query_is_stated_and_does_not_claim_a_standby(self, _power):
        _power.query_result = lambda script, timeout: (_ for _ in ()).throw(subprocess.TimeoutExpired("p", 1))
        host = RB.collect_host_evidence(started=1.0, finished=2.0, keep_awake=None, session_start=None)
        text, = RB.host_limitations(host)
        assert "could not be queried (timeout)" in text and "cannot be excluded" in text and "suspected" not in text


class TestHostDiagnosticsInTheCell:
    def test_a_clean_cell_carries_a_valid_host_block_and_an_unchanged_verdict(self, tmp_path, _power):
        result, _, clean, _ = _run(tmp_path)
        assert clean and result["host"]["host_interruption_suspected"] is False
        assert result["host"]["session"]["start"] == {"flags": 1, "locked": False, "idle_seconds": 12.5}
        assert result["verdict"] == "VALID" and result["claims"]["platform_throughput"] is True
        assert not [x for x in result["limitations"] if "host interruption" in x or "host power events" in x]
        M.validate_result(result)

    def test_the_query_happens_after_the_run_and_covers_its_window(self, tmp_path, _power):
        _run(tmp_path)
        script, _ = _power.query_calls[0]
        assert RB._host_iso(5003.0) in script and len(_power.query_calls) == 1

    def test_standby_events_do_not_change_the_verdict_but_withdraw_the_timing_claims(self, tmp_path, _power):
        plain, _, _, _ = _run(tmp_path)
        _power.query_events = [(_iso7(5003), 506, 12), (_iso7(5003), 507, 44)]
        (tmp_path / "again").mkdir()
        hit, _, clean, _ = _run(tmp_path / "again")
        assert clean and hit["verdict"] == plain["verdict"] == "VALID"
        assert hit["host"]["host_interruption_suspected"] is True
        assert hit["claims"]["platform_throughput"] is False and hit["claims"]["persistence_latency"] is False
        assert hit["claims"]["span_volume_handled"] is True and hit["claims"]["no_loss_for_this_run"] is True
        assert [x for x in hit["limitations"] if "host interruption suspected" in x]
        for key in ("metrics", "counts", "integrity", "stop", "verdict_reasons", "clock", "workload"):
            assert hit[key] == plain[key], key
        M.validate_result(hit)

    def test_an_unmatched_entry_counts_as_a_possible_interruption(self, tmp_path, _power):
        _power.query_events = [(_iso7(5003), 506, 12)]
        result, _, _, _ = _run(tmp_path)
        assert result["host"]["host_interruption_suspected"] is True and result["host"]["power_events"]["episodes"][0]["exited_utc"] is None

    def test_a_failed_query_is_reported_and_leaves_claims_and_cleanup_alone(self, tmp_path, _power):
        _power.query_result = lambda script, timeout: _proc("", returncode=1, stderr="Access is denied")
        result, path, clean, smoke = _run(tmp_path)
        assert clean and path.is_file() and "cleanup" in smoke.calls
        assert result["host"]["host_interruption_suspected"] is None and result["host"]["power_events"]["status"] == "failed"
        assert result["claims"]["platform_throughput"] is True and result["verdict"] == "VALID"
        assert [x for x in result["limitations"] if "host power events could not be queried" in x]

    def test_a_query_timeout_does_not_block_or_skip_cleanup(self, tmp_path, _power):
        _power.query_result = lambda script, timeout: (_ for _ in ()).throw(subprocess.TimeoutExpired("p", timeout))
        result, path, clean, smoke = _run(tmp_path)
        assert clean and result["host"]["power_events"]["error"] == "timeout" and path.is_file()

    def test_a_failure_assembling_the_block_cannot_prevent_the_result_or_the_cleanup(self, tmp_path, monkeypatch):
        def broken(**kw):
            raise RuntimeError("diagnostics bug")
        monkeypatch.setattr(RB, "collect_host_evidence", broken)
        result, path, clean, _ = _run(tmp_path)
        assert clean and path.is_file() and "host" not in result and result["verdict"] == "VALID"
        assert [x for x in result["limitations"] if "host diagnostics could not be assembled (RuntimeError)" in x]
        M.validate_result(result)

    def test_a_cell_that_fails_still_gets_a_host_block_and_its_failure_verdict(self, tmp_path, _power):
        result, _, clean, smoke = _run(tmp_path, smoke=FakeSmoke(tmp_path, fail="run_stage_measured"))
        assert result["verdict"] != "VALID" and "host" in result and clean
        assert "cleanup" in smoke.calls

    def test_off_windows_the_result_has_no_host_block_and_no_windows_call(self, tmp_path, _power, monkeypatch):
        monkeypatch.setattr(RB, "_is_windows", lambda: False)
        result, _, clean, _ = _run(tmp_path)
        assert clean and "host" not in result and _power.query_calls == [] and ("flags",) not in _power.calls
        assert set(result) == (M.RESULT_KEYS | M.RESULT_OPTIONAL_KEYS) - {"host"}

    def test_thresholds_and_approvals_are_untouched(self):
        assert M.LAG_GROWTH_SAMPLES == 6 and M.LATE_START_FRACTION == 0.05
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6 and LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert "bm-small-r0010-c32-rep10" not in RB.APPROVED_LIVE_CELLS and "bm-small-r0010-c32-rep10" not in RB.COMMIT_BATCHING_CELLS
        assert list(RB.APPROVED_LIVE_CELLS)[-1] == "bm-small-r0010-c32-rep9" and len(RB.APPROVED_LIVE_CELLS) == 13
        assert RB.commit_batching_for("bm-small-r0010-c32-rep7") == (100, 1.0) and RB.commit_batching_for("bm-small-r0010-c32-rep6") == (1, None)


class TestHostDiagnosticsInTheLivePath:
    def test_main_hands_the_keep_awake_status_to_the_cell(self, live, monkeypatch):
        seen = {}
        original = RB.run_cell

        def spy(cell, ladder, **kw):
            seen.update(kw)
            return original(cell, ladder, **kw)
        monkeypatch.setattr(RB, "run_cell", spy)
        assert _live() == 0
        assert seen["keep_awake"] == {"acquisition": "acquired", "readback": "consistent"}

    def test_an_unavailable_readback_is_passed_on_as_such(self, live, monkeypatch):
        live.awake.readback = "none"
        seen = {}
        original = RB.run_cell
        monkeypatch.setattr(RB, "run_cell", lambda cell, ladder, **kw: (seen.update(kw), original(cell, ladder, **kw))[1])
        assert _live() == 0 and seen["keep_awake"]["readback"] == "unavailable"

    def test_the_guard_lifecycle_is_unchanged(self, live):
        assert _live() == 0
        sets = [call for call in live.awake.calls if call[0] == "set"]
        assert sets == [("set", 0x80000003), ("set", 0x80000000)] and live.awake.outstanding == 0


# ---------------------------------------------------------------------------
# B3J-277: SMALL-10 repetition 8 (the N=100 diagnostic, second attempt)
# ---------------------------------------------------------------------------

REP8_LIMITATION = ("SMALL-10 repetition 6 used single-message commits and ended STOPPED; repetition 7 used batched "
                   "commits, was interrupted by a Windows Modern Standby transition mid-run and ended GENERATOR_BOUND; "
                   "neither is a validated performance baseline.")

#: The approvals of repetitions 1-7 as they stand: rep8 must not touch any of them.
_EARLIER_SMALL = {n: {"level": "SMALL", "requests": 1000, "rate": 10, "concurrency": 32, "repetition": n,
                      "warmup_requests": 300} for n in range(1, 8)}


class TestRep8Registration:
    def test_rep8_is_the_only_newly_approved_cell_and_the_ids_are_exact(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == sorted(APPROVED_IDS) and len(RB.APPROVED_LIVE_CELLS) == 13
        assert "bm-small-r0010-c32-rep8" in APPROVED_IDS and APPROVED_IDS.count("bm-small-r0010-c32-rep8") == 1
        assert list(RB.APPROVED_LIVE_CELLS).index(REP8_LIKE) == len(RB.APPROVED_LIVE_CELLS) - 2   # rep9 follows it

    def test_all_seven_structures_carry_rep8_with_the_rep7_values(self):
        assert dict(RB.APPROVED_LIVE_CELLS[REP8_LIKE]) == {**dict(RB.APPROVED_LIVE_CELLS[REP7_LIKE]), "repetition": 8}
        assert dict(RB.APPROVED_DIAGNOSTIC_INTERVALS)[REP8_LIKE] == dict(RB.APPROVED_DIAGNOSTIC_INTERVALS)[REP7_LIKE] == 5.0
        assert dict(RB.APPROVED_COMMIT_BATCHING)[REP8_LIKE] == dict(RB.APPROVED_COMMIT_BATCHING)[REP7_LIKE] == (100, 1.0)
        assert REP8_LIKE in RB.COMMIT_BATCHING_CELLS and REP8_LIKE in RB.DIAGNOSTIC_TIMING_CELLS
        assert dict(RB.COMPARABILITY_REFERENCES[REP8_LIKE]) == dict(RB.COMPARABILITY_REFERENCES[REP7_LIKE])
        assert RB.CELL_LIMITATIONS[REP8_LIKE] == REP8_LIMITATION

    def test_repetitions_one_to_seven_keep_their_exact_approvals(self):
        for n, fields in _EARLIER_SMALL.items():
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-small-r0010-c32-rep{n}"]) == fields, n
        assert dict(RB.APPROVED_COMMIT_BATCHING)[REP7_LIKE] == (100, 1.0)
        for n in range(1, 7):
            assert RB.commit_batching_for(f"bm-small-r0010-c32-rep{n}") == (1, None)
            assert f"bm-small-r0010-c32-rep{n}" not in RB.COMMIT_BATCHING_CELLS
        assert RB.DIAGNOSTIC_TIMING_CELLS == frozenset({"bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6",
                                                        REP7_LIKE, REP8_LIKE, REP9_LIKE})
        assert RB.CELL_LIMITATIONS[REP7_LIKE].startswith("SMALL-10 repetition 6 used single-message commits on the same")

    @pytest.mark.parametrize("n", [10])
    def test_repetition_ten_stays_refused(self, n):
        cell = _small(repetition=n)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
            RB.check_live_authorization([cell], authorize=f"bm-small-r0010-c32-rep{n}", expect_head=HEAD,
                                        warmup_requests=300, repetition=n)

    def test_rep8_has_the_registered_workload(self):
        cell = _small(repetition=8)
        target = cell.target()
        assert RB.is_approved_live_cell(cell) and cell.benchmark_id == REP8_LIKE
        assert (cell.level, cell.requests, cell.rate, cell.concurrency, cell.warmup_requests, cell.seed) == (
            "SMALL", 1000, 10, 32, 300, 42)
        assert target["planned_spans"] == 7000 and target["scenario"] == "normal" and target["measured_seconds"] == 100.0
        assert (target["warmup_run_id"], target["measured_run_id"]) == ("b-small-r0010-c32-w8", "b-small-r0010-c32-m8")
        seven = _small(repetition=7).target()
        assert {k for k, v in target.items() if seven[k] != v} == {"repetition", "warmup_run_id", "measured_run_id"}

    def test_rep8_selects_n_100_t_1_and_five_second_timing(self):
        effective = RB.check_effective_config(_small(repetition=8), LADDER)
        assert (effective["consumer_commit_batch_messages"], effective["consumer_commit_interval_seconds"],
                effective["consumer_timing_interval_seconds"]) == (100, 1.0, 5.0)
        assert type(effective["consumer_commit_batch_messages"]) is int and type(effective["consumer_commit_interval_seconds"]) is float
        rep7 = RB.check_effective_config(_small(repetition=7), LADDER)
        assert {k for k in effective if effective[k] != rep7[k]} == {"target"}

    def test_rep8_is_authorized_only_with_its_exact_selectors(self):
        cell = _small(repetition=8)
        assert _authorize_small(cell, authorize=REP8_LIKE, repetition=8) == cell
        for authorize, repetition in ((REP7_LIKE, 8), (REP8_LIKE, 7), ("bm-small-r0010-c32-rep9", 8)):
            with pytest.raises(RB.BenchmarkError):
                _authorize_small(cell, authorize=authorize, repetition=repetition)
        for change in (dict(requests=999), dict(rate=5), dict(concurrency=16), dict(warmup_requests=299), dict(level="SMOKE")):
            assert not RB.is_approved_live_cell(dataclasses.replace(cell, **change)), change

    def test_the_rep8_limitation_belongs_to_rep8_only(self, tmp_path):
        result, _, clean, _ = _run(tmp_path, cell=_small(repetition=8))
        assert clean and result["limitations"].count(REP8_LIMITATION) == 1
        assert RB.CELL_LIMITATIONS[REP7_LIKE] not in result["limitations"]
        assert result["consumer"]["commit_batching"] == {"enabled": True, "batch_messages": 100, "interval_seconds": 1.0}
        assert result["consumer"]["timing_diagnostic_interval_seconds"] == 5.0
        M.validate_result(result)
        for n in (1, 2, 3, 4, 5, 6, 7):
            (tmp_path / f"c{n}").mkdir()
            other, _, _, _ = _run(tmp_path / f"c{n}", cell=_small(repetition=n))
            assert REP8_LIMITATION not in other["limitations"], n

    def test_the_rep8_claim_marker_is_schema_four_with_the_exact_configuration(self, tmp_path):
        cell = _small(repetition=8)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.check_effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        assert record["schema"] == RB.MARKER_SCHEMA == 4 and record["benchmark_id"] == REP8_LIKE
        effective = record["effective_config"]
        assert (effective["consumer_commit_batch_messages"], effective["consumer_commit_interval_seconds"],
                effective["consumer_timing_interval_seconds"]) == (100, 1.0, 5.0)
        assert effective["target"] == cell.target() and RB.validate_marker(record, cell, tmp_path) == []

    @pytest.mark.parametrize("batch,interval", [(1, None), (50, 1.0), (100, 2.0), (100, None), (True, 1.0)])
    def test_a_rep8_marker_with_other_batching_values_is_refused(self, tmp_path, batch, interval):
        cell = _small(repetition=8)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        record["effective_config"].update(consumer_commit_batch_messages=batch, consumer_commit_interval_seconds=interval)
        assert any("consumer_commit" in p for p in RB.validate_marker(record, cell, tmp_path))

    def test_the_independent_tables_must_still_agree_for_rep8(self, monkeypatch):
        monkeypatch.setattr(RB, "COMMIT_BATCHING_CELLS", frozenset({REP7_LIKE}))
        with pytest.raises(RB.BenchmarkError, match="commit batching configuration differs"):
            RB.check_effective_config(_small(repetition=8), LADDER)

    def test_safety_controls_are_unchanged(self):
        assert M.LAG_GROWTH_SAMPLES == 6 and M.LATE_START_FRACTION == 0.05
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6 and LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert (LADDER["defaults"]["drain_limit_seconds"], LADDER["defaults"]["settle_seconds"],
                LADDER["defaults"]["cell_budget_seconds"]) == (120, 6, 3600)
        assert RB.KEEP_AWAKE_FLAGS == 0x80000003 and RB.MARKER_SCHEMA == 4
        assert M.RESULT_OPTIONAL_KEYS == frozenset({"verdict_reasons", "stop", "claims", "consumer", "host"})

    def test_checking_the_registration_creates_no_claim_or_ledger_entry(self, tmp_path):
        ledger = RB.DEFAULT_OUTPUT / "ledger"
        before = sorted(p.name for p in ledger.glob("*")) if ledger.exists() else []
        RB.check_effective_config(_small(repetition=8), LADDER)
        RB.is_approved_live_cell(_small(repetition=8))
        after = sorted(p.name for p in ledger.glob("*")) if ledger.exists() else []
        assert before == after and not any(tmp_path.rglob("*"))


# ---------------------------------------------------------------------------
# B3J-283: host-resource observations (benchmark-owned processes, host memory/CPU, free disk)
# ---------------------------------------------------------------------------

_REAL_HOST_API = RB.WindowsHostResourceApi
SECOND = RB.FILETIME_TICKS_PER_SECOND


class _RealHostApiBlocked(AssertionError):
    """A test constructed the real Windows host-resource API."""


@pytest.fixture(autouse=True)
def _no_real_host_api(monkeypatch):
    """No test may reach a real Windows host-resource call: constructing the real API fails."""
    def refuse(*args, **kwargs):
        raise _RealHostApiBlocked("the real WindowsHostResourceApi is blocked in the tests")
    monkeypatch.setattr(RB, "WindowsHostResourceApi", refuse)


class FakePopen:
    def __init__(self, pid, alive=True):
        self.pid, self.alive = pid, alive

    def poll(self):
        return None if self.alive else 1


class FakeHostApi:
    """A stand-in for the Windows calls.  `procs` maps pid -> dict(parent, created, per_call, ws, peak,
    active, deny).  CPU ticks advance by `per_call` at every process_times call."""

    def __init__(self, procs, *, idle_step=600, kernel_step=1000, user_step=0, memory=None):
        self.procs = {pid: {"parent": 1, "created": 1000, "ticks": 0, "per_call": 0, "ws": 50_000_000,
                            "peak": 60_000_000, "active": True, "deny": False, **values}
                      for pid, values in procs.items()}
        self.handles: dict[int, int] = {}
        self.opened: list[int] = []
        self.closed: list[int] = []
        self.calls: list[str] = []
        self.fail: dict[str, Exception] = {}
        self.system = [0, 0, 0]
        self.steps = (idle_step, kernel_step, user_step)
        self.memory_values = list(memory) if memory is not None else None
        self._next = 5000

    def _maybe_fail(self, name):
        self.calls.append(name)
        if name in self.fail:
            raise self.fail[name]

    def open_process(self, pid):
        self._maybe_fail("open_process")
        if pid not in self.procs or self.procs[pid]["deny"]:
            raise OSError(5, "access denied")
        self._next += 1
        self.handles[self._next] = pid
        self.opened.append(pid)
        return self._next

    def close(self, handle):
        self._maybe_fail("close")
        self.closed.append(self.handles[handle])
        del self.handles[handle]

    def process_times(self, handle):
        self._maybe_fail("process_times")
        proc = self.procs[self.handles[handle]]
        proc["ticks"] += proc["per_call"]
        return proc["created"], proc["ticks"]

    def is_active(self, handle):
        self._maybe_fail("is_active")
        return self.procs[self.handles[handle]]["active"]

    def working_set(self, handle):
        self._maybe_fail("working_set")
        proc = self.procs[self.handles[handle]]
        return proc["ws"], proc["peak"]

    def process_table(self):
        self._maybe_fail("process_table")
        return [(pid, values["parent"]) for pid, values in self.procs.items()]

    def system_times(self):
        self._maybe_fail("system_times")
        self.system = [a + b for a, b in zip(self.system, self.steps)]
        return tuple(self.system)

    def memory(self):
        self._maybe_fail("memory")
        if self.memory_values is None:
            return 4_000_000_000, 16_000_000_000
        return self.memory_values.pop(0), 16_000_000_000


def _tree_api(changes=None):
    """storage-consumer: launcher 100 -> interpreter 101; stream-processor: launcher 200 -> interpreter
    201; unrelated processes (an MVP-like 300 -> 301) that must never be touched."""
    procs = {100: {"parent": 1, "created": 1000, "per_call": 0},
             101: {"parent": 100, "created": 1001, "per_call": 5 * SECOND, "ws": 80_000_000, "peak": 90_000_000},
             200: {"parent": 1, "created": 1002, "per_call": 0},
             201: {"parent": 200, "created": 1003, "per_call": 2 * SECOND, "ws": 120_000_000, "peak": 130_000_000},
             300: {"parent": 1, "created": 900, "per_call": SECOND},
             301: {"parent": 300, "created": 901, "per_call": SECOND}}
    for pid, values in (changes or {}).items():
        procs[pid] = {**procs[pid], **values}
    return FakeHostApi(procs)


def _owned():
    return {"storage-consumer": FakePopen(100), "stream-processor": FakePopen(200)}


class _Ticker:
    def __init__(self, step=10.0):
        self.now, self.step = -step, step

    def __call__(self):
        self.now += self.step
        return self.now


def _collector(api, processes=None, disk=None, clock=None):
    return RB.HostResourceCollector(_owned() if processes is None else processes, api=api,
                                    disk_free=disk or (lambda: 500 * GB), disk_volume="C:\\",
                                    clock=clock or _Ticker())


class SyncHostSampler(RB.HostResourceSampler):
    """Synchronous like FakeSampler: samples at the planned times, no thread."""

    def __init__(self, collector, interval, plan=(0.0, 10.0), stop_error=None):
        super().__init__(collector, interval)
        self.plan, self.stop_error, self.stops, self.started = list(plan), stop_error, 0, False

    def _take(self, at):
        try:
            self.samples.append((at, self._sample()))
        except Exception as exc:
            self.samples.append((at, None))
            self.errors.append((at, str(exc)))

    def start(self):
        self.started = True
        for at in self.plan[:-1]:
            self._take(at)

    def stop(self, timeout=30.0):
        self.stops += 1
        if self.stops == 1:
            self._take(self.plan[-1])
        if self.stop_error is not None:
            raise self.stop_error
        self.collector.close()


def _host_factory(api, *, plan=(0.0, 10.0, 20.0), disk=None, stop_error=None, built=None, clock=None):
    def factory(*, processes, disk_free, interval):
        sampler = SyncHostSampler(RB.HostResourceCollector(
            processes, api=api, disk_free=disk or disk_free, disk_volume="C:\\", clock=clock or _Ticker()),
            interval, plan=plan, stop_error=stop_error)
        sampler.collector.open()
        if built is not None:
            built.append(sampler)
        return sampler
    return factory


def _run_host(tmp_path, factory, *, owned=None, smoke=None, cell=None, disk=500 * GB):
    smoke = smoke or FakeSmoke(tmp_path)
    smoke.RUN.processes = _owned() if owned is None else owned
    e2e = FakeE2E(smoke)
    ticks = iter(range(10 ** 6))
    result, path, clean = REAL_EXECUTE_CELL(
        cell or _cell(), LADDER, smoke=smoke, e2e=e2e, expect_head=None, output_dir=tmp_path / "results",
        disk_free=lambda: disk, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
        sampler_factory=FakeSampler, host_resources=factory)
    return result, path, clean, smoke


class TestHostProcessIdentity:
    def test_cpu_is_the_tick_delta_over_the_wall_time_and_the_first_sample_has_none(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        rows = [collector.sample()["processes"]["storage-consumer"] for _ in range(3)]
        assert rows[0]["cpu_percent"] is None
        assert rows[1]["cpu_percent"] == pytest.approx(50.0)       # 5 s of CPU in 10 s
        assert rows[2]["cpu_percent"] == pytest.approx(50.0)
        assert all(r["status"] == "ok" for r in rows)

    def test_zero_duration_and_a_backwards_counter_give_no_value_never_zero(self):
        api = _tree_api()
        collector = _collector(api, clock=lambda: 7.0)             # time never advances
        collector.open()
        collector.sample()
        row = collector.sample()["processes"]["storage-consumer"]
        assert row["cpu_percent"] is None and row["working_set_bytes"] == 80_000_000
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        collector.sample()
        api.procs[101]["ticks"] = 0                                 # the counter went backwards
        api.procs[101]["per_call"] = 0
        assert collector.sample()["processes"]["storage-consumer"]["cpu_percent"] is None

    def test_working_set_and_peak_are_read_as_bytes(self):
        collector = _collector(_tree_api())
        collector.open()
        row = collector.sample()["processes"]
        assert (row["storage-consumer"]["working_set_bytes"], row["storage-consumer"]["peak_working_set_bytes"]) == (80_000_000, 90_000_000)
        assert (row["stream-processor"]["working_set_bytes"], row["stream-processor"]["peak_working_set_bytes"]) == (120_000_000, 130_000_000)

    def test_the_launcher_and_the_interpreter_are_separate_entries_never_summed(self):
        api = _tree_api({100: {"ws": 5_000_000, "peak": 6_000_000}})
        collector = _collector(api)
        collector.open()
        row = collector.sample()["processes"]
        assert collector.keys == ["stream-processor", "stream-processor:launcher",
                                  "storage-consumer", "storage-consumer:launcher"]
        assert row["storage-consumer"]["working_set_bytes"] == 80_000_000          # the child alone
        assert row["storage-consumer:launcher"]["working_set_bytes"] == 5_000_000  # the launcher alone
        assert collector.errors == {}

    def test_a_process_without_a_child_is_its_own_entry_and_has_no_launcher(self):
        api = FakeHostApi({100: {"parent": 1, "per_call": SECOND}})
        collector = _collector(api, processes={"storage-consumer": FakePopen(100)})
        collector.open()
        assert collector.keys == ["storage-consumer"]

    def test_only_the_owned_trees_are_ever_opened(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        for _ in range(3):
            collector.sample()
        collector.close()
        assert sorted(set(api.opened)) == [100, 101, 200, 201]
        assert 300 not in api.opened and 301 not in api.opened
        assert api.calls.count("process_table") == 1                  # read once, to follow parent links

    def test_other_names_in_the_process_table_of_the_run_are_ignored(self):
        api = _tree_api()
        owned = {**_owned(), "something-else": FakePopen(300)}
        collector = _collector(api, processes=owned)
        collector.open()
        assert 300 not in api.opened and "something-else" not in collector.keys

    def test_a_child_older_than_its_parent_is_a_reused_id_and_is_not_followed(self):
        api = _tree_api({101: {"created": 500}})                   # created before the launcher (1000)
        collector = _collector(api)
        collector.open()
        assert "storage-consumer:launcher" not in collector.keys and "storage-consumer" in collector.keys
        assert 101 in api.opened and 101 in api.closed               # opened to check, closed again
        assert collector.sample()["processes"]["storage-consumer"]["working_set_bytes"] == 50_000_000   # the launcher

    def test_a_changed_creation_time_is_never_reported_as_the_process(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        collector.sample()
        api.procs[101]["created"] = 999_999                          # another process behind the handle
        snapshot = collector.sample()
        row = snapshot["processes"]["storage-consumer"]
        assert row["status"] == "unavailable" and row["working_set_bytes"] is None and row["cpu_percent"] is None
        assert "identity:changed" in snapshot["errors"]
        again = collector.sample()["processes"]["storage-consumer"]
        assert again["status"] == "unavailable" and again["working_set_bytes"] is None

    def test_an_exited_process_is_exited_with_no_values_and_is_not_read_again(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        collector.sample()
        api.procs[101]["active"] = False
        reads = api.calls.count("working_set")
        row = collector.sample()["processes"]["storage-consumer"]
        assert row == {"status": "exited", "cpu_percent": None, "working_set_bytes": None,
                       "peak_working_set_bytes": None}
        collector.sample()
        assert api.calls.count("working_set") == reads + 6          # only the other three were read, twice

    def test_a_popen_that_has_already_exited_is_exited_and_never_opened(self):
        api = _tree_api()
        collector = _collector(api, processes={"storage-consumer": FakePopen(100, alive=False)})
        collector.open()
        assert api.opened == [] and collector.sample()["processes"]["storage-consumer"]["status"] == "exited"

    def test_a_process_that_cannot_be_opened_is_unavailable_at_every_sample(self):
        api = _tree_api({100: {"deny": True}})
        collector = _collector(api)
        collector.open()
        row = collector.sample()["processes"]
        assert row["storage-consumer"]["status"] == "unavailable"
        assert row["storage-consumer"]["working_set_bytes"] is None and row["storage-consumer"]["cpu_percent"] is None
        assert row["stream-processor"]["status"] == "ok"             # the other role is unaffected
        assert any(label.startswith("open:") for label in collector.errors)

    def test_a_read_that_fails_is_unavailable_and_labelled_without_the_message(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        api.fail["working_set"] = OSError(5, "secret message text")
        snapshot = collector.sample()
        assert snapshot["processes"]["storage-consumer"]["working_set_bytes"] is None
        assert all("secret" not in label for label in snapshot["errors"] + list(collector.errors))
        assert all(len(label) <= RB.HOST_ERROR_LABEL_LIMIT for label in collector.errors)

    def test_every_handle_is_closed_and_closing_twice_is_harmless(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        collector.sample()
        assert api.handles                                           # retained while sampling
        collector.close()
        collector.close()
        assert api.handles == {} and sorted(api.closed) == sorted(api.opened)

    def test_a_handle_that_fails_to_close_is_noted_and_the_rest_still_close(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        api.fail["close"] = OSError(6, "invalid handle")
        collector.close()                                            # must not raise
        assert any(label.startswith("close:") for label in collector.errors)

    def test_a_failed_identification_closes_the_handle_it_opened(self):
        api = _tree_api()
        api.fail["process_times"] = OSError(5, "denied")
        collector = _collector(api)
        collector.open()
        assert api.handles == {} and sorted(api.closed) == sorted(api.opened)
        assert collector.sample()["processes"]["storage-consumer"]["status"] == "unavailable"

    def test_the_process_table_failing_still_samples_the_launcher_alone(self):
        api = _tree_api()
        api.fail["process_table"] = OSError(5, "denied")
        collector = _collector(api)
        collector.open()
        assert collector.keys == ["stream-processor", "storage-consumer"]
        assert collector.sample()["processes"]["storage-consumer"]["working_set_bytes"] == 50_000_000
        assert any(label.startswith("table:") for label in collector.errors)

    def test_the_tree_walk_is_bounded(self):
        procs = {100: {"parent": 1}}
        procs.update({101 + i: {"parent": 100, "created": 1001 + i} for i in range(40)})
        api = FakeHostApi(procs)
        collector = _collector(api, processes={"storage-consumer": FakePopen(100)})
        collector.open()
        assert len(set(api.opened)) <= RB.HOST_TREE_LIMIT + 1
        assert len(api.handles) == len(collector.keys)               # everything else was closed again


class TestHostMachineSamples:
    def test_whole_host_cpu_is_busy_over_total_between_samples(self):
        collector = _collector(_tree_api())                          # idle +600, kernel (incl. idle) +1000
        collector.open()
        snapshots = [collector.sample() for _ in range(3)]
        assert snapshots[0]["host_cpu_percent"] is None
        assert snapshots[1]["host_cpu_percent"] == pytest.approx(40.0)
        assert snapshots[2]["host_cpu_percent"] == pytest.approx(40.0)

    def test_user_time_counts_as_busy_and_kernel_time_includes_idle(self):
        api = FakeHostApi({}, idle_step=100, kernel_step=300, user_step=700)     # busy = (300-100)+700 of 1000
        collector = _collector(api, processes={})
        collector.open()
        collector.sample()
        assert collector.sample()["host_cpu_percent"] == pytest.approx(90.0)

    @pytest.mark.parametrize("steps", [(0, 0, 0), (2000, 1000, 0), (-10, 1000, 0)])
    def test_an_impossible_or_empty_interval_is_no_value(self, steps):
        api = FakeHostApi({}, idle_step=steps[0], kernel_step=steps[1], user_step=steps[2])
        collector = _collector(api, processes={})
        collector.open()
        collector.sample()
        assert collector.sample()["host_cpu_percent"] is None

    def test_available_memory_and_disk_are_read_each_sample(self):
        free = iter([300 * GB, 250 * GB, 280 * GB])
        api = FakeHostApi({}, memory=[5_000, 3_000, 4_000])
        collector = _collector(api, processes={}, disk=lambda: next(free))
        collector.open()
        snapshots = [collector.sample() for _ in range(3)]
        assert [s["memory_available_bytes"] for s in snapshots] == [5_000, 3_000, 4_000]
        assert [s["disk_free_bytes"] for s in snapshots] == [300 * GB, 250 * GB, 280 * GB]
        assert snapshots[0]["memory_total_bytes"] == 16_000_000_000

    def test_available_memory_above_the_total_is_no_value(self):
        api = FakeHostApi({}, memory=[20_000_000_000])
        collector = _collector(api, processes={})
        collector.open()
        assert collector.sample()["memory_available_bytes"] is None

    def test_each_part_fails_on_its_own_and_is_none_never_zero(self):
        api = _tree_api()
        api.fail.update(system_times=OSError(5, "x"), memory=OSError(5, "x"))
        collector = _collector(api, disk=lambda: (_ for _ in ()).throw(RuntimeError("disk")))
        collector.open()
        snapshot = collector.sample()
        assert snapshot["host_cpu_percent"] is None and snapshot["memory_available_bytes"] is None
        assert snapshot["disk_free_bytes"] is None
        assert snapshot["processes"]["storage-consumer"]["working_set_bytes"] == 80_000_000
        assert len(snapshot["errors"]) == 3 and "disk:RuntimeError" in snapshot["errors"]

    def test_a_negative_or_boolean_disk_value_is_no_value(self):
        for bad in (-1, True, None, "1"):
            collector = _collector(FakeHostApi({}), processes={}, disk=lambda bad=bad: bad)
            collector.open()
            assert collector.sample()["disk_free_bytes"] is None

    def test_error_kinds_are_bounded(self):
        api = FakeHostApi({})
        collector = _collector(api, processes={})
        collector.open()
        for i in range(30):
            collector._note_label(f"kind-{i}")
        assert len(collector.errors) <= RB.HOST_ERROR_KINDS + 1 and collector.errors["other"] >= 22


class TestHostSamplerLifecycle:
    def test_stop_raises_when_the_thread_does_not_stop_and_leaves_the_handles_open(self):
        import threading
        release = threading.Event()
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        real_sample = collector.sample

        def blocking():
            release.wait(5)
            return real_sample()
        sampler = RB.HostResourceSampler(collector, 0.01)
        sampler._sample = blocking
        sampler.start()
        try:
            with pytest.raises(RB.BenchmarkError, match="did not stop"):
                sampler.stop(timeout=0.05)
            assert api.handles                                        # not closed under a running thread
        finally:
            release.set()
        sampler.stop(timeout=5)
        assert api.handles == {}

    def test_a_sampler_that_stops_closes_every_handle(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        sampler = RB.HostResourceSampler(collector, 0.01)
        sampler.start()
        sampler.stop(timeout=5)
        assert api.handles == {} and len(sampler.samples) >= 1

    def test_stopping_a_sampler_that_never_started_is_harmless(self):
        api = _tree_api()
        collector = _collector(api)
        collector.open()
        RB.HostResourceSampler(collector, 1.0).stop()
        assert api.handles == {}

    def test_the_factory_builds_nothing_off_windows(self, monkeypatch):
        monkeypatch.setattr(RB, "_is_windows", lambda: False)
        assert RB.make_host_resource_sampler(processes=_owned(), disk_free=lambda: 1, interval=10,
                                             disk_volume="C:\\") is None

    def test_the_default_factory_would_use_the_real_api_which_the_tests_block(self):
        with pytest.raises(_RealHostApiBlocked):
            RB.make_host_resource_sampler(processes=_owned(), disk_free=lambda: 1, interval=10, disk_volume="C:\\")

    def test_the_factory_closes_its_handles_when_identification_raises(self):
        class Boom(FakeHostApi):
            def open_process(self, pid):
                if pid == 101:
                    raise KeyboardInterrupt
                return super().open_process(pid)

        api = Boom({100: {"parent": 1}, 101: {"parent": 100, "created": 1001}})
        with pytest.raises(KeyboardInterrupt):
            RB.make_host_resource_sampler(processes={"storage-consumer": FakePopen(100)}, disk_free=lambda: 1,
                                          interval=10, disk_volume="C:\\", api=api)
        assert api.handles == {}

    def test_the_real_api_requests_only_query_limited_access_and_closes_what_it_opens(self):
        import inspect
        source = inspect.getsource(_REAL_HOST_API)
        assert RB.PROCESS_QUERY_LIMITED_INFORMATION == 0x1000
        assert "PROCESS_QUERY_LIMITED_INFORMATION" in source
        for forbidden in ("PROCESS_ALL_ACCESS", "PROCESS_TERMINATE", "TerminateProcess", "OpenProcessToken",
                          "AdjustTokenPrivileges", "SeDebug", "SetPriorityClass", "SuspendThread"):
            assert forbidden not in source, forbidden
        assert "CloseHandle(snapshot)" in source and "finally" in source

    def test_the_live_disk_helpers_use_the_harnesss_volume(self, monkeypatch):
        import shutil
        seen = []
        monkeypatch.setattr(shutil, "disk_usage", lambda path: seen.append(path) or SimpleNamespace(free=123))
        assert RB._live_disk_volume() == (RB.REPO.anchor or "/")
        assert RB._live_disk_free() == 123 and seen == [RB.REPO.anchor or "/"]

    def test_run_cell_hands_the_live_helpers_to_the_cell_body(self):
        import inspect
        source = inspect.getsource(RB.run_cell)
        assert "disk_free=_live_disk_free" in source and "make_host_resource_sampler(" in source
        assert "disk_volume=_live_disk_volume()" in source


class TestHostResourcesInTheCell:
    def _result(self, tmp_path, **kwargs):
        api = kwargs.pop("api", None) or _tree_api()
        built = []
        factory = _host_factory(api, built=built, **kwargs)
        result, path, clean, smoke = _run_host(tmp_path, factory)
        return result, path, clean, smoke, api, built

    def test_the_metrics_are_recorded_under_resources_and_validate(self, tmp_path):
        result, path, clean, _, api, built = self._result(tmp_path)
        assert clean and result["verdict"] == "VALID"
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))
        resources = result["metrics"]["resources"]
        cpu = resources["host_process_cpu_percent_series"]
        assert sorted(cpu) == ["storage-consumer", "storage-consumer:launcher", "stream-processor",
                               "stream-processor:launcher"]
        assert cpu["storage-consumer"]["value"] == [50.0, 50.0] and cpu["stream-processor"]["value"] == [20.0, 20.0]
        assert resources["host_process_cpu_percent_max"]["storage-consumer"]["value"] == 50.0
        assert resources["host_process_cpu_percent_series_times_s"]["storage-consumer"]["value"] == [10.0, 20.0]
        assert resources["host_process_working_set_bytes_max"]["stream-processor"]["value"] == 120_000_000
        assert resources["host_process_peak_working_set_bytes"]["storage-consumer"]["value"] == 90_000_000
        assert resources["host_cpu_percent_series"]["host"]["value"] == [40.0, 40.0]
        assert resources["host_memory_available_bytes_min"]["host"]["value"] == 4_000_000_000
        assert resources["disk_free_bytes_min"]["C:\\"]["value"] == 500 * GB
        assert api.handles == {} and built[0].stops == 2             # stopped by the cell, then by the cleanup

    def test_the_docker_metrics_are_unchanged_and_separate(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        plain = _run(tmp_path / "a")[0]["metrics"]["resources"]
        with_host = self._result(tmp_path / "b")[0]["metrics"]["resources"]
        for name in plain:
            assert with_host[name] == plain[name], name
        added = set(with_host) - set(plain)
        assert added and all(n.startswith(("host_", "disk_free_bytes")) for n in added)
        assert "host_process_cpu_percent_max" not in plain

    def test_a_cell_without_a_host_sampler_has_exactly_the_old_shape(self, tmp_path):
        result = _run(tmp_path)[0]
        assert not [n for n in result["metrics"]["resources"] if n.startswith(("host_", "disk_free_bytes"))]
        assert not [t for t in result["limitations"] if "host resource" in t]
        M.validate_result(result)

    def test_coverage_counts_attempts_failures_and_the_window(self, tmp_path):
        result, _, _, _, _, _ = self._result(tmp_path)
        coverage = result["metrics"]["resources"]["host_sampling_coverage"]
        assert coverage["samples_attempted"]["value"] == 3 and coverage["samples_failed"]["value"] == 0
        assert (coverage["first_sample_s"]["value"], coverage["last_sample_s"]["value"]) == (0.0, 20.0)
        assert coverage["interval_seconds"]["value"] == 10.0
        assert coverage["process_samples_available"]["storage-consumer"]["value"] == 3
        assert coverage["process_samples_exited"]["storage-consumer"]["value"] == 0
        assert coverage["host_cpu_samples_available"]["value"] == 2        # the first sample has no delta
        assert coverage["disk_samples_available"]["value"] == 3
        assert coverage["collection_errors"]["value"] == 0

    def test_an_exited_process_is_counted_and_its_series_stops(self, tmp_path):
        class Exiting(FakeHostApi):
            def system_times(self):                                  # once per sample, after the processes
                result = super().system_times()
                self.procs[101]["active"] = False
                return result

        base = _tree_api()
        api = Exiting({pid: dict(values) for pid, values in base.procs.items()})
        result = self._result(tmp_path, api=api)[0]
        resources = result["metrics"]["resources"]
        coverage = resources["host_sampling_coverage"]
        assert coverage["process_samples_available"]["storage-consumer"]["value"] == 1
        assert coverage["process_samples_exited"]["storage-consumer"]["value"] == 2
        assert coverage["process_samples_available"]["stream-processor"]["value"] == 3
        series = resources["host_process_working_set_bytes_series"]["storage-consumer"]["value"]
        assert series == [80_000_000] and 0 not in series

    def test_failed_reads_are_unavailable_in_the_series_and_named_in_the_limitations(self, tmp_path):
        api = _tree_api()
        api.fail["memory"] = OSError(5, "x")
        result = self._result(tmp_path, api=api)[0]
        resources = result["metrics"]["resources"]
        assert resources["host_memory_available_bytes_series"]["all"]["kind"] == "NOT_MEASURED"
        assert resources["host_memory_available_bytes_min"]["all"]["value"] is None
        assert resources["host_sampling_coverage"]["collection_errors"]["value"] == 3
        text = [t for t in result["limitations"] if "failed reads" in t]
        assert len(text) == 1 and "memory:OSError" in text[0] and "never as 0" in text[0]

    def test_the_limitation_states_the_difference_in_coverage_and_the_unmeasured_load(self, tmp_path):
        result = self._result(tmp_path)[0]
        line = [t for t in result["limitations"] if t.startswith("host resource observations were sampled")]
        assert len(line) == 1
        assert "every 10 s" in line[0] and "Docker container metrics" in line[0]
        assert "recorded Docker resources only" in line[0] and "effect was not measured" in line[0]

    def test_the_disk_minimum_follows_the_sampled_values_and_the_volume_is_named(self, tmp_path):
        free = iter([300 * GB, 250 * GB, 280 * GB])
        result = self._result(tmp_path, disk=lambda: next(free))[0]
        disk = result["metrics"]["resources"]["disk_free_bytes_series"]["C:\\"]["value"]
        assert disk == [300 * GB, 250 * GB, 280 * GB]
        assert result["metrics"]["resources"]["disk_free_bytes_min"]["C:\\"]["value"] == 250 * GB
        assert "'C:\\\\'" in result["metrics"]["resources"]["disk_free_bytes_min"]["C:\\"]["method"]

    def test_the_host_memory_minimum_is_the_smallest_sample(self, tmp_path):
        api = _tree_api()
        api.memory_values = [5_000, 3_000, 4_000]
        result = self._result(tmp_path, api=api)[0]
        assert result["metrics"]["resources"]["host_memory_available_bytes_min"]["host"]["value"] == 3_000

    def test_a_failing_factory_leaves_the_cell_valid_and_says_so(self, tmp_path):
        def factory(**kwargs):
            raise RuntimeError("no api")
        result, _, clean, _ = _run_host(tmp_path, factory)
        assert clean and result["verdict"] == "VALID"
        assert "host resource sampling was not started: RuntimeError" in result["limitations"]
        assert not [n for n in result["metrics"]["resources"] if n.startswith("host_")]

    def test_a_factory_returning_none_changes_nothing(self, tmp_path):
        result, _, clean, _ = _run_host(tmp_path, lambda **kwargs: None)
        assert clean and not [t for t in result["limitations"] if "host resource" in t]

    def test_a_sampler_whose_start_fails_is_still_stopped_and_closed(self, tmp_path):
        api = _tree_api()
        built = []

        class Failing(SyncHostSampler):
            def start(self):
                raise RuntimeError("boom")

        def factory(*, processes, disk_free, interval):
            sampler = Failing(RB.HostResourceCollector(processes, api=api, disk_free=disk_free,
                                                       disk_volume="C:\\", clock=_Ticker()), interval)
            sampler.collector.open()
            built.append(sampler)
            return sampler
        result, _, clean, _ = _run_host(tmp_path, factory)
        assert clean and result["verdict"] == "VALID" and api.handles == {}
        assert "host resource sampling was not started: RuntimeError" in result["limitations"]

    def test_mid_run_sample_failures_are_kept_as_failed_samples(self, tmp_path, monkeypatch):
        calls = {"n": 0}
        real = RB.HostResourceCollector.sample

        def flaky(self):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("sampler bug")
            return real(self)
        monkeypatch.setattr(RB.HostResourceCollector, "sample", flaky)
        result = self._result(tmp_path)[0]
        coverage = result["metrics"]["resources"]["host_sampling_coverage"]
        assert coverage["samples_attempted"]["value"] == 3 and coverage["samples_failed"]["value"] == 1
        assert result["verdict"] == "VALID"

    def test_a_sampler_stop_failure_is_reported_and_the_cleanup_is_not_verified(self, tmp_path):
        built = []
        factory = _host_factory(_tree_api(), stop_error=RB.BenchmarkError("did not stop"), built=built)
        result, _, clean, smoke = _run_host(tmp_path, factory)
        assert clean is False                                       # never silently verified
        assert any("host resource sampler stop problem: BenchmarkError: did not stop" in t
                   for t in result["limitations"])
        assert any("cleanup step samplers failed" in t for t in result["limitations"])
        assert built[0].stops == 2 and "cleanup" in smoke.calls     # the rest of the cleanup still ran
        assert "stop_host_processes" in smoke.calls

    def test_the_stage_samples_are_not_lost_when_the_stop_fails(self, tmp_path):
        factory = _host_factory(_tree_api(), stop_error=RuntimeError("x"))
        result = _run_host(tmp_path, factory)[0]
        assert result["metrics"]["resources"]["host_sampling_coverage"]["samples_attempted"]["value"] == 3

    def test_the_verdict_and_stop_rules_do_not_change_with_host_samples(self, tmp_path):
        api = _tree_api()
        api.memory_values = [1, 1, 1]                                # almost no host memory left
        stats = "proj-pg-1|1.0%|950MiB / 1000MiB"                    # a container above 90% of its limit
        for name in "abc":
            (tmp_path / name).mkdir()
        plain = _run(tmp_path / "a", smoke=FakeSmoke(tmp_path / "a", stats=stats))[0]
        hosted = _run_host(tmp_path / "b", _host_factory(api), smoke=FakeSmoke(tmp_path / "b", stats=stats))[0]
        assert plain["verdict"] == hosted["verdict"] == "STOPPED"
        assert plain["stop"] == hosted["stop"] and plain["claims"] == hosted["claims"]
        clean_api = _tree_api()
        clean_api.memory_values = [1, 1, 1]
        calm = _run_host(tmp_path / "c", _host_factory(clean_api))[0]
        assert calm["verdict"] == "VALID" and calm["stop"]["reasons"] == []        # host memory never stops a run

    def test_host_cpu_never_feeds_the_cpu_saturation_rule(self, tmp_path):
        api = FakeHostApi({100: {"parent": 1}}, idle_step=0, kernel_step=1000, user_step=0)   # 100% busy host
        result = _run_host(tmp_path, _host_factory(api), owned={"storage-consumer": FakePopen(100)})[0]
        assert result["verdict"] == "VALID" and result["stop"]["reasons"] == []

    def test_the_existing_resource_stop_function_is_unchanged(self):
        import inspect
        assert list(inspect.signature(M.resource_stops).parameters) == [
            "memory", "disk_free_bytes", "projected_need_bytes", "cpu_percent", "memory_fraction",
            "disk_free_min_bytes", "disk_projection_factor", "cpu_saturation_percent", "cpu_saturation_seconds"]
        assert M.resource_stops(memory=[M.MemorySample("c", 95, 100)], disk_free_bytes=100 * GB) \
            == ("c memory 95.0% of its limit > 90%",)

    def test_the_host_sampler_is_not_one_of_the_indexed_samplers(self, tmp_path):
        built = []
        FakeSampler.instances.clear()
        _run_host(tmp_path, _host_factory(_tree_api(), built=built))
        assert all(not isinstance(i, RB.HostResourceSampler) for i in FakeSampler.instances)
        assert len(FakeSampler.instances) >= 2 and len(built) == 1

    def test_the_cell_order_of_harness_calls_is_unchanged(self, tmp_path):
        smoke = _run_host(tmp_path, _host_factory(_tree_api()))[3]
        assert smoke.calls == ORDER


class TestRep9AndRep8StayUntouched:
    def test_rep10_is_not_registered_anywhere(self):
        rep10 = "bm-small-r0010-c32-rep10"
        for table in (RB.APPROVED_LIVE_CELLS, RB.APPROVED_COMMIT_BATCHING, RB.APPROVED_DIAGNOSTIC_INTERVALS,
                      RB.COMPARABILITY_REFERENCES, RB.CELL_LIMITATIONS):
            assert rep10 not in table
        assert rep10 not in RB.COMMIT_BATCHING_CELLS and rep10 not in RB.DIAGNOSTIC_TIMING_CELLS
        assert len(RB.APPROVED_LIVE_CELLS) == 13 and list(RB.APPROVED_LIVE_CELLS)[-1] == "bm-small-r0010-c32-rep9"

    def test_rep8_limitation_and_approvals_have_no_host_resource_text(self):
        assert "host resource" not in RB.CELL_LIMITATIONS["bm-small-r0010-c32-rep8"]

    def test_the_recorded_rep8_evidence_still_has_its_hashes_when_it_is_present(self):
        import hashlib
        base = Path(tempfile.gettempdir()) / "agentops-benchmarks"
        done = base / "ledger" / "bm-small-r0010-c32-rep8.done"
        if not done.is_file():
            pytest.skip("the rep8 evidence is not on this machine")
        record = json.loads(done.read_text(encoding="utf-8"))
        result = Path(record["result_path"])
        assert hashlib.sha256(result.read_bytes()).hexdigest() == record["result_sha256"]
        M.validate_result(json.loads(result.read_text(encoding="utf-8")))     # still valid under the new checks
        assert "host_sampling_coverage" not in json.loads(result.read_text(encoding="utf-8"))["metrics"]["resources"]


# ---------------------------------------------------------------------------
# B3J-287: the Docker resource rules inside one cell (window from the sampler, gate, verdicts)
# ---------------------------------------------------------------------------

class ScriptedStatsSmoke(FakeSmoke):
    """A FakeSmoke whose `docker stats` answers follow a script: a string, or an Exception to raise.  The
    last entry repeats."""

    def __init__(self, tmp, script, **kwargs):
        super().__init__(tmp, **kwargs)
        self.script = list(script)

    def checked(self, command, **kwargs):
        if command[:2] == ["docker", "stats"]:
            self.commands.append(list(command))
            self._step("docker_stats")
            item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
            if isinstance(item, Exception):
                raise item
            return item
        return super().checked(command, **kwargs)


def _planned_sampler(times, stop_s):
    """A synchronous sampler that takes its samples at the planned times and reports a window, like the real
    PeriodicSampler does after stop()."""
    made = []

    class Planned:
        def __init__(self, sample, interval):
            self.sample, self.samples, self.errors, self.stopped_at = sample, [], [], None
            made.append(self)

        @property
        def window(self):
            return None if self.stopped_at is None else (0.0, self.stopped_at)

        def start(self):
            for at in times:
                try:
                    self.samples.append((float(at), self.sample()))
                except Exception as exc:
                    self.samples.append((float(at), None))
                    self.errors.append((float(at), str(exc)))

        def stop(self):
            if self.stopped_at is None:
                self.stopped_at = float(stop_s)
    Planned.made = made
    return Planned


_ADEQUATE_TIMES = [10.0 * i for i in range(13)]
STATS_OK = "proj-kafka-1|50.0%|100MiB / 100GiB\nproj-pg-1|10.0%|50MiB / 100GiB"


def _run_planned(tmp_path, *, times=_ADEQUATE_TIMES, stop_s=125.0, script=(STATS_OK,), cell=None):
    smoke = ScriptedStatsSmoke(tmp_path, script)
    e2e = FakeE2E(smoke)
    ticks = iter(range(10 ** 6))
    factory = _planned_sampler(times, stop_s)
    result, path, clean = REAL_EXECUTE_CELL(
        cell or _cell(), LADDER, smoke=smoke, e2e=e2e, expect_head=None, output_dir=tmp_path / "results",
        disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
        sampler_factory=factory)
    return result, path, clean, smoke, factory


def _gate_of(result):
    return [g for g in result["integrity"]["gates"] if g["name"] == "docker resource coverage"]


class TestDockerResourceRulesInTheCell:
    def test_an_adequately_sampled_cell_is_valid_and_the_window_is_the_samplers(self, tmp_path):
        result, path, clean, smoke, factory = _run_planned(tmp_path)
        assert clean and result["verdict"] == "VALID"
        assert [c for c in smoke.calls if c != "docker_stats"] == [c for c in ORDER if c != "docker_stats"]
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))
        gate, = _gate_of(result)
        assert gate["ok"] is True
        coverage = result["metrics"]["resources"]["docker_resource_coverage"]
        assert coverage["window_seconds"]["value"] == 125.0                  # the sampler's stop, not 120 (the last sample)
        assert coverage["expected_containers"]["value"] == 2                 # compose ps -q listed two containers
        assert coverage["ncpu"]["value"] == 8 and coverage["vm_memory_bytes"]["value"] == 8 * GB   # from docker info
        assert result["metrics"]["resources"]["docker_vm_cpu_percent_max"]["benchmark-containers"]["value"] == 7.5
        assert any("differ from SMALL-10 repetition 8" in t for t in result["limitations"])

    def test_the_docker_metrics_that_existed_before_are_unchanged(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        old = _run(tmp_path / "a", smoke=FakeSmoke(tmp_path / "a", stats=STATS_OK))[0]["metrics"]["resources"]
        new = _run_planned(tmp_path / "b")[0]["metrics"]["resources"]
        assert set(old) <= set(new) and set(new) - set(old) >= {"docker_vm_cpu_percent_max", "docker_resource_coverage"}
        for container, leaf in old["cpu_percent_max"].items():
            assert new["cpu_percent_max"][container]["value"] == leaf["value"]
        for container, leaf in old["memory_peak_bytes"].items():
            assert new["memory_peak_bytes"][container]["value"] == leaf["value"]

    def test_a_cell_with_the_old_fake_sampler_has_no_window_and_keeps_the_old_rules(self, tmp_path):
        result = _run(tmp_path)[0]
        assert _gate_of(result) == [] and len(result["integrity"]["gates"]) == 12
        assert not [n for n in result["metrics"]["resources"] if n.startswith("docker_")]

    def test_too_few_ticks_make_the_cell_invalid_but_its_cleanup_and_ledger_rules_are_untouched(self, tmp_path):
        result, path, clean, smoke, _ = _run_planned(tmp_path, times=[0.0, 10.0, 20.0], stop_s=125.0)
        assert clean is True and result["verdict"] == "INVALID"
        assert "fewer than 5" in _gate_of(result)[0]["evidence"]
        assert smoke.calls[-3:] == ["stop_host_processes", "remove_profile_resources", "cleanup"]
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    def test_docker_stats_failing_every_time_is_invalid_not_zero(self, tmp_path):
        result = _run_planned(tmp_path, script=[RuntimeError("docker stats failed")])[0]
        assert result["verdict"] == "INVALID"
        resources = result["metrics"]["resources"]
        assert resources["docker_vm_cpu_percent_series"]["all"]["kind"] == "NOT_MEASURED"
        assert resources["docker_resource_coverage"]["ticks_failed"]["value"] == 13

    def test_one_failed_docker_stats_call_is_tolerated(self, tmp_path):
        script = [STATS_OK] * 4 + [RuntimeError("blip")] + [STATS_OK]
        result = _run_planned(tmp_path, script=script)[0]
        assert result["verdict"] == "VALID"
        assert result["metrics"]["resources"]["docker_resource_coverage"]["ticks_failed"]["value"] == 1

    def test_a_tick_with_a_missing_container_is_incomplete(self, tmp_path):
        script = [STATS_OK] * 4 + ["proj-kafka-1|50.0%|100MiB / 100GiB"] + [STATS_OK]
        result = _run_planned(tmp_path, script=script)[0]
        assert result["verdict"] == "VALID"
        coverage = result["metrics"]["resources"]["docker_resource_coverage"]
        assert coverage["cpu_ticks_usable"]["value"] == 12 and coverage["memory_ticks_lower_bound_only"]["value"] == 1

    def test_a_sampler_that_stopped_early_is_invalid(self, tmp_path):
        result = _run_planned(tmp_path, times=[0.0, 10.0, 20.0, 30.0, 40.0, 50.0], stop_s=125.0)[0]
        assert result["verdict"] == "INVALID"

    def test_sustained_docker_cpu_saturation_is_stopped_and_still_cleans_up(self, tmp_path):
        hot = "proj-kafka-1|790.0%|100MiB / 100GiB\nproj-pg-1|10.0%|50MiB / 100GiB"        # 800 / 8 CPUs = 100 %
        result, _, clean, smoke, _ = _run_planned(tmp_path, script=[hot])
        assert clean and result["verdict"] == "STOPPED" and _gate_of(result)[0]["ok"] is True
        assert result["stop"]["reasons"] == ["Docker container CPU at or above 99.5% of 8 CPUs for 60 s"]
        assert smoke.calls[-1] == "cleanup"

    def test_a_per_container_cpu_over_one_core_alone_is_not_saturation(self, tmp_path):
        busy_kafka = "proj-kafka-1|390.0%|100MiB / 100GiB\nproj-pg-1|1.0%|50MiB / 100GiB"    # 391 / 8 = 48.9 % of the VM
        assert _run_planned(tmp_path, script=[busy_kafka])[0]["verdict"] == "VALID"

    def test_aggregate_memory_over_the_vm_is_stopped_where_the_per_container_check_is_silent(self, tmp_path):
        heavy = "proj-kafka-1|1.0%|4GiB / 100GiB\nproj-pg-1|1.0%|3.5GiB / 100GiB"       # 7.5 GiB of 8 GiB
        result = _run_planned(tmp_path, script=[heavy])[0]
        assert result["verdict"] == "STOPPED"
        assert [r for r in result["stop"]["reasons"] if r.startswith("Docker containers memory")]
        assert not [r for r in result["stop"]["reasons"] if "of its limit" in r]

    def test_the_resource_checks_run_after_the_measured_stage_only(self, tmp_path):
        result, _, _, smoke, _ = _run_planned(tmp_path)
        assert smoke.calls.index("run_stage_measured") < smoke.calls.index("psql")
        assert any("judged only after the measured run" in t for t in result["limitations"])
        assert "resource and lag stops are judged after the measured run; a running stage is never interrupted" \
            in result["limitations"]

    def test_the_samplers_still_stop_before_the_database_is_read_and_the_window_comes_from_the_first_stop(self, tmp_path):
        result, _, _, _, factory = _run_planned(tmp_path, stop_s=140.0)
        assert [s.stopped_at for s in factory.made] == [140.0, 140.0]
        assert result["metrics"]["resources"]["docker_resource_coverage"]["window_seconds"]["value"] == 140.0

    def test_keep_awake_host_interruption_and_the_host_sampler_are_unaffected(self, tmp_path):
        smoke = ScriptedStatsSmoke(tmp_path, [STATS_OK])
        smoke.RUN.processes = _owned()
        ticks = iter(range(10 ** 6))
        result, _, clean = REAL_EXECUTE_CELL(
            _cell(), LADDER, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None, output_dir=tmp_path / "results",
            disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
            sampler_factory=_planned_sampler(_ADEQUATE_TIMES, 125.0),
            host_resources=_host_factory(_tree_api()), keep_awake={"acquisition": "acquired", "readback": "consistent"})
        assert clean and result["verdict"] == "VALID"
        assert result["host"]["keep_awake"] == {"acquisition": "acquired", "readback": "consistent"}
        resources = result["metrics"]["resources"]
        assert "host_sampling_coverage" in resources and "docker_resource_coverage" in resources
        M.validate_result(result)


class TestPeriodicSamplerRealWindow:
    def test_a_real_thread_sampler_reports_its_window_after_stop(self):
        sampler = RB.PeriodicSampler(lambda: 1, 0.01)
        sampler.start()
        sampler.stop(timeout=5)
        window = sampler.window
        assert window is not None and window[0] == 0.0 and window[1] >= 0.0
        assert sampler.samples and all(at <= window[1] + 1.0 for at, _ in sampler.samples)

    def test_rep10_is_still_unregistered(self):
        assert "bm-small-r0010-c32-rep10" not in RB.APPROVED_LIVE_CELLS and len(RB.APPROVED_LIVE_CELLS) == 13


# ---------------------------------------------------------------------------
# B3J-288: malformed Docker memory evidence is incomplete evidence, never an exception and never 0
# ---------------------------------------------------------------------------

def _mem_row(name, used, limit=100 * GB, cpu=10.0):
    return {"name": name, "cpu_percent": cpu, "memory_used_bytes": used, "memory_limit_bytes": limit}


def _rows_sampler(rows_for_tick, stop_s=125.0, times=_ADEQUATE_TIMES):
    """The first sampler built (lag) samples normally; the second (the Docker resource sampler) returns the
    rows the test chooses for each tick, so malformed observations can be injected as they would arrive."""
    made = []

    class Planned:
        def __init__(self, sample, interval):
            self.index, self.sample, self.samples, self.errors, self.stopped_at = len(made), sample, [], [], None
            made.append(self)

        @property
        def window(self):
            return None if self.stopped_at is None else (0.0, self.stopped_at)

        def start(self):
            for i, at in enumerate(times):
                value = rows_for_tick(i) if self.index == 1 else self.sample()
                self.samples.append((float(at), value))

        def stop(self):
            if self.stopped_at is None:
                self.stopped_at = float(stop_s)
    return Planned


def _run_rows(tmp_path, rows_for_tick):
    smoke = FakeSmoke(tmp_path)
    ticks = iter(range(10 ** 6))
    return REAL_EXECUTE_CELL(
        _cell(), LADDER, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None, output_dir=tmp_path / "results",
        disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
        sampler_factory=_rows_sampler(rows_for_tick))


def _good(i=0, kafka=100_000_000, pg=50_000_000, limit=100 * GB):
    return [_mem_row("proj-kafka-1", kafka, limit), _mem_row("proj-pg-1", pg, limit, cpu=1.0)]


MALFORMED_USED = [
    pytest.param(lambda r: r.pop("memory_used_bytes"), id="missing"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", None), id="none"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", -1), id="negative"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", float("nan")), id="nan"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", float("inf")), id="infinity"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", float("-inf")), id="minus-infinity"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", "100000000"), id="string"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", 1.5), id="float"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", True), id="bool"),
    pytest.param(lambda r: r.__setitem__("memory_used_bytes", [5]), id="list"),
]
MALFORMED_LIMIT = [
    pytest.param(lambda r: r.pop("memory_limit_bytes"), id="missing"),
    pytest.param(lambda r: r.__setitem__("memory_limit_bytes", 0), id="zero"),
    pytest.param(lambda r: r.__setitem__("memory_limit_bytes", -5), id="negative"),
    pytest.param(lambda r: r.__setitem__("memory_limit_bytes", float("nan")), id="nan"),
    pytest.param(lambda r: r.__setitem__("memory_limit_bytes", float("inf")), id="infinity"),
    pytest.param(lambda r: r.__setitem__("memory_limit_bytes", "1000"), id="string"),
    pytest.param(lambda r: r.__setitem__("memory_limit_bytes", None), id="none"),
]


class TestMemoryObservations:
    def test_valid_rows_are_kept_with_their_limits(self):
        samples = [(0.0, _good()), (10.0, _good(kafka=7))]
        assert RB._memory_observations(samples) == [
            ("proj-kafka-1", 100_000_000, 100 * GB), ("proj-pg-1", 50_000_000, 100 * GB),
            ("proj-kafka-1", 7, 100 * GB), ("proj-pg-1", 50_000_000, 100 * GB)]

    def test_zero_is_a_valid_reading_but_a_missing_one_is_not_zero(self):
        assert RB._memory_observations([(0.0, [_mem_row("a", 0)])]) == [("a", 0, 100 * GB)]
        assert RB._memory_observations([(0.0, [{"name": "a"}])]) == []

    @pytest.mark.parametrize("mutate", MALFORMED_USED)
    def test_a_malformed_reading_gives_no_observation(self, mutate):
        row = _mem_row("a", 5)
        mutate(row)
        assert RB._memory_observations([(0.0, [row])]) == []

    @pytest.mark.parametrize("mutate", MALFORMED_LIMIT)
    def test_a_malformed_limit_keeps_the_reading_but_gives_no_limit(self, mutate):
        row = _mem_row("a", 5)
        mutate(row)
        assert RB._memory_observations([(0.0, [row])]) == [("a", 5, None)]

    @pytest.mark.parametrize("sample", [None, "x", 5, (1,), (0.0, None), (0.0, "rows"), (0.0, 7), (0.0, {"a": 1}),
                                        (0.0, ["row", 5, None, {"name": ""}, {"name": 3, "memory_used_bytes": 1}])])
    def test_malformed_samples_and_rows_are_skipped_without_raising(self, sample):
        assert RB._memory_observations([sample]) == []


class TestMalformedMemoryInTheCell:
    def _kafka_bad(self, mutate, bad_ticks=None):
        def rows(i):
            rows_ = _good(i)
            if bad_ticks is None or i in bad_ticks:
                mutate(rows_[0])
            return rows_
        return rows

    @pytest.mark.parametrize("mutate", MALFORMED_USED)
    def test_a_container_with_no_valid_memory_in_any_tick_makes_the_cell_invalid_not_an_exception(self, tmp_path, mutate):
        result, path, clean = _run_rows(tmp_path, self._kafka_bad(mutate))
        assert clean is True and result["verdict"] == "INVALID"
        gate, = [g for g in result["integrity"]["gates"] if g["name"] == "docker resource coverage"]
        assert gate["ok"] is False and "memory:" in gate["evidence"]
        resources = result["metrics"]["resources"]
        assert resources["memory_peak_bytes"]["proj-pg-1"]["value"] == 50_000_000        # the valid container
        assert "proj-kafka-1" not in resources["memory_peak_bytes"]                      # absent, not 0
        assert resources["docker_memory_aggregate_bytes_max"]["all"]["kind"] == "NOT_MEASURED"
        assert resources["docker_vm_cpu_percent_max"]["benchmark-containers"]["value"] > 0     # CPU is unaffected
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    @pytest.mark.parametrize("mutate", MALFORMED_LIMIT)
    def test_a_missing_or_zero_limit_skips_only_the_per_container_judgement(self, tmp_path, mutate):
        result = _run_rows(tmp_path, self._kafka_bad(mutate))[0]
        assert result["verdict"] == "VALID" and result["stop"]["reasons"] == []
        resources = result["metrics"]["resources"]
        assert resources["memory_peak_bytes"]["proj-kafka-1"]["value"] == 100_000_000
        assert resources["docker_memory_aggregate_bytes_max"]["benchmark-containers"]["value"] == 150_000_000

    @pytest.mark.parametrize("mutate", MALFORMED_USED)
    def test_a_few_malformed_ticks_are_tolerated_and_never_counted_as_zero(self, tmp_path, mutate):
        result = _run_rows(tmp_path, self._kafka_bad(mutate, bad_ticks={3, 8}))[0]
        assert result["verdict"] == "VALID"
        resources = result["metrics"]["resources"]
        peak = resources["memory_peak_bytes"]["proj-kafka-1"]
        assert peak["value"] == 100_000_000 and peak["n"] == 11                             # the 11 valid readings
        series = resources["docker_memory_aggregate_bytes_series"]["benchmark-containers"]["value"]
        assert len(series) == 11 and min(series) == 150_000_000
        assert resources["docker_resource_coverage"]["memory_ticks_lower_bound_only"]["value"] == 2

    def test_mostly_malformed_evidence_is_insufficient_coverage(self, tmp_path):
        result = _run_rows(tmp_path, self._kafka_bad(lambda r: r.__setitem__("memory_used_bytes", "x"),
                                                     bad_ticks=set(range(1, 12))))[0]
        assert result["verdict"] == "INVALID"
        gate, = [g for g in result["integrity"]["gates"] if g["name"] == "docker resource coverage"]
        assert "memory: 2 usable ticks, fewer than 5" in gate["evidence"]

    @pytest.mark.parametrize("bad", [None, "rows", 7, [None, "x"], [{"name": "proj-kafka-1"}], []])
    def test_every_kind_of_bad_sample_in_every_tick_is_invalid_without_raising(self, tmp_path, bad):
        assert _run_rows(tmp_path, lambda i: bad)[0]["verdict"] == "INVALID"

    def test_a_valid_conclusive_aggregate_violation_still_stops_with_malformed_ticks_around_it(self, tmp_path):
        heavy = int(3.75 * GB)

        def rows(i):
            if i in (2, 9):
                return [_mem_row("proj-kafka-1", "bad"), _mem_row("proj-pg-1", heavy)]
            return [_mem_row("proj-kafka-1", heavy), _mem_row("proj-pg-1", heavy, cpu=1.0)]
        result = _run_rows(tmp_path, rows)[0]
        assert result["verdict"] == "STOPPED"
        assert [r for r in result["stop"]["reasons"] if r.startswith("Docker containers memory 93.8%")]

    def test_a_valid_per_container_violation_still_stops_with_malformed_rows_elsewhere(self, tmp_path):
        def rows(i):
            if i == 5:
                return [_mem_row("proj-kafka-1", float("nan"), 1000), _mem_row("proj-pg-1", 10, 1000)]
            return [_mem_row("proj-kafka-1", 950, 1000), _mem_row("proj-pg-1", 10, 1000, cpu=1.0)]
        result = _run_rows(tmp_path, rows)[0]
        assert result["verdict"] == "STOPPED"
        assert result["stop"]["reasons"] == ["proj-kafka-1 memory 95.0% of its limit > 90%"]

    def test_the_invalid_precedence_keeps_a_measured_violation_in_the_stop_reasons(self, tmp_path):
        def rows(i):
            return [_mem_row("proj-kafka-1", 950, 1000), _mem_row("proj-pg-1", "bad", 1000)]
        result = _run_rows(tmp_path, rows)[0]
        assert result["verdict"] == "INVALID"                         # no complete tick: evidence is insufficient
        assert result["stop"]["reasons"] == ["proj-kafka-1 memory 95.0% of its limit > 90%"]

    def test_fully_valid_rows_behave_exactly_as_before(self, tmp_path):
        result = _run_rows(tmp_path, _good)[0]
        assert result["verdict"] == "VALID" and result["stop"]["reasons"] == []
        resources = result["metrics"]["resources"]
        assert resources["memory_peak_bytes"]["proj-kafka-1"] == {
            "value": 100_000_000, "unit": "bytes", "kind": "OBSERVATION", "source": "docker stats",
            "method": "maximum of samples", "window": None, "n": 13, "reason": None}

    def test_the_old_path_without_a_sampler_window_no_longer_raises_either(self):
        evidence = RB.CellEvidence(
            cell=_cell(), git_sha=SHA, git_dirty=False, started=1.0, finished=2.0,
            resource_samples=[(0.0, [_mem_row("a", "x"), {"name": "b"}, _mem_row("c", 9, 0), "junk"]), (10.0, None)])
        result = RB.assemble_result(evidence, LADDER["stop_limits"])
        peaks = result["metrics"]["resources"]["memory_peak_bytes"]
        assert list(peaks) == ["c"] and peaks["c"]["value"] == 9 and peaks["c"]["n"] == 1
        assert all("memory" not in r for r in result["stop"]["reasons"])

    def test_no_valid_reading_at_all_is_not_measured_with_its_own_reason(self):
        evidence = RB.CellEvidence(cell=_cell(), git_sha=SHA, git_dirty=False, started=1.0, finished=2.0,
                                   resource_samples=[(0.0, [_mem_row("a", -1)])])
        peaks = RB.assemble_result(evidence, LADDER["stop_limits"])["metrics"]["resources"]["memory_peak_bytes"]
        assert peaks["all"]["kind"] == "NOT_MEASURED" and peaks["all"]["reason"] == "no sample held a valid memory reading"
        empty = RB.CellEvidence(cell=_cell(), git_sha=SHA, git_dirty=False, started=1.0, finished=2.0)
        assert RB.assemble_result(empty, LADDER["stop_limits"])["metrics"]["resources"]["memory_peak_bytes"][
            "all"]["reason"] == "no resource samples"

    def test_the_b3j_287_rules_and_thresholds_are_unchanged(self):
        assert (M.DOCKER_COVERAGE_MIN_TICKS, M.DOCKER_COVERAGE_MIN_FRACTION, M.DOCKER_COVERAGE_EDGE_FACTOR,
                M.DOCKER_COVERAGE_GAP_FACTOR, M.DOCKER_CPU_GAP_FACTOR) == (5, 0.80, 2.0, 3.0, 2.0)
        assert (M.MEMORY_FRACTION_MAX, M.CPU_SATURATION_PERCENT, M.CPU_SATURATION_SECONDS) == (0.90, 99.5, 60.0)
        assert M.verdict(integrity_ok=False, stop_reasons=["x"], generator_bound_run=False) == "INVALID"
        assert M.verdict(integrity_ok=True, stop_reasons=["x"], generator_bound_run=False) == "STOPPED"


# ---------------------------------------------------------------------------
# B3J-291: SMALL-10 repetition 9 (the N=100 diagnostic with host-resource observations and the new rules)
# ---------------------------------------------------------------------------

#: The approvals of repetitions 1-8 as they stand: rep9 must not touch any of them.
_EARLIER_SMALL_TO_8 = {n: {"level": "SMALL", "requests": 1000, "rate": 10, "concurrency": 32, "repetition": n,
                           "warmup_requests": 300} for n in range(1, 9)}


class TestRep9Registration:
    def test_rep9_is_the_only_newly_approved_cell_and_the_ids_are_exact(self):
        assert sorted(RB.APPROVED_LIVE_CELLS) == sorted(APPROVED_IDS) and len(RB.APPROVED_LIVE_CELLS) == 13
        assert APPROVED_IDS.count(REP9_LIKE) == 1 and REP9_LIKE == "bm-small-r0010-c32-rep9"
        assert list(RB.APPROVED_LIVE_CELLS)[-1] == REP9_LIKE

    def test_all_seven_structures_agree_and_carry_rep9_with_the_rep8_values(self):
        assert dict(RB.APPROVED_LIVE_CELLS[REP9_LIKE]) == {**dict(RB.APPROVED_LIVE_CELLS[REP8_LIKE]), "repetition": 9}
        assert dict(RB.APPROVED_DIAGNOSTIC_INTERVALS)[REP9_LIKE] == dict(RB.APPROVED_DIAGNOSTIC_INTERVALS)[REP8_LIKE] == 5.0
        assert dict(RB.APPROVED_COMMIT_BATCHING)[REP9_LIKE] == dict(RB.APPROVED_COMMIT_BATCHING)[REP8_LIKE] == (100, 1.0)
        assert REP9_LIKE in RB.COMMIT_BATCHING_CELLS and REP9_LIKE in RB.DIAGNOSTIC_TIMING_CELLS
        assert dict(RB.COMPARABILITY_REFERENCES[REP9_LIKE]) == dict(RB.COMPARABILITY_REFERENCES[REP8_LIKE]) == {
            "against": "SMALL-10 repetitions 1-4", "NCPU": 22, "MemTotal": 8_168_574_976}
        assert RB.CELL_LIMITATIONS[REP9_LIKE] == REP9_LIMITATION
        seven_tables = (RB.APPROVED_LIVE_CELLS, RB.APPROVED_DIAGNOSTIC_INTERVALS, RB.APPROVED_COMMIT_BATCHING,
                        RB.COMMIT_BATCHING_CELLS, RB.COMPARABILITY_REFERENCES, RB.CELL_LIMITATIONS,
                        RB.DIAGNOSTIC_TIMING_CELLS)
        assert all(REP9_LIKE in table for table in seven_tables)

    def test_the_limitation_is_the_approved_text_and_names_the_differences(self):
        text = RB.CELL_LIMITATIONS[REP9_LIKE]
        assert text.startswith("SMALL-10 repetition 9 uses the same workload, rate, concurrency, warm-up and offset-commit batching")
        for phrase in ("(100 messages or 1.0 s, consumer timing every 5 s)", "ended VALID under its original rules and is not reclassified",
                       "host-side resource observations", "aggregates per sampling tick against the recorded Docker NCPU and MemTotal",
                       "inadequate resource-sampling coverage makes a run INVALID", "Repetition 6 ended STOPPED and repetition 7 ended GENERATOR_BOUND"):
            assert phrase in text, phrase

    def test_repetitions_one_to_eight_keep_their_exact_approvals_and_rep8_keeps_its_text(self):
        for n, fields in _EARLIER_SMALL_TO_8.items():
            assert dict(RB.APPROVED_LIVE_CELLS[f"bm-small-r0010-c32-rep{n}"]) == fields, n
        for n in range(1, 7):
            assert RB.commit_batching_for(f"bm-small-r0010-c32-rep{n}") == (1, None)
            assert f"bm-small-r0010-c32-rep{n}" not in RB.COMMIT_BATCHING_CELLS
        assert RB.CELL_LIMITATIONS[REP8_LIKE] == REP8_LIMITATION
        assert RB.CELL_LIMITATIONS[REP7_LIKE].startswith("SMALL-10 repetition 6 used single-message commits on the same")
        assert dict(RB.APPROVED_COMMIT_BATCHING)[REP7_LIKE] == dict(RB.APPROVED_COMMIT_BATCHING)[REP8_LIKE] == (100, 1.0)

    @pytest.mark.parametrize("n", [10])
    def test_repetition_ten_stays_refused(self, n):
        cell = _small(repetition=n)
        assert not RB.is_approved_live_cell(cell)
        with pytest.raises(RB.BenchmarkError, match="not an approved live cell"):
            RB.check_live_authorization([cell], authorize=f"bm-small-r0010-c32-rep{n}", expect_head=HEAD,
                                        warmup_requests=300, repetition=n)

    def test_rep9_has_the_registered_workload(self):
        cell = _small(repetition=9)
        target = cell.target()
        assert RB.is_approved_live_cell(cell) and cell.benchmark_id == REP9_LIKE
        assert (cell.level, cell.requests, cell.rate, cell.concurrency, cell.warmup_requests, cell.seed) == (
            "SMALL", 1000, 10, 32, 300, 42)
        assert target["planned_spans"] == 7000 and target["scenario"] == "normal" and target["measured_seconds"] == 100.0
        assert (target["warmup_run_id"], target["measured_run_id"]) == ("b-small-r0010-c32-w9", "b-small-r0010-c32-m9")
        eight = _small(repetition=8).target()
        assert {k for k, v in target.items() if eight[k] != v} == {"repetition", "warmup_run_id", "measured_run_id"}

    def test_rep9_selects_n_100_t_1_and_five_second_timing_like_rep8(self):
        effective = RB.check_effective_config(_small(repetition=9), LADDER)
        assert (effective["consumer_commit_batch_messages"], effective["consumer_commit_interval_seconds"],
                effective["consumer_timing_interval_seconds"]) == (100, 1.0, 5.0)
        assert type(effective["consumer_commit_batch_messages"]) is int and type(effective["consumer_commit_interval_seconds"]) is float
        rep8 = RB.check_effective_config(_small(repetition=8), LADDER)
        assert {k for k in effective if effective[k] != rep8[k]} == {"target"}
        assert effective["stop_limits"] == rep8["stop_limits"] and effective["sample_interval_seconds"] == 10

    def test_rep9_is_authorized_only_with_its_exact_selectors(self):
        cell = _small(repetition=9)
        assert _authorize_small(cell, authorize=REP9_LIKE, repetition=9) == cell
        for authorize, repetition in ((REP8_LIKE, 9), (REP9_LIKE, 8), ("bm-small-r0010-c32-rep10", 9), (REP9_LIKE, None)):
            with pytest.raises(RB.BenchmarkError):
                _authorize_small(cell, authorize=authorize, repetition=repetition)
        for change in (dict(requests=999), dict(rate=5), dict(concurrency=16), dict(warmup_requests=299), dict(level="SMOKE")):
            assert not RB.is_approved_live_cell(dataclasses.replace(cell, **change)), change

    def test_rep9_needs_a_full_expect_head_and_the_exact_warmup(self):
        cell = _small(repetition=9)
        for expect_head in (None, "abc", HEAD[:39], "A" * 40):
            with pytest.raises(RB.BenchmarkError):
                RB.check_live_authorization([cell], authorize=REP9_LIKE, expect_head=expect_head,
                                            warmup_requests=300, repetition=9)
        with pytest.raises(RB.BenchmarkError):
            RB.check_live_authorization([cell], authorize=REP9_LIKE, expect_head=HEAD, warmup_requests=301, repetition=9)

    def test_the_rep9_limitation_belongs_to_rep9_only(self, tmp_path):
        result, _, clean, _ = _run(tmp_path, cell=_small(repetition=9))
        assert clean and result["limitations"].count(REP9_LIMITATION) == 1
        assert RB.CELL_LIMITATIONS[REP8_LIKE] not in result["limitations"]
        assert result["consumer"]["commit_batching"] == {"enabled": True, "batch_messages": 100, "interval_seconds": 1.0}
        assert result["consumer"]["timing_diagnostic_interval_seconds"] == 5.0
        M.validate_result(result)
        for n in range(1, 9):
            (tmp_path / f"d{n}").mkdir()
            other, _, _, _ = _run(tmp_path / f"d{n}", cell=_small(repetition=n))
            assert REP9_LIMITATION not in other["limitations"], n

    def test_the_rep9_claim_marker_is_schema_four_with_the_exact_configuration(self, tmp_path):
        cell = _small(repetition=9)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.check_effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        assert record["schema"] == RB.MARKER_SCHEMA == 4 and record["benchmark_id"] == REP9_LIKE
        effective = record["effective_config"]
        assert (effective["consumer_commit_batch_messages"], effective["consumer_commit_interval_seconds"],
                effective["consumer_timing_interval_seconds"]) == (100, 1.0, 5.0)
        assert effective["target"] == cell.target() and RB.validate_marker(record, cell, tmp_path) == []

    def test_a_rep9_claim_is_single_use(self, tmp_path):
        cell = _small(repetition=9)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.check_effective_config(cell, LADDER)}
        RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)
        with pytest.raises(RB.BenchmarkError):
            RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding)

    @pytest.mark.parametrize("batch,interval", [(1, None), (50, 1.0), (100, 2.0), (100, None), (True, 1.0)])
    def test_a_rep9_marker_with_other_batching_values_is_refused(self, tmp_path, batch, interval):
        cell = _small(repetition=9)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.effective_config(cell, LADDER)}
        record = json.loads(RB.claim_run(tmp_path, cell, head=HEAD, arguments={}, binding=binding).read_text(encoding="utf-8"))
        record["effective_config"].update(consumer_commit_batch_messages=batch, consumer_commit_interval_seconds=interval)
        assert any("consumer_commit" in p for p in RB.validate_marker(record, cell, tmp_path))

    def test_the_independent_tables_must_still_agree_for_rep9(self, monkeypatch):
        monkeypatch.setattr(RB, "COMMIT_BATCHING_CELLS", frozenset({REP7_LIKE, REP8_LIKE}))
        with pytest.raises(RB.BenchmarkError, match="commit batching configuration differs"):
            RB.check_effective_config(_small(repetition=9), LADDER)

    def test_the_resource_rules_apply_to_rep9_through_the_cell_path_not_through_registration(self, tmp_path):
        (tmp_path / "a").mkdir()
        result, _, clean = _run_planned(tmp_path / "a", cell=_small(repetition=9))[:3]
        assert clean and result["benchmark_id"] == REP9_LIKE        # the fake harness's counts are for a smaller cell
        assert [g for g in result["integrity"]["gates"] if g["name"] == "docker resource coverage"][0]["ok"] is True
        assert any("differ from SMALL-10 repetition 8 and every earlier cell" in t for t in result["limitations"])

    def test_safety_controls_and_thresholds_are_unchanged(self):
        assert M.LAG_GROWTH_SAMPLES == 6 and M.LATE_START_FRACTION == 0.05
        assert LADDER["stop_limits"]["lag_growth_samples"] == 6 and LADDER["stop_limits"]["late_start_fraction"] == 0.05
        assert (LADDER["defaults"]["drain_limit_seconds"], LADDER["defaults"]["settle_seconds"],
                LADDER["defaults"]["cell_budget_seconds"], LADDER["defaults"]["sample_interval_seconds"]) == (120, 6, 3600, 10)
        assert (LADDER["stop_limits"]["cpu_saturation_percent"], LADDER["stop_limits"]["cpu_saturation_seconds"],
                LADDER["stop_limits"]["memory_fraction"]) == (99.5, 60, 0.90)
        assert RB.KEEP_AWAKE_FLAGS == 0x80000003 and RB.MARKER_SCHEMA == 4

    def test_checking_the_registration_creates_no_claim_or_ledger_entry(self, tmp_path):
        ledger = RB.DEFAULT_OUTPUT / "ledger"
        before = sorted(p.name for p in ledger.glob("*")) if ledger.exists() else []
        RB.check_effective_config(_small(repetition=9), LADDER)
        RB.is_approved_live_cell(_small(repetition=9))
        after = sorted(p.name for p in ledger.glob("*")) if ledger.exists() else []
        assert before == after and not any(tmp_path.rglob("*"))


# ---------------------------------------------------------------------------
# B3J-299: the host-memory checkpoint between the warm-up and the measured traffic
# ---------------------------------------------------------------------------

MIB = 1024 ** 2
THRESHOLD = 2048 * MIB


class MemReader:
    """A fake host-memory reader: returns or raises its items in order, then repeats the last one."""

    def __init__(self, *items):
        self.items, self.calls = list(items), 0

    def __call__(self):
        self.calls += 1
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, BaseException):
            raise item
        return item


def _run_memory(tmp_path, reader, *, cell=None, smoke=None, out=None, factory=None, sleeps=None):
    smoke = smoke or FakeSmoke(tmp_path)
    smoke.RUN.processes = {}
    ticks = iter(range(10 ** 6))
    result, path, clean = REAL_EXECUTE_CELL(
        cell or _cell(), LADDER, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None,
        output_dir=out or (tmp_path / "results"), disk_free=lambda: 500 * GB,
        clock=lambda: float(next(ticks)), wall=lambda: 5003.0, sampler_factory=FakeSampler,
        host_resources=factory, host_memory=reader, host_memory_sleep=(sleeps.append if sleeps is not None else (lambda s: None)))
    return result, path, clean, smoke


GOOD = 4096 * MIB
MALFORMED_READINGS = [
    pytest.param(None, id="none"), pytest.param(True, id="bool"), pytest.param(False, id="false"),
    pytest.param("4096", id="string"), pytest.param(1.5, id="float"), pytest.param(4096.0, id="whole-float"),
    pytest.param(float("nan"), id="nan"), pytest.param(float("inf"), id="infinity"),
    pytest.param(float("-inf"), id="minus-infinity"), pytest.param(-1, id="negative"),
    pytest.param([4096], id="list"), pytest.param({"a": 1}, id="dict"),
    pytest.param(OSError(5, "denied"), id="oserror"), pytest.param(RuntimeError("x"), id="runtimeerror"),
    pytest.param(ValueError("x"), id="valueerror"),
]


class TestHostMemoryCheckpointFunction:
    def test_the_constants_are_the_approved_provisional_values(self):
        assert RB.HOST_MEMORY_CHECKPOINT_MIN_BYTES == 2048 * MIB == 2_147_483_648
        assert (RB.HOST_MEMORY_CHECKPOINT_READINGS, RB.HOST_MEMORY_CHECKPOINT_SPACING_SECONDS) == (3, 0.25)

    def test_above_the_threshold_passes_and_keeps_all_three_readings_in_order(self):
        out = RB.host_memory_checkpoint(MemReader(3000 * MIB, 3100 * MIB, 3200 * MIB), sleep=lambda s: None)
        assert out == {"readings": [3000 * MIB, 3100 * MIB, 3200 * MIB], "minimum": 3000 * MIB,
                       "threshold": THRESHOLD, "status": "ok"}

    def test_exactly_equal_to_the_threshold_passes(self):
        assert RB.host_memory_checkpoint(MemReader(THRESHOLD), sleep=lambda s: None)["status"] == "ok"

    def test_one_byte_below_the_threshold_stops(self):
        out = RB.host_memory_checkpoint(MemReader(THRESHOLD - 1), sleep=lambda s: None)
        assert out["status"] == "below_threshold" and out["minimum"] == THRESHOLD - 1

    def test_the_minimum_of_the_three_decides_wherever_it_is(self):
        for readings, expected in (([5 * GB, 3 * GB, 4 * GB], 3 * GB), ([1 * GB, 5 * GB, 5 * GB], 1 * GB),
                                   ([5 * GB, 5 * GB, 1 * GB], 1 * GB)):
            out = RB.host_memory_checkpoint(MemReader(*readings), sleep=lambda s: None)
            assert out["minimum"] == expected and out["readings"] == readings
            assert out["status"] == ("ok" if expected >= THRESHOLD else "below_threshold")

    def test_the_reader_is_called_three_times_with_quarter_second_pauses_between(self):
        reader, sleeps = MemReader(GOOD), []
        RB.host_memory_checkpoint(reader, sleep=sleeps.append)
        assert reader.calls == 3 and sleeps == [0.25, 0.25]

    @pytest.mark.parametrize("bad", MALFORMED_READINGS)
    @pytest.mark.parametrize("position", [0, 1, 2])
    def test_any_one_unavailable_reading_makes_the_whole_checkpoint_unavailable(self, bad, position):
        items = [GOOD, GOOD, GOOD]
        items[position] = bad
        out = RB.host_memory_checkpoint(MemReader(*items), sleep=lambda s: None)
        assert out["status"] == "unavailable" and out["minimum"] is None
        assert out["readings"][position] is None and [r for r in out["readings"] if r is None] == [None]

    @pytest.mark.parametrize("bad", MALFORMED_READINGS)
    def test_all_three_unavailable(self, bad):
        out = RB.host_memory_checkpoint(MemReader(bad), sleep=lambda s: None)
        assert out == {"readings": [None, None, None], "minimum": None, "threshold": THRESHOLD, "status": "unavailable"}

    def test_a_zero_reading_is_a_valid_value_and_below_the_threshold(self):
        out = RB.host_memory_checkpoint(MemReader(0), sleep=lambda s: None)
        assert out["status"] == "below_threshold" and out["minimum"] == 0 and out["readings"] == [0, 0, 0]

    def test_a_missing_reading_is_never_turned_into_zero(self):
        out = RB.host_memory_checkpoint(MemReader(None), sleep=lambda s: None)
        assert 0 not in out["readings"] and out["status"] == "unavailable"

    def test_a_sleep_that_fails_does_not_break_the_checkpoint(self):
        def boom(seconds):
            raise RuntimeError("no sleep")
        assert RB.host_memory_checkpoint(MemReader(GOOD), sleep=boom)["status"] == "ok"

    def test_the_threshold_can_be_overridden_by_the_caller_only(self):
        out = RB.host_memory_checkpoint(MemReader(GOOD), sleep=lambda s: None, threshold=GOOD + 1)
        assert out["status"] == "below_threshold" and out["threshold"] == GOOD + 1

    def test_the_stop_reasons_are_distinct_and_exact(self):
        low = RB.host_memory_checkpoint(MemReader(1000 * MIB, 3000 * MIB, 3000 * MIB), sleep=lambda s: None)
        assert RB.host_memory_checkpoint_stop_reason(low) == (
            "host memory checkpoint: available memory 1000.0 MiB (1048576000 bytes) is below the 2048 MiB threshold "
            "after the warm-up and before the measured run")
        gone = RB.host_memory_checkpoint(MemReader(GOOD, None, GOOD), sleep=lambda s: None)
        assert RB.host_memory_checkpoint_stop_reason(gone) == (
            "host memory checkpoint: 1 of 3 readings after the warm-up were unavailable, so the host's available "
            "memory could not be verified")
        assert RB.host_memory_checkpoint_stop_reason(RB.host_memory_checkpoint(MemReader(GOOD), sleep=lambda s: None)) is None

    def test_the_real_reader_is_blocked_in_the_tests_and_every_reading_becomes_unavailable(self):
        with pytest.raises(_RealHostApiBlocked):
            RB.read_host_available_memory()
        out = RB.host_memory_checkpoint(RB.read_host_available_memory, sleep=lambda s: None)
        assert out["status"] == "unavailable"          # the blocked call failed; the checkpoint swallowed it

    def test_the_real_reader_uses_the_host_sampler_api_and_nothing_else(self):
        import inspect
        source = inspect.getsource(RB.read_host_available_memory)
        assert "WindowsHostResourceApi().memory()" in source and "ctypes" not in source


class TestHostMemoryCheckpointInTheCell:
    PASSING = (GOOD, GOOD, GOOD, GOOD, GOOD)          # before_startup, stack_ready, then three checkpoint readings

    def test_a_passing_checkpoint_changes_nothing_in_the_run_and_records_its_evidence(self, tmp_path):
        reader, sleeps = MemReader(*self.PASSING), []
        result, path, clean, smoke = _run_memory(tmp_path, reader, sleeps=sleeps)
        assert clean and result["verdict"] == "VALID" and smoke.calls == ORDER
        assert reader.calls == 5 and sleeps == [0.25, 0.25]
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))
        resources = result["metrics"]["resources"]
        points = resources["host_memory_checkpoint_bytes"]
        assert points["before_startup"]["value"] == GOOD and points["stack_ready"]["value"] == GOOD
        assert points["after_warmup"]["value"] == [GOOD, GOOD, GOOD] and points["after_warmup"]["n"] == 3
        assert resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["value"] == GOOD
        assert resources["host_memory_checkpoint_threshold_bytes"]["after_warmup"]["value"] == THRESHOLD
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == 0
        line, = [t for t in result["limitations"] if t.startswith("host-memory checkpoint")]
        assert "passed" in line and "threshold 2048 MiB" in line and "4096.0, 4096.0, 4096.0 MiB" in line

    def test_a_cell_without_a_reader_is_exactly_what_it_was(self, tmp_path):
        result = _run(tmp_path)[0]
        assert not [n for n in result["metrics"]["resources"] if n.startswith("host_memory_checkpoint")]
        assert not [t for t in result["limitations"] if "host-memory checkpoint" in t]

    def test_exactly_the_threshold_runs_the_measured_traffic(self, tmp_path):
        result, _, clean, smoke = _run_memory(tmp_path, MemReader(GOOD, GOOD, THRESHOLD))
        assert clean and result["verdict"] == "VALID" and "run_stage_measured" in smoke.calls

    def test_below_the_threshold_stops_before_any_measured_traffic_and_cleans_up(self, tmp_path):
        reader = MemReader(GOOD, GOOD, 3000 * MIB, THRESHOLD - 1, 3000 * MIB)
        built = []
        result, path, clean, smoke = _run_memory(tmp_path, reader, factory=lambda **kw: built.append(kw))
        assert clean is True and result["verdict"] == "STOPPED"
        assert result["stop"]["reasons"] == [
            "host memory checkpoint: available memory 2048.0 MiB (2147483647 bytes) is below the 2048 MiB threshold "
            "after the warm-up and before the measured run"]
        for step in ("run_stage_measured", "clock_probe", "compose_ps", "docker_stats", "psql"):
            assert step not in smoke.calls, step
        assert "run_stage_warmup" in smoke.calls
        assert smoke.calls[-3:] == ["stop_host_processes", "remove_profile_resources", "cleanup"]
        assert built == []                                        # no sampler of any kind was started
        assert result["integrity"]["ok"] is None and result["claims"] == {k: False for k in result["claims"]}
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    def test_the_checkpoint_evidence_survives_the_early_stop_without_any_sampler_window(self, tmp_path):
        result = _run_memory(tmp_path, MemReader(GOOD, GOOD, 1000 * MIB, 3000 * MIB, 4000 * MIB))[0]
        resources = result["metrics"]["resources"]
        assert resources["host_memory_checkpoint_bytes"]["after_warmup"]["value"] == [1000 * MIB, 3000 * MIB, 4000 * MIB]
        assert resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["value"] == 1000 * MIB
        assert not [n for n in resources if n.startswith("docker_") or n.startswith("host_sampling")]
        assert [g for g in result["integrity"]["gates"] if g["name"] == "docker resource coverage"] == []
        assert any("stopped the cell (below the threshold)" in t for t in result["limitations"])

    def test_one_unavailable_reading_stops_with_the_instrumentation_reason(self, tmp_path):
        reader = MemReader(GOOD, GOOD, GOOD, RuntimeError("api"), GOOD)
        result, path, clean, smoke = _run_memory(tmp_path, reader)
        assert clean and result["verdict"] == "STOPPED" and "run_stage_measured" not in smoke.calls
        assert result["stop"]["reasons"] == [
            "host memory checkpoint: 1 of 3 readings after the warm-up were unavailable, so the host's available "
            "memory could not be verified"]
        resources = result["metrics"]["resources"]
        assert resources["host_memory_checkpoint_bytes"]["after_warmup"]["value"] == [GOOD, GOOD]
        assert resources["host_memory_checkpoint_minimum_bytes"]["after_warmup"]["kind"] == "NOT_MEASURED"
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == 1
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    def test_all_three_unavailable_stops_and_records_no_value(self, tmp_path):
        reader = MemReader(GOOD, GOOD, None)
        result, path, clean, smoke = _run_memory(tmp_path, reader)
        assert clean and result["verdict"] == "STOPPED" and "run_stage_measured" not in smoke.calls
        resources = result["metrics"]["resources"]
        assert resources["host_memory_checkpoint_bytes"]["after_warmup"]["kind"] == "NOT_MEASURED"
        assert resources["host_memory_checkpoint_unavailable_readings"]["after_warmup"]["value"] == 3
        assert "3 of 3 readings" in result["stop"]["reasons"][0]
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    @pytest.mark.parametrize("bad", MALFORMED_READINGS)
    def test_every_malformed_checkpoint_reading_stops_the_cell(self, tmp_path, bad):
        result, _, clean, smoke = _run_memory(tmp_path, MemReader(GOOD, GOOD, GOOD, bad, GOOD))
        assert clean and result["verdict"] == "STOPPED" and "run_stage_measured" not in smoke.calls
        assert "unavailable" in result["stop"]["reasons"][0]

    def test_a_failed_observation_reading_never_stops_the_run(self, tmp_path):
        reader = MemReader(OSError(5, "x"), RuntimeError("y"), GOOD, GOOD, GOOD)
        result, path, clean, smoke = _run_memory(tmp_path, reader)
        assert clean and result["verdict"] == "VALID" and "run_stage_measured" in smoke.calls
        points = result["metrics"]["resources"]["host_memory_checkpoint_bytes"]
        assert points["before_startup"]["kind"] == "NOT_MEASURED" and points["stack_ready"]["kind"] == "NOT_MEASURED"
        assert points["after_warmup"]["value"] == [GOOD] * 3
        M.validate_result(json.loads(path.read_text(encoding="utf-8")))

    @pytest.mark.parametrize("bad", MALFORMED_READINGS)
    def test_a_malformed_observation_reading_is_not_measured_and_never_stops(self, tmp_path, bad):
        result = _run_memory(tmp_path, MemReader(bad, bad, GOOD, GOOD, GOOD))[0]
        assert result["verdict"] == "VALID"
        assert result["metrics"]["resources"]["host_memory_checkpoint_bytes"]["before_startup"]["kind"] == "NOT_MEASURED"

    def test_the_observation_readings_are_taken_at_the_documented_points(self, tmp_path):
        order = []
        smoke = FakeSmoke(tmp_path)
        original = smoke._step

        def traced(name):
            order.append(name)
            return original(name)
        smoke._step = traced
        reader = MemReader(GOOD)

        def spy():
            order.append("read")
            return reader()
        _run_memory(tmp_path, spy, smoke=smoke)
        assert order.index("read") < order.index("create_workspace")                     # before_startup
        ready = [i for i, n in enumerate(order) if n == "read"]
        assert order.index("check_baseline") < ready[1] < order.index("run_stage_warmup")   # stack_ready
        assert order.index("run_stage_warmup") < ready[2] < ready[3] < ready[4] < order.index("clock_probe")

    def test_a_checkpoint_stop_goes_through_the_claim_and_the_ledger_like_any_stopped_cell(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        cell = _small(repetition=9)
        binding = {"branch": "work", "ladder_sha256": RB.APPROVED_LADDER_SHA256, "config_path": "c.json",
                   "effective_config": RB.check_effective_config(cell, LADDER)}
        RB.claim_run(out, cell, head=HEAD, arguments={}, binding=binding)
        result, path, clean, smoke = _run_memory(tmp_path, MemReader(GOOD, GOOD, 100 * MIB), cell=cell, out=out)
        assert clean and result["verdict"] == "STOPPED"
        assert RB.finish_run(out, cell, result=result, result_path=path, cleanup_verified=clean, intended_status=1) is True
        done = json.loads((out / "ledger" / f"{cell.benchmark_id}.done").read_text(encoding="utf-8"))
        assert done["verdict"] == "STOPPED" and done["cleanup_verified"] is True
        assert (out / "ledger" / f"{cell.benchmark_id}.started").exists() and not (out / RB.OWNER_FILE).exists()
        with pytest.raises(RB.BenchmarkError):
            RB.claim_run(out, cell, head=HEAD, arguments={}, binding=binding)         # single use: spent

    def test_a_failed_cleanup_after_a_checkpoint_stop_is_still_reported_unverified(self, tmp_path):
        smoke = FakeSmoke(tmp_path, cleanup_ok=False)
        result, _, clean, _ = _run_memory(tmp_path, MemReader(GOOD, GOOD, 100 * MIB), smoke=smoke)
        assert clean is False and result["verdict"] == "STOPPED"

    def test_a_passing_checkpoint_does_not_hide_the_budget_stop_that_follows_it(self, tmp_path):
        ladder = json.loads(json.dumps(LADDER))
        ladder["defaults"]["cell_budget_seconds"] = 2
        smoke = FakeSmoke(tmp_path)
        smoke.RUN.processes = {}
        ticks = iter(range(10 ** 6))
        result, _, _ = REAL_EXECUTE_CELL(
            _cell(), ladder, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None, output_dir=tmp_path / "r",
            disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
            sampler_factory=FakeSampler, host_memory=MemReader(GOOD), host_memory_sleep=lambda s: None)
        assert result["verdict"] == "STOPPED" and "budget" in result["stop"]["reasons"][0]
        points = result["metrics"]["resources"]["host_memory_checkpoint_bytes"]
        assert list(points) == ["before_startup", "stack_ready", "after_warmup"]     # the checkpoint ran and passed
        M.validate_result(result)

    def test_a_passing_checkpoint_does_not_disturb_the_docker_coverage_rules_or_precedence(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        smoke = ScriptedStatsSmoke(tmp_path / "a", [STATS_OK])
        smoke.RUN.processes = {}
        ticks = iter(range(10 ** 6))
        good, _, clean = REAL_EXECUTE_CELL(
            _cell(), LADDER, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None, output_dir=tmp_path / "a" / "r",
            disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
            sampler_factory=_planned_sampler(_ADEQUATE_TIMES, 125.0), host_memory=MemReader(GOOD),
            host_memory_sleep=lambda s: None)
        assert clean and good["verdict"] == "VALID"
        assert [g for g in good["integrity"]["gates"] if g["name"] == "docker resource coverage"][0]["ok"] is True
        smoke = ScriptedStatsSmoke(tmp_path / "b", [STATS_OK])
        smoke.RUN.processes = {}
        ticks = iter(range(10 ** 6))
        poor, _, _ = REAL_EXECUTE_CELL(
            _cell(), LADDER, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None, output_dir=tmp_path / "b" / "r",
            disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
            sampler_factory=_planned_sampler([0.0, 10.0, 20.0], 125.0), host_memory=MemReader(GOOD),
            host_memory_sleep=lambda s: None)
        assert poor["verdict"] == "INVALID"

    def test_the_checkpoint_works_together_with_the_host_sampler_fields(self, tmp_path):
        result = _run_memory(tmp_path, MemReader(GOOD), factory=_host_factory(_tree_api()))[0]
        M.validate_result(result)
        resources = result["metrics"]["resources"]
        assert "host_sampling_coverage" in resources and "host_memory_checkpoint_bytes" in resources

    def test_run_cell_hands_the_real_reader_to_the_cell_body_on_windows_only(self):
        import inspect
        source = inspect.getsource(RB.run_cell)
        assert "host_memory=read_host_available_memory if _is_windows() else None" in source

    def test_the_registration_the_ladder_and_the_stop_thresholds_are_untouched(self):
        assert len(RB.APPROVED_LIVE_CELLS) == 13 and list(RB.APPROVED_LIVE_CELLS)[-1] == "bm-small-r0010-c32-rep9"
        assert "bm-small-r0010-c32-rep10" not in RB.APPROVED_LIVE_CELLS
        assert (LADDER["stop_limits"]["memory_fraction"], LADDER["stop_limits"]["cpu_saturation_percent"],
                LADDER["stop_limits"]["cpu_saturation_seconds"]) == (0.90, 99.5, 60)
        assert hasattr(RB, "APPROVED_LADDER_SHA256") and "host_memory_checkpoint" not in json.dumps(LADDER)


# ---------------------------------------------------------------------------
# B3J-301: warm-up-only labelling after a checkpoint stop, and the reading-count guard
# ---------------------------------------------------------------------------

class TestCheckpointStopLabelling:
    @pytest.mark.parametrize("reader", [MemReader(GOOD, GOOD, 100 * MIB), MemReader(GOOD, GOOD, None)])
    def test_a_checkpoint_stop_says_the_consumer_observations_cover_the_warm_up_only(self, tmp_path, reader):
        result, _, clean, _ = _run_memory(tmp_path, reader, cell=_small(repetition=9))
        assert clean and result["verdict"] == "STOPPED"
        line, = [t for t in result["limitations"] if t == RB.HOST_MEMORY_CHECKPOINT_WARMUP_ONLY]
        assert "before any measured traffic" in line and "cover the warm-up only" in line
        assert "not measured-stage throughput" in line
        M.validate_result(result)

    def test_the_sidecar_line_is_still_produced_by_the_unchanged_capture_and_the_warm_up_line_accompanies_it(self, tmp_path):
        result = _run_memory(tmp_path, MemReader(GOOD, GOOD, 100 * MIB), cell=_small(repetition=9))[0]
        text = "\n".join(result["limitations"])
        assert "consumer timing sidecar" in text and RB.HOST_MEMORY_CHECKPOINT_WARMUP_ONLY in result["limitations"]

    def test_a_passing_checkpoint_does_not_claim_a_warm_up_only_result(self, tmp_path):
        result = _run_memory(tmp_path, MemReader(GOOD))[0]
        assert RB.HOST_MEMORY_CHECKPOINT_WARMUP_ONLY not in result["limitations"] and result["verdict"] == "VALID"

    def test_a_budget_stop_does_not_get_the_checkpoint_label(self, tmp_path):
        ladder = json.loads(json.dumps(LADDER))
        ladder["defaults"]["cell_budget_seconds"] = 2
        smoke = FakeSmoke(tmp_path)
        smoke.RUN.processes = {}
        ticks = iter(range(10 ** 6))
        result, _, _ = REAL_EXECUTE_CELL(
            _cell(), ladder, smoke=smoke, e2e=FakeE2E(smoke), expect_head=None, output_dir=tmp_path / "r",
            disk_free=lambda: 500 * GB, clock=lambda: float(next(ticks)), wall=lambda: 5003.0,
            sampler_factory=FakeSampler, host_memory=MemReader(GOOD), host_memory_sleep=lambda s: None)
        assert RB.HOST_MEMORY_CHECKPOINT_WARMUP_ONLY not in result["limitations"]

    def test_the_stop_reason_and_the_evidence_agree_in_the_written_result(self, tmp_path):
        result, path, _, _ = _run_memory(tmp_path, MemReader(GOOD, GOOD, 1000 * MIB, 3000 * MIB, 3000 * MIB))
        written = json.loads(path.read_text(encoding="utf-8"))
        M.validate_result(written)
        assert M.host_memory_checkpoint_consistency_problems(
            written["metrics"]["resources"], written["stop"]["reasons"], written["verdict"]) == []


class TestCheckpointReadingCountGuard:
    @pytest.mark.parametrize("readings", [0, -1, True, False, 3.0, "3", None])
    def test_an_unsupported_reading_count_is_refused_explicitly(self, readings):
        reader = MemReader(GOOD)
        with pytest.raises(ValueError, match="whole number of readings"):
            RB.host_memory_checkpoint(reader, sleep=lambda s: None, readings=readings)
        assert reader.calls == 0

    @pytest.mark.parametrize("readings", [1, 2, 3, 5])
    def test_supported_counts_take_exactly_that_many_readings(self, readings):
        reader = MemReader(GOOD)
        out = RB.host_memory_checkpoint(reader, sleep=lambda s: None, readings=readings)
        assert reader.calls == readings == len(out["readings"]) and out["status"] == "ok"

    def test_the_docstring_no_longer_overclaims(self):
        doc = RB.host_memory_checkpoint.__doc__
        assert "only an unsupported `readings`" in doc and "ValueError" in doc and "Never raises." not in doc

    def test_the_live_path_still_takes_exactly_three_readings(self):
        assert RB.HOST_MEMORY_CHECKPOINT_READINGS == 3
        reader = MemReader(GOOD)
        RB.host_memory_checkpoint(reader, sleep=lambda s: None)
        assert reader.calls == 3

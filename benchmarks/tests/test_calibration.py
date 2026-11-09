"""
benchmarks/tests/test_calibration.py

Offline tests of the generator-only calibration harness (condition A).
No calibration runs, no demo agent, no Docker, no network, no process
launches: children, launchers, observations, clocks and the driver are
fakes, and any process or socket attempt that is not an explicit fake fails
the test.  Where a test opens the execution gate, it does so in memory only.
"""

from __future__ import annotations

import dataclasses
import gc
import hashlib
import importlib
import importlib.abc
import inspect
import io
import json
import os
import socket
import subprocess
import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

_BENCH = Path(__file__).resolve().parents[1]
_REPO = _BENCH.parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import calibrate_generator as C  # noqa: E402
import metrics as M  # noqa: E402
import run_benchmark as RB  # noqa: E402
import win32_job as W  # noqa: E402  (the injected plan and validator of the planned path)

HEAD = "a" * 40
TOKEN = "0123456789abcdef0123456789abcdef"
CREATED = "2026-10-09T10:00:00.000Z"
SPACED_PYTHON = r"C:\Program Files\Python 3\python.exe"
LOG_DIR = r"C:\Temp\S"          # a space-free log directory, as the detached wrapper requires


class LiveAccessAttempt(AssertionError):
    """A test reached something live."""


class _BlockHarness(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in ("run_smoke", "run_e2e"):
            raise ImportError(f"{name} is blocked in the calibration tests")
        return None


@pytest.fixture(autouse=True)
def fail_closed(monkeypatch):
    def refuse(what):
        def call(*args, **kwargs):
            raise LiveAccessAttempt(f"{what} attempted")
        return call

    monkeypatch.setattr(sys, "meta_path", [_BlockHarness(), *sys.meta_path])
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    monkeypatch.setattr(os, "system", refuse("os.system"))
    monkeypatch.setattr(socket, "create_connection", refuse("a network connection"))
    monkeypatch.setattr(socket.socket, "connect", refuse("a socket connection"))
    # The child's guard refuses to start over loaded native network
    # libraries; hide any another test module loaded (restored afterwards).
    for name in [n for n in sys.modules if C._NativeStubFinder.blocked(n)]:
        monkeypatch.delitem(sys.modules, name)


SID = "S-1-15-2-99"


def open_gate(monkeypatch, ids=("cal-a-01",), head=HEAD):
    """In memory only: enable, approve `ids`, and fake the Git HEAD."""
    monkeypatch.setattr(C, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(C, "APPROVED_CALIBRATIONS", frozenset(ids))
    monkeypatch.setattr(C, "_git_head", lambda *require: head)


def open_probe_gate(monkeypatch, ids=("probe-01",), head=HEAD, sid=SID):
    """In memory only: enable and approve the probe, authorize a profile."""
    monkeypatch.setattr(C, "PROBE_ENABLED", True)
    monkeypatch.setattr(C, "APPROVED_PROBES", frozenset(ids))
    monkeypatch.setattr(C, "AUTHORIZED_APPCONTAINER_SID", sid)
    monkeypatch.setattr(C, "_git_head", lambda *require: head)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.pauses = []

    def clock(self):
        return self.now

    def pause(self, seconds):
        self.pauses.append(seconds)
        self.now += seconds


def _report(traces, late=0, lags=None, **overrides):
    lags = [0.001] * traces if lags is None else lags
    entries = [[i, round(0.2 * i, 6), lag] for i, lag in enumerate(lags)]
    report = {"started_requests": traces, "not_started_requests": 0, "late_starts": late,
              "max_start_lag_seconds": max(lags), "mean_start_lag_seconds": sum(lags) / traces,
              "run_status": "completed",
              "start_lags": {"limit": 10000, "expected": traces, "recorded": traces,
                             "complete": True, "truncated_reason": None, "entries": entries}}
    report.update(overrides)
    return SimpleNamespace(to_dict=lambda: report)


def _child_deps(clock, *, execute=None, calls=None, import_check=None):
    calls = [] if calls is None else calls

    def default_execute(plan, **kwargs):
        calls.append((plan.traces, kwargs))
        clock.now += 20.0
        return _report(plan.traces)

    def import_driver():
        if import_check:
            import_check()
        return (execute or default_execute), (lambda: "demo")

    return C.ChildDeps(
        import_driver=import_driver, exporter=lambda: "memory-exporter",
        plans=lambda n: (SimpleNamespace(traces=C.WARMUP_REQUESTS),
                         SimpleNamespace(traces=C.MEASURED_REQUESTS)),
        clock=clock.clock, pause=clock.pause, wall=lambda: 1_800_000_000.0)


def _own(directory, runs=1, token=TOKEN):
    ids = [C.calibration_id(n) for n in range(1, runs + 1)]
    return C.claim_series(directory, calibration_ids=ids, expected_head=HEAD,
                          now=lambda: 1_800_000_000.0, new_token=lambda: token)


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class FakeProcess:
    """A launched child: exits after `polls` polls (never when None)."""

    def __init__(self, *, polls=1, returncode=None, on_exit=None, pid=4242, created=CREATED):
        self.pid, self.creation_time = pid, created
        self.returncode = None
        self._polls, self._override, self._on_exit = polls, returncode, on_exit
        self.killed = False

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if self._polls is None:
            return None
        if self._polls > 0:
            self._polls -= 1
            return None
        status = self._on_exit() if self._on_exit else 0
        self.returncode = status if self._override is None else self._override
        return self.returncode

    def kill(self):
        self.killed = True

    terminate = kill


def _arg(command, flag):
    argv = list(command.argv)
    return argv[argv.index(flag) + 1]


def real_child(*, execute=None, returncode=None, polls=1, write=None):
    """A fake process whose exit runs the real child_main logic with fakes
    (or `write` instead)."""
    def make(command):
        number, out = int(_arg(command, "--child")), Path(_arg(command, "--output-dir"))
        token = _arg(command, "--token")

        def finish():
            if write is not None:
                write(out / f"{command.calibration_id}.json")
                return 0
            return C.child_main(number, out, _child_deps(FakeClock(), execute=execute),
                                series_token=token)
        return FakeProcess(polls=polls, returncode=returncode, on_exit=finish)
    return make


def good_observe(identity):
    return C.Observation([], [], [f"proc {identity.pid} 1 {identity.creation_time}"], True)


def _orchestrator(clock, makers, *, observe=good_observe, launched=None):
    launched = [] if launched is None else launched

    def launch(command, stdout, stderr):
        assert stdout.writable() and stderr.writable()
        launched.append(command)
        return makers[len(launched) - 1](command)

    deps = C.OrchestratorDeps(launch=launch, observe=observe, clock=clock.clock,
                              pause=clock.pause, now=lambda: 1_800_000_000.0,
                              interpreter=SPACED_PYTHON, expected_head=HEAD)
    return deps, launched


# ---------------------------------------------------------------------------
# Plans and identifiers
# ---------------------------------------------------------------------------

class TestPlans:
    def test_traffic_identical_to_the_smoke_cell(self):
        sys.path.insert(0, str(_REPO / "workload-generator"))
        from workload_generator.plan import PlanConfig, build_plan
        from workload_generator.scenarios import Scenario

        warm, measured = C.build_plans(1)
        smoke_m = build_plan(PlanConfig(seed=42, run_id="b-smoke-r0005-c32-m1",
                                        scenario=Scenario("normal"), traces=100, rate=5.0))
        smoke_w = build_plan(PlanConfig(seed=42, run_id="b-smoke-r0005-c32-w1",
                                        scenario=Scenario("normal"), traces=25, rate=5.0))
        for ours, theirs in ((measured, smoke_m), (warm, smoke_w)):
            assert [r.arrival_offset_seconds for r in ours.requests] == \
                [r.arrival_offset_seconds for r in theirs.requests]
            assert [r.latency for r in ours.requests] == [r.latency for r in theirs.requests]
        assert len(measured.requests) == 100 and len(warm.requests) == 25

    def test_parameters(self):
        assert (C.SEED, C.RATE, C.CONCURRENCY, C.WARMUP_REQUESTS, C.MEASURED_REQUESTS) == (
            42, 5.0, 32, 25, 100)

    def test_identifiers_are_calibration_ids(self):
        assert C.calibration_id(1) == "cal-a-01" and C.run_ids(20) == ("cal-a-w20", "cal-a-m20")
        for n in (1, 9, 20):
            assert not C.calibration_id(n).startswith("bm-")
            assert all(RB.RUN_ID_RE.fullmatch(r) for r in C.run_ids(n))
        for bad in (0, 21, True):
            with pytest.raises(C.CalibrationError):
                C.calibration_id(bad)

    def test_thresholds_are_the_existing_ones(self):
        sys.path.insert(0, str(_REPO / "workload-generator"))
        from workload_generator import real_driver
        assert C.LATE_START_SECONDS == real_driver.LATE_START_SECONDS == 0.1
        assert C.LATE_FRACTION == M.LATE_START_FRACTION == 0.05


class TestRealDriverReuse:
    def test_the_real_driver_functions_are_targeted(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8").split('"""', 2)[2]
        assert "from workload_generator import real_driver" in code
        assert "return real_driver.execute, real_driver.load_demo" in code
        assert "InMemorySpanExporter()" in code

    def test_no_production_export_path_or_harness_in_the_source(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8").split('"""', 2)[2]
        for word in ("run_real(", "check_reachable", "build_otlp_exporter", "import run_smoke",
                     "import run_e2e", "docker", "compose", "OTLPSpanExporter("):
            assert word not in code, word

    def test_production_child_uses_real_time(self, monkeypatch):
        open_gate(monkeypatch)
        deps = C.production_child_deps(C.authorize(["cal-a-01"], HEAD), 1)
        assert deps.clock is time.monotonic and deps.pause is time.sleep
        assert deps.plans is C.build_plans and deps.guard_factory is C.NetworkGuard


# ---------------------------------------------------------------------------
# Execution gates
# ---------------------------------------------------------------------------

IDENTITY = C.ProcessIdentity(4242, CREATED)

LEAVES = {
    "_import_driver": lambda auth: C._import_driver(auth),
    "_memory_exporter": lambda auth: C._memory_exporter(auth),
    "_run_powershell": lambda auth: C._run_powershell(auth, "x", 1.0),
    "observe_process": lambda auth: C.observe_process(auth, IDENTITY),
    "production_child_deps": lambda auth: C.production_child_deps(auth, 1),
    "production_orchestrator_deps": lambda auth: C.production_orchestrator_deps(auth),
    "AppContainerLauncher": lambda auth: C.AppContainerLauncher(auth, object()),
    "Win32AppContainerApi": lambda auth: C.Win32AppContainerApi(auth),
    "CtypesWin32": lambda auth: C.CtypesWin32(auth),
}

#: Leaves only the probe may use; they refuse calibration authorizations too.
PROBE_LEAVES = {
    "production_probe_deps": lambda auth: C.production_probe_deps(auth),
    "production_probe_child_deps": lambda auth: C.production_probe_child_deps(auth),
    "LoopbackListener": lambda auth: C.LoopbackListener(auth),
    "_loopback_connect": lambda auth: C._loopback_connect(auth, 50000),
    "_resolve": lambda auth: C._resolve(auth, "localhost"),
}


class TestExecutionGates:
    def test_defaults_are_gone(self, tmp_path):
        with pytest.raises(TypeError):
            C.child_main(1, tmp_path)
        with pytest.raises(TypeError):
            C.run_series(1, tmp_path)
        with pytest.raises(TypeError):
            C.ChildDeps()
        with pytest.raises(TypeError):
            C.OrchestratorDeps()
        with pytest.raises(TypeError):
            C.child_main(1, tmp_path, object(), series_token=TOKEN)
        with pytest.raises(TypeError):
            C.run_series(1, tmp_path, object())
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize("leaf", sorted(LEAVES))
    def test_every_leaf_refuses_while_disabled(self, leaf):
        assert C.EXECUTION_ENABLED is False and C.APPROVED_CALIBRATIONS == frozenset()
        with pytest.raises(C.ExecutionDisabled, match="not enabled"):
            LEAVES[leaf](None)

    def test_head_and_authorize_refuse_while_disabled(self):
        with pytest.raises(C.ExecutionDisabled, match="not enabled"):
            C._git_head()
        with pytest.raises(C.ExecutionDisabled, match="not enabled"):
            C.authorize(["cal-a-01"], HEAD)

    @pytest.mark.parametrize("leaf", sorted(LEAVES))
    def test_the_flag_alone_is_not_enough(self, monkeypatch, leaf):
        monkeypatch.setattr(C, "EXECUTION_ENABLED", True)
        with pytest.raises(C.ExecutionDisabled, match="APPROVED_CALIBRATIONS is empty"):
            LEAVES[leaf](None)
        with pytest.raises(C.ExecutionDisabled, match="APPROVED_CALIBRATIONS is empty"):
            C.authorize(["cal-a-01"], HEAD)

    @pytest.mark.parametrize("leaf", sorted(LEAVES))
    def test_forged_authorizations_are_refused(self, monkeypatch, leaf):
        open_gate(monkeypatch)
        for forged in (None, C.Authorization(("cal-a-01",), HEAD),
                       C.Authorization(("cal-a-01",), HEAD, object()),
                       SimpleNamespace(calibration_ids=("cal-a-01",), expected_head=HEAD)):
            with pytest.raises(C.ExecutionDisabled, match="no valid calibration authorization"):
                LEAVES[leaf](forged)

    def test_authorization_checks(self, monkeypatch):
        open_gate(monkeypatch, ids=("cal-a-01",))
        cases = [(["cal-a-02"], HEAD, "not an approved"),
                 (["cal-a-01", "cal-a-01"], HEAD, "distinct"),
                 ([], HEAD, "distinct"),
                 (["cal-a-01"], "abc123", "full 40"),
                 (["cal-a-01"], None, "full 40"),
                 (["cal-a-01"], "b" * 40, "not the expected")]
        for ids, head, message in cases:
            with pytest.raises(C.ExecutionDisabled, match=message):
                C.authorize(ids, head)
        auth = C.authorize(["cal-a-01"], HEAD)
        assert auth.calibration_ids == ("cal-a-01",) and auth.expected_head == HEAD
        with pytest.raises(C.ExecutionDisabled, match="not covered"):
            C.production_child_deps(auth, 2)

    def test_authorization_dies_with_the_gate(self, monkeypatch):
        open_gate(monkeypatch)
        auth = C.authorize(["cal-a-01"], HEAD)
        monkeypatch.setattr(C, "APPROVED_CALIBRATIONS", frozenset({"cal-a-02"}))
        with pytest.raises(C.ExecutionDisabled, match="not approved: cal-a-01"):
            C._import_driver(auth)
        monkeypatch.setattr(C, "EXECUTION_ENABLED", False)
        with pytest.raises(C.ExecutionDisabled, match="not enabled"):
            C._import_driver(auth)

    def test_production_orchestrator_uses_the_app_container(self, monkeypatch):
        open_gate(monkeypatch)
        deps = C.production_orchestrator_deps(C.authorize(["cal-a-01"], HEAD))
        assert isinstance(deps.launch, C.AppContainerLauncher)
        assert isinstance(deps.launch.api, C.Win32AppContainerApi)
        assert isinstance(deps.launch.api.win32, C.CtypesWin32)
        assert deps.launch.api.win32.loaded_dlls == []           # nothing loaded or called
        assert deps.interpreter == C.base_interpreter() and deps.expected_head == HEAD
        assert not C.is_venv_launcher(deps.interpreter)
        assert deps.python_paths == C.venv_paths()

    def test_cli_refuses_while_disabled(self, tmp_path, capsys):
        assert C.main(["--execute", "--output-dir", str(tmp_path)]) == 2
        assert "not enabled" in capsys.readouterr().err
        assert C.main(["--child", "1", "--output-dir", str(tmp_path), "--token", TOKEN]) == 2
        assert "not enabled" in capsys.readouterr().err
        assert list(tmp_path.iterdir()) == []

    def test_cli_flag_alone_refused(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(C, "EXECUTION_ENABLED", True)
        assert C.main(["--execute", "--runs", "1", "--authorize", "cal-a-01",
                       "--expect-head", HEAD, "--output-dir", str(tmp_path)]) == 2
        assert "APPROVED_CALIBRATIONS is empty" in capsys.readouterr().err
        assert list(tmp_path.iterdir()) == []

    def test_cli_execute_needs_exact_ids(self, tmp_path, monkeypatch, capsys):
        open_gate(monkeypatch, ids=("cal-a-01", "cal-a-02"))
        assert C.main(["--execute", "--runs", "2", "--authorize", "cal-a-01",
                       "--expect-head", HEAD, "--output-dir", str(tmp_path)]) == 2
        assert "exactly the calibration ids" in capsys.readouterr().err
        assert C.main(["--execute", "--runs", "1", "--authorize", "cal-a-01",
                       "--expect-head", "c" * 40, "--output-dir", str(tmp_path)]) == 2
        assert "not the expected" in capsys.readouterr().err
        assert list(tmp_path.iterdir()) == []

    def test_cli_child_needs_the_series_token(self, tmp_path, monkeypatch, capsys):
        open_gate(monkeypatch)
        _own(tmp_path)
        child = ["--child", "1", "--output-dir", str(tmp_path), "--authorize", "cal-a-01",
                 "--expect-head", HEAD]
        assert C.main(child + ["--token", "f" * 32]) == 2
        assert "token does not match" in capsys.readouterr().err
        assert C.main(child) == 2
        assert not (tmp_path / "cal-a-01.json").exists()

    def test_plan_mode_starts_nothing(self, tmp_path):
        out = io.StringIO()
        assert C.main(["--runs", "3", "--output-dir", str(tmp_path / "c")], stdout=out) == 0
        lines = out.getvalue().splitlines()
        assert lines[0].startswith("PLAN ONLY")
        assert [line.split(":")[0] for line in lines if line.startswith("cal-a-")] == [
            "cal-a-01", "cal-a-02", "cal-a-03"]
        assert not (tmp_path / "c").exists()


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------

class TestOwnership:
    def test_claim_is_exclusive_and_records_the_token(self, tmp_path):
        owner, token = _own(tmp_path, runs=2)
        record = _read(owner)
        assert token == TOKEN and record["series_token"] == TOKEN
        assert record["calibration_ids"] == ["cal-a-01", "cal-a-02"]
        with pytest.raises(C.CalibrationError, match="owns this directory"):
            _own(tmp_path)
        with pytest.raises(C.CalibrationError, match="32 lowercase hex"):
            C.claim_series(tmp_path / "x", calibration_ids=["cal-a-01"], expected_head=HEAD,
                           now=time.time, new_token=lambda: "short")

    def test_child_without_ownership_never_starts(self, tmp_path):
        imported = []
        deps = _child_deps(FakeClock(), import_check=lambda: imported.append(1))
        with pytest.raises(C.CalibrationError, match="no ACTIVE_CALIBRATION"):
            C.child_main(1, tmp_path, deps, series_token=TOKEN)
        (tmp_path / C.OWNER_FILE).write_text("{not json", encoding="utf-8")
        with pytest.raises(C.CalibrationError, match="malformed"):
            C.child_main(1, tmp_path, deps, series_token=TOKEN)
        (tmp_path / C.OWNER_FILE).write_text('{"series_token": 1}', encoding="utf-8")
        with pytest.raises(C.CalibrationError, match="malformed"):
            C.child_main(1, tmp_path, deps, series_token=TOKEN)
        assert imported == [] and not (tmp_path / "cal-a-01.json").exists()

    def test_token_mismatch_and_foreign_run(self, tmp_path):
        _own(tmp_path, runs=1)
        deps = _child_deps(FakeClock())
        with pytest.raises(C.CalibrationError, match="token does not match"):
            C.child_main(1, tmp_path, deps, series_token="f" * 32)
        with pytest.raises(C.CalibrationError, match="not part of the owning series"):
            C.child_main(2, tmp_path, deps, series_token=TOKEN)
        assert sorted(p.name for p in tmp_path.iterdir()) == [C.OWNER_FILE]


# ---------------------------------------------------------------------------
# Network guard
# ---------------------------------------------------------------------------

class TestNetworkGuard:
    def test_every_python_target_is_intercepted(self):
        guard = C.NetworkGuard().install()
        try:
            sock = socket.socket.__new__(socket.socket)
            calls = [
                ("__init__", lambda: socket.socket()),
                ("create_connection", lambda: socket.create_connection(("127.0.0.1", 1))),
                ("create_server", lambda: socket.create_server(("127.0.0.1", 0))),
                ("getaddrinfo", lambda: socket.getaddrinfo("example.invalid", 80)),
                ("getnameinfo", lambda: socket.getnameinfo(("127.0.0.1", 80), 0)),
                ("gethostbyname", lambda: socket.gethostbyname("example.invalid")),
                ("gethostbyname_ex", lambda: socket.gethostbyname_ex("example.invalid")),
                ("gethostbyaddr", lambda: socket.gethostbyaddr("127.0.0.1")),
                ("socketpair", lambda: socket.socketpair()),
                ("connect", lambda: socket.socket.connect(sock, ("127.0.0.1", 1))),
                ("connect_ex", lambda: socket.socket.connect_ex(sock, ("127.0.0.1", 1))),
                ("sendto", lambda: socket.socket.sendto(sock, b"x", ("127.0.0.1", 1))),
            ]
            for _, call in calls:
                with pytest.raises(C.NetworkBlocked):
                    call()
            assert [v["operation"] for v in guard.violations] == [n for n, _ in calls]
        finally:
            guard.uninstall()

    def test_uninstall_restores_and_double_install_refused(self):
        before = (socket.getaddrinfo, socket.gethostbyname, socket.socket.__init__,
                  socket.socket.sendto, list(sys.meta_path))
        guard = C.NetworkGuard().install()
        with pytest.raises(C.CalibrationError, match="already installed"):
            guard.install()
        guard.uninstall()
        assert (socket.getaddrinfo, socket.gethostbyname, socket.socket.__init__,
                socket.socket.sendto, list(sys.meta_path)) == before
        assert not guard.installed

    def test_native_network_libraries_are_refusing_stubs(self):
        guard = C.NetworkGuard().install()
        try:
            import grpc
            from confluent_kafka import Producer
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            assert isinstance(grpc, C._NativeStub)
            for call in (lambda: grpc.insecure_channel("localhost:4317"),
                         lambda: Producer({"bootstrap.servers": "localhost:9092"}),
                         lambda: OTLPSpanExporter(endpoint="http://localhost:4317")):
                with pytest.raises(C.NetworkBlocked):
                    call()
            assert [v["arguments"] for v in guard.violations] == [
                "grpc.insecure_channel", "confluent_kafka.Producer",
                "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter"]
            assert "confluent_kafka" in guard.stubbed_imports
        finally:
            guard.uninstall()
        assert not any(isinstance(m, C._NativeStub) for m in sys.modules.values())
        assert not any(C._NativeStubFinder.blocked(n) for n in sys.modules)

    def test_refuses_over_already_loaded_native_libraries(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "grpc", types.ModuleType("grpc"))
        before = socket.getaddrinfo
        with pytest.raises(C.CalibrationError, match="already loaded: grpc"):
            C.NetworkGuard().install()
        assert socket.getaddrinfo is before

    def test_guard_is_installed_before_the_driver_import(self, tmp_path):
        _own(tmp_path)
        seen = {}

        def check():
            seen["socket"] = socket.getaddrinfo.__name__ == "blocked"
            seen["native"] = any(isinstance(f, C._NativeStubFinder) for f in sys.meta_path)

        deps = _child_deps(FakeClock(), import_check=check)
        assert C.child_main(1, tmp_path, deps, series_token=TOKEN) == C.EXIT_OK
        assert seen == {"socket": True, "native": True}
        assert socket.getaddrinfo.__name__ != "blocked"


# ---------------------------------------------------------------------------
# Child runs
# ---------------------------------------------------------------------------

class TestChild:
    def test_completed_run_record(self, tmp_path):
        _own(tmp_path, runs=3)
        clock, calls = FakeClock(), []
        assert C.child_main(3, tmp_path, _child_deps(clock, calls=calls),
                            series_token=TOKEN) == C.EXIT_OK
        record = _read(tmp_path / "cal-a-03.json")
        assert C.result_problems(record, 3, 0) == []
        assert record["plan"] == C.plan_record(3) and record["measured_duration_seconds"] == 20.0
        assert [c[0] for c in calls] == [25, 100]
        for _, kwargs in calls:
            assert kwargs["endpoint"] == "in-memory" and kwargs["concurrency"] == 32
            assert kwargs["span_exporter"] == "memory-exporter"

    @pytest.mark.parametrize("kind", ["socket", "socket-swallowed", "native-swallowed"])
    def test_network_attempt_fails_the_run(self, tmp_path, kind):
        _own(tmp_path)
        calls = []

        def leaking_execute(plan, **kwargs):
            calls.append(plan.traces)
            try:
                if kind.startswith("native"):
                    import grpc
                    grpc.insecure_channel("localhost:4317")
                else:
                    socket.getaddrinfo("collector.example", 4317)
            except OSError:
                if kind == "socket":
                    raise
            return _report(plan.traces)

        status = C.child_main(1, tmp_path, _child_deps(FakeClock(), execute=leaking_execute),
                              series_token=TOKEN)
        record = _read(tmp_path / "cal-a-01.json")
        assert status == C.EXIT_NETWORK and record["status"] == "network_violation"
        assert record["network_guard_violations"]
        assert calls == [25] and record["measured"] is None
        assert C.result_problems(record, 1, status)

    def test_failure_is_recorded_not_retried(self, tmp_path):
        _own(tmp_path)
        calls = []

        def broken(plan, **kwargs):
            calls.append(plan.traces)
            raise RuntimeError("driver failed")

        assert C.child_main(1, tmp_path, _child_deps(FakeClock(), execute=broken),
                            series_token=TOKEN) == C.EXIT_FAILED
        record = _read(tmp_path / "cal-a-01.json")
        assert record["status"] == "failed" and "driver failed" in record["failure"]
        assert calls == [25]

    def test_interruption_still_writes_evidence(self, tmp_path):
        _own(tmp_path)

        def interrupted(plan, **kwargs):
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            C.child_main(1, tmp_path, _child_deps(FakeClock(), execute=interrupted),
                         series_token=TOKEN)
        record = _read(tmp_path / "cal-a-01.json")
        assert record["status"] == "failed" and record["child_exit_status"] == C.EXIT_FAILED

    def test_a_run_is_never_repeated(self, tmp_path):
        _own(tmp_path)
        C.child_main(1, tmp_path, _child_deps(FakeClock()), series_token=TOKEN)
        with pytest.raises(C.CalibrationError, match="never repeated"):
            C.child_main(1, tmp_path, _child_deps(FakeClock()), series_token=TOKEN)


# ---------------------------------------------------------------------------
# Result validation
# ---------------------------------------------------------------------------

def _valid_record(tmp_path):
    _own(tmp_path)
    C.child_main(1, tmp_path, _child_deps(FakeClock()), series_token=TOKEN)
    return _read(tmp_path / "cal-a-01.json")


MUTATIONS = {
    "wrong id": lambda r: r.update(calibration_id="cal-a-02"),
    "failed status": lambda r: r.update(status="failed"),
    "recorded exit differs": lambda r: r.update(child_exit_status=4),
    "concurrency changed": lambda r: r["plan"].update(concurrency=16),
    "seed changed": lambda r: r["plan"]["measured"].update(seed=7),
    "violations": lambda r: r.update(network_guard_violations=[{"operation": "connect"}]),
    "violations missing": lambda r: r.pop("network_guard_violations"),
    "diagnostic incomplete": lambda r: r["measured"].update(diagnostic_usable=False),
    "short measured": lambda r: r["measured"].update(started_requests=99),
    "not started": lambda r: r["warmup"].update(not_started_requests=1),
    "deadline": lambda r: r["measured"].update(run_status="deadline_reached"),
    "no warm-up": lambda r: r.update(warmup=None),
}


class TestResultValidation:
    def test_valid_record(self, tmp_path):
        assert C.result_problems(_valid_record(tmp_path), 1, 0) == []

    @pytest.mark.parametrize("mutation", sorted(MUTATIONS))
    def test_malformed_records_are_rejected(self, tmp_path, mutation):
        record = _valid_record(tmp_path)
        MUTATIONS[mutation](record)
        assert C.result_problems(record, 1, 0)

    def test_exit_code_mismatch_and_non_objects(self, tmp_path):
        record = _valid_record(tmp_path)
        assert any("differs" in p for p in C.result_problems(record, 1, 4))
        assert C.result_problems([], 1, 0) == ["the result is not a JSON object"]


# ---------------------------------------------------------------------------
# Child command and launchers
# ---------------------------------------------------------------------------

def _windows_argv(command_line):
    import ctypes
    from ctypes import wintypes
    parse = ctypes.windll.shell32.CommandLineToArgvW
    parse.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(wintypes.LPWSTR)
    count = ctypes.c_int()
    argv = parse(command_line, ctypes.byref(count))
    try:
        return [argv[i] for i in range(count.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))


class TestChildCommand:
    def _command(self, tmp_path, **kwargs):
        out = tmp_path / "with space" / "cal out"
        args = dict(series_token=TOKEN, expected_head=HEAD, interpreter=SPACED_PYTHON)
        args.update(kwargs)
        return C.build_child_command(2, out, **args), out

    def test_explicit_argv(self, tmp_path):
        command, out = self._command(tmp_path)
        assert command.argv == (
            SPACED_PYTHON, "-B", "-s", str((_BENCH / "calibrate_generator.py").resolve()),
            "--child", "2", "--output-dir", str(out), "--token", TOKEN,
            "--authorize", "cal-a-02", "--expect-head", HEAD)
        assert command.cwd == str(_REPO)
        assert command.stdout_path == out / "cal-a-02.stdout"
        assert command.stderr_path == out / "cal-a-02.stderr"
        assert command.argv_fingerprint == hashlib.sha256(
            command.command_line.encode("utf-8")).hexdigest()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows command-line parsing")
    def test_spaces_survive_windows_quoting(self, tmp_path):
        command, _ = self._command(tmp_path)
        assert " " in command.argv[0] and " " in command.argv[7]
        assert _windows_argv(command.command_line) == list(command.argv)

    def test_environment_is_an_explicit_allowlist(self, tmp_path, monkeypatch):
        for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "PG_PASSWORD", "HTTPS_PROXY",
                     "AGENTOPS_DIRECT_EXPORT", "USERPROFILE"):
            monkeypatch.setenv(name, "x")
        command, out = self._command(tmp_path)
        assert set(command.environment_names) <= {
            "SYSTEMROOT", "SYSTEMDRIVE", "PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE",
            "PYTHONUNBUFFERED", "TEMP", "TMP"}
        assert command.env["TEMP"] == command.env["TMP"] == str(out / "temp" / "cal-a-02")

    @pytest.mark.parametrize("kwargs, message", [
        ({"interpreter": 'C:\\py"thon.exe'}, "unsafe"),
        ({"interpreter": "C:\\100%\\python.exe"}, "unsafe"),
        ({"interpreter": "C:\\a!b\\python.exe"}, "unsafe"),
        ({"series_token": "XYZ"}, "series token"),
        ({"expected_head": "abc"}, "40-character"),
    ])
    def test_unsafe_or_malformed_arguments(self, tmp_path, kwargs, message):
        with pytest.raises(C.CalibrationError, match=message):
            self._command(tmp_path, **kwargs)

    def test_detached_wrapper_keeps_the_verified_form(self, tmp_path):
        text = C.detached_orchestrator_command(
            interpreter=SPACED_PYTHON, runs=2, output_dir=tmp_path / "cal out",
            expected_head=HEAD, log_dir=Path(LOG_DIR))
        assert text.startswith("Start-Process cmd.exe -ArgumentList '/d /s /v:on /c \"")
        assert text.endswith(rf'1>{LOG_DIR}\orchestrator.out '
                             rf'2>{LOG_DIR}\orchestrator.err & '
                             rf'>{LOG_DIR}\orchestrator.exit '
                             "echo exit_code=!errorlevel!\"'")
        assert f'"{SPACED_PYTHON}"' in text and text.count("--authorize") == 2
        with pytest.raises(C.CalibrationError, match="space-free"):
            C.detached_orchestrator_command(interpreter=SPACED_PYTHON, runs=1,
                                            output_dir=tmp_path, expected_head=HEAD,
                                            log_dir=Path("C:/with space"))


GOOD_TOKEN = {"is_app_container": True, "app_container_sid": SID,
              "capabilities": [], "integrity_level": "low", "loopback_exempt": False}
LAUNCH_TOKEN = {**GOOD_TOKEN, "pid": 4242, "image_path": SPACED_PYTHON}


class FakeAppContainerApi:
    def __init__(self, sid=SID, token=None, folder=True, token_error=None, resume_error=None,
                 discard_error=None):
        self.sid, self.token, self.folder = sid, token or dict(LAUNCH_TOKEN), folder
        self.token_error, self.resume_error = token_error, resume_error
        self.discard_error, self.calls = discard_error, []

    def profile_sid(self, name):
        self.calls.append(("profile_sid", name))
        return self.sid

    def profile_folder_present(self, sid):
        self.calls.append(("profile_folder_present", sid))
        return self.folder

    def create_suspended(self, command, sid, capabilities, stdout, stderr):
        self.calls.append(("create_suspended", sid, capabilities))
        return FakeProcess()

    def token_info(self, process):
        self.calls.append(("token_info",))
        if self.token_error:
            raise self.token_error
        return self.token

    def resume(self, process):
        self.calls.append(("resume",))
        if self.resume_error:
            raise self.resume_error

    def discard_suspended(self, process):
        self.calls.append(("discard_suspended",))
        if self.discard_error:
            raise self.discard_error


PREFLIGHT = {"profile_name": C.APPCONTAINER_PROFILE, "app_container_sid": SID,
             "capabilities": [], "loopback_exempt": False,
             "verified_by": "separately authorized profile step",
             "verified_utc": "2026-10-09T10:00:00Z"}


def write_preflight(monkeypatch, directory, record=None, raw=None):
    """An authorized preflight record (its SHA-256 set in memory only)."""
    data = raw if raw is not None else json.dumps(record or PREFLIGHT).encode("utf-8")
    path = Path(directory) / "preflight.json"
    path.write_bytes(data)
    monkeypatch.setattr(C, "AUTHORIZED_PROFILE_PREFLIGHT_SHA256",
                        hashlib.sha256(data).hexdigest())
    return path


class TestAppContainerLauncher:
    def _launch(self, monkeypatch, tmp_path, api, number=1, interpreter=SPACED_PYTHON,
                preflight=None):
        open_gate(monkeypatch)
        monkeypatch.setattr(C, "AUTHORIZED_APPCONTAINER_SID", SID)
        path = preflight if preflight is not None else write_preflight(monkeypatch, tmp_path)
        launcher = C.AppContainerLauncher(C.authorize(["cal-a-01"], HEAD), api,
                                          preflight_path=path)
        command = C.build_child_command(number, tmp_path, series_token=TOKEN,
                                        expected_head=HEAD, interpreter=interpreter)
        return launcher(command, io.BytesIO(), io.BytesIO())

    def test_capability_free_launch(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi()
        assert isinstance(self._launch(monkeypatch, tmp_path, api), FakeProcess)
        assert [c[0] for c in api.calls] == ["profile_sid", "profile_folder_present",
                                             "create_suspended", "token_info", "resume"]
        assert api.calls[0][1] == C.APPCONTAINER_PROFILE and api.calls[2][2] == ()
        assert C.APPCONTAINER_CAPABILITIES == ()

    @pytest.mark.parametrize("change, message", [
        ({"is_app_container": False}, "not in an AppContainer"),
        ({"app_container_sid": "S-1-15-2-1"}, "SID"),
        ({"capabilities": ["S-1-15-3-1"]}, "internetClient"),
        ({"capabilities": ["S-1-15-3-3"]}, "privateNetworkClientServer"),
        ({"capabilities": None}, "unknown"),
        ({"integrity_level": "medium"}, "integrity"),
        ({"loopback_exempt": True}, "loopback"),
        ({"loopback_exempt": None}, "loopback"),
        ({"pid": 999}, "another process"),
        ({"image_path": r"C:\Windows\System32\cmd.exe"}, "intended interpreter"),
    ])
    def test_rejected_token_is_never_resumed(self, monkeypatch, tmp_path, change, message):
        api = FakeAppContainerApi(token={**LAUNCH_TOKEN, **change})
        with pytest.raises(C.LaunchFailure, match=message) as raised:
            self._launch(monkeypatch, tmp_path, api)
        assert "was discarded and confirmed exited" in str(raised.value)
        assert [c[0] for c in api.calls][-1] == "discard_suspended"
        assert ("resume",) not in api.calls

    def test_unreadable_token_is_discarded(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi(token_error=C.Win32Error("OpenProcessToken", 5))
        with pytest.raises(C.LaunchFailure, match="token could not be read"):
            self._launch(monkeypatch, tmp_path, api)
        assert ("resume",) not in api.calls and api.calls[-1] == ("discard_suspended",)

    def test_resume_failure_is_discarded(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi(resume_error=C.CalibrationError("suspend count was 0"))
        with pytest.raises(C.LaunchFailure, match="resume failed"):
            self._launch(monkeypatch, tmp_path, api)
        assert api.calls[-1] == ("discard_suspended",)

    def test_failed_discard_keeps_the_evidence(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi(token={**LAUNCH_TOKEN, "capabilities": ["S-1-15-3-1"]},
                                  discard_error=C.CalibrationError("TerminateProcess failed"))
        with pytest.raises(C.LaunchFailure, match="PID 4242 could not be discarded") as raised:
            self._launch(monkeypatch, tmp_path, api)
        assert "handles are kept" in str(raised.value)
        assert raised.value.evidence["pid"] == 4242

    def test_no_authorized_profile(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi()
        open_gate(monkeypatch)
        launcher = C.AppContainerLauncher(C.authorize(["cal-a-01"], HEAD), api)
        command = C.build_child_command(1, tmp_path, series_token=TOKEN, expected_head=HEAD,
                                        interpreter=SPACED_PYTHON)
        with pytest.raises(C.CalibrationError, match="AUTHORIZED_APPCONTAINER_SID is None"):
            launcher(command, io.BytesIO(), io.BytesIO())
        assert api.calls == []

    def test_preflight_record_is_required(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi()
        open_gate(monkeypatch)
        monkeypatch.setattr(C, "AUTHORIZED_APPCONTAINER_SID", SID)
        assert C.AUTHORIZED_PROFILE_PREFLIGHT_SHA256 is None
        launcher = C.AppContainerLauncher(C.authorize(["cal-a-01"], HEAD), api,
                                          preflight_path=tmp_path / "preflight.json")
        command = C.build_child_command(1, tmp_path, series_token=TOKEN, expected_head=HEAD,
                                        interpreter=SPACED_PYTHON)
        with pytest.raises(C.CalibrationError, match="no profile-preflight record is authorized"):
            launcher(command, io.BytesIO(), io.BytesIO())
        assert api.calls == []
        assert C.AppContainerLauncher(C.authorize(["cal-a-01"], HEAD), api).preflight_path \
            == C.DEFAULT_PROFILE_PREFLIGHT

    @pytest.mark.parametrize("case, message", [
        ("missing", "missing or unreadable"),
        ("tampered", "not the authorized one"),
        ("malformed", "malformed"),
        ("other sid", "another SID"),
        ("capabilities", "capabilities are present"),
        ("loopback", "loopback exemption"),
        ("unattributed", "not attributed"),
        ("incomplete", "fields are missing"),
        ("other profile", "another profile name"),
    ])
    def test_invalid_preflight_blocks_the_launch(self, monkeypatch, tmp_path, case, message):
        records = {"other sid": {**PREFLIGHT, "app_container_sid": "S-1-15-2-7"},
                   "capabilities": {**PREFLIGHT, "capabilities": ["S-1-15-3-1"]},
                   "loopback": {**PREFLIGHT, "loopback_exempt": True},
                   "unattributed": {**PREFLIGHT, "verified_by": " "},
                   "incomplete": {"profile_name": C.APPCONTAINER_PROFILE},
                   "other profile": {**PREFLIGHT, "profile_name": "x"}}
        if case == "malformed":
            path = write_preflight(monkeypatch, tmp_path, raw=b"{not json")
        else:
            path = write_preflight(monkeypatch, tmp_path, records.get(case))
        if case == "missing":
            path.unlink()
        if case == "tampered":
            path.write_bytes(path.read_bytes() + b" ")
        api = FakeAppContainerApi()
        with pytest.raises(C.CalibrationError, match=message):
            self._launch(monkeypatch, tmp_path, api, preflight=path)
        assert api.calls == []

    def test_other_profile_sid_refused(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi(sid="S-1-15-2-7")
        with pytest.raises(C.CalibrationError, match="not the authorized one"):
            self._launch(monkeypatch, tmp_path, api)
        assert [c[0] for c in api.calls] == ["profile_sid"]

    def test_missing_folder_blocks_without_claiming_existence(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi(folder=False)
        with pytest.raises(C.CalibrationError, match="not proof either way") as raised:
            self._launch(monkeypatch, tmp_path, api)
        assert "its own authorization" in str(raised.value)
        assert [c[0] for c in api.calls] == ["profile_sid", "profile_folder_present"]

    def test_venv_launcher_refused(self, monkeypatch, tmp_path):
        venv = tmp_path / "my venv"
        (venv / "Scripts").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = x\n")
        launcher_path = str(venv / "Scripts" / "python.exe")
        assert C.is_venv_launcher(launcher_path)
        api = FakeAppContainerApi()
        with pytest.raises(C.CalibrationError, match="not the venv launcher"):
            self._launch(monkeypatch, tmp_path, api, interpreter=launcher_path)
        assert api.calls == []

    def test_capabilities_constant_is_enforced(self, monkeypatch, tmp_path):
        monkeypatch.setattr(C, "APPCONTAINER_CAPABILITIES", ("S-1-15-3-1",))
        api = FakeAppContainerApi()
        with pytest.raises(C.CalibrationError, match="no capabilities"):
            self._launch(monkeypatch, tmp_path, api)
        assert api.calls == []

    def test_unauthorized_run_is_refused(self, monkeypatch, tmp_path):
        api = FakeAppContainerApi()
        with pytest.raises(C.ExecutionDisabled, match="not covered"):
            self._launch(monkeypatch, tmp_path, api, number=2)
        assert api.calls == []

    def test_token_validation_is_pure(self):
        assert C.validate_app_container_token(GOOD_TOKEN, SID) == []
        assert C.validate_app_container_token(None, SID) == ["no token information"]
        assert "no AppContainer profile is authorized" in C.validate_app_container_token(
            GOOD_TOKEN, None)
        assert C.validate_app_container_token({**GOOD_TOKEN, "loopback_exempt": None}, SID,
                                              check_loopback=False) == []
        assert C.validate_app_container_token(LAUNCH_TOKEN, SID, expected_pid=4242,
                                              expected_image=SPACED_PYTHON.upper()) == []


# ---------------------------------------------------------------------------
# OS-level observation
# ---------------------------------------------------------------------------

PROC = f"proc 4242 1 {CREATED}"


class TestObservation:
    def test_script_fails_closed(self):
        script = C.observation_script(4242)
        assert "$ErrorActionPreference = 'Stop'" in script and "SilentlyContinue" not in script
        assert "exit 1" in script and "CreationDate -ge $root.CreationDate" in script
        assert "Get-NetTCPConnection" in script and "Get-NetUDPEndpoint" in script

    def test_clean_observation(self):
        seen = C.parse_observation(0, PROC + "\nproc 4300 4242 " + CREATED + "\n", "", IDENTITY)
        assert seen.problems == [] and seen.root_present and len(seen.processes) == 2

    @pytest.mark.parametrize("code, out, err, message", [
        (1, PROC, "", "exited with 1"),
        (0, PROC, "Access is denied", "stderr"),
        (0, "", "", "identity is missing"),
        (0, "proc 4242 1 2026-10-09T09:00:00.000Z", "", "another process"),
        (0, "proc 4242", "", "malformed"),
        (0, PROC + "\nsomething else", "", "unexpected"),
        (0, PROC + "\ntcp 127.0.0.1:50000 127.0.0.1:4317 Established", "", "endpoints"),
        (0, PROC + "\nudp 0.0.0.0:5353", "", "endpoints"),
        (0, PROC + "\ndll 4242 librdkafka.dll", "", "native network libraries"),
    ])
    def test_problems(self, code, out, err, message):
        seen = C.parse_observation(code, out, err, IDENTITY)
        assert any(message in p for p in seen.problems), seen.problems

    def test_root_missing_is_left_to_the_orchestrator(self):
        seen = C.parse_observation(0, "root-missing", "", IDENTITY)
        assert seen.problems == [] and seen.root_present is False

    def test_observe_process_failures(self, monkeypatch):
        open_gate(monkeypatch)
        auth = C.authorize(["cal-a-01"], HEAD)

        def timeout(script, limit):
            raise subprocess.TimeoutExpired("powershell", limit)

        def denied(script, limit):
            raise PermissionError("denied")

        assert C.observe_process(auth, IDENTITY, runner=timeout).problems == [
            "observation timed out"]
        assert "PermissionError" in C.observe_process(auth, IDENTITY, runner=denied).problems[0]
        ok = C.observe_process(auth, IDENTITY, runner=lambda s, t: (0, PROC, ""))
        assert ok.problems == [] and ok.root_present


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _series_record(directory):
    records = list(Path(directory).glob("series-a-*.json"))
    assert len(records) == 1
    return _read(records[0])


def _journal(directory, stage, run):
    return C._journal_path(directory, stage, run)


class TestOrchestrator:
    def test_clean_series(self, tmp_path):
        clock = FakeClock()
        deps, launched = _orchestrator(clock, [real_child()] * 3)
        outcome = C.run_series(3, tmp_path, deps)
        assert outcome.completed == 3 and outcome.stopped_reason is None
        assert outcome.ownership_released and not (tmp_path / C.OWNER_FILE).exists()
        assert [c.calibration_id for c in launched] == ["cal-a-01", "cal-a-02", "cal-a-03"]
        assert clock.pauses.count(C.REST_SECONDS) == 2
        for number in (1, 2, 3):
            for stage in ("launch", "process", "complete"):
                assert _journal(tmp_path, stage, number).exists()
            complete = _read(_journal(tmp_path, "complete", number))
            assert complete["exit_status"] == 0 and complete["pid"] == 4242
            assert complete["creation_time"] == CREATED and complete["samples"] >= 1
            assert complete["argv_fingerprint"] == launched[number - 1].argv_fingerprint
            assert "PATH" in complete["environment_names"] and complete["stop_reason"] is None
            assert (tmp_path / f"cal-a-0{number}.stdout").exists()
        record = _series_record(tmp_path)
        assert record["ownership"] == "released" and "cannot prove" in record["note"]

    def test_existing_ownership_refused(self, tmp_path):
        (tmp_path / C.OWNER_FILE).write_text("{}")
        deps, launched = _orchestrator(FakeClock(), [real_child()])
        with pytest.raises(C.CalibrationError, match="owns this directory"):
            C.run_series(1, tmp_path, deps)
        assert launched == []

    @pytest.mark.parametrize("existing", ["cal-a-02.json", "journal/launch-02.json"])
    def test_existing_evidence_refused_before_ownership(self, tmp_path, existing):
        (tmp_path / existing).parent.mkdir(exist_ok=True)
        (tmp_path / existing).write_text("{}")
        deps, launched = _orchestrator(FakeClock(), [real_child()] * 3)
        with pytest.raises(C.CalibrationError, match="never repeated"):
            C.run_series(3, tmp_path, deps)
        assert launched == [] and not (tmp_path / C.OWNER_FILE).exists()

    def _stopped(self, tmp_path, makers, runs=3, **kwargs):
        clock = FakeClock()
        deps, launched = _orchestrator(clock, makers, **kwargs)
        outcome = C.run_series(runs, tmp_path, deps)
        assert outcome.stopped_reason and not outcome.ownership_released
        assert (tmp_path / C.OWNER_FILE).exists()
        assert _series_record(tmp_path)["ownership"] == "retained for review"
        assert len(launched) == 1                      # never retried, nothing after
        return outcome

    def test_nonzero_child_stops(self, tmp_path):
        def broken(plan, **kwargs):
            raise RuntimeError("boom")

        outcome = self._stopped(tmp_path, [real_child(execute=broken), real_child()])
        assert "result rejected" in outcome.stopped_reason
        assert _read(_journal(tmp_path, "complete", 1))["exit_status"] == C.EXIT_FAILED

    def test_exit_code_mismatch_stops(self, tmp_path):
        def broken(plan, **kwargs):
            raise RuntimeError("boom")

        outcome = self._stopped(tmp_path, [real_child(execute=broken, returncode=0)] * 2)
        assert "result rejected" in outcome.stopped_reason

    @pytest.mark.parametrize("content", ["{}", "not json", "[]"])
    def test_malformed_result_stops(self, tmp_path, content):
        outcome = self._stopped(tmp_path, [real_child(
            write=lambda p: p.write_text(content, encoding="utf-8"))] * 2)
        assert "result rejected" in outcome.stopped_reason

    def test_missing_result_stops(self, tmp_path):
        outcome = self._stopped(tmp_path, [real_child(write=lambda p: None)] * 2)
        assert "no result file" in outcome.stopped_reason

    def test_timeout_preserves_the_child(self, tmp_path):
        hung = FakeProcess(polls=None, pid=5150)
        outcome = self._stopped(tmp_path, [lambda c: hung, real_child()])
        assert "PID 5150" in outcome.stopped_reason and CREATED in outcome.stopped_reason
        assert "not terminated" in outcome.stopped_reason and not hung.killed
        complete = _read(_journal(tmp_path, "complete", 1))
        assert complete["child_left_running"] and complete["exit_status"] is None
        assert _read(_journal(tmp_path, "process", 1))["pid"] == 5150

    @pytest.mark.parametrize("observe, message", [
        (lambda i: C.Observation(["observation stderr: Access is denied"], [], [], False),
         "failed closed"),
        (lambda i: C.Observation(["observation timed out"], [], [], False), "failed closed"),
        (lambda i: C.Observation([], [], [], False), "identity is missing"),
        (lambda i: C.Observation(["network endpoints or native network libraries observed"],
                                 ["tcp 127.0.0.1:50000 127.0.0.1:9092 Established"], [PROC],
                                 True), "network endpoints"),
    ])
    def test_observation_failures_stop(self, tmp_path, observe, message):
        alive = FakeProcess(polls=None)
        outcome = self._stopped(tmp_path, [lambda c: alive, real_child()], observe=observe)
        assert message in outcome.stopped_reason and not alive.killed
        assert _read(_journal(tmp_path, "complete", 1))["child_left_running"]

    def test_observation_exception_stops(self, tmp_path):
        def raising(identity):
            raise RuntimeError("cim failure")

        outcome = self._stopped(tmp_path, [lambda c: FakeProcess(polls=None), real_child()],
                                observe=raising)
        assert "observation raised RuntimeError" in outcome.stopped_reason

    def test_missing_identity_at_exit_is_not_a_failure(self, tmp_path):
        state = {"n": 0}

        def observe(identity):
            state["n"] += 1
            return good_observe(identity) if state["n"] == 1 else C.Observation(
                [], [], [], False)

        deps, _ = _orchestrator(FakeClock(), [real_child(polls=2)], observe=observe)
        outcome = C.run_series(1, tmp_path, deps)
        assert outcome.stopped_reason is None and outcome.ownership_released

    def test_insufficient_sampling_stops(self, tmp_path):
        clock = FakeClock()

        def slow(identity):
            clock.now += C.MAX_SAMPLE_GAP_SECONDS + 1
            return good_observe(identity)

        deps, launched = _orchestrator(clock, [real_child(polls=3)] * 2, observe=slow)
        outcome = C.run_series(2, tmp_path, deps)
        assert "insufficient sampling" in outcome.stopped_reason and len(launched) == 1

    def test_no_observation_at_all_stops(self, tmp_path):
        outcome = self._stopped(tmp_path, [real_child(polls=0)] * 2)
        assert "no observation" in outcome.stopped_reason

    def test_launch_failure_is_recorded(self, tmp_path):
        def failing(command):
            raise OSError("CreateProcess failed")

        outcome = self._stopped(tmp_path, [failing, real_child()])
        assert "launch failed" in outcome.stopped_reason
        assert _journal(tmp_path, "launch", 1).exists()
        assert not _journal(tmp_path, "process", 1).exists()
        assert _read(_journal(tmp_path, "complete", 1))["pid"] is None

    def test_interruption_keeps_ownership_and_writes_the_record(self, tmp_path):
        def interrupted(command):
            raise KeyboardInterrupt

        deps, launched = _orchestrator(FakeClock(), [interrupted, real_child()])
        with pytest.raises(KeyboardInterrupt):
            C.run_series(2, tmp_path, deps)
        record = _series_record(tmp_path)
        assert record["stopped_reason"] == "series interrupted: KeyboardInterrupt"
        assert record["ownership"] == "retained for review"
        assert (tmp_path / C.OWNER_FILE).exists() and len(launched) == 1

    def test_crash_before_the_first_child(self, tmp_path):
        (tmp_path / "cal-a-01.stdout").write_text("")       # exclusive output refused
        deps, launched = _orchestrator(FakeClock(), [real_child()])
        outcome = C.run_series(1, tmp_path, deps)
        assert "series failed: FileExistsError" in outcome.stopped_reason
        assert launched == [] and (tmp_path / C.OWNER_FILE).exists()
        assert _series_record(tmp_path)["ownership"] == "retained for review"

    def test_series_bounds(self, tmp_path):
        for runs in (0, 21, True):
            with pytest.raises(C.CalibrationError):
                C.run_series(runs, tmp_path, _orchestrator(FakeClock(), [])[0])


# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

class TestOutputPaths:
    @pytest.mark.parametrize("path", [
        _REPO, _REPO / "benchmarks", _REPO / "x" / "y",
        RB.DEFAULT_OUTPUT, RB.DEFAULT_OUTPUT / "ledger",
        Path(os.environ.get("TEMP", "C:/tmp")) / "agentops-benchmarks" / "cal",
    ])
    def test_forbidden_locations(self, path):
        with pytest.raises(C.CalibrationError, match="never written inside"):
            C.check_output_dir(path)

    def test_default_is_separate(self):
        C.check_output_dir(C.DEFAULT_OUTPUT)
        assert C.DEFAULT_OUTPUT.name == "agentops-calibration"


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _rep3_like_entries():
    _, measured = C.build_plans(1)
    offsets = [r.arrival_offset_seconds for r in measured.requests]
    lags = [0.0005] * 100
    for index, dispatch in ((19, offsets[19] + 0.0611), (53, offsets[53] + 0.0915),
                            (98, offsets[98] + 0.1402)):
        lags[index] = dispatch - offsets[index]
    group_end = offsets[47] + 0.1398
    for index in range(47, 52):
        lags[index] = group_end - offsets[index]
    return [[i, round(offsets[i], 6), round(lags[i], 6)] for i in range(100)]


class TestAnalysis:
    def test_groups_propagation_and_isolated(self):
        groups = C.stall_groups(_rep3_like_entries())
        assert [g["request_indices"] for g in groups] == [[19], [47, 48, 49, 50, 51], [53], [98]]
        assert [g["propagated"] for g in groups] == [False, True, False, False]

    def test_burst_association(self):
        result = C.burst_association(_rep3_like_entries())
        assert result["requests"] == 100 and result["late"] == 2
        assert result["requests_in_bursts"] == 29 and result["late_in_bursts"] == 0

    def test_summary_percentiles_and_late_indices(self):
        entries = _rep3_like_entries()
        report = _report(100, late=2, lags=[e[2] for e in entries]).to_dict()
        report["start_lags"]["entries"] = entries
        record = C.summarize_stage(report)
        lags = [e[2] for e in entries]
        assert record["late_request_indices"] == [47, 98]
        assert record["start_lag_percentiles"]["p95"] == round(M.percentile(lags, 95), 6)
        assert record["late_start_percent"] == 2.0 and record["diagnostic_usable"]

    @pytest.mark.parametrize("lags, reason", [
        (None, "no start-lag diagnostic"),
        ({"limit": 10000, "expected": 2, "recorded": 1, "complete": False,
          "truncated_reason": "limit", "entries": [[0, 0.0, 0.1]]}, "incomplete"),
        ({"entries": []}, "malformed"),
    ])
    def test_unusable_diagnostic_gives_no_numbers(self, lags, reason):
        record = C.summarize_stage({"started_requests": 2, "late_starts": 0,
                                    "start_lags": lags})
        assert not record["diagnostic_usable"] and reason in " ".join(
            record["diagnostic_problems"])
        for key in ("start_lag_percentiles", "late_request_indices", "stall_groups",
                    "burst_association"):
            assert record[key] is None

    def test_distribution_is_an_observation(self):
        runs = [{"status": "completed", "measured": {"late_start_percent": p,
                                                     "stall_groups": []}}
                for p in (0.0, 2.0, 10.0)] + [{"status": "failed", "measured": None}]
        dist = C.distribution(runs)
        assert dist == {"runs": 3, "median_late_percent": 2.0, "min_late_percent": 0.0,
                        "max_late_percent": 10.0, "runs_over_rule": 1, "stall_groups": 0,
                        "propagated_groups": 0, "kind": "OBSERVATION"}


# ---------------------------------------------------------------------------
# Unchanged benchmark code
# ---------------------------------------------------------------------------

class TestScope:
    def test_benchmark_authorization_and_rules_unchanged(self):
        # The allowlist has grown since this test was first written (it had pinned only the
        # first two SMOKE cells); it now names every approved cell, rep5 being the diagnostic.
        assert sorted(RB.APPROVED_LIVE_CELLS) == [
            "bm-small-r0010-c32-rep1", "bm-small-r0010-c32-rep2", "bm-small-r0010-c32-rep3",
            "bm-small-r0010-c32-rep4", "bm-small-r0010-c32-rep5", "bm-small-r0010-c32-rep6",
            "bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8", "bm-small-r0010-c32-rep9",
            "bm-smoke-r0005-c32-rep2", "bm-smoke-r0005-c32-rep3", "bm-smoke-r0005-c32-rep4",
            "bm-smoke-r0005-c32-rep5"]
        assert RB.DRIVER_LATE_START_SECONDS == 0.1 and M.LATE_START_FRACTION == 0.05
        assert RB.OWNER_FILE == "ACTIVE_RUN" and C.OWNER_FILE == "ACTIVE_CALIBRATION"

    def test_benchmark_directory_untouched_by_the_harness(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8").split('"""', 2)[2]
        assert "ACTIVE_RUN" not in code and "ledger" not in code.lower()

    def test_gates_closed_in_source(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        assert "\nEXECUTION_ENABLED: bool = False\n" in code
        assert "\nAPPROVED_CALIBRATIONS: frozenset[str] = frozenset()\n" in code
        assert "\nPROBE_ENABLED: bool = False\n" in code
        assert "\nAPPROVED_PROBES: frozenset[str] = frozenset()\n" in code
        assert "\nAUTHORIZED_APPCONTAINER_SID: Optional[str] = None\n" in code
        assert "\nAUTHORIZED_PROFILE_PREFLIGHT_SHA256: Optional[str] = None\n" in code
        assert (C.PROBE_ENABLED, C.APPROVED_PROBES, C.AUTHORIZED_APPCONTAINER_SID,
                C.AUTHORIZED_PROFILE_PREFLIGHT_SHA256) == (False, frozenset(), None, None)

    def test_no_profile_or_acl_changes_in_the_source(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8").split('"""', 2)[2]
        for word in ("CreateAppContainerProfile(", "DeleteAppContainerProfile(", "icacls ",
                     "SetNamedSecurityInfo", "SetFileSecurity", "NetworkIsolationSet",
                     "netsh", "New-NetFirewallRule"):
            assert word not in code, word


# ---------------------------------------------------------------------------
# Isolation probe gates
# ---------------------------------------------------------------------------

class TestProbeGates:
    def test_probe_refuses_while_disabled(self):
        with pytest.raises(C.ExecutionDisabled, match="isolation probe is not enabled"):
            C.authorize_probe("probe-01", HEAD)

    @pytest.mark.parametrize("leaf", sorted(PROBE_LEAVES))
    def test_probe_leaves_refuse_while_disabled(self, leaf):
        with pytest.raises(C.ExecutionDisabled, match="isolation probe is not enabled"):
            PROBE_LEAVES[leaf](None)

    @pytest.mark.parametrize("leaf", sorted(PROBE_LEAVES))
    def test_probe_flag_alone_is_not_enough(self, monkeypatch, leaf):
        monkeypatch.setattr(C, "PROBE_ENABLED", True)
        with pytest.raises(C.ExecutionDisabled, match="APPROVED_PROBES is empty"):
            PROBE_LEAVES[leaf](None)
        with pytest.raises(C.ExecutionDisabled, match="APPROVED_PROBES is empty"):
            C.authorize_probe("probe-01", HEAD)

    def test_the_gates_are_independent(self, monkeypatch):
        open_gate(monkeypatch)
        with pytest.raises(C.ExecutionDisabled, match="isolation probe is not enabled"):
            C.authorize_probe("probe-01", HEAD)
        monkeypatch.setattr(C, "EXECUTION_ENABLED", False)
        open_probe_gate(monkeypatch)
        with pytest.raises(C.ExecutionDisabled, match="real calibration is not enabled"):
            C.authorize(["cal-a-01"], HEAD)

    def test_a_probe_authorization_never_reaches_the_driver(self, monkeypatch):
        open_gate(monkeypatch)
        open_probe_gate(monkeypatch)
        probe = C.authorize_probe("probe-01", HEAD)
        for leaf in ("_import_driver", "_memory_exporter", "production_child_deps",
                     "production_orchestrator_deps"):
            with pytest.raises(C.ExecutionDisabled, match="no valid calibration authorization"):
                LEAVES[leaf](probe)
        calibration = C.authorize(["cal-a-01"], HEAD)
        for leaf in sorted(PROBE_LEAVES):
            with pytest.raises(C.ExecutionDisabled, match="no valid probe authorization"):
                PROBE_LEAVES[leaf](calibration)

    def test_probe_authorization_checks(self, monkeypatch):
        open_probe_gate(monkeypatch)
        for probe_id, head, message in (("probe-02", HEAD, "not an approved probe"),
                                        ("probe-9", HEAD, "probe-01 .. probe-05"),
                                        (None, HEAD, "probe-01 .. probe-05"),
                                        ("probe-01", "abc", "full 40"),
                                        ("probe-01", "b" * 40, "not the expected")):
            with pytest.raises(C.ExecutionDisabled, match=message):
                C.authorize_probe(probe_id, head)
        auth = C.authorize_probe("probe-01", HEAD)
        assert auth.probe_id == "probe-01"
        for forged in (C.ProbeAuthorization("probe-01", HEAD),
                       C.ProbeAuthorization("probe-01", HEAD, object())):
            with pytest.raises(C.ExecutionDisabled, match="no valid probe authorization"):
                C.production_probe_deps(forged)
        monkeypatch.setattr(C, "PROBE_ENABLED", False)
        with pytest.raises(C.ExecutionDisabled, match="not enabled"):
            C.production_probe_deps(auth)

    def test_cli_probe_refused_while_disabled(self, tmp_path, capsys):
        assert C.main(["--probe", "probe-01", "--expect-head", HEAD,
                       "--output-dir", str(tmp_path)]) == 2
        assert "isolation probe is not enabled" in capsys.readouterr().err
        assert C.main(["--probe-child", "probe-01", "--expect-head", HEAD, "--token", TOKEN,
                       "--port", "50123", "--output-dir", str(tmp_path)]) == 2
        assert "isolation probe is not enabled" in capsys.readouterr().err
        assert list(tmp_path.iterdir()) == []

    def test_production_probe_wiring(self, monkeypatch):
        open_probe_gate(monkeypatch)
        deps = C.production_probe_deps(C.authorize_probe("probe-01", HEAD))
        assert isinstance(deps.launch, C.AppContainerLauncher)
        assert isinstance(deps.launch.api.win32, C.CtypesWin32)
        assert deps.launch.api.win32.loaded_dlls == []
        assert deps.interpreter == C.base_interpreter()
        child = C.production_probe_child_deps(C.authorize_probe("probe-01", HEAD))
        assert child.import_module is importlib.import_module


# ---------------------------------------------------------------------------
# Git HEAD without a git process
# ---------------------------------------------------------------------------

SHA2 = "b" * 40


def _gitdir(root, head, refs=None, packed=None):
    git = root / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(head + "\n")
    for ref, sha in (refs or {}).items():
        path = git.joinpath(*ref.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sha + "\n")
    if packed:
        (git / "packed-refs").write_text(packed)
    return git


class TestGitHead:
    def test_this_repository(self):
        assert C._HEAD_RE.fullmatch(C._read_git_head(_REPO))

    def test_detached_loose_nested_and_packed(self, tmp_path):
        _gitdir(tmp_path / "a", HEAD)
        _gitdir(tmp_path / "b", "ref: refs/heads/claude/x", {"refs/heads/claude/x": SHA2})
        _gitdir(tmp_path / "c", "ref: refs/heads/main",
                packed=f"# pack-refs with: peeled\n{SHA2} refs/heads/main\n^{HEAD}\n")
        assert C._read_git_head(tmp_path / "a") == HEAD
        assert C._read_git_head(tmp_path / "b") == SHA2
        assert C._read_git_head(tmp_path / "c") == SHA2

    def test_worktree(self, tmp_path):
        main = _gitdir(tmp_path / "main", "ref: refs/heads/main", {"refs/heads/w": SHA2})
        wt = main / "worktrees" / "w"
        wt.mkdir(parents=True)
        (wt / "HEAD").write_text("ref: refs/heads/w\n")
        (wt / "commondir").write_text("../..\n")
        (tmp_path / "w").mkdir()
        (tmp_path / "w" / ".git").write_text(f"gitdir: {wt}\n")
        assert C._read_git_head(tmp_path / "w") == SHA2

    @pytest.mark.parametrize("head, refs", [
        ("ref: refs/heads/gone", {}),
        ("ref: refs/heads/main", {"refs/heads/main": "not-a-sha"}),
        ("garbage", {}),
    ])
    def test_unresolvable(self, tmp_path, head, refs):
        _gitdir(tmp_path, head, refs)
        with pytest.raises(C.ExecutionDisabled, match="cannot be resolved"):
            C._read_git_head(tmp_path)

    def test_no_repository(self, tmp_path):
        with pytest.raises(C.ExecutionDisabled, match="cannot be resolved"):
            C._read_git_head(tmp_path)


# ---------------------------------------------------------------------------
# Interpreter, environment block and Win32 helpers
# ---------------------------------------------------------------------------

class TestWin32Helpers:
    def test_base_interpreter_is_not_the_venv_launcher(self):
        assert not C.is_venv_launcher(C.base_interpreter())
        if sys.prefix != sys.base_prefix:
            assert C.is_venv_launcher(sys.executable)

    def test_venv_paths_reach_the_child(self, tmp_path):
        command = C.build_child_command(1, tmp_path, series_token=TOKEN, expected_head=HEAD,
                                        interpreter=SPACED_PYTHON,
                                        python_paths=(r"C:\my venv\Lib\site-packages",))
        assert command.env["PYTHONPATH"].split(os.pathsep)[-1] == \
            r"C:\my venv\Lib\site-packages"
        with pytest.raises(C.CalibrationError, match="unsafe"):
            C.build_child_command(1, tmp_path, series_token=TOKEN, expected_head=HEAD,
                                  interpreter=SPACED_PYTHON, python_paths=("C:\\a%b",))

    def test_environment_block(self):
        block = C.environment_block({"b": "2", "A": "1", "PATH": r"C:\x y"})
        assert block == "A=1\0b=2\0PATH=C:\\x y\0"
        for bad in ({"": "x"}, {"A=B": "x"}, {"A": "x\0y"}, {}):
            with pytest.raises(C.CalibrationError):
                C.environment_block(bad)

    def test_filetime_and_integrity(self):
        from datetime import datetime, timezone
        epoch = int(datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc).timestamp())
        ticks = (epoch + 11644473600) * 10_000_000 + 1_230_000
        assert C._filetime_iso(ticks & 0xFFFFFFFF, ticks >> 32) == "2026-10-09T10:00:00.123Z"
        assert C._integrity_name("S-1-16-4096") == "low"
        assert C._integrity_name("S-1-16-8192") == "medium"
        assert C._integrity_name("S-1-16-12288") == "high" and C._integrity_name(None) is None

    def test_handle_validity(self):
        assert C._valid_handle(101) and not C._valid_handle(0)
        for bad in (None, -1, (1 << 64) - 1, (1 << 32) - 1, True):
            assert not C._valid_handle(bad)

    def test_documented_structure_layouts(self):
        t = C._win32_types()
        c = t.ctypes
        if c.sizeof(c.c_void_p) == 8:
            assert c.sizeof(t.STARTUPINFOEXW) == 112 and c.sizeof(t.PROCESS_INFORMATION) == 24
            assert c.sizeof(t.SECURITY_CAPABILITIES) == 24
            assert t.TOKEN_GROUPS.Groups.offset == 8 and c.sizeof(t.SID_AND_ATTRIBUTES) == 16
        assert set(dll for dll, _, _ in C._signatures(t).values()) == set(C.WIN32_DLLS)
        assert C.CREATION_FLAGS & C.CREATE_SUSPENDED
        assert C.CREATION_FLAGS & C.EXTENDED_STARTUPINFO_PRESENT


# ---------------------------------------------------------------------------
# Win32 backend logic (mocked primitive layer)
# ---------------------------------------------------------------------------

class FakeWin32:
    def __init__(self, **overrides):
        self.calls = []
        self.handles = C.Win32Handles(101, 102, 4242, 77)
        self.pid, self.previous, self.waits = 4242, 1, [True]
        self.code, self.exempt, self.fail = C.DISCARD_EXIT_CODE, [], {}
        self.token = {"is_app_container": True, "app_container_sid": SID, "capabilities": [],
                      "integrity_level": "low"}
        self.__dict__.update(overrides)

    def _record(self, name, *args):
        self.calls.append((name, *args))
        if name in self.fail:
            raise self.fail[name]

    def derive_sid(self, name):
        self._record("derive_sid", name)
        return SID

    def profile_folder(self, sid):
        self._record("profile_folder", sid)
        return r"C:\Users\x\AppData\Local\Packages\p"

    def create_process(self, **kwargs):
        self._record("create_process")
        self.created = kwargs
        return self.handles

    def process_id(self, handle):
        self._record("process_id", handle)
        return self.pid

    def creation_time(self, handle):
        self._record("creation_time", handle)
        return CREATED

    def image_path(self, handle):
        self._record("image_path", handle)
        return SPACED_PYTHON

    def token_info(self, handle):
        self._record("token_info", handle)
        return dict(self.token)

    def loopback_exempt_sids(self):
        self._record("loopback_exempt_sids")
        return list(self.exempt)

    def resume(self, thread):
        self._record("resume", thread)
        return self.previous

    def terminate(self, handle, code):
        self._record("terminate", handle, code)

    def wait(self, handle, milliseconds):
        self._record("wait", handle, milliseconds)
        return self.waits.pop(0) if self.waits else True

    def exit_code(self, handle):
        self._record("exit_code", handle)
        return self.code

    def close(self, handle):
        self._record("close", handle)


class TestWin32Backend:
    def _launch(self, monkeypatch, tmp_path, win32):
        open_probe_gate(monkeypatch)
        auth = C.authorize_probe("probe-01", HEAD)
        api = C.Win32AppContainerApi(auth, win32=win32)
        command = C.build_probe_command("probe-01", tmp_path, series_token=TOKEN,
                                        expected_head=HEAD, interpreter=SPACED_PYTHON,
                                        port=50123)
        launcher = C.AppContainerLauncher(auth, api,
                                          preflight_path=write_preflight(monkeypatch, tmp_path))
        return launcher(command, 1, 2), command

    def _names(self, win32):
        return [c[0] for c in win32.calls]

    def test_validated_launch(self, monkeypatch, tmp_path):
        win32 = FakeWin32()
        process, command = self._launch(monkeypatch, tmp_path, win32)
        assert isinstance(process, C.Win32Process) and process.resumed
        assert process.pid == 4242 and process.creation_time == CREATED
        assert process.resume_previous_count == 1
        assert process.execution_history == C.MAY_HAVE_EXECUTED
        assert process.liveness == C.ALIVE_AT_LAST_CHECK
        assert self._names(win32) == [
            "derive_sid", "profile_folder", "create_process", "process_id", "creation_time",
            "image_path", "token_info", "loopback_exempt_sids", "process_id", "resume", "close"]
        assert win32.calls[-1] == ("close", 102)                 # thread handle after resume
        assert win32.created == {"application": SPACED_PYTHON,
                                 "command_line": command.command_line, "env": command.env,
                                 "cwd": str(_REPO), "stdout": 1, "stderr": 2, "sid": SID}
        assert "terminate" not in self._names(win32)

    def test_exit_status_is_the_real_one(self, monkeypatch, tmp_path):
        win32 = FakeWin32()
        process, _ = self._launch(monkeypatch, tmp_path, win32)
        win32.waits, win32.code = [False, True], 3
        assert process.poll() is None and process.liveness == C.ALIVE_AT_LAST_CHECK
        assert process.poll() == 3 and process.returncode == 3
        assert process.liveness == C.CONFIRMED_EXITED
        assert process.execution_history == C.MAY_HAVE_EXECUTED
        assert win32.calls[-1] == ("close", 101) and process.poll() == 3

    @pytest.mark.parametrize("change, message", [
        ({"token": {"is_app_container": True, "app_container_sid": "S-1-15-2-1",
                    "capabilities": [], "integrity_level": "low"}}, "SID"),
        ({"token": {"is_app_container": True, "app_container_sid": SID,
                    "capabilities": ["S-1-15-3-1"], "integrity_level": "low"}},
         "internetClient"),
        ({"token": {"is_app_container": False, "app_container_sid": None,
                    "capabilities": [], "integrity_level": "medium"}}, "not in an AppContainer"),
        ({"exempt": [SID]}, "loopback"),
        ({"fail": {"token_info": C.Win32Error("GetTokenInformation", 87)}},
         "token could not be read"),
    ])
    def test_rejection_before_resume_never_executed(self, monkeypatch, tmp_path, change,
                                                    message):
        win32 = FakeWin32(**change)
        with pytest.raises(C.LaunchFailure, match=message) as raised:
            self._launch(monkeypatch, tmp_path, win32)
        evidence = raised.value.evidence
        assert evidence["execution_history"] == C.NEVER_EXECUTED
        assert evidence["liveness"] == C.CONFIRMED_EXITED and not evidence["handles_retained"]
        assert ("terminate", 101, C.DISCARD_EXIT_CODE) in win32.calls
        assert ("wait", 101, C.DISCARD_WAIT_MILLISECONDS) in win32.calls
        assert ("close", 101) in win32.calls and "resume" not in self._names(win32)

    @pytest.mark.parametrize("previous, history", [
        (0, C.MAY_HAVE_EXECUTED), (2, C.NEVER_EXECUTED), (7, C.NEVER_EXECUTED)])
    def test_resume_count_edge_cases(self, monkeypatch, tmp_path, previous, history):
        win32 = FakeWin32(previous=previous)
        with pytest.raises(C.LaunchFailure, match=f"suspend count was {previous}") as raised:
            self._launch(monkeypatch, tmp_path, win32)
        evidence = raised.value.evidence
        assert evidence["execution_history"] == history         # never improved by discard
        assert evidence["liveness"] == C.CONFIRMED_EXITED
        assert f"execution history: {history}" in str(raised.value)

    def test_failed_resume_call_is_unknown_history(self, monkeypatch, tmp_path):
        win32 = FakeWin32(fail={"resume": C.Win32Error("ResumeThread", 6)})
        with pytest.raises(C.LaunchFailure, match="resume failed") as raised:
            self._launch(monkeypatch, tmp_path, win32)
        assert raised.value.evidence["execution_history"] == C.STATE_UNKNOWN

    @pytest.mark.parametrize("handles", [
        C.Win32Handles(0, 0, 4242, 0), C.Win32Handles(None, None, 4242, 0)])
    def test_invalid_handles_keep_the_pid(self, monkeypatch, tmp_path, handles):
        win32 = FakeWin32(handles=handles)
        with pytest.raises(C.LaunchFailure, match="no valid process handle") as raised:
            self._launch(monkeypatch, tmp_path, win32)
        evidence = raised.value.evidence
        assert "invalid handle" in str(raised.value) and evidence["pid"] == 4242
        assert evidence["liveness"] == C.STATE_UNKNOWN and evidence["handles_retained"]
        assert evidence["execution_history"] == C.NEVER_EXECUTED
        assert "resume" not in self._names(win32)

    def test_invalid_thread_handle_terminates_the_process(self, monkeypatch, tmp_path):
        win32 = FakeWin32(handles=C.Win32Handles(101, -1, 4242, 0))
        with pytest.raises(C.LaunchFailure, match="invalid handle"):
            self._launch(monkeypatch, tmp_path, win32)
        assert ("terminate", 101, C.DISCARD_EXIT_CODE) in win32.calls

    def test_native_cleanup_errors_discard_the_child(self, monkeypatch, tmp_path):
        failing = "SetHandleInformation could not reset inheritance of handle 11"
        win32 = FakeWin32(handles=C.Win32Handles(101, 102, 4242, 77, [failing]))
        with pytest.raises(C.LaunchFailure, match="native cleanup") as raised:
            self._launch(monkeypatch, tmp_path, win32)
        assert failing in raised.value.evidence["cleanup_errors"]
        assert raised.value.evidence["liveness"] == C.CONFIRMED_EXITED
        assert "create_process" in self._names(win32) and "resume" not in self._names(win32)

    def test_foreign_pid_is_discarded(self, monkeypatch, tmp_path):
        win32 = FakeWin32(pid=9)
        with pytest.raises(C.LaunchFailure, match="does not belong"):
            self._launch(monkeypatch, tmp_path, win32)
        assert ("terminate", 101, C.DISCARD_EXIT_CODE) in win32.calls

    @pytest.mark.parametrize("change, message, liveness, history", [
        ({"waits": [False]}, "did not exit", C.STATE_UNKNOWN, C.NEVER_EXECUTED),
        ({"code": 0}, "not the discard code", C.CONFIRMED_EXITED, C.STATE_UNKNOWN),
        ({"fail": {"terminate": C.Win32Error("TerminateProcess", 5)}}, "TerminateProcess",
         C.STATE_UNKNOWN, C.NEVER_EXECUTED),
    ])
    def test_unverified_discard_keeps_handles(self, monkeypatch, tmp_path, change, message,
                                              liveness, history):
        win32 = FakeWin32(exempt=[SID], **change)
        with pytest.raises(C.LaunchFailure, match="could not be discarded") as raised:
            self._launch(monkeypatch, tmp_path, win32)
        evidence = raised.value.evidence
        assert message in str(raised.value) and "inspect it" in str(raised.value)
        assert evidence["liveness"] == liveness and evidence["execution_history"] == history
        assert evidence["handles_retained"] and evidence["pid"] == 4242
        assert ("close", 101) not in win32.calls                 # process handle kept

    def test_missing_folder(self, monkeypatch, tmp_path):
        win32 = FakeWin32(fail={"profile_folder": C.Win32Error("GetAppContainerFolderPath",
                                                               0x80070002)})
        with pytest.raises(C.CalibrationError, match="not proof either way"):
            self._launch(monkeypatch, tmp_path, win32)
        assert "create_process" not in self._names(win32)

    def test_capabilities_are_refused_by_the_backend(self, monkeypatch, tmp_path):
        open_probe_gate(monkeypatch)
        win32 = FakeWin32()
        api = C.Win32AppContainerApi(C.authorize_probe("probe-01", HEAD), win32=win32)
        command = C.build_probe_command("probe-01", tmp_path, series_token=TOKEN,
                                        expected_head=HEAD, interpreter=SPACED_PYTHON,
                                        port=50123)
        with pytest.raises(C.CalibrationError, match="no capabilities"):
            api.create_suspended(command, SID, ("S-1-15-3-1",), 1, 2)
        assert win32.calls == []

    def test_closed_gate_stops_every_call(self, monkeypatch):
        open_probe_gate(monkeypatch)
        win32 = FakeWin32()
        api = C.Win32AppContainerApi(C.authorize_probe("probe-01", HEAD), win32=win32)
        monkeypatch.setattr(C, "PROBE_ENABLED", False)
        for call in (lambda: api.profile_sid("x"), lambda: api.profile_folder_present(SID),
                     lambda: api.resume(None), lambda: api.discard_suspended(None),
                     lambda: api.token_info(None)):
            with pytest.raises(C.ExecutionDisabled):
                call()
        assert win32.calls == []

    def test_evidence_of_untracked_processes_is_unknown(self):
        evidence = C.process_evidence(object())
        assert evidence["execution_history"] == C.STATE_UNKNOWN
        assert evidence["liveness"] == C.STATE_UNKNOWN
        assert set(C.EXECUTION_HISTORIES) == {C.NEVER_EXECUTED, C.MAY_HAVE_EXECUTED,
                                              C.STATE_UNKNOWN}
        assert set(C.LIVENESS_STATES) == {C.CONFIRMED_EXITED, C.ALIVE_AT_LAST_CHECK,
                                          C.STATE_UNKNOWN}


# ---------------------------------------------------------------------------
# ctypes layer (fake DLLs; no real Windows call)
# ---------------------------------------------------------------------------

class FakeFunction:
    def __init__(self, name, implementation, log):
        self.name, self.implementation, self.log = name, implementation, log

    def __call__(self, *args):
        self.log.append(self.name)
        return self.implementation(*args)


class FakeDll:
    def __init__(self, functions, log):
        self._functions, self._log = functions, log

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._functions:
            raise LiveAccessAttempt(f"unexpected Windows API {name}")
        return FakeFunction(name, self._functions[name], self._log)


#: Sentinel SID pointers (outside any token buffer).
SIDS = {0x5001: SID, 0x6001: "S-1-15-2-1001", 0x6002: "S-1-15-2-1002"}
#: SIDs placed inside fake token buffers: 16 bytes "FAKESID" + index.
FAKE_SID_STRINGS = {1: SID, 2: "S-1-16-4096", 3: "S-1-15-3-1", 4: "S-1-15-3-3",
                    5: "S-1-16-8192"}


def _fake_sid(index):
    return b"FAKESID" + bytes([index]) + b"\0" * 8


def _convert_sid(psid, out):
    value = getattr(psid, "value", psid)
    if value in SIDS:
        out._obj.value = SIDS[value]
        return 1
    data = C._win32_types().ctypes.string_at(value, 8)
    if data[:7] != b"FAKESID":
        return 0
    out._obj.value = FAKE_SID_STRINGS[data[7]]
    return 1


def _fake_ctypes(monkeypatch, functions, state):
    open_probe_gate(monkeypatch)
    log, loaded = [], []
    base = {"ConvertSidToStringSidW": _convert_sid, "CloseHandle": lambda h: 1,
            "LocalFree": lambda p: state.setdefault("freed", []).append(p),
            "FreeSid": lambda p: state.__setitem__("sid_freed", True),
            "CoTaskMemFree": lambda p: state.__setitem__("cotask_freed", True)}

    def loader(name):
        loaded.append(name)
        return FakeDll({**base, **functions}, log)

    win32 = C.CtypesWin32(C.authorize_probe("probe-01", HEAD), loader=loader,
                          last_error=lambda: state.get("last_error", 0),
                          os_handle=lambda stream: stream)
    state["loaded"] = loaded
    return win32, log


def _create_fakes(state):
    t = C._win32_types()
    c = t.ctypes

    def to_sid(sid, out):
        state["sid_in"] = sid
        out._obj.value = 0x5001
        return 1

    def inherit(handle, mask, flags):
        state.setdefault("inherit", []).append((handle, flags))
        if flags == 0 and state.get("reset_fails"):
            return 0
        return 1

    def initialize(address, count, flags, size):
        if address is None:
            state["sizing_count"] = count
            size._obj.value = state.get("size", 64)
            return state.get("first_result", 0)
        state["attribute_count"] = count
        state["buffer_address"] = address
        return state.get("second_ok", 1)

    def reread():
        return [c.string_at(value, size) for _, value, size in state.get("updates", [])]

    def update(address, flags, attribute, value, size, previous, returned):
        position = len(state.setdefault("updates", []))
        state["updates"].append((attribute, value, size))
        state.setdefault("update_bytes", []).append(c.string_at(value, size))
        if state.get("update_fail_at") == position:
            return 0
        if attribute == C.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES:
            caps = t.SECURITY_CAPABILITIES.from_address(value)
            state["capabilities"] = (caps.AppContainerSid, caps.CapabilityCount,
                                     bool(caps.Capabilities))
        elif attribute == C.PROC_THREAD_ATTRIBUTE_JOB_LIST:
            state["job_list"] = list(
                (t.w.HANDLE * (size // c.sizeof(t.w.HANDLE))).from_address(value))
        else:
            state["inherited"] = list(
                (t.w.HANDLE * (size // c.sizeof(t.w.HANDLE))).from_address(value))
        return state.get("update_ok", 1)

    def create(app, command, pa, ta, inherit_handles, flags, env, cwd, startup, info):
        state.update(app=app, command=c.wstring_at(command), flags=flags, cwd=cwd,
                     inherit_handles=inherit_handles, env=c.wstring_at(env, state["env_len"]))
        s = startup._obj
        state["startup"] = (s.StartupInfo.cb, s.StartupInfo.dwFlags, s.StartupInfo.hStdOutput,
                            s.StartupInfo.hStdError, bool(s.lpAttributeList))
        state["list_address"] = s.lpAttributeList
        state["bytes_at_create"] = reread()
        if "during_create" in state:
            state["during_create"]()
        if not state.get("create_ok", 1):
            return 0
        i = info._obj
        i.hProcess, i.hThread, i.dwProcessId, i.dwThreadId = 101, 102, 4242, 77
        if "after_create" in state:
            state["after_create"]()
        return 1

    def delete(address):
        state["deleted"] = True
        state["bytes_at_delete"] = reread()
        state["delete_address"] = address
        if state.get("delete_raises"):
            raise OSError("access violation")

    def local_free(pointer):
        state.setdefault("freed", []).append(pointer)
        return 0x99 if state.get("local_free_fails") else None

    return {"ConvertStringSidToSidW": to_sid, "SetHandleInformation": inherit,
            "InitializeProcThreadAttributeList": initialize,
            "UpdateProcThreadAttribute": update, "CreateProcessW": create,
            "DeleteProcThreadAttributeList": delete, "LocalFree": local_free}


def _probe_command(tmp_path):
    return C.build_probe_command("probe-01", tmp_path, series_token=TOKEN, expected_head=HEAD,
                                 interpreter=SPACED_PYTHON, port=50123)


def _create(win32, command):
    return win32.create_process(application=command.argv[0], command_line=command.command_line,
                                env=command.env, cwd=command.cwd, stdout=11, stderr=12,
                                sid=SID)


class TestCtypesCreateProcess:
    def test_suspended_without_capabilities(self, monkeypatch, tmp_path):
        command = _probe_command(tmp_path)
        state = {"env_len": len(C.environment_block(command.env)) + 1}
        win32, log = _fake_ctypes(monkeypatch, _create_fakes(state), state)
        handles = _create(win32, command)
        assert (handles.process, handles.thread, handles.pid) == (101, 102, 4242)
        assert handles.cleanup_errors == []
        assert state["app"] == SPACED_PYTHON and state["command"] == command.command_line
        assert state["env"] == C.environment_block(command.env) + "\0"
        assert state["flags"] == C.CREATION_FLAGS and state["flags"] & C.CREATE_SUSPENDED
        assert state["inherit_handles"] is True and state["cwd"] == str(_REPO)
        assert state["capabilities"] == (0x5001, 0, False)      # the SID, zero capabilities
        assert state["inherited"] == [11, 12] and state["sid_in"] == SID
        t = C._win32_types()
        assert state["startup"] == (t.ctypes.sizeof(t.STARTUPINFOEXW), C.STARTF_USESTDHANDLES,
                                    11, 12, True)
        assert state["inherit"] == [(11, 1), (12, 1), (11, 0), (12, 0)]
        assert state["deleted"] and state["freed"]
        assert "ResumeThread" not in log and state["loaded"] == ["advapi32", "kernel32"]

    @pytest.mark.parametrize("failure", ["create_ok", "update_ok"])
    def test_failure_cleans_up(self, monkeypatch, tmp_path, failure):
        command = _probe_command(tmp_path)
        state = {"env_len": len(C.environment_block(command.env)) + 1, failure: 0,
                 "last_error": 5}
        win32, _ = _fake_ctypes(monkeypatch, _create_fakes(state), state)
        with pytest.raises(C.Win32Error, match="Windows error 5"):
            _create(win32, command)
        assert state["deleted"] and state["freed"]
        assert state["inherit"][-2:] == [(11, 0), (12, 0)]

    @pytest.mark.parametrize("fault, expected", [
        ("reset_fails", "could not reset inheritance"),
        ("delete_raises", "DeleteProcThreadAttributeList"),
        ("local_free_fails", "LocalFree of the AppContainer SID failed"),
    ])
    def test_cleanup_failure_never_loses_the_process(self, monkeypatch, tmp_path, fault,
                                                     expected):
        command = _probe_command(tmp_path)
        state = {"env_len": len(C.environment_block(command.env)) + 1, fault: True}
        win32, _ = _fake_ctypes(monkeypatch, _create_fakes(state), state)
        handles = _create(win32, command)
        assert (handles.process, handles.thread, handles.pid) == (101, 102, 4242)
        assert any(expected in e for e in handles.cleanup_errors)
        assert win32.last_cleanup_errors == handles.cleanup_errors

    def test_gate_closing_during_creation_cannot_lose_the_process(self, monkeypatch, tmp_path):
        command = _probe_command(tmp_path)
        state = {"env_len": len(C.environment_block(command.env)) + 1}
        state["during_create"] = lambda: monkeypatch.setattr(C, "PROBE_ENABLED", False)
        win32, _ = _fake_ctypes(monkeypatch, _create_fakes(state), state)
        handles = _create(win32, command)                       # cleanup is pre-bound
        assert handles.process == 101 and handles.cleanup_errors == []
        assert state["deleted"] and state["inherit"][-2:] == [(11, 0), (12, 0)]
        with pytest.raises(C.ExecutionDisabled):
            win32.process_id(101)

    def test_failed_creation_records_cleanup_errors(self, monkeypatch, tmp_path):
        command = _probe_command(tmp_path)
        state = {"env_len": len(C.environment_block(command.env)) + 1, "create_ok": 0,
                 "reset_fails": True, "last_error": 2}
        win32, _ = _fake_ctypes(monkeypatch, _create_fakes(state), state)
        with pytest.raises(C.Win32Error, match="CreateProcessW"):
            _create(win32, command)
        assert any("could not reset" in e for e in win32.last_cleanup_errors)

    def test_invalid_output_handle_stops_before_any_call(self, monkeypatch, tmp_path):
        state = {}
        win32, log = _fake_ctypes(monkeypatch, _create_fakes(state), state)
        with pytest.raises(C.Win32Error, match="invalid output handle"):
            win32.create_process(application=SPACED_PYTHON, command_line="x", env={"A": "1"},
                                 cwd="C:\\", stdout=-1, stderr=12, sid=SID)
        assert log == [] and state["loaded"] == []


def _token_payloads(capabilities=(), integrity=2, sid=1, flag=1, app_sid_pointer=None,
                    label_pointer=None):
    """Builders of GetTokenInformation output; SIDs live inside the buffer."""
    t = C._win32_types()
    c, w = t.ctypes, t.w
    SAA = t.SID_AND_ATTRIBUTES

    def is_app_container(address):
        return bytes(w.DWORD(flag))

    def app_sid(address):
        header = c.sizeof(t.TOKEN_APPCONTAINER_INFORMATION)
        pointer = app_sid_pointer if app_sid_pointer is not None else (
            address + header if sid else 0)
        return bytes(t.TOKEN_APPCONTAINER_INFORMATION(pointer)) + (_fake_sid(sid) if sid else b"")

    def caps(address):
        if not capabilities:
            return bytes(w.DWORD(0)) + b"\0" * 4
        n = len(capabilities)
        at = t.TOKEN_GROUPS.Groups.offset + n * c.sizeof(SAA)

        class Groups(c.Structure):
            _fields_ = [("GroupCount", w.DWORD), ("Groups", SAA * n)]

        groups = Groups(n, (SAA * n)(*[SAA(address + at + 16 * i, 4) for i in range(n)]))
        return bytes(groups) + b"".join(_fake_sid(k) for k in capabilities)

    def label(address):
        header = c.sizeof(t.TOKEN_MANDATORY_LABEL)
        pointer = label_pointer if label_pointer is not None else address + header
        return bytes(t.TOKEN_MANDATORY_LABEL(SAA(pointer, 0x20))) + _fake_sid(integrity)

    return {C.TOKEN_IS_APP_CONTAINER: is_app_container, C.TOKEN_APP_CONTAINER_SID: app_sid,
            C.TOKEN_CAPABILITIES: caps, C.TOKEN_INTEGRITY_LEVEL: label}


def _token_fakes(payloads, state):
    c = C._win32_types().ctypes
    pointer = c.sizeof(c.c_void_p)

    def open_token(process, access, out):
        state["access"] = access
        out._obj.value = 900
        return state.get("open_ok", 1)

    def query(token, information_class, address, length, returned):
        build = payloads[information_class]
        if address is None:
            state.setdefault("sized", []).append(information_class)
            returned._obj.value = len(build(0))
            state["last_error"] = state.get("sizing_error", C.ERROR_INSUFFICIENT_BUFFER)
            return 0
        state.setdefault("alignment", []).append(address % pointer)
        data = build(address)
        if len(data) > length:
            return 0
        c.memmove(address, data, len(data))
        returned._obj.value = state.get("returned", {}).get(information_class, len(data))
        return 1

    def close(handle):
        state.setdefault("closed", []).append(getattr(handle, "value", handle))
        return 1

    return {"OpenProcessToken": open_token, "GetTokenInformation": query,
            "CloseHandle": close, "GetCurrentProcess": lambda: -1}


class TestCtypesToken:
    @pytest.mark.parametrize("capabilities, expected", [
        ((), []), ((3, 4), ["S-1-15-3-1", "S-1-15-3-3"])])
    def test_token_info(self, monkeypatch, capabilities, expected):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _token_fakes(_token_payloads(capabilities), state),
                                state)
        assert win32.token_info(101) == {"is_app_container": True, "app_container_sid": SID,
                                         "capabilities": expected, "integrity_level": "low"}
        assert state["access"] == C.TOKEN_QUERY and state["closed"] == [900]
        assert C.TOKEN_IS_APP_CONTAINER not in state["sized"]   # fixed size, one call
        assert set(state["alignment"]) == {0}                   # pointer-aligned buffers
        assert win32.current_token_info()["app_container_sid"] == SID

    def test_not_an_app_container(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _token_fakes(
            _token_payloads(flag=0, sid=0, integrity=5), state), state)
        assert win32.token_info(101) == {"is_app_container": False, "app_container_sid": None,
                                         "capabilities": [], "integrity_level": "medium"}

    @pytest.mark.parametrize("payload_kwargs, state_kwargs, message", [
        ({"flag": 7}, {}, "unexpected TokenIsAppContainer"),
        ({"app_sid_pointer": 0x5001}, {}, "outside the returned buffer"),
        ({"label_pointer": 0}, {}, "outside the returned buffer"),
        ({}, {"returned": {C.TOKEN_IS_APP_CONTAINER: 2}}, "unexpected length"),
        ({}, {"returned": {C.TOKEN_APP_CONTAINER_SID: 4}}, "short"),
        ({}, {"sizing_error": 5}, "Windows error 5"),
    ])
    def test_unexpected_layouts_fail_closed(self, monkeypatch, payload_kwargs, state_kwargs,
                                            message):
        state = dict(state_kwargs)
        win32, _ = _fake_ctypes(monkeypatch, _token_fakes(_token_payloads(**payload_kwargs),
                                                          state), state)
        with pytest.raises(C.Win32Error, match=message):
            win32.token_info(101)
        assert state["closed"] == [900]                      # the token is still closed

    def test_malformed_capabilities(self, monkeypatch):
        payloads = _token_payloads()
        payloads[C.TOKEN_CAPABILITIES] = lambda address: bytes(
            C._win32_types().w.DWORD(3)) + b"\0" * 4
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _token_fakes(payloads, state), state)
        with pytest.raises(C.Win32Error, match="malformed capabilities"):
            win32.token_info(101)

    def test_open_token_failure(self, monkeypatch):
        state = {"open_ok": 0, "last_error": 6}
        win32, _ = _fake_ctypes(monkeypatch, _token_fakes(_token_payloads(), state), state)
        with pytest.raises(C.Win32Error, match="OpenProcessToken"):
            win32.token_info(0)


def _heap_fakes(state, sids=(), *, result=0, array=True, null_index=None, fail_free=None):
    t = C._win32_types()
    c = t.ctypes
    SAA = t.SID_AND_ATTRIBUTES
    entries = [0 if i == null_index else p for i, p in enumerate(sids)]
    keep = (SAA * max(len(entries), 1))(*[SAA(p, 0) for p in entries])
    state["array_address"] = c.addressof(keep)
    state["keep"] = keep

    def config(count, out):
        count._obj.value = len(entries) if array or entries else 0
        if array:
            out._obj.contents = keep[0]
        if not array and entries:
            count._obj.value = len(entries)
        return result

    def heap_free(heap, flags, pointer):
        value = getattr(pointer, "value", pointer)
        state.setdefault("heap_freed", []).append((heap, flags, value))
        return 0 if value == fail_free else 1

    return {"GetProcessHeap": lambda: state.get("heap", 0x77), "HeapFree": heap_free,
            "NetworkIsolationGetAppContainerConfig": config}


class TestLoopbackExemptionMemory:
    def _freed(self, state):
        return [value for _, _, value in state.get("heap_freed", [])]

    def test_multiple_entries_free_every_sid_and_the_array(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001, 0x6002)), state)
        assert win32.loopback_exempt_sids() == ["S-1-15-2-1001", "S-1-15-2-1002"]
        assert self._freed(state) == [0x6001, 0x6002, state["array_address"]]
        assert all(heap == 0x77 and flags == 0 for heap, flags, _ in state["heap_freed"])

    def test_zero_entries(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (), array=False), state)
        assert win32.loopback_exempt_sids() == [] and self._freed(state) == []
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, ()), state)
        assert win32.loopback_exempt_sids() == []
        assert self._freed(state) == [state["array_address"]]  # an empty array is freed

    def test_null_sid_and_conversion_failure_still_free_everything(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001, 0x6002),
                                                         null_index=0), state)
        with pytest.raises(C.Win32Error, match="SID 0 is null"):
            win32.loopback_exempt_sids()
        assert self._freed(state) == [0x6002, state["array_address"]]
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001, 0x7777)), state)
        with pytest.raises(C.Win32Error, match="SID 1"):
            win32.loopback_exempt_sids()
        assert self._freed(state) == [0x6001, 0x7777, state["array_address"]]

    def test_api_failure_frees_partial_output(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001,), result=5), state)
        with pytest.raises(C.Win32Error, match="Windows error 5"):
            win32.loopback_exempt_sids()
        assert self._freed(state) == [0x6001, state["array_address"]]

    def test_heap_free_failure_is_reported_and_freeing_continues(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001, 0x6002),
                                                         fail_free=0x6001), state)
        with pytest.raises(C.Win32Error, match="HeapFree of SID 0 failed"):
            win32.loopback_exempt_sids()
        assert self._freed(state) == [0x6001, 0x6002, state["array_address"]]

    def test_count_without_array(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001,), array=False), state)
        with pytest.raises(C.Win32Error, match="a count without an array"):
            win32.loopback_exempt_sids()
        assert self._freed(state) == []

    def test_invalid_process_heap(self, monkeypatch):
        state = {"heap": 0, "last_error": 8}
        win32, log = _fake_ctypes(monkeypatch, _heap_fakes(state, (0x6001,)), state)
        with pytest.raises(C.Win32Error, match="GetProcessHeap"):
            win32.loopback_exempt_sids()
        assert "NetworkIsolationGetAppContainerConfig" not in log


class TestCtypesQueries:
    def test_profile_queries_and_lazy_loading(self, monkeypatch):
        def derive(name, out):
            out._obj.value = 0x5001
            return 0

        def folder(sid, out):
            out._obj.value = r"C:\Users\x\AppData\Local\Packages\agentops"
            return 0

        state = {}
        win32, log = _fake_ctypes(monkeypatch, {
            "DeriveAppContainerSidFromAppContainerName": derive,
            "GetAppContainerFolderPath": folder}, state)
        assert win32.loaded_dlls == []
        assert win32.derive_sid(C.APPCONTAINER_PROFILE) == SID and state["sid_freed"]
        assert win32.loaded_dlls == ["advapi32", "kernel32", "userenv"]
        assert win32.profile_folder(SID).endswith("agentops") and state["cotask_freed"]
        assert win32.loaded_dlls == ["advapi32", "kernel32", "ole32", "userenv"]
        assert "firewallapi" not in state["loaded"]
        assert "CreateAppContainerProfile" not in log

    def test_hresult_failures(self, monkeypatch):
        state = {}
        win32, _ = _fake_ctypes(monkeypatch, {
            "DeriveAppContainerSidFromAppContainerName": lambda n, o: -2147024809,
            "GetAppContainerFolderPath": lambda s, o: -2147024894}, state)
        with pytest.raises(C.Win32Error, match=str(0x80070057)):
            win32.derive_sid("x")
        with pytest.raises(C.Win32Error, match="GetAppContainerFolderPath"):
            win32.profile_folder(SID)
        assert "cotask_freed" not in state                      # nothing was returned

    def test_process_queries_and_control(self, monkeypatch):
        from datetime import datetime, timezone
        c = C._win32_types().ctypes
        epoch = int(datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc).timestamp())
        ticks = (epoch + 11644473600) * 10_000_000

        def times(handle, created, exited, kernel, user):
            created._obj.dwLowDateTime, created._obj.dwHighDateTime = ticks & 0xFFFFFFFF, \
                ticks >> 32
            return 1

        def image(handle, flags, address, size):
            data = SPACED_PYTHON.encode("utf-16-le") + b"\0\0"
            c.memmove(address, data, len(data))
            return 1

        def exit_code(handle, out):
            out._obj.value = 7
            return 1

        waits = [C.WAIT_OBJECT_0, C.WAIT_TIMEOUT, 0xFFFFFFFF]
        state = {}
        win32, log = _fake_ctypes(monkeypatch, {
            "GetProcessId": lambda h: 4242, "GetProcessTimes": times,
            "QueryFullProcessImageNameW": image, "GetExitCodeProcess": exit_code,
            "ResumeThread": lambda h: state.get("resume", 1),
            "TerminateProcess": lambda h, code: state.setdefault("terminated", code),
            "WaitForSingleObject": lambda h, ms: waits.pop(0)}, state)
        assert win32.process_id(101) == 4242 and state["loaded"] == ["kernel32"]
        assert win32.creation_time(101) == "2026-10-09T10:00:00.000Z"
        assert win32.image_path(101) == SPACED_PYTHON
        assert win32.exit_code(101) == 7 and win32.resume(102) == 1
        win32.terminate(101, C.DISCARD_EXIT_CODE)
        assert state["terminated"] == C.DISCARD_EXIT_CODE
        assert win32.wait(101, 0) is True and win32.wait(101, 0) is False
        with pytest.raises(C.Win32Error, match="WaitForSingleObject"):
            win32.wait(101, 0)
        state["resume"] = C.RESUME_FAILED
        with pytest.raises(C.Win32Error, match="ResumeThread"):
            win32.resume(102)
        assert state["loaded"] == ["kernel32"]

    def test_gate_checked_before_loading(self, monkeypatch):
        state = {}
        win32, log = _fake_ctypes(monkeypatch, {"GetProcessId": lambda h: 4242}, state)
        monkeypatch.setattr(C, "APPROVED_PROBES", frozenset())
        with pytest.raises(C.ExecutionDisabled):
            win32.process_id(101)
        assert log == [] and state["loaded"] == []

    def test_default_loader_is_never_used_offline(self, monkeypatch):
        open_probe_gate(monkeypatch)
        win32 = C.CtypesWin32(C.authorize_probe("probe-01", HEAD))
        assert win32.loaded_dlls == [] and win32._loader is C._default_loader


# ---------------------------------------------------------------------------
# Probe child (fakes; the driver is never imported)
# ---------------------------------------------------------------------------

def _wsa(code, cls=OSError):
    """An OSError carrying a Windows Sockets error code."""
    if sys.platform == "win32":
        return OSError(0, "socket error", None, code)
    error = cls(0, "socket error")
    error.winerror = code
    return error


def _probe_own(directory, token=TOKEN):
    return C.claim_series(directory, calibration_ids=["probe-01"], expected_head=HEAD,
                          now=lambda: 1_800_000_000.0, new_token=lambda: token,
                          owner_file=C.PROBE_OWNER_FILE)


def _probe_deps(*, token=None, connect=None, resolve=None, import_module=None, imported=None,
                identity=(4242, SPACED_PYTHON)):
    imported = [] if imported is None else imported

    def denied(port):
        raise _wsa(C.WSAEACCES, PermissionError)

    def no_dns(name):
        raise socket.gaierror(11001, "getaddrinfo failed")

    def fake_import(name):
        imported.append(name)
        return types.ModuleType(name)

    return C.ProbeChildDeps(token_info=lambda: dict(token or GOOD_TOKEN),
                            connect=connect or denied, resolve=resolve or no_dns,
                            import_module=import_module or fake_import,
                            identity=lambda: identity, wall=lambda: 1_800_000_000.0)


EXPECTED = {"expected_pid": 4242, "expected_executable": SPACED_PYTHON, "expected_sid": SID,
            "expected_port": 50123}


def _fresh_child_process(monkeypatch):
    """A probe child is a fresh process: hide the driver other tests loaded."""
    monkeypatch.setattr(C, "AUTHORIZED_APPCONTAINER_SID", SID)
    for name in C.PROBE_FORBIDDEN_MODULES:
        monkeypatch.delitem(sys.modules, name, raising=False)


class TestLoopbackClassification:
    @pytest.mark.parametrize("make, outcome", [
        (lambda: _wsa(10013, PermissionError), "access_denied"),
        (lambda: _wsa(10061, ConnectionRefusedError), "refused"),
        (lambda: ConnectionRefusedError("refused"), "refused"),
        (lambda: _wsa(10060, TimeoutError), "timeout"),
        (lambda: TimeoutError("timed out"), "timeout"),
        (lambda: socket.timeout("timed out"), "timeout"),
        (lambda: _wsa(10065), "unreachable"),
        (lambda: _wsa(10051), "unreachable"),
        (lambda: PermissionError(13, "denied without a Windows code"), "other"),
        (lambda: OSError(5, "other"), "other"),
    ])
    def test_only_wsaeacces_is_denial(self, make, outcome):
        evidence = C.classify_loopback_attempt(make())
        assert evidence["outcome"] == outcome
        assert evidence["denied"] is (outcome == "access_denied")
        assert evidence["inconclusive"] is (outcome != "access_denied")

    def test_connection_is_a_failure_not_inconclusive(self):
        assert C.classify_loopback_attempt(None) == {
            "outcome": "connected", "denied": False, "inconclusive": False, "error": None,
            "errno": None, "winerror": None}


class TestProbeChild:
    @pytest.fixture(autouse=True)
    def fresh(self, monkeypatch):
        _fresh_child_process(monkeypatch)

    def _run(self, tmp_path, **kwargs):
        _probe_own(tmp_path)
        status = C.probe_child_main("probe-01", tmp_path, _probe_deps(**kwargs),
                                    series_token=TOKEN, port=50123)
        return status, _read(tmp_path / "probe-01.json")

    def test_pass(self, tmp_path):
        imported = []
        status, record = self._run(tmp_path, imported=imported)
        assert status == C.EXIT_OK and record["status"] == "passed"
        assert imported == list(C.PROBE_IMPORTS)
        assert record["loopback"]["outcome"] == "access_denied"
        assert record["loopback"]["winerror"] == C.WSAEACCES
        assert record["dns"] == {"name": "localhost", "resolved": False, "error": "gaierror"}
        assert "supplementary" in record["dns_note"]
        assert record["scope"] == C.PROBE_SCOPE_NOTE and "NOT tested" in record["scope"]
        assert (record["pid"], record["executable"], record["port"]) == (4242, SPACED_PYTHON,
                                                                         50123)
        assert C.probe_result_problems(record, "probe-01", status, **EXPECTED) == []

    def test_dns_success_does_not_fail_the_probe(self, tmp_path):
        status, record = self._run(tmp_path, resolve=lambda name: [("x",)])
        assert status == C.EXIT_OK and record["dns"]["resolved"] is True

    def test_reachable_loopback_fails(self, tmp_path):
        status, record = self._run(tmp_path, connect=lambda port: None)
        assert status == C.EXIT_PROBE_FAILED and record["loopback"]["outcome"] == "connected"
        assert any("WSAEACCES" in p for p in C.probe_result_problems(
            record, "probe-01", status, **EXPECTED))

    @pytest.mark.parametrize("error, outcome", [
        (lambda: _wsa(10061, ConnectionRefusedError), "refused"),
        (lambda: TimeoutError("timed out"), "timeout"),
        (lambda: _wsa(10065), "unreachable"),
        (lambda: PermissionError(13, "no Windows code"), "other"),
    ])
    def test_inconclusive_errors_fail(self, tmp_path, error, outcome):
        def connect(port):
            raise error()

        status, record = self._run(tmp_path, connect=connect)
        assert status == C.EXIT_PROBE_FAILED and record["status"] == "failed"
        assert record["loopback"]["outcome"] == outcome and record["loopback"]["inconclusive"]

    def test_non_socket_error_fails(self, tmp_path):
        def connect(port):
            raise RuntimeError("unexpected")

        status, record = self._run(tmp_path, connect=connect)
        assert status == C.EXIT_PROBE_FAILED and "RuntimeError" in record["failure"]

    @pytest.mark.parametrize("token", [
        {**GOOD_TOKEN, "capabilities": ["S-1-15-3-1"]},
        {**GOOD_TOKEN, "is_app_container": False},
        {**GOOD_TOKEN, "app_container_sid": "S-1-15-2-7"},
    ])
    def test_wrong_token_fails(self, tmp_path, token):
        status, record = self._run(tmp_path, token=token)
        assert status == C.EXIT_PROBE_FAILED and record["token_problems"]

    def test_failed_import_fails(self, tmp_path):
        def missing(name):
            if name == "langgraph.graph":
                raise ImportError("No module named 'langgraph'")
            return types.ModuleType(name)

        status, record = self._run(tmp_path, import_module=missing)
        assert status == C.EXIT_PROBE_FAILED
        assert record["imports"]["langgraph.graph"].startswith("ImportError")

    @pytest.mark.parametrize("leak", ["socket", "native"])
    def test_network_activity_during_imports(self, tmp_path, leak):
        def leaking(name):
            if leak == "socket":
                try:
                    socket.getaddrinfo("collector.example", 4317)
                except OSError:
                    pass
            else:
                import grpc
                try:
                    grpc.insecure_channel("localhost:4317")
                except OSError:
                    pass
            return types.ModuleType(name)

        status, record = self._run(tmp_path, import_module=leaking)
        assert status == C.EXIT_NETWORK and record["status"] == "network_violation"
        assert record["network_guard_violations"]

    def test_the_driver_cannot_be_imported(self, tmp_path, monkeypatch):
        sys.path.insert(0, str(_REPO / "workload-generator"))
        monkeypatch.delitem(sys.modules, "workload_generator.real_driver", raising=False)

        def driver(name):
            return importlib.import_module("workload_generator.real_driver")

        status, record = self._run(tmp_path, import_module=driver)
        assert status == C.EXIT_PROBE_FAILED
        assert record["forbidden_import_attempts"] and record["driver_loaded"] is False
        assert "workload_generator.real_driver" not in sys.modules
        assert all(v.startswith("ImportError") for v in record["imports"].values())

    def test_the_probe_code_never_names_the_driver(self):
        for function in (C.probe_child_main, C.run_probe, C.production_probe_child_deps,
                         C.production_probe_deps, C._loopback_connect, C._resolve):
            source = inspect.getsource(function)
            for word in ("execute(", "_import_driver", "load_demo", "real_driver."):
                assert word not in source, (function.__name__, word)
        assert C.PROBE_FORBIDDEN_MODULES == ("workload_generator.real_driver",)
        assert not any("real_driver" in name for name in C.PROBE_IMPORTS)

    @pytest.mark.parametrize("change, message", [
        ({"pid": 999}, "PID differs"),
        ({"executable": r"C:\other\python.exe"}, "another executable"),
        ({"port": 50124}, "another port"),
        ({"token": {**GOOD_TOKEN, "app_container_sid": "S-1-15-2-7"}}, "validated AppContainer"),
        ({"loopback": {"outcome": "access_denied", "winerror": None}}, "WSAEACCES"),
    ])
    def test_cross_check_against_the_launched_process(self, tmp_path, change, message):
        status, record = self._run(tmp_path)
        record.update(change)
        problems = C.probe_result_problems(record, "probe-01", status, **EXPECTED)
        assert any(message in p for p in problems), problems

    def test_ownership_and_no_repeat(self, tmp_path):
        with pytest.raises(C.CalibrationError, match="no ACTIVE_PROBE"):
            C.probe_child_main("probe-01", tmp_path, _probe_deps(), series_token=TOKEN,
                               port=50123)
        _probe_own(tmp_path)
        with pytest.raises(C.CalibrationError, match="token does not match"):
            C.probe_child_main("probe-01", tmp_path, _probe_deps(), series_token="f" * 32,
                               port=50123)
        assert not (tmp_path / "probe-01.json").exists()
        C.probe_child_main("probe-01", tmp_path, _probe_deps(), series_token=TOKEN, port=50123)
        with pytest.raises(C.CalibrationError, match="never repeated"):
            C.probe_child_main("probe-01", tmp_path, _probe_deps(), series_token=TOKEN,
                               port=50123)

    @pytest.mark.parametrize("port", [None, 80, 70000, True])
    def test_bad_port(self, tmp_path, port):
        with pytest.raises(C.CalibrationError, match="1024-65535"):
            C.probe_child_main("probe-01", tmp_path, _probe_deps(), series_token=TOKEN,
                               port=port)


# ---------------------------------------------------------------------------
# Probe command and orchestrator
# ---------------------------------------------------------------------------

class TestProbeCommand:
    def test_explicit_argv_without_the_driver(self, tmp_path):
        out = tmp_path / "probe out"
        command = C.build_probe_command("probe-01", out, series_token=TOKEN, expected_head=HEAD,
                                        interpreter=SPACED_PYTHON, port=50123,
                                        python_paths=(r"C:\my venv\Lib\site-packages",))
        assert command.argv == (
            SPACED_PYTHON, "-B", "-s", str((_BENCH / "calibrate_generator.py").resolve()),
            "--probe-child", "probe-01", "--output-dir", str(out), "--token", TOKEN,
            "--expect-head", HEAD, "--port", "50123")
        assert "--child" not in command.argv and "--authorize" not in command.argv
        assert command.stdout_path == out / "probe-01.stdout"
        assert command.env["PYTHONPATH"].endswith(r"C:\my venv\Lib\site-packages")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows command-line parsing")
    def test_spaces_survive_windows_quoting(self, tmp_path):
        command = C.build_probe_command("probe-01", tmp_path / "a b", series_token=TOKEN,
                                        expected_head=HEAD, interpreter=SPACED_PYTHON,
                                        port=50123)
        assert _windows_argv(command.command_line) == list(command.argv)

    @pytest.mark.parametrize("probe_id, port, message", [
        ("probe-6", 50123, "probe-01"), ("cal-a-01", 50123, "probe-01"),
        ("probe-01", 22, "1024-65535"), ("probe-01", "50123", "1024-65535")])
    def test_bad_arguments(self, tmp_path, probe_id, port, message):
        with pytest.raises(C.CalibrationError, match=message):
            C.build_probe_command(probe_id, tmp_path, series_token=TOKEN, expected_head=HEAD,
                                  interpreter=SPACED_PYTHON, port=port)


class FakeListener:
    """Scripted counts: before the child (control), from the child, after
    (control).  control() can fail."""

    def __init__(self, counts=(1, 0, 1), port=50123, control_error=None):
        self.port, self.counts, self.control_error = port, list(counts), control_error
        self.controls, self.closed = 0, False

    def control(self):
        self.controls += 1
        if self.control_error:
            raise self.control_error

    def connections(self):
        return self.counts.pop(0) if self.counts else 0

    def close(self):
        self.closed = True


def probe_child(*, polls=1, returncode=None, **deps_kwargs):
    """A fake process whose exit runs the real probe_child_main with fakes."""
    def make(command):
        out = Path(_arg(command, "--output-dir"))
        token, port = _arg(command, "--token"), int(_arg(command, "--port"))

        def finish():
            return C.probe_child_main("probe-01", out, _probe_deps(**deps_kwargs),
                                      series_token=token, port=port)
        return FakeProcess(polls=polls, returncode=returncode, on_exit=finish)
    return make


def _prober(clock, maker, *, observe=good_observe, listener=None):
    launched = []
    listener = listener or FakeListener()

    def launch(command, stdout, stderr):
        launched.append(command)
        return maker(command)

    deps = C.ProbeDeps(launch=launch, observe=observe, listener=lambda: listener,
                       clock=clock.clock, pause=clock.pause, now=lambda: 1_800_000_000.0,
                       interpreter=SPACED_PYTHON, expected_head=HEAD,
                       python_paths=(r"C:\my venv\Lib\site-packages",))
    return deps, launched, listener


def _probe_record(directory):
    records = list(Path(directory).glob("probe-record-probe-01-*.json"))
    assert len(records) == 1
    return _read(records[0])


class TestRunProbe:
    @pytest.fixture(autouse=True)
    def fresh(self, monkeypatch):
        _fresh_child_process(monkeypatch)

    def test_pass_releases_ownership(self, tmp_path):
        deps, launched, listener = _prober(FakeClock(), probe_child())
        outcome = C.run_probe("probe-01", tmp_path, deps)
        assert outcome.passed and outcome.ownership_released, outcome.stopped_reason
        assert not (tmp_path / C.PROBE_OWNER_FILE).exists() and listener.closed
        assert listener.controls == 2 and len(launched) == 1
        assert _arg(launched[0], "--port") == "50123"
        for stage in ("launch", "process", "complete"):
            assert _journal(tmp_path, stage, "probe-01").exists()
        record = _probe_record(tmp_path)
        assert record["passed"] and record["scope"] == C.PROBE_SCOPE_NOTE
        assert "not a proof of complete isolation" in record["note"]
        run = record["run"]
        assert (run["listener_control_before"], run["listener_child_connections"],
                run["listener_control_after"]) == (1, 0, 1)
        assert run["execution_history"] == C.MAY_HAVE_EXECUTED
        assert run["liveness"] == C.CONFIRMED_EXITED and run["process_created"]

    def _failed(self, tmp_path, maker, launches=1, **kwargs):
        deps, launched, listener = _prober(FakeClock(), maker, **kwargs)
        outcome = C.run_probe("probe-01", tmp_path, deps)
        assert not outcome.passed and not outcome.ownership_released
        assert (tmp_path / C.PROBE_OWNER_FILE).exists() and listener.closed
        assert _probe_record(tmp_path)["ownership"] == "retained for review"
        assert len(launched) == launches
        return outcome

    @pytest.mark.parametrize("listener, message", [
        (FakeListener(counts=(0,)), "counted 0 control connections"),
        (FakeListener(counts=(2,)), "counted 2 control connections"),
        (FakeListener(control_error=ConnectionRefusedError()), "control connection failed"),
    ])
    def test_unverified_listener_blocks_the_launch(self, tmp_path, listener, message):
        outcome = self._failed(tmp_path, probe_child(), launches=0, listener=listener)
        assert "not verified before launch" in outcome.stopped_reason
        assert message in outcome.stopped_reason
        assert not _journal(tmp_path, "launch", "probe-01").exists()

    def test_reached_listener_fails(self, tmp_path):
        outcome = self._failed(tmp_path, probe_child(), listener=FakeListener(counts=(1, 1, 1)))
        assert "loopback is NOT denied" in outcome.stopped_reason

    def test_listener_lost_after_the_child(self, tmp_path):
        outcome = self._failed(tmp_path, probe_child(), listener=FakeListener(counts=(1, 0, 0)))
        assert "not verified after the child" in outcome.stopped_reason

    def test_inconclusive_child_error_fails(self, tmp_path):
        def refused(port):
            raise _wsa(10061, ConnectionRefusedError)

        outcome = self._failed(tmp_path, probe_child(connect=refused))
        assert "probe failed" in outcome.stopped_reason
        assert any("not denied with WSAEACCES (outcome 'refused')" in p
                   for p in outcome.entry["result_problems"])

    @pytest.mark.parametrize("identity, message", [
        ((999, SPACED_PYTHON), "PID differs"),
        ((4242, r"C:\other\python.exe"), "another executable"),
    ])
    def test_child_identity_mismatch_fails(self, tmp_path, identity, message):
        outcome = self._failed(tmp_path, probe_child(identity=identity))
        assert message in outcome.stopped_reason

    def test_exit_code_mismatch(self, tmp_path):
        outcome = self._failed(tmp_path, probe_child(returncode=1))
        assert "probe failed" in outcome.stopped_reason

    def test_launch_failure_keeps_the_process_evidence(self, tmp_path):
        def failing(command):
            raise C.LaunchFailure("AppContainer token rejected; could not be discarded",
                                  pid=4242, execution_history=C.NEVER_EXECUTED,
                                  liveness=C.STATE_UNKNOWN, handles_retained=True,
                                  cleanup_errors=["TerminateProcess failed"])

        outcome = self._failed(tmp_path, failing)
        assert "launch failed" in outcome.stopped_reason
        run = _probe_record(tmp_path)["run"]
        assert run["process_created"] and run["pid"] == 4242
        assert run["execution_history"] == C.NEVER_EXECUTED
        assert run["liveness"] == C.STATE_UNKNOWN and run["handles_retained"]
        assert run["cleanup_errors"] == ["TerminateProcess failed"]
        assert not _journal(tmp_path, "process", "probe-01").exists()

    def test_timeout_keeps_the_child(self, tmp_path):
        hung = FakeProcess(polls=None, pid=5150)
        outcome = self._failed(tmp_path, lambda c: hung)
        assert "PID 5150" in outcome.stopped_reason and not hung.killed
        run = _probe_record(tmp_path)["run"]
        assert run["liveness"] == C.ALIVE_AT_LAST_CHECK and run["handles_retained"]

    def test_observed_endpoint_fails(self, tmp_path):
        outcome = self._failed(tmp_path, lambda c: FakeProcess(polls=None), observe=lambda i: (
            C.Observation(["network endpoints or native network libraries observed"],
                          ["tcp 127.0.0.1:50000 127.0.0.1:50123 Established"], [PROC], True)))
        assert "network endpoints" in outcome.stopped_reason

    def test_listener_failure(self, tmp_path):
        def no_listener():
            raise OSError("bind failed")

        deps, launched, _ = _prober(FakeClock(), probe_child())
        deps.listener = no_listener
        outcome = C.run_probe("probe-01", tmp_path, deps)
        assert not outcome.passed and "OSError" in outcome.stopped_reason and launched == []
        assert (tmp_path / C.PROBE_OWNER_FILE).exists()

    def test_interruption(self, tmp_path):
        def interrupted(command):
            raise KeyboardInterrupt

        deps, _, listener = _prober(FakeClock(), interrupted)
        with pytest.raises(KeyboardInterrupt):
            C.run_probe("probe-01", tmp_path, deps)
        record = _probe_record(tmp_path)
        assert record["stopped_reason"] == "probe interrupted: KeyboardInterrupt"
        assert (tmp_path / C.PROBE_OWNER_FILE).exists() and listener.closed

    def test_existing_evidence_refused(self, tmp_path):
        (tmp_path / "probe-01.json").write_text("{}")
        deps, launched, _ = _prober(FakeClock(), probe_child())
        with pytest.raises(C.CalibrationError, match="never repeated"):
            C.run_probe("probe-01", tmp_path, deps)
        (tmp_path / "probe-01.json").unlink()
        (tmp_path / C.PROBE_OWNER_FILE).write_text("{}")
        with pytest.raises(C.CalibrationError, match="owns this directory"):
            C.run_probe("probe-01", tmp_path, deps)
        assert launched == []

    def test_explicit_dependencies(self, tmp_path):
        with pytest.raises(TypeError):
            C.run_probe("probe-01", tmp_path)
        with pytest.raises(TypeError):
            C.run_probe("probe-01", tmp_path, object())
        with pytest.raises(TypeError):
            C.probe_child_main("probe-01", tmp_path, object(), series_token=TOKEN, port=50123)


# ---------------------------------------------------------------------------
# Process-state evidence in the calibration journals
# ---------------------------------------------------------------------------

class TestCalibrationStateEvidence:
    def test_completed_run(self, tmp_path):
        deps, _ = _orchestrator(FakeClock(), [real_child()])
        C.run_series(1, tmp_path, deps)
        complete = _read(_journal(tmp_path, "complete", 1))
        assert complete["process_created"] and complete["liveness"] == C.CONFIRMED_EXITED
        assert complete["execution_history"] == C.MAY_HAVE_EXECUTED
        assert not complete["handles_retained"] and complete["cleanup_errors"] == []

    def test_launch_failure_evidence_reaches_the_series_record(self, tmp_path):
        def failing(command):
            raise C.LaunchFailure("resume failed", pid=4242,
                                  execution_history=C.MAY_HAVE_EXECUTED,
                                  liveness=C.CONFIRMED_EXITED)

        deps, _ = _orchestrator(FakeClock(), [failing])
        C.run_series(1, tmp_path, deps)
        for run in (_read(_journal(tmp_path, "complete", 1)), _series_record(tmp_path)["runs"][0]):
            assert run["execution_history"] == C.MAY_HAVE_EXECUTED and run["pid"] == 4242
            assert run["liveness"] == C.CONFIRMED_EXITED and run["process_created"]

    def test_failure_before_any_process(self, tmp_path):
        def failing(command):
            raise C.CalibrationError("no profile-preflight record is authorized")

        deps, _ = _orchestrator(FakeClock(), [failing])
        C.run_series(1, tmp_path, deps)
        complete = _read(_journal(tmp_path, "complete", 1))
        assert complete["process_created"] is False and complete["execution_history"] is None

    def test_timeout_is_alive_at_last_check(self, tmp_path):
        hung = FakeProcess(polls=None)
        deps, _ = _orchestrator(FakeClock(), [lambda c: hung])
        C.run_series(1, tmp_path, deps)
        complete = _read(_journal(tmp_path, "complete", 1))
        assert complete["liveness"] == C.ALIVE_AT_LAST_CHECK and complete["handles_retained"]


# ---------------------------------------------------------------------------
# Planned (JOB_LIST) creation plumbing over fake DLLs (J-41; no native call)
# ---------------------------------------------------------------------------

SC_ATTR = C.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
HL_ATTR = C.PROC_THREAD_ATTRIBUTE_HANDLE_LIST
JL_ATTR = C.PROC_THREAD_ATTRIBUTE_JOB_LIST
JOB_HANDLE = 0x500
CREATE_API = {"ConvertStringSidToSidW", "SetHandleInformation",
              "InitializeProcThreadAttributeList", "UpdateProcThreadAttribute",
              "DeleteProcThreadAttributeList", "CreateProcessW", "LocalFree",
              "ConvertSidToStringSidW", "CloseHandle", "FreeSid", "CoTaskMemFree"}


def _plan(entries=None, count=None):
    """A duck-typed plan, built without the job backend."""
    if entries is None:
        entries = [(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,))]
    return SimpleNamespace(
        entries=tuple(SimpleNamespace(attribute=a, name="entry", handles=h) for a, h in entries),
        count=len(entries) if count is None else count)


def _planned_setup(monkeypatch, tmp_path, **extra):
    command = _probe_command(tmp_path)
    state = {"env_len": len(C.environment_block(command.env)) + 1, "last_error": 122, **extra}
    win32, log = _fake_ctypes(monkeypatch, _create_fakes(state), state)
    return command, state, win32, log


def _create_planned(win32, command, plan, validator=W.validate_attribute_list_size,
                    custody=None):
    return win32.create_process(application=command.argv[0], command_line=command.command_line,
                                env=command.env, cwd=command.cwd, stdout=11, stderr=12,
                                sid=SID, attribute_plan=plan, size_validator=validator,
                                custody=C.HandleCustody() if custody is None else custody)


def _nothing_native(state, log):
    assert log == [] and state["loaded"] == []


def _unwound(state, *, initialized):
    assert state["inherit"][-2:] == [(11, 0), (12, 0)]       # inheritance restored
    assert state["freed"]                                       # the SID was freed
    assert bool(state.get("deleted")) is initialized            # list deleted iff initialized


class TestPlannedCreation:
    def test_no_plan_is_the_unchanged_legacy_creation(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        handles = win32.create_process(application=command.argv[0],
                                       command_line=command.command_line, env=command.env,
                                       cwd=command.cwd, stdout=11, stderr=12, sid=SID)
        assert state["sizing_count"] == state["attribute_count"] == 2
        assert [u[0] for u in state["updates"]] == [SC_ATTR, HL_ATTR]
        assert state["inherited"] == [11, 12] and "job_list" not in state
        assert handles.receipt == C.CreationReceipt((SC_ATTR, HL_ATTR), (), True, False)

    def test_three_attribute_plan_with_derived_count(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        plan = W.job_list_attribute_plan(JOB_HANDLE, 11, 12)
        handles = _create_planned(win32, command, plan)
        assert plan.count == state["sizing_count"] == state["attribute_count"] == 3
        assert handles.pid == 4242 and handles.cleanup_errors == []
        assert log.count("InitializeProcThreadAttributeList") == 2
        assert log.count("UpdateProcThreadAttribute") == 3 and log.count("CreateProcessW") == 1
        smaller = _plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,))])
        assert smaller.count == 3                                # derived, not written down

    def test_identifiers_and_order(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        handles = _create_planned(win32, command, _plan())
        assert [u[0] for u in state["updates"]] == [0x00020009, 0x00020002, 0x0002000D]
        assert handles.receipt.applied_attributes == (0x00020009, 0x00020002, 0x0002000D)
        assert C.PLAN_ATTRIBUTES == handles.receipt.applied_attributes

    def test_job_list_is_a_handle_array(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        _create_planned(win32, command, _plan())
        t = C._win32_types()
        job_update = [u for u in state["updates"] if u[0] == JL_ATTR][0]
        assert job_update[2] == t.ctypes.sizeof(t.w.HANDLE) and state["job_list"] == [JOB_HANDLE]

    def test_security_capabilities_structure(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        _create_planned(win32, command, _plan())
        t = C._win32_types()
        sc_update = [u for u in state["updates"] if u[0] == SC_ATTR][0]
        assert sc_update[2] == t.ctypes.sizeof(t.SECURITY_CAPABILITIES)
        assert state["capabilities"] == (0x5001, 0, False)         # the SID, zero capabilities

    def test_handle_list_is_only_the_authorized_standard_handles(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        _create_planned(win32, command, _plan())
        assert state["inherited"] == [11, 12] and JOB_HANDLE not in state["inherited"]
        assert state["inherit"] == [(11, 1), (12, 1), (11, 0), (12, 0)]   # only stdio inherits

    def test_pointer_aligned_buffer(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path, size=65)
        t = C._win32_types()

        def refuse(*args, **kwargs):
            raise LiveAccessAttempt("an unaligned character buffer")

        monkeypatch.setattr(t.ctypes, "create_string_buffer", refuse)
        _create_planned(win32, command, _plan())                    # never uses a char buffer
        assert state["buffer_address"] % t.ctypes.alignment(t.ctypes.c_void_p) == 0
        assert state["list_address"] == state["buffer_address"] == state["delete_address"]
        command2, state2, win32_2, _ = _planned_setup(monkeypatch, tmp_path)
        with pytest.raises(LiveAccessAttempt):                      # the legacy path does
            win32_2.create_process(application=command2.argv[0],
                                   command_line=command2.command_line, env=command2.env,
                                   cwd=command2.cwd, stdout=11, stderr=12, sid=SID)

    def test_works_with_the_job_backend_plan_and_validator(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        handles = _create_planned(win32, command, W.job_list_attribute_plan(JOB_HANDLE, 11, 12))
        assert handles.receipt.job_list_handles == (JOB_HANDLE,)
        assert handles.receipt.job_list_applied is True

    # -- sizing ------------------------------------------------------------

    @pytest.mark.parametrize("extra, message", [
        ({"first_result": 1}, "not FALSE"),
        ({"last_error": 87}, "ERROR_INSUFFICIENT_BUFFER"),
        ({"last_error": 0}, "ERROR_INSUFFICIENT_BUFFER"),
        ({"size": 0}, "implausible attribute-list size"),
        ({"size": 4097}, "implausible attribute-list size"),
    ])
    def test_sizing_refusals(self, monkeypatch, tmp_path, extra, message):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path, **extra)
        with pytest.raises(W.PlanRefused, match=message):
            _create_planned(win32, command, _plan())
        assert log.count("InitializeProcThreadAttributeList") == 1
        assert "UpdateProcThreadAttribute" not in log and "CreateProcessW" not in log
        _unwound(state, initialized=False)

    def test_sizing_accepts_the_documented_contract(self, monkeypatch, tmp_path):
        for size in (1, 64, 4096):
            command, state, win32, _ = _planned_setup(monkeypatch, tmp_path, size=size)
            assert _create_planned(win32, command, _plan()).pid == 4242

    def test_a_validator_is_required_and_must_not_change_the_size(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        with pytest.raises(C.CalibrationError, match="needs its attribute-list size validator"):
            _create_planned(win32, command, _plan(), validator=None)
        _nothing_native(state, log)
        with pytest.raises(C.CalibrationError, match="without an attribute plan"):
            win32.create_process(application=command.argv[0], command_line=command.command_line,
                                 env=command.env, cwd=command.cwd, stdout=11, stderr=12,
                                 sid=SID, size_validator=W.validate_attribute_list_size)
        _nothing_native(state, log)
        with pytest.raises(C.CalibrationError, match="changed the attribute-list size"):
            _create_planned(win32, command, _plan(), validator=lambda f, e, s: s + 8)
        _unwound(state, initialized=False)

    def test_second_initialization_failure(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path, second_ok=0)
        with pytest.raises(C.Win32Error, match="InitializeProcThreadAttributeList"):
            _create_planned(win32, command, _plan())
        assert log.count("InitializeProcThreadAttributeList") == 2
        assert "UpdateProcThreadAttribute" not in log and "CreateProcessW" not in log
        _unwound(state, initialized=False)                          # never initialized: no delete

    # -- updates and creation ---------------------------------------------------

    @pytest.mark.parametrize("position", [0, 1, 2])
    def test_update_failure_at_each_position(self, monkeypatch, tmp_path, position):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path,
                                                    update_fail_at=position)
        with pytest.raises(C.Win32Error, match="UpdateProcThreadAttribute"):
            _create_planned(win32, command, _plan())
        assert len(state["updates"]) == position + 1                # stopped at the failure
        assert "CreateProcessW" not in log                          # no fallback creation
        _unwound(state, initialized=True)

    def test_create_process_failure(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path, create_ok=0)
        with pytest.raises(C.Win32Error, match="CreateProcessW"):
            _create_planned(win32, command, _plan())
        assert log.count("CreateProcessW") == 1                     # attempted once, never retried
        assert log.count("UpdateProcThreadAttribute") == 3
        _unwound(state, initialized=True)

    def test_attribute_values_live_until_cleanup(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path,
                                                  during_create=gc.collect)
        _create_planned(win32, command, _plan())
        assert len(state["update_bytes"]) == 3
        assert state["bytes_at_create"] == state["update_bytes"]    # intact at CreateProcessW
        assert state["bytes_at_delete"] == state["update_bytes"]    # and at the list's deletion

    # -- the receipt ---------------------------------------------------------

    def test_receipt_is_immutable(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        receipt = _create_planned(win32, command, _plan()).receipt
        assert isinstance(receipt, C.CreationReceipt)
        assert isinstance(receipt.applied_attributes, tuple)
        assert isinstance(receipt.job_list_handles, tuple)
        for name, value in (("planned", False), ("applied_attributes", ()),
                            ("create_process_ok", False)):
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(receipt, name, value)

    def test_receipt_distinguishes_planned_from_legacy(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        planned = _create_planned(win32, command, _plan()).receipt
        assert planned == C.CreationReceipt(C.PLAN_ATTRIBUTES, (JOB_HANDLE,), True, True)
        assert planned.job_list_applied is True
        command2, state2, win32_2, _ = _planned_setup(monkeypatch, tmp_path)
        legacy = win32_2.create_process(application=command2.argv[0],
                                        command_line=command2.command_line, env=command2.env,
                                        cwd=command2.cwd, stdout=11, stderr=12, sid=SID).receipt
        assert legacy.planned is False and legacy.job_list_applied is False
        assert legacy.job_list_handles == () and JL_ATTR not in legacy.applied_attributes

    def test_receipt_records_native_results_not_the_request(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        original = C.CreationReceipt
        applied_when_built = []

        def spy(applied, jobs, ok, planned):
            applied_when_built.append((tuple(u[0] for u in state["updates"]), applied))
            return original(applied, jobs, ok, planned)

        monkeypatch.setattr(C, "CreationReceipt", spy)
        _create_planned(win32, command, _plan())
        assert applied_when_built == [(C.PLAN_ATTRIBUTES, C.PLAN_ATTRIBUTES)]

    def test_receipt_claims_no_membership(self):
        fields = {f.name for f in dataclasses.fields(C.CreationReceipt)}
        assert fields == {"applied_attributes", "job_list_handles", "create_process_ok",
                          "planned"}
        assert "membership" not in inspect.getsource(C.CreationReceipt).split('"""')[2]

    # -- invalid plans ------------------------------------------------------------

    @pytest.mark.parametrize("plan, message", [
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (HL_ATTR, (11, 12))]), "duplicate"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12))]), "lacks an attribute: 0x2000d"),
        (_plan([(HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,))]), "lacks an attribute: 0x20009"),
        (_plan([(SC_ATTR, ()), (JL_ATTR, (JOB_HANDLE,))]), "lacks an attribute: 0x20002"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,)),
                (0x00020007, ())]), "unexpected attribute: 0x20007"),
        (_plan([(JL_ATTR, (JOB_HANDLE,)), (SC_ATTR, ()), (HL_ATTR, (11, 12))]),
         "not in the accepted order"),
        (_plan(count=5), "count is not derived"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,))], count=True),
         "count is not derived"),
        (_plan([(True, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,))]), "malformed entry"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, [11, 12]), (JL_ATTR, (JOB_HANDLE,))]),
         "malformed entry"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (0, 12)), (JL_ATTR, (JOB_HANDLE,))]), "malformed entry"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (-1,))]), "malformed entry"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (True,))]), "malformed entry"),
        (_plan([(SC_ATTR, (5,)), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE,))]),
         "carries handles"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11,)), (JL_ATTR, (JOB_HANDLE,))]),
         "not exactly the authorized"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (12, 11)), (JL_ATTR, (JOB_HANDLE,))]),
         "not exactly the authorized"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12, 13)), (JL_ATTR, (JOB_HANDLE,))]),
         "not exactly the authorized"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 13)), (JL_ATTR, (JOB_HANDLE,))]),
         "not exactly the authorized"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (JOB_HANDLE, 0x600))]),
         "exactly one handle"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, ())]), "exactly one handle"),
        (_plan([(SC_ATTR, ()), (HL_ATTR, (11, 12)), (JL_ATTR, (11,))]),
         "never be in the inherited handle list"),
        (_plan([]), "no entries"),
        (object(), "no entries"),
        (SimpleNamespace(entries="abc", count=3), "no entries"),
    ])
    def test_invalid_plans_refuse_before_any_native_call(self, monkeypatch, tmp_path, plan,
                                                         message):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        with pytest.raises(C.CalibrationError, match=message):
            _create_planned(win32, command, plan)
        _nothing_native(state, log)

    # -- cleanup, fallbacks, isolation --------------------------------------------------

    @pytest.mark.parametrize("fault, expected", [
        ("reset_fails", "could not reset inheritance"),
        ("delete_raises", "DeleteProcThreadAttributeList"),
        ("local_free_fails", "LocalFree of the AppContainer SID failed"),
    ])
    def test_cleanup_failure_never_loses_the_planned_process(self, monkeypatch, tmp_path, fault,
                                                             expected):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path, **{fault: True})
        handles = _create_planned(win32, command, _plan())
        assert (handles.process, handles.thread, handles.pid) == (101, 102, 4242)
        assert any(expected in e for e in handles.cleanup_errors)
        assert handles.receipt.job_list_applied is True            # the receipt is untouched

    def test_no_after_creation_assignment_or_legacy_fallback(self, monkeypatch, tmp_path):
        for extra in ({"update_fail_at": 2}, {"create_ok": 0}, {"second_ok": 0},
                      {"first_result": 1}):
            command, state, win32, log = _planned_setup(monkeypatch, tmp_path, **extra)
            with pytest.raises(C.CalibrationError):
                _create_planned(win32, command, _plan())
            assert set(log) <= CREATE_API                           # nothing else is reachable
            assert log.count("CreateProcessW") <= 1                 # no second, legacy attempt
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        assert "AssignProcess" not in code and "JobObject" not in code

    def test_only_the_injected_fake_dlls_are_loaded(self, monkeypatch, tmp_path):
        command, state, win32, _ = _planned_setup(monkeypatch, tmp_path)
        _create_planned(win32, command, _plan())
        assert state["loaded"] == ["advapi32", "kernel32"]

    def test_closed_gate_stops_a_planned_creation(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        monkeypatch.setattr(C, "PROBE_ENABLED", False)
        with pytest.raises(C.ExecutionDisabled):
            _create_planned(win32, command, _plan())
        _nothing_native(state, log)

    def test_the_production_path_passes_no_plan(self, monkeypatch, tmp_path):
        open_probe_gate(monkeypatch)
        win32 = FakeWin32()
        api = C.Win32AppContainerApi(C.authorize_probe("probe-01", HEAD), win32=win32)
        command = _probe_command(tmp_path)
        api.create_suspended(command, SID, (), 1, 2)
        assert "attribute_plan" not in win32.created and "size_validator" not in win32.created
        for function in (C.Win32AppContainerApi.create_suspended, C.AppContainerLauncher.__call__,
                         C.Win32AppContainerApi.resume):
            source = inspect.getsource(function)
            assert "attribute_plan" not in source and "size_validator" not in source
        defaults = inspect.signature(C.CtypesWin32.create_process).parameters
        assert defaults["attribute_plan"].default is None
        assert defaults["size_validator"].default is None

    def test_no_integration_or_gate_activation(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        for word in ("win32_job", "CreationAssertion", "JobController", "evidence_store",
                     "JOB_LIST_CREATION_INTEGRATED"):
            assert word not in code, word
        assert W.JOB_LIST_CREATION_INTEGRATED is False
        assert (C.EXECUTION_ENABLED, C.APPROVED_CALIBRATIONS, C.PROBE_ENABLED,
                C.APPROVED_PROBES, C.AUTHORIZED_APPCONTAINER_SID,
                C.AUTHORIZED_PROFILE_PREFLIGHT_SHA256) == (False, frozenset(), False,
                                                          frozenset(), None, None)
        assert C.APPCONTAINER_CAPABILITIES == () and not (C.CREATION_FLAGS & 0x01000000)


# ---------------------------------------------------------------------------
# Handle custody of the planned creation (B3J-47b; fakes only, no native call)
# ---------------------------------------------------------------------------

PROCESS_VALUES = (101, 102, 4242, 77)             # what the fake CreateProcessW writes


class TestHandleCustody:
    @pytest.fixture(autouse=True)
    def no_real_dll(self, monkeypatch):
        import ctypes

        def refuse(*args, **kwargs):
            raise LiveAccessAttempt("a real DLL load attempted")

        monkeypatch.setattr(ctypes, "WinDLL", refuse)

    # -- the holder itself ---------------------------------------------------

    def test_a_new_custody_holds_nothing(self):
        custody = C.HandleCustody()
        assert custody.attached is False and custody.entered is False
        assert custody.raw_values() is None
        assert custody.snapshot() == C.CustodySnapshot(False, False, False, False, True, False)

    def test_attachment_is_write_once(self):
        t = C._win32_types()
        custody = C.HandleCustody()
        first = t.PROCESS_INFORMATION()
        custody.attach(first)
        with pytest.raises(C.CalibrationError, match="already holds"):
            custody.attach(t.PROCESS_INFORMATION())
        assert custody.raw_values() == (None, None, 0, 0) and custody._info is first

    def test_entry_is_write_once_and_needs_a_structure(self):
        t = C._win32_types()
        custody = C.HandleCustody()
        with pytest.raises(C.CalibrationError, match="no structure attached"):
            custody.mark_entered()
        custody.attach(t.PROCESS_INFORMATION())
        custody.mark_entered()
        assert custody.entered is True
        with pytest.raises(C.CalibrationError, match="already entered"):
            custody.mark_entered()
        assert custody.entered is True

    def test_only_a_zeroed_process_information_is_taken(self):
        t = C._win32_types()
        custody = C.HandleCustody()
        for wrong in (object(), None, 5, t.FILETIME()):
            with pytest.raises(C.CalibrationError, match="only a PROCESS_INFORMATION"):
                custody.attach(wrong)
        stale = t.PROCESS_INFORMATION()
        stale.hProcess = 99
        with pytest.raises(C.CalibrationError, match="only a zeroed structure"):
            custody.attach(stale)
        assert custody.attached is False

    def test_no_close_reset_detach_or_finalizer_and_no_stray_state(self):
        for name in ("close", "reset", "detach", "terminate", "recover", "release",
                     "__del__"):
            assert not hasattr(C.HandleCustody, name), name
        custody = C.HandleCustody()
        assert not hasattr(custody, "__dict__")
        with pytest.raises(AttributeError):
            custody.extra = 1
        with pytest.raises(AttributeError):
            custody.attached = True
        with pytest.raises(AttributeError):
            custody.entered = True

    def test_observation_means_a_plausible_value_only(self):
        t = C._win32_types()
        custody = C.HandleCustody()
        info = t.PROCESS_INFORMATION()
        custody.attach(info)
        custody.mark_entered()
        for value in (0, -1, (1 << 32) - 1):
            info.hProcess = info.hThread = value
            snap = custody.snapshot()
            assert not snap.process_handle_observed and not snap.thread_handle_observed
        info.hProcess = 101
        snap = custody.snapshot()
        assert snap.process_handle_observed and not snap.thread_handle_observed
        assert snap.readable and not snap.inconsistent
        info.hThread = 102
        assert custody.snapshot().thread_handle_observed

    def test_a_handle_without_entry_is_flagged_inconsistent(self):
        t = C._win32_types()
        custody = C.HandleCustody()
        info = t.PROCESS_INFORMATION()
        custody.attach(info)
        info.hProcess = 101
        snap = custody.snapshot()
        assert snap.process_handle_observed and snap.entered is False and snap.inconsistent

    def test_an_unreadable_structure_is_reported_and_never_raises(self):
        class Broken:
            def __getattr__(self, name):
                raise OSError("unreadable")

        custody = C.HandleCustody()
        custody._info = Broken()
        snap = custody.snapshot()
        assert snap == C.CustodySnapshot(True, False, False, False, False, False)

    def test_snapshot_is_immutable(self):
        snap = C.HandleCustody().snapshot()
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.readable = False

    # -- observation must never raise, whatever interrupts it ----------------------

    @pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(9), GeneratorExit(),
                                         RuntimeError("unreadable")])
    def test_a_failing_read_is_reported_unreadable_never_raised(self, failure):
        class Unreadable:
            def __getattr__(self, name):
                raise failure

        custody = C.HandleCustody()
        custody._info = Unreadable()
        custody._entered = True
        snap = custody.snapshot()
        assert snap == C.CustodySnapshot(True, True, False, False, False, False)
        assert not snap.readable and not snap.process_handle_observed
        assert not snap.thread_handle_observed and not snap.inconsistent

    @pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(9)])
    def test_a_failing_validity_check_is_reported_unreadable(self, monkeypatch, failure):
        t = C._win32_types()
        custody = C.HandleCustody()
        info = t.PROCESS_INFORMATION()
        custody.attach(info)
        custody.mark_entered()
        info.hProcess = 101

        def broken(handle):
            raise failure

        monkeypatch.setattr(C, "_valid_handle", broken)
        snap = custody.snapshot()
        assert snap == C.CustodySnapshot(True, True, False, False, False, False)

    @pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(9)])
    def test_a_failure_building_the_snapshot_yields_the_unreadable_constant(
            self, monkeypatch, failure):
        custody = C.HandleCustody()

        def broken(*args, **kwargs):
            raise failure

        monkeypatch.setattr(C, "CustodySnapshot", broken)
        snap = custody.snapshot()
        assert snap is C._UNREADABLE_SNAPSHOT
        assert (snap.attached, snap.entered, snap.readable, snap.process_handle_observed,
                snap.thread_handle_observed, snap.inconsistent) == (
            False, False, False, False, False, False)

    def test_the_unreadable_snapshot_claims_nothing_and_is_immutable(self):
        snap = C._UNREADABLE_SNAPSHOT
        assert isinstance(snap, C.CustodySnapshot) and snap.readable is False
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.process_handle_observed = True

    def test_observation_does_not_alter_the_custody(self):
        t = C._win32_types()
        custody = C.HandleCustody()
        info = t.PROCESS_INFORMATION()
        custody.attach(info)
        custody.mark_entered()
        info.hProcess, info.hThread = 101, 102
        first = custody.snapshot()
        assert custody.snapshot() == first
        assert custody.raw_values() == (101, 102, 0, 0)
        assert custody.attached and custody.entered

    # -- the creator's contract (all refusals precede any native call) ----------

    def test_a_planned_creation_needs_custody(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        for wrong in (None, object(), "custody"):
            with pytest.raises(C.CalibrationError, match="needs its handle custody"):
                win32.create_process(application=command.argv[0],
                                     command_line=command.command_line, env=command.env,
                                     cwd=command.cwd, stdout=11, stderr=12, sid=SID,
                                     attribute_plan=_plan(),
                                     size_validator=W.validate_attribute_list_size,
                                     custody=wrong)
        _nothing_native(state, log)

    def test_the_legacy_creation_refuses_a_custody(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        custody = C.HandleCustody()
        with pytest.raises(C.CalibrationError, match="without an attribute plan"):
            win32.create_process(application=command.argv[0],
                                 command_line=command.command_line, env=command.env,
                                 cwd=command.cwd, stdout=11, stderr=12, sid=SID,
                                 custody=custody)
        _nothing_native(state, log)
        assert custody.attached is False and custody.entered is False

    def test_a_used_custody_is_refused_before_anything_native(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        custody = C.HandleCustody()
        handles = _create_planned(win32, command, _plan(), custody=custody)
        calls = log.count("CreateProcessW")
        before = custody.raw_values()
        with pytest.raises(C.CalibrationError, match="already used"):
            _create_planned(win32, command, _plan(), custody=custody)
        assert log.count("CreateProcessW") == calls == 1       # never a second creation
        assert custody.raw_values() == before == PROCESS_VALUES
        assert handles.process == 101

    def test_an_entered_or_attached_custody_is_refused(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        attached = C.HandleCustody()
        attached.attach(C._win32_types().PROCESS_INFORMATION())
        with pytest.raises(C.CalibrationError, match="already used"):
            _create_planned(win32, command, _plan(), custody=attached)
        _nothing_native(state, log)

    def test_the_signature_keeps_custody_optional_and_keyword_only(self):
        parameter = inspect.signature(C.CtypesWin32.create_process).parameters["custody"]
        assert parameter.default is None and parameter.kind is parameter.KEYWORD_ONLY

    # -- success, and what custody holds ----------------------------------------

    def test_success_is_unchanged_and_custody_holds_the_handles(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        custody = C.HandleCustody()
        seen = {}
        state["during_create"] = lambda: seen.update(
            attached=custody.attached, entered=custody.entered,
            updates=log.count("UpdateProcThreadAttribute"))
        handles = _create_planned(win32, command, _plan(), custody=custody)
        assert seen == {"attached": True, "entered": True, "updates": 3}
        assert (handles.process, handles.thread, handles.pid, handles.tid) == PROCESS_VALUES
        assert custody.raw_values() == PROCESS_VALUES
        assert custody.snapshot() == C.CustodySnapshot(True, True, True, True, True, False)
        assert handles.receipt == C.CreationReceipt(C.PLAN_ATTRIBUTES, (JOB_HANDLE,), True, True)
        _unwound(state, initialized=True)
        assert "CloseHandle" not in log

    @pytest.mark.parametrize("position", [0, 1, 2])
    def test_an_update_failure_never_attaches_or_enters(self, monkeypatch, tmp_path, position):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path,
                                                    update_fail_at=position)
        custody = C.HandleCustody()
        with pytest.raises(C.Win32Error, match="UpdateProcThreadAttribute"):
            _create_planned(win32, command, _plan(), custody=custody)
        assert custody.snapshot() == C.CustodySnapshot(False, False, False, False, True, False)
        assert "CreateProcessW" not in log

    def test_a_refused_plan_never_attaches_or_enters(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        custody = C.HandleCustody()
        with pytest.raises(C.CalibrationError):
            _create_planned(win32, command, _plan(count=7), custody=custody)
        _nothing_native(state, log)
        assert custody.attached is False and custody.entered is False

    def test_a_false_return_leaves_the_call_entered_and_no_handle(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path, create_ok=0)
        custody = C.HandleCustody()
        with pytest.raises(C.Win32Error, match="CreateProcessW"):
            _create_planned(win32, command, _plan(), custody=custody)
        assert custody.snapshot() == C.CustodySnapshot(True, True, False, False, True, False)
        assert log.count("CreateProcessW") == 1
        _unwound(state, initialized=True)

    # -- interruptions after the native call --------------------------------------

    @pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(3), GeneratorExit(),
                                         RuntimeError("after the call")])
    def test_interruption_after_the_call_keeps_identity_and_the_handles(
            self, monkeypatch, tmp_path, failure):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        state["after_create"] = lambda: (_ for _ in ()).throw(failure)
        custody = C.HandleCustody()
        with pytest.raises(type(failure)) as raised:
            _create_planned(win32, command, _plan(), custody=custody)
        assert raised.value is failure                         # never wrapped or replaced
        assert custody.raw_values() == PROCESS_VALUES
        assert custody.snapshot() == C.CustodySnapshot(True, True, True, True, True, False)
        _unwound(state, initialized=True)                       # the unwinding still ran
        assert "CloseHandle" not in log                         # nothing was closed

    @pytest.mark.parametrize("target", ["Win32Handles", "CreationReceipt"])
    def test_a_failure_building_the_result_keeps_the_handles(self, monkeypatch, tmp_path,
                                                             target):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        failure = KeyboardInterrupt()

        def broken(*args, **kwargs):
            raise failure

        monkeypatch.setattr(C, target, broken)
        custody = C.HandleCustody()
        with pytest.raises(KeyboardInterrupt) as raised:
            _create_planned(win32, command, _plan(), custody=custody)
        assert raised.value is failure
        assert custody.raw_values() == PROCESS_VALUES
        assert custody.snapshot().process_handle_observed
        _unwound(state, initialized=True)
        assert "CloseHandle" not in log

    def test_handles_stay_reachable_and_open_after_the_custody_is_dropped_elsewhere(
            self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        state["after_create"] = lambda: (_ for _ in ()).throw(RuntimeError("x"))
        custody = C.HandleCustody()
        with pytest.raises(RuntimeError):
            _create_planned(win32, command, _plan(), custody=custody)
        gc.collect()
        assert custody.raw_values() == PROCESS_VALUES and "CloseHandle" not in log

    # -- the legacy creation is unchanged -------------------------------------------

    def test_the_legacy_creation_is_unchanged(self, monkeypatch, tmp_path):
        command, state, win32, log = _planned_setup(monkeypatch, tmp_path)
        handles = win32.create_process(application=command.argv[0],
                                       command_line=command.command_line, env=command.env,
                                       cwd=command.cwd, stdout=11, stderr=12, sid=SID)
        assert (handles.process, handles.thread, handles.pid, handles.tid) == PROCESS_VALUES
        assert handles.receipt == C.CreationReceipt((SC_ATTR, HL_ATTR), (), True, False)

    def test_the_source_guards_still_hold(self):
        code = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        for word in ("win32_job", "CreationAssertion", "JobController", "evidence_store",
                     "JOB_LIST_CREATION_INTEGRATED", "ContainmentAdapter"):
            assert word not in code, word
        body = code.split('"""', 2)[2]
        for word in ("__del__", "atexit", "weakref"):
            assert word not in body, word

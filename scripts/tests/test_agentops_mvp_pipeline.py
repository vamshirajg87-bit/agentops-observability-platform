"""
scripts/tests/test_agentops_mvp_pipeline.py

Offline tests of the detector-to-RCA runner (scripts/agentops_mvp_pipeline.py) and of the disposable
validation environment it targets (docker/mvp-workers-pipetest/compose.yml).

Nothing real is ever run.  Every container command goes to a fake engine that records it, every lock is
a fake, and an autouse fixture makes any real subprocess, shell, socket or executable lookup raise.  No
Docker, no database, no network, no process.

    P01  Command construction
    P02  Credentials location and secret handling
    P03  The target registry and the protection of the accepted MVP
    P04  Identity of the accepted target (the existing contract, unchanged)
    P05  Identity of the disposable target (exact equality only)
    P06  Conflicting workers and the lock
    P07  Dry run
    P08  Detector stage
    P09  Pending discovery
    P10  RCA stage
    P11  Idempotent reruns and the final check
    P12  Timeouts and interrupts
    P13  Secret canaries
    P14  Detector configuration (mart-signal refusal)
    P15  Compose contracts (the accepted worker project and the disposable one)
    P16  Static properties of the module (no shell, one place that starts a process)
    P17  The offline guard itself
"""

from __future__ import annotations

import ast
import builtins
import dataclasses
import hashlib
import io
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentops_mvp as creds  # noqa: E402
import agentops_mvp_demo as demo  # noqa: E402
import agentops_mvp_lifecycle as lifecycle  # noqa: E402
import agentops_mvp_pipeline as pipe  # noqa: E402
import agentops_mvp_workers as workers  # noqa: E402

_REPO = Path(pipe.__file__).resolve().parents[1]
_PIPE_SOURCE = Path(pipe.__file__)
_COMPOSE = _REPO / "docker" / "mvp-workers" / "compose.yml"
_PIPETEST_COMPOSE = _REPO / "docker" / "mvp-workers-pipetest" / "compose.yml"
_CANARY = "CANARY-SECRET-5c1e9a"
ACCEPTED = pipe.TARGETS["accepted"]
PIPETEST = pipe.TARGETS["pipetest"]
_ACCEPTED_NAMES = ("agentops-mvp-workers", "agentops-mvp-workers-postgres-1", "agentops-mvp-workers-postgres-data",
                   "agentops-mvp-workers-net")
_PIPETEST_NAMES = ("agentops-pipetest", "agentops-pipetest-postgres-1", "agentops-pipetest-pgdata",
                   "agentops-pipetest-net")


def _ids(n: int) -> list[str]:
    return [hashlib.sha256(f"anomaly-{i}".encode()).hexdigest() for i in range(n)]


# ---------------------------------------------------------------------------
# The offline guard: any attempt to reach the outside world fails the test
# ---------------------------------------------------------------------------

def _blocked(*_a, **_k):
    raise AssertionError("external access blocked by the offline guard")


@pytest.fixture(autouse=True)
def _offline_guard(monkeypatch):
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _blocked)
    monkeypatch.setattr(os, "system", _blocked)
    monkeypatch.setattr(shutil, "which", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeEngine:
    """Answers every command of the runner from a small model of ONE target and records each one.

    Any command that names a resource of the OTHER target, or that addresses its own target wrongly, is
    recorded in `violations`; every test that goes through go() asserts that list stays empty."""

    def __init__(self, *, target="pipetest", pending=(), detector_adds=(), detector_code=0, rca_codes=None,
                 rca_default=0, persist=True, facts=None, volume_facts=None, network_facts=None, ledger=None,
                 workers_running=(), workers_running_after=None, no_evidence=(), read_overrides=None,
                 raise_at=None, noisy=False, facts_after_detector=None):
        self.target = target
        self.t = pipe.TARGETS[target]
        self.pending = list(pending)
        self.detector_adds, self.detector_code = list(detector_adds), detector_code
        self.rca_codes, self.rca_default, self.persist = dict(rca_codes or {}), rca_default, persist
        default_facts = (workers._EXPECTED_FACTS + "|{}") if target == "accepted" \
            else pipe.expected_container_facts(self.t) + "|{}"
        self.facts = facts if facts is not None else default_facts
        self.facts_after_detector = facts_after_detector
        self.volume_facts = volume_facts if volume_facts is not None else pipe.expected_volume_facts(self.t)[0]
        self.network_facts = network_facts if network_facts is not None else pipe.expected_network_facts(self.t)
        self.ledger = ledger if ledger is not None else "\n".join(
            f"{i + 1}|{s}" for i, s in enumerate(demo.EXPECTED_LEDGER_STEPS))
        self.workers_running, self.workers_running_after = list(workers_running), workers_running_after
        self.no_evidence = list(no_evidence)
        self.read_overrides = dict(read_overrides or {})   # (kind, ordinal) -> CommandResult | Exception
        self.raise_at = dict(raise_at or {})               # event -> exception to raise
        self.noisy = noisy
        self.calls: list[tuple[list[str], dict, float]] = []
        self.events: list[str] = []
        self.compose: list[tuple[str, str]] = []
        self.violations: list[str] = []
        self._counts: dict[str, int] = {}
        self.detector_ran = False

    def _tick(self, kind: str) -> int:
        n = self._counts.get(kind, 0)
        self._counts[kind] = n + 1
        return n

    def _audit(self, argv):
        other = _PIPETEST_NAMES[0] if self.target == "accepted" else _ACCEPTED_NAMES[0]
        if any(other in a for a in argv):
            self.violations.append(f"names the other target: {argv[:3]}")
        if argv[1] == "compose":
            if argv[argv.index("-p") + 1] != self.t.project:
                self.violations.append("wrong project")
            if not argv[argv.index("-f") + 1].replace("\\", "/").endswith(self.t.compose_file):
                self.violations.append("wrong compose file")
        if argv[1] == "exec" and argv[argv.index("psql") - 1] != self.t.postgres_container:
            self.violations.append("wrong container")
        if argv[1] == "inspect" and argv[-1] != self.t.postgres_container:
            self.violations.append("wrong container inspected")
        if argv[1] == "volume" and argv[-1] != self.t.volume:
            self.violations.append("wrong volume inspected")
        if argv[1] == "network" and argv[-1] != self.t.network:
            self.violations.append("wrong network inspected")
        if argv[1] == "ps" and f"label=com.docker.compose.project={self.t.project}" not in argv:
            self.violations.append("wrong project filter")
        if argv[1] not in ("inspect", "ps", "exec", "compose", "volume", "network"):
            self.violations.append(f"unexpected verb {argv[1]}")
        if argv[1] in ("volume", "network") and argv[2] != "inspect":
            self.violations.append(f"unexpected {argv[1]} verb {argv[2]}")

    def __call__(self, argv, env, timeout):
        self.calls.append((list(argv), dict(env), timeout))
        self._audit(argv)
        verb = argv[1]
        if verb == "inspect":
            return self._done("inspect", workers.CommandResult(0, (
                self.facts_after_detector if self.detector_ran and self.facts_after_detector is not None
                else self.facts).encode()))
        if verb == "volume":
            return self._done("volume", workers.CommandResult(0, self.volume_facts.encode()))
        if verb == "network":
            return self._done("network", workers.CommandResult(0, self.network_facts.encode()))
        if verb == "ps":
            n = self._tick("ps")
            ids = self.workers_running if n == 0 or self.workers_running_after is None else self.workers_running_after
            return self._done("ps", workers.CommandResult(0, "\n".join(ids).encode()))
        if verb == "exec":
            sql = argv[argv.index("-c") + 1]
            if sql == demo.LEDGER_SQL:
                return self._done("read:ledger", workers.CommandResult(0, self.ledger.encode()))
            if sql == pipe.NO_EVIDENCE_SQL:
                return self._read("noevidence", "\n".join(self.no_evidence))
            if sql.startswith("SELECT a.anomaly_id"):
                limit = int(re.search(r"LIMIT (\d+)$", sql).group(1))
                return self._read("pending", "\n".join(self.pending[:limit]))
            raise AssertionError(sql)
        if verb == "compose":
            service = next(a for a in argv if a in (pipe.DETECTOR_SERVICE, pipe.RCA_SERVICE))
            if service == pipe.DETECTOR_SERVICE:
                self.events.append("compose:detector")
                self.compose.append((service, ""))
                self._maybe_raise("compose:detector")
                self.detector_ran = True
                if self.detector_code == 0:
                    self.pending += [i for i in self.detector_adds if i not in self.pending]
                return workers.CommandResult(self.detector_code, _CANARY.encode() if self.noisy else b"")
            anomaly_id = argv[-1]
            self.events.append(f"compose:rca:{anomaly_id[:8]}")
            self.compose.append((service, anomaly_id))
            self._maybe_raise(f"compose:rca:{anomaly_id[:8]}")
            code = self.rca_codes.get(anomaly_id, self.rca_default)
            if code == 0 and self.persist and anomaly_id in self.pending:
                self.pending.remove(anomaly_id)
            return workers.CommandResult(code, _CANARY.encode() if self.noisy else b"")
        raise AssertionError(argv)

    def _maybe_raise(self, event):
        if event in self.raise_at:
            raise self.raise_at[event]

    def _done(self, event, result):
        self.events.append(event)
        self._maybe_raise(event)
        return result

    def _read(self, kind, text):
        n = self._tick("read:" + kind)
        self.events.append(f"read:{kind}")
        self._maybe_raise(f"read:{kind}")
        override = self.read_overrides.get((kind, n))
        if isinstance(override, Exception):
            raise override
        if override is not None:
            return override
        return workers.CommandResult(0, text.encode())


class FakeLock:
    """Stands in for ExclusiveLock; records when it is taken and released into the engine's event list."""

    created: list["FakeLock"] = []

    def __init__(self, path, events=None, error=None):
        self.path, self.events, self.error = path, events if events is not None else [], error
        self.entered = self.exited = 0
        FakeLock.created.append(self)

    def __enter__(self):
        if self.error is not None:
            raise self.error
        self.entered += 1
        self.events.append("lock:enter")
        return self

    def __exit__(self, *exc):
        self.exited += 1
        self.events.append("lock:exit")
        return False


class World:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.home = str(tmp_path / "home")
        self.local = tmp_path / "local"
        self.environ = {"PATH": "p", "LOCALAPPDATA": str(self.local), "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
                        "POSTGRES_PASSWORD": _CANARY, "COMPOSE_PROJECT_NAME": "other", "DOCKER_CONFIG": "x",
                        "SystemRoot": "C:\\Windows"}
        # the disposable target's file lives in its own tree: <...>/agentops-pipetest/agentops-mvp/credentials.env
        pipe_dir = tmp_path / "pipetest-creds" / "agentops-pipetest" / creds.DIRECTORY_NAME
        pipe_dir.mkdir(parents=True)
        self.creds_file = pipe_dir / creds.FILE_NAME
        self.creds_file.write_text(f"PIPETEST_POSTGRES_PASSWORD={_CANARY}\n", encoding="utf-8")
        self.creds = str(self.creds_file)
        acc_dir = tmp_path / "workers-creds" / creds.DIRECTORY_NAME
        acc_dir.mkdir(parents=True)
        self.accepted_file = acc_dir / creds.FILE_NAME
        self.accepted_file.write_text(f"POSTGRES_PASSWORD={_CANARY}\n", encoding="utf-8")
        self.accepted_creds = str(self.accepted_file)
        self.mvp_default = creds.default_credentials_path(self.environ, os.name, self.home)

    def creds_for(self, target: str) -> str:
        return self.creds if target == "pipetest" else self.accepted_creds


@pytest.fixture
def world(tmp_path):
    FakeLock.created.clear()
    return World(tmp_path)


def go(world, engine, *args, execute=False, lock=None, creds_path=None, environ=None, config=None, docker="docker",
       file_exists=None, target=None, omit_target=False):
    """Run main() against the engine's target (or `target`).  Always asserts the engine saw no violation."""
    out, err = io.StringIO(), io.StringIO()
    events = engine.events if engine is not None else []
    tgt = target or (engine.target if engine is not None else "pipetest")
    argv = ["run", "--credentials-file", creds_path if creds_path is not None else world.creds_for(tgt)]
    if not omit_target:
        argv += ["--target", tgt]
    argv += list(args)
    if execute:
        argv.append("--execute")
    factory = lock or (lambda path: FakeLock(path, events))
    code = pipe.main(argv, environ=environ if environ is not None else world.environ, run=engine, docker=docker,
                     out=out, err=err, lock_factory=factory, repo_root=_REPO, home=world.home,
                     platform_name=os.name, detector_config_text=config, file_exists=file_exists)
    if engine is not None:
        assert engine.violations == [], engine.violations
    return code, out.getvalue(), err.getvalue()


def _no_run_events(engine):
    return [e for e in engine.events if e.startswith(("compose", "lock", "read:pending"))]


# ===========================================================================
# P01 Command construction
# ===========================================================================

class TestCommands:
    @pytest.mark.parametrize("target", [ACCEPTED, PIPETEST], ids=lambda t: t.key)
    def test_detector_command(self, target):
        argv = pipe.compose_run_argv("docker", _REPO, "/c/agentops-mvp/credentials.env", pipe.DETECTOR_SERVICE, target)
        assert argv == ["docker", "compose", "-p", target.project, "-f", str(_REPO / target.compose_file),
                        "--env-file", "/c/agentops-mvp/credentials.env", "run", "--rm", "-T", "--no-deps",
                        "anomaly-detector"]

    @pytest.mark.parametrize("target", [ACCEPTED, PIPETEST], ids=lambda t: t.key)
    def test_rca_command_is_one_anomaly(self, target):
        anomaly = _ids(1)[0]
        argv = pipe.rca_argv("docker", _REPO, "/c/agentops-mvp/credentials.env", anomaly, target)
        assert argv[-3:] == ["rca-analyzer", "--anomaly-id", anomaly]
        assert argv[:4] == ["docker", "compose", "-p", target.project]

    @pytest.mark.parametrize("bad", ["", "A" * 64, "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n", "a b", "--help"])
    def test_rca_command_refuses_a_bad_id(self, bad):
        with pytest.raises(pipe.PipelineError):
            pipe.rca_argv("docker", _REPO, "/c/agentops-mvp/credentials.env", bad, PIPETEST)

    def test_only_the_two_workers_can_be_run(self):
        for service in ("postgres", "viewer", "db-bootstrap", "anomaly-detector; rm", ""):
            with pytest.raises(pipe.PipelineError):
                pipe.compose_run_argv("docker", _REPO, "/c", service, PIPETEST)

    def test_the_disposable_commands_never_name_an_accepted_or_protected_resource(self):
        every = (pipe.compose_run_argv("docker", _REPO, "/c", pipe.DETECTOR_SERVICE, PIPETEST)
                 + pipe.rca_argv("docker", _REPO, "/c", _ids(1)[0], PIPETEST)
                 + pipe.read_argv("docker", pipe.NO_EVIDENCE_SQL, PIPETEST) + pipe.workers_ps_argv("docker", PIPETEST)
                 + pipe.container_probe_argv("docker", PIPETEST) + pipe.volume_probe_argv("docker", PIPETEST)
                 + pipe.network_probe_argv("docker", PIPETEST))
        text = " ".join(every)
        for name in _ACCEPTED_NAMES + tuple(n for n in workers.PROTECTED_NAMES if n != "agentops"):
            assert not re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text), name
        assert "agentops-mvp" not in text.replace("/agentops-mvp/credentials.env", "")

    def test_every_command_is_a_list_of_strings(self):
        for argv in (pipe.compose_run_argv("docker", _REPO, "/c", pipe.DETECTOR_SERVICE, PIPETEST),
                     pipe.read_argv("docker", pipe.pending_sql(5), ACCEPTED), pipe.workers_ps_argv("docker", PIPETEST),
                     pipe.container_probe_argv("docker", PIPETEST), pipe.volume_probe_argv("docker", PIPETEST),
                     pipe.network_probe_argv("docker", PIPETEST)):
            assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)

    @pytest.mark.parametrize("target", [ACCEPTED, PIPETEST], ids=lambda t: t.key)
    def test_read_command_is_read_only_on_the_targets_container(self, target):
        argv = pipe.read_argv("docker", pipe.pending_sql(25), target)
        assert argv[:4] == ["docker", "exec", "-e", "PGOPTIONS=-cdefault_transaction_read_only=on"]
        assert argv[4] == target.postgres_container
        assert "-w" not in argv and "PGPASSWORD" not in " ".join(argv)

    def test_read_command_refuses_anything_not_fixed(self):
        for sql in ("SELECT 1", "DELETE FROM public.anomaly_events", pipe.pending_sql(25) + "; DROP TABLE x",
                    pipe.pending_sql(25).replace("LIMIT 25", "LIMIT 25 OFFSET 1")):
            with pytest.raises(pipe.PipelineError):
                pipe.read_argv("docker", sql, PIPETEST)

    def test_the_fixed_queries_are_read_only_text(self):
        for sql in (pipe.pending_sql(25), pipe.NO_EVIDENCE_SQL, demo.LEDGER_SQL):
            assert sql.startswith("SELECT ")
            assert not re.search(r"(?i)\b(insert|update|delete|drop|alter|create|grant|truncate|copy|call|do|set)\b", sql)
            assert ";" not in sql and "%" not in sql

    def test_the_pending_query_selects_anomalies_without_any_investigation_in_a_stable_order(self):
        sql = pipe.pending_sql(25)
        assert "FROM public.anomaly_events AS a" in sql
        assert "NOT EXISTS (SELECT 1 FROM public.rca_investigations AS i WHERE i.anomaly_id = a.anomaly_id)" in sql
        assert sql.endswith("ORDER BY a.event_time, a.anomaly_id LIMIT 25")

    @pytest.mark.parametrize("bad", [0, -1, 101, True, "5", 2.5, None])
    def test_the_limit_is_bounded(self, bad):
        with pytest.raises(pipe.PipelineError):
            pipe.pending_sql(bad)

    def test_the_default_limit_is_25(self, world):
        engine = FakeEngine()
        go(world, engine)
        sql = [c[0][c[0].index("-c") + 1] for c in engine.calls if c[0][1] == "exec" and "-c" in c[0]
               and c[0][c[0].index("-c") + 1].startswith("SELECT a.")]
        assert sql == [pipe.pending_sql(25)]

    def test_the_exit_codes_are_the_documented_ones(self):
        assert (pipe.EXIT_OK, pipe.EXIT_FAILED, pipe.EXIT_USAGE, pipe.EXIT_DETECTOR, pipe.EXIT_RCA, pipe.EXIT_BUSY,
                pipe.EXIT_INTERRUPTED) == (0, 1, 2, 3, 4, 5, 130)
        assert (workers.EXIT_OK, workers.EXIT_FAILED, workers.EXIT_USAGE) == (0, 1, 2)

    def test_the_timeouts_and_bounds_are_the_documented_ones(self):
        assert (pipe.DETECTOR_TIMEOUT_SECONDS, pipe.RCA_TIMEOUT_SECONDS, pipe.READ_TIMEOUT_SECONDS) == (900.0, 300.0, 60.0)
        assert (pipe.DEFAULT_MAX_ANOMALIES, pipe.MAX_ANOMALIES_LIMIT, pipe.MAX_CONSECUTIVE_RCA_FAILURES) == (25, 100, 3)

    def test_plan_prints_and_runs_nothing(self):
        engine = FakeEngine()
        code = pipe.main(["plan"], environ={"DOCKER_HOST": "tcp://x"}, run=engine, out=io.StringIO(), err=io.StringIO())
        assert code == 0 and engine.calls == []
        out = io.StringIO()
        pipe.main(["plan"], out=out)
        text = out.getvalue()
        assert "NOTHING IS RUN" in text and "anomaly-detector" in text and "rca-analyzer" in text
        assert "accepted" in text and "pipetest" in text and "always refused" in text


# ===========================================================================
# P02 Credentials location and secret handling
# ===========================================================================

class OpenSpy:
    """Records every path opened through open(), io.open, Path.open/read_* and os.open."""

    def __init__(self, monkeypatch):
        self.paths: list[str] = []
        real_open, real_os_open = builtins.open, os.open

        def spy_open(file, *a, **k):
            if isinstance(file, (str, bytes, os.PathLike)):
                self.paths.append(os.path.normcase(os.path.abspath(os.fsdecode(file))))
            return real_open(file, *a, **k)

        def spy_os_open(path, *a, **k):
            self.paths.append(os.path.normcase(os.path.abspath(os.fsdecode(path))))
            return real_os_open(path, *a, **k)

        monkeypatch.setattr(builtins, "open", spy_open)
        monkeypatch.setattr(io, "open", spy_open)
        monkeypatch.setattr(os, "open", spy_os_open)

    def opened(self, path) -> bool:
        return os.path.normcase(os.path.abspath(str(path))) in self.paths


class TestCredentials:
    @pytest.mark.parametrize("target", ["accepted", "pipetest"])
    def test_the_file_is_never_opened_and_never_printed(self, world, monkeypatch, target):
        spy = OpenSpy(monkeypatch)
        engine = FakeEngine(target=target, pending=_ids(2))
        code, out, err = go(world, engine, execute=(target == "pipetest"))
        assert code == 0
        path = world.creds_for(target)
        assert not spy.opened(path)
        for text in (out, err):
            assert _CANARY not in text and path not in text and str(Path(path).parent) not in text
        for argv, _env, _t in engine.calls:
            if argv[1] == "compose":
                assert argv[argv.index("--env-file") + 1] == path and argv.count(path) == 1

    @pytest.mark.parametrize("path", ["", "credentials.env", "agentops-mvp/credentials.env", "relative/agentops-mvp/credentials.env"])
    def test_a_relative_or_empty_path_is_refused(self, world, path):
        engine = FakeEngine()
        code, _o, err = go(world, engine, creds_path=path)
        assert code == 2 and engine.calls == []

    def test_a_wrong_file_name_is_refused(self, world):
        wrong = world.creds_file.parent / "other.env"
        wrong.write_text("x", encoding="utf-8")
        engine = FakeEngine()
        assert go(world, engine, creds_path=str(wrong))[0] == 2 and engine.calls == []

    def test_a_wrong_directory_name_is_refused(self, world, tmp_path):
        directory = tmp_path / "pipetest-creds" / "agentops-pipetest" / "elsewhere"
        directory.mkdir()
        (directory / creds.FILE_NAME).write_text("x", encoding="utf-8")
        engine = FakeEngine()
        assert go(world, engine, creds_path=str(directory / creds.FILE_NAME))[0] == 2 and engine.calls == []

    def test_a_path_inside_the_repository_is_refused(self, world):
        inside = _REPO / "scripts" / "agentops-pipetest" / creds.DIRECTORY_NAME / creds.FILE_NAME
        engine = FakeEngine()
        assert go(world, engine, creds_path=str(inside))[0] == 2 and engine.calls == []

    def test_a_cloud_synchronized_path_is_refused(self, world, tmp_path):
        environ = dict(world.environ, OneDrive=str(tmp_path / "pipetest-creds"))
        engine = FakeEngine()
        assert go(world, engine, environ=environ)[0] == 2 and engine.calls == []

    @pytest.mark.parametrize("target", ["accepted", "pipetest"])
    def test_the_mvps_own_file_is_refused(self, world, target):
        Path(world.mvp_default).parent.mkdir(parents=True, exist_ok=True)
        Path(world.mvp_default).write_text("x", encoding="utf-8")
        engine = FakeEngine(target=target)
        code, _o, err = go(world, engine, creds_path=world.mvp_default, execute=(target == "pipetest"))
        assert code == 2 and engine.calls == [] and "MVP's own" in err

    def test_an_undeterminable_mvp_default_is_refused(self, world):
        environ = {k: v for k, v in world.environ.items() if k not in ("LOCALAPPDATA", "XDG_CONFIG_HOME")}
        engine = FakeEngine()
        code = pipe.main(["run", "--target", "pipetest", "--credentials-file", world.creds], environ=environ,
                         run=engine, docker="docker", out=io.StringIO(), err=io.StringIO(), repo_root=_REPO, home="",
                         platform_name=os.name)
        assert code == 2 and engine.calls == []

    def test_a_missing_file_is_refused_only_when_executing(self, world):
        world.creds_file.unlink()
        engine = FakeEngine()
        assert go(world, engine, execute=True)[0] == 2
        assert [e for e in engine.events if e.startswith("compose")] == []
        dry = FakeEngine()
        assert go(world, dry)[0] == 0          # a dry run never needs the file

    def test_the_credentials_option_is_required(self, world):
        engine = FakeEngine()
        assert pipe.main(["run"], environ=world.environ, run=engine, docker="docker", out=io.StringIO(),
                         err=io.StringIO()) == 2 and engine.calls == []

    def test_the_disposable_target_needs_a_file_in_its_own_tree(self, world):
        engine = FakeEngine()
        code, _o, err = go(world, engine, creds_path=world.accepted_creds, execute=True)
        assert code == 2 and engine.calls == [] and "agentops-pipetest" in err

    @pytest.mark.parametrize("parent", ["x", "agentops-pipetest-copy", "AGENTOPS-PIPETEST", "pipetest", "agentops-mvp-workers"])
    def test_a_lookalike_parent_directory_is_refused(self, world, tmp_path, parent):
        directory = tmp_path / "other-tree" / parent / creds.DIRECTORY_NAME
        directory.mkdir(parents=True)
        (directory / creds.FILE_NAME).write_text("x", encoding="utf-8")
        engine = FakeEngine()
        code, _o, _e = go(world, engine, creds_path=str(directory / creds.FILE_NAME))
        assert code == 2 and engine.calls == []

    def test_a_deeper_agentops_pipetest_ancestor_is_not_enough(self, world, tmp_path):
        directory = tmp_path / "agentops-pipetest" / "inner" / creds.DIRECTORY_NAME
        directory.mkdir(parents=True)
        (directory / creds.FILE_NAME).write_text("x", encoding="utf-8")
        engine = FakeEngine()
        assert go(world, engine, creds_path=str(directory / creds.FILE_NAME))[0] == 2 and engine.calls == []

    def test_the_accepted_target_keeps_its_existing_path_rules(self, world):
        engine = FakeEngine(target="accepted")
        assert go(world, engine)[0] == 0


# ===========================================================================
# P03 The target registry and the protection of the accepted MVP
# ===========================================================================

class TestRegistry:
    def test_the_registry_is_closed_and_has_exactly_two_targets(self):
        assert set(pipe.TARGETS) == {"accepted", "pipetest"} and pipe.DEFAULT_TARGET == "accepted"
        with pytest.raises(TypeError):
            pipe.TARGETS["other"] = ACCEPTED            # a read-only mapping
        with pytest.raises(TypeError):
            del pipe.TARGETS["pipetest"]

    def test_a_target_cannot_be_changed(self):
        for target in (ACCEPTED, PIPETEST):
            with pytest.raises(dataclasses.FrozenInstanceError):
                target.volume = "x"                     # type: ignore[misc]

    def test_the_names_are_exact(self):
        assert (ACCEPTED.project, ACCEPTED.postgres_container, ACCEPTED.volume, ACCEPTED.network) == _ACCEPTED_NAMES
        assert (PIPETEST.project, PIPETEST.postgres_container, PIPETEST.volume, PIPETEST.network) == _PIPETEST_NAMES
        assert PIPETEST.compose_file == "docker/mvp-workers-pipetest/compose.yml"
        assert PIPETEST.ownership_label == "agentops.pipetest" and ACCEPTED.ownership_label == "agentops.mvp-workers"

    def test_the_accepted_target_is_the_existing_isolated_project(self):
        assert (ACCEPTED.project, ACCEPTED.compose_file, ACCEPTED.postgres_container, ACCEPTED.volume, ACCEPTED.network) == (
            workers.PROJECT_NAME, workers.COMPOSE_FILE, workers.POSTGRES_CONTAINER, workers.VOLUME_NAME, workers.NETWORK_NAME)

    def test_only_the_disposable_target_is_executable(self):
        assert ACCEPTED.executable is False and PIPETEST.executable is True

    def test_no_name_is_shared_and_no_disposable_name_is_protected(self):
        accepted = {ACCEPTED.project, ACCEPTED.postgres_container, ACCEPTED.volume, ACCEPTED.network}
        disposable = {PIPETEST.project, PIPETEST.postgres_container, PIPETEST.volume, PIPETEST.network}
        assert not accepted & disposable and not disposable & set(workers.PROTECTED_NAMES)
        for name in disposable:
            assert "agentops-mvp" not in name and "agentops_" not in name

    @pytest.mark.parametrize("value", ["agentops-mvp-workers", "Pipetest", "PIPETEST", "agentops-pipetest", "", " accepted",
                                       "accepted;pipetest", "../accepted", "all"])
    def test_an_unknown_target_name_is_refused_by_the_parser(self, world, value):
        engine = FakeEngine()
        code = pipe.main(["run", "--target", value, "--credentials-file", world.creds], environ=world.environ,
                         run=engine, docker="docker", out=io.StringIO(), err=io.StringIO())
        assert code == 2 and engine.calls == []

    def test_there_is_no_option_to_name_a_project_file_container_or_volume(self):
        parser = pipe.build_parser()
        sub = next(a for a in parser._actions if a.dest == "command").choices["run"]
        options = {s for action in sub._actions for s in action.option_strings}
        assert options == {"-h", "--help", "--target", "--credentials-file", "--execute", "--max-anomalies"}
        target_action = next(a for a in sub._actions if a.dest == "target")
        assert tuple(target_action.choices) == ("accepted", "pipetest")

    @pytest.mark.parametrize("field,value", [("volume", "agentops-mvp-workers-postgres-data"), ("project", "agentops-mvp-workers"),
                                              ("postgres_container", "agentops-mvp-workers-postgres-1"),
                                              ("compose_file", "docker/mvp-workers/compose.yml"), ("network", "x")])
    def test_a_lookalike_target_object_is_never_used_to_build_a_command(self, field, value):
        fake = dataclasses.replace(PIPETEST, **{field: value})
        for build in (lambda: pipe.compose_run_argv("docker", _REPO, "/c", pipe.DETECTOR_SERVICE, fake),
                      lambda: pipe.read_argv("docker", pipe.NO_EVIDENCE_SQL, fake),
                      lambda: pipe.workers_ps_argv("docker", fake), lambda: pipe.container_probe_argv("docker", fake),
                      lambda: pipe.volume_probe_argv("docker", fake), lambda: pipe.network_probe_argv("docker", fake)):
            with pytest.raises(pipe.PipelineError):
                build()
        with pytest.raises(pipe.PipelineError):
            pipe.verify_target(FakeEngine(), "docker", {}, fake)


class TestAcceptedIsProtected:
    @pytest.mark.parametrize("extra", [[], ["--target", "accepted"]])
    def test_execute_on_the_accepted_target_is_refused_before_anything_else(self, world, extra):
        engine = FakeEngine(target="accepted", pending=_ids(1))
        out, err = io.StringIO(), io.StringIO()
        code = pipe.main(["run", "--credentials-file", world.accepted_creds, "--execute", *extra],
                         environ=dict(world.environ, DOCKER_HOST="tcp://x"), run=engine, docker=None, out=out, err=err,
                         lock_factory=lambda p: FakeLock(p, engine.events), repo_root=_REPO, home=world.home,
                         platform_name=os.name)
        assert code == 2 and engine.calls == [] and FakeLock.created == []
        assert "can never be the target of --execute" in err.getvalue()

    def test_execute_on_the_accepted_target_is_refused_even_with_every_other_input_valid(self, world):
        engine = FakeEngine(target="accepted", pending=_ids(1))
        code, out, err = go(world, engine, execute=True)
        assert code == 2 and engine.calls == [] and FakeLock.created == [] and engine.compose == []

    def test_the_workflow_itself_refuses_the_accepted_target(self, world):
        engine = FakeEngine(target="accepted", pending=_ids(1))
        ctx = pipe.Context(engine, "docker", {}, _REPO, world.accepted_creds, 25, ACCEPTED)
        out = io.StringIO()
        locks = []
        code = pipe.execute_workflow(ctx, lambda p: locks.append(p), out)
        assert code == 2 and engine.calls == [] and locks == []
        assert "pipeline summary (target accepted)" in out.getvalue()

    def test_the_workflow_refuses_a_lookalike_target_object(self, world):
        engine = FakeEngine(pending=_ids(1))
        fake = dataclasses.replace(ACCEPTED, key="pipetest", executable=True)
        ctx = pipe.Context(engine, "docker", {}, _REPO, world.creds, 25, fake)
        assert pipe.execute_workflow(ctx, lambda p: FakeLock(p), io.StringIO()) == 2 and engine.calls == []

    def test_the_accepted_target_can_still_be_dry_run_without_a_target_option(self, world):
        engine = FakeEngine(target="accepted", pending=_ids(1))
        out, err = io.StringIO(), io.StringIO()
        code = pipe.main(["run", "--credentials-file", world.accepted_creds], environ=world.environ, run=engine,
                         docker="docker", out=out, err=err, repo_root=_REPO, home=world.home, platform_name=os.name)
        assert code == 0 and engine.violations == [] and engine.compose == []
        assert "target is accepted" in out.getvalue() and "can never be executed" in out.getvalue()
        assert _ids(1)[0] in out.getvalue()

    def test_a_dry_run_of_the_accepted_target_only_reads_and_never_probes_a_volume_or_network(self, world):
        engine = FakeEngine(target="accepted", pending=_ids(2))
        go(world, engine)
        assert {e for e in engine.events} <= {"inspect", "read:ledger", "ps", "read:pending"}
        assert FakeLock.created == []

    def test_nothing_in_a_run_on_the_disposable_target_names_the_accepted_one(self, world):
        engine = FakeEngine(pending=_ids(2))
        go(world, engine, execute=True)
        for argv, _e, _t in engine.calls:
            assert not any(n in a for n in _ACCEPTED_NAMES for a in argv), argv[:3]


# ===========================================================================
# P04 Identity of the accepted target (the existing contract, unchanged)
# ===========================================================================

class TestAcceptedIdentity:
    @pytest.mark.parametrize("facts", [
        "other-project|postgres|true|volume:agentops-mvp-workers-postgres-data:/var/lib/postgresql/data;|{}",
        "agentops-mvp-workers|postgres|false|volume:agentops-mvp-workers-postgres-data:/var/lib/postgresql/data;|{}",
        "agentops-mvp-workers|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{}",
        workers._EXPECTED_FACTS + '|{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5432"}]}',
        "", "garbage"])
    def test_a_wrong_accepted_target_is_refused(self, world, facts):
        engine = FakeEngine(target="accepted", facts=facts)
        code, _o, _e = go(world, engine)
        assert code == 2 and _no_run_events(engine) == []

    @pytest.mark.parametrize("ledger", ["", "1|001", "\n".join(f"{i + 1}|{s}" for i, s in enumerate(demo.EXPECTED_LEDGER_STEPS[:-1]))])
    def test_a_wrong_ledger_is_refused(self, world, ledger):
        engine = FakeEngine(target="accepted", ledger=ledger)
        assert go(world, engine)[0] == 2 and _no_run_events(engine) == []

    def test_the_existing_check_is_the_one_used(self, world):
        calls = []
        real = workers.verify_target

        def spy(run, docker, env):
            calls.append(docker)
            return real(run, docker, env)

        engine = FakeEngine(target="accepted")
        original = workers.verify_target
        workers.verify_target = spy
        try:
            assert go(world, engine)[0] == 0
        finally:
            workers.verify_target = original
        assert calls == ["docker"]


# ===========================================================================
# P05 Identity of the disposable target (exact equality only)
# ===========================================================================

_GOOD = pipe.expected_container_facts(PIPETEST)


def _facts(**changes):
    parts = {"name": "/agentops-pipetest-postgres-1", "project": "agentops-pipetest", "service": "postgres",
             "label": "true", "running": "true", "privileged": "false",
             "mounts": "volume:agentops-pipetest-pgdata:/var/lib/postgresql/data;", "networks": "agentops-pipetest-net;",
             "ports": "{}"}
    parts.update(changes)
    return "|".join(parts[k] for k in ("name", "project", "service", "label", "running", "privileged", "mounts",
                                       "networks", "ports"))


class TestDisposableIdentity:
    def test_the_good_facts_pass(self, world):
        assert _facts() == _GOOD + "|{}"
        assert go(world, FakeEngine(pending=_ids(1)))[0] == 0

    @pytest.mark.parametrize("facts", [
        _facts(name="/agentops-pipetest-postgres-1-evil"),
        _facts(name="/Xagentops-pipetest-postgres-1"),
        _facts(name="/agentops-pipetest-other-1"),
        _facts(name="/pipetest"),
        _facts(name="agentops-pipetest-postgres-1"),
        _facts(project="agentops-mvp-workers"),
        _facts(project="agentops-pipetest2"),
        _facts(project=""),
        _facts(service="viewer"),
        _facts(service="postgres2"),
        _facts(label=""),
        _facts(label="false"),
        _facts(label="True"),
        _facts(running="false"),
        _facts(privileged="true"),
        _facts(mounts=""),
        _facts(mounts="volume:agentops-mvp-workers-postgres-data:/var/lib/postgresql/data;"),
        _facts(mounts="volume:agentops-pipetest-pgdata:/var/lib/postgresql/data2;"),
        _facts(mounts="volume:agentops-pipetest-pgdata:/var/lib/postgresql/data;bind::/var/run/docker.sock:/var/run/docker.sock;"),
        _facts(mounts="bind:/var/run/docker.sock:/var/run/docker.sock;volume:agentops-pipetest-pgdata:/var/lib/postgresql/data;"),
        _facts(mounts="volume:agentops-pipetest-pgdata:/var/lib/postgresql/data;volume:agentops-mvp-workers-postgres-data:/x;"),
        _facts(mounts="bind:agentops-pipetest-pgdata:/var/lib/postgresql/data;"),
        _facts(networks="agentops-mvp-workers-net;"),
        _facts(networks="agentops-pipetest-net;agentops-mvp-workers-net;"),
        _facts(networks="bridge;"),
        _facts(networks=""),
        _facts(ports='{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]}'),
        _facts(ports='{"5432/tcp":null}'),
        "", "garbage", _GOOD, _GOOD + "|"])
    def test_a_container_that_differs_in_any_way_is_refused(self, world, facts):
        engine = FakeEngine(facts=facts, pending=_ids(1))
        code, out, err = go(world, engine, execute=True)
        assert code == 2 and _no_run_events(engine) == []
        assert "volume" not in engine.events and "network" not in engine.events   # stopped at the first difference

    def test_a_name_that_merely_contains_pipetest_passes_nothing(self, world):
        engine = FakeEngine(facts=_facts(name="/my-pipetest-agentops-pipetest-postgres-1-copy", project="pipetest",
                                         mounts="volume:pipetest:/var/lib/postgresql/data;", networks="pipetest;"))
        assert go(world, engine)[0] == 2 and _no_run_events(engine) == []

    @pytest.mark.parametrize("volume", [
        "agentops-pipetest-pgdata|false|local|null", "agentops-pipetest-pgdata||local|null",
        "agentops-pipetest-pgdata|true|local|{\"device\":\"C:\\\\x\",\"o\":\"bind\",\"type\":\"none\"}",
        "agentops-pipetest-pgdata|true|nfs|null", "agentops-pipetest-pgdata|true|local|{\"a\":\"b\"}",
        "agentops-mvp-workers-postgres-data|true|local|null", "agentops-pipetest-pgdata2|true|local|null",
        "xagentops-pipetest-pgdata|true|local|null", "", "garbage", "agentops-pipetest-pgdata|true|local|null|x"])
    def test_a_volume_that_differs_is_refused(self, world, volume):
        engine = FakeEngine(volume_facts=volume)
        assert go(world, engine)[0] == 2 and _no_run_events(engine) == []
        assert "network" not in engine.events and "read:ledger" not in engine.events

    @pytest.mark.parametrize("good", ["agentops-pipetest-pgdata|true|local|null", "agentops-pipetest-pgdata|true|local|{}"])
    def test_the_two_empty_option_spellings_pass(self, world, good):
        assert go(world, FakeEngine(volume_facts=good))[0] == 0

    @pytest.mark.parametrize("network", [
        "agentops-pipetest-net||bridge|false", "agentops-pipetest-net|false|bridge|false",
        "agentops-pipetest-net|true|overlay|false", "agentops-pipetest-net|true|bridge|true",
        "agentops-mvp-workers-net|true|bridge|false", "agentops-pipetest-net2|true|bridge|false", "", "garbage"])
    def test_a_network_that_differs_is_refused(self, world, network):
        engine = FakeEngine(network_facts=network)
        assert go(world, engine)[0] == 2 and _no_run_events(engine) == [] and "read:ledger" not in engine.events

    @pytest.mark.parametrize("ledger", ["", "1|001", "garbage", "\n".join(f"{i + 1}|{s}" for i, s in enumerate(demo.EXPECTED_LEDGER_STEPS[:-1])),
                                        "\n".join(f"{i + 1}|{s}" for i, s in enumerate(demo.EXPECTED_LEDGER_STEPS)) + "\n19|extra"])
    def test_a_wrong_ledger_is_refused(self, world, ledger):
        engine = FakeEngine(ledger=ledger)
        assert go(world, engine, execute=True)[0] == 2 and _no_run_events(engine) == []

    @pytest.mark.parametrize("event", ["inspect", "volume", "network", "read:ledger"])
    def test_an_unreadable_identity_answer_is_refused_without_leaking(self, world, event):
        engine = FakeEngine(raise_at={event: OSError(_CANARY)})
        code, out, err = go(world, engine, execute=True)
        assert code == 2 and _CANARY not in out + err and _no_run_events(engine) == []

    @pytest.mark.parametrize("event", ["inspect", "volume", "network"])
    def test_a_nonzero_identity_probe_is_refused(self, world, event):
        class Failing(FakeEngine):
            def __call__(self, argv, env, timeout):
                result = super().__call__(argv, env, timeout)
                if self.events and self.events[-1] == event:
                    return workers.CommandResult(1, b"")
                return result
        assert go(world, Failing())[0] == 2

    def test_the_checks_run_in_order_container_volume_network_ledger(self, world):
        engine = FakeEngine()
        go(world, engine)
        assert engine.events[:4] == ["inspect", "volume", "network", "read:ledger"]

    def test_the_probes_are_read_only_inspections_of_the_targets_own_resources(self):
        container = pipe.container_probe_argv("docker", PIPETEST)
        assert container[:4] == ["docker", "inspect", "--type", "container"] and container[-1] == "agentops-pipetest-postgres-1"
        assert 'index .Config.Labels "agentops.pipetest"' in container[5]
        assert pipe.volume_probe_argv("docker", PIPETEST)[:3] == ["docker", "volume", "inspect"]
        assert pipe.volume_probe_argv("docker", PIPETEST)[-1] == "agentops-pipetest-pgdata"
        assert pipe.network_probe_argv("docker", PIPETEST)[:3] == ["docker", "network", "inspect"]
        assert pipe.network_probe_argv("docker", PIPETEST)[-1] == "agentops-pipetest-net"

    def test_a_disposable_dry_run_that_passes_reads_only(self, world):
        engine = FakeEngine(pending=_ids(2))
        assert go(world, engine)[0] == 0
        assert set(engine.events) <= {"inspect", "volume", "network", "read:ledger", "ps", "read:pending"}
        assert engine.compose == []


# ===========================================================================
# P06 Conflicting workers and the lock
# ===========================================================================

class TestLock:
    def test_a_running_one_off_worker_is_refused_before_anything_starts(self, world):
        engine = FakeEngine(workers_running=["a" * 12])
        code, _o, err = go(world, engine, execute=True)
        assert code == 5 and engine.compose == [] and "lock:enter" not in engine.events

    def test_a_worker_that_appears_after_the_lock_is_refused(self, world):
        engine = FakeEngine(workers_running=[], workers_running_after=["b" * 64])
        code, out, _e = go(world, engine, execute=True)
        assert code == 5 and engine.compose == []
        assert engine.events.index("lock:enter") < engine.events.index("lock:exit")
        assert engine.events.count("ps") == 2
        assert FakeLock.created[0].exited == 1                 # released even though it refused

    def test_the_check_runs_before_and_after_the_lock(self, world):
        engine = FakeEngine(pending=[])
        go(world, engine, execute=True)
        events = engine.events
        assert events.index("ps") < events.index("lock:enter") < events.index("compose:detector")
        assert events.count("ps") == 2 and events[-1] == "lock:exit"

    @pytest.mark.parametrize("output", ["not-a-container-id", "ZZZ", "abc", "a" * 65])
    def test_an_unreadable_worker_list_is_refused(self, world, output):
        engine = FakeEngine(workers_running=[output])
        assert go(world, engine, execute=True)[0] in (2, 5) and engine.compose == []

    def test_a_held_lock_refuses_and_starts_nothing(self, world):
        engine = FakeEngine(pending=_ids(1))
        lock = lambda path: FakeLock(path, engine.events, error=lifecycle.LockHeldError("held"))
        code, out, err = go(world, engine, execute=True, lock=lock)
        assert code == 5 and engine.compose == [] and "holds the lock" in out + err

    def test_a_lock_failure_refuses_and_starts_nothing(self, world):
        engine = FakeEngine(pending=_ids(1))
        lock = lambda path: FakeLock(path, engine.events, error=lifecycle.LifecycleError(_CANARY))
        code, out, err = go(world, engine, execute=True, lock=lock)
        assert code == 2 and engine.compose == [] and _CANARY not in out + err

    def test_the_lock_lives_next_to_the_credentials_file_and_is_released(self, world):
        engine = FakeEngine(pending=_ids(1))
        go(world, engine, execute=True)
        lock = FakeLock.created[0]
        assert lock.path == str(world.creds_file.parent / "pipeline.lock")
        assert lock.entered == 1 and lock.exited == 1

    def test_the_lock_is_released_after_a_failure(self, world):
        engine = FakeEngine(detector_code=1)
        go(world, engine, execute=True)
        assert FakeLock.created[0].entered == 1 and FakeLock.created[0].exited == 1

    def test_the_lock_is_released_after_an_unexpected_exception(self, world):
        engine = FakeEngine(raise_at={"compose:detector": RuntimeError(_CANARY)})
        code, out, err = go(world, engine, execute=True)
        assert code == 1 and _CANARY not in out + err and FakeLock.created[0].exited == 1

    def test_a_dry_run_never_takes_the_lock(self, world):
        for target in ("accepted", "pipetest"):
            engine = FakeEngine(target=target, pending=_ids(1))
            go(world, engine)
            assert FakeLock.created == [] and "lock:enter" not in engine.events

    def test_the_real_lock_helper_is_used_by_default_and_the_file_is_not_deleted(self, world):
        calls = []
        lock_path = str(world.creds_file.parent / "pipeline.lock")
        factory = lambda path: lifecycle.ExclusiveLock(path, lock=lambda fd: calls.append("lock"),
                                                       unlock=lambda fd: calls.append("unlock"))
        engine = FakeEngine(pending=[])
        code, _o, _e = go(world, engine, execute=True, lock=factory)
        assert code == 0 and calls == ["lock", "unlock"]
        assert os.path.exists(lock_path)                        # created, held, released, never deleted
        assert pipe.main.__kwdefaults__["lock_factory"] is None  # None means lifecycle.ExclusiveLock at run time
        assert "lifecycle.ExclusiveLock" in _PIPE_SOURCE.read_text(encoding="utf-8")


# ===========================================================================
# P07 Dry run
# ===========================================================================

class TestDryRun:
    @pytest.mark.parametrize("target", ["accepted", "pipetest"])
    def test_a_dry_run_starts_no_worker_and_takes_no_lock(self, world, target):
        engine = FakeEngine(target=target, pending=_ids(3))
        code, out, err = go(world, engine)
        assert code == 0
        assert engine.compose == [] and "lock:enter" not in engine.events
        assert "nothing was started" in out and "no lock was taken" in out
        for i in _ids(3):
            assert i in out

    @pytest.mark.parametrize("target", ["accepted", "pipetest"])
    def test_a_dry_run_only_reads(self, world, target):
        engine = FakeEngine(target=target, pending=_ids(1))
        go(world, engine)
        for argv, _env, _t in engine.calls:
            assert argv[1] in ("inspect", "ps", "exec", "volume", "network")
            if argv[1] == "exec":
                assert "PGOPTIONS=-cdefault_transaction_read_only=on" in argv

    def test_a_dry_run_is_the_default(self, world):
        engine = FakeEngine(pending=_ids(1))
        out, err = io.StringIO(), io.StringIO()
        code = pipe.main(["run", "--target", "pipetest", "--credentials-file", world.creds], environ=world.environ,
                         run=engine, docker="docker", out=out, err=err, repo_root=_REPO, home=world.home,
                         platform_name=os.name)
        assert code == 0 and engine.compose == [] and "add --execute to run" in out.getvalue()

    def test_a_dry_run_still_refuses_a_wrong_target(self, world):
        assert go(world, FakeEngine(facts="x|y|true|z|{}"))[0] == 2

    def test_a_dry_run_still_refuses_a_running_worker(self, world):
        assert go(world, FakeEngine(workers_running=["c" * 12]))[0] == 5

    def test_a_dry_run_with_an_unreadable_list_fails(self, world):
        engine = FakeEngine(read_overrides={("pending", 0): workers.CommandResult(1, b"")})
        assert go(world, engine)[0] == 1

    def test_the_limit_is_validated_on_the_command_line(self, world):
        for value in ("0", "101", "-1", "x", "2.5"):
            engine = FakeEngine()
            out, err = io.StringIO(), io.StringIO()
            code = pipe.main(["run", "--target", "pipetest", "--credentials-file", world.creds, "--max-anomalies", value],
                             environ=world.environ, run=engine, docker="docker", out=out, err=err, repo_root=_REPO,
                             home=world.home, platform_name=os.name)
            assert code == 2 and engine.calls == []

    def test_a_dry_run_reports_at_most_the_limit(self, world):
        engine = FakeEngine(pending=_ids(10))
        code, out, _e = go(world, engine, "--max-anomalies", "3")
        assert code == 0 and sum(1 for i in _ids(10) if i in out) == 3

    def test_a_dry_run_on_a_target_that_does_not_exist_is_refused(self, world):
        class Missing(FakeEngine):
            def __call__(self, argv, env, timeout):
                self.calls.append((list(argv), dict(env), timeout))
                return workers.CommandResult(1, b"")
        assert go(world, Missing())[0] == 2


# ===========================================================================
# P08 Detector stage
# ===========================================================================

class TestDetector:
    def test_success_permits_discovery_and_rca(self, world):
        engine = FakeEngine(pending=_ids(1))
        code, out, _e = go(world, engine, execute=True)
        assert code == 0 and [s for s, _ in engine.compose] == ["anomaly-detector", "rca-analyzer"]
        assert "succeeded (exit 0)" in out and "pipeline summary (target pipetest)" in out

    def test_new_anomalies_from_the_detector_are_investigated(self, world):
        engine = FakeEngine(pending=_ids(1), detector_adds=_ids(3)[1:])
        code, _o, _e = go(world, engine, execute=True)
        assert code == 0 and sorted(a for s, a in engine.compose if s == "rca-analyzer") == sorted(_ids(3))

    @pytest.mark.parametrize("code_", [1, 2, 3, 4, 130, 5, 9, 125, 137, -9])
    def test_any_nonzero_result_stops_before_rca(self, world, code_):
        engine = FakeEngine(pending=_ids(2), detector_code=code_, noisy=True)
        code, out, err = go(world, engine, execute=True)
        assert code == 3
        assert [s for s, _ in engine.compose] == ["anomaly-detector"]            # one start, no retry, no RCA
        assert not [e for e in engine.events if e.startswith("read:pending")]
        assert "unsuccessful" in out and _CANARY not in out + err

    def test_the_uncertain_commit_case_is_reported_as_possibly_uncertain_and_not_retried(self, world):
        engine = FakeEngine(pending=_ids(1), detector_code=1)
        code, out, _e = go(world, engine, execute=True)
        assert code == 3 and "failed or uncertain" in out and len(engine.compose) == 1

    def test_a_detector_timeout_stops_without_cleanup(self, world):
        engine = FakeEngine(pending=_ids(1), raise_at={"compose:detector": pipe.StageTimeout()})
        code, out, _e = go(world, engine, execute=True)
        assert code == 3 and "timed out" in out and "nothing was cleaned up" in out
        assert len(engine.compose) == 1
        assert all(c[0][1] != "stop" and c[0][1] != "rm" and "rm" not in c[0][:3] for c in engine.calls)

    def test_a_detector_that_could_not_be_started_stops(self, world):
        engine = FakeEngine(pending=_ids(1), raise_at={"compose:detector": FileNotFoundError(_CANARY)})
        code, out, err = go(world, engine, execute=True)
        assert code == 3 and "could not be run" in out and _CANARY not in out + err

    def test_the_detector_gets_the_detector_timeout(self, world):
        engine = FakeEngine()
        go(world, engine, execute=True)
        timeouts = [t for argv, _e, t in engine.calls if argv[1] == "compose"]
        assert timeouts == [pipe.DETECTOR_TIMEOUT_SECONDS]

    def test_read_checks_get_the_read_timeout(self, world):
        engine = FakeEngine()
        go(world, engine, execute=True)
        assert {t for argv, _e, t in engine.calls if argv[1] != "compose"} == {pipe.READ_TIMEOUT_SECONDS}

    def test_the_detector_command_targets_only_the_disposable_environment(self, world):
        engine = FakeEngine()
        go(world, engine, execute=True)
        detector = [argv for argv, _e, _t in engine.calls if argv[1] == "compose"][0]
        assert detector[3] == "agentops-pipetest" and detector[5].replace("\\", "/").endswith(PIPETEST.compose_file)
        assert detector[-1] == "anomaly-detector"


# ===========================================================================
# P09 Pending discovery
# ===========================================================================

class TestPending:
    @pytest.mark.parametrize("output", [
        b"short\n", b"A" * 64 + b"\n", (b"a" * 64 + b"\n") * 2, b"a" * 64 + b" extra\n", b"\xff\xfe\n",
        b"ERROR: " + _CANARY.encode(), b"a" * 63 + b"\n"])
    def test_a_bad_list_stops_the_run_before_rca(self, world, output):
        engine = FakeEngine(read_overrides={("pending", 0): workers.CommandResult(0, output)})
        code, out, err = go(world, engine, execute=True)
        assert code == 1 and [s for s, _ in engine.compose] == ["anomaly-detector"]
        assert _CANARY not in out + err

    def test_a_failed_read_stops_the_run_before_rca(self, world):
        engine = FakeEngine(read_overrides={("pending", 0): workers.CommandResult(2, b"")})
        assert go(world, engine, execute=True)[0] == 1 and len(engine.compose) == 1

    def test_a_timed_out_read_stops_the_run_before_rca(self, world):
        engine = FakeEngine(read_overrides={("pending", 0): pipe.StageTimeout()})
        assert go(world, engine, execute=True)[0] == 1 and len(engine.compose) == 1

    def test_more_rows_than_the_limit_is_refused(self, world):
        rows = "\n".join(_ids(30)).encode()
        engine = FakeEngine(read_overrides={("pending", 0): workers.CommandResult(0, rows)})
        assert go(world, engine, execute=True)[0] == 1

    def test_blank_lines_are_ignored_and_every_id_is_validated(self, world):
        rows = ("\n" + "\n\n".join(_ids(2)) + "\n").encode()
        engine = FakeEngine(read_overrides={("pending", 0): workers.CommandResult(0, rows)}, pending=_ids(2))
        assert go(world, engine, execute=True)[0] == 0

    def test_the_limit_bounds_the_run(self, world):
        engine = FakeEngine(pending=_ids(10))
        code, out, _e = go(world, engine, "--max-anomalies", "4", execute=True)
        assert [a for s, a in engine.compose if s == "rca-analyzer"] == _ids(10)[:4]
        assert code == 0 and "still pending" in out

    def test_no_sql_is_built_from_an_anomaly_id(self, world):
        engine = FakeEngine(pending=_ids(2))
        go(world, engine, execute=True)
        for argv, _e, _t in engine.calls:
            if argv[1] == "exec":
                sql = argv[argv.index("-c") + 1]
                assert not any(i in sql for i in _ids(2)) and sql in pipe.ALLOWED_READS

    def test_no_write_is_ever_sent_to_the_database(self, world):
        engine = FakeEngine(pending=_ids(2))
        go(world, engine, execute=True)
        database_calls = [argv for argv, _e, _t in engine.calls if argv[1] == "exec"]
        assert database_calls
        for argv in database_calls:
            assert "--single-transaction" not in argv and "-f" not in argv and "-i" not in argv
            assert argv.count("-c") == 1 and argv[argv.index("-c") + 1].startswith("SELECT ")


# ===========================================================================
# P10 RCA stage
# ===========================================================================

class TestRca:
    def test_each_anomaly_is_one_invocation_in_order(self, world):
        engine = FakeEngine(pending=_ids(4))
        code, out, _e = go(world, engine, execute=True)
        assert code == 0 and [a for s, a in engine.compose if s == "rca-analyzer"] == _ids(4)
        assert len(engine.compose) == 5

    def test_the_rca_runs_get_the_rca_timeout(self, world):
        engine = FakeEngine(pending=_ids(2))
        go(world, engine, execute=True)
        timeouts = [t for argv, _e, t in engine.calls if argv[1] == "compose"]
        assert timeouts == [pipe.DETECTOR_TIMEOUT_SECONDS, pipe.RCA_TIMEOUT_SECONDS, pipe.RCA_TIMEOUT_SECONDS]

    def test_the_rca_commands_target_only_the_disposable_environment(self, world):
        engine = FakeEngine(pending=_ids(2))
        go(world, engine, execute=True)
        for argv, _e, _t in engine.calls:
            if argv[1] == "compose":
                assert argv[3] == "agentops-pipetest" and argv[5].replace("\\", "/").endswith(PIPETEST.compose_file)

    @pytest.mark.parametrize("failure", [1, 2, 7, 125, 137])
    def test_an_isolated_failure_is_reported_and_the_rest_continue(self, world, failure):
        ids = _ids(4)
        engine = FakeEngine(pending=ids, rca_codes={ids[1]: failure})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4
        assert [a for s, a in engine.compose if s == "rca-analyzer"] == ids          # all four were tried, none twice
        assert f"{ids[1]}: exit {failure}" in out and "investigated: 3" in out

    def test_an_ambiguous_exit_code_counts_as_a_failure(self, world):
        ids = _ids(1)
        engine = FakeEngine(pending=ids, rca_codes={ids[0]: 42})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and "unexpected exit code" in out

    def test_three_consecutive_failures_stop_the_stage(self, world):
        ids = _ids(6)
        engine = FakeEngine(pending=ids, rca_default=1)
        code, out, _e = go(world, engine, execute=True)
        assert code == 4
        assert [a for s, a in engine.compose if s == "rca-analyzer"] == ids[:3]
        assert "3 consecutive RCA failures" in out and "not attempted: 3" in out

    def test_a_success_resets_the_consecutive_count(self, world):
        ids = _ids(6)
        engine = FakeEngine(pending=ids, rca_codes={ids[0]: 1, ids[1]: 1, ids[3]: 1, ids[4]: 1})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and len([1 for s, _ in engine.compose if s == "rca-analyzer"]) == 6
        assert "consecutive" not in out

    @pytest.mark.parametrize("systemic", [3, 4])
    def test_a_configuration_or_database_failure_stops_at_once(self, world, systemic):
        ids = _ids(5)
        engine = FakeEngine(pending=ids, rca_codes={ids[1]: systemic})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and [a for s, a in engine.compose if s == "rca-analyzer"] == ids[:2]
        assert "not attempted: 3" in out and "configuration or database failure" in out

    def test_an_interrupted_rca_run_stops_the_stage(self, world):
        ids = _ids(4)
        engine = FakeEngine(pending=ids, rca_codes={ids[0]: 130})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and len([1 for s, _ in engine.compose if s == "rca-analyzer"]) == 1 and "interrupted" in out

    def test_an_rca_that_could_not_be_started_stops_the_stage(self, world):
        ids = _ids(3)
        engine = FakeEngine(pending=ids, raise_at={f"compose:rca:{ids[0][:8]}": OSError(_CANARY)})
        code, out, err = go(world, engine, execute=True)
        assert code == 4 and len(engine.compose) == 2 and _CANARY not in out + err

    def test_no_failure_is_ever_retried(self, world):
        ids = _ids(3)
        engine = FakeEngine(pending=ids, rca_codes={i: 1 for i in ids[:2]})
        go(world, engine, execute=True)
        rca = [a for s, a in engine.compose if s == "rca-analyzer"]
        assert len(rca) == len(set(rca))

    def test_worker_output_is_never_printed(self, world):
        engine = FakeEngine(pending=_ids(2), rca_default=1, noisy=True)
        code, out, err = go(world, engine, execute=True)
        assert _CANARY not in out + err


# ===========================================================================
# P11 Idempotent reruns and the final check
# ===========================================================================

class TestRerun:
    def test_nothing_pending_runs_no_rca(self, world):
        engine = FakeEngine(pending=[])
        code, out, _e = go(world, engine, execute=True)
        assert code == 0 and [s for s, _ in engine.compose] == ["anomaly-detector"] and "investigated: 0" in out

    def test_a_second_run_finds_nothing_left(self, world):
        engine = FakeEngine(pending=_ids(3))
        assert go(world, engine, execute=True)[0] == 0
        first = len(engine.compose)
        assert go(world, engine, execute=True)[0] == 0
        assert [s for s, _ in engine.compose[first:]] == ["anomaly-detector"]

    def test_a_rerun_after_a_partial_failure_only_takes_what_is_still_pending(self, world):
        ids = _ids(3)
        engine = FakeEngine(pending=ids, rca_codes={ids[1]: 1})
        assert go(world, engine, execute=True)[0] == 4
        engine.rca_codes = {}
        first = len(engine.compose)
        assert go(world, engine, execute=True)[0] == 0
        assert [a for s, a in engine.compose[first:] if s == "rca-analyzer"] == [ids[1]]

    def test_a_success_that_left_the_anomaly_pending_is_reported_as_inconsistent(self, world):
        ids = _ids(2)
        engine = FakeEngine(pending=ids, persist=False)
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and "INCONSISTENT" in out and ids[0] in out

    def test_an_unreadable_final_set_is_reported(self, world):
        engine = FakeEngine(pending=_ids(1), read_overrides={("pending", 1): workers.CommandResult(1, b"")})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and "final pending set could not be read" in out

    def test_an_unreadable_evidence_check_does_not_fail_a_clean_run(self, world):
        engine = FakeEngine(pending=_ids(1), read_overrides={("noevidence", 0): workers.CommandResult(1, b"")})
        code, out, _e = go(world, engine, execute=True)
        assert code == 0 and "evidence check could not be read" in out

    def test_investigations_without_evidence_are_reported_not_acted_on(self, world):
        engine = FakeEngine(pending=_ids(1), no_evidence=_ids(5)[3:])
        code, out, _e = go(world, engine, execute=True)
        assert code == 0 and "without evidence that are not INSUFFICIENT_DATA: 2" in out
        assert len(engine.compose) == 2

    def test_the_summary_is_printed_on_every_path(self, world):
        for engine in (FakeEngine(), FakeEngine(detector_code=1), FakeEngine(pending=_ids(1), rca_default=1)):
            _c, out, _e = go(world, engine, execute=True)
            assert "pipeline summary" in out


# ===========================================================================
# P12 Timeouts and interrupts
# ===========================================================================

class TestTimeoutsAndInterrupts:
    def test_an_rca_timeout_stops_the_stage_without_cleanup_or_retry(self, world):
        ids = _ids(4)
        engine = FakeEngine(pending=ids, raise_at={f"compose:rca:{ids[1][:8]}": pipe.StageTimeout()})
        code, out, _e = go(world, engine, execute=True)
        assert code == 4 and [a for s, a in engine.compose if s == "rca-analyzer"] == ids[:2]
        assert "timed out" in out and "nothing was cleaned up" in out and "not attempted: 2" in out
        for argv, _env, _t in engine.calls:
            assert argv[1] in ("inspect", "ps", "exec", "compose", "volume", "network")
            assert "rm" not in argv[1:3] and "stop" not in argv[1:3]

    def test_an_interrupt_during_the_detector_reports_and_releases_the_lock(self, world):
        engine = FakeEngine(pending=_ids(2), raise_at={"compose:detector": KeyboardInterrupt()})
        code, out, _e = go(world, engine, execute=True)
        assert code == 130 and "interrupted" in out and "pipeline summary" in out
        assert FakeLock.created[0].exited == 1 and len(engine.compose) == 1

    def test_an_interrupt_during_rca_reports_the_progress_made(self, world):
        ids = _ids(4)
        engine = FakeEngine(pending=ids, raise_at={f"compose:rca:{ids[2][:8]}": KeyboardInterrupt()})
        code, out, _e = go(world, engine, execute=True)
        assert code == 130 and "investigated: 2" in out
        assert [a for s, a in engine.compose if s == "rca-analyzer"] == ids[:3]
        assert FakeLock.created[0].exited == 1

    def test_an_interrupt_during_a_dry_run_exits_130(self, world):
        engine = FakeEngine(raise_at={"read:pending": KeyboardInterrupt()})
        assert go(world, engine)[0] == 130

    def test_an_unexpected_exception_is_reported_by_type_only(self, world):
        engine = FakeEngine(pending=_ids(2), raise_at={"read:pending": ValueError(_CANARY)})
        code, out, err = go(world, engine, execute=True)
        assert code == 1 and "ValueError" in out and _CANARY not in out + err

    def test_a_docker_failure_during_the_final_read_is_reported(self, world):
        engine = FakeEngine(pending=_ids(1), read_overrides={("pending", 1): OSError(_CANARY)})
        code, out, err = go(world, engine, execute=True)
        assert code == 4 and _CANARY not in out + err


# ===========================================================================
# P13 Secret canaries
# ===========================================================================

class TestCanaries:
    @pytest.mark.parametrize("builder", [
        lambda: FakeEngine(pending=_ids(2), noisy=True),
        lambda: FakeEngine(pending=_ids(2), detector_code=1, noisy=True),
        lambda: FakeEngine(pending=_ids(2), rca_default=1, noisy=True),
        lambda: FakeEngine(facts=_CANARY),
        lambda: FakeEngine(volume_facts=_CANARY),
        lambda: FakeEngine(network_facts=_CANARY),
        lambda: FakeEngine(ledger=_CANARY),
        lambda: FakeEngine(read_overrides={("pending", 0): workers.CommandResult(0, _CANARY.encode())}),
        lambda: FakeEngine(workers_running=[_CANARY]),
        lambda: FakeEngine(raise_at={"compose:detector": RuntimeError(_CANARY)}),
        lambda: FakeEngine(raise_at={"inspect": RuntimeError(_CANARY)}),
        lambda: FakeEngine(target="accepted", facts=_CANARY),
        lambda: FakeEngine(target="accepted", pending=_ids(1))])
    @pytest.mark.parametrize("execute", [False, True])
    def test_no_canary_no_command_output_no_credentials_path_is_ever_printed(self, world, builder, execute):
        engine = builder()
        execute = execute and engine.target == "pipetest"
        code, out, err = go(world, engine, execute=execute)
        path = world.creds_for(engine.target)
        for text in (out, err):
            assert _CANARY not in text
            assert path not in text and str(Path(path).parent) not in text
            assert "credentials.env" not in text.replace("the credentials file", "")

    def test_the_canary_in_the_environment_never_reaches_a_command(self, world):
        engine = FakeEngine(pending=_ids(1))
        go(world, engine, execute=True)
        for argv, env, _t in engine.calls:
            assert _CANARY not in " ".join(argv) and _CANARY not in " ".join(env.values())

    def test_the_credentials_file_content_is_not_reachable_from_the_report(self, world):
        engine = FakeEngine(pending=_ids(1))
        code, out, err = go(world, engine, execute=True)
        assert code == 0 and "PASSWORD" not in out + err


# ===========================================================================
# P14 Detector configuration (mart-signal refusal)
# ===========================================================================

class TestDetectorConfig:
    @pytest.mark.parametrize("signal", sorted(pipe.MART_SIGNALS))
    def test_a_mart_signal_is_refused_before_any_command(self, world, signal):
        engine = FakeEngine()
        config = '{"groups": [{"signal_path": "%s", "service_name": "s"}]}' % signal
        code, _o, err = go(world, engine, execute=True, config=config)
        assert code == 2 and engine.calls == [] and "analytics refresh" in err

    def test_one_mart_signal_among_view_signals_is_refused(self, world):
        config = ('{"groups": [{"signal_path": "tool_latency", "service_name": "s"},'
                  ' {"signal_path": "trace_latency", "service_name": "s", "operation_name": "o"}]}')
        engine = FakeEngine()
        assert go(world, engine, execute=True, config=config)[0] == 2 and engine.calls == []

    @pytest.mark.parametrize("config", ["not json", "[]", "{}", '{"groups": []}', '{"groups": ["x"]}',
                                        '{"groups": [{"signal_path": "nonsense"}]}', '{"groups": [{}]}'])
    def test_an_unreadable_or_unknown_configuration_is_refused(self, world, config):
        engine = FakeEngine()
        assert go(world, engine, config=config)[0] == 2 and engine.calls == []

    def test_the_accepted_configuration_passes(self, world):
        text = (_REPO / "docker" / "mvp-workers" / "detector_config.json").read_text(encoding="utf-8")
        pipe.check_detector_config(text)
        assert go(world, FakeEngine())[0] == 0

    def test_a_missing_configuration_file_is_refused(self, world, tmp_path):
        engine = FakeEngine()
        out, err = io.StringIO(), io.StringIO()
        code = pipe.main(["run", "--target", "pipetest", "--credentials-file", world.creds], environ=world.environ,
                         run=engine, docker="docker", out=out, err=err, repo_root=tmp_path, home=world.home,
                         platform_name=os.name)
        assert code == 2 and engine.calls == []

    def test_the_signal_sets_match_the_detectors_own_queries(self):
        source = (_REPO / "anomaly-detector" / "telemetry_queries.py").read_text(encoding="utf-8")
        found = dict(re.findall(r"fetch_(\w+?)_history\(\)\s+\S+\s+analytics\.(\w+)", source))
        assert set(found) == pipe.VIEW_SIGNALS | pipe.MART_SIGNALS
        for signal, relation in found.items():
            assert (relation == "stg_telemetry_spans") == (signal in pipe.VIEW_SIGNALS), signal
            assert relation.startswith("mart_") == (signal in pipe.MART_SIGNALS), signal

    def test_the_configuration_is_one_the_detector_accepts_by_name(self):
        source = (_REPO / "anomaly-detector" / "run_config.py").read_text(encoding="utf-8")
        for signal in pipe.VIEW_SIGNALS | pipe.MART_SIGNALS:
            assert f'"{signal}"' in source


# ===========================================================================
# P15 Compose contracts
# ===========================================================================

def _service_block(text: str, name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n(?P<body>(?:    .*\n|\n|      .*\n)+?)(?=^  [a-z][a-z-]*:\n|^[a-z]|\Z)", text, re.M)
    assert match, name
    return match.group("body")


def _without_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


class TestComposeContract:
    def test_the_project_and_file_are_the_isolated_ones(self):
        text = _COMPOSE.read_text(encoding="utf-8")
        assert re.search(r"^name: agentops-mvp-workers$", text, re.M)
        assert ACCEPTED.project == "agentops-mvp-workers" and ACCEPTED.compose_file == "docker/mvp-workers/compose.yml"
        assert (_REPO / ACCEPTED.compose_file).is_file()

    def test_the_detector_service_is_one_shot_and_takes_no_arguments_from_the_runner(self):
        block = _service_block(_COMPOSE.read_text(encoding="utf-8"), pipe.DETECTOR_SERVICE)
        assert 'profiles: ["workers"]' in block
        assert 'entrypoint: ["python", "main.py"]' in block
        assert '"--config", "/opt/agentops/config/detector_config.json"' in block
        assert "ANOMALY_DETECTOR_DB_PASSWORD" in block and "restart" not in block.replace("worker_hardening", "")

    def test_the_rca_service_takes_the_anomaly_id_from_the_command_line(self):
        block = _service_block(_COMPOSE.read_text(encoding="utf-8"), pipe.RCA_SERVICE)
        assert 'profiles: ["workers"]' in block and 'entrypoint: ["python", "main.py"]' in block
        assert not re.search(r"^\s+command:", block, re.M)
        assert "RCA_ANALYZER_DB_PASSWORD" in block

    def test_the_workers_publish_nothing(self):
        text = _COMPOSE.read_text(encoding="utf-8")
        for service in (pipe.DETECTOR_SERVICE, pipe.RCA_SERVICE):
            assert "ports:" not in _service_block(text, service)

    def test_the_runner_names_the_isolated_container(self):
        assert ACCEPTED.postgres_container == "agentops-mvp-workers-postgres-1" == workers.POSTGRES_CONTAINER

    def test_the_worker_exit_codes_the_runner_relies_on_are_documented_by_the_workers(self):
        detector = (_REPO / "anomaly-detector" / "main.py").read_text(encoding="utf-8")
        rca = (_REPO / "rca-analyzer" / "main.py").read_text(encoding="utf-8")
        for code in (0, 1, 2, 3, 4, 130):
            assert re.search(rf"^\s+{code}\s", detector, re.M), code
        for code in (0, 1, 2, 3, 4, 130):
            assert re.search(rf"^\s+{code}\s", rca, re.M), code
        assert set(pipe.DETECTOR_MESSAGES) == {1, 2, 3, 4, 130} and set(pipe.RCA_MESSAGES) == {1, 2, 3, 4, 130}

    def test_the_investigation_identity_does_not_depend_on_the_hosts_copy_of_the_version(self):
        sql = pipe.pending_sql(25)
        assert "analyzer_version" not in sql and "investigation_id" not in sql


_PIPETEST_IMAGES = ("agentops-mvp-workers-postgres:latest", "agentops-mvp-workers-anomaly-detector:latest",
                    "agentops-mvp-workers-rca-analyzer:latest")


class TestDisposableCompose:
    TEXT = _PIPETEST_COMPOSE.read_text(encoding="utf-8")
    CODE = _without_comments(TEXT)

    def test_the_file_exists_and_names_the_registry_entry(self):
        assert _PIPETEST_COMPOSE.is_file() and PIPETEST.compose_file == "docker/mvp-workers-pipetest/compose.yml"
        assert re.search(r"^name: agentops-pipetest$", self.CODE, re.M)
        assert re.search(r"^    name: agentops-pipetest-net$", self.CODE, re.M)
        assert re.search(r"^    name: agentops-pipetest-pgdata$", self.CODE, re.M)
        assert PIPETEST.project == "agentops-pipetest" and PIPETEST.network == "agentops-pipetest-net"
        assert PIPETEST.volume == "agentops-pipetest-pgdata"
        assert PIPETEST.postgres_container == f"{PIPETEST.project}-postgres-1"

    def test_exactly_the_three_services(self):
        services = re.findall(r"^  ([a-z][a-z-]*):\n", self.CODE.split("\nnetworks:")[0].split("services:")[1], re.M)
        assert services == ["postgres", "anomaly-detector", "rca-analyzer"]

    def test_no_service_sets_a_container_name(self):
        assert "container_name" not in self.CODE

    def test_nothing_is_built_and_nothing_is_pulled(self):
        assert "build:" not in self.CODE and "dockerfile" not in self.CODE and "context:" not in self.CODE
        assert self.CODE.count("pull_policy: never") == 2            # postgres, and the anchor the workers merge
        for service in ("anomaly-detector", "rca-analyzer"):
            assert "<<: *worker_hardening" in _service_block(self.CODE, service)
        assert re.search(r"x-worker-hardening: &worker_hardening\n(?:  .*\n)*?  pull_policy: never", self.CODE)

    def test_only_the_existing_local_images_are_used(self):
        images = re.findall(r"^    image: (\S+)$", self.CODE, re.M)
        assert sorted(images) == sorted(_PIPETEST_IMAGES)

    def test_no_resource_of_the_accepted_projects_is_referenced(self):
        stripped = self.CODE
        for image in _PIPETEST_IMAGES:
            stripped = stripped.replace(f"image: {image}", "image: IMAGE")
        for forbidden in ("agentops-mvp", "agentops_", "agentops-postgres", "workers-net", "postgres-data:/", "8001", "8000",
                          "viewer", "grafana", "kafka"):
            assert forbidden not in stripped.replace("postgres-data:\n", "").replace("- postgres-data:/var/lib/postgresql/data", ""), forbidden

    def test_nothing_is_published_and_nothing_is_privileged(self):
        for forbidden in ("ports:", "expose:", "privileged", "docker.sock", "network_mode", "pid:", "ipc:", "devices:",
                          "cap_add", "external:", "driver_opts", "/var/run", "bind", "userns_mode", "extra_hosts"):
            assert forbidden not in self.CODE, forbidden

    def test_the_only_mount_is_the_disposable_volume(self):
        mounts = re.findall(r"^\s+- (\S+:/\S+)$", self.CODE, re.M)
        assert mounts == ["postgres-data:/var/lib/postgresql/data"]
        assert "volumes:\n  postgres-data:\n    name: agentops-pipetest-pgdata" in self.CODE

    def test_names_labels_and_ownership_are_explicit_and_fixed(self):
        assert self.CODE.count('agentops.pipetest: "true"') >= 4
        assert PIPETEST.ownership_label == "agentops.pipetest"
        assert re.search(r"^networks:\n  pipetest-net:\n    name: agentops-pipetest-net\n    driver: bridge\n    labels:\n      agentops.pipetest: \"true\"", self.CODE, re.M)

    def test_no_password_is_written_in_the_file(self):
        variables = set(re.findall(r"\$\{([A-Z0-9_]+)(?::\?[^}]*)?\}", self.CODE))
        assert variables == {"PIPETEST_POSTGRES_PASSWORD", "PIPETEST_ANOMALY_DETECTOR_DB_PASSWORD",
                             "PIPETEST_RCA_ANALYZER_DB_PASSWORD"}
        for line in self.CODE.splitlines():
            if "PASSWORD" in line and ":" in line:
                assert re.search(r"\$\{PIPETEST_[A-Z_]+:\?", line), line
        assert "env_file" not in self.CODE

    def test_the_accepted_credential_names_are_not_used(self):
        for name in ("${POSTGRES_PASSWORD", "${ANOMALY_DETECTOR_DB_PASSWORD", "${RCA_ANALYZER_DB_PASSWORD", "${TRACE_VIEWER",
                     "${GF_", "${ALERT_", "${INCIDENT_"):
            assert name not in self.CODE
        for variable in ("PIPETEST_POSTGRES_PASSWORD", "PIPETEST_ANOMALY_DETECTOR_DB_PASSWORD", "PIPETEST_RCA_ANALYZER_DB_PASSWORD"):
            assert f"${{{variable}:?" in self.CODE

    def test_each_service_gets_only_its_own_password(self):
        assert "PIPETEST_POSTGRES_PASSWORD" in _service_block(self.CODE, "postgres")
        detector = _service_block(self.CODE, "anomaly-detector")
        rca = _service_block(self.CODE, "rca-analyzer")
        assert "PIPETEST_ANOMALY_DETECTOR_DB_PASSWORD" in detector and "PIPETEST_RCA" not in detector and "PIPETEST_POSTGRES" not in detector
        assert "PIPETEST_RCA_ANALYZER_DB_PASSWORD" in rca and "PIPETEST_ANOMALY" not in rca and "PIPETEST_POSTGRES" not in rca

    def test_the_workers_are_one_shot_and_hardened(self):
        anchor = re.search(r"x-worker-hardening: &worker_hardening\n(?P<b>(?:  .*\n)+)", self.CODE).group("b")
        for needle in ('restart: "no"', "read_only: true", "- ALL", "no-new-privileges:true", "pipetest-net"):
            assert needle in anchor, needle
        for service, config in ((pipe.DETECTOR_SERVICE, '"--config", "/opt/agentops/config/detector_config.json"'),
                                (pipe.RCA_SERVICE, None)):
            block = _service_block(self.CODE, service)
            assert 'profiles: ["workers"]' in block and 'entrypoint: ["python", "main.py"]' in block
            assert ("command:" in block) == (config is not None)
            if config:
                assert config in block

    def test_postgres_publishes_nothing_and_has_a_healthcheck(self):
        block = _service_block(self.CODE, "postgres")
        assert "healthcheck:" in block and "pg_isready" in block and 'restart: "no"' in block and "ports" not in block

    def test_the_detector_config_it_relies_on_is_the_accepted_one(self):
        assert _service_block(self.CODE, "anomaly-detector").count("detector_config.json") == 1
        assert pipe.DETECTOR_CONFIG == "docker/mvp-workers/detector_config.json"


# ===========================================================================
# P16 Static properties of the module
# ===========================================================================

class TestStatic:
    SOURCE = _PIPE_SOURCE.read_text(encoding="utf-8")
    TREE = ast.parse(SOURCE)

    def test_no_shell(self):
        for node in ast.walk(self.TREE):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert isinstance(node.value, ast.Constant) and node.value.value is False
        assert "os.system" not in self.SOURCE and "Popen" not in self.SOURCE and "shell=True" not in self.SOURCE

    def test_a_process_is_started_in_exactly_one_function(self):
        runner = next(n for n in ast.walk(self.TREE) if isinstance(n, ast.FunctionDef) and n.name == "default_runner")
        for node in ast.walk(self.TREE):
            if isinstance(node, ast.Name) and node.id == "subprocess":
                assert runner.lineno <= node.lineno <= runner.end_lineno
        calls = [n for n in ast.walk(runner) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "run"]
        assert len(calls) == 1
        keywords = {k.arg: k.value for k in calls[0].keywords}
        assert keywords["check"].value is False and keywords["shell"].value is False and "timeout" in keywords

    def test_the_only_file_read_is_the_detector_configuration(self):
        calls = [n for n in ast.walk(self.TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr in ("read_text", "read_bytes", "open")]
        assert len(calls) == 1 and "DETECTOR_CONFIG" in ast.unparse(calls[0])
        assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
                       for n in ast.walk(self.TREE))

    def test_nothing_is_imported_beyond_the_standard_library_and_the_four_scripts(self):
        allowed = {"argparse", "json", "os", "re", "shutil", "subprocess", "sys", "dataclasses", "pathlib", "typing",
                   "types", "__future__", "agentops_mvp", "agentops_mvp_demo", "agentops_mvp_lifecycle",
                   "agentops_mvp_workers"}
        for node in ast.walk(self.TREE):
            if isinstance(node, ast.Import):
                assert {a.name.split(".")[0] for a in node.names} <= allowed
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                assert node.module.split(".")[0] in allowed

    def test_no_sleep_loop_or_retry_exists(self):
        assert "sleep(" not in self.SOURCE and "while True" not in self.SOURCE and "retry" not in self.SOURCE.lower().replace("retries", "")

    def test_messages_never_format_command_output(self):
        for node in ast.walk(self.TREE):
            if isinstance(node, ast.Attribute) and node.attr == "stdout":
                owner = ast.unparse(node.value)
                # only where a command result is parsed or wrapped (sys.stdout is the default report stream)
                assert owner in ("result", "completed", "sys"), owner

    def test_the_module_does_not_modify_existing_files(self):
        assert "write_text" not in self.SOURCE and "write_bytes" not in self.SOURCE and "unlink" not in self.SOURCE
        assert "rmtree" not in self.SOURCE and "os.remove" not in self.SOURCE

    def test_no_command_is_built_from_a_free_name(self):
        # every builder takes a registry Target and checks it; none takes a project, container or volume string
        for name in ("compose_run_argv", "rca_argv", "read_argv", "workers_ps_argv", "container_probe_argv",
                     "volume_probe_argv", "network_probe_argv"):
            function = next(n for n in ast.walk(self.TREE) if isinstance(n, ast.FunctionDef) and n.name == name)
            assert any(a.arg == "target" for a in function.args.args), name
            assert not {a.arg for a in function.args.args} & {"project", "container", "volume", "network", "compose_file"}

    def test_an_accepted_name_is_written_as_a_literal_only_in_the_registry_self_check(self):
        # the accepted target's names come from the operator script's constants; the one literal list is the
        # deny-list that proves the disposable target does not use them
        holders = set()
        for function in (n for n in ast.walk(self.TREE) if isinstance(n, ast.FunctionDef)):
            for node in ast.walk(function):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                        node.value.startswith("agentops-mvp-workers"):
                    holders.add(function.name)
        assert holders == {"_check_registry"}

    def test_there_is_no_way_to_execute_on_the_accepted_target(self):
        # the only place that may run a worker is behind refuse_if_not_executable, called in main() and again
        # inside the workflow
        calls = [n for n in ast.walk(self.TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == "refuse_if_not_executable"]
        assert len(calls) == 2


# ===========================================================================
# P17 The offline guard itself
# ===========================================================================

class TestOfflineGuard:
    def test_the_default_runner_is_blocked_in_tests(self):
        with pytest.raises(AssertionError, match="external access blocked"):
            pipe.default_runner(["docker", "ps"], {}, 1.0)

    def test_every_real_way_out_is_blocked(self):
        for call in (lambda: subprocess.run(["x"]), lambda: subprocess.Popen(["x"]), lambda: os.system("x"),
                     lambda: shutil.which("docker"), lambda: socket.create_connection(("127.0.0.1", 1)),
                     lambda: socket.getaddrinfo("localhost", 1), lambda: subprocess.check_output(["x"])):
            with pytest.raises(AssertionError, match="external access blocked"):
                call()

    @pytest.mark.parametrize("target", ["accepted", "pipetest"])
    def test_a_run_without_an_injected_runner_cannot_reach_a_process(self, world, target):
        out, err = io.StringIO(), io.StringIO()
        code = pipe.main(["run", "--target", target, "--credentials-file", world.creds_for(target)],
                         environ=world.environ, docker="docker", out=out, err=err, repo_root=_REPO, home=world.home,
                         platform_name=os.name)
        assert code == 2                                        # the guard raised inside the engine call: refused
        assert "external access blocked" not in out.getvalue() + err.getvalue()

    def test_the_parser_rejects_unknown_input(self):
        for argv in ([], ["bogus"], ["run"], ["plan", "--execute"], ["run", "--credentials-file"]):
            assert pipe.main(argv, out=io.StringIO(), err=io.StringIO()) == 2

"""
workload-generator/tests/unit/test_viewer_sql_it.py

Offline tests of the disposable-PostgreSQL validation harness for the trace viewer
(workload-generator/run_viewer_sql_it.py) and of the opt-in guard and fixtures of
trace-viewer/tests/integration.

Nothing here starts Docker, WSL or PostgreSQL, reads the live engine, or reaches an external network:
subprocess calls are replaced by a recording shell, inventories and host readings are synthetic, the test
run is a fake that writes a JUnit report, and the only socket used is a local listener on 127.0.0.1 that
never answers (for the connection-timeout test).  The SQL itself is NOT exercised: that needs the live run.

    T01  Inertness and the command line
    T02  Names, ports, override and credentials
    T03  Compose commands: one project, two services, no other verb
    T04  Gates and preflight order
    T05  The single-attempt rule
    T06  Reading the test report and the verdict
    T07  Cleanup scoping, ownership and markers
    T08  The whole flow, every command scripted
    T09  The opt-in guard of the live tests and their inventory
    T10  The deterministic fixtures
    T11  The connection timeout against a local silent listener
"""

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parents[2]
_REPO = _HERE.parent
sys.path.insert(0, str(_HERE))

H = importlib.import_module("run_viewer_sql_it")
S = importlib.import_module("run_shutdown_it")
smoke = importlib.import_module("run_smoke")
SmokeFailure = smoke.SmokeFailure
_REAL_REMOVE_TREE = smoke._remove_tree     # the shared guard itself: every test replaces it by a recorder unless it says so

PROJECT = "agentops-viewer-it-0a1b2c3d"
PORT = 23456
HEAD = "a" * 40
BRANCH = H.EXPECTED_BRANCH
OWN_STATUS = "\n".join(f"?? {path}" for path in H.OWN_FILES)
INTEGRATION = _REPO / "trace-viewer" / "tests" / "integration"
LIVE_FILE = _REPO / H.LIVE_TEST_FILE


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class RecordingShell:
    def __init__(self, router=None):
        self.commands = []
        self.router = router or (lambda command: Result())

    def __call__(self, command, *, timeout, what=""):
        self.commands.append(list(command))
        return self.router(list(command))


def git_router(branch=BRANCH, head=HEAD, status=OWN_STATUS, cached=""):
    def route(command):
        args = command[3:] if command[:2] == ["git", "-C"] else command[1:]
        if args[:2] == ["rev-parse", "--abbrev-ref"]:
            return Result(stdout=branch + "\n")
        if args[:1] == ["rev-parse"]:
            return Result(stdout=head + "\n")
        if args[:2] == ["diff", "--cached"]:
            return Result(stdout=cached)
        if args[:1] == ["status"]:
            return Result(stdout=status)
        return Result()
    return route


class RemovalRecorder:
    """Stands in for smoke._remove_tree in every test of this module.  It NEVER deletes: it records the path it was
    handed and reports success, so cleanup code runs to completion without touching the disk.  A path that is not
    strictly inside the test's own tmp_path, or that is (or contains, or lies inside) the development repository,
    the recovery area, an OneDrive folder or the Windows directory, is an AssertionError, never a recorded call."""

    def __init__(self, sandbox: Path) -> None:
        self.sandbox = sandbox.resolve()
        self.calls: list[Path] = []
        windows = os.environ.get("SystemRoot") or "C:/Windows"
        self.protected = [_REPO.resolve(), Path("C:/AgentOps-Development"), Path("C:/AgentOps-Recovery"),
                          Path.home() / "OneDrive", Path(windows)]

    def __call__(self, path) -> bool:
        resolved = Path(path).resolve()
        if self.sandbox not in resolved.parents:
            raise AssertionError(f"a test tried to delete {resolved}, which is outside its tmp_path")
        for root in self.protected:
            root = root.resolve()
            if resolved == root or root in resolved.parents or resolved in root.parents:
                raise AssertionError(f"a test tried to delete {resolved}, which touches the protected path {root}")
        self.calls.append(resolved)
        return True


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """No test may touch the real temp area, the real run state, or the real machine.  Nothing is ever deleted:
    smoke._remove_tree is a RemovalRecorder (read the calls from smoke._remove_tree.calls)."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(smoke, "_remove_tree", RemovalRecorder(tmp_path))
    monkeypatch.setattr(smoke, "_windows", lambda: False)     # the supported-host paths; TestUnsupportedWindowsHost sets True
    monkeypatch.setattr(smoke, "_OWNED", {})                  # no ownership record leaks between tests
    for name in ("AGENTOPS_VIEWER_IT_DSN", "AGENTOPS_VIEWER_IT_VIEWER_PASSWORD", "AGENTOPS_VIEWER_IT_PROJECT",
                 "AGENTOPS_VIEWER_IT_APPROVAL"):
        monkeypatch.delenv(name, raising=False)
    saved = {name: getattr(smoke.RUN, name) for name in ("temp", "generated", "env_file", "compose_used", "masked_in_logs")}
    yield
    for name, value in saved.items():
        setattr(smoke.RUN, name, value)


def credentials():
    return {name: f"secret-{name.lower()}-value" for name in smoke.PASSWORD_VARIABLES}


# ---------------------------------------------------------------------------
# T01  Inertness and the command line
# ---------------------------------------------------------------------------

class TestInertAndCommandLine:
    def test_the_plan_mode_runs_nothing(self, monkeypatch, capsys):
        def forbidden(*args, **kwargs):
            raise AssertionError("the plan mode must not run anything")
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(smoke, "run", forbidden)
        assert H.main([]) == 0
        text = capsys.readouterr().out
        assert "plan (nothing is created or started" in text and "postgres, db-bootstrap only" in text
        assert "20 test functions" in text and "no --rmi" in text

    def test_the_plan_names_the_confirmation_phrase_for_a_given_head(self, capsys):
        assert H.main(["--expect-head", HEAD]) == 0
        assert H.confirmation_phrase(HEAD) in capsys.readouterr().out

    @pytest.mark.parametrize("argv", [
        ["--execute", "--expect-head", HEAD],
        ["--execute", "--expect-head", HEAD, "--confirm", "yes"],
        ["--execute", "--expect-head", HEAD, "--confirm", H.CONFIRM_PREFIX + "b" * 12],
        ["--execute", "--confirm", H.CONFIRM_PREFIX + "a" * 12],
        ["--execute", "--expect-head", "abc123", "--confirm", H.CONFIRM_PREFIX + "abc123"],
        ["--preflight"],
        ["--preflight", "--expect-head", "main"],
    ])
    def test_a_refused_invocation_exits_2_and_issues_no_command(self, monkeypatch, argv):
        def forbidden(*args, **kwargs):
            raise AssertionError("a refused invocation must not run anything")
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(smoke, "run", forbidden)
        assert H.main(argv) == 2

    def test_importing_the_module_runs_nothing(self):
        source = (_HERE / "run_viewer_sql_it.py").read_text(encoding="utf-8")
        assert source.count('if __name__ == "__main__":') == 1 and source.count("sys.exit(main())") == 1

    def test_confirmation_is_bound_to_the_head(self):
        H.check_confirmation(H.confirmation_phrase(HEAD), HEAD)
        with pytest.raises(SmokeFailure):
            H.check_confirmation(H.confirmation_phrase("b" * 40), HEAD)
        with pytest.raises(SmokeFailure):
            H.check_confirmation(None, HEAD)

    def test_the_preflight_command_creates_nothing_and_reads_only(self, monkeypatch, capsys, tmp_path):
        pre = H.Preflight(PROJECT, PORT, "development", {}, {}, S.Readings(), None)
        monkeypatch.setattr(H, "run_preflight", lambda *a, **k: pre)
        before = sorted(p.name for p in tmp_path.iterdir())
        assert H.main(["--preflight", "--expect-head", HEAD]) == 0
        assert "nothing was created" in capsys.readouterr().out
        assert sorted(p.name for p in tmp_path.iterdir()) == before and not H.attempts_dir().exists()

    def test_a_failing_preflight_command_exits_1(self, monkeypatch, capsys):
        def refuse(*a, **k):
            raise SmokeFailure("memory too low")
        monkeypatch.setattr(H, "run_preflight", refuse)
        assert H.main(["--preflight", "--expect-head", HEAD]) == 1
        assert "PREFLIGHT FAILED: memory too low" in capsys.readouterr().out

    def test_the_execute_command_hands_over_to_execute_once(self, monkeypatch):
        calls = []
        monkeypatch.setattr(H, "execute", lambda args: calls.append(args) or 0)
        monkeypatch.setattr(H.pipeline, "keep_awake", lambda: None)
        monkeypatch.setattr(H.pipeline, "release_awake", lambda: None)
        assert H.main(["--execute", "--expect-head", HEAD, "--confirm", H.confirmation_phrase(HEAD)]) == 0
        assert len(calls) == 1


def _forbidden(name):
    def fail(*args, **kwargs):
        raise AssertionError(f"{name} must not be reached on an unsupported host")
    return fail


class TestUnsupportedWindowsHost:
    """A Windows host is refused before anything is read, started or created: smoke._remove_tree never deletes
    there, so this harness could not verify its cleanup.  Every side-effecting entry is replaced by a function that
    fails the test; nothing is deleted and nothing is run."""

    @pytest.fixture
    def windows(self, monkeypatch):
        monkeypatch.setattr(smoke, "_windows", lambda: True)
        for owner, name in ((subprocess, "run"), (smoke, "run"), (tempfile, "mkdtemp"), (H.pipeline, "keep_awake"),
                            (H, "run_preflight"), (H, "execute"), (H, "record_attempt"), (H, "write_marker"),
                            (H, "write_evidence")):
            monkeypatch.setattr(owner, name, _forbidden(f"{owner.__name__}.{name}"))

    EXECUTE = ["--execute", "--expect-head", HEAD, "--confirm", H.confirmation_phrase(HEAD)]

    def test_t1_the_execute_command_is_refused_with_a_nonzero_exit_and_creates_nothing(self, windows, capsys, tmp_path):
        before = sorted(p.name for p in tmp_path.iterdir())
        assert H.main(self.EXECUTE) == 1
        out = capsys.readouterr().out
        assert "REFUSED: unsupported host" in out and "cannot verify its cleanup" in out
        assert sorted(p.name for p in tmp_path.iterdir()) == before and not H.attempts_dir().exists()

    def test_t2_the_preflight_command_is_refused_before_any_diagnostic(self, windows, capsys, tmp_path):
        before = sorted(p.name for p in tmp_path.iterdir())
        assert H.main(["--preflight", "--expect-head", HEAD]) == 1
        assert "REFUSED: unsupported host" in capsys.readouterr().out
        assert sorted(p.name for p in tmp_path.iterdir()) == before

    def test_t3_a_direct_execute_raises_before_the_preflight_callback_and_any_attempt_record(self, tmp_path):
        flow = Flow(tmp_path)
        with pytest.raises(SmokeFailure, match="unsupported host"):
            H.execute(args_for(), sh=flow.shell, preflight=_forbidden("preflight"), run_tests=flow.runner,
                      attempts_root=flow.attempts, windows=lambda: True)
        assert flow.shell.commands == [] and flow.runner.calls == [] and not flow.attempts.exists()

    def test_t3_the_refusal_precedes_the_confirmation_check(self, tmp_path):
        flow = Flow(tmp_path)
        with pytest.raises(SmokeFailure, match="unsupported host"):
            H.execute(args_for(confirm=False), sh=flow.shell, preflight=_forbidden("preflight"), run_tests=flow.runner,
                      attempts_root=flow.attempts, windows=lambda: True)
        assert flow.shell.commands == [] and not flow.attempts.exists()

    def test_t4_the_plan_mode_stays_available(self, windows, capsys):
        assert H.main([]) == 0
        assert "plan (nothing is created or started" in capsys.readouterr().out

    @pytest.mark.parametrize("argv", [
        ["--execute", "--expect-head", HEAD],
        ["--execute", "--expect-head", HEAD, "--confirm", "yes"],
        ["--preflight"],
        ["--preflight", "--expect-head", "main"],
    ])
    def test_t4_invalid_arguments_keep_exit_2(self, windows, argv):
        assert H.main(argv) == 2

    def test_t4_a_supported_host_is_not_refused_and_the_default_follows_the_shared_guard(self, monkeypatch):
        assert H.unsupported_host(lambda: False) is None
        assert "unsupported host" in H.unsupported_host(lambda: True)
        assert H.unsupported_host() is None                      # the isolated fixture: smoke._windows() is False
        monkeypatch.setattr(smoke, "_windows", lambda: True)     # looked up at call time, so it follows the guard
        assert "unsupported host" in H.unsupported_host()

    def test_t4_the_supported_host_commands_are_unchanged(self, monkeypatch, capsys):
        seen = []
        pre = H.Preflight(PROJECT, PORT, "development", {}, {}, S.Readings(), None)
        monkeypatch.setattr(H, "run_preflight", lambda *a, **k: seen.append("preflight") or pre)
        assert H.main(["--preflight", "--expect-head", HEAD]) == 0 and seen == ["preflight"]
        monkeypatch.setattr(H, "execute", lambda args: seen.append("execute") or 0)
        monkeypatch.setattr(H.pipeline, "keep_awake", lambda: None)
        monkeypatch.setattr(H.pipeline, "release_awake", lambda: None)
        assert H.main(self.EXECUTE) == 0 and seen == ["preflight", "execute"]

    def test_t5_main_refuses_before_keep_awake_the_preflight_and_execute(self):
        tree = ast.parse((_HERE / "run_viewer_sql_it.py").read_text(encoding="utf-8"))
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        lines = {}
        for call in (n for n in ast.walk(main) if isinstance(n, ast.Call)):
            lines.setdefault(ast.unparse(call.func), call.lineno)
        refusal = lines["unsupported_host"]
        for later in ("pipeline.keep_awake", "run_preflight", "execute"):
            assert refusal < lines[later], later

    def test_t5_execute_refuses_as_its_first_statement(self):
        tree = ast.parse((_HERE / "run_viewer_sql_it.py").read_text(encoding="utf-8"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
        body = [n for n in function.body if not (isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant))]
        assert isinstance(body[0], ast.Assign) and ast.unparse(body[0].value) == "unsupported_host(windows)"
        assert isinstance(body[1], ast.If) and isinstance(body[1].body[0], ast.Raise)
        assert [a.arg for a in function.args.kwonlyargs] == ["windows"]

    def test_t5_the_helper_is_pure_and_the_harness_gained_no_deletion(self):
        source = (_HERE / "run_viewer_sql_it.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "unsupported_host")
        names = {n.id for n in ast.walk(helper) if isinstance(n, ast.Name)} | {
            n.attr for n in ast.walk(helper) if isinstance(n, ast.Attribute)}
        assert not names & {"os", "subprocess", "shutil", "tempfile", "Path", "open", "run", "rmtree", "mkdir"}
        assert "rmtree" not in source and "_OWNED" not in source

    def test_t5_the_shared_windows_refusal_is_still_the_first_thing_remove_tree_does(self):
        tree = ast.parse((_HERE / "run_smoke.py").read_text(encoding="utf-8"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_remove_tree")
        body = [n for n in function.body if not (isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant))]
        first = body[0]
        assert isinstance(first, ast.If) and ast.unparse(first.test) == "_windows()"
        assert ast.unparse(first.body[-1]) == "return False"


class TestWorkspaceRegistration:
    """T12  The workspace is resolved, checked and registered with the shared ownership record before anything is written
    to it.  The real ownership guard is exercised only with its deletion sink (smoke._rmtree) replaced by a recorder that
    never deletes; nothing here deletes, starts Docker or runs a subprocess."""

    @pytest.fixture
    def registrar(self, monkeypatch):
        """Wraps the real smoke.register_workspace; records each path with the names inside it at that moment."""
        original, seen = smoke.register_workspace, []

        def spy(path):
            seen.append((Path(path), sorted(p.name for p in Path(path).iterdir())))
            return original(path)
        monkeypatch.setattr(smoke, "register_workspace", spy)
        return seen

    @pytest.fixture
    def real_guard(self, tmp_path, monkeypatch):
        """The real smoke._remove_tree on a simulated non-Windows host, with a recorder instead of the recursive delete."""
        deleted, state = [], {"gone": False}

        def record(path, **kwargs):
            resolved = Path(path).resolve()
            if tmp_path.resolve() not in resolved.parents:
                raise AssertionError(f"the guard handed {resolved}, which is outside this test's tmp_path, to the delete")
            deleted.append(resolved)
            state["gone"] = True                                  # reported as gone; nothing is removed from the disk
        monkeypatch.setattr(smoke, "_remove_tree", _REAL_REMOVE_TREE)
        monkeypatch.setattr(smoke, "_rmtree", record)
        monkeypatch.setattr(smoke, "_lexists", lambda path: not state["gone"])
        monkeypatch.setattr(smoke, "_pause", _forbidden("smoke._pause"))
        return deleted

    def test_a_the_resolved_workspace_is_registered_empty_and_recorded_with_its_identity(self, tmp_path, registrar):
        flow = Flow(tmp_path)
        assert flow.run() == 0
        ((registered, contents),) = registrar
        assert contents == [], "nothing may be written to the workspace before it is registered"
        assert registered == registered.resolve() and registered.name.startswith("viewer-it-")
        (handed,) = smoke._remove_tree.calls
        assert handed == registered
        info = os.lstat(registered)
        assert smoke._OWNED[smoke._norm(registered)] == (info.st_dev, info.st_ino)

    @pytest.mark.parametrize("error", [OSError("denied"), SmokeFailure("no verifiable identity")])
    def test_b_a_failed_registration_stops_before_any_write_docker_or_deletion(self, tmp_path, monkeypatch, error):
        def refuse(path):
            raise error
        monkeypatch.setattr(smoke, "register_workspace", refuse)
        flow = Flow(tmp_path)
        with pytest.raises(SmokeFailure, match="could not record ownership"):
            flow.run()
        (workspace,) = list(tmp_path.glob("viewer-it-*"))
        assert list(workspace.iterdir()) == []                          # left untouched, empty
        assert flow.verbs() == [] and flow.runner.calls == [] and smoke._remove_tree.calls == []
        assert H.own_markers(flow.markers) == [] and smoke._OWNED == {}
        assert (flow.attempts / f"attempt-{HEAD[:12]}.txt").is_file()    # the attempt was recorded before the workspace

    @pytest.mark.parametrize("where, expected", [
        ("repo", "protected location"), ("inside-repo", "protected location"), ("repo-ancestor", "protected location"),
        ("recovery", "protected location"), ("sandbox", "protected location"), ("onedrive", "protected location"),
        ("backups", "protected location"), ("temp-root", "temporary directory"), ("outside-temp", "temporary directory"),
        ("bad-name", "not named like"),
    ])
    def test_c_an_inappropriate_workspace_path_is_refused(self, tmp_path, monkeypatch, where, expected):
        temp_root = tmp_path / "tmp"
        temp_root.mkdir()
        repo = tmp_path / "repo"
        monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
        monkeypatch.setattr(smoke, "REPO", repo.resolve())
        monkeypatch.setattr(smoke, "_PROTECTED_TREES", (str(tmp_path / "recovery"),))
        monkeypatch.setattr(H, "WORKSPACE_PROTECTED", (str(tmp_path / "sandbox"),))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
        monkeypatch.setenv("OneDrive", str(tmp_path / "onedrive"))
        monkeypatch.delenv("OneDriveConsumer", raising=False)
        monkeypatch.delenv("OneDriveCommercial", raising=False)
        paths = {"repo": repo, "inside-repo": repo / "viewer-it-x", "repo-ancestor": tmp_path,
                 "recovery": tmp_path / "recovery" / "viewer-it-x", "sandbox": tmp_path / "sandbox" / "viewer-it-x",
                 "onedrive": tmp_path / "onedrive" / "viewer-it-x",
                 "backups": tmp_path / "local" / "agentops-backups" / "viewer-it-x", "temp-root": temp_root,
                 "outside-temp": tmp_path / "elsewhere" / "viewer-it-x", "bad-name": temp_root / "other-x"}
        problem = H.workspace_problem(paths[where])
        assert problem and expected in problem, problem
        assert H.workspace_problem(temp_root / "viewer-it-ok") is None          # the one acceptable shape

    def test_c_a_workspace_inside_the_repository_is_refused_before_registration_and_any_write(self, tmp_path, monkeypatch, registrar):
        fake_repo = tmp_path / "fake-repo"                                      # a stand-in: the real repository is never named
        fake_repo.mkdir()
        monkeypatch.setattr(smoke, "REPO", fake_repo.resolve())

        def inside(prefix):
            path = fake_repo / (prefix + "x")
            path.mkdir()
            return str(path)
        monkeypatch.setattr(tempfile, "mkdtemp", inside)
        flow = Flow(tmp_path)
        with pytest.raises(SmokeFailure, match="refusing to use"):
            flow.run()
        assert registrar == [] and smoke._OWNED == {} and list((fake_repo / "viewer-it-x").iterdir()) == []
        assert flow.verbs() == [] and flow.runner.calls == [] and smoke._remove_tree.calls == []

    def test_d_a_registered_workspace_is_accepted_by_the_real_ownership_guard(self, tmp_path, real_guard, capsys):
        flow = Flow(tmp_path)
        assert flow.run() == 0, capsys.readouterr().out
        (deleted,) = real_guard
        assert deleted.parent == tmp_path.resolve() and deleted.name.startswith("viewer-it-")
        assert smoke._OWNED == {} and H.own_markers(flow.markers) == []         # the guard cleared the record it accepted
        assert flow.records()["final"]["cleanup"]["verified"] is True

    def test_d_without_the_registration_the_real_guard_refuses_and_nothing_is_deleted(self, tmp_path, monkeypatch, real_guard, capsys):
        monkeypatch.setattr(smoke, "register_workspace", lambda path: None)     # reproduces the gap this patch closes
        flow = Flow(tmp_path)
        assert flow.run() == 1
        assert real_guard == [] and "not a workspace created by this run" in capsys.readouterr().out
        assert H.own_markers(flow.markers) == ["viewer-it:CLEANUP_UNVERIFIED"]
        assert flow.records()["final"]["verdict"] == "FAIL"

    def test_e_the_windows_refusal_still_precedes_the_workspace_and_its_registration(self, tmp_path, monkeypatch, registrar):
        monkeypatch.setattr(tempfile, "mkdtemp", _forbidden("tempfile.mkdtemp"))
        flow = Flow(tmp_path)
        with pytest.raises(SmokeFailure, match="unsupported host"):
            H.execute(args_for(), sh=flow.shell, preflight=_forbidden("preflight"), run_tests=flow.runner,
                      attempts_root=flow.attempts, windows=lambda: True)
        assert registrar == [] and smoke._OWNED == {} and flow.shell.commands == [] and not flow.attempts.exists()

    def test_e_execute_orders_refusal_confirmation_workspace_check_registration_and_first_write(self):
        tree = ast.parse((_HERE / "run_viewer_sql_it.py").read_text(encoding="utf-8"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
        lines = {}
        for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
            lines.setdefault(ast.unparse(call.func), call.lineno)
        order = ["unsupported_host", "check_confirmation", "tempfile.mkdtemp", "workspace_problem", "smoke.register_workspace",
                 "generate_credentials", "env_file.write_text"]
        assert [lines[name] for name in order] == sorted(lines[name] for name in order)
        creation = next(n for n in function.body if isinstance(n, ast.Assign) and "mkdtemp" in ast.unparse(n.value))
        assert ast.unparse(creation.value).endswith(".resolve()")


# ---------------------------------------------------------------------------
# T02  Names, ports, override, credentials
# ---------------------------------------------------------------------------

class TestNamesPortsOverride:
    def test_names_are_fresh_and_well_formed(self):
        a, b = H.new_project_name(), H.new_project_name()
        assert a != b and re.fullmatch(r"agentops-viewer-it-[0-9a-f]{8}", a)
        H.validate_project_name(a, ["abc1234 something-else running"])

    @pytest.mark.parametrize("bad", ["agentops", "agentops-workload-smoke", "agentops-mvp", "agentops-postgres",
                                     "agentops-pipeline-it-0a1b2c3d", "agentops-batching-it-0a1b2c3d",
                                     "agentops-shutdown-it-0a1b2c3d", "agentops-viewer-it-", "agentops-viewer-it-ZZZZZZZZ",
                                     "x" + PROJECT, PROJECT + "-2", PROJECT.upper()])
    def test_unacceptable_names_are_rejected(self, bad):
        with pytest.raises(SmokeFailure):
            H.validate_project_name(bad, [])

    def test_a_name_any_docker_object_carries_is_rejected(self):
        for line in (f"deadbeef {PROJECT}-postgres-1 running", f"{PROJECT}_agentops-net", f"{PROJECT}-postgres:latest abc"):
            with pytest.raises(SmokeFailure):
                H.validate_project_name(PROJECT, [line])

    def test_prohibited_ports_cover_the_normal_stack_the_viewer_grafana_and_the_sibling_harnesses(self):
        assert {5432, 9092, 4317, 4318, 8000, 3000, 14317, 15432, 19092} == set(H.PROHIBITED_PORTS)

    def test_a_port_is_random_free_in_range_and_never_prohibited(self):
        seen = [H.allocate_port(lambda p: False) for _ in range(200)]
        assert all(H.PORT_LOW <= p <= H.PORT_HIGH and p not in H.PROHIBITED_PORTS for p in seen)
        assert len(set(seen)) > 100

    def test_prohibited_in_use_and_unknown_ports_are_skipped(self):
        picks = iter([15432, 5432, 20001, 20002, 20003])
        probe = {20001: True, 20002: None, 20003: False}
        assert H.allocate_port(lambda p: probe[p], choose=lambda lo, hi: next(picks)) == 20003

    def test_no_free_port_is_a_failure(self):
        with pytest.raises(SmokeFailure, match="no free loopback port"):
            H.allocate_port(lambda p: True, attempts=10)
        with pytest.raises(SmokeFailure):
            H.allocate_port(lambda p: False, choose=lambda lo, hi: 15432, attempts=5)

    @pytest.mark.parametrize("port", [5432, 15432, 19092, 8000, 3000, 80, 19999, 30000, "23456", 23456.0, True, None])
    def test_unusable_ports_are_refused_by_the_override_and_the_environment(self, port):
        with pytest.raises(SmokeFailure):
            H.override_text(port)
        with pytest.raises(SmokeFailure):
            H.integration_environment(PROJECT, port, credentials())

    def test_the_override_moves_only_the_postgres_port_and_only_to_loopback(self):
        text = H.override_text(PORT)
        assert text.count("services:") == 1 and text.count("postgres:") == 1
        assert f'- "127.0.0.1:{PORT}:5432"' in text and "ports: !override" in text
        for forbidden in ("container_name", "volumes", "image:", "privileged", "network_mode", "0.0.0.0", "kafka", "environment"):
            assert forbidden not in text

    def test_credentials_are_random_complete_and_distinct(self):
        a, b = H.generate_credentials(), H.generate_credentials()
        assert set(a) == set(smoke.PASSWORD_VARIABLES) and len(set(a.values())) == len(a) and a != b
        assert all(len(v) >= 24 for v in a.values())
        text = H.env_file_text(a)
        assert all(f"{k}={v}\n" in text for k, v in a.items())

    def test_the_test_environment_carries_the_approval_and_the_passwords_only_there(self):
        creds = credentials()
        env = H.integration_environment(PROJECT, PORT, creds)
        assert env[H.ENV_APPROVAL] == f"disposable-loopback:{PROJECT}:{PORT}" and env[H.ENV_PROJECT] == PROJECT
        assert env[H.ENV_DSN] == f"postgresql://agentops:{creds['POSTGRES_PASSWORD']}@127.0.0.1:{PORT}/agentops"
        assert env[H.ENV_VIEWER_PASSWORD] == creds["TRACE_VIEWER_DB_PASSWORD"]
        assert not any(name.endswith("_PASSWORD") and name not in (H.ENV_VIEWER_PASSWORD,) for name in env)

    def test_the_default_evidence_and_marker_areas_are_outside_the_repository(self):
        for path in (H.default_evidence_dir(), H.marker_dir(), H.attempts_dir()):
            resolved = path.resolve()
            assert resolved != _REPO and _REPO not in resolved.parents
            assert resolved.parent == Path(tempfile.gettempdir()).resolve()          # directly in the temp area


# ---------------------------------------------------------------------------
# T03  Compose commands
# ---------------------------------------------------------------------------

class TestComposeCommands:
    override, env_file = Path("o.yml"), Path("e.env")

    def command(self, *args, project=PROJECT):
        return H.compose_command(project, self.override, self.env_file, *args)

    def test_a_command_names_the_project_three_files_and_the_env_file(self):
        command = self.command("ps", "-a", "-q", "postgres")
        assert command[:4] == ["docker", "compose", "-p", PROJECT]
        assert [command[i + 1] for i, c in enumerate(command) if c == "-f"] == [
            "docker-compose.yml", "workload-generator/compose.smoke.override.yml", "o.yml"]
        assert command[command.index("--env-file") + 1] == "e.env" and command[-4:] == ["ps", "-a", "-q", "postgres"]

    @pytest.mark.parametrize("project", ["agentops", "agentops-shutdown-it-0a1b2c3d", "agentops-mvp", "agentops-viewer-it-ZZZZZZZZ",
                                         "agentops-workload-smoke", ""])
    def test_another_project_is_refused(self, project):
        with pytest.raises(SmokeFailure):
            self.command("ps", project=project)

    @pytest.mark.parametrize("verb", ["run", "rm", "kill", "pause", "unpause", "stop", "restart", "start", "create", "pull",
                                      "cp", "config", "events", "top", "stats", "push", "scale", "watch", "wait"])
    def test_only_the_allowed_verbs_are_issued(self, verb):
        with pytest.raises(SmokeFailure):
            self.command(verb, "postgres")
        with pytest.raises(SmokeFailure):
            H.compose_command(PROJECT, self.override, self.env_file)

    @pytest.mark.parametrize("service", list(H.FORBIDDEN_SERVICES))
    def test_no_other_service_is_ever_named(self, service):
        for verb in ("build", "up", "ps", "logs", "exec"):
            with pytest.raises(SmokeFailure):
                self.command(verb, "postgres", service)

    def test_build_and_up_name_exactly_postgres_and_the_bootstrap(self):
        self.command("build", "postgres", "db-bootstrap")
        self.command("up", "-d", "--no-build", "postgres", "db-bootstrap")
        for args in (("build", "postgres"), ("up", "-d", "postgres"), ("up", "-d"), ("build",),
                     ("up", "-d", "postgres", "db-bootstrap", "postgres-extra")):
            with pytest.raises(SmokeFailure):
                self.command(*args)

    def test_down_is_exactly_volumes_and_orphans_with_no_rmi(self):
        assert self.command("down", "--volumes", "--remove-orphans")[-3:] == ["down", "--volumes", "--remove-orphans"]
        for args in (("down",), ("down", "--volumes"), ("down", "--volumes", "--rmi", "local", "--remove-orphans"),
                     ("down", "--volumes", "--remove-orphans", "-t", "0"), ("down", "--rmi", "all")):
            with pytest.raises(SmokeFailure):
                self.command(*args)

    def test_no_command_carries_a_credential(self):
        creds = credentials()
        stack = H.Stack(PROJECT, self.override, self.env_file, RecordingShell())
        stack.sh.router = lambda c: Result(stdout="a" * 64 if "ps" in c else "x|y|0")
        for call in (lambda: stack.compose("ps", "-a", "-q", "postgres"), stack.ledger):
            try:
                call()
            except SmokeFailure:
                pass
        text = json.dumps(stack.sh.commands)
        assert not any(value in text for value in creds.values())


# ---------------------------------------------------------------------------
# T04  Gates and preflight
# ---------------------------------------------------------------------------

INVENTORY = {"containers": ["id1 agentops-postgres exited", "id2 agentops-mvp-viewer-1 running"],
             "volumes": ["agentops-mvp-postgres-data"], "networks": ["n1 bridge", "u1 agentops-mvp_mvp-net", "u2 agentops_agentops-net"],
             "images": ["postgres:17.11 i1"]}
SNAPSHOT = {"agentops-mvp-postgres-1": "i running s f 0", "agentops-mvp-viewer-1": "i running s f 0",
            "agentops-mvp-db-bootstrap-1": None, "agentops-postgres": "i exited s f 0"}
BRIDGE_OPTIONS = {"com.docker.network.bridge.default_bridge": "true", "com.docker.network.bridge.name": "docker0"}
USER_NETWORK_IDS = {"agentops-mvp_mvp-net": "u1", "agentops_agentops-net": "u2"}
USER_NETWORK_LABELS = {"com.docker.compose.project": "agentops"}


def net_json(id_, name, *, labels=None, options=None):
    return json.dumps([{"Id": id_, "Name": name, "Driver": "bridge", "Scope": "local", "Internal": False,
                        "Created": "2026-01-01T00:00:00Z", "Labels": labels or {}, "Options": options or {}, "Containers": {}}])


def good_readings(**changes):
    values = dict(power_source="AC", battery_percent=100, available_mib=6000.0, engine_bytes=4 * 1024 ** 3,
                  free_disk_bytes=50 * 1024 ** 3, ports_in_use={PORT: False})
    values.update(changes)
    return S.Readings(**values)


class TestGates:
    def test_good_readings_pass(self):
        assert H.host_gate_problems(good_readings(), PORT) == []

    @pytest.mark.parametrize("changes, needle", [
        ({"power_source": "battery"}, "not AC power"),
        ({"power_source": None}, "power source could not be read"),
        ({"available_mib": 4095.0}, "below 4096 MiB"),
        ({"available_mib": None}, "memory could not be read"),
        ({"available_mib": float("nan")}, "memory could not be read"),
        ({"free_disk_bytes": 9 * 1024 ** 3}, "below 10 GiB"),
        ({"free_disk_bytes": None}, "free disk space could not be read"),
        ({"ports_in_use": {PORT: True}}, f"port {PORT} is in use"),
        ({"ports_in_use": {PORT: None}}, f"port {PORT} could not be checked"),
        ({"ports_in_use": {}}, "could not be checked"),
    ])
    def test_every_unmet_or_unmeasurable_gate_fails_closed(self, changes, needle):
        assert any(needle in problem for problem in H.host_gate_problems(good_readings(**changes), PORT))

    def test_boundaries_and_thresholds(self):
        assert H.host_gate_problems(good_readings(available_mib=4096), PORT) == []
        assert H.host_gate_problems(good_readings(free_disk_bytes=10 * 1024 ** 3), PORT) == []
        assert H.MIN_HOST_MEMORY_MIB == 4096 == S.MIN_HOST_MEMORY_MIB


class FakeEngine:
    """Answers the reads of a preflight: info, the inventory, the protected containers and the networks."""

    def __init__(self, *, engine=4 * 1024 ** 3, inventory=None, snapshot=None, bridge_id="n1", two_bridges=False,
                 user_missing=None, status=OWN_STATUS, branch=BRANCH, head=HEAD):
        self.commands, self.engine, self.inventory = [], engine, inventory or INVENTORY
        self.snapshot, self.bridge_id, self.two_bridges, self.user_missing = snapshot or SNAPSHOT, bridge_id, two_bridges, user_missing
        self.git = git_router(branch=branch, head=head, status=status)

    def __call__(self, command):
        self.commands.append(list(command))
        if command[:1] == ["git"]:
            return self.git(command)
        if command[:2] == ["docker", "info"]:
            return Result(stdout=json.dumps({"MemTotal": self.engine}))
        if command[:3] == ["docker", "network", "ls"]:
            lines = [line for line in self.inventory["networks"] if not line.endswith(" bridge")]
            lines += [f"{self.bridge_id} bridge"] + (["n9 bridge"] if self.two_bridges else [])
            return Result(stdout="\n".join(lines))
        if command[:3] == ["docker", "network", "inspect"]:
            ref = command[3]
            if ref == self.bridge_id:
                return Result(stdout=net_json(ref, "bridge", options=BRIDGE_OPTIONS))
            if ref in USER_NETWORK_IDS and ref != self.user_missing:
                return Result(stdout=net_json(USER_NETWORK_IDS[ref], ref, labels=USER_NETWORK_LABELS))
            return Result(returncode=1, stderr="Error response from daemon: network not found")
        if command[:2] == ["docker", "inspect"]:
            value = self.snapshot.get(command[-1])
            return Result(stdout=value) if value else Result(returncode=1)
        if command[:2] == ["docker", "ps"]:
            return Result(stdout="\n".join(self.inventory["containers"]))
        if command[:3] == ["docker", "volume", "ls"]:
            return Result(stdout="\n".join(self.inventory["volumes"]))
        if command[:2] == ["docker", "images"]:
            return Result(stdout="\n".join(self.inventory["images"]))
        return Result()


def preflight(engine=None, **overrides):
    engine = engine or FakeEngine()
    shell = RecordingShell(engine)
    options = dict(docker_data_dir=_HERE, power=lambda: ("AC", 100), memory=lambda: 8000.0,
                   disk=lambda p: 60 * 1024 ** 3, port_probe=lambda p: False, markers=lambda: [],
                   processes=lambda: [], own=lambda: [], name=PROJECT, port=PORT)
    options.update(overrides)
    return shell, lambda: H.run_preflight(shell, _REPO, HEAD, **options)


def docker_subcommands(shell):
    return [c for c in shell.commands if c[:1] == ["docker"]]


class TestPreflight:
    def test_success_returns_the_project_port_and_the_before_state(self):
        shell, call = preflight()
        pre = call()
        assert pre.project == PROJECT and pre.port == PORT and pre.git_state == "development" and pre.before == INVENTORY
        assert pre.networks.bridge_verified and set(pre.networks.users) == set(USER_NETWORK_IDS)
        assert all(c[1] in ("info", "ps", "images", "inspect", "network", "volume") for c in docker_subcommands(shell))
        assert all(c[2] in ("ls", "inspect") for c in docker_subcommands(shell) if c[1] in ("network", "volume"))

    def test_a_random_port_is_chosen_when_none_is_given(self):
        _, call = preflight(port=None)
        assert H.PORT_LOW <= call().port <= H.PORT_HIGH

    @pytest.mark.parametrize("case", ["git", "power", "memory", "disk", "port", "benchmark", "own-marker", "process"])
    def test_no_docker_command_is_issued_when_a_non_docker_check_fails(self, case):
        engine = FakeEngine(branch="main") if case == "git" else FakeEngine()
        overrides = {"git": {}, "power": {"power": lambda: ("battery", 50)}, "memory": {"memory": lambda: 1000.0},
                     "disk": {"disk": lambda p: 1}, "port": {"port_probe": lambda p: True},
                     "benchmark": {"markers": lambda: ["ACTIVE_RUN"]}, "own-marker": {"own": lambda: ["viewer-it:CLEANUP_UNVERIFIED"]},
                     "process": {"processes": lambda: ["99"]}}[case]
        shell, call = preflight(engine, **overrides)
        with pytest.raises(SmokeFailure):
            call()
        assert docker_subcommands(shell) == [], "Docker must not be touched before the host gates pass"

    def test_unmeasurable_readings_fail_closed_without_docker(self):
        def boom():
            raise OSError("cannot read")
        for override in ({"power": boom}, {"memory": boom}, {"disk": lambda p: (_ for _ in ()).throw(OSError("x"))}):
            shell, call = preflight(**override)
            with pytest.raises(SmokeFailure):
                call()
            assert docker_subcommands(shell) == []

    def test_a_missing_docker_data_directory_fails_closed(self, tmp_path):
        shell, call = preflight(docker_data_dir=tmp_path / "absent")
        with pytest.raises(SmokeFailure, match="free disk space could not be read"):
            call()
        assert docker_subcommands(shell) == []

    @pytest.mark.parametrize("kwargs, needle", [
        ({"branch": "main"}, "the branch is"), ({"head": "b" * 40}, "HEAD is"),
        ({"status": OWN_STATUS + "\n M trace-viewer/app.py"}, "neither clean"),
        ({"status": f"?? {H.OWN_FILES[0]}"}, "neither clean"),
    ])
    def test_the_git_state_must_be_exact(self, kwargs, needle):
        shell, call = preflight(FakeEngine(**kwargs))
        with pytest.raises(SmokeFailure, match=needle):
            call()
        assert docker_subcommands(shell) == []

    def test_a_clean_committed_tree_is_accepted(self):
        _, call = preflight(FakeEngine(status=""))
        assert call().git_state == "committed"

    def test_engine_memory_failure_issues_only_the_info_read(self):
        shell, call = preflight(FakeEngine(engine=2 * 1024 ** 3))
        with pytest.raises(SmokeFailure, match="Docker engine memory"):
            call()
        assert [c[:2] for c in docker_subcommands(shell)] == [["docker", "info"]]

    @pytest.mark.parametrize("line, needle", [
        ("i agentops-workload-smoke-kafka-1 running", "benchmark Docker object"),
        ("i agentops-pipeline-it-aaaaaaaa-x running", "pipeline test Docker object"),
        ("i agentops-batching-it-aaaaaaaa-x running", "batching validation Docker object"),
        ("i agentops-shutdown-it-aaaaaaaa-x running", "shutdown validation Docker object"),
        (f"i agentops-viewer-it-aaaaaaaa-postgres-1 exited", "earlier viewer validation Docker object"),
    ])
    def test_docker_objects_of_every_sibling_harness_block_the_run(self, line, needle):
        shell, call = preflight(FakeEngine(inventory={**INVENTORY, "containers": [line]}))
        with pytest.raises(SmokeFailure, match=needle):
            call()

    def test_a_project_name_any_object_carries_is_rejected(self):
        _, call = preflight(FakeEngine(inventory={**INVENTORY, "volumes": [f"{PROJECT}_postgres-data"]}))
        with pytest.raises(SmokeFailure, match="earlier viewer validation|already exist"):
            call()

    def test_a_running_legacy_database_stops_the_run(self):
        _, call = preflight(FakeEngine(snapshot={**SNAPSHOT, "agentops-postgres": "i running s f 0"}))
        with pytest.raises(SmokeFailure, match="not exited"):
            call()

    @pytest.mark.parametrize("kwargs, needle", [({"two_bridges": True}, "default bridge is not verified"),
                                                ({"user_missing": "agentops_agentops-net"}, "protected network agentops_agentops-net was not found")])
    def test_the_network_state_must_be_verified_before_anything_changes(self, kwargs, needle):
        _, call = preflight(FakeEngine(**kwargs))
        with pytest.raises(SmokeFailure, match=needle):
            call()

    def test_the_real_marker_readers_block_on_either_harness_marker(self, tmp_path):
        assert H.own_markers(tmp_path / "v") == [] and S.own_markers() == []
        H.write_marker("a volume remained", tmp_path / "v")
        assert H.own_markers(tmp_path / "v")[0] == "viewer-it:CLEANUP_UNVERIFIED"
        S.write_marker("shutdown leftovers")                       # the shutdown harness's own marker (in the isolated temp area)
        assert "shutdown-it:CLEANUP_UNVERIFIED" in H.own_markers(tmp_path / "none")
        blockers = H.find_blockers(benchmark_markers=[], own_markers_found=H.own_markers(tmp_path / "v"), docker_lines=[], processes=[])
        assert len(blockers) == 2 and all("unverified cleanup marker" in b for b in blockers)

    def test_the_candidate_name_never_collides_with_a_protected_token(self):
        for _ in range(20):
            H.validate_project_name(H.new_project_name(), [])


# ---------------------------------------------------------------------------
# T05  The single-attempt rule
# ---------------------------------------------------------------------------

class TestSingleAttempt:
    def test_a_head_is_attempted_once(self, tmp_path):
        first = H.record_attempt(HEAD, PROJECT, tmp_path / "a")
        assert first.is_file() and first.name == f"attempt-{HEAD[:12]}.txt"
        with pytest.raises(SmokeFailure, match="already made"):
            H.record_attempt(HEAD, "agentops-viewer-it-bbbbbbbb", tmp_path / "a")
        H.record_attempt("b" * 40, PROJECT, tmp_path / "a")                 # another commit is another authorization

    def test_the_record_is_written_exclusively_and_never_overwritten(self, tmp_path):
        path = H.record_attempt(HEAD, PROJECT, tmp_path / "a", "stamp")
        content = path.read_text(encoding="utf-8")
        with pytest.raises(SmokeFailure):
            H.record_attempt(HEAD, "other", tmp_path / "a")
        assert path.read_text(encoding="utf-8") == content


# ---------------------------------------------------------------------------
# T06  The test report and the verdict
# ---------------------------------------------------------------------------

def junit_text(outcomes=None, extra=()):
    outcomes = dict(outcomes) if outcomes is not None else {name: "passed" for name in H.ALL_EXPECTED_TESTS}
    cases = []
    for name, outcome in [*outcomes.items(), *extra]:
        inner = {"passed": "", "failed": '<failure message="assert 1 == 2">trace</failure>',
                 "error": '<error message="fixture failed">trace</error>',
                 "skipped": '<skipped type="pytest.skip" message="not approved"/>'}[outcome]
        cases.append(f'<testcase classname="tests.integration.test_viewer_sql_live" name="{name}" time="0.5">{inner}</testcase>')
    return f'<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="{len(cases)}">{"".join(cases)}</testsuite></testsuites>'


class TestReportAndVerdict:
    def test_every_case_is_read_with_its_outcome_and_parameters_stripped(self):
        text = junit_text({"test_sql_a[x]": "passed", "test_sql_a[y]": "failed", "test_query_b": "skipped", "test_endpoint_c": "error"})
        outcomes = H.parse_junit(text)
        assert [(o.base, o.outcome) for o in outcomes] == [("test_sql_a", "passed"), ("test_sql_a", "failed"),
                                                           ("test_query_b", "skipped"), ("test_endpoint_c", "error")]
        assert outcomes[1].detail.startswith("assert 1 == 2") and outcomes[0].name == "test_sql_a[x]"

    @pytest.mark.parametrize("text", ["", "not xml", "<testsuites"])
    def test_an_unreadable_report_is_a_failure_to_read(self, text):
        with pytest.raises(SmokeFailure):
            H.parse_junit(text)

    def verdict(self, outcomes=None, extra=(), **run):
        values = dict(returncode=0, stdout="", stderr="", timed_out=False)
        values.update(run)
        return H.evaluate_tests(H.parse_junit(junit_text(outcomes, extra)), H.TestRun(**values))

    def test_all_expected_tests_passing_is_a_pass(self):
        result = self.verdict()
        assert result.verdict == "PASS" and result.problems == [] and len(result.tests) == len(H.ALL_EXPECTED_TESTS)
        assert {t["level"] for t in result.tests} == {"sql", "query", "endpoint", "connection"}

    @pytest.mark.parametrize("bad", ["failed", "error"])
    def test_one_failure_is_a_fail(self, bad):
        outcomes = {name: "passed" for name in H.ALL_EXPECTED_TESTS}
        outcomes[H.ALL_EXPECTED_TESTS[3]] = bad
        result = self.verdict(outcomes)
        assert result.verdict == "FAIL" and H.ALL_EXPECTED_TESTS[3] in result.problems[0]

    def test_a_skipped_test_is_inconclusive_not_a_pass(self):
        outcomes = {name: "passed" for name in H.ALL_EXPECTED_TESTS}
        outcomes[H.ALL_EXPECTED_TESTS[0]] = "skipped"
        result = self.verdict(outcomes)
        assert result.verdict == "INCONCLUSIVE" and "skipped" in result.problems[0]

    def test_a_missing_or_an_unexpected_test_is_inconclusive(self):
        outcomes = {name: "passed" for name in H.ALL_EXPECTED_TESTS[1:]}
        assert self.verdict(outcomes).verdict == "INCONCLUSIVE"
        assert self.verdict(extra=[("test_sql_new_unlisted", "passed")]).verdict == "INCONCLUSIVE"

    def test_a_timeout_or_an_empty_report_is_inconclusive(self):
        assert H.evaluate_tests(H.parse_junit(junit_text()), H.TestRun(None, "", "", True)).verdict == "INCONCLUSIVE"
        assert H.evaluate_tests([], H.TestRun(0, "", "")).verdict == "INCONCLUSIVE"

    def test_a_non_zero_pytest_exit_is_never_a_pass(self):
        assert self.verdict(returncode=1).verdict == "FAIL"
        assert self.verdict(returncode=5).verdict == "FAIL"

    def test_a_failure_wins_over_a_skip_and_a_missing_test(self):
        outcomes = {name: "passed" for name in H.ALL_EXPECTED_TESTS[2:]}
        outcomes[H.ALL_EXPECTED_TESTS[2]] = "failed"
        outcomes["extra_skipped"] = "skipped"
        assert self.verdict(outcomes).verdict == "FAIL"

    def test_the_final_verdict_never_turns_anything_into_a_pass(self):
        ok = H.TestsVerdict("PASS", [], [])
        assert H.final_verdict(ok, cleanup_verified=True, failure="", evidence_problems=[]) == "PASS"
        assert H.final_verdict(ok, cleanup_verified=False, failure="", evidence_problems=[]) == "FAIL"
        assert H.final_verdict(ok, cleanup_verified=True, failure="boom", evidence_problems=[]) == "FAIL"
        assert H.final_verdict(ok, cleanup_verified=True, failure="", evidence_problems=["x"]) == "FAIL"
        assert H.final_verdict(None, cleanup_verified=True, failure="", evidence_problems=[]) == "INCONCLUSIVE"
        for verdict in ("FAIL", "INCONCLUSIVE"):
            assert H.final_verdict(H.TestsVerdict(verdict, [], []), cleanup_verified=True, failure="", evidence_problems=[]) == verdict

    def test_the_pytest_command_runs_only_the_integration_directory_without_a_cache(self, tmp_path):
        command = H.pytest_command(tmp_path / "j.xml")
        assert command[1:4] == ["-m", "pytest", "trace-viewer/tests/integration"] and "no:cacheprovider" in command
        assert command[command.index("--junitxml") + 1] == str(tmp_path / "j.xml")

    def test_the_port_binding_must_be_exactly_loopback_and_the_chosen_port(self):
        good = json.dumps({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}]})
        assert H.verify_port_binding(good, PORT) == []
        for bad in (json.dumps({"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": str(PORT)}]}),
                    json.dumps({"5432/tcp": [{"HostIp": "", "HostPort": str(PORT)}]}),
                    json.dumps({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15432"}]}),
                    json.dumps({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}, {"HostIp": "127.0.0.1", "HostPort": "1"}]}),
                    json.dumps({"5432/tcp": [], }), json.dumps({}), json.dumps({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}], "9092/tcp": []}),
                    json.dumps(None), "not json"):
            assert H.verify_port_binding(bad, PORT), bad


# ---------------------------------------------------------------------------
# T07  Cleanup
# ---------------------------------------------------------------------------

class TestCleanupOwnership:
    def test_cleanup_refuses_other_projects(self):
        for bad in ("agentops", "agentops-shutdown-it-0a1b2c3d", "agentops-mvp", ""):
            with pytest.raises(SmokeFailure):
                H.ViewerOps(bad, None, None, RecordingShell(), None)

    def test_only_images_named_after_the_project_can_be_removed(self):
        ops = H.ViewerOps(PROJECT, None, None, RecordingShell(), None)
        for reference in ("postgres:17.11", "python:3.11-slim-bookworm", "agentops-viewer-it-bbbbbbbb-postgres:latest",
                          "agentops-postgres:latest", "agentops-shutdown-it-0a1b2c3d-postgres:latest", "abc123"):
            with pytest.raises(SmokeFailure, match="not named after the project"):
                ops.remove_image(reference)
        assert ops.sh.commands == []
        assert ops.remove_image(f"{PROJECT}-postgres:latest") is True
        assert ops.sh.commands == [["docker", "image", "remove", f"{PROJECT}-postgres:latest"]]

    def test_owned_images_need_the_name_and_the_label(self):
        shell = RecordingShell(lambda c: Result(stdout=f"{PROJECT}-postgres:latest\npostgres:17.11\n<none>:<none>\n"
                                                        f"{PROJECT}-<none>:x\n"))
        assert H.ViewerOps(PROJECT, None, None, shell, None).owned_images() == [f"{PROJECT}-postgres:latest"]
        assert f"label=com.docker.compose.project={PROJECT}" in shell.commands[0]

    def test_remove_temp_refuses_the_repository_and_anything_outside_the_temp_area(self, tmp_path, monkeypatch):
        # Everything here is synthetic and under tmp_path: a stand-in repository, a stand-in temp area and a
        # stand-in "elsewhere".  The real repository, the recovery backups and the system directories are never
        # named, and the deletion sink is a recorder, so nothing can be deleted whatever the guard does.
        fake_repo = tmp_path / "fake-repo"
        temp_root = tmp_path / "fake-temp-root"
        elsewhere = tmp_path / "elsewhere"
        for folder in (fake_repo / "workload-generator", temp_root / "viewer-it-x", elsewhere):
            folder.mkdir(parents=True)
        deleted = []
        monkeypatch.setattr(smoke, "REPO", fake_repo.resolve())
        monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
        monkeypatch.setattr(smoke, "_remove_tree", lambda path: deleted.append(Path(path)) or True)
        for path in (fake_repo, fake_repo / "workload-generator", elsewhere, temp_root, tmp_path):
            ops = H.ViewerOps(PROJECT, None, None, RecordingShell(), path)
            with pytest.raises(SmokeFailure, match="not a temporary directory"):
                ops.remove_temp()
        assert deleted == []                                               # the sink was never reached
        allowed = temp_root / "viewer-it-x"
        assert H.ViewerOps(PROJECT, None, None, RecordingShell(), allowed).remove_temp() is True
        assert deleted == [allowed.resolve()]                              # the recorder is wired in, and only this path reached it

    def test_a_leaked_credential_in_a_temp_file_is_counted_but_the_env_file_is_exempt(self, tmp_path):
        smoke.RUN.generated, smoke.RUN.masked_in_logs = {"X": "s3cr3t-value"}, 0
        (tmp_path / H.ENV_FILE_NAME).write_text("X=s3cr3t-value\n", encoding="utf-8")
        ops = H.ViewerOps(PROJECT, None, None, RecordingShell(), tmp_path)
        assert ops.leaked() == 0
        (tmp_path / "junit.xml").write_text("oops s3cr3t-value s3cr3t-value", encoding="utf-8")
        assert ops.leaked() == 2

    def test_down_is_the_exact_project_scoped_command(self, tmp_path):
        env = tmp_path / "e.env"
        env.write_text("A=b\n", encoding="utf-8")
        shell = RecordingShell(lambda c: Result(returncode=0, stderr="done"))
        ops = H.ViewerOps(PROJECT, tmp_path / "o.yml", env, shell, None)
        assert ops.can_down() and ops.down() == (0, "done")
        assert ops.down_command[-3:] == ["down", "--volumes", "--remove-orphans"] and "--rmi" not in ops.down_command
        assert not H.ViewerOps(PROJECT, None, None, shell, None).can_down()

    def test_an_exception_in_cleanup_is_a_problem_not_a_silent_success(self):
        class Broken(H.ViewerOps):
            def can_down(self):
                raise RuntimeError("engine gone")
        result = H.cleanup_detailed(Broken(PROJECT, None, None, RecordingShell(), None), dict(INVENTORY))
        assert not result.verified and "RuntimeError: engine gone" in result.problems[0]

    def test_the_blocking_marker_is_written_and_blocks_the_next_start(self, tmp_path):
        assert H.own_markers(tmp_path) == []
        path = H.write_marker("a volume remained", tmp_path)
        assert path.read_text(encoding="utf-8").startswith("a volume remained") and H.own_markers(tmp_path)[0].endswith("CLEANUP_UNVERIFIED")

    def test_evidence_may_not_live_in_the_repository_the_benchmark_area_or_a_marker_directory(self, tmp_path):
        assert H.evidence_dir_problem(_REPO / "evidence")
        assert H.evidence_dir_problem(_REPO)
        assert H.evidence_dir_problem(tmp_path / "agentops-benchmarks" / "x")
        assert H.evidence_dir_problem(H.marker_dir() / "evidence")
        assert H.evidence_dir_problem(H.attempts_dir() / "evidence")
        assert H.evidence_dir_problem(S.marker_path().parent / "evidence")
        assert H.evidence_dir_problem(tmp_path / "evidence") is None
        assert not (_REPO / "evidence").exists()


# ---------------------------------------------------------------------------
# T08  The whole flow
# ---------------------------------------------------------------------------

CIDS = {"postgres": "a" * 64, "db-bootstrap": "b" * 64}
LEDGER_OK = f"{smoke.LEDGER_STEPS}|" + ",".join(smoke.LEDGER_PLAN)
BINDING_OK = json.dumps({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}]})
PROJECT_IMAGES = [f"{PROJECT}-postgres:latest", f"{PROJECT}-db-bootstrap:latest"]


class FakeDocker:
    """A scripted engine for execute(): build, start, inspect, exec, logs, down, image removal and every read."""

    def __init__(self, *, bootstrap_exit=0, ledger=LEDGER_OK, binding=BINDING_OK, down_code=0, leftover=False,
                 protected_after=None, recreate_bridge=False, repo_status_after=None, pg_health="healthy", fail_build=False):
        self.commands, self.bootstrap_exit, self.ledger, self.binding = [], bootstrap_exit, ledger, binding
        self.down_code, self.leftover, self.protected_after = down_code, leftover, protected_after or {}
        self.recreate_bridge, self.repo_status_after, self.pg_health, self.fail_build = recreate_bridge, repo_status_after, pg_health, fail_build
        self.built = self.up = self.downed = False
        self.removed: set[str] = set()
        self.bridge_id = "n1"

    def present(self):
        return self.up and (not self.downed or self.leftover)

    def project_lines(self, kind):
        if not self.present():
            return []
        return {"containers": [f"c1 {PROJECT}-postgres-1 running", f"c2 {PROJECT}-db-bootstrap-1 exited"],
                "volumes": [f"{PROJECT}_postgres-data"], "networks": [f"pn1 {PROJECT}_agentops-net"]}.get(kind, [])

    def images(self):
        return [ref for ref in PROJECT_IMAGES if self.built and ref not in self.removed]

    def __call__(self, command):
        self.commands.append(list(command))
        if command[:2] == ["git", "-C"]:
            args = command[3:]
            if args[:1] == ["status"]:
                return Result(stdout=self.repo_status_after if self.downed and self.repo_status_after is not None else OWN_STATUS)
            return git_router()(command)
        label = f"label=com.docker.compose.project={PROJECT}"
        if command[:3] == ["docker", "network", "ls"] and label not in command:
            lines = [f"{self.bridge_id} bridge", "u1 agentops-mvp_mvp-net", "u2 agentops_agentops-net", *self.project_lines("networks")]
            return Result(stdout="\n".join(lines))
        if command[:3] == ["docker", "network", "inspect"]:
            ref = command[3]
            if ref == self.bridge_id:
                return Result(stdout=net_json(ref, "bridge", options=BRIDGE_OPTIONS))
            if ref in USER_NETWORK_IDS:
                return Result(stdout=net_json(USER_NETWORK_IDS[ref], ref, labels=USER_NETWORK_LABELS))
            return Result(returncode=1, stderr="network not found")
        if "compose" in command:
            verb = command[command.index("--env-file") + 2]
            if verb == "build":
                if self.fail_build:
                    return Result(returncode=1, stderr="build failed")
                self.built = True
            if verb == "up":
                self.up = True
            if verb == "down":
                self.downed = True
                if self.recreate_bridge:
                    self.bridge_id = "n2"
                return Result(returncode=self.down_code)
            if verb == "ps":
                return Result(stdout=CIDS[command[-1]] + "\n")
            if verb == "exec":
                return Result(stdout=self.ledger + "\n")
            if verb == "logs":
                return Result(stdout="bootstrap log line\n")
            return Result()
        if command[:2] == ["docker", "inspect"]:
            ref = command[-1]
            if ref in SNAPSHOT:
                value = self.protected_after.get(ref, SNAPSHOT[ref]) if self.downed else SNAPSHOT[ref]
                return Result(stdout=value) if value else Result(returncode=1)
            if ref in CIDS.values():
                if "PortBindings" in command[3]:
                    return Result(stdout=self.binding + "\n")
                if ref == CIDS["postgres"]:
                    return Result(stdout=f"running|{self.pg_health}|0\n")
                return Result(stdout=f"exited||{self.bootstrap_exit}\n")
            return Result(returncode=1)
        if command[:3] == ["docker", "image", "remove"]:
            self.removed.add(command[3])
            return Result()
        if command[:2] == ["docker", "images"]:
            if label in command:
                return Result(stdout="abc\n" if "-q" in command and self.images() else "\n".join(self.images()) if "-q" not in command else "")
            return Result(stdout="\n".join([*INVENTORY["images"], *(f"{ref} img-{ref}" for ref in self.images())]))
        if command[:2] == ["docker", "ps"]:
            if label in command:
                return Result(stdout="c1\nc2\n" if self.project_lines("containers") else "")
            return Result(stdout="\n".join([*INVENTORY["containers"], *self.project_lines("containers")]))
        if command[:3] == ["docker", "volume", "ls"]:
            if label in command:
                return Result(stdout=f"{PROJECT}_postgres-data\n" if self.project_lines("volumes") else "")
            return Result(stdout="\n".join([*INVENTORY["volumes"], *self.project_lines("volumes")]))
        if command[:3] == ["docker", "network", "ls"] and label in command:
            return Result(stdout="pn1\n" if self.project_lines("networks") else "")
        return Result()


class FakeRunner:
    def __init__(self, outcomes=None, *, returncode=0, timed_out=False, write_junit=True, raises=None, extra=()):
        self.outcomes, self.returncode, self.timed_out, self.write_junit, self.raises, self.extra = outcomes, returncode, timed_out, write_junit, raises, extra
        self.calls = []

    def __call__(self, command, env, timeout, cwd):
        self.calls.append((list(command), dict(env), timeout, cwd))
        if self.raises is not None:
            raise self.raises
        if self.write_junit:
            Path(command[command.index("--junitxml") + 1]).write_text(junit_text(self.outcomes, self.extra), encoding="utf-8")
        return H.TestRun(self.returncode, "20 passed in 30s\n", "", self.timed_out)


def args_for(head=HEAD, confirm=True):
    return argparse.Namespace(expect_head=head, confirm=H.confirmation_phrase(head) if confirm else "no", preflight=False,
                              execute=True, docker_data_dir=_HERE)


class Flow:
    """One execute() with every dependency scripted; the folders it writes are under the isolated temp area."""

    def __init__(self, tmp_path, docker=None, runner=None, head=HEAD, evidence_dir=None):
        self.docker, self.runner = docker or FakeDocker(), runner or FakeRunner()
        self.shell = RecordingShell(self.docker)
        self.tmp, self.head = tmp_path, head
        self.evidence = evidence_dir or tmp_path / "evidence"
        self.markers, self.attempts = tmp_path / "markers", tmp_path / "attempts"

    def preflight(self, sh, repo, expect_head, **kwargs):
        return H.Preflight(PROJECT, PORT, "development", {k: list(v) for k, v in INVENTORY.items()}, dict(SNAPSHOT),
                           good_readings(), S.read_network_snapshot(sh))

    def run(self):
        clock = iter(range(0, 100000))
        return H.execute(args_for(self.head), sh=self.shell, preflight=self.preflight, run_tests=self.runner,
                         sleeper=lambda s: None, clock=lambda: float(next(clock)), evidence_dir=self.evidence,
                         attempts_root=self.attempts, marker_root=self.markers)

    def evidence_files(self):
        return sorted(self.evidence.glob("*.json")) if self.evidence.exists() else []

    def records(self):
        return {json.loads(p.read_text(encoding="utf-8"))["kind"]: json.loads(p.read_text(encoding="utf-8")) for p in self.evidence_files()}

    def verbs(self):
        return [c[c.index("--env-file") + 2] for c in self.docker.commands if "compose" in c]


ALLOWED_DOCKER = {"info", "ps", "images", "inspect", "network", "volume", "image", "compose"}


class TestWholeFlow:
    def test_a_good_run_passes_cleans_up_and_writes_two_evidence_files(self, tmp_path, capsys):
        flow = Flow(tmp_path)
        assert flow.run() == 0
        out = capsys.readouterr().out
        assert "overall: PASS" in out and "cleanup verified: yes" in out and "evidence written: yes" in out
        verbs = flow.verbs()
        assert verbs.index("build") < verbs.index("up") < verbs.index("exec") < verbs.index("down")
        assert set(verbs) <= {"build", "up", "ps", "exec", "logs", "down"}
        assert H.own_markers(flow.markers) == [] and (flow.attempts / f"attempt-{HEAD[:12]}.txt").is_file()

    def test_only_postgres_and_the_bootstrap_are_ever_named_and_nothing_destructive_is_issued(self, tmp_path):
        flow = Flow(tmp_path)
        flow.run()
        text = json.dumps(flow.docker.commands)
        for service in H.FORBIDDEN_SERVICES:
            assert f'"{service}"' not in text, service
        for command in flow.docker.commands:
            if command[:1] == ["docker"]:
                assert command[1] in ALLOWED_DOCKER, command
                if command[1] == "compose":
                    assert command[2:4] == ["-p", PROJECT]
            assert not {"kill", "pause", "prune", "--rmi", "rm", "stop", "restart", "run"} & set(command[2:] if "compose" not in command else command[command.index("--env-file") + 2:]), command
        up = next(c for c in flow.docker.commands if "compose" in c and c[c.index("--env-file") + 2] == "up")
        assert up[-2:] == ["postgres", "db-bootstrap"] and "--no-deps" not in up
        down = next(c for c in flow.docker.commands if "compose" in c and c[c.index("--env-file") + 2] == "down")
        assert down[-3:] == ["down", "--volumes", "--remove-orphans"]

    def test_only_this_projects_images_are_removed_and_shared_images_are_untouched(self, tmp_path):
        flow = Flow(tmp_path)
        flow.run()
        removed = [c[3] for c in flow.docker.commands if c[:3] == ["docker", "image", "remove"]]
        assert sorted(removed) == sorted(PROJECT_IMAGES)
        assert all(ref.startswith(PROJECT + "-") for ref in removed)
        assert not any("postgres:17.11" in " ".join(c) for c in flow.docker.commands if c[:3] == ["docker", "image", "remove"])

    def test_the_tests_run_once_with_the_approval_for_exactly_this_target(self, tmp_path):
        flow = Flow(tmp_path)
        flow.run()
        (command, env, timeout, cwd), = flow.runner.calls
        assert command[1:4] == ["-m", "pytest", H.INTEGRATION_DIR] and timeout == H.T_TESTS and cwd == smoke.REPO
        assert env[H.ENV_APPROVAL] == f"disposable-loopback:{PROJECT}:{PORT}" and env[H.ENV_PROJECT] == PROJECT
        assert env[H.ENV_DSN].startswith("postgresql://agentops:") and f"@127.0.0.1:{PORT}/agentops" in env[H.ENV_DSN]

    def test_no_credential_reaches_a_command_line_or_an_evidence_file(self, tmp_path):
        flow = Flow(tmp_path)
        flow.run()
        (_, env, _, _), = flow.runner.calls
        passwords = [v for k, v in env.items() if k == H.ENV_VIEWER_PASSWORD] + [env[H.ENV_DSN].split(":")[2].split("@")[0]]
        assert all(len(p) >= 20 for p in passwords)
        commands = json.dumps(flow.docker.commands)
        evidence = "".join(p.read_text(encoding="utf-8") for p in flow.evidence_files())
        assert evidence
        for password in passwords:
            assert password not in commands and password not in evidence

    def test_the_evidence_has_matching_hashes_and_claims_only_the_disposable_database(self, tmp_path, capsys):
        flow = Flow(tmp_path)
        flow.run()
        out = capsys.readouterr().out
        records = flow.records()
        assert set(records) == {"pre-cleanup", "final"} and len(flow.evidence_files()) == 2
        for path in flow.evidence_files():
            digest = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
            assert digest in out
        final, pre = records["final"], records["pre-cleanup"]
        assert final["verdict"] == "PASS" and final["cleanup"]["verified"] is True and final["attempt"] == 1
        assert final["pre_cleanup_file"]["name"] in {p.name for p in flow.evidence_files()}
        assert final["services"] == list(H.SERVICES) and "production" in final["claims"]
        assert pre["verdict_note"].startswith("provisional") and final["tests"]["verdict"] == "PASS"
        assert len(final["tests"]["cases"]) == len(H.ALL_EXPECTED_TESTS) and final["loopback_port"] == PORT

    def test_the_temporary_directory_and_the_run_state_are_given_back(self, tmp_path, monkeypatch):
        # Cleanup is simulated (smoke._remove_tree is a RemovalRecorder): this checks the hand-over, not the disk.
        original, via_remove_temp = H.ViewerOps.remove_temp, []

        def spy(self):
            via_remove_temp.append(Path(self.temp).resolve())
            return original(self)
        monkeypatch.setattr(H.ViewerOps, "remove_temp", spy)
        flow = Flow(tmp_path)
        flow.run()
        (handed,) = smoke._remove_tree.calls                       # exactly one directory reached the deletion sink
        assert handed.parent == tmp_path.resolve() and handed.name.startswith("viewer-it-")
        assert via_remove_temp == [handed]                         # ... through ViewerOps.remove_temp, with the run's own directory
        assert smoke.RUN.generated == {} and smoke.RUN.temp is None

    def test_the_run_hands_its_temporary_directory_to_the_deletion_sink_exactly_once(self, tmp_path):
        flow = Flow(tmp_path)
        assert flow.run() == 0
        (handed,) = smoke._remove_tree.calls                       # simulated cleanup: recorded, not deleted
        assert handed.parent == tmp_path.resolve() and handed.name.startswith("viewer-it-")

    @pytest.mark.parametrize("outcomes, verdict", [
        ({H.ALL_EXPECTED_TESTS[0]: "failed"}, "FAIL"),
        ({H.ALL_EXPECTED_TESTS[0]: "skipped"}, "INCONCLUSIVE"),
    ])
    def test_failed_or_skipped_tests_are_not_a_pass_and_cleanup_still_runs(self, tmp_path, outcomes, verdict, capsys):
        full = {name: "passed" for name in H.ALL_EXPECTED_TESTS}
        full.update(outcomes)
        flow = Flow(tmp_path, runner=FakeRunner(full))
        assert flow.run() == 1
        assert f"overall: {verdict}" in capsys.readouterr().out and "down" in flow.verbs()
        assert flow.records()["final"]["verdict"] == verdict and H.own_markers(flow.markers) == []

    def test_a_pytest_timeout_is_inconclusive_and_a_missing_report_too(self, tmp_path):
        for runner in (FakeRunner(timed_out=True, returncode=None), FakeRunner(write_junit=False)):
            flow = Flow(tmp_path / runner.__class__.__name__ / str(id(runner)), runner=runner)
            flow.tmp.mkdir(parents=True)
            assert flow.run() == 1
            assert flow.records()["final"]["verdict"] == "INCONCLUSIVE" and "down" in flow.verbs()

    def test_a_failed_bootstrap_runs_no_test_and_keeps_diagnostics(self, tmp_path):
        flow = Flow(tmp_path, docker=FakeDocker(bootstrap_exit=3))
        assert flow.run() == 1
        assert flow.runner.calls == [] and "down" in flow.verbs()
        final = flow.records()["final"]
        assert final["verdict"] == "FAIL" and "bootstrap exited 3" in final["failure"]
        assert final["diagnostics"]["bootstrap_log_tail"] == ["bootstrap log line"]

    def test_an_incomplete_ledger_or_a_wrong_binding_runs_no_test(self, tmp_path):
        for index, docker in enumerate((FakeDocker(ledger="3|001_create_telemetry_spans.sql,dbt_run,002_create_grafana_reader.sql"),
                                        FakeDocker(binding=json.dumps({"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": str(PORT)}]})))):
            folder = tmp_path / str(index)
            folder.mkdir()
            flow = Flow(folder, docker=docker)
            assert flow.run() == 1 and flow.runner.calls == []
            assert flow.records()["final"]["verdict"] == "FAIL" and "down" in flow.verbs()

    def test_a_failed_build_is_a_failure_and_cleanup_still_runs(self, tmp_path):
        flow = Flow(tmp_path, docker=FakeDocker(fail_build=True))
        assert flow.run() == 1 and flow.runner.calls == []
        assert "down" in flow.verbs() and flow.records()["final"]["verdict"] == "FAIL"

    @pytest.mark.parametrize("error", [KeyboardInterrupt(), RuntimeError("unforeseen")])
    def test_an_interruption_or_an_unforeseen_error_is_a_failure_and_cleanup_still_runs(self, tmp_path, error):
        flow = Flow(tmp_path, runner=FakeRunner(raises=error))
        assert flow.run() == 1
        assert "down" in flow.verbs() and flow.records()["final"]["verdict"] == "FAIL"

    @pytest.mark.parametrize("docker, needle", [
        (FakeDocker(down_code=1), "compose down failed"),
        (FakeDocker(leftover=True), "remain|left"),
        (FakeDocker(protected_after={"agentops-mvp-postgres-1": "i exited s f 255"}), "agentops-mvp-postgres-1 changed"),
        (FakeDocker(repo_status_after=OWN_STATUS + "\n M trace-viewer/app.py"), "repository changed"),
    ])
    def test_any_cleanup_doubt_is_a_fail_and_writes_the_blocking_marker(self, tmp_path, docker, needle):
        flow = Flow(tmp_path, docker=docker)
        assert flow.run() == 1
        assert H.own_markers(flow.markers) == ["viewer-it:CLEANUP_UNVERIFIED"]
        final = flow.records()["final"]
        assert final["verdict"] == "FAIL" and final["cleanup"]["verified"] is False
        assert re.search(needle, " ".join(final["cleanup"]["problems"])), final["cleanup"]["problems"]

    def test_a_recreated_default_bridge_is_informational_only_when_verified(self, tmp_path):
        flow = Flow(tmp_path, docker=FakeDocker(recreate_bridge=True))
        assert flow.run() == 0
        bridge = flow.records()["final"]["cleanup"]["networks"]["default_bridge"]
        assert bridge["recreated"] is True and bridge["treated_as"] == "informational"

    def test_evidence_that_cannot_be_written_safely_makes_the_run_a_fail(self, tmp_path, monkeypatch):
        fake_repo = tmp_path / "fake-repo"                                  # a stand-in repository: the real one is never written to
        fake_repo.mkdir()
        monkeypatch.setattr(smoke, "REPO", fake_repo.resolve())
        flow = Flow(tmp_path, evidence_dir=fake_repo / "should-not-exist")
        assert flow.run() == 1
        assert not (fake_repo / "should-not-exist").exists()
        assert "down" in flow.verbs()

    def test_a_credential_in_a_record_is_masked_not_written(self, tmp_path):
        smoke.RUN.generated = {"X": "s3cr3t-value"}
        path, digest = H.write_evidence(tmp_path / "ev", PROJECT, "final", {"failure": "oops s3cr3t-value", "x": ["s3cr3t-value"]}, "20260101T000000Z")
        text = path.read_text(encoding="utf-8")
        assert "s3cr3t-value" not in text and "<redacted>" in text
        assert __import__("hashlib").sha256(path.read_bytes()).hexdigest() == digest

    def test_evidence_is_never_overwritten(self, tmp_path):
        first, _ = H.write_evidence(tmp_path / "ev", PROJECT, "final", {"a": 1}, "20260101T000000Z")
        second, _ = H.write_evidence(tmp_path / "ev", PROJECT, "final", {"a": 2}, "20260101T000000Z")
        assert first != second and json.loads(first.read_text(encoding="utf-8")) == {"a": 1}

    def test_a_refused_confirmation_issues_no_command_and_consumes_no_attempt(self, tmp_path):
        flow = Flow(tmp_path)
        with pytest.raises(SmokeFailure):
            H.execute(args_for(confirm=False), sh=flow.shell, preflight=flow.preflight, run_tests=flow.runner,
                      attempts_root=flow.attempts)
        assert flow.shell.commands == [] and not flow.attempts.exists()

    def test_a_failing_preflight_issues_no_docker_change_and_consumes_no_attempt(self, tmp_path):
        flow = Flow(tmp_path)

        def refuse(*a, **k):
            raise SmokeFailure("memory too low")
        with pytest.raises(SmokeFailure, match="memory too low"):
            H.execute(args_for(), sh=flow.shell, preflight=refuse, run_tests=flow.runner, attempts_root=flow.attempts)
        assert flow.shell.commands == [] and not flow.attempts.exists()

    def test_a_second_execution_for_the_same_head_is_refused_before_any_docker_change(self, tmp_path):
        first = Flow(tmp_path)
        assert first.run() == 0
        second = Flow(tmp_path, docker=FakeDocker(), runner=FakeRunner())
        second.attempts = first.attempts
        with pytest.raises(SmokeFailure, match="already made"):
            second.run()
        assert second.verbs() == [] and second.runner.calls == []

    def test_a_second_execution_for_another_head_is_a_new_authorization(self, tmp_path):
        first = Flow(tmp_path)
        assert first.run() == 0
        second = Flow(tmp_path / "again", head="b" * 40)
        second.tmp.mkdir()
        second.attempts = first.attempts
        assert second.run() == 0


# ---------------------------------------------------------------------------
# T09  The guard of the live tests and their inventory
# ---------------------------------------------------------------------------

_CONFTEST = []


def load_conftest():
    """The integration conftest, loaded once (two loads would give two distinct dataclass types)."""
    if _CONFTEST:
        return _CONFTEST[0]
    spec = importlib.util.spec_from_file_location("viewer_it_conftest_under_test", INTEGRATION / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module                       # dataclasses look their module up by name
    spec.loader.exec_module(module)
    _CONFTEST.append(module)
    return module


class TestOptInGuard:
    def good(self, port=PORT, project=PROJECT, host="127.0.0.1"):
        creds = credentials()
        shown = f"[{host}]" if ":" in host else host
        return {"dsn": f"postgresql://agentops:{creds['POSTGRES_PASSWORD']}@{shown}:{port}/agentops",
                "viewer_password": creds["TRACE_VIEWER_DB_PASSWORD"], "project": project,
                "approval": f"disposable-loopback:{project}:{port}"}

    def test_what_the_orchestrator_supplies_is_accepted(self):
        guard = load_conftest()
        env = H.integration_environment(PROJECT, PORT, credentials())
        target, reason = guard.target_from_environment(env)
        assert target is not None and reason == "" and (target.host, target.port, target.project) == ("127.0.0.1", PORT, PROJECT)

    def test_the_two_sides_agree_on_names_ports_and_the_approval_text(self):
        guard = load_conftest()
        assert (guard.ENV_DSN, guard.ENV_VIEWER_PASSWORD, guard.ENV_PROJECT, guard.ENV_APPROVAL) == (
            H.ENV_DSN, H.ENV_VIEWER_PASSWORD, H.ENV_PROJECT, H.ENV_APPROVAL)
        assert set(guard.PROHIBITED_PORTS) == set(H.PROHIBITED_PORTS)
        assert guard.approval_token(PROJECT, PORT) == H.approval_token(PROJECT, PORT)
        for name in (PROJECT, "agentops-viewer-it-ffffffff", "agentops", "agentops-shutdown-it-0a1b2c3d", "agentops-viewer-it-0a1b2c3", PROJECT + "0",
                     "xagentops-viewer-it-0a1b2c3d", "agentops-viewer-it-0A1B2C3D"):
            assert bool(guard.PROJECT_RE.fullmatch(name)) == bool(H._PROJECT_RE.fullmatch(name)), name
        assert (guard.OWNER_ROLE, guard.DATABASE) == (H.OWNER_ROLE, H.DATABASE)

    def test_every_port_the_orchestrator_may_choose_is_accepted_by_the_guard(self):
        guard = load_conftest()
        for port in (H.PORT_LOW, H.PORT_HIGH, 24680):
            target, reason = guard.check_target(**self.good(port=port))
            assert target is not None, reason

    def test_an_ipv6_loopback_literal_is_accepted(self):
        guard = load_conftest()
        values = self.good()
        values["dsn"] = values["dsn"].replace("@127.0.0.1:", "@[::1]:")
        assert guard.check_target(**values)[0] is not None

    @pytest.mark.parametrize("name", ["dsn", "viewer_password", "project", "approval"])
    def test_a_missing_setting_skips(self, name):
        guard = load_conftest()
        values = self.good()
        values[name] = None
        target, reason = guard.check_target(**values)
        assert target is None and "not approved" in reason
        values[name] = ""
        assert guard.check_target(**values)[0] is None

    @pytest.mark.parametrize("host", ["localhost", "10.0.0.5", "192.168.1.9", "0.0.0.0", "example.com", "127.0.0.2", "172.17.0.2", "::", "host.docker.internal"])
    def test_a_non_loopback_or_non_literal_host_is_rejected(self, host):
        guard = load_conftest()
        target, reason = guard.check_target(**self.good(host=host))
        assert target is None and "loopback" in reason

    @pytest.mark.parametrize("port", [5432, 8000, 9092, 4317, 4318, 3000, 14317, 15432, 19092, 80, 1023, 65536])
    def test_a_protected_or_unusable_port_is_rejected(self, port):
        guard = load_conftest()
        target, reason = guard.check_target(**self.good(port=port))
        assert target is None

    @pytest.mark.parametrize("change", [
        {"dsn": "postgresql://postgres:pw@127.0.0.1:23456/agentops"},
        {"dsn": "postgresql://agentops:pw@127.0.0.1:23456/other"},
        {"dsn": "postgresql://agentops@127.0.0.1:23456/agentops"},
        {"dsn": "postgresql://agentops:pw@127.0.0.1:23456/agentops?sslmode=disable"},
        {"dsn": "mysql://agentops:pw@127.0.0.1:23456/agentops"},
        {"dsn": "postgresql://agentops:pw@127.0.0.1/agentops"},
        {"dsn": "not a url"},
        {"project": "agentops"}, {"project": "agentops-shutdown-it-0a1b2c3d"}, {"project": "agentops-viewer-it-ZZZZZZZZ"},
        {"approval": "yes"}, {"approval": f"disposable-loopback:{PROJECT}:23457"},
        {"approval": "disposable-loopback:agentops-viewer-it-bbbbbbbb:23456"},
    ])
    def test_a_target_that_is_not_exactly_the_disposable_one_is_rejected(self, change):
        guard = load_conftest()
        values = {**self.good(), **change}
        assert guard.check_target(**values)[0] is None

    def test_without_the_environment_every_live_test_is_skipped_and_none_runs(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTOPS_VIEWER_IT_")}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run([sys.executable, "-m", "pytest", str(INTEGRATION), "-q", "-p", "no:cacheprovider", "-rs"],
                                cwd=str(_REPO), env=env, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        assert result.returncode == 0, output[-1500:]
        match = re.search(r"(\d+) skipped", output)
        assert match and int(match.group(1)) >= len(H.ALL_EXPECTED_TESTS), output[-800:]
        assert "passed" not in output.splitlines()[-1] and "failed" not in output.splitlines()[-1] and "error" not in output.splitlines()[-1]

    def test_a_non_loopback_or_protected_target_in_the_environment_still_skips_everything(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTOPS_VIEWER_IT_")}
        env.update({"PYTHONDONTWRITEBYTECODE": "1", H.ENV_DSN: "postgresql://agentops:pw@10.1.2.3:5432/agentops",
                    H.ENV_VIEWER_PASSWORD: "pw", H.ENV_PROJECT: PROJECT, H.ENV_APPROVAL: f"disposable-loopback:{PROJECT}:5432"})
        result = subprocess.run([sys.executable, "-m", "pytest", str(INTEGRATION), "-q", "-p", "no:cacheprovider"],
                                cwd=str(_REPO), env=env, capture_output=True, text=True, timeout=300)
        assert result.returncode == 0 and "passed" not in result.stdout.splitlines()[-1]
        assert re.search(r"\d+ skipped", result.stdout)


class TestLiveTestInventory:
    def functions(self):
        tree = ast.parse(LIVE_FILE.read_text(encoding="utf-8"))
        return [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]

    def test_the_orchestrator_lists_exactly_the_test_functions_of_the_file(self):
        names = [n.name for n in self.functions()]
        assert sorted(names) == sorted(H.ALL_EXPECTED_TESTS) and len(names) == len(set(names))

    def test_every_test_carries_its_level_marker_and_prefix(self):
        prefix = {"sql": "test_sql_", "query": "test_query_", "endpoint": "test_endpoint_", "connection": "test_connection_"}
        marker = {"sql": "sql_level", "query": "query_level", "endpoint": "endpoint_level", "connection": "connection_level"}
        for node in self.functions():
            level = H.level_of(node.name)
            assert level != "unknown" and node.name.startswith(prefix[level]), node.name
            marks = {d.attr for d in node.decorator_list if isinstance(d, ast.Attribute)} | {
                d.func.attr for d in node.decorator_list if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)}
            assert marker[level] in marks, node.name

    def test_the_planned_checks_are_all_present(self):
        text = LIVE_FILE.read_text(encoding="utf-8")
        for needle in ("default_transaction_read_only", "statement_timeout", "pg_sleep(6)", "SET TRANSACTION READ WRITE",
                       "ReadOnlySqlTransaction", "InsufficientPrivilege", "QueryCanceled", "_INVESTIGATION_SELECT", "limitations[1:51]",
                       "evidence_total", "/api/health/ready", "wrong-password", "silent", "OperationalError",
                       "analytics.stg_telemetry_spans", "no-such-service", '"0" * 32', "[\"first\", None, \"third\"]"):
            assert needle in text, needle

    def test_the_live_tests_connect_only_through_the_approved_target(self):
        text = LIVE_FILE.read_text(encoding="utf-8")
        assert text.count("psycopg.connect(") == 1 and "live_target.admin_dsn" in text
        for forbidden in ("5432", "localhost", "0.0.0.0", "docker", "subprocess", "os.system"):
            assert forbidden not in text.replace("5432/tcp", ""), forbidden

    def test_the_conftest_skips_every_test_through_one_autouse_fixture(self):
        tree = ast.parse((INTEGRATION / "conftest.py").read_text(encoding="utf-8"))
        autouse = [n for n in tree.body if isinstance(n, ast.FunctionDef) and any(
            isinstance(d, ast.Call) and any(k.arg == "autouse" and getattr(k.value, "value", None) is True for k in d.keywords)
            for d in n.decorator_list)]
        assert len(autouse) == 1 and [a.arg for a in autouse[0].args.args] == ["live_target"]

    def test_the_package_marker_exists_and_is_empty(self):
        assert (INTEGRATION / "__init__.py").read_bytes() == b""


# ---------------------------------------------------------------------------
# T10  The fixtures
# ---------------------------------------------------------------------------

class TestFixtures:
    def fixtures(self):
        return load_conftest().build_fixtures()

    def test_they_are_deterministic(self):
        a, b = self.fixtures(), self.fixtures()
        assert a.rows == b.rows and a.span_cases == b.span_cases and a.evidence_cases == b.evidence_cases
        assert a.big_traces == b.big_traces and a.long_limitation_investigation == b.long_limitation_investigation

    def test_the_row_counts_are_the_planned_ones(self):
        f = self.fixtures()
        assert len(f.rows["telemetry_spans"]) == 96 + 1 + 10 + 1000 + 1001
        assert len(f.rows["anomaly_events"]) == 2 + 10 + 10 + 5 + 2 + 6 + 1
        assert len(f.rows["rca_investigations"]) == 2 + 10 + 5 + 2 + 6
        assert len(f.rows["rca_evidence"]) == 12 + 10 + (0 + 1 + 200 + 201 + 230 + 1000)

    def test_the_boundary_text_lengths_and_characters(self):
        f = self.fixtures()
        lengths = {(case.char, case.length) for case, _ in f.span_cases}
        assert lengths == {("x", n) for n in (1, 1999, 2000, 2001, 2002, 5000)} | {(c, n) for c in ("\u00e9", "\U0001F600") for n in (2000, 2001)}
        by_id = {r["span_id"]: r for r in f.rows["telemetry_spans"] if r["trace_id"] == f.text_trace_id}
        for case, span_id in f.span_cases:
            assert by_id[span_id]["error_message"] == by_id[span_id]["status_message"] == case.text and len(case.text) == case.length
        assert len({r["parent_span_id"] for r in by_id.values() if r["parent_span_id"]}) == 1

    def test_the_big_traces_have_exactly_1000_and_1001_spans_and_one_root(self):
        f = self.fixtures()
        for size, trace in f.big_traces.items():
            rows = [r for r in f.rows["telemetry_spans"] if r["trace_id"] == trace]
            assert len(rows) == size and sum(1 for r in rows if r["parent_span_id"] is None) == 1

    def test_limitation_and_evidence_counts_and_ties(self):
        f = self.fixtures()
        investigations = {r["investigation_id"]: r for r in f.rows["rca_investigations"]}
        assert [len(investigations[i]["limitations"]) for _, i in f.limitation_cases] == [0, 1, 50, 51, 500]
        assert investigations[f.null_limitation_investigation]["limitations"] == ["first", None, "third"]
        assert [len(x) for x in investigations[f.long_limitation_investigation]["limitations"]] == [2001, 5000, 5]
        evidence = {}
        for row in f.rows["rca_evidence"]:
            evidence.setdefault(row["investigation_id"], []).append(row)
        for count, investigation_id in f.evidence_cases:
            rows = evidence.get(investigation_id, [])
            assert len(rows) == count
            ranks = [r["rank_position"] for r in rows]
            assert all(r >= 1 for r in ranks) and (len(set(ranks)) < len(ranks) if count >= 2 else True)

    def test_keys_are_unique_well_formed_and_consistent(self):
        f = self.fixtures()
        hex64, hex32, hex16 = (re.compile(p) for p in (r"^[0-9a-f]{64}$", r"^[0-9a-f]{32}$", r"^[0-9a-f]{16}$"))
        spans = f.rows["telemetry_spans"]
        assert len({(r["trace_id"], r["span_id"]) for r in spans}) == len(spans)
        boundary = [r for r in spans if r["attributes"].get("viewer_it")]
        assert all(hex32.match(r["trace_id"]) and hex16.match(r["span_id"]) for r in boundary)
        assert len({(r["kafka_topic"], r["kafka_partition"], r["kafka_offset"]) for r in spans}) == len(spans)
        anomalies = {r["anomaly_id"] for r in f.rows["anomaly_events"]}
        assert len(anomalies) == len(f.rows["anomaly_events"]) and all(hex64.match(a) for a in anomalies)
        investigations = {r["investigation_id"] for r in f.rows["rca_investigations"]}
        assert len(investigations) == len(f.rows["rca_investigations"]) and all(hex64.match(i) for i in investigations)
        assert all(r["anomaly_id"] in anomalies for r in f.rows["rca_investigations"])
        assert all(r["investigation_id"] in investigations for r in f.rows["rca_evidence"])
        keys = [(r["investigation_id"], r["span_id"]) for r in f.rows["rca_evidence"]]
        assert len(set(keys)) == len(keys)
        assert f.anomaly_without_investigation in anomalies and f.anomaly_without_investigation not in {
            r["anomaly_id"] for r in f.rows["rca_investigations"]}

    def test_values_stay_inside_the_visible_constraints(self):
        f = self.fixtures()
        assert all(r["severity"] in ("INFO", "WARNING", "CRITICAL") for r in f.rows["anomaly_events"])
        assert all(r["severity"] in ("INFO", "WARNING", "CRITICAL") and r["confidence"] in ("HIGH", "MEDIUM", "LOW", "INSUFFICIENT_DATA")
                   for r in f.rows["rca_investigations"])
        assert all(r["duration_ms"] >= 0 and r["depth"] >= 0 and 0.0 <= r["evidence_score"] <= 1.0 and r["rank_position"] > 0
                   for r in f.rows["rca_evidence"])
        assert all(r["end_time"] >= r["start_time"] for r in f.rows["telemetry_spans"])

    def test_boundary_rows_are_not_marked_as_demo_data_and_the_demo_rows_are(self):
        f = self.fixtures()
        demo_marked = [r for r in f.rows["telemetry_spans"] if "demo_seed" in r["attributes"]]
        assert len(demo_marked) == 96 and all("demo_seed" not in r["attributes"] for r in f.rows["telemetry_spans"][96:])

    def test_the_fixture_module_needs_no_clock_randomness_or_network(self):
        text = (INTEGRATION / "conftest.py").read_text(encoding="utf-8")
        for pattern in (r"datetime\.now", r"utcnow", r"time\.time", r"import random", r"random\.", r"uuid", r"secrets",
                        r"import socket", r"urlopen", r"requests"):
            assert not re.search(pattern, text), pattern


# ---------------------------------------------------------------------------
# T11  The connection timeout against a local silent listener
# ---------------------------------------------------------------------------

class TestConnectionTimeout:
    def test_db_connect_gives_up_after_about_five_seconds_against_a_listener_that_never_answers(self, monkeypatch):
        """Self-contained: a thread on 127.0.0.1 accepts and stays silent.  No PostgreSQL, no Docker, no external network."""
        spec = importlib.util.spec_from_file_location("viewer_db_under_test", _REPO / "trace-viewer" / "db.py")
        db = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(db)
        import psycopg
        held: list[socket.socket] = []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        listener.settimeout(0.2)
        stop = threading.Event()

        def accept() -> None:
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                    held.append(connection)
                except OSError:
                    continue

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        monkeypatch.setenv("TRACE_VIEWER_DB_HOST", "127.0.0.1")
        monkeypatch.setenv("TRACE_VIEWER_DB_PORT", str(listener.getsockname()[1]))
        monkeypatch.setenv("TRACE_VIEWER_DB_PASSWORD", "not-a-real-password")
        try:
            started = time.monotonic()
            with pytest.raises(psycopg.OperationalError):
                db.connect()
            elapsed = time.monotonic() - started
        finally:
            stop.set()
            thread.join(timeout=2)
            for connection in held:
                connection.close()
            listener.close()
        assert db.CONNECT_TIMEOUT_SECONDS == 5 and 4.0 <= elapsed <= 8.0, elapsed

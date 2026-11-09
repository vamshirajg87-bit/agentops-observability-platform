"""
workload-generator/tests/unit/test_smoke_cleanup_containment.py

Offline tests of the recursive-deletion guard in workload-generator/run_smoke.py (B3J-416).

Nothing here deletes anything.  The recursive delete (run_smoke._rmtree), the existence check after it
(_lexists), lstat, realpath and the retry pause are module-level names in run_smoke; the tests replace those
names inside the run_smoke module, never os / shutil / time themselves, and monkeypatch restores them.
Directories are only created, under pytest's tmp_path.

    T01  A registered workspace is deleted, once, and its record is cleared
    T02  Unregistered, forged and re-pointed (RUN.temp) paths are refused
    T03  Roots, the repository and its ancestors, protected and shared locations are refused
    T04  Symlinks, junctions, replaced directories and redirected paths are refused
    T05  Anything that cannot be verified is refused
    T06  A refusal is reported as an incomplete cleanup, never as success
    T07  create_workspace() and the shutdown harness register what they create
    T08  On Windows nothing is deleted recursively, even for a registered workspace
"""

from __future__ import annotations

import ast
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

_HERE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_HERE))

import run_smoke  # noqa: E402


@pytest.fixture
def guard(monkeypatch, tmp_path):
    """A clean registry, recording delete/say seams and one registered workspace."""
    state = SimpleNamespace(deleted=[], said=[], pauses=[])
    monkeypatch.setattr(run_smoke, "_OWNED", {})
    monkeypatch.setattr(run_smoke, "_windows", lambda: False)   # the ownership checks below are the non-Windows path
    monkeypatch.setattr(run_smoke, "_rmtree", lambda path, **kw: state.deleted.append(Path(path)))
    monkeypatch.setattr(run_smoke, "_lexists", lambda path: Path(path) not in state.deleted)
    monkeypatch.setattr(run_smoke, "_pause", lambda seconds: state.pauses.append(seconds))
    monkeypatch.setattr(run_smoke, "say", lambda text="", *a, **k: state.said.append(str(text)))
    monkeypatch.setattr(run_smoke, "section", lambda *a, **k: None)
    workspace = tmp_path / "agentops-d3-smoke-owned"
    workspace.mkdir()
    run_smoke.register_workspace(workspace)
    state.workspace, state.tmp = workspace, tmp_path
    return state


def _fake_lstat(monkeypatch, target: Path, **overrides):
    """run_smoke._lstat reporting `target` with some fields replaced and everything else truthfully."""
    real = run_smoke._lstat
    key = run_smoke._norm(target)

    def lstat(path, *args, **kwargs):
        info = real(path, *args, **kwargs)
        if run_smoke._norm(path) != key:
            return info
        fields = {n: getattr(info, n) for n in ("st_mode", "st_dev", "st_ino", "st_file_attributes") if hasattr(info, n)}
        fields.update(overrides)
        return SimpleNamespace(**fields)

    monkeypatch.setattr(run_smoke, "_lstat", lstat)


def _forge(path: Path) -> None:
    run_smoke._OWNED[run_smoke._norm(path)] = (1, 1)


# T01 ------------------------------------------------------------------------------------------------

def test_registered_workspace_is_deleted_once_and_the_record_is_cleared(guard):
    assert run_smoke._deletion_refusal(guard.workspace) is None
    assert run_smoke._remove_tree(guard.workspace) is True
    assert guard.deleted == [guard.workspace] and guard.pauses == []
    assert run_smoke._norm(guard.workspace) not in run_smoke._OWNED


def test_a_second_removal_after_success_is_refused(guard):
    assert run_smoke._remove_tree(guard.workspace) is True
    guard.deleted.clear()
    assert run_smoke._remove_tree(guard.workspace) is False
    assert guard.deleted == []


def test_registered_workspace_that_is_already_gone_counts_as_cleaned(guard, monkeypatch):
    monkeypatch.setattr(run_smoke, "_lexists", lambda path: False)
    assert run_smoke._remove_tree(guard.workspace) is True
    assert guard.deleted == [] and run_smoke._norm(guard.workspace) not in run_smoke._OWNED


# T02 ------------------------------------------------------------------------------------------------

def test_unregistered_directory_is_refused(guard):
    other = guard.tmp / "agentops-d3-smoke-other"
    other.mkdir()
    assert "not a workspace created by this run" in run_smoke._deletion_refusal(other)
    assert run_smoke._remove_tree(other) is False
    assert guard.deleted == []


def test_missing_unregistered_path_is_not_reported_as_cleaned(guard):
    assert run_smoke._remove_tree(guard.tmp / "never-created") is False
    assert guard.deleted == []


def test_repointing_run_temp_cannot_authorize_a_deletion(guard, monkeypatch):
    other = guard.tmp / "agentops-d3-smoke-repointed"
    other.mkdir()
    monkeypatch.setattr(run_smoke.RUN, "temp", other)
    assert run_smoke._remove_tree(run_smoke.RUN.temp) is False
    assert guard.deleted == []


def test_prefix_and_temp_location_alone_are_not_enough(guard):
    lookalike = Path(tempfile.gettempdir()) / "agentops-d3-smoke-lookalike"
    assert run_smoke._deletion_refusal(lookalike) is not None


# T03 ------------------------------------------------------------------------------------------------

def test_protected_and_shared_paths_are_refused_even_when_registered(guard):
    paths = [
        Path(Path.cwd().anchor),
        run_smoke.REPO,
        run_smoke.REPO / "workload-generator",
        run_smoke.REPO.parent,
        Path(r"C:\AgentOps-Development"),
        Path(r"C:\AgentOps-Development\sub"),
        Path(r"C:\AgentOps-Recovery"),
        Path.home(),
        Path(tempfile.gettempdir()),
    ]
    for path in paths:
        _forge(path)
        assert run_smoke._deletion_refusal(path) is not None, path
        assert run_smoke._remove_tree(path) is False, path
    assert guard.deleted == []


def test_onedrive_location_is_refused(guard, monkeypatch):
    drive = guard.tmp / "OneDrive"
    drive.mkdir()
    monkeypatch.setenv("OneDrive", str(drive))
    assert run_smoke._deletion_refusal(guard.tmp) is not None


# T04 ------------------------------------------------------------------------------------------------

def test_symlink_is_refused(guard, monkeypatch):
    _fake_lstat(monkeypatch, guard.workspace, st_mode=0o120777)
    assert "symlink" in run_smoke._deletion_refusal(guard.workspace)
    assert run_smoke._remove_tree(guard.workspace) is False
    assert guard.deleted == []


def test_junction_or_reparse_point_is_refused(guard, monkeypatch):
    _fake_lstat(monkeypatch, guard.workspace, st_file_attributes=0x400 | 0x10)
    assert "reparse" in run_smoke._deletion_refusal(guard.workspace)
    assert run_smoke._remove_tree(guard.workspace) is False
    assert guard.deleted == []


def test_replaced_directory_with_a_different_identity_is_refused(guard, monkeypatch):
    real = os.lstat(guard.workspace)
    _fake_lstat(monkeypatch, guard.workspace, st_ino=real.st_ino + 1)
    assert "identity" in run_smoke._deletion_refusal(guard.workspace)
    assert run_smoke._remove_tree(guard.workspace) is False
    assert guard.deleted == []


def test_path_reached_through_redirection_is_refused(guard, monkeypatch):
    monkeypatch.setattr(run_smoke, "_realpath", lambda _p: str(guard.tmp / "elsewhere"))
    assert "redirected" in run_smoke._deletion_refusal(guard.workspace)
    assert run_smoke._remove_tree(guard.workspace) is False
    assert guard.deleted == []


def test_a_file_in_place_of_the_directory_is_refused(guard, monkeypatch):
    _fake_lstat(monkeypatch, guard.workspace, st_mode=0o100644)
    assert run_smoke._deletion_refusal(guard.workspace) is not None
    assert run_smoke._remove_tree(guard.workspace) is False


def test_the_permission_retry_never_touches_a_link(guard, monkeypatch):
    captured = {}
    monkeypatch.setattr(run_smoke, "_rmtree", lambda path, **kw: captured.update(handler=kw.get("onexc") or kw.get("onerror")))
    monkeypatch.setattr(run_smoke, "_lexists", lambda path: False if captured else True)
    run_smoke._remove_tree(guard.workspace)
    link = guard.tmp / "junction"
    link.mkdir()
    _fake_lstat(monkeypatch, link, st_file_attributes=0x400 | 0x10)
    retried = []
    with pytest.raises(PermissionError, match="a link"):
        captured["handler"](lambda t: retried.append(t), str(link), OSError("denied"))
    assert retried == []


# T05 ------------------------------------------------------------------------------------------------

def test_unexpected_error_while_verifying_fails_closed(guard, monkeypatch):
    def boom(_path):
        raise PermissionError("denied")

    monkeypatch.setattr(run_smoke, "_lstat", boom)
    assert "could not be verified" in run_smoke._deletion_refusal(guard.workspace)
    assert run_smoke._remove_tree(guard.workspace) is False
    assert guard.deleted == []


def test_registration_of_a_directory_without_identity_is_refused(guard, monkeypatch):
    other = guard.tmp / "no-identity"
    other.mkdir()
    _fake_lstat(monkeypatch, other, st_ino=0)
    with pytest.raises(run_smoke.SmokeFailure, match="no verifiable identity"):
        run_smoke.register_workspace(other)
    assert run_smoke._norm(other) not in run_smoke._OWNED


def test_registration_of_a_link_is_refused(guard, monkeypatch):
    other = guard.tmp / "a-link"
    other.mkdir()
    _fake_lstat(monkeypatch, other, st_file_attributes=0x400)
    with pytest.raises(run_smoke.SmokeFailure):
        run_smoke.register_workspace(other)


# T06 ------------------------------------------------------------------------------------------------

@pytest.fixture
def cleanup_world(guard, monkeypatch):
    """cleanup() with every Docker / Git / process reading replaced by a quiet answer."""
    monkeypatch.setattr(run_smoke, "stop_host_processes", lambda: [])
    monkeypatch.setattr(run_smoke, "docker_lines", lambda *a, **k: [])
    monkeypatch.setattr(run_smoke, "docker_fingerprint", lambda: {"containers": [], "volumes": [], "networks": [], "images": []})
    monkeypatch.setattr(run_smoke, "repository_state", lambda: [])
    monkeypatch.setattr(run_smoke, "bytecode_caches", lambda: frozenset())
    for name, value in (("compose_used", False), ("env_file", None), ("before", None), ("generated", {}),
                        ("masked_in_logs", 0), ("caches_before", frozenset())):
        monkeypatch.setattr(run_smoke.RUN, name, value)
    return guard


def test_a_refused_deletion_makes_cleanup_incomplete(cleanup_world, monkeypatch):
    unregistered = cleanup_world.tmp / "agentops-d3-smoke-unregistered"
    unregistered.mkdir()
    monkeypatch.setattr(run_smoke.RUN, "temp", unregistered)
    assert run_smoke.cleanup() is False
    said = "\n".join(cleanup_world.said)
    assert "refusing to delete" in said and "temporary directory deleted: NO" in said
    assert "CLEANUP PROBLEM: the temporary directory could not be deleted" in said
    assert cleanup_world.deleted == []


def test_a_verified_deletion_lets_cleanup_complete(cleanup_world, monkeypatch):
    monkeypatch.setattr(run_smoke.RUN, "temp", cleanup_world.workspace)
    assert run_smoke.cleanup() is True
    assert cleanup_world.deleted == [cleanup_world.workspace]
    assert "temporary directory deleted: yes" in "\n".join(cleanup_world.said)


def test_the_shared_cleanup_masks_a_generated_password_before_it_truncates(cleanup_world, monkeypatch, tmp_path):
    """PR-03E.  The compose-down failure text keeps its 400-character bound, but a generated password that
    straddles the cut is masked first, so no fragment of it is ever printed."""
    password = "Aq3-" + "x" * 28                      # 32 characters; the only 'x' characters in the text below
    env = tmp_path / "smoke.env"
    env.write_text("X=1\n", encoding="utf-8")
    stderr = "a" * 284 + password + "b" * 384        # the previous order cut at 300, inside the password
    monkeypatch.setattr(run_smoke.RUN, "compose_used", True)
    monkeypatch.setattr(run_smoke.RUN, "env_file", env)
    monkeypatch.setattr(run_smoke.RUN, "generated", {"POSTGRES_PASSWORD": password})
    monkeypatch.setattr(run_smoke.RUN, "temp", None)
    monkeypatch.setattr(run_smoke, "run",
                        lambda command, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr=stderr))
    assert run_smoke.cleanup() is False
    prefix = "CLEANUP PROBLEM: compose down failed: "
    line = next(text for text in "\n".join(cleanup_world.said).splitlines() if text.startswith(prefix))
    assert "xxxxxxxx" not in line and password not in line         # no complete or partial credential
    assert "<redacted>" in line and len(line) <= len(prefix) + 400


def test_the_shared_cleanup_no_longer_slices_before_it_redacts():
    text = Path(run_smoke.__file__).read_text(encoding="utf-8")
    assert "redact(down.stderr.strip()[-400:])" not in text
    assert "redact(result.stderr.strip()[-300:])" not in text
    assert "redact_tail(down.stderr, 400)" in text and "redact_tail(result.stderr, 300)" in text


def test_refusal_leaves_the_workspace_files_and_its_record_in_place(cleanup_world, monkeypatch):
    (cleanup_world.workspace / "evidence.json").write_text("{}", encoding="utf-8")
    _fake_lstat(monkeypatch, cleanup_world.workspace, st_file_attributes=0x400)
    assert run_smoke._remove_tree(cleanup_world.workspace) is False
    assert (cleanup_world.workspace / "evidence.json").is_file()
    assert run_smoke._norm(cleanup_world.workspace) in run_smoke._OWNED


# T07 ------------------------------------------------------------------------------------------------

def test_create_workspace_registers_what_it_creates(guard, monkeypatch):
    fresh = guard.tmp / "agentops-d3-smoke-fresh"
    fresh.mkdir()
    monkeypatch.setattr(run_smoke, "tempfile",
                        SimpleNamespace(mkdtemp=lambda **_k: str(fresh), gettempdir=tempfile.gettempdir))
    monkeypatch.setattr(run_smoke, "REPO", guard.tmp / "unrelated-repo")
    for name, value in (("temp", None), ("before", {}), ("env_file", None), ("generated", {})):
        monkeypatch.setattr(run_smoke.RUN, name, value)
    run_smoke.create_workspace()
    assert run_smoke._norm(fresh) in run_smoke._OWNED
    assert run_smoke._deletion_refusal(run_smoke.RUN.temp) is None


def test_create_workspace_inside_the_repository_never_calls_rmtree(guard, monkeypatch):
    inside = guard.tmp / "agentops-d3-smoke-inside"
    inside.mkdir()
    discarded = []
    monkeypatch.setattr(run_smoke, "tempfile",
                        SimpleNamespace(mkdtemp=lambda **_k: str(inside), gettempdir=tempfile.gettempdir))
    monkeypatch.setattr(run_smoke, "REPO", guard.tmp)
    monkeypatch.setattr(run_smoke, "_discard_unused_workspace", discarded.append)
    monkeypatch.setattr(run_smoke.RUN, "temp", None)
    with pytest.raises(run_smoke.SmokeFailure, match="inside the repository"):
        run_smoke.create_workspace()
    assert discarded == [inside.resolve()] and guard.deleted == []
    assert run_smoke.RUN.temp is None


def test_create_workspace_stops_when_ownership_cannot_be_recorded(guard, monkeypatch):
    fresh = guard.tmp / "agentops-d3-smoke-noident"
    fresh.mkdir()
    monkeypatch.setattr(run_smoke, "tempfile",
                        SimpleNamespace(mkdtemp=lambda **_k: str(fresh), gettempdir=tempfile.gettempdir))
    monkeypatch.setattr(run_smoke, "REPO", guard.tmp / "unrelated-repo")
    monkeypatch.setattr(run_smoke.RUN, "temp", None)
    _fake_lstat(monkeypatch, fresh, st_ino=0)
    with pytest.raises(run_smoke.SmokeFailure, match="could not record ownership"):
        run_smoke.create_workspace()
    assert run_smoke.RUN.temp is None and guard.deleted == []


def test_the_discard_helper_only_ever_removes_an_empty_directory():
    source = Path(run_smoke.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_discard_unused_workspace")
    calls = {ast.unparse(n.func) for n in ast.walk(function) if isinstance(n, ast.Call)}
    assert "os.rmdir" in calls and not any("rmtree" in call for call in calls)


def test_no_recursive_delete_remains_outside_the_guarded_function():
    tree = ast.parse(Path(run_smoke.__file__).read_text(encoding="utf-8"))
    users = []
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
            if "rmtree" in ast.unparse(call.func):
                users.append(function.name)
    assert set(users) == {"_remove_tree"}


# T08  Windows: no recursive deletion at all -----------------------------------------------------------

@pytest.fixture
def windows(guard, monkeypatch):
    """Windows mode, where any call to the recursive delete, existence check, lstat or realpath is a failure."""
    def forbidden(*args, **kwargs):
        raise AssertionError("the Windows refusal must come before any filesystem call")

    monkeypatch.setattr(run_smoke, "_windows", lambda: True)
    monkeypatch.setattr(run_smoke, "_rmtree", forbidden)
    monkeypatch.setattr(run_smoke, "_lexists", forbidden)
    monkeypatch.setattr(run_smoke, "_lstat", forbidden)
    monkeypatch.setattr(run_smoke, "_realpath", forbidden)
    monkeypatch.setattr(run_smoke, "_pause", forbidden)
    return guard


def test_windows_never_deletes_even_a_registered_verified_workspace(windows):
    assert run_smoke._remove_tree(windows.workspace) is False
    assert any("disabled on Windows" in line for line in windows.said)
    assert windows.deleted == []


def test_windows_refusal_keeps_the_ownership_record(windows):
    run_smoke._remove_tree(windows.workspace)
    assert run_smoke._norm(windows.workspace) in run_smoke._OWNED


def test_windows_refusal_applies_to_unregistered_and_missing_paths_too(windows):
    assert run_smoke._remove_tree(windows.tmp / "never-created") is False
    assert run_smoke._remove_tree(windows.tmp) is False
    assert windows.deleted == []


def test_windows_refusal_is_reported_by_cleanup_as_incomplete(windows, monkeypatch):
    monkeypatch.setattr(run_smoke, "stop_host_processes", lambda: [])
    monkeypatch.setattr(run_smoke, "docker_lines", lambda *a, **k: [])
    monkeypatch.setattr(run_smoke, "docker_fingerprint", lambda: {"containers": [], "volumes": [], "networks": [], "images": []})
    monkeypatch.setattr(run_smoke, "repository_state", lambda: [])
    monkeypatch.setattr(run_smoke, "bytecode_caches", lambda: frozenset())
    for name, value in (("compose_used", False), ("env_file", None), ("before", None), ("generated", {}),
                        ("masked_in_logs", 0), ("caches_before", frozenset()), ("temp", windows.workspace)):
        monkeypatch.setattr(run_smoke.RUN, name, value)
    assert run_smoke.cleanup() is False
    said = "\n".join(windows.said)
    assert "temporary directory deleted: NO" in said
    assert "CLEANUP PROBLEM: the temporary directory could not be deleted" in said
    assert windows.deleted == [] and workspace_still_registered(windows)


def workspace_still_registered(state) -> bool:
    return run_smoke._norm(state.workspace) in run_smoke._OWNED


def test_the_windows_refusal_is_the_first_thing_remove_tree_does():
    tree = ast.parse(Path(run_smoke.__file__).read_text(encoding="utf-8"))
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_remove_tree")
    body = [n for n in function.body if not (isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant))]
    first = body[0]
    assert isinstance(first, ast.If) and ast.unparse(first.test) == "_windows()"
    assert isinstance(first.body[-1], ast.Return) and ast.unparse(first.body[-1].value) == "False"
    assert not any("rmtree" in ast.unparse(n) or "_OWNED" in ast.unparse(n) for n in ast.walk(first))


def test_every_create_workspace_failure_path_avoids_recursive_deletion():
    tree = ast.parse(Path(run_smoke.__file__).read_text(encoding="utf-8"))
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_workspace")
    calls = {ast.unparse(n.func) for n in ast.walk(function) if isinstance(n, ast.Call)}
    assert not any("rmtree" in call or "_remove_tree" in call for call in calls)
    assert "_discard_unused_workspace" in calls and "register_workspace" in calls


def test_the_shutdown_harness_registers_the_workspace_it_creates():
    tree = ast.parse((_HERE / "run_shutdown_it.py").read_text(encoding="utf-8"))
    found = False
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for index, statement in enumerate(function.body):
            if isinstance(statement, ast.Assign) and "mkdtemp" in ast.unparse(statement.value):
                found = True
                assert ".resolve()" in ast.unparse(statement.value)
                following = function.body[index + 1]
                assert isinstance(following, ast.Try)
                assert "smoke.register_workspace(temp)" in ast.unparse(following.body[0])
                assert isinstance(following.handlers[0].body[-1], ast.Raise)
    assert found

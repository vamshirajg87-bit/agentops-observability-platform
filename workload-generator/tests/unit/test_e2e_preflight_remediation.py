"""
workload-generator/tests/unit/test_e2e_preflight_remediation.py

Offline tests of the PR-03C2 safety remediation of run_e2e.py / run_smoke.py.

Everything here uses fakes.  Docker, git, the host counters and the subprocess layer are replaced inside the
run_smoke / run_e2e modules (monkeypatch restores them); nothing contacts the Docker engine, a database, the
network or the host's performance counters.  Files are only created under pytest's tmp_path.

    R   Approved working-tree manifest: acceptance and every fail-closed case
    A   Execution authorization: the default is a plan, and every live condition
    G   Resource gate: thresholds, the paging rule, one sampling session, no mutation
    W   Workspace: disposition, retention, secured creation and permissions
    D   Docker containment: ownership, exact identities, preservation, no inventory-difference removal
    P   Host processes this run started
    F   Failure paths and the four-part result
    C   Compatibility with the unchanged shared interfaces
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_HERE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_HERE))

import run_e2e as e2e  # noqa: E402
import run_smoke as smoke  # noqa: E402
from run_smoke import SmokeFailure  # noqa: E402

H = "a" * 40
OTHER = "b" * 40
BRANCH = smoke.APPROVED_TREE_BRANCH
GIB = 1024 ** 3
P = smoke.PROJECT
LABEL = "com.docker.compose.project"


def result(stdout: str = "", returncode: int = 0, stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture
def quiet(monkeypatch):
    """smoke.say / smoke.section recorded instead of printed."""
    said: list[str] = []
    monkeypatch.setattr(smoke, "say", lambda text="", *a, **k: said.append(str(text)))
    monkeypatch.setattr(smoke, "section", lambda *a, **k: None)
    return said


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch, request):
    """A clean RUN, a clean contained state and an empty ownership registry for every test."""
    monkeypatch.setattr(smoke, "RUN", smoke.Run())
    monkeypatch.setattr(smoke, "_OWNED", {})
    smoke.CONTAINED.reset()
    request.addfinalizer(smoke.CONTAINED.reset)


# ======================================================================================================
# R. Approved working-tree manifest
# ======================================================================================================

def sha_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def entry(path, status=" M", sha=None, deleted=False):
    return {"path": path, "status": status, "sha256": sha, "deleted": deleted}


def write_manifest(tmp_path: Path, entries, /, *, head=H, branch=BRANCH, raw: bytes | None = None, **overrides):
    # tmp_path and entries are positional-only, so an override named "entries" (or any other document key)
    # reaches the manifest document instead of colliding with a parameter.
    document = {"schema": smoke.APPROVED_TREE_SCHEMA, "branch": branch, "head": head,
                "index_empty": True, "entries": entries}
    document.update(overrides)
    data = raw if raw is not None else json.dumps(document).encode("utf-8")
    path = tmp_path / "manifest.json"
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def status_z(*items) -> str:
    return "".join(f"{status} {path}\0" for status, path in items)


class FakeGit:
    def __init__(self, *, branch=BRANCH, head=H, staged="", status=""):
        self.branch, self.head, self.staged, self.status = branch, head, staged, status
        self.calls: list[tuple] = []

    def __call__(self, *args):
        self.calls.append(args)
        if args[:2] == ("rev-parse", "--abbrev-ref"):
            return self.branch + "\n"
        if args[:1] == ("rev-parse",):
            return self.head + "\n"
        if args[:2] == ("diff", "--cached"):
            return self.staged
        if args[0] == "status":
            return self.status
        raise AssertionError(f"unexpected git call {args}")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("print('a')\n", encoding="utf-8")
    (root / "b.txt").write_text("b\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "REPO", root)
    return root


@pytest.fixture
def approved(repo, tmp_path):
    path, digest = write_manifest(tmp_path, [entry("a.py", " M", sha_of(repo / "a.py")),
                                             entry("b.txt", "??", sha_of(repo / "b.txt"))])
    return smoke.load_approved_tree(path, digest, repo=repo)


def good_git() -> FakeGit:
    return FakeGit(status=status_z((" M", "a.py"), ("??", "b.txt")))


def test_a_valid_manifest_and_tree_are_accepted(monkeypatch, approved):
    monkeypatch.setattr(smoke, "git", good_git())
    smoke.verify_approved_tree(H, approved)


def test_the_untracked_files_are_enumerated_completely_and_without_quoting(monkeypatch, approved):
    git = good_git()
    monkeypatch.setattr(smoke, "git", git)
    smoke.verify_approved_tree(H, approved)
    assert ("status", "--porcelain", "-z", "--untracked-files=all") in git.calls


def test_manifest_sha256_mismatch_is_rejected(repo, tmp_path):
    path, _ = write_manifest(tmp_path, [])
    with pytest.raises(SmokeFailure, match="SHA-256"):
        smoke.load_approved_tree(path, "0" * 64, repo=repo)


@pytest.mark.parametrize("bad", ["", "xyz", "a" * 63, "g" * 64, None])
def test_supplied_sha256_must_be_64_hex_characters(repo, tmp_path, bad):
    path, _ = write_manifest(tmp_path, [])
    with pytest.raises(SmokeFailure):
        smoke.load_approved_tree(path, bad, repo=repo)


def test_an_uppercase_supplied_sha256_is_accepted(repo, tmp_path):
    path, digest = write_manifest(tmp_path, [])
    assert smoke.load_approved_tree(path, digest.upper(), repo=repo).digest == digest


def test_wrong_head_is_rejected_whichever_side_differs(monkeypatch, approved):
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="HEAD"):
        smoke.verify_approved_tree(OTHER, approved)
    monkeypatch.setattr(smoke, "git", FakeGit(head=OTHER, status=status_z((" M", "a.py"), ("??", "b.txt"))))
    with pytest.raises(SmokeFailure, match="HEAD"):
        smoke.verify_approved_tree(H, approved)


@pytest.mark.parametrize("bad", ["abc", "A" * 40, "a" * 39, "a" * 41, "", None])
def test_expect_head_must_be_a_full_lowercase_commit(monkeypatch, approved, bad):
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="40-character"):
        smoke.verify_approved_tree(bad, approved)


def test_wrong_branch_is_rejected(monkeypatch, approved):
    monkeypatch.setattr(smoke, "git", FakeGit(branch="main", status=status_z((" M", "a.py"), ("??", "b.txt"))))
    with pytest.raises(SmokeFailure, match="branch"):
        smoke.verify_approved_tree(H, approved)


def test_a_manifest_for_another_branch_is_rejected(monkeypatch, repo, tmp_path):
    path, digest = write_manifest(tmp_path, [], branch="main")
    other = smoke.load_approved_tree(path, digest, repo=repo)
    monkeypatch.setattr(smoke, "git", FakeGit(status=""))
    with pytest.raises(SmokeFailure, match="branch"):
        smoke.verify_approved_tree(H, other)


def test_an_unexpected_file_is_rejected(monkeypatch, repo, approved):
    (repo / "c.txt").write_text("new\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z((" M", "a.py"), ("??", "b.txt"), ("??", "c.txt"))))
    with pytest.raises(SmokeFailure, match="unexpected"):
        smoke.verify_approved_tree(H, approved)


def test_a_missing_file_is_rejected(monkeypatch, approved):
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z((" M", "a.py"))))
    with pytest.raises(SmokeFailure, match="approved but not present"):
        smoke.verify_approved_tree(H, approved)


def test_changed_content_is_rejected(monkeypatch, repo, approved):
    (repo / "a.py").write_text("print('changed')\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="content differs"):
        smoke.verify_approved_tree(H, approved)


def test_a_changed_status_is_rejected(monkeypatch, approved):
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z(("??", "a.py"), ("??", "b.txt"))))
    with pytest.raises(SmokeFailure, match="status"):
        smoke.verify_approved_tree(H, approved)


def test_staged_changes_are_rejected(monkeypatch, approved):
    monkeypatch.setattr(smoke, "git", FakeGit(staged="a.py\n", status=status_z((" M", "a.py"), ("??", "b.txt"))))
    with pytest.raises(SmokeFailure, match="index"):
        smoke.verify_approved_tree(H, approved)


@pytest.mark.parametrize("code", ["M ", "A ", "R ", "MM", "UU", " T", " A", "!!"])
def test_every_unsupported_status_code_is_rejected(monkeypatch, approved, code):
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z((code, "a.py"), ("??", "b.txt"))))
    with pytest.raises(SmokeFailure):
        smoke.verify_approved_tree(H, approved)


def _patch_lstat(monkeypatch, name: str, mode: int):
    real = smoke._lstat

    def fake(path, *args, **kwargs):
        if Path(path).name == name:
            return SimpleNamespace(st_mode=mode, st_size=1)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(smoke, "_lstat", fake)


def test_a_symbolic_link_is_rejected(monkeypatch, approved):
    _patch_lstat(monkeypatch, "a.py", stat.S_IFLNK | 0o777)
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="symbolic link"):
        smoke.verify_approved_tree(H, approved)


def test_a_reparse_point_is_rejected(monkeypatch, approved):
    real = smoke._lstat

    def fake(path, *args, **kwargs):
        if Path(path).name == "a.py":
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=1, st_file_attributes=0x400)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(smoke, "_lstat", fake)
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="symbolic link or reparse"):
        smoke.verify_approved_tree(H, approved)


@pytest.mark.parametrize("mode", [stat.S_IFDIR | 0o755, stat.S_IFIFO | 0o644, stat.S_IFCHR | 0o644])
def test_unusual_file_types_are_rejected(monkeypatch, approved, mode):
    _patch_lstat(monkeypatch, "b.txt", mode)
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="not a regular file"):
        smoke.verify_approved_tree(H, approved)


def test_a_deleted_file_is_represented_and_checked(monkeypatch, repo, tmp_path):
    path, digest = write_manifest(tmp_path, [entry("gone.txt", " D", None, True)])
    manifest = smoke.load_approved_tree(path, digest, repo=repo)
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z((" D", "gone.txt"))))
    smoke.verify_approved_tree(H, manifest)
    (repo / "gone.txt").write_text("back\n", encoding="utf-8")
    with pytest.raises(SmokeFailure, match="listed as deleted but it exists"):
        smoke.verify_approved_tree(H, manifest)


def test_a_listed_but_missing_file_is_rejected(monkeypatch, approved, repo):
    (repo / "b.txt").unlink()
    monkeypatch.setattr(smoke, "git", good_git())
    with pytest.raises(SmokeFailure, match="listed but missing"):
        smoke.verify_approved_tree(H, approved)


def test_a_git_error_fails_closed(monkeypatch, approved):
    def boom(*args):
        raise SmokeFailure("git status: exit 128")

    monkeypatch.setattr(smoke, "git", boom)
    with pytest.raises(SmokeFailure, match="git status"):
        smoke.verify_approved_tree(H, approved)


@pytest.mark.parametrize("raw", [
    b"not json",
    b"{}",
    b"[]",
    b'{"schema": "x", "schema": "y"}',
    b'{"x": NaN}',
    b"\xff\xfe",
])
def test_malformed_manifests_are_rejected(repo, tmp_path, raw):
    path, digest = write_manifest(tmp_path, [], raw=raw)
    with pytest.raises(SmokeFailure):
        smoke.load_approved_tree(path, digest, repo=repo)


@pytest.mark.parametrize("overrides", [
    {"schema": "agentops.approved-tree/2"},
    {"index_empty": False},
    {"index_empty": "yes"},
    {"head": "abc"},
    {"head": "A" * 40},
    {"branch": ""},
    {"entries": "nope"},
    {"extra": 1},
])
def test_manifest_top_level_validation(repo, tmp_path, overrides):
    path, digest = write_manifest(tmp_path, [], **overrides)
    with pytest.raises(SmokeFailure):
        smoke.load_approved_tree(path, digest, repo=repo)


def test_a_manifest_missing_a_key_is_rejected(repo, tmp_path):
    document = {"schema": smoke.APPROVED_TREE_SCHEMA, "branch": BRANCH, "head": H, "entries": []}
    path, digest = write_manifest(tmp_path, [], raw=json.dumps(document).encode())
    with pytest.raises(SmokeFailure, match="documented keys"):
        smoke.load_approved_tree(path, digest, repo=repo)


@pytest.mark.parametrize("value", ["nope", "[]", {}, {"path": "a.py"}, None, 5, True])
def test_non_list_entries_reach_the_parser_and_are_rejected(repo, tmp_path, value):
    path, digest = write_manifest(tmp_path, value)
    assert json.loads(path.read_text(encoding="utf-8"))["entries"] == value      # the malformed value is in the file
    with pytest.raises(SmokeFailure, match="entries are not a list"):
        smoke.load_approved_tree(path, digest, repo=repo)


def test_the_parser_itself_rejects_non_list_entries_and_still_accepts_an_empty_list():
    document = {"schema": smoke.APPROVED_TREE_SCHEMA, "branch": BRANCH, "head": H, "index_empty": True,
                "entries": "nope"}
    with pytest.raises(SmokeFailure, match="entries are not a list"):
        smoke.parse_approved_tree(document, "d" * 64)
    assert smoke.parse_approved_tree({**document, "entries": []}, "d" * 64).entries == {}


def test_an_entries_override_replaces_the_default_and_other_overrides_still_work(tmp_path):
    path, _ = write_manifest(tmp_path, [entry("a.py", " M", "a" * 64)], entries="nope", head=OTHER)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["entries"] == "nope" and document["head"] == OTHER


@pytest.mark.parametrize("bad_entry", [
    {"path": "a.py", "status": " M", "sha256": "a" * 64},                                  # a key missing
    {"path": "a.py", "status": " M", "sha256": "a" * 64, "deleted": False, "x": 1},         # an extra key
    entry("a.py", "M ", "a" * 64),                                                          # staged status
    entry("a.py", " M", "A" * 64),                                                          # uppercase hash
    entry("a.py", " M", "a" * 63),                                                          # short hash
    entry("a.py", " M", None),                                                              # no hash
    entry("a.py", " M", "a" * 64, True),                                                    # deleted flag wrong
    entry("a.py", " D", "a" * 64, True),                                                    # deleted with a hash
    entry("a.py", " D", None, False),                                                       # deleted flag wrong
    entry("../x", " M", "a" * 64),
    entry("/abs", " M", "a" * 64),
    entry("a\\b", " M", "a" * 64),
    entry("C:x", " M", "a" * 64),
    entry("a//b", " M", "a" * 64),
    entry("./a", " M", "a" * 64),
    entry("dir/", " M", "a" * 64),
    entry(".git/config", " M", "a" * 64),
    entry("a\nb", " M", "a" * 64),
    entry("e\u0301.txt", " M", "a" * 64),                                                   # not NFC
    entry("", " M", "a" * 64),
    entry(5, " M", "a" * 64),
])
def test_manifest_entry_validation(repo, tmp_path, bad_entry):
    path, digest = write_manifest(tmp_path, [bad_entry])
    with pytest.raises(SmokeFailure):
        smoke.load_approved_tree(path, digest, repo=repo)


def test_duplicate_and_case_ambiguous_paths_are_rejected(repo, tmp_path):
    for entries in ([entry("a.py", " M", "a" * 64), entry("a.py", " M", "a" * 64)],
                    [entry("a.py", " M", "a" * 64), entry("A.py", " M", "a" * 64)]):
        path, digest = write_manifest(tmp_path, entries)
        with pytest.raises(SmokeFailure, match="duplicate"):
            smoke.load_approved_tree(path, digest, repo=repo)


def test_a_manifest_inside_the_repository_is_rejected(repo):
    inside = repo / "manifest.json"
    data = json.dumps({"schema": smoke.APPROVED_TREE_SCHEMA, "branch": BRANCH, "head": H,
                       "index_empty": True, "entries": []}).encode()
    inside.write_bytes(data)
    with pytest.raises(SmokeFailure, match="outside the repository"):
        smoke.load_approved_tree(inside, hashlib.sha256(data).hexdigest(), repo=repo)


def test_a_manifest_that_is_not_a_regular_file_is_rejected(repo, tmp_path, monkeypatch):
    with pytest.raises(SmokeFailure, match="regular file"):
        smoke.load_approved_tree(tmp_path, "a" * 64, repo=repo)
    path, digest = write_manifest(tmp_path, [])
    real = smoke._lstat
    monkeypatch.setattr(smoke, "_lstat", lambda p, *a, **k: SimpleNamespace(st_mode=stat.S_IFLNK, st_size=1)
                        if Path(p) == path else real(p, *a, **k))
    with pytest.raises(SmokeFailure, match="regular file"):
        smoke.load_approved_tree(path, digest, repo=repo)


def test_a_missing_manifest_is_rejected(repo, tmp_path):
    with pytest.raises(SmokeFailure, match="cannot be read"):
        smoke.load_approved_tree(tmp_path / "absent.json", "a" * 64, repo=repo)


def test_an_oversized_manifest_is_rejected(repo, tmp_path, monkeypatch):
    path, digest = write_manifest(tmp_path, [])
    monkeypatch.setattr(smoke, "APPROVED_TREE_MAX_BYTES", 5)
    with pytest.raises(SmokeFailure, match="too large"):
        smoke.load_approved_tree(path, digest, repo=repo)


def test_check_repository_with_a_manifest_records_it_and_never_trusts_the_dirty_tree(
        monkeypatch, quiet, repo, approved):
    monkeypatch.setattr(smoke, "git", good_git())
    monkeypatch.setattr(smoke, "COMPOSE_FILE", "a.py")
    monkeypatch.setattr(smoke, "OVERRIDE_FILE", "b.txt")
    monkeypatch.setattr(smoke, "bytecode_caches", lambda: frozenset())
    smoke.check_repository(H, approved)
    assert smoke.CONTAINED.approved is approved
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z((" M", "a.py"), ("??", "b.txt"), ("??", "z.txt"))))
    (repo / "z.txt").write_text("z\n", encoding="utf-8")
    with pytest.raises(SmokeFailure):
        smoke.check_repository(H, approved)


def test_the_strict_check_is_unchanged_without_a_manifest(monkeypatch, quiet, repo):
    monkeypatch.setattr(smoke, "COMPOSE_FILE", "a.py")
    monkeypatch.setattr(smoke, "OVERRIDE_FILE", "b.txt")
    monkeypatch.setattr(smoke, "bytecode_caches", lambda: frozenset())
    monkeypatch.setattr(smoke, "git", FakeGit(status=""))
    smoke.check_repository(None)
    assert smoke.CONTAINED.approved is None
    monkeypatch.setattr(smoke, "git", FakeGit(status=" M a.py\n"))
    with pytest.raises(SmokeFailure, match="other changes"):
        smoke.check_repository(None)
    monkeypatch.setattr(smoke, "ALLOWED_UNTRACKED", frozenset({" M a.py"}))
    smoke.check_repository(None)


def test_the_same_manifest_is_rechecked_after_the_run(monkeypatch, repo, approved):
    monkeypatch.setattr(smoke, "git", good_git())
    assert smoke.recheck_approved_tree() == []          # no manifest used: nothing to check
    smoke.CONTAINED.approved = approved
    assert smoke.recheck_approved_tree() == []
    (repo / "a.py").write_text("print('changed during the run')\n", encoding="utf-8")
    problems = smoke.recheck_approved_tree()
    assert problems and "no longer matches" in problems[0]
    (repo / "a.py").write_text("print('a')\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "git", FakeGit(status=status_z((" M", "a.py"))))
    assert smoke.recheck_approved_tree()


# ======================================================================================================
# A. Execution authorization
# ======================================================================================================

@pytest.fixture
def forbidden(monkeypatch):
    """Anything that would start or change something raises, and is recorded."""
    calls: list = []

    def boom(*args, **kwargs):
        calls.append(args)
        raise AssertionError("nothing may run")

    for owner, name in ((smoke, "run"), (smoke, "git"), (smoke, "cleanup_contained"), (smoke, "check_repository"),
                        (smoke, "run_resource_gate"), (e2e, "e2e")):
        monkeypatch.setattr(owner, name, boom)
    monkeypatch.setattr(e2e, "configure_harness", lambda: None)
    monkeypatch.setattr(e2e, "_python_supported", lambda: True)
    return calls


def test_no_arguments_prints_the_plan_and_runs_nothing(forbidden, capsys):
    assert e2e.main([]) == 0
    out = capsys.readouterr().out
    assert "NOTHING WAS RUN" in out
    assert not forbidden


def test_the_plan_names_every_required_item_and_holds_no_secret(forbidden, capsys):
    e2e.main(["--expect-head", H])
    out = capsys.readouterr().out
    for needle in (P, "14317", "19092", "15432", "analytics-refresh", "--execute", "--confirm",
                   "--approved-tree", "--approved-tree-sha256", H, "RETAINED", "Network downloads",
                   "Images built", "Database writes", "Cleanup policy", "Workload stages", "Resource preflight",
                   "30 normal", "40 slow-tool", "40 repeated-failure"):
        assert needle in out, needle
    for image in smoke.PROJECT_IMAGES:
        assert image in out
    assert "password" not in out.lower()
    assert "secret" not in out.lower()


def test_a_missing_execute_flag_never_executes(forbidden, capsys):
    phrase = e2e.confirmation_phrase(H)
    assert e2e.main(["--expect-head", H, "--confirm", phrase]) == 0
    assert "NOTHING WAS RUN" in capsys.readouterr().out
    assert not forbidden


@pytest.mark.parametrize("argv", [
    ["--execute"],
    ["--execute", "--expect-head", H],
    ["--execute", "--expect-head", H, "--confirm", "wrong phrase"],
    ["--execute", "--expect-head", H, "--confirm", "AUTHORIZE-LIVE-E2E " + P + " " + OTHER],
    ["--execute", "--confirm", "AUTHORIZE-LIVE-E2E " + P + " " + H],
    ["--expect-head", "abc"],
    ["--expect-head", "A" * 40],
    ["--approved-tree", "m.json"],
    ["--approved-tree-sha256", "a" * 64],
    ["--approved-tree", "m.json", "--approved-tree-sha256", "xyz"],
    ["--execute", "--preflight", "--expect-head", H],
    ["--preflight"],
])
def test_invalid_arguments_fail_before_anything_starts(forbidden, argv):
    with pytest.raises(SystemExit) as stop:
        e2e.main(argv)
    assert stop.value.code == 2
    assert not forbidden


def test_the_confirmation_phrase_binds_the_project_and_the_commit():
    phrase = e2e.confirmation_phrase(H)
    assert phrase == f"AUTHORIZE-LIVE-E2E {P} {H}"
    assert phrase != e2e.confirmation_phrase(OTHER)


def test_an_invalid_manifest_stops_before_any_step(forbidden, capsys):
    argv = ["--execute", "--expect-head", H, "--confirm", e2e.confirmation_phrase(H),
            "--approved-tree", "does-not-exist.json", "--approved-tree-sha256", "0" * 64]
    assert e2e.main(argv) == 1
    out = capsys.readouterr().out
    assert "refused" in out and "nothing was started" in out
    assert not forbidden


def test_a_manifest_hash_mismatch_stops_before_any_step(forbidden, capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(smoke, "REPO", tmp_path / "repo")
    path, _ = write_manifest(tmp_path, [])
    argv = ["--execute", "--expect-head", H, "--confirm", e2e.confirmation_phrase(H),
            "--approved-tree", str(path), "--approved-tree-sha256", "0" * 64]
    assert e2e.main(argv) == 1
    assert "SHA-256" in capsys.readouterr().out
    assert not forbidden


def _record_steps(monkeypatch, record: list, *, gate_fails: bool, stop_after: str | None = None):
    def stub(name, raises=None):
        def function(*args, **kwargs):
            record.append(name)
            if raises is not None:
                raise raises
            if name == stop_after:
                raise SmokeFailure("stop here")
        return function

    monkeypatch.setattr(smoke, "check_repository", stub("repository"))
    monkeypatch.setattr(smoke, "run_resource_gate", stub("gate", SmokeFailure("gate failed") if gate_fails else None))
    for name in ("record_docker_state", "record_protected_state", "create_workspace_secured", "create_workspace",
                 "create_virtual_environment", "check_render", "start_kafka", "create_topics",
                 "track_project_identities", "start_postgres", "run_bootstrap", "start_collector",
                 "start_host_services", "check_ports"):
        monkeypatch.setattr(smoke, name, stub(name))
    monkeypatch.setattr(smoke, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no command")))


def test_nothing_is_created_or_started_before_the_preflight_passes(monkeypatch):
    record: list = []
    _record_steps(monkeypatch, record, gate_fails=True)
    with pytest.raises(SmokeFailure, match="gate failed"):
        e2e.e2e(H)
    assert record == ["repository", "gate"]


def test_the_gate_precedes_every_docker_and_workspace_step(monkeypatch):
    record: list = []
    _record_steps(monkeypatch, record, gate_fails=False, stop_after="create_workspace_secured")
    with pytest.raises(SmokeFailure, match="stop here"):
        e2e.e2e(H)
    assert record == ["repository", "gate", "record_docker_state", "record_protected_state",
                      "create_workspace_secured"]


def test_the_preflight_mode_starts_nothing(monkeypatch, capsys):
    record: list = []
    _record_steps(monkeypatch, record, gate_fails=False)
    monkeypatch.setattr(e2e, "configure_harness", lambda: None)
    monkeypatch.setattr(e2e, "_python_supported", lambda: True)
    monkeypatch.setattr(smoke, "cleanup_contained", lambda **k: record.append("cleanup"))
    assert e2e.main(["--preflight", "--expect-head", H]) == 0
    assert record == ["repository", "gate"]
    assert "PASSED" in capsys.readouterr().out
    record.clear()
    _record_steps(monkeypatch, record, gate_fails=True)
    assert e2e.main(["--preflight", "--expect-head", H]) == 1
    assert record == ["repository", "gate"]


# ======================================================================================================
# G. Resource gate
# ======================================================================================================

def good_readings(**over) -> smoke.GateReadings:
    base = dict(power_source="AC", wmi_available_mib=5000.0, counter_available_mib=5000.0,
                committed_percent=40.0, paging_file_percent=2.0, pages_per_second=[0.0] * 12,
                free_disk_bytes={"temporary storage": 100.0 * GIB, "Docker storage": 100.0 * GIB},
                engine_bytes=4 * GIB, ports_in_use={14317: False, 19092: False, 15432: False},
                project_objects=[])
    base.update(over)
    return smoke.GateReadings(**base)


def test_a_fully_met_gate_has_no_problem():
    assert smoke.resource_gate_problems(good_readings()) == []


@pytest.mark.parametrize("field", ["wmi_available_mib", "counter_available_mib"])
def test_available_memory_boundary_for_both_measurements(field):
    assert smoke.resource_gate_problems(good_readings(**{field: 4096.0})) == []
    problems = smoke.resource_gate_problems(good_readings(**{field: 4095.9}))
    assert len(problems) == 1 and "4096" in problems[0]


@pytest.mark.parametrize("label", ["temporary storage", "Docker storage"])
def test_disk_boundary_on_both_drives(label):
    disks = {"temporary storage": 100.0 * GIB, "Docker storage": 100.0 * GIB}
    assert smoke.resource_gate_problems(good_readings(free_disk_bytes={**disks, label: 20.0 * GIB})) == []
    assert smoke.resource_gate_problems(good_readings(free_disk_bytes={**disks, label: 20.0 * GIB - 1}))


def test_a_missing_disk_reading_fails():
    assert smoke.resource_gate_problems(good_readings(free_disk_bytes={}))
    assert smoke.resource_gate_problems(good_readings(free_disk_bytes={"temporary storage": 100.0 * GIB}))


def test_committed_memory_must_be_below_seventy_percent():
    assert smoke.resource_gate_problems(good_readings(committed_percent=69.9)) == []
    assert smoke.resource_gate_problems(good_readings(committed_percent=70.0))


def test_paging_file_usage_must_be_below_five_percent():
    assert smoke.resource_gate_problems(good_readings(paging_file_percent=4.9)) == []
    assert smoke.resource_gate_problems(good_readings(paging_file_percent=5.0))


def test_docker_engine_memory_boundary():
    assert smoke.resource_gate_problems(good_readings(engine_bytes=3584 * 1024 ** 2)) == []
    assert smoke.resource_gate_problems(good_readings(engine_bytes=3584 * 1024 ** 2 - 1))
    assert smoke.resource_gate_problems(good_readings(engine_bytes=None))


@pytest.mark.parametrize("power", ["battery", None, "unknown"])
def test_ac_power_is_required(power):
    assert smoke.resource_gate_problems(good_readings(power_source=power))


def test_a_busy_or_unreadable_port_fails():
    assert smoke.resource_gate_problems(good_readings(ports_in_use={14317: True, 19092: False, 15432: False}))
    assert smoke.resource_gate_problems(good_readings(ports_in_use={14317: False, 19092: None, 15432: False}))
    assert smoke.resource_gate_problems(good_readings(ports_in_use={}))


def test_pre_existing_project_objects_fail():
    assert smoke.resource_gate_problems(good_readings(project_objects=["containers: x"]))
    assert smoke.resource_gate_problems(good_readings(project_objects=None))


@pytest.mark.parametrize("field", ["wmi_available_mib", "counter_available_mib", "committed_percent",
                                   "paging_file_percent", "pages_per_second", "power_source"])
def test_a_missing_counter_is_a_failure(field):
    assert smoke.resource_gate_problems(good_readings(**{field: None}))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, True, "5000"])
def test_unreadable_numbers_are_failures(bad):
    assert smoke.resource_gate_problems(good_readings(wmi_available_mib=bad))


def test_one_paging_spike_passes_and_two_fail():
    one = [0.0] * 12
    one[5] = 150.0
    assert smoke.pages_per_second_problems(one) == []
    two = [0.0] * 12
    two[5], two[11] = 150.0, 101.0
    assert smoke.pages_per_second_problems(two)


def test_the_two_warm_up_samples_are_ignored():
    samples = [78911.4, 5192.6] + [0.0] * 10
    assert smoke.pages_per_second_problems(samples) == []
    samples[2] = samples[3] = 100.1
    assert smoke.pages_per_second_problems(samples)


def test_exactly_one_hundred_is_not_a_spike():
    assert smoke.pages_per_second_problems([0.0, 0.0] + [100.0] * 10) == []


@pytest.mark.parametrize("samples", [None, [], [0.0] * 11, [0.0] * 13, [0.0] * 11 + ["x"], [0.0] * 11 + [None],
                                     [0.0] * 11 + [float("nan")], 5])
def test_an_incomplete_or_unreadable_paging_sample_set_fails(samples):
    assert smoke.pages_per_second_problems(samples)


def make_sources(**over) -> smoke.GateSources:
    base = dict(
        power=lambda: "AC", wmi_available_mib=lambda: 5000.0,
        counters=lambda: {"pages_per_second": [0.0] * 12, "available_mib": 5000.0, "committed_percent": 40.0,
                          "paging_file_percent": 2.0},
        free_disk_bytes=lambda: {"temporary storage": 100.0 * GIB, "Docker storage": 100.0 * GIB},
        engine_bytes=lambda: 4 * GIB, port_probe=lambda port: False, project_objects=lambda: [])
    base.update(over)
    return smoke.GateSources(**base)


@pytest.fixture
def no_commands(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("the gate may not run a command when its sources are fakes")

    monkeypatch.setattr(smoke, "run", boom)


def test_exactly_one_sampling_session_even_when_the_gate_fails(quiet, no_commands):
    sessions: list[int] = []

    def counters():
        sessions.append(1)
        return {"pages_per_second": [0.0, 0.0] + [500.0] * 10, "available_mib": 5000.0,
                "committed_percent": 40.0, "paging_file_percent": 2.0}

    with pytest.raises(SmokeFailure, match="not measured again|nothing is measured again"):
        smoke.run_resource_gate(make_sources(counters=counters))
    assert sessions == [1]
    sessions.clear()
    smoke.read_gate_readings(make_sources(counters=counters))
    assert sessions == [1]


def test_a_source_that_raises_is_an_unmet_gate_not_a_crash(quiet, no_commands):
    def broken():
        raise RuntimeError("counter unavailable")

    with pytest.raises(SmokeFailure, match="could not be read"):
        smoke.run_resource_gate(make_sources(wmi_available_mib=broken))
    readings = smoke.read_gate_readings(make_sources(counters=broken))
    assert readings.pages_per_second is None and readings.counter_available_mib is None


def test_the_gate_passes_with_fake_sources_and_runs_no_command(quiet, no_commands):
    readings = smoke.run_resource_gate(make_sources())
    assert readings.power_source == "AC"
    assert any("every gate met" in line for line in quiet)


def test_the_gate_reports_every_paging_sample(quiet, no_commands):
    smoke.run_resource_gate(make_sources(counters=lambda: {
        "pages_per_second": [float(i) for i in range(12)], "available_mib": 5000.0,
        "committed_percent": 40.0, "paging_file_percent": 2.0}))
    line = next(text for text in quiet if "Pages/sec" in text)
    assert "0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11" in line


def _typeperf(rows) -> str:
    header = ('"(PDH-CSV 4.0)","\\\\H\\Memory\\Pages/sec","\\\\H\\Memory\\Available MBytes",'
              '"\\\\H\\Memory\\% Committed Bytes In Use","\\\\H\\Paging File(_Total)\\% Usage"')
    body = "\n".join('"11/07/2026 10:00:%02d.000","%s","%s","%s","%s"' % ((i,) + tuple(row))
                     for i, row in enumerate(rows))
    return header + "\n" + body + "\nThe command completed successfully.\n"


def test_the_counter_csv_is_parsed_with_the_stricter_reading():
    rows = [(0.0, 9000.0 - i, 30.0 + i, 1.0 + i / 10) for i in range(12)]
    parsed = smoke.parse_typeperf_csv(_typeperf(rows))
    assert parsed["pages_per_second"] == [0.0] * 12
    assert parsed["available_mib"] == min(row[1] for row in rows[2:])
    assert parsed["committed_percent"] == max(row[2] for row in rows[2:])
    assert parsed["paging_file_percent"] == max(row[3] for row in rows[2:])


@pytest.mark.parametrize("mutate", [
    lambda text: text.replace('"1.0"', '" "', 1),
    lambda text: text.replace('"0.0"', '"-1.#IND"', 1),
    lambda text: "\n".join(text.splitlines()[:-4]),
    lambda text: "",
    lambda text: "The command completed successfully.\n",
])
def test_an_incomplete_counter_csv_is_unreadable(mutate):
    rows = [(0.0, 9000.0, 30.0, 1.0)] * 12
    assert smoke.parse_typeperf_csv(mutate(_typeperf(rows))) is None


def test_the_counter_session_is_one_typeperf_call(monkeypatch):
    calls: list = []

    def fake_run(command, *, timeout, cwd=None, env=None, what=""):
        calls.append(list(command))
        return result(_typeperf([(0.0, 9000.0, 30.0, 1.0)] * 12))

    monkeypatch.setattr(smoke, "run", fake_run)
    assert smoke._read_counter_session()["available_mib"] == 9000.0
    assert len(calls) == 1
    assert calls[0][0] == "typeperf" and calls[0][-4:] == ["-sc", "12", "-si", "1"]
    assert r"\Memory\Pages/sec" in calls[0]


def test_the_wmi_and_engine_readers_issue_only_read_commands(monkeypatch):
    calls: list = []

    def fake_run(command, *, timeout, cwd=None, env=None, what=""):
        calls.append(list(command))
        return result("5242880\n" if command[0] == "powershell" else str(4 * GIB))

    monkeypatch.setattr(smoke, "run", fake_run)
    assert smoke._read_wmi_available_mib() == 5120.0
    assert smoke._read_engine_bytes() == 4 * GIB
    assert calls[1] == ["docker", "info", "--format", "{{.MemTotal}}"]
    assert "Get-CimInstance" in calls[0][-1]


def test_project_objects_are_found_by_name_and_by_label(monkeypatch):
    monkeypatch.setattr(smoke, "docker_fingerprint", lambda: {
        "containers": [f"id1 {P}-kafka-1 running", "id2 agentops-postgres exited"],
        "volumes": [], "networks": [], "images": []})
    monkeypatch.setattr(smoke, "docker_lines", lambda *args: ["abc"] if args[0] == "volume" else [])
    found = smoke.read_project_objects()
    assert len(found) == 2 and any("kafka" in item for item in found)


# ======================================================================================================
# W. Workspace
# ======================================================================================================

@pytest.fixture
def ws(monkeypatch, tmp_path, quiet):
    state = SimpleNamespace(deleted=[], windows=False)
    monkeypatch.setattr(smoke, "_windows", lambda: state.windows)
    monkeypatch.setattr(smoke, "_rmtree", lambda path, **kw: state.deleted.append(Path(path)))
    monkeypatch.setattr(smoke, "_lexists", lambda path: Path(path) not in state.deleted)
    monkeypatch.setattr(smoke, "_pause", lambda seconds: None)
    workspace = tmp_path / "agentops-d3-smoke-owned"
    workspace.mkdir()
    (workspace / "smoke.env").write_text("SOME_SETTING=very-secret-test-value\n", encoding="utf-8")
    (workspace / "run.log").write_text("a log line\n", encoding="utf-8")
    smoke.register_workspace(workspace)
    state.workspace = workspace
    state.tmp = tmp_path
    return state


def test_a_verified_windows_workspace_is_retained_by_policy(ws):
    ws.windows = True
    status, reason = smoke.workspace_disposition(ws.workspace)
    assert status == "retained_by_policy" and "Windows" in reason
    assert ws.deleted == [] and ws.workspace.exists()
    assert (ws.workspace / "smoke.env").exists()


def test_a_verified_workspace_elsewhere_is_deleted_through_the_existing_guard(ws):
    status, _ = smoke.workspace_disposition(ws.workspace)
    assert status == "deleted" and ws.deleted == [ws.workspace]


def test_a_verified_workspace_that_cannot_be_removed_is_failed(ws, monkeypatch):
    def boom(path, **kwargs):
        raise OSError("in use")

    monkeypatch.setattr(smoke, "_rmtree", boom)
    status, _ = smoke.workspace_disposition(ws.workspace)
    assert status == "failed"


def test_no_workspace_and_an_already_removed_workspace_count_as_deleted(ws, monkeypatch):
    assert smoke.workspace_disposition(None)[0] == "deleted"
    monkeypatch.setattr(smoke, "_lexists", lambda path: False)
    assert smoke.workspace_disposition(ws.workspace)[0] == "deleted"


def test_an_unregistered_directory_is_refused(ws):
    other = ws.tmp / "other"
    other.mkdir()
    assert smoke.workspace_disposition(other)[0] == "refused"
    assert ws.deleted == []


def test_path_traversal_cannot_reach_another_directory(ws):
    other = ws.tmp / "other"
    other.mkdir()
    assert smoke.workspace_disposition(ws.workspace / ".." / "other")[0] == "refused"
    assert ws.deleted == []


def test_a_workspace_with_a_different_identity_is_refused(ws):
    smoke._OWNED[smoke._norm(ws.workspace)] = (1, 1)
    assert smoke.workspace_disposition(ws.workspace)[0] == "refused"
    assert ws.deleted == []


def test_a_symbolic_link_or_reparse_point_is_refused(ws, monkeypatch):
    real = smoke._lstat
    key = smoke._norm(ws.workspace)
    info = real(ws.workspace)

    def fake(path, *args, **kwargs):
        if smoke._norm(path) == key:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_dev=info.st_dev, st_ino=info.st_ino)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(smoke, "_lstat", fake)
    assert smoke.workspace_disposition(ws.workspace)[0] == "refused"
    assert ws.deleted == []


def test_the_repository_and_the_recovery_tree_are_refused_even_when_registered(ws):
    for protected in (smoke.REPO, Path(r"C:\AgentOps-Recovery") / "x"):
        smoke._OWNED[smoke._norm(protected)] = (1, 1)
        assert smoke.workspace_disposition(protected)[0] == "refused"
    assert ws.deleted == []


def test_the_retained_listing_never_hashes_the_environment_file(ws):
    lines = smoke.retained_workspace_lines(ws.workspace)
    text = "\n".join(lines)
    env_line = next(line for line in lines if "smoke.env" in line)
    assert "not hashed" in env_line and "sha256" not in env_line
    assert "run.log" in text and "sha256" in next(line for line in lines if "run.log" in line)
    assert "very-secret-test-value" not in text
    assert hashlib.sha256((ws.workspace / "smoke.env").read_bytes()).hexdigest()[:16] not in text


def test_the_retained_listing_does_not_follow_links_or_recurse(ws, monkeypatch):
    (ws.workspace / "venv").mkdir()
    (ws.workspace / "venv" / "inner.txt").write_text("x", encoding="utf-8")
    text = "\n".join(smoke.retained_workspace_lines(ws.workspace))
    assert "venv/" in text and "inner.txt" not in text


def stub_cleanup_steps(monkeypatch, **over):
    steps = dict(stop_registered_processes=lambda: [], _contained_docker_cleanup=lambda profiles: [],
                 _inventory_difference_problems=lambda: [], read_protected_snapshot=lambda: {},
                 recheck_approved_tree=lambda: [], repository_state=lambda: [],
                 bytecode_caches=lambda: frozenset())
    steps.update(over)
    for name, value in steps.items():
        monkeypatch.setattr(smoke, name, value)
    smoke.CONTAINED.protected_before = {}


def test_a_retained_windows_workspace_is_reported_and_is_not_a_cleanup_failure(ws, monkeypatch):
    ws.windows = True
    stub_cleanup_steps(monkeypatch)
    smoke.RUN.temp = ws.workspace
    outcome = smoke.cleanup_contained()
    assert outcome.verified and outcome.protected_ok and outcome.workspace_retained
    assert outcome.workspace_path == str(ws.workspace)
    assert (ws.workspace / "smoke.env").exists() and (ws.workspace / "run.log").exists()
    assert e2e.exit_code(True, outcome) == 0


@pytest.mark.parametrize("status", ["refused", "failed"])
def test_a_refused_or_failed_workspace_is_a_cleanup_failure(ws, monkeypatch, status):
    stub_cleanup_steps(monkeypatch)
    monkeypatch.setattr(smoke, "workspace_disposition", lambda path: (status, "because"))
    smoke.RUN.temp = ws.workspace
    outcome = smoke.cleanup_contained()
    assert not outcome.verified and status in outcome.problems[-1]
    assert e2e.exit_code(True, outcome) == 1


def test_a_workspace_disposition_that_raises_is_a_failure(ws, monkeypatch):
    stub_cleanup_steps(monkeypatch)

    def boom(path):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(smoke, "workspace_disposition", boom)
    smoke.RUN.temp = ws.workspace
    assert not smoke.cleanup_contained().verified


def test_a_masked_or_leaked_generated_password_is_a_cleanup_failure(ws, monkeypatch):
    ws.windows = True
    stub_cleanup_steps(monkeypatch)
    smoke.RUN.temp = ws.workspace
    smoke.RUN.generated = {"POSTGRES_PASSWORD": "leaked-value-1"}
    (ws.workspace / "run.log").write_text("oops leaked-value-1\n", encoding="utf-8")
    outcome = smoke.cleanup_contained()
    assert any("password" in problem for problem in outcome.problems)
    smoke.RUN.generated = {}
    (ws.workspace / "run.log").write_text("clean\n", encoding="utf-8")
    smoke.RUN.masked_in_logs = 1
    assert not smoke.cleanup_contained().verified


def windows_fake_run(*, sid="S-1-5-21-1-2-3", who_rc=0, icacls_rc=0, ps_lines=None, ps_rc=0):
    calls: list = []
    listed = ps_lines if ps_lines is not None else f"{sid}\nS-1-5-18\nS-1-5-32-544\n"

    def fake_run(command, *, timeout, cwd=None, env=None, what=""):
        calls.append(list(command))
        if command[0] == "whoami":
            return result(f'"HOST\\\\user","{sid}"\n', who_rc)
        if command[0] == "icacls":
            return result("", icacls_rc)
        if command[0] == "powershell":
            return result(listed, ps_rc)
        raise AssertionError(command)

    fake_run.calls = calls
    return fake_run


def test_windows_permissions_are_applied_then_verified_by_sid(monkeypatch, tmp_path):
    fake = windows_fake_run()
    monkeypatch.setattr(smoke, "run", fake)
    smoke.restrict_to_owner(tmp_path, directory=True, windows=True)
    icacls = next(c for c in fake.calls if c[0] == "icacls")
    assert "/inheritance:r" in icacls and "/grant:r" in icacls
    assert "*S-1-5-21-1-2-3:(OI)(CI)F" in icacls and "*S-1-5-18:(OI)(CI)F" in icacls
    smoke.restrict_to_owner(tmp_path / "f", directory=False, windows=True)
    assert "*S-1-5-21-1-2-3:F" in [c for c in fake.calls if c[0] == "icacls"][-1]


@pytest.mark.parametrize("kwargs", [
    dict(ps_lines="S-1-5-21-1-2-3\nS-1-1-0\n"),             # Everyone present
    dict(ps_lines="UNPROTECTED\nS-1-5-21-1-2-3\n"),         # inheritance still on
    dict(ps_lines=""),                                      # nothing listed
    dict(ps_rc=1),
    dict(icacls_rc=5),
    dict(who_rc=1),
    dict(sid="not-a-sid"),
])
def test_permissions_that_cannot_be_established_fail_closed(monkeypatch, tmp_path, kwargs):
    monkeypatch.setattr(smoke, "run", windows_fake_run(**kwargs))
    with pytest.raises(SmokeFailure):
        smoke.restrict_to_owner(tmp_path, directory=True, windows=True)


@pytest.fixture
def secured(monkeypatch, tmp_path, quiet):
    created = tmp_path / "agentops-d3-smoke-new"
    record = SimpleNamespace(restricted=[], created=created)

    def fake_mkdtemp(prefix=""):
        created.mkdir()
        return str(created)

    monkeypatch.setattr(smoke.tempfile, "mkdtemp", fake_mkdtemp)
    smoke.RUN.before = {"containers": [], "volumes": [], "networks": [], "images": []}
    return record


def test_the_directory_is_restricted_before_any_secret_is_written(monkeypatch, secured):
    def restrict(path, *, directory, windows=None):
        secured.restricted.append((Path(path).name, directory, (secured.created / "smoke.env").exists()))

    monkeypatch.setattr(smoke, "restrict_to_owner", restrict)
    smoke.create_workspace_secured()
    assert secured.restricted == [(secured.created.name, True, False), ("smoke.env", False, True)]
    assert smoke.RUN.temp == secured.created.resolve()
    assert smoke._norm(secured.created.resolve()) in smoke._OWNED
    assert smoke.RUN.env_file == secured.created.resolve() / "smoke.env"
    assert len(smoke.RUN.generated) == len(smoke.PASSWORD_VARIABLES)
    assert (secured.created / "smoke.env").read_text(encoding="utf-8").count("=") == len(smoke.PASSWORD_VARIABLES)


def test_a_directory_that_cannot_be_restricted_stops_before_any_secret_exists(monkeypatch, secured):
    def restrict(path, *, directory, windows=None):
        raise SmokeFailure("no permissions")

    monkeypatch.setattr(smoke, "restrict_to_owner", restrict)
    with pytest.raises(SmokeFailure, match="could not be restricted"):
        smoke.create_workspace_secured()
    assert smoke.RUN.temp is None and smoke.RUN.generated == {}
    assert not secured.created.exists()                       # only the empty directory was removed
    assert smoke._norm(secured.created.resolve()) not in smoke._OWNED


def test_an_environment_file_that_cannot_be_restricted_is_retained_not_deleted(monkeypatch, secured):
    def restrict(path, *, directory, windows=None):
        if not directory:
            raise SmokeFailure("no permissions")

    monkeypatch.setattr(smoke, "restrict_to_owner", restrict)
    with pytest.raises(SmokeFailure, match="environment file could not be restricted"):
        smoke.create_workspace_secured()
    assert (secured.created / "smoke.env").exists()


def test_a_workspace_inside_the_repository_is_refused(monkeypatch, secured):
    monkeypatch.setattr(smoke, "REPO", secured.created.parent)
    monkeypatch.setattr(smoke, "restrict_to_owner", lambda *a, **k: None)
    with pytest.raises(SmokeFailure, match="inside the repository"):
        smoke.create_workspace_secured()


# ======================================================================================================
# D. Docker containment
# ======================================================================================================

def container(service, suffix="1", *, project=P, name=None, mounts=None, mounts_ok=True):
    return {"id": f"id-{service}", "name": name or f"{P}-{service}-{suffix}",
            "labels": {LABEL: project, "com.docker.compose.service": service},
            "mounts": list(mounts or []), "mounts_ok": mounts_ok}


ANON_A, ANON_B, ANON_C, ANON_D = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)


def anon(name, destination):
    return {"name": name, "destination": destination, "anonymous": True}


def named(name, destination):
    return {"name": name, "destination": destination, "anonymous": False}


class World:
    """A fake Docker engine for the contained cleanup: it records every command it is given."""

    def __init__(self):
        self.commands: list[list[str]] = []
        self.containers = [container("kafka"), container("postgres"), container("otel-collector")]
        self.networks = [{"id": "n1", "name": f"{P}_agentops-net",
                          "labels": {LABEL: P, "com.docker.compose.network": "agentops-net"}}]
        self.volumes = [{"name": f"{P}_postgres-data",
                         "labels": {LABEL: P, "com.docker.compose.volume": "postgres-data"}}]
        self.images = [f"{P}-postgres:latest", f"{P}-db-bootstrap:latest"]
        self.down_rc = 0
        self.down_stderr = "boom"
        self.down_raises: BaseException | None = None
        self.image_remove_raises: dict[str, Exception] = {}
        #: what `docker volume ls -q` lists; a successful compose down removes the anonymous volumes attached to
        #: the containers it removes, unless down_removes_anonymous is False
        self.present_volumes: list[str] = []
        self.down_removes_anonymous = True
        self.volume_ls_raises: BaseException | None = None

    def inventory(self):
        return smoke.ProjectInventory(containers=list(self.containers), networks=list(self.networks),
                                      volumes=list(self.volumes), images=list(self.images))

    def run(self, command, *, timeout, cwd=None, env=None, what=""):
        self.commands.append(list(command))
        if command[:2] == ["docker", "compose"] and "down" in command:
            if self.down_raises is not None:
                raise self.down_raises
            if self.down_rc == 0:
                if self.down_removes_anonymous:
                    gone = {m["name"] for c in self.containers for m in c.get("mounts", []) if m.get("anonymous")}
                    self.present_volumes = [v for v in self.present_volumes if v not in gone]
                self.containers, self.networks, self.volumes = [], [], []
            return result("", self.down_rc, self.down_stderr if self.down_rc else "")
        if command == ["docker", "volume", "ls", "-q"]:
            if self.volume_ls_raises is not None:
                raise self.volume_ls_raises
            return result("".join(name + "\n" for name in self.present_volumes))
        if command[:3] == ["docker", "image", "remove"]:
            if command[3] in self.image_remove_raises:
                raise self.image_remove_raises[command[3]]
            self.images = [i for i in self.images if i != command[3]]
            return result()
        raise AssertionError(f"unexpected command {command}")

    def downs(self):
        return [c for c in self.commands if "down" in c]

    def removes(self):
        return [c for c in self.commands if c[:3] == ["docker", "image", "remove"]]


@pytest.fixture
def world(monkeypatch, tmp_path, quiet):
    fake = World()
    env = tmp_path / "smoke.env"
    env.write_text("X=1\n", encoding="utf-8")
    smoke.RUN.env_file, smoke.RUN.compose_used = env, True
    monkeypatch.setattr(smoke, "read_project_inventory", fake.inventory)
    monkeypatch.setattr(smoke, "run", fake.run)
    return fake


def test_owned_resources_are_removed_by_one_project_scoped_command(world):
    problems = smoke._contained_docker_cleanup(("analytics-refresh",))
    assert problems == []
    down = world.downs()[0]
    assert len(world.downs()) == 1
    assert down[:4] == ["docker", "compose", "-p", P]
    assert down[-3:] == ["down", "--volumes", "--remove-orphans"]
    assert "--profile" in down and "analytics-refresh" in down
    assert "--rmi" not in down
    assert [c[3] for c in world.removes()] == [f"{P}-postgres:latest", f"{P}-db-bootstrap:latest"]
    for command in world.removes():
        assert command == ["docker", "image", "remove", command[3]]      # by exact reference, never forced


@pytest.mark.parametrize("break_it", [
    lambda w: w.containers.append(container("kafka", project="someone-else")),
    lambda w: w.containers.append(container("kafka", name="agentops-mvp-workers-postgres-1")),
    lambda w: w.containers.append(container("rogue")),
    lambda w: w.networks.append({"id": "n2", "name": "agentops_default", "labels": {LABEL: P}}),
    lambda w: w.networks.append({"id": "n2", "name": f"{P}_x", "labels": {LABEL: "other"}}),
    lambda w: w.volumes.append({"name": "agentops-mvp-workers-postgres-data", "labels": {LABEL: P}}),
    lambda w: w.volumes.append({"name": f"{P}_x", "labels": {LABEL: P, "com.docker.compose.volume": "weird"}}),
])
def test_an_object_that_is_not_demonstrably_the_projects_stops_everything(world, break_it):
    break_it(world)
    problems = smoke._contained_docker_cleanup(())
    assert problems and "nothing was removed" in problems[0]
    assert world.commands == []


def test_an_image_carrying_the_label_but_not_the_projects_name_is_preserved(world):
    world.images.append("agentops-mvp-workers-postgres:latest")
    problems = smoke._contained_docker_cleanup(())
    assert any("agentops-mvp-workers-postgres" in p and "manual review" in p for p in problems)
    assert all(c[3] != "agentops-mvp-workers-postgres:latest" for c in world.removes())
    assert len(world.removes()) == 2


def test_a_failed_compose_down_removes_no_image_and_is_not_retried(world):
    world.down_rc = 1
    problems = smoke._contained_docker_cleanup(())
    assert any("compose down failed" in p for p in problems)
    assert len(world.downs()) == 1 and world.removes() == []
    assert any("remain" in p for p in problems)


def test_a_compose_timeout_leaves_everything_in_place_and_is_not_retried(world, monkeypatch):
    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=smoke._contained_docker_cleanup)
    world.down_raises = SmokeFailure("compose down: no result within 120 seconds")
    outcome = smoke.cleanup_contained()
    assert any("compose down did not complete" in p and "no result within 120 seconds" in p
               for p in outcome.problems)
    assert not outcome.verified
    assert len(world.downs()) == 1 and world.removes() == []
    assert world.containers                                      # nothing was removed


def test_an_unreadable_docker_state_removes_nothing(world, monkeypatch):
    def boom():
        raise SmokeFailure("docker ps: exit 1")

    monkeypatch.setattr(smoke, "read_project_inventory", boom)
    problems = smoke._contained_docker_cleanup(())
    assert problems and "nothing was removed" in problems[0]
    assert world.commands == []


def failing_listing(world, monkeypatch, *, fail_on: int, message: str = "docker ps: exit 1", exception=None):
    """read_project_inventory answering from the fake world, but raising on one numbered call:
    1 = the initial listing, 2 = the listing after compose down, 3 = the final verification listing."""
    calls = {"n": 0}

    def listing():
        calls["n"] += 1
        if calls["n"] == fail_on:
            raise exception if exception is not None else SmokeFailure(message)
        return world.inventory()

    monkeypatch.setattr(smoke, "read_project_inventory", listing)
    return calls


def test_a_failed_listing_after_compose_down_names_the_step_and_removes_nothing_more(world, monkeypatch):
    calls = failing_listing(world, monkeypatch, fail_on=2)
    problems = smoke._contained_docker_cleanup(())
    assert len(problems) == 1
    assert "the listing of the project's objects after compose down did not complete" in problems[0]
    assert "SmokeFailure: docker ps: exit 1" in problems[0] and "manual review" in problems[0]
    assert len(world.downs()) == 1 and world.removes() == []
    assert calls["n"] == 2                                              # no further listing was attempted
    assert all(command[:2] == ["docker", "compose"] for command in world.commands)   # only the one compose down


def test_a_failed_final_listing_is_a_failure_after_the_planned_removals_only(world, monkeypatch):
    calls = failing_listing(world, monkeypatch, fail_on=3, message="docker network ls: exit 1")
    problems = smoke._contained_docker_cleanup(())
    assert len(problems) == 1
    assert "the final verification listing of the project's objects did not complete" in problems[0]
    assert "docker network ls: exit 1" in problems[0]
    assert len(world.downs()) == 1 and len(world.removes()) == 2 and len(world.commands) == 3
    assert calls["n"] == 3


def test_a_failed_initial_listing_reports_the_step_and_the_type_and_removes_nothing(world, monkeypatch):
    failing_listing(world, monkeypatch, fail_on=1)
    problems = smoke._contained_docker_cleanup(())
    assert len(problems) == 1 and "initial listing" in problems[0]
    assert "SmokeFailure: docker ps: exit 1" in problems[0] and "nothing was removed" in problems[0]
    assert world.commands == []


def test_earlier_cleanup_errors_survive_a_later_inventory_failure(world, monkeypatch):
    world.down_rc = 1
    failing_listing(world, monkeypatch, fail_on=2)       # 1 = initial; 2 = final (no listing follows a failed down)
    problems = smoke._contained_docker_cleanup(())
    assert len(problems) == 2
    assert problems[0].startswith("compose down failed")
    assert "the final verification listing" in problems[1] and "SmokeFailure" in problems[1]
    assert world.removes() == [] and len(world.downs()) == 1


def test_an_unowned_image_error_survives_a_failed_image_removal_and_stops_further_removal(world):
    world.images = ["agentops-mvp-workers-postgres:latest", f"{P}-postgres:latest", f"{P}-db-bootstrap:latest"]
    world.image_remove_raises[f"{P}-postgres:latest"] = SmokeFailure(
        "docker image remove: no result within 60 seconds")
    problems = smoke._contained_docker_cleanup(())
    assert any("agentops-mvp-workers-postgres" in p and "manual review" in p for p in problems)
    failed = [p for p in problems if "did not complete" in p]
    assert len(failed) == 1 and f"the removal of image '{P}-postgres:latest'" in failed[0]
    assert "no result within 60 seconds" in failed[0]
    assert [command[3] for command in world.removes()] == [f"{P}-postgres:latest"]   # the next image is not attempted
    assert all(command[3] != "agentops-mvp-workers-postgres:latest" for command in world.removes())


def test_a_failed_inventory_check_makes_the_verdict_a_failure_without_a_retry(world, monkeypatch):
    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=smoke._contained_docker_cleanup)
    failing_listing(world, monkeypatch, fail_on=3)
    outcome = smoke.cleanup_contained(profiles=("analytics-refresh",))
    assert not outcome.verified and e2e.exit_code(True, outcome) == 1
    assert any("the final verification listing" in problem for problem in outcome.problems)
    assert len(world.downs()) == 1 and len(world.removes()) == 2          # no destructive operation was repeated


def test_the_failure_text_is_single_line_bounded_and_masks_generated_credentials():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": "pw-secret-123"}
    text = smoke._safe_failure_text(SmokeFailure("boom pw-secret-123\nsecond line\x07\x1b[31m" + "x" * 500))
    assert text.startswith("SmokeFailure: ")
    assert "pw-secret-123" not in text and "<redacted>" in text
    assert "\n" not in text and "\x07" not in text and "\x1b" not in text
    assert len(text) <= len("SmokeFailure: ") + 160
    assert smoke._safe_failure_text(SmokeFailure("")) == "SmokeFailure"
    assert smoke._safe_failure_text(OSError("disk")) == "OSError: disk"


def test_a_credential_in_a_docker_error_never_reaches_the_report(world, monkeypatch):
    smoke.RUN.generated = {"POSTGRES_PASSWORD": "pw-secret-123"}
    failing_listing(world, monkeypatch, fail_on=2, message="refused for pw-secret-123")
    problems = smoke._contained_docker_cleanup(())
    assert "pw-secret-123" not in " ".join(problems) and "<redacted>" in problems[0]


def test_the_generic_docker_handler_keeps_the_type_and_a_sanitized_message(quiet, monkeypatch):
    smoke.RUN.generated = {"POSTGRES_PASSWORD": "pw-secret-123"}

    def boom(profiles):
        raise RuntimeError("weird pw-secret-123")

    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=boom)
    outcome = smoke.cleanup_contained()
    text = " ".join(outcome.problems)
    assert "Docker cleanup could not be completed (RuntimeError: weird <redacted>)" in text
    assert "pw-secret-123" not in text and not outcome.verified


def test_the_inventory_comparison_handler_keeps_the_type_and_message(quiet, monkeypatch):
    def boom():
        raise SmokeFailure("docker ps: exit 1")

    stub_cleanup_steps(monkeypatch, _inventory_difference_problems=boom)
    outcome = smoke.cleanup_contained()
    assert any("the Docker inventory could not be compared (SmokeFailure: docker ps: exit 1)" in problem
               for problem in outcome.problems)
    assert not outcome.verified


PW1 = "Aq3-" + "x" * 28            # 32 characters, like the generated passwords
PW2 = "Zk9_" + "y" * 28


def leaked_fragments(text: str, secret: str, size: int = 8) -> list[str]:
    """Every run of `size` consecutive characters of the secret that appears in the text."""
    return [secret[i:i + size] for i in range(len(secret) - size + 1) if secret[i:i + size] in text]


def test_a_password_entirely_inside_the_retained_output_is_masked():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    text = "e" * 100 + PW1 + "f" * 100
    assert smoke.redact_tail(text, 300) == "e" * 100 + "<redacted>" + "f" * 100


def test_a_password_crossing_the_truncation_boundary_leaves_no_fragment():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    text = "a" * 200 + PW1 + "b" * 284                    # 516 characters: the old cut fell inside the password
    cut_first = smoke.redact(text.strip()[-300:])          # what the previous order produced
    assert leaked_fragments(cut_first, PW1)                # the scenario really does cross the boundary
    masked = smoke.redact_tail(text, 300)
    assert leaked_fragments(masked, PW1) == [] and PW1 not in masked
    assert masked == "a" * 6 + "<redacted>" + "b" * 284 and len(masked) == 300


def test_a_password_immediately_outside_the_retained_output_cannot_reappear():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    text = PW1 + "b" * 300
    masked = smoke.redact_tail(text, 300)
    assert masked == "b" * 300 and leaked_fragments(masked, PW1) == []


def test_a_password_just_inside_the_retained_output_is_masked():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    text = "a" * 100 + PW1 + "b" * 268                    # the old cut started exactly at the password
    masked = smoke.redact_tail(text, 300)
    assert leaked_fragments(masked, PW1) == [] and "<redacted>" in masked and len(masked) <= 300


def test_several_generated_passwords_are_all_masked_even_when_one_crosses_the_cut():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1, "GF_SECURITY_ADMIN_PASSWORD": PW2}
    text = "z" * 150 + PW2 + "m" * 60 + PW1 + "n" * 150 + PW2 + "k" * 100
    masked = smoke.redact_tail(text, 300)
    assert leaked_fragments(masked, PW1) == [] and leaked_fragments(masked, PW2) == []
    assert masked.count("<redacted>") >= 2 and len(masked) <= 300


def test_newlines_are_kept_secrets_are_masked_and_the_ends_are_stripped():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    text = "\n  line one\nline two " + PW1 + "\nline three\n\n"
    masked = smoke.redact_tail(text, 300)
    assert masked == "line one\nline two <redacted>\nline three"


def test_output_without_secrets_is_unchanged_apart_from_the_strip_and_the_bound():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    assert smoke.redact_tail("  plain diagnostic text \n", 300) == "plain diagnostic text"
    assert smoke.redact_tail("0123456789" * 100, 300) == ("0123456789" * 100)[-300:]
    assert smoke.redact_tail("short", 300) == "short"
    smoke.RUN.generated = {}
    assert smoke.redact_tail("nothing is known to mask", 5) == " mask"      # the last five characters, unmasked


def test_the_output_length_bound_is_preserved():
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    for limit in (1, 10, 300, 400):
        assert len(smoke.redact_tail("q" * 5000, limit)) == limit
        assert len(smoke.redact_tail(("q" * 7 + PW1) * 200, limit)) <= limit


def test_the_contained_compose_down_failure_masks_before_it_truncates(world):
    smoke.RUN.generated = {"POSTGRES_PASSWORD": PW1}
    world.down_rc = 1
    # 529 characters: the previous order cut at 229, inside the password (which starts at 213)
    world.down_stderr = "first\nsecond " + "a" * 200 + PW1 + "b" * 274 + "\nlast line"
    assert leaked_fragments(smoke.redact(world.down_stderr.strip()[-300:]), PW1)
    problems = smoke._contained_docker_cleanup(())
    failed = next(p for p in problems if p.startswith("compose down failed: "))
    assert leaked_fragments(failed, PW1) == [] and PW1 not in failed
    assert len(failed) <= len("compose down failed: ") + 300
    assert "<redacted>" in failed and "last line" in failed


def test_the_unknown_secret_limitation_is_documented_where_the_sanitizer_is_defined():
    assert "NOT masked" in smoke.redact.__doc__ and "generated" in smoke.redact.__doc__
    assert "BEFORE" in smoke.redact_tail.__doc__


def test_anonymous_volumes_of_a_verified_container_are_recorded_with_their_identity(world):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    smoke.track_project_identities("after Kafka")
    assert smoke.CONTAINED.tracked_anonymous == {
        ANON_A: {"container_id": "id-kafka", "container": f"{P}-kafka-1", "destination": "/etc/kafka/secrets"}}
    assert smoke.CONTAINED.uncertain_mounts == set()


def test_several_anonymous_mounts_across_containers_are_all_recorded(world):
    world.containers = [
        container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets"), anon(ANON_B, "/mnt/shared/config")]),
        container("kafka-init", mounts=[anon(ANON_C, "/etc/kafka/secrets"), anon(ANON_D, "/mnt/shared/config")]),
    ]
    assert smoke.record_anonymous_volumes(world.inventory()) == 4
    recorded = smoke.CONTAINED.tracked_anonymous
    assert set(recorded) == {ANON_A, ANON_B, ANON_C, ANON_D}
    assert recorded[ANON_C]["container"] == f"{P}-kafka-init-1" and recorded[ANON_B]["destination"] == "/mnt/shared/config"


def test_named_and_anonymous_volumes_are_distinguished(world):
    world.containers = [container("kafka", mounts=[named(f"{P}_kafka-data", "/var/lib/kafka/data"),
                                                   anon(ANON_A, "/etc/kafka/secrets")])]
    smoke.track_project_identities("after Kafka")
    assert set(smoke.CONTAINED.tracked_anonymous) == {ANON_A}
    assert f"{P}_kafka-data" not in smoke.CONTAINED.tracked_anonymous
    mounts, ok = smoke._volume_mounts([{"Type": "volume", "Name": "A" * 64, "Destination": "/x"},
                                       {"Type": "volume", "Name": "a" * 63, "Destination": "/y"}])
    assert ok and [m["anonymous"] for m in mounts] == [False, False]      # not 64 lowercase hexadecimal characters


def test_a_container_without_anonymous_mounts_records_nothing_and_needs_no_volume_listing(world):
    world.containers = [container("kafka", mounts=[named(f"{P}_kafka-data", "/var/lib/kafka/data")]),
                        container("postgres")]
    smoke.track_project_identities("after Kafka")
    assert smoke.CONTAINED.tracked_anonymous == {}
    assert smoke._contained_docker_cleanup(()) == []
    assert not any("volume" in command for command in world.commands)


@pytest.mark.parametrize("raw, expected_ok", [
    (None, True),
    ([], True),
    ([{"Type": "bind", "Source": "/x", "Destination": "/y"}, {"Type": "tmpfs", "Destination": "/tmp"}], True),
    ("not a list", False),
    ({"Type": "volume"}, False),
    ([42], False),
    ([{"Name": "x"}], False),
    ([{"Type": 5, "Name": "x"}], False),
    ([{"Type": "volume", "Destination": "/y"}], False),
    ([{"Type": "volume", "Name": "", "Destination": "/y"}], False),
    ([{"Type": "volume", "Name": "x", "Destination": None}], False),
])
def test_unexpected_mount_metadata_is_reported_as_unaccounted_for(raw, expected_ok):
    mounts, ok = smoke._volume_mounts(raw)
    assert ok is expected_ok
    assert mounts == []                      # none of these shapes yields a usable volume mount


def test_unexpected_mount_metadata_fails_the_cleanup_but_not_the_project_scoped_removal(world):
    world.containers = [container("kafka", mounts_ok=False), container("postgres")]
    problems = smoke._contained_docker_cleanup(())
    assert any("mount metadata had an unexpected shape" in p and f"{P}-kafka-1" in p and "manual review" in p
               for p in problems)
    assert len(world.downs()) == 1 and world.removes() == [f"docker image remove {P}-postgres:latest".split(),
                                                           f"docker image remove {P}-db-bootstrap:latest".split()]


def test_anonymous_mounts_of_a_container_that_fails_ownership_are_never_recorded(world):
    world.containers = [container("kafka", project="someone-else", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    with pytest.raises(SmokeFailure, match="ownership"):
        smoke.track_project_identities("after Kafka")
    assert smoke.CONTAINED.tracked_anonymous == {}
    problems = smoke._contained_docker_cleanup(())
    assert problems and "nothing was removed" in problems[0]
    assert smoke.CONTAINED.tracked_anonymous == {} and world.commands == []


def assert_no_direct_volume_removal(world):
    for command in world.commands:
        assert command[:3] not in (["docker", "volume", "rm"], ["docker", "volume", "remove"],
                                   ["docker", "volume", "prune"])
        assert command[:2] != ["docker", "system"]
        if command[:2] == ["docker", "volume"]:
            assert command == ["docker", "volume", "ls", "-q"]          # the only volume command: a listing
        assert "--rmi" not in command


def test_an_anonymous_volume_that_remains_after_cleanup_fails_it_with_identity_evidence(world):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets"),
                                                   anon(ANON_B, "/mnt/shared/config")])]
    world.present_volumes = [ANON_A, ANON_B]
    world.down_removes_anonymous = False
    assert smoke.CONTAINED.tracked_anonymous == {}                     # nothing was recorded at a checkpoint
    problems = smoke._contained_docker_cleanup(())
    remaining = [p for p in problems if p.startswith("anonymous volume ")]
    assert len(remaining) == 2
    assert f"anonymous volume {ANON_A} (attached to container {P}-kafka-1, mounted at /etc/kafka/secrets) " \
           "still exists after cleanup; left for manual review" in remaining
    assert ANON_B in remaining[1] and "/mnt/shared/config" in remaining[1]
    assert world.present_volumes == [ANON_A, ANON_B]                   # preserved, never removed by the harness
    assert len(world.downs()) == 1 and ["docker", "volume", "ls", "-q"] in world.commands
    assert_no_direct_volume_removal(world)


def test_an_anonymous_volume_removed_by_the_project_scoped_cleanup_is_not_a_problem(world, quiet):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    world.present_volumes = [ANON_A]
    assert smoke._contained_docker_cleanup(()) == []
    assert world.present_volumes == []
    assert any("anonymous volume aaaaaaaaaaaa" in line and "removed with its container" in line for line in quiet)
    assert_no_direct_volume_removal(world)


def test_an_unknown_volume_is_preserved_and_never_named_in_a_command(world):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    world.present_volumes = [ANON_A, ANON_D]                           # ANON_D was never attached to a verified container
    assert smoke._contained_docker_cleanup(()) == []                   # only recorded volumes are accounted for
    assert world.present_volumes == [ANON_D]
    assert not any(ANON_D in " ".join(command) for command in world.commands)
    assert_no_direct_volume_removal(world)


def test_no_cleanup_success_verdict_while_a_recorded_anonymous_volume_remains(world, monkeypatch):
    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=smoke._contained_docker_cleanup)
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    world.present_volumes = [ANON_A]
    world.down_removes_anonymous = False
    outcome = smoke.cleanup_contained(profiles=("analytics-refresh",))
    assert not outcome.verified and e2e.exit_code(True, outcome) == 1
    assert any(p.startswith(f"anonymous volume {ANON_A}") for p in outcome.problems)
    assert_no_direct_volume_removal(world)


def test_a_failed_compose_down_keeps_both_its_error_and_the_remaining_anonymous_volume(world):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    world.present_volumes = [ANON_A]
    world.down_rc = 1
    problems = smoke._contained_docker_cleanup(())
    assert problems[0].startswith("compose down failed") and any(p.startswith("anonymous volume ") for p in problems)
    assert len(world.downs()) == 1 and world.removes() == []
    assert_no_direct_volume_removal(world)


def test_a_failed_volume_listing_is_reported_with_the_recorded_identities(world):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    world.volume_ls_raises = SmokeFailure("docker volume ls: exit 1")
    problems = smoke._contained_docker_cleanup(())
    assert any("the verification of the recorded anonymous volumes did not complete" in p
               and "SmokeFailure: docker volume ls: exit 1" in p for p in problems)
    assert any("recorded anonymous volume(s) were not verified and may remain" in p and ANON_A in p
               and f"{P}-kafka-1" in p for p in problems)
    assert_no_direct_volume_removal(world)


def test_recorded_anonymous_volumes_are_listed_when_the_initial_listing_fails(world, monkeypatch):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    smoke.track_project_identities("after Kafka")                      # recorded while the container exists
    failing_listing(world, monkeypatch, fail_on=1)
    problems = smoke._contained_docker_cleanup(())
    assert "nothing was removed" in problems[0] and ANON_A in problems[-1] and "were not verified" in problems[-1]
    assert world.commands == []


def test_the_anonymous_volume_helpers_contain_no_docker_command_and_no_removal_verb():
    for function in (smoke._volume_mounts, smoke.record_anonymous_volumes, smoke.anonymous_volume_problems,
                     smoke._unverified_anonymous_volumes):
        source = inspect.getsource(function)
        for needle in ("run(", "docker_lines(", "checked(", "subprocess", "prune", "volume rm", "--force", "--rmi"):
            assert needle not in source, (function.__name__, needle)
    verify = inspect.getsource(smoke._contained_docker_cleanup)
    assert '"volume", "ls", "-q"' in verify and '"volume", "rm"' not in verify and "prune" not in verify


def test_objects_without_a_compose_environment_file_are_left_alone(world):
    smoke.RUN.env_file = None
    problems = smoke._contained_docker_cleanup(())
    assert problems and "nothing was removed" in problems[0] and world.commands == []


def test_pre_existing_project_objects_are_not_removed_by_a_run_that_created_nothing(world):
    smoke.RUN.compose_used = False
    problems = smoke._contained_docker_cleanup(())
    assert problems and world.commands == []


def test_a_project_name_that_is_not_disposable_is_refused(world, monkeypatch):
    monkeypatch.setattr(smoke, "PROJECT", "agentops")
    problems = smoke._contained_docker_cleanup(())
    assert problems and world.commands == []


def test_an_empty_project_needs_no_command(world):
    world.containers, world.networks, world.volumes, world.images = [], [], [], []
    assert smoke._contained_docker_cleanup(()) == []
    assert world.commands == []


def test_identity_tracking_records_what_was_created_and_stops_on_a_mismatch(monkeypatch, quiet):
    fake = World()
    monkeypatch.setattr(smoke, "read_project_inventory", fake.inventory)
    smoke.track_project_identities("after Kafka")
    assert smoke.CONTAINED.tracked_containers == {"id-kafka", "id-postgres", "id-otel-collector"}
    assert smoke.CONTAINED.tracked_networks == {"n1"} and f"{P}_postgres-data" in smoke.CONTAINED.tracked_volumes
    assert f"{P}-postgres:latest" in smoke.CONTAINED.tracked_images
    fake.containers.append(container("rogue"))
    with pytest.raises(SmokeFailure, match="ownership"):
        smoke.track_project_identities("after the database")


def fingerprint(**kinds):
    base = {"containers": ["c1 agentops-mvp-workers-postgres-1 running"], "volumes": ["agentops-mvp-workers-postgres-data"],
            "networks": ["n1 agentops-mvp-workers-net"], "images": ["agentops-mvp-workers-postgres:latest i1"]}
    base.update(kinds)
    return base


def test_inventory_differences_are_reported_and_never_acted_on(monkeypatch, quiet):
    smoke.RUN.before = fingerprint()
    monkeypatch.setattr(smoke, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no removal")))
    monkeypatch.setattr(smoke, "docker_fingerprint", lambda: fingerprint(
        volumes=["agentops-mvp-workers-postgres-data", "unrelated-new-volume"],
        images=["agentops-mvp-workers-postgres:latest i1", "newly-built-image:latest i9"]))
    assert smoke._inventory_difference_problems() == []
    assert any("NOT touched" in line and "unrelated-new-volume" in line for line in quiet)
    assert any("NOT touched" in line and "newly-built-image" in line for line in quiet)


def test_an_existing_object_that_vanished_or_changed_is_a_problem(monkeypatch, quiet):
    smoke.RUN.before = fingerprint()
    monkeypatch.setattr(smoke, "docker_fingerprint", lambda: fingerprint(
        containers=["c1 agentops-mvp-workers-postgres-1 exited"], volumes=[]))
    problems = smoke._inventory_difference_problems()
    assert any("containers" in p for p in problems) and any("volumes" in p for p in problems)


def test_a_project_object_still_present_after_cleanup_is_a_problem(monkeypatch, quiet):
    smoke.RUN.before = fingerprint()
    monkeypatch.setattr(smoke, "docker_fingerprint", lambda: fingerprint(
        volumes=["agentops-mvp-workers-postgres-data", f"{P}_kafka-data"]))
    assert any("remain" in p for p in smoke._inventory_difference_problems())


def test_without_a_recorded_inventory_nothing_is_compared(quiet):
    smoke.RUN.before = None
    assert smoke._inventory_difference_problems() == []


def test_protected_resources_must_be_exactly_as_they_were():
    before = {"container a": "1", "volume b": "2"}
    assert smoke.protected_problems(before, dict(before)) == []
    changed = smoke.protected_problems(before, {"container a": "9", "volume b": "2"})
    assert changed == ["protected resource changed: container a"]
    assert smoke.protected_problems(before, {"container a": "1"}) == ["protected resource changed: volume b"]
    assert smoke.protected_problems(None, before)


def test_a_changed_protected_resource_fails_and_no_command_names_a_protected_object(world, monkeypatch):
    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=smoke._contained_docker_cleanup,
                       read_protected_snapshot=lambda: {"container agentops-postgres": "changed"})
    smoke.CONTAINED.protected_before = {"container agentops-postgres": "original"}
    outcome = smoke.cleanup_contained()
    assert not outcome.protected_ok and e2e.exit_code(True, outcome) == 1
    flat = " ".join(" ".join(c) for c in world.commands)
    for name in smoke.PROTECTED_CONTAINER_NAMES + smoke.PROTECTED_VOLUME_NAMES:
        assert name not in flat


def test_the_protected_snapshot_reads_state_and_marks_absent_objects(monkeypatch):
    present = json.dumps([{"Id": "abc" * 20, "State": {"Status": "running", "Health": {"Status": "healthy"},
                                                       "StartedAt": "t0", "FinishedAt": "t1"},
                           "RestartCount": 0, "Mounts": [{"Name": "vol", "Destination": "/data"}],
                           "NetworkSettings": {"Ports": {}}}])

    def fake_run(command, *, timeout, cwd=None, env=None, what=""):
        if command[:2] == ["docker", "inspect"] and command[-1] == "agentops-mvp-workers-postgres-1":
            return result(present)
        if command[:3] == ["docker", "volume", "inspect"] and command[-1] == "agentops-mvp-workers-postgres-data":
            return result(json.dumps([{"CreatedAt": "created"}]))
        return result("", 1)

    monkeypatch.setattr(smoke, "run", fake_run)
    monkeypatch.setattr(smoke, "docker_lines", lambda *args: ["agentops-mvp-workers-postgres-1"])
    snapshot = smoke.read_protected_snapshot()
    assert "running" in snapshot["container agentops-mvp-workers-postgres-1"]
    assert "healthy" in snapshot["container agentops-mvp-workers-postgres-1"]
    assert snapshot["container agentops-postgres"] == "absent"
    assert snapshot["volume agentops-mvp-workers-postgres-data"].startswith("created|attached")


def test_the_project_inventory_is_read_by_exact_label_and_parsed_from_inspect(monkeypatch):
    commands: list = []

    def fake_run(command, *, timeout, cwd=None, env=None, what=""):
        commands.append(list(command))
        selector = f"label={LABEL}={P}"
        if command[:2] == ["docker", "ps"]:
            assert selector in command
            return result("c1\n")
        if command[:2] == ["docker", "inspect"]:
            return result(json.dumps([{"Id": "c1full", "Name": f"/{P}-kafka-1",
                                       "Config": {"Labels": {LABEL: P, "com.docker.compose.service": "kafka"}}}]))
        if command[:3] == ["docker", "network", "ls"]:
            return result("n1\n")
        if command[:3] == ["docker", "network", "inspect"]:
            return result(json.dumps([{"Id": "n1", "Name": f"{P}_agentops-net", "Labels": {LABEL: P}}]))
        if command[:3] == ["docker", "volume", "ls"]:
            return result("")
        if command[:2] == ["docker", "images"]:
            return result(f"{P}-postgres:latest\n")
        raise AssertionError(command)

    monkeypatch.setattr(smoke, "run", fake_run)
    inventory = smoke.read_project_inventory()
    assert inventory.containers[0]["name"] == f"{P}-kafka-1" and inventory.images == [f"{P}-postgres:latest"]
    assert inventory.networks[0]["id"] == "n1" and inventory.volumes == []
    assert all(command[0] == "docker" and command[1] in ("ps", "inspect", "network", "volume", "images")
               for command in commands)


def test_a_docker_listing_that_cannot_be_parsed_is_an_error(monkeypatch):
    monkeypatch.setattr(smoke, "run", lambda command, **k: result("c1\n") if command[1] == "ps"
                        else result("not json"))
    with pytest.raises(SmokeFailure, match="could not be parsed"):
        smoke.read_project_inventory()


def test_the_new_cleanup_contains_no_broad_or_inventory_driven_removal():
    for function in (smoke._contained_docker_cleanup, smoke.cleanup_contained, smoke._inventory_difference_problems,
                     smoke.stop_registered_processes, smoke._terminate_one, smoke.read_project_inventory):
        source = inspect.getsource(function)
        assert "--rmi" not in source
        assert "prune" not in source
        assert "volume rm" not in source and '"volume", "rm"' not in source
        assert '"image", "rm"' not in source and "image rm" not in source
        assert "--force" not in source


def test_the_e2e_main_uses_the_contained_cleanup_and_not_the_shared_one():
    source = inspect.getsource(e2e.main)
    assert "cleanup_contained" in source
    assert "smoke.cleanup()" not in source and "remove_profile_resources" not in source


# ======================================================================================================
# P. Host processes
# ======================================================================================================

class FakeProcess:
    def __init__(self, pid, args, returncode=None, wait_timeouts=0, interrupt=False):
        self.pid, self.args, self.returncode = pid, args, returncode
        self.events: list = []
        self._timeouts = wait_timeouts
        self._interrupt = interrupt

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append("terminate")

    def kill(self):
        self.events.append("kill")

    def wait(self, timeout=None):
        self.events.append(("wait", timeout))
        if self._interrupt:
            raise KeyboardInterrupt()
        if self._timeouts > 0:
            self._timeouts -= 1
            raise subprocess.TimeoutExpired("cmd", timeout)
        self.returncode = 0
        return 0


PY = Path("venv") / "python.exe"


@pytest.fixture
def procs(monkeypatch, quiet):
    state = SimpleNamespace(taskkills=[])
    monkeypatch.setattr(smoke, "_windows", lambda: True)
    monkeypatch.setattr(smoke, "_taskkill", lambda command, **k: state.taskkills.append(list(command)))
    smoke.RUN.python = PY
    return state


def own(name="stream-processor", pid=4242, **kw):
    smoke.RUN.processes[name] = FakeProcess(pid, [str(PY), "main.py"], **kw)
    return smoke.RUN.processes[name]


def test_a_verified_process_is_stopped_with_the_exact_pid_on_windows(procs):
    process = own()
    assert smoke.stop_registered_processes() == []
    assert procs.taskkills == [["taskkill", "/PID", "4242", "/T", "/F"]]
    assert ("wait", 15.0) in process.events


def test_a_process_that_already_exited_is_left_alone(procs):
    own(returncode=0)
    assert smoke.stop_registered_processes() == []
    assert procs.taskkills == []


@pytest.mark.parametrize("name", ["sshd", "storage-consumer-2", ""])
def test_a_process_this_harness_does_not_start_is_never_terminated(procs, name):
    own(name)
    problems = smoke.stop_registered_processes()
    assert problems and "left running" in problems[0] and procs.taskkills == []


def test_a_process_with_another_command_line_is_never_terminated(procs):
    smoke.RUN.processes["stream-processor"] = FakeProcess(4242, ["notepad.exe"])
    problems = smoke.stop_registered_processes()
    assert problems and procs.taskkills == []


@pytest.mark.parametrize("pid", [0, -5, None, True, "42"])
def test_an_invalid_pid_is_never_terminated(procs, pid):
    own(pid=pid)
    assert smoke.stop_registered_processes() and procs.taskkills == []


def test_without_a_recorded_interpreter_nothing_is_terminated(procs):
    own()
    smoke.RUN.python = None
    assert smoke.stop_registered_processes() and procs.taskkills == []


def test_a_process_that_does_not_stop_is_reported_and_not_escalated_on_windows(procs):
    process = own(wait_timeouts=1)
    problems = smoke.stop_registered_processes()
    assert problems and "manual review" in problems[0]
    assert len(procs.taskkills) == 1 and "kill" not in process.events


def test_a_failing_taskkill_is_reported(procs, monkeypatch):
    def boom(command, **kwargs):
        raise OSError("not found")

    monkeypatch.setattr(smoke, "_taskkill", boom)
    own()
    assert smoke.stop_registered_processes()


def test_elsewhere_the_process_is_terminated_then_killed_once_if_needed(procs, monkeypatch):
    monkeypatch.setattr(smoke, "_windows", lambda: False)
    process = own(wait_timeouts=1)
    assert smoke.stop_registered_processes() == []
    assert process.events[0] == "terminate" and process.events.count("kill") == 1
    second = own("storage-consumer", 77, wait_timeouts=2)
    problems = smoke.stop_registered_processes()
    assert any("storage-consumer" in p for p in problems) and second.events.count("kill") == 1


# ======================================================================================================
# F. Failure paths and the four-part result
# ======================================================================================================

@pytest.fixture
def cli(monkeypatch):
    state = SimpleNamespace(cleanups=0, outcome=smoke.CleanupOutcome())
    monkeypatch.setattr(e2e, "configure_harness", lambda: None)
    monkeypatch.setattr(e2e, "_python_supported", lambda: True)

    def cleanup(**kwargs):
        state.cleanups += 1
        assert kwargs == {"profiles": (e2e.REFRESH_PROFILE,)}
        if isinstance(state.outcome, BaseException):
            raise state.outcome
        return state.outcome

    monkeypatch.setattr(smoke, "cleanup_contained", cleanup)
    state.argv = ["--execute", "--expect-head", H, "--confirm", e2e.confirmation_phrase(H)]
    return state


def run_cli(monkeypatch, cli, behaviour):
    monkeypatch.setattr(e2e, "e2e", behaviour)
    return e2e.main(cli.argv)


def test_an_accepted_workload_with_a_verified_cleanup_exits_zero(monkeypatch, cli, capsys):
    assert run_cli(monkeypatch, cli, lambda *a: None) == 0
    out = capsys.readouterr().out
    assert "workload acceptance: PASSED" in out
    assert "docker and process cleanup verified: yes" in out
    assert "workspace retained: no" in out
    assert "protected resources unchanged: yes" in out


def test_an_intentionally_retained_workspace_does_not_fail_a_successful_run(monkeypatch, cli, capsys):
    cli.outcome = smoke.CleanupOutcome(workspace_status="retained_by_policy", workspace_path="C:/tmp/x",
                                       workspace_reason="Windows policy")
    assert run_cli(monkeypatch, cli, lambda *a: None) == 0
    out = capsys.readouterr().out
    assert "workspace retained: yes, by policy (C:/tmp/x)" in out
    assert "cleanup verified: yes" in out


def test_a_genuine_cleanup_failure_exits_nonzero(monkeypatch, cli, capsys):
    cli.outcome = smoke.CleanupOutcome(problems=["2 project volumes remain"])
    assert run_cli(monkeypatch, cli, lambda *a: None) == 1
    out = capsys.readouterr().out
    assert "CLEANUP PROBLEM: 2 project volumes remain" in out
    assert "workload acceptance: PASSED" in out and "cleanup verified: NO" in out


def test_a_changed_protected_resource_exits_nonzero(monkeypatch, cli, capsys):
    cli.outcome = smoke.CleanupOutcome(protected_problems=["protected resource changed: container x"])
    assert run_cli(monkeypatch, cli, lambda *a: None) == 1
    assert "protected resources unchanged: NO" in capsys.readouterr().out


@pytest.mark.parametrize("workspace", ["refused", "failed"])
def test_a_refused_or_failed_workspace_is_shown_as_a_failure(monkeypatch, cli, capsys, workspace):
    cli.outcome = smoke.CleanupOutcome(problems=[f"the temporary workspace is {workspace}: x"],
                                       workspace_status=workspace, workspace_reason="x")
    assert run_cli(monkeypatch, cli, lambda *a: None) == 1
    assert f"workspace retained: NO - {workspace}" in capsys.readouterr().out


@pytest.mark.parametrize("failure", [
    SmokeFailure("worker process exited with code 1"),
    SmokeFailure("generator: no result within 150 seconds"),             # a timeout
    KeyboardInterrupt(),
    RuntimeError("unexpected"),
])
def test_every_failure_path_still_runs_the_contained_cleanup_once(monkeypatch, cli, capsys, failure):
    def behaviour(*args):
        raise failure

    assert run_cli(monkeypatch, cli, behaviour) == 1
    assert cli.cleanups == 1
    assert "workload acceptance: FAILED" in capsys.readouterr().out


def test_a_partial_startup_is_cleaned_up_with_the_same_policy(monkeypatch, cli, capsys):
    started: list = []

    def behaviour(*args):
        started.append("kafka")
        raise SmokeFailure("postgres: not reached within 90 seconds")

    assert run_cli(monkeypatch, cli, behaviour) == 1
    assert started == ["kafka"] and cli.cleanups == 1


def test_a_cleanup_that_itself_raises_is_a_failure_not_a_crash(monkeypatch, cli, capsys):
    cli.outcome = RuntimeError("boom")
    assert run_cli(monkeypatch, cli, lambda *a: None) == 1
    assert "CLEANUP PROBLEM" in capsys.readouterr().out


def test_the_approved_manifest_is_passed_to_the_run_and_the_state_is_reset(monkeypatch, cli, tmp_path, repo):
    path, digest = write_manifest(tmp_path, [])
    seen: dict = {}

    def behaviour(expect_head, approved=None):
        seen.update(head=expect_head, approved=approved)

    smoke.CONTAINED.tracked_containers.add("stale")
    cli.argv += ["--approved-tree", str(path), "--approved-tree-sha256", digest]
    assert run_cli(monkeypatch, cli, behaviour) == 0
    assert seen["head"] == H and seen["approved"].head == H
    assert "stale" not in smoke.CONTAINED.tracked_containers


def test_a_change_made_to_the_repository_during_the_run_is_a_cleanup_failure(monkeypatch, ws, repo, approved):
    stub_cleanup_steps(monkeypatch, recheck_approved_tree=smoke.recheck_approved_tree)
    smoke.CONTAINED.approved = approved
    (repo / "a.py").write_text("print('edited while running')\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "git", good_git())
    ws.windows = True
    smoke.RUN.temp = ws.workspace
    outcome = smoke.cleanup_contained()
    assert any("no longer matches" in p for p in outcome.problems)


def test_a_run_that_stopped_before_anything_was_created_has_nothing_to_compare(ws, monkeypatch):
    stub_cleanup_steps(monkeypatch)
    smoke.CONTAINED.protected_before = None
    outcome = smoke.cleanup_contained()
    assert outcome.protected_ok and outcome.notes
    smoke.RUN.compose_used = True
    assert not smoke.cleanup_contained().protected_ok


def test_the_result_lines_report_four_independent_parts():
    lines = e2e.result_lines(True, smoke.CleanupOutcome(workspace_status="retained_by_policy",
                                                        workspace_path="p", workspace_reason="r"))
    assert [line.split(":")[0] for line in lines] == [
        "workload acceptance", "docker and process cleanup verified", "workspace retained",
        "protected resources unchanged"]


# ======================================================================================================
# S. Interruption-safe cleanup (a second Ctrl-C during cleanup)
# ======================================================================================================

def test_an_interrupt_before_cleanup_starts_still_runs_the_contained_cleanup_once(monkeypatch, cli, capsys):
    def behaviour(*args):
        raise KeyboardInterrupt()

    assert run_cli(monkeypatch, cli, behaviour) == 1
    out = capsys.readouterr().out
    assert cli.cleanups == 1 and "workload acceptance: FAILED" in out and "cleanup interrupted" not in out


def test_an_interrupt_during_project_scoped_cleanup_ends_it_without_a_retry(world, monkeypatch, quiet):
    world.containers = [container("kafka", mounts=[anon(ANON_A, "/etc/kafka/secrets")])]
    world.present_volumes = [ANON_A]
    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=smoke._contained_docker_cleanup,
                       stop_registered_processes=lambda: ["earlier process problem"])
    later: list[str] = []
    monkeypatch.setattr(smoke, "_inventory_difference_problems", lambda: later.append("compared") or [])
    monkeypatch.setattr(smoke, "workspace_disposition", lambda path: later.append("workspace") or ("deleted", ""))
    world.down_raises = KeyboardInterrupt()
    outcome = smoke.cleanup_contained(profiles=("analytics-refresh",))
    assert outcome.interrupted and not outcome.verified
    assert outcome.problems[0] == "earlier process problem"                       # kept, and still first
    assert any("cleanup was interrupted during compose down" in p and "manual review" in p for p in outcome.problems)
    assert any("recorded anonymous volume(s) were not verified" in p and ANON_A in p for p in outcome.problems)
    assert len(world.downs()) == 1 and world.removes() == []                     # no retry, nothing more removed
    assert later == []                                                           # no step after the interrupted one
    assert smoke.CONTAINED.interrupted == "compose down" and not outcome.protected_ok
    assert e2e.exit_code(True, outcome) == 130
    assert any("cleanup was INTERRUPTED" in line for line in quiet)
    assert any(f"anonymous volume {ANON_A}" in line and f"{P}-kafka-1" in line for line in quiet)   # identity evidence
    assert_no_direct_volume_removal(world)


def test_an_interrupt_during_inventory_verification_keeps_earlier_problems_and_stops(world, monkeypatch):
    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=smoke._contained_docker_cleanup)
    world.images = ["agentops-mvp-workers-postgres:latest", f"{P}-postgres:latest"]   # one preserved-image problem first
    failing_listing(world, monkeypatch, fail_on=3, exception=KeyboardInterrupt())
    outcome = smoke.cleanup_contained()
    assert outcome.interrupted and not outcome.verified
    assert any("agentops-mvp-workers-postgres" in p and "manual review" in p for p in outcome.problems)
    assert any("cleanup was interrupted during the final verification listing of the project's objects" in p
               for p in outcome.problems)
    assert len(world.downs()) == 1 and len(world.removes()) == 1
    assert smoke.CONTAINED.interrupted == "the final verification listing of the project's objects"


def test_an_interrupt_in_the_inventory_comparison_is_caught_by_the_wrapper_and_stops_the_rest(monkeypatch, quiet):
    reached: list[str] = []

    def interrupted():
        raise KeyboardInterrupt()

    stub_cleanup_steps(monkeypatch, _contained_docker_cleanup=lambda profiles: ["docker problem"],
                       _inventory_difference_problems=interrupted)
    monkeypatch.setattr(smoke, "workspace_disposition", lambda path: reached.append("workspace") or ("deleted", ""))
    monkeypatch.setattr(smoke, "recheck_approved_tree", lambda: reached.append("repository") or [])
    outcome = smoke.cleanup_contained()
    assert outcome.interrupted and outcome.problems[0] == "docker problem"
    assert any("cleanup was interrupted during the Docker inventory comparison" in p for p in outcome.problems)
    assert reached == [] and not outcome.protected_ok
    assert smoke.CONTAINED.interrupted == "the Docker inventory comparison"


def test_an_interrupt_after_the_protected_check_does_not_claim_it_was_skipped(monkeypatch, quiet):
    def interrupted(path):
        raise KeyboardInterrupt()

    stub_cleanup_steps(monkeypatch)
    monkeypatch.setattr(smoke, "workspace_disposition", interrupted)
    outcome = smoke.cleanup_contained()
    assert outcome.interrupted and outcome.protected_ok          # the protected comparison had already completed
    assert any("interrupted during the temporary workspace disposition" in p for p in outcome.problems)
    assert not outcome.verified


def test_an_interrupt_while_stopping_a_process_is_recorded_and_the_others_are_left_alone(procs):
    own("stream-processor", 4242, interrupt=True)
    second = own("storage-consumer", 77)
    problems = smoke.stop_registered_processes()
    assert smoke.CONTAINED.interrupted == "stopping the host process stream-processor"
    assert "interrupted while it was being stopped (pid 4242)" in problems[0] and "manual review" in problems[0]
    assert problems[1].startswith("storage-consumer: not stopped because cleanup was interrupted")
    assert procs.taskkills == [["taskkill", "/PID", "4242", "/T", "/F"]]         # nothing was attempted on the second
    assert second.events == []


def test_an_interrupt_during_process_termination_stops_every_later_cleanup_step(procs, monkeypatch):
    ran: list[str] = []
    stub_cleanup_steps(monkeypatch, stop_registered_processes=smoke.stop_registered_processes,
                       _contained_docker_cleanup=lambda profiles: ran.append("docker") or [])
    own(interrupt=True)
    outcome = smoke.cleanup_contained()
    assert outcome.interrupted and ran == []
    assert any("interrupted while it was being stopped" in p and "manual review" in p for p in outcome.problems)
    assert not outcome.verified and not outcome.protected_ok and e2e.exit_code(True, outcome) == 130


def test_an_interrupted_outcome_is_never_reported_as_a_success():
    outcome = smoke.CleanupOutcome(interrupted=True)               # even with no recorded problem
    assert not outcome.verified and e2e.exit_code(True, outcome) == 130
    lines = e2e.result_lines(True, outcome)
    assert "docker and process cleanup verified: NO" in lines
    assert lines[-1].startswith("cleanup interrupted: YES") and len(lines) == 5
    assert not any("verified: yes" in line for line in lines)
    assert len(e2e.result_lines(True, smoke.CleanupOutcome())) == 4  # an ordinary outcome keeps its four lines


def test_an_interrupt_outside_cleanup_contained_is_reported_and_exits_130(monkeypatch, cli, capsys):
    cli.outcome = KeyboardInterrupt()
    assert run_cli(monkeypatch, cli, lambda *a: None) == 130
    out = capsys.readouterr().out
    assert "CLEANUP PROBLEM: cleanup was interrupted before it could report" in out
    assert "docker and process cleanup verified: NO" in out and "cleanup interrupted: YES" in out
    assert "protected resources unchanged: NO" in out and "verified: yes" not in out
    assert cli.cleanups == 1                                       # the interrupted cleanup is not run again


def test_an_interrupted_outcome_returned_by_cleanup_contained_exits_130_even_after_an_accepted_workload(
        monkeypatch, cli, capsys):
    cli.outcome = smoke.CleanupOutcome(problems=["cleanup was interrupted during compose down"], interrupted=True)
    assert run_cli(monkeypatch, cli, lambda *a: None) == 130
    out = capsys.readouterr().out
    assert "workload acceptance: PASSED" in out and "cleanup interrupted: YES" in out and "verified: NO" in out


def test_interrupt_handling_is_narrow_and_adds_no_second_removal_path():
    for function in (smoke.cleanup_contained, smoke._run_cleanup_steps, smoke._contained_docker_cleanup,
                     smoke.stop_registered_processes, e2e.main):
        source = inspect.getsource(function)
        assert "BaseException" not in source, function.__name__
    assert "except KeyboardInterrupt" in inspect.getsource(smoke.cleanup_contained)
    docker_source = inspect.getsource(smoke._contained_docker_cleanup)
    assert docker_source.count('"down"') == 1 and docker_source.count('"image", "remove"') == 1


# ======================================================================================================
# L. The legacy run_smoke.py entry point cannot start live work
# ======================================================================================================

@pytest.fixture
def nothing_may_start(monkeypatch):
    reached: list[str] = []

    def boom(name):
        def function(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"{name} must not be reached by the standalone entry point")
        return function

    for name in ("run", "git", "smoke", "cleanup", "check_repository", "check_ports", "record_docker_state",
                 "create_workspace", "create_workspace_secured", "create_virtual_environment", "check_render",
                 "start_kafka", "start_postgres", "start_collector", "start_host_services", "run_resource_gate",
                 "cleanup_contained", "stop_host_processes"):
        monkeypatch.setattr(smoke, name, boom(name))
    monkeypatch.setattr(smoke.subprocess, "Popen", boom("subprocess.Popen"))
    return reached


def test_direct_invocation_without_arguments_refuses_and_starts_nothing(nothing_may_start, capsys):
    assert smoke.main([]) == 2
    captured = capsys.readouterr()
    assert "no longer starts live work" in captured.err and "run_e2e.py" in captured.err
    assert "Nothing was started" in captured.err and captured.out == ""
    assert nothing_may_start == []


@pytest.mark.parametrize("argv", [["--expect-head", H], ["--expect-head", OTHER], ["--expect-head", "not-a-commit"]])
def test_direct_invocation_with_the_legacy_argument_refuses_and_starts_nothing(nothing_may_start, capsys, argv):
    assert smoke.main(argv) == 2
    assert "Nothing was started" in capsys.readouterr().err
    assert nothing_may_start == []


@pytest.mark.parametrize("argv", [["--execute"], ["--confirm", "x"], ["--live"], ["--approved-tree", "m.json"], ["extra"]])
def test_an_option_the_old_command_never_had_is_an_error_and_starts_nothing(nothing_may_start, argv):
    with pytest.raises(SystemExit) as stop:
        smoke.main(argv)
    assert stop.value.code == 2
    assert nothing_may_start == []


def test_help_starts_nothing(nothing_may_start, capsys):
    with pytest.raises(SystemExit) as stop:
        smoke.main(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())            # argparse wraps by terminal width
    assert stop.value.code == 0 and "starts nothing" in help_text
    assert nothing_may_start == []


def test_the_standalone_path_reaches_no_docker_command_resource_gate_or_manifest_check(nothing_may_start):
    smoke.main([])
    for forbidden_step in ("run", "git", "run_resource_gate", "check_repository", "record_docker_state", "smoke"):
        assert forbidden_step not in nothing_may_start
    tree = ast.parse(inspect.getsource(smoke.main))
    called = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert called <= {"argparse.ArgumentParser", "parser.add_argument", "parser.parse_args", "print"}, called


def test_the_standalone_entry_point_offers_no_live_flag_and_does_not_delegate():
    source = inspect.getsource(smoke.main)
    tree = ast.parse(source)
    options = [node.args[0].value for node in ast.walk(tree)
               if isinstance(node, ast.Call) and ast.unparse(node.func) == "parser.add_argument"]
    assert options == ["--expect-head"]
    # it names run_e2e.py in its help text, but it neither imports nor calls it
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree))
    references = ({node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
                  | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)})
    assert not any("e2e" in reference for reference in references)


def test_the_refusal_names_every_requirement_of_the_authorized_path():
    text = smoke.STANDALONE_REFUSAL
    for needle in ("run_e2e.py", "--execute", "--expect-head", "--confirm", "approved-tree manifest",
                   "resource preflight", "Nothing was started"):
        assert needle in text, needle


def test_the_module_still_runs_main_when_executed_and_main_never_starts_work():
    tree = ast.parse(Path(smoke.__file__).read_text(encoding="utf-8"))
    last = tree.body[-1]
    assert isinstance(last, ast.If) and ast.unparse(last.test) == "__name__ == '__main__'"
    assert [ast.unparse(statement) for statement in last.body] == ["sys.exit(main())"]


def test_the_helpers_imported_by_the_benchmark_runner_and_siblings_remain_callable():
    for name in ("smoke", "cleanup", "check_repository", "check_ports", "record_docker_state", "create_workspace",
                 "create_virtual_environment", "check_render", "start_kafka", "create_topics", "start_postgres",
                 "run_bootstrap", "start_collector", "start_host_services", "check_baseline", "run_stage",
                 "check_totals", "check_normal_stack", "stop_host_processes", "docker_fingerprint", "compose_command",
                 "register_workspace", "repository_state", "bytecode_caches", "_remove_tree", "psql", "run", "checked"):
        assert callable(getattr(smoke, name)), name


def test_run_e2e_remains_the_authorized_entry_point(monkeypatch, capsys):
    monkeypatch.setattr(smoke, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no command")))
    assert e2e.main([]) == 0
    out = capsys.readouterr().out
    assert "NOTHING WAS RUN" in out and "--execute" in out and "--confirm" in out
    with pytest.raises(SystemExit) as stop:
        e2e.main(["--execute"])                                        # still needs the head and the phrase
    assert stop.value.code == 2


# ======================================================================================================
# I. The architectural file inventory in test_cli.py stays exact
# ======================================================================================================

_CLI_TEST = _HERE / "tests" / "unit" / "test_cli.py"
_VERIFIED_INVENTORY_ADDITIONS = (
    "PHASE-14.5-FAILURE-RECOVERY.md",
    "run_viewer_sql_it.py",
    "tests/unit/test_viewer_sql_it.py",
    "tests/unit/test_smoke_cleanup_containment.py",
    "tests/unit/test_e2e_preflight_remediation.py",
)


def _cli_guard():
    tree = ast.parse(_CLI_TEST.read_text(encoding="utf-8"))
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name == "test_the_component_holds_only_code_and_tests")
    assertion = next(node for node in ast.walk(function) if isinstance(node, ast.Assert))
    return function, assertion


def _cli_inventory() -> list[str]:
    _, assertion = _cli_guard()
    assert isinstance(assertion.test, ast.Compare) and isinstance(assertion.test.comparators[0], ast.List)
    return [element.value for element in assertion.test.comparators[0].elts]


def test_the_inventory_guard_is_still_an_exact_equality_against_a_literal_list():
    function, assertion = _cli_guard()
    compare = assertion.test
    assert isinstance(compare, ast.Compare) and len(compare.ops) == 1 and isinstance(compare.ops[0], ast.Eq)
    assert isinstance(compare.left, ast.Name) and compare.left.id == "files"
    used = ({node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
            | {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)})
    assert not used & {"fnmatch", "glob", "startswith", "endswith", "any", "all", "issubset", "match", "search"}
    exclusions = {node.left.value for node in ast.walk(function)
                  if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.NotIn)
                  and isinstance(node.left, ast.Constant)}
    assert exclusions == {"__pycache__", ".pytest_cache"}


def test_the_inventory_is_sorted_unique_and_free_of_patterns():
    inventory = _cli_inventory()
    assert inventory == sorted(inventory) and len(inventory) == len(set(inventory))
    for item in inventory:
        assert not any(character in item for character in "*?[]{}\\")
        assert not item.startswith("/") and ".." not in item.split("/")


def test_the_five_verified_files_are_listed_and_each_exists():
    inventory = _cli_inventory()
    for relative in _VERIFIED_INVENTORY_ADDITIONS:
        assert relative in inventory, relative
        assert (_HERE / relative).is_file(), relative


def test_every_listed_file_exists():
    assert [item for item in _cli_inventory() if not (_HERE / item).is_file()] == []


def _component_listing(root: Path) -> list[str]:
    """The listing rule of the guard, applied to a fake component tree."""
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*")
                  if path.is_file() and "__pycache__" not in path.parts and ".pytest_cache" not in path.parts)


def test_an_unexpected_or_missing_file_is_rejected_by_the_exact_comparison(tmp_path):
    inventory = _cli_inventory()
    for relative in inventory:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("", encoding="utf-8")
    assert _component_listing(tmp_path) == inventory
    cache = tmp_path / "workload_generator" / "__pycache__"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "cli.cpython-313.pyc").write_bytes(b"")
    assert _component_listing(tmp_path) == inventory                  # only caches are ignored
    surprise = tmp_path / "tests" / "unit" / "test_surprise.py"
    surprise.write_text("", encoding="utf-8")
    assert _component_listing(tmp_path) != inventory                  # an unexpected file is rejected
    surprise.unlink()
    (tmp_path / inventory[0]).unlink()
    assert _component_listing(tmp_path) != inventory                  # a missing file is rejected


# ======================================================================================================
# C. Compatibility with the unchanged shared interfaces
# ======================================================================================================

def test_the_shared_cleanup_and_deletion_guard_are_unchanged():
    source = inspect.getsource(smoke.cleanup)
    assert '"--rmi", "local"' in source and '"image", "rm"' in source and '"volume", "rm"' in source
    assert "_remove_tree(RUN.temp)" in source
    guard = inspect.getsource(smoke._remove_tree)
    assert "automatic recursive deletion is disabled on Windows" in guard and "_rmtree(path" in guard


def test_check_repository_stays_call_compatible():
    signature = inspect.signature(smoke.check_repository)
    assert list(signature.parameters) == ["expect_head", "approved"]
    assert signature.parameters["approved"].default is None


def test_the_names_the_benchmark_runner_and_sibling_harnesses_use_still_exist():
    for name in ("cleanup", "_remove_tree", "register_workspace", "stop_host_processes", "create_workspace",
                 "repository_state", "bytecode_caches", "docker_fingerprint", "compose_command",
                 "check_normal_stack", "ALLOWED_UNTRACKED", "RUN"):
        assert hasattr(smoke, name), name
    for name in ("remove_profile_resources", "build_refresh_image", "ledger_fingerprint", "refresh_command",
                 "run_detector", "configure_harness", "refresh_analytics", "STAGES"):
        assert hasattr(e2e, name), name


def test_no_new_absolute_protected_path_or_secret_literal_was_added():
    for function in (smoke.restrict_to_owner, smoke.create_workspace_secured, smoke.workspace_disposition,
                     smoke._contained_docker_cleanup, smoke.cleanup_contained, e2e.plan_text, e2e.main):
        source = inspect.getsource(function)
        assert "AgentOps-Recovery" not in source
        assert "C:\\Users" not in source


# ======================================================================================================
# Q. Docker engine identity and required protected resources (Phase 14.7, Step 3)
# ======================================================================================================

ENGINE_ID = "14136b17-759d-4fa3-b3a8-51411d61f7d8"
ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine"
PG_ID, VIEWER_ID, PIPE_ID = "5" * 64, "9" * 64, "7" * 64
PIN = smoke.EnginePin(
    context="desktop-linux", endpoint=ENDPOINT, engine_id=ENGINE_ID,
    required_containers=(("pg", PG_ID, "pg-data"), ("viewer", VIEWER_ID, ""), ("pipe", PIPE_ID, "pipe-data")),
    required_volumes=("pg-data", "pipe-data", "other"))
#: What make_sources() reports for the engine is 4 GiB; the VM agrees and has room.
GOOD_VM = lambda: {"total_mib": 4096.0, "available_mib": 4000.0}  # noqa: E731


class FakeEngine:
    """A fake Docker client for the identity and protected-resource checks; it records every command."""

    def __init__(self):
        self.commands: list[list[str]] = []
        self.context, self.endpoint, self.engine_id = "desktop-linux", ENDPOINT, ENGINE_ID
        self.containers = {PG_ID: ("pg", ["pg-data"]), VIEWER_ID: ("viewer", []), PIPE_ID: ("pipe", ["pipe-data"])}
        self.volumes = {"pg-data", "pipe-data", "other"}
        self.fail_on: str | None = None          # a command word that raises (a timeout)
        self.raw: dict[str, str] = {}            # replacement stdout: "context", "container"
        self.id_override: dict[str, str] = {}

    def run(self, command, *, timeout, cwd=None, env=None, what=""):
        self.commands.append(list(command))
        if self.fail_on is not None and self.fail_on in command:
            raise SmokeFailure(f"{what}: no result within {timeout:.0f} seconds")
        if command == ["docker", "context", "show"]:
            return result(self.context + "\n")
        if command[:3] == ["docker", "context", "inspect"]:
            return result(self.raw.get("context") or json.dumps(
                [{"Name": command[3], "Endpoints": {"docker": {"Host": self.endpoint}}}]))
        if command[:2] == ["docker", "info"]:
            return result(self.engine_id + "\n")
        if command[:4] == ["docker", "inspect", "--type", "container"]:
            if command[4] not in self.containers:
                return result("", 1, "Error: No such container")
            if "container" in self.raw:
                return result(self.raw["container"])
            name, volumes = self.containers[command[4]]
            return result(json.dumps([{"Id": self.id_override.get(command[4], command[4]), "Name": "/" + name,
                                       "Mounts": [{"Type": "volume", "Name": v} for v in volumes]}]))
        if command[:3] == ["docker", "volume", "inspect"]:
            return result("[{}]") if command[3] in self.volumes else result("", 1, "Error: No such volume")
        raise AssertionError(f"unexpected command {command}")


@pytest.fixture
def engine(monkeypatch, quiet):
    fake = FakeEngine()
    monkeypatch.setattr(smoke, "run", fake.run)
    for name in smoke.ENGINE_SELECTOR_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    return fake


@pytest.mark.parametrize("name", smoke.ENGINE_SELECTOR_VARIABLES)
def test_every_selector_variable_is_reported_by_name_and_never_by_value(name):
    problems = smoke.engine_selector_problems({name.lower(): "secret-value", "PATH": "x"})
    assert problems == [f"{name} is set"]
    assert "secret-value" not in " ".join(problems)


def test_no_selector_variable_is_no_problem():
    assert smoke.engine_selector_problems({"PATH": "x", "DOCKER_BUILDKIT": "1"}) == []


def test_the_approved_engine_is_accepted_with_read_only_commands(engine):
    smoke.verify_engine_identity(PIN)
    assert [c[:3] for c in engine.commands] == [["docker", "context", "show"], ["docker", "context", "inspect"],
                                                 ["docker", "info", "--format"]]


@pytest.mark.parametrize("change, message", [
    (lambda f: setattr(f, "context", "default"), "active Docker context"),
    (lambda f: setattr(f, "endpoint", "npipe:////./pipe/other"), "not the approved endpoint"),
    (lambda f: setattr(f, "engine_id", "0" * 36), "engine id"),
    (lambda f: f.raw.update(context="not json"), "context could not be read"),
    (lambda f: f.raw.update(context="[]"), "context could not be read"),
    (lambda f: f.raw.update(context='[{"Endpoints": {}}]'), "context could not be read"),
])
def test_a_wrong_or_unreadable_engine_is_rejected(engine, change, message):
    change(engine)
    with pytest.raises(SmokeFailure, match=message):
        smoke.verify_engine_identity(PIN)


@pytest.mark.parametrize("word", ["show", "inspect", "info"])
def test_a_docker_command_that_cannot_complete_fails_closed(engine, word):
    engine.fail_on = word
    with pytest.raises(SmokeFailure, match="no result within"):
        smoke.verify_engine_identity(PIN)


def test_a_selector_variable_stops_the_check_before_any_docker_command(engine, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    with pytest.raises(SmokeFailure, match="redirected by the environment") as caught:
        smoke.verify_engine_identity(PIN)
    assert "2375" not in str(caught.value) and engine.commands == []


def test_the_required_protected_resources_are_accepted(engine):
    smoke.verify_required_protected(PIN)


@pytest.mark.parametrize("change", [
    lambda f: f.containers.pop(VIEWER_ID),                                    # missing
    lambda f: f.id_override.update({PG_ID: "0" * 64}),                         # a different full id
    lambda f: f.containers.update({PG_ID: ("pg", ["pg-data", "extra"])}),      # an extra attachment
    lambda f: f.containers.update({PG_ID: ("pg", [])}),                        # attachment gone
    lambda f: f.containers.update({VIEWER_ID: ("viewer", ["pg-data"])}),       # attachment that should not exist
    lambda f: f.containers.update({PIPE_ID: ("other-name", ["pipe-data"])}),   # a different name
    lambda f: f.volumes.discard("other"),                                      # a missing protected volume
    lambda f: f.raw.update(container="not json"),                              # unreadable
    lambda f: f.raw.update(container="[]"),
])
def test_a_missing_changed_or_unreadable_protected_resource_is_a_failure(engine, change):
    change(engine)
    with pytest.raises(SmokeFailure):
        smoke.verify_required_protected(PIN)


def test_the_gate_verifies_the_engine_before_it_reads_anything(engine, monkeypatch):
    engine.engine_id = "0" * 36
    monkeypatch.setattr(smoke, "read_gate_readings", lambda s: (_ for _ in ()).throw(AssertionError("read")))
    with pytest.raises(SmokeFailure, match="engine id"):
        smoke.run_resource_gate(make_sources(), pin=PIN)
    assert smoke.CONTAINED.engine_pin is None


def test_the_gate_with_an_approved_engine_still_applies_every_resource_threshold(engine):
    smoke.run_resource_gate(make_sources(vm_memory=GOOD_VM), pin=PIN)
    assert smoke.CONTAINED.engine_pin is PIN
    for field_name in ("wmi_available_mib", "counters"):
        low = {"wmi_available_mib": lambda: 4095.0,
               "counters": lambda: {"pages_per_second": [0.0] * 12, "available_mib": 4095.0,
                                    "committed_percent": 40.0, "paging_file_percent": 2.0}}[field_name]
        with pytest.raises(SmokeFailure, match="available memory"):
            smoke.run_resource_gate(make_sources(vm_memory=GOOD_VM, **{field_name: low}), pin=PIN)


def test_the_gate_without_a_pin_is_unchanged_and_runs_no_docker_command(engine):
    smoke.run_resource_gate(make_sources())
    assert engine.commands == [] and smoke.CONTAINED.engine_pin is None


def test_protected_resources_are_verified_before_the_snapshot_is_taken(engine, monkeypatch):
    monkeypatch.setattr(smoke, "read_protected_snapshot", lambda: (_ for _ in ()).throw(AssertionError("read")))
    engine.containers.pop(PG_ID)
    with pytest.raises(SmokeFailure):
        smoke.record_protected_state(pin=PIN)
    assert smoke.CONTAINED.protected_before is None


def test_a_verified_protected_state_is_recorded_with_the_pin(engine, monkeypatch):
    monkeypatch.setattr(smoke, "read_protected_snapshot", lambda: {"container a": "present"})
    smoke.record_protected_state(pin=PIN)
    assert smoke.CONTAINED.protected_before == {"container a": "present"} and smoke.CONTAINED.engine_pin is PIN


def test_recording_the_protected_state_without_a_pin_is_unchanged(engine, monkeypatch):
    monkeypatch.setattr(smoke, "read_protected_snapshot", lambda: {"container a": "present"})
    smoke.record_protected_state()
    assert engine.commands == [] and smoke.CONTAINED.protected_before == {"container a": "present"}


def test_cleanup_removes_nothing_when_the_engine_cannot_be_verified(engine, monkeypatch):
    monkeypatch.setattr(smoke, "read_project_inventory", lambda: (_ for _ in ()).throw(AssertionError("listed")))
    smoke.CONTAINED.engine_pin = PIN
    engine.engine_id = "0" * 36
    problems = smoke._contained_docker_cleanup(())
    assert len(problems) == 1 and "could not be verified before cleanup" in problems[0]
    assert "nothing was removed" in problems[0]
    assert all(command[:2] in (["docker", "context"], ["docker", "info"]) for command in engine.commands)


def test_cleanup_without_a_pin_does_not_verify_the_engine(engine, monkeypatch):
    monkeypatch.setattr(smoke, "read_project_inventory", lambda: (_ for _ in ()).throw(SmokeFailure("stop")))
    problems = smoke._contained_docker_cleanup(())
    assert "initial listing" in problems[0] and engine.commands == []


def test_a_new_run_starts_without_the_pin():
    smoke.CONTAINED.engine_pin = PIN
    smoke.CONTAINED.reset()
    assert smoke.CONTAINED.engine_pin is None


def test_the_pinned_engine_is_the_approved_one():
    pin = e2e.PINNED_ENGINE
    assert (pin.context, pin.endpoint, pin.engine_id) == ("desktop-linux", ENDPOINT, ENGINE_ID)
    assert [(n, i, v) for n, i, v in pin.required_containers] == [
        ("agentops-mvp-workers-postgres-1", "509fe585c0591886047a869f198fe47d4a2b36dda9eb10a90195d50d9fdd51a4",
         "agentops-mvp-workers-postgres-data"),
        ("agentops-mvp-workers-viewer-1", "94774118be5faad84f24f01fc33f44ca49c55bf8317b19da43b318a882b4710e", ""),
        ("agentops-pipetest-postgres-1", "57ac9ee8ff8bc234ef0c1cecce146b91cf50158e0db53d04ce2365304f510ca8",
         "agentops-pipetest-pgdata")]
    assert pin.required_volumes == smoke.PROTECTED_VOLUME_NAMES and len(pin.required_volumes) == 4


def test_e2e_and_preflight_pass_the_pin_to_the_gate_and_the_protected_state(monkeypatch):
    record: list = []
    _record_steps(monkeypatch, record, gate_fails=False, stop_after="create_workspace_secured")
    seen: list = []
    monkeypatch.setattr(smoke, "run_resource_gate", lambda *a, **k: (record.append("gate"), seen.append(k)))
    monkeypatch.setattr(smoke, "record_protected_state",
                        lambda *a, **k: (record.append("record_protected_state"), seen.append(k)))
    with pytest.raises(SmokeFailure, match="stop here"):
        e2e.e2e(H)
    assert seen == [{"pin": e2e.PINNED_ENGINE}, {"pin": e2e.PINNED_ENGINE}]
    assert record[:2] == ["repository", "gate"]
    seen.clear()
    assert e2e.preflight_only(H, None) == 0 and seen == [{"pin": e2e.PINNED_ENGINE}]


def test_the_plan_names_the_pinned_engine_and_still_holds_no_secret():
    text = e2e.plan_text(H)
    assert "Docker engine        pinned: context desktop-linux, engine id " + ENGINE_ID in text
    assert "3 protected containers and 4 protected volumes" in text


# ======================================================================================================
# Q2. Step 3B: a fresh engine verification before every mutation, and the Docker VM's available memory
# ======================================================================================================

COMPOSE = ["docker", "compose", "-p", P, "-f", "docker-compose.yml", "-f", "override.yml", "--env-file", "smoke.env"]
MUTATIONS = [
    COMPOSE + ["up", "-d", "kafka"], COMPOSE + ["up", "-d", "--no-build", "postgres"],
    COMPOSE + ["build", "postgres"], COMPOSE + ["--profile", "analytics-refresh", "build", "analytics-refresh"],
    COMPOSE + ["--profile", "analytics-refresh", "run", "--rm", "-T", "analytics-refresh"],
    COMPOSE + ["--profile", "analytics-refresh", "down", "--volumes", "--remove-orphans"],
    ["docker", "image", "remove", f"{P}-postgres:latest"], ["docker", "image", "rm", "abc"], ["docker", "rmi", "abc"],
]
READS = [
    COMPOSE + ["ps", "-a", "-q", "kafka"], COMPOSE + ["config", "--quiet"], COMPOSE + ["logs", "--no-color", "kafka"],
    COMPOSE + ["exec", "-T", "kafka", "/opt/kafka/bin/kafka-topics.sh", "--list"],
    ["docker", "ps", "-a", "-q"], ["docker", "inspect", "x"], ["docker", "volume", "ls", "-q"],
    ["docker", "network", "ls"], ["docker", "images"], ["docker", "info", "--format", "{{.MemTotal}}"],
    ["git", "status"], ["wsl", "-d", "docker-desktop", "-e", "cat", "/proc/meminfo"],
]
VERIFY = [["docker", "context", "show"], ["docker", "context", "inspect"], ["docker", "info"]]


class FakeSystem:
    """Stands in for subprocess.run inside run_smoke, so the REAL smoke.run is exercised.  It records, in order,
    every command that would reach the operating system and answers the verification commands like the engine."""

    def __init__(self):
        self.sent: list[list[str]] = []
        self.engine = FakeEngine()
        self.timeout_on: str | None = None

    def __call__(self, command, **kwargs):
        self.sent.append(list(command))
        if self.timeout_on is not None and self.timeout_on in command:
            raise subprocess.TimeoutExpired(command, 1)
        if command[:2] in (["docker", "context"], ["docker", "info"]):
            return self.engine.run(command, timeout=kwargs.get("timeout", 0))
        return result("ok")


@pytest.fixture
def system(monkeypatch):
    fake = FakeSystem()
    monkeypatch.setattr(smoke.subprocess, "run", fake)
    for name in smoke.ENGINE_SELECTOR_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    return fake


def _send(command):
    return smoke.run(command, timeout=5, what="a command")


def test_the_mutation_classification_is_exact():
    assert all(smoke.is_engine_mutation(command) for command in MUTATIONS)
    assert not any(smoke.is_engine_mutation(command) for command in READS)
    assert smoke.is_engine_mutation([]) is False


@pytest.mark.parametrize("command", MUTATIONS)
def test_every_mutation_is_preceded_by_one_fresh_verification_and_then_sent_once(system, command):
    smoke.CONTAINED.engine_pin = PIN
    _send(command)
    assert [c[:3] for c in system.sent[:3]] == VERIFY[:2] + [["docker", "info", "--format"]]
    assert system.sent[3] == command and len(system.sent) == 4


@pytest.mark.parametrize("command", READS)
def test_a_read_only_command_is_sent_without_a_verification(system, command):
    smoke.CONTAINED.engine_pin = PIN
    _send(command)
    assert system.sent == [command]


@pytest.mark.parametrize("command", MUTATIONS)
def test_without_a_pin_nothing_is_verified_and_the_command_is_sent_unchanged(system, command):
    _send(command)
    assert system.sent == [command]


def test_each_mutation_is_verified_again_and_the_results_are_not_reused(system):
    smoke.CONTAINED.engine_pin = PIN
    _send(MUTATIONS[0])
    _send(MUTATIONS[1])
    assert len(system.sent) == 8 and system.sent[3] == MUTATIONS[0] and system.sent[7] == MUTATIONS[1]
    system.engine.engine_id = "0" * 36                    # the engine changes between two mutations
    with pytest.raises(SmokeFailure, match="engine id"):
        _send(MUTATIONS[2])
    assert MUTATIONS[2] not in system.sent


@pytest.mark.parametrize("break_it, message", [
    (lambda s: setattr(s.engine, "engine_id", "0" * 36), "engine id"),
    (lambda s: setattr(s.engine, "context", "default"), "active Docker context"),
    (lambda s: setattr(s.engine, "endpoint", "npipe:////./pipe/other"), "approved endpoint"),
    (lambda s: s.engine.raw.update(context="not json"), "context could not be read"),
])
@pytest.mark.parametrize("command", [MUTATIONS[0], MUTATIONS[5], MUTATIONS[6]])
def test_a_failed_verification_stops_the_mutation_before_it_is_sent(system, break_it, message, command):
    smoke.CONTAINED.engine_pin = PIN
    break_it(system)
    with pytest.raises(SmokeFailure, match=message):
        _send(command)
    assert command not in system.sent


@pytest.mark.parametrize("word", ["show", "inspect", "info"])
def test_a_verification_that_times_out_stops_the_mutation(system, word):
    smoke.CONTAINED.engine_pin = PIN
    system.timeout_on = word
    with pytest.raises(SmokeFailure, match="no result within"):
        _send(MUTATIONS[0])
    assert MUTATIONS[0] not in system.sent


@pytest.mark.parametrize("name", smoke.ENGINE_SELECTOR_VARIABLES)
def test_a_selector_variable_stops_the_mutation_before_anything_is_sent(system, monkeypatch, name):
    smoke.CONTAINED.engine_pin = PIN
    monkeypatch.setenv(name, "x")
    with pytest.raises(SmokeFailure, match="redirected by the environment"):
        _send(MUTATIONS[5])
    assert system.sent == []


def test_the_verification_does_not_recurse_into_the_mutation_check():
    for function in (smoke.verify_engine_identity, smoke.engine_selector_problems):
        source = inspect.getsource(function)
        assert "is_engine_mutation" not in source and "compose_command" not in source
    assert not smoke.is_engine_mutation(["docker", "context", "show"])
    assert not smoke.is_engine_mutation(["docker", "context", "inspect", "desktop-linux"])
    assert not smoke.is_engine_mutation(["docker", "info", "--format", "{{.ID}}"])


# -- the Docker VM's available memory --------------------------------------------------------------------------

MEMINFO = ("MemTotal:        5036656 kB\nMemFree:         2877000 kB\nMemAvailable:    4183060 kB\n"
           "SwapTotal:       2097152 kB\nSwapFree:        2096928 kB\n")
ENGINE_BYTES = 5157535744


def test_the_gate_constants_are_the_approved_ones_and_no_host_threshold_was_lowered():
    assert smoke.GATE_MIN_VM_AVAILABLE_MIB == 3584 and smoke.GATE_VM_TOTAL_TOLERANCE == 0.05
    assert smoke.GATE_MIN_AVAILABLE_MIB == 4096 and smoke.GATE_MIN_ENGINE_BYTES == 3584 * 1024 ** 2
    assert smoke.GATE_MIN_FREE_DISK_GIB == 20 and smoke.GATE_MAX_COMMITTED_PERCENT == 70.0
    assert smoke.GATE_MAX_PAGING_FILE_PERCENT == 5.0


def test_meminfo_total_and_available_are_read_and_swap_is_ignored():
    assert smoke.parse_vm_meminfo(MEMINFO) == {"total_mib": 5036656 / 1024, "available_mib": 4183060 / 1024}
    assert smoke.parse_vm_meminfo(MEMINFO.replace("\n", "\r\n")) is not None


@pytest.mark.parametrize("text", [
    "", "garbage", "MemTotal: 5036656 kB\n", "MemAvailable: 4183060 kB\n",
    "MemTotal: x kB\nMemAvailable: 4 kB\n", "MemTotal: 5 MB\nMemAvailable: 4 MB\n",
    "MemTotal: 5 kB\nMemTotal: 6 kB\nMemAvailable: 4 kB\n", "memtotal: 5 kB\nmemavailable: 4 kB\n",
    "SwapTotal: 2097152 kB\nSwapFree: 2096928 kB\n",
])
def test_an_unreliable_meminfo_is_rejected(text):
    assert smoke.parse_vm_meminfo(text) is None


def test_the_vm_reader_runs_one_read_only_command_without_a_shell(monkeypatch):
    sent: list = []
    monkeypatch.setattr(smoke, "run", lambda command, **k: (sent.append(list(command)), result(MEMINFO))[1])
    assert smoke._read_vm_memory()["available_mib"] == 4183060 / 1024
    assert sent == [["wsl", "-d", "docker-desktop", "-e", "cat", "/proc/meminfo"]]


def test_a_failed_or_failing_vm_read_is_an_unreadable_reading(monkeypatch):
    monkeypatch.setattr(smoke, "run", lambda command, **k: result("", 1, "no distro"))
    assert smoke._read_vm_memory() is None
    monkeypatch.setattr(smoke, "run", lambda command, **k: (_ for _ in ()).throw(SmokeFailure("no result")))
    assert smoke._attempt(smoke._read_vm_memory) is None


def test_a_vm_with_room_that_agrees_with_the_engine_has_no_problem():
    assert smoke.vm_memory_problems(4918.4, 4085.0, ENGINE_BYTES) == []


@pytest.mark.parametrize("available, ok", [(3584.0, True), (3584.5, True), (3583.99, False), (0.0, False)])
def test_the_available_memory_boundary_is_3584_mib(available, ok):
    problems = smoke.vm_memory_problems(4918.0, available, ENGINE_BYTES)
    assert (problems == []) is ok
    if not ok:
        assert "available memory" in problems[0] and "swap is not counted" in problems[0]


@pytest.mark.parametrize("total, ok", [(4918.0, True), (4918.0 * 1.04, True), (4918.0 * 0.96, True),
                                       (4918.0 * 1.06, False), (4918.0 * 0.94, False), (2459.0, False)])
def test_the_vm_total_must_agree_with_the_engine_within_five_percent(total, ok):
    problems = smoke.vm_memory_problems(total, 3600.0, ENGINE_BYTES)
    assert (problems == []) is ok
    if not ok:
        assert "does not match" in problems[0]


@pytest.mark.parametrize("total, available, engine", [
    (None, 4000.0, ENGINE_BYTES), (4918.0, None, ENGINE_BYTES), (4918.0, 4000.0, None), ("x", 4000.0, ENGINE_BYTES),
    (4918.0, True, ENGINE_BYTES), (-1.0, 4000.0, ENGINE_BYTES), (float("nan"), 4000.0, ENGINE_BYTES),
    (4918.0, float("inf"), ENGINE_BYTES), (0.0, 0.0, ENGINE_BYTES), (4918.0, 4000.0, 0),
])
def test_a_missing_or_malformed_vm_or_engine_reading_is_a_problem(total, available, engine):
    assert smoke.vm_memory_problems(total, available, engine)


def test_more_available_than_total_memory_is_not_believed():
    assert "more available memory" in smoke.vm_memory_problems(4918.0, 6000.0, ENGINE_BYTES)[0]


def test_the_pinned_gate_accepts_a_vm_with_room_and_reports_it(engine, quiet):
    smoke.run_resource_gate(make_sources(vm_memory=GOOD_VM), pin=PIN)
    assert any("Docker VM memory" in line and "available 4000 MiB" in line for line in quiet)


@pytest.mark.parametrize("vm, message", [
    (lambda: {"total_mib": 4096.0, "available_mib": 3583.0}, "Docker VM available memory"),
    (lambda: {"total_mib": 8192.0, "available_mib": 4000.0}, "does not match"),
    (lambda: None, "could not be read"),
    (lambda: {"total_mib": 4096.0}, "available memory could not be read"),
    (lambda: (_ for _ in ()).throw(RuntimeError("boom")), "could not be read"),
    (None, "could not be read"),
])
def test_the_pinned_gate_fails_closed_on_an_insufficient_or_unverifiable_vm(engine, vm, message):
    with pytest.raises(SmokeFailure, match=message):
        smoke.run_resource_gate(make_sources(vm_memory=vm), pin=PIN)


def test_the_unpinned_gate_never_reads_the_vm(engine):
    smoke.run_resource_gate(make_sources(vm_memory=lambda: (_ for _ in ()).throw(AssertionError("read"))))
    assert engine.commands == []


def test_the_default_sources_read_the_vm_and_the_old_fields_are_unchanged():
    sources = smoke.default_gate_sources()
    assert sources.vm_memory is smoke._read_vm_memory and sources.engine_bytes is smoke._read_engine_bytes
    assert make_sources().vm_memory is None


# ======================================================================================================
# Q3. Step 4B: the OWNER RIGHTS entry that Python 3.13's tempfile.mkdtemp gives a new directory
# ======================================================================================================

@pytest.mark.parametrize("directory, grant", [(True, "(OI)(CI)F"), (False, "F")])
def test_owner_rights_is_removed_in_the_same_icacls_call_and_nothing_new_is_granted(monkeypatch, tmp_path,
                                                                                      directory, grant):
    fake = windows_fake_run()
    monkeypatch.setattr(smoke, "run", fake)
    smoke.restrict_to_owner(tmp_path, directory=directory, windows=True)
    (command,) = [c for c in fake.calls if c[0] == "icacls"]
    assert command == ["icacls", str(tmp_path), "/inheritance:r", "/remove:g", "*S-1-3-4", "/grant:r",
                       f"*S-1-5-21-1-2-3:{grant}", f"*S-1-5-18:{grant}", f"*S-1-5-32-544:{grant}"]
    assert command.count("/grant:r") == 1 and command.count("/remove:g") == 1
    assert command.index("/remove:g") < command.index("/grant:r")            # a removal, never a grant of S-1-3-4
    assert [token for token in command if token.startswith("*S-1-3-4")] == ["*S-1-3-4"]


def test_owner_rights_is_never_part_of_the_allowed_set():
    source = inspect.getsource(smoke.restrict_to_owner)
    allowed = next(line for line in source.splitlines() if line.strip().startswith("allowed ="))
    assert allowed.strip() == "allowed = {sid, _SYSTEM_SID, _ADMINISTRATORS_SID}"
    assert smoke._OWNER_RIGHTS_SID == "S-1-3-4"


@pytest.mark.parametrize("extra", ["S-1-3-4", "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", "S-1-5-21-1-2-4"])
@pytest.mark.parametrize("directory", [True, False])
def test_an_unexpected_entry_in_the_read_back_is_still_rejected(monkeypatch, tmp_path, extra, directory):
    listed = f"S-1-5-21-1-2-3\nS-1-5-18\nS-1-5-32-544\n{extra}\n"
    monkeypatch.setattr(smoke, "run", windows_fake_run(ps_lines=listed))
    with pytest.raises(SmokeFailure, match="not limited to the user, SYSTEM and Administrators"):
        smoke.restrict_to_owner(tmp_path, directory=directory, windows=True)


@pytest.mark.parametrize("directory", [True, False])
def test_exactly_the_three_approved_sids_are_still_accepted(monkeypatch, tmp_path, directory):
    monkeypatch.setattr(smoke, "run", windows_fake_run(ps_lines="S-1-5-32-544\nS-1-5-21-1-2-3\nS-1-5-18\n"))
    smoke.restrict_to_owner(tmp_path, directory=directory, windows=True)


# ======================================================================================================
# V. Optional RCA-to-Viewer stage (--with-rca-viewer): disposable database only, fakes only
# ======================================================================================================

AID = "c" * 64
MISSING = "d" * 64
INV = "inv-" + "e" * 16
TRACE = "f" * 32
SPAN = "1" * 16
OTHER_SPAN = "2" * 16
RCA_PW = "rca-secret-pw"
VIEWER_PW = "viewer-secret-pw"
ANOMALY = {"anomaly_id": AID, "trace_id": TRACE, "span_id": SPAN, "severity": "CRITICAL",
           "anomaly_type": "tool_failure"}


@pytest.fixture
def stage(monkeypatch):
    """The stage's environment: generated credentials, a harness python, logs captured, nothing real run."""
    smoke.RUN.generated = {"RCA_ANALYZER_DB_PASSWORD": RCA_PW, "TRACE_VIEWER_DB_PASSWORD": VIEWER_PW}
    smoke.RUN.python = Path("venv-python")
    logs: dict = {}
    monkeypatch.setattr(smoke, "write_log", lambda name, text: logs.__setitem__(name, text))
    monkeypatch.setattr(smoke, "say", lambda *a, **k: None)
    monkeypatch.setattr(smoke, "section", lambda *a, **k: None)
    monkeypatch.setattr(e2e, "say", lambda *a, **k: None)
    monkeypatch.setattr(e2e, "section", lambda *a, **k: None)
    return SimpleNamespace(logs=logs)


def good_report():
    rca = {"investigation_id": INV, "anomaly_id": AID, "trace_id": TRACE, "subject_span_id": SPAN,
           "anomaly_type": "tool_failure", "severity": "CRITICAL", "omitted_evidence": 0,
           "evidence": [{"span_id": SPAN, "is_direct_subject": True},
                        {"span_id": OTHER_SPAN, "is_direct_subject": False}]}
    return {
        "ready": {"status": 200, "body": {"status": "ready", "database": "ok"}},
        "traces": {"status": 200, "body": {"total": 110}},
        "anomalies": {"status": 200, "body": {"total": 42}},
        "anomaly": {"status": 200, "body": {"anomaly_id": AID, "trace_id": TRACE, "span_id": SPAN}},
        "anomaly_rca": {"status": 200, "body": rca},
        "rca": {"status": 200, "body": dict(rca)},
        "missing_rca": {"status": 404, "body": {"detail": "not found"}},
        "trace": {"status": 200, "span_count": 3, "span_ids": [SPAN, OTHER_SPAN, "3" * 16]},
    }


def check(report):
    return e2e.check_viewer_report(report, anomaly=ANOMALY, investigation_id=INV, evidence_rows=2,
                                   expected_traces=110, expected_anomalies=42)


def test_the_optional_flag_is_off_by_default_and_the_default_call_is_unchanged(monkeypatch, cli):
    calls: list = []
    monkeypatch.setattr(e2e, "e2e", lambda *a, **k: calls.append((a, k)))
    assert e2e.main(cli.argv) == 0
    assert calls == [((H, None), {})]


def test_the_flag_reaches_the_stage_only_when_given(monkeypatch, cli):
    calls: list = []
    monkeypatch.setattr(e2e, "e2e", lambda *a, **k: calls.append((a, k)))
    assert e2e.main(cli.argv + ["--with-rca-viewer"]) == 0
    assert calls == [((H, None), {"with_rca_viewer": True})]


def test_the_flag_without_execute_is_a_usage_error():
    with pytest.raises(SystemExit) as raised:
        e2e.main(["--with-rca-viewer"])
    assert raised.value.code == 2
    with pytest.raises(SystemExit):
        e2e.main(["--with-rca-viewer", "--preflight", "--expect-head", H])
    older = SimpleNamespace(expect_head=None, approved_tree=None, approved_tree_sha256=None, execute=False,
                            preflight=False, confirm=None)
    assert e2e.argument_problem(older) is None          # a namespace without the flag still works


def test_the_plan_names_the_optional_stage_only_when_asked(capsys):
    assert e2e.main([]) == 0
    default = capsys.readouterr().out
    assert default.strip() == e2e.plan_text(None).strip() and e2e.plan_text(H) == e2e.plan_text(H, False)
    assert "Optional stage" not in default
    with_stage = e2e.plan_text(H, True)
    assert "Optional stage" in with_stage and "No server, no extra port" in with_stage
    assert "127.0.0.1:15432" in with_stage and RCA_PW not in with_stage


def _run_e2e_with_stubs(monkeypatch, record, **kwargs):
    for name in ("check_repository", "run_resource_gate", "record_docker_state", "record_protected_state",
                 "create_workspace_secured", "create_virtual_environment", "check_render", "start_kafka",
                 "create_topics", "track_project_identities", "start_postgres", "run_bootstrap", "start_collector",
                 "start_host_services", "check_totals", "check_host_processes", "check_normal_stack"):
        monkeypatch.setattr(smoke, name, lambda *a, _n=name, **k: record.append(_n))
    monkeypatch.setattr(smoke, "check_baseline", lambda: {})
    monkeypatch.setattr(smoke, "run_stage", lambda stage_, offsets: offsets)
    for name in ("check_plans", "build_refresh_image", "refresh_analytics", "detect_and_reconcile",
                 "install_viewer_dependencies", "rca_and_viewer"):
        monkeypatch.setattr(e2e, name, lambda *a, _n=name, **k: record.append(_n))
    monkeypatch.setattr(e2e, "planned_requests", lambda stage_: [])
    e2e.e2e(H, None, **kwargs)


def test_by_default_neither_the_dependency_step_nor_the_stage_runs(monkeypatch, quiet):
    record: list = []
    _run_e2e_with_stubs(monkeypatch, record)
    assert "rca_and_viewer" not in record and "install_viewer_dependencies" not in record
    assert record[-1] == "check_normal_stack"
    assert record.index("detect_and_reconcile") < record.index("check_host_processes")


def test_the_stage_runs_after_the_detector_and_the_dependency_step_after_the_environment(monkeypatch, quiet):
    record: list = []
    _run_e2e_with_stubs(monkeypatch, record, with_rca_viewer=True)
    assert record.index("create_virtual_environment") < record.index("install_viewer_dependencies") \
        < record.index("check_render")
    assert record.index("detect_and_reconcile") < record.index("check_host_processes") < record.index(
        "rca_and_viewer")
    assert record[-1] == "check_normal_stack"


def test_a_failing_stage_still_gets_the_contained_cleanup(monkeypatch, cli, capsys):
    def behaviour(*args, **kwargs):
        assert kwargs == {"with_rca_viewer": True}
        raise SmokeFailure("Trace Viewer: boom")

    monkeypatch.setattr(e2e, "e2e", behaviour)
    assert e2e.main(cli.argv + ["--with-rca-viewer"]) == 1
    assert cli.cleanups == 1
    assert "Trace Viewer: boom" in capsys.readouterr().out


@pytest.mark.parametrize("change", [{"project": "agentops"}, {"port": 15433}, {"port": 5432},
                                    {"missing": "TRACE_VIEWER_DB_PASSWORD"}, {"missing": "RCA_ANALYZER_DB_PASSWORD"},
                                    {"database": "postgres"}])
def test_an_ambiguous_database_identity_fails_closed(monkeypatch, stage, change):
    monkeypatch.setattr(smoke, "PROJECT", change.get("project", "agentops-workload-smoke"))
    monkeypatch.setattr(smoke, "POSTGRES_PORT", change.get("port", 15432))
    if "missing" in change:
        smoke.RUN.generated.pop(change["missing"])
    monkeypatch.setattr(smoke, "psql", lambda sql: change.get("database", "agentops"))
    with pytest.raises(SmokeFailure):
        e2e.require_disposable_database()


def test_the_disposable_database_is_accepted(monkeypatch, stage):
    monkeypatch.setattr(smoke, "psql", lambda sql: "agentops")
    e2e.require_disposable_database()


def test_the_anomaly_is_chosen_by_a_fixed_read_only_query(monkeypatch, stage):
    seen: list = []
    monkeypatch.setattr(smoke, "psql", lambda sql: (seen.append(sql), json.dumps(ANOMALY))[1])
    assert e2e.select_rca_anomaly() == ANOMALY
    (sql,) = seen
    assert sql.startswith("SELECT") and "tool_failure" in sql and "CRITICAL" in sql
    assert "ORDER BY event_time, anomaly_id LIMIT 1" in sql
    assert not any(word in sql.upper() for word in ("INSERT", "UPDATE", "DELETE", "DROP"))


@pytest.mark.parametrize("row", ["", json.dumps({**ANOMALY, "anomaly_id": "XYZ"}),
                                 json.dumps({**ANOMALY, "span_id": None})])
def test_no_usable_anomaly_is_a_failure(monkeypatch, stage, row):
    monkeypatch.setattr(smoke, "psql", lambda sql: row)
    with pytest.raises(SmokeFailure):
        e2e.select_rca_anomaly()


def test_an_anomaly_without_an_investigation_is_chosen_for_the_404_check(monkeypatch, stage):
    seen: list = []
    monkeypatch.setattr(smoke, "psql", lambda sql: (seen.append(sql), MISSING)[1])
    assert e2e.select_uninvestigated_anomaly(AID) == MISSING
    assert "NOT EXISTS" in seen[0] and "ORDER BY a.event_time, a.anomaly_id" in seen[0] and AID in seen[0]
    monkeypatch.setattr(smoke, "psql", lambda sql: "")
    with pytest.raises(SmokeFailure):
        e2e.select_uninvestigated_anomaly(AID)


def _fake_tool(calls, stdout="", returncode=0, stderr=""):
    def fake(command, **kwargs):
        calls.append((list(command), kwargs))
        return result(stdout, returncode, stderr)
    return fake


RCA_LINE = "2026 INFO    investigation_id=%s confidence=high evidence=%d inserted=%s"


def test_the_analyzer_runs_as_its_own_role_on_the_disposable_endpoint_only(monkeypatch, stage):
    calls: list = []
    monkeypatch.setattr(smoke, "run", _fake_tool(calls, RCA_LINE % (INV, 5, "True")))
    assert e2e.run_rca("first", AID) == {"investigation_id": INV, "evidence": 5, "inserted": True}
    ((command, kwargs),) = calls
    assert command == ["venv-python", "main.py", "--anomaly-id", AID]
    assert kwargs["cwd"] == smoke.REPO / "rca-analyzer" and kwargs["timeout"] == e2e.T_RCA
    env = kwargs["env"]
    assert (env["RCA_ANALYZER_DB_HOST"], env["RCA_ANALYZER_DB_PORT"], env["RCA_ANALYZER_DB_NAME"],
            env["RCA_ANALYZER_DB_USER"], env["RCA_ANALYZER_DB_PASSWORD"]) == (
        "127.0.0.1", "15432", "agentops", "rca_analyzer", RCA_PW)
    assert not [k for k in env if k.startswith("TRACE_VIEWER")] and RCA_PW not in " ".join(command)


@pytest.mark.parametrize("stdout, returncode, message", [
    ("", 1, "rca analyzer first failed"), ("no result line", 0, "result line was not found"),
    ("connect 127.0.0.1:5432 ok " + RCA_LINE % (INV, 1, "True"), 0, "normal stack's port")])
def test_analyzer_failures_are_failures(monkeypatch, stage, stdout, returncode, message):
    monkeypatch.setattr(smoke, "run", _fake_tool([], stdout, returncode))
    with pytest.raises(SmokeFailure, match=message):
        e2e.run_rca("first", AID)


def test_the_rows_check_accepts_one_idempotent_investigation():
    rows = {"investigations": 1, "investigation_id": INV, "evidence": 4}
    first = {"investigation_id": INV, "inserted": True}
    second = {"investigation_id": INV, "inserted": False}
    assert e2e.check_rca_rows(first, second, rows, dict(rows)) == []


@pytest.mark.parametrize("second, before, after", [
    ({"investigation_id": INV, "inserted": True}, {}, {}),
    ({"investigation_id": "other", "inserted": False}, {}, {}),
    ({"investigation_id": INV, "inserted": False}, {"investigations": 2}, {"investigations": 2}),
    ({"investigation_id": INV, "inserted": False}, {"evidence": 0}, {"evidence": 0}),
    ({"investigation_id": INV, "inserted": False}, {"investigation_id": "x"}, {"investigation_id": "x"}),
    ({"investigation_id": INV, "inserted": False}, {}, {"evidence": 9}),
])
def test_the_rows_check_rejects_each_defect(second, before, after):
    base = {"investigations": 1, "investigation_id": INV, "evidence": 4}
    first = {"investigation_id": INV, "inserted": True}
    assert e2e.check_rca_rows(first, second, {**base, **before}, {**base, **after})


def test_the_viewer_probe_is_in_process_as_the_reader_with_no_server(monkeypatch, stage):
    assert "TestClient" in e2e.VIEWER_PROBE and 'base_url="http://127.0.0.1:8000"' in e2e.VIEWER_PROBE
    for word in ("uvicorn", ".run(", "socket", "--publish", "bind", ".post(", ".put(", ".delete("):
        assert word not in e2e.VIEWER_PROBE
    calls: list = []
    line = e2e.VIEWER_REPORT_PREFIX + json.dumps(good_report())
    monkeypatch.setattr(smoke, "run", _fake_tool(calls, "noise\n" + line + "\n"))
    assert e2e.run_viewer_probe(AID, INV, MISSING, TRACE) == good_report()
    ((command, kwargs),) = calls
    assert command[:3] == ["venv-python", "-c", e2e.VIEWER_PROBE] and command[3:] == [AID, INV, MISSING, TRACE]
    assert kwargs["cwd"] == smoke.REPO / "trace-viewer"
    env = kwargs["env"]
    assert (env["TRACE_VIEWER_DB_HOST"], env["TRACE_VIEWER_DB_PORT"], env["TRACE_VIEWER_DB_USER"],
            env["TRACE_VIEWER_DB_PASSWORD"]) == ("127.0.0.1", "15432", "trace_viewer_reader", VIEWER_PW)
    assert not [k for k in env if k.startswith("RCA_ANALYZER")]


@pytest.mark.parametrize("stdout, returncode", [("", 0), ("x", 1), ("VIEWER_REPORT {bad", 0),
                                                 ("VIEWER_REPORT {}\nVIEWER_REPORT {}\n", 0)])
def test_a_missing_or_broken_probe_report_is_a_failure(monkeypatch, stage, stdout, returncode):
    monkeypatch.setattr(smoke, "run", _fake_tool([], stdout, returncode))
    with pytest.raises(SmokeFailure):
        e2e.run_viewer_probe(AID, INV, MISSING, TRACE)


def test_a_consistent_viewer_report_has_no_problems():
    assert check(good_report()) == []


def _mutated(path, value):
    report = good_report()
    target = report
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return report


@pytest.mark.parametrize("report", [
    _mutated(("ready", "status"), 503),
    _mutated(("traces", "body", "total"), 38),                           # the accepted MVP database holds 38
    _mutated(("anomalies", "body", "total"), 2),                         # ... and 2 anomalies
    _mutated(("missing_rca", "status"), 200),
    _mutated(("anomaly_rca", "status"), 404),
    _mutated(("rca", "body", "evidence"), [{"span_id": SPAN, "is_direct_subject": True}]),
    _mutated(("anomaly_rca", "body", "investigation_id"), "other"),
    _mutated(("anomaly_rca", "body", "anomaly_id"), MISSING),
    _mutated(("anomaly_rca", "body", "severity"), "WARNING"),
    _mutated(("anomaly_rca", "body", "omitted_evidence"), 3),
    _mutated(("anomaly_rca", "body", "evidence"), []),
    _mutated(("trace", "span_ids"), [OTHER_SPAN]),                       # the anomaly's span is not in the trace
    _mutated(("anomaly", "body", "span_id"), OTHER_SPAN),
])
def test_each_viewer_inconsistency_is_reported(report):
    assert check(report)


def test_evidence_that_leaves_the_trace_or_the_subject_is_reported():
    report = good_report()
    report["anomaly_rca"]["body"]["evidence"] = [{"span_id": SPAN, "is_direct_subject": False},
                                                {"span_id": "9" * 16, "is_direct_subject": False}]
    report["rca"]["body"] = dict(report["anomaly_rca"]["body"])
    problems = check(report)
    assert any("not in the investigated trace" in p for p in problems)
    assert any("direct subject" in p for p in problems)


def _stage_fakes(monkeypatch, *, second_inserted=False, traces=110, report=None):
    log: list = []
    monkeypatch.setattr(e2e, "require_disposable_database", lambda: log.append("identity"))
    monkeypatch.setattr(e2e, "select_rca_anomaly", lambda: dict(ANOMALY))
    monkeypatch.setattr(e2e, "select_uninvestigated_anomaly", lambda excluding: MISSING)
    runs = iter([{"investigation_id": INV, "evidence": 2, "inserted": True},
                 {"investigation_id": INV, "evidence": 0, "inserted": second_inserted}])
    monkeypatch.setattr(e2e, "run_rca", lambda label, anomaly_id: (log.append("rca-" + label), next(runs))[1])
    monkeypatch.setattr(e2e, "read_rca_rows", lambda anomaly_id: {"investigations": 1, "investigation_id": INV,
                                                                 "evidence": 2})
    values = {"int_trace_spans": str(traces), "anomaly_events": "42"}
    monkeypatch.setattr(e2e, "_single_value", lambda sql, what: next(v for k, v in values.items() if k in sql))
    monkeypatch.setattr(e2e, "run_viewer_probe", lambda *a: (log.append("viewer"), report or good_report())[1])
    return log


def test_the_whole_stage_runs_in_order_and_passes(monkeypatch, stage):
    log = _stage_fakes(monkeypatch)
    e2e.rca_and_viewer()
    assert log == ["identity", "rca-first", "rca-second", "viewer"]


def test_a_non_idempotent_second_run_stops_before_the_viewer(monkeypatch, stage):
    log = _stage_fakes(monkeypatch, second_inserted=True)
    with pytest.raises(SmokeFailure, match="not idempotent"):
        e2e.rca_and_viewer()
    assert "viewer" not in log


def test_the_viewer_must_list_the_expected_traces(monkeypatch, stage):
    log = _stage_fakes(monkeypatch, traces=38)
    with pytest.raises(SmokeFailure, match="expected 110"):
        e2e.rca_and_viewer()
    assert "viewer" not in log


def test_a_bad_viewer_report_fails_the_stage(monkeypatch, stage):
    _stage_fakes(monkeypatch, report=_mutated(("missing_rca", "status"), 200))
    with pytest.raises(SmokeFailure, match="Trace Viewer"):
        e2e.rca_and_viewer()


def test_the_dependency_step_installs_only_the_two_viewer_packages(monkeypatch, stage):
    calls: list = []
    monkeypatch.setattr(smoke, "run", _fake_tool(calls, "ok"))
    e2e.install_viewer_dependencies()
    ((command, kwargs),) = calls
    assert command[:4] == ["venv-python", "-m", "pip", "install"]
    assert command[-2:] == list(e2e.VIEWER_EXTRA_REQUIREMENTS) and "-r" not in command
    assert [r.split(">")[0] for r in e2e.VIEWER_EXTRA_REQUIREMENTS] == ["fastapi", "httpx"]
    monkeypatch.setattr(smoke, "run", _fake_tool([], "", 1, "no network"))
    with pytest.raises(SmokeFailure, match="pip install"):
        e2e.install_viewer_dependencies()


def test_the_stage_never_addresses_the_accepted_database_or_publishes_ports():
    source = inspect.getsource(e2e.rca_and_viewer) + inspect.getsource(e2e.run_rca) \
        + inspect.getsource(e2e.run_viewer_probe) + inspect.getsource(e2e._db_environment)
    for forbidden_text in ("5432\"", "docker", "compose", "--publish", "uvicorn", "agentops-mvp"):
        assert forbidden_text not in source

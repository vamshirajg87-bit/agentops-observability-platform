"""
workload-generator/tests/unit/test_pipeline_it_network.py

The network-membership assertion of the disposable pipeline integration test
(workload-generator/run_pipeline_it.py), checked on in-memory Docker metadata.
Nothing here starts Docker or reads the live engine.

B3J-96 compared the containers attached to the project network with ALL of the
project's containers.  Those sets differ by design: kafka-init and db-bootstrap
run once and exit, and an exited container is not attached.  The corrected
assertion requires (1) every attached container to carry the project's label and
be one of its own, (2) every running project container to be attached to that
network, and (3) each needed service to be running exactly once.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "run_pipeline_it.py"
PROJECT = "agentops-pipeline-it-0a1b2c3d"
NETWORK = f"{PROJECT}_agentops-net"


def _wrapper():
    sys.path.insert(0, str(_PATH.parent))
    try:
        spec = importlib.util.spec_from_file_location("run_pipeline_it", _PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules["run_pipeline_it"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(_PATH.parent))


W = _wrapper()

_SERVICES = ("kafka", "postgres", "otel-collector", "stream-processor", "storage-consumer",
             "kafka-init", "db-bootstrap")


def _id(service: str) -> str:
    return (service.encode().hex() * 8)[:64]


def _stack(**overrides):
    """The finished stack as Docker reports it: five running services on the project
    network, the two one-shot jobs exited.  `docker ps` still lists the network an exited
    container was on (observed on the live stack), but `docker network inspect` no longer
    lists the container, so it is not attached."""
    containers = {}
    for service in _SERVICES:
        running = service not in ("kafka-init", "db-bootstrap")
        containers[_id(service)] = {"service": service,
                                    "state": "running" if running else "exited",
                                    "networks": [NETWORK]}
    attached = {i: {"project": PROJECT, "service": c["service"]}
                for i, c in containers.items() if c["state"] == "running"}
    containers.update(overrides.get("containers", {}))
    attached.update(overrides.get("attached", {}))
    for identifier in overrides.get("detached", ()):
        attached.pop(identifier)
    return attached, containers


def _problems(attached, containers):
    return W.network_membership_problems(PROJECT, NETWORK, attached, containers)


def test_running_project_containers_attached_and_exited_one_shots_absent_pass():
    attached, containers = _stack()
    assert set(attached) != set(containers)               # the B3J-96 equality could never hold
    assert {containers[i]["service"] for i in set(containers) - set(attached)} == {
        "kafka-init", "db-bootstrap"}
    assert _problems(attached, containers) == []


def test_a_foreign_container_on_the_project_network_fails():
    for labels in ({"project": "agentops", "service": "postgres"},           # the live stack
                   {"project": "", "service": ""}):                          # no label at all
        attached, containers = _stack(attached={_id("intruder"): labels})
        problems = _problems(attached, containers)
        assert len(problems) == 1 and "foreign container" in problems[0], problems
    # A container that claims the project's label but is not among the project's own.
    attached, containers = _stack(
        attached={_id("spoof"): {"project": PROJECT, "service": "postgres"}})
    assert any("not among the project's containers" in p for p in _problems(attached, containers))


def test_an_expected_running_container_missing_from_or_on_the_wrong_network_fails():
    attached, containers = _stack(detached=[_id("storage-consumer")])
    problems = _problems(attached, containers)
    assert problems == [f"running storage-consumer ({_id('storage-consumer')[:12]}) is not "
                        f"attached to {NETWORK}"]
    # Attached to some network, but not this project's.
    attached, containers = _stack(containers={_id("kafka"): {
        "service": "kafka", "state": "running", "networks": ["bridge"]}})
    problems = _problems(attached, containers)
    assert len(problems) == 1, problems
    assert "is attached, but its networks are ['bridge']" in problems[0]
    # A required service that is not running at all (or runs twice) fails even though
    # nothing running is unattached.
    attached, containers = _stack()
    containers[_id("postgres")]["state"] = "exited"
    containers[_id("postgres")]["networks"] = []
    del attached[_id("postgres")]
    assert _problems(attached, containers) == ["expected one running postgres, found 0"]


def test_docker_output_is_parsed_into_the_metadata_the_assertion_uses():
    attached_ids = [_id("kafka"), _id("postgres")]
    text = json.dumps({i: {"Name": "x", "IPv4Address": "172.19.0.2/16"} for i in attached_ids})
    assert W.parse_network_containers(text) == sorted(attached_ids)
    assert W.parse_network_containers("null\n") == [] and W.parse_network_containers("") == []
    listing = "\n".join([
        f"{_id('kafka')}|kafka|running|{NETWORK}",
        f"{_id('kafka-init')}|kafka-init|exited|{NETWORK}",        # as Docker prints it
        f"{_id('db-bootstrap')}|db-bootstrap|exited|", ""])         # and with no network
    parsed = W.parse_project_containers(listing)
    assert parsed[_id("kafka")] == {"service": "kafka", "state": "running", "networks": [NETWORK]}
    assert parsed[_id("kafka-init")] == {"service": "kafka-init", "state": "exited",
                                         "networks": [NETWORK]}
    assert parsed[_id("db-bootstrap")]["networks"] == []
    with pytest.raises(W.SmokeFailure):
        W.parse_project_containers("abc|only-three|fields")
    with pytest.raises(W.SmokeFailure):
        W.parse_network_containers("[1, 2]")


def test_exited_one_shots_are_ignored_whatever_networks_docker_still_reports_for_them():
    attached, containers = _stack()
    one_shots = [i for i, c in containers.items() if c["state"] == "exited"]
    assert one_shots and all(containers[i]["networks"] == [NETWORK] for i in one_shots)
    assert not set(one_shots) & set(attached)
    assert _problems(attached, containers) == []
    for identifier in one_shots:                       # no network reported at all: same result
        containers[identifier]["networks"] = []
    assert _problems(attached, containers) == []


# ---------------------------------------------------------------------------
# The Git preflight: development state, committed state, and nothing else
# ---------------------------------------------------------------------------
#
# Temporary Git repositories stand in for the real one; no Docker, no real repository.

import subprocess  # noqa: E402

BRANCH = "approved-branch"
FILES = ("docker/pipeline/Dockerfile", "docker/compose.pipeline.yml", "tool/run_it.py")


def _run_git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", *args],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout.strip()


def _write(repo, relative, text="x\n"):
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _repo(tmp_path):
    """A repository on the approved branch with one base commit; returns (repo, base)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(repo, "init", "-q", "-b", BRANCH)
    _write(repo, "app/service.py", "print('app')\n")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "base")
    return repo, _run_git(repo, "rev-parse", "HEAD")


def _state(repo, base, expect=None, **kwargs):
    head = expect or _run_git(repo, "rev-parse", "HEAD")
    return W.git_state(repo, head, base=base, branch=BRANCH, files=FILES, **kwargs)


def _add_approved(repo):
    for name in FILES:
        _write(repo, name)


def _commit_all(repo, message):
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", message)
    return _run_git(repo, "rev-parse", "HEAD")


def test_the_development_state_with_exactly_the_approved_untracked_files_is_accepted(tmp_path):
    repo, base = _repo(tmp_path)
    _add_approved(repo)
    assert _state(repo, base) == "development"


def test_an_approved_clean_committed_state_is_accepted_whatever_its_head(tmp_path):
    repo, base = _repo(tmp_path)
    _add_approved(repo)
    first = _commit_all(repo, "approved files")
    assert _state(repo, base) == "committed"
    _write(repo, FILES[0], "changed\n")                  # a later commit, approved files only
    second = _commit_all(repo, "revise")
    assert second != first and _state(repo, base) == "committed"


@pytest.mark.parametrize("damage", ["extra untracked file", "one approved file missing",
                                    "modified tracked file", "staged change"])
def test_unexpected_files_are_rejected_in_the_development_state(tmp_path, damage):
    repo, base = _repo(tmp_path)
    _add_approved(repo)
    assert _state(repo, base) == "development"
    if damage == "extra untracked file":
        _write(repo, "notes.txt")
    elif damage == "one approved file missing":
        (repo / FILES[2]).unlink()
    elif damage == "modified tracked file":
        _write(repo, "app/service.py", "print('changed')\n")
    else:
        _write(repo, "notes.txt")
        _run_git(repo, "add", "notes.txt")
    with pytest.raises(W.SmokeFailure):
        _state(repo, base)


@pytest.mark.parametrize("damage", ["extra untracked file", "edited approved file",
                                    "modified other tracked file", "staged change"])
def test_unexpected_files_are_rejected_in_the_committed_state(tmp_path, damage):
    repo, base = _repo(tmp_path)
    _add_approved(repo)
    _commit_all(repo, "approved files")
    assert _state(repo, base) == "committed"
    if damage == "extra untracked file":
        _write(repo, "notes.txt")
    elif damage == "edited approved file":
        _write(repo, FILES[1], "edited\n")
    elif damage == "modified other tracked file":
        _write(repo, "app/service.py", "print('changed')\n")
    else:
        _write(repo, "notes.txt")
        _run_git(repo, "add", "notes.txt")
    with pytest.raises(W.SmokeFailure):
        _state(repo, base)


def test_an_arbitrary_clean_committed_head_is_rejected(tmp_path):
    repo, base = _repo(tmp_path)
    # Clean, but the approved files are not committed: the base commit itself.
    with pytest.raises(W.SmokeFailure, match="not tracked at HEAD"):
        _state(repo, base)
    # Clean, approved files tracked, but the commit also changes an unrelated file.
    _add_approved(repo)
    _write(repo, "app/service.py", "print('unrelated change')\n")
    _commit_all(repo, "approved files and an unrelated change")
    with pytest.raises(W.SmokeFailure, match="files other than the approved ones"):
        _state(repo, base)
    # Clean, approved-only, but on a history that does not contain the approved base.
    other = tmp_path / "other"
    other.mkdir()
    _run_git(other, "init", "-q", "-b", BRANCH)
    _add_approved(other)
    _commit_all(other, "unrelated history")
    with pytest.raises(W.SmokeFailure, match="does not descend"):
        _state(other, base)


def test_the_branch_and_the_named_head_must_match(tmp_path):
    repo, base = _repo(tmp_path)
    _add_approved(repo)
    with pytest.raises(W.SmokeFailure, match="not the expected commit"):
        _state(repo, base, expect="1" * 40)
    _run_git(repo, "checkout", "-q", "-b", "another-branch")
    with pytest.raises(W.SmokeFailure, match="branch"):
        _state(repo, base)


# ---------------------------------------------------------------------------
# Cleanup (B3J-100): project-scoped only, never driven by an inventory difference
# ---------------------------------------------------------------------------
#
# An in-memory Docker stands in for the engine.  Nothing here reaches Docker.

import re  # noqa: E402

SOURCE = _PATH.read_text(encoding="utf-8")
OTHER = "agentops-pipeline-it-ffffffff"            # another disposable project, not ours


class FakeDocker:
    """Objects as (kind, name, owner-project-or-None).  Only `down` and an exact-name
    image removal can delete anything, and every call is recorded."""

    def __init__(self, project=PROJECT, *, down_code=0, down_removes_image=True,
                 image_rm_ok=True, temp_ok=True, leaked=0, repo_problems=(), stack_problem=None,
                 can_down=True):
        self.project = project
        self.objects = set()
        self.calls = []
        self.down_code, self.down_removes_image = down_code, down_removes_image
        self.image_rm_ok, self.temp_ok, self.leak = image_rm_ok, temp_ok, leaked
        self.repo, self.stack, self.down_possible = list(repo_problems), stack_problem, can_down
        self.temp_removed = False

    def add(self, kind, name, owner=None):
        self.objects.add((kind, name, owner))

    # --- the interface safe_cleanup uses
    def can_down(self):
        return self.down_possible

    def down(self):
        self.calls.append(("down", self.project))
        for obj in list(self.objects):
            kind, name, owner = obj
            if owner == self.project and (kind != "images" or self.down_removes_image):
                self.objects.discard(obj)
        return self.down_code, "boom" if self.down_code else ""

    def project_objects(self, kind):
        return [n for k, n, o in self.objects if k == kind and o == self.project]

    def owned_images(self):
        return [n.split(" ")[0] for k, n, o in self.objects
                if k == "images" and o == self.project and n.startswith(self.project + "-")]

    def remove_image(self, reference):
        self.calls.append(("image rm", reference))
        if not reference.startswith(self.project + "-"):
            raise W.SmokeFailure("not named after the project")
        if self.image_rm_ok:
            self.objects = {x for x in self.objects
                            if not (x[0] == "images" and x[1].split(" ")[0] == reference)}
        return self.image_rm_ok

    def fingerprint(self):
        return {kind: sorted(n for k, n, _ in self.objects if k == kind)
                for kind in W.FINGERPRINT_KINDS}

    def leaked(self):
        return self.leak

    def remove_temp(self):
        self.calls.append(("temp", None))
        self.temp_removed = self.temp_ok
        return self.temp_ok

    def repository_problems(self):
        return list(self.repo)

    def normal_stack_problem(self):
        return self.stack


def _existing(fake):
    """Resources that were there before the run; returns the 'before' inventory."""
    fake.add("images", "postgres:16 sha256:aaa")
    fake.add("volumes", "normal_pgdata")
    fake.add("networks", "bridge")
    fake.add("containers", "normal-postgres")
    return fake.fingerprint()


def _run_stack(fake):
    for kind, name in (("containers", f"{PROJECT}-kafka-1"), ("networks", NETWORK),
                       ("volumes", f"{PROJECT}_pgdata"),
                       ("images", f"{PROJECT}-stream-processor:latest sha256:bbb")):
        fake.add(kind, name, fake.project)


def _clean(fake, before, lines=None):
    out = [] if lines is None else lines
    return W.safe_cleanup(fake.project, before, fake, report=out.append), out


def test_cleanup_removes_only_the_disposable_projects_resources():
    fake = FakeDocker()
    before = _existing(fake)
    other = ("containers", f"{OTHER}-kafka-1", OTHER)      # a different disposable project
    fake.objects.add(other)
    before = fake.fingerprint()
    _run_stack(fake)
    problems, _ = _clean(fake, before)
    assert problems == []
    assert fake.calls[0] == ("down", PROJECT)
    assert fake.project_objects("containers") == [] and fake.project_objects("volumes") == []
    assert fake.project_objects("networks") == [] and fake.project_objects("images") == []
    assert other in fake.objects                           # another project's object survives
    assert fake.fingerprint() == before


def test_an_unrelated_image_created_during_the_run_is_not_touched_but_is_reported():
    fake = FakeDocker()
    before = _existing(fake)
    _run_stack(fake)
    fake.add("images", "someone/else:1 sha256:ccc")        # appeared during the run, not ours
    fake.add("images", "<none>:<none> sha256:ddd")         # dangling build layer
    problems, lines = _clean(fake, before)
    assert problems == []                                   # reported, not a failure
    assert ("images", "someone/else:1 sha256:ccc", None) in fake.objects
    assert ("images", "<none>:<none> sha256:ddd", None) in fake.objects
    assert [c for c in fake.calls if c[0] == "image rm"] == []
    text = "\n".join(lines)
    assert "someone/else:1" in text and "NOT touched" in text
    assert "<none>:<none>" in text


def test_an_unrelated_volume_created_during_the_run_is_not_touched_but_is_reported():
    fake = FakeDocker()
    before = _existing(fake)
    _run_stack(fake)
    fake.add("volumes", "unrelated_cache")
    problems, lines = _clean(fake, before)
    assert problems == []
    assert ("volumes", "unrelated_cache", None) in fake.objects
    assert "unrelated_cache" in "\n".join(lines)
    assert all(c[0] in ("down", "image rm", "temp") for c in fake.calls)    # no volume removal


def test_existing_resources_are_untouched():
    fake = FakeDocker()
    before = _existing(fake)
    snapshot = set(fake.objects)
    _run_stack(fake)
    problems, _ = _clean(fake, before)
    assert problems == []
    assert snapshot <= fake.objects
    assert fake.fingerprint() == before


def test_an_existing_object_that_disappears_is_a_problem_not_a_pass():
    fake = FakeDocker()
    before = _existing(fake)
    _run_stack(fake)
    fake.objects = {o for o in fake.objects if o[1] != "normal_pgdata"}
    problems, _ = _clean(fake, before)
    assert any("existing volumes" in p for p in problems)


def test_a_project_image_left_by_down_is_removed_by_exact_name_only():
    fake = FakeDocker(down_removes_image=False)
    before = _existing(fake)
    _run_stack(fake)
    problems, lines = _clean(fake, before)
    assert problems == []
    assert fake.calls[1] == ("image rm", f"{PROJECT}-stream-processor:latest")
    assert [c for c in fake.calls if c[0] == "image rm"] == [fake.calls[1]]
    assert "removed" in "\n".join(lines)


def test_an_image_without_proven_ownership_is_never_a_removal_candidate():
    fake = FakeDocker(down_removes_image=False)
    before = _existing(fake)
    fake.add("images", "stream-processor:latest sha256:eee", PROJECT)    # label, but not named for it
    fake.add("images", f"{PROJECT}-x:latest sha256:fff", None)           # named for it, no label
    problems, _ = _clean(fake, before)
    assert [c for c in fake.calls if c[0] == "image rm"] == []
    assert any("images" in p for p in problems)      # the labelled one is reported as left over
    assert ("images", f"{PROJECT}-x:latest sha256:fff", None) in fake.objects
    with pytest.raises(W.SmokeFailure):              # and the removal itself re-checks the name
        fake.remove_image("postgres:16")


@pytest.mark.parametrize("fault", ["down fails", "image will not go", "temp will not go",
                                   "password leaked", "repository dirty", "normal stack changed",
                                   "project object left"])
def test_every_cleanup_failure_is_a_problem_so_the_result_is_not_a_pass(fault):
    fake = FakeDocker(down_code=1 if fault == "down fails" else 0,
                      down_removes_image=fault != "image will not go",
                      image_rm_ok=fault != "image will not go",
                      temp_ok=fault != "temp will not go",
                      leaked=1 if fault == "password leaked" else 0,
                      repo_problems=["dirty"] if fault == "repository dirty" else (),
                      stack_problem="changed" if fault == "normal stack changed" else None)
    before = _existing(fake)
    _run_stack(fake)
    if fault == "project object left":
        fake.down = lambda: (0, "")                      # down "succeeds" but removes nothing
    problems, lines = _clean(fake, before)
    assert problems, fault
    assert any(line for line in lines)
    W.T.project = PROJECT
    assert W.teardown(fake) is False


def test_a_successful_cleanup_is_the_only_passing_one():
    fake = FakeDocker()
    before = _existing(fake)
    _run_stack(fake)
    W.T.project = PROJECT
    assert W.teardown(fake) is True
    assert fake.temp_removed


def test_temporary_files_are_still_removed_even_when_down_failed():
    fake = FakeDocker(down_code=1)
    before = _existing(fake)
    _run_stack(fake)
    problems, _ = _clean(fake, before)
    assert ("temp", None) in fake.calls and fake.temp_removed
    assert any("compose down failed" in p for p in problems)


def test_the_cleanup_runs_after_a_failed_run_as_well_as_a_successful_one():
    body = SOURCE[SOURCE.index("def main(argv"):]
    # the failure branches only record the failure; cleanup follows them unconditionally
    assert body.index("except SmokeFailure") < body.index("teardown()")
    after_excepts = body[body.index("teardown()") - 120:body.index("teardown()")]
    assert "if not passed" not in after_excepts and "if passed" not in after_excepts
    assert "clean = teardown() if T.project else True" in body
    assert "return 0 if passed and clean else 1" in body


def test_the_inherited_global_cleanup_is_unreachable_from_the_wrapper():
    import ast
    tree = ast.parse(SOURCE)
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            called.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)                 and node.value.id == "smoke":
            assert node.attr != "cleanup", "the wrapper references run_smoke.cleanup"
    assert "cleanup" not in called                      # no inherited cleanup() by any spelling
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
               and isinstance(n.value, str)]
    assert not any("prune" in x for x in strings if not x.lstrip().startswith(("-", "no ")) and len(x) < 40)
    # the only deletion commands in the wrapper's code: the Compose down and one image rm
    assert sum(1 for n in ast.walk(tree) if isinstance(n, ast.List)
               and [getattr(e, "value", None) for e in n.elts[:3]] == ["docker", "image", "remove"]) == 1
    assert not any(isinstance(n, ast.List) and len(n.elts) > 1
                   and getattr(n.elts[0], "value", None) == "docker"
                   and getattr(n.elts[1], "value", None) in ("volume", "system", "container")
                   for n in ast.walk(tree))
    # the inventory comparison only reads: safe_cleanup reaches deletion through ops only
    body = ast.get_source_segment(SOURCE, next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "safe_cleanup"))
    assert body.count("ops.remove_image(") == 1 and body.count("ops.down(") == 1
    assert "smoke." not in body


def test_liveops_issues_only_the_scoped_commands(monkeypatch, tmp_path):
    issued = []

    class Done:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(W.smoke, "run", lambda command, **kw: (issued.append(list(command)), Done())[1])
    monkeypatch.setattr(W.smoke, "docker_lines", lambda *a: (issued.append(["docker", *a]), [])[1])
    ops = W.LiveOps(PROJECT)
    W.T.override = tmp_path / "override.yml"
    monkeypatch.setattr(W, "compose4", lambda *a: ["docker", "compose", "-p", PROJECT, *a])
    ops.down()
    assert ops.remove_image(f"{PROJECT}-stream-processor:latest") is True
    for kind in W.FINGERPRINT_KINDS:
        ops.project_objects(kind)
    ops.owned_images()
    assert issued[0][:5] == ["docker", "compose", "-p", PROJECT, "down"]
    assert issued[0][5:] == ["--volumes", "--rmi", "local", "--remove-orphans"]
    assert issued[1] == ["docker", "image", "remove", f"{PROJECT}-stream-processor:latest"]
    for command in issued[2:]:                           # everything else only lists, by label
        assert "rm" not in command and "remove" not in command
        assert any(PROJECT in part for part in command) or "images" in command
    with pytest.raises(W.SmokeFailure):
        ops.remove_image("postgres:16")
    for bad in ("agentops", "agentops-pipeline-it-xyz", ""):
        with pytest.raises(W.SmokeFailure):
            W.LiveOps(bad)


def test_the_temporary_directory_removal_is_guarded(monkeypatch, tmp_path):
    ops = W.LiveOps(PROJECT)
    removed = []
    monkeypatch.setattr(W.smoke, "_remove_tree", lambda path: (removed.append(path), True)[1])
    monkeypatch.setattr(W.smoke.RUN, "temp", None)
    assert ops.remove_temp() is True and removed == []
    monkeypatch.setattr(W.smoke.RUN, "temp", W.smoke.REPO / "db-bootstrap")      # inside the repository
    with pytest.raises(W.SmokeFailure):
        ops.remove_temp()
    monkeypatch.setattr(W.smoke.RUN, "temp", Path(W.smoke.REPO.anchor) / "definitely-not-temp-dir")
    with pytest.raises(W.SmokeFailure):
        ops.remove_temp()
    assert removed == []
    import tempfile
    good = Path(tempfile.gettempdir()) / "agentops-smoke-test-dir"
    monkeypatch.setattr(W.smoke.RUN, "temp", good)
    assert ops.remove_temp() is True and removed == [good.resolve()]

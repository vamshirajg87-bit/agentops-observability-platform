"""
benchmarks/tests/test_appcontainer_preflight.py

Offline tests of the read-only AppContainer staging planner.  Only fake
host data is used: the real collectors are disabled, and any process,
socket or registry access fails the test.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1]
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import appcontainer_preflight as P  # noqa: E402
import calibrate_generator as C  # noqa: E402

HEAD = "a" * 40
SOURCE = (_BENCH / "appcontainer_preflight.py").read_text(encoding="utf-8")


class LiveAccessAttempt(AssertionError):
    """A test reached the real host."""


@pytest.fixture(autouse=True)
def fail_closed(monkeypatch):
    def refuse(what):
        def call(*args, **kwargs):
            raise LiveAccessAttempt(f"{what} attempted")
        return call

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    monkeypatch.setattr(os, "system", refuse("os.system"))
    monkeypatch.setattr(socket, "create_connection", refuse("a network connection"))
    monkeypatch.setattr(socket.socket, "connect", refuse("a socket connection"))
    monkeypatch.setattr(P.RealHostSource, "_registry_value",
                        staticmethod(refuse("a registry read")))


REPO_FILES = [
    "benchmarks/calibrate_generator.py", "benchmarks/metrics.py",
    "benchmarks/run_benchmark.py", "benchmarks/ladder.json", "benchmarks/report.py",
    "benchmarks/tests/test_metrics.py",
    "workload-generator/workload_generator/__init__.py",
    "workload-generator/workload_generator/plan.py",
    "workload-generator/workload_generator/scenarios.py",
    "workload-generator/workload_generator/real_driver.py",
    "workload-generator/tests/test_plan.py",
    "demo-app/graph.py", "demo-app/state.py", "demo-app/main.py",
    "demo-app/agents/retrieval.py", "demo-app/observability/tracing.py",
    "demo-app/observability/__pycache__/tracing.cpython-313.py",
]
REQUIRED = [
    "benchmarks/calibrate_generator.py", "benchmarks/ladder.json", "benchmarks/metrics.py",
    "benchmarks/run_benchmark.py", "demo-app/agents/retrieval.py", "demo-app/graph.py",
    "demo-app/observability/tracing.py", "demo-app/state.py",
    "workload-generator/workload_generator/__init__.py",
    "workload-generator/workload_generator/plan.py",
    "workload-generator/workload_generator/real_driver.py",
    "workload-generator/workload_generator/scenarios.py",
]


def good_inventory():
    return {
        "windows": {"collected": True, "edition": "Core", "build": "26200.1",
                    "architecture": "AMD64", "pointer_bits": 64},
        "python": {"collected": True, "executable": r"C:\Py\python.exe", "home": r"C:\Py",
                   "version": [3, 13, 7], "files": P._python_runtime_files((3, 13)),
                   "sha256": {"python.exe": "1" * 64}},
        "venv": {"collected": True, "site_packages": r"C:\v\Lib\site-packages",
                 "top_level": ["pydantic", "pydantic_core", "langgraph", "opentelemetry",
                               "grpc"],
                 "native": ["pydantic_core/_pydantic_core.cp313-win_amd64.pyd",
                            "grpc/_cython/cygrpc.cp313-win_amd64.pyd"],
                 "pth": [{"name": "distutils-precedence.pth",
                          "lines": ["import os; var = 'SETUPTOOLS_USE_DISTUTILS'"]}]},
        "onedrive": {"collected": True, "roots": [r"C:\Users\u\OneDrive"], "placeholders": [],
                     "repo_under_onedrive": True},
        "repository": {"collected": True, "root": r"C:\Users\u\OneDrive\repo", "head": HEAD,
                       "git_kind": "directory", "files": list(REPO_FILES)},
        "staging_parent": {"collected": True, "path": r"C:\Users\u\AppData\Local",
                           "exists": True, "writable": True, "root_exists": False},
        "services": {"collected": True, "MpsSvc": {"status": "Running", "start": "Automatic"},
                     "BFE": {"status": "Running", "start": "Automatic"}},
        "firewall_profiles": {"collected": True,
                              "enabled": {"domain": True, "private": True, "public": True}},
        "appcontainer_profiles": {"collected": True,
                                  "profiles": [{"name": "other.app", "sid": "S-1-15-2-5"}]},
        "loopback_exemptions": {"collected": True, "sids": [], "names": []},
        "privileges": {"collected": True, "is_admin": False,
                       "privileges": ["SeChangeNotifyPrivilege"]},
        "agentops_baseline": {"collected": True, "containers": ["agentops-postgres"]},
    }


def findings(inventory, expected_head=HEAD):
    return P.inventory_findings(inventory, expected_head=expected_head)


def blockers(inventory, expected_head=HEAD):
    return [f"{f.area}: {f.message}" for f in findings(inventory, expected_head)
            if f.severity == "blocker"]


def has(messages, text):
    return any(text in m for m in messages)


class FakeSource:
    def __init__(self, data):
        self.data, self.calls = data, []

    def collect(self, name):
        self.calls.append(name)
        value = self.data.get(name)
        if isinstance(value, Exception):
            raise value
        return value


# ---------------------------------------------------------------------------
# Gates and scope
# ---------------------------------------------------------------------------

class TestGates:
    def test_disabled_by_default(self):
        assert P.HOST_INVENTORY_ENABLED is False
        assert "\nHOST_INVENTORY_ENABLED: bool = False\n" in SOURCE

    @pytest.mark.parametrize("name", P.COLLECTORS)
    def test_every_real_collector_refuses(self, name):
        with pytest.raises(P.InventoryDisabled, match="not enabled"):
            P.RealHostSource().collect(name)

    def test_collect_inventory_refuses_as_a_whole(self):
        with pytest.raises(P.InventoryDisabled):
            P.collect_inventory(P.RealHostSource())
        with pytest.raises(P.InventoryDisabled):
            P._sha256_file(Path(__file__))

    def test_unknown_collector(self, monkeypatch):
        monkeypatch.setattr(P, "HOST_INVENTORY_ENABLED", True)        # in memory only
        with pytest.raises(P.PreflightError, match="unknown collector"):
            P.RealHostSource().collect("bogus")

    def test_cli_collect_refused(self, tmp_path, capsys):
        out = io.StringIO()
        assert P.main(["--collect"], stdout=out) == 2
        assert "not enabled" in capsys.readouterr().err and out.getvalue() == ""

    def test_cli_plans_from_supplied_data_only(self, tmp_path):
        source = tmp_path / "inventory.json"
        source.write_text(json.dumps(good_inventory()), encoding="utf-8")
        before = sorted(tmp_path.iterdir())
        out = io.StringIO()
        assert P.main(["--inventory-json", str(source), "--expected-head", HEAD],
                      stdout=out) == 0
        plan = json.loads(out.getvalue())
        assert plan["recommendation"] == "NO-GO" and plan["host_inventory_enabled"] is False
        assert sorted(tmp_path.iterdir()) == before                 # nothing written

    def test_cli_unreadable_input(self, tmp_path, capsys):
        assert P.main(["--inventory-json", str(tmp_path / "missing.json")]) == 2
        assert "cannot read" in capsys.readouterr().err

    def test_no_host_changing_operation_exists(self):
        code = SOURCE.split('"""', 2)[2]
        for word in ("CreateAppContainerProfile(", "DeleteAppContainerProfile(", "icacls ",
                     "subprocess", "Popen", "import socket", "mkdir", "makedirs", "shutil",
                     "copyfile", "SetValue", "CreateKey", "DeleteKey", "WinDLL", "windll",
                     "unlink", "rmdir", "write_text", "write_bytes", "NetworkIsolationSet",
                     "netsh", "docker", "wsl"):
            assert word not in code, word
        assert re.findall(r"\bopen\([^)]*\)", code) == ['open(path, "rb")']
        assert "KEY_READ" in code

    def test_profile_name_matches_the_harness(self):
        assert P.PROFILE_NAME == C.APPCONTAINER_PROFILE


class TestCollectInventory:
    def test_fake_source(self):
        source = FakeSource(good_inventory())
        inventory = P.collect_inventory(source)
        assert source.calls == list(P.COLLECTORS) and inventory == good_inventory()

    def test_failing_collector_is_recorded_not_raised(self):
        data = good_inventory()
        data["services"] = RuntimeError("OpenSCManager failed")
        data["venv"] = None
        inventory = P.collect_inventory(FakeSource(data))
        assert inventory["services"] == {"collected": False,
                                         "error": "RuntimeError: OpenSCManager failed"}
        assert inventory["venv"]["collected"] is False
        assert has(blockers(inventory), "services: not collected (RuntimeError")


# ---------------------------------------------------------------------------
# Inventory findings
# ---------------------------------------------------------------------------

class TestInventoryFindings:
    def test_clean_inventory_has_no_blocker(self):
        result = findings(good_inventory())
        assert [f for f in result if f.severity == "blocker"] == []
        assert any(f.area == "venv" and "executes code" in f.message for f in result)
        assert any(f.severity == "risk" and f.area == "onedrive" for f in result)

    def test_uncollected_evidence_blocks(self):
        result = blockers({})
        for name in P.COLLECTORS:
            assert has(result, f"{name}: not collected")
        inventory = good_inventory()
        inventory["services"] = dict(P.NOT_IMPLEMENTED)
        assert has(blockers(inventory), "separately reviewed read-only implementation")

    @pytest.mark.parametrize("missing", ["python313.dll", "DLLs/_socket.pyd",
                                         "vcruntime140.dll", "Lib/os.py"])
    def test_missing_python_dll(self, missing):
        inventory = good_inventory()
        inventory["python"]["files"].remove(missing)
        assert has(blockers(inventory), f"missing Python runtime file {missing}")

    def test_missing_native_extension(self):
        inventory = good_inventory()
        inventory["venv"]["native"] = ["grpc/_cython/cygrpc.cp313-win_amd64.pyd"]
        assert has(blockers(inventory), "native extension pydantic_core/_pydantic_core")

    def test_missing_package_and_incomplete_dependency_inventory(self):
        inventory = good_inventory()
        inventory["venv"]["top_level"].remove("langgraph")
        assert has(blockers(inventory), "required package langgraph missing")
        inventory["venv"]["top_level"] = []
        assert has(blockers(inventory), "incomplete dependency inventory")

    def test_onedrive_placeholder(self):
        inventory = good_inventory()
        inventory["onedrive"]["placeholders"] = ["demo-app/graph.py"]
        assert has(blockers(inventory), "OneDrive placeholder (not local): demo-app/graph.py")

    @pytest.mark.parametrize("architecture, bits", [("ARM64", 64), ("x86", 32), ("AMD64", 32),
                                                    (None, 64)])
    def test_unsupported_architecture(self, architecture, bits):
        inventory = good_inventory()
        inventory["windows"].update(architecture=architecture, pointer_bits=bits)
        assert has(blockers(inventory), "unsupported architecture")

    @pytest.mark.parametrize("service, state", [
        ("MpsSvc", {"status": "Stopped", "start": "Automatic"}),
        ("BFE", {"status": "Running", "start": "Manual"}),
        ("BFE", None),
    ])
    def test_stopped_service(self, service, state):
        inventory = good_inventory()
        inventory["services"][service] = state
        assert has(blockers(inventory), f"{service} is not Running/Automatic")

    def test_existing_foreign_profile(self):
        inventory = good_inventory()
        inventory["appcontainer_profiles"]["profiles"].append(
            {"name": P.PROFILE_NAME, "sid": "S-1-15-2-77"})
        assert has(blockers(inventory), "already exists (SID S-1-15-2-77)")

    def test_loopback_exemption(self):
        inventory = good_inventory()
        inventory["loopback_exemptions"] = {"collected": True, "sids": ["S-1-15-2-77"],
                                            "names": [P.PROFILE_NAME]}
        assert has(blockers(inventory), f"{P.PROFILE_NAME} has a loopback exemption")
        inventory["loopback_exemptions"]["names"] = ["other.app"]
        assert not has(blockers(inventory), "loopback exemption")
        assert any(f.area == "loopback_exemptions" and f.severity == "info"
                   for f in findings(inventory))

    @pytest.mark.parametrize("change, message", [
        ({"exists": False}, "missing or inaccessible"),
        ({"path": None}, "missing or inaccessible"),
        ({"writable": False}, "not writable"),
        ({"root_exists": True}, "never reused"),
        ({"path": r"C:\Users\u\OneDrive\Local"}, "under OneDrive"),
    ])
    def test_inaccessible_staging_path(self, change, message):
        inventory = good_inventory()
        inventory["staging_parent"].update(change)
        assert has(blockers(inventory), message)

    def test_incorrect_git_head(self):
        assert has(blockers(good_inventory(), expected_head="b" * 40), "incorrect Git HEAD")
        inventory = good_inventory()
        inventory["repository"]["head"] = "not-a-sha"
        assert has(blockers(inventory), "HEAD is unknown")

    def test_missing_source_file(self):
        inventory = good_inventory()
        inventory["repository"]["files"].remove("demo-app/graph.py")
        assert has(blockers(inventory), "required source file missing: demo-app/graph.py")

    def test_risks(self):
        inventory = good_inventory()
        inventory["privileges"] = {"collected": True, "is_admin": True, "privileges": []}
        inventory["firewall_profiles"]["enabled"]["public"] = False
        risks = [f.message for f in findings(inventory) if f.severity == "risk"]
        assert has(risks, "running elevated") and has(risks, "SeChangeNotifyPrivilege")
        assert has(risks, "firewall profiles disabled: public")


# ---------------------------------------------------------------------------
# Staging plan, manifest and recommendation
# ---------------------------------------------------------------------------

class TestStaging:
    def test_layout_is_pure(self, tmp_path):
        layout = P.propose_layout(str(tmp_path / "parent"))
        assert layout.root.endswith(r"parent\agentops-probe")
        assert layout.python.endswith(r"agentops-probe\python")
        assert not (tmp_path / "parent").exists()
        assert P.propose_layout(None).root == r"%LOCALAPPDATA%\agentops-probe"

    def test_required_repository_files(self):
        required, missing = P.required_repository_files(REPO_FILES)
        assert required == REQUIRED and missing == []
        _, missing = P.required_repository_files(["benchmarks/metrics.py"])
        assert "benchmarks/calibrate_generator.py" in missing

    def test_acl_intentions_are_minimal(self):
        grants = P.acl_intentions(P.propose_layout(r"C:\L"))
        assert {g["principal"] for g in grants} == {f"<SID of {P.PROFILE_NAME}>"}
        assert [g["rights"] for g in grants] == ["RX", "RX", "RX", "M"]
        assert grants[0]["inheritance"].startswith("none")
        assert grants[3]["path"] == r"C:\L\agentops-probe\out"
        text = json.dumps(grants)
        for broad in ("ALL APPLICATION PACKAGES", "S-1-15-2-1\"", "Everyone", "Users"):
            assert broad not in text


def _manifest(files=None, head=HEAD):
    files = files if files is not None else [(r, f"# {r}\n".encode()) for r in REQUIRED]
    return P.build_manifest(files, source_head=head, staged_repo=r"C:\L\agentops-probe\repo")


def _ls_tree(manifest):
    return {e["source_relative"]: e["git_blob_sha1"] for e in manifest["entries"]}


class TestManifest:
    def test_entries(self):
        manifest = P.build_manifest([("benchmarks\\metrics.py", b"hello\n")], source_head=HEAD,
                                    staged_repo=r"C:\S\repo")
        entry = manifest["entries"][0]
        assert entry == {"source_relative": "benchmarks/metrics.py",
                         "staged_path": r"C:\S\repo\benchmarks\metrics.py", "size": 6,
                         "sha256": hashlib.sha256(b"hello\n").hexdigest(),
                         "git_blob_sha1": "ce013625030ba8dba906f756967f9e9ca394464a"}
        assert manifest["source_head"] == HEAD and manifest["schema"] == P.SCHEMA_MANIFEST

    def test_complete_and_verified(self):
        manifest = _manifest()
        assert P.manifest_findings(manifest, required=REQUIRED, expected_head=HEAD,
                                   ls_tree=_ls_tree(manifest)) == []

    def test_incomplete_manifest(self):
        manifest = _manifest([(r, b"x") for r in REQUIRED[1:]])
        result = P.manifest_findings(manifest, required=REQUIRED, expected_head=HEAD,
                                     ls_tree=_ls_tree(manifest))
        assert has([f.message for f in result], f"incomplete manifest: {REQUIRED[0]} missing")

    def test_incorrect_head(self):
        manifest = _manifest(head="c" * 40)
        result = P.manifest_findings(manifest, required=REQUIRED, expected_head=HEAD,
                                     ls_tree=_ls_tree(manifest))
        assert has([f.message for f in result], "incorrect Git HEAD")

    def test_committed_content_checks(self):
        manifest = _manifest()
        tree = _ls_tree(manifest)
        tree[REQUIRED[0]] = "0" * 40
        del tree[REQUIRED[1]]
        messages = [f.message for f in P.manifest_findings(
            manifest, required=REQUIRED, expected_head=HEAD, ls_tree=tree)]
        assert has(messages, f"{REQUIRED[0]} differs from the committed file")
        assert has(messages, f"{REQUIRED[1]} is not tracked at HEAD")
        messages = [f.message for f in P.manifest_findings(
            manifest, required=REQUIRED, expected_head=HEAD, ls_tree=None)]
        assert has(messages, "committed content not verified")

    def test_malformed_entries(self):
        manifest = _manifest()
        broken = copy.deepcopy(manifest)
        broken["entries"][0]["sha256"] = "short"
        broken["entries"][1]["staged_path"] = r"C:\elsewhere\x.py"
        broken["entries"].append(dict(broken["entries"][2]))
        messages = [f.message for f in P.manifest_findings(
            broken, required=REQUIRED, expected_head=HEAD, ls_tree=_ls_tree(manifest))]
        assert has(messages, "incomplete entry") and has(messages, "mirrored path")
        assert has(messages, "duplicate entry")
        assert [f.message for f in P.manifest_findings(
            {"schema": "x"}, required=REQUIRED, expected_head=HEAD, ls_tree=None)] == [
            "no manifest in the expected format"]


class TestPlan:
    def test_default_plan_is_no_go(self):
        plan = P.build_plan({}, expected_head=None)
        assert plan["recommendation"] == "NO-GO" and plan["schema"] == P.SCHEMA_PLAN
        assert has(plan["reasons"], "windows: not collected")
        assert has(plan["reasons"], "no manifest in the expected format")

    def test_even_a_perfect_plan_is_no_go_until_the_harness_is_resolved(self):
        manifest = _manifest()
        plan = P.build_plan(good_inventory(), expected_head=HEAD, manifest=manifest,
                            ls_tree=_ls_tree(manifest),
                            verified={p: True for p in P.PREREQUISITES})
        assert plan["recommendation"] == "NO-GO"
        assert [r for r in plan["reasons"]] == [
            "harness: " + P.GIT_HEAD_STRATEGY["harness_incompatibility"]]

    def test_plan_contents(self):
        plan = P.build_plan(good_inventory(), expected_head=HEAD)
        staging = plan["staging"]
        assert staging["layout"]["root"] == r"C:\Users\u\AppData\Local\agentops-probe"
        assert staging["repository_files"] == REQUIRED
        assert "python313.dll" in staging["python_runtime_files"]
        assert staging["site_packages"]["destination"].endswith(
            r"agentops-probe\python\Lib\site-packages")
        assert "pydantic_core/_pydantic_core.cp313-win_amd64.pyd" in staging["native_extensions"]
        assert plan["manifest_format"]["fields"] == ["source_relative", "staged_path", "size",
                                                     "sha256", "git_blob_sha1"]
        assert "no_fabrication" in plan["git_head_strategy"]
        for key in ("permissions", "verification_checks", "host_side_effects",
                    "rollback_prerequisites", "unresolved_assumptions"):
            assert plan[key]

    def test_recommend(self):
        verified = {p: True for p in P.PREREQUISITES}
        assert P.recommend([], verified) == ("GO", [])
        assert P.recommend([P._risk("x", "y")], verified) == ("GO", [])
        decision, reasons = P.recommend([], {**verified, "host_prep_tool_reviewed": False})
        assert decision == "NO-GO" and has(reasons, "host_prep_tool_reviewed")
        assert P.recommend([P._blocker("a", "b")], verified) == ("NO-GO", ["a: b"])


# ---------------------------------------------------------------------------
# Staged identity: pure helpers
# ---------------------------------------------------------------------------

#: Independent published vectors: Git's EMPTY_BLOB constants (SHA-1 and
#: SHA-256), `echo hello | git hash-object --stdin`, and the Pro Git book's
#: "what is up, doc?" example.
EMPTY_SHA1 = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
EMPTY_SHA256 = "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
HELLO_SHA1 = "ce013625030ba8dba906f756967f9e9ca394464a"
DOC_SHA1 = "bd9dbf5aae1a3862dd1526723246b20206e5fc37"


class TestGitIdentity:
    def test_published_vectors(self):
        assert P.git_blob_id(b"", "sha1") == EMPTY_SHA1
        assert P.git_blob_id(b"", "sha256") == EMPTY_SHA256
        assert P.git_blob_id(b"hello\n", "sha1") == HELLO_SHA1
        assert P.git_blob_id(b"what is up, doc?", "sha1") == DOC_SHA1

    def test_formats_differ_and_inputs_are_checked(self):
        sha256 = P.git_blob_id(b"hello\n", "sha256")
        assert len(sha256) == 64 and sha256 != P.git_blob_id(b"hello\r\n", "sha256")
        with pytest.raises(P.PreflightError, match="unknown Git object format"):
            P.git_blob_id(b"x", "sha512")
        with pytest.raises(P.PreflightError, match="must be bytes"):
            P.git_blob_id("text", "sha1")

    @pytest.mark.parametrize("config, expected", [
        ("", "sha1"),
        ("[core]\n\trepositoryformatversion = 0\n\tautocrlf = true\n", "sha1"),
        ('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = x\n', "sha1"),
        ("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n",
         "sha256"),
        ("[core]\nrepositoryFormatVersion=1\n[Extensions]\nobjectFormat = SHA256 ; comment\n",
         "sha256"),
        ("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha1\n", "sha1"),
    ])
    def test_object_format_of(self, config, expected):
        assert P.object_format_of(config) == expected

    @pytest.mark.parametrize("config, message", [
        ("[core]\n\trepositoryformatversion = 0\n[extensions]\n\tobjectformat = sha256\n",
         "requires repositoryformatversion 1"),
        ("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha512\n",
         "unknown Git object format"),
        ("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha1\n"
         "\tobjectformat = sha256\n", "conflicting extensions.objectformat"),
        ("[core]\n\trepositoryformatversion = 0\n\trepositoryformatversion = 1\n",
         "conflicting repositoryformatversion"),
        ("[core]\n\trepositoryformatversion = 2\n", "unsupported"),
        ("[core\n\tbare = false\n", "malformed Git config section"),
        ("objectformat = sha1\n", "malformed Git config line"),
        ("[core]\n= x\n", "malformed Git config line"),
        (None, "must be text"),
    ])
    def test_object_format_rejections(self, config, message):
        with pytest.raises(P.PreflightError, match=message):
            P.object_format_of(config)


class TestCanonical:
    def test_canonical_bytes(self):
        assert P.canonical_json({"b": 1, "a": [True, None, "\u00e9"]}) == \
            '{"a":[true,null,"\u00e9"],"b":1}'.encode("utf-8")
        assert P.CANONICAL_SEPARATORS == (",", ":")

    def test_digest_stability(self):
        one = {"schema": "s", "entries": [{"path": "a.py", "size": 1}], "z": {"y": 2, "x": 1}}
        two = json.loads(json.dumps({"z": {"x": 1, "y": 2}, "entries": one["entries"],
                                     "schema": "s"}, indent=4))
        assert P.manifest_digest(one) == P.manifest_digest(two)
        assert P.manifest_digest(one) == hashlib.sha256(P.canonical_json(one)).hexdigest()
        changed = copy.deepcopy(one)
        changed["entries"][0]["size"] = 2
        assert P.manifest_digest(changed) != P.manifest_digest(one)

    @pytest.mark.parametrize("value, message", [
        ({"a": 1.5}, "floats"), ({"a": float("nan")}, "floats"), ({1: "x"}, "non-string key"),
        ({"a": {1, 2}}, "not canonical JSON"), ({"a": object()}, "not canonical JSON"),
    ])
    def test_non_canonical_values(self, value, message):
        with pytest.raises(P.PreflightError, match=message):
            P.canonical_json(value)

    @pytest.mark.parametrize("key", ["digest", "sha256", "manifest_sha256"])
    def test_a_manifest_cannot_carry_its_own_digest(self, key):
        with pytest.raises(P.PreflightError, match="own digest"):
            P.manifest_digest({"schema": "s", "entries": [], key: "0" * 64})


class TestRelativePaths:
    @pytest.mark.parametrize("path", [
        "benchmarks/metrics.py", "demo-app/agents/retrieval.py", "a/.hidden", "con_x.py",
        "COM10.py", "Lib/site-packages/pydantic_core/_pydantic_core.cp313-win_amd64.pyd",
    ])
    def test_valid(self, path):
        assert P.validate_relative_path(path) == path

    @pytest.mark.parametrize("path", [
        "", "/abs/x", "//server/share/x", "\\\\server\\share\\x", "C:/x", "C:x", "a\\b",
        "a/../b", "../a", "./a", "a//b", "a/", "a/b.", "a/b ", "a/file.py:stream",
        "a/file.py::$DATA", "con", "a/NUL.txt", "Com1.py", "LPT9", "conin$", "aux .py",
        "a/b?c", "a/b*c", "a\x00b", "a/<x>", 'a/"q"', "a/b|c", "x" * 241, 123, None,
    ])
    def test_attacks_rejected(self, path):
        with pytest.raises(P.PreflightError):
            P.validate_relative_path(path)

    def test_duplicates_and_case_collisions(self):
        manifest = {"entries": [{"path": "a.py"}, {"path": "b.py"}]}
        with pytest.raises(P.PreflightError, match="duplicate in the listing"):
            P.unexpected_files(["a.py", "a.py"], manifest)
        with pytest.raises(P.PreflightError, match="case-insensitive collision"):
            P.unexpected_files(["a/B.py", "a/b.py"], manifest)
        with pytest.raises(P.PreflightError, match="case-insensitive collision in the manifest"):
            P.unexpected_files([], {"entries": [{"path": "A.py"}, {"path": "a.py"}]})

    def test_missing_and_unexpected(self):
        manifest = {"entries": [{"path": "a.py"}, {"path": "b/c.py"},
                                {"source_relative": "d.py"}]}
        assert P.unexpected_files(["a.py", "b/c.py", "d.py"], manifest) == {
            "missing": [], "unexpected": []}
        assert P.unexpected_files(["a.py", "e.py", "sitecustomize.py"], manifest) == {
            "missing": ["b/c.py", "d.py"], "unexpected": ["e.py", "sitecustomize.py"]}
        assert P.unexpected_files(["A.py", "b/c.py", "d.py"], manifest) == {
            "missing": [], "unexpected": ["A.py"]}
        with pytest.raises(P.PreflightError, match="no entry list"):
            P.unexpected_files([], {"entries": None})
        with pytest.raises(P.PreflightError):
            P.unexpected_files(["../x"], manifest)


def _runtime_files(version=(3, 13)):
    files = [(path, f"{path}\n".encode()) for path in P._python_runtime_files(version)]
    return files + [("Lib/site-packages/pydantic/__init__.py", b"")]


class TestRuntimeManifest:
    def test_complete_and_deterministic(self):
        files = _runtime_files()
        manifest = P.build_runtime_manifest(files)
        assert manifest["schema"] == P.RUNTIME_SCHEMA
        assert [e["path"] for e in manifest["entries"]] == sorted(p for p, _ in files)
        entry = next(e for e in manifest["entries"] if e["path"] == "python.exe")
        assert entry == {"path": "python.exe", "size": len(b"python.exe\n"),
                         "sha256": hashlib.sha256(b"python.exe\n").hexdigest()}
        assert P.runtime_manifest_problems(manifest, version=(3, 13)) == []
        assert P.manifest_digest(manifest) == P.manifest_digest(
            P.build_runtime_manifest(list(reversed(files))))

    @pytest.mark.parametrize("drop", ["python313.dll", "DLLs/_socket.pyd", "Lib/site.py"])
    def test_missing_runtime_file(self, drop):
        manifest = P.build_runtime_manifest([f for f in _runtime_files() if f[0] != drop])
        assert f"missing runtime file {drop}" in P.runtime_manifest_problems(manifest,
                                                                            version=(3, 13))

    @pytest.mark.parametrize("extra", ["pyvenv.cfg", "Lib/sitecustomize.py",
                                       "Lib/site-packages/usercustomize.py"])
    def test_forbidden_runtime_file(self, extra):
        manifest = P.build_runtime_manifest(_runtime_files() + [(extra, b"")])
        assert f"forbidden runtime file {extra}" in P.runtime_manifest_problems(
            manifest, version=(3, 13))

    def test_malformed_input_and_manifest(self):
        with pytest.raises(P.PreflightError, match="case-insensitive collision"):
            P.build_runtime_manifest([("Lib/os.py", b""), ("lib/OS.py", b"")])
        with pytest.raises(P.PreflightError, match="must be bytes"):
            P.build_runtime_manifest([("a.py", "text")])
        with pytest.raises(P.PreflightError):
            P.build_runtime_manifest([("../a.py", b"")])
        manifest = P.build_runtime_manifest(_runtime_files())
        assert P.runtime_manifest_problems({"schema": "x"}, version=(3, 13)) == [
            "not a runtime manifest"]
        broken = copy.deepcopy(manifest)
        broken["entries"][0]["size"] = True
        broken["entries"][1]["sha256"] = "short"
        problems = P.runtime_manifest_problems(broken, version=(3, 13))
        assert sum("incomplete runtime entry" in p for p in problems) == 2


NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
SID7 = "S-1-15-2-1-2-3-4-5-6-7"
ROOT = r"C:\Users\u\AppData\Local\agentops-probe"


def good_context(**changes):
    context = {
        "schema": P.CONTEXT_SCHEMA, "head": HEAD, "object_format": "sha1",
        "repository_manifest_sha256": "1" * 64, "runtime_manifest_sha256": "2" * 64,
        "staging_root": ROOT, "interpreter_path": ROOT + r"\python\python.exe",
        "interpreter_sha256": "3" * 64, "run_id": "probe-01", "app_container_sid": SID7,
        "preflight_sha256": "4" * 64,
        "parent": {"pid": 1234, "creation_time": "2026-10-09T11:59:00.000Z"},
        "ownership_token": "0123456789abcdef0123456789abcdef",
        "created_utc": "2026-10-09T11:55:00Z", "expires_utc": "2026-10-09T12:25:00Z",
    }
    context.update(changes)
    return context


def expectations(context):
    return {k: copy.deepcopy(v) for k, v in context.items()
            if k not in ("schema", "created_utc", "expires_utc")}


class TestAuthorizationContext:
    def test_valid_and_bound(self):
        context = good_context()
        assert P.context_problems(context, now=NOW) == []
        assert P.verify_context_binding(context, expected_digest=P.context_digest(context),
                                        expected=expectations(context), now=NOW) == []
        assert P.verify_context_binding(
            context, expected_digest=P.context_digest(context),
            expected={**expectations(context), "staging_root": ROOT.upper(),
                      "interpreter_path": context["interpreter_path"].lower()}, now=NOW) == []

    def test_missing_and_extra_fields(self):
        context = good_context()
        del context["run_id"]
        assert P.context_problems(context, now=NOW) == ["missing fields: run_id"]
        assert P.context_problems(good_context(note="x"), now=NOW) == [
            "unexpected fields: note"]
        assert P.context_problems([], now=NOW) == ["the context is not a JSON object"]

    @pytest.mark.parametrize("changes, message", [
        ({"schema": "other/1"}, "wrong schema"),
        ({"object_format": "sha512"}, "unknown object format"),
        ({"object_format": "sha256"}, "not a sha256 commit id"),
        ({"head": "A" * 40}, "not a sha1 commit id"),
        ({"repository_manifest_sha256": "x"}, "repository_manifest_sha256 is not a SHA-256"),
        ({"interpreter_sha256": None}, "interpreter_sha256 is not a SHA-256"),
        ({"staging_root": "relative\\path"}, "staging_root is not a valid absolute path"),
        ({"staging_root": r"\\server\share\x"}, "staging_root is not a valid absolute path"),
        ({"staging_root": ROOT + r"\..\other"}, "staging_root is not a valid absolute path"),
        ({"staging_root": ROOT + "\\"}, "staging_root is not a valid absolute path"),
        ({"interpreter_path": r"C:\Python313\python.exe"}, "inside staging_root"),
        ({"interpreter_path": ROOT + r"\python\pythonw.exe"}, "inside staging_root"),
        ({"interpreter_path": ROOT + r"\python\python.exe:ads"}, "interpreter_path is not"),
        ({"run_id": "bm-smoke-r0005-c32-rep2"}, "run_id is not an approved form"),
        ({"run_id": "probe-06"}, "run_id is not an approved form"),
        ({"app_container_sid": "S-1-5-21-1-2-3-1001"}, "not an AppContainer SID"),
        ({"parent": {"pid": 0, "creation_time": "2026-10-09T11:59:00Z"}}, "parent identity"),
        ({"parent": {"pid": True, "creation_time": "2026-10-09T11:59:00Z"}}, "parent identity"),
        ({"parent": {"pid": 5}}, "parent identity"),
        ({"ownership_token": "ABCDEF" * 5 + "AB"}, "ownership_token is malformed"),
        ({"created_utc": "yesterday"}, "malformed"),
        ({"expires_utc": "2026-10-09T11:00:00Z"}, "not after created_utc"),
        ({"expires_utc": "2026-10-09T14:00:01Z"}, "lifetime exceeds"),
        ({"preflight_sha256": 4.0}, "not canonical"),
    ])
    def test_malformed_fields(self, changes, message):
        problems = P.context_problems(good_context(**changes), now=NOW)
        assert any(message in p for p in problems), problems

    def test_clock_boundaries(self):
        context = good_context()
        created = datetime(2026, 10, 9, 11, 55, tzinfo=timezone.utc)
        expires = datetime(2026, 10, 9, 12, 25, tzinfo=timezone.utc)
        assert P.context_problems(context, now=created) == []
        assert P.context_problems(context, now=expires - timedelta(microseconds=1)) == []
        assert P.context_problems(context, now=expires) == ["the context has expired"]
        assert P.context_problems(context, now=created - timedelta(seconds=1)) == [
            "the context is not yet valid (created in the future)"]

    @pytest.mark.parametrize("field_name, value", [
        ("head", "b" * 40), ("object_format", "sha256"),
        ("repository_manifest_sha256", "9" * 64), ("runtime_manifest_sha256", "9" * 64),
        ("staging_root", r"C:\Users\u\AppData\Local\other"),
        ("interpreter_path", ROOT + r"\other\python.exe"), ("interpreter_sha256", "9" * 64),
        ("run_id", "probe-02"), ("app_container_sid", "S-1-15-2-9-9-9-9-9-9-9"),
        ("preflight_sha256", "9" * 64),
        ("parent", {"pid": 99, "creation_time": "2026-10-09T11:59:00Z"}),
        ("ownership_token", "f" * 32),
    ])
    def test_substitution_is_rejected_even_with_a_matching_digest(self, field_name, value):
        original = good_context()
        substituted = copy.deepcopy(original)
        substituted[field_name] = value
        if field_name == "object_format":
            substituted["head"] = "a" * 64
        if field_name == "staging_root":
            substituted["interpreter_path"] = value + r"\python\python.exe"
        problems = P.verify_context_binding(
            substituted, expected_digest=P.context_digest(substituted),   # attacker's digest
            expected=expectations(original), now=NOW)
        assert any(f"{field_name} differs" in p for p in problems), problems
        problems = P.verify_context_binding(
            substituted, expected_digest=P.context_digest(original),
            expected=expectations(original), now=NOW)
        assert "the context does not match the independently supplied digest" in problems

    def test_digest_is_never_self_authenticating(self):
        context = good_context()
        assert P.verify_context_binding(context, expected_digest=None,
                                        expected=expectations(context), now=NOW) == [
            "no independently supplied context digest"]
        with pytest.raises(P.PreflightError, match="own digest"):
            P.context_digest({**context, "context_sha256": P.context_digest(context)})
        assert "unexpected fields: context_sha256" in P.context_problems(
            {**context, "context_sha256": "0" * 64}, now=NOW)

    def test_every_field_needs_an_independent_expectation(self):
        context = good_context()
        expected = expectations(context)
        del expected["app_container_sid"]
        assert P.verify_context_binding(context, expected_digest=P.context_digest(context),
                                        expected=expected, now=NOW) == [
            "no independent expectation for app_container_sid"]

    def test_an_expired_context_is_never_bound(self):
        context = good_context()
        assert P.verify_context_binding(
            context, expected_digest=P.context_digest(context), expected=expectations(context),
            now=datetime(2026, 10, 9, 13, 0, tzinfo=timezone.utc)) == ["the context has expired"]


def _all_checks(**failures):
    return [P.PrelaunchCheck(name, name not in failures, failures.get(name, ""))
            for name in P.REQUIRED_PRELAUNCH_CHECKS]


UTC = "2026-10-09T12:00:00Z"


class TestPrelaunchModel:
    def test_categories_cover_the_failure_model(self):
        assert set(P.CHECK_CATEGORIES.values()) == set(P.FAILURE_CATEGORIES)
        assert len(P.FAILURE_CATEGORIES) == 12
        assert "evidence_durable" not in P.REQUIRED_PRELAUNCH_CHECKS

    def test_passed_record_and_launch(self):
        record = P.build_prelaunch_record("probe-01", _all_checks(), utc=UTC,
                                          context_sha256="5" * 64)
        assert record["result"] == "passed" and record["failure_category"] is None
        assert record["failure_categories"] == [] and record["context_sha256"] == "5" * 64
        assert P.launch_permitted(record, evidence_durable=True) == (True, "passed")
        allowed, reason = P.launch_permitted(record, evidence_durable=False)
        assert not allowed and reason.startswith("evidence_write_failed")

    @pytest.mark.parametrize("name", P.REQUIRED_PRELAUNCH_CHECKS)
    def test_every_failing_check(self, name):
        record = P.build_prelaunch_record("cal-a-01", _all_checks(**{name: "bad"}), utc=UTC)
        assert record["result"] == "refused"
        assert record["failure_category"] == P.CHECK_CATEGORIES[name]
        allowed, reason = P.launch_permitted(record, evidence_durable=True)
        assert not allowed and reason.startswith(P.CHECK_CATEGORIES[name])

    @pytest.mark.parametrize("category", [c for c in P.FAILURE_CATEGORIES
                                          if c != "evidence_write_failed"])
    def test_every_category_is_reachable(self, category):
        name = next(n for n, c in P.CHECK_CATEGORIES.items()
                    if c == category and n != "evidence_durable")
        record = P.build_prelaunch_record("probe-01", _all_checks(**{name: "x"}), utc=UTC)
        assert category in record["failure_categories"]

    def test_evidence_write_failure(self):
        record = P.build_evidence_failure_record("probe-01", utc=UTC,
                                                 path=r"C:\x\evidence\prelaunch-probe-01.json",
                                                 error="OSError: disk full")
        assert record["failure_category"] == "evidence_write_failed"
        assert record["result"] == "refused" and record["detail"]["error"].endswith("disk full")
        assert P.launch_permitted(record, evidence_durable=True)[0] is False

    def test_missing_check_counts_as_failed(self):
        checks = [c for c in _all_checks() if c.name != "locks_acquired"]
        record = P.build_prelaunch_record("probe-01", checks, utc=UTC)
        row = next(r for r in record["checks"] if r["name"] == "locks_acquired")
        assert row == {"name": "locks_acquired", "ok": False, "category": "lock_failed",
                       "detail": "not performed"}
        assert record["failure_category"] == "lock_failed"

    @pytest.mark.parametrize("checks, message", [
        (_all_checks() + [P.PrelaunchCheck("head", True)], "duplicate prelaunch check"),
        ([P.PrelaunchCheck("bogus", True)], "unknown prelaunch check"),
        ([P.PrelaunchCheck("evidence_durable", True)], "launch_permitted"),
        (["head"], "unknown prelaunch check"),
    ])
    def test_malformed_checks(self, checks, message):
        with pytest.raises(P.PreflightError, match=message):
            P.build_prelaunch_record("probe-01", checks, utc=UTC)

    @pytest.mark.parametrize("run_id, utc", [("bm-x", UTC), ("probe-01", "now"),
                                             ("probe-01", "2026-10-09T12:00:00+02:00")])
    def test_malformed_record_arguments(self, run_id, utc):
        with pytest.raises(P.PreflightError):
            P.build_prelaunch_record(run_id, _all_checks(), utc=utc)

    def test_tampered_records_are_not_launchable(self):
        record = P.build_prelaunch_record("probe-01", _all_checks(), utc=UTC)
        tampered = copy.deepcopy(record)
        tampered["checks"][0]["ok"] = False
        assert P.launch_permitted(tampered, evidence_durable=True)[0] is False
        shortened = copy.deepcopy(record)
        shortened["checks"].pop()
        assert P.launch_permitted(shortened, evidence_durable=True)[0] is False
        assert P.launch_permitted({"result": "passed"}, evidence_durable=True)[0] is False
        assert P.launch_permitted(None, evidence_durable=True)[0] is False


class TestNoImplicitAuthorization:
    def test_helpers_grant_nothing_and_gates_stay_closed(self):
        context = good_context()
        result = P.verify_context_binding(context, expected_digest=P.context_digest(context),
                                          expected=expectations(context), now=NOW)
        assert result == [] and isinstance(result, list)
        record = P.build_prelaunch_record("probe-01", _all_checks(), utc=UTC)
        assert P.launch_permitted(record, evidence_durable=True) == (True, "passed")
        assert (C.EXECUTION_ENABLED, C.APPROVED_CALIBRATIONS, C.PROBE_ENABLED,
                C.APPROVED_PROBES, C.AUTHORIZED_APPCONTAINER_SID,
                C.AUTHORIZED_PROFILE_PREFLIGHT_SHA256) == (False, frozenset(), False,
                                                          frozenset(), None, None)
        assert P.HOST_INVENTORY_ENABLED is False

    def test_the_planner_source_never_authorizes(self):
        code = SOURCE.split('"""', 2)[2]
        assert set(re.findall(r"harness\.(\w+)", code)) == {"_read_git_head"}
        assert not re.search(r"\bauthorize(_probe)?\(\w", code)          # no call with args
        assert not re.search(r"harness\.\w+\s*=", code)
        assert "Authorization(" not in code and "_SEAL" not in code

    def test_default_verdict_is_still_no_go(self):
        plan = P.build_plan({}, expected_head=None, verified={p: True for p in P.PREREQUISITES})
        assert plan["recommendation"] == "NO-GO"
        assert any(r.startswith("harness: ") for r in plan["reasons"])


# ---------------------------------------------------------------------------
# Job Object lifecycle policy (pure; fake evidence only)
# ---------------------------------------------------------------------------

PID, CREATED_AT = 4242, "2026-10-09T12:00:00.000Z"
SAME = {"pid": PID, "creation_time": CREATED_AT}
#: Complete job-verification evidence for the expected child.
MEMBER = SAME | {"in_job": True, "job_assignment": "assigned_at_creation",
                 "active_processes": 1, "total_processes": 1, "member_pids": [PID]}


def _lc(state, event, **evidence):
    return P.lifecycle_transition(state, event, evidence)


def created(assignment="assigned_at_creation"):
    return _lc(P.LifecycleState(), "created", pid=PID, creation_time=CREATED_AT,
               job_assignment=assignment, job_limits_verified=True)


def assigned():
    return _lc(created(), "job_assigned", **MEMBER)


def validated():
    return _lc(assigned(), "validated", **SAME, token_ok=True, image_ok=True)


def resumed():
    return _lc(validated(), "resume_result", **SAME, previous=1, intent_durable=True)


class TestLifecyclePolicyStatus:
    def test_policy_is_design_only(self):
        assert P.TERMINATION_POLICY == "conditionally_accepted_design_only"
        assert P.policy_enables_execution() is False
        assert P.timeout_schedule()["enables_execution"] is False
        assert P.DISCARD_EXIT_CODE == C.DISCARD_EXIT_CODE
        harness = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        assert "TERMINATION_POLICY" not in harness and "JobObject" not in harness

    def test_lifecycle_code_is_pure(self):
        start = SOURCE.index("# Job Object lifecycle policy")
        section = SOURCE[start:SOURCE.index("# Entry point (prints a plan")]
        for word in ("ctypes", "WinDLL", "windll", "subprocess", "socket", "open(", "Path(",
                     "os.", "time.sleep", "TerminateJobObject(", "CreateJobObject",
                     "threading", "harness."):
            assert word not in section, word


class TestLifecycleTransitions:
    def test_initial_state(self):
        state = P.LifecycleState()
        assert state.as_dict() == {
            "phase": "not_started", "process_created": False, "pid": None,
            "creation_time": None, "job_assignment": "not_created",
            "job_limits_verified": False, "execution_history": None, "liveness": None,
            "termination_cause": None, "exit_code": None, "exit_evidence": None,
            "handles_retained": False, "cleanup_errors": []}

    def test_happy_path_with_natural_exit(self):
        state = created()
        assert (state.phase, state.execution_history, state.liveness) == (
            "created_suspended", P.NEVER_EXECUTED, P.ALIVE_AT_LAST_CHECK)
        assert state.handles_retained and state.process_created
        state = resumed()
        assert (state.phase, state.execution_history) == ("resumed", P.MAY_HAVE_EXECUTED)
        state = _lc(state, "wait_result", **SAME, signaled=False, exit_code=None)
        assert state.liveness == P.ALIVE_AT_LAST_CHECK and state.phase == "resumed"
        state = _lc(state, "wait_result", **SAME, signaled=True, exit_code=0)
        assert (state.phase, state.liveness, state.termination_cause, state.exit_code,
                state.exit_evidence, state.handles_retained) == (
            "exited", P.CONFIRMED_EXITED, "natural_exit", 0, "wait+exit_code", False)
        assert state.execution_history == P.MAY_HAVE_EXECUTED

    def test_assignment_at_creation_is_the_only_success(self):
        state = assigned()
        assert (state.phase, state.job_assignment) == ("job_assigned", "assigned_at_creation")
        assert state.execution_history == P.NEVER_EXECUTED      # unchanged by membership

    def test_assignment_failure_then_verified_discard(self):
        state = _lc(created(), "assignment_failed", **SAME, reason="access denied")
        assert state.job_assignment == "assignment_failed" and state.phase == "assignment_failed"
        state = _lc(state, "terminate_result", **SAME, cause="discarded_before_resume",
                    api_ok=True, signaled=True, exit_code=P.DISCARD_EXIT_CODE)
        assert (state.liveness, state.termination_cause, state.execution_history) == (
            P.CONFIRMED_EXITED, "discarded_before_resume", P.NEVER_EXECUTED)

    def test_rejected_validation_is_discarded(self):
        state = _lc(assigned(), "validated", **SAME, token_ok=False, image_ok=True)
        assert state.phase == "rejected"
        with pytest.raises(P.LifecycleError, match="not allowed in phase rejected"):
            _lc(state, "resume_result", **SAME, previous=1, intent_durable=True)
        state = _lc(state, "terminate_result", **SAME, cause="discarded_before_resume",
                    api_ok=True, signaled=True, exit_code=P.DISCARD_EXIT_CODE)
        assert state.execution_history == P.NEVER_EXECUTED

    @pytest.mark.parametrize("evidence, phase, history", [
        ({"previous": 1}, "resumed", P.MAY_HAVE_EXECUTED),
        ({"previous": 0}, "resume_rejected", P.MAY_HAVE_EXECUTED),
        ({"previous": 2}, "resume_rejected", P.NEVER_EXECUTED),
        ({"previous": P.RESUME_FAILED_VALUE}, "resume_rejected", P.STATE_UNKNOWN),
        ({"error": "ResumeThread failed (Windows error 6)"}, "resume_rejected",
         P.STATE_UNKNOWN),
    ])
    def test_resume_results(self, evidence, phase, history):
        state = _lc(validated(), "resume_result", **SAME, intent_durable=True, **evidence)
        assert (state.phase, state.execution_history) == (phase, history)

    def test_no_resume_without_durable_intent(self):
        with pytest.raises(P.LifecycleError, match="durable resume-intent"):
            _lc(validated(), "resume_result", **SAME, previous=1, intent_durable=False)
        with pytest.raises(P.LifecycleError, match="exactly one of previous or error"):
            _lc(validated(), "resume_result", **SAME, previous=1, error="x", intent_durable=True)

    def test_timeout_termination_verified(self):
        state = _lc(resumed(), "terminate_result", **SAME, cause="job_terminated_timeout",
                    api_ok=True, signaled=True, exit_code=P.TIMEOUT_EXIT_CODE)
        assert (state.liveness, state.termination_cause, state.exit_evidence) == (
            P.CONFIRMED_EXITED, "job_terminated_timeout", "wait+exit_code")
        assert state.execution_history == P.MAY_HAVE_EXECUTED and not state.handles_retained

    def test_termination_api_success_without_exit_verification(self):
        state = _lc(resumed(), "terminate_result", **SAME, cause="job_terminated_timeout",
                    api_ok=True, signaled=False, exit_code=None)
        assert (state.phase, state.liveness, state.handles_retained) == (
            "termination_unverified", P.STATE_UNKNOWN, True)
        assert "not verified" in state.cleanup_errors[-1]
        with pytest.raises(P.LifecycleError, match="not allowed in phase termination_unverif"):
            _lc(state, "terminate_result", **SAME, cause="job_terminated_timeout",
                api_ok=True, signaled=True, exit_code=P.TIMEOUT_EXIT_CODE)   # no retry

    def test_wrong_exit_code_is_not_a_verified_termination(self):
        state = _lc(created(), "terminate_result", **SAME, cause="discarded_before_resume",
                    api_ok=True, signaled=True, exit_code=0)
        assert state.liveness == P.CONFIRMED_EXITED and state.termination_cause == "unknown"
        assert state.execution_history == P.STATE_UNKNOWN          # never upgraded
        state = _lc(resumed(), "terminate_result", **SAME, cause="job_terminated_operator",
                    api_ok=True, signaled=True, exit_code=P.TIMEOUT_EXIT_CODE)
        assert state.termination_cause == "unknown" and state.handles_retained

    def test_interrupted_cleanup(self):
        state = _lc(resumed(), "terminate_result", **SAME, cause="job_terminated_operator",
                    api_ok=False, signaled=False, exit_code=None)
        assert state.liveness == P.STATE_UNKNOWN and "call failed" in state.cleanup_errors[-1]
        state = _lc(state, "parent_lost")
        assert (state.phase, state.liveness, state.termination_cause) == (
            "parent_lost", P.STATE_UNKNOWN, "job_closed_parent_exit")

    def test_parent_crash_then_recovery(self):
        state = _lc(resumed(), "parent_lost")
        assert state.liveness == P.STATE_UNKNOWN and state.execution_history == \
            P.MAY_HAVE_EXECUTED
        gone = _lc(state, "recovery_inspection", pid=PID, found=False)
        assert (gone.liveness, gone.exit_evidence) == (P.CONFIRMED_EXITED,
                                                       "absent_from_process_table")
        reused = _lc(state, "recovery_inspection", pid=PID, found=True, creation_match=False)
        assert reused.liveness == P.CONFIRMED_EXITED
        exited = _lc(state, "recovery_inspection", pid=PID, found=True, creation_match=True,
                     signaled=True, exit_code=1)
        assert (exited.liveness, exited.exit_code) == (P.CONFIRMED_EXITED, 1)
        alive = _lc(state, "recovery_inspection", pid=PID, found=True, creation_match=True,
                    signaled=False, exit_code=None)
        assert alive.liveness == P.ALIVE_AT_LAST_CHECK and "still alive" in \
            alive.cleanup_errors[-1]
        ambiguous = _lc(state, "recovery_inspection", pid=PID, found=True, creation_match=True,
                        signaled=None, exit_code=None)
        assert ambiguous.liveness == P.STATE_UNKNOWN

    def test_parent_crash_before_resume_keeps_never_executed(self):
        state = _lc(created(), "parent_lost")
        assert state.execution_history == P.NEVER_EXECUTED and state.liveness == P.STATE_UNKNOWN

    @pytest.mark.parametrize("event, evidence", [
        ("job_assigned", MEMBER | {"pid": 999}),
        ("job_assigned", MEMBER | {"creation_time": "2026-10-09T12:00:01.000Z"}),
        ("validated", {"pid": 999, "creation_time": CREATED_AT, "token_ok": True,
                       "image_ok": True}),
    ])
    def test_pid_and_creation_time_mismatches(self, event, evidence):
        state = created() if event == "job_assigned" else assigned()
        with pytest.raises(P.LifecycleError, match="another process"):
            P.lifecycle_transition(state, event, evidence)
        with pytest.raises(P.LifecycleError, match="another PID"):
            _lc(_lc(resumed(), "parent_lost"), "recovery_inspection", pid=1, found=False)

    @pytest.mark.parametrize("state_factory, event, evidence, message", [
        (P.LifecycleState, "job_assigned", MEMBER, "not allowed"),
        (P.LifecycleState, "resume_result", SAME | {"previous": 1, "intent_durable": True},
         "not allowed"),
        (created, "created", {"pid": PID, "creation_time": CREATED_AT,
                              "job_assignment": "assigned_at_creation",
                              "job_limits_verified": True}, "not allowed"),
        (created, "resume_result", SAME | {"previous": 1, "intent_durable": True},
         "not allowed"),
        (created, "wait_result", SAME | {"signaled": True, "exit_code": 0}, "not allowed"),
        (resumed, "terminate_result", SAME | {"cause": "discarded_before_resume",
                                              "api_ok": True, "signaled": True,
                                              "exit_code": P.DISCARD_EXIT_CODE},
         "only possible before a valid resume"),
        (created, "terminate_result", SAME | {"cause": "job_terminated_timeout",
                                              "api_ok": True, "signaled": True,
                                              "exit_code": P.TIMEOUT_EXIT_CODE},
         "needs a resumed"),
        (resumed, "terminate_result", SAME | {"cause": "reboot", "api_ok": True,
                                              "signaled": True, "exit_code": 1},
         "unknown termination cause"),
        (P.LifecycleState, "parent_lost", {}, "created child"),
        (resumed, "recovery_inspection", {"pid": PID, "found": False}, "not allowed"),
        (resumed, "explode", {}, "unknown lifecycle event"),
    ])
    def test_illegal_transitions(self, state_factory, event, evidence, message):
        with pytest.raises(P.LifecycleError, match=message):
            P.lifecycle_transition(state_factory(), event, evidence)

    @pytest.mark.parametrize("state_factory, event, evidence, message", [
        (resumed, "wait_result", SAME | {"signaled": True, "exit_code": None},
         "needs the exit code"),
        (resumed, "wait_result", SAME | {"signaled": False, "exit_code": 0}, "contradictory"),
        (resumed, "terminate_result", SAME | {"cause": "job_terminated_timeout",
                                              "api_ok": True, "signaled": False,
                                              "exit_code": 7}, "contradictory"),
        (resumed, "wait_result", SAME | {"signaled": "yes", "exit_code": 0},
         "true or false"),
        (resumed, "wait_result", SAME | {"signaled": True, "exit_code": True},
         "must be an integer"),
        (created, "job_assigned", SAME | {"in_job": False}, "use assignment_failed"),
    ])
    def test_contradictory_evidence(self, state_factory, event, evidence, message):
        with pytest.raises(P.LifecycleError, match=message):
            P.lifecycle_transition(state_factory(), event, evidence)

    @pytest.mark.parametrize("evidence, message", [
        ({"pid": 0, "creation_time": CREATED_AT, "job_assignment": "assigned_at_creation",
          "job_limits_verified": True}, "positive PID"),
        ({"pid": PID, "creation_time": "noon", "job_assignment": "assigned_at_creation",
          "job_limits_verified": True}, "UTC creation time"),
        ({"pid": PID, "creation_time": CREATED_AT, "job_assignment": "assigned_at_creation",
          "job_limits_verified": False}, "job limits are verified"),
        ({"pid": PID, "creation_time": CREATED_AT, "job_assignment": "assignment_failed",
          "job_limits_verified": True}, "job_assignment"),
    ])
    def test_creation_requirements(self, evidence, message):
        with pytest.raises(P.LifecycleError, match=message):
            P.lifecycle_transition(P.LifecycleState(), "created", evidence)

    def test_exited_is_terminal(self):
        state = _lc(resumed(), "wait_result", **SAME, signaled=True, exit_code=0)
        for event in ("wait_result", "terminate_result", "parent_lost", "resume_result"):
            with pytest.raises(P.LifecycleError):
                _lc(state, event, **SAME, signaled=True, exit_code=0)


class TestResumeClassification:
    @pytest.mark.parametrize("value, history", [
        (1, P.MAY_HAVE_EXECUTED), (0, P.MAY_HAVE_EXECUTED), (2, P.NEVER_EXECUTED),
        (127, P.NEVER_EXECUTED), (P.RESUME_FAILED_VALUE, P.STATE_UNKNOWN),
        (OSError("failed"), P.STATE_UNKNOWN), ("Windows error 6", P.STATE_UNKNOWN),
    ])
    def test_classification(self, value, history):
        assert P.classify_resume(value) == history

    @pytest.mark.parametrize("value", [True, None, 1.0, -1, P.RESUME_FAILED_VALUE + 1])
    def test_invalid(self, value):
        with pytest.raises(P.LifecycleError):
            P.classify_resume(value)


class TestTimeoutSchedule:
    def test_default_plan(self):
        plan = P.timeout_schedule()
        assert plan["plan_only"] is True and plan["policy"] == P.TERMINATION_POLICY
        assert (plan["deadline_s"], plan["grace_s"], plan["hard_deadline_s"]) == (180, 60, 240)
        assert plan["max_wall_s"] == 240 + 5 + 2 + 5
        assert plan["evidence_checkpoints"] == ["timeout", "terminate_intent",
                                                "terminate_result", "final_inspection",
                                                "complete"]
        assert plan["exit_verification"] == {"required": True, "signalled_wait": True,
                                             "exit_code": P.TIMEOUT_EXIT_CODE, "within_s": 5}
        times = [a["at_s"] for a in plan["actions"]]
        assert times == sorted(times) and max(times) == 240
        texts = " | ".join(a["action"] for a in plan["actions"])
        for phrase in ("durable resume-intent", "durable timeout evidence", "notify the operator",
                       "durable terminate-intent", "verify the exit", "ownership retained"):
            assert phrase in texts

    def test_custom_bounds(self):
        plan = P.timeout_schedule(10, 1, 1, 0.5, 0.5)
        assert plan["hard_deadline_s"] == 11 and plan["max_wall_s"] == 13

    @pytest.mark.parametrize("kwargs, message", [
        ({"deadline_s": 0}, "positive"), ({"grace_s": -1}, "positive"),
        ({"terminate_wait_s": float("inf")}, "finite"), ({"observe_interval_s": float("nan")},
                                                         "finite"),
        ({"deadline_s": None}, "finite"), ({"deadline_s": True}, "finite"),
        ({"deadline_s": 3601}, "exceeds its bound"), ({"grace_s": 601}, "exceeds"),
        ({"terminate_wait_s": 61}, "exceeds"), ({"observe_timeout_s": 31}, "exceeds"),
        ({"deadline_s": 3, "observe_timeout_s": 5}, "fit inside the deadline"),
        ({"policy": "accepted"}, "unsupported termination policy"),
        ({"policy": "never_terminate"}, "unsupported termination policy"),
        ({"exit_verification": False}, "exit verification is required"),
    ])
    def test_rejections(self, kwargs, message):
        with pytest.raises(P.LifecycleError, match=message):
            P.timeout_schedule(**kwargs)


GOOD_READBACK = {"limit_flags": P.JOB_LIMIT_POLICY["required_flags"], "active_process_limit": 1,
                 "job_handle_inheritable": False, "in_job_before_resume": True}


class TestJobLimits:
    def test_policy_and_good_readback(self):
        assert P.JOB_LIMIT_POLICY["required_flags"] == 0x2000 | 0x8 | 0x400
        assert P.JOB_LIMIT_POLICY["prohibited_flags"] == 0x800 | 0x1000
        assert P.job_limits_problems(GOOD_READBACK) == []

    @pytest.mark.parametrize("change, message", [
        ({"limit_flags": 0x8 | 0x400}, "required limit flags missing: 0x2000"),
        ({"limit_flags": P.JOB_LIMIT_POLICY["required_flags"] | 0x800}, "breakaway"),
        ({"limit_flags": P.JOB_LIMIT_POLICY["required_flags"] | 0x1000}, "breakaway"),
        ({"limit_flags": P.JOB_LIMIT_POLICY["required_flags"] | 0x2}, "unexpected limit flags"),
        ({"active_process_limit": 2}, "not 1"),
        ({"active_process_limit": True}, "not 1"),
        ({"job_handle_inheritable": True}, "inheritable"),
        ({"job_handle_inheritable": None}, "inheritable"),
        ({"in_job_before_resume": False}, "not verified before resume"),
    ])
    def test_wrong_limits(self, change, message):
        assert any(message in p for p in P.job_limits_problems({**GOOD_READBACK, **change}))

    def test_malformed_readback(self):
        assert P.job_limits_problems(None) == ["no job read-back"]
        assert P.job_limits_problems({"limit_flags": "x"}) == ["limit_flags missing or malformed"]


# ---------------------------------------------------------------------------
# Assignment policy, configuration and membership validation (J-34)
# ---------------------------------------------------------------------------

@pytest.fixture
def no_native(monkeypatch):
    """Any native library load fails the test."""
    import ctypes

    def refuse(*args, **kwargs):
        raise LiveAccessAttempt("a native library load attempted")

    monkeypatch.setattr(ctypes, "WinDLL", refuse)
    monkeypatch.setattr(ctypes, "CDLL", refuse)


GOOD_CONFIG = {"limit_flags": P.JOB_LIMIT_POLICY["required_flags"], "active_process_limit": 1,
               "job_handle_inheritable": False}


def membership(**changes):
    evidence = {key: value for key, value in (MEMBER | changes).items()
                if value is not _ABSENT}
    return P.job_membership_problems(evidence, expected_pid=PID,
                                     expected_creation_time=CREATED_AT)


_ABSENT = object()


@pytest.mark.usefixtures("no_native")
class TestAssignmentPolicy:
    def test_accepted_assignment_reaches_resume(self):
        assert P.ACCEPTED_JOB_ASSIGNMENT == "assigned_at_creation"
        assert "assigned_before_resume" in P.JOB_ASSIGNMENTS        # recordable, never accepted
        state = resumed()
        assert (state.phase, state.job_assignment, state.execution_history) == (
            "resumed", "assigned_at_creation", P.MAY_HAVE_EXECUTED)

    def test_assigned_before_resume_refused_everywhere(self):
        with pytest.raises(P.LifecycleError, match="after creation is refused"):
            created("assigned_before_resume")
        with pytest.raises(P.LifecycleError, match="assigned_before_resume\\) is refused"):
            _lc(created(), "job_assigned", **(MEMBER | {"job_assignment":
                                                         "assigned_before_resume"}))
        forged = P.LifecycleState(phase="created_suspended", process_created=True, pid=PID,
                                  creation_time=CREATED_AT,
                                  job_assignment="assigned_before_resume",
                                  job_limits_verified=True,
                                  execution_history=P.NEVER_EXECUTED,
                                  liveness=P.ALIVE_AT_LAST_CHECK, handles_retained=True)
        with pytest.raises(P.LifecycleError, match="assignment after creation is refused"):
            _lc(forged, "job_assigned", **MEMBER)

    @pytest.mark.parametrize("value", ["unknown", "not_created", "assignment_failed",
                                       "assigned_before_resume"])
    def test_unknown_or_unsuccessful_assignment_refused_at_creation(self, value):
        with pytest.raises(P.LifecycleError, match="job_assignment assigned_at_creation"):
            created(value)

    def test_missing_assignment_refused(self):
        with pytest.raises(P.LifecycleError, match="job_assignment"):
            _lc(P.LifecycleState(), "created", pid=PID, creation_time=CREATED_AT,
                job_limits_verified=True)
        evidence = {k: v for k, v in MEMBER.items() if k != "job_assignment"}
        with pytest.raises(P.LifecycleError, match="missing: job_assignment"):
            _lc(created(), "job_assigned", **evidence)

    @pytest.mark.parametrize("value", [None, 1, True, ["assigned_at_creation"],
                                       "ASSIGNED_AT_CREATION", "assigned_at_creation ",
                                       b"assigned_at_creation"])
    def test_malformed_assignment_refused(self, value):
        with pytest.raises(P.LifecycleError, match="job_assignment"):
            created(value)
        with pytest.raises(P.LifecycleError, match="job_assignment"):
            _lc(created(), "job_assigned", **(MEMBER | {"job_assignment": value}))

    @pytest.mark.parametrize("assignment, verified", [
        ("assigned_before_resume", True), ("unknown", True), ("assignment_failed", True),
        ("not_created", True), ("assigned_at_creation", False)])
    def test_no_advancement_without_assignment_at_creation(self, assignment, verified):
        base = dict(process_created=True, pid=PID, creation_time=CREATED_AT,
                    job_assignment=assignment, job_limits_verified=verified,
                    execution_history=P.NEVER_EXECUTED, liveness=P.ALIVE_AT_LAST_CHECK,
                    handles_retained=True)
        with pytest.raises(P.LifecycleError, match="assigned to a verified job at creation"):
            _lc(P.LifecycleState(phase="job_assigned", **base), "validated", **SAME,
                token_ok=True, image_ok=True)
        with pytest.raises(P.LifecycleError, match="assigned to a verified job at creation"):
            _lc(P.LifecycleState(phase="validated", **base), "resume_result", **SAME,
                previous=1, intent_durable=True)

    def test_refused_membership_keeps_history_and_allows_discard(self):
        state = created()
        with pytest.raises(P.LifecycleError, match="membership is not verified"):
            _lc(state, "job_assigned", **(MEMBER | {"total_processes": 2}))
        assert (state.phase, state.execution_history) == ("created_suspended",
                                                          P.NEVER_EXECUTED)
        state = _lc(state, "assignment_failed", **SAME, reason="membership refused")
        state = _lc(state, "terminate_result", **SAME, cause="discarded_before_resume",
                    api_ok=True, signaled=True, exit_code=P.DISCARD_EXIT_CODE)
        assert (state.liveness, state.execution_history, state.termination_cause) == (
            P.CONFIRMED_EXITED, P.NEVER_EXECUTED, "discarded_before_resume")

    def test_failure_and_recovery_rules_unchanged(self):
        expected = {
            "assignment_failed": ("discard_before_resume", "discard", P.NEVER_EXECUTED),
            "not_in_job": ("discard_before_resume", "discard", P.NEVER_EXECUTED),
            "nested_job_incompatible": ("prelaunch_refusal", "none", None),
            "job_readback_mismatch": ("prelaunch_refusal", "none", None),
            "parent_crash": ("unknown_liveness", "recovery_inspection", "unchanged"),
            "resume_api_failed": ("possible_execution", "bounded_termination",
                                  P.STATE_UNKNOWN),
        }
        for key, (action, containment, history) in expected.items():
            entry = P.FAILURE_ACTIONS[key]
            assert (entry["action_class"], entry["containment"],
                    entry["execution_history"]) == (action, containment, history), key
        assert len(P.FAILURE_ACTIONS) == 22
        state = _lc(assigned(), "parent_lost")
        assert state.execution_history == P.NEVER_EXECUTED and state.liveness == P.STATE_UNKNOWN

    def test_lifecycle_state_shape_unchanged(self):
        assert list(P.LifecycleState().as_dict()) == [
            "phase", "process_created", "pid", "creation_time", "job_assignment",
            "job_limits_verified", "execution_history", "liveness", "termination_cause",
            "exit_code", "exit_evidence", "handles_retained", "cleanup_errors"]


@pytest.mark.usefixtures("no_native")
class TestConfigurationValidation:
    def test_good_configuration(self):
        assert P.job_configuration_problems(GOOD_CONFIG) == []

    @pytest.mark.parametrize("flags, message", [
        (0x8 | 0x400, "required limit flags missing: 0x2000"),
        (0x2000 | 0x400, "required limit flags missing: 0x8"),
        (0x2000 | 0x8, "required limit flags missing: 0x400"),
        (P.JOB_LIMIT_POLICY["required_flags"] | 0x800, "breakaway flags present: 0x800"),
        (P.JOB_LIMIT_POLICY["required_flags"] | 0x1000, "breakaway flags present: 0x1000"),
        (P.JOB_LIMIT_POLICY["required_flags"] | 0x2, "unexpected limit flags: 0x2"),
    ])
    def test_required_and_prohibited_flags(self, flags, message):
        problems = P.job_configuration_problems(GOOD_CONFIG | {"limit_flags": flags})
        assert problems == [message]

    @pytest.mark.parametrize("change, message", [
        ({"active_process_limit": 0}, "active process limit is 0, not 1"),
        ({"active_process_limit": 2}, "active process limit is 2, not 1"),
        ({"active_process_limit": True}, "active process limit is True, not 1"),
        ({"active_process_limit": None}, "active process limit is None, not 1"),
        ({"job_handle_inheritable": True}, "the job handle is (or may be) inheritable"),
        ({"job_handle_inheritable": None}, "the job handle is (or may be) inheritable"),
        ({"job_handle_inheritable": 0}, "the job handle is (or may be) inheritable"),
    ])
    def test_limit_and_inheritance_failures(self, change, message):
        assert P.job_configuration_problems(GOOD_CONFIG | change) == [message]

    def test_malformed_configuration(self):
        assert P.job_configuration_problems(None) == ["no job read-back"]
        for flags in ("x", None, -1, True, 1.0):
            assert P.job_configuration_problems(GOOD_CONFIG | {"limit_flags": flags}) == [
                "limit_flags missing or malformed"]

    def test_configuration_ignores_membership(self):
        for extra in ({}, {"in_job_before_resume": False}, {"in_job_before_resume": True}):
            assert P.job_configuration_problems(GOOD_CONFIG | extra) == []

    @pytest.mark.parametrize("change", [
        {}, {"limit_flags": 0x408}, {"limit_flags": 0x2408 | 0x1800},
        {"active_process_limit": 3}, {"job_handle_inheritable": True},
        {"in_job_before_resume": False}, {"in_job_before_resume": None},
        {"limit_flags": "x", "in_job_before_resume": False},
    ])
    def test_original_interface_is_compatible(self, change):
        readback = GOOD_READBACK | change
        legacy = [] if readback.get("in_job_before_resume") is True else [
            "job membership was not verified before resume"]
        config = P.job_configuration_problems(readback)
        expected = config if config == ["limit_flags missing or malformed"] else config + legacy
        assert P.job_limits_problems(readback) == expected

    @pytest.mark.parametrize("readback", [
        {"limit_flags": 0x2408, "active_process_limit": 1},
        {"limit_flags": 0x0408, "active_process_limit": 1},
        {"limit_flags": 0x2408 | 0x800, "active_process_limit": 1},
        {"limit_flags": 0x2408 | 0x2, "active_process_limit": 1},
        {"limit_flags": 0x2408, "active_process_limit": 2},
        {"limit_flags": 0x2408, "active_process_limit": True},
        {"limit_flags": None, "active_process_limit": 1},
        {"limit_flags": -1, "active_process_limit": None},
        {},
    ])
    @pytest.mark.parametrize("inheritable", [False, True, None])
    def test_equivalent_to_the_backend_rules(self, readback, inheritable):
        import win32_job as W                                      # backend: unchanged here
        planner = P.job_configuration_problems({**readback, "job_handle_inheritable":
                                                inheritable})
        assert W.configuration_problems(readback, inheritable) == planner


@pytest.mark.usefixtures("no_native")
class TestMembershipValidation:
    def test_complete_evidence(self):
        assert membership() == []
        assert membership(member_pids=(PID,)) == []

    @pytest.mark.parametrize("total, ok", [(0, False), (1, True), (2, False)])
    def test_total_processes(self, total, ok):
        problems = membership(total_processes=total)
        assert (problems == []) is ok
        if not ok:
            assert problems == [f"{total} processes have been in the job, not 1"]

    @pytest.mark.parametrize("active", [0, 2])
    def test_active_processes(self, active):
        assert membership(active_processes=active) == [f"{active} active processes, not 1"]

    @pytest.mark.parametrize("field", P.JOB_MEMBERSHIP_FIELDS)
    def test_each_missing_field_refuses(self, field):
        assert membership(**{field: _ABSENT}) == [f"membership evidence missing: {field}"]

    def test_non_mapping_and_empty(self):
        assert P.job_membership_problems(None, expected_pid=PID,
                                         expected_creation_time=CREATED_AT) == [
            "no membership evidence"]
        assert P.job_membership_problems({}, expected_pid=PID,
                                         expected_creation_time=CREATED_AT) == [
            "membership evidence missing: " + ", ".join(P.JOB_MEMBERSHIP_FIELDS)]

    @pytest.mark.parametrize("changes, message", [
        ({"active_processes": True}, "active_processes is malformed"),
        ({"active_processes": "1"}, "active_processes is malformed"),
        ({"total_processes": None}, "total_processes is malformed"),
        ({"total_processes": 1.0}, "total_processes is malformed"),
        ({"in_job": "yes"}, "in_job is malformed"),
        ({"in_job": None}, "in_job is malformed"),
        ({"in_job": False}, "the child is not in the job"),
        ({"member_pids": None}, "member_pids is malformed"),
        ({"member_pids": str(PID)}, "member_pids is malformed"),
        ({"member_pids": [True]}, "member_pids is malformed"),
        ({"member_pids": []}, "the job members are [], not [4242]"),
        ({"member_pids": [PID, 7]}, "the job members are [4242, 7], not [4242]"),
        ({"member_pids": [7]}, "the job members are [7], not [4242]"),
        ({"job_assignment": "unknown"}, "job_assignment is unknown, not assigned_at_creation"),
        ({"job_assignment": "bogus"}, "job_assignment is malformed"),
    ])
    def test_malformed_or_contradictory_evidence(self, changes, message):
        assert any(message in problem for problem in membership(**changes))

    @pytest.mark.parametrize("changes, message", [
        ({"pid": 999}, "the PID 999 is not the expected child's"),
        ({"pid": True}, "the PID True is not the expected child's"),
        ({"pid": str(PID)}, "is not the expected child's"),
        ({"creation_time": "2026-10-09T12:00:01.000Z"}, "creation time is not the expected"),
        ({"creation_time": None}, "creation time is not the expected"),
    ])
    def test_identity_mismatch(self, changes, message):
        assert any(message in problem for problem in membership(**changes))

    @pytest.mark.parametrize("expected_pid, expected_time", [
        (None, CREATED_AT), (0, CREATED_AT), (True, CREATED_AT), (PID, "noon"), (PID, None)])
    def test_invalid_expected_identity_refuses(self, expected_pid, expected_time):
        problems = P.job_membership_problems(MEMBER, expected_pid=expected_pid,
                                             expected_creation_time=expected_time)
        assert "no valid expected child identity" in problems

    @pytest.mark.parametrize("changes", [
        {"total_processes": 0}, {"total_processes": 2}, {"active_processes": 2},
        {"member_pids": [PID, 7]}, {"in_job": "true"}, {"total_processes": _ABSENT},
    ])
    def test_lifecycle_refuses_bad_membership(self, changes):
        evidence = {k: v for k, v in (MEMBER | changes).items() if v is not _ABSENT}
        with pytest.raises(P.LifecycleError):
            P.lifecycle_transition(created(), "job_assigned", evidence)

    def test_validators_are_pure(self):
        start = SOURCE.index("def job_configuration_problems")
        section = SOURCE[start:SOURCE.index("#: Durable evidence stages")]
        for word in ("ctypes", "WinDLL", "subprocess", "socket", "open(", "Path(", "os.",
                     "time.", "harness.", "import "):
            assert word not in section, word


STAGES = list(P.LIFECYCLE_STAGES)


class TestStageOrder:
    def test_happy_progression(self):
        assert P.next_stage_allowed([], False)["allowed"] == ["prelaunch"]
        state = P.next_stage_allowed(STAGES[:2], False)
        assert state["allowed"] == ["process_created"] and state["may_launch"]
        state = P.next_stage_allowed(STAGES[:5], False)
        assert state["allowed"] == ["resume_result"] and state["may_resume"]
        assert not P.next_stage_allowed(STAGES[:4], False)["may_resume"]
        assert P.next_stage_allowed(STAGES[:6], False)["allowed"] == [
            "timeout_or_termination", "final_inspection"]
        assert P.next_stage_allowed(STAGES[:7], False)["allowed"] == ["final_inspection"]
        skipped = [s for s in STAGES if s != "timeout_or_termination"]
        assert P.next_stage_allowed(skipped[:-1], False)["allowed"] == ["complete"]
        assert P.next_stage_allowed(STAGES, False)["allowed"] == []

    @pytest.mark.parametrize("stages, message", [
        (["job_configured"], "skipped"),
        (["prelaunch", "process_created"], "skipped"),
        (["job_configured", "prelaunch"], "out of order"),
        (["prelaunch", "prelaunch"], "repeated"),
        (["prelaunch", "bogus"], "unknown"),
        (STAGES[:5] + ["timeout_or_termination"], "needs a resume result"),
    ])
    def test_order_violations(self, stages, message):
        with pytest.raises(P.LifecycleError, match=message):
            P.next_stage_allowed(stages, False)

    @pytest.mark.parametrize("stages, containment, allowed", [
        ([], "none", []),
        (STAGES[:1], "none", []),
        (STAGES[:2], "discard_if_created", ["final_inspection"]),
        (STAGES[:4], "discard_if_created", ["final_inspection"]),
        (STAGES[:5], "bounded_termination", ["timeout_or_termination", "final_inspection"]),
        (STAGES[:6], "bounded_termination", ["timeout_or_termination", "final_inspection"]),
        (STAGES[:8], "bounded_termination", []),
        (STAGES, "none", []),
    ])
    def test_evidence_failure(self, stages, containment, allowed):
        state = P.next_stage_allowed(stages, True)
        assert not state["may_launch"] and not state["may_resume"] and state["series_blocked"]
        assert (state["containment"], state["allowed"]) == (containment, allowed)

    def test_evidence_flag_must_be_boolean(self):
        with pytest.raises(P.LifecycleError):
            P.next_stage_allowed([], None)


class TestFailureActions:
    REQUIRED = ("create_job_failed", "set_job_information_failed", "assignment_failed",
                "nested_job_incompatible", "inheritable_job_handle", "resume_api_failed",
                "resume_previous_zero", "timeout_live_child", "parent_crash",
                "parent_forced_termination", "evidence_failure_before_resume",
                "evidence_failure_after_resume", "interrupted_cleanup",
                "termination_verified", "termination_unverified")

    def test_matrix_is_complete_and_immutable(self):
        for key in self.REQUIRED:
            assert key in P.FAILURE_ACTIONS
        assert {a["action_class"] for a in P.FAILURE_ACTIONS.values()} == set(P.ACTION_CLASSES)
        with pytest.raises(TypeError):
            P.FAILURE_ACTIONS["new"] = {}
        with pytest.raises(TypeError):
            P.FAILURE_ACTIONS["parent_crash"]["containment"] = "none"
        for action in P.FAILURE_ACTIONS.values():
            assert action["ownership"] == "retained" and action["series_blocked"] is True

    def test_creation_outcome_keys_classify_without_authorizing_action(self):
        for key in ("creation_failed", "creation_no_child", "retention_failed"):
            entry = P.FAILURE_ACTIONS[key]
            assert entry["series_blocked"] is True and entry["ownership"] == "retained"
            assert entry["containment"] in ("recovery_inspection", "none")
            assert entry["containment"] not in ("discard", "bounded_termination")
            assert entry["action_class"] not in ("termination_requested", "possible_execution",
                                                 "discard_before_resume")
        for key in ("creation_failed", "retention_failed"):
            entry = P.FAILURE_ACTIONS[key]
            assert (entry["action_class"], entry["liveness"], entry["execution_history"]) == (
                "unknown_liveness", P.STATE_UNKNOWN, "unchanged")
        no_child = P.FAILURE_ACTIONS["creation_no_child"]
        assert (no_child["action_class"], no_child["containment"]) == ("prelaunch_refusal",
                                                                       "none")
        assert P.TERMINATION_POLICY == "conditionally_accepted_design_only"

    def test_containment_rules(self):
        after = P.FAILURE_ACTIONS["evidence_failure_after_resume"]
        assert (after["action_class"], after["containment"]) == ("possible_execution",
                                                                 "bounded_termination")
        before = P.FAILURE_ACTIONS["evidence_failure_before_resume"]
        assert (before["action_class"], before["execution_history"]) == (
            "discard_before_resume", P.NEVER_EXECUTED)
        for key in ("create_job_failed", "set_job_information_failed",
                    "inheritable_job_handle", "nested_job_incompatible"):
            assert P.FAILURE_ACTIONS[key]["action_class"] == "prelaunch_refusal"
        assert P.FAILURE_ACTIONS["timeout_live_child"]["liveness"] == "requires_os_evidence"
        assert P.FAILURE_ACTIONS["termination_unverified"]["liveness"] == P.STATE_UNKNOWN
        assert P.FAILURE_ACTIONS["interrupted_cleanup"]["action_class"] == "cleanup_incomplete"
        assert P.FAILURE_ACTIONS["termination_verified"]["liveness"] == P.CONFIRMED_EXITED

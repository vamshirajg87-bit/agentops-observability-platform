"""
workload-generator/tests/unit/test_commit_batching_it.py

Offline tests of the integration-validation harness (workload-generator/run_commit_batching_it.py)
and of the opt-in gate of the integration module
(storage-consumer/tests/integration/test_commit_batching_it.py).

Nothing here starts Docker, reads the live engine or connects to Kafka or PostgreSQL: the
pure guards are called with in-memory values, and the few functions that talk to the machine are
replaced.

    T01  Project names and endpoint rules
    T02  Resource gates, Git state, blockers and protected resources
    T03  Classification: an incomplete or skipped deterministic case can never pass
    T04  Evidence, manifest, markers and the test environment
    T05  The commands the harness would run, and what it never touches
    T06  Cleanup rules
    T07  The opt-in gate of the integration module
    T08  The overall flow, with every service replaced
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

_WG = Path(__file__).resolve().parents[2]
_REPO = _WG.parent
_HARNESS = _WG / "run_commit_batching_it.py"
_MODULE = _REPO / "storage-consumer" / "tests" / "integration" / "test_commit_batching_it.py"
HEAD = "a" * 40


def _code_only(path: Path) -> str:
    """Source text without comments and docstrings, so that a word in the documentation cannot
    hide, or fake, a use in the code."""
    text = re.sub(r'""".*?"""', "", path.read_text(encoding="utf-8"), flags=re.S)
    return "\n".join(re.sub(r"(?m)#.*$", "", line) for line in text.splitlines())


@pytest.fixture(scope="module")
def h():
    sys.path.insert(0, str(_WG))
    try:
        spec = importlib.util.spec_from_file_location("run_commit_batching_it", _HARNESS)
        module = importlib.util.module_from_spec(spec)
        sys.modules["run_commit_batching_it"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(_WG))


@pytest.fixture(scope="module")
def it_module():
    import os
    saved = os.environ.pop("AGENTOPS_BATCHING_IT", None)
    try:
        spec = importlib.util.spec_from_file_location("test_commit_batching_it_module", _MODULE)
        module = importlib.util.module_from_spec(spec)
        sys.modules["test_commit_batching_it_module"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if saved is not None:
            os.environ["AGENTOPS_BATCHING_IT"] = saved


# ---------------------------------------------------------------------------
# T01  project names and endpoints
# ---------------------------------------------------------------------------

class TestNamesAndEndpoints:

    def test_a_fresh_project_name_has_the_prefix_and_eight_hex_digits(self, h):
        name = h.new_project_name()
        assert re.fullmatch(r"agentops-batching-it-[0-9a-f]{8}", name)
        h.validate_project_name(name, [])
        assert h.new_project_name() != h.new_project_name()

    @pytest.mark.parametrize("name", ["agentops", "agentops-mvp", "agentops-workload-smoke",
                                      "agentops-pipeline-it-0a1b2c3d", "agentops-batching-it-xyz",
                                      "agentops-batching-it-0a1b2c3", "agentops-batching-it-0A1B2C3D", ""])
    def test_other_names_are_refused(self, h, name):
        with pytest.raises(h.SmokeFailure):
            h.validate_project_name(name, [])

    def test_a_name_that_docker_objects_already_carry_is_refused(self, h):
        name = "agentops-batching-it-0a1b2c3d"
        with pytest.raises(h.SmokeFailure, match="already exist"):
            h.validate_project_name(name, [f"abc123 {name}_agentops-net"])

    @pytest.mark.parametrize("host, port", [("127.0.0.1", 19092), ("127.0.0.1", "15432"), (" 127.0.0.1 ", " 19092 ")])
    def test_the_disposable_loopback_endpoints_are_accepted(self, h, host, port):
        assert h.validate_endpoint(host, port)[0] == "127.0.0.1"

    @pytest.mark.parametrize("host, port", [
        ("localhost", 19092), ("0.0.0.0", 19092), ("::1", 19092), ("192.168.1.5", 19092), ("", 19092),
        (None, 19092), ("127.0.0.1", 9092), ("127.0.0.1", 5432), ("127.0.0.1", 4317), ("127.0.0.1", 4318),
        ("127.0.0.1", 8000), ("127.0.0.1", 3000), ("127.0.0.1", 14317), ("127.0.0.1", 1234),
        ("127.0.0.1", "abc"), ("127.0.0.1", True), ("127.0.0.1", None), ("127.0.0.1", "")])
    def test_everything_else_is_refused(self, h, host, port):
        with pytest.raises(h.SmokeFailure):
            h.validate_endpoint(host, port)

    def test_the_prohibited_ports_are_the_normal_stack_the_mvp_and_grafana(self, h):
        assert set(h.PROHIBITED_PORTS) == {9092, 5432, 4317, 4318, 8000, 3000}
        assert set(h.ALLOWED_ENDPOINT_PORTS) == {19092, 15432}
        assert not set(h.ALLOWED_ENDPOINT_PORTS) & set(h.PROHIBITED_PORTS)

    def test_the_integration_module_applies_the_same_rules(self, h, it_module):
        grid = [("127.0.0.1", 19092), ("127.0.0.1", 15432), ("localhost", 19092), ("127.0.0.1", 9092),
                ("127.0.0.1", 5432), ("127.0.0.1", 8000), ("127.0.0.1", 4317), ("127.0.0.1", 14317),
                ("0.0.0.0", 15432), ("127.0.0.1", True), ("127.0.0.1", "x")]
        for host, port in grid:
            try:
                expected = h.validate_endpoint(host, port)
            except h.SmokeFailure:
                with pytest.raises(ValueError):
                    it_module.validate_endpoint(host, port)
            else:
                assert it_module.validate_endpoint(host, port) == expected
        assert it_module.split_endpoint("127.0.0.1:19092") == ("127.0.0.1", "19092")
        assert it_module.split_endpoint("") == ("", "")

    def test_the_environment_builder_refuses_prohibited_ports(self, h, tmp_path):
        for port in (9092, 5432, 8000):
            with pytest.raises(h.SmokeFailure):
                h.integration_environment(project="agentops-batching-it-0a1b2c3d", run_id="bit-0a1b2c3d",
                                          evidence_dir=tmp_path, password="pw", kafka_port=port)
            with pytest.raises(h.SmokeFailure):
                h.integration_environment(project="agentops-batching-it-0a1b2c3d", run_id="bit-0a1b2c3d",
                                          evidence_dir=tmp_path, password="pw", pg_port=port)


# ---------------------------------------------------------------------------
# T02  gates, Git state, blockers, protected resources
# ---------------------------------------------------------------------------

class TestGates:

    @pytest.mark.parametrize("mib, ok, preferred", [(3071.9, False, False), (3072, True, False), (3499, True, False),
                                                    (3500, True, True), (8000, True, True), (0, False, False)])
    def test_memory_gate_hard_minimum_and_preferred_headroom(self, h, mib, ok, preferred):
        gate = h.memory_gate(mib)
        assert (gate.ok, gate.preferred) == (ok, preferred)

    @pytest.mark.parametrize("value", [None, "3500", float("nan"), True, [], {}])
    def test_memory_that_cannot_be_read_never_passes(self, h, value):
        assert h.memory_gate(value).ok is False

    @pytest.mark.parametrize("value, ok", [(5_157_535_744, True), (3584 * 1024 ** 2, True), (3584 * 1024 ** 2 - 1, False),
                                           (None, False), (True, False), ("5", False)])
    def test_engine_gate(self, h, value, ok):
        assert h.engine_gate(value).ok is ok

    @pytest.mark.parametrize("value, ok", [(10 * 1024 ** 3, True), (10 * 1024 ** 3 - 1, False), (None, False), (True, False)])
    def test_disk_gate(self, h, value, ok):
        assert h.disk_gate(value).ok is ok


class TestGitState:

    @staticmethod
    def _git(answers):
        def run(*args):
            return answers[args]
        return run

    def _answers(self, **over):
        base = {("rev-parse", "--abbrev-ref", "HEAD"): "claude/compassionate-noether-7peel4\n",
                ("rev-parse", "HEAD"): HEAD + "\n", ("diff", "--cached", "--name-only"): "",
                ("status", "--porcelain", "--untracked-files=all"): ""}
        base.update(over)
        return base

    def test_the_exact_clean_state_passes(self, h):
        h.check_git_state(HEAD, self._git(self._answers()))

    @pytest.mark.parametrize("key, value, text", [
        (("rev-parse", "--abbrev-ref", "HEAD"), "main\n", "branch"),
        (("rev-parse", "HEAD"), "b" * 40 + "\n", "HEAD is"),
        (("diff", "--cached", "--name-only"), "a.py\n", "index"),
        (("status", "--porcelain", "--untracked-files=all"), " M a.py\n", "not clean"),
        (("status", "--porcelain", "--untracked-files=all"), "?? new.txt\n", "not clean")])
    def test_any_difference_is_refused(self, h, key, value, text):
        with pytest.raises(h.SmokeFailure, match=text):
            h.check_git_state(HEAD, self._git(self._answers(**{}) | {key: value}))

    @pytest.mark.parametrize("head", ["", "abc", "A" * 40, "g" * 40, "a" * 39, "a" * 41])
    def test_the_expected_head_must_be_a_full_commit(self, h, head):
        with pytest.raises(h.SmokeFailure, match="40-character"):
            h.check_git_state(head, self._git(self._answers()))


class TestBlockersAndProtectedResources:

    def test_nothing_present_means_no_blockers(self, h):
        assert h.find_blockers(benchmark_markers=[], own_markers=[], docker_lines=["x agentops-mvp-postgres-1"],
                               processes=[]) == []

    def test_each_kind_of_blocker_is_reported(self, h):
        blockers = h.find_blockers(
            benchmark_markers=["ACTIVE_RUN", "CLEANUP_UNVERIFIED"], own_markers=["CLEANUP_UNVERIFIED"],
            docker_lines=["id agentops-workload-smoke-kafka-1", "id agentops-pipeline-it-0a1b2c3d_net",
                          "id agentops-batching-it-0a1b2c3d_volume"], processes=["123", " ", "456"])
        text = "\n".join(blockers)
        assert "benchmark marker ACTIVE_RUN" in text and "benchmark marker CLEANUP_UNVERIFIED" in text
        assert "unverified cleanup marker" in text
        assert "benchmark Docker object" in text and "pipeline test Docker object" in text
        assert "earlier batching validation Docker object" in text
        assert "process 123" in text and "process 456" in text and len(blockers) == 8

    def test_protected_containers_must_not_change(self, h):
        before = {"agentops-mvp-postgres-1": "id running t0 f0 0", "agentops-postgres": "id exited t f 0", "x": None}
        assert h.protected_changes(before, dict(before)) == []
        changed = dict(before, **{"agentops-mvp-postgres-1": "id running t1 f0 1", "x": "id exited a b 0"})
        problems = h.protected_changes(before, changed)
        assert len(problems) == 2 and any("agentops-mvp-postgres-1" in p for p in problems)
        assert h.protected_changes({"a": "1"}, {}) and h.protected_changes({}, {"a": "1"})

    @pytest.mark.parametrize("state, problem", [
        (None, False), ("b2b3d05e exited 2026-10-11T05:09:40Z 2026-10-12T05:30:29Z 0", False),
        ("b2b3d05e running 2026-10-11T05:09:40Z 0001-01-01T00:00:00Z 0", True),
        ("b2b3d05e paused a b 0", True), ("garbage", True)])
    def test_the_legacy_postgres_must_be_absent_or_exited(self, h, state, problem):
        assert (h.legacy_problem(state) is not None) is problem

    def test_the_protected_set_names_the_mvp_and_the_legacy_container(self, h):
        assert set(h.MVP_CONTAINERS) == {"agentops-mvp-postgres-1", "agentops-mvp-viewer-1", "agentops-mvp-db-bootstrap-1"}
        assert h.LEGACY_POSTGRES == "agentops-postgres"


# ---------------------------------------------------------------------------
# T03  classification
# ---------------------------------------------------------------------------

def passing(h):
    return ([{"case": c, "status": "PASS"} for c in h.DETERMINISTIC_CASES]
            + [{"case": c, "status": "OBSERVED"} for c in h.TIMING_CASES])


class TestClassification:

    def test_every_deterministic_case_passing_is_a_pass(self, h):
        result = h.classify(passing(h))
        assert result["overall"] == "PASS" and not result["failed"] and not result["not_passed"]

    @pytest.mark.parametrize("status", ["OBSERVED", "NOT_OBSERVED", "INCONCLUSIVE"])
    def test_a_timing_case_that_was_not_observed_does_not_change_the_verdict(self, h, status):
        records = [r for r in passing(h) if r["case"] not in h.TIMING_CASES] + [
            {"case": c, "status": status} for c in h.TIMING_CASES]
        assert h.classify(records)["overall"] == "PASS"

    def test_missing_timing_cases_are_reported_but_do_not_fail(self, h):
        records = [r for r in passing(h) if r["case"] not in h.TIMING_CASES]
        result = h.classify(records)
        assert result["overall"] == "PASS" and set(result["timing"].values()) == {"MISSING"}

    @pytest.mark.parametrize("missing", list(range(9)))
    def test_a_missing_deterministic_case_can_never_pass(self, h, missing):
        case = h.DETERMINISTIC_CASES[missing]
        result = h.classify([r for r in passing(h) if r["case"] != case])
        assert result["overall"] != "PASS" and result["deterministic"][case] == "MISSING"

    @pytest.mark.parametrize("skipped", list(range(9)))
    def test_a_skipped_deterministic_case_can_never_pass(self, h, skipped):
        records = [dict(r, status="BLOCKED") if r["case"] == h.DETERMINISTIC_CASES[skipped] else r for r in passing(h)]
        result = h.classify(records)
        assert result["overall"] == "BLOCKED" and h.final_verdict(result, cleanup_verified=True, pytest_exit=0) == "BLOCKED"

    def test_everything_skipped_is_blocked_not_pass(self, h):
        records = [{"case": c, "status": "BLOCKED"} for c in h.DETERMINISTIC_CASES]
        assert h.classify(records)["overall"] == "BLOCKED"
        assert h.classify([])["overall"] == "BLOCKED"

    @pytest.mark.parametrize("case_index", list(range(9)))
    def test_a_deterministic_failure_fails_everything(self, h, case_index):
        case = h.DETERMINISTIC_CASES[case_index]
        records = [dict(r, status="FAIL") if r["case"] == case else r for r in passing(h)]
        result = h.classify(records)
        assert result["overall"] == "FAIL" and case in result["failed"]

    @pytest.mark.parametrize("case", ["C04_cooperative_rebalance", "C05_lost_ownership", "C07b_forced_kill_restart",
                                      "C12_sustained_main_n100"])
    def test_a_safety_violation_in_a_timing_case_fails_everything(self, h, case):
        records = [dict(r, status="FAIL") if r["case"] == case else r for r in passing(h)]
        assert h.classify(records)["overall"] == "FAIL"

    @pytest.mark.parametrize("bad", [
        {"case": "C01_commit_response_shape", "status": "OBSERVED"},      # a timing status on a deterministic case
        {"case": "C04_cooperative_rebalance", "status": "PASS"},          # a deterministic status on a timing case
        {"case": "C01_commit_response_shape", "status": "pass"},
        {"case": "C01_commit_response_shape", "status": None},
        {"case": "C01_commit_response_shape"}, {"status": "PASS"}, {"case": "unknown", "status": "PASS"}, "text", None])
    def test_malformed_or_unknown_records_can_never_produce_a_pass(self, h, bad):
        records = [r for r in passing(h) if r["case"] != (bad.get("case") if isinstance(bad, dict) else None)] + [bad]
        assert h.classify(records)["overall"] != "PASS"

    def test_a_duplicated_deterministic_record_is_not_a_pass(self, h):
        records = passing(h) + [{"case": "C01_commit_response_shape", "status": "PASS"}]
        assert h.classify(records)["overall"] != "PASS"

    def test_the_final_verdict_also_needs_pytest_exit_zero_and_a_verified_cleanup(self, h):
        result = h.classify(passing(h))
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=0) == "PASS"
        assert h.final_verdict(result, cleanup_verified=False, pytest_exit=0) == "FAIL"
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=1) == "FAIL"
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=None) == "FAIL"

    def test_the_case_lists_equal_those_of_the_integration_module(self, h, it_module):
        assert h.DETERMINISTIC_CASES == it_module.DETERMINISTIC_CASES
        assert h.TIMING_CASES == it_module.TIMING_CASES
        assert set(h.TIMING_STATUSES) - {"FAIL"} == set(it_module.TIMING_STATUSES)

    def test_every_case_is_implemented_exactly_once_in_the_module(self, it_module):
        source = _MODULE.read_text(encoding="utf-8")
        ids = re.findall(r'^@case\("([A-Za-z0-9_]+)"\)', source, re.M)
        assert len(ids) == len(set(ids)) == 13
        assert set(ids) == set(it_module.DETERMINISTIC_CASES) | set(it_module.TIMING_CASES)


# ---------------------------------------------------------------------------
# T04  evidence, markers, environment
# ---------------------------------------------------------------------------

class TestEvidenceAndEnvironment:

    def test_the_evidence_directory_is_outside_the_repository(self, h, tmp_path):
        run_id = h.new_run_id()
        directory = h.evidence_dir_for(run_id, root=tmp_path)
        assert directory == (tmp_path.resolve() / run_id)
        with pytest.raises(h.SmokeFailure, match="inside the repository"):
            h.evidence_dir_for(run_id, root=_REPO / "evidence")
        with pytest.raises(h.SmokeFailure, match="inside the repository"):
            h.evidence_dir_for(run_id, root=_REPO)
        default = h.evidence_dir_for(run_id)
        assert _REPO not in default.resolve().parents

    @pytest.mark.parametrize("run_id", ["", "bit-xyz", "bit-0a1b2c3", "../bit-0a1b2c3d", "bit-0a1b2c3d/x", "bm-0a1b2c3d"])
    def test_run_ids_are_strict(self, h, tmp_path, run_id):
        with pytest.raises(h.SmokeFailure):
            h.evidence_dir_for(run_id, root=tmp_path)

    def test_the_manifest_lists_every_file_with_its_sha256_and_not_itself(self, h, tmp_path):
        (tmp_path / "results.json").write_bytes(b"[]\n")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "kafka.log").write_bytes(b"log\n")
        import hashlib
        path = h.write_manifest(tmp_path)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        assert set(manifest) == {"results.json", "sub/kafka.log"}
        assert manifest["results.json"] == hashlib.sha256(b"[]\n").hexdigest()
        assert h.write_manifest(tmp_path) == path and json.loads(path.read_text(encoding="utf-8")) == manifest

    def test_secrets_are_removed_from_evidence_text(self, h):
        assert h.sanitize("password=hunter2 and hunter2", ["hunter2", ""]) == "password=<redacted> and <redacted>"
        assert h.sanitize("nothing", []) == "nothing"

    def test_an_unverified_cleanup_leaves_a_blocking_marker(self, h, tmp_path):
        assert not h.marker_path(tmp_path).exists()
        path = h.write_marker("a volume remains", root=tmp_path)
        assert path == tmp_path / "CLEANUP_UNVERIFIED" and "a volume remains" in path.read_text(encoding="utf-8")
        blockers = h.find_blockers(benchmark_markers=[], own_markers=[path.name], docker_lines=[], processes=[])
        assert blockers and "unverified cleanup" in blockers[0]

    def test_the_test_environment_is_explicit_and_carries_one_credential(self, h, tmp_path, monkeypatch):
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
        monkeypatch.setenv("PG_PASSWORD", "also-leak-me")
        monkeypatch.setenv("COMPOSE_PROJECT_NAME", "agentops")
        env = h.integration_environment(project="agentops-batching-it-0a1b2c3d", run_id="bit-0a1b2c3d",
                                        evidence_dir=tmp_path, password="temp-pw", python="/venv/python")
        assert env["AGENTOPS_BATCHING_IT"] == "1"
        assert env["AGENTOPS_IT_KAFKA"] == "127.0.0.1:19092" and env["AGENTOPS_IT_PG_PORT"] == "15432"
        assert env["AGENTOPS_IT_PG_HOST"] == "127.0.0.1" and env["AGENTOPS_IT_PG_PASSWORD"] == "temp-pw"
        assert env["AGENTOPS_IT_PROJECT"] == "agentops-batching-it-0a1b2c3d"
        assert env["AGENTOPS_IT_EVIDENCE_DIR"] == str(tmp_path) and env["AGENTOPS_IT_PYTHON"] == "/venv/python"
        assert "leak-me" not in env.values() and "also-leak-me" not in env.values()
        assert not any(key in env for key in ("AWS_SECRET_ACCESS_KEY", "PG_PASSWORD", "COMPOSE_PROJECT_NAME"))
        assert [v for v in env.values() if v == "temp-pw"] == ["temp-pw"]
        parts = env["PYTHONPATH"].split(";" if ";" in env["PYTHONPATH"] else ":")
        assert any(p.endswith("storage-consumer") for p in parts) and any(p.endswith("demo-app") for p in parts)
        assert env["PYTHONDONTWRITEBYTECODE"] == "1"


# ---------------------------------------------------------------------------
# T05  commands and untouched resources
# ---------------------------------------------------------------------------

class TestCommandsAndBoundaries:

    def test_the_harness_runs_only_the_new_integration_module(self, h, tmp_path):
        command = h.pytest_command("/venv/python", tmp_path)
        assert command[:4] == ["/venv/python", "-B", "-m", "pytest"]
        assert h.TEST_FILE in command and command.count(h.TEST_FILE) == 1
        assert "-p" in command and "no:cacheprovider" in command
        assert str(tmp_path / "junit.xml") in command
        assert not any("persistence" in part for part in command)
        assert (_REPO / h.TEST_FILE).is_file()

    def test_the_older_persistence_test_is_never_named_by_the_harness_code(self):
        assert "test_persistence_e2e" not in _code_only(_HARNESS)

    def test_the_harness_never_prunes_or_force_removes_and_never_opens_the_benchmark_ledger(self):
        source = _code_only(_HARNESS)
        for forbidden in ("prune", "system prune", "volume rm", "docker rm", "rm -f", "--force", "shutil.rmtree"):
            assert forbidden not in source, forbidden
        assert not re.search(r"""["']ledger["']""", source)
        for forbidden in ("APPROVED_LIVE_CELLS", "claim_run", "finish_run", "import run_benchmark", "run_benchmark.py"):
            assert forbidden not in source, forbidden

    def test_the_gate_variable_is_set_only_by_the_harness_and_never_by_ci_or_compose(self):
        # The CI workflow is intentionally absent from the initial public release candidate; when it is
        # present, it is checked first, exactly as before.
        paths = [_REPO / "docker-compose.yml",
                 _REPO / "docker" / "compose.pipeline.yml", _REPO / "docker" / "mvp" / "compose.yml"]
        workflow = _REPO / ".github" / "workflows" / "ci.yml"
        if workflow.is_file():
            paths.insert(0, workflow)
        for path in paths:
            assert "AGENTOPS_BATCHING_IT" not in path.read_text(encoding="utf-8"), path
        assert "AGENTOPS_BATCHING_IT=\"1\"" in _HARNESS.read_text(encoding="utf-8")

    def test_ci_does_not_collect_the_integration_directory(self):
        workflow = _REPO / ".github" / "workflows" / "ci.yml"
        if not workflow.is_file():
            pytest.skip("the CI workflow is intentionally absent from the initial public release candidate")
        ci = workflow.read_text(encoding="utf-8")
        assert "storage-consumer/tests/unit" in ci and "tests/integration" not in ci


# ---------------------------------------------------------------------------
# T06  cleanup rules
# ---------------------------------------------------------------------------

class TestCleanup:

    @pytest.mark.parametrize("name", ["agentops", "", "agentops-mvp", "agentops-batching-it-xyz", "agentops-pipeline-it-0a1b2c3d"])
    def test_cleanup_refuses_names_that_are_not_a_disposable_batching_project(self, h, name):
        with pytest.raises(h.SmokeFailure):
            h.BatchingOps(name)

    def test_only_images_named_after_the_project_may_be_removed(self, h):
        ops = h.BatchingOps("agentops-batching-it-0a1b2c3d")
        for reference in ("agentops-mvp-viewer:latest", "postgres:17", "agentops-batching-it-0a1b2c3e-kafka:latest", "x"):
            with pytest.raises(h.SmokeFailure, match="not named after the project"):
                ops.remove_image(reference)

    def test_the_temporary_directory_must_be_a_temporary_directory(self, h, tmp_path):
        ops = h.BatchingOps("agentops-batching-it-0a1b2c3d")
        saved = h.smoke.RUN.temp
        try:
            h.smoke.RUN.temp = h.smoke.REPO / "workload-generator"
            with pytest.raises(h.SmokeFailure, match="not a temporary directory"):
                ops.remove_temp()
            h.smoke.RUN.temp = Path("/")
            with pytest.raises(h.SmokeFailure, match="not a temporary directory"):
                ops.remove_temp()
            h.smoke.RUN.temp = None
            assert ops.remove_temp() is True
        finally:
            h.smoke.RUN.temp = saved

    def test_down_is_not_attempted_when_no_compose_command_ran(self, h):
        ops = h.BatchingOps("agentops-batching-it-0a1b2c3d")
        saved = (h.smoke.RUN.compose_used, h.smoke.RUN.env_file)
        try:
            h.smoke.RUN.compose_used, h.smoke.RUN.env_file = False, None
            assert ops.can_down() is False
        finally:
            h.smoke.RUN.compose_used, h.smoke.RUN.env_file = saved

    def test_the_project_scoped_down_command_names_the_project_and_removes_nothing_else(self, h):
        saved = (h.smoke.PROJECT, h.smoke.RUN.env_file)
        try:
            h.smoke.PROJECT, h.smoke.RUN.env_file = "agentops-batching-it-0a1b2c3d", Path("smoke.env")
            command = h.smoke.compose_command("down", "--volumes", "--rmi", "local", "--remove-orphans")
        finally:
            h.smoke.PROJECT, h.smoke.RUN.env_file = saved
        assert command[:4] == ["docker", "compose", "-p", "agentops-batching-it-0a1b2c3d"]
        assert command[-5:] == ["down", "--volumes", "--rmi", "local", "--remove-orphans"]

    def test_teardown_writes_a_blocking_marker_when_cleanup_is_uncertain(self, h, tmp_path, monkeypatch):
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path)
        monkeypatch.setattr(h.pipeline, "safe_cleanup", lambda project, before, ops: ["1 project volumes left"])
        monkeypatch.setattr(h, "protected_snapshot", lambda: {})
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "protected_before", {})
        assert h.teardown() is False
        assert (tmp_path / "CLEANUP_UNVERIFIED").read_text(encoding="utf-8").startswith("1 project volumes left")

    def test_teardown_detects_a_changed_protected_container(self, h, tmp_path, monkeypatch):
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path)
        monkeypatch.setattr(h.pipeline, "safe_cleanup", lambda project, before, ops: [])
        monkeypatch.setattr(h, "protected_snapshot", lambda: {"agentops-mvp-viewer-1": "new"})
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "protected_before", {"agentops-mvp-viewer-1": "old"})
        assert h.teardown() is False and (tmp_path / "CLEANUP_UNVERIFIED").exists()

    def test_a_verified_cleanup_writes_no_marker(self, h, tmp_path, monkeypatch):
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path)
        monkeypatch.setattr(h.pipeline, "safe_cleanup", lambda project, before, ops: [])
        monkeypatch.setattr(h, "protected_snapshot", lambda: {"a": "1"})
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "protected_before", {"a": "1"})
        assert h.teardown() is True and not (tmp_path / "CLEANUP_UNVERIFIED").exists()


# ---------------------------------------------------------------------------
# T07  the opt-in gate of the integration module
# ---------------------------------------------------------------------------

class TestIntegrationModuleGate:

    def test_every_test_is_skipped_unless_the_variable_is_one(self, it_module):
        marks = [m for m in (it_module.pytestmark if isinstance(it_module.pytestmark, list) else [it_module.pytestmark])
                 if m.name == "skipif"]
        assert len(marks) == 1 and marks[0].args[0] is True          # condition true: the variable was unset at import
        assert "AGENTOPS_BATCHING_IT" in marks[0].kwargs["reason"]

    def test_importing_the_module_needs_no_service_and_no_kafka_or_postgres_package(self):
        source = _MODULE.read_text(encoding="utf-8")
        top_level = "\n".join(line for line in source.splitlines() if line.startswith(("import ", "from ")))
        assert "confluent_kafka" not in top_level and "psycopg" not in top_level
        assert "consumer" not in top_level.replace("typing", "") and "repository" not in top_level

    def test_the_module_never_defaults_to_the_normal_stack(self):
        source = _MODULE.read_text(encoding="utf-8")
        assert "localhost" not in source and "agentops_dev" not in source
        for port in ("9092", "5432"):
            assert not re.search(rf"[\"'][^\"']*:{port}[\"']", source)

    def test_every_test_function_is_a_recorded_case(self):
        source = _MODULE.read_text(encoding="utf-8")
        tests = re.findall(r"^def (test_\w+)\(", source, re.M)
        decorated = re.findall(r'^@case\("[^"]+"\)\ndef (test_\w+)\(', source, re.M)
        assert tests and sorted(tests) == sorted(decorated)

    def test_the_older_persistence_test_is_unchanged_by_this_work(self):
        source = (_REPO / "storage-consumer" / "tests" / "integration" / "test_persistence_e2e.py").read_text(encoding="utf-8")
        assert 'KAFKA_BOOTSTRAP = "localhost:9092"' in source                # still the normal-stack test it always was

    def test_the_results_file_masks_the_credential(self, it_module, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTOPS_IT_EVIDENCE_DIR", str(tmp_path))
        monkeypatch.setenv("AGENTOPS_IT_PG_PASSWORD", "s3cret-value")
        it_module._RECORDS[:] = [{"case": "C08_postgres_idempotency", "status": "PASS", "detail": {"x": "s3cret-value"}}]
        it_module.write_results()
        text = (tmp_path / "results.json").read_text(encoding="utf-8")
        assert "s3cret-value" not in text and "<redacted>" in text
        it_module._RECORDS[:] = []

    def test_the_case_decorator_classifies_outcomes(self, it_module):
        case = it_module.case
        records = it_module._RECORDS
        records.clear()

        @case("C08_postgres_idempotency")
        def passes():
            it_module.note("k", "v")

        @case("C08_postgres_idempotency")
        def fails():
            raise AssertionError("no")

        @case("C08_postgres_idempotency")
        def errors():
            raise RuntimeError("boom")

        @case("C05_lost_ownership")
        def timing_observed():
            return "OBSERVED"

        @case("C05_lost_ownership")
        def timing_unknown_value():
            return "whatever"

        @case("C05_lost_ownership")
        def timing_error():
            raise TimeoutError("the broker did not answer")

        @case("C05_lost_ownership")
        def timing_assertion():
            raise AssertionError("unsafe")

        @case("C08_postgres_idempotency")
        def skipped():
            pytest.skip("not here")

        passes()
        for function in (fails, errors, timing_assertion, skipped):
            with pytest.raises(BaseException):
                function()
        timing_observed()
        timing_unknown_value()
        timing_error()
        statuses = [r["status"] for r in records]
        assert statuses == ["PASS", "FAIL", "FAIL", "FAIL", "BLOCKED", "OBSERVED", "INCONCLUSIVE", "INCONCLUSIVE"]
        assert records[0]["detail"]["k"] == "v" and records[0]["detail"]["driver"]
        records.clear()


# ---------------------------------------------------------------------------
# T08  the overall flow, with every service replaced
# ---------------------------------------------------------------------------

class TestMain:

    @pytest.fixture(autouse=True)
    def _quiet(self, h, monkeypatch, tmp_path):
        monkeypatch.setattr(h.pipeline, "keep_awake", lambda: None)
        monkeypatch.setattr(h.pipeline, "release_awake", lambda: None)
        monkeypatch.setattr(h.S, "project", "")
        monkeypatch.setattr(h.S, "evidence", None)

        def refused(*args, **kwargs):
            raise AssertionError("a Docker or git command was attempted")
        monkeypatch.setattr(h.smoke, "run", refused)
        monkeypatch.setattr(h.smoke, "checked", refused)

    def test_a_failure_before_anything_exists_returns_one_without_cleanup(self, h, monkeypatch, capsys):
        def boom(expect_head):
            raise h.SmokeFailure("preflight said no")
        monkeypatch.setattr(h, "it", boom)
        assert h.main(["--expect-head", HEAD]) == 1
        out = capsys.readouterr().out
        assert "preflight said no" in out and "overall: FAIL" in out

    def test_all_deterministic_cases_passing_with_a_verified_cleanup_returns_zero(self, h, monkeypatch, capsys):
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 0
        assert "overall: PASS" in capsys.readouterr().out

    def test_an_incomplete_run_never_returns_zero(self, h, monkeypatch, capsys):
        records = [r for r in passing(h) if r["case"] != "C03_eager_rebalance"]
        monkeypatch.setattr(h, "it", lambda expect_head: (records, 0, []))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 1
        assert "overall: BLOCKED" in capsys.readouterr().out

    def test_an_unverified_cleanup_never_returns_zero(self, h, monkeypatch):
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h, "teardown", lambda: False)
        assert h.main(["--expect-head", HEAD]) == 1

    def test_a_failing_pytest_exit_never_returns_zero(self, h, monkeypatch):
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 1, []))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 1

    def test_an_exception_in_teardown_leaves_a_marker_and_returns_one(self, h, monkeypatch, tmp_path):
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path)
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")

        def broken():
            raise RuntimeError("docker vanished")
        monkeypatch.setattr(h, "teardown", broken)
        assert h.main(["--expect-head", HEAD]) == 1
        assert (tmp_path / "CLEANUP_UNVERIFIED").exists()

    def test_the_evidence_gets_a_verdict_and_a_manifest(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 0
        verdict = json.loads((evidence / "verdict.json").read_text(encoding="utf-8"))
        assert verdict["verdict"] == "PASS" and verdict["cleanup_verified"] is True and verdict["pytest_exit"] == 0
        manifest = json.loads((evidence / "manifest.sha256.json").read_text(encoding="utf-8"))
        assert "verdict.json" in manifest and "manifest.sha256.json" not in manifest

    def test_the_expected_head_argument_is_required(self, h):
        with pytest.raises(SystemExit):
            h.main([])


# ---------------------------------------------------------------------------
# T09  process-tree termination: only the exact subprocess, verified (H1)
# ---------------------------------------------------------------------------

class FakeProc:
    """A Popen stand-in."""

    def __init__(self, pid=4242, running=True, stubborn=False):
        self.pid, self._running, self.stubborn = pid, running, stubborn
        self.kills = self.waits = 0
        self.on_stop = None

    def _stop(self):
        self._running = False
        if self.on_stop:
            self.on_stop()

    def poll(self):
        return None if self._running else 0

    def wait(self, timeout=None):
        self.waits += 1
        if self._running and self.stubborn:
            raise subprocess.TimeoutExpired("fake", timeout)
        self._stop()
        return 0

    def kill(self):
        self.kills += 1
        if not self.stubborn:
            self._stop()


class Machine:
    """The operating system, as far as terminate_* can see it: a set of live PIDs, the commands run,
    and whether taskkill / kill really remove a PID."""

    def __init__(self, live, children=(), effective=True):
        self.live, self.child_pids, self.effective = set(live), set(children), effective
        self.commands, self.signalled = [], []

    def run(self, command, **kwargs):
        self.commands.append(list(command))
        if command[0] == "taskkill" and self.effective:
            target = int(command[2])
            self.live.discard(target)
            if "/T" in command:
                self.live -= self.child_pids
        return types.SimpleNamespace(returncode=0 if self.effective else 1, stdout="", stderr="")

    def kill_pid(self, pid):
        self.signalled.append(pid)
        if self.effective:
            self.live.discard(pid)

    def children(self, pid):
        return set(self.child_pids)

    def alive(self, pid):
        return pid in self.live


def terminate(module_function, proc, machine, **kwargs):
    return module_function(proc, run=machine.run, children=machine.children, alive=machine.alive,
                           kill_pid=machine.kill_pid, sleep=lambda s: None, grace=0.01, **kwargs)


@pytest.fixture(params=["harness", "integration"])
def terminator(request, h, it_module):
    """The same behavior is required of the orchestrator's helper and of the test module's own."""
    return (h.terminate_process_tree, h.SmokeFailure) if request.param == "harness" \
        else (it_module.terminate_tree, it_module.ProcessNotStopped)


class TestProcessTermination:

    def test_windows_runs_one_taskkill_for_the_exact_pid_with_its_tree_and_verifies_it(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242), Machine(live={4242, 4300}, children={4300})
        assert terminate(function, proc, machine, windows=True) == []
        assert machine.commands == [["taskkill", "/PID", "4242", "/T", "/F"]]
        assert machine.live == set() and not machine.signalled

    def test_posix_signals_only_the_descendants_found_by_parent_pid_and_the_process_itself(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242), Machine(live={4242, 4300, 4301, 9999}, children={4300, 4301})
        proc.on_stop = lambda: machine.live.discard(4242)
        assert terminate(function, proc, machine, windows=False) == []
        assert machine.signalled == [4300, 4301] and proc.kills == 1
        assert machine.live == {9999}                     # an unrelated process was never touched
        assert machine.commands == []

    @pytest.mark.parametrize("pid", [0, 1, 4, -5, True, None, "12", 1.5])
    def test_a_system_or_invalid_pid_is_refused_before_anything_is_signalled(self, terminator, pid):
        function, error = terminator
        machine = Machine(live={4242})
        with pytest.raises(error):
            terminate(function, FakeProc(pid=pid), machine, windows=True)
        assert machine.commands == [] and machine.signalled == []

    def test_this_process_itself_is_refused(self, terminator):
        import os
        function, error = terminator
        machine = Machine(live=set())
        with pytest.raises(error):
            terminate(function, FakeProc(pid=os.getpid()), machine, windows=True)
        assert machine.commands == []

    def test_a_process_that_survives_the_kill_is_reported_not_assumed_gone(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242, stubborn=True), Machine(live={4242, 4300}, children={4300}, effective=False)
        problems = terminate(function, proc, machine, windows=True)
        assert "pid 4242 is still running" in problems and "pid 4300 is still running" in problems

    def test_a_surviving_descendant_alone_is_enough_to_report_a_problem(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242), Machine(live={4242, 4300}, children={4300})

        def partial_run(command, **kwargs):          # kills the launcher only: the very failure being guarded against
            machine.commands.append(list(command))
            machine.live.discard(4242)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        problems = function(proc, run=partial_run, children=machine.children, alive=machine.alive,
                            sleep=lambda s: None, grace=0.01, windows=True)
        assert problems == ["pid 4300 is still running"]

    def test_a_taskkill_that_cannot_run_is_a_problem(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242), Machine(live={4242})

        def broken(command, **kwargs):
            raise OSError("no taskkill")
        problems = function(proc, run=broken, children=machine.children, alive=machine.alive,
                            sleep=lambda s: None, grace=0.01, windows=True)
        assert any("taskkill" in p for p in problems)

    def test_a_process_table_that_cannot_be_read_means_the_tree_is_unverified(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242), Machine(live={4242})

        def unreadable(pid):
            raise OSError("no process table")
        problems = function(proc, run=machine.run, children=unreadable, alive=machine.alive,
                            sleep=lambda s: None, grace=0.01, windows=True)
        assert any("could not be listed" in p for p in problems)

    def test_a_liveness_check_that_fails_is_a_problem_not_a_pass(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242), Machine(live={4242})

        def broken(pid):
            raise OSError("tasklist failed")
        problems = function(proc, run=machine.run, children=machine.children, alive=broken,
                            sleep=lambda s: None, grace=0.01, windows=True)
        assert any("could not be checked" in p for p in problems)

    def test_an_already_exited_process_is_never_signalled_by_its_possibly_reused_pid(self, terminator):
        function, _ = terminator
        proc, machine = FakeProc(pid=4242, running=False), Machine(live={4242, 4300}, children={4300})
        assert terminate(function, proc, machine, windows=True) == []
        assert machine.commands == [["taskkill", "/PID", "4300", "/T", "/F"]]        # the orphaned child only
        assert 4242 in machine.live and proc.kills == 0

    def test_an_exited_process_with_no_descendants_needs_no_signal(self, terminator):
        function, _ = terminator
        machine = Machine(live=set())
        assert terminate(function, FakeProc(pid=4242, running=False), machine, windows=True) == []
        assert machine.commands == []

    def test_descendants_are_found_by_parent_pid_and_never_by_command_line(self, h, it_module):
        table = "10 1\n11 10\n12 11\n13 1\n14 12\nnot a row\n"

        def run(command, **kwargs):
            return types.SimpleNamespace(returncode=0, stdout=table, stderr="")
        assert h._children_of(10, run) == {11, 12, 14}
        assert it_module._children_of(10, run) == {11, 12, 14}
        assert h._children_of(99, run) == set()
        for function in (h.terminate_process_tree, h._children_of, h._pid_alive,
                         it_module.terminate_tree, it_module._children_of, it_module._pid_alive):
            source = inspect.getsource(function)
            assert "CommandLine -match" not in source and "-match" not in source and "re.search" not in source

    def test_a_process_table_error_is_raised_not_ignored(self, h):
        def run(command, **kwargs):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")
        with pytest.raises(OSError):
            h._children_of(10, run)

    def test_the_module_never_uses_a_plain_kill_on_the_consumer_it_started(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c07b_forced_kill_of_the_real_consumer"):source.index('# C12  sustained')]
        assert ".kill()" not in body and ".terminate()" not in body
        assert body.count("terminate_tree(") == 3        # first consumer, restarted consumer, final cleanup


class TestPytestTimeoutAndInterruption:

    @pytest.fixture(autouse=True)
    def _state(self, h, monkeypatch):
        monkeypatch.setattr(h.S, "process_problems", [])

    class Pytest:
        def __init__(self, behavior):
            self.pid, self.returncode, self.behavior, self.calls = 777, 0, behavior, 0

        def communicate(self, timeout=None):
            self.calls += 1
            outcome = self.behavior[min(self.calls, len(self.behavior)) - 1]
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

    def _run(self, h, monkeypatch, tmp_path, process, terminated, result=()):
        monkeypatch.setattr(h.subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(h, "terminate_process_tree", lambda proc: terminated.append(proc.pid) or list(result))
        return h.run_tests(Path("/venv/python"), {}, tmp_path, ["s3cret"])

    def test_a_timeout_terminates_exactly_that_pytest_tree_and_returns_124(self, h, monkeypatch, tmp_path):
        process, killed = self.Pytest([subprocess.TimeoutExpired("pytest", 1), ("partial s3cret", "")]), []
        assert self._run(h, monkeypatch, tmp_path, process, killed) == 124
        assert killed == [777] and h.S.process_problems == []
        text = (tmp_path / "pytest-output.txt").read_text(encoding="utf-8")
        assert "timed out" in text and "s3cret" not in text and "partial <redacted>" in text

    def test_a_tree_that_cannot_be_verified_stopped_is_recorded_for_the_cleanup_marker(self, h, monkeypatch, tmp_path):
        process = self.Pytest([subprocess.TimeoutExpired("pytest", 1), subprocess.TimeoutExpired("pytest", 30)])
        assert self._run(h, monkeypatch, tmp_path, process, [], result=["pid 888 is still running"]) == 124
        assert h.S.process_problems == ["pytest timeout: pid 888 is still running"]
        assert (tmp_path / "pytest-output.txt").is_file()

    def test_an_interruption_terminates_the_tree_and_propagates_unchanged(self, h, monkeypatch, tmp_path):
        interrupt, killed = KeyboardInterrupt(), []
        process = self.Pytest([interrupt])
        monkeypatch.setattr(h.subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(h, "terminate_process_tree", lambda proc: killed.append(proc.pid) or ["pid 5 is still running"])
        with pytest.raises(KeyboardInterrupt) as raised:
            h.run_tests(Path("/venv/python"), {}, tmp_path, [])
        assert raised.value is interrupt and killed == [777]
        assert h.S.process_problems == ["pytest interrupted: pid 5 is still running"]

    def test_a_normal_run_terminates_nothing_and_masks_the_credential(self, h, monkeypatch, tmp_path):
        process, killed = self.Pytest([("out s3cret", "err")]), []
        process.returncode = 3
        assert self._run(h, monkeypatch, tmp_path, process, killed, result=["must not be used"]) == 3
        assert killed == [] and h.S.process_problems == []
        assert "s3cret" not in (tmp_path / "pytest-output.txt").read_text(encoding="utf-8")

    def test_pytest_is_started_with_pipes_and_no_shell(self, h, monkeypatch, tmp_path):
        seen = {}

        def popen(command, **kwargs):
            seen.update(kwargs, command=command)
            return self.Pytest([("", "")])
        monkeypatch.setattr(h.subprocess, "Popen", popen)
        h.run_tests(Path("/venv/python"), {"A": "1"}, tmp_path, [])
        assert "shell" not in seen and seen["stdin"] == subprocess.DEVNULL and seen["env"] == {"A": "1"}
        assert seen["command"][-2] == "--junitxml"


class TestCleanupClassificationOfProcesses:

    @pytest.fixture(autouse=True)
    def _state(self, h, monkeypatch, tmp_path):
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path / "root")
        monkeypatch.setattr(h.pipeline, "safe_cleanup", lambda project, before, ops: [])
        monkeypatch.setattr(h, "protected_snapshot", lambda: {})
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "protected_before", {})
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h.S, "secrets", [])
        monkeypatch.setattr(h.S, "evidence", None)
        self.marker = tmp_path / "root" / "CLEANUP_UNVERIFIED"

    def test_no_process_problem_means_a_verified_cleanup(self, h):
        assert h.teardown() is True and not self.marker.exists()

    def test_a_pytest_tree_that_was_not_verified_stopped_blocks_future_runs(self, h, monkeypatch):
        monkeypatch.setattr(h.S, "process_problems", ["pytest timeout: pid 9 is still running"])
        assert h.teardown() is False
        assert "pid 9 is still running" in self.marker.read_text(encoding="utf-8")

    def test_a_process_reported_by_the_test_module_blocks_future_runs(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        (evidence / "process-report.json").write_text(json.dumps(["second consumer: pid 12 is still running"]),
                                                      encoding="utf-8")
        monkeypatch.setattr(h.S, "evidence", evidence)
        assert h.teardown() is False
        assert "second consumer: pid 12" in self.marker.read_text(encoding="utf-8")

    def test_an_unreadable_process_report_also_blocks(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        (evidence / "process-report.json").write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(h.S, "evidence", evidence)
        assert h.teardown() is False and self.marker.exists()

    def test_the_report_reader(self, h, tmp_path):
        assert h.read_process_report(None) == [] and h.read_process_report(tmp_path) == []
        (tmp_path / "process-report.json").write_text('"text"', encoding="utf-8")
        assert len(h.read_process_report(tmp_path)) == 1
        (tmp_path / "process-report.json").write_text("[]", encoding="utf-8")
        assert h.read_process_report(tmp_path) == []

    def test_the_report_file_name_is_the_same_in_both_files(self, h, it_module):
        assert h.PROCESS_REPORT == it_module.PROCESS_REPORT == "process-report.json"

    def test_a_blocking_marker_stops_the_next_run(self, h):
        h.write_marker("pid 9 is still running", root=self.marker.parent)
        blockers = h.find_blockers(benchmark_markers=[], own_markers=[self.marker.name], docker_lines=[], processes=[])
        assert blockers and "unverified cleanup" in blockers[0]


# ---------------------------------------------------------------------------
# T10  safety exceptions can never become INCONCLUSIVE (H2) and environment is not a violation (M6)
# ---------------------------------------------------------------------------

class CommitFailed(RuntimeError):            # same name as consumer.CommitFailed, which is matched by name
    pass


class KafkaException(Exception):
    pass


class FakeKafkaError:
    def __init__(self, name):
        self._name = name

    def name(self):
        return self._name


def _caused(outer, inner):
    try:
        try:
            raise inner
        except BaseException as cause:
            raise outer from cause
    except BaseException as final:
        return final


class TestExceptionClassification:

    @pytest.mark.parametrize("exc", [
        CommitFailed("offsets were not committed"), AssertionError("invariant"),
        RuntimeError("offset batching state is unsafe: bad"),
        _caused(RuntimeError("wrapper"), CommitFailed("inner")),
        _caused(TimeoutError("poll timed out"), CommitFailed("hidden under a timeout")),
        _caused(ConnectionError("lost"), RuntimeError("offset batching state is unsafe: x")),
        _caused(RuntimeError("w"), AssertionError("a")),
    ])
    def test_safety_exceptions_are_failures_whatever_surrounds_them(self, it_module, exc):
        assert it_module.classify_exception(exc) == ("FAIL", "safety")

    def test_an_unstopped_process_is_a_safety_failure(self, it_module):
        assert it_module.classify_exception(it_module.ProcessNotStopped("pid 1")) == ("FAIL", "safety")

    @pytest.mark.parametrize("exc", [
        TimeoutError("t"), ConnectionRefusedError("c"), ConnectionResetError("r"), BrokenPipeError("b"),
        subprocess.TimeoutExpired("x", 1), KafkaException(FakeKafkaError("_TRANSPORT")),
        KafkaException(FakeKafkaError("_ALL_BROKERS_DOWN")), KafkaException(FakeKafkaError("REQUEST_TIMED_OUT"))])
    def test_the_narrow_infrastructure_allowlist_is_inconclusive(self, it_module, exc):
        assert it_module.classify_exception(exc) == ("INCONCLUSIVE", "infrastructure")

    def test_the_module_defined_environment_errors_are_inconclusive(self, it_module):
        assert it_module.classify_exception(it_module.InfrastructureError("topic did not appear")) \
            == ("INCONCLUSIVE", "infrastructure")
        assert it_module.classify_exception(it_module.EnvironmentNotReady("slow join")) \
            == ("INCONCLUSIVE", "infrastructure")

    def test_the_psycopg_connection_errors_are_infrastructure_but_other_database_errors_are_not(self, it_module):
        operational = type("OperationalError", (Exception,), {"__module__": "psycopg.errors"})
        integrity = type("IntegrityError", (Exception,), {"__module__": "psycopg.errors"})
        elsewhere = type("OperationalError", (Exception,), {"__module__": "other"})
        assert it_module.classify_exception(operational("down"))[0] == "INCONCLUSIVE"
        assert it_module.classify_exception(integrity("dup"))[0] == "FAIL"
        assert it_module.classify_exception(elsewhere("x"))[0] == "FAIL"

    @pytest.mark.parametrize("exc", [
        RuntimeError("consumer error: x"), ValueError("v"), KeyError("k"), OSError("disk"), Exception("e"),
        ImportError("no module"), KafkaException(FakeKafkaError("UNKNOWN_TOPIC_OR_PART")),
        KafkaException("text"), KafkaException()])
    def test_everything_unexpected_is_a_failure(self, it_module, exc):
        assert it_module.classify_exception(exc) == ("FAIL", "unexpected")


class TestCaseDecorator:

    @pytest.fixture(autouse=True)
    def _records(self, it_module):
        it_module._RECORDS.clear()
        it_module._PROCESS_PROBLEMS.clear()
        yield
        it_module._RECORDS.clear()
        it_module._PROCESS_PROBLEMS.clear()

    def _run(self, it_module, case_id, exc):
        @it_module.case(case_id)
        def body():
            raise exc
        try:
            body()
        except BaseException as raised:
            assert raised is exc
            raised_it = True
        else:
            raised_it = False
        record = it_module._RECORDS[-1]
        return record["status"], raised_it, record["detail"]

    @pytest.mark.parametrize("case_id", ["C04_cooperative_rebalance", "C05_lost_ownership", "C07b_forced_kill_restart"])
    @pytest.mark.parametrize("exc", [CommitFailed("c"), RuntimeError("offset batching state is unsafe: s"),
                                     AssertionError("a"), RuntimeError("something unforeseen"),
                                     _caused(TimeoutError("t"), CommitFailed("hidden"))])
    def test_a_safety_or_unexpected_exception_in_a_timing_case_is_a_failure_that_still_raises(self, it_module, case_id, exc):
        status, raised, detail = self._run(it_module, case_id, exc)
        assert status == "FAIL" and raised
        assert detail["error_category"] in ("safety", "unexpected")

    @pytest.mark.parametrize("case_id", ["C04_cooperative_rebalance", "C05_lost_ownership", "C07b_forced_kill_restart"])
    @pytest.mark.parametrize("make", [lambda m: TimeoutError("t"), lambda m: ConnectionRefusedError("c"),
                                      lambda m: m.EnvironmentNotReady("a join took too long"),
                                      lambda m: m.InfrastructureError("topic did not appear")])
    def test_only_the_allowlist_makes_a_timing_case_inconclusive(self, it_module, case_id, make):
        exc = make(it_module)

        @it_module.case(case_id)
        def body():
            raise exc
        body()                                               # swallowed: nothing unsafe was seen
        record = it_module._RECORDS[-1]
        assert record["status"] == "INCONCLUSIVE" and record["detail"]["error_category"] == "infrastructure"

    @pytest.mark.parametrize("case_id", list(range(9)))
    @pytest.mark.parametrize("exc", [TimeoutError("t"), ConnectionError("e")])
    def test_a_deterministic_case_never_becomes_inconclusive(self, it_module, case_id, exc):
        status, raised, _ = self._run(it_module, it_module.DETERMINISTIC_CASES[case_id], exc)
        assert status == "FAIL" and raised

    def test_an_environment_error_in_a_deterministic_case_is_a_failure(self, it_module):
        status, raised, _ = self._run(it_module, "C03_eager_rebalance", it_module.EnvironmentNotReady("slow"))
        assert status == "FAIL" and raised

    def test_a_timing_case_that_returns_observed_but_left_an_unverified_process_fails(self, it_module):
        @it_module.case("C07b_forced_kill_restart")
        def body():
            it_module.record_process_problems(["second consumer: pid 7 is still running"])
            return "OBSERVED"
        body()
        record = it_module._RECORDS[-1]
        assert record["status"] == "FAIL"
        assert record["detail"]["process_problems"] == ["second consumer: pid 7 is still running"]

    def test_process_problems_are_written_to_the_report_the_orchestrator_reads(self, it_module, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTOPS_IT_EVIDENCE_DIR", str(tmp_path))

        @it_module.case("C07b_forced_kill_restart")
        def body():
            it_module.record_process_problems(["first consumer: pid 3 is still running"])
        body()
        assert json.loads((tmp_path / "process-report.json").read_text(encoding="utf-8")) \
            == ["first consumer: pid 3 is still running"]

    def test_results_are_written_after_every_case_so_a_killed_run_keeps_what_finished(self, it_module, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTOPS_IT_EVIDENCE_DIR", str(tmp_path))

        @it_module.case("C08_postgres_idempotency")
        def body():
            return None
        body()
        assert [r["case"] for r in json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))] \
            == ["C08_postgres_idempotency"]

    def test_environmental_preconditions_use_require_and_safety_checks_stay_assertions(self, it_module):
        with pytest.raises(it_module.EnvironmentNotReady):
            it_module.require(False, "slow")
        it_module.require(True, "fine")
        assert not issubclass(it_module.EnvironmentNotReady, AssertionError)

    def test_the_timing_preconditions_in_the_source_use_require(self):
        source = _MODULE.read_text(encoding="utf-8")
        for needle in ("the first member never got 3 partitions", "the first member did not persist 12 messages",
                       "the stalled member never got 3 partitions", "had not caught up within the time allowed"):
            line = next(l for l in source.splitlines() if needle in l)
            assert "require(" in line, needle
        assert "assert run_until" not in source.split('@case("C04_')[0].split("def rebalance_scenario")[1]

    def test_helpers_raise_infrastructure_errors_not_bare_runtime_errors(self):
        source = _MODULE.read_text(encoding="utf-8")
        assert "InfrastructureError(f\"topic" in source and "InfrastructureError(f\"produce failed" in source
        assert "RuntimeError(f\"produce failed" not in source and "RuntimeError(f\"topic" not in source


class TestHonestDriverLabels:

    def _bodies(self):
        source = _MODULE.read_text(encoding="utf-8")
        parts = re.split(r'^@case\("([A-Za-z0-9_]+)"\)', source, flags=re.M)[1:]
        return {parts[i]: parts[i + 1].split("\n\n\n")[0] for i in range(0, len(parts), 2)}

    def test_every_case_has_a_driver_and_it_is_recorded_in_the_detail(self, it_module):
        assert set(it_module.DRIVERS) == set(it_module.DETERMINISTIC_CASES) | set(it_module.TIMING_CASES)
        it_module._RECORDS.clear()

        @it_module.case("C03_eager_rebalance")
        def body():
            return None
        body()
        assert it_module._RECORDS[-1]["detail"]["driver"] == it_module.DRIVERS["C03_eager_rebalance"]
        it_module._RECORDS.clear()

    def test_a_case_is_labelled_with_the_real_loop_only_if_its_code_calls_it(self, it_module):
        for case_id, body in self._bodies().items():
            label = it_module.DRIVERS[case_id]
            if "run_consumer_loop" in label:
                assert any(word in body for word in ("run_consumer_loop", "drain_with_loop", "start_loop(", "main.py")), case_id
            if "Member.step" in label:
                assert "Member(" in body or "rebalance_scenario(" in body, case_id

    def test_the_cases_driven_by_member_step_are_not_called_the_real_loop(self, it_module):
        for case_id in ("C03_eager_rebalance", "C04_cooperative_rebalance", "C05_lost_ownership",
                        "C11_subscription_callbacks"):
            assert "re-implemented" in it_module.DRIVERS[case_id] and "(real loop)" not in it_module.DRIVERS[case_id]
        assert "re-implemented" in it_module.DRIVERS["C07a_crash_replay"] and "real loop" in it_module.DRIVERS["C07a_crash_replay"]
        for case_id in ("C06_close_callbacks", "C09_n1_versus_n100", "C10_idle_and_time_flush"):
            assert it_module.DRIVERS[case_id].endswith("(real loop)")

    def test_the_documentation_says_member_step_reimplements_the_loop(self):
        source = _MODULE.read_text(encoding="utf-8")
        assert "RE-IMPLEMENTATION" in source and "must not be read as evidence about the loop" in source


# ---------------------------------------------------------------------------
# T11  compose project identity, interrupted teardown, redaction, diagnostics (M1-M4)
# ---------------------------------------------------------------------------

class TestComposeProjectIdentity:

    def test_down_is_refused_when_the_compose_project_is_not_the_generated_one(self, h, monkeypatch):
        calls = []
        monkeypatch.setattr(h.smoke, "run", lambda *a, **k: calls.append(a) or None)
        for other in ("agentops", "agentops-workload-smoke", "agentops-batching-it-ffffffff", ""):
            monkeypatch.setattr(h.smoke, "PROJECT", other)
            with pytest.raises(h.SmokeFailure, match="refusing compose down"):
                h.BatchingOps("agentops-batching-it-0a1b2c3d").down()
        assert calls == []

    def test_down_runs_against_the_matching_project_only(self, h, monkeypatch):
        seen = []
        monkeypatch.setattr(h.smoke, "PROJECT", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.smoke, "compose_command", lambda *a: ["docker", "compose", "-p", h.smoke.PROJECT, *a])
        monkeypatch.setattr(h.smoke, "run", lambda command, **k: seen.append(command)
                            or types.SimpleNamespace(returncode=0, stderr="all gone", stdout=""))
        ops = h.BatchingOps("agentops-batching-it-0a1b2c3d")
        assert ops.down() == (0, "all gone")
        assert seen == [["docker", "compose", "-p", "agentops-batching-it-0a1b2c3d", "down", "--volumes",
                         "--rmi", "local", "--remove-orphans"]]
        assert "exit 0" in ops.log[0]

    def test_a_refused_teardown_is_a_cleanup_problem_with_a_marker_not_a_silent_redirect(self, h, monkeypatch, tmp_path):
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path)
        monkeypatch.setattr(h.smoke, "PROJECT", "agentops")
        monkeypatch.setattr(h.smoke.RUN, "compose_used", True)
        monkeypatch.setattr(h.smoke.RUN, "env_file", Path(__file__))
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "protected_before", None)
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h.S, "evidence", None)
        ran = []
        monkeypatch.setattr(h.smoke, "run", lambda *a, **k: ran.append(a))
        with pytest.raises(h.SmokeFailure):
            h.teardown()
        assert ran == []


class TestInterruptedTeardown:

    @pytest.fixture(autouse=True)
    def _quiet(self, h, monkeypatch, tmp_path):
        self.released = []
        monkeypatch.setattr(h.pipeline, "keep_awake", lambda: None)
        monkeypatch.setattr(h.pipeline, "release_awake", lambda: self.released.append(True))
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path / "root")
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "evidence", None)
        monkeypatch.setattr(h.S, "secrets", [])
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h.smoke, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("docker")))
        self.marker = tmp_path / "root" / "CLEANUP_UNVERIFIED"

    @pytest.mark.parametrize("interruption", [KeyboardInterrupt(), SystemExit(2)])
    def test_an_interrupted_teardown_writes_the_marker_and_propagates_the_same_exception(self, h, monkeypatch, interruption, capsys):
        def interrupted():
            raise interruption
        monkeypatch.setattr(h, "teardown", interrupted)
        with pytest.raises(type(interruption)) as raised:
            h.main(["--expect-head", HEAD])
        assert raised.value is interruption
        assert self.marker.exists() and type(interruption).__name__ in self.marker.read_text(encoding="utf-8")
        assert self.released == [True]
        out = capsys.readouterr().out
        assert "CLEANUP PROBLEM" in out and "cleanup verified: NO" in out

    def test_the_summary_and_evidence_are_still_written_before_the_interruption_propagates(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h, "teardown", lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        with pytest.raises(KeyboardInterrupt):
            h.main(["--expect-head", HEAD])
        verdict = json.loads((evidence / "verdict.json").read_text(encoding="utf-8"))
        assert verdict["verdict"] == "FAIL" and verdict["cleanup_verified"] is False
        assert (evidence / "manifest.sha256.json").is_file()

    def test_an_interruption_during_the_run_itself_still_tears_down_and_returns_one(self, h, monkeypatch):
        def interrupted(expect_head):
            raise KeyboardInterrupt
        torn = []
        monkeypatch.setattr(h, "it", interrupted)
        monkeypatch.setattr(h, "teardown", lambda: torn.append(True) or True)
        assert h.main(["--expect-head", HEAD]) == 1 and torn == [True]

    def test_the_teardown_itself_writes_the_marker_if_interrupted_after_finding_problems(self, h, monkeypatch):
        monkeypatch.setattr(h.S, "process_problems", ["pytest timeout: pid 9 is still running"])
        monkeypatch.setattr(h.S, "protected_before", {})

        def interrupted(project, before, ops):
            raise KeyboardInterrupt
        monkeypatch.setattr(h.pipeline, "safe_cleanup", interrupted)
        with pytest.raises(KeyboardInterrupt):
            h.teardown()
        assert "pid 9 is still running" in self.marker.read_text(encoding="utf-8")


class TestCredentialRedaction:

    SECRET = "Tr0ub4dor&3-temporary"

    def test_every_evidence_artifact_is_sanitized_in_place_whatever_its_type(self, h, tmp_path):
        (tmp_path / "junit.xml").write_text(f'<testcase message="password={self.SECRET}"/>', encoding="utf-8")
        (tmp_path / "c07b-first.log").write_text(f"connect failed for {self.SECRET}\n", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "raw.bin").write_bytes(b"\x00" + self.SECRET.encode() + b"\xff")
        (tmp_path / "clean.txt").write_text("nothing", encoding="utf-8")
        assert h.find_secret_leaks(tmp_path, [self.SECRET]) == ["c07b-first.log", "junit.xml", "sub/raw.bin"]
        assert h.sanitize_tree(tmp_path, [self.SECRET, ""]) == 3
        assert h.find_secret_leaks(tmp_path, [self.SECRET]) == []
        assert "<redacted>" in (tmp_path / "junit.xml").read_text(encoding="utf-8")
        assert (tmp_path / "clean.txt").read_text(encoding="utf-8") == "nothing"

    def test_the_leak_report_names_files_never_the_secret(self, h, tmp_path):
        (tmp_path / "a.log").write_text(f"x {self.SECRET} y", encoding="utf-8")
        leaks = h.find_secret_leaks(tmp_path, [self.SECRET])
        assert leaks == ["a.log"] and not any(self.SECRET in item for item in leaks)

    def test_the_manifest_file_is_not_scanned_and_empty_secrets_never_match(self, h, tmp_path):
        (tmp_path / "manifest.sha256.json").write_text(self.SECRET, encoding="utf-8")
        (tmp_path / "a.txt").write_text("text", encoding="utf-8")
        assert h.find_secret_leaks(tmp_path, [self.SECRET]) == [] and h.find_secret_leaks(tmp_path, [""]) == []

    def test_finalize_sanitizes_then_verifies(self, h, tmp_path):
        (tmp_path / "junit.xml").write_text(self.SECRET, encoding="utf-8")
        assert h.finalize_evidence(tmp_path, [self.SECRET]) == []

    def test_a_credential_that_cannot_be_removed_fails_the_verdict_without_printing_it(self, h, monkeypatch, tmp_path, capsys):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        (evidence / "junit.xml").write_text(self.SECRET, encoding="utf-8")
        for name in ("keep_awake", "release_awake"):
            monkeypatch.setattr(h.pipeline, name, lambda: None)
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h.S, "secrets", [self.SECRET])
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h, "sanitize_tree", lambda directory, secrets: 0)          # sanitizing fails
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 1
        out = capsys.readouterr().out
        assert "CREDENTIAL FOUND IN EVIDENCE FILES: junit.xml" in out and self.SECRET not in out
        verdict_text = (evidence / "verdict.json").read_text(encoding="utf-8")
        assert self.SECRET not in verdict_text
        assert json.loads(verdict_text)["verdict"] == "FAIL"
        assert json.loads(verdict_text)["evidence_files_with_a_credential"] == ["junit.xml"]

    def test_a_clean_run_sanitizes_junit_and_logs_and_still_passes(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        (evidence / "junit.xml").write_text(self.SECRET, encoding="utf-8")
        (evidence / "c07b-second.log").write_text(self.SECRET, encoding="utf-8")
        for name in ("keep_awake", "release_awake"):
            monkeypatch.setattr(h.pipeline, name, lambda: None)
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h.S, "secrets", [self.SECRET])
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 0
        assert h.find_secret_leaks(evidence, [self.SECRET]) == []
        manifest = json.loads((evidence / "manifest.sha256.json").read_text(encoding="utf-8"))
        assert {"junit.xml", "c07b-second.log", "verdict.json"} <= set(manifest)

    def test_the_final_verdict_needs_clean_evidence(self, h):
        result = h.classify(passing(h))
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=0, evidence_clean=False) == "FAIL"
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=0, evidence_clean=True) == "PASS"

    def test_the_subprocess_log_helper_masks_the_credential(self, it_module, tmp_path):
        log = tmp_path / "c07b-first.log"
        log.write_text(f"PG_PASSWORD={self.SECRET}\nok\n", encoding="utf-8")
        it_module.sanitize_file(log, self.SECRET)
        assert self.SECRET not in log.read_text(encoding="utf-8") and "ok" in log.read_text(encoding="utf-8")
        it_module.sanitize_file(tmp_path / "missing.log", self.SECRET)
        it_module.sanitize_file(log, "")

    def test_c07b_masks_both_consumer_logs_after_the_processes_are_stopped(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c07b_forced_kill_of_the_real_consumer"):source.index('# C12  sustained')]
        assert "sanitize_file(env.evidence / name, env.pg_password)" in body
        finally_part = body[body.rindex("    finally:"):]
        assert finally_part.index("terminate_tree(process)") < finally_part.index("sanitize_file(")


class TestFailureDiagnostics:

    SECRET = "Tr0ub4dor&3-temporary"

    def test_only_sanitized_logs_are_copied_and_smoke_env_never(self, h, tmp_path):
        temp, evidence = tmp_path / "temp", tmp_path / "evidence"
        temp.mkdir()
        evidence.mkdir()
        (temp / "pip-install.log").write_text(f"pip {self.SECRET}", encoding="utf-8")
        (temp / "bootstrap.log").write_text("bootstrap failed", encoding="utf-8")
        (temp / "smoke.env").write_text(f"POSTGRES_PASSWORD={self.SECRET}", encoding="utf-8")
        (temp / "offsets.json").write_text("{}", encoding="utf-8")
        (temp / "venv").mkdir()
        copied = h.preserve_diagnostics(evidence, temp, [self.SECRET])
        assert copied == ["bootstrap.log", "pip-install.log"]
        assert sorted(p.name for p in (evidence / "diagnostics").iterdir()) == copied
        assert self.SECRET not in (evidence / "diagnostics" / "pip-install.log").read_text(encoding="utf-8")

    def test_nothing_happens_without_a_temp_or_an_evidence_directory(self, h, tmp_path):
        assert h.preserve_diagnostics(tmp_path, None, []) == []
        assert h.preserve_diagnostics(tmp_path / "none", tmp_path, []) == []
        assert h.preserve_diagnostics(tmp_path, tmp_path / "none", []) == []

    def test_a_failure_before_pytest_keeps_the_logs_before_the_temp_directory_is_deleted(self, h, monkeypatch, tmp_path):
        temp, evidence = tmp_path / "temp", tmp_path / "bit-0a1b2c3d"
        temp.mkdir()
        evidence.mkdir()
        (temp / "bootstrap.log").write_text(f"error with {self.SECRET}", encoding="utf-8")
        for name in ("keep_awake", "release_awake"):
            monkeypatch.setattr(h.pipeline, name, lambda: None)
        monkeypatch.setattr(h.smoke.RUN, "temp", temp)
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h.S, "secrets", [self.SECRET])
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h.S, "logs_collected", False)
        monkeypatch.setattr(h.smoke.RUN, "compose_used", False)

        def failing(expect_head):
            raise h.SmokeFailure("bootstrap failed")
        seen = {}

        def teardown():
            seen["kept"] = (evidence / "diagnostics" / "bootstrap.log").is_file()      # the temp directory goes now
            return True
        monkeypatch.setattr(h, "it", failing)
        monkeypatch.setattr(h, "teardown", teardown)
        assert h.main(["--expect-head", HEAD]) == 1
        assert seen["kept"] is True
        kept = (evidence / "diagnostics" / "bootstrap.log").read_text(encoding="utf-8")
        assert "<redacted>" in kept and self.SECRET not in kept

    def test_container_logs_are_collected_on_a_failure_only_when_compose_ran_and_not_yet_collected(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        collected = []
        monkeypatch.setattr(h, "collect_logs", lambda directory, secrets: collected.append(directory))
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h.smoke.RUN, "temp", None)
        monkeypatch.setattr(h.smoke.RUN, "compose_used", True)
        monkeypatch.setattr(h.S, "logs_collected", False)
        h.preserve_failure_evidence([], ran=False)
        h.preserve_failure_evidence([], ran=True)
        monkeypatch.setattr(h.S, "logs_collected", True)
        h.preserve_failure_evidence([], ran=False)
        monkeypatch.setattr(h.smoke.RUN, "compose_used", False)
        monkeypatch.setattr(h.S, "logs_collected", False)
        h.preserve_failure_evidence([], ran=False)
        assert collected == [evidence]

    def test_a_failure_to_keep_evidence_never_stops_the_cleanup(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h.smoke.RUN, "temp", tmp_path)
        monkeypatch.setattr(h.smoke.RUN, "compose_used", True)
        monkeypatch.setattr(h.S, "logs_collected", False)

        def broken(*args, **kwargs):
            raise OSError("disk full")
        monkeypatch.setattr(h, "preserve_diagnostics", broken)
        monkeypatch.setattr(h, "collect_logs", broken)
        h.preserve_failure_evidence([], ran=False)            # must not raise

    def test_the_teardown_output_is_kept_sanitized(self, h, monkeypatch, tmp_path):
        evidence = tmp_path / "bit-0a1b2c3d"
        evidence.mkdir()
        monkeypatch.setattr(h, "evidence_root", lambda: tmp_path / "root")
        monkeypatch.setattr(h.S, "evidence", evidence)
        monkeypatch.setattr(h.S, "secrets", [self.SECRET])
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "protected_before", {})
        monkeypatch.setattr(h.S, "process_problems", [f"leftover {self.SECRET}"])
        monkeypatch.setattr(h.pipeline, "safe_cleanup", lambda project, before, ops: [])
        monkeypatch.setattr(h, "protected_snapshot", lambda: {})
        assert h.teardown() is False
        text = (evidence / "teardown.log").read_text(encoding="utf-8")
        assert "CLEANUP PROBLEM" in text and self.SECRET not in text


# ---------------------------------------------------------------------------
# T12  B3J-248: stand-in signatures, the spy, C06/C10 checks, C07b replay, C04 diagnostics
# ---------------------------------------------------------------------------

import ast  # noqa: E402


def _ast(path):
    return ast.parse(path.read_text(encoding="utf-8"))


class FakeTP:
    def __init__(self, partition, offset):
        self.partition, self.offset = partition, offset


class FakeKafka:
    """The real consumer, as far as the spy forwards to it."""

    def __init__(self, polls=(), fail_commit=None):
        self.polls, self.fail_commit, self.commits, self.closed = list(polls), fail_commit, [], 0

    def poll(self, timeout=None):
        return self.polls.pop(0) if self.polls else None

    def commit(self, *args, **kwargs):
        self.commits.append(kwargs)
        if self.fail_commit:
            raise self.fail_commit
        return [FakeTP(tp.partition, tp.offset) for tp in kwargs.get("offsets", [])]

    def close(self):
        self.closed += 1

    def assignment(self):
        return ["assigned"]


class StubBatcher:
    """What a batcher does with its consumer: it commits through it."""

    def __init__(self, consumer):
        self.consumer, self.closing = consumer, False

    def flush(self, offsets=((0, 5),)):
        return self.consumer.commit(offsets=[FakeTP(p, o) for p, o in offsets], asynchronous=False)


class FakeMessage:
    def __init__(self, partition=0, offset=0):
        self._p, self._o = partition, offset

    def partition(self):
        return self._p

    def offset(self):
        return self._o


def commit_event(seq, **over):
    base = {"kind": "commit", "seq": seq, "keywords": ["asynchronous", "offsets"], "closing": False,
            "shutdown": False, "after_empty_poll": False}
    base.update(over)
    return base


def close_event(seq):
    return {"kind": "close", "seq": seq}


class TestRepositoryStandIn:

    def test_the_stand_in_has_exactly_the_real_signature(self, it_module):
        real = next(node for node in ast.walk(_ast(_REPO / "storage-consumer" / "repository.py"))
                    if isinstance(node, ast.FunctionDef) and node.name == "insert_span")
        wanted = [a.arg for a in real.args.args]
        assert wanted == ["self", "event", "topic", "partition", "offset"]
        assert list(inspect.signature(it_module.RecordingRepo.insert_span).parameters) == wanted

    def test_every_insert_span_defined_in_the_integration_module_has_the_real_parameter_names(self):
        defs = [node for node in ast.walk(_ast(_MODULE)) if isinstance(node, ast.FunctionDef) and node.name == "insert_span"]
        assert defs
        for node in defs:
            assert [a.arg for a in node.args.args] == ["self", "event", "topic", "partition", "offset"]

    def test_the_consumer_calls_insert_span_by_these_keywords(self):
        calls = [node for node in ast.walk(_ast(_REPO / "storage-consumer" / "consumer.py"))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "insert_span"]
        assert calls
        for call in calls:
            assert sorted(k.arg for k in call.keywords) == ["offset", "partition", "topic"]

    def test_the_stand_in_accepts_the_loops_keyword_call_and_records_results(self, it_module):
        seen = []

        class Real:
            def insert_span(self, event, topic, partition, offset):
                seen.append((event, topic, partition, offset))
                return len(seen) % 2 == 1
        stops = []
        repo = it_module.RecordingRepo(Real(), on_insert=lambda count, fresh: stops.append((count, fresh)))
        assert repo.insert_span("e1", topic="t", partition=1, offset=7) is True
        assert repo.insert_span("e2", topic="t", partition=1, offset=8) is False
        assert seen == [("e1", "t", 1, 7), ("e2", "t", 1, 8)]
        assert repo.results == [True, False] and stops == [(1, True), (2, False)]
        with pytest.raises(TypeError):
            repo.insert_span("e", topic_="t", partition=0, offset=0)           # the old, wrong keyword

    def test_the_stand_in_can_stop_a_loop_after_a_number_of_inserts(self, it_module):
        import threading
        stop = threading.Event()
        repo = it_module.RecordingRepo(types.SimpleNamespace(insert_span=lambda *a, **k: True),
                                       on_insert=lambda count, fresh: stop.set() if count >= 3 else None)
        for index in range(3):
            assert not stop.is_set()
            repo.insert_span("e", topic="t", partition=0, offset=index)
        assert stop.is_set()


class TestSpyObservesTheBatchersConsumer:

    def test_a_batcher_built_on_the_spy_has_its_commits_observed_in_order(self, it_module):
        real = FakeKafka()
        spy = it_module.SpyConsumer(real)
        batcher = StubBatcher(spy)
        spy.batcher = batcher
        batcher.flush(((0, 5), (1, 9)))
        spy.close()
        kinds = [e["kind"] for e in spy.events]
        assert kinds == ["commit", "close"] and len(spy.commits) == 1
        event = spy.commits[0]
        assert event["keywords"] == ["asynchronous", "offsets"] and event["offsets"] == [(0, 5), (1, 9)]
        assert event["closing"] is False and event["shutdown"] is False and real.closed == 1

    def test_a_batcher_built_on_the_raw_consumer_is_invisible_which_is_why_the_module_never_does_it(self, it_module):
        real = FakeKafka()
        spy = it_module.SpyConsumer(real)
        StubBatcher(real).flush()
        assert spy.commits == [] and len(real.commits) == 1                        # the original defect

    def test_the_state_at_each_commit_is_recorded(self, it_module):
        import threading
        shutdown, real = threading.Event(), FakeKafka(polls=[None])
        spy = it_module.SpyConsumer(real, shutdown)
        spy.batcher = batcher = StubBatcher(spy)
        spy.poll(1.0)                                  # an idle poll
        batcher.flush()
        shutdown.set()
        batcher.flush()
        batcher.closing = True
        batcher.flush()
        flags = [(e["after_empty_poll"], e["shutdown"], e["closing"]) for e in spy.commits]
        assert flags == [(True, False, False), (True, True, False), (True, True, True)]

    def test_the_message_form_is_recorded_too(self, it_module):
        spy = it_module.SpyConsumer(FakeKafka())
        spy.commit(message=FakeMessage(2, 41), asynchronous=False)
        assert spy.commits[0]["keywords"] == ["asynchronous", "message"] and spy.commits[0]["offsets"] == [(2, 42)]

    def test_a_failing_commit_is_recorded_and_still_raises(self, it_module):
        spy = it_module.SpyConsumer(FakeKafka(fail_commit=RuntimeError("generation")))
        spy.batcher = StubBatcher(spy)
        with pytest.raises(RuntimeError):
            spy.batcher.flush()
        assert "RuntimeError: generation" in spy.commits[0]["error"]

    def test_other_calls_are_forwarded(self, it_module):
        spy = it_module.SpyConsumer(FakeKafka())
        assert spy.assignment() == ["assigned"]

    def test_every_batcher_for_the_loop_cases_is_built_on_the_spy(self):
        found = {}
        for func in [n for n in ast.walk(_ast(_MODULE)) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and "OffsetBatcher" in ast.unparse(node.func) and node.args:
                    found.setdefault(func.name, set()).add(ast.unparse(node.args[0]))
        assert found["test_c06_close_callbacks"] == {"spy"}
        assert found["drain_with_loop"] == {"spy"}
        assert found["start_loop"] == {"spy"}
        assert found["__init__"] == {"self.spy"}                                  # Member
        assert found["test_c02_commit_for_unknown_partitions"] == {"consumer"}    # fed by hand, deliberately raw
        assert found["test_c07a_crash_and_replay"] == {"consumer"}                # phase 2: no commit counting claimed

    def test_the_loop_cases_give_the_spy_to_the_loop_as_well(self):
        source = _MODULE.read_text(encoding="utf-8")
        assert source.count("run_consumer_loop(spy,") >= 3
        assert "run_consumer_loop(spy, Repo()" not in source


class TestCloseOrderingCannotPassVacuously:

    def test_zero_observed_commits_is_a_problem(self, it_module):
        assert any("vacuous" in p for p in it_module.verify_close_ordering([close_event(0)]))
        assert any("vacuous" in p for p in it_module.verify_close_ordering([]))

    def test_the_expected_sequence_passes(self, it_module):
        events = [commit_event(0), commit_event(1, shutdown=True), close_event(2)]
        assert it_module.verify_close_ordering(events) == []

    def test_a_missing_or_repeated_close_is_a_problem(self, it_module):
        assert it_module.verify_close_ordering([commit_event(0)])
        assert it_module.verify_close_ordering([commit_event(0), close_event(1), close_event(2)])

    def test_a_commit_after_close_began_is_detected_two_ways(self, it_module):
        after = [commit_event(0), close_event(1), commit_event(2, shutdown=True)]
        assert any("after closing began" in p for p in it_module.verify_close_ordering(after))
        flagged = [commit_event(0), commit_event(1, closing=True, shutdown=True), close_event(2)]
        assert any("after closing began" in p for p in it_module.verify_close_ordering(flagged))
        assert any("does not precede" in p for p in it_module.verify_close_ordering(after))

    def test_the_wrong_keyword_form_is_a_problem(self, it_module):
        events = [commit_event(0, keywords=["asynchronous", "message"]), close_event(1)]
        assert any("expected" in p for p in it_module.verify_close_ordering(events))
        assert it_module.verify_close_ordering(events, ("asynchronous", "message")) == []

    def test_the_c06_body_requires_the_ordering_check_and_commits_through_the_spy(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c06_close_callbacks"):source.index('@case("C07a_')]
        assert "verify_close_ordering(spy.events)" in body and "assert not problems" in body
        assert "SpyConsumer(consumer, shutdown)" in body and "OffsetBatcher(spy," in body
        assert "commit_calls" not in body


class TestIntervalFlushIsNotAShutdownFlush:

    def test_classification(self, it_module):
        events = [commit_event(0), commit_event(1, after_empty_poll=True), commit_event(2),
                  commit_event(3, shutdown=True), close_event(4), commit_event(5, shutdown=True)]
        result = it_module.classify_flushes(events)
        assert result == {"interval": [0, 2], "idle": [1], "shutdown": [3], "during_close": [5]}

    def test_two_interval_flushes_before_shutdown_pass(self, it_module):
        assert it_module.verify_interval_run([commit_event(0), commit_event(1), commit_event(2, shutdown=True)]) == []

    def test_only_a_shutdown_flush_does_not_count(self, it_module):
        problems = it_module.verify_interval_run([commit_event(0, shutdown=True), close_event(1)])
        assert problems and "0 interval" in problems[0]

    def test_idle_flushes_do_not_count_as_interval_flushes(self, it_module):
        events = [commit_event(0, after_empty_poll=True), commit_event(1, after_empty_poll=True)]
        assert it_module.verify_interval_run(events)

    def test_one_interval_flush_is_not_enough(self, it_module):
        assert it_module.verify_interval_run([commit_event(0)])
        assert it_module.verify_interval_run([commit_event(0)], minimum=1) == []

    def test_a_commit_after_closing_began_fails_the_run(self, it_module):
        events = [commit_event(0), commit_event(1), close_event(2), commit_event(3)]
        assert any("after closing began" in p for p in it_module.verify_interval_run(events))

    def test_the_c10_body_runs_both_scenarios_and_applies_the_checks(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def start_loop"):source.index('@case("C11_')]
        assert body.count("start_loop(env, topic, group, 1000, 1.0)") == 2          # N=1000, T=1.0 s, both scenarios
        assert "verify_interval_run(loop.spy.events)" in body and "classify_flushes(" in body
        assert "time.sleep(0.4)" in body and "midway" in body and "reached_end == total" in body
        assert "trickle_errors" in body


class TestReplayVerification:

    def test_expected_replays_count_rows_at_or_beyond_the_committed_offset_per_partition(self, it_module):
        pairs = [(0, o) for o in range(44)] + [(1, o) for o in range(43)] + [(2, o) for o in range(43)]
        assert it_module.expected_replays(pairs, {0: 14, 1: 43, 2: 43}) == {0: 30, 1: 0, 2: 0}
        assert it_module.expected_replays(pairs, {0: None, 1: 40}) == {0: 44, 1: 3, 2: 43}
        assert it_module.expected_replays([], {0: 5}) == {0: 0}

    def test_the_numbers_of_the_preserved_live_run_give_23(self, it_module):
        pairs = [(0, o) for o in range(41)] + [(1, o) for o in range(41)] + [(2, o) for o in range(41)]       # 123 rows
        assert it_module.expected_replays(pairs, {0: 34, 1: 33, 2: 33}) == {0: 7, 1: 8, 2: 8}
        assert sum(it_module.expected_replays(pairs, {0: 34, 1: 33, 2: 33}).values()) == 23

    def test_gaps_duplicates_and_extras_are_detected(self, it_module):
        good = [(0, 0), (0, 1), (1, 0)]
        assert it_module.contiguity_problems(good) == [] and it_module.contiguity_problems(good, {0: 2, 1: 1}) == []
        assert "missing [1]" in it_module.contiguity_problems([(0, 0), (0, 2)])[0]
        assert "1 duplicate" in it_module.contiguity_problems([(0, 0), (0, 0)])[0]
        assert it_module.contiguity_problems(good, {0: 3, 1: 1})                       # a missing tail
        assert it_module.contiguity_problems(good, {0: 1, 1: 1})                       # an unexpected extra

    def _line(self, kind="window", **counters):
        base = {"conflicts": 0, "idle_polls": 0, "inserted": 0, "messages": 0}
        base.update(counters)
        return "storage-consumer timing " + json.dumps({"kind": kind, "counters": base})

    def test_only_timing_windows_are_summed_and_junk_is_ignored(self, it_module):
        text = "\n".join(["starting", self._line(messages=2, inserted=2), self._line(messages=3, inserted=1, conflicts=2),
                          self._line(kind="final", messages=99), "storage-consumer timing {broken", ""])
        assert it_module.parse_timing_counters(text) == {"windows": 2, "messages": 5, "inserted": 3, "conflicts": 2}

    def test_matching_counts_are_ok(self, it_module):
        totals = {"windows": 16, "messages": 300, "inserted": 277, "conflicts": 23}
        assert it_module.verify_replay(23, 300, totals) == ("OK", [])

    def test_a_log_missing_messages_is_incomplete_not_a_pass_or_a_failure(self, it_module):
        verdict, problems = it_module.verify_replay(23, 300, {"windows": 9, "messages": 277, "inserted": 277, "conflicts": 0})
        assert verdict == "INCOMPLETE" and problems

    def test_a_conflict_count_that_differs_from_the_expected_replay_is_a_mismatch(self, it_module):
        for conflicts in (0, 22, 24):
            verdict, problems = it_module.verify_replay(
                23, 300, {"windows": 5, "messages": 300, "inserted": 300 - conflicts, "conflicts": conflicts})
            assert verdict == "MISMATCH" and problems

    def test_counters_that_do_not_add_up_are_a_mismatch(self, it_module):
        verdict, _ = it_module.verify_replay(23, 300, {"windows": 5, "messages": 300, "inserted": 270, "conflicts": 23})
        assert verdict == "MISMATCH"

    def test_zero_expected_replays_with_conflicts_counted_is_a_mismatch(self, it_module):
        assert it_module.verify_replay(0, 10, {"windows": 1, "messages": 10, "inserted": 7, "conflicts": 3})[0] == "MISMATCH"
        assert it_module.verify_replay(0, 10, {"windows": 1, "messages": 10, "inserted": 10, "conflicts": 0})[0] == "OK"

    def test_c07b_reads_the_log_only_after_the_restarted_process_is_stopped_and_derives_the_expectation(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c07b_forced_kill_of_the_real_consumer"):source.index('# C12  sustained')]
        assert "conflicts_seen_in_timing_windows" not in body
        assert body.index("terminate_tree(second)") < body.index("parse_timing_counters(")
        assert body.index("persisted_pairs(conn, tag)") < body.index('start_consumer("c07b-second.log")')
        assert "expected_replays(pairs_at_kill, held_at_kill)" in body and "verify_replay(expected_conflicts" in body
        assert "contiguity_problems(final_pairs, end)" in body
        assert 'require(verdict != "INCOMPLETE"' in body and 'assert verdict == "OK"' in body

    def test_c07a_derives_its_replay_count_from_the_database_too(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c07a_crash_and_replay"):source.index('@case("C07b_')]
        assert "expected_replays(pairs_at_crash, held)" in body and "RecordingRepo(" in body


class TestC04DiagnosticsSurviveAFailure:

    def _scenario(self, it_module, monkeypatch, raise_in_run_until):
        class CommitFailed(RuntimeError):
            pass

        class Member:
            def __init__(self, env, topic, group, **kwargs):
                self.timeline = [{"t": 1.0, "event": "assign", "partitions": [0, 1, 2]}]
                self.spy = it_module.SpyConsumer(FakeKafka(fail_commit=RuntimeError("ILLEGAL_GENERATION")))
                self.spy.batcher = types.SimpleNamespace(closing=False)
                self.batcher = types.SimpleNamespace(owned={("t", 0)}, commit_failed=True, fatal=None,
                                                     pending_offsets=lambda: {("t", 1): 6})
                self.persisted, self.closed = 12, False
                self.consumer = FakeKafka()
                try:
                    self.spy.commit(offsets=[FakeTP(1, 6)], asynchronous=False)
                except RuntimeError:
                    pass

            def assignment(self):
                return [0, 1]

            def close(self, **kwargs):
                self.closed = True
        calls = []

        def run_until(predicate, members, timeout, step=0.3):
            calls.append(1)
            if len(calls) >= raise_in_run_until:
                raise CommitFailed("Kafka offset commit failed: ILLEGAL_GENERATION")
            return True
        monkeypatch.setattr(it_module, "Member", Member)
        monkeypatch.setattr(it_module, "run_until", run_until)
        monkeypatch.setattr(it_module, "make_topic", lambda env, partitions: "topic")
        monkeypatch.setattr(it_module, "produce", lambda *a, **k: {})
        monkeypatch.setattr(it_module, "end_offsets", lambda *a, **k: {0: 6, 1: 6, 2: 6})
        monkeypatch.setattr(it_module, "committed", lambda *a, **k: {0: 6, 1: 6, 2: 6})
        return CommitFailed

    def test_the_timeline_and_commit_attempts_are_kept_when_the_scenario_raises(self, it_module, monkeypatch):
        error = self._scenario(it_module, monkeypatch, raise_in_run_until=3)
        it_module._RECORDS.clear()

        @it_module.case("C04_cooperative_rebalance")
        def body():
            it_module.rebalance_scenario(types.SimpleNamespace(kafka="x"), "cooperative-sticky")
        with pytest.raises(error):
            body()
        record = it_module._RECORDS[-1]
        assert record["status"] == "FAIL" and record["detail"]["error_category"] == "safety"
        first = record["detail"]["diagnostics_first"]
        assert first["timeline"][0]["event"] == "assign"
        assert first["commit_attempts"][0]["offsets"] == [(1, 6)] and "ILLEGAL_GENERATION" in first["commit_attempts"][0]["error"]
        assert first["batcher"]["commit_failed"] is True and first["batcher"]["pending"] == {"1": 6}
        assert first["assignment"] == [0, 1]
        assert "diagnostics_second" in record["detail"]
        it_module._RECORDS.clear()

    def test_the_failure_is_still_a_failure_and_never_inconclusive(self, it_module, monkeypatch):
        error = self._scenario(it_module, monkeypatch, raise_in_run_until=2)
        it_module._RECORDS.clear()

        @it_module.case("C04_cooperative_rebalance")
        def body():
            it_module.rebalance_scenario(types.SimpleNamespace(kafka="x"), "cooperative-sticky")
        with pytest.raises(error):
            body()
        assert it_module._RECORDS[-1]["status"] == "FAIL"
        assert it_module.classify_exception(error("generation")) == ("FAIL", "safety")
        it_module._RECORDS.clear()

    def test_snapshot_never_raises_even_with_a_broken_member(self, it_module):
        broken = types.SimpleNamespace(timeline=[{"event": "x"}], spy=None, batcher=types.SimpleNamespace(),
                                       assignment=lambda: (_ for _ in ()).throw(OSError("closed")))
        info = it_module.snapshot_member(broken)
        assert info["timeline"] == [{"event": "x"}] and ("snapshot_error" in info or "assignment_error" in info)

    def test_c05_keeps_its_diagnostics_in_a_finally(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c05_lost_ownership"):source.index('@case("C06_')]
        assert 'note("diagnostics_stalled", snapshot_member(stalled))' in body

    def test_production_classification_is_unchanged(self, it_module):
        class CommitFailed(RuntimeError):
            pass
        assert it_module.classify_exception(CommitFailed("ILLEGAL_GENERATION")) == ("FAIL", "safety")
        assert it_module.classify_exception(_caused(TimeoutError("t"), CommitFailed("c"))) == ("FAIL", "safety")


# ---------------------------------------------------------------------------
# T13  B3J-252: C12, sustained load through the production entry point
# ---------------------------------------------------------------------------

class FakeProducer:
    """A producer for paced_produce: records what was produced and 'delivers' it with offsets."""

    def __init__(self, clock=None, cost=0.0, fail_every=0, flush_result=0):
        self.sent, self.polls, self.clock, self.cost = [], 0, clock, cost
        self.fail_every, self.flush_result, self.counters = fail_every, flush_result, {}

    def produce(self, topic, value, partition, on_delivery):
        self.sent.append((topic, partition, json.loads(value)["span_id"]))
        if self.clock is not None:
            self.clock.now += self.cost                    # a producer slower than the schedule
        if self.fail_every and len(self.sent) % self.fail_every == 0:
            on_delivery("delivery failed", None)
            return
        offset = self.counters.get(partition, 0)
        self.counters[partition] = offset + 1
        on_delivery(None, types.SimpleNamespace(partition=lambda: partition, offset=lambda: offset))

    def poll(self, timeout):
        self.polls += 1

    def flush(self, timeout):
        return self.flush_result


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class TestPacedProduce:

    def test_it_sends_the_target_count_at_the_target_rate_and_reports_what_happened(self, it_module):
        clock, producer = FakeClock(), FakeProducer()
        clock.cost = 0
        result = it_module.paced_produce(producer, "t", "tag", rate=70, seconds=30, clock=clock, sleep=clock.sleep)
        assert result["sent"] == 2100 and result["delivered"] == 2100 and result["errors"] == []
        assert 69.0 <= result["observed_rate"] <= 71.0 and 29.0 <= result["elapsed_s"] <= 30.1
        assert sorted(result["offsets"]) == [0, 1, 2] and result["offsets"][0] == list(range(700))
        assert it_module.expected_end_from_offsets(result["offsets"]) == {0: 700, 1: 700, 2: 700}
        assert producer.polls == 2100

    def test_the_observed_rate_is_measured_not_assumed(self, it_module):
        clock = FakeClock()
        producer = FakeProducer(clock=clock, cost=0.05)          # 20 msg/s at best, slower than the 70 target
        result = it_module.paced_produce(producer, "t", "tag", rate=70, seconds=2, clock=clock, sleep=clock.sleep)
        assert result["sent"] == 140 and result["observed_rate"] < 25 and result["target_rate"] == 70

    def test_span_ids_are_unique_and_partitions_round_robin(self, it_module):
        clock, producer = FakeClock(), FakeProducer()
        it_module.paced_produce(producer, "t", "tag", rate=10, seconds=3, start_index=100, clock=clock, sleep=clock.sleep)
        ids = [span for _, _, span in producer.sent]
        assert len(set(ids)) == 30 and ids[0] == f"{100:016x}"
        assert [p for _, p, _ in producer.sent][:6] == [0, 1, 2, 0, 1, 2]

    def test_delivery_errors_and_a_failed_flush_are_reported(self, it_module):
        clock = FakeClock()
        result = it_module.paced_produce(FakeProducer(fail_every=5, flush_result=3), "t", "tag", rate=10, seconds=1,
                                         clock=clock, sleep=clock.sleep)
        assert result["errors"] and result["flush_remaining"] == 3 and result["delivered"] < result["sent"]

    def test_a_stop_request_ends_the_traffic_early(self, it_module):
        import threading
        stop, clock, producer = threading.Event(), FakeClock(), FakeProducer()
        original = producer.produce

        def produce_then_stop(*args, **kwargs):
            original(*args, **kwargs)
            if len(producer.sent) == 7:
                stop.set()
        producer.produce = produce_then_stop
        result = it_module.paced_produce(producer, "t", "tag", rate=10, seconds=10, stop=stop, clock=clock, sleep=clock.sleep)
        assert result["sent"] == 7


class TestMainConsumerEnvironment:

    def _env(self, tmp_path):
        return types.SimpleNamespace(repo=tmp_path, kafka="127.0.0.1:19092", pg_host="127.0.0.1", pg_port=15432,
                                     pg_database="agentops", pg_user="agentops", pg_password="temp-secret",
                                     python="python", evidence=tmp_path)

    def test_the_settings_reach_the_production_subprocess(self, it_module, tmp_path):
        values = it_module.main_consumer_environment(
            self._env(tmp_path), "topic-x", "group-x", batch=it_module.SUSTAINED_BATCH,
            interval=it_module.SUSTAINED_INTERVAL, timing=2, source={"PATH": "/bin", "OTHER": "no"})
        assert values["CONSUMER_COMMIT_BATCH_MESSAGES"] == "100" and values["CONSUMER_COMMIT_INTERVAL_SECONDS"] == "1.0"
        assert values["CONSUMER_TIMING_INTERVAL_SECONDS"] == "2"
        assert values["KAFKA_BOOTSTRAP_SERVERS"] == "127.0.0.1:19092" and values["TOPIC_SPANS"] == "topic-x"
        assert values["CONSUMER_GROUP_ID"] == "group-x" and values["PG_PORT"] == "15432"
        assert values["PATH"] == "/bin" and "OTHER" not in values

    def test_no_partition_assignment_strategy_is_set_so_the_client_default_applies(self, it_module, tmp_path):
        values = it_module.main_consumer_environment(self._env(tmp_path), "t", "g", batch=100, interval=1.0, timing=2, source={})
        assert not any("ASSIGN" in key.upper() or "STRATEGY" in key.upper() for key in values)
        source = _MODULE.read_text(encoding="utf-8")
        starter = source[source.index("def start_main_consumer"):source.index("def committed(")]
        assert "assignment" not in starter

    def test_the_credential_is_passed_only_through_the_environment(self, it_module, tmp_path):
        values = it_module.main_consumer_environment(self._env(tmp_path), "t", "g", batch=1, interval=1, timing=0, source={})
        assert list(values.values()).count("temp-secret") == 1
        source = _MODULE.read_text(encoding="utf-8")
        starter = source[source.index("def start_main_consumer"):source.index("def committed(")]
        assert "env.pg_password" not in starter.split("main_consumer_environment(")[0]
        assert "shell" not in starter and "stdin=subprocess.DEVNULL" in starter

    def test_c07b_keeps_its_original_settings_through_the_shared_starter(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c07b_forced_kill_of_the_real_consumer"):source.index('@case("C12_')]
        assert 'batch="50", interval="30", timing="2"' in body and "start_main_consumer(" in body

    def test_c12_constants_and_registration(self, it_module):
        assert (it_module.SUSTAINED_BATCH, it_module.SUSTAINED_INTERVAL) == ("100", "1.0")
        assert (it_module.SUSTAINED_RATE, it_module.SUSTAINED_SECONDS) == (70, 30)
        assert "C12_sustained_main_n100" in it_module.TIMING_CASES
        assert "C12_sustained_main_n100" not in it_module.DETERMINISTIC_CASES
        assert "main.py" in it_module.DRIVERS["C12_sustained_main_n100"] and "N=100" in it_module.DRIVERS["C12_sustained_main_n100"]

    def test_c12_is_gated_like_every_other_case(self, it_module):
        marks = [m for m in (it_module.pytestmark if isinstance(it_module.pytestmark, list) else [it_module.pytestmark])
                 if m.name == "skipif"]
        assert len(marks) == 1 and marks[0].args[0] is True
        source = _MODULE.read_text(encoding="utf-8")
        assert '@case("C12_sustained_main_n100")\ndef test_c12_sustained_production_entry_point' in source
        assert "localhost" not in source and "9092\"" not in source


class TestSustainedChecks:

    def test_reconciliation_needs_equal_offsets_and_a_running_consumer(self, it_module):
        end = {0: 700, 1: 700, 2: 700}
        assert it_module.reconciliation_problems(dict(end), end, True) == []
        assert any("not running" in p for p in it_module.reconciliation_problems(dict(end), end, False))
        behind = it_module.reconciliation_problems({0: 700, 1: 650, 2: None}, end, True)
        assert len(behind) == 2 and "partition 1" in behind[0] and "partition 2" in behind[1]
        assert it_module.reconciliation_problems({}, end, True)

    def test_offsets_of_other_records_in_the_topic_are_not_counted(self, it_module):
        assert it_module.expected_end_from_offsets({0: [3, 4, 5], 1: [], 2: [0]}) == {0: 6, 2: 1}

    def test_persistence_problems_detect_missing_duplicate_and_noncontiguous_records(self, it_module):
        end = {0: 3, 1: 2}
        pairs = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]
        assert it_module.persistence_problems(pairs, 5, 5, end, 5) == []
        assert any("missing [1]" in p for p in it_module.persistence_problems([(0, 0), (0, 2), (1, 0), (1, 1)], 4, 4, end, 5))
        assert any("rows persisted" in p for p in it_module.persistence_problems(pairs[:-1], 4, 4, end, 5))
        assert any("duplicate logical" in p for p in it_module.persistence_problems(pairs, 5, 4, end, 5))
        assert any("partition/offset pairs" in p for p in it_module.persistence_problems(pairs + [(1, 1)], 5, 5, end, 5))
        assert any("unexpected" in p for p in it_module.persistence_problems(pairs + [(1, 5)], 6, 6, end, 6))

    def test_zero_expected_replay_is_valid_and_not_a_proof_of_a_replay_path(self, it_module):
        pairs = [(p, o) for p in range(3) for o in range(700)]
        expected = it_module.expected_replays(pairs, {0: 700, 1: 700, 2: 700})
        assert expected == {0: 0, 1: 0, 2: 0} and sum(expected.values()) == 0
        totals = {"windows": 8, "messages": 30, "inserted": 30, "conflicts": 0}
        assert it_module.verify_replay(0, 30, totals) == ("OK", [])
        assert it_module.verify_replay(0, 30, dict(totals, inserted=29, conflicts=1))[0] == "MISMATCH"
        # a restarted consumer that never ran cannot be mistaken for a clean zero-replay: the marker batch is required
        assert it_module.verify_replay(0, 30, {"windows": 3, "messages": 0, "inserted": 0, "conflicts": 0})[0] == "INCOMPLETE"

    def test_a_nonzero_replay_is_still_checked_exactly(self, it_module):
        assert it_module.verify_replay(12, 42, {"windows": 5, "messages": 42, "inserted": 30, "conflicts": 12})[0] == "OK"
        assert it_module.verify_replay(12, 42, {"windows": 5, "messages": 42, "inserted": 31, "conflicts": 11})[0] == "MISMATCH"

    def test_the_c12_body_orders_its_steps_safely(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c12_sustained_production_entry_point"):source.index("# C08  PostgreSQL")]
        order = [body.index(text) for text in (
            "reconciliation_problems(held, expected_end, alive)",         # reconciled while the process is alive
            "terminate_tree(first)",                                       # then the verified kill
            "held_at_kill = committed(",                                   # read only afterwards
            "expected_replays(pairs_at_kill, held_at_kill)",
            'start_main_consumer(env, topic, group, "c12-second.log"',    # restart, same group and settings
            "terminate_tree(second)",                                      # the restarted process is stopped ...
            "parse_timing_counters(",                                      # ... before its log is read
            "verify_replay(expected_conflicts, expected_messages, totals)")]
        assert order == sorted(order)
        assert body.count("**settings") == 2 and "assert first.poll() is None" in body
        assert 'assert verdict == "OK"' in body and 'require(verdict != "INCOMPLETE"' in body
        assert "InfrastructureError(f\"the producer failed" in body and "SUSTAINED_MARKER_PER_PARTITION" in body
        assert "sanitize_file(env.evidence / name, env.pg_password)" in body and "terminate_tree(process)" in body

    def test_the_c12_records_distinguish_this_cases_records_from_the_topic(self):
        source = _MODULE.read_text(encoding="utf-8")
        body = source[source.index("def test_c12_sustained_production_entry_point"):source.index("# C08  PostgreSQL")]
        assert "expected_end_from_offsets(stats[\"offsets\"])" in body and "make_topic(env, 3)" in body
        assert "reconciled_before_termination" in body and "seconds_from_last_row_to_reconciled_offsets" in body


class TestC12FailurePropagation:
    """The whole case, with the services replaced by fakes."""

    @pytest.fixture
    def world(self, it_module, monkeypatch, tmp_path):
        import threading
        state = types.SimpleNamespace(poll_codes=[None], terminate=[[], [], []], stats=None, producer_error=None,
                                      rows=6, held={0: 2, 1: 2, 2: 2}, pairs=[(p, o) for p in range(3) for o in range(2)],
                                      terminated=[], started=[])
        state.stats = {"target_rate": 70, "target_seconds": 30, "sent": 6, "elapsed_s": 29.9, "observed_rate": 69.5,
                       "delivered": 6, "errors": [], "flush_remaining": 0, "offsets": {0: [0, 1], 1: [0, 1], 2: [0, 1]}}

        class Proc:
            def __init__(self, name):
                self.name, self.pid = name, 4000 + len(state.started)

            def poll(self):
                return state.poll_codes[0] if self.name == "first" else None

        def start(env, topic, group, log_name, **settings):
            state.started.append((log_name, settings))
            return Proc("first" if len(state.started) == 1 else "second"), types.SimpleNamespace(close=lambda: None)

        def paced(*args, **kwargs):
            if state.producer_error is not None:
                raise state.producer_error
            threading.Event().wait(0.3)
            return state.stats

        def terminate(process):
            state.terminated.append(process.name)
            return state.terminate[len(state.terminated) - 1] if len(state.terminated) <= 3 else []
        env = types.SimpleNamespace(kafka="127.0.0.1:19092", pg_host="127.0.0.1", pg_port=15432, pg_database="a",
                                    pg_user="a", pg_password="pw", evidence=tmp_path, repo=tmp_path, python="py")
        ticks = iter(range(10 ** 9))
        fake_time = types.SimpleNamespace(time=lambda: 1000.0 + next(ticks) * 0.5, sleep=lambda s: None)
        monkeypatch.setattr(it_module, "time", fake_time)
        monkeypatch.setattr(it_module, "make_topic", lambda env, n: "topic")
        monkeypatch.setattr(it_module, "connect_pg", lambda env: types.SimpleNamespace(close=lambda: None))
        monkeypatch.setattr(it_module, "kafka", lambda: types.SimpleNamespace(Producer=lambda conf: object()))
        monkeypatch.setattr(it_module, "start_main_consumer", start)
        monkeypatch.setattr(it_module, "paced_produce", paced)
        monkeypatch.setattr(it_module, "terminate_tree", terminate)
        monkeypatch.setattr(it_module, "count_rows", lambda conn, tag: (state.rows, state.rows))
        monkeypatch.setattr(it_module, "committed", lambda *a, **k: dict(state.held))
        monkeypatch.setattr(it_module, "persisted_pairs", lambda conn, tag: list(state.pairs))
        monkeypatch.setattr(it_module, "produce", lambda *a, **k: {0: [2], 1: [2], 2: [2]})
        it_module._RECORDS.clear()
        it_module._PROCESS_PROBLEMS.clear()
        yield env, state
        it_module._RECORDS.clear()
        it_module._PROCESS_PROBLEMS.clear()

    def _run(self, it_module, env):
        outcome = {}
        try:
            it_module.test_c12_sustained_production_entry_point.__wrapped__(env)
        except BaseException as exc:  # noqa: BLE001
            outcome["error"] = exc
        return outcome

    def _case(self, it_module, env):
        try:
            it_module.test_c12_sustained_production_entry_point(env)
        except BaseException as exc:  # noqa: BLE001
            return exc
        return None

    def test_both_consumers_get_the_production_settings(self, it_module, world):
        env, state = world
        state.poll_codes = [None]
        self._case(it_module, env)
        assert [name for name, _ in state.started][:1] == ["c12-first.log"]
        for _, settings in state.started:
            assert settings == {"batch": "100", "interval": "1.0", "timing": 2}

    def test_a_consumer_that_exits_during_the_traffic_fails_the_case(self, it_module, world):
        env, state = world
        state.poll_codes = [1]
        error = self._case(it_module, env)
        assert isinstance(error, AssertionError) and "exited during the traffic" in str(error)
        assert it_module._RECORDS[-1]["status"] == "FAIL"

    def test_a_producer_failure_is_reported_as_an_environment_problem_never_a_pass(self, it_module, world):
        env, state = world
        state.producer_error = OSError("broker gone")
        self._case(it_module, env)
        record = it_module._RECORDS[-1]
        assert record["status"] == "INCONCLUSIVE" and "the producer failed" in record["detail"]["error"]

    def test_delivery_errors_in_the_traffic_are_not_a_pass(self, it_module, world):
        env, state = world
        state.stats = dict(state.stats, errors=["delivery failed"])
        self._case(it_module, env)
        assert it_module._RECORDS[-1]["status"] == "INCONCLUSIVE"

    def test_offsets_that_are_not_reconciled_before_termination_fail_the_case(self, it_module, world):
        env, state = world
        state.held = {0: 2, 1: 1, 2: 2}
        error = self._case(it_module, env)
        record = it_module._RECORDS[-1]
        assert isinstance(error, AssertionError) and record["status"] == "FAIL"
        assert record["detail"]["reconciled_before_termination"] is False
        assert state.terminated == ["first", "second"][:len(state.terminated)] and "first" in state.terminated   # cleanup only

    def test_a_missing_record_fails_the_case(self, it_module, world):
        env, state = world
        state.pairs = state.pairs[:-1]
        state.rows = 5
        error = self._case(it_module, env)
        assert isinstance(error, AssertionError) and "every offset is committed but only 5 of 6" in str(error)
        assert it_module._RECORDS[-1]["status"] == "FAIL"

    def test_a_consumer_that_is_merely_behind_is_inconclusive_not_a_failure(self, it_module, world):
        env, state = world
        state.rows = 5
        state.held = {0: 1, 1: 1, 2: 1}
        self._case(it_module, env)
        record = it_module._RECORDS[-1]
        assert record["status"] == "INCONCLUSIVE" and "had not persisted every record" in record["detail"]["error"]

    def test_a_kill_that_cannot_be_verified_fails_and_is_reported_for_the_cleanup_marker(self, it_module, world):
        env, state = world
        state.terminate = [["pid 4000 is still running"], [], []]
        error = self._case(it_module, env)
        record = it_module._RECORDS[-1]
        assert isinstance(error, it_module.ProcessNotStopped) and record["status"] == "FAIL"
        assert any("first consumer" in p for p in it_module._PROCESS_PROBLEMS)
        assert record["detail"]["process_problems"]

    def test_evidence_logs_are_masked_in_the_final_cleanup(self, it_module, world, tmp_path):
        env, state = world
        (tmp_path / "c12-first.log").write_text("PG_PASSWORD=pw", encoding="utf-8")
        (tmp_path / "c12-second.log").write_text("PG_PASSWORD=pw", encoding="utf-8")
        state.poll_codes = [1]
        self._case(it_module, env)
        assert "pw" not in (tmp_path / "c12-first.log").read_text(encoding="utf-8").replace("PG_PASSWORD=", "")


# ---------------------------------------------------------------------------
# T14  B3J-253: the orchestrator recognizes all 13 cases, C12 among them
# ---------------------------------------------------------------------------

class TestOrchestratorRecognizesAllCases:

    ALL = ("C01_commit_response_shape", "C02_partial_failure", "C03_eager_rebalance", "C06_close_callbacks",
           "C07a_crash_replay", "C08_postgres_idempotency", "C09_n1_versus_n100", "C10_idle_and_time_flush",
           "C11_subscription_callbacks", "C04_cooperative_rebalance", "C05_lost_ownership",
           "C07b_forced_kill_restart", "C12_sustained_main_n100")

    def test_thirteen_distinct_cases_are_registered_and_match_the_integration_module(self, h, it_module):
        registered = h.DETERMINISTIC_CASES + h.TIMING_CASES
        assert len(registered) == len(set(registered)) == 13
        assert set(registered) == set(self.ALL)
        assert registered == it_module.DETERMINISTIC_CASES + it_module.TIMING_CASES

    def test_c12_is_a_timing_case_and_the_deterministic_set_is_unchanged(self, h):
        assert "C12_sustained_main_n100" in h.TIMING_CASES and "C12_sustained_main_n100" not in h.DETERMINISTIC_CASES
        assert len(h.DETERMINISTIC_CASES) == 9 and h.TIMING_CASES[:3] == (
            "C04_cooperative_rebalance", "C05_lost_ownership", "C07b_forced_kill_restart")

    def test_the_source_defines_no_case_twice(self):
        ids = re.findall(r'^@case\("([A-Za-z0-9_]+)"\)', _MODULE.read_text(encoding="utf-8"), re.M)
        assert len(ids) == len(set(ids)) == 13 and set(ids) == set(self.ALL)

    @pytest.mark.parametrize("status", ["OBSERVED", "NOT_OBSERVED", "INCONCLUSIVE"])
    def test_c12_not_being_observed_does_not_change_the_verdict(self, h, status):
        records = [dict(r, status=status) if r["case"] == "C12_sustained_main_n100" else r for r in passing(h)]
        result = h.classify(records)
        assert result["overall"] == "PASS" and result["timing"]["C12_sustained_main_n100"] == status
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=0) == "PASS"

    def test_a_c12_failure_fails_everything(self, h):
        records = [dict(r, status="FAIL") if r["case"] == "C12_sustained_main_n100" else r for r in passing(h)]
        result = h.classify(records)
        assert result["overall"] == "FAIL" and result["failed"] == ["C12_sustained_main_n100"]
        assert h.final_verdict(result, cleanup_verified=True, pytest_exit=1) == "FAIL"

    def test_c12_cannot_be_given_a_deterministic_status(self, h):
        records = [dict(r, status="PASS") if r["case"] == "C12_sustained_main_n100" else r for r in passing(h)]
        result = h.classify(records)
        assert result["overall"] == "FAIL" and any("C12" in p for p in result["problems"])

    def test_a_missing_c12_is_reported_and_does_not_decide_the_verdict(self, h):
        result = h.classify([r for r in passing(h) if r["case"] != "C12_sustained_main_n100"])
        assert result["timing"]["C12_sustained_main_n100"] == "MISSING" and result["overall"] == "PASS"

    def test_a_duplicated_c12_record_is_flagged(self, h):
        records = passing(h) + [{"case": "C12_sustained_main_n100", "status": "OBSERVED"}]
        assert h.classify(records)["timing"]["C12_sustained_main_n100"] == "DUPLICATE"

    @pytest.mark.parametrize("name", ["C13_unknown", "C12", "c12_sustained_main_n100", "C12_sustained_main_n100 "])
    def test_an_unknown_case_still_fails_the_run(self, h, name):
        result = h.classify(passing(h) + [{"case": name, "status": "PASS"}])
        assert result["overall"] == "FAIL" and result["problems"]

    def test_c04_commit_failed_still_fails_the_overall_verdict_end_to_end(self, h, it_module):
        class CommitFailed(RuntimeError):
            pass
        status, category = it_module.classify_exception(CommitFailed("ILLEGAL_GENERATION"))
        assert (status, category) == ("FAIL", "safety")
        records = [dict(r, status=status) if r["case"] == "C04_cooperative_rebalance" else r for r in passing(h)]
        result = h.classify(records)
        assert result["overall"] == "FAIL" and result["failed"] == ["C04_cooperative_rebalance"]

    def test_the_result_table_lists_every_case_including_c12(self, h, monkeypatch, capsys):
        for name in ("keep_awake", "release_awake"):
            monkeypatch.setattr(h.pipeline, name, lambda: None)
        monkeypatch.setattr(h.S, "project", "agentops-batching-it-0a1b2c3d")
        monkeypatch.setattr(h.S, "evidence", None)
        monkeypatch.setattr(h.S, "secrets", [])
        monkeypatch.setattr(h.S, "process_problems", [])
        monkeypatch.setattr(h, "it", lambda expect_head: (passing(h), 0, []))
        monkeypatch.setattr(h, "teardown", lambda: True)
        assert h.main(["--expect-head", HEAD]) == 0
        out = capsys.readouterr().out
        for case in self.ALL:
            assert case in out
        assert "overall: PASS" in out

    def test_evidence_and_cleanup_rules_are_unchanged_by_the_registration(self, h):
        source = _HARNESS.read_text(encoding="utf-8")
        for needle in ("def finalize_evidence", "def terminate_process_tree", "refusing compose down",
                       "write_marker(", "def read_process_report", 'AGENTOPS_BATCHING_IT="1"'):
            assert needle in source, needle
        assert h.DETERMINISTIC_STATUSES == ("PASS", "FAIL", "BLOCKED")
        assert h.TIMING_STATUSES == ("OBSERVED", "NOT_OBSERVED", "INCONCLUSIVE", "FAIL")

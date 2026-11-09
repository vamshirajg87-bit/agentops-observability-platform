"""
workload-generator/tests/unit/test_shutdown_it.py

Offline tests of the graceful-shutdown validation harness (workload-generator/run_shutdown_it.py).

Nothing here starts Docker, reads the live engine, connects to Kafka or PostgreSQL, or sends a signal:
subprocess calls are replaced by a recording shell, inventories and host readings are synthetic, and
the cases run against a small in-memory simulation of the pipeline.

    T01  Inertness and the command line
    T02  Project names and protected names
    T03  Git states
    T04  Resource gates (fail closed)
    T05  Preflight order: no Docker before the host gates pass, and only reads afterwards
    T06  The override, the Compose commands and the production files
    T07  The test-data contract, checked against the real decoder and canonicalizer
    T08  Parsers of the tools' output
    T09  Offset-versus-durability assertions and replay accounting
    T10  The cases S1 to S4 on the simulation, passing and failing
    T11  The commands the live environment issues
    T12  Cleanup scoping, verification and failure handling
    T13  The whole live flow with every command scripted
"""

from __future__ import annotations

import importlib
import json
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parents[2]
_REPO = _HERE.parent
sys.path.insert(0, str(_HERE))

H = importlib.import_module("run_shutdown_it")
smoke = importlib.import_module("run_smoke")
SmokeFailure = smoke.SmokeFailure

PROJECT = "agentops-shutdown-it-0a1b2c3d"
HEAD = "a" * 40
BRANCH = H.EXPECTED_BRANCH
OWN_STATUS = "\n".join(f"?? {path}" for path in H.OWN_FILES)


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class RecordingShell:
    """Records every command; answers through `router` (default: success, no output)."""

    def __init__(self, router=None):
        self.commands = []
        self.router = router or (lambda command: Result())

    def __call__(self, command, *, timeout, what=""):
        self.commands.append(list(command))
        return self.router(list(command))


def compose_verb(command):
    """The Compose sub-command of a `docker compose ...` command line."""
    index = len(command) - 1 - command[::-1].index("--env-file") + 2 if "--env-file" in command else 2
    return command[index] if index < len(command) else ""


def docker_commands(shell):
    return [c for c in shell.commands if c[:1] == ["docker"]]


READ_ONLY_DOCKER = {"info", "ps", "images", "inspect", "version"}


def only_reads(commands):
    for command in commands:
        if command[:1] != ["docker"]:
            continue
        if command[1] in {"volume", "network"}:
            assert command[2] == "ls", command
        else:
            assert command[1] in READ_ONLY_DOCKER, command


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
    strictly inside the test's own tmp_path is refused with an AssertionError and kept in `refused`, because cleanup
    code may swallow the exception; the fixture fails the test on any refusal."""

    def __init__(self, sandbox: Path) -> None:
        self.sandbox = sandbox.resolve()
        self.calls: list[Path] = []
        self.refused: list[Path] = []

    def __call__(self, path) -> bool:
        resolved = Path(path).resolve()
        if self.sandbox not in resolved.parents:
            self.refused.append(resolved)
            raise AssertionError(f"a test tried to delete {resolved}, which is outside its tmp_path")
        self.calls.append(resolved)
        return True


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """No test may touch the real temp area, the real run state, or the real machine.  Nothing is ever deleted:
    smoke._remove_tree is a fresh RemovalRecorder per test (read the calls from smoke._remove_tree.calls)."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    recorder = RemovalRecorder(tmp_path)
    monkeypatch.setattr(smoke, "_remove_tree", recorder)
    monkeypatch.setattr(smoke, "_OWNED", {})
    saved = {name: getattr(smoke.RUN, name) for name in ("temp", "generated", "env_file", "compose_used",
                                                          "masked_in_logs")}
    yield
    for name, value in saved.items():
        setattr(smoke.RUN, name, value)
    assert recorder.refused == [], f"cleanup asked to delete paths the recorder refused: {recorder.refused}"


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
        assert "PLAN ONLY" in text and "Nothing was read, started or changed" in text
        assert "stop_grace_period 30s" in text and "127.0.0.1 only" in text

    def test_the_plan_names_the_confirmation_phrase_for_a_given_head(self, capsys):
        assert H.main(["--expect-head", HEAD]) == 0
        assert H.confirmation_phrase(HEAD) in capsys.readouterr().out

    @pytest.mark.parametrize("argv", [
        ["--execute", "--expect-head", HEAD],                                   # no confirmation
        ["--execute", "--expect-head", HEAD, "--confirm", "yes"],               # wrong phrase
        ["--execute", "--expect-head", HEAD, "--confirm", H.CONFIRM_PREFIX + "b" * 12],   # another head
        ["--execute", "--confirm", H.CONFIRM_PREFIX + "a" * 12],                # no head
        ["--execute", "--expect-head", "abc123", "--confirm", H.CONFIRM_PREFIX + "abc123"],   # short head
        ["--preflight"],                                                        # no head
        ["--preflight", "--expect-head", "main"],
        ["--cases", "S9"], ["--cases", "S1,S1"], ["--cases", ""],
    ])
    def test_a_refused_invocation_exits_2_and_issues_no_command(self, monkeypatch, argv):
        def forbidden(*args, **kwargs):
            raise AssertionError("a refused invocation must not run anything")
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(smoke, "run", forbidden)
        assert H.main(argv) == 2

    def test_importing_the_module_runs_nothing(self):
        source = (_HERE / "run_shutdown_it.py").read_text(encoding="utf-8")
        assert "if __name__ == \"__main__\":" in source
        assert source.count("sys.exit(main())") == 1

    def test_confirmation_is_bound_to_the_head(self):
        H.check_confirmation(H.confirmation_phrase(HEAD), HEAD)
        with pytest.raises(SmokeFailure):
            H.check_confirmation(H.confirmation_phrase("b" * 40), HEAD)
        with pytest.raises(SmokeFailure):
            H.check_confirmation(None, HEAD)

    def test_case_selection(self):
        assert H.parse_cases("s1, S3") == ["S1", "S3"]
        assert H.parse_cases("s4, S5, s6") == ["S4", "S5", "S6"]
        with pytest.raises(SmokeFailure):
            H.parse_cases("S1,S7")
        assert H.build_parser().parse_args([]).cases == "S1,S2,S3,S4"           # the destructive S5 is never a default


# ---------------------------------------------------------------------------
# T02  Names
# ---------------------------------------------------------------------------

class TestProjectNames:
    def test_names_are_fresh_and_well_formed(self):
        a, b = H.new_project_name(), H.new_project_name()
        assert a != b and a.startswith("agentops-shutdown-it-") and re.fullmatch(r"agentops-shutdown-it-[0-9a-f]{8}", a)
        H.validate_project_name(a, ["abc1234 something-else running"])

    @pytest.mark.parametrize("bad", ["agentops", "agentops-workload-smoke", "agentops-mvp", "agentops-postgres",
                                     "agentops-pipeline-it-0a1b2c3d", "agentops-batching-it-0a1b2c3d",
                                     "agentops-shutdown-it-", "agentops-shutdown-it-ZZZZZZZZ",
                                     "x" + PROJECT, PROJECT + "-2", PROJECT.upper()])
    def test_unacceptable_names_are_rejected(self, bad):
        with pytest.raises(SmokeFailure):
            H.validate_project_name(bad, [])

    def test_a_name_any_docker_object_carries_is_rejected(self):
        for line in (f"deadbeef {PROJECT}-postgres-1 running", f"{PROJECT}_agentops-net", f"{PROJECT}-stream-processor:latest abc"):
            with pytest.raises(SmokeFailure):
                H.validate_project_name(PROJECT, [line])

    def test_protected_names_cover_the_mvp_legacy_and_benchmark_resources(self):
        assert set(H.PROTECTED_CONTAINERS) == {"agentops-mvp-postgres-1", "agentops-mvp-viewer-1",
                                               "agentops-mvp-db-bootstrap-1", "agentops-postgres"}
        assert "agentops-workload-smoke" in H.PROTECTED_TOKENS and "agentops-mvp" in H.PROTECTED_TOKENS

    def test_blockers(self):
        blockers = H.find_blockers(
            benchmark_markers=["ACTIVE_RUN"], own_markers=["CLEANUP_UNVERIFIED"],
            docker_lines=["1 agentops-workload-smoke-kafka-1 running", "2 agentops-pipeline-it-aaaaaaaa-x running",
                          f"3 {PROJECT}-kafka-1 exited", "4 unrelated running"],
            processes=["123"])
        text = "\n".join(blockers)
        for needle in ("benchmark marker ACTIVE_RUN", "unverified cleanup marker", "benchmark Docker object",
                       "pipeline test Docker object", "earlier shutdown validation", "process 123"):
            assert needle in text
        assert "unrelated" not in text
        assert H.find_blockers(benchmark_markers=[], own_markers=[], docker_lines=["4 unrelated running"], processes=[]) == []


# ---------------------------------------------------------------------------
# T03  Git
# ---------------------------------------------------------------------------

class TestGitState:
    def run(self, **kwargs):
        return H.git_state(RecordingShell(git_router(**kwargs)), _REPO, HEAD)

    def test_the_development_state_is_exactly_this_harness_and_its_test(self):
        assert self.run() == "development"

    def test_a_clean_tree_is_the_committed_state(self):
        assert self.run(status="") == "committed"

    @pytest.mark.parametrize("kwargs, needle", [
        ({"branch": "main"}, "the branch is"),
        ({"head": "b" * 40}, "HEAD is"),
        ({"cached": "x.py\n"}, "index is not empty"),
        ({"status": OWN_STATUS + "\n M stream-processor/main.py"}, "neither clean"),
        ({"status": f"?? {H.OWN_FILES[0]}"}, "neither clean"),                         # only one of the two
        ({"status": OWN_STATUS + "\n?? stray.txt"}, "neither clean"),
        ({"status": " M benchmarks/run_benchmark.py"}, "neither clean"),
    ])
    def test_every_other_state_is_rejected(self, kwargs, needle):
        with pytest.raises(SmokeFailure, match=needle):
            self.run(**kwargs)

    def test_a_malformed_expected_head_is_rejected_before_git_is_asked(self):
        shell = RecordingShell(git_router())
        with pytest.raises(SmokeFailure):
            H.git_state(shell, _REPO, "main")
        assert shell.commands == []

    def test_a_failing_git_command_is_a_failure_not_a_pass(self):
        with pytest.raises(SmokeFailure):
            H.git_state(RecordingShell(lambda c: Result(returncode=128)), _REPO, HEAD)


# ---------------------------------------------------------------------------
# T04  Gates
# ---------------------------------------------------------------------------

def good_readings(**changes):
    values = dict(power_source="AC", battery_percent=100, available_mib=6000.0, engine_bytes=4 * 1024 ** 3,
                  free_disk_bytes=50 * 1024 ** 3, ports_in_use={19092: False, 15432: False})
    values.update(changes)
    return H.Readings(**values)


class TestGates:
    def test_good_readings_pass(self):
        assert H.evaluate_gates(good_readings()) == []

    @pytest.mark.parametrize("changes, needle", [
        ({"power_source": "battery"}, "not AC power"),
        ({"power_source": None}, "power source could not be read"),
        ({"available_mib": 4095.0}, "below 4096 MiB"),
        ({"available_mib": None}, "memory could not be read"),
        ({"available_mib": float("nan")}, "memory could not be read"),
        ({"engine_bytes": 3 * 1024 ** 3}, "Docker engine memory"),
        ({"engine_bytes": None}, "Docker engine memory could not be read"),
        ({"free_disk_bytes": 9 * 1024 ** 3}, "below 10 GiB"),
        ({"free_disk_bytes": None}, "free disk space could not be read"),
        ({"ports_in_use": {19092: True, 15432: False}}, "port 19092 is in use"),
        ({"ports_in_use": {19092: False, 15432: None}}, "port 15432 could not be checked"),
        ({"ports_in_use": {}}, "could not be checked"),
    ])
    def test_every_unmet_or_unmeasurable_gate_fails_closed(self, changes, needle):
        assert any(needle in problem for problem in H.evaluate_gates(good_readings(**changes)))

    def test_boundaries(self):
        assert H.evaluate_gates(good_readings(available_mib=4096)) == []
        assert H.evaluate_gates(good_readings(engine_bytes=H.MIN_ENGINE_BYTES)) == []
        assert H.evaluate_gates(good_readings(free_disk_bytes=10 * 1024 ** 3)) == []

    def test_the_thresholds_are_the_authorized_ones(self):
        assert H.MIN_HOST_MEMORY_MIB == 4096 and H.MIN_ENGINE_BYTES == 3584 * 1024 ** 2 and H.MIN_DISK_GIB == 10
        assert H.PORTS == (19092, 15432)


# ---------------------------------------------------------------------------
# T05  Preflight
# ---------------------------------------------------------------------------

INVENTORY = {"containers": ["id1 agentops-postgres exited", "id2 agentops-mvp-viewer-1 running"],
             "volumes": ["agentops-mvp-postgres-data"], "networks": ["n1 bridge"], "images": ["python:3.13 i1"]}
SNAPSHOT = {"agentops-mvp-postgres-1": "i running s f 0", "agentops-mvp-viewer-1": "i running s f 0",
            "agentops-mvp-db-bootstrap-1": None, "agentops-postgres": "i exited s f 0"}


def preflight(shell=None, **overrides):
    shell = shell or RecordingShell(git_router())
    options = dict(docker_data_dir=_HERE, power=lambda: ("AC", 100), memory=lambda: 8000.0,
                   disk=lambda p: 60 * 1024 ** 3, port_probe=lambda p: False, markers=lambda: [],
                   processes=lambda: [], own=lambda: [], inventory=lambda: dict(INVENTORY),
                   snapshot=lambda: dict(SNAPSHOT), name=PROJECT)
    options.update(overrides)
    return shell, lambda: H.run_preflight(shell, _REPO, HEAD, **options)


def info_router(engine=4 * 1024 ** 3):
    def route(command):
        if command[:2] == ["docker", "info"]:
            return Result(stdout=json.dumps({"MemTotal": engine}))
        return git_router()(command)
    return route


class TestPreflightOrder:
    def test_success_returns_the_candidate_project_and_the_before_state(self):
        shell, call = preflight(RecordingShell(info_router()))
        pre = call()
        assert pre.project == PROJECT and pre.git_state == "development" and pre.before == INVENTORY
        only_reads(shell.commands)

    @pytest.mark.parametrize("case", ["git", "power", "memory", "disk", "port", "benchmark", "own-marker", "process"])
    def test_no_docker_command_is_issued_when_a_non_docker_check_fails(self, case):
        shell = RecordingShell(info_router())
        overrides = {
            "git": {}, "power": {"power": lambda: ("battery", 50)}, "memory": {"memory": lambda: 1000.0},
            "disk": {"disk": lambda p: 1}, "port": {"port_probe": lambda p: True},
            "benchmark": {"markers": lambda: ["ACTIVE_RUN"]}, "own-marker": {"own": lambda: ["CLEANUP_UNVERIFIED"]},
            "process": {"processes": lambda: ["99"]}}[case]
        if case == "git":
            shell = RecordingShell(git_router(branch="main"))
        shell, call = preflight(shell, **overrides)
        with pytest.raises(SmokeFailure):
            call()
        assert docker_commands(shell) == [], "Docker must not be touched before the host gates pass"

    def test_unmeasurable_host_readings_fail_closed_without_docker(self):
        def boom():
            raise OSError("cannot read")
        for override in ({"power": boom}, {"memory": boom}, {"disk": lambda p: (_ for _ in ()).throw(OSError("x"))}):
            shell, call = preflight(RecordingShell(info_router()), **override)
            with pytest.raises(SmokeFailure):
                call()
            assert docker_commands(shell) == []

    def test_a_missing_docker_data_directory_fails_closed(self, tmp_path):
        shell, call = preflight(RecordingShell(info_router()), docker_data_dir=tmp_path / "absent")
        with pytest.raises(SmokeFailure, match="free disk space could not be read"):
            call()
        assert docker_commands(shell) == []
        shell, call = preflight(RecordingShell(info_router()), docker_data_dir=None)
        with pytest.raises(SmokeFailure):
            call()

    def test_engine_memory_failure_issues_only_the_info_read(self):
        shell, call = preflight(RecordingShell(info_router(engine=2 * 1024 ** 3)))
        with pytest.raises(SmokeFailure, match="Docker engine memory"):
            call()
        assert [c[:2] for c in docker_commands(shell)] == [["docker", "info"]]

    def test_docker_object_blockers_and_a_running_legacy_database_stop_the_run(self):
        shell, call = preflight(RecordingShell(info_router()),
                                inventory=lambda: {**INVENTORY, "containers": ["i agentops-workload-smoke-kafka-1 running"]})
        with pytest.raises(SmokeFailure, match="benchmark Docker object"):
            call()
        only_reads(shell.commands)
        shell, call = preflight(RecordingShell(info_router()), snapshot=lambda: {**SNAPSHOT, "agentops-postgres": "i running s f 0"})
        with pytest.raises(SmokeFailure, match="not exited"):
            call()

    def test_a_pre_existing_project_resource_is_ambiguous_and_rejected(self):
        shell, call = preflight(RecordingShell(info_router()),
                                inventory=lambda: {**INVENTORY, "volumes": [f"{PROJECT}_kafka-data"]})
        with pytest.raises(SmokeFailure, match="earlier shutdown validation|already exist"):
            call()

    def test_the_default_inventory_and_snapshot_issue_only_reads(self):
        def route(command):
            if command[:2] == ["docker", "info"]:
                return Result(stdout=json.dumps({"MemTotal": 4 * 1024 ** 3}))
            if command[:2] == ["docker", "inspect"]:
                return Result(returncode=1)
            if command[:1] == ["docker"]:
                return Result(stdout="")
            return git_router()(command)
        shell = RecordingShell(route)
        _, call = preflight(shell, inventory=None, snapshot=None)
        call()
        only_reads(shell.commands)
        assert sum(1 for c in shell.commands if c[:2] == ["docker", "inspect"]) == 4


# ---------------------------------------------------------------------------
# T06  Override and commands
# ---------------------------------------------------------------------------

class TestOverrideAndCommands:
    def test_the_override_sets_the_grace_period_and_groups_on_both_services_only(self):
        text = H.test_override_text(PROJECT)
        assert text.count("stop_grace_period: 30s") == 2
        stream, storage = H.group_ids(PROJECT)
        assert f'CONSUMER_GROUP_ID: "{stream}"' in text and f'CONSUMER_GROUP_ID: "{storage}"' in text
        assert stream != storage and stream.startswith(PROJECT) and storage.startswith(PROJECT)
        for forbidden in ("ports:", "container_name:", "volumes:", "network_mode", "privileged", "image:", "init:", "stop_signal"):
            assert forbidden not in text
        assert "CONSUMER_COMMIT_BATCH_MESSAGES" not in text
        assert not {stream, storage} & {"agentops-stream-processor", "agentops-storage-consumer"}

    def test_the_batching_variant_sets_the_documented_variables(self):
        text = H.test_override_text(PROJECT, batching_messages=50)
        assert 'CONSUMER_COMMIT_BATCH_MESSAGES: "50"' in text and 'CONSUMER_COMMIT_INTERVAL_SECONDS: "30"' in text
        assert text.count("stop_grace_period: 30s") == 2

    def test_the_override_is_valid_yaml_when_a_parser_is_available(self):
        yaml = pytest.importorskip("yaml")
        for batching in (None, 50):
            document = yaml.safe_load(H.test_override_text(PROJECT, batching_messages=batching))
            for service in H.APP_SERVICES:
                assert document["services"][service]["stop_grace_period"] == "30s"

    def test_compose_commands_name_the_project_four_files_and_the_env_file(self, tmp_path):
        command = H.compose_command(PROJECT, tmp_path / "o.yml", tmp_path / "e.env", "stop", "stream-processor")
        assert command[:5] == ["docker", "compose", "-p", PROJECT, "-f"]
        files = [command[i + 1] for i, token in enumerate(command) if token == "-f"]
        assert files == ["docker-compose.yml", "workload-generator/compose.smoke.override.yml",
                         "docker/compose.pipeline.yml", str(tmp_path / "o.yml")]
        assert command[-4:-2] == ["--env-file", str(tmp_path / "e.env")] and command[-2:] == ["stop", "stream-processor"]

    @pytest.mark.parametrize("bad", ["agentops", "agentops-workload-smoke", "", "agentops-shutdown-it-xyz"])
    def test_compose_refuses_any_other_project(self, bad, tmp_path):
        with pytest.raises(SmokeFailure):
            H.compose_command(bad, tmp_path / "o.yml", tmp_path / "e.env", "up")

    def test_production_compose_files_are_not_changed_by_the_design(self):
        # the grace period reaches the services only through the temporary override
        for name in ("docker/compose.pipeline.yml", "docker-compose.yml", "workload-generator/compose.smoke.override.yml"):
            assert "stop_grace_period" not in (_REPO / name).read_text(encoding="utf-8"), name
        assert H.OVERLAY_FILE == "docker/compose.pipeline.yml"

    def test_credentials_are_random_and_cover_every_required_variable(self):
        first, second = H.generate_credentials(), H.generate_credentials()
        assert set(first) == set(smoke.PASSWORD_VARIABLES) and first != second
        assert all(len(v) >= 24 for v in first.values()) and len(set(first.values())) == len(first)
        text = H.env_file_text(first)
        assert all(f"{name}={value}\n" in text for name, value in first.items())


# ---------------------------------------------------------------------------
# T07  The test-data contract
# ---------------------------------------------------------------------------

def _load_pipeline_modules():
    """The real decoder and canonicalizer, loaded under private names so the stream-processor's flat
    modules cannot collide with anything else in the session."""
    pytest.importorskip("opentelemetry.proto.collector.trace.v1.trace_service_pb2")
    pytest.importorskip("pydantic")
    import importlib.util
    sys.path.insert(0, str(_REPO / "demo-app"))
    try:
        loaded = {}
        for name in ("otlp_decoder", "canonicalizer"):
            spec = importlib.util.spec_from_file_location(f"_shutdown_it_{name}", _REPO / "stream-processor" / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded[name] = module
        return loaded
    finally:
        sys.path.remove(str(_REPO / "demo-app"))


class FakeProducer:
    sent = []

    def __init__(self, config):
        self.config = config

    def produce(self, topic, key=None, value=None, on_delivery=None):
        FakeProducer.sent.append((topic, key, value))
        message = types.SimpleNamespace(key=lambda: key, partition=lambda: len(FakeProducer.sent) % 3,
                                        offset=lambda: len(FakeProducer.sent))
        on_delivery(None, message)

    def poll(self, timeout=0):
        return 0

    def flush(self, timeout=None):
        return 0


class TestTestDataContract:
    def test_identifiers_are_deterministic_valid_and_distinct(self):
        spans = H.expected_spans(1, 50, 3)
        assert len(spans) == 150
        assert all(re.fullmatch(r"[0-9a-f]{32}", t) and re.fullmatch(r"[0-9a-f]{16}", s) for t, s in spans)
        assert H.expected_spans(1, 50, 3) == spans and H.expected_spans(2, 50, 3).isdisjoint(spans)
        assert not any(set(t) == {"0"} or set(s) == {"0"} for t, s in spans)        # OTLP rejects all-zero ids
        assert len({t for t, _ in spans}) == 50 and len({s for _, s in spans}) == 150

    def test_the_cases_use_distinct_batches(self):
        assert sorted(H.CASE_BATCH.values()) == [1, 2, 3, 4, 5]

    def test_the_producer_script_embeds_the_one_id_definition_and_the_contract(self):
        compile(H.PRODUCER_SOURCE, "<producer>", "exec")
        assert H.IDS_SOURCE in H.PRODUCER_SOURCE
        assert H.SOURCE_TOPIC == "agentops.telemetry.otlp.traces" and H.SOURCE_TOPIC in H.PRODUCER_SOURCE
        assert H.BROKER in H.PRODUCER_SOURCE and "key=trace" in H.PRODUCER_SOURCE
        assert "SerializeToString()" in H.PRODUCER_SOURCE

    def test_what_the_producer_sends_decodes_and_canonicalizes_to_exactly_the_expected_spans(self, monkeypatch):
        modules = _load_pipeline_modules()
        FakeProducer.sent = []
        fake = types.ModuleType("confluent_kafka")
        fake.Producer = FakeProducer
        monkeypatch.setitem(sys.modules, "confluent_kafka", fake)
        monkeypatch.setattr(sys, "argv", ["producer", "2", "7", "3"])
        buffer = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: buffer.append(" ".join(map(str, a))))
        with pytest.raises(SystemExit) as stopped:
            exec(compile(H.PRODUCER_SOURCE, "<producer>", "exec"), {"__name__": "__producer__"})
        assert stopped.value.code == 0 and len(FakeProducer.sent) == 7

        seen = set()
        for topic, key, value in FakeProducer.sent:
            assert topic == H.SOURCE_TOPIC and isinstance(key, bytes) and len(key) == 16
            spans = modules["otlp_decoder"].decode(value)                  # the real decoder: raw bytes are consumable
            assert len(spans) == 3
            for span in spans:
                event = modules["canonicalizer"].canonicalize(span)       # the real canonicalizer accepts them
                assert event.trace_id == key.hex()
                seen.add((event.trace_id, event.span_id))
        assert seen == H.expected_spans(2, 7, 3)

        produced = H.parse_producer_output("\n".join(buffer), 2, 7, 3)
        assert set(produced.acks) == set(range(7)) and produced.expected() == seen

    def test_source_messages_map_to_canonical_records_and_rows(self):
        produced = H.Produced(1, 2, 3, {0: (0, 10), 1: (1, 4)})
        assert produced.message_spans(1) == {(H.trace_hex(1, 1), H.span_hex(1, k)) for k in range(3)}
        assert produced.expected() == produced.message_spans(0) | produced.message_spans(1)

    def test_the_producer_output_is_checked_closed(self):
        good = json.dumps({"acks": {"0": [0, 5], "1": [1, 6]}, "errors": [], "unflushed": 0})
        assert H.parse_producer_output("noise\n" + good, 1, 2, 3).acks == {0: (0, 5), 1: (1, 6)}
        for bad in ("", "not json", json.dumps({"acks": {"0": [0, 1]}, "errors": [], "unflushed": 0}),
                    json.dumps({"acks": {"0": [0, 5], "1": [1, 6]}, "errors": ["x"], "unflushed": 0}),
                    json.dumps({"acks": {"0": [0, 5], "1": [1, 6]}, "errors": [], "unflushed": 2})):
            with pytest.raises(SmokeFailure):
                H.parse_producer_output(bad, 1, 2, 3)


# ---------------------------------------------------------------------------
# T08  Parsers
# ---------------------------------------------------------------------------

GROUP_TEXT = """
GROUP  TOPIC  PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG  CONSUMER-ID  HOST  CLIENT-ID
g1  agentops.telemetry.spans  0  10  12  2  c1  /h  cl
g1  agentops.telemetry.spans  1  -  4  -  -  -  -
g1  agentops.telemetry.spans  2  7  7  0  c1  /h  cl
g1  other.topic  0  1  1  0  c1  /h  cl
"""


class TestParsers:
    def test_group_offsets(self):
        parsed = H.parse_group_offsets(GROUP_TEXT, "g1", "agentops.telemetry.spans")
        assert parsed == {0: H.GroupPartition(10, 12), 1: H.GroupPartition(None, 4), 2: H.GroupPartition(7, 7)}
        assert H.committed_total(parsed) == 17 and H.log_end_total(parsed) == 23
        assert H.committed_offsets(parsed) == {0: 10, 1: None, 2: 7}

    @pytest.mark.parametrize("text", ["", "Consumer group 'g1' does not exist.", GROUP_TEXT.replace("g1  agentops.telemetry.spans  2  7  7  0  c1  /h  cl\n", ""),
                                      GROUP_TEXT.replace("  10  12", "  x  12")])
    def test_an_incomplete_or_malformed_description_is_none(self, text):
        assert H.parse_group_offsets(text, "g1", "agentops.telemetry.spans") is None

    def test_canonical_records(self):
        body = json.dumps({"trace_id": "t" * 32, "span_id": "s" * 16, "x": 1})
        records = H.parse_canonical_records(f"Partition:1\tOffset:5\t{body}\n\nProcessed a total of 1 messages\n")
        assert records == [H.Canonical(1, 5, "t" * 32, "s" * 16)]

    @pytest.mark.parametrize("text", ["garbage line", "Partition:1\tOffset:5\t{not json}", "Partition:1\tOffset:5\t{\"a\": 1}"])
    def test_an_unrecognized_canonical_line_is_an_error_not_a_guess(self, text):
        with pytest.raises(SmokeFailure):
            H.parse_canonical_records(text)

    def test_rows(self):
        assert H.parse_rows("t|s|1|9\n\nt2|s2|0|3\n") == [H.Row("t", "s", 1, 9), H.Row("t2", "s2", 0, 3)]
        for bad in ("t|s|1", "t|s|x|9"):
            with pytest.raises(SmokeFailure):
                H.parse_rows(bad)

    def test_inspect(self):
        assert H.parse_inspect("exited|0|0|false\n") == H.Inspect("exited", 0, 0, False)
        assert H.parse_inspect("exited|137|2|true").oom_killed is True
        for bad in ("", "exited|0|0", "exited|x|0|false"):
            with pytest.raises(SmokeFailure):
                H.parse_inspect(bad)

    def test_diagnostic_counts(self):
        logs = ("storage consumer: SIGTERM received; finishing the current message, then shutting down. Send it again to stop immediately.\n"
                "agentops storage consumer stopped (shutdown requested).\nstarting\n")
        assert H.diagnostic_counts(logs) == (1, 1) and H.diagnostic_counts("nothing") == (0, 0)


# ---------------------------------------------------------------------------
# T09  Assertions
# ---------------------------------------------------------------------------

def canon(batch, index, k, partition, offset):
    return H.Canonical(partition, offset, H.trace_hex(batch, index), H.span_hex(index, k))


class TestAssertions:
    batch = H.Produced(1, 3, 2, {0: (0, 0), 1: (0, 1), 2: (1, 0)})

    def full(self, index, partition=0, base=0):
        return [canon(1, index, k, partition, base + k) for k in range(2)]

    def test_source_commit_is_safe_when_every_committed_message_is_fully_published(self):
        canonical = self.full(0) + self.full(1, base=2)
        assert H.source_commit_problems(self.batch, {0: 2, 1: 0, 2: None}, canonical) == []

    def test_source_commit_past_an_unpublished_message_is_reported(self):
        problems = H.source_commit_problems(self.batch, {0: 2, 1: 0, 2: None}, self.full(0))
        assert len(problems) == 1 and "message 1" in problems[0] and "partition 0" in problems[0]

    def test_a_partially_published_committed_message_is_reported(self):
        problems = H.source_commit_problems(self.batch, {0: 1}, self.full(0)[:1])
        assert problems and "1 span(s)" in problems[0]

    def test_uncommitted_messages_may_be_missing(self):
        assert H.source_commit_problems(self.batch, {0: 0, 1: None, 2: 0}, []) == []

    def test_storage_commit_past_an_unpersisted_span_is_reported(self):
        canonical = self.full(0) + self.full(1, base=2)
        rows = [H.Row(r.trace, r.span, r.partition, r.offset) for r in canonical[:3]]
        assert H.storage_commit_problems(canonical, {0: 3}, rows) == []
        assert len(H.storage_commit_problems(canonical, {0: 4}, rows)) == 1
        assert H.storage_commit_problems(canonical, {0: None}, []) == []

    def test_replay_is_told_apart_from_loss(self):
        expected = H.Produced(1, 2, 2, {}).expected()
        records = [canon(1, 0, 0, 0, 0), canon(1, 0, 1, 0, 1), canon(1, 1, 0, 0, 2), canon(1, 0, 0, 0, 3)]
        accounting = H.account_canonical(expected, records)
        assert (accounting.missing, accounting.unexpected, accounting.duplicate_copies) == (1, 0, 1)
        assert accounting.detail and "missing" in accounting.detail[0]
        extra = H.account_canonical(expected, [*records, canon(9, 0, 0, 0, 9)])
        assert extra.unexpected == 1

    def test_rows_must_be_exactly_the_expected_set_each_once(self):
        expected = {("t1", "s1"), ("t1", "s2")}
        assert H.account_rows(expected, [H.Row("t1", "s1", 0, 0), H.Row("t1", "s2", 0, 1)]) == H.Accounting(0, 0, 0, ())
        acc = H.account_rows(expected, [H.Row("t1", "s1", 0, 0), H.Row("t1", "s1", 0, 5), H.Row("tx", "sx", 0, 2)])
        assert (acc.missing, acc.unexpected, acc.duplicate_copies) == (1, 1, 1)

    def test_window_states(self):
        assert [H.window_state(p, (0.1, 0.7)) for p in (0.0, 0.1, 0.5, 0.7, 0.71, 1.0)] == [
            "before", "inside", "inside", "inside", "after", "after"]

    def test_overall_verdict_semantics(self):
        ok = H.Case("S1", "PASS")
        assert H.overall_verdict([ok], cleanup_verified=True, selected=["S1"]) == "PASS"
        assert H.overall_verdict([ok], cleanup_verified=False, selected=["S1"]) == "FAIL"
        assert H.overall_verdict([ok, H.Case("S2", "FAIL")], cleanup_verified=True, selected=["S1", "S2"]) == "FAIL"
        assert H.overall_verdict([ok, H.Case("S2", "INCONCLUSIVE")], cleanup_verified=True, selected=["S1", "S2"]) == "HOLD"
        assert H.overall_verdict([ok], cleanup_verified=True, selected=["S1", "S2"]) == "HOLD"        # S2 never ran
        assert H.overall_verdict([], cleanup_verified=True, selected=["S1"]) == "HOLD"


# ---------------------------------------------------------------------------
# T10  The cases, on an in-memory simulation of the pipeline
# ---------------------------------------------------------------------------

class SimEnv(H.Env):
    """Three partitions, a stream processor and a storage consumer that make progress on every sleep()."""

    def __init__(self, **faults):
        self.stream_group, self.storage_group = H.group_ids(PROJECT)
        self.faults = faults
        self.produced = []
        self.running = {s: True for s in H.APP_SERVICES}
        self.exit = {s: 0 for s in H.APP_SERVICES}
        self.restarts = {s: 0 for s in H.APP_SERVICES}
        self.logs_text = {s: "starting\n" for s in H.APP_SERVICES}
        self.now = 0.0
        self.src_end, self.src_committed = [0, 0, 0], [0, 0, 0]
        self.can_end, self.can_committed = [0, 0, 0], [0, 0, 0]
        self.sp_queue, self.st_pos = [], 0
        self.canonical_list, self.row_list = [], []
        self.pending_sp = self.pending_st = None
        self.batching = None
        self.unflushed = []
        self.stops = 0
        self.batching_history = []
        self.st_msgs = self.st_commits = 0              # the storage consumer process's own counters
        self.st_inserted = self.st_conflicts = 0
        self.row_ids = set()
        self.project, self.protected_ids = PROJECT, frozenset()
        self.no_restart, self.killed, self.replaying, self.kills = False, False, False, 0
        self.cid = ("c" * 63) + "1"
        self.cids = {"storage-consumer": self.cid, "stream-processor": ("b" * 63) + "2",
                     "kafka": ("a" * 63) + "3", "postgres": ("9" * 63) + "4"}
        self.sp_cur, self.sp_log, self.stream_killed = None, [], False
        self.kill_log = []
        self.calls = []                                                 # (method, argument) of the calls S6 cares about
        self.stream_no_restart, self.storage_timing, self.override_history = False, False, []

    # -- progress ----------------------------------------------------------------------
    def _sp_step(self):
        if self.faults.get("sp_per_span"):                               # one acknowledged span per step, like the real loop
            if self.sp_cur is None:
                if not self.sp_queue:
                    return
                self.sp_cur = [self.sp_queue.pop(0), 0]
            message, k = self.sp_cur
            self._publish_span(message, k)
            self.sp_cur[1] += 1
            if self.faults.get("sp_commit_after_first") and self.sp_cur[1] == 1:
                self.src_committed[message[2]] = message[3] + 1          # a defect: committed before the last span
            if self.sp_cur[1] >= message[4]:
                self.src_committed[message[2]] = message[3] + 1          # committed only after the last span
                self.sp_cur = None
            return
        if self.pending_sp is not None:                                  # publishes what it committed too early
            self._publish(self.pending_sp)
            self.pending_sp = None
        if not self.sp_queue:
            return
        message = self.sp_queue.pop(0)
        partition, offset = message[2], message[3]
        if self.faults.get("sp_commit_early"):
            self.src_committed[partition] = offset + 1
            self.pending_sp = message
        else:
            self._publish(message)
            self.src_committed[partition] = offset + 1

    def _publish(self, message):
        for k in range(message[4]):
            self._publish_span(message, k)

    def _publish_span(self, message, k):
        batch, index = message[0], message[1]
        self.canonical_list.append(H.Canonical(index % 3, self.can_end[index % 3], H.trace_hex(batch, index), H.span_hex(index, k)))
        self.can_end[index % 3] += 1

    def _st_step(self):
        if self.pending_st is not None:
            self._persist(self.pending_st)
            self.pending_st = None
        if self.st_pos >= len(self.canonical_list):
            return
        while self.replaying and self.st_pos < len(self.canonical_list) and \
                self.canonical_list[self.st_pos].offset < self.can_committed[self.canonical_list[self.st_pos].partition]:
            self.st_pos += 1                                            # below the committed offset: never redelivered
        if self.st_pos >= len(self.canonical_list):
            return
        record = self.canonical_list[self.st_pos]
        self.st_pos += 1
        if self.faults.get("st_commit_early"):
            self.can_committed[record.partition] = record.offset + 1
            self.pending_st = record
            return
        self._persist(record)

    def _persist(self, record):
        self.st_msgs += 1
        wrong = 1 if self.faults.get("row_offset_wrong") else 0
        if (record.trace, record.span) in self.row_ids:
            self.st_conflicts += 1                                      # ON CONFLICT DO NOTHING: a replay
        else:
            self.row_ids.add((record.trace, record.span))
            self.st_inserted += 1
            self.row_list.append(H.Row(record.trace, record.span, record.partition, record.offset + wrong))
        if self.batching and not self.faults.get("per_message_commit"):
            self.unflushed.append(record)
            if len(self.unflushed) >= self.batching:
                self._flush()
        else:
            self.st_commits += 1
            self.can_committed[record.partition] = record.offset + 1

    def _flush(self):
        if self.unflushed:
            self.st_commits += 1
        for record in self.unflushed:
            self.can_committed[record.partition] = max(self.can_committed[record.partition], record.offset + 1)
        self.unflushed = []

    def _advance(self):
        rate = 1000 if self.faults.get("instant") else self.faults.get("rate", 4)
        for _ in range(rate):
            if self.running["stream-processor"]:
                self._sp_step()
            if self.running["storage-consumer"]:
                self._st_step()

    # -- the Env interface ---------------------------------------------------------------
    def sleep(self, seconds):
        self.now += seconds
        self._advance()

    def clock(self):
        return self.now

    def produce(self, batch, count, spans):
        self.calls.append(("produce", count))
        acks = {}
        for index in range(count):
            partition = index % 3
            acks[index] = (partition, self.src_end[partition])
            self.sp_queue.append((batch, index, partition, self.src_end[partition], spans))
            self.sp_log.append(self.sp_queue[-1])
            self.src_end[partition] += 1
        produced = H.Produced(batch, count, spans, acks)
        self.produced.append(produced)
        return produced

    def group(self, group, topic):
        self.calls.append(("group", topic))
        if topic == H.SOURCE_TOPIC:
            return {p: H.GroupPartition(self.src_committed[p], self.src_end[p]) for p in range(3)}
        return {p: H.GroupPartition(self.can_committed[p], self.can_end[p]) for p in range(3)}

    def group_after_stop(self, group, topic, service):
        if self.running[service]:
            raise H.PostStopError(f"{service} is not stopped")
        hook = self.faults.get("post_stop")
        if hook is not None:
            answer = hook(self, group, topic, service)
            if answer is not None:
                return answer
        groups = SimEnv.group(self, group, topic)
        commits = {p: H.PartitionCommit("committed", row.current, 0, row.log_end) for p, row in groups.items()}
        return H.PostStopOffsets(groups, commits, {"agreement": "agreed"})

    def canonical(self):
        return list(self.canonical_list)

    def rows(self):
        return list(self.row_list)

    def wait_drained(self, group, topic, timeout):
        service = "stream-processor" if topic == H.SOURCE_TOPIC else "storage-consumer"
        if not self.running[service]:
            return False
        for _ in range(100000):
            if topic == H.SOURCE_TOPIC and not self.sp_queue and self.pending_sp is None and self.sp_cur is None:
                return True
            if topic == H.CANONICAL_TOPIC and self.st_pos >= len(self.canonical_list) and self.pending_st is None:
                if self.batching:
                    self._flush()
                return True
            self._advance()
        return False

    def set_storage_batching(self, messages, *, no_restart=False):
        self.batching_history.append(messages)
        self.batching = messages
        self.no_restart = no_restart

    def write_override(self, *, batching_messages=None, no_restart=False, stream_no_restart=False, storage_timing=False):
        self.override_history.append({"batching_messages": batching_messages, "no_restart": no_restart,
                                      "stream_no_restart": stream_no_restart, "storage_timing": storage_timing})
        self.batching, self.no_restart = batching_messages, no_restart
        self.stream_no_restart, self.storage_timing = stream_no_restart, storage_timing

    def restart_policy(self, service):
        if self.faults.get("policy_error"):
            raise H.SmokeFailure("docker inspect failed")
        no = self.stream_no_restart if service == "stream-processor" else self.no_restart
        return "no" if no and not self.faults.get("policy_wrong") else "unless-stopped"

    def container_id(self, service):
        self.calls.append(("container_id", service))
        if self.faults.get("container_id_error"):
            raise H.SmokeFailure("compose ps failed")
        return self.cids[service]

    def recheck_containers(self, ids):
        """One inspect of full ids: the facts come from the state the simulation is in NOW (a test may change the
        state, or the answer, through the `recheck_hook` fault)."""
        self.calls.append(("recheck_containers", tuple(ids)))
        if self.faults.get("recheck_error"):
            raise H.SmokeFailure("docker inspect failed")
        by_id = {cid: service for service, cid in self.cids.items()}
        facts = {}
        for one in ids:
            service = by_id[one]
            if service in ("kafka", "postgres"):
                status = "exited" if self.faults.get("others_down") == service else "running"
                policy = "always"
            else:
                status = "running" if self.running[service] else "exited"
                policy = self.restart_policy(service)
            facts[one] = H.ContainerFacts(one, PROJECT, service, f"/{PROJECT}-{service}-1", status, policy)
        hook = self.faults.get("recheck_hook")
        if hook is not None:
            facts = hook(self, facts) or facts
        return facts

    def kill_target(self, service):
        self.calls.append(("kill_target", service))
        faults = self.faults
        cid = self.cids[service]
        other = "stream-processor" if service == "storage-consumer" else "storage-consumer"
        return H.KillTarget(cid, ("d" * 64) if faults.get("kill_id_mismatch") else cid,
                            "agentops" if faults.get("kill_wrong_project") else PROJECT,
                            other if faults.get("kill_wrong_service") else service,
                            "/agentops-mvp-postgres-1" if faults.get("kill_protected_name") else f"/{PROJECT}-{service}-1",
                            "running" if self.running[service] else "exited", self.restart_policy(service))

    def kill(self, service, container_id, case="S5"):
        self.calls.append(("kill", service))
        self.kill_log.append((service, case))
        self.kills += 1
        if H.KILL_TARGETS.get(case) != service:
            raise H.SmokeFailure(f"refusing to kill {service!r} for case {case!r}")
        assert container_id == self.cids[service]
        if self.faults.get("kill_rc"):
            return H.KillResult(self.faults["kill_rc"], 0.2)
        if self.faults.get("kill_miss"):
            return H.KillResult(0, 0.2)                                 # reports success, kills nothing
        self.running[service] = False
        self.exit[service] = self.faults.get("kill_exit_code", 137)
        if service == "stream-processor":
            self.stream_killed = True                                   # published spans stay, the offset does not move
        else:
            self.killed = True
            self.unflushed = []                                         # durable, never committed
        if self.faults.get("kill_graceful"):
            self.logs_text[service] += (f"x: SIGTERM {H.FIRST_SIGNAL_MARKER}.\nagentops {H.GRACEFUL_MARKER}.\n")
        if self.faults.get("kill_final_summary"):
            self.logs_text[service] += self.timing_line()
        return H.KillResult(0, 0.2)

    def termination_facts(self, service):
        faults = self.faults
        return H.TerminationFacts(("e" * 64) if faults.get("kill_new_container") else self.cids[service],
                                  "running" if self.running[service] else "exited", self.exit[service],
                                  bool(faults.get("kill_oom")), faults.get("kill_restarts", 0), "", "2026-10-18T00:00:00Z")

    def inspect(self, service):
        self.calls.append(("inspect", service))
        if service in ("kafka", "postgres"):
            return H.Inspect("exited" if self.faults.get("others_down") == service else "running", 0, 0, False)
        return H.Inspect("running" if self.running[service] else "exited", self.exit[service], self.restarts[service], False)

    def logs(self, service):
        self.calls.append(("logs", service))
        return self.logs_text[service]

    def start(self, service):
        self.running[service] = True
        if service == "stream-processor" and self.stream_killed:       # a fresh process: empty deduplicator, committed offsets
            self.stream_killed, self.sp_cur = False, None
            self.sp_queue = [m for m in self.sp_log if m[3] >= self.src_committed[m[2]]]
            if self.faults.get("restart_skips"):                        # a defect: the interrupted message is skipped
                self.sp_queue = [m for m in self.sp_queue if m[3] > self.src_committed[m[2]]]
            if self.faults.get("restart_double_head") and self.sp_queue:  # a defect: one message is published twice
                self.sp_queue = [self.sp_queue[0]] + self.sp_queue
        if service == "storage-consumer":
            self.st_msgs = self.st_commits = 0
            self.st_inserted = self.st_conflicts = 0
            if self.killed:                                             # a fresh process resumes at the committed offsets
                self.killed, self.replaying, self.st_pos = False, True, 0
        if service == "storage-consumer" and self.batching and not self.faults.get("no_startup_line"):
            shown = self.faults.get("startup_numbers", (self.batching, 30))
            self.logs_text[service] += f"  commit     : batches of up to {shown[0]} messages, about every {shown[1]} s\n"

    def timing_line(self):
        if self.faults.get("timing_garbage"):
            return H.TIMING_LINE_PREFIX + "{not json\n"
        messages, commits = self.st_msgs, self.st_commits
        override = self.faults.get("timing_override", {})
        payload = {"kind": "final", "elapsed_s": 1.0,
                   "counters": {"messages": override.get("messages", messages), "idle_polls": 0,
                                "inserted": override.get("inserted", self.st_inserted),
                                "conflicts": override.get("conflicts", self.st_conflicts)},
                   "stages": {"kafka_commit": {"count": override.get("commits", commits)}}}
        text = H.TIMING_LINE_PREFIX + json.dumps(payload) + "\n"
        return text * self.faults.get("timing_copies", 1)

    def timing_text(self, service):
        return "".join(line + "\n" for line in self.logs_text[service].splitlines() if line.startswith(H.TIMING_LINE_PREFIX))

    def container_env(self, service, names):
        self.env_reads = getattr(self, "env_reads", 0) + 1
        if self.faults.get("env_read_error"):
            raise H.SmokeFailure("docker inspect failed")
        values = self.faults.get("env_values")
        if values is None and service == "stream-processor":
            values = {"CONSUMER_GROUP_ID": self.faults.get("stream_group_env", self.stream_group)}
        if values is None:
            values = ({H.BATCH_ENV_NAME: str(self.batching), H.INTERVAL_ENV_NAME: H.BATCH_INTERVAL_SECONDS,
                       H.TIMING_ENV_NAME: H.TIMING_INTERVAL_SECONDS} if self.batching else
                      ({H.TIMING_ENV_NAME: H.TIMING_INTERVAL_SECONDS} if self.storage_timing else {}))
        return {name: values.get(name) for name in names}

    def wait_running(self, service):
        assert self.running[service], f"{service} should be running"

    def stop(self, services):
        self.stops += 1
        for service in services:
            if not self.running[service]:
                continue
            self.running[service] = False
            self.exit[service] = self.faults.get("exit_code", 0)
            if service == "stream-processor":
                self.pending_sp = None if self.faults.get("sp_commit_early") else self.pending_sp
            if service == "storage-consumer":
                self.pending_st = None if self.faults.get("st_commit_early") else self.pending_st
                if self.batching and not self.faults.get("st_no_final_flush"):
                    self._flush()
            if service == "storage-consumer" and (self.batching or self.storage_timing) and not self.faults.get("no_timing"):
                self.logs_text[service] += self.timing_line()
            if not self.faults.get("no_diagnostic"):
                self.logs_text[service] += (f"x: SIGTERM {H.FIRST_SIGNAL_MARKER}. Send it again to stop immediately.\n"
                                            f"agentops {H.GRACEFUL_MARKER}.\n")
            if self.faults.get("double_diagnostic"):
                self.logs_text[service] += f"x: SIGTERM {H.FIRST_SIGNAL_MARKER}.\n"
        requested = self.now
        self.now += self.faults.get("stop_seconds", 1.5)
        return H.StopResult(self.faults.get("stop_seconds", 1.5), self.faults.get("stop_returncode", 0),
                            requested, "2026-10-18T00:00:00.000000+00:00")


CFG = H.Config(messages=60, spans=3, batch_messages=10, idle_seconds=0.0, window_timeout=60.0)


class TestCasesOnTheSimulation:
    def test_s1_passes_and_restarts_both_services(self):
        env = SimEnv()
        case = H.case_s1(env, CFG)
        assert case.verdict == "PASS" and case.problems == [] and env.running == {s: True for s in H.APP_SERVICES}

    @pytest.mark.parametrize("fault, needle", [
        ({"exit_code": 137}, "killed after the grace period"),
        ({"exit_code": 1}, "exit code 1"),
        ({"stop_seconds": 11.0}, "stop took"),
        ({"no_diagnostic": True}, "0 first-signal diagnostics"),
        ({"double_diagnostic": True}, "2 first-signal diagnostics"),
        ({"stop_returncode": 1}, "compose stop returned 1"),
    ])
    def test_s1_fails_on_each_shutdown_defect(self, fault, needle):
        case = H.case_s1(SimEnv(**fault), CFG)
        assert case.verdict == "FAIL" and any(needle in problem for problem in case.problems)

    def test_s2_passes_when_nothing_is_lost_and_no_offset_runs_ahead(self):
        env = SimEnv()
        case = H.case_s2(env, CFG)
        assert case.verdict == "PASS", case.problems
        assert H.account_canonical(env.expected(), env.canonical()).missing == 0
        assert 0 < case.metrics["committed_at_stop"] < CFG.messages

    def test_s2_fails_when_the_source_offset_runs_ahead_of_the_publication(self):
        case = H.case_s2(SimEnv(sp_commit_early=True), CFG)
        assert case.verdict == "FAIL"
        text = "\n".join(case.problems)
        assert "past message" in text and "missing" in text

    def test_s2_is_inconclusive_when_the_work_finished_before_the_stop_could_be_issued(self):
        case = H.case_s2(SimEnv(instant=True), CFG)
        assert case.verdict == "INCONCLUSIVE" and "not inside its processing window" in case.problems[0]

    def test_s3_passes_and_every_row_is_present_once(self):
        env = SimEnv()
        case = H.case_s3(env, CFG)
        assert case.verdict == "PASS", case.problems
        assert H.account_rows(env.expected(), env.rows()) == H.Accounting(0, 0, 0, ())

    def test_s3_fails_when_the_destination_offset_runs_ahead_of_the_database(self):
        case = H.case_s3(SimEnv(st_commit_early=True), CFG)
        assert case.verdict == "FAIL" and any("has no row" in p for p in case.problems)

    def test_s3_is_inconclusive_when_it_finishes_too_early(self):
        assert H.case_s3(SimEnv(instant=True), CFG).verdict == "INCONCLUSIVE"

    def test_s4_enables_batching_for_the_case_and_restores_it(self):
        env = SimEnv()
        case = H.case_s4(env, CFG)
        assert case.verdict == "PASS", case.problems
        assert env.batching_history == [10, None] and case.metrics["batching_messages"] == 10

    def test_s4_reports_replayable_work_when_the_final_flush_is_missing_without_failing_safety(self):
        uneven_batches = H.Config(messages=60, spans=3, batch_messages=13, idle_seconds=0.0, window_timeout=60.0)
        case = H.case_s4(SimEnv(st_no_final_flush=True), uneven_batches)
        assert case.verdict == "PASS", case.problems
        assert case.metrics["persisted_but_uncommitted"] > 0

    def test_s4_still_fails_when_batching_commits_past_the_database(self):
        assert H.case_s4(SimEnv(st_commit_early=True), CFG).verdict == "FAIL"

    def test_a_missing_span_after_restart_is_a_failure(self):
        env = SimEnv()
        original = env.start

        def lossy(service):
            original(service)
            if service == "stream-processor" and env.canonical_list:
                env.canonical_list.pop()
                env.can_end[env.canonical_list[-1].partition] -= 0
        env.start = lossy
        case = H.case_s2(env, CFG)
        assert case.verdict == "FAIL" and any("missing" in p for p in case.problems)

    def test_duplicates_above_the_tolerance_are_a_failure_and_within_it_are_reported(self):
        def with_duplicates(copies):
            env = SimEnv()
            original = env.start

            def duplicating(service):
                original(service)
                if service == "stream-processor":
                    env.canonical_list.extend(env.canonical_list[:copies])
            env.start = duplicating
            return H.case_s2(env, CFG)
        assert with_duplicates(CFG.spans).verdict == "PASS"
        assert with_duplicates(CFG.spans).metrics["duplicate_copies"] == CFG.spans
        over = with_duplicates(CFG.spans + 1)
        assert over.verdict == "FAIL" and any("duplicate copies" in p for p in over.problems)

    def test_run_cases_orders_the_cases_and_stops_at_the_first_failure(self):
        results = H.run_cases(SimEnv(), CFG, ["S4", "S1", "S3"])
        assert [c.name for c in results] == ["S1", "S3", "S4"] and all(c.verdict == "PASS" for c in results)
        failing = H.run_cases(SimEnv(exit_code=137), CFG, list(H.CASES))
        assert [c.name for c in failing] == ["S1"] and failing[0].verdict == "FAIL"

    def test_every_case_can_run_alone(self):
        for name in H.CASES:
            results = H.run_cases(SimEnv(), CFG, [name])
            assert [c.verdict for c in results] == ["PASS"], (name, results[0].problems)


# ---------------------------------------------------------------------------
# T11  The commands the live environment issues
# ---------------------------------------------------------------------------

FORBIDDEN_WORDS = ("prune", "--rmi", "system", "rm", "kill", "pause", "unpause", "rename", "-f=true")


def live_env(tmp_path, router=None):
    shell = RecordingShell(router)
    clock = iter(range(0, 10000, 3))
    env = H.LiveEnv(PROJECT, tmp_path / "o.yml", tmp_path / "e.env", shell, clock=lambda: float(next(clock)), sleeper=lambda s: None)
    return env, shell


class TestLiveEnvCommands:
    def test_stop_uses_the_configured_grace_period_not_an_explicit_timeout(self, tmp_path):
        env, shell = live_env(tmp_path)
        result = env.stop(["stream-processor", "storage-consumer"])
        command = shell.commands[0]
        assert compose_verb(command) == "stop" and command[-2:] == ["stream-processor", "storage-consumer"]
        assert "-t" not in command and "--timeout" not in command
        assert result.returncode == 0 and result.seconds == 3.0

    def test_start_is_project_scoped_and_never_builds_or_touches_dependencies(self, tmp_path):
        env, shell = live_env(tmp_path)
        env.start("storage-consumer")
        command = shell.commands[0]
        assert compose_verb(command) == "up" and command[-4:] == ["-d", "--no-deps", "--no-build", "storage-consumer"] \
            or command[-5:] == ["up", "-d", "--no-deps", "--no-build", "storage-consumer"]

    def test_the_producer_step_runs_inside_the_projects_own_image(self, tmp_path):
        out = json.dumps({"acks": {str(i): [i % 3, i] for i in range(4)}, "errors": [], "unflushed": 0})
        env, shell = live_env(tmp_path, lambda c: Result(stdout=out))
        produced = env.produce(1, 4, 3)
        command = shell.commands[0]
        assert compose_verb(command) == "run" and "--rm" in command and "--no-deps" in command and "-T" in command
        assert command[command.index("--entrypoint") + 1] == "python" and "stream-processor" in command
        assert command[command.index("-c") + 1] == H.PRODUCER_SOURCE and command[-3:] == ["1", "4", "3"]
        assert env.produced == [produced] and env.expected() == produced.expected()

    def test_reads_go_through_the_projects_kafka_and_postgres_containers(self, tmp_path):
        def router(command):
            if "kafka-consumer-groups.sh" in " ".join(command):
                return Result(stdout=GROUP_TEXT.replace("g1", env.stream_group).replace("agentops.telemetry.spans", H.SOURCE_TOPIC))
            return Result(stdout="t|s|0|1\n")
        env, shell = live_env(tmp_path, router)
        assert set(env.group(env.stream_group, H.SOURCE_TOPIC)) == {0, 1, 2}
        assert env.rows() == [H.Row("t", "s", 0, 1)]
        kafka = shell.commands[0]
        assert "exec" in kafka and "kafka" in kafka and "--bootstrap-server" in kafka and H.BROKER in kafka
        assert "postgres" in shell.commands[1] and "psql" in shell.commands[1]

    def test_a_group_that_does_not_exist_yet_has_committed_nothing(self, tmp_path):
        def router(command):
            joined = " ".join(command)
            if "kafka-consumer-groups.sh" in joined:
                return Result(returncode=1, stderr="Consumer group 'x' does not exist.")
            if "kafka-get-offsets.sh" in joined:
                return Result(stdout=f"{H.CANONICAL_TOPIC}:0:5 {H.CANONICAL_TOPIC}:1:6 {H.CANONICAL_TOPIC}:2:7")
            return Result()
        env, _ = live_env(tmp_path, router)
        groups = env.group("x", H.CANONICAL_TOPIC)
        assert groups == {0: H.GroupPartition(None, 5), 1: H.GroupPartition(None, 6), 2: H.GroupPartition(None, 7)}

    def test_an_undescribable_group_times_out_as_a_failure(self, tmp_path):
        env, _ = live_env(tmp_path, lambda c: Result(stdout="GROUP TOPIC\n"))
        with pytest.raises(SmokeFailure, match="no stable description"):
            env.group("g", H.SOURCE_TOPIC)

    def test_canonical_reads_use_a_bounded_console_consumer(self, tmp_path):
        body = json.dumps({"trace_id": "t", "span_id": "s"})
        env, shell = live_env(tmp_path, lambda c: Result(stdout=f"Partition:0\tOffset:1\t{body}\n"))
        assert env.canonical() == [H.Canonical(0, 1, "t", "s")]
        command = shell.commands[0]
        assert "kafka-console-consumer.sh" in " ".join(command) and "--timeout-ms" in command and "--from-beginning" in command

    def test_batching_is_switched_only_through_the_temporary_override(self, tmp_path):
        env, shell = live_env(tmp_path)
        env.set_storage_batching(50)
        assert 'CONSUMER_COMMIT_BATCH_MESSAGES: "50"' in (tmp_path / "o.yml").read_text(encoding="utf-8")
        env.set_storage_batching(None)
        assert "BATCH" not in (tmp_path / "o.yml").read_text(encoding="utf-8") and shell.commands == []

    def test_no_command_the_environment_can_issue_is_destructive(self, tmp_path):
        out = json.dumps({"acks": {"0": [0, 0]}, "errors": [], "unflushed": 0})
        env, shell = live_env(tmp_path, lambda c: Result(stdout=out if "run" in c else "cid\n"))
        env.start("stream-processor")
        env.stop(["stream-processor"])
        env.produce(1, 1, 3)
        for command in shell.commands:
            words = set(command) - {H.PRODUCER_SOURCE}
            assert "agentops" not in command[command.index("-p") + 1:command.index("-p") + 2]
            assert not words & {"prune", "--rmi", "system", "kill", "pause", "rm", "down", "-v", "--volumes"}


# ---------------------------------------------------------------------------
# T12  Cleanup
# ---------------------------------------------------------------------------

BEFORE = {"containers": ["id1 agentops-postgres exited"], "volumes": ["agentops-mvp-postgres-data"],
          "networks": ["n1 bridge"], "images": ["python:3.13 i1"]}


class ScriptedDocker:
    """Answers the cleanup's reads; `leftovers` are objects of the project that survive `down`."""

    def __init__(self, *, down_code=0, leftovers=None, extra_after=None, images=None, remove_code=0, protected_after=None):
        self.down_code, self.leftovers, self.extra_after = down_code, leftovers or {}, extra_after or {}
        self.images = list(images if images is not None else [f"{PROJECT}-stream-processor:latest", f"{PROJECT}-storage-consumer:latest"])
        self.remove_code, self.protected_after = remove_code, protected_after
        self.downed = False
        self.removed = []

    def __call__(self, command):
        joined = " ".join(command)
        if "compose" in command and "down" in command:
            self.downed = True
            return Result(returncode=self.down_code, stderr="down failed" if self.down_code else "")
        if command[:3] == ["docker", "image", "remove"]:
            self.removed.append(command[3])
            if self.remove_code == 0:
                self.images = [i for i in self.images if i != command[3]]
            return Result(returncode=self.remove_code)
        if command[:2] == ["docker", "images"] and "--filter" in command:
            if "-q" in command:
                return Result(stdout=("abc\n" * len(self.images)) if self.images else "")
            return Result(stdout="\n".join(self.images))
        if command[:2] == ["docker", "ps"] and "--filter" in command:
            return Result(stdout="cid\n" * len(self.leftovers.get("containers", [])))
        if command[:2] in (["docker", "network"], ["docker", "volume"]) and "--filter" in command:
            kind = "networks" if command[1] == "network" else "volumes"
            return Result(stdout="x\n" * len(self.leftovers.get(kind, [])))
        if command[:2] == ["docker", "ps"]:
            return Result(stdout="\n".join(BEFORE["containers"] + self.extra_after.get("containers", [])))
        if command[:3] == ["docker", "volume", "ls"]:
            return Result(stdout="\n".join(BEFORE["volumes"]))
        if command[:3] == ["docker", "network", "ls"]:
            return Result(stdout="\n".join(BEFORE["networks"]))
        if command[:2] == ["docker", "images"]:
            return Result(stdout="\n".join(BEFORE["images"]))
        if command[:2] == ["docker", "inspect"]:
            return Result(returncode=1)
        if command[:3] == ["git", "-C", str(smoke.REPO)]:
            return Result(stdout=OWN_STATUS)
        return Result()


def make_ops(tmp_path, scripted, *, status_before=None, protected_before=None):
    temp = Path(tempfile.mkdtemp(prefix="shutdown-it-")).resolve()
    smoke.register_workspace(temp)               # the harness registers its own directory; smoke._remove_tree needs it
    env_file = temp / "shutdown.env"
    env_file.write_text("A=b\n", encoding="utf-8")
    shell = RecordingShell(scripted)
    ops = H.ShutdownOps(PROJECT, temp / "o.yml", env_file, shell, temp,
                        status_before if status_before is not None else sorted(OWN_STATUS.splitlines()), protected_before)
    return ops, shell, temp


class TestCleanup:
    def test_a_clean_run_is_verified_and_scoped_to_the_exact_project(self, tmp_path):
        scripted = ScriptedDocker()
        ops, shell, temp = make_ops(tmp_path, scripted)
        problems = H.cleanup(ops, BEFORE, report=lambda text: None)
        assert problems == [], problems
        down = ops.down_command
        assert down[:4] == ["docker", "compose", "-p", PROJECT] and down[-3:] == ["down", "--volumes", "--remove-orphans"]
        assert "--rmi" not in down and "--rmi" not in " ".join(sum(shell.commands, []))
        assert sorted(scripted.removed) == sorted([f"{PROJECT}-stream-processor:latest", f"{PROJECT}-storage-consumer:latest"])
        # Cleanup is simulated (smoke._remove_tree is a RemovalRecorder): this checks the hand-over, not the disk.
        assert smoke._remove_tree.calls == [temp.resolve()]
        assert temp.exists()

    def test_nothing_broad_is_ever_issued(self, tmp_path):
        ops, shell, _ = make_ops(tmp_path, ScriptedDocker())
        H.cleanup(ops, BEFORE, report=lambda text: None)
        for command in shell.commands:
            if command[:1] != ["docker"]:
                continue
            assert command[1] not in {"system", "builder", "container", "kill", "rm", "rmi", "stop"}
            if command[1:3] == ["image", "remove"]:
                assert command[3].startswith(PROJECT + "-") and "-f" not in command and "--force" not in command
            if command[1] in {"volume", "network"}:
                assert command[2] == "ls"

    def test_a_shared_image_is_never_removed(self, tmp_path):
        scripted = ScriptedDocker(images=["python:3.13-slim-bookworm", f"{PROJECT}-storage-consumer:latest", "<none>:<none>"])
        ops, _, _ = make_ops(tmp_path, scripted)
        H.cleanup(ops, BEFORE, report=lambda text: None)
        assert scripted.removed == [f"{PROJECT}-storage-consumer:latest"]
        with pytest.raises(SmokeFailure):
            ops.remove_image("python:3.13-slim-bookworm")

    def test_a_failed_down_leftover_objects_and_a_failed_image_removal_are_problems(self, tmp_path):
        ops, _, _ = make_ops(tmp_path, ScriptedDocker(down_code=1, leftovers={"volumes": ["v"]}, remove_code=1))
        problems = H.cleanup(ops, BEFORE, report=lambda text: None)
        text = "\n".join(problems)
        assert "compose down failed" in text and "volumes left" in text and "could not be removed" in text

    def test_unrelated_new_objects_are_reported_and_never_removed(self, tmp_path):
        scripted = ScriptedDocker(extra_after={"containers": ["zz someone-elses-container running"]})
        ops, shell, _ = make_ops(tmp_path, scripted)
        lines = []
        problems = H.cleanup(ops, BEFORE, report=lines.append)
        assert "someone-elses-container" in "\n".join(lines) and "NOT touched" in "\n".join(lines)
        assert not any("someone-elses" in " ".join(c) for c in shell.commands if c[1:3] in (["image", "remove"], ["container", "rm"]))
        assert problems == []

    def test_a_changed_protected_object_is_a_problem(self, tmp_path):
        before = {**BEFORE, "containers": ["id1 agentops-postgres exited", "id2 agentops-mvp-viewer-1 running"]}
        ops, _, _ = make_ops(tmp_path, ScriptedDocker())
        problems = H.cleanup(ops, before, report=lambda text: None)
        assert any("protected object missing or changed: id2 agentops-mvp-viewer-1" in p for p in problems)

    def test_protected_inventory_comparison(self):
        old = {"containers": ["1 agentops-mvp-viewer-1 running", "2 other running"], "volumes": ["agentops-mvp-postgres-data"]}
        assert H.protected_inventory_problems(old, old) == []
        new = {"containers": ["2 other running", "9 agentops-workload-smoke-kafka-1 running"], "volumes": []}
        problems = H.protected_inventory_problems(old, new)
        assert len(problems) == 3 and any("appeared" in p for p in problems)

    def test_an_exception_during_cleanup_is_a_problem_never_a_success(self, tmp_path):
        class Boom(ScriptedDocker):
            def __call__(self, command):
                if command[:2] == ["docker", "images"] and "--filter" not in command:
                    raise OSError("daemon went away")
                return super().__call__(command)
        ops, _, _ = make_ops(tmp_path, Boom())
        problems = H.cleanup(ops, BEFORE, report=lambda text: None)
        assert problems and "cleanup could not be completed" in problems[-1]

    def test_the_repository_changing_during_the_run_is_a_problem(self, tmp_path):
        ops, _, _ = make_ops(tmp_path, ScriptedDocker(), status_before=["?? something-else"])
        assert any("repository changed" in p for p in ops.repository_problems())

    def test_ops_refuse_any_other_project_and_non_temporary_paths(self, tmp_path):
        for bad in ("agentops", "agentops-workload-smoke", PROJECT + "x"):
            with pytest.raises(SmokeFailure):
                H.ShutdownOps(bad, None, None, RecordingShell(), None)
        for path in (smoke.REPO, smoke.REPO / "workload-generator", Path("C:/Windows") if sys.platform == "win32" else Path("/etc")):
            ops = H.ShutdownOps(PROJECT, None, None, RecordingShell(), path)
            with pytest.raises(SmokeFailure, match="not a temporary directory"):
                ops.remove_temp()

    def test_the_blocking_marker_is_written_and_then_blocks_the_next_start(self, tmp_path):
        assert H.own_markers(tmp_path) == []
        path = H.write_marker("a volume remained", tmp_path)
        assert path.read_text(encoding="utf-8").startswith("a volume remained") and H.own_markers(tmp_path) == ["CLEANUP_UNVERIFIED"]
        assert H.find_blockers(benchmark_markers=[], own_markers=H.own_markers(tmp_path), docker_lines=[], processes=[])


# ---------------------------------------------------------------------------
# T13  The whole live flow, every command scripted
# ---------------------------------------------------------------------------

BRIDGE_OPTIONS = {"com.docker.network.bridge.default_bridge": "true", "com.docker.network.bridge.name": "docker0"}
USER_NETWORK_IDS = {"agentops-mvp_mvp-net": "u1", "agentops_agentops-net": "u2"}
USER_NETWORK_LABELS = {"com.docker.compose.project": "agentops"}


def net_json(id_, name, *, driver="bridge", scope="local", internal=False, labels=None, options=None, attached=None,
             created="2026-01-01T00:00:00Z"):
    """What `docker network inspect <network>` prints."""
    return json.dumps([{"Id": id_, "Name": name, "Driver": driver, "Scope": scope, "Internal": internal,
                        "Created": created, "Labels": labels if labels is not None else {},
                        "Options": options if options is not None else {},
                        "Containers": {cid: {"Name": n} for cid, n in (attached or {}).items()}}])


class FlowDocker:
    """A scripted engine good enough for execute(--cases S1).  It also answers the network inspections:
    `recreate_bridge` gives the default bridge a new ID after `compose down`; `bridge_after`, `user_after` (per
    network) and `protected_after` (per container) change what is read AFTER the teardown; `two_bridges` and
    `user_missing_before` change what is read BEFORE; `leftover` leaves a network of the project behind."""

    def __init__(self, *, down_code=0, app_exit=0, recreate_bridge=False, bridge_after=None, user_after=None,
                 protected_after=None, two_bridges=False, user_missing_before=None, leftover=False):
        self.stopped, self.down_code, self.app_exit = False, down_code, app_exit
        self.images = [f"{PROJECT}-stream-processor:latest"]
        self.commands = []
        self.downed, self.bridge_id, self.recreate_bridge = False, "n1", recreate_bridge
        self.bridge_after, self.user_after, self.protected_after = bridge_after or {}, user_after or {}, protected_after or {}
        self.two_bridges, self.user_missing_before, self.leftover = two_bridges, user_missing_before, leftover

    def networks(self, command):
        if command[:3] == ["docker", "network", "ls"] and "--filter" not in command and "--no-trunc" in command:
            lines = [f"{self.bridge_id} bridge"] + (["n9 bridge"] if self.two_bridges else [])
            return Result(stdout="\n".join(lines))
        if command[:3] == ["docker", "network", "inspect"]:
            ref = command[3]
            if ref == self.bridge_id:
                kw = dict(self.bridge_after) if self.downed else {}
                return Result(stdout=net_json(self.bridge_id, "bridge", **{"options": BRIDGE_OPTIONS, **kw}))
            if ref in USER_NETWORK_IDS:
                kw = dict(self.user_after.get(ref, {})) if self.downed else {}
                if kw.pop("missing", False) or (not self.downed and ref == self.user_missing_before):
                    return Result(returncode=1, stderr=f"Error response from daemon: network {ref} not found")
                return Result(stdout=net_json(kw.pop("id", USER_NETWORK_IDS[ref]), ref,
                                              **{"labels": USER_NETWORK_LABELS, **kw}))
            return Result(returncode=1, stderr="Error response from daemon: network not found")
        return None

    def __call__(self, command):
        self.commands.append(list(command))
        joined = " ".join(command)
        answer = self.networks(command)
        if answer is not None:
            return answer
        if self.downed and self.leftover and command[:3] == ["docker", "network", "ls"] and "--filter" in command:
            return Result(stdout="leftover\n")
        if command[:2] == ["git", "-C"]:
            return Result(stdout=OWN_STATUS)
        if "compose" in command:
            verb = compose_verb(command)
            if verb == "stop":
                self.stopped = True
            if verb == "up" and any(s in command for s in H.APP_SERVICES):
                self.stopped = False
            if verb == "down":
                self.downed = True
                if self.recreate_bridge:
                    self.bridge_id = "n2"
                return Result(returncode=self.down_code)
            if verb == "ps":
                return Result(stdout=f"cid-{command[-1]}\n")
            if verb == "logs":
                if not self.stopped:
                    return Result(stdout="starting\n")
                return Result(stdout=f"x: SIGTERM {H.FIRST_SIGNAL_MARKER}.\nagentops {H.GRACEFUL_MARKER}.\n")
            return Result()
        if command[:2] == ["docker", "inspect"]:
            if command[-1] in SNAPSHOT:                                   # the protected containers, as at preflight
                value = self.protected_after.get(command[-1], SNAPSHOT[command[-1]]) if self.downed else SNAPSHOT[command[-1]]
                return Result(stdout=value) if value else Result(returncode=1)
            if command[-1].startswith("cid-"):
                service = command[-1][4:]
                if service in H.APP_SERVICES:
                    state = f"exited|{self.app_exit}|0|false" if self.stopped else "running|0|0|false"
                else:
                    state = "exited|0|0|false"
                return Result(stdout=state + "\n")
            return Result(returncode=1)
        if command[:3] == ["docker", "image", "remove"]:
            self.images = []
            return Result()
        if command[:2] == ["docker", "images"] and "--filter" in command:
            if "-q" in command:
                return Result(stdout="abc\n" if self.images else "")
            return Result(stdout="\n".join(self.images))
        if command[:2] in (["docker", "ps"], ["docker", "network"], ["docker", "volume"]) and "--filter" in command:
            return Result(stdout="")
        if command[:2] == ["docker", "ps"]:
            return Result(stdout="\n".join(BEFORE["containers"]))
        if command[:3] == ["docker", "volume", "ls"]:
            return Result(stdout="\n".join(BEFORE["volumes"]))
        if command[:3] == ["docker", "network", "ls"]:
            return Result(stdout="\n".join(BEFORE["networks"]))
        if command[:2] == ["docker", "images"]:
            return Result(stdout="\n".join(BEFORE["images"]))
        return Result()


def flow_args(confirm=True):
    import argparse
    return argparse.Namespace(expect_head=HEAD, confirm=H.confirmation_phrase(HEAD) if confirm else "no",
                              docker_data_dir=_HERE, cases="S1", messages=60, preflight=False, execute=True)


def fake_preflight(*args, **kwargs):
    return H.Preflight(PROJECT, "development", dict(BEFORE), dict(SNAPSHOT), good_readings())


class TestWholeFlow:
    cfg = H.Config(messages=60, idle_seconds=0.0)

    def run(self, docker, args=None):
        return H.execute(args or flow_args(), ["S1"], self.cfg, sh=RecordingShell(docker), preflight=fake_preflight,
                         sleeper=lambda s: None, clock=lambda c=iter(range(0, 100000)): float(next(c)))

    def test_a_good_run_passes_and_cleans_up(self, capsys):
        docker = FlowDocker()
        shell = RecordingShell(docker)
        code = H.execute(flow_args(), ["S1"], self.cfg, sh=shell, preflight=fake_preflight,
                         sleeper=lambda s: None, clock=lambda c=iter(range(0, 100000)): float(next(c)))
        out = capsys.readouterr().out
        assert code == 0 and "overall: PASS" in out and "cleanup verified: yes" in out
        verbs = [compose_verb(c) for c in docker.commands if "compose" in c]
        assert verbs.index("build") < verbs.index("stop") < verbs.index("down")
        assert any(c[:3] == ["docker", "image", "remove"] for c in docker.commands)
        for command in docker.commands:
            assert "--rmi" not in command and "prune" not in command and "-p" not in command or command[command.index("-p") + 1] == PROJECT
        assert not any(w in command for command in docker.commands for w in ("kill", "pause", "prune", "--rmi"))
        assert H.own_markers() == []

    def test_a_refused_confirmation_issues_no_command(self):
        docker = FlowDocker()
        shell = RecordingShell(docker)
        with pytest.raises(SmokeFailure):
            H.execute(flow_args(confirm=False), ["S1"], self.cfg, sh=shell, preflight=fake_preflight,
                      sleeper=lambda s: None, clock=lambda: 0.0)
        assert shell.commands == []

    def test_a_failing_preflight_stops_before_anything_is_created(self):
        shell = RecordingShell(FlowDocker())

        def failing(*args, **kwargs):
            raise SmokeFailure("preflight failed before any Docker command:\nport 19092 is in use")
        with pytest.raises(SmokeFailure):
            H.execute(flow_args(), ["S1"], self.cfg, sh=shell, preflight=failing, sleeper=lambda s: None, clock=lambda: 0.0)
        assert shell.commands == []

    def test_a_killed_service_fails_the_run_but_cleanup_still_runs(self, capsys):
        docker = FlowDocker(app_exit=137)
        code = self.run(docker)
        out = capsys.readouterr().out
        assert code == 1 and "overall: FAIL" in out and "killed after the grace period" in out
        assert any(compose_verb(c) == "down" for c in docker.commands if "compose" in c)

    def test_the_report_does_not_claim_a_flag_the_command_does_not_use(self, capsys):
        self.run(FlowDocker())
        out = capsys.readouterr().out
        assert "--rmi" in out and "no --rmi: own images are removed by exact name" in out
        assert "--rmi local" not in out

    def test_a_failed_down_is_not_a_success_and_leaves_the_blocking_marker(self, capsys):
        code = self.run(FlowDocker(down_code=1))
        out = capsys.readouterr().out
        assert code == 1 and "cleanup verified: NO" in out and "CLEANUP PROBLEM" in out
        assert H.own_markers() == ["CLEANUP_UNVERIFIED"]


# ---------------------------------------------------------------------------
# T14  Per-service shutdown observations
# ---------------------------------------------------------------------------

GOOD_LOGS = (f"x: SIGTERM {H.FIRST_SIGNAL_MARKER}. Send it again to stop immediately.\n"
             f"agentops {H.GRACEFUL_MARKER}.\nunrelated line\n")
BEFORE_STATE = H.Inspect("running", 0, 0, False)
STOP = H.StopResult(1.37, 0, 12.5, "2026-10-18T01:02:03.123456+00:00")


class StubEnv(H.Env):
    """Returns (or raises) exactly what a test sets."""

    def __init__(self, state=H.Inspect("exited", 0, 0, False), logs=GOOD_LOGS):
        self.state, self.logs_text = state, logs

    def inspect(self, service):
        if isinstance(self.state, Exception):
            raise self.state
        return self.state

    def logs(self, service):
        if isinstance(self.logs_text, Exception):
            raise self.logs_text
        return self.logs_text


def observe(env=None, *, stop=STOP, limit=10.0, logs_before=(0, 0), with_=("stream-processor", "storage-consumer")):
    return H.observe_stop(env or StubEnv(), "storage-consumer", BEFORE_STATE, logs_before, stop, limit, with_)


class TestPerServiceObservations:
    def test_every_required_field_is_extracted(self):
        observation, problems = observe()
        assert problems == [] and observation.all_passed is True
        assert observation.service == "storage-consumer"
        assert observation.stop_requested_monotonic == 12.5 and observation.stop_requested_utc == STOP.requested_utc
        assert observation.stop_seconds == 1.37 and observation.stop_returncode == 0
        assert observation.stop_command_services == ["stream-processor", "storage-consumer"]
        assert (observation.exit_code, observation.status) == (0, "exited")
        assert (observation.restarts_before, observation.restarts_after, observation.oom_killed) == (0, 0, False)
        assert (observation.first_signal_diagnostics, observation.graceful_stop_lines) == (1, 1)
        assert len(observation.shutdown_log_lines) == 2 and all("unrelated" not in l for l in observation.shutdown_log_lines)
        assert observation.missing_observations == [] and set(observation.assertions.values()) == {True}
        assert set(observation.assertions) == {
            "exit_code_0", "status_exited", "restart_count_unchanged", "not_oom_killed", "compose_stop_ok",
            "stop_within_limit", "one_first_signal_diagnostic", "one_graceful_stop_line"}

    @pytest.mark.parametrize("code, needle", [(1, "exit code 1"), (2, "exit code 2"), (137, "killed after the grace period")])
    def test_a_nonzero_exit_code_is_recorded_and_fails(self, code, needle):
        observation, problems = observe(StubEnv(H.Inspect("exited", code, 0, False)))
        assert observation.exit_code == code and observation.assertions["exit_code_0"] is False
        assert observation.all_passed is False and any(needle in p for p in problems)

    def test_missing_or_duplicated_diagnostics_fail(self):
        for text, first, graceful in (("starting\n", 0, 0), (GOOD_LOGS + GOOD_LOGS, 2, 2),
                                      (f"x: SIGTERM {H.FIRST_SIGNAL_MARKER}.\n", 1, 0)):
            observation, problems = observe(StubEnv(logs=text))
            assert (observation.first_signal_diagnostics, observation.graceful_stop_lines) == (first, graceful)
            assert observation.all_passed is False and problems

    def test_diagnostics_are_counted_since_the_stop_was_requested(self):
        observation, problems = observe(StubEnv(logs=GOOD_LOGS * 3), logs_before=(2, 2))
        assert (observation.first_signal_diagnostics, observation.graceful_stop_lines) == (1, 1) and problems == []

    def test_an_unexpected_restart_count_change_fails(self):
        observation, problems = observe(StubEnv(H.Inspect("exited", 0, 2, False)))
        assert (observation.restarts_before, observation.restarts_after) == (0, 2)
        assert observation.assertions["restart_count_unchanged"] is False and any("restart count 0 -> 2" in p for p in problems)

    def test_an_oom_killed_container_fails(self):
        observation, problems = observe(StubEnv(H.Inspect("exited", 0, 0, True)))
        assert observation.oom_killed is True and observation.assertions["not_oom_killed"] is False
        assert any("OOM killed" in p for p in problems)

    def test_a_service_that_is_still_running_fails(self):
        observation, problems = observe(StubEnv(H.Inspect("running", 0, 0, False)))
        assert observation.assertions["status_exited"] is False and any("not 'exited'" in p for p in problems)

    def test_slow_or_failed_stop_commands_fail(self):
        observation, problems = observe(stop=H.StopResult(11.0, 1, 0.0, "2026-10-18T00:00:00.000000+00:00"))
        assert observation.assertions["compose_stop_ok"] is False and observation.assertions["stop_within_limit"] is False
        assert any("compose stop returned 1" in p for p in problems) and any("stop took 11.0s" in p for p in problems)

    @pytest.mark.parametrize("which, field", [("state", "container state"), ("logs", "service log")])
    def test_a_missing_observation_is_recorded_and_is_never_a_pass(self, which, field):
        failure = SmokeFailure("unparsable docker inspect output: 'garbage'")
        env = StubEnv(state=failure) if which == "state" else StubEnv(logs=failure)
        observation, problems = observe(env)
        assert observation.all_passed is False
        assert any(m.startswith(field) for m in observation.missing_observations)
        assert any(f"observation missing: {field}" in p for p in problems)
        assert None in observation.assertions.values()               # what could not be observed is not 'True'

    def test_both_observations_missing(self):
        observation, problems = observe(StubEnv(state=SmokeFailure("a"), logs=SmokeFailure("b")))
        assert len(observation.missing_observations) == 2 and observation.exit_code is None and observation.all_passed is False
        assert observation.first_signal_diagnostics is None and len(problems) >= 2

    def test_log_lines_are_redacted(self, monkeypatch):
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "hunter2hunter2hunter2"})
        logs = f"x: SIGTERM {H.FIRST_SIGNAL_MARKER} hunter2hunter2hunter2 DB_PASSWORD=abc123 .\nagentops {H.GRACEFUL_MARKER}.\n"
        observation, _ = observe(StubEnv(logs=logs))
        text = "\n".join(observation.shutdown_log_lines)
        assert "hunter2" not in text and "abc123" not in text and "<redacted>" in text

    def test_check_stop_keeps_its_signature_and_messages(self):
        problems = H.check_stop(StubEnv(H.Inspect("exited", 137, 0, False)), "storage-consumer", BEFORE_STATE, (0, 0), STOP, 10.0)
        assert problems == ["storage-consumer: exit code 137, killed after the grace period"]

    def test_a_stop_without_a_recorded_request_time_is_a_missing_observation(self):
        observation, problems = observe(stop=H.StopResult(1.0, 0))
        assert observation.all_passed is False and observation.missing_observations == ["stop request time"]
        assert any("observation missing: stop request time" in p for p in problems)

    def test_the_live_environment_records_when_the_stop_was_requested(self, tmp_path):
        env = H.LiveEnv(PROJECT, tmp_path / "o.yml", tmp_path / "e.env", RecordingShell(),
                        clock=iter([100.0, 104.0]).__next__, sleeper=lambda s: None, utc=lambda: "2026-10-18T00:00:00.000000+00:00")
        result = env.stop(["stream-processor"])
        assert (result.requested_monotonic, result.seconds, result.requested_utc) == (100.0, 4.0, "2026-10-18T00:00:00.000000+00:00")


class TestCasesKeepTheirStops:
    def test_s1_records_one_observation_per_service(self):
        case = H.case_s1(SimEnv(), CFG)
        assert [s.service for s in case.stops] == list(H.APP_SERVICES) and all(s.all_passed for s in case.stops)
        assert all(s.stop_command_services == list(H.APP_SERVICES) for s in case.stops)
        assert json.loads(json.dumps(case.to_dict()))["stops"][0]["exit_code"] == 0

    def test_s2_s3_s4_record_the_service_they_stopped(self):
        for fn, service in ((H.case_s2, "stream-processor"), (H.case_s3, "storage-consumer"), (H.case_s4, "storage-consumer")):
            case = fn(SimEnv(), CFG)
            assert case.verdict == "PASS" and [s.service for s in case.stops] == [service] and case.stops[0].all_passed

    def test_a_failed_stop_is_kept_in_the_case(self):
        case = H.case_s1(SimEnv(exit_code=137), CFG)
        assert case.verdict == "FAIL" and all(s.exit_code == 137 and not s.all_passed for s in case.stops)

    def test_an_inconclusive_case_has_no_stop_to_report(self):
        case = H.case_s2(SimEnv(instant=True), CFG)
        assert case.verdict == "INCONCLUSIVE" and case.stops == []


# ---------------------------------------------------------------------------
# T15  Evidence files
# ---------------------------------------------------------------------------

def sample_results():
    return [H.case_s1(SimEnv(), CFG)]


def sample_record(kind="pre-cleanup", **changes):
    values = dict(kind=kind, project=PROJECT, git_head=HEAD, git_state="committed", selected=["S1"],
                  results=sample_results(), failure="", verdict="PASS", started_utc="2026-10-18T00:00:00.000000+00:00",
                  finished_utc="2026-10-18T00:01:00.000000+00:00")
    values.update(changes)
    return H.build_evidence(**values)


STAMP = "20261018T000100000000Z"


class TestEvidenceFiles:
    def test_the_record_has_an_explicit_schema_and_the_required_context(self):
        record = sample_record()
        assert record["schema_version"] == "run_shutdown_it.evidence/1" == H.EVIDENCE_SCHEMA
        assert (record["project"], record["git_head"], record["selected_cases"]) == (PROJECT, HEAD, ["S1"])
        assert record["stop_grace_period"] == "30s" and record["verdict"] == "PASS" and "provisional" in record["verdict_note"]
        assert record["cases"][0]["stops"][0]["service"] == "stream-processor"
        assert "cleanup" not in record and "pre_cleanup_file" not in record

    def test_the_final_record_adds_cleanup_and_the_protected_comparison(self):
        cleaned = H.CleanupResult(problems=[], inventory_before={"containers": {"count": 8, "fingerprint": "ab"}},
                                  inventory_after={"containers": {"count": 8, "fingerprint": "ab"}},
                                  protected_before={"agentops-postgres": "i exited s f 0"},
                                  protected_after={"agentops-postgres": "i exited s f 0"})
        record = sample_record("final", cleanup=cleaned, precleanup={"name": "x.json", "sha256": "0" * 64})
        assert record["cleanup"]["verified"] is True and record["cleanup"]["protected_container_changes"] == []
        assert record["cleanup"]["inventory_before"] == record["cleanup"]["inventory_after"]
        assert record["pre_cleanup_file"] == {"name": "x.json", "sha256": "0" * 64} and "final" in record["verdict_note"]

    def test_serialization_is_deterministic_parseable_json(self):
        text = H.serialize_evidence(sample_record())
        assert text.endswith("\n") and json.loads(text)["schema_version"] == H.EVIDENCE_SCHEMA
        assert text == H.serialize_evidence(json.loads(text))

    def test_filenames_are_timestamped_unique_per_kind_and_attempt(self):
        names = {H.evidence_filename(PROJECT, kind, STAMP, attempt) for kind in ("pre-cleanup", "final") for attempt in (0, 1, 2)}
        assert len(names) == 6 and all(n.startswith("shutdown-it-" + STAMP) and PROJECT in n and n.endswith(".json") for n in names)
        assert H.utc_stamp("2026-10-18T01:02:03.123456+00:00") == "20261018T010203123456Z"

    def test_writing_returns_the_path_and_the_sha256_of_what_is_on_disk(self, tmp_path):
        import hashlib
        path, digest = H.write_evidence(tmp_path / "ev", PROJECT, "pre-cleanup", sample_record(), STAMP)
        assert path.parent == tmp_path / "ev" and hashlib.sha256(path.read_bytes()).hexdigest() == digest
        assert json.loads(path.read_text(encoding="utf-8"))["project"] == PROJECT

    def test_existing_evidence_is_never_overwritten(self, tmp_path):
        directory = tmp_path / "ev"
        directory.mkdir()
        existing = directory / H.evidence_filename(PROJECT, "final", STAMP)
        existing.write_text("ORIGINAL", encoding="utf-8")
        path, _ = H.write_evidence(directory, PROJECT, "final", sample_record("final"), STAMP)
        assert path != existing and existing.read_text(encoding="utf-8") == "ORIGINAL" and path.name.endswith("-1.json")

    def test_a_filename_collision_that_cannot_be_resolved_is_a_failure(self, tmp_path):
        directory = tmp_path / "ev"
        directory.mkdir()
        for attempt in range(10):
            (directory / H.evidence_filename(PROJECT, "final", STAMP, attempt)).write_text("x", encoding="utf-8")
        with pytest.raises(SmokeFailure, match="no unique evidence filename"):
            H.write_evidence(directory, PROJECT, "final", sample_record("final"), STAMP)

    def test_directories_inside_the_repository_or_the_benchmark_area_are_refused(self, tmp_path):
        assert H.evidence_dir_problem(smoke.REPO / "evidence") and H.evidence_dir_problem(smoke.REPO)
        assert H.evidence_dir_problem(Path(tempfile.gettempdir()) / "agentops-benchmarks")
        assert H.evidence_dir_problem(Path(tempfile.gettempdir()) / "agentops-benchmarks" / "ledger")
        assert H.evidence_dir_problem(H.marker_path().parent)
        assert H.evidence_dir_problem(tmp_path / "somewhere") is None
        assert H.evidence_dir_problem(H.default_evidence_dir()) is None
        with pytest.raises(SmokeFailure, match="evidence directory refused"):
            H.write_evidence(smoke.REPO / "stray-evidence", PROJECT, "final", sample_record("final"), STAMP)
        assert not (smoke.REPO / "stray-evidence").exists()

    def test_credentials_never_reach_the_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "Zx9Qw8Er7Ty6Ui5Op4As3"})
        record = sample_record(failure="boom Zx9Qw8Er7Ty6Ui5Op4As3 and DB_PASSWORD=hunter2")
        path, _ = H.write_evidence(tmp_path / "ev", PROJECT, "final", record, STAMP)
        text = path.read_text(encoding="utf-8")
        assert "Zx9Qw8Er7Ty6Ui5Op4As3" not in text and "hunter2" not in text and "<redacted>" in text

    def test_the_file_stays_valid_json_whatever_the_strings_contain(self, tmp_path, monkeypatch):
        # a secret-looking assignment inside a string must never swallow the quote or comma that follows it
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "Zx9Qw8Er7Ty6Ui5Op4As3"})
        nasty = ['leaked DB_PASSWORD=hunter2", "next": "x', "A_TOKEN=abc, B_SECRET=def) tail", "KEY=v}]",
                 'quote " and backslash \\ and Zx9Qw8Er7Ty6Ui5Op4As3 and newline\nDB_PASSWORD=<redacted>']
        record = sample_record(failure=" | ".join(nasty))
        record["diagnostics"] = {"aborted_case_snapshot": {"log_tail": nasty, "errors": []}}
        path, _ = H.write_evidence(tmp_path / "ev", PROJECT, "final", record, STAMP)
        text = path.read_text(encoding="utf-8")
        loaded = json.loads(text)                                         # still parses
        assert len(loaded["diagnostics"]["aborted_case_snapshot"]["log_tail"]) == 4
        assert all(secret not in text for secret in ("hunter2", "Zx9Qw8Er7Ty6Ui5Op4As3", "abc,", "=def"))
        assert loaded["diagnostics"]["aborted_case_snapshot"]["log_tail"][0].startswith("leaked DB_PASSWORD=<redacted>")

    def test_redact_text_stops_at_delimiters(self):
        assert H.redact_text('x DB_PASSWORD=abc", "y": 1') == 'x DB_PASSWORD=<redacted>", "y": 1'
        assert H.redact_text("A_SECRET=v, B_TOKEN=w;") == "A_SECRET=<redacted>, B_TOKEN=<redacted>;"
        assert H.redact_structure({"a": ["PW_PASSWORD=zz", 3, None], "b": ("KEY=q",)}) == {
            "a": ["PW_PASSWORD=<redacted>", 3, None], "b": ["KEY=<redacted>"]}

    def test_text_that_still_holds_a_credential_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "Zx9Qw8Er7Ty6Ui5Op4As3"})
        monkeypatch.setattr(H, "redact_structure", lambda value: value)       # a broken redactor
        monkeypatch.setattr(smoke, "redact", lambda text: text)
        with pytest.raises(SmokeFailure, match="generated credential"):
            H.write_evidence(tmp_path / "ev", PROJECT, "final",
                             sample_record(failure="Zx9Qw8Er7Ty6Ui5Op4As3"), STAMP)
        assert not list((tmp_path / "ev").glob("*")) if (tmp_path / "ev").exists() else True

    def test_write_failures_are_raised_not_swallowed(self, tmp_path):
        blocker = tmp_path / "a-file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises((OSError, SmokeFailure)):
            H.write_evidence(blocker / "ev", PROJECT, "final", sample_record("final"), STAMP)

    def test_a_file_that_does_not_read_back_as_written_is_a_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "read_bytes", lambda self: b"corrupted")
        with pytest.raises(SmokeFailure, match="did not read back"):
            H.write_evidence(tmp_path / "ev", PROJECT, "final", sample_record("final"), STAMP)


# ---------------------------------------------------------------------------
# T16  Verdict consistency
# ---------------------------------------------------------------------------

def passing_case(stops_ok=True):
    case = H.Case("S1", "PASS")
    stop = H.ServiceStop("stream-processor", 0.0, "", ["stream-processor"], 1.0, 0, all_passed=stops_ok)
    case.stops.append(stop)
    return case


class TestVerdictConsistency:
    def test_final_verdict_rules(self):
        base = dict(selected=["S1"], cleanup_verified=True, failure="", evidence_problems=[])
        assert H.final_verdict([passing_case()], **base) == "PASS"
        assert H.final_verdict([passing_case()], **{**base, "failure": "boom"}) == "FAIL"
        assert H.final_verdict([passing_case()], **{**base, "evidence_problems": ["x"]}) == "FAIL"
        assert H.final_verdict([passing_case()], **{**base, "cleanup_verified": False}) == "FAIL"
        assert H.final_verdict([passing_case(stops_ok=False)], **base) == "FAIL"
        assert H.final_verdict([H.Case("S1", "INCONCLUSIVE")], **base) == "HOLD"
        assert H.final_verdict([H.Case("S1", "FAIL")], **base) == "FAIL"
        assert H.final_verdict([], **base) == "HOLD"

    def test_inconsistent_passes_are_detected(self):
        base = dict(selected=["S1"], cleanup_verified=True, failure="", evidence_problems=[])
        assert H.verdict_consistency_problems("PASS", [passing_case()], **base) == []
        for change, needle in (({"failure": "x"}, "recorded failure"), ({"evidence_problems": ["e"]}, "evidence problem"),
                               ({"cleanup_verified": False}, "without verified cleanup")):
            assert any(needle in p for p in H.verdict_consistency_problems("PASS", [passing_case()], **{**base, **change}))
        assert any("did not pass" in p for p in H.verdict_consistency_problems("PASS", [], **base))
        assert any("per-service" in p for p in H.verdict_consistency_problems("PASS", [passing_case(False)], **base))
        assert any("failed case" in p for p in H.verdict_consistency_problems("HOLD", [H.Case("S1", "FAIL")], **base))
        assert any("unknown verdict" in p for p in H.verdict_consistency_problems("OK", [passing_case()], **base))

    def test_a_pass_is_always_consistent_and_nothing_inconclusive_becomes_one(self):
        import itertools
        for verdict, ok, cleaned, failure, evidence in itertools.product(("PASS", "FAIL", "INCONCLUSIVE"), (True, False),
                                                                      (True, False), ("", "x"), ([], ["e"])):
            case = H.Case("S1", verdict)
            case.stops.append(H.ServiceStop("s", 0.0, "", ["s"], 1.0, 0, all_passed=ok))
            final = H.final_verdict([case], selected=["S1"], cleanup_verified=cleaned, failure=failure, evidence_problems=evidence)
            if final == "PASS":
                assert verdict == "PASS" and ok and cleaned and not failure and not evidence
                assert H.verdict_consistency_problems(final, [case], selected=["S1"], cleanup_verified=cleaned,
                                                      failure=failure, evidence_problems=evidence) == []


# ---------------------------------------------------------------------------
# T17  The live flow writes its evidence before cleanup and reports honestly
# ---------------------------------------------------------------------------

class HookedFlowDocker(FlowDocker):
    """FlowDocker that notes which evidence files exist at the moment of `compose down`."""

    def __init__(self, evidence_dir, **kwargs):
        super().__init__(**kwargs)
        self.evidence_dir, self.at_down = evidence_dir, None

    def __call__(self, command):
        if "compose" in command and compose_verb(command) == "down":
            self.at_down = sorted(p.name for p in Path(self.evidence_dir).glob("*.json")) if Path(self.evidence_dir).exists() else []
        return super().__call__(command)


class TestEvidenceInTheLiveFlow:
    cfg = H.Config(messages=60, idle_seconds=0.0)

    def run(self, docker, evidence_dir):
        shell = RecordingShell(docker)
        code = H.execute(flow_args(), ["S1"], self.cfg, sh=shell, preflight=fake_preflight, sleeper=lambda s: None,
                         clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=evidence_dir,
                         utc=lambda c=iter(range(1000)): f"2026-10-18T00:00:{next(c) % 60:02d}.000000+00:00")
        return code, shell

    def read(self, evidence_dir, kind):
        files = sorted(Path(evidence_dir).glob(f"*-{kind}.json"))
        assert len(files) == 1, files
        return files[0], json.loads(files[0].read_text(encoding="utf-8"))

    def test_a_good_run_leaves_two_files_with_the_per_service_results(self, tmp_path, capsys):
        import hashlib
        docker = HookedFlowDocker(tmp_path / "ev")
        code, shell = self.run(docker, tmp_path / "ev")
        out = capsys.readouterr().out
        assert code == 0 and "overall: PASS" in out and "evidence written: yes" in out
        pre_path, pre = self.read(tmp_path / "ev", "pre-cleanup")
        final_path, final = self.read(tmp_path / "ev", "final")
        assert (final["project"], final["git_head"], final["stop_grace_period"], final["selected_cases"]) == (
            PROJECT, HEAD, "30s", ["S1"])
        assert final["verdict"] == "PASS" and pre["verdict"] == "PASS" and "provisional" in pre["verdict_note"]
        stops = final["cases"][0]["stops"]
        assert [s["service"] for s in stops] == list(H.APP_SERVICES)
        for stop in stops:
            assert (stop["exit_code"], stop["status"], stop["restarts_before"], stop["restarts_after"], stop["oom_killed"]) == (
                0, "exited", 0, 0, False)
            assert (stop["first_signal_diagnostics"], stop["graceful_stop_lines"], stop["all_passed"]) == (1, 1, True)
            assert stop["stop_seconds"] is not None and stop["stop_requested_utc"].startswith("2026-10-18")
            assert stop["shutdown_log_lines"] and stop["missing_observations"] == []
        assert final["cleanup"]["verified"] is True and final["cleanup"]["protected_container_changes"] == []
        assert final["cleanup"]["inventory_before"] == final["cleanup"]["inventory_after"]
        assert final["cleanup"]["protected_containers_before"] == final["cleanup"]["protected_containers_after"] == SNAPSHOT
        assert final["pre_cleanup_file"] == {"name": pre_path.name, "sha256": hashlib.sha256(pre_path.read_bytes()).hexdigest()}
        assert str(pre_path) in out and str(final_path) in out and hashlib.sha256(final_path.read_bytes()).hexdigest() in out
        assert pre_path.name != final_path.name

    def test_the_pre_cleanup_file_exists_before_the_containers_are_removed(self, tmp_path):
        docker = HookedFlowDocker(tmp_path / "ev")
        self.run(docker, tmp_path / "ev")
        assert len(docker.at_down) == 1 and docker.at_down[0].endswith("-pre-cleanup.json")

    def test_no_credential_reaches_either_file(self, tmp_path):
        self.run(HookedFlowDocker(tmp_path / "ev"), tmp_path / "ev")
        credentials = list(smoke.RUN.generated.values())
        assert credentials
        for path in (tmp_path / "ev").glob("*.json"):
            text = path.read_text(encoding="utf-8")
            assert not any(value in text for value in credentials)

    def test_a_killed_service_is_recorded_and_fails_the_run(self, tmp_path, capsys):
        code, _ = self.run(HookedFlowDocker(tmp_path / "ev", app_exit=137), tmp_path / "ev")
        _, final = self.read(tmp_path / "ev", "final")
        assert code == 1 and final["verdict"] == "FAIL" and final["cases"][0]["verdict"] == "FAIL"
        assert all(s["exit_code"] == 137 and s["all_passed"] is False for s in final["cases"][0]["stops"])
        assert "NOT all passed" in capsys.readouterr().out

    def test_a_cleanup_failure_is_reported_unverified_and_the_diagnostics_are_kept(self, tmp_path):
        code, _ = self.run(HookedFlowDocker(tmp_path / "ev", down_code=1), tmp_path / "ev")
        pre_path, _ = self.read(tmp_path / "ev", "pre-cleanup")
        _, final = self.read(tmp_path / "ev", "final")
        assert code == 1 and final["verdict"] == "FAIL" and final["cleanup"]["verified"] is False
        assert any("compose down failed" in p for p in final["cleanup"]["problems"]) and pre_path.exists()
        assert H.own_markers() == ["CLEANUP_UNVERIFIED"]

    def test_an_unusable_evidence_directory_is_never_a_pass_and_cleanup_still_runs(self, tmp_path, capsys):
        docker = HookedFlowDocker(tmp_path / "ev")
        code, shell = self.run(docker, smoke.REPO / "must-not-be-created")
        out = capsys.readouterr().out
        assert code == 1 and "overall: FAIL" in out and "evidence written: NO" in out and "EVIDENCE PROBLEM" in out
        assert any("compose" in c and compose_verb(c) == "down" for c in docker.commands)
        assert not (smoke.REPO / "must-not-be-created").exists()

    def test_a_final_file_that_cannot_be_written_is_never_a_pass(self, tmp_path, monkeypatch, capsys):
        real = H.write_evidence

        def failing_final(directory, project, kind, record, stamp):
            if kind == "final":
                raise OSError("disk full")
            return real(directory, project, kind, record, stamp)
        monkeypatch.setattr(H, "write_evidence", failing_final)
        code, _ = self.run(HookedFlowDocker(tmp_path / "ev"), tmp_path / "ev")
        out = capsys.readouterr().out
        assert code == 1 and "overall: FAIL" in out and "the final evidence could not be written" in out
        assert len(list((tmp_path / "ev").glob("*-pre-cleanup.json"))) == 1

    def test_the_commands_are_the_ones_the_harness_always_issued(self, tmp_path):
        docker = HookedFlowDocker(tmp_path / "ev")
        self.run(docker, tmp_path / "ev")
        verbs = [compose_verb(c) for c in docker.commands if "compose" in c]
        assert verbs.index("build") < verbs.index("stop") < verbs.index("down")
        stop = next(c for c in docker.commands if "compose" in c and compose_verb(c) == "stop")
        assert stop[-2:] == ["stream-processor", "storage-consumer"] and "-t" not in stop
        down = next(c for c in docker.commands if "compose" in c and compose_verb(c) == "down")
        assert down[-3:] == ["down", "--volumes", "--remove-orphans"] and down[3] == PROJECT
        assert not any(w in c for c in docker.commands for w in ("prune", "--rmi", "kill", "pause"))

    def test_the_default_evidence_directory_is_outside_the_repository_and_the_benchmarks(self):
        directory = H.default_evidence_dir()
        assert H.evidence_dir_problem(directory) is None and directory.name == "agentops-shutdown-it-evidence"


# ---------------------------------------------------------------------------
# T18  Classifying a consumer-group description
# ---------------------------------------------------------------------------

TOPIC_SRC = H.SOURCE_TOPIC
HEADER = "GROUP  TOPIC  PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG  CONSUMER-ID  HOST  CLIENT-ID\n"


def table(group, rows, topic=TOPIC_SRC):
    """rows: (partition, current, log_end) with current None for '-' (nothing committed)."""
    lines = []
    for partition, current, log_end in rows:
        lag = "-" if current is None else str(log_end - current)
        lines.append(f"{group}  {topic}  {partition}  {'-' if current is None else current}  {log_end}  {lag}  c1  /h  cl\n")
    return HEADER + "".join(lines)


class TestGroupClassification:
    G = "g1"

    def classify(self, stdout="", stderr="", rc=0):
        return H.classify_group_output(stdout, stderr, rc, self.G, TOPIC_SRC)

    def test_the_accepted_shape_is_still_accepted(self):
        classification, rows = self.classify(table(self.G, [(0, 10, 12), (1, 4, 4), (2, 7, 7)]))
        assert classification == H.GROUP_COMMITTED and rows == {0: H.GroupPartition(10, 12), 1: H.GroupPartition(4, 4),
                                                                2: H.GroupPartition(7, 7)}

    def test_a_formed_group_with_nothing_committed_keeps_none_and_is_never_zero(self):
        classification, rows = self.classify(table(self.G, [(0, None, 0), (1, None, 0), (2, None, 0)]))
        assert classification == H.GROUP_FORMED_NO_COMMIT
        assert all(row.current is None and row.log_end == 0 for row in rows.values())
        assert H.partitions_without_commit(rows) == [0, 1, 2] and H.committed_offsets(rows) == {0: None, 1: None, 2: None}

    def test_a_mixed_description_reports_which_partitions_have_no_commit(self):
        classification, rows = self.classify(table(self.G, [(0, 3, 5), (1, None, 2), (2, 0, 1)]))
        assert classification == H.GROUP_COMMITTED and H.partitions_without_commit(rows) == [1]
        assert rows[2].current == 0                                  # a real committed 0 is not 'unknown'

    def test_an_absent_group(self):
        assert self.classify("", "Error: Consumer group 'g1' does not exist.", 1) == (H.GROUP_ABSENT, None)
        assert self.classify("Consumer group 'g1' does not exist.", "", 0) == (H.GROUP_ABSENT, None)

    def test_a_cli_failure_is_not_an_absent_group(self):
        assert self.classify("", "Error: Executing consumer group command failed due to timeout", 1) == (H.GROUP_CLI_FAILURE, None)
        assert self.classify("Warning only", "", 2)[0] == H.GROUP_CLI_FAILURE

    def test_empty_stdout_with_a_message_on_stderr_and_exit_0_has_no_rows(self):
        assert self.classify("", "some warning", 0) == (H.GROUP_NO_ROWS, None)
        assert self.classify("", "", 0) == (H.GROUP_NO_ROWS, None)
        assert self.classify(HEADER, "", 0) == (H.GROUP_NO_ROWS, None)

    def test_rows_of_another_topic_or_group_do_not_count(self):
        assert self.classify(table(self.G, [(0, 1, 1), (1, 1, 1), (2, 1, 1)], topic="other.topic"))[0] == H.GROUP_NO_ROWS
        assert self.classify(table("someone-else", [(0, 1, 1), (1, 1, 1), (2, 1, 1)]))[0] == H.GROUP_NO_ROWS

    def test_missing_partition_rows_are_incomplete(self):
        assert self.classify(table(self.G, [(0, 1, 1), (2, 1, 1)])) == (H.GROUP_INCOMPLETE, None)

    def test_unreadable_rows_are_malformed(self):
        assert self.classify(table(self.G, [(0, 1, 1), (1, 1, 1), (2, 1, 1)]).replace("  1  1  0  c1", "  x  1  0  c1", 1))[0] == H.GROUP_MALFORMED
        short = HEADER + f"{self.G}  {TOPIC_SRC}  0  1  1\n"
        assert self.classify(short) == (H.GROUP_MALFORMED, None)
        assert self.classify(table(self.G, [(0, 1, 1), (1, 1, 1), (2, 1, 1), (3, 1, 1)]))[0] == H.GROUP_MALFORMED

    def test_parse_group_offsets_keeps_its_contract(self):
        assert H.parse_group_offsets(table(self.G, [(0, None, 0), (1, None, 0), (2, None, 0)]), self.G, TOPIC_SRC) is not None
        for bad in ("", "Consumer group 'g1' does not exist.", table(self.G, [(0, 1, 1)]), HEADER):
            assert H.parse_group_offsets(bad, self.G, TOPIC_SRC) is None


class TestBoundedExcerpts:
    def test_short_text_is_unchanged_and_none_is_empty(self):
        assert H.bounded_excerpt("  hello  ") == "hello" and H.bounded_excerpt("") == "" and H.bounded_excerpt(None) == ""

    def test_long_text_is_bounded_with_the_omitted_count(self):
        text = "A" * 5000 + "Z" * 5000
        excerpt = H.bounded_excerpt(text, 400)
        assert len(excerpt) < 500 and excerpt.startswith("A") and excerpt.endswith("Z")
        assert "chars omitted" in excerpt and f"[{10000 - 266 - 133} chars omitted]" in excerpt

    def test_credentials_and_secret_assignments_are_redacted_before_truncation(self, monkeypatch):
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "Zx9Qw8Er7Ty6Ui5Op4As3"})
        excerpt = H.bounded_excerpt("x " * 300 + "Zx9Qw8Er7Ty6Ui5Op4As3 PG_PASSWORD=abc123 " + "y " * 300, 5000)
        assert "Zx9Qw8Er7Ty6Ui5Op4As3" not in excerpt and "abc123" not in excerpt and "<redacted>" in excerpt


# ---------------------------------------------------------------------------
# T19  The polled read keeps what it saw
# ---------------------------------------------------------------------------

def group_router(outputs):
    """Answers kafka-consumer-groups calls from `outputs` in order (the last repeats); other commands succeed."""
    state = {"i": 0}

    def route(command):
        if "kafka-consumer-groups.sh" in " ".join(command):
            out = outputs[min(state["i"], len(outputs) - 1)]
            state["i"] += 1
            return Result(returncode=out[2] if len(out) > 2 else 0, stdout=out[0], stderr=out[1])
        return Result()
    route.state = state
    return route


class TestPolledReadDiagnostics:
    def env(self, tmp_path, outputs):
        router = group_router(outputs)
        env, shell = live_env(tmp_path, router)
        return env, shell, router

    def test_a_group_that_settles_after_several_attempts_is_returned_without_a_failure_record(self, tmp_path):
        good = table("G", [(0, None, 0), (1, None, 0), (2, None, 0)])
        env, _, router = self.env(tmp_path, [("", "", 0), ("", "no coordinator", 1), (good, "")])
        groups = env.group("G", TOPIC_SRC)
        assert router.state["i"] == 3 and H.partitions_without_commit(groups) == [0, 1, 2]
        assert env.tool_reads == []

    def test_an_unusable_description_fails_with_attempts_elapsed_time_and_bounded_output(self, tmp_path, monkeypatch):
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "Zx9Qw8Er7Ty6Ui5Op4As3"})
        noisy = ("line of output " * 2000) + " Zx9Qw8Er7Ty6Ui5Op4As3"
        env, _, router = self.env(tmp_path, [(noisy, "Error: coordinator not available DB_PASSWORD=hunter2", 1)])
        with pytest.raises(H.GroupReadError) as caught:
            env.group("G", TOPIC_SRC)
        error, read = caught.value, caught.value.read
        assert isinstance(error, SmokeFailure) and str(error).startswith("no stable description of group G")
        assert read.attempts == router.state["i"] > 1 and read.elapsed_seconds >= 30
        assert (read.returncode, read.classification, read.group_state) == (1, H.GROUP_CLI_FAILURE, "unknown")
        assert len(read.stdout_excerpt) < 500 and len(read.stderr_excerpt) < 500 and len(str(error)) < 1600
        assert "Zx9Qw8Er7Ty6Ui5Op4As3" not in str(error) and "hunter2" not in str(error)
        assert f"{read.attempts} attempt(s)" in str(error) and "cli-failure" in str(error)
        assert env.tool_reads == [read] and "kafka-consumer-groups --describe --group G" in read.purpose

    @pytest.mark.parametrize("output, classification, state", [
        (("", "", 0), H.GROUP_NO_ROWS, "unknown"),
        ((table("G", [(0, 1, 1)]), "", 0), H.GROUP_INCOMPLETE, "present"),
        ((table("G", [(0, 1, 1), (1, 1, 1), (2, 1, 1), (3, 1, 1)]), "", 0), H.GROUP_MALFORMED, "present"),
        (("", "Error: timeout", 1), H.GROUP_CLI_FAILURE, "unknown"),
    ])
    def test_the_failure_says_which_kind_of_failure_it_was(self, tmp_path, output, classification, state):
        env, _, _ = self.env(tmp_path, [output])
        with pytest.raises(H.GroupReadError) as caught:
            env.group("G", TOPIC_SRC)
        assert caught.value.read.classification == classification and caught.value.read.group_state == state

    def test_an_absent_group_is_remembered_and_falls_back_to_the_topic_end_offsets(self, tmp_path):
        def router(command):
            joined = " ".join(command)
            if "kafka-consumer-groups.sh" in joined:
                return Result(returncode=1, stderr="Consumer group 'G' does not exist.")
            if "kafka-get-offsets.sh" in joined:
                return Result(stdout=f"{TOPIC_SRC}:0:5 {TOPIC_SRC}:1:6 {TOPIC_SRC}:2:7")
            return Result()
        env, _ = live_env(tmp_path, router)
        groups = env.group("G", TOPIC_SRC)
        assert H.partitions_without_commit(groups) == [0, 1, 2] and [g.log_end for g in groups.values()] == [5, 6, 7]
        assert env.tool_reads[-1].classification == H.GROUP_ABSENT and env.tool_reads[-1].group_state == "absent"

    def test_only_the_last_few_failed_reads_are_kept(self, tmp_path):
        env, _, _ = self.env(tmp_path, [("", "", 0)])
        for _ in range(8):
            with pytest.raises(H.GroupReadError):
                env.group("G", TOPIC_SRC)
        assert len(env.tool_reads) == 5

    def test_the_timeout_is_still_thirty_seconds_of_polling(self, tmp_path):
        env, _, _ = self.env(tmp_path, [("", "", 0)])
        with pytest.raises(H.GroupReadError) as caught:
            env.group("G", TOPIC_SRC)
        assert 30 <= caught.value.read.elapsed_seconds < 40                  # one more attempt at most, no extension


# ---------------------------------------------------------------------------
# T20  The aborted-case snapshot
# ---------------------------------------------------------------------------

class SnapshotEnv(H.Env):
    """Raises on anything that would change a container."""

    def __init__(self, state=H.Inspect("running", 0, 2, False), logs="", inspect_error=None, logs_error=None):
        self.state, self.logs_text, self.inspect_error, self.logs_error = state, logs, inspect_error, logs_error
        self.tool_reads = []

    def inspect(self, service):
        if self.inspect_error:
            raise self.inspect_error
        return self.state

    def logs(self, service):
        if self.logs_error:
            raise self.logs_error
        return self.logs_text

    def start(self, service):
        raise AssertionError("a snapshot must not start anything")

    def stop(self, services):
        raise AssertionError("a snapshot must not stop anything")


class TestAbortedCaseSnapshot:
    def test_it_collects_the_state_and_a_bounded_log_tail(self):
        text = "\n".join(f"log line {i}" for i in range(100))
        snapshot = H.collect_snapshot(SnapshotEnv(logs=text))
        assert snapshot["service"] == "stream-processor" and snapshot["errors"] == []
        assert snapshot["state"] == {"status": "running", "exit_code": 0, "restarts": 2, "oom_killed": False}
        assert snapshot["log_lines_total"] == 100 and len(snapshot["log_tail"]) == 40
        assert snapshot["log_tail"][0] == "log line 60" and snapshot["log_tail"][-1] == "log line 99"

    def test_long_lines_are_bounded_and_secrets_are_redacted(self, monkeypatch):
        monkeypatch.setattr(smoke.RUN, "generated", {"POSTGRES_PASSWORD": "Zx9Qw8Er7Ty6Ui5Op4As3"})
        snapshot = H.collect_snapshot(SnapshotEnv(logs="Zx9Qw8Er7Ty6Ui5Op4As3 " + "x" * 5000 + "\nDB_PASSWORD=hunter2"))
        assert all(len(line) < 400 for line in snapshot["log_tail"])
        assert "Zx9Qw8Er7Ty6Ui5Op4As3" not in " ".join(snapshot["log_tail"]) and "hunter2" not in " ".join(snapshot["log_tail"])

    def test_a_failed_state_read_is_recorded_and_the_log_is_still_collected(self):
        snapshot = H.collect_snapshot(SnapshotEnv(logs="a\nb", inspect_error=SmokeFailure("unparsable docker inspect output")))
        assert snapshot["state"] is None and snapshot["log_tail"] == ["a", "b"]
        assert snapshot["errors"] and snapshot["errors"][0].startswith("state: SmokeFailure")

    def test_nothing_that_can_go_wrong_raises(self):
        for env in (SnapshotEnv(logs_error=OSError("x")), SnapshotEnv(inspect_error=OSError("y"), logs_error=RuntimeError("z"))):
            snapshot = H.collect_snapshot(env)
            assert snapshot["errors"] and snapshot["log_tail"] == []

    def test_the_failure_diagnostics_combine_the_reads_and_the_snapshot_without_repeating_a_read(self):
        read = H.ToolRead("purpose", 4, 31.0, 1, H.GROUP_CLI_FAILURE, "unknown", "out", "err")
        env = SnapshotEnv(logs="x")
        env.tool_reads = [read]
        diagnostics = H.failure_diagnostics(env, read)
        assert diagnostics["tool_reads"] == [read.to_dict()] and diagnostics["aborted_case_snapshot"]["log_tail"] == ["x"]
        other = H.ToolRead("other", 1, 0.0, 0, H.GROUP_NO_ROWS, "unknown", "", "")
        assert len(H.failure_diagnostics(env, other)["tool_reads"]) == 2


# ---------------------------------------------------------------------------
# T21  A setup failure in the whole live flow
# ---------------------------------------------------------------------------

class SetupFailureDocker(FlowDocker):
    """FlowDocker for S2: stops are tracked per service, and the Kafka group tool answers as configured."""

    def __init__(self, group_output=("", "Error: Executing consumer group command failed: boom", 1), logs_error=False, **kwargs):
        super().__init__(**kwargs)
        self.group_output, self.logs_error = group_output, logs_error
        self.stopped_services, self.log = set(), 0

    def __call__(self, command):
        joined = " ".join(command)
        if "compose" in command:
            verb = compose_verb(command)
            if verb == "stop":
                self.commands.append(list(command))
                self.stopped_services.update(c for c in command if c in H.APP_SERVICES)
                return Result()
            if verb == "up" and any(s in command for s in H.APP_SERVICES):
                self.stopped_services.difference_update(command)
            if verb == "exec" and "kafka-consumer-groups.sh" in joined:
                self.commands.append(list(command))
                stdout, stderr, code = self.group_output
                return Result(returncode=code, stdout=stdout, stderr=stderr)
            if verb == "logs" and command[-1] == "stream-processor":
                self.commands.append(list(command))
                if self.logs_error:
                    return Result(returncode=1, stderr="no such service")
                secret = next(iter(smoke.RUN.generated.values()), "")
                lines = [f"stream processor log line {i}" for i in range(59)] + [f"leaked {secret} DB_PASSWORD=hunter2"]
                return Result(stdout="\n".join(lines))
        if command[:2] == ["docker", "inspect"] and command[-1].startswith("cid-"):
            self.commands.append(list(command))
            service = command[-1][4:]
            if service in H.APP_SERVICES:
                return Result(stdout=("exited|0|0|false" if service in self.stopped_services else "running|0|0|false") + "\n")
        return super().__call__(command)


class TestSetupFailureInTheLiveFlow:
    cfg = H.Config(messages=60, idle_seconds=0.0)

    def run(self, docker, evidence_dir):
        shell = RecordingShell(docker)
        code = H.execute(flow_args(), ["S2"], self.cfg, sh=shell, preflight=fake_preflight, sleeper=lambda s: None,
                         clock=lambda c=iter(range(0, 1000000)): float(next(c)), evidence_dir=evidence_dir,
                         utc=lambda c=iter(range(1000)): f"2026-10-18T00:00:{next(c) % 60:02d}.000000+00:00")
        return code

    def files(self, evidence_dir):
        return {kind: json.loads(next(Path(evidence_dir).glob(f"*-{kind}.json")).read_text(encoding="utf-8"))
                for kind in ("pre-cleanup", "final")}

    def test_the_failed_read_and_the_snapshot_reach_both_evidence_files_before_cleanup(self, tmp_path, capsys):
        docker = SetupFailureDocker()
        code = self.run(docker, tmp_path / "ev")
        out = capsys.readouterr().out
        assert code == 1 and "overall: FAIL" in out and "cleanup verified: yes" in out and "evidence written: yes" in out
        assert "DIAGNOSTICS: 1 failed tool read(s); stream-processor state running" in out
        for kind, record in self.files(tmp_path / "ev").items():
            assert record["verdict"] == "FAIL" and record["failure"].startswith("no stable description of group")
            assert record["selected_cases"] == ["S2"]
            assert [c["name"] for c in record["cases"]] == ["S2"] and record["cases"][0]["partial"] is True
            assert record["cases"][0]["verdict"] == "FAIL" and record["cases"][0]["stops"] == []
            read = record["diagnostics"]["tool_reads"][0]
            assert read["classification"] == "cli-failure" and read["returncode"] == 1 and read["attempts"] > 1
            assert "boom" in read["stderr_excerpt"] and read["elapsed_seconds"] >= 30
            snapshot = record["diagnostics"]["aborted_case_snapshot"]
            assert snapshot["service"] == "stream-processor" and snapshot["state"]["status"] == "running"
            assert snapshot["log_lines_total"] == 60 and len(snapshot["log_tail"]) == 40 and snapshot["errors"] == []
        assert self.files(tmp_path / "ev")["final"]["cleanup"]["verified"] is True

    def test_the_snapshot_is_read_only_and_cleanup_still_runs_after_it(self, tmp_path):
        docker = SetupFailureDocker()
        self.run(docker, tmp_path / "ev")
        verbs = [compose_verb(c) if "compose" in c else " ".join(c[:2]) for c in docker.commands]
        last_group = max(i for i, c in enumerate(docker.commands) if "kafka-consumer-groups.sh" in " ".join(c))
        between = verbs[last_group + 1:verbs.index("down")]
        assert between and set(between) <= {"ps", "logs", "docker inspect"}, between
        assert "down" in verbs and verbs.index("down") > last_group

    def test_no_credential_reaches_the_evidence_or_the_output(self, tmp_path, capsys):
        self.run(SetupFailureDocker(), tmp_path / "ev")
        credentials = list(smoke.RUN.generated.values())
        text = capsys.readouterr().out + "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "ev").glob("*.json"))
        assert credentials and not any(value in text for value in credentials) and "hunter2" not in text

    def test_a_snapshot_that_cannot_be_collected_never_masks_the_failure_or_blocks_cleanup(self, tmp_path):
        docker = SetupFailureDocker(logs_error=True)
        code = self.run(docker, tmp_path / "ev")
        record = self.files(tmp_path / "ev")["final"]
        assert code == 1 and record["failure"].startswith("no stable description of group")
        assert record["diagnostics"]["aborted_case_snapshot"]["errors"] and record["cleanup"]["verified"] is True
        assert any("compose" in c and compose_verb(c) == "down" for c in docker.commands)

    def test_each_kind_of_unusable_output_is_classified_in_the_evidence(self, tmp_path):
        for index, (output, classification) in enumerate([
                (("", "", 0), "no-rows"), (("Consumer group 'x' has no active members.", "", 0), "no-active-members"),
                ((table(H.group_ids(PROJECT)[0], [(0, 1, 1)]), "", 0), "partitions-incomplete")]):
            directory = tmp_path / f"ev{index}"
            self.run(SetupFailureDocker(group_output=output), directory)
            assert self.files(directory)["final"]["diagnostics"]["tool_reads"][0]["classification"] == classification

    def test_a_run_that_does_not_abort_carries_no_diagnostics(self, tmp_path):
        shell = RecordingShell(HookedFlowDocker(tmp_path / "ev"))
        H.execute(flow_args(), ["S1"], H.Config(messages=60, idle_seconds=0.0), sh=shell, preflight=fake_preflight,
                  sleeper=lambda s: None, clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=tmp_path / "ev")
        assert "diagnostics" not in json.loads(next((tmp_path / "ev").glob("*-final.json")).read_text(encoding="utf-8"))


class TestUnknownCommitsAreVisibleInTheCaseMetrics:
    def test_s2_records_the_partitions_that_had_no_committed_offset_at_the_baseline(self):
        class FreshGroup(SimEnv):
            def group(self, group, topic):
                groups = super().group(group, topic)
                if not getattr(self, "_seen", False):
                    self._seen = True
                    return {p: H.GroupPartition(None, row.log_end) for p, row in groups.items()}
                return groups
        case = H.case_s2(FreshGroup(), CFG)
        assert case.verdict == "PASS", case.problems
        assert case.metrics["uncommitted_partitions_at_baseline"] == [0, 1, 2]

    def test_s2_s3_s4_metrics_keep_their_existing_keys(self):
        assert {"stop_seconds", "committed_at_stop", "duplicate_copies", "uncommitted_partitions_at_baseline"} <= set(
            H.case_s2(SimEnv(), CFG).metrics)
        for fn in (H.case_s3, H.case_s4):
            assert {"stop_seconds", "persisted_but_uncommitted", "batching_messages",
                    "uncommitted_partitions_at_baseline"} <= set(fn(SimEnv(), CFG).metrics)


# ======================================================================================================
# B3J-350: committed offsets after a stop, and the partial case record
# ======================================================================================================

def committed_json(offsets, highs=(5, 5, 5), lows=(0, 0, 0), errors=(), extra=None):
    """What COMMITTED_SOURCE prints; offsets uses H.OFFSET_INVALID for 'no commit'."""
    partitions = {str(p): {"offset": o, "error": None, "low": lows[p], "high": highs[p]} for p, o in enumerate(offsets)}
    partitions.update(extra or {})
    return json.dumps({"group": "g", "topic": TOPIC_SRC, "partitions": partitions, "errors": list(errors)})


NO_COMMIT = H.OFFSET_INVALID


class TestPostStopClassification:
    G = "g1"

    def test_a_stopped_group_that_lists_only_some_partitions_is_its_own_class_not_usable_as_a_whole_listing(self):
        stdout = table(self.G, [(0, 3, 5), (2, 4, 5)])
        stderr = f"Consumer group '{self.G}' has no active members."
        assert H.classify_group_output(stdout, stderr, 0, self.G, TOPIC_SRC) == (H.GROUP_NO_ACTIVE_MEMBERS, None)

    def test_the_strict_reader_still_refuses_that_listing(self):
        assert H.parse_group_offsets(table(self.G, [(0, 3, 5), (2, 4, 5)]), self.G, TOPIC_SRC) is None

    def test_a_complete_listing_is_still_accepted_with_the_no_members_message(self):
        stdout = table(self.G, [(0, 3, 5), (1, None, 5), (2, 4, 5)])
        classification, rows = H.classify_group_output(stdout, "has no active members", 0, self.G, TOPIC_SRC)
        assert classification == H.GROUP_COMMITTED and rows[1].current is None

    def test_the_message_with_a_failing_exit_is_a_cli_failure_not_a_stopped_group(self):
        assert H.classify_group_output("", "Consumer group 'g' has no active members.", 1, self.G, TOPIC_SRC) == (
            H.GROUP_CLI_FAILURE, None)

    def test_a_polled_read_does_not_accept_the_partial_listing_as_usable(self, tmp_path):
        router = group_router([(table("G", [(0, 3, 5)]), "Consumer group 'G' has no active members.", 0)])
        env, _ = live_env(tmp_path, router)
        with pytest.raises(H.GroupReadError) as caught:
            env.group("G", TOPIC_SRC)
        assert caught.value.read.classification == H.GROUP_NO_ACTIVE_MEMBERS


class TestParseCommittedOutput:
    def test_numeric_commits_are_kept_exactly(self):
        commits = H.parse_committed_output(committed_json([3, 0, 5], highs=(5, 4, 5)))
        assert {p: (c.state, c.offset, c.high) for p, c in commits.items()} == {
            0: ("committed", 3, 5), 1: ("committed", 0, 4), 2: ("committed", 5, 5)}

    def test_zero_is_a_real_commit_and_no_commit_is_a_different_state(self):
        commits = H.parse_committed_output(committed_json([0, NO_COMMIT, 2]))
        assert (commits[0].state, commits[0].offset) == ("committed", 0)
        assert (commits[1].state, commits[1].offset) == ("uncommitted", None)

    def test_the_end_offset_is_never_taken_as_the_committed_offset(self):
        commits = H.parse_committed_output(committed_json([NO_COMMIT] * 3, highs=(9, 9, 9)))
        assert all(c.offset is None and c.high == 9 for c in commits.values())

    @pytest.mark.parametrize("text, needle", [
        ("", "no usable result"), ("not json", "no usable result"), ('{"x": 1}', "no usable result"),
        ('{"partitions": {}, "errors": ["Boom: x"]}', "reported errors"),
    ])
    def test_unreadable_output_fails_closed(self, text, needle):
        with pytest.raises(H.PostStopError, match=needle):
            H.parse_committed_output(text)

    def test_a_missing_topic_partition_fails_closed(self):
        text = json.dumps({"partitions": {"0": {"offset": 1, "error": None, "low": 0, "high": 2},
                                           "2": {"offset": 1, "error": None, "low": 0, "high": 2}}, "errors": []})
        with pytest.raises(H.PostStopError, match="partition-set mismatch"):
            H.parse_committed_output(text)

    def test_an_extra_topic_partition_fails_closed(self):
        extra = {"3": {"offset": 1, "error": None, "low": 0, "high": 2}}
        with pytest.raises(H.PostStopError, match="partition-set mismatch"):
            H.parse_committed_output(committed_json([1, 1, 1], extra=extra))

    def test_a_per_partition_error_fails_closed(self):
        text = committed_json([1, 1, 1], extra={"1": {"offset": -1001, "error": "KafkaError{UNKNOWN_TOPIC}", "low": 0, "high": 5}})
        with pytest.raises(H.PostStopError, match="partition 1: Kafka returned an error"):
            H.parse_committed_output(text)

    @pytest.mark.parametrize("offset", [-1, -1000, -1002, -2, None, "3", 3.5, True])
    def test_an_ambiguous_or_non_integer_offset_fails_closed(self, offset):
        with pytest.raises(H.PostStopError):
            H.parse_committed_output(committed_json([offset, 1, 1]))

    def test_a_commit_beyond_the_end_offset_fails_closed(self):
        with pytest.raises(H.PostStopError, match="beyond the end offset"):
            H.parse_committed_output(committed_json([6, 1, 1], highs=(5, 5, 5)))

    def test_missing_end_offsets_fail_closed(self):
        text = json.dumps({"partitions": {str(p): {"offset": 1, "error": None, "low": 0} for p in range(3)}, "errors": []})
        with pytest.raises(H.PostStopError, match="unreadable answer"):
            H.parse_committed_output(text)

    def test_noise_before_the_json_line_is_ignored(self):
        assert len(H.parse_committed_output("warning: x\n" + committed_json([1, 1, 1]))) == 3


class TestCorroboration:
    G = "g1"

    def commits(self, offsets):
        return H.parse_committed_output(committed_json(offsets))

    def check(self, rows, offsets, stderr="", rc=0):
        return H.corroborate_with_cli(table(self.G, rows), stderr, rc, self.G, TOPIC_SRC, self.commits(offsets))

    def test_a_listing_that_matches_is_agreement(self):
        out = self.check([(0, 3, 5), (1, 4, 5), (2, 5, 5)], [3, 4, 5])
        assert out["agreement"] == "agreed" and out["unlisted_partitions"] == []

    def test_an_unlisted_partition_kafka_says_is_uncommitted_is_the_established_absence(self):
        out = self.check([(0, 3, 5), (2, 5, 5)], [3, NO_COMMIT, 5], stderr="Consumer group 'g1' has no active members.")
        assert out["agreement"] == "agreed" and out["unlisted_partitions"] == [1]
        assert out["cli_classification"] == H.GROUP_NO_ACTIVE_MEMBERS

    def test_an_unlisted_partition_kafka_says_is_committed_is_a_conflict(self):
        with pytest.raises(H.PostStopConflict, match="partition 1: Kafka answers committed offset 4"):
            self.check([(0, 3, 5), (2, 5, 5)], [3, 4, 5], stderr="has no active members")

    def test_a_listed_offset_that_differs_is_a_conflict(self):
        with pytest.raises(H.PostStopConflict, match="CLI shows 2, Kafka answers 3"):
            self.check([(0, 2, 5), (1, 4, 5), (2, 5, 5)], [3, 4, 5])

    def test_a_listed_dash_against_a_numeric_answer_is_a_conflict(self):
        with pytest.raises(H.PostStopConflict):
            self.check([(0, None, 5), (1, 4, 5), (2, 5, 5)], [3, 4, 5])

    def test_a_cli_failure_is_recorded_as_unavailable_not_as_agreement(self):
        out = H.corroborate_with_cli("", "Error: boom", 1, self.G, TOPIC_SRC, self.commits([3, 4, 5]))
        assert out["agreement"] == "unavailable" and out["cli_classification"] == H.GROUP_CLI_FAILURE

    def test_an_unreadable_row_is_recorded_as_unavailable(self):
        out = H.corroborate_with_cli(HEADER + f"{self.G} {TOPIC_SRC} 0 oops\n", "", 0, self.G, TOPIC_SRC, self.commits([3, 4, 5]))
        assert out["agreement"] == "unavailable"


def stopped_router(committed_stdout, committed_rc=0, listing=None, status="exited|0|0|false"):
    calls = []

    def route(command):
        calls.append(list(command))
        joined = " ".join(command)
        if command[:2] == ["docker", "inspect"]:
            return Result(stdout=status + "\n")
        if "compose" in command and compose_verb(command) == "ps":
            return Result(stdout="cid-x\n")
        if "compose" in command and compose_verb(command) == "run":
            return Result(returncode=committed_rc, stdout=committed_stdout, stderr="")
        if "kafka-consumer-groups.sh" in joined:
            out = listing or ("", "", 0)
            return Result(returncode=out[2], stdout=out[0], stderr=out[1])
        return Result()
    route.calls = calls
    return route


class TestLiveGroupAfterStop:
    G = "G"

    def env(self, tmp_path, **kwargs):
        router = stopped_router(**kwargs)
        env, shell = live_env(tmp_path, router)
        return env, router

    def agree_listing(self, offsets):
        rows = [(p, o, 5) for p, o in enumerate(offsets) if o != NO_COMMIT]
        return table(self.G, rows), "Consumer group 'G' has no active members.", 0

    def test_numeric_commits_are_returned_and_the_cli_is_only_a_cross_check(self, tmp_path):
        env, router = self.env(tmp_path, committed_stdout=committed_json([3, 4, 5]), listing=self.agree_listing([3, 4, 5]))
        out = env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")
        assert {p: g.current for p, g in out.groups.items()} == {0: 3, 1: 4, 2: 5}
        assert out.corroboration["agreement"] == "agreed"

    def test_an_uncommitted_partition_stays_none_and_is_never_zero_or_the_end_offset(self, tmp_path):
        env, _ = self.env(tmp_path, committed_stdout=committed_json([3, NO_COMMIT, 5], highs=(5, 9, 5)),
                          listing=self.agree_listing([3, NO_COMMIT, 5]))
        out = env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")
        assert out.groups[1].current is None and out.groups[1].log_end == 9
        assert H.committed_offsets(out.groups) == {0: 3, 1: None, 2: 5}
        assert out.commits[1].state == "uncommitted"

    def test_explicit_dash_rows_agree_with_uncommitted_answers(self, tmp_path):
        listing = (table(self.G, [(0, 3, 5), (1, None, 5), (2, 5, 5)]), "", 0)
        env, _ = self.env(tmp_path, committed_stdout=committed_json([3, NO_COMMIT, 5]), listing=listing)
        assert env.group_after_stop(self.G, TOPIC_SRC, "stream-processor").corroboration["agreement"] == "agreed"

    def test_it_refuses_while_the_consumer_is_still_running(self, tmp_path):
        env, router = self.env(tmp_path, committed_stdout=committed_json([3, 4, 5]), status="running|0|0|false")
        with pytest.raises(H.PostStopError, match="not stopped"):
            env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")
        assert not any("compose" in c and compose_verb(c) == "run" for c in router.calls)

    def test_it_runs_in_the_project_image_and_commits_nothing(self, tmp_path):
        env, router = self.env(tmp_path, committed_stdout=committed_json([3, 4, 5]), listing=self.agree_listing([3, 4, 5]))
        env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")
        run = next(c for c in router.calls if "compose" in c and compose_verb(c) == "run")
        assert "--rm" in run and "stream-processor" in run and run[-3] == H.COMMITTED_SOURCE and run[-2:] == [self.G, TOPIC_SRC]
        assert ".commit(" not in H.COMMITTED_SOURCE and ".subscribe(" not in H.COMMITTED_SOURCE
        assert ".assign(" not in H.COMMITTED_SOURCE and "OFFSET_END" not in H.COMMITTED_SOURCE

    def test_the_source_text_is_valid_python_with_the_broker_filled_in(self):
        compile(H.COMMITTED_SOURCE, "committed_source", "exec")
        assert H.BROKER in H.COMMITTED_SOURCE

    def test_a_failing_step_fails_closed_with_diagnostics(self, tmp_path):
        env, _ = self.env(tmp_path, committed_stdout="", committed_rc=1)
        with pytest.raises(H.PostStopError) as caught:
            env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")
        assert caught.value.detail["exit_status"] == 1

    def test_a_nonzero_exit_with_an_otherwise_valid_answer_still_fails_closed(self, tmp_path):
        env, _ = self.env(tmp_path, committed_stdout=committed_json([3, 4, 5]), committed_rc=1)
        with pytest.raises(H.PostStopError, match="exited 1"):
            env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")

    def test_a_conflict_between_cli_and_kafka_fails_closed(self, tmp_path):
        env, _ = self.env(tmp_path, committed_stdout=committed_json([3, 4, 5]), listing=self.agree_listing([3, NO_COMMIT, 5]))
        with pytest.raises(H.PostStopConflict):
            env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")

    def test_an_unusable_cli_does_not_block_a_complete_kafka_answer_but_is_recorded(self, tmp_path):
        env, _ = self.env(tmp_path, committed_stdout=committed_json([3, 4, 5]), listing=("", "Error: boom", 1))
        out = env.group_after_stop(self.G, TOPIC_SRC, "stream-processor")
        assert out.corroboration["agreement"] == "unavailable" and out.groups[0].current == 3

    def test_the_evidence_form_serialises(self, tmp_path):
        env, _ = self.env(tmp_path, committed_stdout=committed_json([3, NO_COMMIT, 5]), listing=self.agree_listing([3, NO_COMMIT, 5]))
        text = json.dumps(env.group_after_stop(self.G, TOPIC_SRC, "stream-processor").to_dict())
        assert json.loads(text)["partitions"]["1"] == {"state": "uncommitted", "offset": None, "low": 0, "high": 5}

    def test_the_pre_stop_read_is_still_strict(self, tmp_path):
        router = group_router([(table("G", [(0, 3, 5), (2, 4, 5)]), "Consumer group 'G' has no active members.", 0)])
        env, _ = live_env(tmp_path, router)
        with pytest.raises(H.GroupReadError):
            env.group("G", TOPIC_SRC)


def failing_after_stop(env, group, topic, service):
    raise H.PostStopError("synthetic: the committed offsets could not be established")


class TestCasesAfterTheStop:
    def test_s2_uses_the_post_stop_inspection_and_records_what_it_established(self):
        env = SimEnv()
        case = H.case_s2(env, CFG)
        assert case.verdict == "PASS", case.problems
        assert case.observations["post_stop_offsets"]["source"] == "Consumer.committed() per partition"
        assert case.observations["window"]["state"] == "inside" and case.partial is False

    def test_s3_and_s4_use_it_too(self):
        for fn in (H.case_s3, H.case_s4):
            case = fn(SimEnv(), CFG)
            assert case.verdict == "PASS", case.problems
            assert "post_stop_offsets" in case.observations

    def test_an_uncommitted_partition_after_the_stop_is_handled_as_none_without_a_false_failure(self):
        def hook(env, group, topic, service):
            groups = env.group(group, topic)
            commits = {p: H.PartitionCommit("uncommitted", None, 0, g.log_end) for p, g in groups.items()}
            return H.PostStopOffsets({p: H.GroupPartition(None, g.log_end) for p, g in groups.items()}, commits, {})
        case = H.case_s2(SimEnv(post_stop=hook), CFG)
        assert case.verdict == "PASS" and case.observations["post_stop_offsets"]["partitions"]["0"]["state"] == "uncommitted"

    def test_an_offset_that_runs_ahead_of_the_canonical_topic_is_still_a_failure(self):
        case = H.case_s2(SimEnv(sp_commit_early=True), CFG)
        assert case.verdict == "FAIL" and any("past message" in p for p in case.problems)

    def test_the_storage_offset_safety_assertion_is_unchanged(self):
        case = H.case_s3(SimEnv(st_commit_early=True), CFG)
        assert case.verdict == "FAIL" and any("committed to" in p for p in case.problems)

    @pytest.mark.parametrize("name", ["S2", "S3", "S4"])
    def test_a_failure_right_after_a_successful_stop_keeps_the_stop_and_the_original_exception(self, name):
        env = SimEnv(post_stop=failing_after_stop if name == "S2" else failing_on_call(2))
        with pytest.raises(H.PostStopError, match="synthetic") as caught:
            H.run_cases(env, CFG, [name])
        (partial,) = caught.value.partial_cases
        assert partial.name == name and partial.verdict == "FAIL" and partial.partial is True
        assert [s.service for s in partial.stops] == [("stream-processor" if name == "S2" else "storage-consumer")]
        assert partial.stops[0].exit_code == 0 and partial.stops[0].all_passed
        assert partial.observations["window"]["state"] == "inside" and "workload" in partial.observations
        assert "post_stop_offsets" not in partial.observations
        assert partial.observations["aborted"]["after_a_recorded_stop"] is True
        assert any("PostStopError" in p for p in partial.problems)

    def test_earlier_passed_cases_are_kept_ahead_of_the_partial_one(self):
        env = SimEnv(post_stop=failing_after_stop)
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(env, CFG, ["S1", "S2"])
        assert [(c.name, c.verdict) for c in caught.value.partial_cases] == [("S1", "PASS"), ("S2", "FAIL")]

    def test_a_partial_case_never_passes_and_nothing_is_invented(self):
        env = SimEnv(post_stop=failing_after_stop)
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(env, CFG, ["S2"])
        record = caught.value.partial_cases[0].to_dict()
        assert record["verdict"] == "FAIL" and set(record["metrics"]) <= {"uncommitted_partitions_at_baseline"} and "canonical_records_after_stop" not in record["observations"]

    def test_an_abort_before_anything_was_observed_records_no_stops_or_window(self):
        class Early(SimEnv):
            def group(self, group, topic):
                raise H.GroupReadError("never settled", H.ToolRead("p", 1, 0.0, 1, "cli-failure", "", "", ""))
        with pytest.raises(H.GroupReadError) as caught:
            H.run_cases(Early(), CFG, ["S2"])
        (partial,) = caught.value.partial_cases
        assert partial.stops == [] and set(partial.observations) == {"aborted"}

    def test_a_keyboard_interrupt_is_kept_as_a_partial_case_and_still_propagates(self):
        class Interrupted(SimEnv):
            def group_after_stop(self, *args):
                raise KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt) as caught:
            H.run_cases(Interrupted(), CFG, ["S2"])
        assert caught.value.partial_cases[0].partial is True

    def test_a_case_that_returns_normally_is_not_marked_partial(self):
        (case,) = H.run_cases(SimEnv(), CFG, ["S1"])
        assert case.partial is False and case.to_dict()["partial"] is False


class ExecSim(SimEnv):
    """SimEnv as the environment of execute(): the infrastructure steps are no-ops."""

    def __init__(self, project, override, env_file, sh, clock=None, sleeper=None, utc=None, **faults):
        super().__init__(**faults)
        self.sh = sh

    def compose(self, *args, **kwargs):
        return ""

    def inspect(self, service):
        if service in ("kafka-init", "db-bootstrap"):
            return H.Inspect("exited", 0, 0, False)
        return super().inspect(service)

    def logs(self, service):
        if self.running[service] or self.killed or self.stream_killed or H.GRACEFUL_MARKER in self.logs_text[service]:
            return self.logs_text[service]            # cumulative, as the container's log is, once a stop wrote its lines
        return self.timing_text(service) + f"x: {H.FIRST_SIGNAL_MARKER}.\nagentops {H.GRACEFUL_MARKER}.\n"


class TestPartialCaseEvidence:
    cfg = CFG

    def run(self, tmp_path, monkeypatch, docker=None, **faults):
        monkeypatch.setattr(H, "LiveEnv", lambda *a, **k: ExecSim(*a, **k, **faults))
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        args = flow_args()
        args.cases = "S2"
        docker = docker or FlowDocker()
        code = H.execute(args, ["S2"], self.cfg, sh=RecordingShell(docker), preflight=fake_preflight,
                         sleeper=lambda s: None, clock=lambda c=iter(range(0, 100000)): float(next(c)),
                         evidence_dir=tmp_path / "ev")
        return code, docker

    def files(self, tmp_path):
        return {kind: json.loads(next((tmp_path / "ev").glob(f"*-{kind}.json")).read_text(encoding="utf-8"))
                for kind in ("pre-cleanup", "final")}

    def test_both_files_carry_the_partial_case_with_the_stop_and_the_original_failure(self, tmp_path, monkeypatch, capsys):
        code, docker = self.run(tmp_path, monkeypatch, post_stop=failing_after_stop)
        out = capsys.readouterr().out
        assert code == 1 and "overall: FAIL" in out and "cleanup verified: yes" in out
        for kind, record in self.files(tmp_path).items():
            assert record["verdict"] == "FAIL" and record["failure"] == "synthetic: the committed offsets could not be established"
            (case,) = record["cases"]
            assert case["name"] == "S2" and case["verdict"] == "FAIL" and case["partial"] is True
            assert case["stops"][0]["service"] == "stream-processor" and case["stops"][0]["exit_code"] == 0
            assert case["observations"]["window"]["state"] == "inside"
            assert case["observations"]["aborted"] == {"after_a_recorded_stop": True, "exception": "PostStopError"}
        assert self.files(tmp_path)["final"]["cleanup"]["verified"] is True

    def test_cleanup_runs_after_the_partial_failure(self, tmp_path, monkeypatch):
        _, docker = self.run(tmp_path, monkeypatch, post_stop=failing_after_stop)
        verbs = [compose_verb(c) for c in docker.commands if "compose" in c]
        assert "down" in verbs

    def test_an_evidence_write_failure_does_not_mask_the_original_failure(self, tmp_path, monkeypatch, capsys):
        def refuse(*args, **kwargs):
            raise OSError("disk full")
        monkeypatch.setattr(H, "write_evidence", refuse)
        code, _ = self.run(tmp_path, monkeypatch, post_stop=failing_after_stop)
        out = capsys.readouterr().out
        assert code == 1 and "FAILURE: synthetic: the committed offsets could not be established" in out
        assert "EVIDENCE PROBLEM" in out and "cleanup verified: yes" in out

    def test_credentials_in_the_failure_text_are_redacted_from_the_partial_evidence(self, tmp_path, monkeypatch):
        def leak(env, group, topic, service):
            raise H.PostStopError("failed with DB_PASSWORD=hunter2 in the message")
        self.run(tmp_path, monkeypatch, post_stop=leak)
        text = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "ev").glob("*.json"))
        assert "hunter2" not in text and json.loads(next((tmp_path / "ev").glob("*-final.json")).read_text(encoding="utf-8"))

    def test_a_good_run_has_no_partial_case(self, tmp_path, monkeypatch):
        code, _ = self.run(tmp_path, monkeypatch)
        record = self.files(tmp_path)["final"]
        assert code == 0 and record["cases"][0]["partial"] is False and record["cases"][0]["verdict"] == "PASS"
        assert "post_stop_offsets" in record["cases"][0]["observations"]


class TestEarlierCasesStillBehave:
    def test_s1_is_unchanged_and_has_no_post_stop_observation(self):
        case = H.case_s1(SimEnv(), CFG)
        assert case.verdict == "PASS" and "post_stop_offsets" not in case.observations

    def test_a_failing_case_still_stops_the_run_without_an_exception(self):
        results = H.run_cases(SimEnv(sp_commit_early=True), CFG, ["S2", "S3"])
        assert [c.name for c in results] == ["S2"] and results[0].verdict == "FAIL" and results[0].partial is False


# ======================================================================================================
# B3J-354: the baseline of S3/S4 is read from a STOPPED group; the aborted-case snapshot follows the case
# ======================================================================================================

class CliLikeSim(SimEnv):
    """SimEnv whose strict group() behaves like the real CLI for a group without active members: a stopped
    consumer's group cannot be described (no rows, 'has no active members'), so group() raises GroupReadError.
    The authoritative group_after_stop() is unaffected.  Every strict read is recorded with the state of the
    consumer at that moment."""

    def __init__(self, **faults):
        user = faults.get("post_stop")

        def hook(env, group, topic, service):
            answer = user(env, group, topic, service) if user is not None else None
            if answer is not None:
                return answer
            # Kafka reports "no commit" for a partition nothing was ever committed on (the sim's 0).
            plain = {p: row for p, row in SimEnv.group(env, group, topic).items()}
            commits = {p: H.PartitionCommit("uncommitted" if row.current == 0 else "committed",
                                            None if row.current == 0 else row.current, 0, row.log_end)
                       for p, row in plain.items()}
            return H.PostStopOffsets({p: H.GroupPartition(c.offset, c.high) for p, c in commits.items()}, commits,
                                     {"agreement": "agreed"})
        super().__init__(**{**faults, "post_stop": hook})
        self.strict_reads = []
        self.after_stop_calls = []

    def group(self, group, topic):
        service = "stream-processor" if topic == H.SOURCE_TOPIC else "storage-consumer"
        self.strict_reads.append((topic, self.running[service]))
        if not self.running[service]:
            raise H.GroupReadError(
                f"no stable description of group {group} on {topic}",
                H.ToolRead("kafka-consumer-groups --describe", 30, 30.0, 0, H.GROUP_NO_ACTIVE_MEMBERS, "present",
                           "", "Consumer group 'x' has no active members."))
        return super().group(group, topic)

    def group_after_stop(self, group, topic, service):
        self.after_stop_calls.append((topic, service))
        return super().group_after_stop(group, topic, service)


def offsets_from(env, topic, committed):
    """A PostStopOffsets for `topic` with the given committed offsets (None = uncommitted) and the real ends."""
    ends = {p: row.log_end for p, row in SimEnv.group(env, "g", topic).items()}
    commits = {p: H.PartitionCommit("uncommitted" if c is None else "committed", c, 0, ends[p])
               for p, c in enumerate(committed)}
    return H.PostStopOffsets({p: H.GroupPartition(c.offset, c.high) for p, c in commits.items()}, commits,
                             {"agreement": "agreed"})


def failing_on_call(n, error=None):
    """A post_stop hook that passes through, except that call number n raises."""
    calls = []

    def hook(env, group, topic, service):
        calls.append(service)
        if len(calls) == n:
            raise error or H.PostStopError("synthetic: the committed offsets could not be established")
        return None
    return hook


class TestStoppedGroupBaseline:
    @pytest.mark.parametrize("fn, name", [(H.case_s3, "S3"), (H.case_s4, "S4")])
    def test_a_first_run_group_with_nothing_committed_gets_a_baseline_while_stopped(self, fn, name):
        env = CliLikeSim()
        case = fn(env, CFG)
        assert case.verdict == "PASS", case.problems
        baseline = case.observations["baseline"]
        assert baseline["progress_baseline"] == 0 and baseline["backlog_records"] == CFG.messages * CFG.spans
        assert baseline["counted_as_zero_in_progress_sum_only"] == [0, 1, 2]
        assert case.metrics["uncommitted_partitions_at_baseline"] == [0, 1, 2]
        assert env.after_stop_calls[0] == (H.CANONICAL_TOPIC, "storage-consumer")

    def test_the_authoritative_record_keeps_none_and_the_ends_apart_and_is_valid_json(self):
        case = H.case_s3(CliLikeSim(), CFG)
        offsets = case.observations["baseline"]["offsets"]["partitions"]
        assert {p: (v["state"], v["offset"]) for p, v in offsets.items()} == {
            "0": ("uncommitted", None), "1": ("uncommitted", None), "2": ("uncommitted", None)}
        assert all(v["high"] > 0 for v in offsets.values())
        assert json.loads(json.dumps(case.to_dict()))["observations"]["baseline"]["offsets"]["partitions"]["0"]["offset"] is None

    def test_a_mix_of_numeric_commits_and_uncommitted_partitions(self):
        def hook(env, group, topic, service):
            if hook.calls == 0:
                hook.calls += 1
                return offsets_from(env, topic, [0, None, 0])
            return None
        hook.calls = 0
        case = H.case_s3(CliLikeSim(post_stop=hook), CFG)
        baseline = case.observations["baseline"]
        assert baseline["counted_as_zero_in_progress_sum_only"] == [1]
        assert {p: v["offset"] for p, v in baseline["offsets"]["partitions"].items()} == {"0": 0, "1": None, "2": 0}

    def test_numeric_commits_are_added_to_the_progress_baseline_and_none_is_counted_as_zero_only_there(self):
        groups = {0: H.GroupPartition(7, 20), 1: H.GroupPartition(None, 30), 2: H.GroupPartition(0, 10)}
        assert H.progress_baseline(groups) == (7, 53, [1])
        assert groups[1].current is None and H.committed_offsets(groups) == {0: 7, 1: None, 2: 0}

    def test_an_ambiguous_or_missing_authoritative_baseline_fails_closed_before_the_consumer_starts(self):
        env = CliLikeSim(post_stop=failing_on_call(1))
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(env, CFG, ["S3"])
        (partial,) = caught.value.partial_cases
        assert partial.verdict == "FAIL" and partial.partial and partial.stops == []
        assert env.running["storage-consumer"] is False and "baseline" not in partial.observations

    def test_the_consumer_must_be_exited_at_baseline(self):
        class StillRunning(CliLikeSim):
            def stop(self, services):
                return super().stop([s for s in services if s != "storage-consumer"])
        with pytest.raises(H.PostStopError, match="not stopped") as caught:
            H.run_cases(StillRunning(), CFG, ["S3"])
        assert caught.value.partial_cases[0].stops == []

    def test_the_live_reader_establishes_a_baseline_for_a_stopped_group_that_the_cli_cannot_describe(self, tmp_path):
        router = stopped_router(committed_stdout=committed_json([NO_COMMIT] * 3, highs=(2, 2, 2)),
                                listing=("", "Consumer group 'G' has no active members.", 0))
        env, _ = live_env(tmp_path, router)
        out = env.group_after_stop("G", H.CANONICAL_TOPIC, "storage-consumer")
        assert H.committed_offsets(out.groups) == {0: None, 1: None, 2: None} and out.corroboration["agreement"] == "agreed"
        with pytest.raises(H.GroupReadError):                                 # the strict reader still cannot
            env.group("G", H.CANONICAL_TOPIC)

    def test_a_group_the_cli_calls_absent_is_corroborated_when_kafka_says_nothing_is_committed(self, tmp_path):
        router = stopped_router(committed_stdout=committed_json([NO_COMMIT] * 3),
                                listing=("", "Error: Consumer group 'G' does not exist.", 1))
        env, _ = live_env(tmp_path, router)
        assert env.group_after_stop("G", H.CANONICAL_TOPIC, "storage-consumer").corroboration["agreement"] == "agreed"

    def test_strict_reads_happen_only_while_the_consumer_runs(self):
        env = CliLikeSim()
        H.case_s3(env, CFG)
        storage_reads = [running for topic, running in env.strict_reads if topic == H.CANONICAL_TOPIC]
        assert storage_reads and all(storage_reads)

    def test_the_window_requirement_is_unchanged(self):
        assert H.Config().window == (0.10, 0.70) and CFG.window == (0.10, 0.70)
        case = H.case_s3(CliLikeSim(), CFG)
        assert case.observations["window"] == {"state": "inside", "required_range": [0.10, 0.70]}
        missed = H.case_s3(CliLikeSim(instant=True), CFG)
        assert missed.verdict == "INCONCLUSIVE" and missed.stops == []

    def test_s2_is_unchanged(self):
        env = CliLikeSim()
        case = H.case_s2(env, CFG)
        assert case.verdict == "PASS", case.problems
        assert "baseline" not in case.observations
        assert all(running for topic, running in env.strict_reads if topic == H.SOURCE_TOPIC)
        assert env.after_stop_calls == [(H.SOURCE_TOPIC, "stream-processor")]

    def test_the_offset_safety_assertions_are_unchanged(self):
        case = H.case_s3(CliLikeSim(st_commit_early=True), CFG)
        assert case.verdict == "FAIL" and any("committed to" in p for p in case.problems)
        assert H.case_s2(CliLikeSim(sp_commit_early=True), CFG).verdict == "FAIL"

    def test_row_accounting_is_unchanged(self):
        expected = {("t", "a"), ("t", "b")}
        rows = [H.Row("t", "a", 0, 0), H.Row("t", "a", 0, 0)]
        accounting = H.account_rows(expected, rows)
        assert (accounting.missing, accounting.unexpected, accounting.duplicate_copies) == (1, 0, 1)


class TestServiceAwareSnapshot:
    @pytest.mark.parametrize("name, service", [("S1", "stream-processor"), ("S2", "stream-processor"),
                                                ("S3", "storage-consumer"), ("S4", "storage-consumer")])
    def test_each_case_is_snapshotted_on_its_own_service(self, name, service):
        env = SnapshotEnv(logs="a\nb")
        env.current_case = H.Case(name, "FAIL")
        result = H.failure_diagnostics(env)
        assert result["aborted_case_snapshot"]["service"] == service and "aborted_case_snapshots" not in result

    @pytest.mark.parametrize("current", [None, H.Case("S9", "FAIL")])
    def test_an_unknown_or_missing_case_snapshots_both_services(self, current):
        env = SnapshotEnv(logs="a\nb")
        env.current_case = current
        result = H.failure_diagnostics(env)
        assert result["aborted_case_snapshot"]["service"] == "stream-processor"
        assert [s["service"] for s in result["aborted_case_snapshots"]] == ["stream-processor", "storage-consumer"]

    def test_the_snapshot_is_read_only(self):
        env = SnapshotEnv(logs="a")
        env.current_case = H.Case("S3", "FAIL")
        H.failure_diagnostics(env)                                            # start/stop would raise AssertionError

    def test_a_broken_case_object_or_service_cannot_mask_anything(self):
        class Broken(SnapshotEnv):
            @property
            def current_case(self):
                raise RuntimeError("boom")

            @current_case.setter
            def current_case(self, value):
                pass
        result = H.failure_diagnostics(Broken(inspect_error=RuntimeError("no state"), logs_error=RuntimeError("no logs")))
        assert [s["service"] for s in result["aborted_case_snapshots"]] == ["stream-processor", "storage-consumer"]
        assert all(len(s["errors"]) == 2 for s in result["aborted_case_snapshots"])


class TestS3AbortEvidence:
    cfg = CFG

    def run(self, tmp_path, monkeypatch, case="S3", **faults):
        monkeypatch.setattr(H, "LiveEnv", lambda *a, **k: ExecSimCli(*a, **k, **faults))
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        args = flow_args()
        args.cases = case
        code = H.execute(args, [case], self.cfg, sh=RecordingShell(FlowDocker()), preflight=fake_preflight,
                         sleeper=lambda s: None, clock=lambda c=iter(range(0, 100000)): float(next(c)),
                         evidence_dir=tmp_path / "ev")
        return code, {kind: json.loads(next((tmp_path / "ev").glob(f"*-{kind}.json")).read_text(encoding="utf-8"))
                      for kind in ("pre-cleanup", "final")}

    def test_an_s3_failure_after_the_stop_snapshots_the_storage_consumer_in_both_files(self, tmp_path, monkeypatch):
        code, files = self.run(tmp_path, monkeypatch, post_stop=failing_on_call(2))
        assert code == 1
        for record in files.values():
            assert record["verdict"] == "FAIL" and record["failure"].startswith("synthetic")
            assert record["diagnostics"]["aborted_case_snapshot"]["service"] == "storage-consumer"
            (case,) = record["cases"]
            assert case["name"] == "S3" and case["partial"] is True and case["stops"][0]["service"] == "storage-consumer"
            assert case["observations"]["baseline"]["offsets"]["partitions"]["0"]["offset"] is None
        assert files["final"]["cleanup"]["verified"] is True

    def test_an_s3_failure_at_the_baseline_keeps_the_original_exception(self, tmp_path, monkeypatch):
        _, files = self.run(tmp_path, monkeypatch, post_stop=failing_on_call(1))
        record = files["final"]
        assert record["failure"].startswith("synthetic") and record["cases"][0]["stops"] == []
        assert record["diagnostics"]["aborted_case_snapshot"]["service"] == "storage-consumer"

    def test_an_s2_failure_still_snapshots_the_stream_processor(self, tmp_path, monkeypatch):
        _, files = self.run(tmp_path, monkeypatch, case="S2", post_stop=failing_on_call(1))
        assert files["final"]["diagnostics"]["aborted_case_snapshot"]["service"] == "stream-processor"

    def test_a_failing_snapshot_never_masks_the_original_failure_or_blocks_cleanup(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(H, "collect_snapshot", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("snapshot broke")))
        code, files = self.run(tmp_path, monkeypatch, post_stop=failing_on_call(2))
        out = capsys.readouterr().out
        assert code == 1 and files["final"]["failure"].startswith("synthetic") and files["final"]["cleanup"]["verified"] is True
        assert "DIAGNOSTICS could not be collected" in out and "diagnostics" not in files["final"]

    def test_the_partial_evidence_stays_valid_json_and_redacted(self, tmp_path, monkeypatch):
        def leak(env, group, topic, service):
            raise H.PostStopError('failed with DB_PASSWORD=hunter2", "x": "y')
        self.run(tmp_path, monkeypatch, post_stop=leak)
        text = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "ev").glob("*.json"))
        assert "hunter2" not in text
        for path in (tmp_path / "ev").glob("*.json"):
            assert json.loads(path.read_text(encoding="utf-8"))["diagnostics"]["aborted_case_snapshot"]["service"] == "storage-consumer"


class ExecSimCli(CliLikeSim):
    """CliLikeSim as the environment of execute()."""

    def __init__(self, project, override, env_file, sh, clock=None, sleeper=None, utc=None, **faults):
        super().__init__(**faults)
        self.sh = sh

    def compose(self, *args, **kwargs):
        return ""

    def inspect(self, service):
        if service in ("kafka-init", "db-bootstrap"):
            return H.Inspect("exited", 0, 0, False)
        return super().inspect(service)

    def logs(self, service):
        if self.running[service]:
            return self.logs_text[service]
        return (self.timing_text(service) + f"x: {H.FIRST_SIGNAL_MARKER}." + chr(10)
                + f"agentops {H.GRACEFUL_MARKER}." + chr(10))


# ======================================================================================================
# B3J-356: the S3/S4 baseline is trusted only when every low watermark is 0 and no commit is below it
# ======================================================================================================

def offsets_with(env, topic, committed, lows=(0, 0, 0)):
    """Like offsets_from, with explicit low watermarks in the per-partition records."""
    ends = {p: row.log_end for p, row in SimEnv.group(env, "g", topic).items()}
    commits = {p: H.PartitionCommit("uncommitted" if c is None else "committed", c, lows[p], ends[p])
               for p, c in enumerate(committed)}
    return H.PostStopOffsets({p: H.GroupPartition(c.offset, c.high) for p, c in commits.items()}, commits,
                             {"agreement": "agreed"})


def baseline_hook(committed, lows=(0, 0, 0)):
    """A post_stop hook that answers the FIRST call (the S3/S4 baseline) with the given record."""
    state = {"calls": 0}

    def hook(env, group, topic, service):
        state["calls"] += 1
        return offsets_with(env, topic, committed, lows) if state["calls"] == 1 else None
    return hook


def direct(commits):
    """A PostStopOffsets built directly from PartitionCommit values."""
    return H.PostStopOffsets({p: H.GroupPartition(c.offset, c.high) for p, c in commits.items()}, dict(commits), {})


def commit(offset, low=0, high=10):
    return H.PartitionCommit("uncommitted" if offset is None else "committed", offset, low, high)


class TestZeroLowWatermarkGuard:
    @pytest.mark.parametrize("fn", [H.case_s3, H.case_s4])
    def test_zero_low_watermarks_proceed_normally(self, fn):
        case = fn(CliLikeSim(), CFG)
        assert case.verdict == "PASS", case.problems
        lows = {v["low"] for v in case.observations["baseline"]["offsets"]["partitions"].values()}
        assert lows == {0} and "baseline_rejected" not in case.observations

    @pytest.mark.parametrize("name", ["S3", "S4"])
    def test_one_positive_low_watermark_is_refused(self, name):
        env = CliLikeSim(post_stop=baseline_hook([None, None, None], lows=(0, 4, 0)))
        with pytest.raises(H.PostStopError, match="partition 1: low watermark 4 is not 0") as caught:
            H.run_cases(env, CFG, [name])
        (partial,) = caught.value.partial_cases
        assert partial.name == name and partial.verdict == "FAIL" and partial.partial and partial.stops == []

    def test_a_committed_offset_below_its_low_watermark_is_refused(self):
        with pytest.raises(H.PostStopError, match="committed offset 2 is below the low watermark 3"):
            H.require_zero_low_baseline(direct({0: commit(2, low=3), 1: commit(None), 2: commit(None)}))

    def test_a_committed_offset_equal_to_a_zero_low_watermark_is_accepted(self):
        H.require_zero_low_baseline(direct({0: commit(0), 1: commit(None), 2: commit(None)}))

    def test_a_committed_offset_above_a_zero_low_watermark_is_accepted(self):
        H.require_zero_low_baseline(direct({0: commit(5), 1: commit(9, high=9), 2: commit(1)}))

    def test_an_uncommitted_partition_with_low_zero_keeps_none(self):
        post_stop = direct({0: commit(None), 1: commit(None), 2: commit(None)})
        H.require_zero_low_baseline(post_stop)
        assert H.committed_offsets(post_stop.groups) == {0: None, 1: None, 2: None}
        assert post_stop.to_dict()["partitions"]["0"]["offset"] is None

    @pytest.mark.parametrize("bad", [None, "0", 0.0, False, True, -1, 1])
    def test_a_missing_or_malformed_low_watermark_is_refused(self, bad):
        with pytest.raises(H.PostStopError, match="partition 1"):
            H.require_zero_low_baseline(direct({0: commit(None), 1: H.PartitionCommit("uncommitted", None, bad, 10),
                                                2: commit(None)}))

    def test_one_invalid_partition_rejects_the_whole_baseline(self):
        with pytest.raises(H.PostStopError) as caught:
            H.require_zero_low_baseline(direct({0: commit(3), 1: commit(None), 2: commit(4, low=2)}))
        assert "partition 2" in str(caught.value) and "partition 0" not in str(caught.value)

    def test_ambiguous_states_and_partition_mismatches_are_refused(self):
        with pytest.raises(H.PostStopError, match="ambiguous state"):
            H.require_zero_low_baseline(direct({0: H.PartitionCommit("committed?", None, 0, 5), 1: commit(None),
                                                2: commit(None)}))
        with pytest.raises(H.PostStopError, match="ambiguous state"):
            H.require_zero_low_baseline(direct({0: H.PartitionCommit("uncommitted", 3, 0, 5), 1: commit(None),
                                                2: commit(None)}))
        mismatch = direct({0: commit(None), 1: commit(None), 2: commit(None)})
        del mismatch.groups[2]
        with pytest.raises(H.PostStopError, match="do not match"):
            H.require_zero_low_baseline(mismatch)

    def test_the_guard_does_not_alter_or_clamp_the_record(self):
        post_stop = direct({0: commit(5), 1: commit(None), 2: commit(1)})
        before = post_stop.to_dict()
        H.require_zero_low_baseline(post_stop)
        assert post_stop.to_dict() == before

    @pytest.mark.parametrize("name", ["S3", "S4"])
    def test_a_refusal_happens_before_the_window_loop_and_before_the_consumer_starts(self, name):
        env = CliLikeSim(post_stop=baseline_hook([None, None, None], lows=(2, 0, 0)))
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(env, CFG, [name])
        assert env.strict_reads == [] and env.running["storage-consumer"] is False
        assert env.after_stop_calls == [(H.CANONICAL_TOPIC, "storage-consumer")]
        partial = caught.value.partial_cases[0]
        assert "workload" not in partial.observations and "window" not in partial.observations
        assert partial.observations["baseline_rejected"]["offsets"]["partitions"]["0"]["low"] == 2

    def test_a_refusal_is_a_failed_partial_case_never_a_pass(self):
        env = CliLikeSim(post_stop=baseline_hook([None, None, None], lows=(0, 0, 1)))
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(env, CFG, ["S3"])
        record = caught.value.partial_cases[0].to_dict()
        assert record["verdict"] == "FAIL" and record["partial"] is True
        assert any("PostStopError" in p for p in record["problems"]) and json.loads(json.dumps(record))

    def test_s2_does_not_apply_the_guard(self):
        env = CliLikeSim(post_stop=baseline_hook([None, None, None], lows=(3, 3, 3)))
        assert H.case_s2(env, CFG).verdict == "PASS"

    def test_a_refusal_reaches_both_evidence_files_and_survives_a_broken_snapshot(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(H, "collect_snapshot", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("snapshot broke")))
        run = TestS3AbortEvidence()
        code, files = run.run(tmp_path, monkeypatch, post_stop=baseline_hook([None, None, None], lows=(0, 7, 0)))
        out = capsys.readouterr().out
        assert code == 1 and "DIAGNOSTICS could not be collected" in out
        for record in files.values():
            assert record["verdict"] == "FAIL" and "partition 1: low watermark 7 is not 0" in record["failure"]
            (case,) = record["cases"]
            assert case["partial"] is True and case["verdict"] == "FAIL" and case["stops"] == []
            assert case["observations"]["baseline_rejected"]["offsets"]["partitions"]["1"]["low"] == 7
        assert files["final"]["cleanup"]["verified"] is True

    def test_the_refusal_is_redacted_and_valid_json_with_a_normal_snapshot(self, tmp_path, monkeypatch):
        run = TestS3AbortEvidence()
        run.run(tmp_path, monkeypatch, post_stop=baseline_hook([None, None, None], lows=(5, 0, 0)))
        for path in (tmp_path / "ev").glob("*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            assert record["diagnostics"]["aborted_case_snapshot"]["service"] == "storage-consumer"

    def test_the_live_parser_still_reports_the_low_watermark_the_guard_reads(self):
        commits = H.parse_committed_output(committed_json([1, NO_COMMIT, 2], lows=(0, 3, 0)))
        assert [commits[p].low for p in range(3)] == [0, 3, 0]
        with pytest.raises(H.PostStopError, match="partition 1: low watermark 3"):
            H.require_zero_low_baseline(direct(commits))




# ======================================================================================================
# B3J-372: S4 stops at the first in-window observation, batching is proved by the consumer's own counters,
#          and the cleanup comparison tolerates only a verified default-bridge recreation
# ======================================================================================================

def timing_payload(messages, commits, *, kind="final", inserted=None, conflicts=0):
    inserted = messages - conflicts if inserted is None else inserted
    return {"kind": kind, "elapsed_s": 1.0, "counters": {"messages": messages, "idle_polls": 0, "inserted": inserted,
                                                          "conflicts": conflicts},
            "stages": {"kafka_commit": {"count": commits}, "poll": {"count": messages}}}


def timing_log(*payloads):
    return "".join(H.TIMING_LINE_PREFIX + json.dumps(p) + "\n" for p in payloads)


class TestTimingEvidence:
    def test_the_line_prefix_is_the_one_the_consumer_prints(self):
        source = (_REPO / "storage-consumer" / "timing.py").read_text(encoding="utf-8")
        assert f'LINE_PREFIX = "{H.TIMING_LINE_PREFIX}"' in source

    def test_the_counters_mean_what_the_proof_assumes(self):
        text = (_REPO / "storage-consumer" / "consumer.py").read_text(encoding="utf-8")
        commit = text[text.index("def _commit("):text.index("def flush(")]
        # a commit is recorded only after at least one partition was confirmed
        assert commit.index("if confirmed:") < commit.index('self.timing.record("kafka_commit"')
        batched = text[text.index("def _run_batched_loop("):]
        batched = batched[batched.index("polled = timing.clock()"):]                     # the timed branch
        # a message is counted only after it was persisted and recorded
        assert batched.index("process_message(msg, repository, timing)") < batched.index("batcher.record(msg)") \
            < batched.index('timing.count("messages")')
        original = text[text.index("    try:\n        while not shutdown_event.is_set():"):text.index("# Opt-in batched offset commits")]
        original = original[original.index("polled = timing.clock()"):]
        assert original.index("consumer.commit(message=msg, asynchronous=False)") < original.index('timing.record("kafka_commit"') \
            < original.index('timing.count("messages")')

    def test_a_batching_consumer_is_efficient_and_a_per_message_consumer_is_not(self):
        good = H.parse_timing_evidence(timing_log(timing_payload(1000, 21)), 50)
        assert good.status == "valid" and good.efficient and good.messages_per_commit == 47.62 and good.required_messages_per_commit == 12.5
        bad = H.parse_timing_evidence(timing_log(timing_payload(1000, 1000)), 50)
        assert bad.status == "valid" and not bad.efficient and "per commit" in bad.reasons[0]

    def test_the_threshold_sits_between_the_two_regimes(self):
        assert H.parse_timing_evidence(timing_log(timing_payload(1250, 100)), 50).efficient          # exactly the bar
        assert not H.parse_timing_evidence(timing_log(timing_payload(1249, 100)), 50).efficient

    @pytest.mark.parametrize("payloads, status", [
        ([], "missing"),
        ([timing_payload(100, 2, kind="window")], "missing"),                 # window lines alone are not the final summary
        ([timing_payload(100, 2), timing_payload(100, 2)], "ambiguous"),      # two processes cannot be told apart
        ([timing_payload(100, 2, inserted=5)], "ambiguous"),                  # inserted + conflicts != messages
        ([timing_payload(10, 11, inserted=10)], "ambiguous"),                 # more commits than messages
    ])
    def test_missing_or_contradictory_summaries_are_never_efficient(self, payloads, status):
        evidence = H.parse_timing_evidence(timing_log(*payloads), 50)
        assert evidence.status == status and not evidence.efficient and evidence.reasons

    @pytest.mark.parametrize("text", [
        H.TIMING_LINE_PREFIX + "{not json\n",
        H.TIMING_LINE_PREFIX + "[1, 2]\n",
        H.TIMING_LINE_PREFIX + json.dumps({"kind": "final"}) + "\n",
        H.TIMING_LINE_PREFIX + json.dumps(timing_payload(True, 1)) + "\n",
        H.TIMING_LINE_PREFIX + json.dumps(timing_payload(-5, 1)) + "\n",
        H.TIMING_LINE_PREFIX + json.dumps(timing_payload(10.5, 1)) + "\n",
        H.TIMING_LINE_PREFIX + "x" * (H.TIMING_LINE_LIMIT + 1) + "\n",
    ])
    def test_malformed_summaries_are_never_efficient(self, text):
        evidence = H.parse_timing_evidence(text, 50)
        assert evidence.status == "malformed" and not evidence.efficient

    def test_too_few_messages_or_no_commit_is_not_proof(self):
        few = H.parse_timing_evidence(timing_log(timing_payload(30, 1)), 50)
        assert few.status == "valid" and not few.efficient and "fewer than one batch" in few.reasons[0]
        none = H.parse_timing_evidence(timing_log(timing_payload(80, 0)), 50)
        assert none.status == "valid" and not none.efficient and "no Kafka commit" in none.reasons[0]

    def test_window_lines_and_unrelated_log_lines_are_ignored(self):
        logs = ("starting\n" + timing_log(timing_payload(40, 1, kind="window")) + "noise\n"
                + timing_log(timing_payload(500, 10)))
        evidence = H.parse_timing_evidence(logs, 50)
        assert evidence.status == "valid" and evidence.efficient and evidence.final_summaries == 1 and evidence.summary_lines == 2


class TestBatchingIsProvedByTheConsumersCounters:
    def test_batched_counters_pass_and_are_recorded(self):
        case = H.case_s4(SimEnv(), CFG)
        assert case.verdict == "PASS", case.problems
        timing = case.observations["timing_evidence"]
        assert timing["status"] == "valid" and timing["efficient"] is True and timing["final_summaries"] == 1
        assert timing["messages"] > timing["commits"] >= 1 and case.metrics["batching_exercised"] is True

    @pytest.mark.parametrize("faults, status, needle", [
        ({"per_message_commit": True}, "valid", "per commit"),
        ({"no_timing": True}, "missing", "no final timing summary"),
        ({"timing_garbage": True}, "malformed", "could not be read"),
        ({"timing_copies": 2}, "ambiguous", "cannot be told apart"),
        ({"timing_override": {"inserted": 1}}, "ambiguous", "inserted + conflicts"),
        ({"timing_override": {"commits": 10 ** 6}}, "ambiguous", "more commit calls"),
        ({"timing_override": {"commits": 0}}, "valid", "no Kafka commit"),
        ({"timing_override": {"messages": 3, "inserted": 3, "commits": 1}}, "valid", "fewer than one batch"),
    ])
    def test_unproven_batching_is_inconclusive_after_a_clean_stop(self, faults, status, needle):
        case = H.case_s4(SimEnv(**faults), CFG)
        assert case.verdict == "INCONCLUSIVE" and case.metrics["batching_exercised"] is False
        assert case.observations["timing_evidence"]["status"] == status
        assert any(needle in p for p in case.problems)
        assert case.stops and case.stops[0].all_passed                 # the stop and the safety checks still ran

    def test_an_unreadable_log_after_the_stop_is_inconclusive(self):
        class Unreadable(SimEnv):
            calls = 0

            def logs(self, service):
                if service == "storage-consumer" and not self.running[service]:
                    Unreadable.calls += 1
                    if Unreadable.calls == 2:                     # the first read belongs to the stop observation
                        raise H.SmokeFailure("compose logs failed")
                return super().logs(service)
        case = H.case_s4(Unreadable(), CFG)
        assert case.verdict == "INCONCLUSIVE" and case.observations["timing_evidence"]["status"] == "unreadable"

    def test_configured_batching_alone_is_not_proof(self):
        case = H.case_s4(SimEnv(no_timing=True), CFG)
        assert case.observations["batching_configuration"]["status"] == "verified" and case.verdict == "INCONCLUSIVE"

    def test_sampled_offsets_and_lag_never_prove_batching(self):
        samples = [{"t": 1.0, "committed": {"0": None}, "committed_progress": 0, "uncommitted_lag": 50},
                   {"t": 2.0, "committed": {"0": 500}, "committed_progress": 500, "uncommitted_lag": -1300}]
        summary = H.summarize_commit_samples(samples)
        assert "batching_exercised" not in summary and summary["commit_progress_observed"] is True
        assert summary["commit_changes"][0]["partitions"] == {"0": [None, 500]}
        assert H.case_s4(SimEnv(no_timing=True), CFG).verdict == "INCONCLUSIVE"       # progress was sampled, still no proof

    def test_offset_safety_failure_overrides_good_batching_evidence(self):
        case = H.case_s4(SimEnv(st_commit_early=True), CFG)
        assert case.verdict == "FAIL" and any("has no row" in p for p in case.problems)
        both = H.case_s4(SimEnv(st_commit_early=True, per_message_commit=True), CFG)
        assert both.verdict == "FAIL"

    def test_a_stale_summary_of_an_earlier_process_makes_it_ambiguous(self):
        class Stale(SimEnv):
            def start(self, service):
                first = not getattr(self, "_started", False)
                super().start(service)
                if service == "storage-consumer" and self.batching and first:
                    self._started = True
                    self.logs_text[service] += timing_log(timing_payload(900, 18))
        case = H.case_s4(Stale(), CFG)
        assert case.verdict == "INCONCLUSIVE" and case.observations["timing_evidence"]["status"] == "ambiguous"

    def test_the_summary_is_read_before_the_restart_so_the_drain_cannot_be_mixed_in(self):
        class RestartPrints(SimEnv):
            def start(self, service):
                super().start(service)
                if service == "storage-consumer" and self.stops >= 2:      # a restart after the S4 stop
                    self.logs_text[service] += timing_log(timing_payload(5000, 5000))
        case = H.case_s4(RestartPrints(), CFG)
        assert case.verdict == "PASS", case.problems
        assert case.observations["timing_evidence"]["final_summaries"] == 1

    def test_only_the_s4_override_enables_the_timing_summary(self):
        assert f'{H.TIMING_ENV_NAME}: "{H.TIMING_INTERVAL_SECONDS}"' in H.test_override_text(PROJECT, batching_messages=50)
        assert H.TIMING_ENV_NAME not in H.test_override_text(PROJECT)
        s3 = SimEnv()
        H.case_s3(s3, CFG)
        assert s3.batching_history == [None] and getattr(s3, "env_reads", 0) == 0


class TestS4StopsAtTheFirstValidObservation:
    class Spy(SimEnv):
        def __init__(self, **faults):
            super().__init__(**faults)
            self.events = []

        def group(self, group, topic):
            rows = super().group(group, topic)
            if topic == H.CANONICAL_TOPIC and self.running["storage-consumer"] and self.batching:
                self.events.append(("group", sum(r.current or 0 for r in rows.values())))
            return rows

        def stop(self, services):
            if "storage-consumer" in services and self.batching:
                self.events.append(("stop", None))
            return super().stop(services)

    @pytest.mark.parametrize("rate", [4, 20, 55, 100])
    def test_the_stop_follows_the_first_poll_inside_the_window(self, rate):
        env = self.Spy(rate=rate)
        case = H.case_s4(env, CFG)
        assert case.verdict == "PASS", case.problems
        kinds = [kind for kind, _ in env.events]
        cut = kinds.index("stop")
        assert kinds.count("stop") == 1 and cut > 0 and kinds[cut - 1] == "group"              # the stop follows a poll at once
        states = [H.window_state(done / 180, CFG.window) for kind, done in env.events[:cut]]
        assert states[-1] == "inside" and all(state == "before" for state in states[:-1])      # no polling after "inside"
        assert len(case.observations["commit_observations"]["samples"]) == len(states)

    def test_a_consumer_that_finishes_between_two_polls_is_inconclusive_not_stopped_late(self):
        case = H.case_s4(SimEnv(rate=1000), CFG)
        assert case.verdict == "INCONCLUSIVE" and case.stops == [] and case.observations["window"]["state"] == "after"

    def test_the_window_and_the_workload_are_unchanged(self):
        defaults = H.Config()
        assert defaults.window == (0.10, 0.70) and defaults.messages == 2000 and defaults.spans == 3
        assert defaults.window_timeout == 240.0 and defaults.batch_messages == 50


class TestEffectiveConfigurationIsVerified:
    def test_a_correct_configuration_is_recorded_and_the_case_passes(self):
        case = H.case_s4(SimEnv(), CFG)
        assert case.verdict == "PASS", case.problems
        check = case.observations["batching_configuration"]
        assert check["status"] == "verified" and check["problems"] == []
        assert check["observed_env"] == {H.BATCH_ENV_NAME: "10", H.INTERVAL_ENV_NAME: "30", H.TIMING_ENV_NAME: "30"}
        assert check["expected"] == check["observed_env"] and "batches of up to 10 messages" in check["startup_line"]

    @pytest.mark.parametrize("values", [
        {},
        {H.BATCH_ENV_NAME: "1", H.INTERVAL_ENV_NAME: "30", H.TIMING_ENV_NAME: "30"},
        {H.BATCH_ENV_NAME: "10", H.TIMING_ENV_NAME: "30"},
        {H.BATCH_ENV_NAME: "10", H.INTERVAL_ENV_NAME: "5", H.TIMING_ENV_NAME: "30"},
        {H.BATCH_ENV_NAME: "10", H.INTERVAL_ENV_NAME: "30"},                       # timing not enabled: no proof possible
    ])
    def test_an_absent_or_wrong_environment_fails_before_any_stop(self, values):
        case = H.case_s4(SimEnv(env_values=values), CFG)
        assert case.verdict == "FAIL" and case.stops == [] and case.partial is False
        assert any("in the container, expected" in p for p in case.problems)
        assert "commit_observations" not in case.observations and "window" not in case.observations

    def test_a_missing_startup_line_fails_after_waiting_and_keeps_a_redacted_log_tail(self):
        env = SimEnv(no_startup_line=True)
        env.logs_text["storage-consumer"] += "PG_PASSWORD=hunter2\n"
        case = H.case_s4(env, CFG)
        assert case.verdict == "FAIL" and case.stops == []
        check = case.observations["batching_configuration"]
        assert check["status"] == "mismatch" and check["startup_line"] is None and check["waited_seconds"] >= CFG.config_wait
        assert any("never appeared" in p for p in case.problems)
        assert "hunter2" not in json.dumps(case.to_dict()) and any("PG_PASSWORD" in line for line in check["log_tail"])

    def test_a_startup_line_with_other_numbers_fails(self):
        assert H.case_s4(SimEnv(startup_numbers=(1, 30)), CFG).verdict == "FAIL"
        assert H.case_s4(SimEnv(startup_numbers=(10, 5)), CFG).verdict == "FAIL"

    def test_an_environment_or_log_that_cannot_be_read_is_inconclusive_never_a_pass(self):
        case = H.case_s4(SimEnv(env_read_error=True), CFG)
        assert case.verdict == "INCONCLUSIVE" and case.stops == []
        assert case.observations["batching_configuration"]["status"] == "unverifiable"

        class LogBroken(SimEnv):
            def logs(self, service):
                if service == "storage-consumer" and self.running[service]:
                    raise H.SmokeFailure("compose logs failed")
                return super().logs(service)
        assert H.case_s4(LogBroken(), CFG).verdict == "INCONCLUSIVE"

    def test_only_the_named_variables_are_read_out_of_the_container(self, tmp_path):
        environment = json.dumps(["PG_PASSWORD=hunter2", f"{H.BATCH_ENV_NAME}=50", f"{H.INTERVAL_ENV_NAME}=30", "X=1"])
        env, shell = live_env(tmp_path, lambda c: Result(stdout="cid1\n" if "ps" in c else environment))
        found = env.container_env("storage-consumer", (H.BATCH_ENV_NAME, H.INTERVAL_ENV_NAME, "ABSENT"))
        assert found == {H.BATCH_ENV_NAME: "50", H.INTERVAL_ENV_NAME: "30", "ABSENT": None}
        assert shell.commands[-1][:2] == ["docker", "inspect"] and compose_verb(shell.commands[0]) == "ps" and len(shell.commands) == 2

    @pytest.mark.parametrize("raw", ["not json", '"a string"', "{}"])
    def test_an_unreadable_environment_is_an_error(self, tmp_path, raw):
        env, _ = live_env(tmp_path, lambda c: Result(stdout="cid1\n" if "ps" in c else raw))
        with pytest.raises(SmokeFailure):
            env.container_env("storage-consumer", (H.BATCH_ENV_NAME,))

    def test_s3_is_not_given_the_s4_verification(self):
        env = SimEnv()
        case = H.case_s3(env, CFG)
        assert case.verdict == "PASS" and getattr(env, "env_reads", 0) == 0
        assert "batching_configuration" not in case.observations and "timing_evidence" not in case.observations
        assert "batching_exercised" not in case.metrics and case.metrics["batching_messages"] is None


class TestRowEvidence:
    def test_final_row_accounting_is_recorded_with_its_zeros(self):
        case = H.case_s4(SimEnv(), CFG)
        assert case.observations["final_rows"] == {"rows": 180, "expected": 180, "missing": 0, "unexpected": 0,
                                                   "duplicate_copies": 0, "identity_mismatches": 0}
        assert case.observations["row_identity_at_stop"]["mismatches"] == 0

    def test_per_partition_evidence_at_the_stop(self):
        case = H.case_s4(SimEnv(), CFG)
        evidence = case.observations["partition_evidence_at_stop"]
        assert set(evidence["partitions"]) == {"0", "1", "2"} and evidence["partitions_progressed_count"] == 3
        assert sum(p["durable_rows"] for p in evidence["partitions"].values()) == case.observations["records_after_stop"]["rows"]
        assert all(p["committed_within_frontier"] for p in evidence["partitions"].values())
        json.dumps(case.to_dict())

    def test_the_frontier_is_the_first_canonical_offset_without_a_row_and_none_is_kept(self):
        canonical = [canon(1, i, 0, 0, i) for i in range(4)]
        rows = [H.Row(r.trace, r.span, r.partition, r.offset) for r in canonical if r.offset != 2]
        post = H.PostStopOffsets({0: H.GroupPartition(3, 4), 1: H.GroupPartition(None, 0)},
                                 {0: H.PartitionCommit("committed", 3, 0, 4), 1: H.PartitionCommit("uncommitted", None, 0, 0)}, {})
        evidence = H.partition_evidence(post, {0: H.GroupPartition(None, 4), 1: H.GroupPartition(None, 0)}, canonical, rows)
        assert evidence["partitions"]["0"]["durable_frontier"] == 2 and evidence["partitions"]["0"]["committed_within_frontier"] is False
        assert evidence["partitions"]["1"]["committed"] is None and evidence["partitions"]["1"]["progressed"] is False

    @pytest.mark.parametrize("bad_read, needle", [(1, "for"), (2, "after the drain")])
    def test_each_read_of_the_rows_is_checked_against_the_canonical_topic(self, bad_read, needle):
        class OneBadRead(SimEnv):
            reads = 0

            def rows(self):
                OneBadRead.reads += 1
                rows = super().rows()
                if OneBadRead.reads == bad_read:
                    rows = [H.Row(r.trace, r.span, r.partition, r.offset + 1) for r in rows]
                return rows
        case = H.case_s4(OneBadRead(), CFG)
        assert case.verdict == "FAIL" and sum("disagrees with the canonical topic" in p for p in case.problems) == 1
        assert any(needle in p for p in case.problems if "disagrees" in p)

    def test_s3_only_records_the_mismatch_its_criteria_are_unchanged(self):
        case = H.case_s3(SimEnv(row_offset_wrong=True), CFG)
        assert case.verdict == "PASS" and case.observations["row_identity_at_stop"]["mismatches"] > 0

    def test_a_replayed_canonical_record_has_two_acceptable_places(self):
        canonical = [canon(1, 0, 0, 0, 0), canon(1, 0, 0, 1, 7)]
        assert H.identity_mismatches(canonical, [H.Row(canonical[0].trace, canonical[0].span, 1, 7)]) == []
        assert len(H.identity_mismatches(canonical, [H.Row(canonical[0].trace, canonical[0].span, 1, 8)])) == 1
        assert "no canonical record" in H.identity_mismatches([], [H.Row("t", "s", 0, 0)])[0]


class TestPartialAndRegressions:
    def test_an_aborted_s4_keeps_what_it_observed(self):
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(SimEnv(post_stop=failing_on_call(2)), CFG, ["S4"])
        (partial,) = caught.value.partial_cases
        assert partial.partial is True and partial.verdict == "FAIL"
        assert partial.observations["batching_configuration"]["status"] == "verified"
        assert partial.observations["timing_evidence"]["status"] == "valid"
        json.dumps(partial.to_dict())

    def test_an_abort_during_sampling_keeps_the_samples_taken_so_far(self):
        class Dying(SimEnv):
            calls = 0

            def group(self, group, topic):
                if topic == H.CANONICAL_TOPIC and self.running["storage-consumer"]:
                    Dying.calls += 1
                    if Dying.calls == 3:
                        raise H.GroupReadError("synthetic", H.ToolRead("p", 1, 1.0, 1, H.GROUP_CLI_FAILURE, "unknown", "", ""))
                return super().group(group, topic)
        with pytest.raises(H.GroupReadError) as caught:
            H.run_cases(Dying(), CFG, ["S4"])
        (partial,) = caught.value.partial_cases
        assert len(partial.observations["commit_observations"]["samples"]) == 2

    def test_the_evidence_file_carries_the_new_observations_redacted(self, tmp_path):
        env = SimEnv()
        env.logs_text["storage-consumer"] += "PG_PASSWORD=hunter2\n"
        case = H.case_s4(env, CFG)
        record = H.build_evidence(kind="final", project=PROJECT, git_head=HEAD, git_state="committed", selected=["S4"],
                                  results=[case], failure="", verdict="PASS", started_utc="a", finished_utc="b")
        path, _ = H.write_evidence(tmp_path / "ev", PROJECT, "final", record, "20261018T000000000000Z")
        text = path.read_text(encoding="utf-8")
        loaded = json.loads(text)["cases"][0]["observations"]
        assert "hunter2" not in text and loaded["batching_configuration"]["status"] == "verified"
        assert loaded["timing_evidence"]["efficient"] is True and "final_rows" in loaded

    def test_s1_s2_and_s3_verdicts_and_metrics_are_unchanged(self):
        s1, s2, s3 = H.case_s1(SimEnv(), CFG), H.case_s2(SimEnv(), CFG), H.case_s3(SimEnv(), CFG)
        assert s1.verdict == s2.verdict == s3.verdict == "PASS"
        assert set(s3.metrics) == {"stop_seconds", "persisted_but_uncommitted", "batching_messages",
                                   "uncommitted_partitions_at_baseline"}
        assert "commit_observations" not in s2.observations and "batching_configuration" not in s2.observations
        assert "commit_observations" not in s3.observations
        assert H.case_s3(SimEnv(st_commit_early=True), CFG).verdict == "FAIL"
        assert H.case_s3(SimEnv(instant=True), CFG).verdict == "INCONCLUSIVE"

    def test_a_full_run_of_all_cases_still_passes(self):
        results = H.run_cases(SimEnv(), CFG, list(H.CASES))
        assert [c.name for c in results] == list(H.CASES) and all(c.verdict == "PASS" for c in results)


# ------------------------------------------------------------------------------------------------------
# Networks
# ------------------------------------------------------------------------------------------------------

def good_snapshot(sh=None, **kw):
    return H.read_network_snapshot(RecordingShell(FlowDocker(**kw)) if sh is None else sh)


class TestNetworkInspection:
    def test_a_default_bridge_and_both_protected_networks_are_read_and_verified(self):
        snap = good_snapshot()
        assert snap.bridge_verified and snap.bridge.id == "n1" and snap.bridge_problems == []
        assert set(snap.users) == set(H.USER_NETWORKS) and all(snap.users.values())

    @pytest.mark.parametrize("kwargs, needle", [
        ({"driver": "macvlan"}, "driver"), ({"scope": "swarm"}, "scope"), ({"internal": True}, "internal"),
        ({"labels": {"a": "b"}}, "labels"), ({"options": {}}, "not marked as the default bridge"),
        ({"attached": {"c1": "x"}}, "attached"),
    ])
    def test_anything_that_is_not_the_default_bridge_is_not_verified(self, kwargs, needle):
        docker = FlowDocker()
        docker.downed, docker.bridge_after = True, kwargs
        snap = H.read_network_snapshot(RecordingShell(docker))
        assert not snap.bridge_verified and any(needle in p for p in snap.bridge_problems)

    def test_two_bridges_or_none_are_not_verified(self):
        assert not good_snapshot(two_bridges=True).bridge_verified
        shell = RecordingShell(lambda c: Result(stdout="u1 agentops-mvp_mvp-net") if c[:3] == ["docker", "network", "ls"] else Result(returncode=1))
        with pytest.raises(SmokeFailure):
            H.read_network_snapshot(shell)

    def test_a_missing_protected_network_is_none_and_any_other_error_raises(self):
        assert good_snapshot(user_missing_before="agentops_agentops-net").users["agentops_agentops-net"] is None
        broken = RecordingShell(lambda c: Result(returncode=1, stderr="Cannot connect to the Docker daemon"))
        with pytest.raises(SmokeFailure):
            H.read_network(broken, "agentops_agentops-net")

    @pytest.mark.parametrize("text", ["not json", "{}", "[]", json.dumps([{}, {}]), json.dumps([{"Id": "x"}]),
                                      json.dumps([{"Id": "x", "Name": "n", "Driver": "d", "Scope": "s", "Created": "c",
                                                   "Internal": "no"}]),
                                      json.dumps([{"Id": "x", "Name": "n", "Driver": "d", "Scope": "s", "Created": "c",
                                                   "Internal": False, "Containers": {"c": {}}}])])
    def test_ambiguous_or_malformed_inspections_fail_closed(self, text):
        with pytest.raises(SmokeFailure):
            H.parse_network(text)

    def test_an_inspection_of_a_different_network_is_refused(self):
        shell = RecordingShell(lambda c: Result(stdout=net_json("zzz", "other")))
        with pytest.raises(SmokeFailure):
            H.read_network(shell, "agentops_agentops-net")

    def test_only_a_verified_bridge_line_is_normalised_and_only_exactly_once(self):
        inventory = {"networks": ["n1 bridge", "u1 agentops-mvp_mvp-net"], "volumes": []}
        normalised = H.normalise_bridge(inventory, good_snapshot())
        assert normalised["networks"] == sorted([H.BRIDGE_TOKEN + " bridge", "u1 agentops-mvp_mvp-net"])
        assert inventory["networks"][0] == "n1 bridge"                          # the input is not modified
        unverified = good_snapshot(two_bridges=True)
        assert H.normalise_bridge(inventory, unverified)["networks"] == inventory["networks"]
        assert H.normalise_bridge({"networks": ["n1 bridge", "n1 bridge"]}, good_snapshot())["networks"] == ["n1 bridge", "n1 bridge"]

    def test_the_comparison_accepts_a_verified_recreation_and_nothing_else(self):
        before = good_snapshot()
        after = good_snapshot(recreate_bridge=True)
        after_docker = FlowDocker(recreate_bridge=True)
        after_docker.downed, after_docker.bridge_id = True, "n2"
        after = H.read_network_snapshot(RecordingShell(after_docker))
        report = H.compare_networks(before, after)
        assert report["problems"] == [] and report["default_bridge"]["recreated"] is True
        assert report["default_bridge"]["treated_as"] == "informational"
        assert report["default_bridge"]["before"]["id"] == "n1" and report["default_bridge"]["after"]["id"] == "n2"
        assert report["default_bridge"]["before"]["created"] and report["user_defined"]["agentops_agentops-net"]["identical"]

    def _unverified_bridge_snapshot(self):
        docker = FlowDocker(bridge_after={"attached": {"c1": "intruder"}})
        docker.downed = True
        snap = H.read_network_snapshot(RecordingShell(docker))
        assert snap.bridge is not None and not snap.bridge_verified              # present, but not the clean default bridge
        return snap

    def test_a_bridge_that_is_present_but_unverified_is_not_normalised(self):
        inventory = {"networks": ["n1 bridge"]}
        assert H.normalise_bridge(inventory, self._unverified_bridge_snapshot())["networks"] == ["n1 bridge"]

    def test_an_unverified_bridge_is_a_problem_even_when_its_id_did_not_change(self):
        report = H.compare_networks(good_snapshot(), self._unverified_bridge_snapshot())
        assert any("could not be verified after the run" in p and "attached" in p for p in report["problems"])
        assert report["default_bridge"]["recreated"] is False and report["default_bridge"]["treated_as"] == "problem"
        reverse = H.compare_networks(self._unverified_bridge_snapshot(), good_snapshot())
        assert any("could not be verified before the run" in p for p in reverse["problems"])

    @pytest.mark.parametrize("name", list(H.USER_NETWORKS))
    @pytest.mark.parametrize("change, needle", [
        ({"missing": True}, "not found after"), ({"id": "other"}, "id"), ({"labels": {"x": "y"}}, "labels"),
        ({"options": {"o": "1"}}, "options"), ({"driver": "overlay"}, "driver"), ({"attached": {"c9": "intruder"}}, "attached"),
        ({"created": "2027-01-01T00:00:00Z"}, "created"),
    ])
    def test_a_protected_network_must_be_identical_in_every_field(self, name, change, needle):
        docker = FlowDocker(user_after={name: change})
        before = H.read_network_snapshot(RecordingShell(docker))
        docker.downed = True
        after = H.read_network_snapshot(RecordingShell(docker))
        problems = H.compare_networks(before, after)["problems"]
        assert any(name in p and needle in p for p in problems), problems


class TestProtectedSnapshotCoversAttachmentsAndMounts:
    def test_the_inspect_format_names_networks_and_mounts(self):
        shell = RecordingShell(lambda c: Result(stdout="i exited s f 0 nets=a:b, mounts=volume:v:/d:true,"))
        snapshot = H._protected_snapshot(shell)
        template = shell.commands[0][shell.commands[0].index("-f") + 1]
        assert "NetworkSettings.Networks" in template and ".Mounts" in template and template.startswith("{{.Id}} {{.State.Status}}")
        assert set(snapshot) == set(H.PROTECTED_CONTAINERS) and all(v.endswith("true,") for v in snapshot.values())

    def test_the_legacy_check_still_reads_the_state_field(self):
        assert H.batching.legacy_problem("i exited s f 0 nets=a:b, mounts=") is None
        assert H.batching.legacy_problem("i running s f 0 nets=a:b, mounts=")


class TestCleanupVerificationInTheLiveFlow:
    cfg = H.Config(messages=60, idle_seconds=0.0)

    def run(self, docker, tmp_path):
        shell = RecordingShell(docker)
        code = H.execute(flow_args(), ["S1"], self.cfg, sh=shell, preflight=fake_preflight, sleeper=lambda s: None,
                         clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=tmp_path / "ev",
                         utc=lambda c=iter(range(1000)): f"2026-10-18T00:00:{next(c) % 60:02d}.000000+00:00")
        final = json.loads(next((tmp_path / "ev").glob("*-final.json")).read_text(encoding="utf-8"))
        return code, shell, final

    def test_a_verified_bridge_recreation_alone_keeps_cleanup_verified(self, tmp_path, capsys):
        code, _, final = self.run(FlowDocker(recreate_bridge=True), tmp_path)
        assert code == 0 and "cleanup verified: yes" in capsys.readouterr().out and H.own_markers() == []
        bridge = final["cleanup"]["networks"]["default_bridge"]
        assert final["cleanup"]["verified"] is True and bridge["recreated"] is True and bridge["treated_as"] == "informational"
        assert bridge["before"]["id"] == "n1" and bridge["after"]["id"] == "n2" and final["cleanup"]["networks"]["problems"] == []
        assert final["cleanup"]["inventory_before"]["networks"] == final["cleanup"]["inventory_after"]["networks"]

    def test_without_a_recreation_the_run_is_verified_too(self, tmp_path):
        code, _, final = self.run(FlowDocker(), tmp_path)
        assert code == 0 and final["cleanup"]["networks"]["default_bridge"]["recreated"] is False

    @pytest.mark.parametrize("after", [{"driver": "macvlan"}, {"scope": "swarm"}, {"labels": {"a": "b"}}, {"options": {}},
                                       {"attached": {"c1": "x"}}, {"internal": True}])
    @pytest.mark.parametrize("recreate", [True, False])
    def test_a_default_bridge_that_does_not_verify_is_never_tolerated(self, tmp_path, after, recreate, capsys):
        code, _, final = self.run(FlowDocker(recreate_bridge=recreate, bridge_after=after), tmp_path)
        assert code == 1 and "cleanup verified: NO" in capsys.readouterr().out
        assert H.own_markers() == ["CLEANUP_UNVERIFIED"] and final["cleanup"]["verified"] is False
        assert final["cleanup"]["networks"]["default_bridge"]["treated_as"] == "problem"

    @pytest.mark.parametrize("change", [{"missing": True}, {"id": "u1x"}, {"labels": {"x": "y"}}, {"attached": {"c9": "intruder"}}])
    @pytest.mark.parametrize("name", list(H.USER_NETWORKS))
    def test_a_changed_or_deleted_protected_network_fails_cleanup_even_with_a_verified_bridge(self, tmp_path, name, change):
        code, _, final = self.run(FlowDocker(recreate_bridge=True, user_after={name: change}), tmp_path)
        assert code == 1 and final["cleanup"]["verified"] is False and H.own_markers() == ["CLEANUP_UNVERIFIED"]
        assert any(name in p for p in final["cleanup"]["networks"]["problems"])

    @pytest.mark.parametrize("value", ["i running s f 0 nets=agentops-mvp_mvp-net:u1,bridge:n1, mounts=",
                                       "i running s f 0 nets=agentops-mvp_mvp-net:u1, mounts=volume:extra:/x:true,"])
    def test_a_changed_protected_container_attachment_or_mount_fails_cleanup(self, tmp_path, value):
        code, _, final = self.run(FlowDocker(recreate_bridge=True, protected_after={"agentops-mvp-postgres-1": value}), tmp_path)
        assert code == 1 and final["cleanup"]["verified"] is False
        assert any("agentops-mvp-postgres-1 changed" in p for p in final["cleanup"]["problems"])

    def test_an_incomplete_disposable_cleanup_still_fails_with_a_recreated_bridge(self, tmp_path):
        code, _, final = self.run(FlowDocker(recreate_bridge=True, leftover=True), tmp_path)
        assert code == 1 and any("project networks left" in p for p in final["cleanup"]["problems"])

    def test_a_failed_teardown_still_fails_with_a_recreated_bridge(self, tmp_path):
        assert self.run(FlowDocker(recreate_bridge=True, down_code=1), tmp_path)[0] == 1

    def test_two_bridges_or_a_missing_protected_network_stop_the_run_before_anything_is_created(self, tmp_path):
        for docker in (FlowDocker(two_bridges=True), FlowDocker(user_missing_before="agentops_agentops-net")):
            shell = RecordingShell(docker)
            with pytest.raises(SmokeFailure, match="network preflight failed"):
                H.execute(flow_args(), ["S1"], self.cfg, sh=shell, preflight=fake_preflight, sleeper=lambda s: None,
                          clock=lambda: 0.0, evidence_dir=tmp_path / "ev")
            assert not any("compose" in c for c in shell.commands) and not any(c[:2] == ["docker", "image"] for c in shell.commands)
            assert H.own_markers() == []

    def test_the_marker_is_never_removed_by_a_run_or_its_cleanup(self, tmp_path):
        marker = H.write_marker("an earlier run left this")
        before = marker.read_text(encoding="utf-8")
        code, _, _ = self.run(FlowDocker(recreate_bridge=True), tmp_path)
        assert code == 0 and marker.exists() and marker.read_text(encoding="utf-8") == before

    def test_the_shared_cleanup_helper_is_not_modified(self):
        source = (_HERE / "run_pipeline_it.py").read_text(encoding="utf-8")
        assert "normalise_bridge" not in source and "BRIDGE_TOKEN" not in source


# ======================================================================================================
# B3J-382: S5, the forced termination of the storage consumer and the replay that must follow
# ======================================================================================================

CFG5 = H.Config(messages=60, spans=3, batch_messages=10, crash_batch_messages=10, crash_messages=30, crash_spans=4,
                idle_seconds=0.0, window_timeout=60.0, restart_wait=60.0, termination_wait=5.0)


def run_s5(**faults):
    env = SimEnv(**{"rate": 9, **faults})
    return env, H.case_s5(env, CFG5)


class TestS5CrashAndReplay:
    def test_a_kill_with_a_positive_replay_interval_passes_only_on_the_restarted_counters(self):
        env, case = run_s5()
        assert case.verdict == "PASS", case.problems
        assert env.kills == 1 and env.batching_history == [10, None] and env.no_restart is False   # restored afterwards
        prediction = case.observations["replay_prediction"]
        timing = case.observations["restarted_timing"]
        assert prediction["expected_conflicts"] > 0 and timing["status"] == "valid"
        assert (timing["messages"], timing["conflicts"], timing["inserted"]) == (
            prediction["expected_messages"], prediction["expected_conflicts"], prediction["expected_inserted"])
        assert case.metrics["persisted_but_uncommitted"] == case.observations["frozen_state"]["replay_interval_records"] > 0
        assert case.metrics["replay_conflicts"] == case.metrics["replay_predicted"]
        assert case.observations["termination"]["attributed_to_sigkill"] is True
        assert case.observations["final_rows"] == {"rows": 180, "expected": 180, "missing": 0, "unexpected": 0,
                                                   "duplicate_copies": 0, "identity_mismatches": 0}
        assert [s.service for s in case.stops] == ["storage-consumer"] and case.stops[0].all_passed     # the graceful stop after the drain

    def test_the_replay_interval_is_computed_per_partition_from_the_frozen_state(self):
        _, case = run_s5()
        parts = case.observations["frozen_state"]["partitions"]
        assert set(parts) == {"0", "1", "2"}
        for part in parts.values():
            start, frontier = part["replay_interval"]
            assert start == part["restart_position"] <= frontier == part["durable_frontier"] == part["durable_rows"]
            assert part["replay_records"] == frontier - start
        assert sum(p["replay_records"] for p in parts.values()) == case.observations["replay_prediction"]["expected_conflicts"]
        assert case.observations["replay_prediction"]["replay_ranges"] == {k: v["replay_interval"] for k, v in parts.items()}

    def test_a_correct_final_row_count_alone_is_not_replay(self):
        env, case = run_s5(no_timing=True)
        assert case.observations["final_rows"]["missing"] == 0 and case.observations["final_rows"]["duplicate_copies"] == 0
        assert case.verdict == "INCONCLUSIVE" and any("attempted but is not observed" in p for p in case.problems)

    @pytest.mark.parametrize("faults", [{"timing_garbage": True}, {"timing_copies": 2}, {"no_timing": True}])
    def test_missing_malformed_or_ambiguous_counters_are_inconclusive(self, faults):
        _, case = run_s5(**faults)
        assert case.verdict == "INCONCLUSIVE" and case.observations["restarted_timing"]["status"] != "valid"

    @pytest.mark.parametrize("override, needle", [
        ({"conflicts": 0, "inserted": 160}, "conflicts"),                                  # no replay although one was due
        ({"conflicts": 99, "inserted": 61}, "conflicts"),
        ({"messages": 100, "inserted": 93, "conflicts": 7}, "messages"),                   # it did not restart at the commits
    ])
    def test_counters_that_disagree_with_the_prediction_are_a_failure(self, override, needle):
        _, case = run_s5(timing_override=override)
        assert case.verdict == "FAIL" and any(needle in p and "predicts" in p for p in case.problems)

    def test_an_inserted_mismatch_alone_is_a_failure(self):
        _, case = run_s5(timing_override={"inserted": 150, "conflicts": 10})
        assert case.verdict == "FAIL"

    def test_no_replay_interval_is_inconclusive_and_nothing_is_restarted(self):
        env, case = run_s5(rate=10)                       # every message was committed at the moment of the kill
        assert case.verdict == "INCONCLUSIVE" and any("no durable-but-uncommitted interval" in p for p in case.problems)
        assert env.kills == 1 and env.stops == 1 and case.stops == [] and case.metrics["persisted_but_uncommitted"] == 0

    def test_a_consumer_that_commits_every_message_leaves_nothing_to_replay(self):
        _, case = run_s5(per_message_commit=True)
        assert case.verdict == "INCONCLUSIVE" and case.metrics["persisted_but_uncommitted"] == 0

    def test_a_consumer_that_finished_before_the_kill_is_inconclusive_and_not_killed(self):
        env, case = run_s5(rate=1000)
        assert case.verdict == "INCONCLUSIVE" and env.kills == 0 and "nothing was killed" in case.problems[0]


class TestS5KillScopingAndRestartPolicy:
    @pytest.mark.parametrize("faults, needle", [
        ({"kill_id_mismatch": True}, "disagree about the container id"),
        ({"kill_wrong_project": True}, "project label"),
        ({"kill_wrong_service": True}, "service label"),
        ({"kill_protected_name": True}, "protected container"),
        ({"others_down": "kafka"}, "kafka is 'exited'"),
        ({"others_down": "postgres"}, "postgres is 'exited'"),
    ])
    def test_a_target_that_does_not_verify_is_never_killed(self, faults, needle):
        env, case = run_s5(**faults)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE"
        refusals = case.observations["kill_target"]["refusals"]
        assert case.observations["kill_target"]["verified"] is False and any(needle in r for r in refusals), refusals
        assert "nothing was killed" in case.problems[0]

    def test_a_container_id_that_matches_a_protected_container_is_never_killed(self):
        env = SimEnv(rate=9)
        env.protected_ids = frozenset({env.cid})
        case = H.case_s5(env, CFG5)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE" and "matches a protected container" in case.problems[0]

    def test_a_stopped_stream_processor_blocks_the_kill(self):
        class Down(SimEnv):
            def inspect(self, service):
                if service == "stream-processor":
                    return H.Inspect("exited", 0, 0, False)
                return super().inspect(service)
        env = Down(rate=9)
        case = H.case_s5(env, CFG5)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE" and "stream-processor is 'exited'" in case.problems[0]

    def test_a_short_or_non_hex_id_and_a_foreign_name_are_refused(self):
        env = SimEnv()
        env.no_restart = True
        good = env.kill_target("storage-consumer")
        assert H.verify_kill_target(env, good) == []
        for changed in (dataclasses_replace(good, container_id="abc", inspected_id="abc"),
                        dataclasses_replace(good, name="/other-storage-consumer-1"),
                        dataclasses_replace(good, status="exited"),
                        dataclasses_replace(good, restart_policy="unless-stopped")):
            assert H.verify_kill_target(env, changed), changed

    def test_an_undisposable_project_is_refused(self):
        env = SimEnv()
        for name in ("agentops", "", "agentops-shutdown-it-xyz"):
            env.project = name
            assert any("not a disposable" in p for p in H.verify_kill_target(env, env.kill_target("storage-consumer")))

    @pytest.mark.parametrize("faults, needle", [({"policy_wrong": True}, "unless-stopped"), ({"policy_error": True}, "unreadable")])
    def test_a_restart_policy_other_than_no_stops_the_case_before_any_kill(self, faults, needle):
        env, case = run_s5(**faults)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE" and needle in case.observations["restart_policy"]["observed"]
        assert "restart policy" in case.problems[0]

    def test_the_s5_override_alone_sets_restart_no(self):
        assert '    restart: "no"' in H.test_override_text(PROJECT, batching_messages=500, no_restart=True)
        for text in (H.test_override_text(PROJECT), H.test_override_text(PROJECT, batching_messages=50)):
            assert "restart" not in text
        env, _ = run_s5()
        assert env.batching_history[0] == 10

    def test_the_kill_command_is_one_exact_project_scoped_command(self, tmp_path):
        def router(command):
            return Result(stdout="c" * 64 + "\n") if "ps" in command else Result()
        env, shell = live_env(tmp_path, router)
        result = env.kill("storage-consumer", "c" * 64)
        command = shell.commands[-1]
        assert result.returncode == 0 and command[:4] == ["docker", "compose", "-p", PROJECT]
        assert command[-4:] == ["kill", "-s", "SIGKILL", "storage-consumer"] and H.kill_arguments_allowed(command[-4:])
        assert not any(c[:2] == ["docker", "kill"] for c in shell.commands)

    def test_a_kill_of_anything_else_or_of_a_changed_container_is_refused_before_any_command(self, tmp_path):
        env, shell = live_env(tmp_path, lambda c: Result(stdout="d" * 64 + "\n"))
        with pytest.raises(SmokeFailure):
            env.kill("stream-processor", "d" * 64)
        with pytest.raises(SmokeFailure, match="no longer the one"):
            env.kill("storage-consumer", "c" * 64)
        assert not any("kill" in c for c in shell.commands)
        assert not H.kill_arguments_allowed(("kill", "storage-consumer")) and not H.kill_arguments_allowed(("kill", "-s", "SIGKILL"))
        assert not H.kill_arguments_allowed(("kill", "-s", "SIGTERM", "storage-consumer"))

    def test_the_source_issues_a_kill_in_exactly_one_place(self):
        source = (_HERE / "run_shutdown_it.py").read_text(encoding="utf-8")
        assert source.count("self.cmd(*kill_arguments(case))") == 1 and '"docker", "kill"' not in source
        assert "os.kill" not in source and "taskkill" not in source.lower()

    def test_the_inspections_that_gate_the_kill_are_parsed_strictly(self, tmp_path):
        ident = "a" * 64
        out = f"{ident}|{PROJECT}|storage-consumer|/{PROJECT}-storage-consumer-1|running|no"
        env, _ = live_env(tmp_path, lambda c: Result(stdout=ident + "\n" if "ps" in c else out))
        target = env.kill_target("storage-consumer")
        assert (target.container_id, target.inspected_id, target.project_label, target.service_label, target.restart_policy) == (
            ident, ident, PROJECT, "storage-consumer", "no")
        bad, _ = live_env(tmp_path, lambda c: Result(stdout=ident + "\n" if "ps" in c else "a|b"))
        with pytest.raises(SmokeFailure):
            bad.kill_target("storage-consumer")
        facts = f"{ident}|exited|137|false|0||2026-10-18T00:00:00Z"
        env2, _ = live_env(tmp_path, lambda c: Result(stdout=ident + "\n" if "ps" in c else facts))
        assert env2.termination_facts("storage-consumer") == H.TerminationFacts(ident, "exited", 137, False, 0, "", "2026-10-18T00:00:00Z")
        for broken in ("x|y", f"{ident}|exited|abc|false|0||t"):
            env3, _ = live_env(tmp_path, lambda c, b=broken: Result(stdout=ident + "\n" if "ps" in c else b))
            with pytest.raises(SmokeFailure):
                env3.termination_facts("storage-consumer")


def dataclasses_replace(obj, **changes):
    import dataclasses
    return dataclasses.replace(obj, **changes)


class TestS5Termination:
    @pytest.mark.parametrize("faults, needle", [
        ({"kill_miss": True}, "not exited"),
        ({"kill_rc": 1}, "returned 1"),
        ({"kill_exit_code": 1}, "exit code 1"),
        ({"kill_exit_code": 0}, "exit code 0"),
        ({"kill_exit_code": 255}, "exit code 255"),
        ({"kill_oom": True}, "OOM-killed"),
        ({"kill_new_container": True}, "container id changed"),
        ({"kill_restarts": 1}, "restart count 0 -> 1"),
        ({"kill_graceful": True}, "graceful-shutdown diagnostics"),
        ({"kill_final_summary": True}, "final timing summary"),
    ])
    def test_a_termination_that_cannot_be_attributed_to_sigkill_is_inconclusive(self, faults, needle):
        env, case = run_s5(**faults)
        assert case.verdict == "INCONCLUSIVE" and case.stops == [] and env.stops == 1          # nothing was restarted
        assert any("cannot be attributed" in p and needle in p for p in case.problems), case.problems
        assert case.observations["termination"]["attributed_to_sigkill"] is False

    def test_the_exit_code_alone_is_not_the_proof(self):
        record = H.attribute_termination(
            H.KillResult(0, 0.1), H.KillTarget("a" * 64, "a" * 64, PROJECT, "storage-consumer", "n", "running", "no"),
            H.TerminationFacts("a" * 64, "exited", 137, False, 0, "", "t"), (1, 1), 0, 0)
        assert record[0] and record[1]["attributed_to_sigkill"] is False

    def test_the_observations_are_recorded_even_when_attribution_fails(self):
        _, case = run_s5(kill_exit_code=1)
        assert case.observations["termination"]["facts"]["exit_code"] == 1 and "frozen_state" not in case.observations


class TestS5FrozenStateAndSafety:
    def test_a_committed_offset_ahead_of_a_durable_row_is_a_failure(self):
        _, case = run_s5(st_commit_early=True)
        assert case.verdict == "FAIL" and any("has no row" in p for p in case.problems)

    def test_durable_offsets_that_are_not_contiguous_are_a_failure(self):
        class Gap(SimEnv):
            def rows(self):
                return [r for r in super().rows() if not (r.partition == 0 and r.offset == 2)]
        env = Gap(rate=9)
        case = H.case_s5(env, CFG5)
        assert case.verdict == "FAIL" and any("not contiguous" in p for p in case.problems)

    def test_rows_that_keep_changing_after_the_kill_are_inconclusive(self):
        class Moving(SimEnv):
            calls = 0

            def rows(self):
                Moving.calls += 1
                return super().rows() + [H.Row("t", f"s{Moving.calls}", 0, 1000 + Moving.calls)]
        case = H.case_s5(Moving(rate=9), CFG5)
        assert case.verdict == "INCONCLUSIVE" and "still changing" in case.problems[0]

    def test_an_uncommitted_partition_restarts_at_the_verified_low_watermark(self):
        canonical = [canon(1, i, 0, 0, i) for i in range(6)]
        rows = [H.Row(r.trace, r.span, r.partition, r.offset) for r in canonical[:4]]
        post = H.PostStopOffsets(
            {0: H.GroupPartition(None, 6), 1: H.GroupPartition(2, 2)},
            {0: H.PartitionCommit("uncommitted", None, 0, 6), 1: H.PartitionCommit("committed", 2, 0, 2)}, {})
        frozen = H.analyse_frozen_state(post, canonical, rows)
        p0 = frozen.prediction.partitions["0"]
        assert p0["committed"] is None and p0["restart_position"] == 0 and p0["durable_frontier"] == 4
        assert p0["replay_interval"] == [0, 4] and frozen.prediction.replay_total == 4
        assert (frozen.prediction.messages, frozen.prediction.conflicts, frozen.prediction.inserted) == (6, 4, 2)
        assert frozen.fail_problems == [] and frozen.inconclusive == []

    def test_a_low_watermark_that_is_not_zero_stops_the_case_without_a_guess(self):
        def hook(env, group, topic, service):
            if env.kills:
                groups = SimEnv.group(env, group, topic)
                return H.PostStopOffsets(groups, {p: H.PartitionCommit("committed", g.current, 5, g.log_end) for p, g in groups.items()}, {})
            return None
        with pytest.raises(H.PostStopError, match="S5 frozen state cannot be trusted") as caught:
            H.run_cases(SimEnv(rate=9, post_stop=hook), CFG5, ["S5"])
        (partial,) = caught.value.partial_cases
        assert partial.name == "S5" and partial.partial is True and partial.observations["termination"]["attributed_to_sigkill"]

    def test_committed_offsets_that_move_while_the_consumer_is_dead_are_a_failure(self):
        calls = []

        def hook(env, group, topic, service):
            calls.append(1)
            if len(calls) == 3:                                         # the re-check just before the restart
                groups = SimEnv.group(env, group, topic)
                bumped = {p: H.GroupPartition((g.current or 0) + (1 if p == 0 else 0), g.log_end) for p, g in groups.items()}
                return H.PostStopOffsets(bumped, {p: H.PartitionCommit("committed", g.current, 0, g.log_end) for p, g in bumped.items()}, {})
            return None
        env, case = run_s5(post_stop=hook)
        assert case.verdict == "FAIL" and "moved while the consumer was dead" in case.problems[0]
        assert "committed_moved_before_restart" in case.observations and env.stops == 1

    def test_canonical_duplicates_make_the_prediction_ambiguous_and_inconclusive(self):
        canonical = [canon(1, 0, 0, 0, 0), canon(1, 0, 0, 0, 1)]
        post = H.PostStopOffsets({0: H.GroupPartition(0, 2)}, {0: H.PartitionCommit("committed", 0, 0, 2)}, {})
        frozen = H.analyse_frozen_state(post, canonical, [H.Row(canonical[0].trace, canonical[0].span, 0, 0)])
        assert frozen.prediction.ambiguous and any("duplicate identities" in r for r in frozen.inconclusive)

    def test_the_frozen_state_is_recorded_before_the_restart(self):
        _, case = run_s5(timing_override={"conflicts": 0, "inserted": 160})
        assert case.verdict == "FAIL" and "frozen_state" in case.observations and "post_kill_offsets" in case.observations


class TestS5RestartAndFinalAccounting:
    def test_a_restarted_consumer_that_cannot_drain_in_time_is_inconclusive(self):
        class Slow(SimEnv):
            def wait_drained(self, group, topic, timeout):
                if self.replaying:
                    return False
                return super().wait_drained(group, topic, timeout)
        case = H.case_s5(Slow(rate=9), CFG5)
        assert case.verdict == "INCONCLUSIVE" and any("rebalance" in p for p in case.problems)

    def test_missing_unexpected_and_duplicate_rows_after_the_drain_are_failures(self):
        class Bad(SimEnv):
            def rows(self):
                rows = super().rows()
                if self.replaying and not self.running["storage-consumer"]:
                    first = rows[0]
                    return [first, first] + rows[2:] + [H.Row("f" * 32, "a" * 16, 0, 0)]
                return rows
        case = H.case_s5(Bad(rate=9), CFG5)
        assert case.verdict == "FAIL" and case.observations["final_rows"]["duplicate_copies"] == 1
        assert case.observations["final_rows"]["unexpected"] == 1 and case.observations["final_rows"]["missing"] == 1

    def test_identity_mismatches_after_the_drain_are_a_failure(self):
        class Skewed(SimEnv):
            def rows(self):
                rows = super().rows()
                if self.replaying and not self.running["storage-consumer"]:
                    return [H.Row(r.trace, r.span, r.partition, r.offset + 1) for r in rows]
                return rows
        case = H.case_s5(Skewed(rate=9), CFG5)
        assert case.verdict == "FAIL" and any("disagrees with the canonical topic" in p for p in case.problems)

    def test_final_committed_offsets_must_reach_the_end(self):
        calls = []

        def hook(env, group, topic, service):
            calls.append(1)
            if len(calls) == 4:                                         # after the graceful stop of the restarted consumer
                groups = SimEnv.group(env, group, topic)
                behind = {p: H.GroupPartition(max((g.log_end or 0) - 1, 0), g.log_end) for p, g in groups.items()}
                return H.PostStopOffsets(behind, {p: H.PartitionCommit("committed", g.current, 0, g.log_end) for p, g in behind.items()}, {})
            return None
        _, case = run_s5(post_stop=hook)
        assert case.verdict == "FAIL" and any("did not reach the end offsets" in p for p in case.problems)

    def test_a_failed_graceful_stop_after_the_replay_is_a_failure(self):
        class Dirty(SimEnv):
            def stop(self, services):
                result = super().stop(services)
                if self.replaying:
                    self.exit["storage-consumer"] = 1
                return result
        case = H.case_s5(Dirty(rate=9), CFG5)
        assert case.verdict == "FAIL" and any("exit code 1" in p for p in case.problems)


class TestS5InTheLiveFlow:
    def run(self, tmp_path, monkeypatch, docker=None, **faults):
        monkeypatch.setattr(H, "LiveEnv", lambda *a, **k: ExecSim(*a, **k, **{"rate": 9, **faults}))
        args = flow_args()
        args.cases = "S5"
        docker = docker or FlowDocker(recreate_bridge=True)
        code = H.execute(args, ["S5"], CFG5, sh=RecordingShell(docker), preflight=fake_preflight, sleeper=lambda s: None,
                         clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=tmp_path / "ev")
        files = {kind: json.loads(next((tmp_path / "ev").glob(f"*-{kind}.json")).read_text(encoding="utf-8"))
                 for kind in ("pre-cleanup", "final")}
        return code, docker, files

    def test_a_good_run_writes_both_files_with_the_s5_evidence_and_cleans_up(self, tmp_path, monkeypatch, capsys):
        code, docker, files = self.run(tmp_path, monkeypatch)
        out = capsys.readouterr().out
        assert code == 0 and "overall: PASS" in out and "cleanup verified: yes" in out and H.own_markers() == []
        for record in files.values():
            (case,) = record["cases"]
            assert case["name"] == "S5" and case["verdict"] == "PASS"
            observations = case["observations"]
            for key in ("batching_configuration", "restart_policy", "kill_target", "termination", "frozen_state",
                        "replay_prediction", "restarted_timing", "final_offsets", "final_rows"):
                assert key in observations, key
            assert observations["kill_target"]["verified"] is True and observations["restart_policy"]["observed"] == "no"
        assert files["final"]["cleanup"]["verified"] is True and files["final"]["cleanup"]["networks"]["default_bridge"]["recreated"]
        assert not any("kill" in c for c in docker.commands)             # the kill went through the simulated environment only

    def test_the_protected_container_ids_reach_the_environment(self, tmp_path, monkeypatch):
        seen = {}

        class Spy(ExecSim):
            def kill_target(self, service):
                seen["ids"] = self.protected_ids
                return super().kill_target(service)
        monkeypatch.setattr(H, "LiveEnv", lambda *a, **k: Spy(*a, **k, rate=9))
        args = flow_args()
        args.cases = "S5"
        H.execute(args, ["S5"], CFG5, sh=RecordingShell(FlowDocker()), preflight=fake_preflight, sleeper=lambda s: None,
                  clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=tmp_path / "ev")
        assert seen["ids"] == frozenset(value.split()[0] for value in SNAPSHOT.values() if value)

    def test_a_protected_container_change_fails_the_run_and_leaves_the_marker(self, tmp_path, monkeypatch, capsys):
        code, _, files = self.run(tmp_path, monkeypatch, docker=FlowDocker(
            recreate_bridge=True, protected_after={"agentops-mvp-postgres-1": "i running s f 0 nets=x, mounts="}))
        assert code == 1 and files["final"]["cleanup"]["verified"] is False and H.own_markers() == ["CLEANUP_UNVERIFIED"]

    def test_an_incomplete_disposable_cleanup_fails_the_run(self, tmp_path, monkeypatch):
        code, _, files = self.run(tmp_path, monkeypatch, docker=FlowDocker(leftover=True))
        assert code == 1 and any("project networks left" in p for p in files["final"]["cleanup"]["problems"])

    def test_an_inconclusive_s5_is_not_a_pass_and_cleanup_still_runs(self, tmp_path, monkeypatch, capsys):
        code, docker, files = self.run(tmp_path, monkeypatch, rate=10)
        assert code != 0 and files["final"]["cases"][0]["verdict"] == "INCONCLUSIVE" and files["final"]["verdict"] != "PASS"
        assert any(compose_verb(c) == "down" for c in docker.commands if "compose" in c) and H.own_markers() == []


class TestS5DoesNotChangeTheGracefulCases:
    def test_s5_is_never_a_default_or_part_of_the_graceful_set(self):
        assert H.CASES == ("S1", "S2", "S3", "S4") and "S5" in H.ALL_CASES and "S5" not in H.build_parser().parse_args([]).cases
        text = H.plan_text(PROJECT, HEAD, ["S5"], CFG5)
        assert "SIGKILL" in text and "SIGKILL" not in H.plan_text(PROJECT, HEAD, ["S4"], CFG5)

    def test_the_graceful_cases_never_kill_and_keep_their_overrides(self):
        env = SimEnv()
        results = H.run_cases(env, CFG, list(H.CASES))
        assert [c.name for c in results] == list(H.CASES) and all(c.verdict == "PASS" for c in results) and env.kills == 0
        assert env.batching_history == [None, 10, None] and env.no_restart is False

    def test_all_cases_including_s5_and_s6_run_in_order(self):
        results = H.run_cases(SimEnv(rate=9, sp_per_span=True), CFG5, list(H.ALL_CASES))
        assert [c.name for c in results] == list(H.ALL_CASES)

    def test_s5_uses_its_own_source_batch(self):
        assert H.CASE_BATCH["S5"] == 4 and H.CASE_BATCH["S6"] == 5 and len(set(H.CASE_BATCH.values())) == 5
        assert H.Config().crash_batch_messages == 500 and H.Config().batch_messages == 50
        assert H.Config().restart_wait == 240.0 and H.Config().termination_wait == 15.0

    def test_the_s5_configuration_is_verified_before_any_destructive_step(self):
        env, case = run_s5(env_values={H.BATCH_ENV_NAME: "1"})
        assert env.kills == 0 and case.verdict == "FAIL" and case.observations["batching_configuration"]["status"] == "mismatch"

    def test_partial_s5_evidence_is_kept_and_serializable(self):
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(SimEnv(rate=9, post_stop=failing_on_call(2)), CFG5, ["S5"])
        (partial,) = caught.value.partial_cases
        assert partial.partial is True and "termination" in partial.observations and "commit_observations" in partial.observations
        json.dumps(partial.to_dict())


# ======================================================================================================
# B3J-390: S6, the forced termination of the stream processor and the republication that must follow
# ======================================================================================================

def run_s6(**faults):
    env = SimEnv(**{"rate": 9, "sp_per_span": True, **faults})
    return env, H.case_s6(env, CFG5)


def canon6(index, k, partition, offset, batch=5):
    return H.Canonical(partition, offset, H.trace_hex(batch, index), H.span_hex(index, k))


def produced6(count=3, spans=2, batch=5):
    """Messages 0..count-1 on source partition index % 2 at offset index // 2."""
    return H.Produced(batch, count, spans, {i: (i % 2, i // 2) for i in range(count)})


def post6(committed, ends=(0, 0), lows=(0, 0)):
    groups = {p: H.GroupPartition(committed[p], ends[p]) for p in committed}
    commits = {p: H.PartitionCommit("committed" if committed[p] is not None else "uncommitted", committed[p], lows[p], ends[p])
               for p in committed}
    return H.PostStopOffsets(groups, commits, {})


class TestS6IdentityMapping:
    def test_a_deterministic_identity_decodes_to_its_source_message(self):
        assert H.decode_identity(H.trace_hex(5, 17), H.span_hex(17, 3)) == H.SourceIdentity(5, 17, 3)

    @pytest.mark.parametrize("trace, span", [
        (H.trace_hex(5, 1), H.span_hex(2, 0)),                 # the span names another message
        ("short", H.span_hex(1, 0)), (H.trace_hex(5, 1), "short"),
        ("z" * 32, H.span_hex(1, 0)), (H.trace_hex(5, 1), "z" * 16),
        (H.trace_hex(5, 1), "0" * 16),                          # span number would be -1
        (None, None),
    ])
    def test_anything_else_is_not_an_identity(self, trace, span):
        assert H.decode_identity(trace, span) is None


class TestS6FrozenStateAnalysis:
    def test_partially_published_uncommitted_messages_are_counted_span_by_span(self):
        produced = produced6(3, 2)                              # partition 0: messages 0, 2; partition 1: message 1
        canonical = [canon6(0, 0, 0, 0), canon6(0, 1, 0, 1),    # message 0 complete
                     canon6(1, 0, 1, 0)]                        # message 1 has only its first span
        post = post6({0: 1, 1: 0}, ends=(2, 1))                 # message 0 committed, message 1 and 2 not
        freeze = H.analyse_stream_freeze(produced, post, canonical, 5)
        assert freeze.fail_problems == [] and freeze.inconclusive == []
        assert freeze.published_uncommitted == 1 and freeze.partial_messages == 1
        assert freeze.replay_messages == 2 and freeze.predicted_growth == 4 and freeze.frozen_records == 3
        assert freeze.partitions["1"]["published_uncommitted_spans"] == 1 and freeze.ends == {0: 2, 1: 1}

    def test_an_uncommitted_partition_restarts_at_the_verified_low_watermark(self):
        produced = produced6(2, 2)
        canonical = [canon6(0, 0, 0, 0), canon6(0, 1, 0, 1), canon6(1, 0, 1, 0)]
        freeze = H.analyse_stream_freeze(produced, post6({0: None, 1: None}, ends=(1, 1)), canonical, 5)
        assert freeze.partitions["0"]["restart_position"] == 0 and freeze.committed == {0: None, 1: None}
        assert freeze.replay_messages == 2 and freeze.published_uncommitted == 3

    def test_a_source_offset_committed_past_an_incomplete_message_is_a_failure(self):
        produced = produced6(2, 2)
        canonical = [canon6(0, 0, 0, 0)]                        # message 0 committed but only one of its two spans published
        freeze = H.analyse_stream_freeze(produced, post6({0: 1, 1: 0}, ends=(1, 1)), canonical, 5)
        assert freeze.fail_problems and "past message 0" in freeze.fail_problems[0]

    def test_no_published_span_of_an_uncommitted_message_is_inconclusive_not_a_pass(self):
        produced = produced6(2, 2)
        canonical = [canon6(0, 0, 0, 0), canon6(0, 1, 0, 1)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 1, 1: 0}, ends=(1, 1)), canonical, 5)
        assert freeze.published_uncommitted == 0 and any("nothing to republish" in r for r in freeze.inconclusive)

    def test_an_identity_already_duplicated_before_the_restart_is_ambiguous(self):
        produced = produced6(2, 2)
        canonical = [canon6(1, 0, 1, 0), canon6(1, 0, 1, 1)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 0, 1: 0}, ends=(0, 2)), canonical, 5)
        assert any("already duplicated" in r for r in freeze.inconclusive)

    def test_records_outside_the_fixture_or_without_an_identity_make_the_mapping_ambiguous(self):
        produced = produced6(2, 2)
        canonical = [canon6(9, 0, 0, 0), H.Canonical(0, 1, "x" * 32, "y" * 16), canon6(1, 0, 1, 0)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 0, 1: 0}, ends=(2, 1)), canonical, 5)
        assert any("ambiguous" in r for r in freeze.inconclusive)

    def test_records_of_other_cases_are_ignored(self):
        produced = produced6(2, 2)
        canonical = [canon6(0, 0, 0, 0, batch=4), canon6(1, 0, 1, 0)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 0, 1: 0}, ends=(1, 1)), canonical, 5)
        assert freeze.frozen_records == 1 and freeze.published_uncommitted == 1 and freeze.inconclusive == []


class TestS6RepublicationAnalysis:
    def freeze(self, **kw):
        base = dict(fail_problems=[], inconclusive=[], committed={}, ends={0: 2, 1: 1}, frozen_records=3,
                    published_uncommitted=1, replay_messages=2, predicted_growth=4, partial_messages=1, partitions={})
        base.update(kw)
        return H.StreamFreeze(**base)

    def after(self, extra=()):
        # message 0 once (offsets 0, 1 on canonical partition 0), message 1: span 0 before the freeze (offset 0), then
        # both spans after it (offsets 1, 2), message 2 once after it
        return [canon6(0, 0, 0, 0), canon6(0, 1, 0, 1), canon6(1, 0, 1, 0), canon6(1, 0, 1, 1), canon6(1, 1, 1, 2),
                canon6(2, 0, 0, 2), canon6(2, 1, 0, 3), *extra]

    def test_one_republished_identity_is_a_straddling_duplicate(self):
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(), self.after())
        assert (rep.growth, rep.missing, rep.unexpected, rep.duplicate_copies, rep.straddling, rep.same_phase) == (4, 0, 0, 1, 1, 0)
        assert rep.fail_problems == [] and rep.inconclusive == []
        assert rep.sample == [{"source_message": 1, "span": 0, "raw": [1, 0], "canonical_copies": [[1, 0], [1, 1]]}]

    def test_a_missing_identity_is_a_failure(self):
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(), self.after()[:-1])
        assert rep.missing == 1 and any("missing" in p for p in rep.fail_problems)

    def test_an_unexpected_identity_is_a_failure(self):
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(), self.after([canon6(7, 0, 0, 4)]))
        assert rep.unexpected == 1 and any("outside the fixture" in p for p in rep.fail_problems)

    def test_less_growth_than_the_committed_offsets_require_is_a_failure(self):
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(predicted_growth=5), self.after())
        assert any("fewer than the 5" in p for p in rep.fail_problems)

    def test_more_growth_is_inconclusive(self):
        extra = [canon6(2, 0, 0, 4)]
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(), self.after(extra))
        assert not rep.fail_problems and any("not explained by the source replay" in p for p in rep.inconclusive)

    def test_a_same_side_duplicate_is_not_a_source_replay(self):
        after = self.after() + [canon6(2, 0, 0, 4)]               # message 2's span 0 twice after the freeze
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(), after)
        assert rep.same_phase == 1 and any("same side of the freeze" in p for p in rep.inconclusive)
        assert rep.straddling == 1 and rep.duplicate_copies == 2                    # only the real source replay is straddling

    def test_an_inconsistent_duplicate_count_is_inconclusive(self):
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(published_uncommitted=2), self.after())
        assert any("duplicate accounting is inconsistent" in p for p in rep.inconclusive)

    def test_records_without_an_identity_are_ambiguous(self):
        rep = H.analyse_republication(produced6(3, 2), 5, self.freeze(), self.after([H.Canonical(0, 9, "q" * 32, "w" * 16)]))
        assert any("no deterministic identity" in p for p in rep.inconclusive)

    def test_the_expected_storage_counters_follow_the_committed_positions_and_the_rows_already_present(self):
        canonical = [canon6(0, 0, 0, 0), canon6(0, 1, 0, 1), canon6(0, 0, 0, 2), canon6(1, 0, 1, 0)]
        start = post6({0: 1, 1: 0}, ends=(3, 1))
        rows = [H.Row(canonical[3].trace, canonical[3].span, 1, 0)]       # one identity is already durable
        assert H.expected_storage_counters(canonical, start, rows) == (3, 2, 1)
        assert H.expected_storage_counters(canonical, start, []) == (3, 3, 0)


class TestS6CrashAndRepublication:
    def test_a_kill_with_published_uncommitted_spans_passes_only_on_exact_observations(self):
        env, case = run_s6()
        assert case.verdict == "PASS", case.problems
        assert env.kill_log == [("stream-processor", "S6")] and env.kills == 1
        prediction, rep = case.observations["replay_prediction"], case.observations["republication"]
        assert prediction["published_uncommitted_spans"] == rep["straddling_duplicates"] == rep["duplicate_copies"] > 0
        assert rep["observed_growth"] == prediction["predicted_growth"] and rep["same_phase_extra_copies"] == 0
        assert rep["missing_identities"] == rep["unexpected_identities"] == 0 and rep["sample"]
        storage = case.observations["storage_timing"]
        assert storage["conflicts"] == rep["duplicate_copies"] and case.observations["final_rows"]["duplicate_copies"] == 0
        assert case.observations["final_rows"]["rows"] == case.observations["final_rows"]["expected"] == 120
        assert [s.service for s in case.stops] == ["stream-processor", "storage-consumer"] and all(s.all_passed for s in case.stops)
        assert case.metrics["republished_duplicates"] == case.metrics["predicted_duplicates"] == case.metrics["storage_conflicts"]

    def test_the_override_is_set_for_s6_and_restored(self):
        env, _ = run_s6()
        assert env.override_history[0] == {"batching_messages": None, "no_restart": False, "stream_no_restart": True,
                                           "storage_timing": True}
        assert env.override_history[-1] == {"batching_messages": None, "no_restart": False, "stream_no_restart": False,
                                            "storage_timing": False}

    def test_a_partially_published_message_is_accounted_span_by_span(self):
        _, case = run_s6()
        assert case.observations["replay_prediction"]["partially_published_messages"] == 1
        sample = case.observations["republication"]["sample"]
        assert len(sample) == case.observations["republication"]["duplicate_copies"]
        assert all(len({c[0] for c in item["canonical_copies"]}) == 1 for item in sample)       # same canonical partition

    def test_a_kill_between_messages_leaves_nothing_to_republish_and_nothing_is_restarted(self):
        env, case = run_s6(rate=8)
        assert case.verdict == "INCONCLUSIVE" and any("nothing to republish" in p for p in case.problems)
        assert env.kills == 1 and env.stops == 1 and case.stops == [] and "republication" not in case.observations

    def test_a_processor_that_finished_before_the_kill_is_inconclusive_and_not_killed(self):
        env, case = run_s6(rate=1000)
        assert case.verdict == "INCONCLUSIVE" and env.kills == 0 and "nothing was killed" in case.problems[0]

    def test_without_republication_the_proof_is_not_claimed(self):
        _, case = run_s6(restart_skips=True)
        assert case.verdict == "FAIL" and case.verdict != "PASS"
        assert case.observations["republication"]["straddling_duplicates"] == 0
        assert any("fewer than the" in p for p in case.problems) and any("missing" in p for p in case.problems)

    def test_a_processor_that_publishes_a_message_twice_is_inconclusive_not_a_pass(self):
        _, case = run_s6(restart_double_head=True)
        assert case.verdict == "INCONCLUSIVE" and case.observations["republication"]["same_phase_extra_copies"] > 0
        assert any("not explained by the source replay" in p or "same side" in p for p in case.problems)

    def test_a_defective_commit_before_the_last_span_is_a_failure(self):
        _, case = run_s6(sp_commit_after_first=True)
        assert case.verdict == "FAIL" and any("whose" in p and "span(s) are not on the canonical topic" in p for p in case.problems)
        assert "republication" not in case.observations

    def test_the_prediction_comes_from_the_frozen_state_not_from_progress(self):
        _, case = run_s6()
        frozen = case.observations["frozen_canonical"]
        assert frozen["records_of_this_case"] > 0 and frozen["ends"] and case.observations["post_kill_offsets"]["partitions"]
        assert case.observations["frozen_source"]["partitions"]


class TestS6KillIsolationAndGuards:
    @pytest.mark.parametrize("faults, needle", [
        ({"kill_id_mismatch": True}, "disagree about the container id"),
        ({"kill_wrong_project": True}, "project label"),
        ({"kill_wrong_service": True}, "service label"),
        ({"kill_protected_name": True}, "protected container"),
        ({"others_down": "kafka"}, "kafka is 'exited'"),
        ({"others_down": "postgres"}, "postgres is 'exited'"),
    ])
    def test_a_target_that_does_not_verify_is_never_killed(self, faults, needle):
        env, case = run_s6(**faults)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE"
        assert case.observations["kill_target"]["verified"] is False
        assert any(needle in r for r in case.observations["kill_target"]["refusals"])

    def test_a_running_storage_consumer_blocks_the_kill(self):
        class Running(SimEnv):
            def inspect(self, service):
                if service == "storage-consumer":
                    return H.Inspect("running", 0, 0, False)
                return super().inspect(service)
        env = Running(rate=9, sp_per_span=True)
        case = H.case_s6(env, CFG5)
        assert env.kills == 0 and "storage-consumer is 'running', expected 'exited'" in case.problems[0]

    def test_a_protected_container_id_is_never_killed(self):
        env = SimEnv(rate=9, sp_per_span=True)
        env.protected_ids = frozenset({env.cids["stream-processor"]})
        case = H.case_s6(env, CFG5)
        assert env.kills == 0 and "matches a protected container" in case.problems[0]

    @pytest.mark.parametrize("faults, needle", [({"policy_wrong": True}, "unless-stopped"), ({"policy_error": True}, "unreadable"),
                                                 ({"stream_group_env": "agentops-stream-processor"}, "agentops-stream-processor")])
    def test_a_restart_policy_or_group_that_is_wrong_stops_the_case_before_any_kill(self, faults, needle):
        env, case = run_s6(**faults)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE" and "nothing was killed" in case.problems[0]
        assert needle in json.dumps(case.observations["stream_processor_configuration"])
        assert "commit_observations" not in case.observations

    def test_each_case_may_kill_only_its_own_service(self, tmp_path):
        assert H.KILL_TARGETS == {"S5": "storage-consumer", "S6": "stream-processor"}
        assert H.kill_arguments("S5") == ("kill", "-s", "SIGKILL", "storage-consumer")
        assert H.kill_arguments("S6") == ("kill", "-s", "SIGKILL", "stream-processor")
        assert H.kill_arguments_allowed(H.kill_arguments("S6"), "S6") and not H.kill_arguments_allowed(H.kill_arguments("S6"))
        assert H.kill_arguments_allowed(H.kill_arguments("S5")) and not H.kill_arguments_allowed(H.kill_arguments("S5"), "S6")
        for case in ("S1", "S2", "S3", "S4", "S7", ""):
            with pytest.raises(SmokeFailure):
                H.kill_arguments(case)
            assert not H.kill_arguments_allowed(("kill", "-s", "SIGKILL", "storage-consumer"), case)
        env, shell = live_env(tmp_path, lambda c: Result(stdout="d" * 64 + "\n"))
        for service, case in (("stream-processor", "S5"), ("storage-consumer", "S6"), ("kafka", "S6"), ("postgres", "S5"),
                              ("storage-consumer", "S1"), ("stream-processor", "S4")):
            with pytest.raises(SmokeFailure, match="refusing to kill"):
                env.kill(service, "d" * 64, case)
        assert shell.commands == []                                 # refused before a single command

    def test_the_sim_enforces_the_same_isolation(self):
        env = SimEnv()
        with pytest.raises(H.SmokeFailure):
            env.kill("stream-processor", env.cids["stream-processor"], "S5")
        with pytest.raises(H.SmokeFailure):
            env.kill("storage-consumer", env.cids["storage-consumer"], "S6")

    def test_the_s6_kill_command_is_one_exact_project_scoped_command(self, tmp_path):
        env, shell = live_env(tmp_path, lambda c: Result(stdout="b" * 64 + "\n") if "ps" in c else Result())
        result = env.kill("stream-processor", "b" * 64, "S6")
        command = shell.commands[-1]
        assert result.returncode == 0 and command[:4] == ["docker", "compose", "-p", PROJECT]
        assert command[-4:] == ["kill", "-s", "SIGKILL", "stream-processor"] and not any(c[:2] == ["docker", "kill"] for c in shell.commands)

    def test_a_changed_container_is_refused_for_s6_too(self, tmp_path):
        env, shell = live_env(tmp_path, lambda c: Result(stdout="e" * 64 + "\n"))
        with pytest.raises(SmokeFailure, match="no longer the one"):
            env.kill("stream-processor", "b" * 64, "S6")
        assert not any("kill" in c for c in shell.commands)

    def test_the_existing_s5_kill_is_unchanged_by_s6(self):
        env, case = run_s5()
        assert case.verdict == "PASS" and env.kill_log == [("storage-consumer", "S5")]

    def test_the_s6_override_text(self):
        text = H.test_override_text(PROJECT, stream_no_restart=True, storage_timing=True)
        assert text.count('restart: "no"') == 1 and f'{H.TIMING_ENV_NAME}: "{H.TIMING_INTERVAL_SECONDS}"' in text
        assert text.index('restart: "no"') < text.index("storage-consumer:")        # on the stream processor, not the storage consumer
        assert "restart" not in H.test_override_text(PROJECT) and H.TIMING_ENV_NAME not in H.test_override_text(PROJECT)
        both = H.test_override_text(PROJECT, batching_messages=50, storage_timing=True)
        assert both.count(H.TIMING_ENV_NAME) == 1


class TestS6Termination:
    @pytest.mark.parametrize("faults, needle", [
        ({"kill_miss": True}, "not exited"), ({"kill_rc": 1}, "returned 1"), ({"kill_exit_code": 1}, "exit code 1"),
        ({"kill_exit_code": 255}, "exit code 255"), ({"kill_oom": True}, "OOM-killed"),
        ({"kill_new_container": True}, "container id changed"), ({"kill_restarts": 1}, "restart count 0 -> 1"),
        ({"kill_graceful": True}, "graceful-shutdown diagnostics"),
    ])
    def test_a_termination_that_cannot_be_attributed_is_inconclusive_and_nothing_is_restarted(self, faults, needle):
        env, case = run_s6(**faults)
        assert case.verdict == "INCONCLUSIVE" and case.stops == [] and env.stops == 1
        assert any("cannot be attributed" in p and needle in p for p in case.problems), case.problems
        assert "frozen_source" not in case.observations and case.observations["termination"]["attributed_to_sigkill"] is False


class TestS6FrozenAndRestart:
    def test_a_canonical_topic_that_keeps_changing_is_inconclusive(self):
        class Moving(SimEnv):
            n = 0

            def canonical(self):
                if self.stream_killed:
                    Moving.n += 1
                    return super().canonical() + [canon6(0, 0, 0, 1000 + Moving.n)]
                return super().canonical()
        case = H.case_s6(Moving(rate=9, sp_per_span=True), CFG5)
        assert case.verdict == "INCONCLUSIVE" and "still changing" in case.problems[0]

    def test_a_low_watermark_that_is_not_zero_stops_the_case_without_a_guess(self):
        def hook(env, group, topic, service):
            if env.stream_killed:
                groups = SimEnv.group(env, group, topic)
                return H.PostStopOffsets(groups, {p: H.PartitionCommit("committed", g.current, 7, g.log_end) for p, g in groups.items()}, {})
        with pytest.raises(H.PostStopError, match="S6 frozen source state cannot be trusted") as caught:
            H.run_cases(SimEnv(rate=9, sp_per_span=True, post_stop=hook), CFG5, ["S6"])
        (partial,) = caught.value.partial_cases
        assert partial.name == "S6" and partial.partial and partial.observations["termination"]["attributed_to_sigkill"]

    def test_committed_source_offsets_that_move_while_the_processor_is_dead_are_a_failure(self):
        calls = []

        def hook(env, group, topic, service):
            calls.append(1)
            if len(calls) == 2:                                        # the re-check just before the restart
                groups = SimEnv.group(env, group, topic)
                bumped = {p: H.GroupPartition((g.current or 0) + (1 if p == 0 else 0), g.log_end) for p, g in groups.items()}
                return H.PostStopOffsets(bumped, {p: H.PartitionCommit("committed", g.current, 0, g.log_end) for p, g in bumped.items()}, {})
        env, case = run_s6(post_stop=hook)
        assert case.verdict == "FAIL" and "moved while the processor was dead" in case.problems[0] and env.stops == 1

    def test_a_restart_that_cannot_drain_in_time_is_inconclusive(self):
        class Slow(SimEnv):
            def wait_drained(self, group, topic, timeout):
                if topic == H.SOURCE_TOPIC and self.kills:
                    return False
                return super().wait_drained(group, topic, timeout)
        case = H.case_s6(Slow(rate=9, sp_per_span=True), CFG5)
        assert case.verdict == "INCONCLUSIVE" and any("rebalance" in p for p in case.problems)

    def test_final_source_offsets_must_reach_the_end(self):
        calls = []

        def hook(env, group, topic, service):
            calls.append(1)
            if len(calls) == 3 and topic == H.SOURCE_TOPIC:
                groups = SimEnv.group(env, group, topic)
                behind = {p: H.GroupPartition(max((g.log_end or 0) - 1, 0), g.log_end) for p, g in groups.items()}
                return H.PostStopOffsets(behind, {p: H.PartitionCommit("committed", g.current, 0, g.log_end) for p, g in behind.items()}, {})
        _, case = run_s6(post_stop=hook)
        assert case.verdict == "FAIL" and any("source offsets did not reach the end" in p for p in case.problems)

    def test_a_failed_graceful_stop_of_the_restarted_processor_is_a_failure(self):
        class Dirty(SimEnv):
            def stop(self, services):
                result = super().stop(services)
                if "stream-processor" in services and not self.stream_killed and self.kills:
                    self.exit["stream-processor"] = 1
                return result
        case = H.case_s6(Dirty(rate=9, sp_per_span=True), CFG5)
        assert case.verdict == "FAIL" and any("exit code 1" in p for p in case.problems)


class TestS6Downstream:
    def test_unusable_storage_counters_are_inconclusive_after_the_republication(self):
        for faults in ({"no_timing": True}, {"timing_garbage": True}, {"timing_copies": 2}):
            _, case = run_s6(**faults)
            assert case.verdict == "INCONCLUSIVE" and case.observations["republication"]["straddling_duplicates"] > 0
            assert any("downstream absorption is not" in p for p in case.problems)

    @pytest.mark.parametrize("override", [{"conflicts": 0, "inserted": 122}, {"conflicts": 9, "inserted": 113},
                                          {"messages": 100, "inserted": 98, "conflicts": 2, "commits": 100}])
    def test_storage_counters_that_disagree_with_the_canonical_topic_are_a_failure(self, override):
        _, case = run_s6(timing_override=override)
        assert case.verdict == "FAIL" and any("the storage consumer reports" in p and "predicts" in p for p in case.problems)

    def test_a_storage_consumer_that_cannot_drain_is_inconclusive(self):
        class Stuck(SimEnv):
            def wait_drained(self, group, topic, timeout):
                if topic == H.CANONICAL_TOPIC and self.kills:
                    return False
                return super().wait_drained(group, topic, timeout)
        case = H.case_s6(Stuck(rate=9, sp_per_span=True), CFG5)
        assert case.verdict == "INCONCLUSIVE" and any("did not drain the canonical topic" in p for p in case.problems)

    def test_missing_unexpected_and_duplicate_rows_are_failures(self):
        class Bad(SimEnv):
            def rows(self):
                rows = super().rows()
                if self.stream_killed is False and self.kills and not self.running["storage-consumer"] and len(rows) >= 100:
                    first = rows[0]
                    return [first, first] + rows[2:] + [H.Row("f" * 32, "a" * 16, 0, 0)]
                return rows
        case = H.case_s6(Bad(rate=9, sp_per_span=True), CFG5)
        rows = case.observations["final_rows"]
        assert case.verdict == "FAIL" and (rows["missing"], rows["unexpected"], rows["duplicate_copies"]) == (1, 1, 1)

    def test_missing_and_duplicate_rows_alone_are_failures(self):
        class Lossy(SimEnv):
            def rows(self):
                rows = super().rows()
                if self.kills and not self.running["storage-consumer"] and len(rows) >= 100:
                    return [rows[0], rows[0]] + rows[2:]                              # one row lost, another doubled
                return rows
        case = H.case_s6(Lossy(rate=9, sp_per_span=True), CFG5)
        rows = case.observations["final_rows"]
        assert case.verdict == "FAIL" and (rows["missing"], rows["unexpected"], rows["duplicate_copies"]) == (1, 0, 1)
        assert rows["identity_mismatches"] == 0 and any(p.startswith("rows:") for p in case.problems)

    def test_identity_mismatches_in_the_rows_are_a_failure(self):
        class Skewed(SimEnv):
            def rows(self):
                rows = super().rows()
                if self.kills and not self.running["storage-consumer"] and len(rows) >= 100:
                    return [H.Row(r.trace, r.span, r.partition, r.offset + 1) for r in rows]
                return rows
        case = H.case_s6(Skewed(rate=9, sp_per_span=True), CFG5)
        assert case.verdict == "FAIL" and any("disagrees with the canonical topic" in p for p in case.problems)

    def test_final_storage_offsets_must_reach_the_end(self):
        calls = []

        def hook(env, group, topic, service):
            calls.append(topic)
            if topic == H.CANONICAL_TOPIC and calls.count(H.CANONICAL_TOPIC) == 2:
                groups = SimEnv.group(env, group, topic)
                behind = {p: H.GroupPartition(max((g.log_end or 0) - 1, 0), g.log_end) for p, g in groups.items()}
                return H.PostStopOffsets(behind, {p: H.PartitionCommit("committed", g.current, 0, g.log_end) for p, g in behind.items()}, {})
        _, case = run_s6(post_stop=hook)
        assert case.verdict == "FAIL" and any("storage offsets did not reach the end" in p for p in case.problems)

    def test_the_storage_consumer_stays_stopped_until_the_republication_is_complete(self):
        order = []

        class Spy(SimEnv):
            def start(self, service):
                order.append(("start", service, len(self.canonical_list)))
                super().start(service)

            def stop(self, services):
                order.append(("stop", tuple(services), len(self.canonical_list)))
                return super().stop(services)
        env = Spy(rate=9, sp_per_span=True)
        case = H.case_s6(env, CFG5)
        assert case.verdict == "PASS"
        assert order[0][:2] == ("stop", ("storage-consumer",))                  # stopped before anything is produced
        storage_start = next(item for item in order if item[:2] == ("start", "storage-consumer"))
        assert storage_start[2] == 120 + case.observations["republication"]["duplicate_copies"]    # started on the final canonical topic


class TestS6InTheLiveFlow:
    def run(self, tmp_path, monkeypatch, docker=None, **faults):
        monkeypatch.setattr(H, "LiveEnv", lambda *a, **k: ExecSim(*a, **k, **{"rate": 9, "sp_per_span": True, **faults}))
        args = flow_args()
        args.cases = "S6"
        docker = docker or FlowDocker(recreate_bridge=True)
        code = H.execute(args, ["S6"], CFG5, sh=RecordingShell(docker), preflight=fake_preflight, sleeper=lambda s: None,
                         clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=tmp_path / "ev")
        files = {kind: json.loads(next((tmp_path / "ev").glob(f"*-{kind}.json")).read_text(encoding="utf-8"))
                 for kind in ("pre-cleanup", "final")}
        return code, docker, files

    def test_a_good_run_writes_both_files_with_the_s6_evidence_and_cleans_up(self, tmp_path, monkeypatch, capsys):
        code, docker, files = self.run(tmp_path, monkeypatch)
        out = capsys.readouterr().out
        assert code == 0 and "overall: PASS" in out and "cleanup verified: yes" in out and H.own_markers() == []
        for record in files.values():
            (case,) = record["cases"]
            assert case["name"] == "S6" and case["verdict"] == "PASS"
            for key in ("stream_processor_configuration", "kill_target", "termination", "frozen_source", "frozen_canonical",
                        "replay_prediction", "republication", "storage_prediction", "storage_timing", "final_source_offsets",
                        "final_storage_offsets", "final_rows"):
                assert key in case["observations"], key
        assert files["final"]["cleanup"]["verified"] is True
        assert not any("kill" in c for c in docker.commands)

    def test_the_protected_container_ids_reach_the_environment(self, tmp_path, monkeypatch):
        seen = {}

        class Spy(ExecSim):
            def kill_target(self, service):
                seen["ids"] = self.protected_ids
                return super().kill_target(service)
        monkeypatch.setattr(H, "LiveEnv", lambda *a, **k: Spy(*a, **k, rate=9, sp_per_span=True))
        args = flow_args()
        args.cases = "S6"
        H.execute(args, ["S6"], CFG5, sh=RecordingShell(FlowDocker()), preflight=fake_preflight, sleeper=lambda s: None,
                  clock=lambda c=iter(range(0, 100000)): float(next(c)), evidence_dir=tmp_path / "ev")
        assert seen["ids"] == frozenset(value.split()[0] for value in SNAPSHOT.values() if value)

    def test_a_protected_container_change_fails_the_run_and_leaves_the_marker(self, tmp_path, monkeypatch):
        code, _, files = self.run(tmp_path, monkeypatch, docker=FlowDocker(
            recreate_bridge=True, protected_after={"agentops-mvp-postgres-1": "i running s f 0 nets=x, mounts="}))
        assert code == 1 and files["final"]["cleanup"]["verified"] is False and H.own_markers() == ["CLEANUP_UNVERIFIED"]

    def test_an_incomplete_disposable_cleanup_fails_the_run(self, tmp_path, monkeypatch):
        code, _, files = self.run(tmp_path, monkeypatch, docker=FlowDocker(leftover=True))
        assert code == 1 and any("project networks left" in p for p in files["final"]["cleanup"]["problems"])

    def test_an_inconclusive_s6_is_not_a_pass_and_cleanup_still_runs(self, tmp_path, monkeypatch):
        code, docker, files = self.run(tmp_path, monkeypatch, rate=8)
        assert code != 0 and files["final"]["cases"][0]["verdict"] == "INCONCLUSIVE" and files["final"]["verdict"] != "PASS"
        assert any(compose_verb(c) == "down" for c in docker.commands if "compose" in c) and H.own_markers() == []

    def test_partial_s6_evidence_is_kept_and_serializable(self):
        with pytest.raises(H.PostStopError) as caught:
            H.run_cases(SimEnv(rate=9, sp_per_span=True, post_stop=failing_on_call(2)), CFG5, ["S6"])
        (partial,) = caught.value.partial_cases
        assert partial.partial is True and "termination" in partial.observations and "frozen_source" in partial.observations
        json.dumps(partial.to_dict())


class TestS6DoesNotChangeTheOtherCases:
    def test_s6_is_opt_in_and_ordered_last(self):
        assert H.CASES == ("S1", "S2", "S3", "S4") and H.ALL_CASES == (*H.CASES, "S5", "S6")
        assert H.build_parser().parse_args([]).cases == "S1,S2,S3,S4"
        assert "SIGKILL" in H.plan_text(PROJECT, HEAD, ["S6"], CFG5) and "stream processor" in H.plan_text(PROJECT, HEAD, ["S6"], CFG5)
        assert "stream processor" not in H.plan_text(PROJECT, HEAD, ["S5"], CFG5)

    def test_the_defaults_of_s6_do_not_touch_the_other_workloads(self):
        defaults = H.Config()
        assert (defaults.crash_messages, defaults.crash_spans) == (60, 500) and (defaults.messages, defaults.spans) == (2000, 3)
        assert defaults.crash_batch_messages == 500 and defaults.batch_messages == 50

    def test_s1_to_s5_never_kill_the_stream_processor(self):
        env = SimEnv(rate=9)
        H.run_cases(env, CFG5, ["S1", "S2", "S3", "S4", "S5"])
        assert ("stream-processor", "S6") not in env.kill_log and all(case == "S5" for _s, case in env.kill_log)
        assert env.kill_log == [("storage-consumer", "S5")]

    def test_s1_to_s4_overrides_have_no_s6_settings(self):
        for text in (H.test_override_text(PROJECT), H.test_override_text(PROJECT, batching_messages=50)):
            assert "restart" not in text


# ---------------------------------------------------------------------------
# B3J-395: the S6 workload (60 messages x 500 spans) and the ordering of the kill checks
# ---------------------------------------------------------------------------

import dataclasses as _dc

#: The real S6 dimensions, with the waits shortened for the simulation only.
CFG6 = H.Config(idle_seconds=0.0, window_timeout=600.0, restart_wait=600.0, termination_wait=5.0)


def run_s6_full(**faults):
    env = SimEnv(**{"rate": 9, "sp_per_span": True, **faults})
    return env, H.case_s6(env, CFG6)


def calls_after_last_progress_reading(env):
    """The environment calls between the last source-topic progress reading BEFORE the kill and the kill itself."""
    kill = next(i for i, call in enumerate(env.calls) if call[0] == "kill")
    last = max(i for i, call in enumerate(env.calls[:kill]) if call == ("group", H.SOURCE_TOPIC))
    return env.calls[last + 1:kill]


class TestS6WorkloadDimensions:
    def test_the_defaults_are_sixty_messages_of_five_hundred_spans_and_the_other_cases_are_unchanged(self):
        d = H.Config()
        assert (d.crash_messages, d.crash_spans) == (60, 500) and d.crash_messages * d.crash_spans == 30000
        assert (d.messages, d.spans, d.batch_messages, d.crash_batch_messages) == (2000, 3, 50, 500)
        assert (d.window, d.restart_wait, d.termination_wait, d.drain_timeout) == ((0.10, 0.70), 240.0, 15.0, 300.0)
        assert (d.idle_stop_max, d.graceful_stop_max, d.duplicate_tolerance_messages) == (10.0, 25.0, 1)

    def test_thirty_thousand_distinct_identities_each_decode_to_their_message_and_span(self):
        batch = H.CASE_BATCH["S6"]
        identities = H.expected_spans(batch, 60, 500)
        assert len(identities) == 30000
        assert len({trace for trace, _ in identities}) == 60 and len({span for _, span in identities}) == 30000
        decoded = {(i.index, i.k) for i in (H.decode_identity(t, s) for t, s in identities)}
        assert decoded == {(m, k) for m in range(60) for k in range(500)}
        assert H.decode_identity(H.trace_hex(batch, 59), H.span_hex(59, 499)) == H.SourceIdentity(batch, 59, 499)
        assert H.decode_identity(H.trace_hex(batch, 59), H.span_hex(58, 499)) is None        # the span names another message

    def test_the_identity_encoding_has_room_for_the_largest_message(self):
        assert H.span_hex(0, 0xFFFE) == "000000000000ffff"
        assert H.decode_identity(H.trace_hex(5, 0), H.span_hex(0, 0xFFFE)).k == 0xFFFE

    def test_the_producer_step_embeds_the_same_definition_for_any_span_count(self):
        namespace = {}
        exec(H.IDS_SOURCE, namespace)
        assert [namespace["span_hex"](7, k) for k in (0, 499)] == [H.span_hex(7, k) for k in (0, 499)]
        assert H.IDS_SOURCE in H.PRODUCER_SOURCE and "range(spans)" in H.PRODUCER_SOURCE

    def test_the_plan_names_the_new_input(self):
        assert "60 messages x 500 spans" in H.plan_text(PROJECT, HEAD, ["S6"], H.Config())


class TestS6MessageSize:
    def test_the_analytic_bound_is_far_below_the_producer_and_broker_limits(self):
        assert H.source_message_size_bound(500) == 500 * 70 + 128 == 35128
        assert H.source_message_size_bound(500) < H.PRODUCER_MESSAGE_MAX_BYTES < H.BROKER_MESSAGE_MAX_BYTES
        assert H.source_message_fits(500) and H.source_message_fits(10) and not H.source_message_fits(15000)

    def test_the_bound_covers_the_wire_size_of_every_span_the_producer_step_builds(self):
        pb = pytest.importorskip("opentelemetry.proto.trace.v1.trace_pb2")
        collector = pytest.importorskip("opentelemetry.proto.collector.trace.v1.trace_service_pb2")
        common = pytest.importorskip("opentelemetry.proto.common.v1.common_pb2")
        resource_pb = pytest.importorskip("opentelemetry.proto.resource.v1.resource_pb2")

        def serialized(index, spans):
            trace = bytes.fromhex(H.trace_hex(H.CASE_BATCH["S6"], index))
            items = [pb.Span(trace_id=trace, span_id=bytes.fromhex(H.span_hex(index, k)), name="shutdown.it", kind=1,
                             start_time_unix_nano=1700000000000000000, end_time_unix_nano=1700000001000000000,
                             status=pb.Status(code=1)) for k in range(spans)]
            resource = resource_pb.Resource(attributes=[common.KeyValue(key="service.name",
                                                                        value=common.AnyValue(string_value="shutdown-it"))])
            request = collector.ExportTraceServiceRequest(resource_spans=[
                pb.ResourceSpans(resource=resource, scope_spans=[pb.ScopeSpans(spans=items)])])
            return len(request.SerializeToString())
        sizes = {(index, spans): serialized(index, spans) for index in (0, 59, 599) for spans in (1, 10, 500, 4000)}
        for (index, spans), size in sizes.items():
            assert size <= H.source_message_size_bound(spans), (index, spans, size)
        assert sizes[(59, 500)] < 40000 < H.PRODUCER_MESSAGE_MAX_BYTES and sizes[(59, 500)] == sizes[(0, 500)]

    def test_nothing_in_the_producer_step_or_compose_raises_or_lowers_the_limits(self):
        assert "message.max.bytes" not in H.PRODUCER_SOURCE
        compose = (_REPO / "docker-compose.yml").read_text(encoding="utf-8")
        assert not re.search(r"(?i)message[._]max|max[._]message|KAFKA_MESSAGE", compose)

    @pytest.mark.parametrize("spans", [0, -1, 15000, 70000])
    def test_a_span_count_that_does_not_provably_fit_starts_nothing(self, spans):
        env = SimEnv(rate=9, sp_per_span=True)
        case = H.case_s6(env, H.Config(crash_messages=3, crash_spans=spans, window_timeout=60.0))
        assert case.verdict == "INCONCLUSIVE" and "nothing was started or produced" in case.problems[0]
        assert env.calls == [] and env.stops == 0 and env.kills == 0 and env.produced == []


class TestS6VerificationBeforeTheWait:
    def test_the_whole_verification_precedes_the_baseline_the_workload_and_the_progress_wait(self):
        env, case = run_s6()
        assert case.verdict == "PASS", case.problems
        names = [c[0] for c in env.calls]
        before = env.calls[:names.index("group")]
        assert ("kill_target", "stream-processor") in before and ("logs", "stream-processor") in before
        assert [c for c in before if c[0] == "container_id"] == [("container_id", "kafka"), ("container_id", "postgres"),
                                                                 ("container_id", "storage-consumer")]
        assert {c[1] for c in before if c[0] == "inspect"} == {"kafka", "postgres", "storage-consumer", "stream-processor"}
        assert names.index("produce") > names.index("group")
        # nothing of that kind is repeated between the first progress reading and the kill, except the revalidation
        between = env.calls[names.index("group"):names.index("kill")]
        assert {c[0] for c in between} == {"group", "produce", "recheck_containers"}

    def test_a_refusal_before_the_wait_produces_nothing_and_never_reads_progress(self):
        env, case = run_s6(kill_wrong_service=True)
        assert env.kills == 0 and case.verdict == "INCONCLUSIVE" and env.produced == [] and "workload" not in case.observations
        assert ("group", H.SOURCE_TOPIC) not in env.calls and "commit_observations" not in case.observations

    def test_the_neighbour_containers_are_recorded_with_their_full_ids(self):
        env, case = run_s6()
        recorded = case.observations["kill_target"]["neighbour_container_ids"]
        assert recorded == {name: env.cids[name] for name in ("kafka", "postgres", "storage-consumer")}

    def test_neighbour_ids_that_cannot_be_read_stop_the_case_before_the_workload(self):
        env, case = run_s6(container_id_error=True)
        assert case.verdict == "INCONCLUSIVE" and "nothing was killed" in case.problems[0] and env.produced == [] and env.kills == 0

    def test_a_kill_target_that_cannot_be_identified_is_not_killed(self):
        class Unreadable(SimEnv):
            def kill_target(self, service):
                raise H.SmokeFailure("compose ps failed")
        env = Unreadable(rate=9, sp_per_span=True)
        case = H.case_s6(env, CFG5)
        assert case.verdict == "INCONCLUSIVE" and "nothing was killed" in case.problems[0] and env.kills == 0 and env.produced == []


class TestS6RevalidationJustBeforeTheKill:
    def test_exactly_one_inspect_of_the_four_verified_ids_sits_between_the_last_reading_and_the_kill(self):
        env, case = run_s6()
        assert case.verdict == "PASS", case.problems
        tail = calls_after_last_progress_reading(env)
        expected = (env.cids["stream-processor"], env.cids["kafka"], env.cids["postgres"], env.cids["storage-consumer"])
        assert tail == [("recheck_containers", expected)]
        record = case.observations["kill_revalidation"]
        assert record["checked_container_ids"] == list(expected) and record["refusals"] == []
        assert record["seconds_from_last_progress_reading_to_kill_request"] >= 0.0 and env.kills == 1

    def test_the_full_default_workload_passes_end_to_end_on_the_simulation(self):
        env, case = run_s6_full()
        assert case.verdict == "PASS", case.problems
        assert case.observations["workload"]["expected_identities"] == 30000
        assert case.observations["final_rows"]["rows"] == case.observations["final_rows"]["expected"] == 30000
        assert env.kill_log == [("stream-processor", "S6")] and len(calls_after_last_progress_reading(env)) == 1
        prediction, rep = case.observations["replay_prediction"], case.observations["republication"]
        assert 0 < prediction["published_uncommitted_spans"] == rep["straddling_duplicates"] == rep["duplicate_copies"]
        assert rep["observed_growth"] == prediction["predicted_growth"] == prediction["replayed_messages"] * 500

    @staticmethod
    def alter(service, **changes):
        def apply(env, facts):
            facts[env.cids[service]] = _dc.replace(facts[env.cids[service]], **changes)
        return apply

    @pytest.mark.parametrize("service, changes, needle", [
        ("stream-processor", {"container_id": "d" * 64}, "container id changed since it was verified"),
        ("stream-processor", {"project_label": "agentops"}, "project label"),
        ("stream-processor", {"service_label": "storage-consumer"}, "service label"),
        ("stream-processor", {"restart_policy": "always"}, "restart policy is 'always'"),
        ("stream-processor", {"status": "exited"}, "is 'exited', not running"),
        ("stream-processor", {"name": "/agentops-mvp-postgres-1"}, "protected container"),
        ("stream-processor", {"name": "/other-stream-processor-1"}, "is not this project's stream-processor"),
        ("kafka", {"status": "exited"}, "kafka is 'exited'"),
        ("postgres", {"status": "restarting"}, "postgres is 'restarting'"),
        ("storage-consumer", {"status": "running"}, "storage-consumer is 'running', expected 'exited'"),
        ("kafka", {"container_id": "d" * 64}, "kafka's container id changed"),
        ("postgres", {"project_label": "agentops"}, "postgres is no longer this project's postgres"),
        ("storage-consumer", {"service_label": "kafka"}, "storage-consumer is no longer this project's storage-consumer"),
    ])
    def test_a_change_between_the_verification_and_the_kill_refuses_the_kill(self, service, changes, needle):
        env, case = run_s6(recheck_hook=self.alter(service, **changes))
        self.assert_refused(env, case, needle)

    def test_a_target_that_became_protected_is_refused_at_the_kill(self):
        def hook(env, facts):
            env.protected_ids = frozenset({env.cids["stream-processor"]})
        env, case = run_s6(recheck_hook=hook)
        self.assert_refused(env, case, "matches a protected container")

    def test_a_disposable_project_that_changed_is_refused_at_the_kill(self):
        def hook(env, facts):
            env.project = "agentops"
        env, case = run_s6(recheck_hook=hook)
        self.assert_refused(env, case, "not a disposable shutdown-validation project")

    @staticmethod
    def assert_refused(env, case, needle):
        assert env.kills == 0 and env.kill_log == [] and case.verdict == "INCONCLUSIVE"
        assert "at the moment of the kill" in case.problems[0] and "nothing was killed" in case.problems[0]
        refusals = case.observations["kill_revalidation"]["refusals"]
        assert any(needle in r for r in refusals), refusals
        assert case.observations["kill_target"]["verified"] is True            # the early verification had passed
        assert "termination" not in case.observations and case.stops == [] and env.stops == 1
        assert env.running["stream-processor"] is True                         # still alive: nothing was signalled

    def test_a_recheck_that_cannot_be_read_or_is_incomplete_refuses_the_kill(self):
        env, case = run_s6(recheck_error=True)
        assert env.kills == 0 and any("could not be re-inspected" in r for r in case.observations["kill_revalidation"]["refusals"])
        env2, case2 = run_s6(recheck_hook=lambda e, f: {e.cids["stream-processor"]: f[e.cids["stream-processor"]]})
        assert env2.kills == 0 and any("did not describe exactly" in r for r in case2.observations["kill_revalidation"]["refusals"])

    def test_the_revalidation_checks_what_it_is_given_not_what_it_remembers(self):
        env = SimEnv(rate=9, sp_per_span=True)
        env.write_override(stream_no_restart=True)
        target = env.kill_target("stream-processor")
        ids = {"kafka": env.cids["kafka"], "postgres": env.cids["postgres"], "storage-consumer": env.cids["storage-consumer"]}
        env.running["storage-consumer"] = False
        assert H.revalidate_kill(env, target, "stream-processor", ids, H.S6_NEIGHBOURS) == []
        env.running["stream-processor"] = False
        assert any("not running" in p for p in H.revalidate_kill(env, target, "stream-processor", ids, H.S6_NEIGHBOURS))

    def test_a_replaced_container_is_refused_by_the_guarded_kill_as_well(self, tmp_path):
        env, shell = live_env(tmp_path, lambda c: Result(stdout="e" * 64 + "\n") if "ps" in c else Result())
        with pytest.raises(SmokeFailure, match="no longer the one"):
            env.kill("stream-processor", "b" * 64, "S6")
        assert not any("kill" in c for c in shell.commands)


class TestS6LiveCommandSequence:
    IDS = ["b" * 64, "a" * 64, "9" * 64, "c" * 64]
    TARGET = H.KillTarget("b" * 64, "b" * 64, PROJECT, "stream-processor", f"/{PROJECT}-stream-processor-1", "running", "no")

    def router(self, status=("running", "running", "running", "exited"), policy="no", project=PROJECT):
        services = ("stream-processor", "kafka", "postgres", "storage-consumer")

        def route(command):
            if command[:2] == ["docker", "inspect"]:
                return Result(stdout="\n".join(
                    f"{cid}|{project}|{svc}|/{PROJECT}-{svc}-1|{state}|{policy if svc == 'stream-processor' else 'always'}"
                    for cid, svc, state in zip(self.IDS, services, status)) + "\n")
            return Result(stdout="b" * 64 + "\n") if "ps" in command else Result()
        return route

    def neighbour_ids(self):
        return dict(zip(("kafka", "postgres", "storage-consumer"), self.IDS[1:]))

    def test_between_the_last_progress_reading_and_the_kill_the_live_environment_runs_three_commands(self, tmp_path):
        env, shell = live_env(tmp_path, self.router())
        assert H.revalidate_kill(env, self.TARGET, "stream-processor", self.neighbour_ids(), H.S6_NEIGHBOURS) == []
        result = env.kill("stream-processor", "b" * 64, "S6")
        assert result.returncode == 0 and len(shell.commands) == 3
        inspect, ps, kill = shell.commands
        assert inspect[:2] == ["docker", "inspect"] and inspect[-4:] == self.IDS
        assert sum(1 for c in shell.commands if c[:2] == ["docker", "inspect"]) == 1
        assert ps[:4] == ["docker", "compose", "-p", PROJECT] and "ps" in ps and kill[-4:] == ["kill", "-s", "SIGKILL", "stream-processor"]
        assert not any("logs" in c for c in shell.commands) and not any(c[:2] == ["docker", "kill"] for c in shell.commands)

    @pytest.mark.parametrize("kwargs, needle", [
        ({"status": ("exited", "running", "running", "exited")}, "not running"),
        ({"policy": "unless-stopped"}, "restart policy"), ({"project": "agentops"}, "project label"),
        ({"status": ("running", "exited", "running", "exited")}, "kafka is 'exited'")])
    def test_a_container_that_changed_is_refused_by_the_live_revalidation_before_any_kill(self, tmp_path, kwargs, needle):
        env, shell = live_env(tmp_path, self.router(**kwargs))
        problems = H.revalidate_kill(env, self.TARGET, "stream-processor", self.neighbour_ids(), H.S6_NEIGHBOURS)
        assert any(needle in p for p in problems), problems
        assert not any("kill" in c for c in shell.commands)

    def test_an_inspect_that_fails_or_is_malformed_is_a_refusal(self, tmp_path):
        first_line = self.router()(["docker", "inspect"]).stdout.splitlines()[0] + "\n"
        for router in (lambda c: Result(returncode=1, stderr="no such container"), lambda c: Result(stdout="garbage\n"),
                       lambda c: Result(stdout=first_line)):
            env, shell = live_env(tmp_path, router)
            assert H.revalidate_kill(env, self.TARGET, "stream-processor", self.neighbour_ids(), H.S6_NEIGHBOURS)
            assert not any("kill" in c for c in shell.commands)

    def test_a_repeated_id_is_inspected_once(self, tmp_path):
        env, shell = live_env(tmp_path, lambda c: Result(stdout=self.router()(c).stdout.splitlines()[0] + "\n"))
        facts = env.recheck_containers(["b" * 64, "b" * 64])
        assert list(facts) == ["b" * 64] and shell.commands[0][-1] == "b" * 64 and shell.commands[0].count("b" * 64) == 1

    def test_a_short_or_non_hex_id_is_never_inspected(self, tmp_path):
        env, shell = live_env(tmp_path, self.router())
        for bad in (["b" * 12], ["B" * 64], [], ["b" * 64, "zz"]):
            with pytest.raises(SmokeFailure):
                env.recheck_containers(bad)
        assert shell.commands == []


class TestS6OneKillCallSite:
    def test_the_harness_has_one_kill_command_and_the_revalidation_cannot_kill(self):
        import inspect as _inspect
        source = Path(H.__file__).read_text(encoding="utf-8")
        assert source.count("self.cmd(*kill_arguments(case))") == 1
        assert not re.search(r'"docker",\s*"kill"', source) and "docker kill" not in source
        for function in (H.revalidate_kill, H.target_problems, H.verify_kill_target):
            assert ".kill(" not in _inspect.getsource(function)
        assert source.count('env.kill(S6_SERVICE, target.container_id, "S6")') == 1
        assert source.count('env.kill("storage-consumer", target.container_id)') == 1

    def test_s5_neither_prechecks_ids_nor_revalidates(self):
        env, case = run_s5()
        assert case.verdict == "PASS" and "kill_revalidation" not in case.observations
        assert not any(call[0] in ("recheck_containers", "container_id") for call in env.calls)
        assert env.kill_log == [("storage-consumer", "S5")]

    def test_s1_to_s5_never_revalidate_or_kill_the_stream_processor(self):
        env = SimEnv(rate=9)
        H.run_cases(env, CFG5, ["S1", "S2", "S3", "S4", "S5"])
        assert env.kill_log == [("storage-consumer", "S5")] and not any(c[0] == "recheck_containers" for c in env.calls)


class TestS6PartialPublicationOfALargeMessage:
    def test_a_message_killed_after_237_of_500_spans_is_accounted_span_by_span(self):
        produced = produced6(3, 500)                       # partition 0: messages 0, 2; partition 1: message 1
        canonical = [canon6(0, k, 0, k) for k in range(500)] + [canon6(1, k, 1, k) for k in range(237)]
        post = post6({0: 1, 1: 0}, ends=(500, 237))        # message 0 committed; messages 1 and 2 not
        freeze = H.analyse_stream_freeze(produced, post, canonical, 5)
        assert freeze.fail_problems == [] and freeze.inconclusive == []
        assert (freeze.published_uncommitted, freeze.partial_messages, freeze.replay_messages) == (237, 1, 2)
        assert freeze.predicted_growth == 1000 and freeze.frozen_records == 737
        assert freeze.partitions["1"]["published_uncommitted_spans"] == 237 and freeze.partitions["1"]["partial_messages"] == 1
        after = canonical + [canon6(1, k, 1, 237 + k) for k in range(500)] + [canon6(2, k, 0, 500 + k) for k in range(500)]
        rep = H.analyse_republication(produced, 5, freeze, after)
        assert (rep.growth, rep.missing, rep.unexpected, rep.duplicate_copies, rep.straddling, rep.same_phase) == (1000, 0, 0, 237, 237, 0)
        assert rep.fail_problems == [] and rep.inconclusive == [] and len(rep.sample) == 5

    def test_a_kill_between_two_large_messages_has_no_replay_to_prove(self):
        produced = produced6(3, 500)
        canonical = [canon6(0, k, 0, k) for k in range(500)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 1, 1: 0}, ends=(500, 0)), canonical, 5)
        assert freeze.published_uncommitted == 0 and any("nothing to republish" in r for r in freeze.inconclusive)

    def test_a_commit_before_the_last_of_five_hundred_spans_is_a_failure(self):
        produced = produced6(2, 500)
        canonical = [canon6(0, k, 0, k) for k in range(499)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 1, 1: 0}, ends=(499, 0)), canonical, 5)
        assert freeze.fail_problems and "past message 0" in freeze.fail_problems[0]

    def test_a_replay_that_publishes_only_part_of_the_message_is_missing_data(self):
        produced = produced6(3, 500)
        canonical = [canon6(0, k, 0, k) for k in range(500)] + [canon6(1, k, 1, k) for k in range(237)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 1, 1: 0}, ends=(500, 237)), canonical, 5)
        after = canonical + [canon6(1, k, 1, 237 + k) for k in range(499)] + [canon6(2, k, 0, 500 + k) for k in range(500)]
        rep = H.analyse_republication(produced, 5, freeze, after)
        assert rep.fail_problems and any("fewer than" in p for p in rep.fail_problems)

    def test_a_replay_that_publishes_an_extra_copy_of_a_large_message_is_not_a_pass(self):
        produced = produced6(3, 500)
        canonical = [canon6(0, k, 0, k) for k in range(500)] + [canon6(1, k, 1, k) for k in range(237)]
        freeze = H.analyse_stream_freeze(produced, post6({0: 1, 1: 0}, ends=(500, 237)), canonical, 5)
        after = (canonical + [canon6(1, k, 1, 237 + k) for k in range(500)] + [canon6(2, k, 0, 500 + k) for k in range(500)]
                 + [canon6(2, k, 0, 1000 + k) for k in range(500)])
        rep = H.analyse_republication(produced, 5, freeze, after)
        assert rep.fail_problems == [] and rep.same_phase == 500 and rep.inconclusive and rep.growth == 1500

    def test_the_simulation_with_a_500_span_message_kills_inside_a_message_and_converges(self):
        cfg = H.Config(idle_seconds=0.0, window_timeout=600.0, restart_wait=600.0, crash_messages=6, crash_spans=500)
        env = SimEnv(rate=7, sp_per_span=True)
        case = H.case_s6(env, cfg)
        assert case.verdict == "PASS", case.problems
        assert case.observations["replay_prediction"]["partially_published_messages"] == 1
        assert 0 < case.observations["replay_prediction"]["published_uncommitted_spans"] < 500
        assert case.observations["final_rows"]["rows"] == 3000
        assert case.observations["storage_timing"]["conflicts"] == case.observations["republication"]["duplicate_copies"]


class TestS6WindowAndFailureHandling:
    def test_a_processor_that_finished_before_the_first_reading_is_never_revalidated_or_killed(self):
        env, case = run_s6(rate=1000)
        assert case.verdict == "INCONCLUSIVE" and "nothing was killed" in case.problems[0]
        assert env.kills == 0 and not any(c[0] == "recheck_containers" for c in env.calls)
        assert case.observations["window"]["state"] == "after" and "kill_revalidation" not in case.observations

    def test_a_window_that_times_out_is_never_revalidated_or_killed(self):
        env = SimEnv(rate=1, sp_per_span=True)
        case = H.case_s6(env, H.Config(idle_seconds=0.0, window_timeout=0.0, crash_messages=30, crash_spans=4))
        assert case.verdict == "INCONCLUSIVE" and "(timeout)" in case.problems[0] and "nothing was killed" in case.problems[0]
        assert env.kills == 0 and not any(c[0] == "recheck_containers" for c in env.calls)
        assert case.observations["kill_target"]["verified"] is True            # verified up front, still never used

    def test_the_override_is_restored_after_every_refusal(self):
        for faults in ({"recheck_error": True}, {"kill_wrong_service": True}, {"rate": 1000}):
            env, _ = run_s6(**faults)
            assert env.override_history[-1] == {"batching_messages": None, "no_restart": False, "stream_no_restart": False,
                                                "storage_timing": False}


class TestS6RevalidationInTheLiveFlow:
    def run(self, tmp_path, monkeypatch, docker=None, **faults):
        return TestS6InTheLiveFlow().run(tmp_path, monkeypatch, docker=docker, **faults)

    @staticmethod
    def refusing(env, facts):
        facts[env.cids["kafka"]] = _dc.replace(facts[env.cids["kafka"]], status="exited")

    def test_a_refused_revalidation_is_inconclusive_sends_no_signal_and_still_cleans_up(self, tmp_path, monkeypatch, capsys):
        code, docker, files = self.run(tmp_path, monkeypatch, recheck_hook=self.refusing)
        out = capsys.readouterr().out
        assert code != 0 and "cleanup verified: yes" in out and H.own_markers() == []
        (case,) = files["final"]["cases"]
        assert case["verdict"] == "INCONCLUSIVE" and case["observations"]["kill_revalidation"]["refusals"]
        assert not any("kill" in c for c in docker.commands) and files["final"]["cleanup"]["verified"] is True

    def test_a_cleanup_failure_after_a_refused_revalidation_preserves_the_marker(self, tmp_path, monkeypatch):
        code, _, files = self.run(tmp_path, monkeypatch, docker=FlowDocker(leftover=True), recheck_hook=self.refusing)
        assert code == 1 and files["final"]["cleanup"]["verified"] is False and H.own_markers() == ["CLEANUP_UNVERIFIED"]
        assert any("project networks left" in p for p in files["final"]["cleanup"]["problems"])

    def test_a_good_run_records_the_revalidation_in_both_evidence_files(self, tmp_path, monkeypatch):
        code, _, files = self.run(tmp_path, monkeypatch)
        assert code == 0
        for record in files.values():
            observed = record["cases"][0]["observations"]
            assert observed["kill_revalidation"]["refusals"] == [] and len(observed["kill_revalidation"]["checked_container_ids"]) == 4
            assert len(observed["kill_target"]["neighbour_container_ids"]) == 3

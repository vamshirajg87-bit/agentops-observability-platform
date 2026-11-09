"""
scripts/tests/test_agentops_mvp_lifecycle.py

Offline tests for scripts/agentops_mvp_lifecycle.py and the `status` command of
scripts/agentops_mvp.py.

A fake Docker (a state machine over containers, networks, volumes and images) answers
every inspection; nothing real is ever run.  Resources of the OTHER stack are present in
the fake world and must never be queried or reported.

Test inventory:
    L01  The fixed read-only commands
    L02  Strict parsers
    L03  Classification: fresh, partial, complete, failed bootstrap
    L04  Classification: ambiguous resources, labels and contradictions
    L05  Inspection errors make the answer UNKNOWN
    L06  Memory readings (Windows, Linux, macOS)
    L07  Disk and port helpers
    L08  The exclusive lock
    L09  The status command: no credentials, no files, no locks, no secrets
    L10  Formatting, redaction and safe messages
    L11  Scope: nothing that modifies anything
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import textwrap
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentops_mvp as mvp  # noqa: E402
import agentops_mvp_lifecycle as lc  # noqa: E402

_DOCKER = "/usr/bin/docker"
_LOCAL = "npipe:////./pipe/dockerDesktopLinuxEngine"
_LIFECYCLE_SOURCE = Path(lc.__file__).read_text(encoding="utf-8")
_CANARY = "LEAK-CANARY-a1b2c3d4e5f6-0123456789"

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX behaviour")
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows behaviour")


# ---------------------------------------------------------------------------
# The fake Docker
# ---------------------------------------------------------------------------

def _full_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def _container(service, *, state="running", exit_code=0, health="healthy", started="2026-10-15T01:00:00.123456789Z",
               finished="0001-01-01T00:00:00Z", name=None, project="agentops-mvp", labelled_service=None):
    name = name or f"agentops-mvp-{service}-1"
    return {
        "id": _full_id(name), "name": name,
        "service": service if labelled_service is None else labelled_service, "project": project,
        "state": state, "exit": exit_code, "health": health,
        "running": "true" if state == "running" else "false", "started": started, "finished": finished,
    }


LEGACY_CONTAINERS = [
    {"id": _full_id("agentops-postgres"), "name": "agentops-postgres", "service": "postgres", "project": "agentops",
     "state": "exited", "exit": 0, "health": "none", "running": "false",
     "started": "2026-10-12T05:00:00Z", "finished": "2026-10-12T05:30:29Z"},
    {"id": _full_id("agentops-grafana"), "name": "agentops-grafana", "service": "grafana", "project": "agentops",
     "state": "exited", "exit": 255, "health": "none", "running": "false",
     "started": "2026-10-01T05:00:00Z", "finished": "2026-10-04T05:30:29Z"},
]
LEGACY_NETWORKS = {"agentops_agentops-net": {lc.LABEL_PROJECT: "agentops"}}
LEGACY_VOLUMES = {"agentops_postgres-data": {lc.LABEL_PROJECT: "agentops"}, "agentops_grafana-data": {}}
LEGACY_IMAGES = [("agentops-postgres", "latest", "255fdc081c3e"), ("agentops-trace-viewer", "local", "512fb6fb907c")]
LEGACY_WORDS = ("agentops-postgres", "agentops_postgres-data", "agentops-grafana", "agentops_agentops-net",
                "agentops-trace-viewer", "agentops_grafana-data")


class World:
    def __init__(self, containers=None, networks=None, volumes=None, images=None, engine_up=True):
        self.containers = list(LEGACY_CONTAINERS) + list(containers or [])
        self.networks = dict(LEGACY_NETWORKS)
        self.networks.update(networks or {})
        self.volumes = dict(LEGACY_VOLUMES)
        self.volumes.update(volumes or {})
        self.images = list(LEGACY_IMAGES) + list(images or [])
        self.engine_up = engine_up


_NETWORK_LABELS = {lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_NETWORK: "mvp-net", "com.docker.compose.version": _CANARY}
_VOLUME_LABELS = {lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_VOLUME: "postgres-data", lc.LABEL_MVP: "true",
                  "com.docker.compose.config-hash": _CANARY}
_ALL_IMAGES = [(f"agentops-mvp-{s}", "latest", _full_id(s)[:12]) for s in lc.SERVICES]


def complete_world() -> World:
    return World(
        containers=[
            _container("postgres", started="2026-10-15T01:00:00.100000000Z"),
            _container("db-bootstrap", state="exited", exit_code=0, health="none",
                       started="2026-10-15T01:00:05.200000000Z", finished="2026-10-15T01:03:20.500000000Z"),
            _container("viewer", started="2026-10-15T01:03:25.000000000Z"),
        ],
        networks={"agentops-mvp_mvp-net": dict(_NETWORK_LABELS)},
        volumes={"agentops-mvp-postgres-data": dict(_VOLUME_LABELS)},
        images=list(_ALL_IMAGES),
    )


class FakeDocker:
    """Answers the module's read-only commands from a World; records every call."""

    def __init__(self, world: World, *, fail=(), raises=(), garbage=None, endpoint=_LOCAL, context_rc=0):
        self.world = world
        self.fail = set(fail)
        self.raises = set(raises)
        self.garbage = dict(garbage or {})
        self.endpoint = endpoint
        self.context_rc = context_rc
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    @staticmethod
    def key(argv):
        tail = argv[1:]
        if tail[0] == "ps":
            return "ps:label" if "label=" in " ".join(tail) else "ps:name"
        if tail[0] in ("network", "volume", "image"):
            return f"{tail[0]} {tail[1]}"
        return tail[0] if tail[0] != "context" else "context inspect"

    def __call__(self, argv, env):
        self.calls.append((list(argv), dict(env)))
        key = self.key(argv)
        if key in self.raises:
            raise OSError("boom " + _CANARY)
        if key == "context inspect":
            return lc.DockerResult(self.context_rc, (self.endpoint + "\n").encode())
        if key in self.fail or (key != "info" and not self.world.engine_up):
            return lc.DockerResult(1, b"")
        if key in self.garbage:
            return lc.DockerResult(0, self.garbage[key])
        w = self.world
        if key == "info":
            return lc.DockerResult(0 if w.engine_up else 1, b"29.7.2\n" if w.engine_up else b"")
        if key.startswith("ps:"):
            filt = argv[argv.index("--filter") + 1]
            rows = []
            for c in w.containers:
                if filt.startswith("label="):
                    k, v = filt[len("label="):].split("=", 1)
                    if not (k == lc.LABEL_PROJECT and c["project"] == v):
                        continue
                elif filt.startswith("name=") and filt[len("name="):] not in c["name"]:
                    continue
                rows.append(f'{c["id"][:12]}|{c["name"]}|{c["service"]}|{c["project"]}|{c["state"]}')
            return lc.DockerResult(0, ("\n".join(rows) + "\n").encode())
        if key == "inspect":
            ids = argv[argv.index("--format") + 2:]
            out = []
            for prefix in ids:
                for c in w.containers:
                    if c["id"].startswith(prefix):
                        out.append("|".join([c["id"], c["state"], str(c["exit"]), c["health"], c["running"],
                                             c["started"], c["finished"]]))
            return lc.DockerResult(0, ("\n".join(out) + "\n").encode())
        if key == "network ls":
            names = [n for n in w.networks if "agentops-mvp" in n]
            return lc.DockerResult(0, ("\n".join(f"{n}|bridge|local" for n in names) + "\n").encode())
        if key == "network inspect":
            labels = w.networks.get(argv[3])
            return lc.DockerResult(0, json.dumps(labels).encode()) if labels is not None else lc.DockerResult(1, b"")
        if key == "volume ls":
            names = [n for n in w.volumes if "agentops-mvp" in n]
            return lc.DockerResult(0, ("\n".join(f"{n}|local" for n in names) + "\n").encode())
        if key == "volume inspect":
            labels = w.volumes.get(argv[3])
            return lc.DockerResult(0, json.dumps(labels).encode()) if labels is not None else lc.DockerResult(1, b"")
        if key == "image ls":
            rows = [f"{r}|{t}|{i}" for r, t, i in w.images if r.startswith("agentops-mvp-")]
            return lc.DockerResult(0, ("\n".join(rows) + "\n").encode())
        raise AssertionError("unexpected command: " + " ".join(argv))


def _snapshot(world: World, **kwargs):
    fake = FakeDocker(world, **kwargs)
    return lc.inspect_stack(_DOCKER, fake, {}), fake


def _report(world: World, **kwargs):
    snapshot, fake = _snapshot(world, **kwargs)
    return lc.classify(snapshot), fake


def _probes():
    return lc.Probes(memory_mib=lambda: 4096, disk_free_gib=lambda: 700.0, port_in_use=lambda port: False)


def _status(tmp_path, world=None, *, environ=None, docker=_DOCKER, fake=None, probes=None, platform_name=None):
    fake = fake or FakeDocker(world or World())
    env = {"SystemRoot": r"C:\Windows", "LOCALAPPDATA": str(tmp_path / "local"),
           "XDG_CONFIG_HOME": str(tmp_path / "local"), "PATH": "/usr/bin"}
    env.update(environ or {})
    out, err = io.StringIO(), io.StringIO()
    code = mvp.main(["status"], environ=env, platform_name=platform_name or os.name, compose_runner=fake,
                    docker=docker, home=str(tmp_path / "home"), probes=probes or _probes(), out=out, err=err)
    return code, out.getvalue(), err.getvalue(), fake


# ---------------------------------------------------------------------------
# L01  Commands
# ---------------------------------------------------------------------------

class TestCommands:

    def test_exact_argument_lists(self):
        d = _DOCKER
        assert lc.cmd_info(d) == [d, "info", "--format", "{{.ServerVersion}}"]
        assert lc.cmd_ps_by_label(d)[:6] == [d, "ps", "-a", "--filter", "label=com.docker.compose.project=agentops-mvp", "--format"]
        assert lc.cmd_ps_by_name(d)[:5] == [d, "ps", "-a", "--filter", "name=agentops-mvp"]
        assert lc.cmd_inspect_containers(d, ["abc123", "def456"])[:4] == [d, "inspect", "--type", "container"]
        assert lc.cmd_inspect_containers(d, ["abc123", "def456"])[-2:] == ["abc123", "def456"]
        assert lc.cmd_network_ls(d) == [d, "network", "ls", "--filter", "name=agentops-mvp", "--format", "{{.Name}}|{{.Driver}}|{{.Scope}}"]
        assert lc.cmd_network_labels(d) == [d, "network", "inspect", "agentops-mvp_mvp-net", "--format", "{{json .Labels}}"]
        assert lc.cmd_volume_ls(d) == [d, "volume", "ls", "--filter", "name=agentops-mvp", "--format", "{{.Name}}|{{.Driver}}"]
        assert lc.cmd_volume_labels(d) == [d, "volume", "inspect", "agentops-mvp-postgres-data", "--format", "{{json .Labels}}"]
        assert lc.cmd_image_ls(d) == [d, "image", "ls", "--filter", "reference=agentops-mvp-*", "--format", "{{.Repository}}|{{.Tag}}|{{.ID}}"]

    def test_templates_ask_for_identity_state_and_time_only(self):
        for template in (lc._PS_FORMAT, lc._STATE_FORMAT):
            for forbidden in (".Config", ".Env", ".Cmd", ".Args", ".Mounts", ".HostConfig", ".Health.Log", ".Logs",
                              "Password", "Secret", ".NetworkSettings", ".Path"):
                assert forbidden not in template, forbidden
        assert "State.Health.Log" not in lc._STATE_FORMAT

    def test_every_command_is_one_of_the_read_only_forms_and_no_shell_string(self):
        fake = FakeDocker(complete_world())
        lc.inspect_stack(_DOCKER, fake, {})
        allowed = {("info",), ("ps",), ("inspect",), ("network", "ls"), ("network", "inspect"),
                   ("volume", "ls"), ("volume", "inspect"), ("image", "ls")}
        for argv, _env in fake.calls:
            assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
            verb = tuple(argv[1:3]) if argv[1] in ("network", "volume", "image") else (argv[1],)
            assert verb in allowed, argv
            assert "compose" not in argv and all(not a.startswith("--") or a in (
                "--filter", "--format", "--type") for a in argv[1:] if a.startswith("--"))

    def test_the_legacy_stack_is_never_named_in_any_command(self):
        fake = FakeDocker(complete_world())
        lc.inspect_stack(_DOCKER, fake, {})
        flat = " ".join(" ".join(argv) for argv, _ in fake.calls)
        for word in LEGACY_WORDS:
            assert word not in flat, word

    def test_the_constants_match_the_credential_tool_and_the_compose_file(self):
        assert (lc.PROJECT_NAME, lc.VOLUME_NAME, lc.SERVICES) == (mvp.PROJECT_NAME, mvp.VOLUME_NAME, mvp.SERVICES)
        text = (Path(mvp.__file__).resolve().parents[1] / "docker" / "mvp" / "compose.yml").read_text(encoding="utf-8")
        assert re.search(rf"^name: {lc.PROJECT_NAME}$", text, re.M) and lc.VOLUME_NAME in text
        assert lc.NETWORK_NAME == f"{lc.PROJECT_NAME}_mvp-net" and "  mvp-net:" in text
        assert [lc.container_name(s) for s in lc.SERVICES] == ["agentops-mvp-postgres-1", "agentops-mvp-db-bootstrap-1",
                                                               "agentops-mvp-viewer-1"]
        assert lc.PUBLISHED_PORT == 8000 and "127.0.0.1:8000:8000" in text


# ---------------------------------------------------------------------------
# L02  Parsers
# ---------------------------------------------------------------------------

class TestParsers:

    def test_valid_rows(self):
        rows = lc.parse_ps(b"0123456789ab|agentops-mvp-viewer-1|viewer|agentops-mvp|running\n")
        assert rows == [lc.PsRow("0123456789ab", "agentops-mvp-viewer-1", "viewer", "agentops-mvp", "running")]
        assert lc.parse_ps(b"") == [] and lc.parse_ps(b"\n \n") == []
        assert lc.parse_ps(b"0123456789ab|n1||| created\n"[:0] or b"0123456789ab|n1|||created\n")[0].service == ""

    @pytest.mark.parametrize("data", [
        b"short|name|svc|proj|running\n", b"0123456789ab|na me|svc|proj|running\n", b"0123456789ab|name|svc|proj\n",
        b"0123456789ab|name|svc|proj|running|extra\n", b"0123456789ab|name|s;c|proj|running\n",
        b"0123456789ab|name|svc|proj|RUNNING\n", b"\xff\xfe\x00bad", b"0123456789ab|-name|svc|proj|running\n",
    ])
    def test_malformed_container_rows_are_rejected(self, data):
        with pytest.raises(lc.ParseError):
            lc.parse_ps(data)

    def test_oversized_output_is_rejected(self):
        with pytest.raises(lc.ParseError):
            lc.parse_ps(b"x" * 300_000)

    def test_times(self):
        assert lc.parse_time("0001-01-01T00:00:00Z") is None
        a = lc.parse_time("2026-10-15T01:00:00.123456789Z")
        b = lc.parse_time("2026-10-15T01:00:00.1234567+00:00")
        assert a == b and a.microsecond == 123456 and a.tzinfo is not None
        assert lc.parse_time("2026-10-15T03:00:00+02:00") == lc.parse_time("2026-10-15T01:00:00Z")
        for bad in ("", "yesterday", "2026-13-45T01:00:00Z", "2026-10-15 01:00:00Z", "2026-10-15T01:00:00"):
            with pytest.raises(lc.ParseError):
                lc.parse_time(bad)

    def test_state_rows(self):
        c = _container("viewer")
        row = lc.parse_states(("|".join([c["id"], "running", "0", "healthy", "true", c["started"], c["finished"]]) + "\n").encode())[0]
        assert row.running and row.health == "healthy" and row.exit_code == 0 and row.started and row.finished is None

    @pytest.mark.parametrize("line", [
        "x|running|0|healthy|true|2026-10-15T01:00:00Z|0001-01-01T00:00:00Z",
        "0" * 64 + "|running|0|odd|true|2026-10-15T01:00:00Z|0001-01-01T00:00:00Z",
        "0" * 64 + "|running|zero|healthy|true|2026-10-15T01:00:00Z|0001-01-01T00:00:00Z",
        "0" * 64 + "|running|0|healthy|maybe|2026-10-15T01:00:00Z|0001-01-01T00:00:00Z",
        "0" * 64 + "|running|0|healthy|true|nope|0001-01-01T00:00:00Z",
        "0" * 64 + "|running|0|healthy|true",
    ])
    def test_malformed_state_rows_are_rejected(self, line):
        with pytest.raises(lc.ParseError):
            lc.parse_states((line + "\n").encode())

    def test_labels(self):
        assert lc.parse_labels(b'{"a":"b"}') == {"a": "b"} and lc.parse_labels(b"null") == {} and lc.parse_labels(b"") == {}
        for bad in (b"[]", b'{"a":1}', b'{"a":null}', b"not json", b"\xff"):
            with pytest.raises(lc.ParseError):
                lc.parse_labels(bad)

    def test_name_rows(self):
        assert lc.parse_names(b"a-b|bridge|local\n", 3) == [("a-b", "bridge", "local")]
        for bad in (b"a|b\n", b"-a|b|c\n", b"a b|b|c\n"):
            with pytest.raises(lc.ParseError):
                lc.parse_names(bad, 3)


# ---------------------------------------------------------------------------
# L03  Classification
# ---------------------------------------------------------------------------

class TestClassification:

    def test_fresh_when_only_the_other_stack_exists(self):
        report, fake = _report(World())
        assert report.state == lc.STATE_FRESH and report.exit_code == 0
        assert report.details == [] and report.ambiguities == []

    def test_a_world_with_no_resources_at_all_is_fresh(self):
        world = World()
        world.containers, world.networks, world.volumes, world.images = [], {}, {}, []
        assert _report(world)[0].state == lc.STATE_FRESH

    def test_images_only_is_partial_not_fresh(self):
        report, _ = _report(World(images=list(_ALL_IMAGES)))
        assert report.state == lc.STATE_PARTIAL and any("images are built" in d for d in report.details)

    def test_a_volume_alone_is_partial_and_never_complete(self):
        report, _ = _report(World(volumes={"agentops-mvp-postgres-data": dict(_VOLUME_LABELS)}))
        assert report.state == lc.STATE_PARTIAL
        assert any("bootstrap success cannot be shown" in d for d in report.details)

    def test_a_network_alone_is_partial(self):
        assert _report(World(networks={"agentops-mvp_mvp-net": dict(_NETWORK_LABELS)}))[0].state == lc.STATE_PARTIAL

    def test_complete_requires_the_whole_evidence(self):
        report, _ = _report(complete_world())
        assert report.state == lc.STATE_COMPLETE and report.exit_code == 0
        assert any("migration ledger was not read" in d for d in report.details)
        assert report.container_lines == {"postgres": "running (healthy)", "db-bootstrap": "exited (0)",
                                          "viewer": "running (healthy)"}

    def test_running_containers_alone_never_make_it_complete(self):
        world = complete_world()
        world.containers = [c for c in world.containers if c["service"] != "db-bootstrap" or c["project"] != "agentops-mvp"]
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any("db-bootstrap container does not exist" in d for d in report.details)

    @pytest.mark.parametrize("mutate,expected", [
        (lambda w: w.volumes.pop("agentops-mvp-postgres-data"), "data volume does not exist"),
        (lambda w: w.networks.pop("agentops-mvp_mvp-net"), "network does not exist"),
        (lambda w: w.images.remove(_ALL_IMAGES[2]), "images missing: viewer"),
        (lambda w: w.images.remove(_ALL_IMAGES[1]), "images missing: db-bootstrap"),
    ])
    def test_missing_resources_prevent_complete(self, mutate, expected):
        world = complete_world()
        mutate(world)
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any(expected in d for d in report.details)

    @pytest.mark.parametrize("code", [1, 4, 5, 6, 125])
    def test_failed_bootstrap_is_partial_with_a_hold_message_and_no_reset(self, code):
        world = World(containers=[
            _container("postgres"),
            _container("db-bootstrap", state="exited", exit_code=code, health="none", finished="2026-10-15T01:03:20Z")],
            networks={"agentops-mvp_mvp-net": dict(_NETWORK_LABELS)},
            volumes={"agentops-mvp-postgres-data": dict(_VOLUME_LABELS)}, images=list(_ALL_IMAGES))
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL
        hold = [d for d in report.details if d.startswith("HOLD")]
        assert hold and f"exit code {code}" in hold[0] and "nothing was reset" in hold[0]

    def test_a_running_bootstrap_is_partial(self):
        world = complete_world()
        for c in world.containers:
            if c["service"] == "db-bootstrap" and c["project"] == "agentops-mvp":
                c.update(state="running", running="true", exit=0, health="none", finished="0001-01-01T00:00:00Z")
        world.containers = [c for c in world.containers if c["service"] != "viewer" or c["project"] != "agentops-mvp"]
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any("bootstrap is still running" in d for d in report.details)

    def test_the_viewer_not_yet_created_after_a_good_bootstrap_is_partial(self):
        world = complete_world()
        world.containers = [c for c in world.containers if c["service"] != "viewer" or c["project"] != "agentops-mvp"]
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any("viewer container does not exist" in d for d in report.details)

    @pytest.mark.parametrize("service,health,expected", [
        ("viewer", "unhealthy", "viewer container is not healthy"), ("viewer", "starting", "viewer container is not healthy"),
        ("postgres", "starting", "postgres container is not healthy"), ("postgres", "none", "postgres container is not healthy"),
    ])
    def test_unhealthy_services_prevent_complete(self, service, health, expected):
        world = complete_world()
        for c in world.containers:
            if c["service"] == service and c["project"] == "agentops-mvp":
                c["health"] = health
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any(expected in d for d in report.details)

    def test_stopped_services_after_a_down_style_stop_are_partial(self):
        world = complete_world()
        for c in world.containers:
            if c["project"] == "agentops-mvp" and c["service"] in ("postgres", "viewer"):
                c.update(state="exited", running="false", exit=0, health="none", finished="2026-10-15T02:00:00Z")
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any("not running" in d for d in report.details)

    def test_volume_survives_a_down_and_stays_partial(self):
        world = complete_world()
        world.containers = list(LEGACY_CONTAINERS)
        world.networks.pop("agentops-mvp_mvp-net")
        report, _ = _report(world)
        assert report.state == lc.STATE_PARTIAL and any("exists but no container" in d for d in report.details)

    def test_legacy_resources_never_change_the_answer(self):
        assert _report(World())[0].state == lc.STATE_FRESH
        assert _report(complete_world())[0].state == lc.STATE_COMPLETE
        report, _ = _report(complete_world())
        assert not any(word in " ".join(report.details + report.ambiguities) for word in LEGACY_WORDS)


# ---------------------------------------------------------------------------
# L04  Ambiguity
# ---------------------------------------------------------------------------

class TestAmbiguity:

    def _with(self, extra_container=None, **kwargs):
        world = complete_world()
        if extra_container:
            world.containers.append(extra_container)
        for key, value in kwargs.items():
            getattr(world, key).update(value) if isinstance(value, dict) else getattr(world, key).append(value)
        return world

    def test_unexpected_service_in_the_project(self):
        report, _ = _report(self._with(_container("worker", name="agentops-mvp-worker-1")))
        assert report.state == lc.STATE_AMBIGUOUS and report.exit_code == 6
        assert any("unexpected service" in a and "worker" in a for a in report.ambiguities)

    def test_a_container_with_an_mvp_name_and_no_project_label(self):
        stray = _container("viewer", name="agentops-mvp-viewer-7", project="")
        report, _ = _report(self._with(stray))
        assert report.state == lc.STATE_AMBIGUOUS and any("no MVP project label" in a for a in report.ambiguities)

    def test_a_container_with_an_mvp_name_in_another_project(self):
        stray = _container("viewer", name="agentops-mvp-viewer-9", project="somebody-else")
        assert _report(self._with(stray))[0].state == lc.STATE_AMBIGUOUS

    def test_wrong_container_name_for_a_known_service(self):
        world = complete_world()
        for c in world.containers:
            if c["service"] == "viewer" and c["project"] == "agentops-mvp":
                c["name"], c["id"] = "agentops-mvp-viewer-2", _full_id("agentops-mvp-viewer-2")
        report, _ = _report(world)
        assert report.state == lc.STATE_AMBIGUOUS and any("name differs" in a for a in report.ambiguities)

    def test_two_containers_for_one_service(self):
        report, _ = _report(self._with(_container("viewer", name="agentops-mvp-viewer-2")))
        assert report.state == lc.STATE_AMBIGUOUS and any("more than one container" in a for a in report.ambiguities)

    @pytest.mark.parametrize("labels", [
        {}, {lc.LABEL_PROJECT: "agentops-mvp"}, {lc.LABEL_PROJECT: "other", lc.LABEL_NETWORK: "mvp-net"},
        {lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_NETWORK: "other"},
    ])
    def test_the_expected_network_with_wrong_or_missing_labels(self, labels):
        world = complete_world()
        world.networks["agentops-mvp_mvp-net"] = labels
        report, _ = _report(world)
        assert report.state == lc.STATE_AMBIGUOUS and any("network does not belong" in a for a in report.ambiguities)

    @pytest.mark.parametrize("labels", [
        {}, {lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_VOLUME: "postgres-data"},          # missing agentops.mvp
        {lc.LABEL_MVP: "true"},                                                              # missing compose labels
        {lc.LABEL_MVP: "false", lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_VOLUME: "postgres-data"},
        {lc.LABEL_MVP: "true", lc.LABEL_PROJECT: "agentops", lc.LABEL_VOLUME: "postgres-data"},
        {lc.LABEL_MVP: "true", lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_VOLUME: "other"},
    ])
    def test_the_expected_volume_with_wrong_or_missing_labels(self, labels):
        world = complete_world()
        world.volumes["agentops-mvp-postgres-data"] = labels
        report, _ = _report(world)
        assert report.state == lc.STATE_AMBIGUOUS and any("data volume" in a for a in report.ambiguities)

    def test_an_unlabelled_volume_of_that_name_with_nothing_else_is_ambiguous(self):
        report, _ = _report(World(volumes={"agentops-mvp-postgres-data": {}}))
        assert report.state == lc.STATE_AMBIGUOUS

    def test_extra_resources_with_mvp_like_names(self):
        for extra in ({"networks": {"agentops-mvp_other": {}}}, {"volumes": {"agentops-mvp-scratch": {}}},
                      {"images": ("agentops-mvp-viewer", "old", "abcdef123456")},
                      {"images": ("agentops-mvp-extra", "latest", "abcdef123456")}):
            report, _ = _report(self._with(**extra))
            assert report.state == lc.STATE_AMBIGUOUS, extra

    def test_the_viewer_running_without_a_successful_bootstrap_is_contradictory(self):
        world = complete_world()
        for c in world.containers:
            if c["service"] == "db-bootstrap" and c["project"] == "agentops-mvp":
                c["exit"] = 6
        report, _ = _report(world)
        assert report.state == lc.STATE_AMBIGUOUS and any("has not completed successfully" in a for a in report.ambiguities)

    def test_the_viewer_running_while_postgres_is_not_is_contradictory(self):
        world = complete_world()
        for c in world.containers:
            if c["service"] == "postgres" and c["project"] == "agentops-mvp":
                c.update(state="exited", running="false")
        assert _report(world)[0].state == lc.STATE_AMBIGUOUS

    def test_the_viewer_started_before_the_bootstrap_finished_is_contradictory(self):
        world = complete_world()
        for c in world.containers:
            if c["service"] == "viewer" and c["project"] == "agentops-mvp":
                c["started"] = "2026-10-15T01:02:00Z"
        report, _ = _report(world)
        assert report.state == lc.STATE_AMBIGUOUS and any("started before the bootstrap finished" in a for a in report.ambiguities)

    def test_ambiguity_wins_over_a_partial_picture_and_changes_nothing(self):
        world = World(volumes={"agentops-mvp-postgres-data": {}}, images=list(_ALL_IMAGES))
        report, fake = _report(world)
        assert report.state == lc.STATE_AMBIGUOUS
        assert all(argv[1] in ("info", "ps", "inspect", "network", "volume", "image") for argv, _ in fake.calls)

    def test_unprintable_names_are_not_echoed(self):
        report = lc.StatusReport(lc.STATE_AMBIGUOUS, [], [], lc.Snapshot(), {})
        assert lc.printable_name("bad name\x1b[31m") == "<unprintable name>"
        assert lc.printable_name("ok-name_1") == "ok-name_1"
        assert report.exit_code == 6


# ---------------------------------------------------------------------------
# L05  Inspection errors
# ---------------------------------------------------------------------------

class TestErrors:

    def test_engine_down(self):
        report, fake = _report(World(engine_up=False))
        assert report.state == lc.STATE_UNKNOWN and report.exit_code == 7 and "ENGINE_UNAVAILABLE" in report.details
        assert [c[0][1] for c in fake.calls] == ["info"]           # nothing else is tried

    @pytest.mark.parametrize("key,code", [
        ("ps:label", "CONTAINER_LIST_FAILED"), ("ps:name", "CONTAINER_LIST_FAILED"), ("inspect", "CONTAINER_INSPECT_FAILED"),
        ("network ls", "NETWORK_LIST_FAILED"), ("network inspect", "NETWORK_INSPECT_FAILED"),
        ("volume ls", "VOLUME_LIST_FAILED"), ("volume inspect", "VOLUME_INSPECT_FAILED"), ("image ls", "IMAGE_LIST_FAILED"),
    ])
    def test_each_failing_command_makes_the_answer_unknown(self, key, code):
        report, _ = _report(complete_world(), fail={key})
        assert report.state == lc.STATE_UNKNOWN and code in report.details

    @pytest.mark.parametrize("key", ["ps:label", "ps:name", "inspect", "network ls", "network inspect", "volume ls",
                                     "volume inspect", "image ls"])
    def test_an_exception_from_the_runner_is_contained(self, key):
        report, _ = _report(complete_world(), raises={key})
        assert report.state == lc.STATE_UNKNOWN
        text = lc.format_status(report)
        assert _CANARY not in text and "boom" not in text

    @pytest.mark.parametrize("key,garbage", [
        ("ps:label", b"nonsense"), ("ps:name", b"a|b|c"), ("inspect", b"0|1|2"), ("network ls", b"x"),
        ("network inspect", b"[1,2]"), ("volume ls", b"x|y|z|w"), ("volume inspect", b"nope"), ("image ls", b"a|b"),
    ])
    def test_unreadable_output_makes_the_answer_unknown_without_echoing_it(self, key, garbage):
        report, _ = _report(complete_world(), garbage={key: garbage + _CANARY.encode()})
        assert report.state == lc.STATE_UNKNOWN
        assert _CANARY not in lc.format_status(report)

    def test_a_missing_container_state_is_incomplete(self):
        world = complete_world()
        fake = FakeDocker(world, garbage={"inspect": b""})
        report = lc.classify(lc.inspect_stack(_DOCKER, fake, {}))
        assert report.state == lc.STATE_UNKNOWN and "CONTAINER_INSPECT_INCOMPLETE" in report.details

    def test_too_many_containers(self):
        world = World(containers=[_container("viewer", name=f"agentops-mvp-viewer-{i}") for i in range(50)])
        assert _report(world)[0].state == lc.STATE_UNKNOWN

    def test_unparsable_timestamps(self):
        world = complete_world()
        for c in world.containers:
            if c["service"] == "viewer" and c["project"] == "agentops-mvp":
                c["started"] = "garbage"
        assert _report(world)[0].state == lc.STATE_UNKNOWN

    def test_errors_take_precedence_over_a_complete_looking_picture(self):
        report, _ = _report(complete_world(), fail={"image ls"})
        assert report.state == lc.STATE_UNKNOWN


# ---------------------------------------------------------------------------
# L06  Memory
# ---------------------------------------------------------------------------

_MEMINFO = textwrap.dedent("""\
    MemTotal:       16384000 kB
    MemFree:          500000 kB
    MemAvailable:    3145728 kB
    Buffers:          100000 kB
    """)

_VM_STAT = textwrap.dedent("""\
    Mach Virtual Memory Statistics: (page size of 16384 bytes)
    Pages free:                               50000.
    Pages active:                            400000.
    Pages inactive:                           30000.
    Pages speculative:                        10000.
    Pages purgeable:                           5000.
    """)


class TestMemory:

    def test_linux_meminfo(self):
        assert lc.parse_meminfo(_MEMINFO) == 3072
        assert lc.read_available_memory_mib("posix", sys_platform="linux", read_text=lambda p: _MEMINFO) == 3072

    @pytest.mark.parametrize("text", ["", "MemTotal: 1 kB\n", "MemAvailable: lots kB\n", "MemAvailable: 100 MB\n"])
    def test_linux_unreadable_meminfo_fails_closed(self, text):
        with pytest.raises(lc.LifecycleError):
            lc.parse_meminfo(text)

    def test_macos_vm_stat(self):
        assert lc.parse_vm_stat(_VM_STAT) == (50000 + 30000 + 10000) * 16384 // (1024 * 1024)
        seen = []

        def runner(argv, env):
            seen.append(list(argv))
            return lc.DockerResult(0, _VM_STAT.encode())

        assert lc.read_available_memory_mib("posix", sys_platform="darwin", runner=runner, env={}) == 1406
        assert seen == [["/usr/bin/vm_stat"]]

    @pytest.mark.parametrize("text", ["", "Pages free: 5.\n", "Mach (page size of 4096 bytes)\nPages free: x.\n"])
    def test_macos_unreadable_output_fails_closed(self, text):
        with pytest.raises(lc.LifecycleError):
            lc.parse_vm_stat(text)

    def test_macos_tool_failure_or_missing_runner_fails_closed(self):
        with pytest.raises(lc.LifecycleError):
            lc.read_available_memory_mib("posix", sys_platform="darwin", runner=lambda a, e: lc.DockerResult(1, b""), env={})
        with pytest.raises(lc.LifecycleError):
            lc.read_available_memory_mib("posix", sys_platform="darwin")

    def test_windows_uses_the_injected_reader(self):
        assert lc.read_available_memory_mib("nt", windows_reader=lambda: 5 * 1024 ** 3) == 5120

    @pytest.mark.parametrize("value", [0, -1])
    def test_a_non_positive_reading_fails_closed(self, value):
        with pytest.raises(lc.LifecycleError):
            lc.read_available_memory_mib("nt", windows_reader=lambda: value)

    def test_a_reader_that_raises_fails_closed_without_its_message(self):
        def boom():
            raise RuntimeError("secret detail " + _CANARY)

        with pytest.raises(lc.LifecycleError) as info:
            lc.read_available_memory_mib("nt", windows_reader=boom)
        assert _CANARY not in str(info.value)

    def test_an_unknown_platform_fails_closed(self):
        with pytest.raises(lc.LifecycleError):
            lc.read_available_memory_mib("posix", sys_platform="plan9")

    @windows_only
    def test_the_real_windows_reading_is_plausible(self):
        mib = lc.read_available_memory_mib("nt")
        assert 64 < mib < 4 * 1024 * 1024

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc")
    def test_the_real_linux_reading_is_plausible(self):
        assert 16 < lc.read_available_memory_mib("posix") < 4 * 1024 * 1024

    def test_thresholds(self):
        assert lc.memory_problem(2000, lc.BUILD_MIN_MIB) is not None and lc.memory_problem(2048, lc.BUILD_MIN_MIB) is None
        assert lc.memory_problem(2559, lc.UP_MIN_MIB) is not None and lc.memory_problem(2560, lc.UP_MIN_MIB) is None
        assert lc.BUILD_MIN_MIB < lc.UP_MIN_MIB < lc.DOCKER_VM_MIN_MIB * 1


# ---------------------------------------------------------------------------
# L07  Disk and port
# ---------------------------------------------------------------------------

class TestDiskAndPort:

    def test_nearest_existing_directory(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "file.env"
        assert lc.nearest_existing_directory(str(deep)) == str(tmp_path)
        assert lc.nearest_existing_directory(str(tmp_path)) == str(tmp_path)
        assert not (tmp_path / "a").exists()                       # nothing was created

    def test_disk_free_is_positive_and_does_not_create_anything(self, tmp_path):
        assert lc.disk_free_gib(str(tmp_path / "x" / "y")) > 0
        assert list(tmp_path.iterdir()) == []

    def test_disk_threshold(self):
        assert lc.disk_problem(9.9) is not None and lc.disk_problem(10.0) is None and lc.disk_problem(3, 2) is None
        assert "GiB" in lc.disk_problem(1.0)

    def test_disk_errors_fail_closed(self, monkeypatch):
        def boom(path):
            raise OSError(5, "denied " + _CANARY)

        monkeypatch.setattr(lc.shutil, "disk_usage", boom)
        with pytest.raises(lc.LifecycleError) as info:
            lc.disk_free_gib("/")
        assert _CANARY not in str(info.value)

    def test_a_port_in_use_and_a_port_that_is_free(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        busy = holder.getsockname()[1]
        try:
            assert lc.port_in_use(busy) is True
        finally:
            holder.close()
        assert lc.port_in_use(busy) is False                        # released again, nothing left behind

    @pytest.mark.parametrize("port", [0, -1, 65536, 99999, "8000", None, True, 8000.0])
    def test_invalid_ports_are_refused(self, port):
        with pytest.raises(lc.LifecycleError):
            lc.port_in_use(port)

    def test_port_5432_is_never_consulted_by_status(self, tmp_path):
        asked = []
        probes = lc.Probes(memory_mib=lambda: 4096, disk_free_gib=lambda: 700.0,
                           port_in_use=lambda port: asked.append(port) or False)
        code, out, err, fake = _status(tmp_path, World(), probes=probes)
        assert asked == [8000] and "5432" not in out


# ---------------------------------------------------------------------------
# L08  Lock
# ---------------------------------------------------------------------------

class TestLock:

    def test_acquire_release_and_reacquire(self, tmp_path):
        path = str(tmp_path / "lifecycle.lock")
        lock = lc.ExclusiveLock(path)
        assert not lock.held
        lock.acquire()
        assert lock.held and os.path.isfile(path)
        lock.release()
        lock.release()                                              # idempotent
        assert not lock.held and os.path.isfile(path)               # the file is never deleted
        with lc.ExclusiveLock(path):
            pass

    def test_contention_inside_one_process(self, tmp_path):
        path = str(tmp_path / "lifecycle.lock")
        with lc.ExclusiveLock(path):
            second = lc.ExclusiveLock(path)
            with pytest.raises(lc.LockHeldError, match="another lifecycle command is running"):
                second.acquire()
            assert not second.held
        with lc.ExclusiveLock(path):                                # free again after the first one left
            pass

    def test_contention_across_processes(self, tmp_path):
        path = str(tmp_path / "lifecycle.lock")
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import agentops_mvp_lifecycle as lc\n"
                "try:\n    lc.ExclusiveLock(sys.argv[2]).acquire(); print('ACQUIRED')\n"
                "except lc.LockHeldError as e: print('HELD:' + str(e))\n")
        scripts = str(Path(lc.__file__).resolve().parent)
        with lc.ExclusiveLock(path):
            held = subprocess.run([sys.executable, "-c", code, scripts, path], capture_output=True, text=True, timeout=60)
        assert "HELD:another lifecycle command is running" in held.stdout
        free = subprocess.run([sys.executable, "-c", code, scripts, path], capture_output=True, text=True, timeout=60)
        assert "ACQUIRED" in free.stdout

    def test_an_exception_inside_the_block_releases_the_lock(self, tmp_path):
        path = str(tmp_path / "lifecycle.lock")
        with pytest.raises(RuntimeError):
            with lc.ExclusiveLock(path):
                raise RuntimeError("boom")
        with lc.ExclusiveLock(path):
            pass

    def test_a_second_acquire_on_the_same_object_is_refused(self, tmp_path):
        lock = lc.ExclusiveLock(str(tmp_path / "lifecycle.lock")).acquire()
        try:
            with pytest.raises(lc.LifecycleError):
                lock.acquire()
        finally:
            lock.release()

    def test_the_directory_must_exist_and_is_never_created(self, tmp_path):
        with pytest.raises(lc.LifecycleError, match="does not exist"):
            lc.ExclusiveLock(str(tmp_path / "missing" / "lifecycle.lock")).acquire()
        assert not (tmp_path / "missing").exists()

    def test_a_directory_that_is_a_link_is_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        try:
            os.symlink(real, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available here")
        with pytest.raises(lc.LifecycleError):
            lc.ExclusiveLock(str(link / "lifecycle.lock")).acquire()

    def test_the_lock_path_must_be_a_regular_file(self, tmp_path):
        (tmp_path / "isdir").mkdir()
        with pytest.raises(lc.LifecycleError):
            lc.ExclusiveLock(str(tmp_path / "isdir")).acquire()

    @posix_only
    def test_the_lock_file_is_private_and_an_open_one_is_refused(self, tmp_path):
        path = tmp_path / "lifecycle.lock"
        with lc.ExclusiveLock(str(path)):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        os.chmod(path, 0o644)
        with pytest.raises(lc.LifecycleError, match="group or others"):
            lc.ExclusiveLock(str(path)).acquire()

    def test_platform_dispatch_uses_the_matching_implementation(self, tmp_path):
        calls = []
        lock = lc.ExclusiveLock(str(tmp_path / "lifecycle.lock"), platform_name="nt",
                                lock=lambda fd: calls.append("lock"), unlock=lambda fd: calls.append("unlock"))
        with lock:
            pass
        assert calls == ["lock", "unlock"]
        assert lc.ExclusiveLock("x", platform_name="nt")._lock is lc._lock_windows
        assert lc.ExclusiveLock("x", platform_name="posix")._lock is lc._lock_posix
        assert lc.ExclusiveLock("x", platform_name="nt")._unlock is lc._unlock_windows
        assert lc.ExclusiveLock("x", platform_name="posix")._unlock is lc._unlock_posix

    def test_a_refusing_lock_closes_the_descriptor(self, tmp_path):
        closed = []
        real_close = os.close

        def refuse(fd):
            raise PermissionError(13, "locked")

        lock = lc.ExclusiveLock(str(tmp_path / "lifecycle.lock"), lock=refuse)
        with pytest.raises(lc.LockHeldError):
            lock.acquire()
        assert not lock.held
        os.remove(tmp_path / "lifecycle.lock")                      # would fail on Windows if the handle leaked


# ---------------------------------------------------------------------------
# L09  The status command
# ---------------------------------------------------------------------------

class TestStatusCommand:

    def test_a_complete_stack(self, tmp_path):
        code, out, err, fake = _status(tmp_path, complete_world())
        assert code == 0 and err == ""
        assert out.startswith("MVP stack status: COMPLETE")
        for line in ("postgres: running (healthy)", "db-bootstrap: exited (0)", "viewer: running (healthy)",
                     "network agentops-mvp_mvp-net: present", "data volume agentops-mvp-postgres-data: present"):
            assert line in out
        assert "migration ledger was not read" in out and "nothing was created, changed or removed" in out

    @pytest.mark.parametrize("world,state,code", [
        (World(), "FRESH", 0), (World(images=list(_ALL_IMAGES)), "PARTIAL", 0),
        (World(volumes={"agentops-mvp-postgres-data": {}}), "AMBIGUOUS", 6), (World(engine_up=False), "UNKNOWN", 7),
    ])
    def test_exit_codes(self, tmp_path, world, state, code):
        result = _status(tmp_path, world)
        assert result[1].startswith(f"MVP stack status: {state}") and result[0] == code

    def test_status_does_not_need_a_credential_file(self, tmp_path):
        assert not (tmp_path / "local").exists()
        code, out, err, fake = _status(tmp_path, World())
        assert code == 0 and not (tmp_path / "local").exists() and not (tmp_path / "home").exists()
        assert "credential file was not read" in out

    def test_status_never_touches_credential_code_or_files(self, tmp_path, monkeypatch):
        def forbidden(*a, **k):
            raise AssertionError("credential code was called during status")

        for name in ("check_credentials", "parse_file", "_read_bytes", "init_credentials", "check_location",
                     "check_config", "generate_credentials"):
            monkeypatch.setattr(mvp, name, forbidden)
        opened = []
        real_open = os.open

        def recording(path, *a, **k):
            opened.append(str(path))
            return real_open(path, *a, **k)

        monkeypatch.setattr(mvp.os, "open", recording)
        monkeypatch.setattr(lc.os, "open", recording)
        # a real credential file exists, and must stay unread
        target = tmp_path / "local" / "agentops-mvp"
        target.mkdir(parents=True)
        (target / "credentials.env").write_bytes(b"not read")
        before = (target / "credentials.env").stat().st_mtime_ns
        code, out, err, fake = _status(tmp_path, complete_world())
        assert code == 0
        assert not any("credentials.env" in p for p in opened)
        assert (target / "credentials.env").read_bytes() == b"not read" and (target / "credentials.env").stat().st_mtime_ns == before

    def test_status_creates_and_modifies_no_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "home").mkdir()
        (tmp_path / "local").mkdir()
        before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
        _status(tmp_path, complete_world())
        _status(tmp_path, World())
        assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == before

    def test_status_takes_no_lock(self, tmp_path, monkeypatch):
        def forbidden(*a, **k):
            raise AssertionError("a lock was used during status")

        monkeypatch.setattr(lc.ExclusiveLock, "acquire", forbidden)
        monkeypatch.setattr(lc, "_lock_windows", forbidden)
        monkeypatch.setattr(lc, "_lock_posix", forbidden)
        assert _status(tmp_path, World())[0] == 0
        assert not list(tmp_path.rglob("*.lock"))

    def test_only_read_only_docker_commands_are_issued_and_no_compose(self, tmp_path):
        code, out, err, fake = _status(tmp_path, complete_world())
        verbs = [tuple(argv[1:3]) if argv[1] in ("network", "volume", "image", "context") else (argv[1],) for argv, _ in fake.calls]
        assert set(verbs) <= {("context", "inspect"), ("info",), ("ps",), ("inspect",), ("network", "ls"),
                              ("network", "inspect"), ("volume", "ls"), ("volume", "inspect"), ("image", "ls")}
        flat = " ".join(" ".join(argv) for argv, _ in fake.calls).split()
        for forbidden in ("compose", "up", "down", "build", "run", "start", "stop", "kill", "rm", "create", "exec",
                          "cp", "logs", "pull", "push", "prune", "reset", "-v", "--volumes", "-d"):
            assert forbidden not in flat, forbidden

    def test_the_child_environment_is_sanitized(self, tmp_path):
        host = {"COMPOSE_FILE": "x", "compose_profiles": "y", "POSTGRES_PASSWORD": _CANARY,
                "trace_viewer_db_password": _CANARY, "KEEP": "1"}
        code, out, err, fake = _status(tmp_path, World(), environ=host)
        assert code == 0
        for _argv, env in fake.calls:
            upper = {k.upper() for k in env}
            assert not any(k.startswith("COMPOSE_") for k in upper)
            assert not upper & {n.upper() for n in mvp.CREDENTIAL_VARIABLES}
            assert env["KEEP"] == "1"
        assert _CANARY not in out + err

    def test_no_secret_bearing_output(self, tmp_path):
        # labels in the fake world carry a canary; neither labels nor docker output may be shown
        world = complete_world()
        code, out, err, fake = _status(tmp_path, world)
        assert _CANARY not in out + err and "config-hash" not in out
        code, out, err, fake = _status(tmp_path, complete_world(), fake=FakeDocker(complete_world(), garbage={"volume ls": _CANARY.encode()}))
        assert code == 7 and _CANARY not in out + err

    def test_a_non_local_engine_is_refused_before_any_inspection(self, tmp_path):
        code, out, err, fake = _status(tmp_path, World(), environ={"DOCKER_HOST": "tcp://10.1.2.3:2375"})
        assert code == mvp.EXIT_REFUSED and "local" in err and fake.calls == []
        code, out, err, fake = _status(tmp_path, World(), fake=FakeDocker(World(), endpoint="ssh://user@host"))
        assert code == mvp.EXIT_REFUSED and [c[0][1] for c in fake.calls] == ["context"]

    def test_an_uninspectable_context_or_missing_tool_is_unknown_not_a_crash(self, tmp_path):
        code, out, err, fake = _status(tmp_path, World(), fake=FakeDocker(World(), context_rc=1))
        assert code == 7 and "MVP stack status: UNKNOWN" in out and "could not be reached" in out
        code, out, err, fake = _status(tmp_path, World(), docker=None)
        # no explicit docker path: the lookup finds nothing in this controlled run
        assert code in (0, 7)

    def test_a_missing_docker_tool_gives_unknown(self, tmp_path):
        out, err = io.StringIO(), io.StringIO()
        code = mvp.main(["status"], environ={"SystemRoot": r"C:\Windows"}, platform_name=os.name,
                        compose_runner=FakeDocker(World()), which=lambda name: None, home=str(tmp_path),
                        probes=_probes(), out=out, err=err)
        assert code == 7 and "could not be reached" in out.getvalue() and err.getvalue() == ""

    def test_the_resource_hints_are_shown_and_never_block_status(self, tmp_path):
        low = lc.Probes(memory_mib=lambda: 800, disk_free_gib=lambda: 2.0, port_in_use=lambda p: True)
        code, out, err, fake = _status(tmp_path, complete_world(), probes=low)
        assert code == 0 and "memory: 800 MiB available" in out and "LOW for a launch" in out
        assert "disk: 2.0 GiB free" in out and "port 8000: in use" in out

    def test_a_failing_probe_is_reported_not_raised(self, tmp_path):
        def bad():
            raise lc.LifecycleError("x")

        probes = lc.Probes(memory_mib=bad, disk_free_gib=bad, port_in_use=lambda p: (_ for _ in ()).throw(lc.LifecycleError("x")))
        code, out, err, fake = _status(tmp_path, World(), probes=probes)
        assert code == 0 and "memory: could not be read" in out and "disk: could not be read" in out
        assert "could not be checked" in out

    def test_existing_commands_are_unchanged(self):
        choices = set(mvp._build_parser()._subparsers._group_actions[0].choices)
        assert {"init-credentials", "check-credentials", "check-config", "status", "build", "up", "seed-demo"} == choices
        assert mvp.EXIT_AMBIGUOUS == 6 and mvp.EXIT_UNKNOWN == 7
        assert [mvp.EXIT_OK, mvp.EXIT_INTERNAL, mvp.EXIT_USAGE, mvp.EXIT_REFUSED, mvp.EXIT_EXISTS, mvp.EXIT_FAILED] == [0, 1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------
# L10  Formatting, redaction, safe messages
# ---------------------------------------------------------------------------

class TestFormatting:

    def test_fixed_vocabulary_for_every_unknown_code(self):
        for code in lc.CODE_TEXT:
            report = lc.StatusReport(lc.STATE_UNKNOWN, [code], [], lc.Snapshot(), {})
            text = lc.format_status(report)
            assert lc.CODE_TEXT[code] in text and "UNKNOWN" in text

    def test_every_error_code_the_inspection_can_produce_has_text(self):
        codes = set(re.findall(r'"([A-Z][A-Z_]+_(?:FAILED|UNREADABLE|INCOMPLETE|UNAVAILABLE|CONTAINERS))"', _LIFECYCLE_SOURCE))
        assert codes <= set(lc.CODE_TEXT), codes - set(lc.CODE_TEXT)

    def test_ambiguity_lists_are_bounded(self):
        report = lc.StatusReport(lc.STATE_AMBIGUOUS, [], [f"item {i}" for i in range(30)], lc.Snapshot(), {})
        text = lc.format_status(report)
        assert text.count("  ! item") == lc.MAX_LISTED_NAMES and "and 20 more" in text and "nothing was changed" in text

    def test_safe_message(self):
        assert lc.safe_message(lc.LifecycleError("fixed text")) == "fixed text"
        assert lc.safe_message(ValueError("password=hunter2 " + _CANARY)) == "internal error (ValueError)"

    def test_redaction(self):
        text = f"login failed for POSTGRES_PASSWORD=abc123 using {_CANARY} and token: zzz"
        cleaned = lc.redact(text, [_CANARY, "", "abc123"])
        assert _CANARY not in cleaned and "abc123" not in cleaned and "zzz" not in cleaned and "***" in cleaned
        longer = lc.redact("aXbXc", ["aXb", "X"])
        assert "X" not in longer.replace("***", "") or longer.count("***") >= 1


# ---------------------------------------------------------------------------
# L11  Scope
# ---------------------------------------------------------------------------

class TestScope:

    def _tree(self):
        return ast.parse(_LIFECYCLE_SOURCE)

    def test_only_the_standard_library_is_imported(self):
        imported = set()
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add((node.module or "").split(".")[0])
        assert imported <= set(sys.stdlib_module_names) | {"__future__"}
        assert "subprocess" not in imported and "agentops_mvp" not in imported

    def test_no_process_start_no_removal_no_rename_no_write(self):
        banned = {"system", "popen", "Popen", "run", "call", "check_call", "check_output", "spawn", "startfile",
                  "unlink", "remove", "rmdir", "rmtree", "removedirs", "rename", "truncate", "mkdir",
                  "makedirs", "write_text", "write_bytes", "chmod", "chown", "symlink", "link", "touch"}
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in banned, node.func.attr
                # str.replace is fine; os.replace / shutil.* are not
                if node.func.attr == "replace":
                    assert not (isinstance(node.func.value, ast.Name) and node.func.value.id in ("os", "shutil"))
        assert "shell=True" not in _LIFECYCLE_SOURCE and "os.system" not in _LIFECYCLE_SOURCE

    def test_files_are_opened_only_by_the_lock_and_only_for_reading_elsewhere(self):
        tree = self._tree()
        for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(function):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "open" \
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    assert function.name == "acquire", function.name
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                    raise AssertionError("builtin open is not used")
        assert "write_text" not in _LIFECYCLE_SOURCE and "'w'" not in _LIFECYCLE_SOURCE and '"w"' not in _LIFECYCLE_SOURCE

    def test_docker_verb_constants_are_read_only(self):
        constants = {n.value for n in ast.walk(self._tree()) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for verb in ("compose", "up", "down", "build", "run", "start", "stop", "restart", "kill", "rm", "create", "exec",
                     "cp", "logs", "pull", "push", "prune", "reset", "--volumes", "--force", "--detach", "-d", "-v",
                     "system", "context", "export", "import", "save", "load", "commit", "tag", "update", "wait"):
            assert verb not in constants, verb
        assert {"info", "ps", "inspect", "network", "volume", "image", "ls"} <= constants

    def test_no_credential_or_database_vocabulary(self):
        for word in ("credentials.env", "POSTGRES_PASSWORD", "psycopg", "psql", "sqlite", "SELECT ", "INSERT ", "CREATE TABLE"):
            assert word not in _LIFECYCLE_SOURCE, word

    def test_no_launch_state_file(self):
        for word in ("launch-state", "launch_state", ".json'", 'json")'):
            assert word not in _LIFECYCLE_SOURCE or word == ".json'", word
        assert "json.dump" not in _LIFECYCLE_SOURCE

    def test_the_modified_cli_still_holds_the_old_guarantees(self):
        source = Path(mvp.__file__).read_text(encoding="utf-8")
        status = source[source.index("def _status_command"):source.index("def main(")]
        for word in ("init_credentials", "check_credentials", "check_config", "ExclusiveLock", "parse_file", "check_location",
                     "open(", "unlink(", ".write(", "write_text(", "write_bytes("):
            assert word not in status, word
        assert "require_local_engine" in status and "build_child_environment" in status


# ---------------------------------------------------------------------------
# L12  Classifier hardening: unsafe snapshots can never be COMPLETE
# ---------------------------------------------------------------------------

def _info(service, **over):
    base = dict(name=lc.container_name(service), service=service, project=lc.PROJECT_NAME, state="running",
                exit_code=0, health="healthy", running=True,
                started=lc.parse_time("2026-10-15T01:03:25Z"), finished=None)
    base.update(over)
    return lc.ContainerInfo(**base)


def _good_snapshot():
    boot = _info("db-bootstrap", state="exited", health="none", running=False,
                 started=lc.parse_time("2026-10-15T01:00:05Z"), finished=lc.parse_time("2026-10-15T01:03:20Z"))
    return lc.Snapshot(containers=[_info("postgres"), boot, _info("viewer")],
                       network={lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_NETWORK: "mvp-net"},
                       volume={lc.LABEL_PROJECT: "agentops-mvp", lc.LABEL_VOLUME: "postgres-data", lc.LABEL_MVP: "true"},
                       images={s: True for s in lc.SERVICES})


def _edit(snapshot, service, **over):
    snapshot.containers = [lc.ContainerInfo(**{**c.__dict__, **over}) if c.service == service else c
                           for c in snapshot.containers]
    return snapshot


def _unsafe_snapshots():
    def drop(service):
        s = _good_snapshot()
        s.containers = [c for c in s.containers if c.service != service]
        return s

    cases = {
        "baseline-sanity-is-complete": None,
        "container without project label": lambda s: _edit(s, "viewer", project=""),
        "container in another project": lambda s: _edit(s, "postgres", project="other"),
        "unexpected container": lambda s: s.containers.append(_info("worker")),
        "duplicate service": lambda s: s.containers.append(_info("viewer", name="agentops-mvp-viewer-2")),
        "stray container": lambda s: s.stray_containers.append("agentops-mvp-x-1"),
        "wrong volume label": lambda s: s.volume.update({lc.LABEL_MVP: "no"}),
        "no volume": lambda s: setattr(s, "volume", None),
        "no network": lambda s: setattr(s, "network", None),
        "wrong network label": lambda s: s.network.update({lc.LABEL_NETWORK: "x"}),
        "viewer started before bootstrap finished": lambda s: _edit(s, "viewer", started=lc.parse_time("2026-10-15T01:00:00Z")),
        "viewer without start time": lambda s: _edit(s, "viewer", started=None),
        "bootstrap exit 1": lambda s: _edit(s, "db-bootstrap", exit_code=1),
        "bootstrap exit unknown": lambda s: _edit(s, "db-bootstrap", exit_code=None),
        "bootstrap without finish time": lambda s: _edit(s, "db-bootstrap", finished=None),
        "bootstrap running": lambda s: _edit(s, "db-bootstrap", state="running", running=True, finished=None),
        "missing image": lambda s: s.images.update({"viewer": False}),
        "image entry absent": lambda s: s.images.pop("db-bootstrap"),
        "engine unreachable": lambda s: s.errors.append("ENGINE_UNAVAILABLE"),
        "postgres unhealthy": lambda s: _edit(s, "postgres", health="unhealthy"),
        "viewer unhealthy": lambda s: _edit(s, "viewer", health="unhealthy"),
        "postgres health unknown": lambda s: _edit(s, "postgres", health=None),
        "viewer running flag unknown": lambda s: _edit(s, "viewer", running=None),
        "viewer healthy but postgres stopped": lambda s: _edit(s, "postgres", state="exited", running=False),
        "postgres starting, viewer healthy": lambda s: _edit(s, "postgres", health="starting"),
        "extra network": lambda s: s.other_networks.append("agentops-mvp_x"),
        "extra volume": lambda s: s.other_volumes.append("agentops-mvp-x"),
        "extra image": lambda s: s.other_images.append("agentops-mvp-x"),
    }
    for name, mutate in cases.items():
        s = _good_snapshot()
        if mutate:
            mutate(s)
        yield name, s
    for service in lc.SERVICES:
        yield f"no {service} container", drop(service)


class TestClassifierHardening:

    def test_the_unmutated_snapshot_is_complete(self):
        assert lc.classify(_good_snapshot()).state == lc.STATE_COMPLETE

    @pytest.mark.parametrize("name,snapshot", [p for p in _unsafe_snapshots() if p[0] != "baseline-sanity-is-complete"],
                             ids=lambda v: v if isinstance(v, str) else "")
    def test_no_unsafe_snapshot_is_complete(self, name, snapshot):
        report = lc.classify(snapshot)
        assert report.state in (lc.STATE_PARTIAL, lc.STATE_AMBIGUOUS, lc.STATE_UNKNOWN), name
        assert report.exit_code in (0, 6, 7)
        assert report.state != lc.STATE_FRESH

    def test_expected_states_for_the_named_mutations(self):
        wanted = {"container without project label": lc.STATE_AMBIGUOUS, "unexpected container": lc.STATE_AMBIGUOUS,
                  "duplicate service": lc.STATE_AMBIGUOUS, "wrong volume label": lc.STATE_AMBIGUOUS,
                  "viewer started before bootstrap finished": lc.STATE_AMBIGUOUS, "bootstrap exit 1": lc.STATE_AMBIGUOUS,
                  "missing image": lc.STATE_PARTIAL, "engine unreachable": lc.STATE_UNKNOWN,
                  "postgres unhealthy": lc.STATE_PARTIAL, "viewer unhealthy": lc.STATE_PARTIAL,
                  "viewer healthy but postgres stopped": lc.STATE_AMBIGUOUS}
        got = {name: lc.classify(s).state for name, s in _unsafe_snapshots()}
        for name, state in wanted.items():
            assert got[name] == state, name

    def test_a_snapshot_with_errors_ignores_everything_else(self):
        s = _good_snapshot()
        s.errors.append("IMAGE_LIST_FAILED")
        assert lc.classify(s).state == lc.STATE_UNKNOWN


# ---------------------------------------------------------------------------
# L13  Health template (B3J-167)
# ---------------------------------------------------------------------------

class _StrictTemplateDocker(FakeDocker):
    """Rejects, as the real engine does, a bare `.State.Health` lookup on a container with no health block."""

    def __call__(self, argv, env):
        if self.key(argv) == "inspect":
            fmt = argv[argv.index("--format") + 1]
            has_bare = re.search(r"\.State\.Health(?!\w)", fmt) is not None
            uses_index = 'index .State "Health"' in fmt
            if has_bare and not uses_index and any(c["health"] == "none" for c in self.world.containers):
                self.calls.append((list(argv), dict(env)))
                return lc.DockerResult(1, b"template parsing error: map has no entry for key")
        return super().__call__(argv, env)


class TestHealthTemplate:

    def test_the_template_uses_a_lookup_that_tolerates_a_missing_health_block(self):
        assert 'index .State "Health"' in lc._STATE_FORMAT
        assert "{{if .State.Health}}" not in lc._STATE_FORMAT
        assert not re.search(r"\.State\.Health(?!\w)", lc._STATE_FORMAT.replace('index .State "Health"', ""))
        assert "{{else}}none{{end}}" in lc._STATE_FORMAT
        for forbidden in ("Health.Log", ".Config", ".Env", "Output"):
            assert forbidden not in lc._STATE_FORMAT

    def test_a_complete_world_is_classified_through_the_strict_engine(self):
        # db-bootstrap has no healthcheck ("none"); a bare lookup would make this UNKNOWN
        snapshot = lc.inspect_stack(_DOCKER, _StrictTemplateDocker(complete_world()), {})
        assert snapshot.errors == [] and lc.classify(snapshot).state == lc.STATE_COMPLETE

    def test_the_strict_engine_really_rejects_the_old_template(self, monkeypatch):
        monkeypatch.setattr(lc, "_STATE_FORMAT", lc._STATE_FORMAT.replace(
            '{{with index .State "Health"}}{{.Status}}{{else}}none{{end}}',
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"))
        report = lc.classify(lc.inspect_stack(_DOCKER, _StrictTemplateDocker(complete_world()), {}))
        assert report.state == lc.STATE_UNKNOWN and "CONTAINER_INSPECT_FAILED" in report.details

    @pytest.mark.parametrize("health", ["healthy", "unhealthy", "starting", "none"])
    def test_every_health_value_is_parsed(self, health):
        c = _container("viewer", health=health)
        row = "|".join([c["id"], c["state"], "0", health, "true", c["started"], c["finished"]]) + "\n"
        assert lc.parse_states(row.encode())[0].health == health

    @pytest.mark.parametrize("health", ["<no value>", "<nil>", "null", ""])
    def test_a_null_or_missing_health_rendering_is_not_accepted(self, health):
        c = _container("viewer")
        row = "|".join([c["id"], c["state"], "0", health, "true", c["started"], c["finished"]]) + "\n"
        with pytest.raises(lc.ParseError):
            lc.parse_states(row.encode())

    def test_an_exited_bootstrap_without_health_parses(self):
        c = _container("db-bootstrap", state="exited", exit_code=0, health="none",
                       finished="2026-10-15T01:03:20.500000000Z")
        row = "|".join([c["id"], "exited", "0", "none", "false", c["started"], c["finished"]]) + "\n"
        parsed = lc.parse_states(row.encode())[0]
        assert parsed.health == "none" and parsed.exit_code == 0 and not parsed.running and parsed.finished

    @pytest.mark.parametrize("world_factory,state", [
        (lambda: World(), lc.STATE_FRESH), (lambda: World(images=list(_ALL_IMAGES)), lc.STATE_PARTIAL),
        (complete_world, lc.STATE_COMPLETE),
    ])
    def test_classification_is_unchanged_with_the_strict_engine(self, world_factory, state):
        assert lc.classify(lc.inspect_stack(_DOCKER, _StrictTemplateDocker(world_factory()), {})).state == state


# ---------------------------------------------------------------------------
# L14  The guarded image-build command (B3J-168).  A fake engine only: no real build.
# ---------------------------------------------------------------------------

import test_agentops_mvp_config as cfg  # noqa: E402  (helpers: credential files, the resolved configuration)

_REPO = Path(mvp.__file__).resolve().parents[1]
_BASE_IMAGES = {"postgres:17.11", "python:3.11-slim-bookworm", "python:3.13-slim-bookworm"}
_HELP = b"Usage:  docker compose build [OPTIONS] [SERVICE...]\n\nBuild or rebuild services\n"
_BUILD_ORDER = ["postgres", "viewer", "db-bootstrap"]


class BuildDocker(FakeDocker):
    """A fake engine that also understands the few commands the build command issues."""

    def __init__(self, world=None, *, engine_mib=7800, base_images=None, help_rc=0, help_text=_HELP,
                 build_plan=None, create_after=None, config=None, **kwargs):
        super().__init__(world if world is not None else World(), **kwargs)
        self.engine_mib = engine_mib
        self.base_images = set(_BASE_IMAGES if base_images is None else base_images)
        self.help_rc, self.help_text = help_rc, help_text
        self.build_plan = dict(build_plan or {})            # service -> ("fail", rc, output) | "timeout" | "no-image" | "crash"
        self.create_after = create_after                    # callable(world) run after the last build
        self.config = cfg._resolved() if config is None else config
        self.builds: list[tuple[list[str], dict[str, str]]] = []
        self.first_inspect_hook = None
        self.fail_base_lookup = False

    def __call__(self, argv, env):
        if self.first_inspect_hook and argv[1:2] == ["ps"]:
            hook, self.first_inspect_hook = self.first_inspect_hook, None
            hook()
        if argv[1:2] == ["compose"]:
            self.calls.append((list(argv), dict(env)))
            if "config" in argv:
                return lc.DockerResult(0, json.dumps(self.config).encode())
            if argv[-2:] == ["build", "--help"]:
                return lc.DockerResult(self.help_rc, self.help_text)
            assert argv[-2] == "build", argv
            service = argv[-1]
            self.builds.append((list(argv), dict(env)))
            plan = self.build_plan.get(service)
            if plan == "timeout":
                raise subprocess.TimeoutExpired(argv, 1800)
            if plan == "crash":
                raise RuntimeError("boom " + _CANARY)
            if isinstance(plan, tuple) and plan[0] == "fail":
                return lc.DockerResult(plan[1], plan[2].encode())
            if plan != "no-image":
                self.world.images.append((f"agentops-mvp-{service}", "latest", _full_id(service)[:12]))
            if len(self.builds) == len(_BUILD_ORDER) and self.create_after:
                self.create_after(self.world)
            return lc.DockerResult(0, b"#1 building\n")
        if argv[1:3] == ["info", "--format"] and argv[3] == "{{.MemTotal}}":
            self.calls.append((list(argv), dict(env)))
            if "info" in self.fail:
                return lc.DockerResult(1, b"")
            return lc.DockerResult(0, str(self.engine_mib * 1024 * 1024).encode() + b"\n")
        if argv[1:3] == ["image", "ls"] and not argv[argv.index("--filter") + 1].startswith("reference=agentops-mvp-"):
            self.calls.append((list(argv), dict(env)))
            if self.fail_base_lookup:
                return lc.DockerResult(1, b"")
            ref = argv[argv.index("--filter") + 1][len("reference="):]
            return lc.DockerResult(0, b"0123456789ab\n" if ref in self.base_images else b"")
        return super().__call__(argv, env)

    @property
    def build_services(self):
        return [argv[-1] for argv, _ in self.builds]


class _Run:
    def __init__(self, code, out, err, target, docker):
        self.code, self.out, self.err, self.target, self.docker = code, out, err, target, docker

    @property
    def text(self):
        return self.out + self.err


def _prepare(tmp_path, values=None):
    if os.name == "nt":
        target, fake = cfg._write_valid(tmp_path, values=values)
        return target, fake, "nt"
    target = cfg._target(tmp_path)
    target.parent.mkdir(parents=True)
    os.chmod(target.parent, 0o700)
    target.write_bytes(cfg._content(values))
    os.chmod(target, 0o600)

    def forbidden(argv):
        raise AssertionError("no external tool may run on POSIX: " + " ".join(argv))

    return target, forbidden, "posix"


def _probes_with(memory=4096, disk=700.0):
    if callable(memory):
        return lc.Probes(memory_mib=memory, disk_free_gib=lambda: disk, port_in_use=lambda p: False)
    return lc.Probes(memory_mib=lambda: memory, disk_free_gib=lambda: disk, port_in_use=lambda p: False)


def _build_cli(tmp_path, docker=None, *, probes=None, host=None, prepared=None, repo_root=_REPO, no_file=False):
    docker = docker if docker is not None else BuildDocker()
    target, runner, platform = prepared if prepared else _prepare(tmp_path)
    if no_file:
        target = target.parent / "missing" / mvp.FILE_NAME
    environ = {"SystemRoot": r"C:\Windows", "PATH": "/usr/bin", "DOCKER_CONFIG": "/home/x/.docker"}
    environ.update(host or {})
    out, err = io.StringIO(), io.StringIO()
    code = mvp.main(["build", "--credentials-file", str(target)], environ=environ, platform_name=platform,
                    runner=runner, compose_runner=docker, docker=_DOCKER, repo_root=repo_root,
                    probes=probes or _probes_with(), out=out, err=err)
    return _Run(code, out.getvalue(), err.getvalue(), target, docker)


class TestBuildCommand:

    def test_a_successful_sequential_build(self, tmp_path):
        run = _build_cli(tmp_path)
        assert run.code == 0, run.err
        assert run.docker.build_services == _BUILD_ORDER
        assert run.out.startswith("images built: postgres, viewer, db-bootstrap")
        assert "no container, network or volume was created" in run.out
        assert {r for r, _t, _i in run.docker.world.images if r.startswith("agentops-mvp-")} == {
            "agentops-mvp-postgres", "agentops-mvp-viewer", "agentops-mvp-db-bootstrap"}

    def test_the_exact_compose_arguments(self, tmp_path):
        run = _build_cli(tmp_path)
        compose_file = _REPO / "docker" / "mvp" / "compose.yml"
        for service, (argv, _env) in zip(_BUILD_ORDER, run.docker.builds):
            assert argv == [_DOCKER, "compose", "-p", "agentops-mvp", "--project-directory", str(compose_file.parent),
                            "-f", str(compose_file), "build", service]
        assert mvp.build_capability_argv(_DOCKER, _REPO) == [
            _DOCKER, "compose", "-p", "agentops-mvp", "--project-directory", str(compose_file.parent),
            "-f", str(compose_file), "build", "--help"]

    def test_only_permitted_commands_and_no_forbidden_option(self, tmp_path):
        run = _build_cli(tmp_path)
        kinds = set()
        for argv, _env in run.docker.calls:
            tail = argv[1:]
            if tail[0] == "compose":
                kinds.add("compose " + ("config" if "config" in tail else "build"))
            else:
                kinds.add(" ".join(tail[:2]) if tail[0] in ("context", "network", "volume", "image") else tail[0])
        assert kinds <= {"compose config", "compose build", "context inspect", "info", "ps", "inspect", "network ls",
                         "network inspect", "volume ls", "volume inspect", "image ls"}
        flat = " ".join(" ".join(a) for a, _ in run.docker.calls).split()
        for forbidden in ("up", "down", "run", "start", "stop", "kill", "rm", "create", "exec", "pull", "push", "prune",
                          "--pull", "--no-cache", "--push", "--build", "--force-recreate", "--volumes", "-v", "-d",
                          "--build-arg", "--secret", "--ssh", "--env-file", "system", "reset"):
            assert forbidden not in flat, forbidden

    def test_credentials_are_never_in_arguments_and_builds_get_only_a_fixed_placeholder(self, tmp_path):
        real = set(cfg._values().values())
        host = {"POSTGRES_PASSWORD": _CANARY, "COMPOSE_PROFILES": "x", "compose_file": "y"}
        run = _build_cli(tmp_path, host=host)
        assert run.code == 0, run.err
        build_envs = [e for _, e in run.docker.builds]
        for argv, env in run.docker.calls:
            assert not any(v in " ".join(argv) for v in real | {_CANARY})
            assert not any(v in env.values() for v in real | {_CANARY})
            assert not any(k.upper().startswith("COMPOSE_") for k in env)
            if env not in build_envs:                              # inspections get no credential name at all
                assert not {k.upper() for k in env} & {n.upper() for n in mvp.CREDENTIAL_VARIABLES}
        for env in build_envs:
            for name in mvp.CREDENTIAL_VARIABLES:
                assert env[name] == mvp._BUILD_PLACEHOLDER
        assert not any(v in run.text for v in real | {_CANARY})

    def test_production_uses_the_bounded_build_runner_for_builds_only(self, tmp_path, monkeypatch):
        used = {"inspect": [], "build": []}
        docker = BuildDocker()
        monkeypatch.setattr(mvp, "default_compose_runner", lambda argv, env: used["inspect"].append(list(argv)) or docker(argv, env))
        monkeypatch.setattr(mvp, "default_build_runner", lambda argv, env: used["build"].append(list(argv)) or docker(argv, env))
        target, runner, platform = _prepare(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        code = mvp.main(["build", "--credentials-file", str(target)], environ={"SystemRoot": r"C:\Windows"},
                        platform_name=platform, runner=runner, docker=_DOCKER, repo_root=_REPO,
                        probes=_probes_with(), out=out, err=err)
        assert code == 0, err.getvalue()
        assert [a[-1] for a in used["build"]] == _BUILD_ORDER and all(a[-2] == "build" for a in used["build"])
        assert used["inspect"] and not any(a[-2] == "build" and a[-1] in _BUILD_ORDER for a in used["inspect"])

    # -- preflight refusals: nothing is built ------------------------------------------------------

    def _refused(self, run, fragment, code=mvp.EXIT_REFUSED):
        assert run.code == code, (run.code, run.err)
        assert fragment in run.err, run.err
        assert run.docker.builds == []
        assert run.out == ""

    def test_missing_credentials(self, tmp_path):
        run = _build_cli(tmp_path, no_file=True)
        assert run.code != 0 and run.docker.calls == [] and run.docker.builds == []

    def test_invalid_credentials(self, tmp_path):
        prepared = _prepare(tmp_path)
        weak = cfg._values()["POSTGRES_PASSWORD"].encode()
        prepared[0].write_bytes(prepared[0].read_bytes().replace(weak, b"short"))
        run = _build_cli(tmp_path, prepared=prepared)
        assert run.code != 0 and run.docker.builds == [] and run.docker.calls == []

    def test_an_invalid_configuration(self, tmp_path):
        config = cfg._resolved()
        config["services"]["extra"] = {"build": {}}
        run = _build_cli(tmp_path, BuildDocker(config=config))
        self._refused(run, "configuration is not acceptable")

    def test_a_non_local_engine_is_refused(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(endpoint="tcp://10.1.2.3:2375"))
        self._refused(run, "not a local endpoint")

    def test_an_unsupported_compose_is_refused_without_assuming_support(self, tmp_path):
        for index, docker in enumerate((BuildDocker(help_rc=1), BuildDocker(help_text=b"Usage: docker compose up\n"),
                                        BuildDocker(help_text=b"Usage:  docker compose build [OPTIONS]\n"))):
            run = _build_cli(tmp_path / str(index), docker)
            self._refused(run, "does not support building named services", mvp.EXIT_FAILED)

    def test_low_host_memory(self, tmp_path):
        run = _build_cli(tmp_path, probes=_probes_with(memory=2047))
        self._refused(run, "available memory is 2047 MiB; 2048 MiB is required")
        assert _build_cli(tmp_path / "ok", probes=_probes_with(memory=2048)).code == 0

    def test_unreadable_host_memory(self, tmp_path):
        def bad():
            raise lc.LifecycleError("x")

        self._refused(_build_cli(tmp_path, probes=_probes_with(memory=bad)), "available memory could not be read")

    def test_insufficient_engine_memory(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(engine_mib=3000))
        self._refused(run, "engine has too little memory")
        assert _build_cli(tmp_path / "ok", BuildDocker(engine_mib=3584)).code == 0

    def test_unreadable_engine_memory(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(fail={"info"}))
        assert run.code != 0 and run.docker.builds == []

    def test_low_disk_space(self, tmp_path):
        run = _build_cli(tmp_path, probes=_probes_with(disk=9.9))
        self._refused(run, "free disk space is 9.9 GiB; 10 GiB is required")
        assert _build_cli(tmp_path / "ok", probes=_probes_with(disk=10.0)).code == 0

    @pytest.mark.parametrize("missing", ["postgres:17.11", "python:3.11-slim-bookworm", "python:3.13-slim-bookworm"])
    def test_a_missing_base_image_stops_before_any_build(self, tmp_path, missing):
        run = _build_cli(tmp_path, BuildDocker(base_images=_BASE_IMAGES - {missing}))
        self._refused(run, "base images are not present locally (nothing is pulled): " + missing)

    def test_a_failing_base_image_lookup(self, tmp_path):
        docker = BuildDocker()
        docker.fail_base_lookup = True
        self._refused(_build_cli(tmp_path, docker), "a base image could not be looked up")

    @pytest.mark.parametrize("label,factory,fragment", [
        ("foreign container with an MVP name", lambda: World(containers=[_container("viewer", name="agentops-mvp-viewer-7", project="")]), "unexpected, conflicting"),
        ("unexpected service", lambda: World(containers=[_container("worker", name="agentops-mvp-worker-1")]), "unexpected, conflicting"),
        ("unlabelled volume", lambda: World(volumes={"agentops-mvp-postgres-data": {}}), "unexpected, conflicting"),
        ("conflicting volume labels", lambda: World(volumes={"agentops-mvp-postgres-data": {**_VOLUME_LABELS, lc.LABEL_PROJECT: "agentops"}}), "unexpected, conflicting"),
        ("conflicting network labels", lambda: World(networks={"agentops-mvp_mvp-net": {lc.LABEL_PROJECT: "other"}}), "unexpected, conflicting"),
        ("extra MVP-like network", lambda: World(networks={"agentops-mvp_other": {}}), "unexpected, conflicting"),
        ("extra MVP-like image", lambda: World(images=[("agentops-mvp-extra", "latest", "abcdef123456")]), "unexpected, conflicting"),
        ("a volume with correct labels", lambda: World(volumes={"agentops-mvp-postgres-data": dict(_VOLUME_LABELS)}), "already partly created"),
        ("a network with correct labels", lambda: World(networks={"agentops-mvp_mvp-net": dict(_NETWORK_LABELS)}), "already partly created"),
        ("an existing container", lambda: World(containers=[_container("postgres")]), "already partly created"),
        ("a complete stack", complete_world, "already partly created"),
    ])
    def test_unexpected_or_existing_mvp_resources_are_refused(self, tmp_path, label, factory, fragment):
        self._refused(_build_cli(tmp_path, BuildDocker(factory())), fragment)

    def test_an_uninspectable_engine_state_is_refused(self, tmp_path):
        self._refused(_build_cli(tmp_path, BuildDocker(World(), fail={"volume ls"})), "could not be determined")

    def test_existing_images_alone_may_be_rebuilt(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(World(images=list(_ALL_IMAGES))))
        assert run.code == 0, run.err

    def test_the_legacy_stack_never_blocks_or_is_named(self, tmp_path):
        run = _build_cli(tmp_path)
        assert run.code == 0
        flat = " ".join(" ".join(a) for a, _ in run.docker.calls)
        for word in LEGACY_WORDS:
            assert word not in flat

    # -- the lock ------------------------------------------------------------------------------------

    def test_a_concurrent_lifecycle_command_is_refused_and_nothing_is_built(self, tmp_path):
        prepared = _prepare(tmp_path)
        docker = BuildDocker()
        with lc.ExclusiveLock(str(prepared[0].parent / "lifecycle.lock")):
            run = _build_cli(tmp_path, docker, prepared=prepared)
        self._refused(run, "another lifecycle command is running")
        assert _build_cli(tmp_path, BuildDocker(), prepared=prepared).code == 0       # free again afterwards

    def test_the_lock_is_held_while_the_resources_are_inspected_and_released_afterwards(self, tmp_path):
        prepared = _prepare(tmp_path)
        lock_path = str(prepared[0].parent / "lifecycle.lock")
        observed = []

        def probe_lock():
            try:
                lc.ExclusiveLock(lock_path).acquire()
                observed.append("free")
            except lc.LockHeldError:
                observed.append("held")

        docker = BuildDocker()
        docker.first_inspect_hook = probe_lock
        assert _build_cli(tmp_path, docker, prepared=prepared).code == 0
        assert observed == ["held"]
        lc.ExclusiveLock(lock_path).acquire().release()

    def test_the_lock_is_released_after_a_failure(self, tmp_path):
        prepared = _prepare(tmp_path)
        run = _build_cli(tmp_path, BuildDocker(build_plan={"postgres": ("fail", 1, "boom")}), prepared=prepared)
        assert run.code == mvp.EXIT_FAILED
        lc.ExclusiveLock(str(prepared[0].parent / "lifecycle.lock")).acquire().release()

    def test_status_takes_no_lock(self, tmp_path):
        _status(tmp_path, World())
        assert not list(tmp_path.rglob("*.lock"))

    # -- failures during the build ----------------------------------------------------------------------

    def test_memory_is_rechecked_before_every_service(self, tmp_path):
        readings = []

        def memory():
            readings.append(1)
            return 4096

        run = _build_cli(tmp_path, probes=_probes_with(memory=memory))
        assert run.code == 0 and len(readings) == 1 + len(_BUILD_ORDER)

    def test_memory_falling_during_the_build_stops_it_without_removing_anything(self, tmp_path):
        readings = []

        def memory():
            readings.append(1)
            return 4096 if len(readings) <= 2 else 1500          # preflight, before postgres, then low

        run = _build_cli(tmp_path, probes=_probes_with(memory=memory))
        assert run.code == mvp.EXIT_FAILED
        assert "stopped before building viewer" in run.err and "built so far: postgres" in run.err
        assert run.docker.build_services == ["postgres"] and "nothing was removed" in run.err
        assert any(r == "agentops-mvp-postgres" for r, _t, _i in run.docker.world.images)    # kept

    def test_a_build_failure_stops_the_sequence_and_redacts_the_output(self, tmp_path):
        real = list(cfg._values().values())
        output = f"step failed\nPOSTGRES_PASSWORD={real[0]}\nvalue {real[1]} and {mvp._BUILD_PLACEHOLDER}\npassword: hunter2\n"
        run = _build_cli(tmp_path, BuildDocker(build_plan={"viewer": ("fail", 2, output)}))
        assert run.code == mvp.EXIT_FAILED
        assert "the viewer image build failed (exit code 2)" in run.err and "built so far: postgres" in run.err
        assert run.docker.build_services == ["postgres", "viewer"]                      # db-bootstrap never started
        assert "nothing was removed" in run.err and "step failed" in run.err
        assert not any(v in run.text for v in real) and mvp._BUILD_PLACEHOLDER not in run.text and "hunter2" not in run.text
        flat = " ".join(" ".join(a) for a, _ in run.docker.calls).split()      # no destructive command followed
        for forbidden in ("rm", "rmi", "prune", "down", "--volumes", "kill", "stop"):
            assert forbidden not in flat

    def test_the_failure_output_is_bounded_and_printable(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(build_plan={"postgres": ("fail", 1, "x" * 50_000 + "\x1b[31mend\x00")}))
        assert run.code == mvp.EXIT_FAILED and len(run.err) < 2500 and "\x1b" not in run.err and "\x00" not in run.err

    def test_a_build_timeout(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(build_plan={"postgres": "timeout"}))
        assert run.code == mvp.EXIT_FAILED and "timed out" in run.err and "nothing was removed" in run.err
        assert run.docker.build_services == ["postgres"]

    def test_the_default_runner_times_out_and_is_bounded(self, monkeypatch):
        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(kwargs)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        monkeypatch.setattr(mvp.subprocess, "run", fake_run)
        with pytest.raises(mvp.CredentialError) as info:
            mvp.default_build_runner(["docker"], {"A": "b"})
        assert info.value.exit_code == mvp.EXIT_FAILED and "timed out" in str(info.value)
        assert seen["timeout"] == mvp.BUILD_TIMEOUT_SECONDS == 1800 and seen["shell"] is False
        assert seen["stderr"] == subprocess.STDOUT and seen["env"] == {"A": "b"}

    def test_the_default_runner_keeps_only_the_tail_and_hides_os_errors(self, monkeypatch):
        monkeypatch.setattr(mvp.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 3, b"a" * 10_000 + b"END", None))
        result = mvp.default_build_runner(["docker"], {})
        assert result.returncode == 3 and len(result.stdout) == mvp._BUILD_OUTPUT_TAIL and result.stdout.endswith(b"END")

        def boom(argv, **k):
            raise OSError(2, "no such file " + _CANARY)

        monkeypatch.setattr(mvp.subprocess, "run", boom)
        with pytest.raises(mvp.CredentialError) as info:
            mvp.default_build_runner(["docker"], {})
        assert _CANARY not in str(info.value) and info.value.__cause__ is None

    def test_a_crashing_runner_never_leaks_its_message(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(build_plan={"postgres": "crash"}))
        assert run.code == mvp.EXIT_FAILED and "could not be run" in run.err and _CANARY not in run.text and "boom" not in run.text

    def test_a_missing_output_image(self, tmp_path):
        run = _build_cli(tmp_path, BuildDocker(build_plan={"viewer": "no-image"}))
        assert run.code == mvp.EXIT_FAILED and "expected images missing after the build: viewer" in run.err
        assert run.docker.build_services == _BUILD_ORDER and "nothing was removed" in run.err

    @pytest.mark.parametrize("label,create,fragment", [
        ("container", lambda w: w.containers.append(_container("viewer")), "a container with an MVP name exists"),
        ("network", lambda w: w.networks.update({"agentops-mvp_mvp-net": dict(_NETWORK_LABELS)}), "a network with an MVP name exists"),
        ("volume", lambda w: w.volumes.update({"agentops-mvp-postgres-data": dict(_VOLUME_LABELS)}), "a volume with an MVP name exists"),
        ("extra image", lambda w: w.images.append(("agentops-mvp-extra", "latest", "abcdef123456")), "unexpected image"),
    ])
    def test_a_resource_created_by_the_build_is_reported_and_not_removed(self, tmp_path, label, create, fragment):
        run = _build_cli(tmp_path, BuildDocker(create_after=create))
        assert run.code == mvp.EXIT_FAILED and fragment in run.err and "nothing was removed" in run.err

    def test_an_unreadable_state_after_the_build_is_a_failure(self, tmp_path):
        docker = BuildDocker()
        docker.create_after = lambda world: docker.fail.add("image ls")
        run = _build_cli(tmp_path, docker)
        assert run.code == mvp.EXIT_FAILED and "could not be inspected after the build" in run.err

    # -- regression and scope -------------------------------------------------------------------------------

    def test_the_other_commands_still_work_alongside_build(self, tmp_path):
        assert _status(tmp_path / "s", World())[0] == 0
        code, out, err, *_ = cfg._check_config(tmp_path / "c", cfg.FakeEngine())
        assert code == mvp.EXIT_OK

    def test_build_argv_accepts_only_the_three_services_and_adds_nothing(self):
        for service in mvp.SERVICES:
            assert mvp.build_argv("d", _REPO, service)[-2:] == ["build", service]
            assert len(mvp.build_argv("d", _REPO, service)) == 10
        for bad in ("up", "down", "all", "", "postgres --pull", "--pull", "viewer;x", "agentops-mvp-viewer"):
            with pytest.raises(mvp.CredentialError):
                mvp.build_argv("d", _REPO, bad)
        for verb in ("build", "up", "down"):
            with pytest.raises(mvp.CredentialError):
                mvp.compose_argv("d", _REPO, [verb])                # compose_argv still allows config only

    def test_the_build_functions_contain_no_forbidden_option_or_verb(self):
        source = Path(mvp.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        forbidden = {"up", "down", "--pull", "--no-cache", "--push", "--build", "--volumes", "-v", "-d", "prune", "rm",
                     "rmi", "run", "start", "stop", "kill", "create", "exec", "cp", "system", "--env-file", "--build-arg"}
        for name in ("build_argv", "build_capability_argv", "_compose_prefix", "_build_command", "_build_locked",
                     "default_build_runner"):
            constants = {n.value for n in ast.walk(functions[name]) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            assert not constants & forbidden, (name, constants & forbidden)
        for name in ("build_argv", "build_capability_argv", "_compose_prefix"):
            constants = {n.value for n in ast.walk(functions[name]) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                         and " " not in n.value and len(n.value) < 30}
            assert constants <= {"docker", "compose", "-p", "--project-directory", "-f", "build", "--help"}, (name, constants)
        assert "shell=True" not in source and "os.system" not in source


class TestBuildHelpers:

    def test_the_real_dockerfiles_name_only_the_expected_base_images(self):
        seen = {}
        for service, relative in mvp._DOCKERFILES.items():
            seen[service] = lc.parse_base_images((_REPO / relative).read_text(encoding="utf-8"))
        assert seen == {"postgres": ["postgres:17.11"], "db-bootstrap": ["python:3.11-slim-bookworm"],
                        "viewer": ["python:3.13-slim-bookworm"]}
        assert set().union(*map(set, seen.values())) == _BASE_IMAGES

    def test_multi_stage_files_and_stage_references(self):
        text = "FROM python:3.12-slim AS builder\nRUN x\nFROM builder AS final\nfrom scratch\nFROM node:20 as web\n"
        assert lc.parse_base_images(text) == ["python:3.12-slim", "node:20"]

    @pytest.mark.parametrize("text", [
        "RUN echo hi\n", "", "FROM python\n", "FROM python:${VERSION}\n", "FROM python@sha256:" + "a" * 64 + "\n",
        "FROM UPPER/Case:1\n", "FROM python:3.12 extra words\n", "FROM\n", "FROM -x\n", "FROM py:3 AS\n",
    ])
    def test_unclear_or_unpinned_from_lines_fail_closed(self, text):
        with pytest.raises(lc.LifecycleError):
            lc.parse_base_images(text)

    def test_image_presence_command_and_engine_memory_command(self):
        assert lc.cmd_image_present(_DOCKER, "postgres:17.11") == [
            _DOCKER, "image", "ls", "--filter", "reference=postgres:17.11", "--format", "{{.ID}}"]
        assert lc.cmd_info_memory(_DOCKER) == [_DOCKER, "info", "--format", "{{.MemTotal}}"]
        for bad in ("postgres:*", "postgres", "a b:1", "x:1;y", ""):
            with pytest.raises(lc.LifecycleError):
                lc.cmd_image_present(_DOCKER, bad)

    @pytest.mark.parametrize("out,expected", [(b"8168574976\n", 7790), (b"3758096384", 3584), (b"1048576", 1)])
    def test_engine_memory(self, out, expected):
        assert lc.read_engine_memory_mib(_DOCKER, lambda a, e: lc.DockerResult(0, out), {}) == expected

    @pytest.mark.parametrize("rc,out", [(1, b"8168574976"), (0, b""), (0, b"lots"), (0, b"-5"), (0, b"0"), (0, b"1 2"),
                                        (0, b"9" * 30)])
    def test_unreadable_engine_memory_fails_closed(self, rc, out):
        with pytest.raises(lc.LifecycleError):
            lc.read_engine_memory_mib(_DOCKER, lambda a, e: lc.DockerResult(rc, out), {})

        def boom(a, e):
            raise OSError(_CANARY)

        with pytest.raises(lc.LifecycleError) as info:
            lc.read_engine_memory_mib(_DOCKER, boom, {})
        assert _CANARY not in str(info.value)

    def test_preflight_and_result_rules(self):
        assert lc.build_preflight_problem(lc.Snapshot()) is None
        assert lc.build_preflight_problem(lc.Snapshot(images={s: True for s in lc.SERVICES})) is None
        assert "could not be determined" in lc.build_preflight_problem(lc.Snapshot(errors=["ENGINE_UNAVAILABLE"]))
        assert "conflicting" in lc.build_preflight_problem(lc.Snapshot(other_volumes=["agentops-mvp-x"]))
        assert "already partly created" in lc.build_preflight_problem(_good_snapshot())
        ok = lc.Snapshot(images={s: True for s in lc.SERVICES})
        assert lc.build_result_problems(ok) == []
        assert lc.build_result_problems(lc.Snapshot(errors=["X"], images=ok.images))
        assert any("missing" in p for p in lc.build_result_problems(lc.Snapshot(images={"postgres": True})))
        assert len(lc.build_result_problems(_good_snapshot())) == 3


# ---------------------------------------------------------------------------
# L15  The guarded start command `up` (B3J-172).  A fake engine only: nothing is ever started.
# ---------------------------------------------------------------------------

_UP_HELP = (b"Usage:  docker compose up [OPTIONS] [SERVICE...]\n  -d, --detach\n  --no-build\n"
            b"  --no-recreate\n  --pull string   Pull image before running (\"always\"|\"missing\"|\"never\")\n")
_UP_ARGV_TAIL = ["up", "-d", "--no-build", "--pull", "never", "--no-recreate"]
_BOOTSTRAP_FAILED_OUTPUT = "dependency failed to start: container agentops-mvp-db-bootstrap-1 exited (6)\n"


def _mvp_parts(world):
    return ([c for c in world.containers if c["project"] == "agentops-mvp"],
            {k: v for k, v in world.networks.items() if "agentops-mvp" in k},
            {k: v for k, v in world.volumes.items() if "agentops-mvp" in k})


class UpDocker(BuildDocker):
    """A fake engine that also models `compose up`: it creates (or half creates) the stack."""

    def __init__(self, world=None, *, up_plan="ok", up_help=_UP_HELP, viewer_health=("starting", "starting", "healthy"),
                 up_output=b"", **kwargs):
        super().__init__(world if world is not None else World(images=list(_ALL_IMAGES)), **kwargs)
        self.up_plan, self.up_help, self.up_output = up_plan, up_help, up_output
        self.viewer_health = list(viewer_health)
        self.ups: list[tuple[list[str], dict[str, str]]] = []
        self.helps: list[list[str]] = []
        self.inspections_after_up = 0
        self.on_up = None

    def _create(self, *, bootstrap_exit=0, viewer=True, network_labels=None, extra=()):
        full = complete_world()
        containers, networks, volumes = _mvp_parts(full)
        if not viewer:
            containers = [c for c in containers if c["service"] != "viewer"]
        for c in containers:
            if c["service"] == "db-bootstrap":
                c["exit"] = bootstrap_exit
        self.world.containers += containers + list(extra)
        for name, labels in networks.items():
            self.world.networks[name] = network_labels if network_labels is not None else labels
        self.world.volumes.update(volumes)

    def __call__(self, argv, env):
        if argv[8:9] == ["up"] and argv[1:2] == ["compose"]:
            self.calls.append((list(argv), dict(env)))
            if argv[-1] == "--help":
                self.helps.append(list(argv))
                return lc.DockerResult(0, self.up_help)
            self.ups.append((list(argv), dict(env)))
            if self.on_up:
                self.on_up()
            plan = self.up_plan
            if plan == "bootstrap-fail":
                self._create(bootstrap_exit=6, viewer=False)
                return lc.DockerResult(1, (_BOOTSTRAP_FAILED_OUTPUT + "password: hunter2\n").encode())
            if plan in ("timeout", "interrupt", "crash"):
                self._create(viewer=False)
                self.world.containers = [c for c in self.world.containers if c["service"] != "db-bootstrap"
                                         or c["project"] != "agentops-mvp"]
                if plan == "timeout":
                    raise subprocess.TimeoutExpired(argv, 1500)
                if plan == "interrupt":
                    raise KeyboardInterrupt
                raise RuntimeError("boom " + _CANARY)
            if plan == "foreign-network":
                self._create(network_labels={lc.LABEL_PROJECT: "somebody-else", lc.LABEL_NETWORK: "mvp-net"})
            elif plan == "extra-container":
                self._create(extra=[_container("worker", name="agentops-mvp-worker-1")])
            else:
                self._create()
            return lc.DockerResult(0, self.up_output)
        if argv[1:2] == ["inspect"] and self.ups:
            self.inspections_after_up += 1
            index = min(self.inspections_after_up - 1, len(self.viewer_health) - 1)
            for c in self.world.containers:
                if c["service"] == "viewer" and c["project"] == "agentops-mvp":
                    c["health"] = self.viewer_health[index]
        return super().__call__(argv, env)


def _up_cli(tmp_path, docker=None, *, probes=None, host=None, prepared=None, no_file=False, sleep=None):
    docker = docker if docker is not None else UpDocker()
    target, runner, platform = prepared if prepared else _prepare(tmp_path)
    if no_file:
        target = target.parent / "missing" / mvp.FILE_NAME
    environ = {"SystemRoot": r"C:\Windows", "PATH": "/usr/bin", "DOCKER_CONFIG": "/home/x/.docker"}
    environ.update(host or {})
    slept = []
    out, err = io.StringIO(), io.StringIO()
    code = mvp.main(["up", "--credentials-file", str(target)], environ=environ, platform_name=platform,
                    runner=runner, compose_runner=docker, docker=_DOCKER, repo_root=_REPO,
                    probes=probes or _probes_with(memory=4096), sleep=sleep or slept.append, out=out, err=err)
    run = _Run(code, out.getvalue(), err.getvalue(), target, docker)
    run.slept = slept
    return run


def _flat(docker):
    return " ".join(" ".join(a) for a, _ in docker.calls).split()


class TestUpCommand:

    def test_a_successful_start(self, tmp_path):
        run = _up_cli(tmp_path)
        assert run.code == 0, run.err
        assert run.out.startswith("stack started: COMPLETE") and "http://127.0.0.1:8000/" in run.out
        assert "nothing was built, pulled, recreated or removed" in run.out
        assert len(run.docker.ups) == 1 and run.docker.builds == []
        assert run.slept == [lc.START_POLL_SECONDS] * 2            # two polls saw the viewer still starting
        assert lc.classify(lc.inspect_stack(_DOCKER, FakeDocker(run.docker.world), {})).state == lc.STATE_COMPLETE

    def test_the_exact_start_arguments(self, tmp_path):
        run = _up_cli(tmp_path)
        compose_file = _REPO / "docker" / "mvp" / "compose.yml"
        prefix = [_DOCKER, "compose", "-p", "agentops-mvp", "--project-directory", str(compose_file.parent),
                  "-f", str(compose_file)]
        assert run.docker.ups[0][0] == prefix + _UP_ARGV_TAIL
        assert run.docker.helps == [prefix + ["up", "--help"]]
        assert mvp.up_argv(_DOCKER, _REPO) == prefix + _UP_ARGV_TAIL

    def test_no_forbidden_option_and_only_permitted_commands(self, tmp_path):
        run = _up_cli(tmp_path)
        flat = _flat(run.docker)
        for forbidden in ("down", "rm", "kill", "stop", "restart", "run", "exec", "create", "push", "prune", "build",
                          "--build", "--force-recreate", "--remove-orphans", "--renew-anon-volumes", "-V", "--volumes",
                          "-v", "--no-cache", "--abort-on-container-exit", "--wait", "--env-file", "reset", "system"):
            assert forbidden not in flat, forbidden
        assert flat.count("--pull") == 1 and flat[flat.index("--pull") + 1] == "never"
        kinds = set()
        for argv, _env in run.docker.calls:
            tail = argv[1:]
            if tail[0] == "compose":
                kinds.add("compose " + ("config" if "config" in tail else "up --help" if tail[-1] == "--help" else "up"))
            else:
                kinds.add(" ".join(tail[:2]) if tail[0] in ("context", "network", "volume", "image") else tail[0])
        assert kinds <= {"compose config", "compose up", "compose up --help", "context inspect", "info", "ps", "inspect",
                         "network ls", "network inspect", "volume ls", "volume inspect", "image ls"}

    def test_credentials_reach_only_the_start_environment(self, tmp_path):
        real = cfg._values()
        host = {"POSTGRES_PASSWORD": _CANARY, "COMPOSE_PROFILES": "x", "compose_file": "y"}
        run = _up_cli(tmp_path, host=host)
        assert run.code == 0, run.err
        up_env = run.docker.ups[0][1]
        for name, value in real.items():
            assert up_env[name] == value
        assert _CANARY not in up_env.values() and not any(k.upper().startswith("COMPOSE_") for k in up_env)
        for argv, env in run.docker.calls:
            assert not any(v in " ".join(argv) for v in set(real.values()) | {_CANARY})
            if env is not up_env and env != up_env:
                assert not {k.upper() for k in env} & {n.upper() for n in mvp.CREDENTIAL_VARIABLES}
                assert not any(k.upper().startswith("COMPOSE_") for k in env)
        assert not any(v in run.text for v in set(real.values()) | {_CANARY})

    def test_production_uses_the_bounded_start_runner_for_the_start_only(self, tmp_path, monkeypatch):
        used = {"inspect": [], "up": []}
        docker = UpDocker()
        monkeypatch.setattr(mvp, "default_compose_runner", lambda argv, env: used["inspect"].append(list(argv)) or docker(argv, env))
        monkeypatch.setattr(mvp, "default_up_runner", lambda argv, env: used["up"].append(list(argv)) or docker(argv, env))
        target, runner, platform = _prepare(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        code = mvp.main(["up", "--credentials-file", str(target)], environ={"SystemRoot": r"C:\Windows"},
                        platform_name=platform, runner=runner, docker=_DOCKER, repo_root=_REPO,
                        probes=_probes_with(memory=4096), sleep=lambda s: None, out=out, err=err)
        assert code == 0, err.getvalue()
        assert used["up"] == [mvp.up_argv(_DOCKER, _REPO)]
        assert used["inspect"] and mvp.up_argv(_DOCKER, _REPO) not in used["inspect"]

    def test_the_default_start_runner_is_bounded(self, monkeypatch):
        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(kwargs)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        monkeypatch.setattr(mvp.subprocess, "run", fake_run)
        with pytest.raises(mvp.CredentialError) as info:
            mvp.default_up_runner(["docker"], {"A": "b"})
        assert info.value.exit_code == mvp.EXIT_FAILED and "timed out" in str(info.value)
        assert seen["timeout"] == mvp.UP_TIMEOUT_SECONDS == 1500 and seen["shell"] is False

    # -- preflight refusals: nothing is started ----------------------------------------------------

    def _refused(self, run, fragment, code=mvp.EXIT_REFUSED):
        assert run.code == code, (run.code, run.err)
        assert fragment in run.err, run.err
        assert run.docker.ups == [], "the start must not be attempted"
        assert run.out == ""

    def test_missing_and_invalid_credentials(self, tmp_path):
        run = _up_cli(tmp_path, no_file=True)
        assert run.code != 0 and run.docker.calls == [] and run.docker.ups == []
        prepared = _prepare(tmp_path / "bad")
        weak = cfg._values()["POSTGRES_PASSWORD"].encode()
        prepared[0].write_bytes(prepared[0].read_bytes().replace(weak, b"short"))
        run = _up_cli(tmp_path / "bad", prepared=prepared)
        assert run.code != 0 and run.docker.ups == [] and run.docker.calls == []

    def test_an_invalid_configuration_and_a_non_local_engine(self, tmp_path):
        config = cfg._resolved()
        config["services"]["extra"] = {"build": {}}
        self._refused(_up_cli(tmp_path / "a", UpDocker(config=config)), "configuration is not acceptable")
        self._refused(_up_cli(tmp_path / "b", UpDocker(endpoint="tcp://10.1.2.3:2375")), "not a local endpoint")

    @pytest.mark.parametrize("word", ["docker compose up", "--detach", "--no-build", "--pull", "never", "--no-recreate"])
    def test_a_compose_without_a_needed_option_is_refused(self, tmp_path, word):
        run = _up_cli(tmp_path, UpDocker(up_help=_UP_HELP.replace(word.encode(), b"XXXX")))
        self._refused(run, "does not support the options the start command needs", mvp.EXIT_FAILED)

    def test_a_failing_help_command_is_refused(self, tmp_path):
        class NoHelp(UpDocker):
            def __call__(self, argv, env):
                if argv[8:9] == ["up"] and argv[-1] == "--help":
                    self.calls.append((list(argv), dict(env)))
                    return lc.DockerResult(1, b"")
                return super().__call__(argv, env)

        self._refused(_up_cli(tmp_path, NoHelp()), "does not support the options", mvp.EXIT_FAILED)

    def test_images_must_exist_first(self, tmp_path):
        self._refused(_up_cli(tmp_path, UpDocker(World())), "the images are not built yet (missing: postgres, db-bootstrap, viewer)")
        self._refused(_up_cli(tmp_path / "b", UpDocker(World(images=_ALL_IMAGES[:2]))), "missing: viewer")

    @pytest.mark.parametrize("label,factory,fragment", [
        ("complete stack", complete_world, "already exists"),
        ("stopped containers", lambda: World(containers=[_container("postgres", state="exited", health="none")], images=list(_ALL_IMAGES)), "already exists"),
        ("failed bootstrap evidence", lambda: World(containers=[_container("db-bootstrap", state="exited", exit_code=6, health="none")], images=list(_ALL_IMAGES)), "already exists"),
        ("volume only", lambda: World(volumes={"agentops-mvp-postgres-data": dict(_VOLUME_LABELS)}, images=list(_ALL_IMAGES)), "already exists"),
        ("network only", lambda: World(networks={"agentops-mvp_mvp-net": dict(_NETWORK_LABELS)}, images=list(_ALL_IMAGES)), "already exists"),
        ("unlabelled volume", lambda: World(volumes={"agentops-mvp-postgres-data": {}}, images=list(_ALL_IMAGES)), "unexpected, conflicting"),
        ("foreign network labels", lambda: World(networks={"agentops-mvp_mvp-net": {lc.LABEL_PROJECT: "other"}}, images=list(_ALL_IMAGES)), "unexpected, conflicting"),
        ("unexpected service", lambda: World(containers=[_container("worker", name="agentops-mvp-worker-1")], images=list(_ALL_IMAGES)), "unexpected, conflicting"),
        ("stray container", lambda: World(containers=[_container("viewer", name="agentops-mvp-viewer-9", project="")], images=list(_ALL_IMAGES)), "unexpected, conflicting"),
        ("extra image", lambda: World(images=list(_ALL_IMAGES) + [("agentops-mvp-old", "x", "abcdef123456")]), "unexpected, conflicting"),
    ])
    def test_an_existing_or_ambiguous_stack_is_refused_and_left_alone(self, tmp_path, label, factory, fragment):
        docker = UpDocker(factory())
        before = deepcopy(docker.world.containers), dict(docker.world.networks), dict(docker.world.volumes)
        self._refused(_up_cli(tmp_path, docker), fragment)
        assert (docker.world.containers, docker.world.networks, docker.world.volumes) == before

    def test_an_uninspectable_state_is_refused(self, tmp_path):
        self._refused(_up_cli(tmp_path, UpDocker(fail={"volume ls"})), "could not be determined")

    def test_low_host_memory(self, tmp_path):
        self._refused(_up_cli(tmp_path, probes=_probes_with(memory=2559)), "available memory is 2559 MiB; 2560 MiB is required")
        assert _up_cli(tmp_path / "ok", probes=_probes_with(memory=2560)).code == 0

    def test_memory_is_read_again_right_before_the_start(self, tmp_path):
        readings = []

        def memory():
            readings.append(1)
            return 4096 if len(readings) == 1 else 1000

        run = _up_cli(tmp_path, probes=_probes_with(memory=memory))
        self._refused(run, "available memory is 1000 MiB")
        assert len(readings) == 2

    def test_unreadable_host_memory_disk_and_port(self, tmp_path):
        def bad():
            raise lc.LifecycleError("x")

        self._refused(_up_cli(tmp_path / "a", probes=_probes_with(memory=bad)), "available memory could not be read")
        probes = lc.Probes(memory_mib=lambda: 4096, disk_free_gib=bad, port_in_use=lambda p: False)
        self._refused(_up_cli(tmp_path / "b", probes=probes), "free disk space could not be read")
        probes = lc.Probes(memory_mib=lambda: 4096, disk_free_gib=lambda: 700.0, port_in_use=lambda port: bad())
        self._refused(_up_cli(tmp_path / "c", probes=probes), "port 8000 could not be checked")

    def test_low_disk_space(self, tmp_path):
        self._refused(_up_cli(tmp_path, probes=_probes_with(memory=4096, disk=9.9)), "free disk space is 9.9 GiB")

    def test_insufficient_engine_memory(self, tmp_path):
        self._refused(_up_cli(tmp_path, UpDocker(engine_mib=3500)), "engine has too little memory")
        assert _up_cli(tmp_path / "ok", UpDocker(engine_mib=3584)).code == 0

    def test_a_busy_port_is_refused(self, tmp_path):
        probes = lc.Probes(memory_mib=lambda: 4096, disk_free_gib=lambda: 700.0, port_in_use=lambda p: p == 8000)
        self._refused(_up_cli(tmp_path, probes=probes), "port 8000 is already in use")

    def test_the_database_port_is_never_consulted(self, tmp_path):
        asked = []
        probes = lc.Probes(memory_mib=lambda: 4096, disk_free_gib=lambda: 700.0,
                           port_in_use=lambda p: asked.append(p) or False)
        assert _up_cli(tmp_path, probes=probes).code == 0
        assert asked == [8000]

    # -- the lock ------------------------------------------------------------------------------------

    def test_a_concurrent_lifecycle_command_is_refused(self, tmp_path):
        prepared = _prepare(tmp_path)
        with lc.ExclusiveLock(str(prepared[0].parent / "lifecycle.lock")):
            run = _up_cli(tmp_path, UpDocker(), prepared=prepared)
        self._refused(run, "another lifecycle command is running")
        assert _up_cli(tmp_path, UpDocker(), prepared=prepared).code == 0

    def test_the_lock_is_held_during_the_start_and_released_after_a_failure(self, tmp_path):
        prepared = _prepare(tmp_path)
        lock_path = str(prepared[0].parent / "lifecycle.lock")
        observed = []

        def probe_lock():
            try:
                lc.ExclusiveLock(lock_path).acquire()
                observed.append("free")
            except lc.LockHeldError:
                observed.append("held")

        docker = UpDocker(up_plan="bootstrap-fail")
        docker.on_up = probe_lock
        run = _up_cli(tmp_path, docker, prepared=prepared)
        assert run.code == mvp.EXIT_FAILED and observed == ["held"]
        lc.ExclusiveLock(lock_path).acquire().release()

    # -- failure evidence is preserved --------------------------------------------------------------------

    def test_a_failed_bootstrap_is_reported_with_its_evidence_and_nothing_is_removed(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(up_plan="bootstrap-fail"))
        assert run.code == mvp.EXIT_FAILED
        assert "the start failed (exit code 1)" in run.err
        assert "HOLD: the bootstrap container failed (exit code 6); nothing was reset" in run.err
        assert "db-bootstrap: exited (6)" in run.err and "exited (6)" in run.err
        assert "nothing was removed; every container, the network and the data volume were kept for inspection" in run.err
        assert "hunter2" not in run.text and "***" in run.err
        mvp_containers, networks, volumes = _mvp_parts(run.docker.world)
        assert {c["service"] for c in mvp_containers} == {"postgres", "db-bootstrap"}
        assert "agentops-mvp_mvp-net" in networks and "agentops-mvp-postgres-data" in volumes
        flat = _flat(run.docker)
        for forbidden in ("down", "rm", "kill", "stop", "prune", "--volumes", "-v", "restart"):
            assert forbidden not in flat
        assert len(run.docker.ups) == 1                                      # never retried
        assert run.docker.builds == []

    def test_a_start_timeout(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(up_plan="timeout"))
        assert run.code == mvp.EXIT_FAILED and "the start timed out" in run.err and "were kept for inspection" in run.err
        assert "postgres: running (healthy)" in run.err and len(run.docker.ups) == 1

    def test_an_interrupted_start_keeps_everything_and_releases_the_lock(self, tmp_path):
        prepared = _prepare(tmp_path)
        run = _up_cli(tmp_path, UpDocker(up_plan="interrupt"), prepared=prepared)
        assert run.code == mvp.EXIT_FAILED and "the start was interrupted" in run.err and "kept for inspection" in run.err
        assert "postgres: running (healthy)" in run.err
        lc.ExclusiveLock(str(prepared[0].parent / "lifecycle.lock")).acquire().release()
        flat = _flat(run.docker)
        for forbidden in ("down", "rm", "kill", "stop", "prune"):
            assert forbidden not in flat

    def test_a_crashing_start_command_never_leaks_its_message(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(up_plan="crash"))
        assert run.code == mvp.EXIT_FAILED and "could not be run" in run.err
        assert _CANARY not in run.text and "boom" not in run.text

    def test_a_runner_error_from_the_default_runner_is_reported(self, tmp_path):
        class Failing(UpDocker):
            def __call__(self, argv, env):
                if argv[8:9] == ["up"] and argv[-1] != "--help":
                    self.ups.append((argv, env))
                    raise mvp.CredentialError("the container tool could not be run", mvp.EXIT_FAILED)
                return super().__call__(argv, env)

        run = _up_cli(tmp_path, Failing())
        assert run.code == mvp.EXIT_FAILED and "the start did not complete (the container tool could not be run)" in run.err

    def test_waiting_that_never_ends_times_out_without_cleanup(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(viewer_health=("starting",)))
        assert run.code == mvp.EXIT_FAILED and "timed out waiting for the stack to become healthy" in run.err
        assert len(run.slept) == lc.START_POLLS - 1 and set(run.slept) == {lc.START_POLL_SECONDS}
        assert lc.START_POLLS * lc.START_POLL_SECONDS == 180
        assert "viewer: running (starting)" in run.err and "kept for inspection" in run.err
        assert len(run.docker.ups) == 1

    def test_an_unhealthy_viewer_also_times_out(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(viewer_health=("unhealthy",)))
        assert run.code == mvp.EXIT_FAILED and "the viewer container is not healthy (health: unhealthy)" in run.err

    def test_an_interrupted_wait(self, tmp_path):
        def interrupt(seconds):
            raise KeyboardInterrupt

        run = _up_cli(tmp_path, sleep=interrupt)
        assert run.code == mvp.EXIT_FAILED and "waiting was interrupted; the stack was started" in run.err

    # -- ownership -----------------------------------------------------------------------------------------

    def test_a_network_that_does_not_belong_to_the_project_is_not_success(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(up_plan="foreign-network"))
        assert run.code == mvp.EXIT_FAILED and "the stack did not reach a complete state" in run.err
        assert "the network does not belong to the MVP project" in run.err and "stack started" not in run.text

    def test_an_unexpected_container_is_not_success(self, tmp_path):
        run = _up_cli(tmp_path, UpDocker(up_plan="extra-container"))
        assert run.code == mvp.EXIT_FAILED and "unexpected service in the MVP project: worker" in run.err

    def test_the_legacy_stack_is_never_named_started_or_changed(self, tmp_path):
        docker = UpDocker()
        legacy_before = deepcopy([c for c in docker.world.containers if c["project"] == "agentops"])
        volumes_before = {k: v for k, v in docker.world.volumes.items() if k.startswith("agentops_")}
        run = _up_cli(tmp_path, docker)
        assert run.code == 0
        assert [c for c in docker.world.containers if c["project"] == "agentops"] == legacy_before
        assert all(c["state"] == "exited" for c in legacy_before)
        assert {k: v for k, v in docker.world.volumes.items() if k.startswith("agentops_")} == volumes_before
        flat = " ".join(" ".join(a) for a, _ in docker.calls)
        for word in LEGACY_WORDS + ("5432",):
            assert word not in flat
        for argv, _env in docker.ups:
            assert argv[argv.index("-p") + 1] == "agentops-mvp" and argv.count("-f") == 1 and len(argv) == 14

    def test_only_a_fresh_images_only_state_passes_and_the_result_is_complete_by_the_classifier(self, tmp_path):
        docker = UpDocker()
        assert lc.classify(lc.inspect_stack(_DOCKER, FakeDocker(docker.world), {})).state == lc.STATE_PARTIAL
        assert _up_cli(tmp_path, docker).code == 0

    # -- regression and scope -----------------------------------------------------------------------------------

    def test_status_build_and_check_config_are_unaffected(self, tmp_path):
        assert _status(tmp_path / "s", World())[0] == 0
        assert _build_cli(tmp_path / "b").code == 0
        assert cfg._check_config(tmp_path / "c", cfg.FakeEngine())[0] == mvp.EXIT_OK

    def test_up_argv_is_fixed(self):
        assert mvp.up_argv("d", _REPO)[8:] == _UP_ARGV_TAIL
        assert mvp.up_capability_argv("d", _REPO)[8:] == ["up", "--help"]
        for verb in ("up", "down", "build"):
            with pytest.raises(mvp.CredentialError):
                mvp.compose_argv("d", _REPO, [verb])

    def test_the_start_functions_contain_no_forbidden_option_or_verb(self):
        source = Path(mvp.__file__).read_text(encoding="utf-8")
        functions = {n.name: n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef)}
        forbidden = {"down", "rm", "kill", "stop", "restart", "run", "exec", "create", "push", "prune", "pull", "build",
                     "--build", "--force-recreate", "--remove-orphans", "--renew-anon-volumes", "-V", "--volumes", "-v",
                     "--no-cache", "--wait", "--abort-on-container-exit", "--env-file", "system"}
        for name in ("up_argv", "up_capability_argv", "_up_command", "_up_locked", "_up_evidence", "_require_help",
                     "default_up_runner", "_run_bounded"):
            constants = {n.value for n in ast.walk(functions[name]) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            assert not constants & forbidden, (name, constants & forbidden)
        constants = {n.value for n in ast.walk(functions["up_argv"]) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert constants <= {"up", "-d", "--no-build", "--pull", "never", "--no-recreate"} | {n for n in constants if " " in n}


class TestStartHelpers:

    def _snap(self, **kwargs):
        return lc.Snapshot(images={s: True for s in lc.SERVICES}, **kwargs)

    def test_only_a_never_created_stack_with_all_images_may_start(self):
        assert lc.start_preflight_problem(self._snap()) is None
        assert "not built yet (missing: viewer)" in lc.start_preflight_problem(lc.Snapshot(images={"postgres": True, "db-bootstrap": True}))
        assert "could not be determined" in lc.start_preflight_problem(lc.Snapshot(errors=["ENGINE_UNAVAILABLE"]))
        assert "conflicting" in lc.start_preflight_problem(self._snap(other_networks=["agentops-mvp_x"]))
        assert "already exists" in lc.start_preflight_problem(_good_snapshot())
        assert "already exists" in lc.start_preflight_problem(self._snap(volume={lc.LABEL_PROJECT: "agentops-mvp",
                                                                                  lc.LABEL_VOLUME: "postgres-data", lc.LABEL_MVP: "true"}))

    def test_verdicts(self):
        complete = lc.classify(_good_snapshot())
        assert lc.start_verdict(complete) == lc.VERDICT_READY
        starting = _good_snapshot()
        _edit(starting, "viewer", health="starting")
        assert lc.start_verdict(lc.classify(starting)) == lc.VERDICT_PENDING
        failed = _good_snapshot()
        _edit(failed, "db-bootstrap", exit_code=6)
        _edit(failed, "viewer", state="exited", running=False)
        assert lc.start_verdict(lc.classify(failed)) == lc.VERDICT_FAILED
        assert lc.start_verdict(lc.classify(lc.Snapshot(errors=["IMAGE_LIST_FAILED"]))) == lc.VERDICT_PENDING
        assert lc.start_verdict(lc.classify(lc.Snapshot(images={s: True for s in lc.SERVICES}))) == lc.VERDICT_PENDING
        assert lc.start_verdict(lc.classify(lc.Snapshot())) == lc.VERDICT_FAILED
        contradictory = _good_snapshot()
        contradictory.containers.append(_info("viewer", name="agentops-mvp-viewer-2"))
        assert lc.start_verdict(lc.classify(contradictory)) == lc.VERDICT_FAILED

    def test_evidence_has_no_read_only_banner_and_no_secret_or_label_values(self):
        snapshot = _good_snapshot()
        snapshot.volume["com.docker.compose.config-hash"] = _CANARY
        text = lc.format_evidence(lc.classify(snapshot))
        assert text.startswith("MVP stack status: COMPLETE") and "read-only inspection" not in text
        assert "credential file" not in text and _CANARY not in text and "memory:" not in text

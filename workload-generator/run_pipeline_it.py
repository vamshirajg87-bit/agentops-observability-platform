"""
workload-generator/run_pipeline_it.py

One functional integration test of the containerized ingestion pipeline
(docker/compose.pipeline.yml) on a separate, disposable Compose project:

    REAL driver -> OTLP -> collector -> Kafka raw topic -> stream processor (container)
        -> Kafka canonical topic -> storage consumer (container) -> PostgreSQL

It is NOT a benchmark: nothing is timed, no throughput or latency is judged, and
nothing is written to the benchmark directory or ledger.

It only ORCHESTRATES.  The disposable stack, its readiness checks, the generator
run, the exact Kafka and database reconciliation and the cleanup are
run_smoke.py's, imported and unchanged; this file points them at its own project
name and consumer groups at run time and adds what is new: the two processing
services, and the checks that they used the disposable broker and database.

Isolation, in the order it is established
    - a unique project name "agentops-pipeline-it-<8 hex>", never "agentops", and
      none that any Docker object already carries
    - run_smoke's own override, unchanged: every fixed container name removed,
      every published port loopback-only (127.0.0.1 14317, 19092, 15432)
    - the project's network and volumes are named after the project
    - image names are the project's (the overlay has no fixed tag)
    - throw-away random passwords in a temporary directory outside the repository
    - consumer groups of its own, on a broker of its own
    - refuses to start while a benchmark process, marker or project is present
    - the generator refuses the platform's own ports 4317 and 4318
    - cleanup is "docker compose down --volumes --rmi local --remove-orphans" for
      this project only, and nothing else is ever deleted: run_smoke's cleanup() is
      NOT called, because it also removes every image and volume that merely appeared
      since the run began, whoever made it.  Here, a leftover image of this project is
      removed only by its exact name, which must start with the project name and carry
      its Compose label; objects found by comparing inventories are REPORTED, never
      removed; no prune of any kind

    python workload-generator/run_pipeline_it.py --expect-head <commit>

Exit codes:
    0  every check passed and cleanup was verified
    1  anything else

Nothing is retried.  Standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_smoke as smoke  # noqa: E402
from run_smoke import Checks, SmokeFailure, Stage, say, section  # noqa: E402

PROJECT_PREFIX: str = "agentops-pipeline-it-"
OVERLAY_FILE: str = "docker/compose.pipeline.yml"
NEW_SERVICES: tuple[str, ...] = ("stream-processor", "storage-consumer")
BASE_IMAGE: str = "python:3.13-slim-bookworm"

#: The five files of the containerized ingestion deployment and its test tooling: the
#: only files whose presence, as untracked files or as a commit on the approved base,
#: this test accepts.
APPROVED_FILES: tuple[str, ...] = (
    "db-bootstrap/tests/unit/test_pipeline_compose_contract.py",
    "docker/compose.pipeline.yml",
    "docker/pipeline/Dockerfile",
    "workload-generator/run_pipeline_it.py",
    "workload-generator/tests/unit/test_pipeline_it_network.py",
)
#: Their lines in `git status --porcelain --untracked-files=all` while they are untracked.
EXPECTED_STATE: frozenset[str] = frozenset(f"?? {path}" for path in APPROVED_FILES)

#: The commit these files were developed on.  It is not "the" approved HEAD: a commit is
#: accepted when it descends from this one and differs from it in the approved files
#: only (see git_state).
BASE_COMMIT: str = "8f78f4a4ec118e5fcdf9130682ed3202794a90f8"
EXPECTED_BRANCH: str = "claude/compassionate-noether-7peel4"

TRACES: int = 20
RATE: int = 2
SEED: int = 42
CONCURRENCY: int = 4
SPANS_PER_TRACE: int = 7
EXPECTED_SPANS: int = TRACES * SPANS_PER_TRACE
MIN_BATTERY_PERCENT: int = 30

_PROJECT_RE = re.compile(re.escape(PROJECT_PREFIX) + r"[0-9a-f]{8}")


# ---------------------------------------------------------------------------
# Pure guards
# ---------------------------------------------------------------------------

def validate_project_name(name: str, docker_lines: Sequence[str]) -> None:
    """Raises SmokeFailure unless the name is a fresh disposable one."""
    if name == "agentops":
        raise SmokeFailure("the project name must never be the default 'agentops'")
    if not _PROJECT_RE.fullmatch(name):
        raise SmokeFailure(f"project name {name!r} is not {PROJECT_PREFIX}<8 hex>")
    taken = [line for line in docker_lines if name in line]
    if taken:
        raise SmokeFailure("Docker objects of this project name already exist:\n"
                           + "\n".join(taken[:6]))


def new_project_name() -> str:
    return PROJECT_PREFIX + uuid.uuid4().hex[:8]


def group_ids(project: str) -> tuple[str, str]:
    """Consumer groups of this run only; never a production or benchmark group."""
    return f"{project}-stream", f"{project}-storage"


def test_override_text(project: str) -> str:
    stream, storage = group_ids(project)
    return (
        "# Written by run_pipeline_it.py into its temporary directory; never in the repository.\n"
        "services:\n"
        "  stream-processor:\n"
        "    environment:\n"
        f"      CONSUMER_GROUP_ID: \"{stream}\"\n"
        "  storage-consumer:\n"
        "    environment:\n"
        f"      CONSUMER_GROUP_ID: \"{storage}\"\n"
    )


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Test:
    project: str = ""
    override: Optional[Path] = None
    run_id: str = ""
    awake: bool = False
    git_state: str = ""


T = Test()


def compose4(*args: str) -> list[str]:
    """Every Compose command of the processing services: the project, the main file,
    run_smoke's override, the overlay, this run's own group-id file and the
    temporary environment file."""
    if smoke.RUN.env_file is None or T.override is None:
        raise SmokeFailure("no Compose command before the temporary files exist")
    return ["docker", "compose", "-p", T.project, "-f", smoke.COMPOSE_FILE,
            "-f", smoke.OVERRIDE_FILE, "-f", OVERLAY_FILE, "-f", str(T.override),
            "--env-file", str(smoke.RUN.env_file), *args]


def comp(*args: str, timeout: float = smoke.T_COMMAND, what: str = "") -> str:
    smoke.RUN.compose_used = True
    return smoke.checked(compose4(*args), timeout=timeout, what=what or "compose " + args[0])


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def keep_awake() -> None:
    """Asks Windows not to idle-sleep while this process runs.  It is a request of
    this thread, not a power setting: nothing is changed, and it ends with the
    process (or at once, in release_awake)."""
    if os.name == "nt":
        import ctypes
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        T.awake = bool(ctypes.windll.kernel32.SetThreadExecutionState(
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED))


def release_awake() -> None:
    if os.name == "nt" and T.awake:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        T.awake = False


def power_state() -> tuple[str, int]:
    """('AC' or 'battery', percent); read-only."""
    if os.name != "nt":
        return "AC", 100
    import ctypes

    class Status(ctypes.Structure):
        _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                    ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                    ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]

    status = Status()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        raise SmokeFailure("the power status could not be read")
    percent = status.BatteryLifePercent if status.BatteryLifePercent <= 100 else 100
    return ("AC" if status.ACLineStatus == 1 else "battery"), int(percent)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
                          timeout=60)


def git_state(repo: Path, expect_head: str, *, base: str = BASE_COMMIT,
              branch: str = EXPECTED_BRANCH,
              files: Sequence[str] = APPROVED_FILES) -> str:
    """'development' or 'committed' when the repository is in one of the two states this
    test accepts; SmokeFailure naming what is wrong otherwise.  Read-only.

    Both states need the expected branch, HEAD equal to expect_head (the commit the
    operator names), an empty index and no tracked change.

    development   HEAD is the approved base commit and the only changes are exactly the
                  approved files, untracked.
    committed     the working tree is clean, every approved file is tracked at HEAD, and
                  HEAD descends from the approved base and differs from it in approved
                  files only.  No particular HEAD is hard-coded: any such commit is
                  recognized, and a commit that changes anything else, or does not descend
                  from the base, is not, however clean the tree.
    """
    def out(*args: str) -> str:
        result = _git(repo, *args)
        if result.returncode != 0:
            raise SmokeFailure(f"git {' '.join(args[:2])}: exit {result.returncode}: "
                               + result.stderr.strip()[-200:])
        return result.stdout.strip()

    head = out("rev-parse", "HEAD")
    current = out("rev-parse", "--abbrev-ref", "HEAD")
    if current != branch:
        raise SmokeFailure(f"the branch is {current!r}, not {branch!r}")
    if head != expect_head:
        raise SmokeFailure(f"HEAD is {head}, not the expected commit {expect_head}")
    if out("diff", "--cached", "--name-only"):
        raise SmokeFailure("the index is not empty")
    status = {line for line in out("status", "--porcelain", "--untracked-files=all").splitlines()
              if line.strip()}
    wanted = {f"?? {path}" for path in files}
    tracked = set(out("ls-tree", "-r", "--name-only", "HEAD", "--", *files).splitlines())
    if status == wanted:
        if tracked:
            raise SmokeFailure("approved files are both tracked and untracked")
        if head != base:
            raise SmokeFailure("the approved files are untracked, but HEAD is not the approved "
                               f"base commit {base}")
        return "development"
    if status:
        raise SmokeFailure("the working tree is neither clean nor exactly the approved untracked "
                           "files; differences: " + ", ".join(sorted(status ^ wanted)))
    if tracked != set(files):
        raise SmokeFailure("the tree is clean, but these approved files are not tracked at HEAD: "
                           + ", ".join(sorted(set(files) - tracked)))
    if head == base or _git(repo, "merge-base", "--is-ancestor", base, head).returncode != 0:
        raise SmokeFailure(f"HEAD does not descend from the approved base commit {base}")
    changed = set(out("diff", "--name-only", base, head).splitlines())
    if not changed or not changed <= set(files):
        raise SmokeFailure("HEAD differs from the approved base in files other than the approved "
                           "ones: " + ", ".join(sorted(changed - set(files))))
    return "committed"


def git_preflight(expect_head: str) -> None:
    section("repository")
    T.git_state = git_state(smoke.REPO, expect_head)
    say(f"branch {EXPECTED_BRANCH}; HEAD {expect_head}; state: {T.git_state}")
    for path in APPROVED_FILES:
        digest = hashlib.sha256((smoke.REPO / path).read_bytes()).hexdigest()
        say(f"sha256 {digest}  {path}")
    say("no tracked change, empty index; " + (
        "the only untracked files are the five approved ones" if T.git_state == "development"
        else "the five approved files are committed on the approved base, nothing else differs"))


def benchmark_idle(fingerprint: dict[str, list[str]]) -> None:
    section("no benchmark activity")
    folder = Path(os.environ.get("TEMP", "")) / "agentops-benchmarks"
    markers = [name for name in ("ACTIVE_RUN", "CLEANUP_UNVERIFIED") if (folder / name).exists()]
    say(f"benchmark markers: {markers or 'none'}")
    busy = [line for kind in fingerprint.values() for line in kind
            if smoke.PROJECT_BENCHMARK in line]
    say(f"Docker objects of the benchmark project: {len(busy)}")
    processes = ""
    if os.name == "nt":
        result = smoke.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "
             "'run_benchmark|run_smoke|run_e2e|stream-processor|storage-consumer' -and "
             f"$_.ProcessId -ne {os.getpid()} -and $_.CommandLine -notmatch 'run_pipeline_it' }} "
             "| ForEach-Object { $_.ProcessId }"],
            timeout=smoke.T_COMMAND, what="process list")
        processes = result.stdout.strip()
    say(f"benchmark or consumer host processes: {processes.split() or 'none'}")
    if markers or busy or processes:
        raise SmokeFailure("benchmark activity is present")


def ensure_base_image() -> None:
    """The one image this test needs that may be missing.  It is pulled BEFORE the
    Docker state is recorded, so that run_smoke's cleanup, which removes only what
    appeared after that point, does not try to delete a base image the project's
    own images are built from."""
    section("base image")
    found = smoke.run(["docker", "image", "inspect", BASE_IMAGE, "--format", "{{.Id}}"],
                      timeout=smoke.T_COMMAND, what="docker image inspect")
    if found.returncode == 0:
        say(f"{BASE_IMAGE}: present")
        return
    say(f"{BASE_IMAGE}: absent; pulling it (this stays on the machine)")
    smoke.checked(["docker", "pull", BASE_IMAGE], timeout=smoke.T_BUILD, what="docker pull")
    say(f"{BASE_IMAGE}: pulled")


# ---------------------------------------------------------------------------
# Rendered model of all four Compose files
# ---------------------------------------------------------------------------

def render_checks() -> None:
    section("Compose render of the processing services")
    comp("config", "--quiet", what="compose config")
    model = json.loads(comp("config", "--format", "json", what="compose config"))
    checks = Checks()
    checks.equal("project name", model.get("name"), T.project)
    services = model["services"]
    for name in ("kafka", "kafka-init", "otel-collector", "postgres", "db-bootstrap", *NEW_SERVICES):
        rendered = services[name]
        checks.true(f"{name}: no fixed container name", not rendered.get("container_name"),
                    rendered.get("container_name"))
    published = {name: [(p.get("host_ip"), str(p.get("published")), p.get("target"))
                        for p in services[name].get("ports", [])] for name in services}
    for name in (*NEW_SERVICES, "kafka-init", "db-bootstrap"):
        checks.equal(f"{name}: published ports", published[name], [])
    loopback = [(h, p) for name in ("kafka", "otel-collector", "postgres")
                for h, p, _ in published[name]]
    checks.true("every published port is loopback-only", bool(loopback)
                and all(h == "127.0.0.1" for h, _ in loopback), loopback)
    for name in NEW_SERVICES:
        rendered = services[name]
        checks.true(f"{name}: no fixed image tag (built, named after the project)",
                    "image" not in rendered or rendered["image"].startswith(T.project),
                    rendered.get("image"))
    for kind in ("volumes", "networks"):
        entries = model.get(kind, {})
        names = sorted(entry.get("name", "") for entry in entries.values())
        checks.true(f"{kind} are named after the project and none is external",
                    all(n.startswith(T.project + "_") for n in names)
                    and not any(entry.get("external") for entry in entries.values()), names)
    stream, storage = group_ids(T.project)
    sp = services["stream-processor"]["environment"]
    sc = services["storage-consumer"]["environment"]
    checks.equal("stream processor Kafka", sp["KAFKA_BOOTSTRAP_SERVERS"], smoke.BROKER_INTERNAL)
    checks.equal("storage consumer Kafka", sc["KAFKA_BOOTSTRAP_SERVERS"], smoke.BROKER_INTERNAL)
    checks.equal("storage consumer database host", sc["PG_HOST"], "postgres")
    checks.equal("stream processor group", sp["CONSUMER_GROUP_ID"], stream)
    checks.equal("storage consumer group", sc["CONSUMER_GROUP_ID"], storage)
    checks.true("storage consumer password is this run's throw-away one",
                sc["PG_PASSWORD"] == smoke.RUN.generated["POSTGRES_PASSWORD"], "<not printed>")
    for name, waits in (("stream-processor", {"kafka-init", "db-bootstrap"}),
                        ("storage-consumer", {"kafka-init", "db-bootstrap", "postgres"})):
        found = {k: v["condition"] for k, v in services[name]["depends_on"].items()}
        checks.equal(f"{name}: waits for", sorted(found), sorted(waits))
    checks.finish("render")


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------

def container_info(service: str) -> dict[str, Any]:
    found = comp("ps", "-a", "-q", service).split()
    if len(found) != 1:
        raise SmokeFailure(f"{service}: expected one container, found {len(found)}")
    text = smoke.checked(
        ["docker", "inspect", "-f",
         "{{.State.Status}}|{{.RestartCount}}|{{.State.ExitCode}}|"
         "{{index .Config.Labels \"com.docker.compose.project\"}}", found[0]],
        timeout=smoke.T_COMMAND, what="docker inspect").strip()
    status, restarts, code, project = text.split("|")
    return {"id": found[0], "status": status, "restarts": int(restarts),
            "exit": int(code), "project": project}


def service_log(service: str) -> str:
    return comp("logs", "--no-color", "--no-log-prefix", service, what=f"logs {service}")


def watch_containers() -> None:
    """Replaces run_smoke's check of its host processes: both services must be
    running, in this project, and never restarted."""
    for service in NEW_SERVICES:
        info = container_info(service)
        if info["status"] != "running" or info["restarts"] != 0 or info["project"] != T.project:
            raise SmokeFailure(f"{service}: {info}\n" + service_log(service)[-1200:])


def build_images() -> None:
    section("pipeline image")
    smoke.RUN.compose_used = True
    build = smoke.run(compose4("build", *NEW_SERVICES), timeout=smoke.T_BUILD,
                      what="compose build")
    smoke.write_log("build-pipeline.log", build.stdout + build.stderr)
    if build.returncode != 0:
        raise SmokeFailure("building the pipeline image failed:\n"
                           + "\n".join((build.stdout + build.stderr).splitlines()[-14:]))
    names = smoke.docker_lines("images", "--format", "{{.Repository}}:{{.Tag}}")
    mine = [n for n in names if n.startswith(T.project + "-")]
    say(f"images of this project: {', '.join(mine)}")
    if not any(n.startswith(f"{T.project}-stream-processor") for n in mine) \
            or not any(n.startswith(f"{T.project}-storage-consumer") for n in mine):
        raise SmokeFailure("the project's pipeline images were not found by their own names")


def start_services_and_wait() -> None:
    section("processing services")
    comp("up", "-d", "--no-build", *NEW_SERVICES, timeout=smoke.T_BOOTSTRAP,
         what="compose up services")
    stream, storage = group_ids(T.project)

    def subscribed() -> Optional[bool]:
        watch_containers()
        logs = {s: service_log(s) for s in NEW_SERVICES}
        subscribed.detail = " | ".join(f"{s}: {len(t.splitlines())} lines" for s, t in logs.items())
        return True if all("Subscribed to" in t for t in logs.values()) else None

    smoke.wait_for("both services to report that they are subscribed", 90.0, subscribed,
                   interval=3.0)
    for service in NEW_SERVICES:
        text = service_log(service)
        smoke.write_log(f"{service}-start.log", text)
        for line in text.splitlines():
            if line.startswith("  "):
                say(f"  {service}: {line.strip()}")
    checks = Checks()
    stream_log, storage_log = service_log("stream-processor"), service_log("storage-consumer")
    checks.true("stream processor uses the internal broker",
                re.search(r"bootstrap\s*:\s*agentops-kafka:29092", stream_log) is not None, "")
    checks.true("storage consumer uses the internal broker",
                re.search(r"bootstrap\s*:\s*agentops-kafka:29092", storage_log) is not None, "")
    checks.true("storage consumer uses the project's database",
                re.search(r"pg host\s*:\s*postgres:5432", storage_log) is not None, "")
    checks.true("stream processor group is this run's",
                re.search(rf"group\s*:\s*{re.escape(stream)}\b", stream_log) is not None, stream)
    checks.true("storage consumer group is this run's",
                re.search(rf"group\s*:\s*{re.escape(storage)}\b", storage_log) is not None, storage)
    checks.finish("service configuration")
    for group, topic in ((stream, smoke.TOPIC_RAW), (storage, smoke.TOPIC_SPANS)):
        smoke.wait_for(f"group {group} to be assigned all partitions", 90.0,
                       lambda g=group, t=topic: smoke.group_assigned(g, t), interval=3.0)
        say(f"{group}: assigned {smoke.PARTITIONS} partitions of {topic}")
    watch_containers()


# ---------------------------------------------------------------------------
# What the workload must have produced, beyond run_stage's own reconciliation
# ---------------------------------------------------------------------------

def make_stage() -> Stage:
    base = Stage(
        run_id=T.run_id, scenario="normal", traces=TRACES, max_duration=60, digest_prefix="",
        successes=TRACES, failures=0, failing_indexes=(), spans=EXPECTED_SPANS,
        trace_sizes={str(SPANS_PER_TRACE): TRACES}, status={"UNSET": EXPECTED_SPANS},
        error_spans={}, error_types={}, scenario_roots={"normal": TRACES})
    return dataclasses.replace(base, digest_prefix=smoke.planned_facts(base)["digest"])


def extra_checks() -> None:
    section("persistence, beyond the stage reconciliation")
    checks = Checks()
    rows, distinct = smoke.psql(
        "SELECT count(*) || '|' || count(DISTINCT (trace_id, span_id)) FROM telemetry_spans"
    ).split("|")
    checks.equal("rows in telemetry_spans", int(rows), EXPECTED_SPANS)
    checks.equal("distinct (trace_id, span_id) keys", int(distinct), EXPECTED_SPANS)
    found = json.loads(smoke.psql(smoke._GLOBAL_SQL))
    checks.equal("run ids present in the database", found["run_ids"], [T.run_id])
    checks.equal("rows outside this run's traces", found["rows_outside_workload_traces"], 0)
    checks.equal("traces with a root span", int(smoke.psql(
        "SELECT count(*) FROM telemetry_spans WHERE parent_span_id IS NULL")), TRACES)
    checks.equal("spans per trace -> traces", json.loads(smoke.psql(
        "SELECT coalesce(json_object_agg(n::text, c), '{}') FROM ("
        "SELECT n, count(*) AS c FROM (SELECT trace_id, count(*) AS n FROM telemetry_spans "
        "GROUP BY trace_id) t GROUP BY n) u")), {str(SPANS_PER_TRACE): TRACES})
    checks.equal("rows from another Kafka topic", int(smoke.psql(
        "SELECT count(*) FROM telemetry_spans WHERE kafka_topic <> "
        f"'{smoke.TOPIC_SPANS}'")), 0)
    checks.equal("rows sharing a (partition, offset)", int(smoke.psql(
        "SELECT count(*) FROM (SELECT 1 FROM telemetry_spans GROUP BY kafka_partition, "
        "kafka_offset HAVING count(*) > 1) t")), 0)
    per_partition = json.loads(smoke.psql(
        "SELECT coalesce(json_object_agg(kafka_partition::text, c), '{}') FROM ("
        "SELECT kafka_partition, count(*) AS c FROM telemetry_spans GROUP BY 1) t"))
    checks.true("every row came from one of the three partitions",
                set(per_partition) <= {"0", "1", "2"} and sum(per_partition.values())
                == EXPECTED_SPANS, per_partition)
    for service in NEW_SERVICES:
        info = container_info(service)
        checks.true(f"{service}: still running, never restarted, in this project",
                    info["status"] == "running" and info["restarts"] == 0
                    and info["project"] == T.project, info)
        text = service_log(service)
        smoke.write_log(f"{service}-end.log", text)
        checks.true(f"{service}: no traceback in its log", "Traceback" not in text, "")
    checks.finish("persistence")


#: Services that must be running, and so attached to the project network, when the
#: workload has finished.  kafka-init and db-bootstrap are one-shot jobs: they exit, and
#: an exited container is no longer attached to the network (it is absent from
#: `docker network inspect`).  Docker still REPORTS the network for it in `docker ps`
#: and `docker inspect`, so its recorded networks are never used here.
REQUIRED_RUNNING_SERVICES: tuple[str, ...] = (
    "kafka", "postgres", "otel-collector", "stream-processor", "storage-consumer")

_LABEL_PROJECT = "com.docker.compose.project"
_LABEL_SERVICE = "com.docker.compose.service"


def parse_network_containers(text: str) -> list[str]:
    """Full ids of the containers attached to a network, from
    `docker network inspect --format '{{json .Containers}}'` (null when none)."""
    found = json.loads(text.strip() or "null") or {}
    if not isinstance(found, dict):
        raise SmokeFailure("unexpected network inspect output")
    return sorted(found)


def parse_project_containers(text: str) -> dict[str, dict[str, Any]]:
    """id -> {service, state, networks} from lines of
    `docker ps -a --no-trunc --format '{{.ID}}|{{.Label "<service>"}}|{{.State}}|{{.Networks}}'`
    filtered by the project label.  An exited container still lists the network it was on."""
    found: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.rstrip("\r\n").split("|")
        if len(parts) != 4 or not parts[0]:
            raise SmokeFailure(f"unexpected container line: {line!r}")
        identifier, service, state, networks = parts
        found[identifier] = {"service": service, "state": state,
                             "networks": [n for n in networks.split(",") if n]}
    return found


def network_membership_problems(
    project: str, network: str, attached: dict[str, dict[str, str]],
    project_containers: dict[str, dict[str, Any]],
) -> list[str]:
    """What is wrong with the membership of the project's network; empty when nothing is.

    attached            id -> {"project": its compose project label ("" when it has none),
                               "service": its compose service label}
    project_containers  every container that carries the project's label, running or
                        not (id -> service, state, networks)

    The two sets are NOT expected to be equal: kafka-init and db-bootstrap run once and
    exit, and an exited container is no longer attached (although `docker ps` still reports
    the network it was on).  What must hold is that
      1. every attached container carries this project's label and is one of the
         project's own containers (so no foreign container shares the network),
      2. every running container of the project is attached to this network, and
      3. each service the workload needs is running, exactly once.
    Labels and container ids decide; names are not used."""
    problems = []
    for identifier, labels in sorted(attached.items()):
        if labels.get("project") != project:
            problems.append(f"foreign container {identifier[:12]} (project label "
                            f"{labels.get('project')!r}) is attached to {network}")
        elif identifier not in project_containers:
            problems.append(f"container {identifier[:12]} is attached to {network} but is "
                            "not among the project's containers")
    for identifier, info in sorted(project_containers.items()):
        if info["state"] != "running":
            continue                                   # exited one-shots: nothing required
        if identifier not in attached:
            problems.append(f"running {info['service']} ({identifier[:12]}) is not attached "
                            f"to {network}")
        elif network not in info["networks"]:
            problems.append(f"running {info['service']} ({identifier[:12]}) is attached, but "
                            f"its networks are {info['networks']}, not {network}")
    for service in REQUIRED_RUNNING_SERVICES:
        running = [i for i, info in project_containers.items()
                   if info["service"] == service and info["state"] == "running"]
        if len(running) != 1:
            problems.append(f"expected one running {service}, found {len(running)}")
    return problems


def collect_membership(network: str) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]]]:
    """What Docker says now: (attached containers with their labels, the project's
    containers).  Read-only queries only."""
    ids = parse_network_containers(smoke.checked(
        ["docker", "network", "inspect", network, "--format", "{{json .Containers}}"],
        timeout=smoke.T_COMMAND, what="docker network inspect"))
    attached = {}
    for identifier in ids:
        text = smoke.checked(
            ["docker", "inspect", "-f",
             "{{index .Config.Labels \"" + _LABEL_PROJECT + "\"}}|"
             "{{index .Config.Labels \"" + _LABEL_SERVICE + "\"}}", identifier],
            timeout=smoke.T_COMMAND, what="docker inspect").strip()
        project, _, service = text.partition("|")
        attached[identifier] = {"project": project, "service": service}
    listing = smoke.checked(
        ["docker", "ps", "-a", "--no-trunc", "--filter", f"label={_LABEL_PROJECT}={T.project}",
         "--format", "{{.ID}}|{{.Label \"" + _LABEL_SERVICE + "\"}}|{{.State}}|{{.Networks}}"],
        timeout=smoke.T_COMMAND, what="docker ps")
    return attached, parse_project_containers(listing)


def isolation_checks() -> None:
    section("isolation")
    checks = Checks()
    network = f"{T.project}_agentops-net"
    attached, project_containers = collect_membership(network)
    running = sorted(i["service"] for i in project_containers.values() if i["state"] == "running")
    exited = sorted(i["service"] for i in project_containers.values() if i["state"] != "running")
    say(f"  attached to {network}: {len(attached)}; running services {running}; "
        f"exited one-shots {exited}")
    checks.equal("network membership problems (foreign, unattached or wrong-network)",
                 network_membership_problems(T.project, network, attached, project_containers),
                 [])

    def address(container: str) -> str:
        return smoke.checked(
            ["docker", "inspect", "-f",
             "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}", container],
            timeout=smoke.T_COMMAND, what="docker inspect").strip()

    wanted = {name: address(smoke.container_id(name)) for name in ("postgres", "kafka")}
    resolved = comp("exec", "-T", "storage-consumer", "python", "-c",
                    "import socket; print(socket.gethostbyname('postgres'), "
                    "socket.gethostbyname('agentops-kafka'))", what="resolve names").split()
    checks.equal("the consumer's 'postgres' and 'agentops-kafka' resolve to the project's own "
                 "containers", resolved, [wanted["postgres"], wanted["kafka"]])
    normal = smoke.checked(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
         smoke.NORMAL_POSTGRES_CONTAINER], timeout=smoke.T_COMMAND,
        what="docker inspect").split()
    checks.true("neither resolves to the normal database's address",
                not set(resolved) & set(normal), "<addresses not printed>")
    checks.finish("isolation")
    smoke.check_normal_stack("after the workload")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def diagnose() -> None:
    section("diagnostics (masked, last lines)")
    for service in ("kafka-init", "db-bootstrap", "otel-collector", *NEW_SERVICES):
        try:
            text = comp("logs", "--no-color", "--no-log-prefix", "--tail", "25", service,
                        what=f"logs {service}")
            say(f"--- {service}")
            say(text[-1800:])
        except SmokeFailure as failure:
            say(f"--- {service}: no log ({str(failure)[:120]})")


def it(expect_head: str) -> None:
    git_preflight(expect_head)
    if sys.version_info[:2] != (3, 13):
        raise SmokeFailure("this test needs Python 3.13")
    source, percent = power_state()
    say(f"power: {source}, {percent}%")
    if source == "battery" and percent < MIN_BATTERY_PERCENT:
        raise SmokeFailure(f"on battery at {percent}%")
    T.project = new_project_name()
    T.run_id = "it-" + uuid.uuid4().hex[:8]
    smoke.PROJECT = T.project                    # run_smoke's helpers now name this project
    smoke.PROJECT_BENCHMARK = "agentops-workload-smoke"
    smoke.GROUP_STREAM, smoke.GROUP_STORAGE = group_ids(T.project)
    smoke.RATE, smoke.SEED, smoke.CONCURRENCY = RATE, SEED, CONCURRENCY
    smoke.ALLOWED_UNTRACKED = EXPECTED_STATE if T.git_state == "development" else frozenset()
    smoke.check_host_processes = watch_containers
    smoke.RUN.caches_before = smoke.bytecode_caches()
    say(f"project {T.project}; run id {T.run_id}; groups {', '.join(group_ids(T.project))}")

    smoke.check_ports()
    fingerprint = smoke.docker_fingerprint()
    validate_project_name(T.project, [line for kind in fingerprint.values() for line in kind])
    benchmark_idle(fingerprint)
    smoke.create_workspace()
    assert smoke.RUN.temp is not None
    T.override = smoke.RUN.temp / "pipeline-it.override.yml"
    T.override.write_text(test_override_text(T.project), encoding="utf-8")
    python = smoke.REPO / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        raise SmokeFailure("the repository's virtual environment has no interpreter")
    smoke.RUN.python = python
    # The isolation gate: the rendered model of all four Compose files is verified before any
    # Docker object exists.  (compose config reads files and creates nothing.)
    smoke.check_render()
    render_checks()
    ensure_base_image()
    smoke.record_docker_state()

    smoke.start_kafka()
    smoke.create_topics()
    smoke.start_postgres()
    smoke.run_bootstrap()
    build_images()
    smoke.start_collector()
    start_services_and_wait()
    offsets = smoke.check_baseline()
    offsets = smoke.run_stage(make_stage(), offsets)
    extra_checks()
    isolation_checks()


FINGERPRINT_KINDS: tuple[str, ...] = ("containers", "volumes", "networks", "images")


class LiveOps:
    """What cleanup touches, as run_smoke's helpers expose it.  Every removal is scoped
    by the project name; nothing is ever chosen by comparing inventories."""

    def __init__(self, project: str) -> None:
        if project == "agentops" or not _PROJECT_RE.fullmatch(project):
            raise SmokeFailure(f"cleanup refuses the project name {project!r}")
        self.project = project

    def can_down(self) -> bool:
        return bool(smoke.RUN.compose_used and T.override is not None
                    and smoke.RUN.env_file is not None and smoke.RUN.env_file.is_file())

    def down(self) -> tuple[int, str]:
        """The one Compose invocation that removes containers, networks and volumes."""
        result = smoke.run(compose4("down", "--volumes", "--rmi", "local", "--remove-orphans"),
                           timeout=smoke.T_DOWN, what="compose down")
        return result.returncode, smoke.redact(result.stderr.strip()[-300:])

    def project_objects(self, kind: str) -> list[str]:
        label = f"label={_LABEL_PROJECT}={self.project}"
        command = {"containers": ["ps", "-a", "-q", "--filter", label],
                   "networks": ["network", "ls", "-q", "--filter", label],
                   "volumes": ["volume", "ls", "-q", "--filter", label],
                   "images": ["images", "-q", "--filter", label]}[kind]
        return smoke.docker_lines(*command)

    def owned_images(self) -> list[str]:
        """References (name:tag) of images this project owns: they carry its Compose
        label AND their name starts with the project name.  Anything else is not owned."""
        listed = smoke.docker_lines(
            "images", "--filter", f"label={_LABEL_PROJECT}={self.project}",
            "--format", "{{.Repository}}:{{.Tag}}")
        return [ref for ref in listed
                if ref.startswith(self.project + "-") and "<none>" not in ref]

    def remove_image(self, reference: str) -> bool:
        """Removes one image by its exact reference; never by id, never forced."""
        if not reference.startswith(self.project + "-"):
            raise SmokeFailure(f"refusing to remove {reference!r}: not named after the project")
        return smoke.run(["docker", "image", "remove", reference], timeout=smoke.T_COMMAND,
                         what="docker image remove").returncode == 0

    def fingerprint(self) -> dict[str, list[str]]:
        return smoke.docker_fingerprint()

    def leaked(self) -> int:
        """Generated passwords found in the temporary logs, reports and snapshots, plus
        those run_smoke had to mask before writing."""
        count = smoke.RUN.masked_in_logs
        if smoke.RUN.temp is not None and smoke.RUN.temp.exists():
            for path in smoke.RUN.temp.glob("*"):
                if path.is_file() and path.name != "smoke.env":
                    text = path.read_text(encoding="utf-8", errors="replace")
                    count += sum(text.count(v) for v in smoke.RUN.generated.values())
        return count

    def remove_temp(self) -> bool:
        """The temporary directory (the env file with the throw-away passwords, the logs):
        only a directory under the system temp area, never the repository."""
        temp = smoke.RUN.temp
        if temp is None:
            return True
        resolved = Path(temp).resolve()
        root = Path(tempfile.gettempdir()).resolve()
        if resolved == smoke.REPO or smoke.REPO in resolved.parents or root not in resolved.parents:
            raise SmokeFailure(f"refusing to delete {resolved}: not a temporary directory")
        return smoke._remove_tree(resolved)

    def repository_problems(self) -> list[str]:
        problems = []
        try:
            unexpected = [line for line in smoke.repository_state()
                          if line not in smoke.ALLOWED_UNTRACKED]
            if unexpected:
                problems.append("the repository holds unexpected changes: " + ", ".join(unexpected))
            caches = sorted(smoke.bytecode_caches() - smoke.RUN.caches_before)
            if caches:
                problems.append("bytecode caches were written to the repository")
        except SmokeFailure as failure:
            problems.append(str(failure))
        return problems

    def normal_stack_problem(self) -> Optional[str]:
        try:
            smoke.check_normal_stack("after cleanup")
        except SmokeFailure as failure:
            return str(failure)
        return None


def safe_cleanup(project: str, before: Optional[dict[str, list[str]]], ops: Any,
                 report: Any = say) -> list[str]:
    """Gives back this project's resources and the temporary files, verifies it, and
    returns what went wrong (empty = verified).

    Only three kinds of thing are ever removed: this project's containers, networks and
    volumes, by the exact project-scoped `compose down`; this project's own images, by
    exact name, when ownership is proven by name AND label; and the temporary directory.
    The inventory before and after is compared and reported but is never a source of
    deletions: an object that merely appeared during the run is listed, not touched."""
    problems: list[str] = []
    if ops.can_down():
        code, tail = ops.down()
        report(f"compose down --volumes --rmi local --remove-orphans (project {project}): "
               f"exit {code}")
        if code != 0:
            problems.append("compose down failed: " + tail)
    else:
        report("compose down: not needed, no Compose command had run")

    for reference in ops.owned_images():
        removed = ops.remove_image(reference)
        report(f"image of this project left by compose down: {reference} -> "
               f"{'removed' if removed else 'NOT removed'}")
        if not removed:
            problems.append(f"image {reference} could not be removed")
    for kind in FINGERPRINT_KINDS:
        left = ops.project_objects(kind)
        report(f"project {kind} left: {len(left)}")
        if left:
            problems.append(f"{len(left)} project {kind} left")

    after = ops.fingerprint()
    if before is None:
        report("no inventory was recorded before; nothing to compare")
    else:
        for kind in FINGERPRINT_KINDS:
            gone = sorted(set(before[kind]) - set(after[kind]))
            new = sorted(set(after[kind]) - set(before[kind]))
            mine = [line for line in new if project in line]
            unrelated = [line for line in new if project not in line]
            report(f"{kind}: {len(after[kind])} (before {len(before[kind])}); "
                   f"{'identical' if not gone and not new else 'DIFFERENT'}")
            for line in gone:
                report(f"  - existing, now missing or changed: {line}")
            for line in mine:
                report(f"  + of this project, still present: {line}")
            for line in unrelated:
                report(f"  + appeared during the run, not this project's, NOT touched: {line}")
            if gone:
                problems.append(f"{len(gone)} existing {kind} object(s) missing or changed")
            if mine:
                problems.append(f"{len(mine)} {kind} object(s) of this project remain")

    leaked = ops.leaked()
    report(f"generated passwords found in, or masked from, temporary files: {leaked}")
    if leaked:
        problems.append("a generated password reached a temporary file")
    gone_temp = ops.remove_temp()
    report(f"temporary directory deleted: {'yes' if gone_temp else 'NO'}")
    if not gone_temp:
        problems.append("the temporary directory could not be deleted")
    problems.extend(ops.repository_problems())
    problem = ops.normal_stack_problem()
    if problem:
        problems.append(problem)
    return problems


def teardown(ops: Any = None) -> bool:
    """Runs on the success path and on every failure path (see main)."""
    section("project teardown")
    problems = safe_cleanup(T.project, smoke.RUN.before, ops if ops is not None
                            else LiveOps(T.project))
    for problem in problems:
        say(f"CLEANUP PROBLEM: {problem}")
    return not problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_pipeline_it",
        description="One integration test of the containerized ingestion pipeline "
                    "on a disposable Compose project.")
    parser.add_argument("--expect-head", required=True, metavar="COMMIT")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")

    keep_awake()
    passed = False
    try:
        it(args.expect_head)
        passed = True
    except SmokeFailure as failure:
        section("FAILURE")
        say(str(failure))
    except KeyboardInterrupt:
        section("FAILURE")
        say("interrupted")
    except Exception as exc:  # anything unforeseen is a failure, and is cleaned up too
        section("FAILURE")
        say(f"{type(exc).__name__}: {exc}")
    if not passed and T.override is not None:
        try:
            diagnose()
        except Exception as exc:
            say(f"diagnostics failed: {type(exc).__name__}")
    try:
        clean = teardown() if T.project else True
    except Exception as exc:
        clean = False
        say(f"CLEANUP PROBLEM: {type(exc).__name__}: {exc}")
    release_awake()

    section("result")
    say(f"functional and isolation checks: {'PASSED' if passed else 'FAILED'}")
    say(f"cleanup verified: {'yes' if clean else 'NO'}")
    return 0 if passed and clean else 1


if __name__ == "__main__":
    sys.exit(main())

"""
workload-generator/run_smoke.py

Live smoke test of the workload generator on a separate, disposable stack.

It proves one path, for two small workloads (NORMAL and API_500):

    REAL driver -> OTLP -> collector -> Kafka -> stream processor
        -> canonical Kafka topic -> storage consumer -> PostgreSQL

It only ORCHESTRATES.  Planning, fault injection, stream processing, storage
and the database bootstrap are the existing components, run unchanged:

    Compose project   agentops-workload-smoke (docker-compose.yml plus
                      compose.smoke.override.yml), services kafka,
                      kafka-init, postgres, db-bootstrap, otel-collector
    host processes    stream-processor/main.py, storage-consumer/main.py and
                      python -m workload_generator, from a fresh virtual
                      environment built from the pinned requirements

Everything temporary (generated passwords, the virtual environment, logs,
reports, snapshots) lives in one directory outside the repository and is
deleted at the end.  The normal stack is never addressed: every Compose
command names the project, both files and the temporary environment file,
and the Docker state outside the project is compared before and after.

The first failure stops the run; nothing is retried or adjusted.  Cleanup
always runs.

This file is now a library of helpers.  Run directly it starts nothing: it prints a refusal and exits 2.
The live path is workload-generator/run_e2e.py (plan by default; a live run needs --execute, the full
--expect-head, the exact --confirm phrase, an approved-tree manifest for a dirty tree and a passing resource
preflight).  smoke() below, the older two-stage flow, is kept for importers and is not reachable from the
command line.

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import posixpath
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

REPO: Path = Path(__file__).resolve().parent.parent

PROJECT: str = "agentops-workload-smoke"
COMPOSE_FILE: str = "docker-compose.yml"
OVERRIDE_FILE: str = "workload-generator/compose.smoke.override.yml"
ALLOWED_UNTRACKED: frozenset[str] = frozenset({
    "?? workload-generator/compose.smoke.override.yml",
    "?? workload-generator/run_smoke.py",
})

OTLP_PORT: int = 14317
KAFKA_PORT: int = 19092
POSTGRES_PORT: int = 15432
#: Ports of the normal stack.  Seeing one of them in a log of this run means
#: something was pointed at the wrong stack.
NORMAL_STACK_PORTS: tuple[int, ...] = (9092, 5432, 4317)
NORMAL_POSTGRES_CONTAINER: str = "agentops-postgres"

BROKER_INTERNAL: str = "agentops-kafka:29092"
KAFKA_BIN: str = "/opt/kafka/bin"
TOPIC_RAW: str = "agentops.telemetry.otlp.traces"
TOPIC_SPANS: str = "agentops.telemetry.spans"
TOPIC_DLQ: str = "agentops.telemetry.dlq"
TOPICS: tuple[str, ...] = (TOPIC_RAW, TOPIC_SPANS, TOPIC_DLQ)
PARTITIONS: int = 3
GROUP_STREAM: str = "d3-stream-processor"
GROUP_STORAGE: str = "d3-storage-consumer"

SERVICES: tuple[str, ...] = ("kafka", "kafka-init", "postgres", "db-bootstrap", "otel-collector")
#: The bootstrap ledger of a finished bootstrap, in order: db-bootstrap's own plan (the base
#: migrations with dbt after 001, post_dbt_grants.sql, the "complete" marker, and then the
#: upgrades, today 015).  The upgrades come AFTER "complete", so the last step is not "complete".
#: A test compares this tuple with db-bootstrap/bootstrap.py build_plan on the real files, so a
#: new migration or upgrade fails offline instead of in a live run.
LEDGER_PLAN: tuple[str, ...] = (
    "001_create_telemetry_spans.sql", "dbt_run", "002_create_grafana_reader.sql",
    "003_create_trace_viewer_reader.sql", "004_create_anomaly_events.sql",
    "005_create_anomaly_detector_role.sql", "006_create_anomaly_detector_runs.sql",
    "007_create_rca_tables.sql", "008_create_rca_analyzer_role.sql",
    "009_grant_rca_evidence_conflict_select.sql", "010_create_rca_investigation_embeddings.sql",
    "011_create_incident_retrieval_role.sql", "012_create_alert_tables.sql",
    "013_create_alert_evaluator_role.sql", "014_create_alert_notifier_role.sql",
    "post_dbt_grants.sql", "complete", "015_grant_trace_viewer_anomaly_rca_read.sql",
)
LEDGER_STEPS: int = len(LEDGER_PLAN)
SERVICE_NAME: str = "agentops-demo-app"
ROOT_SPAN: str = "agentops.request"
TOOL_SPAN: str = "tool.execute"

PASSWORD_VARIABLES: tuple[str, ...] = (
    "POSTGRES_PASSWORD",
    "GF_DATASOURCE_AGENTOPS_PASSWORD",
    "TRACE_VIEWER_DB_PASSWORD",
    "ANOMALY_DETECTOR_DB_PASSWORD",
    "RCA_ANALYZER_DB_PASSWORD",
    "INCIDENT_RETRIEVAL_DB_PASSWORD",
    "ALERT_EVALUATOR_DB_PASSWORD",
    "ALERT_NOTIFIER_DB_PASSWORD",
    "GF_SECURITY_ADMIN_PASSWORD",
)

# Seconds.
T_BUILD: float = 600.0
T_VENV: float = 900.0
T_BROKER: float = 90.0
T_KAFKA_INIT: float = 60.0
T_POSTGRES: float = 90.0
T_BOOTSTRAP: float = 300.0
T_COLLECTOR: float = 30.0
T_HOST_SERVICE: float = 45.0
T_DRAIN: float = 60.0
T_DOWN: float = 120.0
T_COMMAND: float = 60.0
SETTLE_SECONDS: float = 6.0
#: Diagnostic only: seconds between the storage consumer's timing summaries.  0 (the
#: default) leaves timing off and the consumer's environment exactly as it was.  Only
#: the benchmark harness sets it, and only for a cell listed in
#: run_benchmark.DIAGNOSTIC_TIMING_CELLS; the environment is never inherited.
CONSUMER_TIMING_INTERVAL: float = 0.0
#: Opt-in batched Kafka offset commits of the storage consumer.  1 (the default) is the original
#: one-commit-per-message behavior and adds NO variable to the consumer's environment.  The
#: benchmark harness sets both values explicitly for every cell (run_benchmark.execute_cell), and
#: only a cell approved there ever gets more than 1; the environment is never inherited.
CONSUMER_COMMIT_BATCH_MESSAGES: int = 1
CONSUMER_COMMIT_INTERVAL_SECONDS: float = 1.0
#: The bounds the consumer itself enforces (storage-consumer/config.py).
COMMIT_BATCH_LIMITS: tuple[int, int] = (1, 1000)
COMMIT_INTERVAL_LIMITS: tuple[float, float] = (0.05, 30.0)

_SENSITIVE_NAME = re.compile(
    r"(?i)^(OTEL_|PG|POSTGRES_|KAFKA_|CONSUMER_|TOPIC_|GF_|COMPOSE_|AGENTOPS_DIRECT_EXPORT$)"
    r"|_PASSWORD$"
)
_WRONG_STACK = re.compile(
    r"[A-Za-z0-9.\-\]]:(%s)(?![0-9])" % "|".join(str(port) for port in NORMAL_STACK_PORTS)
)


class SmokeFailure(Exception):
    """The run cannot continue.  Its message is the evidence."""


@dataclass(frozen=True)
class Stage:
    run_id: str
    scenario: str
    traces: int
    max_duration: int
    digest_prefix: str
    successes: int
    failures: int
    failing_indexes: tuple[int, ...]
    spans: int
    trace_sizes: Mapping[str, int]
    status: Mapping[str, int]
    error_spans: Mapping[str, int]
    error_types: Mapping[str, int]
    #: Roots per scenario.  Each root carries the scenario planned for ITS
    #: request: outside an episode that is "normal", whatever the run's is.
    scenario_roots: Mapping[str, int]


STAGES: tuple[Stage, ...] = (
    Stage(
        run_id="d3-normal-002", scenario="normal", traces=10, max_duration=60,
        digest_prefix="822cf8a0c3b1833a",
        successes=10, failures=0, failing_indexes=(),
        spans=70, trace_sizes={"7": 10}, status={"UNSET": 70},
        error_spans={}, error_types={}, scenario_roots={"normal": 10},
    ),
    Stage(
        run_id="d3-api500-002", scenario="api-500", traces=20, max_duration=90,
        digest_prefix="ae77fbb8ebca1e03",
        successes=17, failures=3, failing_indexes=(10, 13, 14),
        spans=134, trace_sizes={"7": 17, "5": 3}, status={"UNSET": 128, "ERROR": 6},
        error_spans={ROOT_SPAN: 3, TOOL_SPAN: 3},
        error_types={"UpstreamServerError": 3},
        scenario_roots={"normal": 17, "api-500": 3},
    ),
)
RATE: int = 2
SEED: int = 42
CONCURRENCY: int = 2


@dataclass
class Run:
    """What the run owns and has to give back."""
    temp: Optional[Path] = None
    env_file: Optional[Path] = None
    python: Optional[Path] = None
    generated: dict[str, str] = field(default_factory=dict)
    processes: dict[str, subprocess.Popen] = field(default_factory=dict)
    logs: dict[str, Path] = field(default_factory=dict)
    before: Optional[dict[str, list[str]]] = None
    normal_postgres: Optional[str] = None
    compose_used: bool = False
    caches_before: frozenset[str] = frozenset()
    #: Generated passwords that had to be masked before a log was written.
    masked_in_logs: int = 0
    started: float = field(default_factory=time.monotonic)


RUN = Run()


# ---------------------------------------------------------------------------
# Output and subprocesses
# ---------------------------------------------------------------------------

def redact(text: str) -> str:
    """Mask the generated credentials listed in RUN.generated.  That is the whole of the sanitizer: it knows
    only those values, so any other secret that reaches a message (an arbitrary token, a password someone
    typed into a tool) is NOT masked.  Anything that limits the length of a message must call this on the
    complete text first (see redact_tail), so that a credential cut by the limit is never left half-shown."""
    for value in RUN.generated.values():
        text = text.replace(value, "<redacted>")
    return text


def redact_tail(text: str, limit: int) -> str:
    """The last `limit` characters of the stripped text, with the generated credentials masked BEFORE the
    slice.  Slicing first would let a credential that straddles the cut survive as an unmatched fragment."""
    return redact(text.strip())[-limit:]


def say(text: str = "") -> None:
    print(redact(text), flush=True)


def section(title: str) -> None:
    say(f"\n=== {title}  [+{time.monotonic() - RUN.started:.0f}s]")


def write_log(name: str, text: str) -> None:
    """Keep the output of a tool in the temporary directory, masked."""
    assert RUN.temp is not None
    RUN.masked_in_logs += sum(text.count(value) for value in RUN.generated.values())
    (RUN.temp / name).write_text(redact(text), encoding="utf-8")


def tool_environment() -> dict[str, str]:
    """
    The environment for docker, git and pip: this process's own, without any
    variable that could reconfigure the stack.  Compose prefers the shell
    environment over --env-file, so nothing of that kind may reach it.
    """
    return {
        name: value for name, value in os.environ.items()
        if _SENSITIVE_NAME.search(name) is None
    }


def host_environment(**extra: str) -> dict[str, str]:
    """The explicit environment of a host process: a few system variables
    plus what that process is deliberately given."""
    env = {
        name: os.environ[name]
        for name in ("SYSTEMROOT", "PATH", "TEMP", "TMP") if name in os.environ
    }
    env["PYTHONUNBUFFERED"] = "1"
    # The components are imported from the repository; nothing is written there.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(REPO / "demo-app")
    env.update(extra)
    return env


def run(
    command: Sequence[str], *, timeout: float, cwd: Path = REPO,
    env: Optional[Mapping[str, str]] = None, what: str = "",
) -> subprocess.CompletedProcess:
    # With an approved engine pinned (run_e2e), every command that creates, starts, builds, runs, stops or
    # removes is preceded by a fresh engine verification.  The verification commands are reads, so they never
    # reach this branch again.  Without a pin (every other caller) nothing changes.
    if CONTAINED.engine_pin is not None and is_engine_mutation(command):
        verify_engine_identity(CONTAINED.engine_pin)
    try:
        return subprocess.run(
            list(command), cwd=cwd, env=dict(tool_environment() if env is None else env),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        raise SmokeFailure(f"{what or command[0]}: no result within {timeout:.0f} seconds")
    except FileNotFoundError:
        raise SmokeFailure(f"{what or command[0]}: {command[0]} is not installed")


#: The Compose subcommands, and the image-removal forms, that change the engine.  A command is a mutation when it
#: is a Compose command naming one of them, or one of these image removals.  Everything else is a read.
_COMPOSE_MUTATIONS: frozenset[str] = frozenset({"up", "build", "run", "down"})
_IMAGE_REMOVALS: tuple[tuple[str, ...], ...] = (("docker", "image", "remove"), ("docker", "image", "rm"),
                                                 ("docker", "rmi"))


def is_engine_mutation(command: Sequence[str]) -> bool:
    """True for a Docker command that creates, starts, builds, runs, stops or removes: a Compose up, build, run
    or down, and an image removal.  Pure."""
    tokens = [str(token) for token in command]
    if tokens[:2] == ["docker", "compose"]:
        return bool(_COMPOSE_MUTATIONS & set(tokens[2:]))
    return any(tokens[:len(form)] == list(form) for form in _IMAGE_REMOVALS)


def checked(command: Sequence[str], *, timeout: float, what: str, **kwargs: Any) -> str:
    result = run(command, timeout=timeout, what=what, **kwargs)
    if result.returncode != 0:
        tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-12:])
        raise SmokeFailure(f"{what}: exit {result.returncode}\n{tail}")
    return result.stdout


def compose_command(*args: str) -> list[str]:
    """Every Compose command names the project, both files and the temporary
    environment file."""
    if RUN.env_file is None:
        raise SmokeFailure("no Compose command before the environment file exists")
    return [
        "docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE, "-f", OVERRIDE_FILE,
        "--env-file", str(RUN.env_file), *args,
    ]


def compose(*args: str, timeout: float = T_COMMAND, what: str = "") -> str:
    RUN.compose_used = True
    return checked(compose_command(*args), timeout=timeout, what=what or "compose " + args[0])


def wait_for(what: str, timeout: float, probe: Callable[[], Any], interval: float = 2.0) -> Any:
    """probe() returns a value when ready, or None.  Its last detail, when it
    sets one on itself, is part of the failure."""
    deadline = time.monotonic() + timeout
    while True:
        value = probe()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            detail = getattr(probe, "detail", "")
            raise SmokeFailure(f"{what}: not reached within {timeout:.0f} seconds\n{detail}")
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def git(*args: str) -> str:
    return checked(["git", *args], timeout=T_COMMAND, what="git " + args[0])


def repository_state() -> list[str]:
    return [line for line in git("status", "--porcelain", "--untracked-files=all").splitlines()
            if line.strip()]


def bytecode_caches() -> frozenset[str]:
    """__pycache__ directories of the repository, outside local environments."""
    found = set()
    for directory, names, _ in os.walk(REPO):
        names[:] = [name for name in names if name not in (".git", "venv", ".venv", "node_modules")]
        if "__pycache__" in names:
            found.add(str(Path(directory, "__pycache__").relative_to(REPO)))
            names.remove("__pycache__")
    return frozenset(found)


def check_repository(expect_head: Optional[str], approved: Optional["ApprovedTree"] = None) -> None:
    section("repository")
    if approved is not None:
        # An operator-approved working tree (PR-03C2): every dirty path, its status and its content are
        # pinned by a manifest whose own SHA-256 the operator supplied.  Callers that pass no manifest
        # take the unchanged strict path below.
        verify_approved_tree(expect_head, approved)
        for path in (COMPOSE_FILE, OVERRIDE_FILE):
            if not (REPO / path).is_file():
                raise SmokeFailure(f"missing {path}")
        CONTAINED.approved = approved
        RUN.caches_before = bytecode_caches()
        say(f"branch {approved.branch}")
        say(f"HEAD   {approved.head}")
        say(f"working tree: the approved manifest ({len(approved.entries)} entries, "
            f"sha256 {approved.digest[:16]}...); index empty")
        return
    head = git("rev-parse", "HEAD").strip()
    say(f"branch {git('rev-parse', '--abbrev-ref', 'HEAD').strip()}")
    say(f"HEAD   {head}")
    if expect_head is not None and head != expect_head:
        raise SmokeFailure(f"HEAD is not the expected commit {expect_head}")
    unexpected = [line for line in repository_state() if line not in ALLOWED_UNTRACKED]
    if unexpected:
        raise SmokeFailure("the working tree holds other changes:\n" + "\n".join(unexpected))
    if git("diff", "--cached", "--name-only").strip():
        raise SmokeFailure("the index is not empty")
    for path in (COMPOSE_FILE, OVERRIDE_FILE):
        if not (REPO / path).is_file():
            raise SmokeFailure(f"missing {path}")
    RUN.caches_before = bytecode_caches()
    say("working tree: committed code plus the two smoke files; index empty")


def check_ports() -> None:
    section("ports")
    for port in (OTLP_PORT, KAFKA_PORT, POSTGRES_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            in_use = probe.connect_ex(("127.0.0.1", port)) == 0
        if not in_use:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
                    holder.bind(("127.0.0.1", port))
            except OSError:
                in_use = True
        say(f"127.0.0.1:{port}  {'IN USE' if in_use else 'free'}")
        if in_use:
            raise SmokeFailure(f"port {port} is in use")


def docker_lines(*args: str) -> list[str]:
    return sorted(
        line for line in checked(["docker", *args], timeout=T_COMMAND,
                                 what="docker " + args[0]).splitlines() if line.strip()
    )


def docker_fingerprint() -> dict[str, list[str]]:
    return {
        "containers": docker_lines("ps", "-a", "--no-trunc", "--format",
                                   "{{.ID}} {{.Names}} {{.State}}"),
        "volumes": docker_lines("volume", "ls", "--format", "{{.Name}}"),
        "networks": docker_lines("network", "ls", "--no-trunc", "--format", "{{.ID}} {{.Name}}"),
        "images": docker_lines("images", "--no-trunc", "--format",
                               "{{.Repository}}:{{.Tag}} {{.ID}}"),
    }


def short_hash(lines: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]


def normal_postgres() -> Optional[str]:
    """'<container id> <state> <health> <StartedAt> <FinishedAt>' of the normal database
    container (the health field is empty when it has none), or None when this machine has
    none.  Read-only: it only inspects.  The two lifecycle timestamps make a start or a
    stop show up even when the id, state and (stale) health look the same."""
    result = run(
        ["docker", "inspect", "-f",
         "{{.Id}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}} "
         "{{.State.StartedAt}} {{.State.FinishedAt}}",
         NORMAL_POSTGRES_CONTAINER],
        timeout=T_COMMAND, what="docker inspect",
    )
    return result.stdout.strip() if result.returncode == 0 else None


def normal_postgres_baseline_ok(state: Optional[str]) -> bool:
    """May a run start with the normal database container in this state?  Yes when there
    is none, when it is running and healthy, or when it is exited (deliberately stopped
    before the run).  Anything else (unhealthy, starting, paused, restarting, dead,
    created) is refused.  The run never starts, stops or changes it: every later check
    compares the whole state string with the baseline."""
    if state is None:
        return True
    fields = state.split(" ")
    if len(fields) != 5:
        return False
    status, health = fields[1], fields[2]
    return (status == "running" and health == "healthy") or status == "exited"


def check_normal_stack(when: str) -> None:
    now = normal_postgres()
    if now != RUN.normal_postgres:
        raise SmokeFailure(
            f"{NORMAL_POSTGRES_CONTAINER} changed ({when}): was {RUN.normal_postgres}, is {now}"
        )
    say(f"{NORMAL_POSTGRES_CONTAINER} ({when}): unchanged"
        + (f", {now.split(' ', 1)[1]}" if now else ", not present on this machine"))


def record_docker_state() -> None:
    section("normal Docker state before")
    RUN.before = docker_fingerprint()
    for kind, lines in RUN.before.items():
        say(f"{kind}: {len(lines)} (fingerprint {short_hash(lines)})")
    for line in RUN.before["containers"]:
        say(f"  container {line[:12]} {line.split(' ', 1)[1]}")
    taken = [line for kind in RUN.before.values() for line in kind if PROJECT in line]
    if taken:
        raise SmokeFailure("objects of the smoke project already exist:\n" + "\n".join(taken))
    RUN.normal_postgres = normal_postgres()
    say(f"{NORMAL_POSTGRES_CONTAINER}: {RUN.normal_postgres or 'not present on this machine'}")
    if not normal_postgres_baseline_ok(RUN.normal_postgres):
        raise SmokeFailure(f"{NORMAL_POSTGRES_CONTAINER} is neither running healthy nor "
                           f"exited (deliberately stopped): {RUN.normal_postgres}")


# ---------------------------------------------------------------------------
# Temporary directory, credentials, virtual environment
# ---------------------------------------------------------------------------

def create_workspace() -> None:
    section("temporary workspace")
    temp = Path(tempfile.mkdtemp(prefix="agentops-d3-smoke-")).resolve()
    try:
        register_workspace(temp)
    except (OSError, SmokeFailure) as exc:  # an unregistered directory is left alone, never deleted
        raise SmokeFailure(f"could not record ownership of the temporary directory: {exc}") from exc
    if temp == REPO or REPO in temp.parents:
        _discard_unused_workspace(temp)
        raise SmokeFailure("the temporary directory would be inside the repository")
    RUN.temp = temp
    say("created outside the repository")

    RUN.generated = {name: secrets.token_urlsafe(24) for name in PASSWORD_VARIABLES}
    env_file = temp / "smoke.env"
    with open(env_file, "x", encoding="utf-8", newline="\n") as handle:
        handle.writelines(f"{name}={value}\n" for name, value in RUN.generated.items())
    RUN.env_file = env_file
    say(f"generated {len(RUN.generated)} test-only passwords "
        f"({len(set(RUN.generated.values()))} distinct); they are never printed")
    (temp / "docker-before.json").write_text(json.dumps(RUN.before, indent=1), encoding="utf-8")


def create_virtual_environment() -> None:
    section("fresh virtual environment")
    assert RUN.temp is not None
    venv = RUN.temp / "venv"
    checked([sys.executable, "-m", "venv", str(venv)], timeout=T_VENV, what="python -m venv")
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        raise SmokeFailure("the virtual environment has no interpreter")
    RUN.python = python
    install = run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
         "-r", "workload-generator/requirements.txt",
         "-r", "stream-processor/requirements.txt",
         "-r", "storage-consumer/requirements.txt"],
        timeout=T_VENV, what="pip install",
    )
    write_log("pip-install.log", install.stdout + install.stderr)
    if install.returncode != 0:
        tail = "\n".join((install.stdout + install.stderr).strip().splitlines()[-8:])
        raise SmokeFailure(f"pip install: exit {install.returncode}\n{tail}")
    versions = json.loads(checked(
        [str(python), "-c",
         "import json, sys\n"
         "from importlib.metadata import version\n"
         "names = ('protobuf', 'opentelemetry-sdk', 'opentelemetry-exporter-otlp-proto-grpc',"
         " 'opentelemetry-proto', 'langgraph', 'pydantic', 'confluent-kafka', 'psycopg',"
         " 'grpcio')\n"
         "found = {name: version(name) for name in names}\n"
         "found['python'] = '.'.join(map(str, sys.version_info[:3]))\n"
         "print(json.dumps(found))"],
        timeout=T_COMMAND, what="version check", env=host_environment(),
    ))
    for name, value in sorted(versions.items()):
        say(f"{name:40} {value}")
    listed = checked([str(python), "-m", "pip", "list", "--format=freeze",
                      "--disable-pip-version-check"], timeout=T_COMMAND, what="pip list")
    say(f"packages installed: {len(listed.splitlines())}; "
        f"dbt packages: {sum(line.lower().startswith('dbt') for line in listed.splitlines())}")
    pip_check = run([str(python), "-m", "pip", "check", "--disable-pip-version-check"],
                    timeout=T_COMMAND, what="pip check")
    say(f"pip check: exit {pip_check.returncode} ({pip_check.stdout.strip() or 'no output'})")
    if not versions["python"].startswith("3.13."):
        raise SmokeFailure("the virtual environment is not Python 3.13")
    if int(versions["protobuf"].split(".")[0]) >= 6:
        raise SmokeFailure("protobuf 6 or later was installed")
    if pip_check.returncode != 0:
        raise SmokeFailure("pip check reported broken requirements")


# ---------------------------------------------------------------------------
# Isolated infrastructure
# ---------------------------------------------------------------------------

def check_render() -> None:
    section("Compose render")
    compose("config", "--quiet", what="compose config")
    # Parsed, never printed: the rendered model holds the generated passwords.
    model = json.loads(compose("config", "--format", "json", what="compose config"))
    expected_ports = {
        "kafka": [("127.0.0.1", str(KAFKA_PORT), 9092)],
        "otel-collector": [("127.0.0.1", str(OTLP_PORT), 4317)],
        "postgres": [("127.0.0.1", str(POSTGRES_PORT), 5432)],
        "kafka-init": [],
        "db-bootstrap": [],
    }
    if model.get("name") != PROJECT:
        raise SmokeFailure(f"rendered project name is {model.get('name')!r}")
    for service, ports in expected_ports.items():
        rendered = model["services"][service]
        if rendered.get("container_name"):
            raise SmokeFailure(f"{service} still has a fixed container name")
        found = [(p.get("host_ip"), str(p.get("published")), p.get("target"))
                 for p in rendered.get("ports", [])]
        if found != ports:
            raise SmokeFailure(f"{service} publishes {found}, expected {ports}")
        say(f"{service:15} no fixed name; ports "
            + (", ".join(f"{h}:{p}->{t}" for h, p, t in found) or "none"))
    kafka = model["services"]["kafka"]
    say(f"kafka hostname {kafka.get('hostname')}; aliases "
        f"{kafka['networks']['agentops-net'].get('aliases')}")
    say(f"kafka advertised {kafka['environment']['KAFKA_ADVERTISED_LISTENERS']}")
    say("networks " + ", ".join(sorted(n["name"] for n in model["networks"].values())))
    say("volumes  " + ", ".join(sorted(v["name"] for v in model["volumes"].values())))
    say("render: exit 0")


def container_id(service: str) -> str:
    found = compose("ps", "-a", "-q", service).split()
    if len(found) != 1:
        raise SmokeFailure(f"{service}: expected one container, found {len(found)}")
    return found[0]


def container_state(service: str) -> tuple[str, str, int]:
    """(status, health, exit code)"""
    text = checked(
        ["docker", "inspect", "-f",
         "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}"
         "|{{.State.ExitCode}}", container_id(service)],
        timeout=T_COMMAND, what="docker inspect",
    ).strip()
    status, health, code = text.split("|")
    return status, health, int(code)


def kafka_tool(tool: str, *args: str) -> subprocess.CompletedProcess:
    RUN.compose_used = True
    return run(
        compose_command("exec", "-T", "kafka", f"{KAFKA_BIN}/{tool}",
                        "--bootstrap-server", BROKER_INTERNAL, *args),
        timeout=T_COMMAND, what=tool,
    )


def wait_exited(service: str, timeout: float) -> int:
    def probe() -> Optional[int]:
        status, _, code = container_state(service)
        probe.detail = f"{service} is {status}"  # type: ignore[attr-defined]
        return code if status == "exited" else None
    return wait_for(f"{service} to finish", timeout, probe)


def start_kafka() -> None:
    section("Kafka")
    compose("up", "-d", "kafka", timeout=T_BROKER, what="compose up kafka")

    def probe() -> Optional[bool]:
        status, _, _ = container_state("kafka")
        if status != "running":
            raise SmokeFailure(f"the broker container is {status}")
        result = kafka_tool("kafka-topics.sh", "--list")
        probe.detail = (result.stdout + result.stderr).strip()[-600:]  # type: ignore[attr-defined]
        return True if result.returncode == 0 else None

    started = time.monotonic()
    wait_for("the broker to answer its own topic tool", T_BROKER, probe, interval=3.0)
    say(f"broker running; topic tool connected through {BROKER_INTERNAL} "
        f"after {time.monotonic() - started:.0f}s")


def topic_partitions() -> dict[str, int]:
    result = kafka_tool("kafka-topics.sh", "--describe")
    if result.returncode != 0:
        raise SmokeFailure("kafka-topics --describe failed:\n" + result.stderr[-600:])
    found = {}
    for line in result.stdout.splitlines():
        match = re.match(r"Topic:\s*(\S+)\s.*PartitionCount:\s*(\d+)", line)
        if match and not match.group(1).startswith("__"):
            found[match.group(1)] = int(match.group(2))
    return found


def create_topics() -> None:
    section("topics")
    compose("up", "-d", "kafka-init", timeout=T_KAFKA_INIT, what="compose up kafka-init")
    code = wait_exited("kafka-init", T_KAFKA_INIT)
    say(f"kafka-init exit code {code}")
    if code != 0:
        raise SmokeFailure("kafka-init failed:\n" + compose("logs", "--no-color", "kafka-init")[-800:])
    found = topic_partitions()
    for name, count in sorted(found.items()):
        say(f"{name}: {count} partitions")
    if found != {name: PARTITIONS for name in TOPICS}:
        raise SmokeFailure("the topics are not exactly the three expected ones")


def start_postgres() -> None:
    section("PostgreSQL")
    assert RUN.temp is not None
    build = run(compose_command("build", "postgres"), timeout=T_BUILD, what="compose build postgres")
    RUN.compose_used = True
    write_log("build-postgres.log", build.stdout + build.stderr)
    if build.returncode != 0:
        raise SmokeFailure("building the postgres image failed:\n"
                           + "\n".join((build.stdout + build.stderr).splitlines()[-10:]))
    compose("up", "-d", "--no-build", "postgres", timeout=T_POSTGRES, what="compose up postgres")

    def probe() -> Optional[bool]:
        status, health, _ = container_state("postgres")
        probe.detail = f"postgres is {status} / {health}"  # type: ignore[attr-defined]
        if status != "running":
            raise SmokeFailure(f"the postgres container is {status}")
        return True if health == "healthy" else None

    started = time.monotonic()
    wait_for("postgres to be healthy", T_POSTGRES, probe)
    say(f"image built; container running and healthy after {time.monotonic() - started:.0f}s")


def psql(sql: str) -> str:
    """One read-only statement in the ISOLATED database, through the project's
    own postgres container."""
    return compose(
        "exec", "-T", "postgres", "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1",
        "-U", "agentops", "-d", "agentops", "-c", " ".join(sql.split()), what="psql",
    ).strip()


def run_bootstrap() -> None:
    section("database bootstrap")
    assert RUN.temp is not None
    build = run(compose_command("build", "db-bootstrap"), timeout=T_BUILD,
                what="compose build db-bootstrap")
    write_log("build-bootstrap.log", build.stdout + build.stderr)
    if build.returncode != 0:
        raise SmokeFailure("building the bootstrap image failed:\n"
                           + "\n".join((build.stdout + build.stderr).splitlines()[-10:]))
    compose("up", "-d", "--no-build", "db-bootstrap", timeout=T_BOOTSTRAP,
            what="compose up db-bootstrap")
    code = wait_exited("db-bootstrap", T_BOOTSTRAP)
    output = compose("logs", "--no-color", "db-bootstrap")
    write_log("bootstrap.log", output)
    say(f"db-bootstrap exit code {code}")
    for line in output.strip().splitlines()[-4:]:
        say("  " + line[:200])
    if code != 0:
        raise SmokeFailure("the bootstrap failed")
    check_bootstrap_ledger()


def ledger_problem(found: str) -> Optional[str]:
    """Why a ledger read as '<count>|<step>,<step>,...' (in position order) is not the finished
    bootstrap, or None when it is exactly LEDGER_PLAN.  Pure."""
    count, _, names = found.strip().partition("|")
    steps = tuple(name for name in names.split(",") if name)
    if steps == LEDGER_PLAN and count == str(len(LEDGER_PLAN)):
        return None
    last = steps[-1] if steps else "none"
    missing = [name for name in LEDGER_PLAN if name not in steps]
    extra = [name for name in steps if name not in LEDGER_PLAN]
    detail = (f"missing {missing}" if missing else "") + (f" unexpected {extra}" if extra else "")
    if not missing and not extra:
        detail = "the steps are not in the plan's order"
    return (f"the ledger is not COMPLETE: expected the {len(LEDGER_PLAN)} steps of the bootstrap "
            f"plan ending '{LEDGER_PLAN[-1]}'; found {count or '0'} (last '{last}'); {detail.strip()}")


def check_bootstrap_ledger() -> None:
    found = psql(
        "SELECT count(*) || '|' || coalesce(string_agg(step, ',' ORDER BY position), '') "
        "FROM agentops_bootstrap.ledger"
    )
    count, _, names = found.strip().partition("|")
    say(f"ledger: {count} steps recorded, last step '{names.rsplit(',', 1)[-1]}'")
    problem = ledger_problem(found)
    if problem:
        raise SmokeFailure(problem)
    say("ledger state COMPLETE")


def start_collector() -> None:
    section("collector")
    compose("up", "-d", "otel-collector", timeout=T_COLLECTOR, what="compose up otel-collector")

    def probe() -> Optional[str]:
        status, _, _ = container_state("otel-collector")
        if status != "running":
            raise SmokeFailure(f"the collector container is {status}:\n"
                               + compose("logs", "--no-color", "otel-collector")[-800:])
        logs = compose("logs", "--no-color", "otel-collector")
        probe.detail = logs[-600:]  # type: ignore[attr-defined]
        return logs if "Everything is ready" in logs else None

    logs = wait_for("the collector to report it is ready", T_COLLECTOR, probe)
    time.sleep(3.0)
    logs = compose("logs", "--no-color", "otel-collector")
    bad = [
        line for line in logs.splitlines()
        if re.search(r"\t(error|fatal)\t|\"level\":\"(error|fatal)\"", line)
        or (re.search(r"(?i)kafka", line)
            and re.search(r"(?i)connection refused|no such host|unreachable|failed to", line))
    ]
    if bad:
        raise SmokeFailure("the collector logged errors at start:\n" + "\n".join(bad[:6]))
    with socket.create_connection(("127.0.0.1", OTLP_PORT), timeout=5.0):
        pass
    say(f"running; reported ready; no error line in {len(logs.splitlines())} startup log lines")
    say(f"127.0.0.1:{OTLP_PORT} accepts TCP connections")


# ---------------------------------------------------------------------------
# Host processes
# ---------------------------------------------------------------------------

def start_host_process(name: str, directory: str, env: Mapping[str, str]) -> None:
    assert RUN.temp is not None and RUN.python is not None
    log = RUN.temp / f"{name}.log"
    handle = open(log, "w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [str(RUN.python), "main.py"], cwd=REPO / directory, env=dict(env),
            stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
    finally:
        handle.close()
    RUN.processes[name] = process
    RUN.logs[name] = log


def read_log(name: str) -> str:
    return RUN.logs[name].read_text(encoding="utf-8", errors="replace")


def check_host_processes() -> None:
    for name, process in RUN.processes.items():
        if process.poll() is not None:
            raise SmokeFailure(
                f"{name} exited with code {process.returncode}:\n" + read_log(name)[-1200:]
            )
        text = read_log(name)
        wrong = _WRONG_STACK.search(text)
        if wrong:
            raise SmokeFailure(f"{name} mentions the normal stack's port {wrong.group(1)}")
        if "Traceback" in text or "halted" in text:
            raise SmokeFailure(f"{name} reported a failure:\n" + text[-1200:])


def wait_started(name: str, expected: Sequence[str], forbidden: Sequence[str] = ()) -> None:
    def probe() -> Optional[bool]:
        check_host_processes()
        text = read_log(name)
        probe.detail = text[-600:]  # type: ignore[attr-defined]
        present = [line for line in forbidden if line in text]
        if present:
            raise SmokeFailure(f"{name} printed a configuration that was not requested: {present[0]!r}")
        return True if all(line in text for line in expected) and "Subscribed to" in text else None

    wait_for(f"{name} to print its configuration", T_HOST_SERVICE, probe, interval=1.0)
    for line in read_log(name).splitlines():
        if line.startswith("  "):
            say("  " + line.strip())


def group_rows(group: str, topic: str) -> Optional[list[dict[str, str]]]:
    """The rows of one topic in the consumer group description, or None when
    the group has no stable description yet."""
    result = kafka_tool("kafka-consumer-groups.sh", "--describe", "--group", group)
    group_rows.detail = (result.stdout + result.stderr).strip()[-800:]  # type: ignore[attr-defined]
    header: Optional[list[str]] = None
    rows = []
    for line in result.stdout.splitlines():
        cells = line.split()
        if cells[:1] == ["GROUP"]:
            header = cells
        elif header and len(cells) == len(header) and cells[0] == group:
            row = dict(zip(header, cells))
            if row.get("TOPIC") == topic:
                rows.append(row)
    return rows if len(rows) == PARTITIONS else None


def group_assigned(group: str, topic: str) -> Optional[bool]:
    rows = group_rows(group, topic)
    group_assigned.detail = getattr(group_rows, "detail", "")  # type: ignore[attr-defined]
    if rows is None:
        return None
    return True if all(row.get("CONSUMER-ID", "-") != "-" for row in rows) else None


def group_lag(group: str, topic: str) -> Optional[int]:
    """Messages the group has not committed, or None when unknown.  A
    partition that never held a message has no committed offset and no lag."""
    rows = group_rows(group, topic)
    if rows is None:
        return None
    total = 0
    for row in rows:
        if row["LAG"] == "-":
            total += int(row["LOG-END-OFFSET"]) if row["LOG-END-OFFSET"] != "-" else 0
        else:
            total += int(row["LAG"])
    return total


def check_commit_batching() -> tuple[int, float]:
    """The batching setting, or SmokeFailure.  Run before any service is started, so an
    unsupported value fails closed.  Returns (messages per commit, interval seconds)."""
    batch, interval = CONSUMER_COMMIT_BATCH_MESSAGES, CONSUMER_COMMIT_INTERVAL_SECONDS
    if isinstance(batch, bool) or not isinstance(batch, int):
        raise SmokeFailure(f"CONSUMER_COMMIT_BATCH_MESSAGES must be a whole number, got {batch!r}")
    low, high = COMMIT_BATCH_LIMITS
    if not low <= batch <= high:
        raise SmokeFailure(f"CONSUMER_COMMIT_BATCH_MESSAGES must be between {low} and {high}, got {batch}")
    if batch > 1:
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval != interval:
            raise SmokeFailure(f"CONSUMER_COMMIT_INTERVAL_SECONDS must be a number, got {interval!r}")
        low_s, high_s = COMMIT_INTERVAL_LIMITS
        if not low_s <= interval <= high_s:
            raise SmokeFailure(f"CONSUMER_COMMIT_INTERVAL_SECONDS must be between {low_s:g} and "
                               f"{high_s:g}, got {interval!r}")
    return batch, (float(interval) if batch > 1 else 1.0)


def start_host_services() -> None:
    batch, commit_interval = check_commit_batching()      # before anything is started
    # The broker is published on 127.0.0.1 only.  "localhost" may resolve to
    # ::1 first, and a Kafka client that tries it waits and can fail a commit.
    section("stream processor")
    start_host_process("stream-processor", "stream-processor", host_environment(
        KAFKA_BOOTSTRAP_SERVERS=f"127.0.0.1:{KAFKA_PORT}",
        CONSUMER_GROUP_ID=GROUP_STREAM,
        CONSUMER_AUTO_OFFSET_RESET="earliest",
        TOPIC_OTLP_TRACES=TOPIC_RAW,
        TOPIC_SPANS=TOPIC_SPANS,
        TOPIC_DLQ=TOPIC_DLQ,
    ))
    wait_started("stream-processor", (
        f"bootstrap : 127.0.0.1:{KAFKA_PORT}", f"group     : {GROUP_STREAM}",
        f"input     : {TOPIC_RAW}", f"trusted   : {TOPIC_SPANS}", f"dlq       : {TOPIC_DLQ}",
    ))
    say("alive; configuration points to the isolated broker")

    section("storage consumer")
    storage_environment = host_environment(
        KAFKA_BOOTSTRAP_SERVERS=f"127.0.0.1:{KAFKA_PORT}",
        CONSUMER_GROUP_ID=GROUP_STORAGE,
        CONSUMER_AUTO_OFFSET_RESET="earliest",
        TOPIC_SPANS=TOPIC_SPANS,
        PG_HOST="127.0.0.1",
        PG_PORT=str(POSTGRES_PORT),
        PG_DATABASE="agentops",
        PG_USER="agentops",
        PG_PASSWORD=RUN.generated["POSTGRES_PASSWORD"],
    )
    if CONSUMER_TIMING_INTERVAL > 0:  # diagnostic cells only; this process only
        storage_environment["CONSUMER_TIMING_INTERVAL_SECONDS"] = f"{CONSUMER_TIMING_INTERVAL:g}"
        say(f"consumer timing summaries every {CONSUMER_TIMING_INTERVAL:g} s (diagnostic)")
    banner = [
        f"bootstrap  : 127.0.0.1:{KAFKA_PORT}", f"group      : {GROUP_STORAGE}",
        f"topic      : {TOPIC_SPANS}", f"pg host    : 127.0.0.1:{POSTGRES_PORT}",
        "pg database: agentops",
    ]
    forbidden: tuple[str, ...] = ("commit     :",)    # N=1 prints no commit line at all
    if batch > 1:  # opt-in; exactly these two variables, only for the storage consumer
        storage_environment["CONSUMER_COMMIT_BATCH_MESSAGES"] = str(batch)
        storage_environment["CONSUMER_COMMIT_INTERVAL_SECONDS"] = f"{commit_interval:g}"
        say(f"offset commits batched: {batch} messages, {commit_interval:g} s (opt-in)")
        banner.append(f"commit     : batches of up to {batch} messages, about every "
                      f"{commit_interval:g} s")
        forbidden = ()
    start_host_process("storage-consumer", "storage-consumer", storage_environment)
    wait_started("storage-consumer", tuple(banner), forbidden=forbidden)
    say("alive; configuration points to the isolated broker and database")

    section("consumer groups")
    for group, topic in ((GROUP_STREAM, TOPIC_RAW), (GROUP_STORAGE, TOPIC_SPANS)):
        wait_for(f"group {group} to be assigned all partitions", T_HOST_SERVICE,
                 lambda: group_assigned(group, topic), interval=3.0)
        say(f"{group}: assigned {PARTITIONS} partitions of {topic}")
    check_host_processes()


def stop_host_processes() -> list[str]:
    """Stop only the processes this run started.  Returns what went wrong."""
    problems = []
    for name, process in RUN.processes.items():
        if process.poll() is None:
            if os.name == "nt":
                # The interpreter of a virtual environment is a child of its
                # launcher; both belong to this run.
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, timeout=30)
            else:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    problems.append(f"{name} (pid {process.pid}) did not stop")
                    continue
        say(f"{name}: stopped (pid {process.pid})")
    return problems


# ---------------------------------------------------------------------------
# Offsets, database, reconciliation
# ---------------------------------------------------------------------------

def end_offsets() -> dict[str, int]:
    """Sum of the end offsets of every partition, per topic."""
    totals = {}
    for topic in TOPICS:
        result = kafka_tool("kafka-get-offsets.sh", "--topic", topic)
        if result.returncode != 0:
            raise SmokeFailure(f"kafka-get-offsets {topic} failed:\n" + result.stderr[-600:])
        parts = [line.rsplit(":", 2) for line in result.stdout.split() if line.count(":") >= 2]
        if len(parts) != PARTITIONS or any(name != topic for name, _, _ in parts):
            raise SmokeFailure(f"unexpected offsets for {topic}: {result.stdout.strip()!r}")
        totals[topic] = sum(int(offset) for _, _, offset in parts)
    return totals


def stored_rows() -> int:
    return int(psql("SELECT count(*) FROM telemetry_spans"))


_RUN_SQL = """
WITH roots AS (
    SELECT * FROM telemetry_spans
    WHERE parent_span_id IS NULL
      AND attributes->>'agentops.workload.run_id' = '{run_id}'
), spans AS (
    SELECT * FROM telemetry_spans WHERE trace_id IN (SELECT trace_id FROM roots)
), sizes AS (
    SELECT trace_id, count(*) AS n FROM spans GROUP BY trace_id
)
SELECT json_build_object(
  'roots', (SELECT count(*) FROM roots),
  'root_traces', (SELECT count(DISTINCT trace_id) FROM roots),
  'request_ids', (SELECT coalesce(json_agg(rid ORDER BY rid), '[]') FROM (
      SELECT coalesce(request_id, attributes->>'agentops.request_id') AS rid FROM roots) t),
  'spans', (SELECT count(*) FROM spans),
  'trace_sizes', (SELECT coalesce(json_object_agg(n::text, c), '{{}}') FROM (
      SELECT n, count(*) AS c FROM sizes GROUP BY n) t),
  'status', (SELECT coalesce(json_object_agg(status_code, c), '{{}}') FROM (
      SELECT status_code, count(*) AS c FROM spans GROUP BY status_code) t),
  'error_spans', (SELECT coalesce(json_object_agg(span_name, c), '{{}}') FROM (
      SELECT span_name, count(*) AS c FROM spans WHERE status_code = 'ERROR'
      GROUP BY span_name) t),
  'error_roots', (SELECT count(*) FROM roots WHERE status_code = 'ERROR'),
  'error_types', (SELECT coalesce(json_object_agg(error_type, c), '{{}}') FROM (
      SELECT error_type, count(*) AS c FROM spans WHERE error_type IS NOT NULL
      GROUP BY error_type) t),
  'error_type_spans', (SELECT coalesce(json_object_agg(span_name, c), '{{}}') FROM (
      SELECT span_name, count(*) AS c FROM spans WHERE error_type IS NOT NULL
      GROUP BY span_name) t),
  'root_names', (SELECT coalesce(json_agg(DISTINCT span_name), '[]') FROM roots),
  'modes', (SELECT coalesce(json_agg(DISTINCT attributes->>'agentops.workload.mode'), '[]')
            FROM roots),
  'root_scenarios', (SELECT coalesce(json_object_agg(
      coalesce(request_id, attributes->>'agentops.request_id'),
      attributes->>'agentops.workload.scenario'), '{{}}') FROM roots),
  'error_root_request_ids', (SELECT coalesce(json_agg(
      coalesce(request_id, attributes->>'agentops.request_id')), '[]')
      FROM roots WHERE status_code = 'ERROR'),
  'roots_without_persona', (SELECT count(*) FROM roots
      WHERE coalesce(attributes->>'agentops.workload.persona', '') = ''),
  'services', (SELECT coalesce(json_agg(DISTINCT service_name), '[]') FROM spans),
  'kafka_topics', (SELECT coalesce(json_agg(DISTINCT kafka_topic), '[]') FROM spans)
)
"""

_GLOBAL_SQL = """
SELECT json_build_object(
  'rows', (SELECT count(*) FROM telemetry_spans),
  'run_ids', (SELECT coalesce(json_agg(DISTINCT attributes->>'agentops.workload.run_id'), '[]')
              FROM telemetry_spans WHERE attributes ? 'agentops.workload.run_id'),
  'rows_outside_workload_traces', (SELECT count(*) FROM telemetry_spans WHERE trace_id NOT IN (
      SELECT trace_id FROM telemetry_spans
      WHERE parent_span_id IS NULL AND attributes ? 'agentops.workload.run_id'))
)
"""


class Checks:
    """Exact comparisons.  Every one is printed; one mismatch fails the stage."""

    def __init__(self) -> None:
        self.failed: list[str] = []

    def equal(self, name: str, found: Any, expected: Any) -> None:
        ok = found == expected
        say(f"  {'ok      ' if ok else 'MISMATCH'} {name}: {found}"
            + ("" if ok else f"   (expected {expected})"))
        if not ok:
            self.failed.append(name)

    def true(self, name: str, condition: bool, found: Any) -> None:
        say(f"  {'ok      ' if condition else 'MISMATCH'} {name}: {found}")
        if not condition:
            self.failed.append(name)

    def finish(self, what: str) -> None:
        if self.failed:
            raise SmokeFailure(f"{what}: mismatch in " + ", ".join(self.failed))


def _tally(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def planned_facts(stage: Stage) -> dict[str, Any]:
    """What the generator's own planner says about the stage.  Computed by the
    generator's code in the fresh environment; nothing is planned here."""
    assert RUN.python is not None
    code = (
        "import json\n"
        "from workload_generator.faults import attempts\n"
        "from workload_generator.plan import PlanConfig, build_plan\n"
        "from workload_generator.report import plan_digest\n"
        "from workload_generator.scenarios import Scenario\n"
        f"plan = build_plan(PlanConfig(seed={SEED}, run_id={stage.run_id!r},"
        f" scenario=Scenario({stage.scenario!r}), traces={stage.traces},"
        f" rate={float(RATE)!r}, persona=None, mode='real'))\n"
        "tries = [a for r in plan.requests for a in attempts(r)]\n"
        "print(json.dumps({'digest': plan_digest(plan),"
        " 'request_ids': sorted(a.request_id for a in tries),"
        " 'scenario_by_request': {a.request_id: r.scenario.value"
        " for r in plan.requests for a in attempts(r)},"
        " 'failing_request_ids': sorted(a.request_id for a in tries"
        " if a.effects.fault is not None),"
        " 'failing_indexes': [r.request_index for r in plan.requests if r.fault is not None],"
        " 'failing_attempts': sum(a.effects.fault is not None for a in tries)}))\n"
    )
    return json.loads(checked(
        [str(RUN.python), "-c", code], cwd=REPO / "workload-generator",
        timeout=T_COMMAND, what="planned facts", env=host_environment(),
    ))


def run_stage(stage: Stage, baseline: dict[str, int]) -> dict[str, int]:
    """Send one workload and reconcile it exactly.  Returns the end offsets
    afterwards, the baseline of the next stage."""
    assert RUN.temp is not None and RUN.python is not None
    label = f"stage {stage.run_id}"
    spans_before = stored_rows()

    section(f"{label}: plan")
    if int(psql(
        "SELECT count(*) FROM telemetry_spans WHERE attributes->>'agentops.workload.run_id' "
        f"= '{stage.run_id}'"
    )) != 0:
        raise SmokeFailure(f"{label}: the run id is already in the database")
    planned = planned_facts(stage)
    checks = Checks()
    checks.equal("planned submissions", len(planned["request_ids"]), stage.traces)
    checks.equal("distinct request ids", len(set(planned["request_ids"])), stage.traces)
    checks.equal("failing request indexes", tuple(planned["failing_indexes"]),
                 stage.failing_indexes)
    checks.equal("failing attempts", planned["failing_attempts"], stage.failures)
    checks.equal("planned scenario per request -> requests",
                 _tally(planned["scenario_by_request"].values()), dict(stage.scenario_roots))
    checks.true("plan digest", planned["digest"].startswith(stage.digest_prefix),
                planned["digest"][:16] + "...")
    checks.finish(f"{label} plan")

    section(f"{label}: driver")
    check_host_processes()
    report_path = RUN.temp / f"{stage.run_id}.json"
    command = [
        str(RUN.python), "-m", "workload_generator",
        "--mode", "real", "--scenario", stage.scenario, "--traces", str(stage.traces),
        "--rate", str(RATE), "--seed", str(SEED), "--concurrency", str(CONCURRENCY),
        "--run-id", stage.run_id, "--max-duration", str(stage.max_duration),
        "--send", "--endpoint", f"http://localhost:{OTLP_PORT}",
        "--report", str(report_path),
    ]
    say("python -m workload_generator " + " ".join(command[3:-1]) + " <temp report>")
    result = run(command, cwd=REPO / "workload-generator", env=host_environment(),
                 timeout=stage.max_duration + 120, what=label)
    output = result.stdout + result.stderr
    write_log(f"{stage.run_id}.log", output)
    wrong = _WRONG_STACK.search(output)
    if wrong:
        raise SmokeFailure(f"{label}: the generator mentions port {wrong.group(1)}")
    if result.returncode != 0 or not report_path.is_file():
        raise SmokeFailure(f"{label}: generator exit {result.returncode}\n{output[-1500:]}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    execution = report["execution"]
    attempts = {name: count for name, count in execution["attempts"].items() if count}
    expected_attempts = {"expected_success": stage.successes}
    if stage.failures:
        expected_attempts["expected_failure"] = stage.failures
    checks = Checks()
    checks.equal("exit code", result.returncode, 0)
    checks.equal("run id", report["run_id"], stage.run_id)
    checks.equal("plan digest equals the planned one", report["plan_digest"], planned["digest"])
    checks.equal("planned requests", report["planned_requests"], stage.traces)
    checks.equal("planned retries", report["planned_retries"], 0)
    checks.equal("planned submissions", report["planned_submissions"], stage.traces)
    checks.equal("endpoint", execution["endpoint"], f"http://localhost:{OTLP_PORT}")
    checks.equal("started requests", execution["started_requests"], stage.traces)
    checks.equal("not started requests", execution["not_started_requests"], 0)
    checks.equal("executed attempts", execution["executed_attempts"], stage.traces)
    checks.equal("executed retries", execution["executed_retries"], 0)
    checks.equal("attempt outcomes (non-zero)", attempts, expected_attempts)
    checks.equal("integrity problems", execution["problems"], [])
    checks.equal("spans ended", execution["spans_ended"], stage.spans)
    checks.equal("spans exported successfully", execution["spans_exported_successfully"],
                 stage.spans)
    checks.equal("export failures", execution["export_failures"], 0)
    checks.equal("flush ok", execution["flush_ok"], True)
    checks.equal("run status", execution["run_status"], "completed")
    say(f"  elapsed {execution['elapsed_seconds']:.1f}s; late starts {execution['late_starts']}")
    checks.finish(f"{label} driver")

    section(f"{label}: drain")

    def drained() -> Optional[tuple[dict[str, int], int, int]]:
        check_host_processes()
        offsets = end_offsets()
        stream, storage = group_lag(GROUP_STREAM, TOPIC_RAW), group_lag(GROUP_STORAGE, TOPIC_SPANS)
        rows = stored_rows() - spans_before
        drained.detail = (  # type: ignore[attr-defined]
            f"canonical delta {offsets[TOPIC_SPANS] - baseline[TOPIC_SPANS]}, rows {rows}, "
            f"stream lag {stream}, storage lag {storage}"
        )
        done = (offsets[TOPIC_SPANS] - baseline[TOPIC_SPANS] >= stage.spans
                and rows >= stage.spans and stream == 0 and storage == 0)
        return (offsets, stream, storage) if done else None

    started = time.monotonic()
    try:
        wait_for(f"{label} to drain", T_DRAIN, drained)
        say(f"drained after {time.monotonic() - started:.0f}s; "
            f"settling {SETTLE_SECONDS:.0f}s to catch late or duplicate records")
    except SmokeFailure as failure:
        # The exact counts below are the evidence of what did not arrive.
        say(str(failure))
    time.sleep(SETTLE_SECONDS)
    check_host_processes()
    offsets = end_offsets()
    stream_lag, storage_lag = group_lag(GROUP_STREAM, TOPIC_RAW), group_lag(GROUP_STORAGE, TOPIC_SPANS)
    (RUN.temp / f"offsets-after-{stage.run_id}.json").write_text(json.dumps(offsets), encoding="utf-8")

    section(f"{label}: Kafka reconciliation")
    checks = Checks()
    checks.equal(f"{GROUP_STREAM} lag", stream_lag, 0)
    checks.equal(f"{GROUP_STORAGE} lag", storage_lag, 0)
    checks.equal("canonical topic delta", offsets[TOPIC_SPANS] - baseline[TOPIC_SPANS], stage.spans)
    checks.equal("DLQ delta", offsets[TOPIC_DLQ] - baseline[TOPIC_DLQ], 0)
    checks.equal("DLQ end offset", offsets[TOPIC_DLQ], 0)
    raw_delta = offsets[TOPIC_RAW] - baseline[TOPIC_RAW]
    checks.true("raw OTLP topic delta > 0 (not compared with spans)", raw_delta > 0, raw_delta)

    section(f"{label}: database reconciliation")
    found = json.loads(psql(_RUN_SQL.format(run_id=stage.run_id)))
    # Ordered here: the database sorts text by its own collation.
    found["request_ids"] = sorted(rid or "" for rid in found["request_ids"])
    checks.equal("root spans", found["roots"], stage.traces)
    checks.equal("distinct root trace ids", found["root_traces"], stage.traces)
    checks.equal("request-id set equals the planned set", found["request_ids"],
                 planned["request_ids"])
    say(f"           request ids sha256 {short_hash(found['request_ids'])} "
        f"(planned {short_hash(planned['request_ids'])})")
    checks.equal("total spans", found["spans"], stage.spans)
    checks.equal("spans per trace -> traces", found["trace_sizes"], dict(stage.trace_sizes))
    checks.equal("status codes", found["status"], dict(stage.status))
    checks.equal("ERROR spans by name", found["error_spans"], dict(stage.error_spans))
    checks.equal("ERROR root spans", found["error_roots"], stage.failures)
    checks.equal("error_type values", found["error_types"], dict(stage.error_types))
    checks.equal("spans carrying error_type", found["error_type_spans"],
                 {TOOL_SPAN: stage.failures} if stage.failures else {})
    checks.equal("root span name", found["root_names"], [ROOT_SPAN])
    checks.equal("agentops.workload.mode", found["modes"], ["real"])
    checks.equal("agentops.workload.scenario per root -> roots",
                 _tally(found["root_scenarios"].values()), dict(stage.scenario_roots))
    checks.equal("every root carries the scenario planned for its request",
                 found["root_scenarios"] == planned["scenario_by_request"], True)
    checks.equal("ERROR roots are exactly the planned failing requests",
                 sorted(found["error_root_request_ids"]), planned["failing_request_ids"])
    checks.equal("roots of the run's scenario are exactly the planned ones",
                 sorted(r for r, s in found["root_scenarios"].items() if s != "normal"),
                 sorted(r for r, s in planned["scenario_by_request"].items() if s != "normal"))
    checks.equal("roots without agentops.workload.persona", found["roots_without_persona"], 0)
    checks.equal("service_name", found["services"], [SERVICE_NAME])
    checks.equal("kafka_topic", found["kafka_topics"], [TOPIC_SPANS])
    checks.equal("rows added to telemetry_spans", stored_rows() - spans_before, stage.spans)

    section(f"{label}: exporter to storage")
    say(f"  driver spans ended {execution['spans_ended']} = exporter reported success for "
        f"{execution['spans_exported_successfully']} = canonical topic records "
        f"{offsets[TOPIC_SPANS] - baseline[TOPIC_SPANS]} = rows stored {found['spans']}")
    check_host_processes()
    checks.finish(label)
    say(f"{label}: PASS")
    return offsets


def check_baseline() -> dict[str, int]:
    section("baseline")
    check_host_processes()
    offsets = end_offsets()
    rows = stored_rows()
    checks = Checks()
    checks.equal("telemetry_spans rows", rows, 0)
    checks.equal("canonical topic end offsets", offsets[TOPIC_SPANS], 0)
    checks.equal("DLQ end offsets", offsets[TOPIC_DLQ], 0)
    checks.equal("raw OTLP topic end offsets", offsets[TOPIC_RAW], 0)
    checks.equal("topics", topic_partitions(), {name: PARTITIONS for name in TOPICS})
    status, health, _ = container_state("postgres")
    checks.equal("isolated postgres", f"{status} {health}", "running healthy")
    checks.equal("isolated collector", container_state("otel-collector")[0], "running")
    checks.equal("isolated broker", container_state("kafka")[0], "running")
    checks.finish("baseline")
    check_normal_stack("before any telemetry")
    return offsets


def check_totals(offsets: dict[str, int]) -> None:
    section("isolated database total")
    found = json.loads(psql(_GLOBAL_SQL))
    checks = Checks()
    checks.equal("rows in telemetry_spans", found["rows"], sum(stage.spans for stage in STAGES))
    checks.equal("workload run ids", sorted(found["run_ids"]),
                 sorted(stage.run_id for stage in STAGES))
    checks.equal("rows outside the workload's traces", found["rows_outside_workload_traces"], 0)
    checks.equal("canonical topic records in all", offsets[TOPIC_SPANS],
                 sum(stage.spans for stage in STAGES))
    checks.equal("DLQ records in all", offsets[TOPIC_DLQ], 0)
    say(f"  raw OTLP topic records in all: {offsets[TOPIC_RAW]}")
    checks.finish("totals")


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# Recursive deletion is allowed for one thing only: a directory this run created with mkdtemp() and
# registered below.  The record (exact path, device and inode) is kept here and not in RUN, so changing
# RUN.temp cannot authorize a deletion.  Anything that cannot be verified is refused, and a refusal makes
# _remove_tree return False, which every caller already reports as an incomplete cleanup.
_OWNED: dict[str, tuple[int, int]] = {}
_PROTECTED_TREES = (r"C:\AgentOps-Development", r"C:\AgentOps-Recovery")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# The filesystem calls the guard makes, as module names so tests can replace them without patching os/shutil.
_lstat = os.lstat
_realpath = os.path.realpath
_lexists = os.path.lexists
_rmtree = shutil.rmtree
_pause = time.sleep


def _windows() -> bool:
    return os.name == "nt"


def _norm(path: Any) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _within(child: str, parent: str) -> bool:
    """True when child is parent or lies below it (both already normalized)."""
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:  # different drives
        return False


def _is_link(info: Any) -> bool:
    """A symlink, a junction or any other Windows reparse point."""
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def register_workspace(path: Path) -> None:
    """Record the directory mkdtemp() just returned.  Only a registered directory can be deleted recursively."""
    info = _lstat(path)
    if _is_link(info) or not stat.S_ISDIR(info.st_mode) or not info.st_ino:
        raise SmokeFailure("the temporary directory has no verifiable identity")
    _OWNED[_norm(path)] = (info.st_dev, info.st_ino)


def _discard_unused_workspace(path: Path) -> None:
    """Undo a create_workspace() that failed before anything was written.  rmdir removes only an empty directory."""
    try:
        os.rmdir(path)
    except OSError:
        pass
    _OWNED.pop(_norm(path), None)


def _deletion_refusal(path: Path) -> Optional[str]:
    """Why path must not be deleted recursively, or None.  Anything that cannot be verified is refused."""
    try:
        key = _norm(path)
        if os.path.dirname(key) == key:
            return "a filesystem root"
        for tree in (_norm(REPO), *map(_norm, _PROTECTED_TREES)):
            if _within(key, tree) or _within(tree, key):
                return f"a protected location or one of its ancestors ({tree})"
        shared = [Path.home(), tempfile.gettempdir(), os.environ.get("SystemDrive", "C:") + "\\"]
        shared += [v for v in (os.environ.get(n) for n in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")) if v]
        for other in map(_norm, shared):
            if _within(other, key):
                return f"a shared location or one of its ancestors ({other})"
        identity = _OWNED.get(key)
        if identity is None:
            return "not a workspace created by this run"
        info = _lstat(key)
        if _is_link(info):
            return "a symlink, junction or other reparse point"
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            return "not the directory that was created (filesystem identity differs)"
        if os.path.normcase(_realpath(key)) != key:
            return "reached through a redirected path"
    except Exception as exc:  # fail closed
        return f"ownership could not be verified ({type(exc).__name__}: {exc})"
    return None


def _remove_tree(path: Path) -> bool:
    """Delete a workspace this run created.  Returns False, deleting nothing, for anything else.

    On Windows nothing is deleted recursively, whatever is registered: a path check cannot exclude a junction or
    directory swapped in between the check and the delete.  The refusal returns False before anything is touched
    (no delete, no existence check, no change to the ownership record), so cleanup() reports the workspace as
    left behind and it is removed by hand after looking at it.

    Elsewhere the ownership check runs before every attempt.  It is by path: a directory swapped between the last
    check and the delete is not detected, so this narrows that window and does not close it.
    """
    if _windows():
        say(f"refusing to delete {path}: automatic recursive deletion is disabled on Windows; "
            "check the directory and remove it by hand")
        return False

    def retry(function: Callable[..., Any], target: str, _exc: Any) -> None:
        if _is_link(_lstat(target)):  # chmod would follow the link and change what it points to
            raise PermissionError(f"refusing to change the permissions of {target}: a link")
        os.chmod(target, stat.S_IWRITE)
        function(target)

    key = _norm(path)
    for _ in range(5):
        if key in _OWNED and not _lexists(path):
            _OWNED.pop(key, None)  # registered and already gone: nothing is left to delete
            return True
        refusal = _deletion_refusal(path)
        if refusal is not None:
            say(f"refusing to delete {path}: {refusal}")
            return False
        try:
            if sys.version_info >= (3, 12):
                _rmtree(path, onexc=retry)
            else:
                _rmtree(path, onerror=retry)
        except OSError:
            _pause(2.0)
        if not _lexists(path):
            _OWNED.pop(key, None)
            return True
    return False


def cleanup() -> bool:
    """Give everything back.  Returns True when all of it was verified."""
    section("cleanup")
    problems = stop_host_processes()

    leaked = 0
    if RUN.temp is not None and RUN.temp.exists():
        for path in RUN.temp.glob("*"):
            if path.is_file() and path.name != "smoke.env":
                text = path.read_text(encoding="utf-8", errors="replace")
                leaked += sum(text.count(value) for value in RUN.generated.values())
        say(f"generated passwords found in logs, reports and snapshots: {leaked} "
            f"(masked before writing: {RUN.masked_in_logs})")
        if leaked or RUN.masked_in_logs:
            problems.append("a generated password reached a temporary log")

    if RUN.compose_used and RUN.env_file is not None and RUN.env_file.is_file():
        down = run(
            compose_command("down", "--volumes", "--rmi", "local", "--remove-orphans"),
            timeout=T_DOWN, what="compose down",
        )
        say(f"compose down --volumes --rmi local --remove-orphans: exit {down.returncode}")
        if down.returncode != 0:
            problems.append("compose down failed: " + redact_tail(down.stderr, 400))
    else:
        say("compose down: not needed, no Compose command had run")

    label = f"label=com.docker.compose.project={PROJECT}"
    for kind, command in (
        ("containers", ["ps", "-a", "-q", "--filter", label]),
        ("networks", ["network", "ls", "-q", "--filter", label]),
        ("volumes", ["volume", "ls", "-q", "--filter", label]),
        ("images", ["images", "-q", "--filter", label]),
    ):
        left = docker_lines(*command)
        say(f"smoke {kind} left: {len(left)}")
        if left:
            problems.append(f"{len(left)} smoke {kind} left")

    after = docker_fingerprint()
    if RUN.before is not None:
        known = {line.rsplit(" ", 1)[1] for line in RUN.before["images"]}
        for line in after["images"]:
            name, image_id = line.rsplit(" ", 1)
            if image_id not in known:
                # Absent before this run, so this run brought it; removed by
                # its exact id, never forced.
                removed = run(["docker", "image", "rm", image_id], timeout=T_COMMAND,
                              what="docker image rm")
                say(f"image new in this run: {name} {image_id[:19]} -> "
                    f"{'removed' if removed.returncode == 0 else 'NOT removed'}")
        for name in after["volumes"]:
            if name not in RUN.before["volumes"]:
                # Absent before this run and left behind by its containers.
                removed = run(["docker", "volume", "rm", name], timeout=T_COMMAND,
                              what="docker volume rm")
                say(f"volume new in this run: {name[:19]} -> "
                    f"{'removed' if removed.returncode == 0 else 'NOT removed'}")
        after = docker_fingerprint()

    if RUN.temp is not None:
        gone = _remove_tree(RUN.temp)
        say(f"temporary directory deleted: {'yes' if gone else 'NO'}")
        if not gone:
            problems.append("the temporary directory could not be deleted")

    section("normal Docker state after")
    if RUN.before is None:
        say("no state was recorded before; nothing to compare")
    else:
        for kind, lines in after.items():
            same = lines == RUN.before[kind]
            say(f"{kind}: {len(lines)} (fingerprint {short_hash(lines)}) "
                f"{'identical' if same else 'DIFFERENT'}")
            if not same:
                problems.append(f"Docker {kind} differ from before")
                for line in sorted(set(lines) ^ set(RUN.before[kind])):
                    say(f"  {'+' if line in lines else '-'} {line}")
        now = normal_postgres()
        say(f"{NORMAL_POSTGRES_CONTAINER}: {now or 'not present on this machine'}")
        if now != RUN.normal_postgres:
            problems.append(f"{NORMAL_POSTGRES_CONTAINER} changed")

    section("repository after")
    try:
        state = repository_state()
        for line in state:
            say(line)
        if any(line not in ALLOWED_UNTRACKED for line in state):
            problems.append("the repository holds unexpected changes")
        caches = sorted(bytecode_caches() - RUN.caches_before)
        say(f"__pycache__ directories written during the run: {len(caches)}")
        if caches:
            problems.append("bytecode caches were written to the repository")
    except SmokeFailure as failure:
        problems.append(str(failure))

    for problem in problems:
        say(f"CLEANUP PROBLEM: {problem}")
    return not problems


# ---------------------------------------------------------------------------
# PR-03C2: approved working tree, resource preflight, secured workspace and project-contained cleanup
#
# Everything below is NEW and used by run_e2e.py only.  cleanup(), _remove_tree() and every other function
# above are unchanged, so the benchmark runner and the sibling harnesses behave exactly as before.
# ---------------------------------------------------------------------------

FULL_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")
_SHA256_LOWER_RE = re.compile(r"[0-9a-f]{64}")


class _ContainedState:
    """What the contained path remembers between its steps.  reset() makes a run start from nothing."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.approved: Optional["ApprovedTree"] = None
        self.tracked_containers: set[str] = set()
        self.tracked_networks: set[str] = set()
        self.tracked_volumes: set[str] = set()
        self.tracked_images: set[str] = set()
        #: anonymous volume name -> {container_id, container, destination}: recorded from the mount metadata of
        #: containers already verified as the project's, while those containers still exist.  Never removed
        #: directly; verified absent after cleanup.
        self.tracked_anonymous: dict[str, dict[str, str]] = {}
        #: containers whose mount metadata had an unexpected shape (their anonymous volumes are unaccounted for)
        self.uncertain_mounts: set[str] = set()
        #: the step during which cleanup was interrupted, or None
        self.interrupted: Optional[str] = None
        self.protected_before: Optional[dict[str, str]] = None
        #: the approved Docker engine of this run (an EnginePin), set once it has been verified; None for a
        #: harness that does not pin one.  Cleared with everything else by reset().
        self.engine_pin: Optional["EnginePin"] = None


CONTAINED = _ContainedState()


# -- approved working-tree manifest ----------------------------------------------------------------------------

APPROVED_TREE_SCHEMA: str = "agentops.approved-tree/1"
APPROVED_TREE_BRANCH: str = "claude/compassionate-noether-7peel4"
APPROVED_TREE_MAX_BYTES: int = 1024 * 1024
#: The only working-tree statuses a manifest may approve: untracked, modified, deleted.  The index must be
#: empty, so every staged, renamed, copied, conflicted or type-changed entry is refused.
APPROVED_STATUSES: frozenset[str] = frozenset({"??", " M", " D"})


@dataclass(frozen=True)
class ApprovedTree:
    branch: str
    head: str
    #: path -> (porcelain status, SHA-256 of the file; None for a deleted file)
    entries: Mapping[str, tuple[str, Optional[str]]]
    #: SHA-256 of the manifest file itself
    digest: str


def _manifest_path_problem(path: Any) -> Optional[str]:
    """Why a repository-relative path is not acceptable in a manifest or a status listing, or None."""
    if not isinstance(path, str) or not path:
        return "a path is empty or not text"
    if "\x00" in path or "�" in path or "\\" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return f"path {path!r} holds a control character, a backslash or a replacement character"
    if unicodedata.normalize("NFC", path) != path:
        return f"path {path!r} is not in NFC form (ambiguous encoding)"
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path) or path.endswith("/"):
        return f"path {path!r} is absolute, names a drive or ends with a separator"
    if posixpath.normpath(path) != path or ".." in path.split("/") or path.split("/")[0].lower() == ".git":
        return f"path {path!r} is not a plain repository-relative path"
    return None


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"constant {name} is not allowed")


def parse_approved_tree(document: Any, digest: str) -> ApprovedTree:
    """A validated manifest, or SmokeFailure.  The keys are exactly the documented ones; nothing is guessed."""
    if not isinstance(document, dict) or set(document) != {"schema", "branch", "head", "index_empty", "entries"}:
        raise SmokeFailure("the approved-tree manifest does not have exactly the documented keys")
    if document["schema"] != APPROVED_TREE_SCHEMA:
        raise SmokeFailure("the approved-tree manifest has an unsupported schema")
    if document["index_empty"] is not True:
        raise SmokeFailure("the approved-tree manifest must state that the index is empty")
    branch, head, entries = document["branch"], document["head"], document["entries"]
    if not isinstance(branch, str) or not branch:
        raise SmokeFailure("the approved-tree manifest has no branch")
    if not isinstance(head, str) or not FULL_COMMIT_RE.fullmatch(head):
        raise SmokeFailure("the approved-tree manifest head is not a full 40-character commit")
    if not isinstance(entries, list):
        raise SmokeFailure("the approved-tree manifest entries are not a list")
    parsed: dict[str, tuple[str, Optional[str]]] = {}
    folded: set[str] = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"path", "status", "sha256", "deleted"}:
            raise SmokeFailure("a manifest entry does not have exactly path, status, sha256 and deleted")
        path, status, sha, deleted = item["path"], item["status"], item["sha256"], item["deleted"]
        problem = _manifest_path_problem(path)
        if problem is not None:
            raise SmokeFailure("a manifest entry is not acceptable: " + problem)
        if not isinstance(status, str) or status not in APPROVED_STATUSES:
            raise SmokeFailure(f"{path}: the status {status!r} is not one of '??', ' M', ' D'")
        if not isinstance(deleted, bool):
            raise SmokeFailure(f"{path}: 'deleted' must be true or false")
        if status == " D":
            if deleted is not True or sha is not None:
                raise SmokeFailure(f"{path}: a deleted file is recorded with deleted=true and sha256=null")
        elif deleted is not False or not isinstance(sha, str) or not _SHA256_LOWER_RE.fullmatch(sha):
            raise SmokeFailure(f"{path}: a present file needs deleted=false and a lowercase SHA-256")
        if path in parsed or path.casefold() in folded:
            raise SmokeFailure(f"{path}: duplicate or case-ambiguous path in the manifest")
        parsed[path] = (status, sha)
        folded.add(path.casefold())
    return ApprovedTree(branch=branch, head=head, entries=parsed, digest=digest)


def load_approved_tree(path: Any, expected_sha256: Any, *, repo: Optional[Path] = None) -> ApprovedTree:
    """Read the manifest file, check its own SHA-256 against the value the operator supplied, then parse it.
    The file must be a regular file outside the repository, not a link, and small."""
    repo = REPO if repo is None else Path(repo)
    if not isinstance(expected_sha256, str) or not SHA256_HEX_RE.fullmatch(expected_sha256):
        raise SmokeFailure("--approved-tree-sha256 must be 64 hexadecimal characters")
    if not isinstance(path, (str, os.PathLike)) or not str(path):
        raise SmokeFailure("--approved-tree needs a file path")
    target = Path(path)
    try:
        info = _lstat(target)
    except OSError:
        raise SmokeFailure("the approved-tree manifest cannot be read") from None
    if _is_link(info) or not stat.S_ISREG(info.st_mode):
        raise SmokeFailure("the approved-tree manifest is not a regular file")
    if _within(_norm(target), _norm(repo)):
        raise SmokeFailure("the approved-tree manifest must be outside the repository")
    if info.st_size > APPROVED_TREE_MAX_BYTES:
        raise SmokeFailure("the approved-tree manifest is too large")
    try:
        data = target.read_bytes()
    except OSError:
        raise SmokeFailure("the approved-tree manifest cannot be read") from None
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256.lower():
        raise SmokeFailure("the approved-tree manifest's SHA-256 is not the supplied value")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                              parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SmokeFailure("the approved-tree manifest is not valid JSON") from None
    return parse_approved_tree(document, digest)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_working_tree(repo: Optional[Path] = None) -> tuple[dict[str, tuple[str, Optional[str]]], list[str]]:
    """The dirty paths of the working tree as (status, SHA-256) and the problems met while reading them.
    Read-only.  Uses NUL-separated porcelain output so that no path is quoted or re-encoded."""
    repo = REPO if repo is None else Path(repo)
    raw = git("status", "--porcelain", "-z", "--untracked-files=all")
    current: dict[str, tuple[str, Optional[str]]] = {}
    folded: set[str] = set()
    problems: list[str] = []
    for part in raw.split("\0"):
        if not part:
            continue
        status, separator, path = part[:2], part[2:3], part[3:]
        if separator != " " or not path:
            problems.append(f"an unparsable status entry: {part[:60]!r}")
            continue
        if status not in APPROVED_STATUSES:
            problems.append(f"{path}: status {status!r} is not supported "
                            "(staged, renamed, copied, conflicted or type-changed)")
            continue
        bad = _manifest_path_problem(path)
        if bad is not None:
            problems.append(bad)
            continue
        if path in current or path.casefold() in folded:
            problems.append(f"{path}: duplicate or case-ambiguous path")
            continue
        folded.add(path.casefold())
        target = repo / path
        try:
            info: Any = _lstat(target)
        except FileNotFoundError:
            info = None
        except OSError as exc:
            problems.append(f"{path}: cannot be inspected ({type(exc).__name__})")
            continue
        if status == " D":
            if info is not None:
                problems.append(f"{path}: listed as deleted but it exists")
                continue
            current[path] = (status, None)
            continue
        if info is None:
            problems.append(f"{path}: listed but missing")
            continue
        if _is_link(info):
            problems.append(f"{path}: is a symbolic link or reparse point")
            continue
        if not stat.S_ISREG(info.st_mode):
            problems.append(f"{path}: is not a regular file")
            continue
        try:
            current[path] = (status, _file_sha256(target))
        except OSError:
            problems.append(f"{path}: cannot be read")
    return current, problems


def _some(names: Sequence[str], limit: int = 8) -> str:
    shown = ", ".join(names[:limit])
    return shown + (f" (and {len(names) - limit} more)" if len(names) > limit else "")


def approved_tree_problems(
    approved: ApprovedTree, current: Mapping[str, tuple[str, Optional[str]]],
    read_problems: Sequence[str] = (),
) -> list[str]:
    """Every difference between the approved manifest and the tree as it is.  Pure."""
    problems = list(read_problems)
    extra = sorted(set(current) - set(approved.entries))
    missing = sorted(set(approved.entries) - set(current))
    if extra:
        problems.append("not in the approved manifest (unexpected): " + _some(extra))
    if missing:
        problems.append("approved but not present in the tree: " + _some(missing))
    for path in sorted(set(current) & set(approved.entries)):
        want_status, want_sha = approved.entries[path]
        status, sha = current[path]
        if status != want_status:
            problems.append(f"{path}: status {status!r}, approved {want_status!r}")
        elif sha != want_sha:
            problems.append(f"{path}: content differs from the approved manifest")
    return problems


def verify_approved_tree(expect_head: Optional[str], approved: ApprovedTree) -> None:
    """Branch, HEAD, empty index and the exact working tree, or SmokeFailure.  Read-only; any Git or
    filesystem error is a failure."""
    if not isinstance(expect_head, str) or not FULL_COMMIT_RE.fullmatch(expect_head):
        raise SmokeFailure("--expect-head must be a full 40-character commit")
    branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
    head = git("rev-parse", "HEAD").strip()
    if branch != APPROVED_TREE_BRANCH or branch != approved.branch:
        raise SmokeFailure(f"the branch is {branch!r}, which is not the approved {APPROVED_TREE_BRANCH!r}")
    if head != expect_head or head != approved.head:
        raise SmokeFailure("HEAD is not the expected commit named by --expect-head and the manifest")
    if git("diff", "--cached", "--name-only").strip():
        raise SmokeFailure("the index is not empty")
    current, read_problems = read_working_tree()
    problems = approved_tree_problems(approved, current, read_problems)
    if problems:
        raise SmokeFailure("the working tree is not the approved one:\n" + "\n".join(problems[:20]))


def recheck_approved_tree() -> list[str]:
    """After the run: the same manifest, the same comparison.  [] when no manifest was used."""
    approved = CONTAINED.approved
    if approved is None:
        return []
    try:
        verify_approved_tree(approved.head, approved)
    except SmokeFailure as failure:
        return [f"the repository no longer matches the approved manifest: {failure}"]
    return []


# -- resource preflight ----------------------------------------------------------------------------------------

GATE_MIN_AVAILABLE_MIB: int = 4096
GATE_MIN_FREE_DISK_GIB: int = 20
GATE_MAX_COMMITTED_PERCENT: float = 70.0
GATE_MAX_PAGING_FILE_PERCENT: float = 5.0
GATE_MIN_ENGINE_BYTES: int = 3584 * 1024 ** 2
#: With an approved engine pinned, the Docker VM's AVAILABLE memory (not its total, and never swap) must be at
#: least this, and the VM's total must agree with the engine's own report within the tolerance.
GATE_MIN_VM_AVAILABLE_MIB: int = 3584
GATE_VM_TOTAL_TOLERANCE: float = 0.05
GATE_PAGES_SAMPLES: int = 12
GATE_PAGES_WARMUP: int = 2
GATE_PAGES_SPIKE: float = 100.0
GATE_PAGES_SPIKE_LIMIT: int = 2
GATE_PORTS: tuple[int, ...] = (OTLP_PORT, KAFKA_PORT, POSTGRES_PORT)
GATE_DISK_LABELS: tuple[str, ...] = ("temporary storage", "Docker storage")

_COUNTER_PATHS: tuple[str, ...] = (
    r"\Memory\Pages/sec",
    r"\Memory\Available MBytes",
    r"\Memory\% Committed Bytes In Use",
    r"\Paging File(_Total)\% Usage",
)


@dataclass
class GateReadings:
    """What the host and the engine report; None means 'could not be measured', which is an unmet gate."""
    power_source: Optional[str] = None
    wmi_available_mib: Optional[float] = None
    counter_available_mib: Optional[float] = None
    committed_percent: Optional[float] = None
    paging_file_percent: Optional[float] = None
    pages_per_second: Optional[Sequence[float]] = None
    free_disk_bytes: Mapping[str, Optional[float]] = field(default_factory=dict)
    engine_bytes: Optional[int] = None
    ports_in_use: Mapping[int, Optional[bool]] = field(default_factory=dict)
    project_objects: Optional[Sequence[str]] = None


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if math.isnan(value) or math.isinf(value) or value < 0:
        return None
    return float(value)


def pages_per_second_problems(samples: Any) -> list[str]:
    """Twelve samples; the first two are warm-up and are ignored; fail when two or more of the ten that
    follow exceed 100.  Pure.  There is no second chance: the caller samples once."""
    try:
        values = [_number(v) for v in list(samples)]
    except TypeError:
        return ["Pages/sec could not be sampled"]
    if len(values) != GATE_PAGES_SAMPLES:
        return [f"Pages/sec could not be sampled (expected {GATE_PAGES_SAMPLES} samples, got {len(values)})"]
    if any(v is None for v in values):
        return ["Pages/sec had an unreadable sample"]
    measured = [v for v in values[GATE_PAGES_WARMUP:] if v is not None]
    spikes = sum(1 for v in measured if v > GATE_PAGES_SPIKE)
    if spikes >= GATE_PAGES_SPIKE_LIMIT:
        return [f"{spikes} of {len(measured)} measured Pages/sec samples exceed {GATE_PAGES_SPIKE:g} "
                f"(the limit is fewer than {GATE_PAGES_SPIKE_LIMIT})"]
    return []


def resource_gate_problems(readings: GateReadings) -> list[str]:
    """Every unmet gate.  Pure.  An unreadable reading is an unmet gate."""
    problems: list[str] = []
    if readings.power_source is None:
        problems.append("the power source could not be read")
    elif readings.power_source != "AC":
        problems.append(f"the machine is on {readings.power_source}, not AC power")
    for label, value in (("WMI", readings.wmi_available_mib),
                         ("performance counter", readings.counter_available_mib)):
        mib = _number(value)
        if mib is None:
            problems.append(f"available memory could not be read ({label})")
        elif mib < GATE_MIN_AVAILABLE_MIB:
            problems.append(f"available memory {mib:.0f} MiB ({label}) is below {GATE_MIN_AVAILABLE_MIB} MiB")
    committed = _number(readings.committed_percent)
    if committed is None:
        problems.append("committed memory could not be read")
    elif committed >= GATE_MAX_COMMITTED_PERCENT:
        problems.append(f"committed memory {committed:.1f}% is not below {GATE_MAX_COMMITTED_PERCENT:g}%")
    paging = _number(readings.paging_file_percent)
    if paging is None:
        problems.append("paging-file usage could not be read")
    elif paging >= GATE_MAX_PAGING_FILE_PERCENT:
        problems.append(f"paging-file usage {paging:.1f}% is not below {GATE_MAX_PAGING_FILE_PERCENT:g}%")
    problems.extend(pages_per_second_problems(readings.pages_per_second))
    for label in GATE_DISK_LABELS:
        free = _number(readings.free_disk_bytes.get(label))
        if free is None:
            problems.append(f"free disk space could not be read ({label})")
        elif free < GATE_MIN_FREE_DISK_GIB * 1024 ** 3:
            problems.append(f"free disk {free / 1024 ** 3:.1f} GiB ({label}) is below {GATE_MIN_FREE_DISK_GIB} GiB")
    engine = _number(readings.engine_bytes)
    if engine is None:
        problems.append("the Docker engine memory could not be read (is the engine reachable?)")
    elif engine < GATE_MIN_ENGINE_BYTES:
        problems.append(f"Docker engine memory {engine / 1024 ** 2:.0f} MiB is below "
                        f"{GATE_MIN_ENGINE_BYTES // 1024 ** 2} MiB")
    for port in GATE_PORTS:
        state = readings.ports_in_use.get(port)
        if state is None:
            problems.append(f"port {port} could not be checked")
        elif state:
            problems.append(f"port {port} is in use")
    if readings.project_objects is None:
        problems.append("the disposable project's Docker objects could not be listed")
    elif len(readings.project_objects) > 0:
        problems.append("objects of the disposable project already exist: " + _some(list(readings.project_objects), 4))
    return problems


def parse_typeperf_csv(text: str) -> Optional[dict[str, Any]]:
    """The four counters of one typeperf session as {pages_per_second: [12], available_mib, committed_percent,
    paging_file_percent}, or None when anything is missing or unreadable.  Available memory is the lowest of
    the measured samples, committed memory and paging-file usage the highest: the stricter reading."""
    rows: list[list[float]] = []
    for record in csv.reader(text.splitlines()):
        if len(record) != len(_COUNTER_PATHS) + 1 or record[0].startswith("(PDH-CSV"):
            continue
        try:
            rows.append([float(cell) for cell in record[1:]])
        except ValueError:
            return None
    if len(rows) != GATE_PAGES_SAMPLES:
        return None
    measured = rows[GATE_PAGES_WARMUP:]
    return {
        "pages_per_second": [row[0] for row in rows],
        "available_mib": min(row[1] for row in measured),
        "committed_percent": max(row[2] for row in measured),
        "paging_file_percent": max(row[3] for row in measured),
    }


def _read_counter_session() -> Optional[dict[str, Any]]:
    """ONE typeperf session: twelve samples one second apart of all four counters."""
    result = run(["typeperf", *_COUNTER_PATHS, "-sc", str(GATE_PAGES_SAMPLES), "-si", "1"],
                 timeout=90.0, what="typeperf")
    if result.returncode != 0:
        return None
    return parse_typeperf_csv(result.stdout)


def _read_wmi_available_mib() -> Optional[float]:
    result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  "(Get-CimInstance -ClassName Win32_OperatingSystem).FreePhysicalMemory"],
                 timeout=60.0, what="WMI memory reading")
    text = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9]+", text):
        return None
    return int(text) / 1024.0


def _read_power_source() -> Optional[str]:
    if os.name != "nt":
        return None
    import ctypes

    class _PowerStatus(ctypes.Structure):
        _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                    ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                    ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]

    status = _PowerStatus()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):  # type: ignore[attr-defined]
        return None
    return {1: "AC", 0: "battery"}.get(status.ACLineStatus)


def _read_free_disk() -> dict[str, Optional[float]]:
    base = os.environ.get("LOCALAPPDATA")
    places: dict[str, Optional[Path]] = {
        "temporary storage": Path(tempfile.gettempdir()),
        "Docker storage": Path(base) / "Docker" if base else None,
    }
    found: dict[str, Optional[float]] = {}
    for label, place in places.items():
        if place is None:
            found[label] = None
            continue
        probe = place
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        try:
            found[label] = float(shutil.disk_usage(probe).free)
        except OSError:
            found[label] = None
    return found


def _read_engine_bytes() -> Optional[int]:
    result = run(["docker", "info", "--format", "{{.MemTotal}}"], timeout=T_COMMAND, what="docker info")
    text = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9]+", text):
        return None
    return int(text)


def probe_port_in_use(port: int) -> Optional[bool]:
    """True when something listens on, or holds, 127.0.0.1:port; False when it is free."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True


def read_project_objects() -> list[str]:
    """Docker objects that already carry this project's name or label.  Read-only."""
    found = [f"{kind}: {line[:80]}" for kind, lines in docker_fingerprint().items()
             for line in lines if PROJECT in line]
    label = f"label=com.docker.compose.project={PROJECT}"
    for kind, command in (("containers", ["ps", "-a", "-q", "--filter", label]),
                          ("networks", ["network", "ls", "-q", "--filter", label]),
                          ("volumes", ["volume", "ls", "-q", "--filter", label]),
                          ("images", ["images", "-q", "--filter", label])):
        left = docker_lines(*command)
        if left:
            found.append(f"{kind} labelled for the project: {len(left)}")
    return found


@dataclass
class GateSources:
    """Where the readings come from.  The defaults read the real host; tests give fakes."""
    power: Callable[[], Optional[str]]
    wmi_available_mib: Callable[[], Optional[float]]
    counters: Callable[[], Optional[Mapping[str, Any]]]
    free_disk_bytes: Callable[[], Mapping[str, Optional[float]]]
    engine_bytes: Callable[[], Optional[int]]
    port_probe: Callable[[int], Optional[bool]]
    project_objects: Callable[[], Optional[Sequence[str]]]
    #: {"total_mib", "available_mib"} of the Docker VM, or None.  Read only when an engine is pinned.
    vm_memory: Optional[Callable[[], Optional[Mapping[str, Any]]]] = None


def default_gate_sources() -> GateSources:
    return GateSources(
        power=_read_power_source, wmi_available_mib=_read_wmi_available_mib, counters=_read_counter_session,
        free_disk_bytes=_read_free_disk, engine_bytes=_read_engine_bytes, port_probe=probe_port_in_use,
        project_objects=read_project_objects, vm_memory=_read_vm_memory,
    )


def parse_vm_meminfo(text: str) -> Optional[dict[str, float]]:
    """{"total_mib", "available_mib"} from the text of /proc/meminfo, or None unless exactly one well-formed
    MemTotal line and one well-formed MemAvailable line are present.  Swap is never read.  Pure."""
    found: dict[str, float] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"(MemTotal|MemAvailable):\s+([0-9]+) kB", line.strip())
        if match is None:
            continue
        key = "total_mib" if match.group(1) == "MemTotal" else "available_mib"
        if key in found:
            return None
        found[key] = int(match.group(2)) / 1024.0
    return found if set(found) == {"total_mib", "available_mib"} else None


def _read_vm_memory() -> Optional[dict[str, float]]:
    """The memory of the Docker Desktop Linux VM, read from inside it without a shell: one read-only command."""
    result = run(["wsl", "-d", "docker-desktop", "-e", "cat", "/proc/meminfo"], timeout=T_COMMAND,
                 what="Docker VM memory")
    if result.returncode != 0:
        return None
    return parse_vm_meminfo(result.stdout)


def vm_memory_problems(total_mib: Any, available_mib: Any, engine_bytes: Any) -> list[str]:
    """Every unmet Docker-VM memory gate.  Pure.  An unreadable value is an unmet gate, the VM total must agree
    with the engine's own total within GATE_VM_TOTAL_TOLERANCE, and the AVAILABLE memory (swap excluded) must
    reach GATE_MIN_VM_AVAILABLE_MIB."""
    total, available, engine = _number(total_mib), _number(available_mib), _number(engine_bytes)
    problems: list[str] = []
    if total is None or total <= 0:
        problems.append("the Docker VM's total memory could not be read")
    if available is None:
        problems.append("the Docker VM's available memory could not be read")
    if engine is None or engine <= 0:
        problems.append("the Docker engine's total memory could not be read, so the VM reading cannot be verified")
    if problems:
        return problems
    assert total is not None and available is not None and engine is not None
    engine_mib = engine / 1024 ** 2
    if abs(total - engine_mib) > GATE_VM_TOTAL_TOLERANCE * engine_mib:
        problems.append(f"the Docker VM's total memory ({total:.0f} MiB) does not match the engine's "
                        f"({engine_mib:.0f} MiB) within {GATE_VM_TOTAL_TOLERANCE:.0%}")
    if available > total:
        problems.append(f"the Docker VM reports more available memory ({available:.0f} MiB) than its total "
                        f"({total:.0f} MiB)")
    elif available < GATE_MIN_VM_AVAILABLE_MIB:
        problems.append(f"Docker VM available memory {available:.0f} MiB is below {GATE_MIN_VM_AVAILABLE_MIB} MiB "
                        "(swap is not counted)")
    return problems


def _attempt(function: Callable[..., Any], *args: Any) -> Any:
    try:
        return function(*args)
    except Exception:  # noqa: BLE001 - an unreadable reading is an unmet gate, never an exception
        return None


def read_gate_readings(sources: GateSources) -> GateReadings:
    """Read everything once.  The counter session is started exactly once and is never repeated."""
    readings = GateReadings()
    readings.power_source = _attempt(sources.power)
    readings.wmi_available_mib = _attempt(sources.wmi_available_mib)
    session = _attempt(sources.counters)
    if isinstance(session, Mapping):
        readings.counter_available_mib = session.get("available_mib")
        readings.committed_percent = session.get("committed_percent")
        readings.paging_file_percent = session.get("paging_file_percent")
        readings.pages_per_second = session.get("pages_per_second")
    disk = _attempt(sources.free_disk_bytes)
    readings.free_disk_bytes = dict(disk) if isinstance(disk, Mapping) else {}
    readings.engine_bytes = _attempt(sources.engine_bytes)
    readings.ports_in_use = {port: _attempt(sources.port_probe, port) for port in GATE_PORTS}
    readings.project_objects = _attempt(sources.project_objects)
    return readings


def _say_gate_readings(readings: GateReadings) -> None:
    def shown(value: Any, unit: str = "") -> str:
        number = _number(value)
        return "unreadable" if number is None else f"{number:g}{unit}"

    say(f"  power source          {readings.power_source or 'unreadable'}")
    say(f"  available memory      WMI {shown(readings.wmi_available_mib, ' MiB')}; "
        f"counter {shown(readings.counter_available_mib, ' MiB')} (minimum {GATE_MIN_AVAILABLE_MIB} MiB)")
    say(f"  committed memory      {shown(readings.committed_percent, ' %')} (below {GATE_MAX_COMMITTED_PERCENT:g} %)")
    say(f"  paging file usage     {shown(readings.paging_file_percent, ' %')} (below {GATE_MAX_PAGING_FILE_PERCENT:g} %)")
    samples = readings.pages_per_second
    try:
        listed = ", ".join(shown(v) for v in list(samples)) if samples is not None else "unreadable"
    except TypeError:
        listed = "unreadable"
    say(f"  Pages/sec (12, first {GATE_PAGES_WARMUP} warm-up)  {listed}")
    for label in GATE_DISK_LABELS:
        free = _number(readings.free_disk_bytes.get(label))
        say(f"  free disk, {label:17} " + ("unreadable" if free is None else f"{free / 1024 ** 3:.1f} GiB")
            + f" (minimum {GATE_MIN_FREE_DISK_GIB} GiB)")
    engine = _number(readings.engine_bytes)
    say("  Docker engine memory  " + ("unreadable" if engine is None else f"{engine / 1024 ** 2:.0f} MiB")
        + f" (minimum {GATE_MIN_ENGINE_BYTES // 1024 ** 2} MiB)")
    say("  ports                 " + ", ".join(
        f"{port} {'in use' if state else 'unreadable' if state is None else 'free'}"
        for port, state in readings.ports_in_use.items()))
    found = readings.project_objects
    say("  project objects       " + ("unreadable" if found is None else str(len(found))))


def run_resource_gate(sources: Optional[GateSources] = None, *, pin: Optional["EnginePin"] = None) -> GateReadings:
    """The fail-closed resource preflight.  It only reads: nothing is created, started or changed to make a
    gate pass, and a failed measurement is reported, never repeated.  With a pin (run_e2e passes one) the
    Docker engine is verified first, so that the engine memory below is read from the approved engine."""
    section("resource preflight")
    if pin is not None:
        verify_engine_identity(pin)
        CONTAINED.engine_pin = pin
        say(f"  Docker engine         approved ({pin.context}, engine id {pin.engine_id})")
    sources = default_gate_sources() if sources is None else sources
    readings = read_gate_readings(sources)
    _say_gate_readings(readings)
    problems = resource_gate_problems(readings)
    if pin is not None:
        raw = _attempt(sources.vm_memory) if sources.vm_memory is not None else None
        vm = raw if isinstance(raw, Mapping) else {}
        vm_total, vm_available = _number(vm.get("total_mib")), _number(vm.get("available_mib"))
        say("  Docker VM memory      " + ("unreadable" if vm_total is None or vm_available is None else
                                          f"total {vm_total:.0f} MiB, available {vm_available:.0f} MiB")
            + f" (available minimum {GATE_MIN_VM_AVAILABLE_MIB} MiB, swap not counted; total within "
            f"{GATE_VM_TOTAL_TOLERANCE:.0%} of the engine's)")
        problems += vm_memory_problems(vm.get("total_mib"), vm.get("available_mib"), readings.engine_bytes)
    if problems:
        raise SmokeFailure("the resource preflight failed; nothing was started or changed, and nothing is "
                           "measured again to obtain a pass:\n" + "\n".join("  - " + p for p in problems))
    say("resource preflight: every gate met")
    return readings


# -- secured temporary workspace ---------------------------------------------------------------------------------

_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
#: OWNER RIGHTS.  Python 3.13's tempfile.mkdtemp gives a new directory an explicit entry for it; icacls /grant:r
#: does not replace it, so it is removed in the same call.  It is never added to the allowed set below: the
#: read-back must still find exactly the user, SYSTEM and Administrators.
_OWNER_RIGHTS_SID = "S-1-3-4"
_SID_RE = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+")


def _current_user_sid() -> str:
    result = run(["whoami", "/user", "/fo", "csv", "/nh"], timeout=T_COMMAND, what="whoami")
    if result.returncode != 0:
        raise SmokeFailure("the current user could not be identified")
    first = result.stdout.strip().splitlines()[:1]
    fields = next(csv.reader(first), [])
    if len(fields) != 2 or not _SID_RE.fullmatch(fields[1].strip()):
        raise SmokeFailure("the current user's SID could not be read")
    return fields[1].strip()


def restrict_to_owner(path: Path, *, directory: bool, windows: Optional[bool] = None) -> None:
    """Owner-only permissions on one path, verified; SmokeFailure when they cannot be established.
    Windows: inheritance removed, any explicit OWNER RIGHTS entry removed and the user, SYSTEM and Administrators
    granted, then the ACL is read back by SID (so the check does not depend on the display language) and must
    list exactly those three.  Elsewhere: mode 0700 / 0600."""
    if not (_windows() if windows is None else windows):
        os.chmod(path, 0o700 if directory else 0o600)
        if stat.S_IMODE(_lstat(path).st_mode) & 0o077:
            raise SmokeFailure("owner-only permissions could not be established")
        return
    sid = _current_user_sid()
    grant = "(OI)(CI)F" if directory else "F"
    result = run(["icacls", str(path), "/inheritance:r", "/remove:g", f"*{_OWNER_RIGHTS_SID}",
                  "/grant:r", f"*{sid}:{grant}", f"*{_SYSTEM_SID}:{grant}", f"*{_ADMINISTRATORS_SID}:{grant}"],
                 timeout=T_COMMAND, what="icacls")
    if result.returncode != 0:
        raise SmokeFailure("restrictive permissions could not be applied")
    script = ("$a = Get-Acl -LiteralPath '" + str(path).replace("'", "''") + "'; "
              "if (-not $a.AreAccessRulesProtected) { 'UNPROTECTED' }; "
              "foreach ($r in $a.Access) "
              "{ $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }")
    check = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=T_COMMAND, what="ACL check")
    if check.returncode != 0:
        raise SmokeFailure("the permissions could not be verified")
    lines = [line.strip() for line in check.stdout.splitlines() if line.strip()]
    allowed = {sid, _SYSTEM_SID, _ADMINISTRATORS_SID}
    if not lines or "UNPROTECTED" in lines or any(line not in allowed for line in lines):
        raise SmokeFailure("the permissions are not limited to the user, SYSTEM and Administrators")


def create_workspace_secured() -> None:
    """create_workspace() with the permissions restricted BEFORE any secret is written.  The directory is
    registered at creation (its identity is what a later disposition checks); the environment file holding
    the generated test-only passwords is retained, never deleted, and also restricted and verified."""
    section("temporary workspace (restricted)")
    temp = Path(tempfile.mkdtemp(prefix="agentops-d3-smoke-")).resolve()
    try:
        register_workspace(temp)
    except (OSError, SmokeFailure) as exc:  # an unregistered directory is left alone, never deleted
        raise SmokeFailure(f"could not record ownership of the temporary directory: {exc}") from exc
    if temp == REPO or REPO in temp.parents:
        _discard_unused_workspace(temp)
        raise SmokeFailure("the temporary directory would be inside the repository")
    RUN.temp = temp
    try:
        restrict_to_owner(temp, directory=True)
    except (OSError, SmokeFailure) as exc:
        RUN.temp = None
        _discard_unused_workspace(temp)  # an empty directory only
        raise SmokeFailure(f"the temporary directory could not be restricted: {exc}") from exc
    say("created outside the repository; owner-only permissions verified")

    RUN.generated = {name: secrets.token_urlsafe(24) for name in PASSWORD_VARIABLES}
    env_file = temp / "smoke.env"
    with open(env_file, "x", encoding="utf-8", newline="\n") as handle:
        handle.writelines(f"{name}={value}\n" for name, value in RUN.generated.items())
    RUN.env_file = env_file
    try:
        restrict_to_owner(env_file, directory=False)
    except (OSError, SmokeFailure) as exc:
        raise SmokeFailure(f"the environment file could not be restricted: {exc}") from exc
    say(f"generated {len(RUN.generated)} test-only passwords "
        f"({len(set(RUN.generated.values()))} distinct); they are never printed")
    (temp / "docker-before.json").write_text(json.dumps(RUN.before, indent=1), encoding="utf-8")


def workspace_disposition(path: Optional[Path]) -> tuple[str, str]:
    """(status, reason) for the run's temporary workspace.  Status is one of:
      deleted             removed (not on Windows), or it no longer exists, or none was created
      retained_by_policy  identity verified; automatic recursive deletion is disabled on Windows
      refused             its identity or location could not be verified; nothing was touched
      failed              a verified workspace could not be removed
    It reuses the ownership checks of _remove_tree and never deletes anything on Windows."""
    if path is None:
        return "deleted", "no workspace was created"
    key = _norm(path)
    if key in _OWNED and not _lexists(path):
        _OWNED.pop(key, None)
        return "deleted", "the workspace no longer exists"
    refusal = _deletion_refusal(path)
    if refusal is not None:
        return "refused", refusal
    if _windows():
        return "retained_by_policy", ("automatic recursive deletion is disabled on Windows; "
                                      "inspect it and remove it by hand")
    if _remove_tree(path):
        return "deleted", "removed"
    return "failed", "the verified workspace could not be removed"


def retained_workspace_lines(path: Path, limit: int = 40) -> list[str]:
    """The top level of a retained workspace: names and sizes, short hashes for plain files, nothing recursive.
    The environment file is listed by size only and is never hashed."""
    lines: list[str] = []
    try:
        with os.scandir(path) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                if len(lines) >= limit:
                    lines.append("  ...")
                    break
                try:
                    info = entry.stat(follow_symlinks=False)
                    if entry.is_symlink():
                        lines.append(f"  {entry.name}  (a link, not followed)")
                    elif entry.is_dir(follow_symlinks=False):
                        lines.append(f"  {entry.name}/  (directory, not listed)")
                    elif entry.name == "smoke.env":
                        lines.append(f"  {entry.name}  {info.st_size} bytes  "
                                     "(test-only generated passwords; owner-only; not hashed)")
                    else:
                        lines.append(f"  {entry.name}  {info.st_size} bytes  "
                                     f"sha256 {_file_sha256(Path(entry.path))[:16]}")
                except OSError:
                    lines.append(f"  {entry.name}  (unreadable)")
    except OSError:
        lines.append("  (the workspace could not be listed)")
    return lines


# -- project-contained Docker cleanup ----------------------------------------------------------------------------

_LABEL_PROJECT = "com.docker.compose.project"
PROJECT_SERVICES: frozenset[str] = frozenset(
    {"kafka", "kafka-init", "postgres", "db-bootstrap", "otel-collector", "analytics-refresh"})
PROJECT_VOLUMES: frozenset[str] = frozenset({"kafka-data", "postgres-data", "grafana-data"})
PROJECT_IMAGES: frozenset[str] = frozenset(
    f"{PROJECT}-{service}:latest" for service in ("postgres", "db-bootstrap", "analytics-refresh"))

#: Resources this harness must never touch and must find unchanged.  Compared by name, then by inspected state.
PROTECTED_CONTAINER_NAMES: tuple[str, ...] = (
    "agentops-mvp-workers-postgres-1", "agentops-mvp-workers-viewer-1", "agentops-mvp-workers-db-bootstrap-1",
    "agentops-mvp-postgres-1", "agentops-mvp-viewer-1", "agentops-mvp-db-bootstrap-1",
    "agentops-postgres", "agentops-pipetest-postgres-1",
)
PROTECTED_VOLUME_NAMES: tuple[str, ...] = (
    "agentops-mvp-workers-postgres-data", "agentops-mvp-postgres-data", "agentops_postgres-data",
    "agentops-pipetest-pgdata",
)


@dataclass
class ProjectInventory:
    containers: list[dict[str, Any]] = field(default_factory=list)   # id, name, labels, mounts, mounts_ok
    networks: list[dict[str, Any]] = field(default_factory=list)     # id, name, labels
    volumes: list[dict[str, Any]] = field(default_factory=list)      # name, labels
    images: list[str] = field(default_factory=list)                  # name:tag

    def total(self) -> int:
        return len(self.containers) + len(self.networks) + len(self.volumes) + len(self.images)


_ANONYMOUS_VOLUME_RE = re.compile(r"[0-9a-f]{64}")


def _volume_mounts(raw: Any) -> tuple[list[dict[str, Any]], bool]:
    """The volume mounts of one inspected container as [{name, destination, anonymous}], and whether the
    metadata had the expected shape.  A volume is anonymous when Docker named it itself (64 hexadecimal
    characters).  Other mount types (bind, tmpfs) are ignored.  Anything unexpected makes the second value
    False: that container's anonymous volumes then cannot be accounted for.  Pure."""
    if raw is None:
        return [], True
    if not isinstance(raw, list):
        return [], False
    mounts: list[dict[str, Any]] = []
    well_formed = True
    for entry in raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("Type"), str):
            well_formed = False
            continue
        if entry["Type"] != "volume":
            continue
        name, destination = entry.get("Name"), entry.get("Destination")
        if not isinstance(name, str) or not name or not isinstance(destination, str) or not destination:
            well_formed = False
            continue
        mounts.append({"name": name, "destination": destination,
                       "anonymous": bool(_ANONYMOUS_VOLUME_RE.fullmatch(name))})
    return mounts, well_formed


def read_project_inventory() -> ProjectInventory:
    """Everything labelled for this project, with the labels read back from each object (not assumed from
    the filter).  Read-only."""
    inventory = ProjectInventory()
    selector = f"label={_LABEL_PROJECT}={PROJECT}"
    try:
        ids = docker_lines("ps", "-a", "-q", "--filter", selector)
        if ids:
            for item in json.loads(checked(["docker", "inspect", "--type", "container", *ids],
                                           timeout=T_COMMAND, what="docker inspect")):
                mounts, mounts_ok = _volume_mounts(item.get("Mounts"))
                inventory.containers.append({
                    "id": str(item.get("Id", "")), "name": str(item.get("Name", "")).lstrip("/"),
                    "labels": dict((item.get("Config") or {}).get("Labels") or {}),
                    "mounts": mounts, "mounts_ok": mounts_ok})
        network_ids = docker_lines("network", "ls", "-q", "--filter", selector)
        if network_ids:
            for item in json.loads(checked(["docker", "network", "inspect", *network_ids],
                                           timeout=T_COMMAND, what="docker network inspect")):
                inventory.networks.append({"id": str(item.get("Id", "")), "name": str(item.get("Name", "")),
                                           "labels": dict(item.get("Labels") or {})})
        volume_names = docker_lines("volume", "ls", "-q", "--filter", selector)
        if volume_names:
            for item in json.loads(checked(["docker", "volume", "inspect", *volume_names],
                                           timeout=T_COMMAND, what="docker volume inspect")):
                inventory.volumes.append({"name": str(item.get("Name", "")),
                                          "labels": dict(item.get("Labels") or {})})
        inventory.images = docker_lines("images", "--filter", selector, "--format", "{{.Repository}}:{{.Tag}}")
    except (ValueError, TypeError, AttributeError) as exc:
        raise SmokeFailure(f"a Docker listing could not be parsed ({type(exc).__name__})") from None
    return inventory


def ownership_problems(inventory: ProjectInventory) -> list[str]:
    """Containers, networks and volumes that carry the project label but are not demonstrably this harness's
    own: the exact label value, the project's naming and a known service or volume.  Pure."""
    problems: list[str] = []
    for item in inventory.containers:
        labels, name = item["labels"], item["name"]
        if labels.get(_LABEL_PROJECT) != PROJECT:
            problems.append(f"container {name!r}: the project label is not {PROJECT!r}")
        elif not name.startswith(PROJECT + "-"):
            problems.append(f"container {name!r}: not named after the project")
        elif labels.get("com.docker.compose.service") not in PROJECT_SERVICES:
            problems.append(f"container {name!r}: not one of the project's services")
    for item in inventory.networks:
        labels, name = item["labels"], item["name"]
        if labels.get(_LABEL_PROJECT) != PROJECT or not name.startswith(PROJECT + "_") \
                or labels.get("com.docker.compose.network") != "agentops-net":
            problems.append(f"network {name!r}: not demonstrably the project's own")
    for item in inventory.volumes:
        labels, name = item["labels"], item["name"]
        if labels.get(_LABEL_PROJECT) != PROJECT or not name.startswith(PROJECT + "_") \
                or labels.get("com.docker.compose.volume") not in PROJECT_VOLUMES:
            problems.append(f"volume {name!r}: not demonstrably the project's own")
    return problems


def unowned_images(inventory: ProjectInventory) -> list[str]:
    """Labelled images that are not exactly one of the project's own built images."""
    return [reference for reference in inventory.images if reference not in PROJECT_IMAGES]


def record_anonymous_volumes(inventory: ProjectInventory) -> int:
    """Record, while the containers still exist, the anonymous volumes attached to the project's verified
    containers.  Docker gives such a volume no project label, so its ownership is the attachment to a
    container that has already passed ownership_problems(); a volume that merely appeared during the run is
    never recorded.  A container whose mount metadata is unexpected is noted as uncertain.  This only
    records.  Returns how many anonymous volumes are recorded in all."""
    for item in inventory.containers:
        if not item.get("mounts_ok", True):
            CONTAINED.uncertain_mounts.add(item["name"])
        for mount in item.get("mounts") or []:
            if mount.get("anonymous"):
                CONTAINED.tracked_anonymous.setdefault(mount["name"], {
                    "container_id": item["id"], "container": item["name"], "destination": mount["destination"]})
    return len(CONTAINED.tracked_anonymous)


def anonymous_volume_problems(existing_volumes: Sequence[str]) -> list[str]:
    """What the recorded anonymous volumes and the mount metadata say after cleanup.  Pure.  A recorded
    anonymous volume that still exists is a problem, reported with the identity evidence for manual review
    (it is never removed here); so is a container whose mount metadata could not be read."""
    present = set(existing_volumes)
    problems = [
        f"anonymous volume {name} (attached to container {evidence['container']}, mounted at "
        f"{evidence['destination']}) still exists after cleanup; left for manual review"
        for name, evidence in sorted(CONTAINED.tracked_anonymous.items()) if name in present
    ]
    problems += [
        f"container {name}: its mount metadata had an unexpected shape, so its anonymous volumes could not be "
        "accounted for; left for manual review" for name in sorted(CONTAINED.uncertain_mounts)
    ]
    return problems


def _unverified_anonymous_volumes() -> list[str]:
    """One note listing the recorded anonymous volumes when cleanup ended before they could be verified."""
    if not CONTAINED.tracked_anonymous:
        return []
    listed = "; ".join(f"{name} (container {evidence['container']}, mount {evidence['destination']})"
                       for name, evidence in sorted(CONTAINED.tracked_anonymous.items()))
    return [f"{len(CONTAINED.tracked_anonymous)} recorded anonymous volume(s) were not verified and may "
            f"remain: {listed}"]


def track_project_identities(when: str) -> ProjectInventory:
    """Record the identities of what the run has created so far; stop the run if anything labelled for the
    project cannot be shown to be its own."""
    inventory = read_project_inventory()
    problems = ownership_problems(inventory)
    if problems:
        raise SmokeFailure(f"project ownership could not be established ({when}): " + "; ".join(problems[:5]))
    CONTAINED.tracked_containers.update(item["id"] for item in inventory.containers)
    CONTAINED.tracked_networks.update(item["id"] for item in inventory.networks)
    CONTAINED.tracked_volumes.update(item["name"] for item in inventory.volumes)
    CONTAINED.tracked_images.update(inventory.images)
    anonymous = record_anonymous_volumes(inventory)
    say(f"  tracked ({when}): {len(CONTAINED.tracked_containers)} containers, "
        f"{len(CONTAINED.tracked_networks)} networks, {len(CONTAINED.tracked_volumes)} named volumes, "
        f"{anonymous} anonymous volumes, {len(CONTAINED.tracked_images)} images")
    return inventory


def read_protected_snapshot() -> dict[str, str]:
    """The inspected state of every protected container and volume.  Read-only; a missing object is 'absent'."""
    snapshot: dict[str, str] = {}
    for name in PROTECTED_CONTAINER_NAMES:
        result = run(["docker", "inspect", "--type", "container", name], timeout=T_COMMAND, what="docker inspect")
        if result.returncode != 0:
            snapshot[f"container {name}"] = "absent"
            continue
        try:
            item = json.loads(result.stdout)[0]
            state = item.get("State") or {}
            health = (state.get("Health") or {}).get("Status", "")
            mounts = sorted(f"{m.get('Name') or m.get('Source')}:{m.get('Destination')}"
                            for m in item.get("Mounts") or [])
            ports = json.dumps((item.get("NetworkSettings") or {}).get("Ports"), sort_keys=True)
            snapshot[f"container {name}"] = "|".join([
                str(item.get("Id", ""))[:12], str(state.get("Status")), str(health), str(state.get("StartedAt")),
                str(state.get("FinishedAt")), str(item.get("RestartCount")), ",".join(mounts), ports])
        except (ValueError, IndexError, TypeError, AttributeError):
            snapshot[f"container {name}"] = "unreadable"
    for name in PROTECTED_VOLUME_NAMES:
        result = run(["docker", "volume", "inspect", name], timeout=T_COMMAND, what="docker volume inspect")
        if result.returncode != 0:
            snapshot[f"volume {name}"] = "absent"
            continue
        try:
            created = json.loads(result.stdout)[0].get("CreatedAt")
        except (ValueError, IndexError, TypeError, AttributeError):
            snapshot[f"volume {name}"] = "unreadable"
            continue
        attached = docker_lines("ps", "-a", "--filter", f"volume={name}", "--format", "{{.Names}}")
        snapshot[f"volume {name}"] = f"{created}|attached {','.join(attached)}"
    return snapshot


def protected_problems(before: Optional[Mapping[str, str]], after: Mapping[str, str]) -> list[str]:
    """Any protected object that is not exactly as it was.  Pure."""
    if before is None:
        return ["the protected resources were not recorded before the run"]
    return [f"protected resource changed: {key}" for key in sorted(set(before) | set(after))
            if before.get(key) != after.get(key)]


# -- the approved Docker engine and the protected resources that must exist on it ---------------------------------

@dataclass(frozen=True)
class EnginePin:
    """The one Docker engine a live run may use, and the protected objects that must be found on it.  The name
    of the context alone proves nothing (two contexts can reach one engine), so the engine id is checked too."""
    context: str
    endpoint: str
    engine_id: str
    #: (container name, full container id, the one volume it must mount, or "" when it mounts none)
    required_containers: tuple[tuple[str, str, str], ...]
    required_volumes: tuple[str, ...]


#: Variables that can send the Docker client to another daemon, another context store or another builder.  The
#: list is the ones known to do so; the engine id check is what catches anything it does not name.
ENGINE_SELECTOR_VARIABLES: tuple[str, ...] = (
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION", "BUILDX_BUILDER", "BUILDKIT_HOST",
)


def engine_selector_problems(environ: Mapping[str, str]) -> list[str]:
    """The selector variables present in `environ` (names only, never values; case-insensitive as on Windows).  Pure."""
    present = {str(name).upper() for name in environ}
    return [f"{name} is set" for name in ENGINE_SELECTOR_VARIABLES if name in present]


def verify_engine_identity(pin: EnginePin) -> None:
    """Read-only.  SmokeFailure unless the Docker client is not redirected by the environment, the active
    context is the approved one with the approved endpoint, and the engine behind it has the approved id.
    Every failure to ask, parse or compare is a failure: nothing is assumed."""
    selectors = engine_selector_problems(os.environ)
    if selectors:
        raise SmokeFailure("the Docker target could be redirected by the environment (" + "; ".join(selectors)
                           + "); nothing was started or changed")
    active = checked(["docker", "context", "show"], timeout=T_COMMAND, what="docker context show").strip()
    if active != pin.context:
        raise SmokeFailure(f"the active Docker context is {active!r}, not the approved {pin.context!r}; "
                           "nothing was started or changed")
    try:
        inspected = json.loads(checked(["docker", "context", "inspect", pin.context], timeout=T_COMMAND,
                                       what="docker context inspect"))
        endpoint = inspected[0]["Endpoints"]["docker"]["Host"]
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise SmokeFailure("the Docker context could not be read; nothing was started or changed") from None
    if endpoint != pin.endpoint:
        raise SmokeFailure(f"the Docker context {pin.context!r} points at {endpoint!r}, not the approved endpoint; "
                           "nothing was started or changed")
    found = checked(["docker", "info", "--format", "{{.ID}}"], timeout=T_COMMAND, what="docker info").strip()
    if found != pin.engine_id:
        raise SmokeFailure(f"the Docker engine id is {found!r}, not the approved {pin.engine_id!r}; "
                           "nothing was started or changed")


def verify_required_protected(pin: EnginePin) -> None:
    """Read-only.  Every required protected container must exist with its exact full id and name and mount
    exactly its approved volume, and every required protected volume must exist.  A missing, unreadable or
    different object is a failure, so an absent object can never look 'unchanged'."""
    for name, full_id, volume in pin.required_containers:
        try:
            item = json.loads(checked(["docker", "inspect", "--type", "container", full_id], timeout=T_COMMAND,
                                      what="docker inspect"))[0]
            found_id, found_name = item["Id"], item["Name"]
            mounted = sorted(mount["Name"] for mount in item.get("Mounts") or [] if mount.get("Type") == "volume")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise SmokeFailure(f"protected container {name} could not be inspected; nothing was started or changed"
                               ) from None
        if found_id != full_id or found_name != "/" + name:
            raise SmokeFailure(f"protected container {name} is not the approved one (its identity differs); "
                               "nothing was started or changed")
        if mounted != ([volume] if volume else []):
            raise SmokeFailure(f"protected container {name} no longer has its approved volume attachment; "
                               "nothing was started or changed")
    for volume in pin.required_volumes:
        checked(["docker", "volume", "inspect", volume], timeout=T_COMMAND, what="docker volume inspect")


def record_protected_state(pin: Optional[EnginePin] = None) -> None:
    section("protected resources before")
    if pin is not None:
        verify_engine_identity(pin)
        verify_required_protected(pin)
        CONTAINED.engine_pin = pin
        say(f"engine approved; {len(pin.required_containers)} protected containers and "
            f"{len(pin.required_volumes)} protected volumes found with their approved identities")
    CONTAINED.protected_before = read_protected_snapshot()
    present = sum(1 for value in CONTAINED.protected_before.values() if value not in ("absent", "unreadable"))
    say(f"recorded {len(CONTAINED.protected_before)} protected objects ({present} present)")


# -- host processes this run started -------------------------------------------------------------------------------

_OWN_PROCESS_NAMES: frozenset[str] = frozenset({"stream-processor", "storage-consumer"})
_taskkill = subprocess.run


def _process_identity_problem(name: str, process: Any) -> Optional[str]:
    if name not in _OWN_PROCESS_NAMES:
        return "is not a process this harness starts"
    python = RUN.python
    args = getattr(process, "args", None)
    if python is None or not isinstance(args, (list, tuple)) or list(args) != [str(python), "main.py"]:
        return "its command line is not the one this harness started"
    pid = getattr(process, "pid", None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return "has no valid process id"
    return None


def _terminate_one(process: Any, pid: int, wait_seconds: float) -> Optional[str]:
    """Stop one verified process; a problem text when that cannot be confirmed.  Never escalates beyond the
    handle this run holds, and never retries."""
    try:
        if _windows():
            _taskkill(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=30)
        else:
            process.terminate()
        process.wait(timeout=wait_seconds)
    except subprocess.TimeoutExpired:
        if _windows():
            return f"pid {pid} did not stop within {wait_seconds:g} s; left for manual review"
        try:
            process.kill()
            process.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            return f"pid {pid} did not stop after a kill; left for manual review"
    except OSError as exc:
        return f"pid {pid} could not be stopped ({type(exc).__name__}); left for manual review"
    return None


def stop_registered_processes(wait_seconds: float = 15.0) -> list[str]:
    """Stop only the host processes this run started, each verified by the handle and command line recorded at
    its start.  Returns what went wrong; an unverified process is left running and reported."""
    problems: list[str] = []
    registered = list(RUN.processes.items())
    for index, (name, process) in enumerate(registered):
        reason = _process_identity_problem(name, process)
        if reason is not None:
            problems.append(f"{name}: {reason}; left running for manual review")
            continue
        if process.poll() is not None:
            say(f"{name}: already exited (code {process.returncode})")
            continue
        pid = process.pid
        try:
            failure = _terminate_one(process, pid, wait_seconds)
        except KeyboardInterrupt:
            # The state of this process is unknown.  Record it, leave the others alone, and let the caller stop
            # the rest of the cleanup.
            CONTAINED.interrupted = f"stopping the host process {name}"
            problems.append(f"{name}: cleanup was interrupted while it was being stopped (pid {pid}); its state "
                            "is unknown; left for manual review")
            problems.extend(f"{other}: not stopped because cleanup was interrupted; left running for manual "
                            "review" for other, _ in registered[index + 1:])
            return problems
        if failure is not None:
            problems.append(f"{name}: {failure}")
        else:
            say(f"{name}: stopped (pid {pid})")
    return problems


# -- the contained cleanup --------------------------------------------------------------------------------------------

@dataclass
class CleanupOutcome:
    """What was given back, reported in four independent parts: cleanup problems (Docker, processes,
    ownership, repository), the workspace disposition, and the protected-resource comparison."""
    problems: list[str] = field(default_factory=list)
    workspace_status: str = "deleted"
    workspace_reason: str = ""
    workspace_path: Optional[str] = None
    protected_problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: True when cleanup was interrupted; the outcome is then never a success (see cleanup_contained)
    interrupted: bool = False

    @property
    def verified(self) -> bool:
        return not self.problems and not self.interrupted

    @property
    def protected_ok(self) -> bool:
        return not self.protected_problems

    @property
    def workspace_retained(self) -> bool:
        return self.workspace_status == "retained_by_policy"


def _safe_failure_text(failure: BaseException, limit: int = 160) -> str:
    """The exception type and a short, single-line message with generated credentials masked, fit for a report."""
    text = redact(str(failure))
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    return f"{type(failure).__name__}: {text[:limit]}" if text else type(failure).__name__


def _contained_docker_cleanup(profiles: Sequence[str]) -> list[str]:
    """Remove this project's own containers, networks and volumes by one project-scoped command, and its own
    images by exact reference, but only after every object has been shown to be the project's.  Anything
    uncertain is left in place and reported.  Nothing is retried."""
    problems: list[str] = []
    if PROJECT == "agentops" or not re.fullmatch(r"agentops-[a-z0-9-]+", PROJECT):
        return [f"the project name {PROJECT!r} is not an approved disposable project; nothing was removed"]
    if CONTAINED.engine_pin is not None:
        try:
            verify_engine_identity(CONTAINED.engine_pin)
        except SmokeFailure as failure:
            return [f"the Docker engine could not be verified before cleanup ({_safe_failure_text(failure)}); "
                    "nothing was removed (manual review)"] + _unverified_anonymous_volumes()
    try:
        inventory = read_project_inventory()
    except SmokeFailure as failure:
        return [f"the initial listing of the project's Docker objects did not complete "
                f"({_safe_failure_text(failure)}); nothing was removed"] + _unverified_anonymous_volumes()
    mismatched = ownership_problems(inventory)
    if mismatched:
        return ["ownership of the project's objects could not be established; nothing was removed "
                "(manual review): " + "; ".join(mismatched[:5])] + _unverified_anonymous_volumes()
    untracked = ([i["id"] for i in inventory.containers if i["id"] not in CONTAINED.tracked_containers]
                 + [i["id"] for i in inventory.networks if i["id"] not in CONTAINED.tracked_networks]
                 + [i["name"] for i in inventory.volumes if i["name"] not in CONTAINED.tracked_volumes])
    if untracked:
        say(f"  {len(untracked)} project object(s) were created after the last identity checkpoint "
            "(their ownership was verified by label, name and service)")
    # The containers are verified as the project's: record their anonymous volumes NOW, while they still exist
    # (compose down removes the containers, and with them the mount metadata).
    record_anonymous_volumes(inventory)

    removable = inventory.containers or inventory.networks or inventory.volumes
    if removable and not (RUN.compose_used and RUN.env_file is not None and RUN.env_file.is_file()):
        return ["the project has objects but no Compose environment file exists to address them; "
                "nothing was removed"] + _unverified_anonymous_volumes()

    # Every step below is labelled, so a failure names the operation that did not complete.  The problems found
    # before it are kept, nothing is retried, and nothing further is removed once a step has failed.
    step = "compose down"
    try:
        down_failed = False
        if removable:
            profile_arguments = [token for profile in profiles for token in ("--profile", profile)]
            command = compose_command(*profile_arguments, "down", "--volumes", "--remove-orphans")
            result = run(command, timeout=T_DOWN, what="compose down")
            say(f"compose down --volumes --remove-orphans (project {PROJECT}): exit {result.returncode}")
            if result.returncode != 0:
                down_failed = True
                problems.append("compose down failed: " + redact_tail(result.stderr, 300))
        else:
            say("compose down: not needed, the project has no containers, networks or volumes")

        if down_failed:
            say("images were not touched because compose down did not succeed")
        else:
            step = "the listing of the project's objects after compose down"
            after = read_project_inventory()
            for reference in after.images:
                if reference not in PROJECT_IMAGES:
                    problems.append(f"image {reference!r} carries the project label but is not one of its own "
                                    "built images; left for manual review")
                    continue
                step = f"the removal of image {reference!r}"
                removed = run(["docker", "image", "remove", reference], timeout=T_COMMAND,
                              what="docker image remove")
                say(f"image of this project: {reference} -> {'removed' if removed.returncode == 0 else 'NOT removed'}")
                if removed.returncode != 0:
                    problems.append(f"image {reference} could not be removed")

        step = "the final verification listing of the project's objects"
        final = read_project_inventory()
        step = "the verification of the recorded anonymous volumes"
        existing_volumes = docker_lines("volume", "ls", "-q") if CONTAINED.tracked_anonymous else []
    except SmokeFailure as failure:
        problems.append(f"{step} did not complete ({_safe_failure_text(failure)}); nothing further was removed, "
                        "and whatever remains is left for manual review")
        problems.extend(_unverified_anonymous_volumes())
        return problems
    except KeyboardInterrupt:
        # An interrupt leaves the state of the step unknown.  Keep what was found, mark the interruption for the
        # caller, remove nothing more and retry nothing.
        CONTAINED.interrupted = step
        problems.append(f"cleanup was interrupted during {step}; nothing further was removed, nothing was "
                        "retried, and whatever remains is left for manual review")
        problems.extend(_unverified_anonymous_volumes())
        return problems
    for kind, count in (("containers", len(final.containers)), ("networks", len(final.networks)),
                        ("volumes", len(final.volumes)), ("images", len(final.images))):
        say(f"project {kind} left: {count}")
        if count:
            problems.append(f"{count} project {kind} remain (left for manual review)")
    for name in sorted(CONTAINED.tracked_anonymous):
        say(f"anonymous volume {name[:12]}...: "
            + ("STILL PRESENT" if name in existing_volumes else "removed with its container"))
    problems.extend(anonymous_volume_problems(existing_volumes))
    return problems


def _inventory_difference_problems() -> list[str]:
    """Compare the whole Docker inventory with the one recorded before the run.  Report only: an object that
    appeared and is not this project's is listed and NOT touched."""
    if RUN.before is None:
        say("no inventory was recorded before; nothing to compare")
        return []
    problems: list[str] = []
    after = docker_fingerprint()
    for kind, lines in after.items():
        before, now = set(RUN.before[kind]), set(lines)
        gone, new = sorted(before - now), sorted(now - before)
        mine = [line for line in new if PROJECT in line]
        unrelated = [line for line in new if PROJECT not in line]
        say(f"{kind}: {len(lines)} (before {len(RUN.before[kind])}); "
            f"{'identical' if not gone and not new else 'DIFFERENT'}")
        for line in gone:
            say(f"  - existing, now missing or changed: {line[:100]}")
        for line in mine:
            say(f"  + of this project, still present: {line[:100]}")
        for line in unrelated:
            say(f"  + appeared during the run, not this project's, NOT touched: {line[:100]}")
        if gone:
            problems.append(f"{len(gone)} existing {kind} object(s) missing or changed")
        if mine:
            problems.append(f"{len(mine)} {kind} object(s) of this project remain")
    return problems


def _run_cleanup_steps(outcome: CleanupOutcome, profiles: Sequence[str], stage: dict[str, Any]) -> None:
    """The cleanup steps, in order.  `stage` names the step that is running, so that an interruption can say
    where it happened.  A step that records an interruption in CONTAINED.interrupted ends the sequence: nothing
    after it runs and nothing is retried."""
    problems = outcome.problems

    stage["name"] = "stopping the host processes"
    try:
        problems.extend(stop_registered_processes())
    except Exception as exc:  # noqa: BLE001
        problems.append(f"host processes could not be stopped ({type(exc).__name__})")
    if CONTAINED.interrupted is not None:
        return

    stage["name"] = "scanning the logs for generated credentials"
    try:
        leaked = 0
        if RUN.temp is not None and RUN.temp.exists():
            for path in RUN.temp.glob("*"):
                if path.is_file() and not path.is_symlink() and path.name != "smoke.env":
                    text = path.read_text(encoding="utf-8", errors="replace")
                    leaked += sum(text.count(value) for value in RUN.generated.values())
            say(f"generated passwords found in logs, reports and snapshots: {leaked} "
                f"(masked before writing: {RUN.masked_in_logs})")
            if leaked or RUN.masked_in_logs:
                problems.append("a generated password reached a temporary log")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"the logs could not be scanned ({type(exc).__name__})")

    stage["name"] = "the project-scoped Docker cleanup"
    try:
        problems.extend(_contained_docker_cleanup(profiles))
    except Exception as exc:  # noqa: BLE001
        problems.append(f"Docker cleanup could not be completed ({_safe_failure_text(exc)}); "
                        "the project's resources are preserved for manual review")
    if CONTAINED.interrupted is not None:
        return

    stage["name"] = "the Docker inventory comparison"
    try:
        problems.extend(_inventory_difference_problems())
    except Exception as exc:  # noqa: BLE001
        problems.append(f"the Docker inventory could not be compared ({_safe_failure_text(exc)})")

    stage["name"] = "the protected-resource comparison"
    try:
        if CONTAINED.protected_before is None:
            if RUN.compose_used or RUN.temp is not None:
                outcome.protected_problems.append("the protected resources were not recorded before the run")
            else:
                outcome.notes.append("the run stopped before anything was created; the protected resources "
                                     "were never touched")
                say("protected resources: the run stopped before anything was created")
        else:
            outcome.protected_problems = protected_problems(CONTAINED.protected_before, read_protected_snapshot())
            for line in outcome.protected_problems:
                say(f"  {line}")
            if RUN.before is not None:
                check_normal_stack("after cleanup")
    except SmokeFailure as failure:
        outcome.protected_problems.append(str(failure))
    except Exception as exc:  # noqa: BLE001
        outcome.protected_problems.append(f"the protected resources could not be compared ({type(exc).__name__})")
    stage["protected"] = True

    stage["name"] = "the temporary workspace disposition"
    try:
        outcome.workspace_status, outcome.workspace_reason = workspace_disposition(RUN.temp)
        outcome.workspace_path = str(RUN.temp) if RUN.temp is not None else None
        say(f"temporary workspace: {outcome.workspace_status} - {outcome.workspace_reason}")
        if outcome.workspace_status == "retained_by_policy" and RUN.temp is not None:
            for line in retained_workspace_lines(RUN.temp):
                say(line)
        elif outcome.workspace_status in ("refused", "failed"):
            problems.append(f"the temporary workspace is {outcome.workspace_status}: {outcome.workspace_reason}")
    except Exception as exc:  # noqa: BLE001
        outcome.workspace_status = "failed"
        outcome.workspace_reason = f"its disposition could not be decided ({type(exc).__name__})"
        problems.append(f"the temporary workspace is failed: {outcome.workspace_reason}")

    stage["name"] = "the repository re-check"
    try:
        problems.extend(recheck_approved_tree())
        if CONTAINED.approved is None:
            unexpected = [line for line in repository_state() if line not in ALLOWED_UNTRACKED]
            if unexpected:
                problems.append("the repository holds unexpected changes")
        caches = sorted(bytecode_caches() - RUN.caches_before)
        if caches:
            problems.append("bytecode caches were written to the repository")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"the repository could not be re-checked ({type(exc).__name__})")


def _record_interruption(outcome: CleanupOutcome, stage: Mapping[str, Any]) -> None:
    """Finish an interrupted cleanup as an explicit failure: mark the outcome, say that the protected
    resources were not re-checked if they were not, and print the last verified identities so that whatever
    remains can be investigated by hand.  It removes nothing and retries nothing."""
    outcome.interrupted = True
    if not stage.get("protected"):
        outcome.protected_problems.append("the protected resources were not re-checked because cleanup was "
                                          "interrupted")
    say("cleanup was INTERRUPTED: the remaining steps did not run and nothing was retried")
    say(f"  last verified identities: {len(CONTAINED.tracked_containers)} containers, "
        f"{len(CONTAINED.tracked_networks)} networks, {len(CONTAINED.tracked_volumes)} named volumes, "
        f"{len(CONTAINED.tracked_anonymous)} anonymous volumes, {len(CONTAINED.tracked_images)} images")
    for name, evidence in sorted(CONTAINED.tracked_anonymous.items()):
        say(f"  anonymous volume {name} (container {evidence['container']}, mount {evidence['destination']})")
    say(f"  inspect whatever carries the label {_LABEL_PROJECT}={PROJECT} and decide by hand; "
        "nothing was removed on the strength of the interruption")


def cleanup_contained(*, profiles: Sequence[str] = ()) -> CleanupOutcome:
    """Give back what this run created and nothing else, and report it in separate parts.  Every step runs
    even if an earlier one failed; an exception in a step is a problem, never a silent success.

    An interrupt (Ctrl-C) is not swallowed and is not a success: it ends the cleanup, keeps every problem found
    so far, and returns an outcome with `interrupted` set and a manual-review problem.  The interrupted step
    is never retried and nothing else is removed because of it; cleanup is not made uninterruptible."""
    section("cleanup (contained)")
    outcome = CleanupOutcome()
    stage: dict[str, Any] = {"name": "starting", "protected": False}
    try:
        _run_cleanup_steps(outcome, profiles, stage)
    except KeyboardInterrupt:
        earlier = CONTAINED.interrupted
        CONTAINED.interrupted = earlier or stage["name"]
        outcome.problems.append(
            ("a further interruption arrived" if earlier else "cleanup was interrupted")
            + f" during {stage['name']}; the remaining steps did not run, nothing was retried, and whatever "
            "remains is left for manual review")
    if CONTAINED.interrupted is not None:
        _record_interruption(outcome, stage)
    return outcome


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def smoke(expect_head: Optional[str]) -> None:
    check_repository(expect_head)
    check_ports()
    record_docker_state()
    create_workspace()
    create_virtual_environment()
    check_render()
    start_kafka()
    create_topics()
    start_postgres()
    run_bootstrap()
    start_collector()
    start_host_services()
    offsets = check_baseline()
    for stage in STAGES:
        # A stage that does not reconcile raises; the next one never runs.
        offsets = run_stage(stage, offsets)
        check_normal_stack(f"after {stage.run_id}")
    check_totals(offsets)


#: What running this file directly prints.  The live path is run_e2e.py, which has the reviewed authorization
#: (plan by default, --execute, the exact confirmation phrase, the full expected HEAD, an approved-tree
#: manifest for a dirty tree) and the resource preflight; this file has none of them, so it starts nothing.
STANDALONE_REFUSAL: str = (
    "run_smoke.py no longer starts live work when it is run directly: it is a library of helpers for the "
    "reviewed harnesses.  Use workload-generator/run_e2e.py, which prints a plan by default; a live run needs "
    "--execute, the full --expect-head, the exact --confirm phrase shown by the plan, an approved-tree "
    "manifest when the working tree is dirty, and a passing resource preflight.  Nothing was started."
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone invocation never starts live work.  The arguments of the old live command are still parsed
    (so --help works and a mistyped option is an error), and every valid invocation prints the refusal and
    returns 2 without touching git, Docker, the filesystem or any host process.  Importers keep using the
    helper functions of this module and smoke() as before."""
    parser = argparse.ArgumentParser(
        prog="run_smoke",
        description="Helpers of the live harnesses.  Run directly, this file starts nothing; use run_e2e.py.",
    )
    parser.add_argument("--expect-head", default=None, metavar="COMMIT",
                        help="accepted for compatibility with the old command; it does not start anything")
    parser.parse_args(argv)
    print(STANDALONE_REFUSAL, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

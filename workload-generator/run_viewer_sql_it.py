"""
workload-generator/run_viewer_sql_it.py

Orchestrator of ONE disposable-PostgreSQL validation of the trace viewer's SQL, session options
and endpoints (Phase 14.6.1).  It creates a separate Compose project with PostgreSQL and the
database bootstrap only, seeds deterministic rows, runs
trace-viewer/tests/integration/test_viewer_sql_live.py against it, and gives everything back:

    python workload-generator/run_viewer_sql_it.py --expect-head <commit>                  # prints the plan
    python workload-generator/run_viewer_sql_it.py --expect-head <commit> --preflight      # reads only
    python workload-generator/run_viewer_sql_it.py --expect-head <commit> --execute --confirm <phrase>

NOTHING here has been run live by its author: the unit tests (tests/unit/test_viewer_sql_it.py) use
fakes for Docker, git and the test runner.  A live run is a separate authorization, once.

It ORCHESTRATES; it does not re-implement.  The gates, protected-resource reads, network snapshots,
the default-bridge rule and the evidence redaction are run_shutdown_it.py's, imported and unchanged
(imported only - none of that harness's code is run); the bootstrap ledger check is run_smoke's; the
project-scoped cleanup is run_pipeline_it.safe_cleanup.  What is new here is the narrow stack, the
loopback port, the test run and its verdict.

Isolation, in the order it is established
    - exact branch, exact HEAD, empty index; the working tree is clean (committed harness) or holds
      exactly this harness's five files untracked (development)
    - a unique project "agentops-viewer-it-<8 hex>", never "agentops", overlapping no protected name,
      and none that any Docker object already carries
    - refuses to start while any sibling harness left a blocking marker, a benchmark marker, a
      benchmark/pipeline/batching/shutdown Docker object or a competing process exists; AC power,
      available memory (4,096 MiB), the Docker engine (3.5 GiB), free disk (10 GiB) and the chosen port
      are gated, and nothing is changed to make a gate pass
    - the MVP containers, the stopped legacy PostgreSQL, both protected networks and the default bridge
      are read before and compared after (the same rules as run_shutdown_it.py)
    - PostgreSQL is published on 127.0.0.1 only, on a randomly chosen free port that is none of the
      ports of the normal stack, the MVP viewer, Grafana or the sibling harnesses; the published binding
      is read back and must be exactly that
    - only the services "postgres" and "db-bootstrap" are ever named: no Kafka, collector, Grafana,
      stream processor, storage consumer or viewer container exists
    - throw-away random passwords in a temporary directory outside the repository (and so outside
      OneDrive); they reach the test process through its environment only, never a command line
    - ONE attempt: a record per HEAD is created exclusively before the first Docker change; a second
      attempt for the same HEAD is refused
    - cleanup is "compose down --volumes --remove-orphans" for this project only (no --rmi) plus the
      removal, by exact name, of images named after this project that carry this project's label;
      shared and pre-existing images (postgres, python, ...) are never touched; nothing is pruned
    - any cleanup doubt writes the blocking marker; the evidence (before and after cleanup, with
      SHA-256) never contains a credential

Exit codes: 0 only for a PASS with verified cleanup and written evidence; 1 otherwise; 2 for a usage error.
Nothing is retried.  Standard library plus the sibling harnesses.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_commit_batching_it as batching  # noqa: E402 - gates and protected-resource guards, unchanged
import run_pipeline_it as pipeline  # noqa: E402 - safe_cleanup and power helpers, unchanged
import run_shutdown_it as shutdown  # noqa: E402 - imported for its helpers only; nothing of it is run
import run_smoke as smoke  # noqa: E402
from run_smoke import SmokeFailure, say, section  # noqa: E402

Shell = Callable[..., "subprocess.CompletedProcess"]

PROJECT_PREFIX: str = "agentops-viewer-it-"
_PROJECT_RE = re.compile(re.escape(PROJECT_PREFIX) + r"[0-9a-f]{8}")
EXPECTED_BRANCH: str = shutdown.EXPECTED_BRANCH
OWN_FILES: tuple[str, ...] = (
    "workload-generator/run_viewer_sql_it.py",
    "workload-generator/tests/unit/test_viewer_sql_it.py",
    "trace-viewer/tests/integration/__init__.py",
    "trace-viewer/tests/integration/conftest.py",
    "trace-viewer/tests/integration/test_viewer_sql_live.py",
)
INTEGRATION_DIR: str = "trace-viewer/tests/integration"
LIVE_TEST_FILE: str = "trace-viewer/tests/integration/test_viewer_sql_live.py"

#: The only services this harness names.  Anything else is refused by compose_command.
SERVICES: tuple[str, ...] = ("postgres", "db-bootstrap")
FORBIDDEN_SERVICES: tuple[str, ...] = (
    "kafka", "kafka-init", "otel-collector", "grafana", "analytics-refresh", "stream-processor",
    "storage-consumer", "trace-viewer", "viewer")
ALLOWED_COMPOSE_VERBS: tuple[str, ...] = ("build", "up", "ps", "exec", "port", "logs", "down")

CONFIRM_PREFIX: str = "CONFIRM-DISPOSABLE-VIEWER-SQL-VALIDATION-"
OWNER_ROLE: str = "agentops"
DATABASE: str = "agentops"
POSTGRES_CONTAINER_PORT: int = 5432
PORT_LOW: int = 20000
PORT_HIGH: int = 29999
#: Never the target: the normal stack, the MVP viewer, Grafana (batching.PROHIBITED_PORTS) and the fixed
#: ports of the sibling harnesses.
PROHIBITED_PORTS: tuple[int, ...] = tuple(sorted({
    *batching.PROHIBITED_PORTS, smoke.OTLP_PORT, smoke.KAFKA_PORT, smoke.POSTGRES_PORT}))
MIN_HOST_MEMORY_MIB: int = shutdown.MIN_HOST_MEMORY_MIB
T_TESTS: float = 600.0

# The environment that approves a target for the live tests (see trace-viewer/tests/integration/conftest.py;
# a unit test keeps the two in step).
ENV_DSN: str = "AGENTOPS_VIEWER_IT_DSN"
ENV_VIEWER_PASSWORD: str = "AGENTOPS_VIEWER_IT_VIEWER_PASSWORD"
ENV_PROJECT: str = "AGENTOPS_VIEWER_IT_PROJECT"
ENV_APPROVAL: str = "AGENTOPS_VIEWER_IT_APPROVAL"

_LABEL_PROJECT = "com.docker.compose.project"
ENV_FILE_NAME: str = "viewer-it.env"
EVIDENCE_SCHEMA: str = "run_viewer_sql_it.evidence/1"
LEDGER_SQL: str = ("SELECT count(*) || '|' || coalesce(string_agg(step, ',' ORDER BY position), '') "
                   "FROM agentops_bootstrap.ledger")

#: The test functions of LIVE_TEST_FILE, by level.  A unit test compares this with the file.
EXPECTED_TESTS: Mapping[str, tuple[str, ...]] = {
    "sql": (
        "test_sql_session_is_read_only_with_five_second_statement_timeout",
        "test_sql_role_cannot_write_or_change_the_schema_even_when_read_write_is_forced",
        "test_sql_statement_timeout_cancels_a_long_statement",
        "test_sql_role_reads_the_granted_relations_and_nothing_wider",
        "test_sql_left_counts_characters_not_bytes",
        "test_sql_limitations_expression_slices_orders_and_shortens",
        "test_sql_evidence_statement_orders_by_rank_then_span_id_limits_and_counts",
    ),
    "query": (
        "test_query_span_text_is_shortened_by_the_database_through_the_dbt_view",
        "test_query_bounded_trace_read_orders_limits_and_reports_truncation",
        "test_query_anomaly_explanation_is_shortened_by_the_database",
        "test_query_rca_text_limitations_and_evidence_totals",
        "test_query_latest_investigation_follows_its_anomaly",
        "test_query_empty_and_missing_results",
    ),
    "endpoint": (
        "test_endpoint_readiness_succeeds_against_the_real_server",
        "test_endpoint_readiness_failure_is_sanitized",
        "test_endpoint_span_text_and_truncation_metadata",
        "test_endpoint_anomaly_and_rca_bounds_and_metadata",
        "test_endpoint_missing_resources_and_empty_filters",
        "test_endpoint_database_errors_are_sanitized",
    ),
    "connection": ("test_connection_timeout_against_a_silent_loopback_listener",),
}
ALL_EXPECTED_TESTS: tuple[str, ...] = tuple(name for names in EXPECTED_TESTS.values() for name in names)


# ---------------------------------------------------------------------------
# Names, ports, override and credentials
# ---------------------------------------------------------------------------

def new_project_name() -> str:
    return PROJECT_PREFIX + uuid.uuid4().hex[:8]


def validate_project_name(name: str, docker_lines: Sequence[str]) -> None:
    if name == "agentops":
        raise SmokeFailure("the project name must never be the default 'agentops'")
    if not _PROJECT_RE.fullmatch(name):
        raise SmokeFailure(f"project name {name!r} is not {PROJECT_PREFIX}<8 hex>")
    for token in shutdown.PROTECTED_TOKENS:
        if name.startswith(token) or token.startswith(name):
            raise SmokeFailure(f"project name {name!r} overlaps the protected name {token!r}")
    taken = [line for line in docker_lines if name in line]
    if taken:
        raise SmokeFailure("Docker objects of this project name already exist:\n" + "\n".join(taken[:6]))


def allocate_port(probe: Callable[[int], Optional[bool]] = shutdown.free_port_probe,
                  choose: Optional[Callable[[int, int], int]] = None, attempts: int = 50) -> int:
    """A random loopback port in PORT_LOW..PORT_HIGH that is not prohibited and that the probe reports free (False)."""
    pick = choose or (lambda low, high: low + secrets.randbelow(high - low + 1))
    tried: set[int] = set()
    for _ in range(attempts):
        port = pick(PORT_LOW, PORT_HIGH)
        if port in PROHIBITED_PORTS or port in tried:
            continue
        tried.add(port)
        if probe(port) is False:
            return port
    raise SmokeFailure("no free loopback port could be found")


def check_port(port: Any) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not PORT_LOW <= port <= PORT_HIGH or port in PROHIBITED_PORTS:
        raise SmokeFailure(f"{port!r} is not an allowed loopback port ({PORT_LOW}-{PORT_HIGH}, none of the protected ports)")
    return port


def override_text(port: int) -> str:
    """The one extra Compose file: written to the temporary directory, never to the repository.  It moves the
    published PostgreSQL port (set to 15432 on 127.0.0.1 by the smoke override) to the chosen loopback port."""
    check_port(port)
    return "\n".join([
        "# Written by run_viewer_sql_it.py into its temporary directory; never in the repository.",
        "services:",
        "  postgres:",
        "    ports: !override",
        f'      - "127.0.0.1:{port}:{POSTGRES_CONTAINER_PORT}"',
    ]) + "\n"


def compose_files(override: Path) -> list[str]:
    return [smoke.COMPOSE_FILE, smoke.OVERRIDE_FILE, str(override)]


def compose_command(project: str, override: Path, env_file: Path, *args: str) -> list[str]:
    """Every Compose command of this harness.  Refuses another project, another verb, another service, --rmi."""
    if project == "agentops" or not _PROJECT_RE.fullmatch(project):
        raise SmokeFailure(f"refusing a Compose command for the project {project!r}")
    if not args or args[0] not in ALLOWED_COMPOSE_VERBS:
        raise SmokeFailure(f"refusing the Compose command {args[:1]!r}")
    for argument in args:
        if argument in FORBIDDEN_SERVICES or argument == "--rmi":
            raise SmokeFailure(f"refusing {argument!r}: this harness starts PostgreSQL and the bootstrap only")
    if args[0] in ("build", "up"):
        named = [a for a in args[1:] if not a.startswith("-")]
        if sorted(named) != sorted(SERVICES):
            raise SmokeFailure(f"{args[0]} must name exactly {', '.join(SERVICES)}")
    if args[0] == "down" and tuple(args) != ("down", "--volumes", "--remove-orphans"):
        raise SmokeFailure("down must be exactly: down --volumes --remove-orphans")
    command = ["docker", "compose", "-p", project]
    for path in compose_files(override):
        command += ["-f", path]
    return [*command, "--env-file", str(env_file), *args]


def generate_credentials() -> dict[str, str]:
    return shutdown.generate_credentials()


def env_file_text(credentials: Mapping[str, str]) -> str:
    return shutdown.env_file_text(credentials)


def approval_token(project: str, port: int) -> str:
    return f"disposable-loopback:{project}:{port}"


def integration_environment(project: str, port: int, credentials: Mapping[str, str]) -> dict[str, str]:
    """The environment of the test process: the approval for exactly this target.  Passwords travel here only."""
    check_port(port)
    dsn = f"postgresql://{OWNER_ROLE}:{credentials['POSTGRES_PASSWORD']}@127.0.0.1:{port}/{DATABASE}"
    return smoke.host_environment(**{
        ENV_DSN: dsn, ENV_VIEWER_PASSWORD: credentials["TRACE_VIEWER_DB_PASSWORD"],
        ENV_PROJECT: project, ENV_APPROVAL: approval_token(project, port)})


def confirmation_phrase(expect_head: str) -> str:
    return CONFIRM_PREFIX + expect_head[:12]


def check_confirmation(given: Optional[str], expect_head: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expect_head or ""):
        raise SmokeFailure("--expect-head needs a full 40-character commit")
    if given != confirmation_phrase(expect_head):
        raise SmokeFailure("live execution needs --confirm " + confirmation_phrase(expect_head))


def unsupported_host(windows: Optional[Callable[[], bool]] = None) -> Optional[str]:
    """Why a live run is refused on this host, or None.  Pure: no file, process, Docker or Git access.  The platform
    test is the deletion guard's own (smoke._windows), looked up when called, so the two cannot disagree."""
    is_windows = windows if windows is not None else smoke._windows
    if is_windows():
        return ("unsupported host: automatic recursive cleanup is disabled on Windows (run_smoke._remove_tree), "
                "so this integration harness cannot verify its cleanup. Nothing was started or created.")
    return None


#: Beside the repository and smoke._PROTECTED_TREES, no workspace may be, lie inside or contain these.
WORKSPACE_PROTECTED: tuple[str, ...] = (r"C:\AgentOps-TestSandbox",)
WORKSPACE_PREFIX: str = "viewer-it-"


def workspace_problem(path: Path) -> Optional[str]:
    """Why path may not become this run's workspace, or None.  Checked before the workspace is registered; it reads the
    environment and resolves the temporary root, and creates and deletes nothing.  The deletion-time guard
    (run_smoke._deletion_refusal) still decides every deletion.  Anything that cannot be checked is refused."""
    try:
        key = smoke._norm(path)
        protected = [smoke.REPO, *smoke._PROTECTED_TREES, *WORKSPACE_PROTECTED]
        local = os.environ.get("LOCALAPPDATA")
        if local:
            protected.append(os.path.join(local, "agentops-backups"))
        protected += [v for v in (os.environ.get(n) for n in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")) if v]
        for tree in map(smoke._norm, protected):
            if smoke._within(key, tree) or smoke._within(tree, key):
                return f"a protected location or one of its ancestors ({tree})"
        root = smoke._norm(Path(tempfile.gettempdir()).resolve())
        if key == root or not smoke._within(key, root):
            return "not inside the system temporary directory"
        if not Path(path).name.startswith(WORKSPACE_PREFIX):
            return "not named like this harness's workspace"
    except Exception as exc:  # noqa: BLE001 - fail closed
        return f"could not be checked ({type(exc).__name__}: {exc})"
    return None


# ---------------------------------------------------------------------------
# Markers, attempts
# ---------------------------------------------------------------------------

def marker_dir(root: Optional[Path] = None) -> Path:
    return Path(tempfile.gettempdir()) / "agentops-viewer-it" if root is None else Path(root)


def marker_path(root: Optional[Path] = None) -> Path:
    return marker_dir(root) / "CLEANUP_UNVERIFIED"


def own_markers(root: Optional[Path] = None) -> list[str]:
    """Blocking markers of this harness and of the shutdown harness (an unverified cleanup of either blocks both)."""
    found = ["viewer-it:CLEANUP_UNVERIFIED"] if marker_path(root).exists() else []
    return found + [f"shutdown-it:{name}" for name in shutdown.own_markers()]


def write_marker(reason: str, root: Optional[Path] = None) -> Path:
    path = marker_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(reason[:2000] + "\n", encoding="utf-8")
    return path


def attempts_dir(root: Optional[Path] = None) -> Path:
    return Path(tempfile.gettempdir()) / "agentops-viewer-it-attempts" if root is None else Path(root)


def record_attempt(expect_head: str, project: str, directory: Optional[Path] = None, stamp: str = "") -> Path:
    """The single-attempt rule: one record per HEAD, created exclusively.  A second attempt for the same HEAD is refused."""
    folder = attempts_dir(directory)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"attempt-{expect_head[:12]}.txt"
    try:
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(f"{project} {stamp}\n")
    except FileExistsError:
        raise SmokeFailure(f"an attempt for HEAD {expect_head[:12]} was already made ({path.name}); "
                           "a live validation runs once per authorization") from None
    return path


# ---------------------------------------------------------------------------
# Gates and preflight
# ---------------------------------------------------------------------------

def host_gate_problems(readings: "shutdown.Readings", port: int) -> list[str]:
    """Power, host memory, disk and the chosen port: an unmeasurable reading is an unmet gate."""
    problems = []
    if readings.power_source is None:
        problems.append("the power source could not be read")
    elif readings.power_source != "AC":
        problems.append(f"the machine is on {readings.power_source}, not AC power")
    mib = readings.available_mib
    if mib is None or isinstance(mib, bool) or not isinstance(mib, (int, float)) or mib != mib:
        problems.append("available host memory could not be read")
    elif mib < MIN_HOST_MEMORY_MIB:
        problems.append(f"available host memory {mib:.0f} MiB is below {MIN_HOST_MEMORY_MIB} MiB")
    disk = batching.disk_gate(readings.free_disk_bytes)
    if not disk.ok:
        problems.append(disk.message)
    state = readings.ports_in_use.get(port)
    if state is None:
        problems.append(f"port {port} could not be checked")
    elif state:
        problems.append(f"port {port} is in use")
    return problems


def find_blockers(*, benchmark_markers: Sequence[str], own_markers_found: Sequence[str],
                  docker_lines: Sequence[str], processes: Sequence[str]) -> list[str]:
    blockers = [f"benchmark marker {name}" for name in benchmark_markers]
    blockers += [f"unverified cleanup marker {name}" for name in own_markers_found]
    for line in docker_lines:
        for needle, what in ((batching.BENCHMARK_PROJECT, "benchmark"), (batching.PIPELINE_IT_PREFIX, "pipeline test"),
                             ("agentops-batching-it-", "batching validation"),
                             (shutdown.PROJECT_PREFIX, "shutdown validation"), (PROJECT_PREFIX, "earlier viewer validation")):
            if needle in line:
                blockers.append(f"{what} Docker object: {line.strip()[:120]}")
                break
    blockers += [f"process {pid}" for pid in processes if str(pid).strip()]
    return blockers


@dataclasses.dataclass
class Preflight:
    project: str
    port: int
    git_state: str
    before: dict[str, list[str]]
    protected_before: dict[str, Optional[str]]
    readings: "shutdown.Readings"
    networks: "shutdown.NetworkSnapshot"


def run_preflight(sh: Shell, repo: Path, expect_head: str, *, docker_data_dir: Optional[Path],
                  power: Callable[[], tuple[str, int]] = pipeline.power_state,
                  memory: Callable[[], float] = batching.available_memory_mib,
                  disk: Callable[[Path], float] = lambda p: shutil.disk_usage(str(p)).free,
                  port_probe: Callable[[int], Optional[bool]] = shutdown.free_port_probe,
                  markers: Callable[[], list[str]] = batching.benchmark_markers,
                  processes: Callable[[], list[str]] = batching.competing_processes,
                  own: Callable[[], list[str]] = own_markers,
                  inventory: Optional[Callable[[], dict[str, list[str]]]] = None,
                  snapshot: Optional[Callable[[], dict[str, Optional[str]]]] = None,
                  network_reader: Optional[Callable[[], "shutdown.NetworkSnapshot"]] = None,
                  name: Optional[str] = None, port: Optional[int] = None) -> Preflight:
    """Everything that must hold before a live run.  Read-only.  Nothing that needs Docker is touched until the git
    state and every host gate have passed."""
    state = shutdown.git_state(sh, repo, expect_head, branch=EXPECTED_BRANCH, own_files=OWN_FILES)
    chosen = check_port(port) if port is not None else allocate_port(port_probe)
    readings = shutdown.Readings(ports_in_use={chosen: port_probe(chosen)})
    try:
        readings.power_source, readings.battery_percent = power()
    except Exception:  # noqa: BLE001 - unmeasurable is a failed gate
        pass
    try:
        readings.available_mib = memory()
    except Exception:  # noqa: BLE001
        pass
    try:
        readings.free_disk_bytes = disk(docker_data_dir) if docker_data_dir and Path(docker_data_dir).exists() else None
    except Exception:  # noqa: BLE001
        pass
    host_problems = host_gate_problems(readings, chosen)
    early = find_blockers(benchmark_markers=markers(), own_markers_found=own(), docker_lines=[], processes=processes())
    if host_problems or early:
        raise SmokeFailure("preflight failed before any Docker command:\n" + "\n".join([*host_problems, *early]))

    # From here on Docker is only read.
    info = json.loads(shutdown._checked(sh, ["docker", "info", "--format", "{{json .}}"], what="docker info"))
    readings.engine_bytes = info.get("MemTotal") if isinstance(info.get("MemTotal"), int) else None
    engine = shutdown.engine_problem(readings.engine_bytes)
    if engine:
        raise SmokeFailure(engine)
    before = inventory() if inventory else shutdown._inventory(sh)
    lines = [line for kind in before.values() for line in kind]
    blockers = find_blockers(benchmark_markers=[], own_markers_found=[], docker_lines=lines, processes=[])
    if blockers:
        raise SmokeFailure("preflight blockers:\n" + "\n".join(blockers))
    protected = (snapshot or (lambda: shutdown._protected_snapshot(sh)))()
    legacy = batching.legacy_problem(protected.get(batching.LEGACY_POSTGRES))
    if legacy:
        raise SmokeFailure(legacy)
    networks = (network_reader or (lambda: shutdown.read_network_snapshot(sh)))()
    network_problems = [*(["the default bridge is not verified: " + "; ".join(networks.bridge_problems)]
                          if not networks.bridge_verified else []),
                        *(f"protected network {n} was not found" for n, facts in networks.users.items() if facts is None)]
    if network_problems:
        raise SmokeFailure("network preflight failed before any Docker change:\n" + "\n".join(network_problems))
    project = name or new_project_name()
    validate_project_name(project, lines)
    return Preflight(project, chosen, state, before, protected, readings, networks)


# ---------------------------------------------------------------------------
# The disposable stack
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ContainerState:
    status: str
    health: str
    exit_code: int


def parse_container_state(text: str) -> ContainerState:
    parts = text.strip().split("|")
    if len(parts) != 3 or not parts[0] or not re.fullmatch(r"-?\d+", parts[2]):
        raise SmokeFailure("the container state was not readable")
    return ContainerState(parts[0], parts[1], int(parts[2]))


def verify_port_binding(text: str, port: int) -> list[str]:
    """Why the published PostgreSQL binding is not exactly 127.0.0.1:<port> (empty = it is).  Reads
    `docker inspect -f '{{json .HostConfig.PortBindings}}'`."""
    try:
        body = json.loads(text)
    except ValueError:
        return ["the port bindings were not readable JSON"]
    if not isinstance(body, dict) or set(body) != {f"{POSTGRES_CONTAINER_PORT}/tcp"}:
        return [f"the container publishes {sorted(body) if isinstance(body, dict) else body!r}, expected only 5432/tcp"]
    bindings = body[f"{POSTGRES_CONTAINER_PORT}/tcp"]
    if not isinstance(bindings, list) or len(bindings) != 1 or not isinstance(bindings[0], dict):
        return ["PostgreSQL is not published exactly once"]
    problems = []
    if bindings[0].get("HostIp") != "127.0.0.1":
        problems.append(f"PostgreSQL is published on {bindings[0].get('HostIp')!r}, not 127.0.0.1")
    if bindings[0].get("HostPort") != str(port):
        problems.append(f"PostgreSQL is published on port {bindings[0].get('HostPort')!r}, not {port}")
    return problems


class Stack:
    """Every command names the project, the three Compose files and the temporary environment file."""

    def __init__(self, project: str, override: Path, env_file: Path, sh: Shell) -> None:
        self.project, self.override, self.env_file, self.sh = project, override, env_file, sh

    def compose(self, *args: str, timeout: float = smoke.T_COMMAND, what: str = "") -> str:
        return shutdown._checked(self.sh, compose_command(self.project, self.override, self.env_file, *args),
                                 what=what or "compose " + args[0], timeout=timeout)

    def container_id(self, service: str) -> str:
        found = self.compose("ps", "-a", "-q", service).split()
        if len(found) != 1 or not re.fullmatch(r"[0-9a-f]{64}", found[0]):
            raise SmokeFailure(f"{service}: expected one container, found {len(found)}")
        return found[0]

    def state(self, service: str) -> ContainerState:
        text = shutdown._checked(
            self.sh, ["docker", "inspect", "-f",
                      "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}",
                      self.container_id(service)], what="docker inspect")
        return parse_container_state(text)

    def port_bindings(self, service: str = "postgres") -> str:
        return shutdown._checked(
            self.sh, ["docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", self.container_id(service)],
            what="docker inspect port bindings")

    def logs(self, service: str) -> str:
        return self.compose("logs", "--no-color", "--no-log-prefix", service, what=f"logs {service}")

    def ledger(self) -> str:
        return self.compose("exec", "-T", "postgres", "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-U", OWNER_ROLE,
                            "-d", DATABASE, "-c", LEDGER_SQL, what="bootstrap ledger").strip()


def wait_until(what: str, timeout: float, probe: Callable[[], Any], interval: float = 3.0,
               clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep) -> Any:
    deadline = clock() + timeout
    while True:
        value = probe()
        if value:
            return value
        if clock() >= deadline:
            raise SmokeFailure(f"timed out after {timeout:.0f}s waiting for {what}")
        sleeper(interval)


def start_and_bootstrap(stack: Stack, port: int, clock: Callable[[], float] = time.monotonic,
                        sleeper: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Build, start PostgreSQL and the bootstrap, wait, and verify the exact ledger and the exact published binding."""
    stack.compose("build", *SERVICES, timeout=smoke.T_BUILD, what="compose build")
    stack.compose("up", "-d", "--no-build", *SERVICES, timeout=smoke.T_BOOTSTRAP, what="compose up")
    wait_until("postgres to be healthy", smoke.T_POSTGRES, lambda: (lambda s: s.status == "running" and s.health == "healthy")(
        stack.state("postgres")), 2.0, clock, sleeper)
    wait_until("db-bootstrap to finish", smoke.T_BOOTSTRAP, lambda: stack.state("db-bootstrap").status == "exited", 3.0,
               clock, sleeper)
    code = stack.state("db-bootstrap").exit_code
    if code != 0:
        raise SmokeFailure(f"the database bootstrap exited {code}")
    found = stack.ledger()
    problem = smoke.ledger_problem(found)
    if problem:
        raise SmokeFailure(problem)
    binding = verify_port_binding(stack.port_bindings(), port)
    if binding:
        raise SmokeFailure("the published PostgreSQL binding is wrong: " + "; ".join(binding))
    return {"ledger_steps": smoke.LEDGER_STEPS, "ledger_complete": True, "binding": f"127.0.0.1:{port}"}


# ---------------------------------------------------------------------------
# The test run
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class TestRun:
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False

    __test__ = False                 # not a pytest test class


@dataclasses.dataclass(frozen=True)
class TestOutcome:
    name: str
    base: str
    outcome: str                     # passed, failed, error, skipped
    seconds: float
    detail: str

    __test__ = False


TestRunner = Callable[[Sequence[str], Mapping[str, str], float, Path], TestRun]


def _default_test_runner(command: Sequence[str], env: Mapping[str, str], timeout: float, cwd: Path) -> TestRun:
    try:
        result = subprocess.run(list(command), cwd=str(cwd), env=dict(env), capture_output=True, text=True,
                                errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        def text(value: Any) -> str:
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
        return TestRun(None, text(expired.stdout), text(expired.stderr), True)
    return TestRun(result.returncode, result.stdout, result.stderr)


def pytest_command(junit: Path) -> list[str]:
    """pytest, on the integration directory only, with no cache plugin and a JUnit report in the temporary directory."""
    return [sys.executable, "-m", "pytest", INTEGRATION_DIR, "-q", "-p", "no:cacheprovider", "-rs",
            "--junitxml", str(junit)]



def parse_junit(text: str) -> list[TestOutcome]:
    """The test cases of a JUnit report.  Raises SmokeFailure when the report cannot be read."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise SmokeFailure("the JUnit report was not readable") from None
    outcomes = []
    for case in root.iter("testcase"):
        name = case.get("name") or ""
        outcome, detail = "passed", ""
        for tag, label in (("failure", "failed"), ("error", "error"), ("skipped", "skipped")):
            child = case.find(tag)
            if child is not None:
                outcome, detail = label, (child.get("message") or child.text or "")[:300]
                break
        try:
            seconds = float(case.get("time") or 0.0)
        except ValueError:
            seconds = 0.0
        outcomes.append(TestOutcome(name, name.split("[", 1)[0], outcome, seconds, detail))
    return outcomes


def level_of(base: str) -> str:
    for level, names in EXPECTED_TESTS.items():
        if base in names:
            return level
    return "unknown"


@dataclasses.dataclass
class TestsVerdict:
    verdict: str                     # PASS, FAIL or INCONCLUSIVE
    problems: list[str]
    tests: list[dict[str, Any]]

    __test__ = False


def evaluate_tests(outcomes: Sequence[TestOutcome], run: TestRun) -> TestsVerdict:
    """PASS needs every expected test function to have run and passed, nothing skipped, nothing unexpected.
    A failure is FAIL; a skip, a missing or unexpected test, a timeout or an unreadable report is INCONCLUSIVE
    (the SQL was not shown to be right or wrong)."""
    summary = [{"name": o.name, "level": level_of(o.base), "outcome": o.outcome, "seconds": round(o.seconds, 2),
                "detail": o.detail} for o in outcomes]
    problems: list[str] = []
    if run.timed_out:
        return TestsVerdict("INCONCLUSIVE", ["pytest did not finish within the time limit"], summary)
    if not outcomes:
        return TestsVerdict("INCONCLUSIVE", ["the test report holds no test case"], summary)
    failed = [o.name for o in outcomes if o.outcome in ("failed", "error")]
    skipped = [o.name for o in outcomes if o.outcome == "skipped"]
    ran = {o.base for o in outcomes}
    missing = [name for name in ALL_EXPECTED_TESTS if name not in ran]
    unexpected = sorted(ran - set(ALL_EXPECTED_TESTS))
    if failed:
        return TestsVerdict("FAIL", [f"{len(failed)} test case(s) failed: " + ", ".join(failed[:6])], summary)
    if skipped:
        problems.append(f"{len(skipped)} test case(s) were skipped (the approval was not accepted?): " + ", ".join(skipped[:4]))
    if missing:
        problems.append("expected test(s) did not run: " + ", ".join(missing[:4]))
    if unexpected:
        problems.append("unexpected test(s) ran: " + ", ".join(unexpected[:4]))
    if problems:
        return TestsVerdict("INCONCLUSIVE", problems, summary)
    if run.returncode != 0:
        return TestsVerdict("FAIL", [f"pytest exited {run.returncode} although every case passed"], summary)
    return TestsVerdict("PASS", [], summary)


def final_verdict(tests: Optional[TestsVerdict], *, cleanup_verified: bool, failure: str,
                  evidence_problems: Sequence[str]) -> str:
    """Never turns a FAIL or an INCONCLUSIVE into a PASS; a failure, an unverified cleanup or missing evidence is a FAIL."""
    if failure or evidence_problems or not cleanup_verified:
        return "FAIL"
    return tests.verdict if tests is not None else "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

class ViewerOps:
    """What cleanup touches, scoped by the project name; the interface pipeline.safe_cleanup uses.  It never passes
    --rmi: its own images are removed one by one by exact name, and only when they carry its Compose label."""

    def __init__(self, project: str, override: Optional[Path], env_file: Optional[Path], sh: Shell,
                 temp: Optional[Path], status_before: Optional[Sequence[str]] = None,
                 protected_before: Optional[Mapping[str, Optional[str]]] = None,
                 networks_before: Optional["shutdown.NetworkSnapshot"] = None) -> None:
        if project == "agentops" or not _PROJECT_RE.fullmatch(project):
            raise SmokeFailure(f"cleanup refuses the project name {project!r}")
        self.project, self.override, self.env_file, self.sh, self.temp = project, override, env_file, sh, temp
        self.status_before, self.protected_before = status_before, protected_before
        self.networks_before = networks_before
        self.networks_after: Optional["shutdown.NetworkSnapshot"] = None
        self.log: list[str] = []
        self.down_command: list[str] = []

    def can_down(self) -> bool:
        return bool(self.override is not None and self.env_file is not None and Path(self.env_file).is_file())

    def down(self) -> tuple[int, str]:
        self.down_command = compose_command(self.project, self.override, self.env_file,  # type: ignore[arg-type]
                                            "down", "--volumes", "--remove-orphans")
        result = self.sh(self.down_command, timeout=smoke.T_DOWN, what="compose down")
        tail = smoke.redact(result.stderr.strip()[-300:])
        self.log.append(f"compose down (project {self.project}): exit {result.returncode}\n{tail}")
        return result.returncode, tail

    def project_objects(self, kind: str) -> list[str]:
        label = f"label={_LABEL_PROJECT}={self.project}"
        command = {"containers": ["ps", "-a", "-q", "--filter", label],
                   "networks": ["network", "ls", "-q", "--filter", label],
                   "volumes": ["volume", "ls", "-q", "--filter", label],
                   "images": ["images", "-q", "--filter", label]}[kind]
        return shutdown._lines(self.sh, *command)

    def owned_images(self) -> list[str]:
        listed = shutdown._lines(self.sh, "images", "--filter", f"label={_LABEL_PROJECT}={self.project}",
                                 "--format", "{{.Repository}}:{{.Tag}}")
        return [ref for ref in listed if ref.startswith(self.project + "-") and "<none>" not in ref]

    def remove_image(self, reference: str) -> bool:
        if not reference.startswith(self.project + "-"):
            raise SmokeFailure(f"refusing to remove {reference!r}: not named after the project")
        result = self.sh(["docker", "image", "remove", reference], timeout=smoke.T_COMMAND, what="docker image remove")
        self.log.append(f"image remove {reference}: exit {result.returncode}")
        return result.returncode == 0

    def fingerprint(self) -> dict[str, list[str]]:
        raw = shutdown._inventory(self.sh)
        if self.networks_before is None:
            return raw
        self.networks_after = shutdown.read_network_snapshot(self.sh)
        return shutdown.normalise_bridge(raw, self.networks_after)

    def leaked(self) -> int:
        count = smoke.RUN.masked_in_logs
        if self.temp is not None and Path(self.temp).exists():
            for path in Path(self.temp).glob("*"):
                if path.is_file() and path.name != ENV_FILE_NAME:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    count += sum(text.count(v) for v in smoke.RUN.generated.values() if v)
        return count

    def remove_temp(self) -> bool:
        if self.temp is None:
            return True
        resolved = Path(self.temp).resolve()
        root = Path(tempfile.gettempdir()).resolve()
        if resolved == smoke.REPO or smoke.REPO in resolved.parents or root not in resolved.parents:
            raise SmokeFailure(f"refusing to delete {resolved}: not a temporary directory")
        return smoke._remove_tree(resolved)

    def repository_problems(self) -> list[str]:
        problems = []
        try:
            now = sorted(line for line in shutdown._checked(
                self.sh, ["git", "-C", str(smoke.REPO), "status", "--porcelain", "--untracked-files=all"],
                what="git status").splitlines() if line.strip())
            if self.status_before is not None and now != sorted(self.status_before):
                problems.append("the repository changed during the run: " + ", ".join(sorted(set(now) ^ set(self.status_before))))
        except SmokeFailure as failure:
            problems.append(str(failure))
        return problems

    def normal_stack_problem(self) -> Optional[str]:
        if self.protected_before is None:
            return None
        problems = batching.protected_changes(self.protected_before, shutdown._protected_snapshot(self.sh))
        return "; ".join(problems) if problems else None


def cleanup_detailed(ops: ViewerOps, before: Optional[dict[str, list[str]]],
                     report: Callable[[str], None] = say) -> "shutdown.CleanupResult":
    """pipeline.safe_cleanup plus the protected-inventory and network comparisons, kept as data for the evidence.
    An exception anywhere is itself a problem, never a silent success."""
    result = shutdown.CleanupResult(problems=[])

    def honest(text: str) -> None:
        report(text.replace("compose down --volumes --rmi local --remove-orphans",
                            "compose down --volumes --remove-orphans (no --rmi: own images are removed by exact name)"))
    compared = (shutdown.normalise_bridge(before, ops.networks_before)
                if before is not None and ops.networks_before is not None else before)
    try:
        result.problems.extend(pipeline.safe_cleanup(ops.project, compared, ops, honest))
        if before is not None:
            after = ops.fingerprint()
            result.inventory_before, result.inventory_after = shutdown.fingerprint_summary(compared), shutdown.fingerprint_summary(after)
            result.protected_inventory_problems = shutdown.protected_inventory_problems(compared, after)
            result.problems.extend(result.protected_inventory_problems)
        if ops.networks_before is not None:
            networks_after = ops.networks_after or shutdown.read_network_snapshot(ops.sh)
            result.network_report = shutdown.compare_networks(ops.networks_before, networks_after)
            result.problems.extend(result.network_report["problems"])
        if ops.protected_before is not None:
            result.protected_before = dict(ops.protected_before)
            result.protected_after = shutdown._protected_snapshot(ops.sh)
            result.protected_changes = batching.protected_changes(result.protected_before, result.protected_after)
    except Exception as exc:  # noqa: BLE001
        result.problems.append(f"cleanup could not be completed: {type(exc).__name__}: {exc}")
    return result


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return shutdown.utc_now_iso()


def default_evidence_dir() -> Path:
    return Path(tempfile.gettempdir()) / "agentops-viewer-it-evidence"


def evidence_dir_problem(directory: Path, repo: Optional[Path] = None) -> Optional[str]:
    """Why this directory may not hold evidence: inside the repository, the benchmark area or a marker directory."""
    problem = shutdown.evidence_dir_problem(directory, repo)
    if problem:
        return problem
    resolved = Path(directory).resolve()
    for folder in (marker_dir(), attempts_dir()):
        folder = folder.resolve()
        if resolved == folder or folder in resolved.parents:
            return f"{resolved} is inside a marker or attempt directory"
    return None


def evidence_filename(project: str, kind: str, stamp: str, attempt: int = 0) -> str:
    return f"viewer-it-{stamp}-{project}-{kind}" + (f"-{attempt}" if attempt else "") + ".json"


def tail_lines(text: str, limit: int = 60) -> list[str]:
    return [shutdown.bounded_excerpt(shutdown.redact_text(line), 300) for line in text.splitlines()[-limit:]]


def build_evidence(*, kind: str, project: str, port: Optional[int], git_head: str, git_state: str, verdict: str,
                   started_utc: str, finished_utc: str, failure: str, tests: Optional[TestsVerdict] = None,
                   test_run: Optional[TestRun] = None, stack_facts: Optional[Mapping[str, Any]] = None,
                   evidence_problems: Sequence[str] = (), cleanup: Optional["shutdown.CleanupResult"] = None,
                   precleanup: Optional[Mapping[str, str]] = None,
                   diagnostics: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA, "kind": kind, "project": project, "loopback_port": port,
        "git_head": git_head, "git_state": git_state, "attempt": 1, "started_utc": started_utc,
        "finished_utc": finished_utc, "failure": shutdown.redact_text(failure)[:2000], "verdict": verdict,
        "verdict_note": ("provisional: cleanup had not yet been performed" if kind == "pre-cleanup"
                         else "final: after cleanup and evidence writing"),
        "claims": "SQL and endpoint behaviour on the disposable PostgreSQL only; no production claim",
        "services": list(SERVICES), "evidence_problems": list(evidence_problems),
        "stack": dict(stack_facts or {}),
    }
    if tests is not None:
        record["tests"] = {"verdict": tests.verdict, "problems": tests.problems, "cases": tests.tests,
                           "expected_functions": len(ALL_EXPECTED_TESTS)}
    if test_run is not None:
        record["pytest"] = {"returncode": test_run.returncode, "timed_out": test_run.timed_out,
                            "stdout_tail": tail_lines(test_run.stdout), "stderr_tail": tail_lines(test_run.stderr, 20)}
    if cleanup is not None:
        record["cleanup"] = {
            "verified": cleanup.verified, "problems": [shutdown.redact_text(p) for p in cleanup.problems],
            "inventory_before": cleanup.inventory_before, "inventory_after": cleanup.inventory_after,
            "protected_inventory_problems": cleanup.protected_inventory_problems,
            "protected_containers_before": cleanup.protected_before, "protected_containers_after": cleanup.protected_after,
            "protected_container_changes": cleanup.protected_changes,
        }
        if cleanup.network_report:
            record["cleanup"]["networks"] = cleanup.network_report
    if precleanup is not None:
        record["pre_cleanup_file"] = dict(precleanup)
    if diagnostics:
        record["diagnostics"] = dict(diagnostics)
    return record


def write_evidence(directory: Path, project: str, kind: str, record: Mapping[str, Any], stamp: str) -> tuple[Path, str]:
    """Writes one new evidence file and returns (path, sha256).  Never overwrites; refuses a directory inside the
    repository, the benchmark area or a marker directory; refuses text holding a generated credential; reads the
    file back and compares its hash."""
    problem = evidence_dir_problem(directory)
    if problem:
        raise SmokeFailure("evidence directory refused: " + problem)
    text = smoke.redact(shutdown.serialize_evidence(shutdown.redact_structure(record)))
    if shutdown.credential_leaks(text):
        raise SmokeFailure("evidence refused: a generated credential would have been written")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    for attempt in range(10):
        path = directory / evidence_filename(project, kind, stamp, attempt)
        try:
            with open(path, "xb") as handle:
                handle.write(data)
        except FileExistsError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SmokeFailure(f"evidence file {path} did not read back as written")
        return path, digest
    raise SmokeFailure("no unique evidence filename was available")


# ---------------------------------------------------------------------------
# Plan and command line
# ---------------------------------------------------------------------------

def plan_text(project: str, expect_head: Optional[str]) -> str:
    return "\n".join([
        "run_viewer_sql_it.py: plan (nothing is created or started by this text)",
        f"  a disposable project {PROJECT_PREFIX}<8 hex> (this run: {project}), services {', '.join(SERVICES)} only",
        f"  PostgreSQL on 127.0.0.1 at a random free port in {PORT_LOW}-{PORT_HIGH}, none of {', '.join(map(str, PROHIBITED_PORTS))}",
        f"  compose files: {', '.join(compose_files(Path('<temporary>/override.yml')))}",
        f"  tests: {INTEGRATION_DIR} ({len(ALL_EXPECTED_TESTS)} test functions: "
        + ", ".join(f"{len(names)} {level}" for level, names in EXPECTED_TESTS.items()) + ")",
        "  a live run happens once per authorization: --execute --confirm "
        + (confirmation_phrase(expect_head) if expect_head else CONFIRM_PREFIX + "<12 hex of HEAD>"),
        "  cleanup: compose down --volumes --remove-orphans (no --rmi) and own images by exact name; fail-closed marker",
        "  claims: SQL and endpoint behaviour on the disposable PostgreSQL only",
    ])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run_viewer_sql_it", description=__doc__.split("\n")[1] if __doc__ else "")
    parser.add_argument("--expect-head", metavar="COMMIT")
    parser.add_argument("--preflight", action="store_true", help="read-only checks; nothing is created")
    parser.add_argument("--execute", action="store_true", help="the live run; needs --confirm")
    parser.add_argument("--confirm", metavar="PHRASE")
    parser.add_argument("--docker-data-dir", type=Path, default=None)
    return parser


def _default_shell(command: Sequence[str], *, timeout: float, what: str = "") -> "subprocess.CompletedProcess":
    return smoke.run(command, timeout=timeout, what=what)


def execute(args: argparse.Namespace, sh: Shell = _default_shell,
            preflight: Callable[..., Preflight] = run_preflight,
            run_tests: TestRunner = _default_test_runner,
            sleeper: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.monotonic,
            evidence_dir: Optional[Path] = None, attempts_root: Optional[Path] = None,
            marker_root: Optional[Path] = None, utc: Callable[[], str] = utc_now_iso, *,
            windows: Optional[Callable[[], bool]] = None) -> int:
    """The live run.  Only reached with --execute and a matching --confirm."""
    reason = unsupported_host(windows)       # first: before the confirmation, the preflight callback and every side effect
    if reason:
        raise SmokeFailure(reason)
    check_confirmation(args.confirm, args.expect_head)
    started_utc = utc()
    evidence_directory = Path(evidence_dir) if evidence_dir is not None else default_evidence_dir()
    data_dir = args.docker_data_dir or shutdown.default_docker_data_dir()
    pre = preflight(sh, smoke.REPO, args.expect_head, docker_data_dir=data_dir)
    project, port = pre.project, pre.port
    record_attempt(args.expect_head, project, attempts_root, started_utc)       # before the first Docker change
    section(f"disposable project {project} (git state: {pre.git_state}; PostgreSQL on 127.0.0.1:{port})")
    status_before = sorted(line for line in shutdown._checked(
        sh, ["git", "-C", str(smoke.REPO), "status", "--porcelain", "--untracked-files=all"],
        what="git status").splitlines() if line.strip())
    temp = Path(tempfile.mkdtemp(prefix=WORKSPACE_PREFIX)).resolve()
    problem = workspace_problem(temp)
    if problem:                                  # the directory is left untouched: nothing is written to it or deleted
        raise SmokeFailure(f"refusing to use {temp} as the workspace: {problem}")
    try:
        smoke.register_workspace(temp)           # without this record smoke._remove_tree refuses to delete it
    except (OSError, SmokeFailure) as exc:
        raise SmokeFailure(f"could not record ownership of the temporary directory: {exc}") from exc
    credentials = generate_credentials()
    smoke.RUN.temp, smoke.RUN.generated = temp, dict(credentials)
    env_file = temp / ENV_FILE_NAME
    env_file.write_text(env_file_text(credentials), encoding="utf-8")
    override = temp / "override.yml"
    override.write_text(override_text(port), encoding="utf-8")
    smoke.RUN.env_file = env_file
    ops = ViewerOps(project, override, env_file, sh, temp, status_before, pre.protected_before, pre.networks)
    stack = Stack(project, override, env_file, sh)
    failure = ""
    stack_facts: dict[str, Any] = {}
    tests: Optional[TestsVerdict] = None
    test_run: Optional[TestRun] = None
    diagnostics: dict[str, Any] = {}
    try:
        stack_facts = start_and_bootstrap(stack, port, clock, sleeper)
        junit = temp / "junit.xml"
        test_run = run_tests(pytest_command(junit), integration_environment(project, port, credentials), T_TESTS, smoke.REPO)
        if junit.is_file():
            tests = evaluate_tests(parse_junit(junit.read_text(encoding="utf-8", errors="replace")), test_run)
        else:
            tests = evaluate_tests([], test_run)
    except SmokeFailure as exc:
        failure = str(exc)
        say(f"FAILURE: {failure}")
    except KeyboardInterrupt:
        failure = "interrupted"
        say("FAILURE: interrupted")
    except Exception as exc:  # noqa: BLE001 - anything unforeseen is a failure, and is cleaned up too
        failure = f"{type(exc).__name__}: {exc}"
        say(f"FAILURE: {failure}")
    if failure:
        try:
            diagnostics = {"bootstrap_log_tail": tail_lines(stack.logs("db-bootstrap"), 40),
                           "postgres_log_tail": tail_lines(stack.logs("postgres"), 20)}
        except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the failure or block cleanup
            diagnostics = {"errors": [f"{type(exc).__name__}"]}
    evidence_problems: list[str] = []
    precleanup: dict[str, str] = {}
    provisional = "FAIL" if failure else (tests.verdict if tests is not None else "INCONCLUSIVE")
    try:
        path, digest = write_evidence(
            evidence_directory, project, "pre-cleanup",
            build_evidence(kind="pre-cleanup", project=project, port=port, git_head=args.expect_head, git_state=pre.git_state,
                           verdict=provisional, started_utc=started_utc, finished_utc=utc(), failure=failure, tests=tests,
                           test_run=test_run, stack_facts=stack_facts, diagnostics=diagnostics),
            shutdown.utc_stamp(utc()))
        precleanup = {"name": path.name, "sha256": digest}
        say(f"evidence (pre-cleanup): {path}  sha256 {digest}")
    except (SmokeFailure, OSError) as exc:
        evidence_problems.append(f"the pre-cleanup evidence could not be written: {exc}")
        say(f"EVIDENCE PROBLEM: {evidence_problems[-1]}")
    section("project teardown")
    cleaned = cleanup_detailed(ops, pre.before)
    problems = cleaned.problems
    for problem in problems:
        say(f"CLEANUP PROBLEM: {problem}")
    if problems:
        write_marker("; ".join(problems), marker_root)
    verdict = final_verdict(tests, cleanup_verified=not problems, failure=failure, evidence_problems=evidence_problems)
    try:
        path, digest = write_evidence(
            evidence_directory, project, "final",
            build_evidence(kind="final", project=project, port=port, git_head=args.expect_head, git_state=pre.git_state,
                           verdict=verdict, started_utc=started_utc, finished_utc=utc(), failure=failure, tests=tests,
                           test_run=test_run, stack_facts=stack_facts, evidence_problems=evidence_problems,
                           cleanup=cleaned, precleanup=precleanup or None, diagnostics=diagnostics),
            shutdown.utc_stamp(utc()))
        say(f"evidence (final): {path}  sha256 {digest}")
    except (SmokeFailure, OSError) as exc:
        evidence_problems.append(f"the final evidence could not be written: {exc}")
        say(f"EVIDENCE PROBLEM: {evidence_problems[-1]}")
        verdict = "FAIL"                      # never a PASS without its evidence
    smoke.RUN.generated, smoke.RUN.temp, smoke.RUN.env_file = {}, None, None
    section("result")
    if tests is not None:
        for item in tests.tests:
            say(f"  {item['outcome']:8} {item['level']:10} {item['name']}")
        for problem in tests.problems:
            say(f"      {problem}")
    say(f"overall: {verdict}")
    say(f"cleanup verified: {'yes' if not problems else 'NO'}")
    say(f"evidence written: {'yes' if not evidence_problems else 'NO'}")
    return 0 if verdict == "PASS" else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.preflight and not args.execute:
        print(plan_text(new_project_name(), args.expect_head))
        return 0
    try:
        if args.execute:
            check_confirmation(args.confirm, args.expect_head)
        elif not re.fullmatch(r"[0-9a-f]{40}", args.expect_head or ""):
            raise SmokeFailure("--expect-head needs a full 40-character commit")
    except SmokeFailure as failure:
        print(str(failure), file=sys.stderr)
        return 2
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")
    reason = unsupported_host()              # before the preflight, keep_awake, execute and every subprocess or write
    if reason:
        say(f"REFUSED: {reason}")
        return 1
    if args.preflight and not args.execute:
        try:
            pre = run_preflight(_default_shell, smoke.REPO, args.expect_head,
                                docker_data_dir=args.docker_data_dir or shutdown.default_docker_data_dir())
        except SmokeFailure as failure:
            say(f"PREFLIGHT FAILED: {failure}")
            return 1
        say(f"preflight passed (git state {pre.git_state}); candidate project {pre.project}, port {pre.port}; nothing was created")
        return 0
    pipeline.keep_awake()
    try:
        return execute(args)
    except SmokeFailure as failure:
        say(f"REFUSED: {failure}")
        return 1
    finally:
        pipeline.release_awake()


if __name__ == "__main__":
    sys.exit(main())

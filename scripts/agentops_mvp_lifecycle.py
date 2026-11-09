"""
scripts/agentops_mvp_lifecycle.py

Read-only lifecycle foundation for the dedicated AgentOps MVP stack
(docker/mvp/compose.yml, Compose project "agentops-mvp").

What is here
  - a read-only inspection of the MVP's own Docker resources and a classification of the
    stack as FRESH, PARTIAL, COMPLETE, AMBIGUOUS or UNKNOWN (the "status" command);
  - small reusable helpers for later commands: available memory on Windows, Linux and
    macOS, disk space, port availability, resource identity validation, fixed-vocabulary
    formatting, secret-safe messages, and a cross-platform exclusive lock.

What is NOT here, on purpose: build, up, down, reset, any Compose command, any launch
state file, any database access.  Nothing in this module creates, changes or removes a
container, network, volume, image or file (the lock helper opens its lock file, which a
later command will use; status never does).

Rules
  - Docker is reached only through an injected runner and only with the fixed argument
    lists below (never a shell).  Every command is a read-only "info", "ps", "inspect",
    "network ls/inspect", "volume ls/inspect" or "image ls".
  - Only identity, state and timing fields are requested.  Container environments,
    command lines, mounts, logs and health-check output are never requested, and the
    credential file is never read.
  - Raw Docker output is parsed strictly and never printed.  Anything that does not parse
    makes the answer UNKNOWN.  Messages come from a fixed vocabulary; resource names are
    printed only after a character check.
  - COMPLETE is never inferred from a volume or a running container alone.  It needs the
    container-level evidence listed in classify().  The migration ledger is NOT read
    (that would need database access), so COMPLETE means "the bootstrap container
    finished successfully and the services that depend on it are healthy", not "the
    ledger was verified".

Standard library only.
"""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import socket
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Identity of the MVP stack (cross-checked against agentops_mvp by the tests)
# ---------------------------------------------------------------------------

PROJECT_NAME = "agentops-mvp"
VOLUME_NAME = "agentops-mvp-postgres-data"
NETWORK_NAME = "agentops-mvp_mvp-net"
SERVICES = ("postgres", "db-bootstrap", "viewer")
PUBLISHED_PORT = 8000

LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"
LABEL_NETWORK = "com.docker.compose.network"
LABEL_VOLUME = "com.docker.compose.volume"
LABEL_MVP = "agentops.mvp"

#: Thresholds for the commands that come later; status only shows them.
BUILD_MIN_MIB = 2048
UP_MIN_MIB = 2560
DOCKER_VM_MIN_MIB = 3584
DISK_MIN_GIB = 10.0

MAX_CONTAINERS = 20
MAX_LISTED_NAMES = 10

STATE_FRESH = "FRESH"
STATE_PARTIAL = "PARTIAL"
STATE_COMPLETE = "COMPLETE"
STATE_AMBIGUOUS = "AMBIGUOUS"
STATE_UNKNOWN = "UNKNOWN"


def container_name(service: str) -> str:
    return f"{PROJECT_NAME}-{service}-1"


def image_name(service: str) -> str:
    return f"{PROJECT_NAME}-{service}"


class LifecycleError(Exception):
    """A failure with a fixed-vocabulary message; never carries output or a secret."""


class LockHeldError(LifecycleError):
    """Another lifecycle command holds the lock."""


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout: bytes


#: (argument list, environment) -> result.  agentops_mvp supplies the real one.
Runner = Callable[[Sequence[str], Mapping[str, str]], "DockerResult"]


# ---------------------------------------------------------------------------
# Fixed read-only Docker commands
# ---------------------------------------------------------------------------

_PS_FORMAT = ('{{.ID}}|{{.Names}}|{{.Label "' + LABEL_SERVICE + '"}}|{{.Label "'
              + LABEL_PROJECT + '"}}|{{.State}}')
# `index` tolerates a container with no healthcheck (the State map has no Health key); a bare
# `.State.Health` is rejected by the engine for such containers.
_STATE_FORMAT = ("{{.Id}}|{{.State.Status}}|{{.State.ExitCode}}|"
                 '{{with index .State "Health"}}{{.Status}}{{else}}none{{end}}|'
                 "{{.State.Running}}|{{.State.StartedAt}}|{{.State.FinishedAt}}")


def cmd_info(docker: str) -> list[str]:
    return [docker, "info", "--format", "{{.ServerVersion}}"]


def cmd_ps_by_label(docker: str) -> list[str]:
    return [docker, "ps", "-a", "--filter", f"label={LABEL_PROJECT}={PROJECT_NAME}",
            "--format", _PS_FORMAT]


def cmd_ps_by_name(docker: str) -> list[str]:
    return [docker, "ps", "-a", "--filter", f"name={PROJECT_NAME}", "--format", _PS_FORMAT]


def cmd_inspect_containers(docker: str, ids: Sequence[str]) -> list[str]:
    return [docker, "inspect", "--type", "container", "--format", _STATE_FORMAT, *ids]


def cmd_network_ls(docker: str) -> list[str]:
    return [docker, "network", "ls", "--filter", f"name={PROJECT_NAME}",
            "--format", "{{.Name}}|{{.Driver}}|{{.Scope}}"]


def cmd_network_labels(docker: str) -> list[str]:
    return [docker, "network", "inspect", NETWORK_NAME, "--format", "{{json .Labels}}"]


def cmd_volume_ls(docker: str) -> list[str]:
    return [docker, "volume", "ls", "--filter", f"name={PROJECT_NAME}",
            "--format", "{{.Name}}|{{.Driver}}"]


def cmd_volume_labels(docker: str) -> list[str]:
    return [docker, "volume", "inspect", VOLUME_NAME, "--format", "{{json .Labels}}"]


def cmd_image_ls(docker: str) -> list[str]:
    return [docker, "image", "ls", "--filter", f"reference={PROJECT_NAME}-*",
            "--format", "{{.Repository}}|{{.Tag}}|{{.ID}}"]


# ---------------------------------------------------------------------------
# Strict parsers (no output is ever echoed)
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"[0-9a-f]{12,64}")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_LABEL_RE = re.compile(r"[A-Za-z0-9_.-]{0,128}")
_STATE_RE = re.compile(r"[a-z]{1,16}")
_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})")
_NEVER = "0001-01-01T00:00:00Z"


class ParseError(LifecycleError):
    pass


def _lines(data: bytes, limit: int = 200_000) -> list[str]:
    if len(data) > limit:
        raise ParseError("output is larger than expected")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseError("output is not text") from None
    return [line for line in text.splitlines() if line.strip()]


@dataclass(frozen=True)
class PsRow:
    short_id: str
    name: str
    service: str
    project: str
    state: str


def parse_ps(data: bytes) -> list[PsRow]:
    rows = []
    for line in _lines(data):
        parts = line.strip().split("|")
        if len(parts) != 5:
            raise ParseError("a container row has an unexpected shape")
        short_id, name, service, project, state = parts
        if not (_ID_RE.fullmatch(short_id) and _NAME_RE.fullmatch(name) and _LABEL_RE.fullmatch(service)
                and _LABEL_RE.fullmatch(project) and _STATE_RE.fullmatch(state)):
            raise ParseError("a container row has unexpected characters")
        rows.append(PsRow(short_id, name, service, project, state))
    return rows


def parse_time(text: str) -> Optional[datetime]:
    """An RFC 3339 time as aware UTC, None for Docker's 'never' value, or an error."""
    if text == _NEVER:
        return None
    match = _TIME_RE.fullmatch(text)
    if not match:
        raise ParseError("a timestamp has an unexpected format")
    date, clock, fraction, zone = match.groups()
    micro = (fraction or "0")[:6].ljust(6, "0")
    zone = "+00:00" if zone == "Z" else zone
    try:
        return datetime.fromisoformat(f"{date}T{clock}.{micro}{zone}").astimezone(timezone.utc)
    except ValueError:
        raise ParseError("a timestamp is not valid") from None


@dataclass(frozen=True)
class StateRow:
    full_id: str
    status: str
    exit_code: int
    health: str
    running: bool
    started: Optional[datetime]
    finished: Optional[datetime]


def parse_states(data: bytes) -> list[StateRow]:
    rows = []
    for line in _lines(data):
        parts = line.strip().split("|")
        if len(parts) != 7:
            raise ParseError("a state row has an unexpected shape")
        full_id, status, exit_code, health, running, started, finished = parts
        if not (re.fullmatch(r"[0-9a-f]{64}", full_id) and _STATE_RE.fullmatch(status)
                and re.fullmatch(r"-?\d{1,5}", exit_code)
                and health in ("none", "starting", "healthy", "unhealthy")
                and running in ("true", "false")):
            raise ParseError("a state row has unexpected values")
        rows.append(StateRow(full_id, status, int(exit_code), health, running == "true",
                             parse_time(started), parse_time(finished)))
    return rows


def parse_names(data: bytes, columns: int) -> list[tuple[str, ...]]:
    rows = []
    for line in _lines(data):
        parts = tuple(line.strip().split("|"))
        if len(parts) != columns or not _NAME_RE.fullmatch(parts[0]):
            raise ParseError("a resource row has an unexpected shape")
        rows.append(parts)
    return rows


def parse_labels(data: bytes) -> dict[str, str]:
    """A label mapping.  Values are used for identity checks only and never shown."""
    try:
        text = data.decode("utf-8").strip()
        parsed = json.loads(text) if text else None
    except (UnicodeDecodeError, ValueError):
        raise ParseError("labels are not valid JSON") from None
    if parsed is None:
        return {}
    if not isinstance(parsed, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()):
        raise ParseError("labels have an unexpected shape")
    return parsed


# ---------------------------------------------------------------------------
# Snapshot of the MVP's resources
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContainerInfo:
    name: str
    service: str
    project: str
    state: str
    exit_code: Optional[int]
    health: Optional[str]
    running: Optional[bool]
    started: Optional[datetime]
    finished: Optional[datetime]


@dataclass
class Snapshot:
    errors: list[str] = field(default_factory=list)            # fixed codes, never output
    containers: list[ContainerInfo] = field(default_factory=list)
    stray_containers: list[str] = field(default_factory=list)  # MVP-looking name, no project label
    network: Optional[dict[str, str]] = None                    # labels of the expected network
    other_networks: list[str] = field(default_factory=list)
    volume: Optional[dict[str, str]] = None                     # labels of the expected volume
    other_volumes: list[str] = field(default_factory=list)
    images: dict[str, bool] = field(default_factory=dict)
    other_images: list[str] = field(default_factory=list)


def _run(runner: Runner, argv: list[str], env: Mapping[str, str], snapshot: Snapshot, code: str) -> Optional[bytes]:
    """Run one read-only command; any failure becomes a fixed error code."""
    try:
        result = runner(argv, env)
    except Exception:  # noqa: BLE001 - never surface the cause
        snapshot.errors.append(code)
        return None
    if result.returncode != 0:
        snapshot.errors.append(code)
        return None
    return result.stdout


def inspect_stack(docker: str, runner: Runner, env: Mapping[str, str]) -> Snapshot:
    """Collect the MVP's resources.  Read-only; never raises on a Docker problem (the
    problem is recorded in snapshot.errors and the classification becomes UNKNOWN)."""
    snapshot = Snapshot()
    if _run(runner, cmd_info(docker), env, snapshot, "ENGINE_UNAVAILABLE") is None:
        return snapshot

    labelled = nameless = None
    out = _run(runner, cmd_ps_by_label(docker), env, snapshot, "CONTAINER_LIST_FAILED")
    if out is not None:
        try:
            labelled = parse_ps(out)
        except ParseError:
            snapshot.errors.append("CONTAINER_LIST_UNREADABLE")
    out = _run(runner, cmd_ps_by_name(docker), env, snapshot, "CONTAINER_LIST_FAILED")
    if out is not None:
        try:
            nameless = parse_ps(out)
        except ParseError:
            snapshot.errors.append("CONTAINER_LIST_UNREADABLE")

    if labelled is not None and nameless is not None:
        if len(labelled) + len(nameless) > MAX_CONTAINERS * 2:
            snapshot.errors.append("TOO_MANY_CONTAINERS")
        else:
            by_id = {row.short_id: row for row in labelled}
            for row in nameless:
                if row.short_id not in by_id:
                    if row.project == PROJECT_NAME:
                        by_id[row.short_id] = row
                    else:
                        snapshot.stray_containers.append(row.name)
            rows = list(by_id.values())
            states: dict[str, StateRow] = {}
            if rows:
                out = _run(runner, cmd_inspect_containers(docker, [r.short_id for r in rows]), env,
                           snapshot, "CONTAINER_INSPECT_FAILED")
                if out is not None:
                    try:
                        for state in parse_states(out):
                            states[state.full_id] = state
                    except ParseError:
                        snapshot.errors.append("CONTAINER_INSPECT_UNREADABLE")
            for row in rows:
                match = [s for full, s in states.items() if full.startswith(row.short_id)]
                state = match[0] if len(match) == 1 else None
                if state is None and "CONTAINER_INSPECT_FAILED" not in snapshot.errors \
                        and "CONTAINER_INSPECT_UNREADABLE" not in snapshot.errors:
                    snapshot.errors.append("CONTAINER_INSPECT_INCOMPLETE")
                snapshot.containers.append(ContainerInfo(
                    row.name, row.service, row.project, row.state,
                    state.exit_code if state else None, state.health if state else None,
                    state.running if state else None, state.started if state else None,
                    state.finished if state else None))

    out = _run(runner, cmd_network_ls(docker), env, snapshot, "NETWORK_LIST_FAILED")
    if out is not None:
        try:
            names = [row[0] for row in parse_names(out, 3)]
        except ParseError:
            snapshot.errors.append("NETWORK_LIST_UNREADABLE")
            names = None
        if names is not None:
            snapshot.other_networks = [n for n in names if n != NETWORK_NAME]
            if NETWORK_NAME in names:
                out = _run(runner, cmd_network_labels(docker), env, snapshot, "NETWORK_INSPECT_FAILED")
                if out is not None:
                    try:
                        snapshot.network = parse_labels(out)
                    except ParseError:
                        snapshot.errors.append("NETWORK_INSPECT_UNREADABLE")

    out = _run(runner, cmd_volume_ls(docker), env, snapshot, "VOLUME_LIST_FAILED")
    if out is not None:
        try:
            names = [row[0] for row in parse_names(out, 2)]
        except ParseError:
            snapshot.errors.append("VOLUME_LIST_UNREADABLE")
            names = None
        if names is not None:
            snapshot.other_volumes = [n for n in names if n != VOLUME_NAME]
            if VOLUME_NAME in names:
                out = _run(runner, cmd_volume_labels(docker), env, snapshot, "VOLUME_INSPECT_FAILED")
                if out is not None:
                    try:
                        snapshot.volume = parse_labels(out)
                    except ParseError:
                        snapshot.errors.append("VOLUME_INSPECT_UNREADABLE")

    out = _run(runner, cmd_image_ls(docker), env, snapshot, "IMAGE_LIST_FAILED")
    if out is not None:
        try:
            rows = parse_names(out, 3)
        except ParseError:
            snapshot.errors.append("IMAGE_LIST_UNREADABLE")
            rows = []
        expected = {image_name(s): s for s in SERVICES}
        snapshot.images = {s: False for s in SERVICES}
        for repository, tag, _image_id in rows:
            if repository in expected and tag in ("latest", ""):
                snapshot.images[expected[repository]] = True
            else:
                snapshot.other_images.append(f"{repository}:{tag}" if tag else repository)
    return snapshot


# ---------------------------------------------------------------------------
# Identity validation and classification (pure)
# ---------------------------------------------------------------------------

def printable_name(name: str) -> str:
    return name if _NAME_RE.fullmatch(name) else "<unprintable name>"


def volume_problem(labels: Mapping[str, str]) -> Optional[str]:
    if labels.get(LABEL_MVP) != "true":
        return "the data volume is not labelled as created by the MVP stack"
    if labels.get(LABEL_PROJECT) != PROJECT_NAME or labels.get(LABEL_VOLUME) != "postgres-data":
        return "the data volume belongs to a different project or volume"
    return None


def network_problem(labels: Mapping[str, str]) -> Optional[str]:
    if labels.get(LABEL_PROJECT) != PROJECT_NAME or labels.get(LABEL_NETWORK) != "mvp-net":
        return "the network does not belong to the MVP project"
    return None


@dataclass
class StatusReport:
    state: str
    details: list[str]
    ambiguities: list[str]
    snapshot: Snapshot
    container_lines: dict[str, str]

    @property
    def exit_code(self) -> int:
        return {STATE_AMBIGUOUS: 6, STATE_UNKNOWN: 7}.get(self.state, 0)


def _container_text(c: ContainerInfo) -> str:
    if c.state == "running":
        return f"running ({c.health or 'unknown health'})" if c.health not in (None, "none") else "running (no health check)"
    if c.state == "exited":
        return f"exited ({c.exit_code})"
    return c.state


def classify(snapshot: Snapshot) -> StatusReport:
    """Classify the stack from a snapshot.

    UNKNOWN    an inspection failed or was unreadable, so the picture is incomplete.
    AMBIGUOUS  something unexpected or contradictory exists (names, labels, services,
               extra resources, or a service running without the evidence it depends on).
    FRESH      no MVP resource of any kind.
    COMPLETE   only with ALL of: exactly one container per service with its expected
               name and project label; postgres and viewer running and healthy; the
               bootstrap container exited with code 0; the viewer started at or after
               the moment the bootstrap finished; the expected network and volume with
               their labels; the three images; nothing unexpected.
    PARTIAL    anything else, with detail codes (images only, volume only, bootstrap
               running or failed, a service missing or unhealthy, ...).
    """
    lines: dict[str, str] = {}
    if snapshot.errors:
        return StatusReport(STATE_UNKNOWN, sorted(set(snapshot.errors)), [], snapshot, lines)

    ambiguities: list[str] = []
    by_service: dict[str, list[ContainerInfo]] = {}
    for c in snapshot.containers:
        if c.project != PROJECT_NAME:
            ambiguities.append("a container with an MVP-like name has no MVP project label")
            continue
        if c.service not in SERVICES:
            ambiguities.append(f"unexpected service in the MVP project: {printable_name(c.service) if c.service else '<none>'}")
            continue
        if c.name != container_name(c.service):
            ambiguities.append(f"container name differs from the expected one: {printable_name(c.name)}")
        by_service.setdefault(c.service, []).append(c)
    for name in snapshot.stray_containers:
        ambiguities.append(f"a container with an MVP-like name has no MVP project label: {printable_name(name)}")
    for service, found in by_service.items():
        if len(found) > 1:
            ambiguities.append(f"more than one container for service {service}")
    if snapshot.network is not None and (problem := network_problem(snapshot.network)):
        ambiguities.append(problem)
    if snapshot.volume is not None and (problem := volume_problem(snapshot.volume)):
        ambiguities.append(problem)
    for name in snapshot.other_networks:
        ambiguities.append(f"an unexpected network has an MVP-like name: {printable_name(name)}")
    for name in snapshot.other_volumes:
        ambiguities.append(f"an unexpected volume has an MVP-like name: {printable_name(name)}")
    for name in snapshot.other_images:
        ambiguities.append(f"an unexpected image has an MVP-like name: {printable_name(name)}")

    one = {s: found[0] for s, found in by_service.items() if len(found) == 1}
    for service, c in one.items():
        lines[service] = _container_text(c)
    postgres, boot, viewer = one.get("postgres"), one.get("db-bootstrap"), one.get("viewer")

    # contradictions: a dependent service running without what it depends on
    if viewer is not None and viewer.running:
        if postgres is not None and not postgres.running:
            ambiguities.append("the viewer is running while PostgreSQL is not")
        if boot is not None and not (boot.state == "exited" and boot.exit_code == 0):
            ambiguities.append("the viewer is running although the bootstrap has not completed successfully")
        if boot is not None and boot.state == "exited" and boot.exit_code == 0 and boot.finished \
                and viewer.started and viewer.started < boot.finished:
            ambiguities.append("the viewer started before the bootstrap finished")
    if ambiguities:
        return StatusReport(STATE_AMBIGUOUS, [], ambiguities, snapshot, lines)

    nothing = (not snapshot.containers and snapshot.network is None and snapshot.volume is None
               and not any(snapshot.images.values()))
    if nothing:
        return StatusReport(STATE_FRESH, [], [], snapshot, lines)

    details: list[str] = []
    missing_images = [s for s in SERVICES if not snapshot.images.get(s)]
    if not snapshot.containers and snapshot.network is None and snapshot.volume is None:
        details.append("images are built; the stack has not been created")
    else:
        if snapshot.volume is None:
            details.append("the data volume does not exist")
        elif not snapshot.containers:
            details.append("the data volume exists but no container does; bootstrap success cannot be shown")
        if snapshot.network is None:
            details.append("the project network does not exist")
        for service in SERVICES:
            if service not in one:
                details.append(f"the {service} container does not exist")
        if boot is not None:
            if boot.state == "exited" and boot.exit_code == 0:
                pass
            elif boot.state == "exited":
                details.append(f"HOLD: the bootstrap container failed (exit code {boot.exit_code}); nothing was reset")
            elif boot.running:
                details.append("the bootstrap is still running")
            else:
                details.append(f"the bootstrap has not run to completion (state {printable_name(boot.state)})")
        for service, c in (("postgres", postgres), ("viewer", viewer)):
            if c is None:
                continue
            if not c.running:
                details.append(f"the {service} container is not running")
            elif c.health != "healthy":
                details.append(f"the {service} container is not healthy (health: {c.health})")
        if missing_images:
            details.append("images missing: " + ", ".join(missing_images))

    boot_ok = boot is not None and boot.state == "exited" and boot.exit_code == 0 and boot.finished is not None
    complete = (
        not details and postgres is not None and viewer is not None and boot_ok
        and postgres.running and postgres.health == "healthy"
        and viewer.running and viewer.health == "healthy"
        and viewer.started is not None and viewer.started >= boot.finished
        and snapshot.network is not None and snapshot.volume is not None
    )
    if complete:
        return StatusReport(STATE_COMPLETE, ["bootstrap container exited 0 and the viewer started after it finished "
                                              "(container evidence only; the migration ledger was not read)"],
                            [], snapshot, lines)
    if not details:
        # everything looked present but a piece of the evidence is missing: do not guess
        return StatusReport(STATE_UNKNOWN, ["the evidence is not sufficient to call the stack complete"],
                            [], snapshot, lines)
    return StatusReport(STATE_PARTIAL, details, [], snapshot, lines)


# ---------------------------------------------------------------------------
# Resource readings (helpers for status and for later commands)
# ---------------------------------------------------------------------------

def parse_meminfo(text: str) -> int:
    """Available memory in MiB from the text of /proc/meminfo (MemAvailable)."""
    match = re.search(r"^MemAvailable:\s+(\d+)\s*kB\s*$", text, re.M)
    if not match:
        raise LifecycleError("available memory could not be read")
    return int(match.group(1)) // 1024


def parse_vm_stat(text: str) -> int:
    """Available memory in MiB from macOS vm_stat output: free + inactive + speculative pages."""
    size = re.search(r"page size of (\d+) bytes", text)
    if not size:
        raise LifecycleError("available memory could not be read")
    pages = 0
    for label in ("free", "inactive", "speculative"):
        match = re.search(rf"^Pages {label}:\s+(\d+)\.?\s*$", text, re.M)
        if not match:
            raise LifecycleError("available memory could not be read")
        pages += int(match.group(1))
    return pages * int(size.group(1)) // (1024 * 1024)


def windows_available_bytes() -> int:
    """Available physical memory from GlobalMemoryStatusEx (what Task Manager calls available)."""
    import ctypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
        raise LifecycleError("available memory could not be read")
    return int(status.ullAvailPhys)


def read_available_memory_mib(
    platform_name: str,
    *,
    sys_platform: Optional[str] = None,
    read_text: Callable[[str], str] = lambda path: Path(path).read_text(encoding="ascii", errors="replace"),
    windows_reader: Callable[[], int] = windows_available_bytes,
    runner: Optional[Runner] = None,
    env: Optional[Mapping[str, str]] = None,
) -> int:
    """Available memory in MiB on Windows ("nt"), Linux or macOS ("posix").

    Raises LifecycleError when it cannot be read: a caller must then refuse, not guess."""
    try:
        if platform_name == "nt":
            value = windows_reader() // (1024 * 1024)
        else:
            system = sys_platform if sys_platform is not None else sys.platform
            if system == "darwin":
                if runner is None:
                    raise LifecycleError("available memory could not be read")
                result = runner(["/usr/bin/vm_stat"], env or {})
                if result.returncode != 0:
                    raise LifecycleError("available memory could not be read")
                value = parse_vm_stat(result.stdout.decode("utf-8", "replace"))
            elif system.startswith("linux"):
                value = parse_meminfo(read_text("/proc/meminfo"))
            else:
                raise LifecycleError("available memory could not be read on this platform")
    except LifecycleError:
        raise
    except Exception:  # noqa: BLE001
        raise LifecycleError("available memory could not be read") from None
    if value <= 0:
        raise LifecycleError("available memory could not be read")
    return value


def memory_problem(available_mib: int, required_mib: int) -> Optional[str]:
    if available_mib < required_mib:
        return f"available memory is {available_mib} MiB; {required_mib} MiB is required"
    return None


def nearest_existing_directory(path: str) -> str:
    current = os.path.abspath(path)
    while current and not os.path.isdir(current):
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return current


def disk_free_gib(path: str) -> float:
    """Free space in GiB on the drive that holds path (its nearest existing ancestor)."""
    try:
        return shutil.disk_usage(nearest_existing_directory(path)).free / (1024 ** 3)
    except OSError:
        raise LifecycleError("free disk space could not be read") from None


def disk_problem(free_gib: float, required_gib: float = DISK_MIN_GIB) -> Optional[str]:
    if free_gib < required_gib:
        return f"free disk space is {free_gib:.1f} GiB; {required_gib:.0f} GiB is required"
    return None


def port_in_use(port: int, host: str = "127.0.0.1", platform_name: Optional[str] = None) -> bool:
    """True when something already holds host:port.  A momentary bind attempt: nothing is
    left behind.  Raises LifecycleError when the answer cannot be established."""
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise LifecycleError("the port number is not valid")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if (platform_name or os.name) == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind((host, port))
        except OSError as error:
            if error.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1), getattr(errno, "EACCES", -1),
                               getattr(errno, "WSAEACCES", -1)):
                return True
            raise LifecycleError("the port could not be checked") from None
        return False
    finally:
        probe.close()


@dataclass
class Probes:
    """The three readings status shows; replaceable in tests."""
    memory_mib: Callable[[], int]
    disk_free_gib: Callable[[], float]
    port_in_use: Callable[[int], bool]


# ---------------------------------------------------------------------------
# Fixed-vocabulary formatting
# ---------------------------------------------------------------------------

#: Fixed text for the codes an incomplete inspection can produce.
CODE_TEXT = {
    "ENGINE_UNAVAILABLE": "the container engine could not be reached or inspected",
    "CONTAINER_LIST_FAILED": "listing the MVP containers failed",
    "CONTAINER_LIST_UNREADABLE": "the container list could not be understood",
    "CONTAINER_INSPECT_FAILED": "reading the container states failed",
    "CONTAINER_INSPECT_UNREADABLE": "the container states could not be understood",
    "CONTAINER_INSPECT_INCOMPLETE": "a container state was missing from the answer",
    "TOO_MANY_CONTAINERS": "more containers match than the MVP stack can have",
    "NETWORK_LIST_FAILED": "listing the networks failed",
    "NETWORK_LIST_UNREADABLE": "the network list could not be understood",
    "NETWORK_INSPECT_FAILED": "reading the MVP network failed",
    "NETWORK_INSPECT_UNREADABLE": "the MVP network could not be understood",
    "VOLUME_LIST_FAILED": "listing the volumes failed",
    "VOLUME_LIST_UNREADABLE": "the volume list could not be understood",
    "VOLUME_INSPECT_FAILED": "reading the MVP data volume failed",
    "VOLUME_INSPECT_UNREADABLE": "the MVP data volume could not be understood",
    "IMAGE_LIST_FAILED": "listing the images failed",
    "IMAGE_LIST_UNREADABLE": "the image list could not be understood",
}


def _resource_hints(probes: Optional[Probes]) -> list[str]:
    if probes is None:
        return []
    out = []
    try:
        mib = probes.memory_mib()
        out.append(f"  memory: {mib} MiB available (build needs {BUILD_MIN_MIB}, up needs {UP_MIN_MIB}): "
                   + ("sufficient" if mib >= UP_MIN_MIB else "LOW for a launch"))
    except LifecycleError:
        out.append("  memory: could not be read")
    try:
        free = probes.disk_free_gib()
        out.append(f"  disk: {free:.1f} GiB free (a launch needs {DISK_MIN_GIB:.0f}): "
                   + ("sufficient" if free >= DISK_MIN_GIB else "LOW for a launch"))
    except LifecycleError:
        out.append("  disk: could not be read")
    try:
        out.append(f"  port {PUBLISHED_PORT}: " + ("in use" if probes.port_in_use(PUBLISHED_PORT) else "free"))
    except LifecycleError:
        out.append(f"  port {PUBLISHED_PORT}: could not be checked")
    return out


def format_status(report: StatusReport, probes: Optional[Probes] = None) -> str:
    snapshot = report.snapshot
    lines = [f"MVP stack status: {report.state}",
             f"  project {PROJECT_NAME}: read-only inspection; nothing was created, changed or removed"]
    if report.state == STATE_UNKNOWN:
        for code in report.details:
            lines.append("  " + CODE_TEXT.get(code, code))
        lines.append("  the stack could not be classified from the evidence available")
    else:
        for service in SERVICES:
            if service in report.container_lines:
                lines.append(f"  {service}: {report.container_lines[service]}")
        lines.append("  network " + NETWORK_NAME + ": " + ("present" if snapshot.network is not None else "absent"))
        lines.append("  data volume " + VOLUME_NAME + ": " + ("present" if snapshot.volume is not None else "absent"))
        lines.append("  images: " + ", ".join(f"{s} {'present' if snapshot.images.get(s) else 'absent'}" for s in SERVICES))
        for detail in report.details:
            lines.append(f"  - {detail}")
        for item in report.ambiguities[:MAX_LISTED_NAMES]:
            lines.append(f"  ! {item}")
        if len(report.ambiguities) > MAX_LISTED_NAMES:
            lines.append(f"  ! ... and {len(report.ambiguities) - MAX_LISTED_NAMES} more")
        if report.state == STATE_AMBIGUOUS:
            lines.append("  nothing was changed; resolve the items above by hand before any lifecycle command")
    lines += _resource_hints(probes)
    lines.append("  the credential file was not read; no lock was taken")
    return "\n".join(lines)


def safe_message(error: BaseException) -> str:
    """A message for any exception that cannot carry output or a secret."""
    if isinstance(error, LifecycleError):
        return str(error)
    return f"internal error ({type(error).__name__})"


_SECRET_LINE_RE = re.compile(r"(?i)(password|passwd|secret|token)\s*[:=]\s*\S+")


def redact(text: str, secrets: Sequence[str]) -> str:
    """Replace every known secret value, longest first, and any NAME=value secret-looking pair."""
    for value in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(value, "***")
    return _SECRET_LINE_RE.sub(lambda m: m.group(1) + "=***", text)


# ---------------------------------------------------------------------------
# Exclusive lock for future lifecycle commands (status never uses it)
# ---------------------------------------------------------------------------

def _lock_windows(descriptor: int) -> None:
    import msvcrt

    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]


def _unlock_windows(descriptor: int) -> None:
    import msvcrt

    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]


def _lock_posix(descriptor: int) -> None:
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_posix(descriptor: int) -> None:
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


class ExclusiveLock:
    """A non-blocking, advisory, whole-process-safe exclusive lock on one file.

    The operating system releases it when the process ends, so a crash leaves no stale
    lock.  The file is never deleted or written.  The directory must already exist.
    """

    def __init__(self, path: str, *, platform_name: Optional[str] = None,
                 lock: Optional[Callable[[int], None]] = None,
                 unlock: Optional[Callable[[int], None]] = None) -> None:
        self.path = path
        windows = (platform_name or os.name) == "nt"
        self._lock = lock or (_lock_windows if windows else _lock_posix)
        self._unlock = unlock or (_unlock_windows if windows else _unlock_posix)
        self._descriptor: Optional[int] = None

    def acquire(self) -> "ExclusiveLock":
        if self._descriptor is not None:
            raise LifecycleError("the lock is already held by this object")
        directory = os.path.dirname(os.path.abspath(self.path))
        if not os.path.isdir(directory) or os.path.islink(directory):
            raise LifecycleError("the lock directory does not exist or is a link")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError:
            raise LifecycleError("the lock file could not be opened") from None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise LifecycleError("the lock path is not a regular file")
            if os.name != "nt" and (info.st_mode & 0o077):
                raise LifecycleError("the lock file is accessible to group or others")
            try:
                self._lock(descriptor)
            except OSError:
                raise LockHeldError("another lifecycle command is running") from None
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def release(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        try:
            self._unlock(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    @property
    def held(self) -> bool:
        return self._descriptor is not None

    def __enter__(self) -> "ExclusiveLock":
        return self.acquire()

    def __exit__(self, *exc: object) -> bool:
        self.release()
        return False


# ---------------------------------------------------------------------------
# Image-build helpers (pure: the build command itself lives in agentops_mvp)
# ---------------------------------------------------------------------------

#: The three images, one at a time, in this order.
BUILD_ORDER = ("postgres", "viewer", "db-bootstrap")

_FROM_RE = re.compile(r"(?i)FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>[A-Za-z0-9_.-]+))?")
_BASE_IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def parse_base_images(text: str) -> list[str]:
    """The external base images a Dockerfile builds on, each with an explicit tag.

    Fail closed: a FROM line that is not understood, a variable, a digest, or an untagged
    image is refused, because the build would then fetch something this tool never checked.
    """
    stages: set[str] = set()
    images: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not re.match(r"(?i)FROM(\s|$)", line):
            continue
        match = _FROM_RE.fullmatch(line)
        if not match:
            raise LifecycleError("a Dockerfile FROM line is not understood")
        image = match.group("image")
        if image.lower() != "scratch" and image not in stages:
            if not _BASE_IMAGE_RE.fullmatch(image):
                raise LifecycleError("a base image is not a plain name with an explicit tag")
            if image not in images:
                images.append(image)
        if match.group("alias"):
            stages.add(match.group("alias"))
    if not images:
        raise LifecycleError("no base image was found in a Dockerfile")
    return images


def cmd_info_memory(docker: str) -> list[str]:
    return [docker, "info", "--format", "{{.MemTotal}}"]


def cmd_image_present(docker: str, reference: str) -> list[str]:
    if not _BASE_IMAGE_RE.fullmatch(reference):
        raise LifecycleError("an image reference is not acceptable")
    return [docker, "image", "ls", "--filter", f"reference={reference}", "--format", "{{.ID}}"]


def read_engine_memory_mib(docker: str, runner: Runner, env: Mapping[str, str]) -> int:
    """The memory the Docker engine itself has (Docker Desktop's VM), in MiB.  Fails closed."""
    try:
        result = runner(cmd_info_memory(docker), env)
    except Exception:  # noqa: BLE001 - never surface the cause
        raise LifecycleError("the container engine memory could not be read") from None
    text = result.stdout.decode("ascii", "replace").strip() if result.returncode == 0 else ""
    if not re.fullmatch(r"[0-9]{1,15}", text) or int(text) <= 0:
        raise LifecycleError("the container engine memory could not be read")
    return int(text) // (1024 * 1024)


def base_image_present(docker: str, runner: Runner, env: Mapping[str, str], reference: str) -> bool:
    """True when the image already exists locally.  Fails closed (an error is an exception)."""
    try:
        result = runner(cmd_image_present(docker, reference), env)
    except LifecycleError:
        raise
    except Exception:  # noqa: BLE001
        raise LifecycleError("a base image could not be looked up") from None
    if result.returncode != 0:
        raise LifecycleError("a base image could not be looked up")
    return bool(result.stdout.strip())


def build_preflight_problem(snapshot: Snapshot) -> Optional[str]:
    """Why an image build must not start, or None.  Only an uncreated stack (nothing, or
    images alone) may be built: no container, network or volume may exist yet."""
    report = classify(snapshot)
    if report.state == STATE_UNKNOWN:
        return "the state of the MVP resources could not be determined"
    if report.state == STATE_AMBIGUOUS:
        return "unexpected, conflicting or mislabelled MVP resources exist; run status for details"
    if snapshot.containers or snapshot.network is not None or snapshot.volume is not None:
        return "an MVP stack is already partly created; building is only for a stack that does not exist yet"
    return None


def build_result_problems(snapshot: Snapshot) -> list[str]:
    """What is wrong after the builds: unreadable state, resources the build must not
    create, or an expected image that is missing.  Empty means the result is as intended."""
    if snapshot.errors:
        return ["the MVP resources could not be inspected after the build"]
    problems: list[str] = []
    if snapshot.containers or snapshot.stray_containers:
        problems.append("a container with an MVP name exists after the build")
    if snapshot.network is not None or snapshot.other_networks:
        problems.append("a network with an MVP name exists after the build")
    if snapshot.volume is not None or snapshot.other_volumes:
        problems.append("a volume with an MVP name exists after the build")
    if snapshot.other_images:
        problems.append("an unexpected image with an MVP-like name exists after the build")
    missing = [s for s in BUILD_ORDER if not snapshot.images.get(s)]
    if missing:
        problems.append("expected images missing after the build: " + ", ".join(missing))
    return problems


# ---------------------------------------------------------------------------
# Start helpers (pure: the start command itself lives in agentops_mvp)
# ---------------------------------------------------------------------------

#: After the start command returns, the stack is re-inspected this many times,
#: this many seconds apart, while the viewer's health check settles.
START_POLLS = 36
START_POLL_SECONDS = 5

VERDICT_READY = "READY"
VERDICT_PENDING = "PENDING"
VERDICT_FAILED = "FAILED"


def start_preflight_problem(snapshot: Snapshot) -> Optional[str]:
    """Why the stack must not be started, or None.  Only a stack that has never been
    created may be started: all three images exist, and no container, network or volume
    does.  An existing, stopped, failed or running stack is left exactly as it is."""
    report = classify(snapshot)
    if report.state == STATE_UNKNOWN:
        return "the state of the MVP resources could not be determined"
    if report.state == STATE_AMBIGUOUS:
        return "unexpected, conflicting or mislabelled MVP resources exist; run status for details"
    if snapshot.containers or snapshot.network is not None or snapshot.volume is not None:
        return ("an MVP stack already exists (running, stopped or failed); it is left untouched and "
                "nothing is started; run status for details")
    missing = [s for s in SERVICES if not snapshot.images.get(s)]
    if missing:
        return "the images are not built yet (missing: " + ", ".join(missing) + "); build them first"
    return None


def start_verdict(report: StatusReport) -> str:
    """READY when the stack is complete, FAILED when it can only get worse or is
    contradictory (a failed bootstrap, ambiguity, nothing created), PENDING while the
    evidence is still settling (a health check starting, an inspection that failed once)."""
    if report.state == STATE_COMPLETE:
        return VERDICT_READY
    if report.state in (STATE_AMBIGUOUS, STATE_FRESH):
        return VERDICT_FAILED
    if report.state == STATE_PARTIAL and any(d.startswith("HOLD") for d in report.details):
        return VERDICT_FAILED
    return VERDICT_PENDING


def format_evidence(report: StatusReport) -> str:
    """The classification lines of a status report, without its read-only banner."""
    skipped = ("  project ", "  the credential file was not read", "  memory:", "  disk:", "  port ")
    lines = [line for line in format_status(report).splitlines() if not line.startswith(skipped)]
    return "\n".join(lines)

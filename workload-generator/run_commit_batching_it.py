"""
workload-generator/run_commit_batching_it.py

Orchestrator of the integration validation of the opt-in batched Kafka offset commits
(storage-consumer/consumer.py, OffsetBatcher) against a REAL Kafka broker and a REAL
PostgreSQL, on a separate, disposable Compose project:

    storage-consumer/tests/integration/test_commit_batching_it.py
        -> Kafka (KRaft) + PostgreSQL of the disposable project only

It is NOT a benchmark: nothing is timed or judged for performance, nothing is written to
the benchmark directory or its ledger, no benchmark cell is registered or consumed, and the
benchmark claim ledger is never opened.

It only ORCHESTRATES.  The disposable broker, database, bootstrap, virtual environment and
Docker inventory are run_smoke.py's, imported and unchanged; the project-scoped cleanup is
run_pipeline_it.py's safe_cleanup (also imported unchanged).  This file adds what is new:
the exact-HEAD preflight, the memory, engine and disk gates, the blocker and protected-resource
checks (benchmarks, MVP, legacy PostgreSQL), the endpoint rules, the evidence and its SHA-256
manifest, the classification of results, and the blocking marker after an uncertain cleanup.

Isolation, in the order it is established
    - exact branch, exact HEAD, clean working tree and empty index
    - a unique project name "agentops-batching-it-<8 hex>", never "agentops", and none that any
      Docker object already carries
    - refuses to start while a benchmark marker, benchmark Docker object, benchmark or consumer
      process, or an earlier unverified cleanup is present
    - the MVP containers and the stopped legacy PostgreSQL are snapshotted before and compared
      after; the legacy container must be absent or exited
    - host ports only on 127.0.0.1 (run_smoke's override); the tests refuse any other endpoint
      and the prohibited ports 9092, 5432, 4317, 4318, 8000 and 3000
    - throw-away random passwords in a temporary directory outside the repository
    - cleanup is "docker compose down --volumes --rmi local --remove-orphans" for this project
      only; nothing is pruned, nothing is chosen by comparing inventories

    python workload-generator/run_commit_batching_it.py --expect-head <commit>

Exit codes:
    0  every deterministic case passed, no case failed, and cleanup was verified
    1  anything else

Nothing is retried.  Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_pipeline_it as pipeline  # noqa: E402 - safe_cleanup and power helpers, unchanged
import run_smoke as smoke  # noqa: E402
from run_smoke import SmokeFailure, say, section  # noqa: E402

PROJECT_PREFIX: str = "agentops-batching-it-"
_PROJECT_RE = re.compile(re.escape(PROJECT_PREFIX) + r"[0-9a-f]{8}")
EXPECTED_BRANCH: str = "claude/compassionate-noether-7peel4"
BENCHMARK_PROJECT: str = "agentops-workload-smoke"
PIPELINE_IT_PREFIX: str = "agentops-pipeline-it-"
TEST_FILE: str = "storage-consumer/tests/integration/test_commit_batching_it.py"

HARD_MIN_MEMORY_MIB: int = 3072
PREFERRED_MEMORY_MIB: int = 3500
MIN_ENGINE_BYTES: int = 3584 * 1024 ** 2
MIN_DISK_GIB: int = 10
PYTEST_TIMEOUT_SECONDS: float = 1800.0

KAFKA_PORT: int = smoke.KAFKA_PORT
POSTGRES_PORT: int = smoke.POSTGRES_PORT
ALLOWED_ENDPOINT_PORTS: tuple[int, ...] = (KAFKA_PORT, POSTGRES_PORT)
#: Never a target of this validation: the normal stack (9092, 5432, 4317, 4318), the MVP viewer
#: (8000) and Grafana (3000).
PROHIBITED_PORTS: tuple[int, ...] = (9092, 5432, 4317, 4318, 8000, 3000)

#: Containers that must be left exactly as they are.
MVP_CONTAINERS: tuple[str, ...] = (
    "agentops-mvp-postgres-1", "agentops-mvp-viewer-1", "agentops-mvp-db-bootstrap-1")
LEGACY_POSTGRES: str = "agentops-postgres"

#: The cases of the integration module.  Deterministic cases decide the verdict; the
#: timing-sensitive ones are reported as observed or not, and fail only on a safety violation.
DETERMINISTIC_CASES: tuple[str, ...] = (
    "C01_commit_response_shape", "C02_partial_failure", "C03_eager_rebalance",
    "C06_close_callbacks", "C07a_crash_replay", "C08_postgres_idempotency",
    "C09_n1_versus_n100", "C10_idle_and_time_flush", "C11_subscription_callbacks",
)
TIMING_CASES: tuple[str, ...] = (
    "C04_cooperative_rebalance", "C05_lost_ownership", "C07b_forced_kill_restart",
    "C12_sustained_main_n100",
)
DETERMINISTIC_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "BLOCKED")
TIMING_STATUSES: tuple[str, ...] = ("OBSERVED", "NOT_OBSERVED", "INCONCLUSIVE", "FAIL")

_LABEL_PROJECT = "com.docker.compose.project"


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


def validate_endpoint(host: Any, port: Any, allowed: Sequence[int] = ALLOWED_ENDPOINT_PORTS) -> tuple[str, int]:
    """The only endpoints the validation may use: 127.0.0.1 on one of the disposable
    project's two published ports.  Anything else (other hosts, prohibited ports) is refused."""
    if not isinstance(host, str) or host.strip() != "127.0.0.1":
        raise SmokeFailure(f"endpoint host {host!r} is not 127.0.0.1")
    if isinstance(port, bool):
        raise SmokeFailure(f"endpoint port {port!r} is not a number")
    try:
        number = int(str(port).strip())
    except ValueError:
        raise SmokeFailure(f"endpoint port {port!r} is not a number") from None
    if number in PROHIBITED_PORTS:
        raise SmokeFailure(f"endpoint port {number} is prohibited")
    if number not in allowed:
        raise SmokeFailure(f"endpoint port {number} is not one of {list(allowed)}")
    return "127.0.0.1", number


class Gate:
    """Result of a resource gate."""

    def __init__(self, ok: bool, preferred: bool, message: str) -> None:
        self.ok, self.preferred, self.message = ok, preferred, message


def memory_gate(available_mib: Any) -> Gate:
    """Hard requirement 3,072 MiB of available Windows memory; 3,500 MiB preferred."""
    if isinstance(available_mib, bool) or not isinstance(available_mib, (int, float)) or available_mib != available_mib:
        return Gate(False, False, "available memory could not be read")
    if available_mib < HARD_MIN_MEMORY_MIB:
        return Gate(False, False, f"available memory {available_mib:.0f} MiB is below {HARD_MIN_MEMORY_MIB} MiB")
    if available_mib < PREFERRED_MEMORY_MIB:
        return Gate(True, False, f"available memory {available_mib:.0f} MiB meets the minimum, "
                                 f"not the preferred {PREFERRED_MEMORY_MIB} MiB")
    return Gate(True, True, f"available memory {available_mib:.0f} MiB")


def engine_gate(mem_total_bytes: Any) -> Gate:
    if isinstance(mem_total_bytes, bool) or not isinstance(mem_total_bytes, int):
        return Gate(False, False, "the Docker engine memory could not be read")
    ok = mem_total_bytes >= MIN_ENGINE_BYTES
    return Gate(ok, ok, f"Docker engine memory {mem_total_bytes / 1024 ** 2:.0f} MiB"
                        + ("" if ok else f" is below {MIN_ENGINE_BYTES // 1024 ** 2} MiB"))


def disk_gate(free_bytes: Any) -> Gate:
    if isinstance(free_bytes, bool) or not isinstance(free_bytes, (int, float)):
        return Gate(False, False, "free disk space could not be read")
    ok = free_bytes >= MIN_DISK_GIB * 1024 ** 3
    return Gate(ok, ok, f"free disk {free_bytes / 1024 ** 3:.0f} GiB"
                        + ("" if ok else f" is below {MIN_DISK_GIB} GiB"))


def check_git_state(expect_head: str, run_git: Callable[..., str]) -> None:
    """Exact branch, exact HEAD, empty index, clean working tree (untracked files included)."""
    if not re.fullmatch(r"[0-9a-f]{40}", expect_head or ""):
        raise SmokeFailure("--expect-head needs a full 40-character commit")
    branch = run_git("rev-parse", "--abbrev-ref", "HEAD").strip()
    if branch != EXPECTED_BRANCH:
        raise SmokeFailure(f"the branch is {branch!r}, not {EXPECTED_BRANCH!r}")
    head = run_git("rev-parse", "HEAD").strip()
    if head != expect_head:
        raise SmokeFailure(f"HEAD is {head}, not the expected commit {expect_head}")
    if run_git("diff", "--cached", "--name-only").strip():
        raise SmokeFailure("the index is not empty")
    status = [line for line in run_git("status", "--porcelain", "--untracked-files=all").splitlines()
              if line.strip()]
    if status:
        raise SmokeFailure("the working tree is not clean:\n" + "\n".join(status[:8]))


def find_blockers(*, benchmark_markers: Sequence[str], own_markers: Sequence[str],
                  docker_lines: Sequence[str], processes: Sequence[str]) -> list[str]:
    """Everything that forbids starting: benchmark markers, objects of the benchmark or
    pipeline-test projects or of an earlier batching project, benchmark or consumer processes,
    and an earlier unverified cleanup of this validation."""
    blockers = [f"benchmark marker {name}" for name in benchmark_markers]
    blockers += [f"unverified cleanup marker {name}" for name in own_markers]
    for line in docker_lines:
        for needle, what in ((BENCHMARK_PROJECT, "benchmark"), (PIPELINE_IT_PREFIX, "pipeline test"),
                             (PROJECT_PREFIX, "earlier batching validation")):
            if needle in line:
                blockers.append(f"{what} Docker object: {line.strip()[:120]}")
                break
    blockers += [f"process {pid}" for pid in processes if str(pid).strip()]
    return blockers


def protected_changes(before: Mapping[str, Optional[str]], after: Mapping[str, Optional[str]]) -> list[str]:
    """Differences in the MVP and legacy containers' identity and lifecycle (None = absent)."""
    problems = []
    for name in sorted(set(before) | set(after)):
        if before.get(name) != after.get(name):
            problems.append(f"{name} changed: {before.get(name)!r} -> {after.get(name)!r}")
    return problems


def legacy_problem(state: Optional[str]) -> Optional[str]:
    """The legacy PostgreSQL must be absent or exited: this validation never starts it."""
    if state is None:
        return None
    fields = state.split(" ")
    if len(fields) < 2 or fields[1] != "exited":
        return f"{LEGACY_POSTGRES} is not exited: {state}"
    return None


# ---------------------------------------------------------------------------
# Classification of results
# ---------------------------------------------------------------------------

def classify(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The verdict of the integration cases.

    PASS needs every deterministic case present exactly once with status PASS, and no FAIL
    anywhere.  A missing, skipped (BLOCKED), malformed or unknown record can never produce a
    PASS.  Timing-sensitive cases (OBSERVED / NOT_OBSERVED / INCONCLUSIVE) are reported and do
    not decide the verdict; a FAIL in one of them (a safety violation) does."""
    problems: list[str] = []
    by_case: dict[str, list[str]] = {}
    for record in records:
        case = record.get("case") if isinstance(record, Mapping) else None
        status = record.get("status") if isinstance(record, Mapping) else None
        if case not in DETERMINISTIC_CASES + TIMING_CASES:
            problems.append(f"unknown case {case!r}")
            continue
        allowed = DETERMINISTIC_STATUSES if case in DETERMINISTIC_CASES else TIMING_STATUSES
        if status not in allowed:
            problems.append(f"{case}: invalid status {status!r}")
            status = "FAIL"
        by_case.setdefault(case, []).append(status)

    deterministic: dict[str, str] = {}
    for case in DETERMINISTIC_CASES:
        statuses = by_case.get(case, [])
        if not statuses:
            deterministic[case] = "MISSING"
        elif len(statuses) > 1:
            deterministic[case] = "FAIL" if "FAIL" in statuses else "DUPLICATE"
        else:
            deterministic[case] = statuses[0]
    timing = {case: (by_case[case][0] if len(by_case.get(case, [])) == 1 else
                     ("MISSING" if case not in by_case else "FAIL" if "FAIL" in by_case[case] else "DUPLICATE"))
              for case in TIMING_CASES}

    failed = [c for c, s in {**deterministic, **timing}.items() if s == "FAIL"]
    not_passed = [c for c, s in deterministic.items() if s != "PASS"]
    if failed or problems:
        overall = "FAIL"
    elif not_passed:
        overall = "BLOCKED" if all(deterministic[c] in ("BLOCKED", "MISSING") for c in not_passed) else "FAIL"
    else:
        overall = "PASS"
    return {"overall": overall, "deterministic": deterministic, "timing": timing,
            "failed": failed, "not_passed": not_passed, "problems": problems}


def final_verdict(classification: Mapping[str, Any], *, cleanup_verified: bool, pytest_exit: Optional[int],
                  evidence_clean: bool = True) -> str:
    """PASS only when the cases passed, pytest exited 0, cleanup was verified (this includes
    every process this run started) and no credential remains in the evidence."""
    if classification.get("overall") != "PASS":
        return str(classification.get("overall", "FAIL"))
    if pytest_exit != 0 or not cleanup_verified or not evidence_clean:
        return "FAIL"
    return "PASS"


# ---------------------------------------------------------------------------
# Process-tree termination (only the exact process this run started)
# ---------------------------------------------------------------------------

#: PIDs below this are never a target (System Idle, System, init).
_MIN_TARGET_PID = 5
PROCESS_REPORT = "process-report.json"


def _children_of(pid: int, run: Callable[..., Any] = subprocess.run) -> set[int]:
    """Every descendant of `pid`, found by parent-process id (never by command line)."""
    if os.name == "nt":
        result = run(["powershell", "-NoProfile", "-Command",
                      "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId) $($_.ParentProcessId)\" }"],
                     capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    else:
        result = run(["ps", "-eo", "pid=,ppid="], capture_output=True, text=True, timeout=60,
                     stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise OSError(f"the process table could not be read (exit {result.returncode})")
    parent_of: dict[int, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and all(f.isdigit() for f in fields):
            parent_of[int(fields[0])] = int(fields[1])
    found: set[int] = set()
    frontier = {pid}
    while frontier:
        frontier = {child for child, parent in parent_of.items() if parent in frontier and child not in found
                    and child != pid}
        found |= frontier
    return found


def _pid_alive(pid: int, run: Callable[..., Any] = subprocess.run) -> bool:
    if os.name == "nt":
        result = run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                     timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            raise OSError(f"tasklist failed (exit {result.returncode})")
        return f'"{pid}"' in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate_process_tree(process: Any, *, run: Callable[..., Any] = subprocess.run,
                           children: Callable[[int], set[int]] = _children_of,
                           alive: Callable[[int], bool] = _pid_alive,
                           kill_pid: Optional[Callable[[int], None]] = None,
                           windows: Optional[bool] = None, grace: float = 15.0,
                           sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Stops the process this run started and everything below it, and VERIFIES it.

    The target is the exact PID of the Popen object (a virtual environment's python.exe on Windows
    is a launcher whose child is the real interpreter, so a plain kill is not enough) and the
    descendants found by parent-process id.  Nothing is chosen by matching command lines.
    Returns the problems: an empty list means every one of those PIDs is verified gone."""
    pid = getattr(process, "pid", None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < _MIN_TARGET_PID or pid == os.getpid():
        raise SmokeFailure(f"refusing to terminate process id {pid!r}")
    windows = (os.name == "nt") if windows is None else windows
    problems: list[str] = []
    try:
        targets = set(children(pid))
    except Exception as exc:  # noqa: BLE001 - enumeration is part of the verification
        targets = set()
        problems.append(f"descendants of pid {pid} could not be listed: {type(exc).__name__}")
    targets.discard(os.getpid())
    # A process this run already reaped may have had its PID reused: the root PID is then never
    # signalled; only the descendants found through it are.
    running = process.poll() is None
    if windows:
        for root in ([pid] if running else sorted(targets)):
            try:
                run(["taskkill", "/PID", str(root), "/T", "/F"], capture_output=True, timeout=30,
                    stdin=subprocess.DEVNULL)
            except Exception as exc:  # noqa: BLE001
                problems.append(f"taskkill for pid {root} failed: {type(exc).__name__}")
    else:
        for target in sorted(targets):
            try:
                (kill_pid or _posix_kill)(target)
            except OSError:
                pass
        if running:
            try:
                process.kill()
            except OSError:
                pass
    if running:
        try:
            process.wait(timeout=grace)
        except Exception:  # noqa: BLE001 - TimeoutExpired: one plain kill of the same process, then verify
            try:
                process.kill()
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
    for target in sorted(targets | ({pid} if running else set())):
        gone = False
        for _ in range(10):
            try:
                if not alive(target):
                    gone = True
                    break
            except Exception as exc:  # noqa: BLE001
                problems.append(f"pid {target} could not be checked: {type(exc).__name__}")
                gone = None
                break
            sleep(0.5)
        if gone is False:
            problems.append(f"pid {target} is still running")
    if running and process.poll() is None and not any(f"pid {pid} " in p for p in problems):
        problems.append(f"pid {pid} is still running")
    return problems


def _posix_kill(pid: int) -> None:
    import signal
    os.kill(pid, signal.SIGKILL)


def read_process_report(evidence_dir: Optional[Path]) -> list[str]:
    """Problems the test process recorded about processes it could not verify stopped.  A
    report that exists but cannot be read counts as a problem."""
    if evidence_dir is None:
        return []
    path = Path(evidence_dir) / PROCESS_REPORT
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("not a list")
    except (OSError, ValueError):
        return ["the process report of the test run could not be read"]
    return [f"process not verified stopped: {str(item)[:200]}" for item in data]


# ---------------------------------------------------------------------------
# Evidence (always outside the repository)
# ---------------------------------------------------------------------------

def evidence_root() -> Path:
    return Path(tempfile.gettempdir()) / "agentops-batching-it"


def new_run_id() -> str:
    return "bit-" + uuid.uuid4().hex[:8]


def evidence_dir_for(run_id: str, root: Optional[Path] = None, repo: Optional[Path] = None) -> Path:
    if not re.fullmatch(r"bit-[0-9a-f]{8}", run_id or ""):
        raise SmokeFailure(f"run id {run_id!r} is not bit-<8 hex>")
    root = (evidence_root() if root is None else Path(root)).resolve()
    repo = (smoke.REPO if repo is None else Path(repo)).resolve()
    if root == repo or repo in root.parents:
        raise SmokeFailure("the evidence directory would be inside the repository")
    return root / run_id


def sanitize(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _evidence_files(directory: Path) -> list[Path]:
    return [p for p in sorted(Path(directory).rglob("*")) if p.is_file() and p.name != "manifest.sha256.json"]


def sanitize_tree(directory: Path, secrets: Sequence[str]) -> int:
    """Masks every secret in every file of the evidence directory, in place (bytes, so the file
    type does not matter).  Returns the number of files that changed."""
    needles = [s.encode("utf-8") for s in secrets if s]
    changed = 0
    for path in _evidence_files(directory):
        data = path.read_bytes()
        cleaned = data
        for needle in needles:
            cleaned = cleaned.replace(needle, b"<redacted>")
        if cleaned != data:
            path.write_bytes(cleaned)
            changed += 1
    return changed


def find_secret_leaks(directory: Path, secrets: Sequence[str]) -> list[str]:
    """Relative names of evidence files that still contain a secret.  Only names are returned,
    never the secret or the text around it."""
    needles = [s.encode("utf-8") for s in secrets if s]
    root = Path(directory)
    return [p.relative_to(root).as_posix() for p in _evidence_files(root)
            if any(needle in p.read_bytes() for needle in needles)]


def finalize_evidence(directory: Path, secrets: Sequence[str]) -> list[str]:
    """Sanitize every artifact, then verify; returns the files that still hold a secret."""
    sanitize_tree(directory, secrets)
    return find_secret_leaks(directory, secrets)


#: Files of the temporary directory worth keeping when a run fails before pytest: logs only.
_DIAGNOSTIC_SUFFIXES = (".log", ".txt")


def preserve_diagnostics(evidence_dir: Path, temp: Optional[Path], secrets: Sequence[str]) -> list[str]:
    """Copies the sanitized logs of the temporary directory (startup, build, bootstrap, dependency
    installation) into the evidence directory.  Must run before the temporary directory is deleted.
    Never copies smoke.env or any non-log file."""
    if temp is None or not Path(temp).is_dir() or not Path(evidence_dir).is_dir():
        return []
    target = Path(evidence_dir) / "diagnostics"
    copied: list[str] = []
    for path in sorted(Path(temp).glob("*")):
        if path.is_file() and path.suffix in _DIAGNOSTIC_SUFFIXES and path.name != "smoke.env":
            target.mkdir(exist_ok=True)
            text = path.read_text(encoding="utf-8", errors="replace")
            (target / path.name).write_text(sanitize(text, secrets), encoding="utf-8")
            copied.append(path.name)
    return copied


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_manifest(directory: Path) -> dict[str, str]:
    """SHA-256 of every file of the evidence directory except the manifest itself."""
    directory = Path(directory)
    return {path.relative_to(directory).as_posix(): sha256_file(path)
            for path in sorted(directory.rglob("*"))
            if path.is_file() and path.name != "manifest.sha256.json"}


def write_manifest(directory: Path) -> Path:
    path = Path(directory) / "manifest.sha256.json"
    path.write_text(json.dumps(build_manifest(directory), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def marker_path(root: Optional[Path] = None) -> Path:
    return (evidence_root() if root is None else Path(root)) / "CLEANUP_UNVERIFIED"


def write_marker(reason: str, root: Optional[Path] = None) -> Path:
    path = marker_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(reason[:2000] + "\n", encoding="utf-8")
    return path


def integration_environment(*, project: str, run_id: str, evidence_dir: Path, password: str,
                            kafka_port: int = KAFKA_PORT, pg_port: int = POSTGRES_PORT,
                            python: str = "", repo: Optional[Path] = None) -> dict[str, str]:
    """The explicit environment of the test process: a few system variables, the opt-in switch,
    the disposable endpoints and the temporary credential.  Nothing else is inherited."""
    validate_endpoint("127.0.0.1", kafka_port)
    validate_endpoint("127.0.0.1", pg_port)
    repo = smoke.REPO if repo is None else Path(repo)
    env = smoke.host_environment(
        AGENTOPS_BATCHING_IT="1",
        AGENTOPS_IT_PROJECT=project,
        AGENTOPS_IT_RUN_ID=run_id,
        AGENTOPS_IT_EVIDENCE_DIR=str(evidence_dir),
        AGENTOPS_IT_KAFKA=f"127.0.0.1:{kafka_port}",
        AGENTOPS_IT_PG_HOST="127.0.0.1",
        AGENTOPS_IT_PG_PORT=str(pg_port),
        AGENTOPS_IT_PG_DATABASE="agentops",
        AGENTOPS_IT_PG_USER="agentops",
        AGENTOPS_IT_PG_PASSWORD=password,
        AGENTOPS_IT_REPO=str(repo),
        AGENTOPS_IT_PYTHON=python or sys.executable,
    )
    env["PYTHONPATH"] = os.pathsep.join([str(repo / "storage-consumer"), str(repo / "demo-app")])
    return env


def pytest_command(python: Any, evidence_dir: Path) -> list[str]:
    """The only test file this harness runs.  The older persistence test that targets the
    normal stack (storage-consumer/tests/integration/test_persistence_e2e.py) is never named."""
    return [str(python), "-B", "-m", "pytest", TEST_FILE, "-q", "-rs", "-p", "no:cacheprovider",
            "--junitxml", str(Path(evidence_dir) / "junit.xml")]


# ---------------------------------------------------------------------------
# Live state (everything below talks to the machine; none of it runs at import)
# ---------------------------------------------------------------------------

class State:
    project: str = ""
    run_id: str = ""
    expect_head: str = ""
    evidence: Optional[Path] = None
    protected_before: Optional[dict[str, Optional[str]]] = None
    secrets: list[str] = []
    process_problems: list[str] = []
    logs_collected: bool = False


S = State()


def current_secrets() -> list[str]:
    """Every generated credential known so far (kept after the run object is cleaned up)."""
    S.secrets = list(dict.fromkeys([*S.secrets, *smoke.RUN.generated.values()]))
    return list(S.secrets)


def _git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(smoke.REPO), *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL, timeout=60)
    if result.returncode != 0:
        raise SmokeFailure(f"git {' '.join(args[:2])}: exit {result.returncode}: " + result.stderr.strip()[-200:])
    return result.stdout


def available_memory_mib() -> float:
    if os.name == "nt":
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong) for name in ("tp", "ap", "tpf", "apf", "tv", "av", "ae")]

        status = Status()
        status.l = ctypes.sizeof(Status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return float("nan")
        return status.ap / 1024 ** 2
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return float("nan")


def protected_snapshot() -> dict[str, Optional[str]]:
    """Identity and lifecycle of the MVP containers and the legacy PostgreSQL (read-only)."""
    snapshot: dict[str, Optional[str]] = {}
    for name in (*MVP_CONTAINERS, LEGACY_POSTGRES):
        result = smoke.run(
            ["docker", "inspect", "-f",
             "{{.Id}} {{.State.Status}} {{.State.StartedAt}} {{.State.FinishedAt}} {{.RestartCount}}", name],
            timeout=smoke.T_COMMAND, what="docker inspect")
        snapshot[name] = result.stdout.strip() if result.returncode == 0 else None
    return snapshot


def benchmark_markers() -> list[str]:
    folder = Path(tempfile.gettempdir()) / "agentops-benchmarks"
    return [name for name in ("ACTIVE_RUN", "CLEANUP_UNVERIFIED") if (folder / name).exists()]


def competing_processes() -> list[str]:
    pattern = "run_benchmark|run_smoke|run_e2e|run_pipeline_it|stream-processor|storage-consumer|calibrate_generator"
    if os.name == "nt":
        result = smoke.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '" + pattern + "' -and "
             f"$_.ProcessId -ne {os.getpid()} -and $_.CommandLine -notmatch 'run_commit_batching_it' }} "
             "| ForEach-Object { $_.ProcessId }"],
            timeout=smoke.T_COMMAND, what="process list")
        return result.stdout.split()
    result = smoke.run(["ps", "-eo", "pid,args"], timeout=smoke.T_COMMAND, what="process list")
    return [line.split(None, 1)[0] for line in result.stdout.splitlines()[1:]
            if re.search(pattern, line) and "run_commit_batching_it" not in line
            and line.split(None, 1)[0] != str(os.getpid())]


class BatchingOps:
    """What cleanup touches, scoped by the project name; the interface run_pipeline_it.safe_cleanup uses."""

    def __init__(self, project: str) -> None:
        if project == "agentops" or not _PROJECT_RE.fullmatch(project):
            raise SmokeFailure(f"cleanup refuses the project name {project!r}")
        self.project = project
        self.log: list[str] = []

    def can_down(self) -> bool:
        return bool(smoke.RUN.compose_used and smoke.RUN.env_file is not None and smoke.RUN.env_file.is_file())

    def down(self) -> tuple[int, str]:
        # run_smoke's compose_command takes the project from its module global; teardown is
        # refused, never redirected, when that is not the project this orchestrator generated.
        if smoke.PROJECT != self.project:
            raise SmokeFailure(f"refusing compose down: the Compose project is {smoke.PROJECT!r}, "
                               f"not the generated {self.project!r}")
        result = smoke.run(smoke.compose_command("down", "--volumes", "--rmi", "local", "--remove-orphans"),
                           timeout=smoke.T_DOWN, what="compose down")
        tail = smoke.redact(result.stderr.strip()[-300:])
        self.log.append(f"compose down (project {self.project}): exit {result.returncode}\n{tail}")
        return result.returncode, tail

    def project_objects(self, kind: str) -> list[str]:
        label = f"label={_LABEL_PROJECT}={self.project}"
        command = {"containers": ["ps", "-a", "-q", "--filter", label],
                   "networks": ["network", "ls", "-q", "--filter", label],
                   "volumes": ["volume", "ls", "-q", "--filter", label],
                   "images": ["images", "-q", "--filter", label]}[kind]
        return smoke.docker_lines(*command)

    def owned_images(self) -> list[str]:
        listed = smoke.docker_lines("images", "--filter", f"label={_LABEL_PROJECT}={self.project}",
                                    "--format", "{{.Repository}}:{{.Tag}}")
        return [ref for ref in listed if ref.startswith(self.project + "-") and "<none>" not in ref]

    def remove_image(self, reference: str) -> bool:
        if not reference.startswith(self.project + "-"):
            raise SmokeFailure(f"refusing to remove {reference!r}: not named after the project")
        return smoke.run(["docker", "image", "remove", reference], timeout=smoke.T_COMMAND,
                         what="docker image remove").returncode == 0

    def fingerprint(self) -> dict[str, list[str]]:
        return smoke.docker_fingerprint()

    def leaked(self) -> int:
        count = smoke.RUN.masked_in_logs
        if smoke.RUN.temp is not None and smoke.RUN.temp.exists():
            for path in smoke.RUN.temp.glob("*"):
                if path.is_file() and path.name != "smoke.env":
                    text = path.read_text(encoding="utf-8", errors="replace")
                    count += sum(text.count(v) for v in smoke.RUN.generated.values())
        return count

    def remove_temp(self) -> bool:
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
            unexpected = [line for line in smoke.repository_state() if line not in smoke.ALLOWED_UNTRACKED]
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


def read_results(evidence_dir: Path) -> list[dict[str, Any]]:
    path = Path(evidence_dir) / "results.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def collect_logs(evidence_dir: Path, secrets: Sequence[str]) -> None:
    """Sanitized container logs of the project, best effort."""
    for service in ("kafka", "postgres"):
        try:
            text = smoke.compose("logs", "--no-color", "--tail", "400", service, what=f"logs {service}")
        except SmokeFailure as failure:
            text = f"logs not available: {failure}"
        (Path(evidence_dir) / f"{service}.log").write_text(sanitize(text, secrets), encoding="utf-8")
    S.logs_collected = True


def run_tests(python: Path, env: Mapping[str, str], evidence_dir: Path, secrets: Sequence[str]) -> int:
    """Runs the one integration module; returns pytest's exit code (nothing is retried).

    pytest is started with Popen so that, on a timeout or an interruption, the process tree of
    exactly this pytest (it starts the real consumer in one case) is terminated and verified.
    A tree that cannot be verified gone is recorded and blocks later runs."""
    output = Path(evidence_dir) / "pytest-output.txt"
    process = subprocess.Popen(pytest_command(python, evidence_dir), cwd=smoke.REPO, env=dict(env),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                               errors="replace", stdin=subprocess.DEVNULL)
    try:
        stdout, stderr = process.communicate(timeout=PYTEST_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        S.process_problems.extend(f"pytest timeout: {p}" for p in terminate_process_tree(process))
        try:
            stdout, stderr = process.communicate(timeout=30)
        except Exception:  # noqa: BLE001 - a surviving grandchild may hold the pipes open
            stdout = stderr = ""
        output.write_text("pytest timed out\n" + sanitize((stdout or "") + "\n" + (stderr or ""), secrets),
                          encoding="utf-8")
        return 124
    except BaseException:
        S.process_problems.extend(f"pytest interrupted: {p}" for p in terminate_process_tree(process))
        raise
    output.write_text(sanitize(stdout + "\n" + stderr, secrets), encoding="utf-8")
    return process.returncode


def preflight() -> None:
    section("preflight")
    check_git_state(S.expect_head, _git)
    if sys.version_info[:2] != (3, 13):
        raise SmokeFailure("this validation needs Python 3.13")
    source, percent = pipeline.power_state()
    say(f"power: {source}, {percent}%")
    if source == "battery" and percent < pipeline.MIN_BATTERY_PERCENT:
        raise SmokeFailure(f"on battery at {percent}%")
    memory = memory_gate(available_memory_mib())
    say(memory.message)
    if not memory.ok:
        raise SmokeFailure(memory.message)
    if not memory.preferred:
        say("note: below the preferred memory headroom")
    info = json.loads(smoke.checked(["docker", "info", "--format", "{{json .}}"], timeout=smoke.T_COMMAND,
                                    what="docker info"))
    engine = engine_gate(info.get("MemTotal"))
    say(f"Docker engine: NCPU {info.get('NCPU')}, {engine.message}")
    if not engine.ok:
        raise SmokeFailure(engine.message)
    disk = disk_gate(shutil.disk_usage(str(smoke.REPO)).free)
    say(disk.message)
    if not disk.ok:
        raise SmokeFailure(disk.message)


def it(expect_head: str) -> tuple[list[dict[str, Any]], Optional[int], list[str]]:
    S.expect_head = expect_head
    preflight()
    S.project = new_project_name()
    S.run_id = new_run_id()
    smoke.PROJECT = S.project
    smoke.ALLOWED_UNTRACKED = frozenset()
    smoke.RUN.caches_before = smoke.bytecode_caches()
    say(f"project {S.project}; run id {S.run_id}")

    S.evidence = evidence_dir_for(S.run_id)
    root = S.evidence.parent
    smoke.check_ports()
    fingerprint = smoke.docker_fingerprint()
    validate_project_name(S.project, [line for kind in fingerprint.values() for line in kind])
    blockers = find_blockers(
        benchmark_markers=benchmark_markers(),
        own_markers=[marker_path(root).name] if marker_path(root).exists() else [],
        docker_lines=[line for kind in fingerprint.values() for line in kind],
        processes=competing_processes())
    section("no competing activity")
    say(f"blockers: {blockers or 'none'}")
    if blockers:
        raise SmokeFailure("cannot start: " + "; ".join(blockers[:5]))
    S.protected_before = protected_snapshot()
    problem = legacy_problem(S.protected_before.get(LEGACY_POSTGRES))
    say(f"protected containers: {sorted(k for k, v in S.protected_before.items() if v)}")
    if problem:
        raise SmokeFailure(problem)

    S.evidence.mkdir(parents=True, exist_ok=False)
    smoke.create_workspace()
    current_secrets()
    smoke.check_render()
    smoke.record_docker_state()
    smoke.start_kafka()
    smoke.create_topics()
    smoke.start_postgres()
    smoke.run_bootstrap()
    smoke.create_virtual_environment()
    assert smoke.RUN.python is not None and smoke.RUN.generated
    password = smoke.RUN.generated["POSTGRES_PASSWORD"]
    env = integration_environment(project=S.project, run_id=S.run_id, evidence_dir=S.evidence,
                                  password=password, python=str(smoke.RUN.python))
    section("integration tests")
    say(f"python {smoke.RUN.python}; test file {TEST_FILE}")
    code = run_tests(smoke.RUN.python, env, S.evidence, [password, *smoke.RUN.generated.values()])
    say(f"pytest exit code {code}")
    collect_logs(S.evidence, [password, *smoke.RUN.generated.values()])
    return read_results(S.evidence), code, list(smoke.RUN.generated.values())


def teardown() -> bool:
    """Project teardown.  Unverified processes (pytest, or the consumer the tests started) are
    cleanup problems like a leftover volume: they write the blocking marker."""
    section("project teardown")
    ops = BatchingOps(S.project)
    problems: list[str] = []
    try:
        problems.extend(pipeline.safe_cleanup(S.project, smoke.RUN.before, ops))
        if S.protected_before is not None:
            problems.extend(protected_changes(S.protected_before, protected_snapshot()))
    finally:
        # also when the teardown itself was interrupted: what is known is kept
        problems.extend(S.process_problems)
        problems.extend(read_process_report(S.evidence))
        _write_teardown_log(ops, problems)
        for problem in problems:
            say(f"CLEANUP PROBLEM: {problem}")
        if problems:
            write_marker("; ".join(problems))
    return not problems


def _write_teardown_log(ops: BatchingOps, problems: Sequence[str]) -> None:
    if S.evidence is None or not S.evidence.is_dir():
        return
    try:
        text = "\n".join([*ops.log, *(f"CLEANUP PROBLEM: {p}" for p in problems)]) or "no teardown output"
        (S.evidence / "teardown.log").write_text(sanitize(text, current_secrets()) + "\n", encoding="utf-8")
    except OSError:
        pass


def preserve_failure_evidence(secrets: Sequence[str], ran: bool) -> None:
    """Before the temporary directory is deleted: the sanitized startup, build, bootstrap and
    dependency-installation logs, and (if pytest never ran) the project's container logs."""
    if S.evidence is None or not S.evidence.is_dir():
        return
    try:
        copied = preserve_diagnostics(S.evidence, smoke.RUN.temp, secrets)
        if copied:
            say(f"diagnostics kept: {', '.join(copied)}")
    except Exception as exc:  # noqa: BLE001 - evidence is best effort
        say(f"diagnostics could not be kept: {type(exc).__name__}")
    if not ran and not S.logs_collected and smoke.RUN.compose_used:
        try:
            collect_logs(S.evidence, secrets)
        except Exception as exc:  # noqa: BLE001
            say(f"container logs could not be kept: {type(exc).__name__}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_commit_batching_it",
        description="Integration validation of the batched Kafka offset commits on a disposable Compose project.")
    parser.add_argument("--expect-head", required=True, metavar="COMMIT")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")

    pipeline.keep_awake()
    records: list[dict[str, Any]] = []
    code: Optional[int] = None
    ran = False
    try:
        records, code, _ = it(args.expect_head)
        ran = True
    except SmokeFailure as failure:
        section("FAILURE")
        say(str(failure))
    except KeyboardInterrupt:
        section("FAILURE")
        say("interrupted")
    except Exception as exc:  # anything unforeseen is a failure, and is cleaned up too
        section("FAILURE")
        say(f"{type(exc).__name__}: {exc}")
    secrets = current_secrets()
    preserve_failure_evidence(secrets, ran)
    interrupted: Optional[BaseException] = None
    try:
        clean = teardown() if S.project else True
    except BaseException as exc:  # noqa: BLE001 - an interrupted teardown must still leave the marker
        clean = False
        say(f"CLEANUP PROBLEM: {type(exc).__name__}: {exc}")
        try:
            write_marker(f"{type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001
            pass
        if not isinstance(exc, Exception):
            interrupted = exc                    # propagated after the summary, unchanged
    pipeline.release_awake()

    classification = classify(records)
    leaks: list[str] = []
    evidence_ready = S.evidence is not None and S.evidence.is_dir()
    if evidence_ready:
        leaks = finalize_evidence(S.evidence, secrets)
    verdict = (final_verdict(classification, cleanup_verified=clean, pytest_exit=code, evidence_clean=not leaks)
               if ran else "FAIL")
    if evidence_ready:
        def write_verdict() -> None:
            (S.evidence / "verdict.json").write_text(
                json.dumps({"verdict": verdict, "cleanup_verified": clean, "pytest_exit": code,
                            "evidence_files_with_a_credential": leaks,
                            "classification": classification}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_verdict()
        late = finalize_evidence(S.evidence, secrets)
        if late and not leaks:
            leaks, verdict = late, "FAIL"
            write_verdict()
        if leaks:
            say(f"CREDENTIAL FOUND IN EVIDENCE FILES: {', '.join(leaks)}")
        say(f"evidence: {S.evidence} (manifest {write_manifest(S.evidence).name})")
    section("result")
    for case in DETERMINISTIC_CASES:
        say(f"  {case:34} {classification['deterministic'][case]}")
    for case in TIMING_CASES:
        say(f"  {case:34} {classification['timing'][case]}")
    say(f"overall: {verdict}")
    say(f"cleanup verified: {'yes' if clean else 'NO'}")
    if interrupted is not None:
        raise interrupted
    return 0 if verdict == "PASS" and clean else 1


if __name__ == "__main__":
    sys.exit(main())

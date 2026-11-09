"""
benchmarks/calibrate_generator.py

Generator-only calibration, condition A: how much do the workload
generator's own request starts lag behind their planned times, with no
AgentOps platform running at all?

The real scheduling path is reused unchanged: real_driver.execute() with its
dispatcher, semaphore, ThreadPoolExecutor, fault injector, BatchSpanProcessor
and start-lag diagnostic, driven by the real clock (time.monotonic) and the
real pause (time.sleep).  Only the span exporter differs: spans go to an
in-memory exporter, so nothing is exported anywhere.  run_real, its
reachability check and the OTLP exporter are never called.

Traffic is the SMOKE cell's: seed 42, warm-up 25 and measured 100 requests,
rate 5 per second, concurrency 32 (arrivals and planned latencies depend on
the seed only).  Run ids are cal-a-wNN / cal-a-mNN; calibration ids are
cal-a-NN, never benchmark (bm-) ids.

Two modes in this one file:
    orchestrator  plans the series; with --execute runs it, one child
                  process at a time, under an exclusive ACTIVE_CALIBRATION
                  ownership record, with exclusive journal, output and result
                  files per run
    child         (--child, started only by the orchestrator) checks the
                  series token, installs the Python network guard, then
                  imports the driver and the demo agent, runs warm-up +
                  measured, writes its result, and exits with its own status

Execution gates (all must hold; none is enough alone):
    - EXECUTION_ENABLED is True (it is False here);
    - every calibration id is in APPROVED_CALIBRATIONS (empty here);
    - --expect-head is the full 40-character Git HEAD and equals it;
    - a child runs only with the series token of the ACTIVE_CALIBRATION
      record in its output directory.
  authorize() is the only way to obtain an Authorization.  Every function
  that could start a process, import the driver or the demo, or observe the
  host requires one, so changing EXECUTION_ENABLED alone starts nothing.
  child_main() and run_series() take their dependencies explicitly; the
  production dependencies come only from the gated factories.

Network safety, stated precisely:
    - The intended denial mechanism is a Windows AppContainer with NO
      capabilities (no internetClient, internetClientServer or
      privateNetworkClientServer) and no loopback exemption: Windows then
      refuses the child's outbound and loopback connections in the kernel,
      for native code too.  The Win32 backend (ctypes, documented APIs)
      starts the base interpreter directly - never the venv launcher, whose
      own child would be a second process - suspended, inside the profile
      whose SID is AUTHORIZED_APPCONTAINER_SID (None here) and whose
      independently verified preflight record matches
      AUTHORIZED_PROFILE_PREFLIGHT_SHA256 (None here; GetAppContainerFolderPath
      is supplementary and is not proof that a profile exists).  It checks
      the real token, process identity and loopback exemption, and only then
      resumes it; otherwise the suspended child is terminated and its exit
      verified, or its PID and handles are kept for inspection.  Execution
      history (never / may have executed / unknown) and liveness (confirmed
      exited / alive at last check / unknown) are recorded separately in
      every journal.  AppContainer compatibility of CPython, the venv
      packages and the demo is NOT assumed: the isolation probe must show
      it first.
    - The isolation probe (--probe, separately gated by PROBE_ENABLED and
      APPROVED_PROBES, both closed here) runs a child in the AppContainer
      that never imports the workload driver.  It reports interpreter
      startup, its own token, a loopback connection attempt to a dedicated
      listener of the orchestrator, the dependency imports under the guard,
      and a lookup of "localhost" that is supplementary evidence only.  The
      orchestrator first proves the listener reachable from outside (one
      control connection), and again after the child; the child's attempt
      counts as denied only on WSAEACCES (10013) - refusal, timeout,
      unreachable or other errors are inconclusive failures - and the
      listener must have received nothing from it.  Only loopback denial is
      tested, not external network denial.  No external name or service,
      Kafka, PostgreSQL or OTLP is contacted.
    - Inside the child, as defence in depth only: a Python-level guard
      blocks socket creation, connect/connect_ex/sendto/sendmsg, and name
      resolution (getaddrinfo, getnameinfo, gethostbyname[_ex],
      gethostbyaddr, create_connection, create_server, socketpair, fromfd),
      and the native network libraries (grpc, the OTLP exporters,
      confluent_kafka, psycopg, kafka) are replaced by stubs that refuse
      to be used.  Any attempt fails the run and stops the series.
    - The orchestrator observes the child and its descendants at the OS
      level (TCP connections, UDP endpoints, loaded network DLLs), failing
      closed on any observation error.  The observation is periodic and
      cannot see name resolution done by the Windows DNS Client service.
    - Neither the Python guard nor the periodic observation guarantees
      network isolation.  They are evidence, not denial.

Proposed operational workflow (each step needs its OWN authorization; none
is performed by this file):
    1. Create the AppContainer profile APPCONTAINER_PROFILE with no
       capabilities (CreateAppContainerProfile); record its SID; confirm no
       loopback exemption (CheckNetIsolation LoopbackExempt -s).
    2. Snapshot the ACLs (icacls <path> /save) of the Python installation,
       the venv, the repository and a dedicated output directory; grant the
       profile SID read+execute on the first three and modify on the
       output directory only.
    3. Set AUTHORIZED_APPCONTAINER_SID, PROBE_ENABLED and APPROVED_PROBES
       (a reviewed code change), then run one isolation probe (--probe):
       the orchestrator listens on an ephemeral 127.0.0.1 port that the
       probe must fail to reach; the token must validate; CPython and the
       dependency imports must work.  No external address is contacted.
    4. Restore the ACLs from the snapshot (icacls /restore) and verify them;
       delete the profile (DeleteAppContainerProfile) unless step 5 is
       authorized in the same window.
    5. Enabling calibration (EXECUTION_ENABLED, APPROVED_CALIBRATIONS) is a
       reviewed code change; running a calibration run or series is a
       separate authorization, followed by step 4.

Outputs go only to <temp>/agentops-calibration (never inside the repository,
never inside the benchmark directory).  Nothing in the benchmark directory
is written by this file.

Analysis is descriptive: delayed-request groups, delay propagation, burst
association, late-start distribution.  These are OBSERVATIONS; no cause of
a delay is inferred from them.

Standard library only at import time.
"""

from __future__ import annotations

import argparse
import errno as errno_module
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import tempfile
import time
import types
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

HERE: Path = Path(__file__).resolve().parent
REPO: Path = HERE.parent
GENERATOR_DIR: Path = REPO / "workload-generator"
DEMO_DIR: Path = REPO / "demo-app"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import metrics as M  # noqa: E402
import run_benchmark as RB  # noqa: E402

#: Real calibration runs are not reachable until an independently enforced
#: network-denial mechanism has been put in place and approved.
EXECUTION_ENABLED: bool = False
#: Calibration ids that may run.  Empty: none may.
APPROVED_CALIBRATIONS: frozenset[str] = frozenset()
#: The isolation probe is gated separately from calibration.
PROBE_ENABLED: bool = False
#: Probe ids that may run.  Empty: none may.
APPROVED_PROBES: frozenset[str] = frozenset()
#: SID of the existing, explicitly authorized AppContainer profile.  None:
#: no profile is authorized, so nothing can be launched.
AUTHORIZED_APPCONTAINER_SID: Optional[str] = None
#: SHA-256 of the independently verified profile-preflight record.  None:
#: no record is authorized, so nothing can be launched.
AUTHORIZED_PROFILE_PREFLIGHT_SHA256: Optional[str] = None

CONDITION: str = "a"
SEED: int = 42
RATE: float = 5.0
CONCURRENCY: int = 32
WARMUP_REQUESTS: int = 25
MEASURED_REQUESTS: int = 100
MAX_RUNS: int = 20
#: The driver's late-start threshold and the benchmark's 5% rule, unchanged.
LATE_START_SECONDS: float = RB.DRIVER_LATE_START_SECONDS
LATE_FRACTION: float = M.LATE_START_FRACTION

STAGE_MAX_SECONDS: float = 120.0
CHILD_TIMEOUT_SECONDS: float = 180.0
REST_SECONDS: float = 15.0
OBSERVE_INTERVAL_SECONDS: float = 2.0
#: One OS observation may take this long before it counts as failed.
OBSERVE_TIMEOUT_SECONDS: float = 5.0
#: Longer than this between two observations is insufficient sampling.
MAX_SAMPLE_GAP_SECONDS: float = 6.0
MIN_SAMPLES: int = 1
#: Launcher and OS creation times of one process may differ by this much.
CREATION_TOLERANCE_SECONDS: float = 1.0
SERIES_BUDGET_SECONDS: float = 30 * 60

DEFAULT_OUTPUT: Path = Path(tempfile.gettempdir()) / "agentops-calibration"
DEFAULT_PROBE_OUTPUT: Path = Path(tempfile.gettempdir()) / "agentops-isolation-probe"
DEFAULT_PROFILE_PREFLIGHT: Path = (Path(tempfile.gettempdir())
                                   / "agentops-appcontainer-preflight.json")
BENCHMARK_OUTPUT: Path = RB.DEFAULT_OUTPUT
OWNER_FILE: str = "ACTIVE_CALIBRATION"
PROBE_OWNER_FILE: str = "ACTIVE_PROBE"
JOURNAL_DIR: str = "journal"

#: Exit statuses of the child.
EXIT_OK, EXIT_NETWORK, EXIT_FAILED, EXIT_PROBE_FAILED = 0, 3, 4, 5

PROBE_ID_RE = re.compile(r"probe-0[1-5]")
#: What the probe child imports (never the workload driver).
PROBE_IMPORTS: tuple[str, ...] = (
    "pydantic", "langgraph.graph", "opentelemetry.sdk.trace",
    "opentelemetry.sdk.trace.export.in_memory_span_exporter",
    "workload_generator.plan", "workload_generator.scenarios", "graph",
)
#: Modules the probe child must never import.
PROBE_FORBIDDEN_MODULES: tuple[str, ...] = ("workload_generator.real_driver",)
#: The loopback attempt gives up after this long (no connection is the goal).
PROBE_CONNECT_TIMEOUT_SECONDS: float = 2.0
#: Resolved only as supplementary evidence; never an external name.
PROBE_DNS_NAME: str = "localhost"
#: Exit code given to a suspended child that is discarded before resuming.
DISCARD_EXIT_CODE: int = 0x0BAD
DISCARD_WAIT_MILLISECONDS: int = 5000

#: A delayed request: start lag above this belongs to a stall group.
GROUP_MIN_LAG_SECONDS: float = 0.02
#: Requests whose implied dispatch times are this close form one group.
GROUP_TOLERANCE_SECONDS: float = 0.005
#: Arrivals closer than this to a neighbour are inside a burst.
BURST_GAP_SECONDS: float = 0.01

APPCONTAINER_PROFILE: str = "agentops.calibration.condition-a"
#: The calibration AppContainer's capabilities: none.
APPCONTAINER_CAPABILITIES: tuple[str, ...] = ()
#: Capability SIDs that would give an AppContainer network access.
NETWORK_CAPABILITY_SIDS: Mapping[str, str] = {
    "S-1-15-3-1": "internetClient",
    "S-1-15-3-2": "internetClientServer",
    "S-1-15-3-3": "privateNetworkClientServer",
}

_HEAD_RE = re.compile(r"[0-9a-f]{40}")
_TOKEN_RE = re.compile(r"[0-9a-f]{32}")


class CalibrationError(Exception):
    """The calibration cannot go on.  The message is the evidence."""


class ExecutionDisabled(CalibrationError):
    """Real calibration was requested where it is not enabled or authorized."""


class NetworkBlocked(ConnectionRefusedError):
    """A network operation was attempted inside a calibration child."""


# ---------------------------------------------------------------------------
# Execution gates
# ---------------------------------------------------------------------------

_SEAL = object()


@dataclass(frozen=True)
class Authorization:
    """Proof that authorize() passed.  Only authorize() can make a valid one."""
    calibration_ids: tuple[str, ...]
    expected_head: str
    seal: object = field(default=None, repr=False, compare=False)


def _require_enabled() -> None:
    if not EXECUTION_ENABLED:
        raise ExecutionDisabled(
            "real calibration is not enabled: an independently enforced network-denial "
            "mechanism must be in place and approved first; nothing was started")
    if not APPROVED_CALIBRATIONS:
        raise ExecutionDisabled("no calibration is approved (APPROVED_CALIBRATIONS is empty); "
                                "nothing was started")


def _require_authorization(auth: Any, calibration: Optional[str] = None) -> Authorization:
    """The gate of every production-capable function."""
    _require_enabled()
    if not isinstance(auth, Authorization) or auth.seal is not _SEAL:
        raise ExecutionDisabled("no valid calibration authorization; nothing was started")
    unapproved = sorted(set(auth.calibration_ids) - APPROVED_CALIBRATIONS)
    if unapproved:
        raise ExecutionDisabled(f"not approved: {', '.join(unapproved)}; nothing was started")
    if calibration is not None and calibration not in auth.calibration_ids:
        raise ExecutionDisabled(f"{calibration} is not covered by this authorization")
    return auth


def _read_git_head(repo: Path) -> str:
    """The full HEAD commit, read from the Git files (no git process, so a
    child inside an AppContainer can check it too)."""
    def fail(why: str) -> ExecutionDisabled:
        return ExecutionDisabled(f"the Git HEAD cannot be resolved ({why}); nothing was started")

    try:
        git = repo / ".git"
        if git.is_file():
            text = git.read_text(encoding="utf-8").strip()
            if not text.startswith("gitdir:"):
                raise fail(".git file without gitdir")
            gitdir = Path(text[len("gitdir:"):].strip())
            gitdir = gitdir if gitdir.is_absolute() else (repo / gitdir)
        else:
            gitdir = git
        common = gitdir
        if (gitdir / "commondir").is_file():
            relative = Path((gitdir / "commondir").read_text(encoding="utf-8").strip())
            common = relative if relative.is_absolute() else (gitdir / relative)
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip()
        if _HEAD_RE.fullmatch(head):
            return head
        if not head.startswith("ref: "):
            raise fail("unexpected HEAD")
        ref = head[len("ref: "):].strip()
        for base in (gitdir, common):
            loose = base.joinpath(*ref.split("/"))
            if loose.is_file():
                value = loose.read_text(encoding="utf-8").strip()
                if _HEAD_RE.fullmatch(value):
                    return value
                raise fail("malformed ref")
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref and _HEAD_RE.fullmatch(parts[0]):
                    return parts[0]
    except OSError as exc:
        raise fail(type(exc).__name__) from None
    raise fail("ref not found")


def _git_head(require: Optional[Callable[[], None]] = None) -> str:
    (require or _require_enabled)()
    return _read_git_head(REPO)


def authorize(calibration_ids: Sequence[str], expected_head: Optional[str]) -> Authorization:
    """An Authorization for exactly these approved ids at exactly this HEAD."""
    _require_enabled()
    ids = tuple(calibration_ids)
    if not ids or len(set(ids)) != len(ids):
        raise ExecutionDisabled("authorization needs distinct calibration ids")
    for cid in ids:
        if cid not in APPROVED_CALIBRATIONS:
            raise ExecutionDisabled(f"{cid} is not an approved calibration; nothing was started")
    if not isinstance(expected_head, str) or not _HEAD_RE.fullmatch(expected_head):
        raise ExecutionDisabled("--expect-head must be the full 40-character Git HEAD")
    actual = _git_head()
    if actual != expected_head:
        raise ExecutionDisabled(f"Git HEAD is {actual[:12]}, not the expected "
                                f"{expected_head[:12]}; nothing was started")
    return Authorization(ids, expected_head, _SEAL)


@dataclass(frozen=True)
class ProbeAuthorization:
    """Proof that authorize_probe() passed.  It never authorizes calibration."""
    probe_id: str
    expected_head: str
    seal: object = field(default=None, repr=False, compare=False)


def _require_probe_enabled() -> None:
    if not PROBE_ENABLED:
        raise ExecutionDisabled("the isolation probe is not enabled; nothing was started")
    if not APPROVED_PROBES:
        raise ExecutionDisabled("no isolation probe is approved (APPROVED_PROBES is empty); "
                                "nothing was started")


def _require_probe_authorization(auth: Any, run: Optional[str] = None) -> ProbeAuthorization:
    _require_probe_enabled()
    if not isinstance(auth, ProbeAuthorization) or auth.seal is not _SEAL:
        raise ExecutionDisabled("no valid probe authorization; nothing was started")
    if auth.probe_id not in APPROVED_PROBES:
        raise ExecutionDisabled(f"not approved: {auth.probe_id}; nothing was started")
    if run is not None and run != auth.probe_id:
        raise ExecutionDisabled(f"{run} is not covered by this authorization")
    return auth


def _require_any_authorization(auth: Any, run: Optional[str] = None) -> Any:
    """The gate of functions shared by calibration and the isolation probe."""
    if isinstance(auth, ProbeAuthorization):
        return _require_probe_authorization(auth, run)
    return _require_authorization(auth, run)


def authorize_probe(probe_id: Any, expected_head: Optional[str]) -> ProbeAuthorization:
    """A ProbeAuthorization for exactly this approved probe at this HEAD."""
    _require_probe_enabled()
    if not isinstance(probe_id, str) or not PROBE_ID_RE.fullmatch(probe_id):
        raise ExecutionDisabled("a probe id is probe-01 .. probe-05")
    if probe_id not in APPROVED_PROBES:
        raise ExecutionDisabled(f"{probe_id} is not an approved probe; nothing was started")
    if not isinstance(expected_head, str) or not _HEAD_RE.fullmatch(expected_head):
        raise ExecutionDisabled("--expect-head must be the full 40-character Git HEAD")
    actual = _git_head(_require_probe_enabled)
    if actual != expected_head:
        raise ExecutionDisabled(f"Git HEAD is {actual[:12]}, not the expected "
                                f"{expected_head[:12]}; nothing was started")
    return ProbeAuthorization(probe_id, expected_head, _SEAL)


# ---------------------------------------------------------------------------
# Identifiers and plans
# ---------------------------------------------------------------------------

def calibration_id(number: int) -> str:
    if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= MAX_RUNS:
        raise CalibrationError(f"run number must be 1-{MAX_RUNS}")
    return f"cal-{CONDITION}-{number:02d}"


def run_ids(number: int) -> tuple[str, str]:
    calibration_id(number)
    return f"cal-{CONDITION}-w{number:02d}", f"cal-{CONDITION}-m{number:02d}"


def plan_config(run_id: str, traces: int) -> dict[str, Any]:
    """The arguments of the SMOKE cell's plans, for any run id."""
    return {"seed": SEED, "run_id": run_id, "scenario": "normal", "traces": traces,
            "rate": RATE, "persona": None, "mode": "real"}


def plan_record(number: int) -> dict[str, Any]:
    """The run parameters a result must carry, exactly."""
    warm, measured = run_ids(number)
    return {"warmup": plan_config(warm, WARMUP_REQUESTS),
            "measured": plan_config(measured, MEASURED_REQUESTS),
            "concurrency": CONCURRENCY, "exporter": "in-memory",
            "late_start_seconds": LATE_START_SECONDS, "late_fraction": LATE_FRACTION}


def build_plans(number: int) -> tuple[Any, Any]:
    """(warm-up plan, measured plan) built by the generator's own planner."""
    _ensure_generator_path()
    from workload_generator.plan import PlanConfig, build_plan
    from workload_generator.scenarios import Scenario

    plans = []
    for run_id, traces in zip(run_ids(number), (WARMUP_REQUESTS, MEASURED_REQUESTS)):
        config = plan_config(run_id, traces)
        config["scenario"] = Scenario(config["scenario"])
        plans.append(build_plan(PlanConfig(**config)))
    return plans[0], plans[1]


def _ensure_generator_path() -> None:
    for path in (str(GENERATOR_DIR), str(DEMO_DIR)):
        if path not in sys.path:
            sys.path.insert(0, path)


# ---------------------------------------------------------------------------
# Output location, ownership, exclusive files
# ---------------------------------------------------------------------------

def _norm(path: Path) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def check_output_dir(output_dir: Path) -> Path:
    """The calibration directory, or CalibrationError when it is inside the
    repository or inside the benchmark output directory."""
    target = _norm(output_dir)
    for forbidden, why in ((REPO, "the repository"), (BENCHMARK_OUTPUT, "the benchmark "
                                                                         "output directory")):
        root = _norm(forbidden)
        if target == root or target.startswith(root + os.sep):
            raise CalibrationError(f"calibration output is never written inside {why}")
    if "agentops-benchmarks" in {part.lower() for part in Path(target).parts}:
        raise CalibrationError("calibration output is never written inside the benchmark "
                               "output directory")
    return Path(output_dir).resolve()


def _exclusive_json(path: Path, payload: Mapping[str, Any]) -> None:
    RB._exclusive_json(path, payload)


def claim_series(output_dir: Path, *, calibration_ids: Sequence[str], expected_head: str,
                 now: Callable[[], float], pid: Callable[[], int] = os.getpid,
                 new_token: Callable[[], str] = lambda: uuid.uuid4().hex,
                 owner_file: str = OWNER_FILE) -> tuple[Path, str]:
    """Take the one ownership record (ACTIVE_CALIBRATION, or ACTIVE_PROBE for
    the probe); refuse if it exists.  Returns (record path, series token)."""
    output_dir = check_output_dir(output_dir)
    token = new_token()
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        raise CalibrationError("a series token is 32 lowercase hex characters")
    owner = output_dir / owner_file
    try:
        _exclusive_json(owner, {"condition": CONDITION, "calibration_ids": list(calibration_ids),
                                "series_token": token, "expected_head": expected_head,
                                "pid": pid(), "started_utc": _iso(now())})
    except FileExistsError:
        raise CalibrationError(f"{owner} exists: another calibration owns this directory, or "
                               "an earlier one did not finish; review it") from None
    except OSError as exc:
        raise CalibrationError(f"cannot create {owner}: {type(exc).__name__}") from None
    return owner, token


def check_ownership(output_dir: Path, number: int, series_token: Any) -> None:
    """A child runs only inside the series that owns its directory."""
    _check_owner(output_dir, calibration_id(number), series_token, OWNER_FILE)


def _check_owner(output_dir: Path, run_id: str, series_token: Any, owner_file: str) -> None:
    owner = Path(output_dir) / owner_file
    try:
        record = json.loads(owner.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CalibrationError(f"no {owner_file}: a child runs only inside an owned "
                               "series") from None
    except (OSError, ValueError):
        raise CalibrationError(f"{owner_file} is unreadable or malformed; review it") \
            from None
    if not isinstance(record, dict) or not isinstance(record.get("series_token"), str) \
            or not isinstance(record.get("calibration_ids"), list):
        raise CalibrationError(f"{owner_file} is malformed; review it")
    if not isinstance(series_token, str) or record["series_token"] != series_token:
        raise CalibrationError(f"the series token does not match {owner_file}")
    if run_id not in record["calibration_ids"]:
        raise CalibrationError(f"{run_id} is not part of the owning series")


def result_path(output_dir: Path, number: int) -> Path:
    return Path(output_dir) / f"{calibration_id(number)}.json"


def _journal_path(output_dir: Path, stage: str, run: Any) -> Path:
    name = f"{run:02d}" if isinstance(run, int) else str(run)
    return Path(output_dir) / JOURNAL_DIR / f"{stage}-{name}.json"


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Python-level network guard (child only; defence in depth, not denial)
# ---------------------------------------------------------------------------

#: Native network libraries replaced by refusing stubs inside the child.
NATIVE_NETWORK_MODULES: tuple[str, ...] = (
    "grpc", "opentelemetry.exporter.otlp", "confluent_kafka", "kafka", "psycopg",
    "psycopg2", "psycopg_binary",
)


class _Refusing:
    """Stands for any name of a stubbed native network library."""

    def __init__(self, name: str, guard: "NetworkGuard") -> None:
        self._name, self._guard = name, guard

    def __getattr__(self, attr: str) -> "_Refusing":
        if attr.startswith("__"):
            raise AttributeError(attr)
        return _Refusing(f"{self._name}.{attr}", self._guard)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._guard.violations.append({"operation": "native library", "arguments": self._name})
        raise NetworkBlocked(f"{self._name} is a network library and is blocked during "
                             "calibration")


class _NativeStub(types.ModuleType):
    def __init__(self, name: str, guard: "NetworkGuard") -> None:
        super().__init__(name, "network library replaced during calibration")
        self._guard = guard

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("__"):
            raise AttributeError(attr)
        return _Refusing(f"{self.__name__}.{attr}", self._guard)


class _NativeStubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, guard: "NetworkGuard") -> None:
        self.guard = guard

    @staticmethod
    def blocked(name: str) -> bool:
        return any(name == m or name.startswith(m + ".") for m in NATIVE_NETWORK_MODULES)

    def find_spec(self, name: str, path: Any = None, target: Any = None) -> Any:
        if self.blocked(name):
            return importlib.machinery.ModuleSpec(name, self, is_package=True)
        return None

    def create_module(self, spec: Any) -> types.ModuleType:
        return _NativeStub(spec.name, self.guard)

    def exec_module(self, module: types.ModuleType) -> None:
        self.guard.stubbed_imports.append(module.__name__)


class NetworkGuard:
    """
    Makes Python-level socket creation, connection, sending and name
    resolution raise NetworkBlocked, replaces the native network libraries
    by refusing stubs, and records each attempt.  Defence in depth: code
    that bypasses Python's socket module is not seen, so this guard does not
    guarantee isolation.
    """

    SOCKET_METHODS = ("__init__", "connect", "connect_ex", "sendto", "sendmsg")
    MODULE_FUNCTIONS = ("create_connection", "create_server", "getaddrinfo", "getnameinfo",
                        "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "socketpair",
                        "fromfd")

    def __init__(self, *, block_native: bool = True) -> None:
        self.violations: list[dict[str, str]] = []
        self.stubbed_imports: list[str] = []
        self.block_native = block_native
        self._saved: list[tuple[Any, str, Any]] = []
        self._finder: Optional[_NativeStubFinder] = None

    def _blocker(self, name: str) -> Callable[..., Any]:
        def blocked(*args: Any, **kwargs: Any) -> Any:
            shown = args[1:3] if name in self.SOCKET_METHODS else args[:2]
            self.violations.append({"operation": name, "arguments": repr(shown)[:200]})
            raise NetworkBlocked(f"network operation {name} is blocked during calibration")
        return blocked

    def install(self) -> "NetworkGuard":
        import socket
        if self._saved or self._finder:
            raise CalibrationError("the network guard is already installed")
        if self.block_native:
            loaded = sorted(n for n in sys.modules if _NativeStubFinder.blocked(n))
            if loaded:
                raise CalibrationError("native network libraries are already loaded: "
                                       + ", ".join(loaded[:5]))
        targets = [(socket.socket, n) for n in self.SOCKET_METHODS] + \
                  [(socket, n) for n in self.MODULE_FUNCTIONS]
        for owner, name in targets:
            if hasattr(owner, name):                 # sendmsg / fromfd vary by platform
                self._saved.append((owner, name, getattr(owner, name)))
                setattr(owner, name, self._blocker(name))
        if self.block_native:
            self._finder = _NativeStubFinder(self)
            sys.meta_path.insert(0, self._finder)
        return self

    def uninstall(self) -> None:
        for owner, name, original in reversed(self._saved):
            setattr(owner, name, original)
        self._saved.clear()
        if self._finder is not None:
            if self._finder in sys.meta_path:
                sys.meta_path.remove(self._finder)
            for name in [n for n, m in sys.modules.items() if isinstance(m, _NativeStub)]:
                stub = sys.modules.pop(name)
                parent, _, child = name.rpartition(".")
                if parent in sys.modules and getattr(sys.modules[parent], child, None) is stub:
                    delattr(sys.modules[parent], child)
            self._finder = None

    @property
    def installed(self) -> bool:
        return bool(self._saved) or self._finder is not None


# ---------------------------------------------------------------------------
# Analysis (pure)
# ---------------------------------------------------------------------------

def diagnostic_problems(start_lags: Any) -> list[str]:
    """Why a start-lag diagnostic cannot be analysed; empty when it can.
    The same checks the benchmark applies."""
    return RB._diagnostic_problems(start_lags)


def stall_groups(entries: Sequence[Sequence[float]], *,
                 min_lag: float = GROUP_MIN_LAG_SECONDS,
                 tolerance: float = GROUP_TOLERANCE_SECONDS) -> list[dict[str, Any]]:
    """
    Requests delayed by more than min_lag, grouped by their implied dispatch
    time (planned offset + lag): consecutive requests whose dispatch times
    lie within `tolerance` were released together after one interruption.
    A group of size > 1 shows delay propagation; size 1 an isolated delay.
    Observation only: nothing here says what caused the interruption.
    """
    delayed = [(int(i), float(o), float(lag), float(o) + float(lag))
               for i, o, lag in entries if lag > min_lag]
    groups: list[list[tuple[int, float, float, float]]] = []
    for item in delayed:
        if groups and abs(item[3] - groups[-1][-1][3]) <= tolerance \
                and item[0] == groups[-1][-1][0] + 1:
            groups[-1].append(item)
        else:
            groups.append([item])
    return [{
        "request_indices": [g[0] for g in group],
        "dispatch_offset_s": round(group[0][3], 6),
        "max_lag_s": round(max(g[2] for g in group), 6),
        "propagated": len(group) > 1,
    } for group in groups]


def burst_association(entries: Sequence[Sequence[float]], *,
                      late_threshold: float = LATE_START_SECONDS,
                      burst_gap: float = BURST_GAP_SECONDS) -> dict[str, Any]:
    """How many late requests lie inside planned bursts, against the share of
    all requests that do.  An association, not a cause."""
    offsets = [float(e[1]) for e in entries]
    in_burst = set()
    for i in range(1, len(offsets)):
        if offsets[i] - offsets[i - 1] < burst_gap:
            in_burst.update((i - 1, i))
    late = [i for i, e in enumerate(entries) if e[2] > late_threshold]
    return {
        "requests": len(entries), "requests_in_bursts": len(in_burst),
        "burst_share": round(len(in_burst) / len(entries), 6) if entries else None,
        "late": len(late), "late_in_bursts": sum(1 for i in late if i in in_burst),
    }


def summarize_stage(report: Mapping[str, Any]) -> dict[str, Any]:
    """The calibration record of one driver report (measured or warm-up)."""
    started = report.get("started_requests")
    late = report.get("late_starts")
    lags = report.get("start_lags")
    problems = ["no start-lag diagnostic"] if lags is None else diagnostic_problems(lags)
    usable = not problems
    entries = [list(e) for e in lags["entries"]] if usable else []
    record: dict[str, Any] = {
        "started_requests": started, "not_started_requests": report.get("not_started_requests"),
        "late_starts": late,
        "late_start_percent": (round(100.0 * late / started, 6)
                               if isinstance(late, int) and isinstance(started, int) and started
                               else None),
        "max_start_lag_seconds": report.get("max_start_lag_seconds"),
        "mean_start_lag_seconds": report.get("mean_start_lag_seconds"),
        "run_status": report.get("run_status"),
        "diagnostic_usable": usable, "diagnostic_problems": problems,
        "start_lags": lags,
        "start_lag_percentiles": None, "late_request_indices": None,
        "stall_groups": None, "burst_association": None,
    }
    if usable and entries:
        record["start_lag_percentiles"] = {k: round(v, 6) for k, v in
                                           M.percentiles([e[2] for e in entries]).items()}
        record["late_request_indices"] = [e[0] for e in entries if e[2] > LATE_START_SECONDS]
        record["stall_groups"] = stall_groups(entries)
        record["burst_association"] = burst_association(entries)
    return record


def distribution(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Late-start distribution across completed runs (measured stages)."""
    percents = [r["measured"]["late_start_percent"] for r in records
                if r.get("status") == "completed"
                and r["measured"].get("late_start_percent") is not None]
    if not percents:
        return {"runs": 0, "note": "no completed run"}
    ordered = sorted(percents)
    groups = [g for r in records if r.get("status") == "completed"
              for g in (r["measured"].get("stall_groups") or [])]
    return {
        "runs": len(percents), "median_late_percent": M.percentile(ordered, 50),
        "min_late_percent": ordered[0], "max_late_percent": ordered[-1],
        "runs_over_rule": sum(1 for p in percents if p > 100 * LATE_FRACTION),
        "stall_groups": len(groups),
        "propagated_groups": sum(1 for g in groups if g["propagated"]),
        "kind": "OBSERVATION",
    }


def result_problems(record: Any, number: int, exit_status: Optional[int]) -> list[str]:
    """Why a child's result is not a valid completed run; empty when it is."""
    if not isinstance(record, Mapping):
        return ["the result is not a JSON object"]
    problems: list[str] = []
    expected = {"calibration_id": calibration_id(number), "condition": CONDITION,
                "status": "completed", "child_exit_status": EXIT_OK}
    for key, value in expected.items():
        if record.get(key) != value:
            problems.append(f"{key} is {record.get(key)!r}, expected {value!r}")
    if exit_status != EXIT_OK:
        problems.append(f"actual child exit status {exit_status!r}")
    if record.get("child_exit_status") != exit_status:
        problems.append("the recorded child exit status differs from the actual one")
    if record.get("plan") != plan_record(number):
        problems.append("run parameters differ from the calibration plan")
    if record.get("network_guard_violations") != []:
        problems.append("network guard violations are recorded or missing")
    for stage, traces in (("warmup", WARMUP_REQUESTS), ("measured", MEASURED_REQUESTS)):
        summary = record.get(stage)
        if not isinstance(summary, Mapping):
            problems.append(f"the {stage} stage is missing")
            continue
        if summary.get("started_requests") != traces or summary.get("not_started_requests") != 0:
            problems.append(f"the {stage} stage did not start exactly {traces} requests")
        if summary.get("run_status") != "completed":
            problems.append(f"the {stage} stage status is {summary.get('run_status')!r}")
        if summary.get("diagnostic_usable") is not True:
            problems.append(f"the {stage} start-lag diagnostic is incomplete or unusable")
    return problems


# ---------------------------------------------------------------------------
# Child mode
# ---------------------------------------------------------------------------

def _import_driver(auth: Any) -> tuple[Any, Any]:
    """(execute, load_demo) of the real driver.  Called after the guard."""
    _require_authorization(auth)
    _ensure_generator_path()
    from workload_generator import real_driver
    return real_driver.execute, real_driver.load_demo


def _memory_exporter(auth: Any) -> Any:
    _require_authorization(auth)
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    return InMemorySpanExporter()


@dataclass
class ChildDeps:
    """What a child needs, always given explicitly; tests pass fakes."""
    import_driver: Callable[[], tuple[Any, Any]]
    exporter: Callable[[], Any]
    plans: Callable[[int], tuple[Any, Any]]
    clock: Callable[[], float]
    pause: Callable[[float], None]
    wall: Callable[[], float]
    guard_factory: Callable[[], NetworkGuard] = NetworkGuard


def production_child_deps(auth: Any, number: int) -> ChildDeps:
    """The real dependencies of one authorized child run."""
    _require_authorization(auth, calibration_id(number))
    return ChildDeps(import_driver=lambda: _import_driver(auth),
                     exporter=lambda: _memory_exporter(auth), plans=build_plans,
                     clock=time.monotonic, pause=time.sleep, wall=time.time)


def _os_description() -> str:
    """Platform text read in-process; platform.platform() may start a subprocess."""
    winver = getattr(sys, "getwindowsversion", None)
    if winver:
        v = winver()
        return f"{sys.platform} {v.major}.{v.minor}.{v.build}"
    return sys.platform


def child_main(number: int, output_dir: Path, deps: ChildDeps, *, series_token: str) -> int:
    """
    One calibration run: ownership -> guard -> import driver and demo ->
    warm-up -> measured -> exclusive result.  Returns the exit status.
    Every outcome after the guard, failures included, is written to the
    run's result file.
    """
    if not isinstance(deps, ChildDeps):
        raise TypeError("child_main needs explicit ChildDeps")
    output_dir = check_output_dir(output_dir)
    path = result_path(output_dir, number)
    if path.exists():
        raise CalibrationError(f"{path} exists; a calibration run is never repeated")
    check_ownership(output_dir, number, series_token)
    guard = deps.guard_factory().install()           # before any driver or demo import
    record: dict[str, Any] = {
        "calibration_id": calibration_id(number), "condition": CONDITION,
        "kind": "generator-only calibration; not a platform benchmark",
        "plan": plan_record(number),
        "started_utc": _iso(deps.wall()), "python": platform.python_version(),
        "os": _os_description(), "status": "failed", "warmup": None, "measured": None,
        "measured_duration_seconds": None, "network_guard_violations": [],
        "observations_note": "groups, propagation and burst association are observations; "
                             "they do not identify why a start was delayed",
    }
    status = EXIT_FAILED
    try:
        execute, load_demo = deps.import_driver()
        demo = load_demo()
        warm_plan, measured_plan = deps.plans(number)
        stages = {}
        for name, plan in (("warmup", warm_plan), ("measured", measured_plan)):
            began = deps.clock()
            report = execute(plan, demo=demo, span_exporter=deps.exporter(),
                             endpoint="in-memory", concurrency=CONCURRENCY,
                             max_duration_seconds=STAGE_MAX_SECONDS, pause=deps.pause,
                             clock=deps.clock)
            stages[name] = (report.to_dict(), deps.clock() - began)
            if guard.violations:
                raise NetworkBlocked("a network operation was attempted")
        record["warmup"] = summarize_stage(stages["warmup"][0])
        record["measured"] = summarize_stage(stages["measured"][0])
        record["measured_duration_seconds"] = round(stages["measured"][1], 6)
        record["status"] = "completed"
        status = EXIT_OK
    except NetworkBlocked:
        record["status"] = "network_violation"
        status = EXIT_NETWORK
    except Exception as exc:  # recorded as evidence; never retried
        record["status"] = "failed"
        record["failure"] = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        record["network_guard_violations"] = list(guard.violations)
        record["stubbed_native_imports"] = sorted(set(guard.stubbed_imports))
        if guard.violations and status == EXIT_OK:
            record["status"], status = "network_violation", EXIT_NETWORK
        record["finished_utc"] = _iso(deps.wall())
        record["child_exit_status"] = status
        guard.uninstall()
        _exclusive_json(path, record)
    return status


# ---------------------------------------------------------------------------
# Child command and launchers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChildCommand:
    """Everything a launcher needs to start one child, built explicitly."""
    calibration_id: str
    argv: tuple[str, ...]
    cwd: str
    env: Mapping[str, str]
    temp_dir: Path
    stdout_path: Path
    stderr_path: Path

    @property
    def command_line(self) -> str:
        """The Windows command line (CreateProcess quoting)."""
        return subprocess.list2cmdline(self.argv)

    @property
    def argv_fingerprint(self) -> str:
        return hashlib.sha256(self.command_line.encode("utf-8")).hexdigest()

    @property
    def environment_names(self) -> list[str]:
        return sorted(self.env)


def child_environment(temp_dir: Path, python_paths: Sequence[str] = ()) -> dict[str, str]:
    """The child's whole environment: an explicit allowlist, nothing more.
    python_paths carries the venv's site-packages, because the child runs
    the base interpreter directly, not the venv launcher."""
    env = {name: os.environ[name] for name in ("SYSTEMROOT", "SYSTEMDRIVE", "PATH")
           if name in os.environ}
    env.update(PYTHONPATH=os.pathsep.join((str(GENERATOR_DIR), str(DEMO_DIR),
                                           *map(str, python_paths))),
               PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1",
               TEMP=str(temp_dir), TMP=str(temp_dir))
    return env


def base_interpreter() -> str:
    """The real python.exe behind the venv (the venv launcher would start
    it as a second process)."""
    return str(getattr(sys, "_base_executable", None) or sys.executable)


def venv_paths() -> tuple[str, ...]:
    paths = sysconfig.get_paths()
    return tuple(dict.fromkeys(str(paths[k]) for k in ("purelib", "platlib")))


def is_venv_launcher(interpreter: str) -> bool:
    """True when `interpreter` sits in a venv (pyvenv.cfg beside it or one
    level up), i.e. it is the launcher, not the interpreter itself."""
    here = Path(interpreter).parent
    return (here / "pyvenv.cfg").is_file() or (here.parent / "pyvenv.cfg").is_file()


def _check_argument(part: str) -> str:
    if not part or any(c in part for c in '"\'!%\r\n\x00'):
        raise CalibrationError(f"unsafe command argument: {part[:60]!r}")
    return part


def _command(run_id: str, mode: Sequence[str], output_dir: Path, *, series_token: str,
             expected_head: str, interpreter: str, python_paths: Sequence[str]) -> ChildCommand:
    if not isinstance(series_token, str) or not _TOKEN_RE.fullmatch(series_token):
        raise CalibrationError("a series token is 32 lowercase hex characters")
    if not isinstance(expected_head, str) or not _HEAD_RE.fullmatch(expected_head):
        raise CalibrationError("the expected head is the full 40-character Git HEAD")
    output_dir = Path(output_dir)
    argv = tuple(_check_argument(str(part)) for part in (
        interpreter, "-B", "-s", str(Path(__file__).resolve()), *mode,
        "--output-dir", str(output_dir), "--token", series_token,
        "--expect-head", expected_head))
    for path in python_paths:
        _check_argument(str(path))
    temp_dir = output_dir / "temp" / run_id
    return ChildCommand(calibration_id=run_id, argv=argv, cwd=str(REPO),
                        env=child_environment(temp_dir, python_paths), temp_dir=temp_dir,
                        stdout_path=output_dir / f"{run_id}.stdout",
                        stderr_path=output_dir / f"{run_id}.stderr")


def build_child_command(number: int, output_dir: Path, *, series_token: str,
                        expected_head: str, interpreter: str,
                        python_paths: Sequence[str] = ()) -> ChildCommand:
    """The exact child command.  Paths may contain spaces; quoting is done
    by list2cmdline, never by hand."""
    cid = calibration_id(number)
    command = _command(cid, ("--child", str(number)), output_dir, series_token=series_token,
                       expected_head=expected_head, interpreter=interpreter,
                       python_paths=python_paths)
    argv = list(command.argv)        # keep --authorize before --expect-head
    argv[-2:-2] = ["--authorize", cid]
    return replace(command, argv=tuple(argv))


def build_probe_command(probe_id: str, output_dir: Path, *, series_token: str,
                        expected_head: str, interpreter: str, port: int,
                        python_paths: Sequence[str] = ()) -> ChildCommand:
    """The exact probe-child command: no --child, so no workload driver."""
    if not isinstance(probe_id, str) or not PROBE_ID_RE.fullmatch(probe_id):
        raise CalibrationError("a probe id is probe-01 .. probe-05")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise CalibrationError("the probe listener port must be 1024-65535")
    command = _command(probe_id, ("--probe-child", probe_id), output_dir,
                       series_token=series_token, expected_head=expected_head,
                       interpreter=interpreter, python_paths=python_paths)
    return replace(command, argv=command.argv + ("--port", str(port)))


def detached_orchestrator_command(*, interpreter: str, runs: int, output_dir: Path,
                                  expected_head: str, log_dir: Path) -> str:
    """
    The verified detached form for the future orchestrator, as text only:
        Start-Process cmd.exe -ArgumentList '/d /s /v:on /c "<cmd>
        1>LOG\\x.out 2>LOG\\x.err & >LOG\\x.exit echo exit_code=!errorlevel!"'
    The log directory must be space-free (an 8.3 path).  Never executed here.
    """
    log = str(log_dir)
    if not log or " " in log or any(c in log for c in '"\'!%&<>|^'):
        raise CalibrationError("the detached wrapper needs a space-free (8.3) log directory")
    ids: list[str] = []
    for number in range(1, runs + 1):
        ids += ["--authorize", calibration_id(number)]
    inner = subprocess.list2cmdline([_check_argument(str(p)) for p in (
        interpreter, "-B", str(Path(__file__).resolve()), "--execute", "--runs", str(runs),
        "--output-dir", str(output_dir), "--expect-head", expected_head, *ids)])
    return (f"Start-Process cmd.exe -ArgumentList '/d /s /v:on /c \"{inner} "
            f"1>{log}\\orchestrator.out 2>{log}\\orchestrator.err & "
            f">{log}\\orchestrator.exit echo exit_code=!errorlevel!\"'")


def _norm_image(path: Any) -> Optional[str]:
    return os.path.normcase(os.path.normpath(str(path))) if path else None


def validate_app_container_token(info: Any, expected_sid: Optional[str], *,
                                 expected_pid: Optional[int] = None,
                                 expected_image: Optional[str] = None,
                                 check_loopback: bool = True) -> list[str]:
    """Why a child's token or identity is not the capability-free, authorized
    AppContainer; empty when it is."""
    if not isinstance(info, Mapping):
        return ["no token information"]
    problems = []
    if not expected_sid:
        problems.append("no AppContainer profile is authorized")
    if info.get("is_app_container") is not True:
        problems.append("the process is not in an AppContainer")
    if not expected_sid or info.get("app_container_sid") != expected_sid:
        problems.append("the AppContainer SID is not the authorized profile's")
    capabilities = info.get("capabilities")
    if not isinstance(capabilities, (list, tuple)):
        problems.append("the token capabilities are unknown")
    elif capabilities:
        named = [NETWORK_CAPABILITY_SIDS.get(c, c) for c in capabilities]
        problems.append("the token has capabilities: " + ", ".join(map(str, named)))
    if info.get("integrity_level") != "low":
        problems.append("the token integrity level is not low")
    if check_loopback and info.get("loopback_exempt") is not False:
        problems.append("absence of a loopback exemption is not shown")
    if expected_pid is not None and info.get("pid") != expected_pid:
        problems.append("the token was read from another process")
    if expected_image is not None and _norm_image(info.get("image_path")) != \
            _norm_image(expected_image):
        problems.append("the process image is not the intended interpreter")
    return problems


#: Process evidence.  Execution history and current liveness are separate:
#: a confirmed exit never turns "may have executed" into "never executed".
NEVER_EXECUTED = "definitely_never_executed"
MAY_HAVE_EXECUTED = "may_have_executed"
CONFIRMED_EXITED = "confirmed_exited"
STATE_UNKNOWN = "state_unknown"
ALIVE_AT_LAST_CHECK = "alive_at_last_check"
EXECUTION_HISTORIES = (NEVER_EXECUTED, MAY_HAVE_EXECUTED, STATE_UNKNOWN)
LIVENESS_STATES = (CONFIRMED_EXITED, ALIVE_AT_LAST_CHECK, STATE_UNKNOWN)


class LaunchFailure(CalibrationError):
    """A launch that failed after a process was (or may have been) created.
    Carries the process evidence for the journals."""

    def __init__(self, message: str, *, pid: Any = None, creation_time: Any = None,
                 execution_history: str = STATE_UNKNOWN, liveness: str = STATE_UNKNOWN,
                 handles_retained: bool = False, cleanup_errors: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.evidence = {"process_created": True, "pid": pid, "creation_time": creation_time,
                         "execution_history": execution_history, "liveness": liveness,
                         "handles_retained": handles_retained,
                         "cleanup_errors": list(cleanup_errors)}


def process_evidence(process: Any) -> dict[str, Any]:
    """The evidence fields of a created process (unknown where not tracked)."""
    return {"process_created": True, "pid": getattr(process, "pid", None),
            "creation_time": getattr(process, "creation_time", None),
            "execution_history": getattr(process, "execution_history", STATE_UNKNOWN),
            "liveness": getattr(process, "liveness", STATE_UNKNOWN),
            "handles_retained": bool(getattr(process, "handles_retained", False)),
            "cleanup_errors": list(getattr(process, "cleanup_errors", []))}


def _launch_failure(message: str, process: Any) -> LaunchFailure:
    evidence = process_evidence(process)
    evidence.pop("process_created")
    return LaunchFailure(message, **evidence)


#: Required profile-preflight fields and their exact expected values.
PREFLIGHT_RECORD_FIELDS = ("profile_name", "app_container_sid", "capabilities",
                           "loopback_exempt", "verified_by", "verified_utc")


def check_profile_preflight(path: Path) -> dict[str, Any]:
    """
    The independently verified profile-preflight record, authorized by its
    exact SHA-256 (AUTHORIZED_PROFILE_PREFLIGHT_SHA256).  The record is
    produced outside this file, by the separately authorized profile step.
    Nothing here proves the profile exists by itself; without this record
    every launch is blocked.
    """
    if not AUTHORIZED_PROFILE_PREFLIGHT_SHA256:
        raise CalibrationError("no profile-preflight record is authorized "
                               "(AUTHORIZED_PROFILE_PREFLIGHT_SHA256 is None); launch blocked")
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise CalibrationError(f"the profile-preflight record {path} is missing or unreadable; "
                               "launch blocked") from None
    if hashlib.sha256(raw).hexdigest() != AUTHORIZED_PROFILE_PREFLIGHT_SHA256:
        raise CalibrationError("the profile-preflight record is not the authorized one; "
                               "launch blocked")
    try:
        record = json.loads(raw)
    except ValueError:
        raise CalibrationError("the profile-preflight record is malformed; launch blocked") \
            from None
    problems = []
    if not isinstance(record, dict) or set(PREFLIGHT_RECORD_FIELDS) - set(record):
        problems.append("fields are missing")
    else:
        if record["profile_name"] != APPCONTAINER_PROFILE:
            problems.append("another profile name")
        if not AUTHORIZED_APPCONTAINER_SID or \
                record["app_container_sid"] != AUTHORIZED_APPCONTAINER_SID:
            problems.append("another SID")
        if record["capabilities"] != []:
            problems.append("capabilities are present")
        if record["loopback_exempt"] is not False:
            problems.append("a loopback exemption is not excluded")
        if not isinstance(record["verified_by"], str) or not record["verified_by"].strip() \
                or not isinstance(record["verified_utc"], str):
            problems.append("the verification is not attributed")
    if problems:
        raise CalibrationError("the profile-preflight record is invalid (" + "; ".join(problems)
                               + "); launch blocked")
    return record


class AppContainerLauncher:
    """
    Starts a child suspended inside the authorized AppContainer profile,
    with no capabilities, checks the real token and the process identity,
    and only then resumes it.  It never creates the profile and never
    changes ACLs.  A child that fails a check before a successful
    ResumeThread never executed; after it, it may have.  A discarded child
    is reported as confirmed exited only when its exit was verified; else
    its PID and handles are kept for inspection.
    """

    def __init__(self, auth: Any, api: Any, *,
                 preflight_path: Optional[Path] = None) -> None:
        self.auth = _require_any_authorization(auth)
        self.api = api
        self.preflight_path = preflight_path or DEFAULT_PROFILE_PREFLIGHT

    def __call__(self, command: ChildCommand, stdout: Any, stderr: Any) -> Any:
        _require_any_authorization(self.auth, command.calibration_id)
        if APPCONTAINER_CAPABILITIES:
            raise CalibrationError("the calibration AppContainer must have no capabilities")
        if not AUTHORIZED_APPCONTAINER_SID:
            raise CalibrationError("no AppContainer profile is authorized "
                                   "(AUTHORIZED_APPCONTAINER_SID is None)")
        if is_venv_launcher(command.argv[0]):
            raise CalibrationError("the child must be the base interpreter, not the venv "
                                   "launcher (its own child would be a second process)")
        check_profile_preflight(self.preflight_path)
        sid = self.api.profile_sid(APPCONTAINER_PROFILE)
        if sid != AUTHORIZED_APPCONTAINER_SID:
            raise CalibrationError(f"profile {APPCONTAINER_PROFILE} has SID {sid}, not the "
                                   "authorized one")
        if not self.api.profile_folder_present(sid):
            raise CalibrationError("GetAppContainerFolderPath found no folder for the profile "
                                   "(not proof either way); launch blocked; a profile is "
                                   "never created here - that needs its own authorization")
        process = self.api.create_suspended(command, sid, APPCONTAINER_CAPABILITIES,
                                            stdout, stderr)
        try:
            problems = validate_app_container_token(
                self.api.token_info(process), sid, expected_pid=process.pid,
                expected_image=command.argv[0])
        except Exception as exc:
            problems = [f"the token could not be read: {type(exc).__name__}: {exc}"]
        if problems:
            self._discard(process, "token rejected: " + "; ".join(problems))
        try:
            self.api.resume(process)
        except Exception as exc:
            self._discard(process, f"resume failed: {type(exc).__name__}: {exc}")
        return process

    def _discard(self, process: Any, why: str) -> None:
        try:
            self.api.discard_suspended(process)
        except Exception as exc:
            raise _launch_failure(
                f"AppContainer {why}; and the child PID {getattr(process, 'pid', None)} could "
                f"not be discarded ({exc}); its handles are kept; inspect it", process) from None
        history = getattr(process, "execution_history", STATE_UNKNOWN)
        raise _launch_failure(f"AppContainer {why}; the child was discarded and confirmed "
                              f"exited (execution history: {history})", process)


# Win32 constants (documented values).
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
CREATION_FLAGS = (CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT
                  | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW)
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
#: The attributes of a planned creation, in the only accepted order.
PLAN_ATTRIBUTES: tuple[int, ...] = (PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                    PROC_THREAD_ATTRIBUTE_JOB_LIST)
TOKEN_QUERY = 0x0008
TOKEN_INTEGRITY_LEVEL, TOKEN_IS_APP_CONTAINER = 25, 29
TOKEN_CAPABILITIES, TOKEN_APP_CONTAINER_SID = 30, 31
ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER = 24, 122
WAIT_OBJECT_0, WAIT_TIMEOUT = 0x0, 0x102
RESUME_FAILED = 0xFFFFFFFF
INTEGRITY_LEVELS: Mapping[int, str] = {0x0: "untrusted", 0x1000: "low", 0x2000: "medium",
                                       0x2100: "medium-plus", 0x3000: "high", 0x4000: "system"}
_INVALID_HANDLES = frozenset({0, -1, (1 << 32) - 1, (1 << 64) - 1})


def _valid_handle(handle: Any) -> bool:
    return isinstance(handle, int) and not isinstance(handle, bool) \
        and handle not in _INVALID_HANDLES


class Win32Error(CalibrationError):
    def __init__(self, api: str, code: Any) -> None:
        super().__init__(f"{api} failed (Windows error {code})")
        self.api, self.code = api, code


def environment_block(env: Mapping[str, str]) -> str:
    """A CREATE_UNICODE_ENVIRONMENT block, sorted case-insensitively; the
    final NUL is added by the buffer."""
    for key, value in env.items():
        if not key or "=" in key or "\0" in key or "\0" in str(value):
            raise CalibrationError(f"unusable environment entry: {key[:40]!r}")
    if not env:
        raise CalibrationError("the child environment is empty")
    return "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper()))


def _filetime_iso(low: int, high: int) -> str:
    ticks = (int(high) << 32) | int(low)
    epoch = (ticks - 116444736000000000) / 10_000_000
    moment = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _integrity_name(sid: Optional[str]) -> Optional[str]:
    if not sid:
        return None
    try:
        rid = int(sid.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return None
    return INTEGRITY_LEVELS.get(rid, f"rid-{rid}")


_TYPES: Optional[types.SimpleNamespace] = None


def _win32_types() -> types.SimpleNamespace:
    """ctypes structures of the documented Win32 types (built on first use)."""
    global _TYPES
    if _TYPES is None:
        import ctypes
        from ctypes import wintypes as w

        class SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", w.DWORD)]

        class SECURITY_CAPABILITIES(ctypes.Structure):
            _fields_ = [("AppContainerSid", ctypes.c_void_p),
                        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
                        ("CapabilityCount", w.DWORD), ("Reserved", w.DWORD)]

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                        ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                        ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                        ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                        ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                        ("lpReserved2", ctypes.c_void_p), ("hStdInput", w.HANDLE),
                        ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

        class STARTUPINFOEXW(ctypes.Structure):
            _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                        ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", w.DWORD), ("dwHighDateTime", w.DWORD)]

        class TOKEN_MANDATORY_LABEL(ctypes.Structure):
            _fields_ = [("Label", SID_AND_ATTRIBUTES)]

        class TOKEN_APPCONTAINER_INFORMATION(ctypes.Structure):
            _fields_ = [("TokenAppContainer", ctypes.c_void_p)]

        class TOKEN_GROUPS(ctypes.Structure):
            _fields_ = [("GroupCount", w.DWORD), ("Groups", SID_AND_ATTRIBUTES * 1)]

        _TYPES = types.SimpleNamespace(
            ctypes=ctypes, w=w, SID_AND_ATTRIBUTES=SID_AND_ATTRIBUTES,
            SECURITY_CAPABILITIES=SECURITY_CAPABILITIES, STARTUPINFOW=STARTUPINFOW,
            STARTUPINFOEXW=STARTUPINFOEXW, PROCESS_INFORMATION=PROCESS_INFORMATION,
            FILETIME=FILETIME, TOKEN_MANDATORY_LABEL=TOKEN_MANDATORY_LABEL,
            TOKEN_APPCONTAINER_INFORMATION=TOKEN_APPCONTAINER_INFORMATION,
            TOKEN_GROUPS=TOKEN_GROUPS)
    return _TYPES


def _signatures(t: types.SimpleNamespace) -> dict[str, tuple[str, Any, list[Any]]]:
    """name -> (DLL, restype, argtypes) of every Win32 function used."""
    c, w = t.ctypes, t.w
    P = c.POINTER
    return {
        "CreateProcessW": ("kernel32", w.BOOL, [
            w.LPCWSTR, c.c_void_p, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD, c.c_void_p,
            w.LPCWSTR, P(t.STARTUPINFOEXW), P(t.PROCESS_INFORMATION)]),
        "InitializeProcThreadAttributeList": ("kernel32", w.BOOL,
                                              [c.c_void_p, w.DWORD, w.DWORD, P(c.c_size_t)]),
        "UpdateProcThreadAttribute": ("kernel32", w.BOOL, [
            c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p]),
        "DeleteProcThreadAttributeList": ("kernel32", None, [c.c_void_p]),
        "SetHandleInformation": ("kernel32", w.BOOL, [w.HANDLE, w.DWORD, w.DWORD]),
        "ResumeThread": ("kernel32", w.DWORD, [w.HANDLE]),
        "TerminateProcess": ("kernel32", w.BOOL, [w.HANDLE, w.UINT]),
        "WaitForSingleObject": ("kernel32", w.DWORD, [w.HANDLE, w.DWORD]),
        "GetExitCodeProcess": ("kernel32", w.BOOL, [w.HANDLE, P(w.DWORD)]),
        "GetProcessId": ("kernel32", w.DWORD, [w.HANDLE]),
        "GetProcessTimes": ("kernel32", w.BOOL, [w.HANDLE] + [P(t.FILETIME)] * 4),
        "QueryFullProcessImageNameW": ("kernel32", w.BOOL,
                                       [w.HANDLE, w.DWORD, c.c_void_p, P(w.DWORD)]),
        "CloseHandle": ("kernel32", w.BOOL, [w.HANDLE]),
        "GetCurrentProcess": ("kernel32", w.HANDLE, []),
        "GetProcessHeap": ("kernel32", w.HANDLE, []),
        "HeapFree": ("kernel32", w.BOOL, [w.HANDLE, w.DWORD, c.c_void_p]),
        "LocalFree": ("kernel32", c.c_void_p, [c.c_void_p]),
        "OpenProcessToken": ("advapi32", w.BOOL, [w.HANDLE, w.DWORD, P(w.HANDLE)]),
        "GetTokenInformation": ("advapi32", w.BOOL,
                                [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, P(w.DWORD)]),
        "ConvertSidToStringSidW": ("advapi32", w.BOOL, [c.c_void_p, P(w.LPWSTR)]),
        "ConvertStringSidToSidW": ("advapi32", w.BOOL, [w.LPCWSTR, P(c.c_void_p)]),
        "FreeSid": ("advapi32", c.c_void_p, [c.c_void_p]),
        "DeriveAppContainerSidFromAppContainerName": ("userenv", c.c_long,
                                                      [w.LPCWSTR, P(c.c_void_p)]),
        "GetAppContainerFolderPath": ("userenv", c.c_long, [w.LPCWSTR, P(w.LPWSTR)]),
        "CoTaskMemFree": ("ole32", None, [c.c_void_p]),
        "NetworkIsolationGetAppContainerConfig": ("firewallapi", w.DWORD,
                                                  [P(w.DWORD), P(P(t.SID_AND_ATTRIBUTES))]),
    }


WIN32_DLLS: tuple[str, ...] = ("kernel32", "advapi32", "userenv", "ole32", "firewallapi")
#: Upper bound for one token information buffer (fail closed beyond it).
TOKEN_BUFFER_LIMIT: int = 64 * 1024
#: Smallest SID: revision, count, authority (8 bytes) - a pointer to a SID
#: inside a token buffer must leave at least this much room.
MIN_SID_BYTES: int = 8


@dataclass(frozen=True)
class CreationReceipt:
    """What one CreateProcessW call actually ran with: the identifiers of
    the attributes whose UpdateProcThreadAttribute call succeeded (in the
    order applied), the handles given to the job-list attribute, and whether
    CreateProcessW itself succeeded.  `planned` is True only when an
    attribute plan was supplied; a creation without one is the legacy,
    uncontained path.  A receipt is a record of native results, not proof
    of job membership, and mints no assertion of it."""
    applied_attributes: tuple[int, ...]
    job_list_handles: tuple[int, ...]
    create_process_ok: bool
    planned: bool

    @property
    def job_list_applied(self) -> bool:
        return (self.planned and self.create_process_ok
                and PROC_THREAD_ATTRIBUTE_JOB_LIST in self.applied_attributes
                and len(self.job_list_handles) == 1)


@dataclass
class Win32Handles:
    process: Any
    thread: Any
    pid: int
    tid: int
    cleanup_errors: list[str] = field(default_factory=list)
    receipt: Optional[CreationReceipt] = None


@dataclass(frozen=True)
class CustodySnapshot:
    """What a custody holder can be seen to hold right now.  Every field is
    an observation about Python-side state, never a verification: an
    observed handle value is not shown to name a live process, its PID or a
    job.  `readable` is False when the structure could not be read;
    `inconsistent` is True when a handle value is present although the
    native call was never entered (the observation is then not trustworthy)."""
    attached: bool
    entered: bool
    process_handle_observed: bool
    thread_handle_observed: bool
    readable: bool
    inconsistent: bool


#: The explicit result of an observation that could not be made at all.
_UNREADABLE_SNAPSHOT = CustodySnapshot(False, False, False, False, False, False)


class HandleCustody:
    """
    Owns, from before the native creation call, the structure into which the
    operating system writes the new process's handles, so that the handles
    stay reachable whatever happens after the call returns.  The creator
    attaches the zeroed structure once and marks the entry once, immediately
    before the call; nothing is stored after it.

    Custody observes and preserves only.  It has no close, reset, detach,
    finalizer, termination or recovery behaviour, and it is never reused.
    """

    __slots__ = ("_info", "_entered")

    def __init__(self) -> None:
        self._info: Any = None
        self._entered = False

    @property
    def attached(self) -> bool:
        return self._info is not None

    @property
    def entered(self) -> bool:
        return self._entered

    def attach(self, info: Any) -> None:
        """Write-once: attach the zeroed PROCESS_INFORMATION structure."""
        if self._info is not None:
            raise CalibrationError("the handle custody already holds a structure")
        t = _win32_types()
        if not isinstance(info, t.PROCESS_INFORMATION):
            raise CalibrationError("the handle custody takes only a PROCESS_INFORMATION")
        if any(getattr(info, name) for name in
               ("hProcess", "hThread", "dwProcessId", "dwThreadId")):
            raise CalibrationError("the handle custody takes only a zeroed structure")
        self._info = info

    def mark_entered(self) -> None:
        """Write-once: the creator is about to make the native call."""
        if self._info is None:
            raise CalibrationError("the handle custody has no structure attached")
        if self._entered:
            raise CalibrationError("the handle custody was already entered")
        self._entered = True

    def snapshot(self) -> CustodySnapshot:
        """The current observations; never raises.  This is a purely
        diagnostic read, so even an interruption while observing is absorbed
        and reported as an unreadable snapshot (nothing observed, nothing
        claimed); no creation, ownership or cleanup path does this."""
        try:
            info, entered = self._info, bool(self._entered)
            attached = info is not None
            try:
                if info is None:
                    return CustodySnapshot(False, entered, False, False, True, False)
                process, thread = _valid_handle(info.hProcess), _valid_handle(info.hThread)
                return CustodySnapshot(attached, entered, process, thread, True,
                                       bool((process or thread) and not entered))
            except BaseException:
                return CustodySnapshot(attached, entered, False, False, False, False)
        except BaseException:
            return _UNREADABLE_SNAPSHOT

    def raw_values(self) -> Optional[tuple[Any, Any, Any, Any]]:
        """(process handle, thread handle, PID, TID) exactly as the structure
        holds them, or None when nothing is attached.  Unverified: for a
        later, separately authorized step only."""
        info = self._info
        if info is None:
            return None
        return info.hProcess, info.hThread, info.dwProcessId, info.dwThreadId


def _validated_plan(plan: Any, size_validator: Any, stdout: Any, stderr: Any
                    ) -> tuple[tuple[int, tuple[int, ...]], ...]:
    """The (attribute, handles) pairs of a supplied attribute plan, or a
    refusal.  The plan is duck-typed (entries with .attribute and .handles,
    and .count); it must be exactly SECURITY_CAPABILITIES, HANDLE_LIST and
    JOB_LIST in that order, with the handle list exactly the authorized
    stdout and stderr handles and a job list of one valid handle that is
    not among them.  Nothing native is called here."""
    if not callable(size_validator):
        raise CalibrationError("an attribute plan needs its attribute-list size validator")
    entries = getattr(plan, "entries", None)
    if not isinstance(entries, (tuple, list)) or not entries:
        raise CalibrationError("the attribute plan has no entries")
    if getattr(plan, "count", None) != len(entries) or isinstance(
            getattr(plan, "count", None), bool):
        raise CalibrationError("the attribute plan's count is not derived from its entries")
    parsed = []
    for entry in entries:
        attribute = getattr(entry, "attribute", None)
        handles = getattr(entry, "handles", None)
        if isinstance(attribute, bool) or not isinstance(attribute, int) \
                or not isinstance(handles, tuple) \
                or not all(_valid_handle(h) for h in handles):
            raise CalibrationError("the attribute plan has a malformed entry")
        parsed.append((attribute, handles))
    attributes = tuple(a for a, _ in parsed)
    if len(set(attributes)) != len(attributes):
        raise CalibrationError("the attribute plan has a duplicate attribute")
    unexpected = [a for a in attributes if a not in PLAN_ATTRIBUTES]
    if unexpected:
        raise CalibrationError("the attribute plan has an unexpected attribute: "
                               + ", ".join(f"{a:#x}" for a in unexpected))
    missing = [a for a in PLAN_ATTRIBUTES if a not in attributes]
    if missing:
        raise CalibrationError("the attribute plan lacks an attribute: "
                               + ", ".join(f"{a:#x}" for a in missing))
    if attributes != PLAN_ATTRIBUTES:
        raise CalibrationError("the attribute plan is not in the accepted order")
    by_attribute = dict(parsed)
    if by_attribute[PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES] != ():
        raise CalibrationError("the security-capabilities entry carries handles")
    inherited = by_attribute[PROC_THREAD_ATTRIBUTE_HANDLE_LIST]
    if inherited != (stdout, stderr):
        raise CalibrationError("the handle list is not exactly the authorized stdout and "
                               "stderr handles")
    job = by_attribute[PROC_THREAD_ATTRIBUTE_JOB_LIST]
    if len(job) != 1:
        raise CalibrationError("the job list must hold exactly one handle")
    if job[0] in inherited:
        raise CalibrationError("the job handle must never be in the inherited handle list")
    return tuple(parsed)


def _default_loader(name: str) -> Any:
    import ctypes
    return ctypes.WinDLL(name, use_last_error=True)


class CtypesWin32:
    """
    The documented Win32 calls, through ctypes.  Every call re-checks the
    authorization; each DLL is loaded only when an operation first needs it.
    Tests pass a fake loader, a fake last-error source and a fake
    file-handle lookup.
    """

    def __init__(self, auth: Any, *, loader: Optional[Callable[[str], Any]] = None,
                 last_error: Optional[Callable[[], int]] = None,
                 os_handle: Optional[Callable[[Any], int]] = None) -> None:
        self.auth = _require_any_authorization(auth)
        self._loader = loader or _default_loader
        self._loaded: dict[str, Any] = {}
        self._last_error = last_error
        self._os_handle = os_handle
        self.last_cleanup_errors: list[str] = []

    @property
    def loaded_dlls(self) -> list[str]:
        return sorted(self._loaded)

    def _api(self, name: str) -> Any:
        _require_any_authorization(self.auth)
        t = _win32_types()
        dll, restype, argtypes = _signatures(t)[name]
        if dll not in self._loaded:
            self._loaded[dll] = self._loader(dll)
        function = getattr(self._loaded[dll], name)
        function.restype, function.argtypes = restype, argtypes
        return function

    def _code(self) -> Any:
        return (self._last_error or _win32_types().ctypes.get_last_error)()

    def _error(self, api: str) -> Win32Error:
        return Win32Error(api, self._code())

    def _sid_string(self, psid: Any) -> str:
        t = _win32_types()
        c = t.ctypes
        local_free = self._api("LocalFree")
        text = t.w.LPWSTR()
        if not self._api("ConvertSidToStringSidW")(psid, c.byref(text)):
            raise self._error("ConvertSidToStringSidW")
        value = str(text.value)
        if local_free(c.cast(text, c.c_void_p)):
            raise Win32Error("LocalFree", self._code())
        return value

    def derive_sid(self, name: str) -> str:
        c = _win32_types().ctypes
        free_sid = self._api("FreeSid")
        psid = c.c_void_p()
        result = self._api("DeriveAppContainerSidFromAppContainerName")(name, c.byref(psid))
        if result != 0 or not psid.value:
            raise Win32Error("DeriveAppContainerSidFromAppContainerName", result & 0xFFFFFFFF)
        try:
            return self._sid_string(psid.value)
        finally:
            free_sid(psid)

    def profile_folder(self, sid: str) -> str:
        """GetAppContainerFolderPath.  Supplementary only: it is not
        documented as a test of profile existence."""
        t = _win32_types()
        c = t.ctypes
        co_task_mem_free = self._api("CoTaskMemFree")
        path = t.w.LPWSTR()
        result = self._api("GetAppContainerFolderPath")(sid, c.byref(path))
        try:
            if result != 0:
                raise Win32Error("GetAppContainerFolderPath", result & 0xFFFFFFFF)
            return str(path.value)
        finally:
            if path.value is not None:
                co_task_mem_free(c.cast(path, c.c_void_p))

    def loopback_exempt_sids(self) -> list[str]:
        """
        NetworkIsolationGetAppContainerConfig, then Microsoft's documented
        release: HeapFree(GetProcessHeap(), 0, sid) for every returned SID
        and HeapFree(GetProcessHeap(), 0, array) for the array - also after
        a failure, for whatever was returned.  Any conversion or release
        problem fails the call.
        """
        t = _win32_types()
        c = t.ctypes
        heap_free = self._api("HeapFree")
        heap = self._api("GetProcessHeap")()
        if not _valid_handle(heap):
            raise self._error("GetProcessHeap")
        count = t.w.DWORD(0)
        array = c.POINTER(t.SID_AND_ATTRIBUTES)()
        result = self._api("NetworkIsolationGetAppContainerConfig")(c.byref(count),
                                                                     c.byref(array))
        entries = count.value if array else 0
        problems: list[str] = []
        if count.value and not array:
            problems.append("a count without an array")
        sids: list[str] = []
        try:
            if result == 0:
                for index in range(entries):
                    psid = array[index].Sid
                    if not psid:
                        problems.append(f"SID {index} is null")
                        continue
                    try:
                        sids.append(self._sid_string(psid))
                    except Exception as exc:
                        problems.append(f"SID {index}: {type(exc).__name__}: {exc}")
        finally:
            for index in range(entries):
                psid = array[index].Sid
                if psid and not heap_free(heap, 0, psid):
                    problems.append(f"HeapFree of SID {index} failed")
            if array and not heap_free(heap, 0, c.cast(array, c.c_void_p)):
                problems.append("HeapFree of the array failed")
        if result != 0:
            raise Win32Error("NetworkIsolationGetAppContainerConfig", result)
        if problems:
            raise Win32Error("NetworkIsolationGetAppContainerConfig", "; ".join(problems))
        return sids

    def _handle_of(self, stream: Any) -> int:
        if self._os_handle is not None:
            return self._os_handle(stream)
        import msvcrt
        return msvcrt.get_osfhandle(stream.fileno())

    def create_process(self, *, application: str, command_line: str, env: Mapping[str, str],
                       cwd: str, stdout: Any, stderr: Any, sid: str,
                       attribute_plan: Any = None, size_validator: Any = None,
                       custody: Optional[HandleCustody] = None) -> Win32Handles:
        """
        CreateProcessW, suspended, in the AppContainer `sid` with NO
        capabilities, inheriting exactly the stdout and stderr handles.  The
        cleanup functions are bound before anything is allocated and the
        cleanup never raises, so a created process is always returned (with
        any cleanup errors attached), never lost.

        Without `attribute_plan` this is the legacy two-attribute creation
        (SECURITY_CAPABILITIES, HANDLE_LIST), unchanged and uncontained.
        With one - an injected plan of exactly SECURITY_CAPABILITIES,
        HANDLE_LIST and JOB_LIST, and the injected `size_validator` for the
        sizing call - the attribute count comes from the plan, the first
        sizing result is validated, the list lives in a pointer-aligned
        buffer, the second initialization must succeed, and every attribute
        value stays alive until after DeleteProcThreadAttributeList.  A
        supplied plan that fails anywhere refuses; it never falls back to
        the legacy creation.  The returned handles carry a CreationReceipt
        of the natively applied attributes; no membership is claimed.

        A supplied plan also requires an unused HandleCustody, which the
        caller owns: the zeroed PROCESS_INFORMATION is attached to it, and
        the entry marked, just before CreateProcessW, so the handles stay
        reachable through it even if this function never returns.  The
        legacy creation refuses a custody.  Both refusals precede any native
        call.
        """
        if attribute_plan is not None:
            if not isinstance(custody, HandleCustody):
                raise CalibrationError("an attribute plan needs its handle custody")
            if custody.attached or custody.entered:
                raise CalibrationError("the handle custody was already used")
        elif custody is not None:
            raise CalibrationError("a handle custody without an attribute plan")
        t = _win32_types()
        c, w = t.ctypes, t.w
        handles = [self._handle_of(stdout), self._handle_of(stderr)]
        if not all(_valid_handle(h) for h in handles):
            raise Win32Error("get_osfhandle", "invalid output handle")
        planned = attribute_plan is not None
        if planned:
            spec = _validated_plan(attribute_plan, size_validator, handles[0], handles[1])
        elif size_validator is not None:
            raise CalibrationError("a size validator without an attribute plan")
        else:
            spec = ((PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, ()),
                    (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, tuple(handles)))
        count = len(spec)
        command_buffer = c.create_unicode_buffer(command_line)
        environment = c.create_unicode_buffer(environment_block(env))
        convert = self._api("ConvertStringSidToSidW")
        set_information = self._api("SetHandleInformation")
        initialize = self._api("InitializeProcThreadAttributeList")
        update = self._api("UpdateProcThreadAttribute")
        delete = self._api("DeleteProcThreadAttributeList")
        local_free = self._api("LocalFree")
        create = self._api("CreateProcessW")
        psid = c.c_void_p()
        if not convert(sid, c.byref(psid)):
            raise self._error("ConvertStringSidToSidW")
        attributes = None
        initialized = False
        inheritable: list[int] = []
        values: list[Any] = []                      # every attribute value, kept alive
        applied: list[int] = []                     # attributes whose update succeeded
        job_handles: tuple[int, ...] = ()
        created: Optional[Win32Handles] = None
        cleanup_errors: list[str] = []
        try:
            for handle in handles:
                if not set_information(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT):
                    raise self._error("SetHandleInformation")
                inheritable.append(handle)
            size = c.c_size_t(0)
            first = initialize(None, count, 0, c.byref(size))
            if planned:
                checked = size_validator(first, self._code(), size.value)
                if checked != size.value or isinstance(checked, bool):
                    raise CalibrationError("the size validator changed the attribute-list size")
                slots = -(-size.value // c.sizeof(c.c_void_p))
                attributes = (c.c_void_p * slots)()               # pointer-aligned
            else:
                if not size.value:
                    raise self._error("InitializeProcThreadAttributeList")
                attributes = c.create_string_buffer(size.value)
            if not initialize(c.addressof(attributes), count, 0, c.byref(size)):
                raise self._error("InitializeProcThreadAttributeList")
            initialized = True
            for attribute, entry_handles in spec:                 # values live until return
                if attribute == PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES:
                    value = t.SECURITY_CAPABILITIES(psid.value, None, 0, 0)
                else:
                    value = (w.HANDLE * len(entry_handles))(*entry_handles)
                values.append(value)
                if not update(c.addressof(attributes), 0, attribute, c.addressof(value),
                              c.sizeof(value), None, None):
                    raise self._error("UpdateProcThreadAttribute")
                applied.append(attribute)
                if attribute == PROC_THREAD_ATTRIBUTE_JOB_LIST:
                    job_handles = tuple(entry_handles)
            startup = t.STARTUPINFOEXW()
            startup.StartupInfo.cb = c.sizeof(startup)
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES
            startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = handles
            startup.lpAttributeList = c.addressof(attributes)
            info = t.PROCESS_INFORMATION()
            if custody is not None:
                custody.attach(info)
                custody.mark_entered()                  # immediately before the native call
            if not create(application, c.addressof(command_buffer), None, None, True,
                          CREATION_FLAGS, c.addressof(environment), cwd, c.byref(startup),
                          c.byref(info)):
                raise self._error("CreateProcessW")
            created = Win32Handles(
                info.hProcess, info.hThread, info.dwProcessId, info.dwThreadId,
                receipt=CreationReceipt(tuple(applied), job_handles, True, planned))
        finally:
            if initialized:
                try:
                    delete(c.addressof(attributes))
                except Exception as exc:
                    cleanup_errors.append(f"DeleteProcThreadAttributeList: {type(exc).__name__}")
            for handle in inheritable:
                try:
                    if not set_information(handle, HANDLE_FLAG_INHERIT, 0):
                        cleanup_errors.append(f"SetHandleInformation could not reset "
                                              f"inheritance of handle {handle}")
                except Exception as exc:
                    cleanup_errors.append(f"SetHandleInformation: {type(exc).__name__}")
            try:
                if local_free(psid):
                    cleanup_errors.append("LocalFree of the AppContainer SID failed")
            except Exception as exc:
                cleanup_errors.append(f"LocalFree: {type(exc).__name__}")
            self.last_cleanup_errors = list(cleanup_errors)
            if created is not None:
                created.cleanup_errors.extend(cleanup_errors)
        return created

    def process_id(self, process: Any) -> int:
        pid = self._api("GetProcessId")(process)
        if not pid:
            raise self._error("GetProcessId")
        return int(pid)

    def creation_time(self, process: Any) -> str:
        t = _win32_types()
        times = [t.FILETIME() for _ in range(4)]
        if not self._api("GetProcessTimes")(process, *[t.ctypes.byref(f) for f in times]):
            raise self._error("GetProcessTimes")
        return _filetime_iso(times[0].dwLowDateTime, times[0].dwHighDateTime)

    def image_path(self, process: Any) -> str:
        t = _win32_types()
        c = t.ctypes
        buffer = c.create_unicode_buffer(32768)
        size = t.w.DWORD(32768)
        if not self._api("QueryFullProcessImageNameW")(process, 0, c.addressof(buffer),
                                                       c.byref(size)):
            raise self._error("QueryFullProcessImageNameW")
        return buffer.value

    def _token_query(self, token: Any, information_class: int) -> tuple[Any, int]:
        """(pointer-aligned buffer, returned length).  Fixed-size classes use
        their documented size and one call; variable ones are sized first."""
        t = _win32_types()
        c = t.ctypes
        query = self._api("GetTokenInformation")
        fixed = {TOKEN_IS_APP_CONTAINER: t.w.DWORD}.get(information_class)
        if fixed is not None:
            needed = c.sizeof(fixed)
        else:
            size = t.w.DWORD(0)
            if query(token, information_class, None, 0, c.byref(size)):
                raise Win32Error("GetTokenInformation", "unexpected success without a buffer")
            code = self._code()
            if code not in (ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH) or not size.value:
                raise Win32Error("GetTokenInformation", code)
            needed = size.value
        if not 0 < needed <= TOKEN_BUFFER_LIMIT:
            raise Win32Error("GetTokenInformation", f"implausible size {needed}")
        pointer = c.sizeof(c.c_void_p)
        buffer = (c.c_void_p * max(1, -(-needed // pointer)))()
        returned = t.w.DWORD(0)
        if not query(token, information_class, c.addressof(buffer), needed, c.byref(returned)):
            raise self._error("GetTokenInformation")
        if returned.value > c.sizeof(buffer) or (fixed is not None and returned.value != needed):
            raise Win32Error("GetTokenInformation", f"unexpected length {returned.value}")
        return buffer, returned.value

    @staticmethod
    def _need(length: int, size: int, what: str) -> None:
        if length < size:
            raise Win32Error("GetTokenInformation", f"short {what}")

    @staticmethod
    def _inside(buffer: Any, length: int, pointer: int, what: str) -> None:
        """A SID pointer must point into the returned buffer (fail closed)."""
        base = _win32_types().ctypes.addressof(buffer)
        if not pointer or not base <= pointer <= base + length - MIN_SID_BYTES:
            raise Win32Error("GetTokenInformation", f"{what} outside the returned buffer")

    def token_info(self, process: Any) -> dict[str, Any]:
        """The token's AppContainer flag, AppContainer SID, capability SIDs
        and integrity level, with every layout checked."""
        t = _win32_types()
        c, w = t.ctypes, t.w
        close = self._api("CloseHandle")
        token = w.HANDLE()
        if not self._api("OpenProcessToken")(process, TOKEN_QUERY, c.byref(token)):
            raise self._error("OpenProcessToken")
        try:
            raw, length = self._token_query(token, TOKEN_IS_APP_CONTAINER)
            flag = w.DWORD.from_buffer(raw).value
            if flag not in (0, 1):
                raise Win32Error("GetTokenInformation", f"unexpected TokenIsAppContainer {flag}")
            raw, length = self._token_query(token, TOKEN_APP_CONTAINER_SID)
            self._need(length, c.sizeof(t.TOKEN_APPCONTAINER_INFORMATION), "TokenAppContainerSid")
            psid = t.TOKEN_APPCONTAINER_INFORMATION.from_buffer(raw).TokenAppContainer
            sid = None
            if psid:
                self._inside(raw, length, psid, "the AppContainer SID")
                sid = self._sid_string(psid)
            raw, length = self._token_query(token, TOKEN_CAPABILITIES)
            self._need(length, c.sizeof(w.DWORD), "TokenCapabilities")
            count = w.DWORD.from_buffer(raw).value
            offset = t.TOKEN_GROUPS.Groups.offset
            if count and offset + count * c.sizeof(t.SID_AND_ATTRIBUTES) > length:
                raise Win32Error("GetTokenInformation", "malformed capabilities")
            capabilities = []
            for group in ((t.SID_AND_ATTRIBUTES * count).from_buffer(raw, offset)
                          if count else []):
                self._inside(raw, length, group.Sid, "a capability SID")
                capabilities.append(self._sid_string(group.Sid))
            raw, length = self._token_query(token, TOKEN_INTEGRITY_LEVEL)
            self._need(length, c.sizeof(t.TOKEN_MANDATORY_LABEL), "TokenIntegrityLevel")
            label = t.TOKEN_MANDATORY_LABEL.from_buffer(raw).Label.Sid
            self._inside(raw, length, label, "the integrity label")
            integrity = _integrity_name(self._sid_string(label))
        finally:
            close(token)
        return {"is_app_container": flag == 1, "app_container_sid": sid,
                "capabilities": capabilities, "integrity_level": integrity}

    def current_token_info(self) -> dict[str, Any]:
        return self.token_info(self._api("GetCurrentProcess")())

    def resume(self, thread: Any) -> int:
        previous = self._api("ResumeThread")(thread)
        if previous == RESUME_FAILED:
            raise self._error("ResumeThread")
        return int(previous)

    def terminate(self, process: Any, code: int) -> None:
        if not self._api("TerminateProcess")(process, code):
            raise self._error("TerminateProcess")

    def wait(self, process: Any, milliseconds: int) -> bool:
        result = self._api("WaitForSingleObject")(process, milliseconds)
        if result == WAIT_OBJECT_0:
            return True
        if result == WAIT_TIMEOUT:
            return False
        raise self._error("WaitForSingleObject")

    def exit_code(self, process: Any) -> int:
        t = _win32_types()
        code = t.w.DWORD()
        if not self._api("GetExitCodeProcess")(process, t.ctypes.byref(code)):
            raise self._error("GetExitCodeProcess")
        return int(code.value)

    def close(self, handle: Any) -> None:
        if not self._api("CloseHandle")(handle):
            raise self._error("CloseHandle")


class Win32Process:
    """
    A child created suspended by Win32AppContainerApi; pid, creation_time,
    poll() and returncode as the orchestrator expects, plus its evidence:
    execution_history (never / may have / unknown) and liveness
    (confirmed exited / alive at last check / unknown), kept separately.
    """

    def __init__(self, win32: Any, handles: Win32Handles) -> None:
        self.win32, self.handles = win32, handles
        self.pid = handles.pid
        self.creation_time: Optional[str] = None
        self.image_path: Optional[str] = None
        self.returncode: Optional[int] = None
        self.execution_history = NEVER_EXECUTED          # created suspended
        self.liveness = ALIVE_AT_LAST_CHECK
        self.resume_previous_count: Optional[int] = None
        self.handles_retained = False
        self.cleanup_errors: list[str] = list(handles.cleanup_errors)
        self.resumed = False
        self.discarded = False

    def _close(self, which: str) -> None:
        handle = getattr(self.handles, which)
        if _valid_handle(handle):
            self.win32.close(handle)
            setattr(self.handles, which, None)

    def poll(self) -> Optional[int]:
        """The actual exit status (GetExitCodeProcess) once the process has
        exited, else None."""
        if self.returncode is not None:
            return self.returncode
        if not self.win32.wait(self.handles.process, 0):
            return None
        self.returncode = self.win32.exit_code(self.handles.process)
        self.liveness = CONFIRMED_EXITED
        try:
            self._close("process")
        except Exception as exc:
            self.cleanup_errors.append(f"closing the process handle failed: {exc}")
        return self.returncode


class Win32AppContainerApi:
    """The Win32 backend of AppContainerLauncher.  Every method re-checks the
    authorization.  It never creates or deletes a profile and never changes
    ACLs."""

    def __init__(self, auth: Any, *, win32: Any = None) -> None:
        self.auth = _require_any_authorization(auth)
        self.win32 = win32 if win32 is not None else CtypesWin32(auth)

    def _gate(self) -> None:
        _require_any_authorization(self.auth)

    def profile_sid(self, name: str) -> str:
        self._gate()
        return self.win32.derive_sid(name)

    def profile_folder_present(self, sid: str) -> bool:
        """Supplementary, necessary-not-sufficient: GetAppContainerFolderPath
        is not documented as a profile-existence test."""
        self._gate()
        try:
            return bool(self.win32.profile_folder(sid))
        except Win32Error:
            return False

    def create_suspended(self, command: ChildCommand, sid: str, capabilities: Sequence[str],
                         stdout: Any, stderr: Any) -> Win32Process:
        self._gate()
        if capabilities:
            raise CalibrationError("the calibration AppContainer must have no capabilities")
        handles = self.win32.create_process(
            application=command.argv[0], command_line=command.command_line, env=command.env,
            cwd=command.cwd, stdout=stdout, stderr=stderr, sid=sid)
        process = Win32Process(self.win32, handles)
        try:
            if handles.cleanup_errors:
                raise CalibrationError("native cleanup after CreateProcessW failed: "
                                       + "; ".join(handles.cleanup_errors))
            if not _valid_handle(handles.process) or not _valid_handle(handles.thread):
                raise CalibrationError("CreateProcessW returned an invalid handle")
            if self.win32.process_id(handles.process) != handles.pid:
                raise CalibrationError("the process handle does not belong to the created PID")
            process.creation_time = self.win32.creation_time(handles.process)
            process.image_path = self.win32.image_path(handles.process)
        except Exception as exc:
            try:
                self.discard_suspended(process)
            except CalibrationError as failed:
                raise _launch_failure(f"{exc}; {failed}", process) from None
            raise _launch_failure(f"{exc}; the child was discarded and confirmed exited "
                                  f"(execution history: {process.execution_history})",
                                  process) from None
        return process

    def token_info(self, process: Win32Process) -> dict[str, Any]:
        self._gate()
        info = dict(self.win32.token_info(process.handles.process))
        info["loopback_exempt"] = info.get("app_container_sid") in set(
            self.win32.loopback_exempt_sids())
        info["pid"] = self.win32.process_id(process.handles.process)
        info["image_path"] = process.image_path
        return info

    def resume(self, process: Win32Process) -> None:
        """ResumeThread.  A previous count of 1 resumes the child: from then
        on it may have executed.  A count of 0 means it was already running
        (may have executed); above 1 it stays suspended (never executed);
        a failed call leaves its history unknown."""
        self._gate()
        try:
            previous = self.win32.resume(process.handles.thread)
        except Exception:
            process.execution_history = STATE_UNKNOWN
            raise
        process.resume_previous_count = previous
        if previous in (0, 1):
            process.execution_history = MAY_HAVE_EXECUTED
        if previous != 1:
            raise CalibrationError(f"the child's suspend count was {previous}, not 1")
        process.resumed = True
        try:
            process._close("thread")
        except Exception as exc:
            process.cleanup_errors.append(f"closing the thread handle failed: {exc}")

    def discard_suspended(self, process: Win32Process) -> None:
        """
        Terminate a child that was not validly resumed and verify its exit
        (signalled, exit code DISCARD_EXIT_CODE).  Only then is it
        confirmed exited and are its handles closed.  Otherwise its liveness
        is unknown, its PID and handles are kept, and this raises.  The
        execution history is never improved by a discard.
        """
        self._gate()
        errors: list[str] = []
        handle = process.handles.process
        exited = False
        if _valid_handle(handle):
            try:
                self.win32.terminate(handle, DISCARD_EXIT_CODE)
                if not self.win32.wait(handle, DISCARD_WAIT_MILLISECONDS):
                    errors.append("it did not exit after termination")
                else:
                    exited = True
                    if self.win32.exit_code(handle) != DISCARD_EXIT_CODE:
                        errors.append("its exit code is not the discard code")
                        if process.execution_history == NEVER_EXECUTED:
                            process.execution_history = STATE_UNKNOWN
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
        else:
            errors.append("there is no valid process handle")
        process.liveness = CONFIRMED_EXITED if exited else STATE_UNKNOWN
        if errors:
            process.handles_retained = True
            process.cleanup_errors.extend(errors)
            raise CalibrationError(f"the child PID {process.pid} could not be discarded: "
                                   + "; ".join(errors) + "; its handles are kept; inspect it")
        for which in ("thread", "process"):
            try:
                process._close(which)
            except Exception as exc:
                process.cleanup_errors.append(f"closing the {which} handle failed: {exc}")
        process.discarded = True


# ---------------------------------------------------------------------------
# OS-level observation (incomplete network evidence; fails closed)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    creation_time: str          # ISO-8601 UTC, as reported by the launcher


@dataclass
class Observation:
    problems: list[str]
    endpoints: list[str]
    processes: list[str]
    root_present: bool


def observation_script(pid: int) -> str:
    """PowerShell that lists the root process and its descendants (with
    creation times, so a reused PID is not mistaken for a descendant), their
    TCP connections, UDP endpoints and loaded network DLLs.  Any error is
    written to stderr with exit 1."""
    pid = int(pid)
    return (
        "$ErrorActionPreference = 'Stop'; try { "
        "$all = @(Get-CimInstance Win32_Process); "
        f"$root = $all | Where-Object {{ $_.ProcessId -eq {pid} }}; "
        "if (-not $root) { 'root-missing'; exit 0 }; "
        f"$ids = @({pid}); "
        "do { $n = $ids.Count; $ids = @(@($ids + ($all | Where-Object { "
        "($ids -contains $_.ParentProcessId) -and ($_.CreationDate -ge $root.CreationDate) } | "
        "ForEach-Object ProcessId)) | Sort-Object -Unique) } while ($ids.Count -ne $n); "
        "$all | Where-Object { $ids -contains $_.ProcessId } | ForEach-Object { 'proc ' + "
        "$_.ProcessId + ' ' + $_.ParentProcessId + ' ' + "
        "$_.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }; "
        "Get-NetTCPConnection | Where-Object { $ids -contains $_.OwningProcess } | "
        "ForEach-Object { 'tcp ' + $_.LocalAddress + ':' + $_.LocalPort + ' ' + "
        "$_.RemoteAddress + ':' + $_.RemotePort + ' ' + $_.State }; "
        "Get-NetUDPEndpoint | Where-Object { $ids -contains $_.OwningProcess } | "
        "ForEach-Object { 'udp ' + $_.LocalAddress + ':' + $_.LocalPort }; "
        "foreach ($id in $ids) { (Get-Process -Id $id).Modules | Where-Object { "
        "$_.ModuleName -match 'rdkafka|grpc|libpq' } | ForEach-Object { 'dll ' + $id + ' ' + "
        "$_.ModuleName } } "
        "} catch { [Console]::Error.WriteLine('observation failed: ' + "
        "$_.Exception.GetType().FullName); exit 1 }"
    )


def _parse_utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def parse_observation(returncode: Any, stdout: str, stderr: str,
                      identity: ProcessIdentity) -> Observation:
    """An Observation; anything unexpected is a problem (fail closed)."""
    problems: list[str] = []
    if returncode != 0:
        problems.append(f"observation exited with {returncode!r}")
    if stderr.strip():
        problems.append("observation stderr: " + stderr.strip()[:300])
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    processes = [line for line in lines if line.startswith("proc ")]
    endpoints = [line for line in lines if line.split(" ", 1)[0] in ("tcp", "udp", "dll")]
    for line in lines:
        if line != "root-missing" and line not in processes and line not in endpoints:
            problems.append(f"unexpected observation output: {line[:100]}")
    root_present = False
    if "root-missing" not in lines:
        for line in processes:
            parts = line.split()
            try:
                pid, created = int(parts[1]), _parse_utc(parts[3])
                expected = _parse_utc(identity.creation_time)
            except (IndexError, ValueError):
                problems.append(f"malformed process line: {line[:100]}")
                continue
            if pid == identity.pid:
                if abs((created - expected).total_seconds()) > CREATION_TOLERANCE_SECONDS:
                    problems.append(f"PID {pid} now belongs to another process (creation time "
                                    "differs)")
                else:
                    root_present = True
        if not root_present and not any("PID" in p for p in problems):
            problems.append("the child's process identity is missing from the observation")
    if endpoints:
        problems.append("network endpoints or native network libraries observed")
    return Observation(problems, endpoints, processes, root_present)


def _run_powershell(auth: Any, script: str, timeout: float) -> tuple[int, str, str]:
    _require_any_authorization(auth)
    done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=timeout)
    return done.returncode, done.stdout, done.stderr


def observe_process(auth: Any, identity: ProcessIdentity, *,
                    runner: Optional[Callable[[str, float], tuple[int, str, str]]] = None
                    ) -> Observation:
    """One OS-level look at the child.  Incomplete network evidence: a
    connection opened and closed between looks, or name resolution done by
    the DNS Client service, is not seen."""
    _require_any_authorization(auth)
    run = runner or (lambda script, timeout: _run_powershell(auth, script, timeout))
    try:
        code, out, err = run(observation_script(identity.pid), OBSERVE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return Observation(["observation timed out"], [], [], False)
    except OSError as exc:
        return Observation([f"observation could not run: {type(exc).__name__}"], [], [], False)
    return parse_observation(code, out, err, identity)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class OrchestratorDeps:
    """What the orchestrator needs, always given explicitly; tests pass fakes.
    launch(command, stdout, stderr) returns a process with pid,
    creation_time, poll() and returncode."""
    launch: Callable[[ChildCommand, Any, Any], Any]
    observe: Callable[[ProcessIdentity], Observation]
    clock: Callable[[], float]
    pause: Callable[[float], None]
    now: Callable[[], float]
    interpreter: str
    expected_head: str
    python_paths: tuple[str, ...] = ()


def production_orchestrator_deps(auth: Any) -> OrchestratorDeps:
    """The real dependencies of an authorized series."""
    auth = _require_authorization(auth)
    return OrchestratorDeps(
        launch=AppContainerLauncher(auth, Win32AppContainerApi(auth)),
        observe=lambda identity: observe_process(auth, identity),
        clock=time.monotonic, pause=time.sleep, now=time.time,
        interpreter=base_interpreter(), expected_head=auth.expected_head,
        python_paths=venv_paths())


@dataclass
class SeriesOutcome:
    completed: int = 0
    stopped_reason: Optional[str] = None
    ownership_released: bool = False
    runs: list[dict[str, Any]] = field(default_factory=list)


def _wait_for_child(handle: Any, identity: ProcessIdentity, deps: OrchestratorDeps,
                    entry: dict[str, Any]) -> Optional[str]:
    """Poll and observe until the child exits.  A stop reason, or None."""
    cid = entry["calibration_id"]
    began = last_sample = deps.clock()
    while handle.poll() is None:
        if deps.clock() - began > CHILD_TIMEOUT_SECONDS:
            entry["child_left_running"] = True
            return (f"{cid}: no exit within {CHILD_TIMEOUT_SECONDS:.0f} s; PID {identity.pid} "
                    f"created {identity.creation_time} was not terminated")
        try:
            seen = deps.observe(identity)
        except Exception as exc:  # an observation that cannot run is a failure
            seen = Observation([f"observation raised {type(exc).__name__}"], [], [], False)
        sampled = deps.clock()
        entry["samples"] += 1
        entry["observations"].extend(seen.endpoints + seen.problems)
        if seen.endpoints:
            entry["child_left_running"] = handle.poll() is None
            return f"{cid}: OS-level observation saw network endpoints or libraries"
        if seen.problems or not seen.root_present:
            if handle.poll() is not None:
                entry["observations"].append("the last observation overlapped the child's exit")
                break
            entry["child_left_running"] = True
            reason = (seen.problems or ["the child's process identity is missing"])[0]
            return f"{cid}: observation failed closed: {reason}"
        if sampled - last_sample > MAX_SAMPLE_GAP_SECONDS:
            entry["child_left_running"] = True
            return (f"{cid}: insufficient sampling ({sampled - last_sample:.1f} s between "
                    "observations)")
        last_sample = sampled
        deps.pause(OBSERVE_INTERVAL_SECONDS)
    if entry["samples"] < MIN_SAMPLES:
        return f"{cid}: insufficient sampling (no observation while the child ran)"
    return None


def _read_result_problems(output_dir: Path, number: int, exit_status: Optional[int]
                          ) -> list[str]:
    path = result_path(output_dir, number)
    if not path.exists():
        return ["no result file"]
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"the result is unreadable: {type(exc).__name__}"]
    return result_problems(record, number, exit_status)


def _state_fields() -> dict[str, Any]:
    """Process evidence of a journal entry before anything was launched."""
    return {"process_created": False, "execution_history": None, "liveness": None,
            "handles_retained": False, "cleanup_errors": []}


def _record_launch_failure(entry: dict[str, Any], exc: BaseException) -> None:
    """A launch failure keeps whatever process evidence it carries."""
    evidence = getattr(exc, "evidence", None)
    if isinstance(evidence, Mapping):
        entry.update(evidence)


def _record_process_state(entry: dict[str, Any], handle: Any) -> None:
    """A returned process was resumed, so it may have executed; its liveness
    is confirmed only by an observed exit."""
    entry["process_created"] = True
    entry["execution_history"] = getattr(handle, "execution_history", MAY_HAVE_EXECUTED)
    entry["liveness"] = CONFIRMED_EXITED if handle.returncode is not None \
        else ALIVE_AT_LAST_CHECK
    entry["handles_retained"] = handle.returncode is None
    entry["cleanup_errors"] = list(getattr(handle, "cleanup_errors", []))


def _run_one(number: int, output_dir: Path, token: str, deps: OrchestratorDeps,
             outcome: SeriesOutcome) -> Optional[str]:
    """Launch, watch and validate one child.  A stop reason, or None."""
    command = build_child_command(number, output_dir, series_token=token,
                                  expected_head=deps.expected_head,
                                  interpreter=deps.interpreter,
                                  python_paths=deps.python_paths)
    cid = command.calibration_id
    entry: dict[str, Any] = {
        "calibration_id": cid, "argv_fingerprint": command.argv_fingerprint,
        "environment_names": command.environment_names, "pid": None, "creation_time": None,
        "exit_status": None, "samples": 0, "observations": [], "result_problems": None,
        "child_left_running": False, **_state_fields(),
    }
    outcome.runs.append(entry)
    _exclusive_json(_journal_path(output_dir, "launch", number), {
        "calibration_id": cid, "argv_fingerprint": command.argv_fingerprint,
        "environment_names": command.environment_names, "utc": _iso(deps.now())})
    command.temp_dir.mkdir(parents=True, exist_ok=False)
    reason: Optional[str] = None
    handle = None
    with open(command.stdout_path, "xb") as stdout, open(command.stderr_path, "xb") as stderr:
        try:
            handle = deps.launch(command, stdout, stderr)
        except Exception as exc:
            reason = f"{cid}: launch failed: {type(exc).__name__}: {exc}"[:500]
            _record_launch_failure(entry, exc)
        if handle is not None:
            identity = ProcessIdentity(int(handle.pid), str(handle.creation_time))
            entry["pid"], entry["creation_time"] = identity.pid, identity.creation_time
            _exclusive_json(_journal_path(output_dir, "process", number), {
                "calibration_id": cid, "pid": identity.pid,
                "creation_time": identity.creation_time,
                "argv_fingerprint": command.argv_fingerprint,
                "environment_names": command.environment_names, "utc": _iso(deps.now())})
            try:
                reason = _wait_for_child(handle, identity, deps, entry)
            finally:
                _record_process_state(entry, handle)
    if handle is not None and reason is None:
        entry["exit_status"] = handle.returncode
        entry["result_problems"] = _read_result_problems(output_dir, number, handle.returncode)
        if entry["result_problems"]:
            reason = f"{cid}: result rejected: {entry['result_problems'][0]}"
    _exclusive_json(_journal_path(output_dir, "complete", number),
                    {**entry, "stop_reason": reason, "utc": _iso(deps.now())})
    return reason


def run_series(runs: int, output_dir: Path, deps: OrchestratorDeps) -> SeriesOutcome:
    """
    The series, one child at a time, under ACTIVE_CALIBRATION.  Stops at
    the first run that is not clean (launch failure, timeout, observation
    failure, network evidence, non-zero exit, invalid result, the series
    budget, an interruption); never retries and never launches after a
    stop.  A series record is written in every case.  Ownership is released
    only when every run completed and validated.
    """
    if not isinstance(deps, OrchestratorDeps):
        raise TypeError("run_series needs explicit OrchestratorDeps")
    if isinstance(runs, bool) or not isinstance(runs, int) or not 1 <= runs <= MAX_RUNS:
        raise CalibrationError(f"runs must be 1-{MAX_RUNS}")
    output_dir = check_output_dir(output_dir)
    ids = [calibration_id(n) for n in range(1, runs + 1)]
    for number in range(1, runs + 1):
        for existing in (result_path(output_dir, number),
                         _journal_path(output_dir, "launch", number)):
            if existing.exists():
                raise CalibrationError(f"{existing.name} exists; calibration runs are never "
                                       "repeated")
    owner, token = claim_series(output_dir, calibration_ids=ids,
                                expected_head=deps.expected_head, now=deps.now)
    outcome = SeriesOutcome()
    series_start = deps.clock()
    try:
        for number in range(1, runs + 1):
            if deps.clock() - series_start > SERIES_BUDGET_SECONDS:
                outcome.stopped_reason = "series budget reached"
                break
            reason = _run_one(number, output_dir, token, deps, outcome)
            if reason is not None:
                outcome.stopped_reason = reason
                break
            outcome.completed += 1
            if number < runs:
                deps.pause(REST_SECONDS)
    except Exception as exc:
        outcome.stopped_reason = f"series failed: {type(exc).__name__}: {exc}"[:500]
    except BaseException as exc:
        outcome.stopped_reason = f"series interrupted: {type(exc).__name__}"
        raise
    finally:
        clean = outcome.stopped_reason is None and outcome.completed == runs
        _exclusive_json(output_dir / f"series-{CONDITION}-{int(deps.now())}.json", {
            "condition": CONDITION, "runs_requested": runs, "completed": outcome.completed,
            "stopped_reason": outcome.stopped_reason, "runs": outcome.runs,
            "ownership": "released" if clean else "retained for review",
            "note": "OS observation is periodic and cannot prove that no short-lived native "
                    "connection or name resolution happened",
        })
        if clean:
            owner.unlink()
            outcome.ownership_released = True
    return outcome


# ---------------------------------------------------------------------------
# Isolation probe (never imports or runs the workload driver)
# ---------------------------------------------------------------------------

class _ForbiddenImports(importlib.abc.MetaPathFinder):
    """Refuses (and records) any import of the workload driver."""

    def __init__(self) -> None:
        self.attempts: list[str] = []

    def find_spec(self, name: str, path: Any = None, target: Any = None) -> Any:
        if any(name == m or name.startswith(m + ".") for m in PROBE_FORBIDDEN_MODULES):
            self.attempts.append(name)
            raise ImportError(f"{name} is never imported by the isolation probe")
        return None


@dataclass
class ProbeChildDeps:
    """What a probe child needs, always given explicitly; tests pass fakes."""
    token_info: Callable[[], Mapping[str, Any]]
    connect: Callable[[int], None]
    resolve: Callable[[str], Any]
    import_module: Callable[[str], Any]
    identity: Callable[[], tuple[int, str]]
    wall: Callable[[], float]
    guard_factory: Callable[[], NetworkGuard] = NetworkGuard


#: Windows Sockets error codes of a loopback connection attempt.
WSAEACCES, WSAENETUNREACH, WSAETIMEDOUT, WSAECONNREFUSED, WSAEHOSTUNREACH = (
    10013, 10051, 10060, 10061, 10065)
PROBE_SCOPE_NOTE = ("only the denial of a loopback connection to the orchestrator's local "
                    "test listener is tested; denial of external (non-loopback) network "
                    "access is NOT tested")


def classify_loopback_attempt(exc: Optional[BaseException]) -> dict[str, Any]:
    """The probe's loopback evidence.  Only an access-denied result
    (WSAEACCES, 10013) counts as denial; refusal, timeout, unreachable and
    anything else are inconclusive, and a connection is a failure."""
    if exc is None:
        return {"outcome": "connected", "denied": False, "inconclusive": False,
                "error": None, "errno": None, "winerror": None}
    winerror = getattr(exc, "winerror", None)
    error_number = getattr(exc, "errno", None)
    if isinstance(exc, OSError) and winerror == WSAEACCES:
        outcome = "access_denied"
    elif isinstance(exc, ConnectionRefusedError) or winerror == WSAECONNREFUSED:
        outcome = "refused"
    elif isinstance(exc, TimeoutError) or winerror == WSAETIMEDOUT:
        outcome = "timeout"
    elif winerror in (WSAENETUNREACH, WSAEHOSTUNREACH) or error_number in (
            getattr(errno_module, "ENETUNREACH", None), getattr(errno_module, "EHOSTUNREACH", None)):
        outcome = "unreachable"
    else:
        outcome = "other"
    return {"outcome": outcome, "denied": outcome == "access_denied",
            "inconclusive": outcome != "access_denied", "error": type(exc).__name__,
            "errno": error_number, "winerror": winerror}


def _loopback_connect(auth: Any, port: int) -> None:
    """The one connection attempt of the probe: to the orchestrator's own
    test listener on 127.0.0.1.  Inside the AppContainer it must be refused
    with access denied."""
    _require_probe_authorization(auth)
    import socket
    with socket.create_connection(("127.0.0.1", int(port)),
                                  timeout=PROBE_CONNECT_TIMEOUT_SECONDS):
        pass


def _resolve(auth: Any, name: str) -> Any:
    _require_probe_authorization(auth)
    if name != PROBE_DNS_NAME:
        raise CalibrationError("the probe resolves only localhost")
    import socket
    return socket.getaddrinfo(name, None)


def production_probe_child_deps(auth: Any) -> ProbeChildDeps:
    """The real dependencies of an authorized probe child."""
    auth = _require_probe_authorization(auth)
    win32 = CtypesWin32(auth)
    return ProbeChildDeps(token_info=win32.current_token_info,
                          connect=lambda port: _loopback_connect(auth, port),
                          resolve=lambda name: _resolve(auth, name),
                          import_module=importlib.import_module,
                          identity=lambda: (os.getpid(), sys.executable), wall=time.time)


def probe_result_path(output_dir: Path, probe_id: str) -> Path:
    return Path(output_dir) / f"{probe_id}.json"


def probe_child_main(probe_id: str, output_dir: Path, deps: ProbeChildDeps, *,
                     series_token: str, port: int) -> int:
    """
    The probe inside the AppContainer: ownership -> own token -> loopback
    attempt (must be refused with access denied) -> localhost lookup
    (supplementary) -> the dependency imports under the network guard.  The
    workload driver is refused at import.  Every outcome is written to the
    probe's result.
    """
    if not isinstance(deps, ProbeChildDeps):
        raise TypeError("probe_child_main needs explicit ProbeChildDeps")
    if not isinstance(probe_id, str) or not PROBE_ID_RE.fullmatch(probe_id):
        raise CalibrationError("a probe id is probe-01 .. probe-05")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise CalibrationError("the probe listener port must be 1024-65535")
    output_dir = check_output_dir(output_dir)
    path = probe_result_path(output_dir, probe_id)
    if path.exists():
        raise CalibrationError(f"{path} exists; a probe is never repeated")
    _check_owner(output_dir, probe_id, series_token, PROBE_OWNER_FILE)
    forbidden = _ForbiddenImports()
    sys.meta_path.insert(0, forbidden)
    guard: Optional[NetworkGuard] = None
    pid, executable = deps.identity()
    record: dict[str, Any] = {
        "probe_id": probe_id,
        "kind": "AppContainer isolation probe; the workload driver is never imported",
        "scope": PROBE_SCOPE_NOTE,
        "started_utc": _iso(deps.wall()), "python": platform.python_version(),
        "executable": executable, "pid": pid, "os": _os_description(), "port": port,
        "status": "failed", "token": None, "token_problems": None, "loopback": None,
        "dns": None, "imports": {}, "network_guard_violations": [],
        "dns_note": "supplementary evidence only; a failed lookup does not prove isolation",
    }
    status = EXIT_PROBE_FAILED
    try:
        token = dict(deps.token_info())
        record["token"] = token
        record["token_problems"] = validate_app_container_token(
            token, AUTHORIZED_APPCONTAINER_SID, check_loopback=False)
        try:
            deps.connect(port)
            record["loopback"] = classify_loopback_attempt(None)
        except OSError as exc:
            record["loopback"] = classify_loopback_attempt(exc)
        try:
            deps.resolve(PROBE_DNS_NAME)
            record["dns"] = {"name": PROBE_DNS_NAME, "resolved": True}
        except OSError as exc:
            record["dns"] = {"name": PROBE_DNS_NAME, "resolved": False,
                             "error": type(exc).__name__}
        guard = deps.guard_factory().install()
        for name in PROBE_IMPORTS:
            try:
                deps.import_module(name)
                record["imports"][name] = "ok"
            except Exception as exc:
                record["imports"][name] = f"{type(exc).__name__}: {exc}"[:300]
        passed = (record["token_problems"] == []
                  and record["loopback"]["outcome"] == "access_denied"
                  and all(v == "ok" for v in record["imports"].values())
                  and not guard.violations and not forbidden.attempts)
        record["status"] = "passed" if passed else "failed"
        status = EXIT_OK if passed else EXIT_PROBE_FAILED
    except Exception as exc:  # recorded as evidence; never retried
        record["status"] = "failed"
        record["failure"] = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        if guard is not None:
            record["network_guard_violations"] = list(guard.violations)
            record["stubbed_native_imports"] = sorted(set(guard.stubbed_imports))
            guard.uninstall()
        if forbidden in sys.meta_path:
            sys.meta_path.remove(forbidden)
        record["forbidden_import_attempts"] = list(forbidden.attempts)
        record["driver_loaded"] = any(m in sys.modules for m in PROBE_FORBIDDEN_MODULES)
        if record["network_guard_violations"]:
            record["status"], status = "network_violation", EXIT_NETWORK
        elif record["driver_loaded"] or forbidden.attempts:
            record["status"], status = "failed", EXIT_PROBE_FAILED
        record["finished_utc"] = _iso(deps.wall())
        record["child_exit_status"] = status
        _exclusive_json(path, record)
    return status


def probe_result_problems(record: Any, probe_id: str, exit_status: Optional[int], *,
                          expected_pid: Any, expected_executable: Any,
                          expected_sid: Any, expected_port: Any) -> list[str]:
    """Why a probe result is not a pass for exactly the launched, validated
    process; empty when it is."""
    if not isinstance(record, Mapping):
        return ["the probe result is not a JSON object"]
    problems: list[str] = []
    for key, value in (("probe_id", probe_id), ("status", "passed"),
                       ("child_exit_status", EXIT_OK)):
        if record.get(key) != value:
            problems.append(f"{key} is {record.get(key)!r}, expected {value!r}")
    if exit_status != EXIT_OK or record.get("child_exit_status") != exit_status:
        problems.append(f"actual probe exit status {exit_status!r} is not a recorded pass")
    if record.get("token_problems") != []:
        problems.append("the probe's own token did not validate")
    loopback = record.get("loopback")
    if not isinstance(loopback, Mapping) or loopback.get("outcome") != "access_denied" \
            or loopback.get("winerror") != WSAEACCES:
        outcome = loopback.get("outcome") if isinstance(loopback, Mapping) else None
        problems.append(f"the loopback attempt was not denied with WSAEACCES "
                        f"(outcome {outcome!r})")
    imports = record.get("imports")
    if not isinstance(imports, Mapping) or set(imports) != set(PROBE_IMPORTS) \
            or any(v != "ok" for v in imports.values()):
        problems.append("the dependency imports did not all succeed")
    if record.get("network_guard_violations") != []:
        problems.append("network guard violations are recorded or missing")
    if record.get("forbidden_import_attempts") != [] or record.get("driver_loaded") is not False:
        problems.append("the workload driver was imported or attempted")
    if expected_pid is None or record.get("pid") != expected_pid:
        problems.append("the probe result was written by another process (PID differs)")
    if not expected_executable or _norm_image(record.get("executable")) != \
            _norm_image(expected_executable):
        problems.append("the probe result names another executable")
    token = record.get("token")
    if not expected_sid or not isinstance(token, Mapping) or \
            token.get("app_container_sid") != expected_sid:
        problems.append("the probe's own token is not the validated AppContainer SID")
    if record.get("port") != expected_port:
        problems.append("the probe attempted another port")
    return problems


class LoopbackListener:
    """The probe's dedicated, harmless test listener: 127.0.0.1, an
    ephemeral port, never reads data; connections are only counted.
    control() is the positive control from outside the AppContainer."""

    def __init__(self, auth: Any) -> None:
        self._auth = _require_probe_authorization(auth)
        import socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._socket.bind(("127.0.0.1", 0))
            self._socket.listen(4)
            self._socket.setblocking(False)
        except BaseException:
            self._socket.close()
            raise
        self.port: int = self._socket.getsockname()[1]

    def control(self) -> None:
        """One connection from the orchestrator itself; it must succeed."""
        _require_probe_authorization(self._auth)
        import socket
        with socket.create_connection(("127.0.0.1", self.port),
                                      timeout=PROBE_CONNECT_TIMEOUT_SECONDS):
            pass

    def connections(self) -> int:
        count = 0
        while True:
            try:
                connection, _ = self._socket.accept()
            except (BlockingIOError, InterruptedError):
                return count
            connection.close()
            count += 1

    def close(self) -> None:
        self._socket.close()


@dataclass
class ProbeDeps:
    """What the probe orchestrator needs, always given explicitly."""
    launch: Callable[[ChildCommand, Any, Any], Any]
    observe: Callable[[ProcessIdentity], Observation]
    listener: Callable[[], Any]
    clock: Callable[[], float]
    pause: Callable[[float], None]
    now: Callable[[], float]
    interpreter: str
    expected_head: str
    python_paths: tuple[str, ...] = ()


def production_probe_deps(auth: Any) -> ProbeDeps:
    """The real dependencies of an authorized probe."""
    auth = _require_probe_authorization(auth)
    return ProbeDeps(
        launch=AppContainerLauncher(auth, Win32AppContainerApi(auth)),
        observe=lambda identity: observe_process(auth, identity),
        listener=lambda: LoopbackListener(auth),
        clock=time.monotonic, pause=time.sleep, now=time.time,
        interpreter=base_interpreter(), expected_head=auth.expected_head,
        python_paths=venv_paths())


@dataclass
class ProbeOutcome:
    passed: bool = False
    stopped_reason: Optional[str] = None
    ownership_released: bool = False
    entry: dict[str, Any] = field(default_factory=dict)


def _read_probe_problems(output_dir: Path, probe_id: str, exit_status: Optional[int],
                         **expected: Any) -> list[str]:
    path = probe_result_path(output_dir, probe_id)
    if not path.exists():
        return ["no probe result file"]
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"the probe result is unreadable: {type(exc).__name__}"]
    return probe_result_problems(record, probe_id, exit_status, **expected)


def _control(listener: Any, entry: dict[str, Any], key: str) -> Optional[str]:
    """Positive control: the orchestrator's own connection must arrive."""
    try:
        listener.control()
        entry[key] = listener.connections()
    except Exception as exc:
        entry[key] = None
        return f"the listener control connection failed ({type(exc).__name__})"
    if entry[key] != 1:
        return f"the listener counted {entry[key]} control connections, not 1"
    return None


def run_probe(probe_id: str, output_dir: Path, deps: ProbeDeps) -> ProbeOutcome:
    """
    One isolation probe under ACTIVE_PROBE: listener -> positive control
    (1 connection) -> launch in the AppContainer -> observe until exit ->
    the listener must have received 0 connections from the child -> second
    positive control (1 connection) -> the probe result must be a pass for
    exactly the launched process.  Never retried; a record is written in
    every case; ownership is released only after a pass.
    """
    if not isinstance(deps, ProbeDeps):
        raise TypeError("run_probe needs explicit ProbeDeps")
    if not isinstance(probe_id, str) or not PROBE_ID_RE.fullmatch(probe_id):
        raise CalibrationError("a probe id is probe-01 .. probe-05")
    output_dir = check_output_dir(output_dir)
    for existing in (probe_result_path(output_dir, probe_id),
                     _journal_path(output_dir, "launch", probe_id)):
        if existing.exists():
            raise CalibrationError(f"{existing.name} exists; a probe is never repeated")
    owner, token = claim_series(output_dir, calibration_ids=[probe_id],
                                expected_head=deps.expected_head, now=deps.now,
                                owner_file=PROBE_OWNER_FILE)
    outcome = ProbeOutcome()
    entry: dict[str, Any] = {
        "calibration_id": probe_id, "argv_fingerprint": None, "environment_names": None,
        "pid": None, "creation_time": None, "exit_status": None, "samples": 0,
        "observations": [], "child_left_running": False, "listener_port": None,
        "listener_control_before": None, "listener_child_connections": None,
        "listener_control_after": None, "result_problems": None, **_state_fields(),
    }
    outcome.entry = entry
    listener = None
    reason: Optional[str] = None
    try:
        listener = deps.listener()
        entry["listener_port"] = listener.port
        reason = _control(listener, entry, "listener_control_before")
        if reason is not None:
            reason = f"{probe_id}: listener not verified before launch: {reason}"
            return outcome
        command = build_probe_command(probe_id, output_dir, series_token=token,
                                      expected_head=deps.expected_head,
                                      interpreter=deps.interpreter, port=listener.port,
                                      python_paths=deps.python_paths)
        entry["argv_fingerprint"] = command.argv_fingerprint
        entry["environment_names"] = command.environment_names
        _exclusive_json(_journal_path(output_dir, "launch", probe_id), {
            "probe_id": probe_id, "argv_fingerprint": command.argv_fingerprint,
            "environment_names": command.environment_names, "utc": _iso(deps.now())})
        command.temp_dir.mkdir(parents=True, exist_ok=False)
        handle = None
        with open(command.stdout_path, "xb") as stdout, \
                open(command.stderr_path, "xb") as stderr:
            try:
                handle = deps.launch(command, stdout, stderr)
            except Exception as exc:
                reason = f"{probe_id}: launch failed: {type(exc).__name__}: {exc}"[:500]
                _record_launch_failure(entry, exc)
            if handle is not None:
                identity = ProcessIdentity(int(handle.pid), str(handle.creation_time))
                entry["pid"], entry["creation_time"] = identity.pid, identity.creation_time
                _exclusive_json(_journal_path(output_dir, "process", probe_id), {
                    "probe_id": probe_id, "pid": identity.pid,
                    "creation_time": identity.creation_time,
                    "argv_fingerprint": command.argv_fingerprint, "utc": _iso(deps.now())})
                try:
                    reason = _wait_for_child(handle, identity, deps, entry)
                finally:
                    _record_process_state(entry, handle)
        if handle is not None and reason is None:
            entry["exit_status"] = handle.returncode
            entry["listener_child_connections"] = listener.connections()
            if entry["listener_child_connections"]:
                reason = f"{probe_id}: the test listener was reached: loopback is NOT denied"
        if handle is not None and reason is None:
            control = _control(listener, entry, "listener_control_after")
            if control is not None:
                reason = f"{probe_id}: listener not verified after the child: {control}"
        if handle is not None and reason is None:
            entry["result_problems"] = _read_probe_problems(
                output_dir, probe_id, handle.returncode, expected_pid=identity.pid,
                expected_executable=deps.interpreter, expected_sid=AUTHORIZED_APPCONTAINER_SID,
                expected_port=listener.port)
            if entry["result_problems"]:
                reason = f"{probe_id}: probe failed: {entry['result_problems'][0]}"
    except Exception as exc:
        reason = f"probe failed: {type(exc).__name__}: {exc}"[:500]
    except BaseException as exc:
        reason = f"probe interrupted: {type(exc).__name__}"
        raise
    finally:
        if listener is not None:
            try:
                if entry["listener_child_connections"] is None and \
                        entry["listener_control_before"] == 1:
                    entry["listener_child_connections"] = listener.connections()
            except Exception as exc:
                entry["observations"].append(f"listener check failed: {type(exc).__name__}")
            finally:
                listener.close()
        outcome.stopped_reason = reason
        outcome.passed = reason is None
        _exclusive_json(_journal_path(output_dir, "complete", probe_id),
                        {**entry, "stop_reason": reason, "utc": _iso(deps.now())})
        _exclusive_json(output_dir / f"probe-record-{probe_id}-{int(deps.now())}.json", {
            "probe_id": probe_id, "passed": outcome.passed, "stopped_reason": reason,
            "run": entry, "ownership": "released" if outcome.passed else "retained for review",
            "scope": PROBE_SCOPE_NOTE,
            "note": "a pass shows that this loopback attempt was refused with access denied "
                    "while the listener was demonstrably reachable from outside, and that "
                    "this run's observations were clean; it is not a proof of complete "
                    "isolation, and the localhost lookup is supplementary evidence only",
        })
        if outcome.passed:
            owner.unlink()
            outcome.ownership_released = True
    return outcome


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None, *, stdout: Any = None) -> int:
    out = sys.stdout if stdout is None else stdout
    parser = argparse.ArgumentParser(prog="calibrate_generator",
                                     description="Generator-only start-lag calibration "
                                                 "(condition A). Without --execute it plans.")
    parser.add_argument("--runs", type=int, default=MAX_RUNS)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorize", action="append", default=[], metavar="CAL_ID")
    parser.add_argument("--expect-head", default=None)
    parser.add_argument("--probe", default=None, metavar="PROBE_ID",
                        help="run one AppContainer isolation probe (separately gated)")
    parser.add_argument("--child", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--probe-child", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--token", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    probing = args.probe is not None or args.probe_child is not None
    try:
        output_dir = check_output_dir(Path(args.output_dir or (
            DEFAULT_PROBE_OUTPUT if probing else DEFAULT_OUTPUT)))
        if not 1 <= args.runs <= MAX_RUNS:
            raise CalibrationError(f"--runs must be 1-{MAX_RUNS}")
    except CalibrationError as exc:
        parser.error(str(exc))
    if args.probe_child is not None:
        try:
            auth = authorize_probe(args.probe_child, args.expect_head)
            return probe_child_main(args.probe_child, output_dir,
                                    production_probe_child_deps(auth),
                                    series_token=args.token, port=args.port)
        except CalibrationError as exc:
            sys.stderr.write(f"calibrate_generator: error: {exc}\n")
            return 2
    if args.probe is not None:
        try:
            auth = authorize_probe(args.probe, args.expect_head)
            probe = run_probe(args.probe, output_dir, production_probe_deps(auth))
        except CalibrationError as exc:
            sys.stderr.write(f"calibrate_generator: error: {exc}\n")
            return 2
        out.write(f"probe {args.probe}: {'passed' if probe.passed else 'FAILED'}; "
                  f"stopped: {probe.stopped_reason}\n")
        return 0 if probe.passed else 1
    if args.child is not None:
        try:
            auth = authorize([calibration_id(args.child)], args.expect_head)
            deps = production_child_deps(auth, args.child)
            return child_main(args.child, output_dir, deps, series_token=args.token)
        except CalibrationError as exc:
            sys.stderr.write(f"calibrate_generator: error: {exc}\n")
            return 2
    if not args.execute:
        out.write("PLAN ONLY - nothing was started.\n")
        out.write(f"output: {output_dir}\n")
        for number in range(1, args.runs + 1):
            warm, measured = run_ids(number)
            out.write(f"{calibration_id(number)}: warm-up {warm} ({WARMUP_REQUESTS}), measured "
                      f"{measured} ({MEASURED_REQUESTS}) at {RATE:g}/s, concurrency "
                      f"{CONCURRENCY}, seed {SEED}, in-memory exporter\n")
        return 0
    try:
        auth = authorize(args.authorize, args.expect_head)
        if list(auth.calibration_ids) != [calibration_id(n) for n in range(1, args.runs + 1)]:
            raise ExecutionDisabled("--authorize must name exactly the calibration ids of "
                                    "--runs, in order")
        outcome = run_series(args.runs, output_dir, production_orchestrator_deps(auth))
    except CalibrationError as exc:
        sys.stderr.write(f"calibrate_generator: error: {exc}\n")
        return 2
    out.write(f"completed {outcome.completed}/{args.runs}; stopped: {outcome.stopped_reason}\n")
    return 0 if outcome.stopped_reason is None else 1


if __name__ == "__main__":
    sys.exit(main())

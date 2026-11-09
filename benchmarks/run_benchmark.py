"""
benchmarks/run_benchmark.py

Pipeline benchmark of the AgentOps observability stack on the separate,
disposable stack of workload-generator/run_smoke.py:

    REAL workload -> OTLP -> collector -> Kafka raw -> stream processor
        -> Kafka canonical -> storage consumer -> PostgreSQL
        (-> analytics refresh -> anomaly detector, small levels only)

One CELL is one (level, rate, concurrency, repetition) on a fresh stack:

    warm-up run (own run id, excluded)  ->  drain
    measured run (own run id)           ->  drain, settle, reconcile
    clock-skew check before and after the measured run
    lag and container-resource samples while it runs
    -> one JSON result, validated by metrics.validate_result

Every number is labelled MEASURED, DERIVED, OBSERVATION or NOT_MEASURED (see
metrics.py); a missing number is NOT_MEASURED with its reason, never 0.  A
result's verdict decides what it may later be used for; this program writes
no claim.

Modes
-----
Without --live it only PLANS: it validates the ladder, prints the cells, run
ids, durations and where results would go, and touches nothing.

    python benchmarks/run_benchmark.py --level SMOKE

With --live it runs cells for real.  Live execution is DISABLED in this
version (LIVE_ENABLED is False): --live is refused before anything starts.
A reviewed step turns it on.

Results go outside the repository (default: <temp>/agentops-benchmarks).

Importing this module starts nothing: no process, socket, file write or
container.  The D3 harness (run_smoke.py) is imported only inside the live
functions.

Standard library only (plus metrics.py beside it).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

HERE: Path = Path(__file__).resolve().parent
REPO: Path = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import metrics as M  # noqa: E402

#: Live execution is not reachable in this version.  Changing it is a
#: reviewed step of its own.
LIVE_ENABLED: bool = True


# ---------------------------------------------------------------------------
# Keeping a Windows laptop awake during a live run (B3J-267)
# ---------------------------------------------------------------------------
# A live cell takes minutes.  B3J-264 (rep7) was interrupted when Windows entered Modern Standby
# in the middle of the measured run, which froze the generator, the consumer and the samplers
# and made the numbers describe the host, not the pipeline.  Before a repetition is claimed the
# live path now asks Windows, for this thread, to stay awake.  This is a REQUEST of the calling
# thread, not a power setting: nothing is changed, and it ends with the thread.  It does not
# change the stop rules, the verdicts, the evidence schemas or the single-use ledger.

ES_CONTINUOUS: int = 0x80000000
ES_SYSTEM_REQUIRED: int = 0x00000001
ES_DISPLAY_REQUIRED: int = 0x00000002
KEEP_AWAKE_FLAGS: int = ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
#: NtPowerInformation level that returns the aggregate system execution state.
SYSTEM_EXECUTION_STATE_LEVEL: int = 16


def _is_windows() -> bool:
    return os.name == "nt"


def _windows_set_execution_state(flags: int) -> int:
    """SetThreadExecutionState for the CALLING thread.  Returns the previous state, or 0 on
    failure (the documented contract).  Windows only; replaced by fakes in the tests."""
    import ctypes
    function = ctypes.WinDLL("kernel32").SetThreadExecutionState
    function.argtypes = [ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    return int(function(flags))


def _windows_read_execution_state() -> Optional[int]:
    """The AGGREGATE system execution state (every requester together), read without
    elevation, or None when it cannot be read.  Supporting evidence only: it cannot say whose
    request it is."""
    import ctypes
    function = ctypes.WinDLL("powrprof").CallNtPowerInformation
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    function.restype = ctypes.c_long
    state = ctypes.c_uint32(0)
    status = function(SYSTEM_EXECUTION_STATE_LEVEL, None, 0, ctypes.byref(state), 4)
    return int(state.value) if status == 0 else None


class KeepAwake:
    """Asks Windows not to sleep or turn the display off while a live cell runs.

    acquire() must be called on the thread that stays alive for the whole run (the main
    thread of the benchmark process) and release() on that same thread: the request belongs
    to the calling thread, is not inherited by child processes (none needs it, the request is
    system-wide), and Windows drops it if the thread or process ends, even by a forced kill.

    acquisition: 'not_applicable' (not Windows), 'acquired' or 'failed'.
    readback:    'skipped', 'consistent' (the aggregate state shows both bits), 'inconsistent'
                 (readable but the bits are missing) or 'unavailable'.  The aggregate state
                 cannot attribute a request to this guard, so 'consistent' supports, but does
                 not prove, ownership; the API's non-zero return value is what counts as
                 acquisition."""

    def __init__(self, *, is_windows: Optional[Callable[[], bool]] = None,
                 set_state: Optional[Callable[[int], int]] = None,
                 read_state: Optional[Callable[[], Optional[int]]] = None,
                 thread_id: Callable[[], int] = threading.get_ident,
                 report: Optional[Callable[[str], None]] = None) -> None:
        # Resolved when the guard is built, so a test can replace the module functions.
        self._is_windows = is_windows or _is_windows
        self._set_state = set_state or _windows_set_execution_state
        self._read_state = read_state or _windows_read_execution_state
        self._thread_id = thread_id
        self._report = report or (lambda text: sys.stderr.write(f"run_benchmark: warning: {text}\n"))
        self.acquisition: str = "not_applicable"
        self.readback: str = "skipped"
        self.owner: Optional[int] = None
        self.held: bool = False

    def acquire(self) -> None:
        """Raises BenchmarkError (nothing is held) when the request cannot be made."""
        if self.held:
            raise BenchmarkError("the keep-awake request is already held")
        if not self._is_windows():
            self.acquisition, self.readback = "not_applicable", "skipped"
            return
        try:
            previous = self._set_state(KEEP_AWAKE_FLAGS)
        except Exception as exc:  # noqa: BLE001 - any failure is a refusal
            self.acquisition = "failed"
            raise BenchmarkError(f"Windows could not be asked to stay awake "
                                 f"({type(exc).__name__})") from None
        if isinstance(previous, bool) or not isinstance(previous, int) or previous == 0:
            self.acquisition = "failed"
            raise BenchmarkError("Windows refused the request to stay awake "
                                 "(SetThreadExecutionState returned 0)")
        self.acquisition, self.held, self.owner = "acquired", True, self._thread_id()
        try:
            state = self._read_state()
        except Exception:  # noqa: BLE001
            state = None
        if state is None:
            self.readback = "unavailable"
        elif state & (ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED) == (ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED):
            self.readback = "consistent"
        else:
            # Readable, and contradicts the call that just succeeded: do not run on it.
            self.readback = "inconsistent"
            self.release()
            raise BenchmarkError("the system execution state does not show the keep-awake request "
                                 f"(0x{state:X}); nothing was started")

    def release(self) -> bool:
        """True when nothing is held any more.  Never raises; a problem is reported and does
        not change a verdict.  Refuses to release from a thread other than the owner."""
        if not self.held:
            return True
        if self._thread_id() != self.owner:
            self._report("the keep-awake request belongs to another thread and was NOT released "
                         "from this one; it ends when its thread ends")
            return False
        try:
            result = self._set_state(ES_CONTINUOUS)
        except Exception as exc:  # noqa: BLE001
            self._report(f"the keep-awake request could not be released ({type(exc).__name__}); "
                         "it ends with this process")
            return False
        if isinstance(result, bool) or not isinstance(result, int) or result == 0:
            self._report("the keep-awake request release was refused by Windows; it ends with this process")
            return False
        self.held = False
        return True

    def describe(self) -> str:
        if self.acquisition == "not_applicable":
            return "not applicable (not Windows)"
        return f"{self.acquisition} (system and display required); read-back {self.readback}"

# ---------------------------------------------------------------------------
# Host-interruption diagnostics (B3J-275)
# ---------------------------------------------------------------------------
# B3J-264 (rep7) was interrupted by a Windows Modern Standby transition that left no trace in the
# result except indirect clues.  A new result now carries an optional `host` block: the keep-awake
# status, the session lock state and local idle time at the start and at the end, and the
# Kernel-Power standby events (ids 506 entry, 507 exit) that Windows logged inside the cell's own
# wall-clock window.  It is information only: it never changes the verdict, a threshold, the
# ledger or the cleanup, and a failed query is reported as a failed query, never as "no events".

HOST_EVENT_IDS: tuple[int, ...] = M.HOST_POWER_EVENT_IDS
HOST_MAX_EVENTS: int = M.HOST_MAX_EVENTS
HOST_ERROR_LIMIT: int = M.HOST_ERROR_LIMIT
HOST_QUERY_TIMEOUT_SECONDS: float = 30.0
HOST_OUTPUT_LIMIT: int = 64 * 1024

#: Built-in PowerShell Get-WinEvent, which reads the System log without elevation.  "No events"
#: is a successful answer (Get-WinEvent reports it as an error id, handled here); any other error
#: fails the query.
_POWER_QUERY_SCRIPT: str = "\n".join([
    "$ErrorActionPreference = 'Stop'",
    "$s = [DateTimeOffset]::Parse('__START__').LocalDateTime",
    "$e = [DateTimeOffset]::Parse('__END__').LocalDateTime",
    "try {",
    "  $ev = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; "
    "Id=506,507; StartTime=$s; EndTime=$e} -MaxEvents __MAX__)",
    "} catch {",
    "  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $ev = @() } else { throw }",
    "}",
    "$out = @($ev | Sort-Object TimeCreated | ForEach-Object {",
    "  $x = [xml]$_.ToXml()",
    "  $r = $x.Event.EventData.Data | Where-Object { $_.Name -eq 'Reason' } | Select-Object -First 1",
    "  [pscustomobject]@{ t = $_.TimeCreated.ToUniversalTime().ToString('o'); id = [int]$_.Id; r = $r.'#text' } })",
    "ConvertTo-Json -Compress -InputObject @{ ok = $true; events = $out }",
])


def _windows_session_flags() -> Optional[int]:
    """SessionFlags of the current session: 0 = locked, 1 = unlocked, None when unreadable.  It is the
    field at byte offset 16 of WTSINFOEXW (class 25): the level union is 8-byte aligned, so offset 8 is
    SessionId and offset 12 SessionState (which does NOT change when the session is locked)."""
    import ctypes
    import struct
    from ctypes import wintypes
    wts = ctypes.WinDLL("wtsapi32")
    wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    buffer, size = ctypes.c_void_p(), wintypes.DWORD()
    if not wts.WTSQuerySessionInformationW(None, 0xFFFFFFFF, 25, ctypes.byref(buffer), ctypes.byref(size)):
        return None
    try:
        if size.value < 20:
            return None
        raw_bytes = ctypes.string_at(buffer, 20)
        level = struct.unpack_from("<I", raw_bytes, 0)[0]
        flags = struct.unpack_from("<i", raw_bytes, 16)[0]
        return flags if level == 1 and flags in (0, 1) else None
    finally:
        wts.WTSFreeMemory(buffer)


def _windows_idle_seconds() -> Optional[float]:
    """Seconds since the last keyboard or mouse input in this session, or None."""
    import ctypes
    from ctypes import wintypes

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    if not ctypes.WinDLL("user32").GetLastInputInfo(ctypes.byref(info)):
        return None
    ticks = ctypes.WinDLL("kernel32").GetTickCount()
    return round(((ticks - info.dwTime) & 0xFFFFFFFF) / 1000.0, 1)


def _run_event_query(script: str, timeout: float) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, stdin=subprocess.DEVNULL)


def _host_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _host_dt(text: str) -> datetime:
    """A UTC time from the query's ISO-8601 text (7 fractional digits are cut to 6)."""
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?Z", text or "")
    if match is None:
        raise ValueError("a time is not UTC ISO-8601")
    fraction = (match.group(2) or "0")[:6].ljust(6, "0")
    return datetime.strptime(f"{match.group(1)}.{fraction}", "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def _host_iso_dt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _bounded_error(text: str) -> str:
    cleaned = " ".join(str(text).split())
    return (cleaned or "unspecified")[:HOST_ERROR_LIMIT]


def parse_power_events(stdout: str, window_start: datetime, window_end: datetime) -> tuple[list[dict[str, Any]], bool]:
    """(events, truncated) from the query's JSON.  Raises ValueError for anything malformed.  Events
    outside [window_start, window_end] (both included) are dropped; the rest are sorted by time and
    cut to HOST_MAX_EVENTS, with `truncated` set when something was cut."""
    lines = [line for line in (stdout or "").splitlines() if line.strip()]
    if not lines:
        raise ValueError("no output")
    try:
        data = json.loads(lines[-1])
    except ValueError:
        raise ValueError("the output is not JSON") from None
    if not isinstance(data, Mapping) or data.get("ok") is not True or "events" not in data:
        raise ValueError("the output lacks ok and events")
    raw_events = data["events"]
    if isinstance(raw_events, Mapping):
        raw_events = [raw_events]
    if not isinstance(raw_events, list):
        raise ValueError("events is not a list")
    found: list[dict[str, Any]] = []
    for item in raw_events:
        if not isinstance(item, Mapping):
            raise ValueError("an event is not an object")
        identifier = item.get("id")
        if isinstance(identifier, bool) or identifier not in HOST_EVENT_IDS:
            raise ValueError("an event has an unexpected id")
        moment = _host_dt(item.get("t"))
        reason = item.get("r")
        if isinstance(reason, str) and reason.strip().isdigit():
            reason = int(reason.strip())
        if isinstance(reason, bool) or not isinstance(reason, int):
            reason = None
        if window_start <= moment <= window_end:
            found.append({"_t": moment, "time_utc": _host_iso_dt(moment), "id": int(identifier), "reason": reason})
    found.sort(key=lambda event: event["_t"])
    truncated = len(found) > HOST_MAX_EVENTS or len(raw_events) > HOST_MAX_EVENTS
    return [{k: v for k, v in event.items() if k != "_t"} for event in found[:HOST_MAX_EVENTS]], truncated


def pair_standby_episodes(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Entries (506) and exits (507) in time order.  An entry never closed (or closed by another entry)
    and an exit without an entry in the window are kept as incomplete episodes: both still count as a
    possible interruption."""
    episodes: list[dict[str, Any]] = []
    open_entry: Optional[str] = None
    for event in events:
        if event["id"] == 506:
            if open_entry is not None:
                episodes.append({"entered_utc": open_entry, "exited_utc": None, "seconds": None})
            open_entry = event["time_utc"]
        else:
            if open_entry is None:
                episodes.append({"entered_utc": None, "exited_utc": event["time_utc"], "seconds": None})
            else:
                seconds = (_host_dt(event["time_utc"]) - _host_dt(open_entry)).total_seconds()
                episodes.append({"entered_utc": open_entry, "exited_utc": event["time_utc"],
                                 "seconds": round(max(seconds, 0.0), 3)})
                open_entry = None
    if open_entry is not None:
        episodes.append({"entered_utc": open_entry, "exited_utc": None, "seconds": None})
    return episodes[:HOST_MAX_EVENTS]


def _failed_query(error: str, seconds: Optional[float]) -> dict[str, Any]:
    return {"status": "failed", "error": _bounded_error(error), "query_seconds": seconds,
            "truncated": False, "events": [], "episodes": []}


def query_power_events(start_epoch: float, end_epoch: float, *,
                       run: Optional[Callable[[str, float], Any]] = None,
                       timeout: float = HOST_QUERY_TIMEOUT_SECONDS,
                       monotonic: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    """The `power_events` block: Kernel-Power 506/507 events logged in [start, end].  Never raises.
    A query that does not complete is 'failed' with a short error; it is never an empty success."""
    run = run or _run_event_query
    end_epoch = max(end_epoch, start_epoch)
    window_start = _host_dt(_host_iso(start_epoch))
    window_end = _host_dt(_host_iso(end_epoch))
    script = (_POWER_QUERY_SCRIPT.replace("__START__", _host_iso(start_epoch))
              .replace("__END__", _host_iso(end_epoch)).replace("__MAX__", str(HOST_MAX_EVENTS + 1)))
    began = monotonic()
    try:
        completed = run(script, timeout)
    except subprocess.TimeoutExpired:
        return _failed_query("timeout", round(monotonic() - began, 3))
    except FileNotFoundError:
        return _failed_query("tool_missing", round(monotonic() - began, 3))
    except Exception as exc:  # noqa: BLE001 - any other failure is a failed query
        return _failed_query(f"unexpected:{type(exc).__name__}", round(monotonic() - began, 3))
    seconds = round(monotonic() - began, 3)
    try:
        code = completed.returncode
        out, err = completed.stdout or "", completed.stderr or ""
        if code != 0:
            return _failed_query(f"nonzero_exit:{code}: {err}", seconds)
        if len(out) > HOST_OUTPUT_LIMIT:
            return _failed_query("output_too_large", seconds)
        events, truncated = parse_power_events(out, window_start, window_end)
        return {"status": "ok", "error": None, "query_seconds": seconds, "truncated": truncated,
                "events": events, "episodes": pair_standby_episodes(events)}
    except ValueError as exc:
        return _failed_query(f"malformed_output: {exc}", seconds)
    except Exception as exc:  # noqa: BLE001
        return _failed_query(f"unexpected:{type(exc).__name__}", seconds)


def session_state(*, read_flags: Optional[Callable[[], Optional[int]]] = None,
                  read_idle: Optional[Callable[[], Optional[float]]] = None) -> dict[str, Any]:
    """Lock state (from SessionFlags: 0 = locked, 1 = unlocked) and local idle seconds.  Never raises;
    what cannot be read is None."""
    read_flags, read_idle = read_flags or _windows_session_flags, read_idle or _windows_idle_seconds
    try:
        flags = read_flags()
    except Exception:  # noqa: BLE001
        flags = None
    if isinstance(flags, bool) or flags not in (0, 1):
        flags = None
    try:
        idle = read_idle()
    except Exception:  # noqa: BLE001
        idle = None
    if isinstance(idle, bool) or not isinstance(idle, (int, float)) or idle != idle or idle < 0 or idle == float("inf"):
        idle = None
    return {"flags": flags, "locked": None if flags is None else flags == 0,
            "idle_seconds": None if idle is None else float(idle)}


def collect_host_evidence(*, started: float, finished: float, keep_awake: Optional[Mapping[str, Any]],
                          session_start: Optional[Mapping[str, Any]],
                          is_windows: Optional[Callable[[], bool]] = None,
                          query: Optional[Callable[..., dict[str, Any]]] = None) -> Optional[dict[str, Any]]:
    """The `host` block, or None off Windows (the result is then exactly what it was).  Never raises."""
    if not (is_windows or _is_windows)():
        return None
    end = max(finished, started)
    keep = dict(keep_awake or {})
    acquisition = keep.get("acquisition") if keep.get("acquisition") in M.HOST_KEEP_AWAKE_ACQUISITION else "unknown"
    readback = keep.get("readback") if keep.get("readback") in M.HOST_KEEP_AWAKE_READBACK else "unknown"
    try:
        session_end: Optional[dict[str, Any]] = session_state()
    except Exception:  # noqa: BLE001
        session_end = None
    try:
        power = (query or query_power_events)(started, end)
    except Exception as exc:  # noqa: BLE001
        power = _failed_query(f"unexpected:{type(exc).__name__}", None)
    if power.get("status") == "ok":
        suspected: Optional[bool] = bool(power.get("events"))
    else:
        suspected = None
    return {"platform": "windows", "keep_awake": {"acquisition": acquisition, "readback": readback},
            "session": {"start": dict(session_start) if session_start is not None else None, "end": session_end},
            "window": {"start_utc": _host_iso(started), "end_utc": _host_iso(end)},
            "power_events": power, "host_interruption_suspected": suspected}


def host_limitations(host: Optional[Mapping[str, Any]]) -> list[str]:
    """Factual sentences for the result's limitations; never changes a verdict."""
    if not host:
        return []
    power = host["power_events"]
    window = host["window"]
    if power["status"] != "ok":
        return [f"host power events could not be queried ({power['error']}); a Windows standby during this "
                "run cannot be excluded"]
    if not power["events"]:
        return []
    entries = sum(1 for event in power["events"] if event["id"] == 506)
    exits = sum(1 for event in power["events"] if event["id"] == 507)
    return [f"host interruption suspected: Windows logged {entries} Modern Standby entr"
            f"{'y' if entries == 1 else 'ies'} and {exits} exit{'' if exits == 1 else 's'} (Kernel-Power 506/507) "
            f"between {window['start_utc']} and {window['end_utc']} UTC; timing, throughput and lag in this "
            "result are not clean platform capacity evidence"]


DEFAULT_CONFIG: Path = HERE / "ladder.json"
DEFAULT_OUTPUT: Path = Path(tempfile.gettempdir()) / "agentops-benchmarks"
RUN_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,38}[a-z0-9]")
SERVICE_NAME: str = "agentops-demo-app"
ROOT_SPAN: str = "agentops.request"


class BenchmarkError(Exception):
    """The benchmark cannot go on.  The message is the evidence."""


class LiveDisabled(BenchmarkError):
    """Live execution was requested where it is not enabled."""


# ---------------------------------------------------------------------------
# Configuration and cells
# ---------------------------------------------------------------------------

#: SHA-256 of the approved ladder file's bytes (benchmarks/ladder.json).  A live run
#: accepts a configuration only when the bytes it read hash to exactly this, whatever
#: the file is called or where it is; a different valid configuration can still be
#: planned.  Changing the ladder is a reviewed step that changes this value with it.
APPROVED_LADDER_SHA256: str = "571138bb0c10e15547345aca5f15422742ffb03d998e88127c2d7aadc8b2c71f"


def read_ladder(path: Path) -> tuple[dict[str, Any], str]:
    """Read the ladder's bytes once; return the validated ladder (targets only) parsed
    from those same bytes, and the SHA-256 of those bytes."""
    try:
        raw = Path(path).read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"cannot read the ladder {path}: {exc}") from None
    try:
        M.check_ladder(data)
    except M.MetricError as exc:
        raise BenchmarkError(f"the ladder is not valid: {exc}") from None
    return data, hashlib.sha256(raw).hexdigest()


def load_ladder(path: Path) -> dict[str, Any]:
    """Read and validate the ladder (targets only)."""
    return read_ladder(path)[0]


@dataclass(frozen=True)
class Cell:
    level: str
    rate: int
    concurrency: int
    repetition: int
    requests: int
    seed: int
    warmup_requests: int
    live_allowed: bool
    refresh_and_detector: bool

    @property
    def measured_seconds(self) -> float:
        return self.requests / self.rate

    @property
    def planned_spans(self) -> int:
        return self.requests * M.SPANS_PER_HEALTHY_REQUEST

    @property
    def stem(self) -> str:
        return f"{self.level.lower()}-r{self.rate:04d}-c{self.concurrency:02d}"

    @property
    def benchmark_id(self) -> str:
        return f"bm-{self.stem}-rep{self.repetition}"

    @property
    def warmup_run_id(self) -> str:
        return f"b-{self.stem}-w{self.repetition}"

    @property
    def measured_run_id(self) -> str:
        return f"b-{self.stem}-m{self.repetition}"

    def target(self) -> dict[str, Any]:
        """What the cell is meant to do.  Never what it achieved."""
        return {
            "level": self.level, "scenario": "normal", "seed": self.seed,
            "requests": self.requests, "planned_spans": self.planned_spans,
            "rate_per_second": self.rate, "concurrency": self.concurrency,
            "measured_seconds": self.measured_seconds,
            "warmup_requests": self.warmup_requests, "repetition": self.repetition,
            "warmup_run_id": self.warmup_run_id, "measured_run_id": self.measured_run_id,
        }


#: The only cells live execution may run (Phase 14.4B3H; rep4 and rep5 added
#: in B3J-48d; the first exploratory SMALL cell added in B3J-54).  rep1 has run
#: and is not here; rep2 and rep3 have run too, and their ledger records keep
#: them from running again.  Every field must match, the repetition must be
#: selected with --repetition, the warm-up given explicitly, and --authorize
#: must name the cell.
_SMOKE_REPEAT: Mapping[str, Any] = {"level": "SMOKE", "requests": 100, "rate": 5,
                                    "concurrency": 32, "warmup_requests": 25}
#: The SMALL-10 cells: 1,000 requests at 10/s, warm-up 300 (the ladder's
#: rate x warmup_seconds).  rep1 to rep3 have run; rep4 is the one further
#: repeat approved, to collect the ingest-gap diagnostics.  The other SMALL
#: rates and repetitions stay unapproved.
_SMALL10_FIRST: Mapping[str, Any] = {"level": "SMALL", "requests": 1000, "rate": 10,
                                     "concurrency": 32, "warmup_requests": 300}
APPROVED_LIVE_CELLS: Mapping[str, Mapping[str, Any]] = {
    "bm-smoke-r0005-c32-rep2": {**_SMOKE_REPEAT, "repetition": 2},
    "bm-smoke-r0005-c32-rep3": {**_SMOKE_REPEAT, "repetition": 3},
    "bm-smoke-r0005-c32-rep4": {**_SMOKE_REPEAT, "repetition": 4},
    "bm-smoke-r0005-c32-rep5": {**_SMOKE_REPEAT, "repetition": 5},
    "bm-small-r0010-c32-rep1": {**_SMALL10_FIRST, "repetition": 1},
    "bm-small-r0010-c32-rep2": {**_SMALL10_FIRST, "repetition": 2},
    "bm-small-r0010-c32-rep3": {**_SMALL10_FIRST, "repetition": 3},
    "bm-small-r0010-c32-rep4": {**_SMALL10_FIRST, "repetition": 4},
    # rep5 is a timing diagnostic (B3J-122).  Its one attempt (B3J-219) ended INVALID before any
    # load because the harness still expected a 17-step ledger; its claim and evidence are
    # permanent, so it cannot run again.  rep6 is the separately approved replacement diagnostic.
    "bm-small-r0010-c32-rep5": {**_SMALL10_FIRST, "repetition": 5},   # diagnostic (B3J-122)
    "bm-small-r0010-c32-rep6": {**_SMALL10_FIRST, "repetition": 6},   # diagnostic (B3J-223)
    # rep7 is the N=100 commit batching diagnostic (B3J-260): the same workload as rep6, with the
    # storage consumer committing offsets every 100 messages or 1.0 s.  Single use, like the rest.
    "bm-small-r0010-c32-rep7": {**_SMALL10_FIRST, "repetition": 7},   # diagnostic, N=100 (B3J-260)
    # rep7 was claimed (B3J-264) and ended GENERATOR_BOUND after a Windows Modern Standby; it cannot run
    # again.  rep8 (B3J-277) is the same N=100 diagnostic, run with the keep-awake guard (B3J-267/268)
    # and the host-interruption diagnostics (B3J-276).  Single use, like the rest.
    "bm-small-r0010-c32-rep8": {**_SMALL10_FIRST, "repetition": 8},   # diagnostic, N=100 (B3J-277)
    # rep8 was claimed (B3J-280) and ended VALID; it cannot run again.  rep9 (B3J-291) is the same N=100
    # diagnostic with the host-resource observations (B3J-284) and the Docker resource-stop and coverage
    # rules (B3J-289).  Single use, like the rest.
    "bm-small-r0010-c32-rep9": {**_SMALL10_FIRST, "repetition": 9},   # diagnostic, N=100 (B3J-291)
}
MAX_WARMUP_REQUESTS: int = 10000
_SHA_RE = re.compile(r"[0-9a-f]{40}")

#: What every approved live cell runs with besides its own id, rate, concurrency, request
#: and warm-up counts: the effective values the ladder supplies.  They repeat the
#: approved ladder on purpose: a second, independent check that a live run uses exactly
#: these, whatever the configuration it was handed.  Nothing here is a new threshold.
APPROVED_EFFECTIVE: Mapping[str, Any] = {
    "scenario": "normal", "seed": 42, "live_allowed": True, "refresh_and_detector": True,
    "drain_limit_seconds": 120, "settle_seconds": 6, "cell_budget_seconds": 3600,
    "sample_interval_seconds": 10,
    "stop_limits": {
        "memory_fraction": 0.90, "disk_free_min_gb": 10, "disk_projection_factor": 2.0,
        "cpu_saturation_percent": 99.5, "cpu_saturation_seconds": 60,
        "lag_growth_samples": 6, "generator_rate_fraction": 0.95,
        "late_start_fraction": 0.05, "skew_uncertainty_ms": 10, "skew_drift_ms": 5},
}


#: The cells approved to run with the storage consumer timing enabled, and the one interval
#: approved for each.  This literal is deliberately independent of DIAGNOSTIC_TIMING_CELLS
#: and DIAGNOSTIC_TIMING_INTERVAL_SECONDS: a live run is refused unless they agree with it,
#: so neither can be changed alone.  Every other cell runs with timing off (0.0).
APPROVED_DIAGNOSTIC_INTERVALS: Mapping[str, float] = {"bm-small-r0010-c32-rep5": 5.0,
                                                      "bm-small-r0010-c32-rep6": 5.0,
                                                      "bm-small-r0010-c32-rep7": 5.0,
                                                      "bm-small-r0010-c32-rep8": 5.0,
                                                      "bm-small-r0010-c32-rep9": 5.0}


#: Opt-in batched Kafka offset commits of the storage consumer (B3J-257).  A cell appears here
#: only in a separately authorized, reviewed change, together with its entries in
#: APPROVED_LIVE_CELLS and COMMIT_BATCHING_CELLS.  Only rep7 (B3J-260), rep8 (B3J-277) and rep9 (B3J-291) are listed; every other cell
#: runs with one commit per message (N=1), which adds no variable to the consumer's environment.
#: This literal is deliberately independent of COMMIT_BATCHING_CELLS and the two constants below:
#: a live run is refused unless they agree with it, so none of them can be changed alone.
APPROVED_COMMIT_BATCHING: Mapping[str, tuple[int, float]] = {"bm-small-r0010-c32-rep7": (100, 1.0),
                                                             "bm-small-r0010-c32-rep8": (100, 1.0),
                                                             "bm-small-r0010-c32-rep9": (100, 1.0)}
COMMIT_BATCHING_CELLS: frozenset[str] = frozenset({"bm-small-r0010-c32-rep7", "bm-small-r0010-c32-rep8",
                                                   "bm-small-r0010-c32-rep9"})
COMMIT_BATCH_MESSAGES: int = 100
COMMIT_INTERVAL_SECONDS: float = 1.0
#: What a cell that is not approved for batching runs with: one commit per message, no interval.
DEFAULT_COMMIT_BATCHING: tuple[int, Optional[float]] = (1, None)


def commit_batching_for(benchmark_id: str) -> tuple[int, Optional[float]]:
    """(messages per commit, interval seconds) a cell would run with: the batching constants for
    a cell in COMMIT_BATCHING_CELLS, else (1, None).  The only place it is derived."""
    if benchmark_id in COMMIT_BATCHING_CELLS:
        return COMMIT_BATCH_MESSAGES, COMMIT_INTERVAL_SECONDS
    return DEFAULT_COMMIT_BATCHING


def timing_interval_for(benchmark_id: str) -> float:
    """The consumer timing interval a cell would run with: the diagnostic interval for a
    cell in DIAGNOSTIC_TIMING_CELLS, else 0.0 (off).  The only place it is derived."""
    return DIAGNOSTIC_TIMING_INTERVAL_SECONDS if benchmark_id in DIAGNOSTIC_TIMING_CELLS else 0.0


#: Diagnostic cells whose throughput and latency must not be read against earlier repetitions
#: unless the Docker engine had the same allocation.  The reference is the allocation the
#: earlier repetitions of THIS cell's series recorded (SMALL-10 reps 1-4: 22 CPUs, 8,168,574,976
#: bytes); it is not a universal baseline and applies to no other cell.
COMPARABILITY_REFERENCES: Mapping[str, Mapping[str, Any]] = {
    "bm-small-r0010-c32-rep5": {"against": "SMALL-10 repetitions 1-4",
                                "NCPU": 22, "MemTotal": 8_168_574_976},
    "bm-small-r0010-c32-rep6": {"against": "SMALL-10 repetitions 1-4",
                                "NCPU": 22, "MemTotal": 8_168_574_976},
    "bm-small-r0010-c32-rep7": {"against": "SMALL-10 repetitions 1-4",
                                "NCPU": 22, "MemTotal": 8_168_574_976},
    "bm-small-r0010-c32-rep8": {"against": "SMALL-10 repetitions 1-4",
                                "NCPU": 22, "MemTotal": 8_168_574_976},
    "bm-small-r0010-c32-rep9": {"against": "SMALL-10 repetitions 1-4",
                                "NCPU": 22, "MemTotal": 8_168_574_976},
}

#: A fact a cell's result must carry about the cells that came before it.  Added to the result's
#: limitations; it never changes a verdict.  The text is exact and applies to the one cell named.
CELL_LIMITATIONS: Mapping[str, str] = {
    "bm-small-r0010-c32-rep7": (
        "SMALL-10 repetition 6 used single-message commits on the same nominal 4-CPU configuration "
        "and ended STOPPED; it is diagnostic context, not a validated performance baseline."),
    "bm-small-r0010-c32-rep8": (
        "SMALL-10 repetition 6 used single-message commits and ended STOPPED; repetition 7 used batched "
        "commits, was interrupted by a Windows Modern Standby transition mid-run and ended GENERATOR_BOUND; "
        "neither is a validated performance baseline."),
    "bm-small-r0010-c32-rep9": (
        "SMALL-10 repetition 9 uses the same workload, rate, concurrency, warm-up and offset-commit batching "
        "(100 messages or 1.0 s, consumer timing every 5 s) as repetition 8, which ended VALID under its "
        "original rules and is not reclassified. Repetition 9 differs in instrumentation and rules: it also "
        "records host-side resource observations (storage consumer and stream processor CPU and working set, "
        "host available memory, whole-host CPU and free disk space), it judges Docker container CPU and memory "
        "as aggregates per sampling tick against the recorded Docker NCPU and MemTotal, and inadequate "
        "resource-sampling coverage makes a run INVALID, which repetition 8 did not require. Throughput and "
        "latency may be compared with repetition 8 only with these differences in mind. Repetition 6 ended "
        "STOPPED and repetition 7 ended GENERATOR_BOUND after a Windows Modern Standby transition; neither is a "
        "validated performance baseline."),
}


def _plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def comparability_limitation(benchmark_id: str, machine: Any) -> Optional[str]:
    """The limitation a diagnostic cell must carry, or None.  For a cell with a reference
    allocation: None when the Docker engine's CPU count and memory equal it; otherwise a text
    saying the numbers are not directly comparable; and when the allocation was not measured
    the text says that comparability could not be verified, so the note is never silently
    omitted.  Pure: it reads only its arguments and never changes a verdict."""
    reference = COMPARABILITY_REFERENCES.get(benchmark_id)
    if reference is None:
        return None
    docker = machine.get("docker") if isinstance(machine, Mapping) else None
    ncpu = docker.get("NCPU") if isinstance(docker, Mapping) else None
    memory = docker.get("MemTotal") if isinstance(docker, Mapping) else None
    against = reference["against"]
    if not (_plain_int(ncpu) and _plain_int(memory)):
        return (f"comparability: diagnostic only; the Docker CPU and memory allocation was not "
                f"measured, so comparability with {against} could not be verified; treat "
                "throughput and latency as not comparable")
    if (ncpu, memory) == (reference["NCPU"], reference["MemTotal"]):
        return None
    return (f"comparability: diagnostic only; throughput and latency are not directly comparable "
            f"with {against} because the Docker engine allocation differs (NCPU {ncpu} vs "
            f"{reference['NCPU']}, MemTotal {memory} vs {reference['MemTotal']} bytes)")


def effective_config(cell: Cell, ladder: Mapping[str, Any]) -> dict[str, Any]:
    """Every value a cell's run takes from the configuration, as it will be used."""
    defaults = ladder["defaults"]
    batch, commit_interval = commit_batching_for(cell.benchmark_id)
    return {
        "consumer_timing_interval_seconds": timing_interval_for(cell.benchmark_id),
        "consumer_commit_batch_messages": batch,
        "consumer_commit_interval_seconds": commit_interval,
        "scenario": defaults["scenario"], "seed": cell.seed, "live_allowed": cell.live_allowed,
        "refresh_and_detector": cell.refresh_and_detector,
        "drain_limit_seconds": defaults["drain_limit_seconds"],
        "settle_seconds": defaults["settle_seconds"],
        "cell_budget_seconds": defaults["cell_budget_seconds"],
        "sample_interval_seconds": defaults["sample_interval_seconds"],
        "stop_limits": dict(ladder["stop_limits"]), "target": cell.target(),
    }


def _commit_batching_problems(effective: Mapping[str, Any], benchmark_id: str) -> list[str]:
    """Names of the commit batching fields that are not exactly what this cell is approved for:
    (1, None) unless APPROVED_COMMIT_BATCHING lists the cell.  Types are exact."""
    batch = effective.get("consumer_commit_batch_messages")
    interval = effective.get("consumer_commit_interval_seconds")
    approved_batch, approved_interval = APPROVED_COMMIT_BATCHING.get(benchmark_id, DEFAULT_COMMIT_BATCHING)
    wrong = []
    if batch != approved_batch or type(batch) is not int:
        wrong.append("consumer_commit_batch_messages")
    if interval != approved_interval or type(interval) is not type(approved_interval):
        wrong.append("consumer_commit_interval_seconds")
    return wrong


def check_effective_config(cell: Cell, ladder: Mapping[str, Any]) -> dict[str, Any]:
    """The cell's effective configuration, or BenchmarkError naming what differs from the
    approved one.  Pure."""
    if frozenset(APPROVED_DIAGNOSTIC_INTERVALS) != DIAGNOSTIC_TIMING_CELLS \
            or not set(APPROVED_DIAGNOSTIC_INTERVALS) <= set(APPROVED_LIVE_CELLS) \
            or set(APPROVED_DIAGNOSTIC_INTERVALS.values()) != {DIAGNOSTIC_TIMING_INTERVAL_SECONDS}:
        raise BenchmarkError("the diagnostic timing configuration differs from the approved "
                             "one (cells or interval); nothing is run")
    if frozenset(APPROVED_COMMIT_BATCHING) != COMMIT_BATCHING_CELLS \
            or not set(APPROVED_COMMIT_BATCHING) <= set(APPROVED_LIVE_CELLS) \
            or any(value != (COMMIT_BATCH_MESSAGES, COMMIT_INTERVAL_SECONDS)
                   or type(value[0]) is not int or type(value[1]) is not float
                   for value in APPROVED_COMMIT_BATCHING.values()):
        raise BenchmarkError("the commit batching configuration differs from the approved "
                             "one (cells, size or interval); nothing is run")
    effective = effective_config(cell, ladder)
    wrong = [key for key, value in APPROVED_EFFECTIVE.items()
             if effective[key] != value or type(effective[key]) is not type(value)]
    if effective["target"]["scenario"] != APPROVED_EFFECTIVE["scenario"] \
            or effective["target"]["seed"] != APPROVED_EFFECTIVE["seed"]:
        wrong.append("target")
    approved_interval = float(APPROVED_DIAGNOSTIC_INTERVALS.get(cell.benchmark_id, 0.0))
    interval = effective["consumer_timing_interval_seconds"]
    if interval != approved_interval or type(interval) is not float:
        wrong.append("consumer_timing_interval_seconds")
    wrong += _commit_batching_problems(effective, cell.benchmark_id)
    if wrong:
        raise BenchmarkError("the effective configuration differs from the approved one in "
                             + ", ".join(
                                 f"consumer_timing_interval_seconds ({interval!r} != "
                                 f"{approved_interval!r})" if key == "consumer_timing_interval_seconds"
                                 else f"{key} ({effective[key]!r} != "
                                      f"{APPROVED_EFFECTIVE.get(key)!r})" if key in effective
                                 and key in APPROVED_EFFECTIVE else key
                                 for key in wrong))
    return effective


def check_live_output_dir(output_dir: Path) -> Path:
    """A live run writes its claim and results only to the one canonical directory, so
    that a cell's single use cannot be escaped by naming another directory."""
    given = Path(output_dir).resolve()
    canonical = Path(DEFAULT_OUTPUT).resolve()
    if os.path.normcase(str(given)) != os.path.normcase(str(canonical)):
        raise BenchmarkError(f"--live writes only to the canonical output directory "
                             f"{canonical}; {given} is not it")
    return given


def check_no_prior_evidence(output_dir: Path, cell: "Cell") -> None:
    """Read-only: nothing that would make the claim fail already exists.  claim_run
    decides again, exclusively; this only refuses early, before any state is created."""
    output_dir = Path(output_dir)
    found = [str(path.name) for path in (
        output_dir / OWNER_FILE,
        output_dir / LEDGER_DIR / f"{cell.benchmark_id}.started",
        output_dir / LEDGER_DIR / f"{cell.benchmark_id}.done") if path.exists()]
    found += sorted(path.name for path in output_dir.glob(f"{cell.benchmark_id}-*.json"))
    if found:
        raise BenchmarkError(f"existing records block {cell.benchmark_id}: {', '.join(found)}")


def read_git_state(repo: Path = None) -> dict[str, Any]:
    """HEAD, branch, working-tree lines and staged paths of the repository, with read-only
    git commands only (no optional index locks)."""
    repo = REPO if repo is None else repo

    def out(*args: str) -> str:
        try:
            result = subprocess.run(
                ["git", "--no-optional-locks", "-C", str(repo), *args], capture_output=True,
                text=True, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
                timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BenchmarkError(f"git {args[0]}: {type(exc).__name__}") from None
        if result.returncode != 0:
            raise BenchmarkError(f"git {args[0]}: exit {result.returncode}")
        return result.stdout

    return {"head": out("rev-parse", "HEAD").strip(),
            "branch": out("rev-parse", "--abbrev-ref", "HEAD").strip(),
            "status": [line for line in out("status", "--porcelain",
                                            "--untracked-files=all").splitlines() if line.strip()],
            "staged": [line for line in out("diff", "--cached", "--name-only").splitlines()
                       if line.strip()]}


def verify_repository_readonly(expect_head: str, *, read: Optional[Callable[[], Any]] = None
                               ) -> dict[str, str]:
    """Before any claim: HEAD is the expected commit, on a named branch, the working tree
    has no change and the index is empty.  Returns the verified head and branch."""
    state = (read_git_state if read is None else read)()
    if state["branch"] in ("", "HEAD"):
        raise BenchmarkError("the repository is on a detached HEAD, not a named branch")
    if state["head"] != expect_head:
        raise BenchmarkError(f"HEAD is {state['head']}, not the expected commit {expect_head}")
    if state["staged"]:
        raise BenchmarkError("the index is not empty")
    if state["status"]:
        raise BenchmarkError("the working tree is not clean: " + "; ".join(state["status"][:5]))
    return {"head": state["head"], "branch": state["branch"]}


#: The format of a claim record written with a binding.  Records without a "schema" key are
#: the historical format; they are never rewritten or re-validated.
MARKER_SCHEMA: int = 4
#: Older claim-record schemas that are still understood when such a record is read (they are
#: never rewritten).  Schema 3 has no commit batching fields in its effective_config.
LEGACY_MARKER_SCHEMAS: tuple[int, ...] = (3,)
_MARKER_KEYS = frozenset({
    "schema", "nonce", "benchmark_id", "git_head", "verified_head", "branch", "pid",
    "started_utc", "arguments", "ladder_sha256", "config_path", "output_dir",
    "effective_config"})


def validate_marker(record: Any, cell: "Cell", output_dir: Path) -> list[str]:
    """What is wrong with a schema-2 claim record, judged against the approved values and
    this cell (not against the record itself).  Empty when consistent.  This checks
    consistency; it is not a signature and does not resist someone able to write the
    ledger."""
    if not isinstance(record, Mapping):
        return ["the record is not an object"]
    problems = [f"missing field {key}" for key in sorted(_MARKER_KEYS - set(record))]
    problems += [f"unexpected field {key}" for key in sorted(set(record) - _MARKER_KEYS)]
    if problems:
        return problems
    if record["schema"] != MARKER_SCHEMA and record["schema"] not in LEGACY_MARKER_SCHEMAS:
        problems.append("unsupported schema")
    if record["benchmark_id"] != cell.benchmark_id:
        problems.append("benchmark_id is not the claimed cell")
    if not isinstance(record["nonce"], str) or not record["nonce"]:
        problems.append("nonce is missing")
    if not isinstance(record["verified_head"], str) or not _SHA_RE.fullmatch(record["verified_head"]):
        problems.append("verified_head is not a full commit")
    if record["git_head"] != record["verified_head"]:
        problems.append("git_head differs from verified_head")
    if not isinstance(record["branch"], str) or record["branch"] in ("", "HEAD"):
        problems.append("branch is not a named branch")
    if record["ladder_sha256"] != APPROVED_LADDER_SHA256:
        problems.append("ladder_sha256 is not the approved ladder")
    if record["output_dir"] != str(Path(output_dir).resolve()):
        problems.append("output_dir is not the directory holding the record")
    effective = record["effective_config"]
    fields = set(APPROVED_EFFECTIVE) | {"target", "consumer_timing_interval_seconds"}
    batching = record["schema"] == MARKER_SCHEMA            # schema 3 predates the batching fields
    if batching:
        fields |= {"consumer_commit_batch_messages", "consumer_commit_interval_seconds"}
    if not isinstance(effective, Mapping) or set(effective) != fields:
        problems.append("effective_config has the wrong fields")
    else:
        for key, value in APPROVED_EFFECTIVE.items():
            if effective[key] != value or type(effective[key]) is not type(value):
                problems.append(f"effective_config.{key} is not the approved value")
        approved_interval = float(APPROVED_DIAGNOSTIC_INTERVALS.get(cell.benchmark_id, 0.0))
        interval = effective["consumer_timing_interval_seconds"]
        if interval != approved_interval or type(interval) is not float:
            problems.append("effective_config.consumer_timing_interval_seconds is not the "
                            "approved value")
        if effective["target"] != cell.target():
            problems.append("effective_config.target is not this cell's workload")
        if batching:
            problems += [f"effective_config.{key} is not the approved value"
                         for key in _commit_batching_problems(effective, cell.benchmark_id)]
        elif cell.benchmark_id in COMMIT_BATCHING_CELLS:
            problems.append("a legacy-schema record cannot describe a cell with commit batching")
    return problems


def _cell_fields(cell: Cell) -> dict[str, Any]:
    return {"level": cell.level, "requests": cell.requests, "rate": cell.rate,
            "concurrency": cell.concurrency, "repetition": cell.repetition,
            "warmup_requests": cell.warmup_requests}


def is_approved_live_cell(cell: Cell) -> bool:
    approved = APPROVED_LIVE_CELLS.get(cell.benchmark_id)
    return approved is not None and _cell_fields(cell) == dict(approved)


def check_live_authorization(
    cells: Sequence[Cell], *, authorize: Optional[str], expect_head: Optional[str],
    warmup_requests: Optional[int], repetition: Optional[int],
) -> Cell:
    """
    The one cell live execution may run, or BenchmarkError.  Pure: it is
    decided before anything is imported or started.  The actual HEAD and a
    clean tree are checked by the harness's first step, before any
    infrastructure.
    """
    if authorize is None:
        raise BenchmarkError("--live needs --authorize <benchmark id>")
    if authorize not in APPROVED_LIVE_CELLS:
        raise BenchmarkError(f"--authorize {authorize!r} is not an approved live cell "
                             f"({', '.join(sorted(APPROVED_LIVE_CELLS))})")
    approved = APPROVED_LIVE_CELLS[authorize]
    if expect_head is None or not _SHA_RE.fullmatch(expect_head):
        raise BenchmarkError("--live needs --expect-head with a full 40-character commit")
    if repetition is None:
        raise BenchmarkError("--live needs --repetition N (one repetition per run)")
    if repetition != approved["repetition"]:
        raise BenchmarkError(f"--repetition {repetition} does not match {authorize}")
    if warmup_requests != approved["warmup_requests"]:
        raise BenchmarkError(f"--live needs --warmup-requests {approved['warmup_requests']}")
    if len(cells) != 1:
        raise BenchmarkError(f"--live runs exactly one cell; {len(cells)} are planned")
    cell = cells[0]
    if cell.benchmark_id != authorize:
        raise BenchmarkError(f"the planned cell {cell.benchmark_id} is not {authorize}")
    found = _cell_fields(cell)
    wrong = sorted(key for key, value in approved.items() if found[key] != value)
    if wrong:
        raise BenchmarkError("the planned cell differs from the approved one in "
                             + ", ".join(f"{k} ({found[k]} != {approved[k]})" for k in wrong))
    return cell


def plan_cells(
    ladder: Mapping[str, Any], level: str, *, rates: Optional[Sequence[int]] = None,
    repetitions: Optional[int] = None, concurrency: Optional[int] = None,
    warmup_requests: Optional[int] = None, repetition: Optional[int] = None,
) -> list[Cell]:
    """The cells of one level, in the order they would run: each rate in
    ascending order, its repetitions one after another.  warmup_requests
    replaces the ladder's rate x warmup_seconds when given; repetition
    selects that one repetition only (it excludes repetitions)."""
    if warmup_requests is not None and (
            isinstance(warmup_requests, bool) or not isinstance(warmup_requests, int)
            or not 1 <= warmup_requests <= MAX_WARMUP_REQUESTS):
        raise BenchmarkError(f"warm-up requests must be 1-{MAX_WARMUP_REQUESTS}")
    found = [lv for lv in ladder["levels"] if lv["name"] == level]
    if not found:
        raise BenchmarkError(f"unknown level {level!r}")
    spec, defaults = found[0], ladder["defaults"]
    chosen = list(spec["rates"] if rates is None else rates)
    unknown = [r for r in chosen if r not in spec["rates"]]
    if unknown:
        raise BenchmarkError(f"rates {unknown} are not in the ladder for {level}")
    if repetition is not None:
        if repetitions is not None:
            raise BenchmarkError("--repetition and --repetitions exclude each other")
        if isinstance(repetition, bool) or not isinstance(repetition, int) \
                or not 1 <= repetition <= 10:
            raise BenchmarkError("repetition must be 1-10")
        selected = [repetition]
    else:
        reps = defaults["repetitions"] if repetitions is None else repetitions
        if not 1 <= reps <= 10:
            raise BenchmarkError("repetitions must be 1-10")
        selected = list(range(1, reps + 1))
    conc = defaults["concurrency"] if concurrency is None else concurrency
    if not 1 <= conc <= 64:
        raise BenchmarkError("concurrency must be 1-64")
    cells = []
    for rate in sorted(chosen):
        for number in selected:
            cell = Cell(
                level=level, rate=rate, concurrency=conc, repetition=number,
                requests=spec["target_requests"], seed=defaults["seed"],
                warmup_requests=(max(1, int(rate * defaults["warmup_seconds"]))
                                 if warmup_requests is None else warmup_requests),
                live_allowed=spec["live_allowed"],
                refresh_and_detector=spec["refresh_and_detector"],
            )
            for run_id in (cell.warmup_run_id, cell.measured_run_id):
                if not RUN_ID_RE.fullmatch(run_id):
                    raise BenchmarkError(f"run id {run_id!r} is not valid for the generator")
            if not M.BENCHMARK_ID_RE.fullmatch(cell.benchmark_id):
                raise BenchmarkError(f"benchmark id {cell.benchmark_id!r} is not valid")
            cells.append(cell)
    return cells


# ---------------------------------------------------------------------------
# Parsers of tool output (pure)
# ---------------------------------------------------------------------------

_UNITS = {"B": 1, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4,
          "KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4}
_SIZE_RE = re.compile(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)\s*", re.IGNORECASE)


def parse_size(text: str) -> int:
    """'512MiB' / '1.5GiB' / '12kB' -> bytes."""
    match = _SIZE_RE.fullmatch(text)
    if match is None:
        raise BenchmarkError(f"not a size: {text!r}")
    return int(round(float(match.group(1)) * _UNITS[match.group(2).upper()]))


def parse_docker_stats(text: str) -> list[dict[str, Any]]:
    """
    Lines of `docker stats --no-stream --format
    "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"` -> one dict per container:
    name, cpu_percent, memory_used_bytes, memory_limit_bytes.
    """
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 3:
            raise BenchmarkError(f"unexpected docker stats line: {line!r}")
        name, cpu, memory = (p.strip() for p in parts)
        used, _, limit = memory.partition("/")
        rows.append({
            "name": name,
            "cpu_percent": float(cpu.rstrip("%")),
            "memory_used_bytes": parse_size(used),
            "memory_limit_bytes": parse_size(limit),
        })
    return rows


_DBT_FINISHED_RE = re.compile(
    r"Finished running .*? in (?:(\d+) hours?,?\s*)?(?:(\d+) minutes?\s*(?:and\s*)?)?"
    r"(\d+(?:\.\d+)?) seconds")


def parse_dbt_seconds(text: str) -> Optional[float]:
    """dbt's own 'Finished running ... in X seconds' as seconds, or None."""
    match = _DBT_FINISHED_RE.search(text)
    if match is None:
        return None
    hours, minutes, seconds = match.groups()
    return int(hours or 0) * 3600 + int(minutes or 0) * 60 + float(seconds)


_GROUP_RE = re.compile(r"\[(\w+) / ([^/\]]+?) / ([^\]]*)\]\s*$")
_DURATION_RE = re.compile(r"\sduration_ms\s*: ([0-9]+(?:\.[0-9]+)?)\s*$")


def parse_detector_durations(text: str) -> dict[str, float]:
    """'signal_path/operation' -> duration_ms, from the detector's log."""
    found: dict[str, float] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        header = _GROUP_RE.search(line)
        if header:
            current = f"{header.group(1)}/{header.group(3)}"
            continue
        duration = _DURATION_RE.search(line)
        if duration and current is not None:
            found[current] = float(duration.group(1))
            current = None
    return found


def clock_probe_code(samples: int) -> str:
    """
    Python run in the temporary environment, next to the database: each
    sample brackets one `SELECT clock_timestamp()` between two host clock
    readings, so a bracket is one local round trip wide.  Connection
    settings come from its environment (PG*), never from this program's
    arguments.
    """
    if not 1 <= samples <= 50:
        raise BenchmarkError("samples must be 1-50")
    return (
        "import json, os, time\n"
        "import psycopg\n"
        "out = []\n"
        "with psycopg.connect(host=os.environ['PGHOST'], port=os.environ['PGPORT'],"
        " dbname=os.environ['PGDATABASE'], user=os.environ['PGUSER'],"
        " password=os.environ['PGPASSWORD'], autocommit=True) as conn:\n"
        "    cur = conn.cursor()\n"
        "    cur.execute('SELECT 1')\n"
        f"    for _ in range({samples}):\n"
        "        before = time.time()\n"
        "        cur.execute('SELECT extract(epoch from clock_timestamp())::float8')\n"
        "        database = cur.fetchone()[0]\n"
        "        after = time.time()\n"
        "        out.append([before, database, after])\n"
        "print(json.dumps(out))\n"
    )


def parse_clock_samples(text: str) -> list[M.ClockSample]:
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"clock probe output is not JSON: {exc}") from None
    if not isinstance(rows, list) or not rows:
        raise BenchmarkError("clock probe returned no samples")
    try:
        return [M.ClockSample(*row) for row in rows]
    except (TypeError, M.MetricError) as exc:
        raise BenchmarkError(f"bad clock sample: {exc}") from None


# ---------------------------------------------------------------------------
# Machine baseline
# ---------------------------------------------------------------------------

def collect_machine_baseline(
    run: Callable[[Sequence[str]], str], *, platform_info: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Environment facts, no secrets.  run(command) returns a command's output;
    platform_info comes from the caller (OS, CPU, RAM, disk, Python).  A
    fact that cannot be read is recorded as NOT_MEASURED with the reason.
    """
    machine: dict[str, Any] = dict(platform_info)

    def fact(name: str, command: Sequence[str], parse: Callable[[str], Any]) -> None:
        try:
            machine[name] = parse(run(command))
        except Exception as exc:  # recorded, never invented
            machine[name] = {"kind": "NOT_MEASURED", "reason": f"{type(exc).__name__}: {exc}"}

    def docker_info(text: str) -> dict[str, Any]:
        info = json.loads(text)
        return {key: info.get(key) for key in (
            "ServerVersion", "OperatingSystem", "KernelVersion", "NCPU", "MemTotal",
            "Driver", "CgroupVersion")}

    fact("docker", ["docker", "info", "--format", "{{json .}}"], docker_info)
    fact("docker_compose", ["docker", "compose", "version", "--short"], str.strip)
    fact("images", ["docker", "images", "--no-trunc", "--format",
                    "{{.Repository}}:{{.Tag}} {{.ID}}"],
         lambda text: sorted(line for line in text.splitlines() if line.strip()))
    return machine


def local_platform_info() -> dict[str, Any]:
    """OS, CPU, memory, disk and Python facts of this machine (live only)."""
    import os
    import platform
    import shutil

    info: dict[str, Any] = {
        "os": platform.platform(), "machine": platform.machine(),
        "processor": platform.processor() or None, "logical_cpus": os.cpu_count(),
        "python": platform.python_version(),
    }
    usage = shutil.disk_usage(REPO.anchor or "/")
    info["disk_free_bytes"], info["disk_total_bytes"] = usage.free, usage.total
    if sys.platform == "win32":
        import ctypes

        class _Status(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = _Status()
        status.dwLength = ctypes.sizeof(_Status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            info["memory_total_bytes"] = status.ullTotalPhys
    return info


# ---------------------------------------------------------------------------
# Sampling while a run goes on
# ---------------------------------------------------------------------------

class PeriodicSampler:
    """
    Calls sample() every interval seconds on a background thread until
    stop(); keeps (seconds since start, value) pairs.  A sample that raises
    is kept as (time, None) with the error, never as 0.
    """

    def __init__(self, sample: Callable[[], Any], interval: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if interval <= 0:
            raise BenchmarkError("interval must be positive")
        self._sample, self._interval, self._clock = sample, interval, clock
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.samples: list[tuple[float, Any]] = []
        self.errors: list[tuple[float, str]] = []
        self._started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None      # seconds after the start, when stop() was first called

    @property
    def window(self) -> Optional[tuple[float, float]]:
        """The sampler's own observation window in its time base, (0, seconds until stop()), or None
        while it is running or was never started.  Sample times are on the same base."""
        return None if self.stopped_at is None else (0.0, self.stopped_at)

    def start(self) -> None:
        start = self._clock()
        self._started_at = start

        def loop() -> None:
            while not self._stop.is_set():
                at = self._clock() - start
                try:
                    self.samples.append((at, self._sample()))
                except Exception as exc:
                    self.samples.append((at, None))
                    self.errors.append((at, f"{type(exc).__name__}: {exc}"))
                self._stop.wait(self._interval)

        self._thread = threading.Thread(target=loop, name="benchmark-sampler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 30.0) -> None:
        if self._started_at is not None and self.stopped_at is None:
            self.stopped_at = max(0.0, self._clock() - self._started_at)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)


# ---------------------------------------------------------------------------
# Host resource sampling (B3J-283): what the benchmark's own host processes and the machine used
# ---------------------------------------------------------------------------
#
# The Docker sampler above sees only the containers.  The stream processor and the storage consumer
# run as host processes, so this sampler reads them through standard Windows calls (no admin right,
# no new dependency), together with the host's available memory, its CPU and the free disk space.
# It is OBSERVATION only: nothing here feeds a stop rule or the verdict, and a failure to sample is
# recorded, never turned into a number.

#: The only host processes ever sampled: the two this run started (by name in RUN.processes).
HOST_PROCESS_ROLES: tuple[str, ...] = ("stream-processor", "storage-consumer")
HOST_TREE_LIMIT = 16                 # processes visited below one root; a venv launcher has one child
HOST_ERROR_KINDS = 8                 # distinct error labels kept in the limitations
HOST_ERROR_LABEL_LIMIT = 60          # characters of one label
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000   # the only access right ever requested
STILL_ACTIVE = 259
FILETIME_TICKS_PER_SECOND = 10_000_000


def _host_error_label(source: str, exc: BaseException) -> str:
    """A short, bounded, secret-free label for a failed read: the source, the exception class and,
    for an OS error, its numeric code.  The message text is never kept."""
    code = getattr(exc, "winerror", None)
    suffix = f"({code})" if isinstance(code, int) and not isinstance(code, bool) else ""
    return f"{source}:{type(exc).__name__}{suffix}"[:HOST_ERROR_LABEL_LIMIT]


class WindowsHostResourceApi:
    """
    The Windows calls the sampler needs, and nothing else.  Every method raises OSError on failure.
    Constructing it loads kernel32 only; nothing is read until a method is called.  Tests never
    use this class: they pass a fake with the same methods.
    """

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes
        self._ctypes = ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._k32 = k32

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        class MEMORYCOUNTERS(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                        ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        self._FILETIME, self._MEMORYCOUNTERS = FILETIME, MEMORYCOUNTERS
        self._PROCESSENTRY32W, self._MEMORYSTATUSEX = PROCESSENTRY32W, MEMORYSTATUSEX
        pointer = ctypes.POINTER
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.GetProcessTimes.argtypes = [wintypes.HANDLE, pointer(FILETIME), pointer(FILETIME),
                                        pointer(FILETIME), pointer(FILETIME)]
        k32.GetProcessTimes.restype = wintypes.BOOL
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, pointer(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, pointer(MEMORYCOUNTERS), wintypes.DWORD]
        k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.Process32FirstW.argtypes = [wintypes.HANDLE, pointer(PROCESSENTRY32W)]
        k32.Process32FirstW.restype = wintypes.BOOL
        k32.Process32NextW.argtypes = [wintypes.HANDLE, pointer(PROCESSENTRY32W)]
        k32.Process32NextW.restype = wintypes.BOOL
        k32.GetSystemTimes.argtypes = [pointer(FILETIME), pointer(FILETIME), pointer(FILETIME)]
        k32.GetSystemTimes.restype = wintypes.BOOL
        k32.GlobalMemoryStatusEx.argtypes = [pointer(MEMORYSTATUSEX)]
        k32.GlobalMemoryStatusEx.restype = wintypes.BOOL

    def _fail(self) -> "OSError":
        return self._ctypes.WinError(self._ctypes.get_last_error())

    @staticmethod
    def _ticks(filetime: Any) -> int:
        return (int(filetime.high) << 32) | int(filetime.low)

    def open_process(self, pid: int) -> Any:
        handle = self._k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            raise self._fail()
        return handle

    def close(self, handle: Any) -> None:
        if not self._k32.CloseHandle(handle):
            raise self._fail()

    def process_times(self, handle: Any) -> tuple[int, int]:
        """(creation time, kernel + user CPU time), both in 100 ns ticks."""
        created, exited, kernel, user = (self._FILETIME() for _ in range(4))
        ctypes = self._ctypes
        if not self._k32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                         ctypes.byref(kernel), ctypes.byref(user)):
            raise self._fail()
        return self._ticks(created), self._ticks(kernel) + self._ticks(user)

    def is_active(self, handle: Any) -> bool:
        from ctypes import wintypes
        code = wintypes.DWORD()
        if not self._k32.GetExitCodeProcess(handle, self._ctypes.byref(code)):
            raise self._fail()
        return code.value == STILL_ACTIVE

    def working_set(self, handle: Any) -> tuple[int, int]:
        """(working set, peak working set) in bytes."""
        counters = self._MEMORYCOUNTERS()
        counters.cb = self._ctypes.sizeof(counters)
        if not self._k32.K32GetProcessMemoryInfo(handle, self._ctypes.byref(counters), counters.cb):
            raise self._fail()
        return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)

    def process_table(self) -> list[tuple[int, int]]:
        """(process id, parent process id) of every process: ids only, nothing else is read."""
        snapshot = self._k32.CreateToolhelp32Snapshot(0x2, 0)
        if snapshot is None or snapshot == self._ctypes.c_void_p(-1).value:
            raise self._fail()
        pairs: list[tuple[int, int]] = []
        try:
            entry = self._PROCESSENTRY32W()
            entry.dwSize = self._ctypes.sizeof(entry)
            more = self._k32.Process32FirstW(snapshot, self._ctypes.byref(entry))
            while more:
                pairs.append((int(entry.th32ProcessID), int(entry.th32ParentProcessID)))
                more = self._k32.Process32NextW(snapshot, self._ctypes.byref(entry))
        finally:
            self._k32.CloseHandle(snapshot)
        return pairs

    def system_times(self) -> tuple[int, int, int]:
        """(idle, kernel including idle, user) time of all logical CPUs, in 100 ns ticks."""
        idle, kernel, user = (self._FILETIME() for _ in range(3))
        ctypes = self._ctypes
        if not self._k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            raise self._fail()
        return self._ticks(idle), self._ticks(kernel), self._ticks(user)

    def memory(self) -> tuple[int, int]:
        """(available physical memory, total physical memory) in bytes."""
        status = self._MEMORYSTATUSEX()
        status.dwLength = self._ctypes.sizeof(status)
        if not self._k32.GlobalMemoryStatusEx(self._ctypes.byref(status)):
            raise self._fail()
        return int(status.ullAvailPhys), int(status.ullTotalPhys)


@dataclass
class _Tracked:
    """One benchmark-owned process.  The handle is kept open for the whole sampling window, so the
    process id cannot be reused by another process while it is sampled; `created` is checked again
    at every sample."""
    key: str                          # "storage-consumer", or "storage-consumer:launcher"
    role: str
    pid: int
    handle: Any = None
    created: Optional[int] = None
    state: str = "active"             # active | exited | unavailable
    last_ticks: Optional[int] = None
    last_at: Optional[float] = None


class HostResourceCollector:
    """
    Reads CPU and working set of the two host processes this run started, plus the host's memory,
    CPU and the free disk space.  `processes` is RUN.processes (name -> Popen); only HOST_PROCESS_ROLES
    in it are ever touched.

    A venv's python.exe is a launcher that starts the real interpreter as its child, so each role is
    resolved once, at open(), to the launcher (the Popen process) and, when it has one, the child that
    runs main.py.  The child is the role's own entry ("storage-consumer"); the launcher is a separate
    entry ("storage-consumer:launcher").  No process is counted twice and no entry is a sum, so a
    parent's numbers are never added to its child's.  The process table is read once, to follow
    parent links from the owned root; no handle is opened for any process that does not descend from it.
    """

    def __init__(self, processes: Mapping[str, Any], *, api: Any, disk_free: Callable[[], int],
                 disk_volume: str, clock: Callable[[], float] = time.monotonic) -> None:
        self._processes, self._api, self._disk_free = processes, api, disk_free
        self.disk_volume, self._clock = disk_volume, clock
        self._tracked: list[_Tracked] = []
        self._host_last: Optional[tuple[int, int, int]] = None
        self.errors: dict[str, int] = {}
        self.unattributed = 0          # descendants found below a root and not sampled
        self.opened = False

    # -- bookkeeping -----------------------------------------------------------
    def _note(self, source: str, exc: BaseException) -> None:
        self._note_label(_host_error_label(source, exc))

    def _note_label(self, label: str) -> None:
        if label in self.errors or len(self.errors) < HOST_ERROR_KINDS:
            self.errors[label] = self.errors.get(label, 0) + 1
        else:
            self.errors["other"] = self.errors.get("other", 0) + 1

    @property
    def keys(self) -> list[str]:
        return [t.key for t in self._tracked]

    # -- identify the benchmark-owned processes ------------------------------------
    def _open_one(self, pid: int) -> Optional[tuple[Any, int]]:
        try:
            handle = self._api.open_process(pid)
        except Exception as exc:  # noqa: BLE001
            self._note("open", exc)
            return None
        try:
            created, _ = self._api.process_times(handle)
            if not self._api.is_active(handle):
                raise OSError("process already exited")
        except Exception as exc:  # noqa: BLE001
            self._note("identify", exc)
            self._close_handle(handle)
            return None
        return handle, created

    def _close_handle(self, handle: Any) -> None:
        try:
            self._api.close(handle)
        except Exception as exc:  # noqa: BLE001
            self._note("close", exc)

    def open(self) -> None:
        """Resolve each role to its process(es).  Never raises for a process it cannot open: that
        role is then reported unavailable at every sample.  Called once, before the first sample."""
        self.opened = True
        try:
            table = list(self._api.process_table())
        except Exception as exc:  # noqa: BLE001
            self._note("table", exc)
            table = []
        children: dict[int, list[int]] = {}
        for pid, parent in table:
            children.setdefault(parent, []).append(pid)
        for role in HOST_PROCESS_ROLES:
            popen = self._processes.get(role)
            if popen is None:
                continue
            pid = int(popen.pid)
            if popen.poll() is not None:
                self._tracked.append(_Tracked(role, role, pid, state="exited"))
                continue
            root = self._open_one(pid)
            if root is None:
                self._tracked.append(_Tracked(role, role, pid, state="unavailable"))
                continue
            kept: list[tuple[int, int, Any, int]] = [(0, pid, root[0], root[1])]   # depth, pid, handle, created
            try:
                queue, seen = [(pid, root[1], 0)], {pid}
                while queue:
                    parent_pid, parent_created, depth = queue.pop(0)
                    for child_pid in children.get(parent_pid, []):
                        if child_pid in seen:
                            continue
                        if len(seen) > HOST_TREE_LIMIT:      # bounded: never more than the limit is opened
                            queue.clear()
                            break
                        seen.add(child_pid)
                        opened = self._open_one(child_pid)
                        if opened is None:
                            continue
                        if opened[1] < parent_created:      # older than its parent: a reused id, not a child
                            self._close_handle(opened[0])
                            continue
                        kept.append((depth + 1, child_pid, opened[0], opened[1]))
                        queue.append((child_pid, opened[1], depth + 1))
                primary = max(kept, key=lambda item: (item[0], -item[3]))
                for entry in kept:
                    if entry is primary or (entry[0] == 0 and primary[0] > 0):
                        continue
                    self._close_handle(entry[2])
                    self.unattributed += 1
            except BaseException:       # nothing is tracked yet: close what was opened, then let it go
                for entry in kept:
                    self._close_handle(entry[2])
                raise
            self._tracked.append(_Tracked(role, role, primary[1], handle=primary[2], created=primary[3]))
            if primary[0] > 0:
                self._tracked.append(_Tracked(f"{role}:launcher", role, pid, handle=root[0], created=root[1]))

    def close(self) -> None:
        """Close every handle that is still open.  Safe to call again."""
        for tracked in self._tracked:
            handle, tracked.handle = tracked.handle, None
            if handle is not None:
                self._close_handle(handle)

    # -- one sample ---------------------------------------------------------------
    def _sample_process(self, tracked: _Tracked, now: float, errors: list[str]) -> dict[str, Any]:
        row: dict[str, Any] = {"status": tracked.state if tracked.state != "active" else "ok",
                               "cpu_percent": None, "working_set_bytes": None,
                               "peak_working_set_bytes": None}
        if tracked.state != "active" or tracked.handle is None:
            return row
        try:
            if not self._api.is_active(tracked.handle):
                tracked.state, row["status"] = "exited", "exited"
                return row
            created, ticks = self._api.process_times(tracked.handle)
            if created != tracked.created:        # not the process identified at open(): never reported
                tracked.state, row["status"] = "unavailable", "unavailable"
                errors.append("identity:changed")
                return row
            working, peak = self._api.working_set(tracked.handle)
        except Exception as exc:  # noqa: BLE001
            row["status"] = "unavailable"
            errors.append(_host_error_label("process", exc))
            return row
        row["working_set_bytes"], row["peak_working_set_bytes"] = int(working), int(peak)
        if tracked.last_ticks is not None and tracked.last_at is not None:
            seconds = now - tracked.last_at
            if seconds > 0 and ticks >= tracked.last_ticks:
                row["cpu_percent"] = (ticks - tracked.last_ticks) / FILETIME_TICKS_PER_SECOND / seconds * 100.0
        tracked.last_ticks, tracked.last_at = ticks, now
        return row

    def sample(self) -> dict[str, Any]:
        """One reading.  Each part succeeds or fails on its own; a part that cannot be read is None."""
        now = self._clock()
        errors: list[str] = []
        snapshot: dict[str, Any] = {
            "processes": {t.key: self._sample_process(t, now, errors) for t in self._tracked},
            "host_cpu_percent": None, "memory_available_bytes": None, "memory_total_bytes": None,
            "disk_free_bytes": None, "errors": errors}
        try:
            idle, kernel, user = self._api.system_times()
            last, self._host_last = self._host_last, (idle, kernel, user)
            if last is not None:
                total = (kernel - last[1]) + (user - last[2])      # kernel time includes idle time
                busy = total - (idle - last[0])
                if total > 0 and -1e-9 <= busy <= total * (1 + 1e-9):
                    snapshot["host_cpu_percent"] = min(100.0, max(0.0, busy / total * 100.0))
        except Exception as exc:  # noqa: BLE001
            errors.append(_host_error_label("host_cpu", exc))
        try:
            available, total_memory = self._api.memory()
            if 0 <= available <= total_memory:
                snapshot["memory_available_bytes"], snapshot["memory_total_bytes"] = int(available), int(total_memory)
        except Exception as exc:  # noqa: BLE001
            errors.append(_host_error_label("memory", exc))
        try:
            free = self._disk_free()
            if isinstance(free, int) and not isinstance(free, bool) and free >= 0:
                snapshot["disk_free_bytes"] = free
        except Exception as exc:  # noqa: BLE001
            errors.append(_host_error_label("disk", exc))
        for label in errors:
            self._note_label(label)
        return snapshot


class HostResourceSampler(PeriodicSampler):
    """
    The host-resource sampler: a PeriodicSampler over HostResourceCollector.sample.  Unlike the base
    class, stop() does not hide a thread that failed to stop: it raises, and the handles are then
    left open (the thread may still be using them) instead of being closed under it.
    """

    def __init__(self, collector: HostResourceCollector, interval: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__(collector.sample, interval, clock)
        self.collector = collector

    def stop(self, timeout: float = 30.0) -> None:
        super().stop(timeout)
        if self._thread is not None and self._thread.is_alive():
            raise BenchmarkError(f"the host resource sampler did not stop within {timeout:g} s")
        self.collector.close()


def make_host_resource_sampler(*, processes: Mapping[str, Any], disk_free: Callable[[], int],
                               interval: float, disk_volume: str, api: Any = None,
                               clock: Callable[[], float] = time.monotonic,
                               sampler_clock: Callable[[], float] = time.monotonic) -> Optional[HostResourceSampler]:
    """The sampler for a live cell, or None off Windows (where nothing is sampled).  The processes
    are identified here, before the measured stage starts; the caller starts it."""
    if not _is_windows():
        return None
    collector = HostResourceCollector(processes, api=api if api is not None else WindowsHostResourceApi(),
                                      disk_free=disk_free, disk_volume=disk_volume, clock=clock)
    try:
        collector.open()
    except BaseException:
        collector.close()
        raise
    return HostResourceSampler(collector, interval, clock=sampler_clock)


# ---------------------------------------------------------------------------
# Database queries (read-only; run by the live code through the harness)
# ---------------------------------------------------------------------------

def run_metrics_sql(run_id: str) -> str:
    """One JSON object describing what the database holds for a run."""
    if not RUN_ID_RE.fullmatch(run_id):
        raise BenchmarkError(f"bad run id {run_id!r}")
    return f"""
WITH roots AS (
    SELECT trace_id FROM telemetry_spans
    WHERE parent_span_id IS NULL AND attributes->>'agentops.workload.run_id' = '{run_id}'
), spans AS (
    SELECT * FROM telemetry_spans WHERE trace_id IN (SELECT trace_id FROM roots)
)
SELECT json_build_object(
  'rows', (SELECT count(*) FROM spans),
  'distinct_spans', (SELECT count(DISTINCT (trace_id, span_id)) FROM spans),
  'roots', (SELECT count(*) FROM roots),
  'first_ingested', (SELECT extract(epoch from min(ingested_at))::float8 FROM spans),
  'last_ingested', (SELECT extract(epoch from max(ingested_at))::float8 FROM spans),
  'request_ms', (SELECT coalesce(json_agg(duration_ms ORDER BY duration_ms), '[]')
                 FROM spans WHERE parent_span_id IS NULL),
  'persistence_ms', (SELECT coalesce(json_agg(
        extract(epoch from (ingested_at - end_time)) * 1000.0 ORDER BY 1), '[]') FROM spans),
  'per_second', (SELECT coalesce(json_agg(c ORDER BY s), '[]') FROM (
        SELECT date_trunc('second', ingested_at) AS s, count(*) AS c FROM spans GROUP BY 1) t)
)
"""


#: The longest observation window, in whole seconds, the optional timed series
#: will cover.  A longer window is reported as not measured, never truncated.
MAX_TIMED_SERIES_SECONDS: int = 1800


def run_series_sql(run_id: str) -> str:
    """
    One optional read-only statement (B3J-68): for one run, the spans ended and
    the spans ingested in every whole second from the first span end to the
    last ingest, including seconds with none, and the persistence latency of
    the seconds that have rows.  It runs once, after the measured run, and
    never replaces run_metrics_sql.  The window is bounded in SQL: beyond
    MAX_TIMED_SERIES_SECONDS the grid is empty and every array is null.
    """
    if not RUN_ID_RE.fullmatch(run_id):
        raise BenchmarkError(f"bad run id {run_id!r}")
    cap = MAX_TIMED_SERIES_SECONDS
    return f"""
WITH roots AS (
    SELECT trace_id FROM telemetry_spans
    WHERE parent_span_id IS NULL AND attributes->>'agentops.workload.run_id' = '{run_id}'
), spans AS (
    SELECT end_time, ingested_at FROM telemetry_spans
    WHERE trace_id IN (SELECT trace_id FROM roots)
), base AS (
    SELECT extract(epoch from date_trunc('second', min(end_time)))::bigint AS t0,
           extract(epoch from date_trunc('second', max(ingested_at)))::bigint AS t1,
           count(*) AS n
    FROM spans
), grid AS (
    SELECT g AS off
    FROM base, generate_series(0::bigint,
         CASE WHEN t1 >= t0 AND t1 - t0 < {cap} THEN t1 - t0 ELSE -1 END) AS g
), ended_s AS (
    SELECT extract(epoch from date_trunc('second', end_time))::bigint - t0 AS off,
           count(*) AS c
    FROM spans, base GROUP BY 1
), ingested_s AS (
    SELECT extract(epoch from date_trunc('second', ingested_at))::bigint - t0 AS off,
           count(*) AS c,
           round(avg(extract(epoch from (ingested_at - end_time)) * 1000.0)::numeric, 3)::float8
               AS mean_ms,
           round(max(extract(epoch from (ingested_at - end_time)) * 1000.0)::numeric, 3)::float8
               AS max_ms
    FROM spans, base GROUP BY 1
)
SELECT json_build_object(
  'start_epoch_s', (SELECT t0 FROM base),
  'end_epoch_s', (SELECT t1 FROM base),
  'rows', (SELECT n FROM base),
  'cap_seconds', {cap},
  'ended', (SELECT json_agg(coalesce(e.c, 0) ORDER BY grid.off)
            FROM grid LEFT JOIN ended_s e ON e.off = grid.off),
  'ingested', (SELECT json_agg(coalesce(i.c, 0) ORDER BY grid.off)
               FROM grid LEFT JOIN ingested_s i ON i.off = grid.off),
  'latency_offsets', (SELECT json_agg(grid.off ORDER BY grid.off)
                      FROM grid JOIN ingested_s i ON i.off = grid.off),
  'latency_mean_ms', (SELECT json_agg(i.mean_ms ORDER BY grid.off)
                      FROM grid JOIN ingested_s i ON i.off = grid.off),
  'latency_max_ms', (SELECT json_agg(i.max_ms ORDER BY grid.off)
                     FROM grid JOIN ingested_s i ON i.off = grid.off)
)
"""


#: A gap between two consecutive ingests longer than this is counted as a stall.
STALL_GAP_MS: float = 100.0
#: The most Kafka partitions the optional gap diagnostic reports.
MAX_GAP_PARTITIONS: int = 16


def run_gap_sql(run_id: str) -> str:
    """
    One optional read-only statement (B3J-84): for one run, the gaps between
    consecutive ingests, overall and per second, and what each Kafka partition
    delivered.  ingested_at is NOW(), the start of the span's transaction, and
    the storage consumer handles one span at a time, so the gap between two
    consecutive ingests is that consumer's whole cycle for the span (previous
    commit, offset commit, poll, parse, BEGIN, INSERT).  The first row has no
    gap (NULL, never 0).  Rows are ordered by ingested_at, then id.  It runs
    once, after the measured run, and never replaces run_metrics_sql.  The time
    axis is the one of run_series_sql, bounded in SQL by MAX_TIMED_SERIES_SECONDS;
    beyond it the per-second arrays are null.  At most MAX_GAP_PARTITIONS
    partitions are returned.
    """
    if not RUN_ID_RE.fullmatch(run_id):
        raise BenchmarkError(f"bad run id {run_id!r}")
    cap, stall, parts = MAX_TIMED_SERIES_SECONDS, STALL_GAP_MS, MAX_GAP_PARTITIONS
    return f"""
WITH roots AS (
    SELECT trace_id FROM telemetry_spans
    WHERE parent_span_id IS NULL AND attributes->>'agentops.workload.run_id' = '{run_id}'
), spans AS (
    SELECT id, end_time, ingested_at, kafka_partition, kafka_offset FROM telemetry_spans
    WHERE trace_id IN (SELECT trace_id FROM roots)
), base AS (
    SELECT extract(epoch from date_trunc('second', min(end_time)))::bigint AS t0,
           extract(epoch from date_trunc('second', max(ingested_at)))::bigint AS t1,
           count(*) AS n
    FROM spans
), grid AS (
    SELECT g AS off
    FROM base, generate_series(0::bigint,
         CASE WHEN t1 >= t0 AND t1 - t0 < {cap} THEN t1 - t0 ELSE -1 END) AS g
), ordered AS (
    SELECT s.id, s.kafka_partition, s.kafka_offset, s.ingested_at,
           extract(epoch from date_trunc('second', s.ingested_at))::bigint - b.t0 AS off,
           round((extract(epoch from (s.ingested_at
                 - lag(s.ingested_at) OVER (ORDER BY s.ingested_at, s.id))) * 1000.0)::numeric,
                 3)::float8 AS gap_ms
    FROM spans s, base b
), gaps AS (
    SELECT * FROM ordered WHERE gap_ms IS NOT NULL
), gap_all AS (
    SELECT count(*) AS n,
           round(percentile_cont(0.5) WITHIN GROUP (ORDER BY gap_ms)::numeric, 3)::float8 AS p50,
           round(percentile_cont(0.9) WITHIN GROUP (ORDER BY gap_ms)::numeric, 3)::float8 AS p90,
           round(percentile_cont(0.99) WITHIN GROUP (ORDER BY gap_ms)::numeric, 3)::float8 AS p99,
           max(gap_ms) AS mx,
           count(*) FILTER (WHERE gap_ms > {stall}) AS stalls
    FROM gaps
), gap_s AS (
    SELECT off, count(*) AS c,
           round(percentile_cont(0.5) WITHIN GROUP (ORDER BY gap_ms)::numeric, 3)::float8 AS med,
           max(gap_ms) AS mx,
           count(*) FILTER (WHERE gap_ms > {stall}) AS stalls
    FROM gaps GROUP BY off
), ing_s AS (
    SELECT off, count(*) AS c FROM ordered GROUP BY off
), part AS (
    SELECT kafka_partition AS pid, count(*) AS n, min(kafka_offset) AS lo,
           max(kafka_offset) AS hi, count(DISTINCT kafka_offset) AS d
    FROM spans GROUP BY kafka_partition ORDER BY kafka_partition LIMIT {parts}
), part_s AS (
    SELECT kafka_partition AS pid, off, count(*) AS c FROM ordered GROUP BY kafka_partition, off
), pcell AS (
    SELECT p.pid, g.off, coalesce(ps.c, 0) AS c
    FROM part p CROSS JOIN grid g LEFT JOIN part_s ps ON ps.pid = p.pid AND ps.off = g.off
), pjson AS (
    SELECT pid, json_agg(c ORDER BY off) AS arr FROM pcell GROUP BY pid
)
SELECT json_build_object(
  'start_epoch_s', (SELECT t0 FROM base),
  'end_epoch_s', (SELECT t1 FROM base),
  'rows', (SELECT n FROM base),
  'cap_seconds', {cap},
  'stall_ms', {stall},
  'partition_limit', {parts},
  'first_row_offset', (SELECT off FROM ordered ORDER BY ingested_at, id LIMIT 1),
  'gap_count', (SELECT n FROM gap_all),
  'gap_p50_ms', (SELECT p50 FROM gap_all),
  'gap_p90_ms', (SELECT p90 FROM gap_all),
  'gap_p99_ms', (SELECT p99 FROM gap_all),
  'gap_max_ms', (SELECT mx FROM gap_all),
  'stall_gaps', (SELECT stalls FROM gap_all),
  'ingested', (SELECT json_agg(coalesce(i.c, 0) ORDER BY grid.off)
               FROM grid LEFT JOIN ing_s i ON i.off = grid.off),
  'gap_offsets', (SELECT json_agg(grid.off ORDER BY grid.off)
                  FROM grid JOIN gap_s ON gap_s.off = grid.off),
  'gap_counts', (SELECT json_agg(gap_s.c ORDER BY grid.off)
                 FROM grid JOIN gap_s ON gap_s.off = grid.off),
  'gap_median_ms', (SELECT json_agg(gap_s.med ORDER BY grid.off)
                    FROM grid JOIN gap_s ON gap_s.off = grid.off),
  'gap_max_by_second_ms', (SELECT json_agg(gap_s.mx ORDER BY grid.off)
                           FROM grid JOIN gap_s ON gap_s.off = grid.off),
  'gap_stall_counts', (SELECT json_agg(gap_s.stalls ORDER BY grid.off)
                       FROM grid JOIN gap_s ON gap_s.off = grid.off),
  'partitions', (SELECT json_agg(json_build_object(
                     'partition', p.pid, 'rows', p.n, 'min_offset', p.lo, 'max_offset', p.hi,
                     'distinct_offsets', p.d, 'per_second', j.arr) ORDER BY p.pid)
                 FROM part p LEFT JOIN pjson j ON j.pid = p.pid)
)
"""


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------

def _get(source: Optional[Mapping[str, Any]], key: str) -> Any:
    """source[key], or None when there is no source or no such key."""
    return None if source is None else source.get(key)


STAGE_TAIL_METHOD: str = ("Driver finished -> run_stage returned; includes consumer drain, "
                          "settle period and reconciliation.")
SCHEDULER_COUNTS: tuple[str, ...] = ("late_starts", "started_requests", "not_started_requests")
SCHEDULER_SECONDS: tuple[str, ...] = ("max_start_lag_seconds", "mean_start_lag_seconds")


def _persisted_rate(db: Optional[Mapping[str, Any]],
                    window: Optional[Mapping[str, str]]) -> dict[str, Any]:
    """
    (n - 1) / (last - first ingested_at): n insert timestamps bound n - 1
    intervals.  Both timestamps are epoch seconds from the database clock.
    Fewer than 2 rows, or a span that is not positive, has no rate.
    """
    source = "telemetry_spans.ingested_at"
    rows = _get(db, "rows")
    first, last = _get(db, "first_ingested"), _get(db, "last_ingested")
    if rows is None or first is None or last is None:
        return M.not_measured("spans/s", source, "rows or ingested_at bounds not read").to_dict()
    if rows < 2:
        return M.not_measured("spans/s", source,
                              f"{rows} row(s): a rate needs at least 2").to_dict()
    span = last - first
    if not span > 0:
        return M.not_measured("spans/s", source,
                              "the first and last rows share one instant").to_dict()
    return M.Metric(
        M.rate(rows - 1, span), "spans/s", "DERIVED", source,
        "(rows - 1) / (max(ingested_at) - min(ingested_at)), in seconds of the database "
        "clock: n insert timestamps bound n - 1 intervals", window, rows).to_dict()


def _scheduler(driver: Optional[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    The measured run's scheduler evidence, from the driver's own report.

    Returns (metrics, evidence).  A field the report lacks is NOT_MEASURED
    and None in the evidence, never 0.  evidence["evaluated"] says whether
    the generator-bound rule can be judged: it needs late_starts and
    started_requests, and at least one planned request.
    """
    metrics: dict[str, Any] = {}
    evidence: dict[str, Any] = {"start_lag_series": None, "missing": []}
    for name in SCHEDULER_COUNTS + SCHEDULER_SECONDS:
        value = _get(driver, name)
        evidence[name] = value
        unit = "requests" if name in SCHEDULER_COUNTS else "s"
        if value is None:
            evidence["missing"].append(name)
            reason = ("no driver report" if driver is None
                      else f"the driver report has no {name}")
            metrics[name] = M.not_measured(unit, "driver report", reason).to_dict()
        else:
            metrics[name] = M.Metric(value, unit, "MEASURED", "driver report",
                                     "the driver's own value for the measured run", None,
                                     1).to_dict()
    evidence["run_status"] = _get(driver, "run_status")
    if evidence["run_status"] is None:
        evidence["missing"].append("run_status")
    planned = (evidence["started_requests"] or 0) + (evidence["not_started_requests"] or 0)
    evidence["evaluated"] = (evidence["late_starts"] is not None
                             and evidence["started_requests"] is not None and planned > 0)
    _start_lag_diagnostic(driver, metrics, evidence)
    return metrics, evidence


#: The driver's own late-start threshold (real_driver.LATE_START_SECONDS);
#: used only to list which recorded requests the driver counted as late.
DRIVER_LATE_START_SECONDS: float = 0.1
_DIAGNOSTIC_KEYS = frozenset({"limit", "expected", "recorded", "complete", "truncated_reason",
                              "entries"})


def _diagnostic_problems(raw: Any) -> list[str]:
    """Why a start-lag diagnostic cannot be used; empty when it can."""
    if not isinstance(raw, Mapping) or set(raw) != _DIAGNOSTIC_KEYS:
        return ["malformed diagnostic object"]
    entries = raw["entries"]
    if not isinstance(entries, list):
        return ["entries are not a list"]
    problems: list[str] = []
    previous = -1
    for entry in entries:
        if (not isinstance(entry, (list, tuple)) or len(entry) != 3
                or isinstance(entry[0], bool) or not isinstance(entry[0], int)):
            problems.append("malformed entry")
            break
        index, offset, lag = entry
        if index <= previous:
            problems.append("request indices not strictly increasing")
            break
        previous = index
        for value in (offset, lag):
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0):
                problems.append("non-finite or negative value")
                break
        if problems:
            break
    if raw["recorded"] != len(entries):
        problems.append("recorded does not equal the number of entries")
    if raw["complete"] is not True:
        problems.append(f"incomplete: {raw.get('truncated_reason') or 'no reason given'}")
    elif raw["recorded"] != raw["expected"]:
        problems.append("recorded does not equal expected")
    return problems


def _start_lag_diagnostic(driver: Optional[Mapping[str, Any]], metrics: dict[str, Any],
                          evidence: dict[str, Any]) -> None:
    """
    Copy the driver's start-lag diagnostic into the evidence and, only when it
    is complete and valid, add start-lag percentiles.  Observational only:
    nothing here is passed to a generator-bound or growing-lag decision, and
    start_lag_series stays None.
    """
    raw = _get(driver, "start_lags")
    source, unit = "driver report start_lags", "s"
    if raw is None:
        evidence["start_lag_diagnostic"] = None
        reason = ("no driver report" if driver is None
                  else "the driver report has no start-lag diagnostic")
        for q in M.PERCENTILES:
            metrics[f"start_lag_p{q}"] = M.not_measured(unit, source, reason).to_dict()
        return
    problems = _diagnostic_problems(raw)
    usable = not problems
    entries = [list(e) for e in raw.get("entries", [])] if isinstance(raw, Mapping) and \
        isinstance(raw.get("entries"), list) else []
    lags = [e[2] for e in entries] if usable else []
    evidence["start_lag_diagnostic"] = {
        **({k: raw[k] for k in _DIAGNOSTIC_KEYS if k != "entries"}
           if isinstance(raw, Mapping) and set(raw) == _DIAGNOSTIC_KEYS else {}),
        "entries": entries if not problems or isinstance(raw, Mapping) else [],
        "usable": usable, "problems": problems,
        "late_threshold_seconds": DRIVER_LATE_START_SECONDS,
        "late_request_indices": ([e[0] for e in entries if e[2] > DRIVER_LATE_START_SECONDS]
                                 if usable else None),
    }
    if usable and lags:
        found = M.percentiles(lags)
        for q in M.PERCENTILES:
            metrics[f"start_lag_p{q}"] = M.Metric(
                found[f"p{q}"], unit, "MEASURED", source,
                "percentile (linear) of the per-request start lags of the started first "
                "attempts; driver monotonic clock", None, len(lags)).to_dict()
    else:
        reason = ("no started request" if usable else "diagnostic not usable: "
                  + "; ".join(problems))
        for q in M.PERCENTILES:
            metrics[f"start_lag_p{q}"] = M.not_measured(unit, source, reason).to_dict()


def generator_bound_from_evidence(
    evidence: Mapping[str, Any], *, late_fraction: float, lag_growth_samples: int,
) -> tuple[bool, tuple[str, ...]]:
    """
    The generator-bound decision from recorded scheduler evidence alone, so
    a result can be re-checked from its JSON.  Not evaluated -> (False, ()).
    A missing not_started_requests or run_status adds no evidence: each can
    only make a run GENERATOR_BOUND, never clear it.  There is no start-lag
    series.
    """
    if not evidence.get("evaluated"):
        return False, ()
    return M.generator_bound(
        late_starts=evidence["late_starts"], started_requests=evidence["started_requests"],
        not_started_requests=evidence.get("not_started_requests") or 0,
        deadline_reached=evidence.get("run_status") == "deadline_reached",
        late_fraction=late_fraction, lag_growth_samples=lag_growth_samples)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


@dataclass
class CellEvidence:
    """Everything one cell produced; any field may be missing (None)."""

    cell: Cell
    git_sha: str
    git_dirty: bool
    started: float
    finished: float
    machine: dict[str, Any] = field(default_factory=dict)
    driver: Optional[Mapping[str, Any]] = None        # the generator's execution report
    canonical_records: Optional[int] = None
    raw_records: Optional[int] = None
    dlq_records: Optional[int] = None
    database: Optional[Mapping[str, Any]] = None      # run_metrics_sql output
    clock_before: Sequence[M.ClockSample] = ()
    clock_after: Sequence[M.ClockSample] = ()
    lag_samples: Sequence[tuple[float, Any]] = ()
    resource_samples: Sequence[tuple[float, Any]] = ()
    #: Host resource observations (B3J-283): the host sampler's samples and what it needs to read them.
    #: None / empty when no host sampler ran (an older cell, a non-Windows host, a failed start).
    host_resource_samples: Sequence[tuple[float, Any]] = ()
    host_resource_info: Optional[Mapping[str, Any]] = None
    #: The Docker resource sampler's window (B3J-287): {"stop_s", "interval_s", "expected_containers"} in the
    #: sampler's own seconds (it starts at 0).  None for evidence assembled without a real sampler, which
    #: keeps the rules that existed before B3J-287 and nothing else.
    resource_window: Optional[Mapping[str, Any]] = None
    #: The host-memory checkpoint (B3J-299): its outcome (readings, minimum, threshold, status) and the
    #: observation-only readings taken earlier.  Empty / None when no memory reader was given.
    host_memory_checkpoint: Optional[Mapping[str, Any]] = None
    host_memory_observations: dict[str, Optional[int]] = field(default_factory=dict)
    #: Driver finished -> run_stage returned: consumer drain, the settle
    #: period and the reconciliation queries together.
    stage_tail_seconds: Optional[float] = None
    #: Older name of stage_tail_seconds, which is what it always held; read
    #: only when stage_tail_seconds is unset.  A pure drain time is never
    #: available: the frozen harness does not expose one.
    drain_seconds: Optional[float] = None
    refresh_seconds: Optional[float] = None           # wall clock around the refresh
    refresh_dbt_seconds: Optional[float] = None       # dbt's own duration, when printed
    detector_ms: Optional[Mapping[str, float]] = None
    #: Optional diagnostics (B3J-59): when the samplers started (wall clock) and
    #: the detector's per-group counts, both read from what the harness already has.
    sampler_started: Optional[float] = None
    detector_counts: Optional[Mapping[str, Mapping[str, int]]] = None
    #: Optional (B3J-68): the run_series_sql result, read once after the measured run.
    timed_series: Optional[Mapping[str, Any]] = None
    #: Optional (B3J-84): the run_gap_sql result, read once after the measured run.
    gap_series: Optional[Mapping[str, Any]] = None
    disk_free_bytes: Optional[int] = None
    projected_need_bytes: Optional[int] = None
    cleanup_verified: Optional[bool] = None
    process_exits: Sequence[str] = ()
    stop_reasons: Sequence[str] = ()
    failure: Optional[str] = None
    limitations: list[str] = field(default_factory=list)
    #: The consumer configuration this cell ran with (B3J-257): configured values only.
    consumer_batch_messages: int = 1
    consumer_commit_interval_seconds: Optional[float] = None
    consumer_timing_interval_seconds: float = 0.0
    #: Measured commit behavior, present only when the consumer's timing windows were captured.
    consumer_observed: Optional[Mapping[str, Any]] = None
    #: What Windows reported about the machine during the cell (B3J-275); None off Windows.
    host: Optional[Mapping[str, Any]] = None


# ---------------------------------------------------------------------------
# Optional diagnostics (B3J-59): already-collected observations, preserved
# ---------------------------------------------------------------------------

#: What the detector prints per group, and the unit of each count.
DETECTOR_COUNT_FIELDS: tuple[tuple[str, str], ...] = (
    ("candidates", "records"), ("emitted", "events"), ("inserted", "events"),
    ("duplicate", "events"))
INGEST_SERIES_METHOD: str = (
    "rows per whole second of ingested_at (database clock), in time order.  The SQL "
    "returns counts only: seconds with no rows are omitted and no bucket carries a "
    "timestamp, so gaps are not represented (the window gives the first and last ingest)")


def detector_counts_from_groups(groups: Any) -> Optional[dict[str, dict[str, int]]]:
    """The detector's own per-group counts (candidates, emitted, inserted,
    duplicate), keyed like detector_ms.  Only fields the harness already
    parsed from the detector log are read.  Never raises: anything it cannot
    read is left out, and None is returned when nothing could be read."""
    try:
        found: dict[str, dict[str, int]] = {}
        for group in groups:
            key = f"{group['signal_path']}/{group['operation_name']}"
            counts: dict[str, int] = {}
            for name, _unit in DETECTOR_COUNT_FIELDS:
                text = group.get(name)
                if text is None:
                    continue
                value = int(str(text).strip())
                if value >= 0:
                    counts[name] = value
            if counts:
                found[key] = counts
        return found or None
    except Exception:
        return None


def _diag_lag_series(evidence: "CellEvidence") -> dict[tuple[str, str], Any]:
    """The raw and canonical lag samples with their elapsed times, and how
    many samples were attempted.  A failed sample is omitted from the series
    (never turned into 0); samples_taken minus a series' n counts them."""
    samples = list(evidence.lag_samples)
    added: dict[tuple[str, str], Any] = {}
    if not samples:
        reason = "no lag samples taken"
        added[("lag", "samples_taken")] = M.not_measured(
            "samples", "harness", reason).to_dict()
    else:
        reason = "every sample failed"
        added[("lag", "samples_taken")] = M.Metric(
            len(samples), "samples", "OBSERVATION", "harness",
            "periodic lag samples attempted, successful or failed", None,
            len(samples)).to_dict()
    for group in ("raw", "canonical"):
        pairs = [(float(at), value.get(group)) for at, value in samples
                 if isinstance(value, Mapping) and value.get(group) is not None]
        if pairs:
            added[("lag", f"{group}_series_records")] = M.Metric(
                [records for _, records in pairs], "records", "OBSERVATION",
                "kafka-consumer-groups",
                "periodic samples in order; a failed sample is omitted, never counted as 0",
                None, len(pairs)).to_dict()
            added[("lag", f"{group}_series_times_s")] = M.Metric(
                [round(at, 3) for at, _ in pairs], "s", "OBSERVATION",
                "harness monotonic clock",
                f"seconds since the samplers started, one per value of "
                f"{group}_series_records", None, len(pairs)).to_dict()
        else:
            for name, unit in ((f"{group}_series_records", "records"),
                               (f"{group}_series_times_s", "s")):
                added[("lag", name)] = M.not_measured(
                    unit, "kafka-consumer-groups", reason).to_dict()
    return added


def _diag_sampler_start(evidence: "CellEvidence") -> dict[tuple[str, str], Any]:
    """When the samplers started (wall clock), for approximate alignment of the
    series times with the measured workload.  Omitted when not recorded."""
    if evidence.sampler_started is None:
        return {}
    instant = _iso(evidence.sampler_started)
    return {("lag", "sampler_started_epoch_s"): M.Metric(
        float(evidence.sampler_started), "s", "OBSERVATION", "harness wall clock",
        "wall-clock time (seconds since the Unix epoch) when the lag and resource samplers "
        "started; the series times are seconds after this instant",
        {"start": instant, "end": instant, "clock": "host"}, 1).to_dict()}


def _diag_ingest_series(db: Optional[Mapping[str, Any]],
                        window_db: Optional[Mapping[str, str]]) -> dict[tuple[str, str], Any]:
    """The per-second persisted-span counts the database query already returned."""
    series = db.get("per_second") if isinstance(db, Mapping) else None
    name = ("throughput", "persisted_per_second_series")
    if isinstance(series, list) and series:
        return {name: M.Metric(list(series), "spans/s", "OBSERVATION",
                               "telemetry_spans.ingested_at", INGEST_SERIES_METHOD,
                               window_db, len(series)).to_dict()}
    reason = ("no database result" if db is None else
              "the database returned no per-second counts")
    return {name: M.not_measured("spans/s", "telemetry_spans.ingested_at", reason).to_dict()}


def _diag_persistence_max(persistence_ms: Sequence[float], window_db: Optional[Mapping[str, str]],
                          clock: Mapping[str, Any], clock_valid: Optional[bool]
                          ) -> dict[tuple[str, str], Any]:
    """The maximum per-span persistence latency, reported only when the
    clock check allows persistence latency at all (as the percentiles are)."""
    name = ("latency", "persistence_ms_max")
    if clock_valid is True:
        if not persistence_ms:
            return {name: M.not_measured("ms", "ingested_at - end_time",
                                         "no spans read").to_dict()}
        return {name: M.Metric(
            max(persistence_ms), "ms", "DERIVED",
            "ingested_at (database clock) - end_time (host clock)",
            "maximum over every per-span value; valid only within the recorded clock skew",
            window_db, len(persistence_ms)).to_dict()}
    reason = ("clock skew not measured" if clock_valid is None
              else "clock skew outside its limits: " + "; ".join(clock["reasons"]))
    return {name: M.not_measured("ms", "ingested_at - end_time", reason).to_dict()}


def _diag_detector_counts(evidence: "CellEvidence") -> dict[tuple[str, str], Any]:
    """The detector's candidate / emitted / inserted / duplicate counts per
    signal, as already parsed from its log.  No severity: it is not logged."""
    name = ("analytics", "detector_counts")
    if not evidence.cell.refresh_and_detector:
        return {name: M.not_measured("records", "detector log",
                                     f"not run at level {evidence.cell.level}").to_dict()}
    if not evidence.detector_counts:
        return {name: M.not_measured("records", "detector log",
                                     "detector counts not read").to_dict()}
    units = dict(DETECTOR_COUNT_FIELDS)
    return {name: {
        group: {field_name: M.Metric(
            value, units[field_name], "OBSERVATION", "detector log",
            f"{field_name} as printed by the detector for the group", None, 1).to_dict()
            for field_name, value in sorted(counts.items())}
        for group, counts in sorted(evidence.detector_counts.items())}}


TIMED_SERIES_AXIS_METHOD: str = (
    "whole-second epoch (floor) of the earliest span end_time of the measured run; index i of "
    "every timed series is the second start + i.  The window runs to the whole second of the "
    "last ingested_at and is at most {cap} s.  A 0 is a second inside the window in which "
    "nothing ended or was ingested; a second with no ingested span has no latency value and is "
    "absent from the latency series (see timed_persistence_ms_series_offsets_s), never 0")
CPU_SERIES_NOTE: str = (
    "docker stats CPU of the container, as a percent of one core (it can exceed 100); it does not "
    "measure the stream processor and the storage consumer, which run as host processes")


def _timed_series_checked(series: Any, db_rows: Any) -> dict[str, Any]:
    """The timed series, normalized, or BenchmarkError naming what is wrong.
    Every array must agree with the counts the required query returned, and
    nothing is repaired or filled in."""
    if not isinstance(series, Mapping):
        raise BenchmarkError("the per-second query returned no object")
    start, end, rows = series.get("start_epoch_s"), series.get("end_epoch_s"), series.get("rows")
    if start is None or end is None or not rows:
        raise BenchmarkError("the run has no spans to place on a time axis")

    def whole(value: Any, what: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise BenchmarkError(f"{what} is not a whole number")
        return value

    start, end, rows = whole(start, "start"), whole(end, "end"), whole(rows, "rows")
    if end < start:
        raise BenchmarkError("the last ingest is before the first span end")
    seconds = end - start + 1
    if seconds > MAX_TIMED_SERIES_SECONDS:
        raise BenchmarkError(f"the window of {seconds} s exceeds the bound of "
                             f"{MAX_TIMED_SERIES_SECONDS} s")
    if db_rows is not None and rows != db_rows:
        raise BenchmarkError(f"the per-second query saw {rows} rows, the required query {db_rows}")
    out: dict[str, Any] = {"start": start, "end": end, "seconds": seconds, "rows": rows}
    for name in ("ended", "ingested"):
        counts = series.get(name)
        if not isinstance(counts, list) or len(counts) != seconds:
            raise BenchmarkError(f"{name} does not hold one count per second of the window")
        for item in counts:
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise BenchmarkError(f"{name} holds a value that is not a count")
        if sum(counts) != rows:
            raise BenchmarkError(f"{name} counts {sum(counts)} spans, not {rows}")
        out[name] = list(counts)
    offsets, mean, peak = (series.get(k) for k in ("latency_offsets", "latency_mean_ms",
                                                   "latency_max_ms"))
    if not (isinstance(offsets, list) and isinstance(mean, list) and isinstance(peak, list)
            and len(offsets) == len(mean) == len(peak)):
        raise BenchmarkError("the latency arrays do not match")
    previous = -1
    for at, low, high in zip(offsets, mean, peak):
        if isinstance(at, bool) or not isinstance(at, int) or not previous < at < seconds:
            raise BenchmarkError("latency offsets are not increasing seconds of the window")
        previous = at
        if out["ingested"][at] == 0:
            raise BenchmarkError("a latency value belongs to a second with no ingested span")
        for value in (low, high):
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(value):
                raise BenchmarkError("a latency value is not a finite number")
        if low > high + 1e-6:
            raise BenchmarkError("a mean latency exceeds its maximum")
    if len(offsets) != sum(1 for item in out["ingested"] if item):
        raise BenchmarkError("latency values are missing for seconds with ingested spans")
    out.update(offsets=list(offsets), mean=[float(v) for v in mean], peak=[float(v) for v in peak])
    return out


def _diag_timed_series(evidence: "CellEvidence", clock: Mapping[str, Any],
                       clock_valid: Optional[bool]) -> dict[tuple[str, str], Any]:
    """Per-second spans ended and ingested, and persistence latency, on one
    explicit epoch-second axis (B3J-68).  The axis mixes the host clock (span
    end) and the database clock (ingest), so, like the persistence
    percentiles, it is reported only when the clock check allows it."""
    leaves: tuple[tuple[str, str, str, str], ...] = (
        ("throughput", "timed_series_start_epoch_s", "s", "telemetry_spans.end_time"),
        ("throughput", "timed_ended_per_second_series", "spans/s", "telemetry_spans.end_time"),
        ("throughput", "timed_ingested_per_second_series", "spans/s",
         "telemetry_spans.ingested_at"),
        ("latency", "timed_persistence_ms_mean_series", "ms", "ingested_at - end_time"),
        ("latency", "timed_persistence_ms_max_series", "ms", "ingested_at - end_time"),
        ("latency", "timed_persistence_ms_series_offsets_s", "s", "ingested_at"))

    def missing(reason: str) -> dict[tuple[str, str], Any]:
        return {(section, name): M.not_measured(unit, source, reason).to_dict()
                for section, name, unit, source in leaves}

    if evidence.timed_series is None:
        return missing("the optional per-second query did not run or failed")
    if clock_valid is not True:
        return missing("clock skew not measured" if clock_valid is None
                       else "clock skew outside its limits: " + "; ".join(clock["reasons"]))
    db_rows = evidence.database.get("rows") if isinstance(evidence.database, Mapping) else None
    try:
        data = _timed_series_checked(evidence.timed_series, db_rows)
    except BenchmarkError as exc:
        return missing(str(exc))
    window = {"start": _iso(data["start"]), "end": _iso(data["end"] + 1), "clock": "host"}
    seconds = data["seconds"]

    def leaf(value: Any, unit: str, kind: str, source: str, method: str, n: int) -> Any:
        return M.Metric(value, unit, kind, source, method, window, n).to_dict()

    latency_how = ("per whole second of ingested_at, over the spans ingested in it; valid only "
                   "within the recorded clock skew; seconds without ingested spans are absent")
    found: dict[tuple[str, str], Any] = {
        ("throughput", "timed_series_start_epoch_s"): leaf(
            data["start"], "s", "OBSERVATION", "telemetry_spans.end_time (host clock)",
            TIMED_SERIES_AXIS_METHOD.format(cap=MAX_TIMED_SERIES_SECONDS), 1),
        ("throughput", "timed_ended_per_second_series"): leaf(
            data["ended"], "spans/s", "OBSERVATION", "telemetry_spans.end_time (host clock)",
            "spans whose end_time falls in each whole second of the window, zeros included",
            seconds),
        ("throughput", "timed_ingested_per_second_series"): leaf(
            data["ingested"], "spans/s", "OBSERVATION", "telemetry_spans.ingested_at (database clock)",
            "spans whose ingested_at falls in each whole second of the window, zeros included",
            seconds)}
    if data["offsets"]:
        count = len(data["offsets"])
        found[("latency", "timed_persistence_ms_mean_series")] = leaf(
            data["mean"], "ms", "DERIVED", "ingested_at (database clock) - end_time (host clock)",
            "mean " + latency_how, count)
        found[("latency", "timed_persistence_ms_max_series")] = leaf(
            data["peak"], "ms", "DERIVED", "ingested_at (database clock) - end_time (host clock)",
            "maximum " + latency_how, count)
        found[("latency", "timed_persistence_ms_series_offsets_s")] = leaf(
            data["offsets"], "s", "OBSERVATION", "telemetry_spans.ingested_at",
            "seconds after the series start of each latency value", count)
    else:
        for section, name, unit, source in leaves[3:]:
            found[(section, name)] = M.not_measured(unit, source, "no spans ingested").to_dict()
    return found


GAP_METHOD_NOTE: str = (
    "gap between consecutive ingested_at values (database clock; the start of each span's "
    "transaction), ordered by ingested_at then id; the storage consumer is serial, so a gap is "
    "its whole cycle for a span; the first span has no gap; a gap is attributed to the second "
    "of the later span")


def _whole_number(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BenchmarkError(f"{what} is not a whole number")
    return value


def _gap_number(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0:
        raise BenchmarkError(f"{what} is not a finite non-negative number")
    return float(value)


def _gap_overall_checked(series: Any, db_rows: Any) -> dict[str, Any]:
    """The overall gap statistics, or BenchmarkError naming what is wrong."""
    if not isinstance(series, Mapping):
        raise BenchmarkError("the ingest-gap query returned no object")
    rows = series.get("rows")
    if not rows:
        raise BenchmarkError("the run has no spans")
    rows = _whole_number(rows, "rows")
    if db_rows is not None and rows != db_rows:
        raise BenchmarkError(f"the ingest-gap query saw {rows} rows, the required query {db_rows}")
    stall = series.get("stall_ms")
    if _gap_number(stall, "stall_ms") != STALL_GAP_MS:
        raise BenchmarkError("the stall threshold is not the documented one")
    # The query echoes the bounds it was built with; a different one is another query.
    if _whole_number(series.get("cap_seconds"), "cap_seconds") != MAX_TIMED_SERIES_SECONDS:
        raise BenchmarkError("the query's window bound is not this version's")
    if _whole_number(series.get("partition_limit"), "partition_limit") != MAX_GAP_PARTITIONS:
        raise BenchmarkError("the query's partition limit is not this version's")
    count = _whole_number(series.get("gap_count"), "gap_count")
    if count != rows - 1:
        raise BenchmarkError(f"{count} gaps for {rows} rows (the first row has none)")
    if count == 0:
        raise BenchmarkError("fewer than two rows: no gap exists")
    values = [_gap_number(series.get(key), key) for key in
              ("gap_p50_ms", "gap_p90_ms", "gap_p99_ms", "gap_max_ms")]
    if any(low > high + 1e-6 for low, high in zip(values, values[1:])):
        raise BenchmarkError("the gap percentiles are not ordered")
    stalls = _whole_number(series.get("stall_gaps"), "stall_gaps")
    if not 0 <= stalls <= count:
        raise BenchmarkError("the stall count is outside 0..gap count")
    # A stall is a gap strictly longer than the threshold, so the maximum decides.
    if (values[3] > STALL_GAP_MS) != (stalls > 0):
        raise BenchmarkError("the stall count does not match the maximum gap against "
                             f"{STALL_GAP_MS} ms")
    return {"rows": rows, "gaps": count, "p50": values[0], "p90": values[1], "p99": values[2],
            "max": values[3], "stalls": stalls}


def _gap_partitions_checked(series: Any, rows: int) -> list[dict[str, Any]]:
    """What each partition delivered, or BenchmarkError.  Offsets are reported as
    counts and bounds only; contiguity is never inferred from min and max."""
    found = series.get("partitions")
    if not isinstance(found, list) or not found:
        raise BenchmarkError("no partition was reported")
    if len(found) > MAX_GAP_PARTITIONS:
        raise BenchmarkError(f"more than {MAX_GAP_PARTITIONS} partitions")
    parts: list[dict[str, Any]] = []
    previous = -1
    for item in found:
        if not isinstance(item, Mapping):
            raise BenchmarkError("a partition entry is not an object")
        pid = _whole_number(item.get("partition"), "partition")
        count = _whole_number(item.get("rows"), "partition rows")
        low = _whole_number(item.get("min_offset"), "min_offset")
        high = _whole_number(item.get("max_offset"), "max_offset")
        distinct = _whole_number(item.get("distinct_offsets"), "distinct_offsets")
        if pid <= previous or count < 1 or low < 0 or high < low:
            raise BenchmarkError("partition entries are not increasing, non-empty and ordered")
        if not 1 <= distinct <= count or distinct > high - low + 1:
            raise BenchmarkError("distinct offsets do not fit the partition's rows and bounds")
        previous = pid
        parts.append({"partition": pid, "rows": count, "min": low, "max": high,
                      "distinct": distinct, "per_second": item.get("per_second")})
    if sum(part["rows"] for part in parts) != rows:
        raise BenchmarkError("the partitions do not add up to the rows")
    return parts


def _gap_seconds_checked(series: Mapping[str, Any], overall: Mapping[str, Any],
                         parts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The per-second gap statistics and per-partition counts on the series' time
    axis, or BenchmarkError.  Every total is cross-checked; nothing is filled in."""
    start = series.get("start_epoch_s")
    end = series.get("end_epoch_s")
    if start is None or end is None:
        raise BenchmarkError("the run has no time window")
    start, end = _whole_number(start, "start"), _whole_number(end, "end")
    if end < start:
        raise BenchmarkError("the last ingest is before the first span end")
    seconds = end - start + 1
    if seconds > MAX_TIMED_SERIES_SECONDS:
        raise BenchmarkError(f"the window of {seconds} s exceeds the bound of "
                             f"{MAX_TIMED_SERIES_SECONDS} s")
    rows = overall["rows"]
    ingested = series.get("ingested")
    if not isinstance(ingested, list) or len(ingested) != seconds:
        raise BenchmarkError("ingested does not hold one count per second of the window")
    for item in ingested:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise BenchmarkError("ingested holds a value that is not a count")
    if sum(ingested) != rows:
        raise BenchmarkError(f"ingested counts {sum(ingested)} spans, not {rows}")
    first = _whole_number(series.get("first_row_offset"), "first_row_offset")
    if not 0 <= first < seconds or ingested[first] < 1:
        raise BenchmarkError("the first ingested row is outside the window")
    arrays = [series.get(key) for key in ("gap_offsets", "gap_counts", "gap_median_ms",
                                          "gap_max_by_second_ms", "gap_stall_counts")]
    if not all(isinstance(item, list) for item in arrays) or len({len(a) for a in arrays}) != 1:
        raise BenchmarkError("the per-second gap arrays do not match")
    offsets, counts, medians, maxima, stall_counts = arrays
    previous = -1
    for at, count, median, high, stalls in zip(offsets, counts, medians, maxima, stall_counts):
        if isinstance(at, bool) or not isinstance(at, int) or not previous < at < seconds:
            raise BenchmarkError("gap offsets are not increasing seconds of the window")
        previous = at
        expected = ingested[at] - (1 if at == first else 0)
        if _whole_number(count, "gap count") != expected or expected < 1:
            raise BenchmarkError("a second's gap count does not match its ingested rows")
        median, high = _gap_number(median, "median"), _gap_number(high, "maximum")
        if median > high + 1e-6 or high > overall["max"] + 1e-3:
            raise BenchmarkError("a second's gap statistics are inconsistent")
        stalls = _whole_number(stalls, "stall count")
        if not 0 <= stalls <= expected:
            raise BenchmarkError("a second's stall count is outside 0..its gaps")
        if (high > STALL_GAP_MS) != (stalls > 0):
            raise BenchmarkError("a second's stall count does not match its maximum gap "
                                 f"against {STALL_GAP_MS} ms")
    if sum(counts) != overall["gaps"] or sum(stall_counts) != overall["stalls"]:
        raise BenchmarkError("the per-second gaps do not add up to the totals")
    if abs(max(maxima) - overall["max"]) > 1e-3:
        raise BenchmarkError("no second holds the overall maximum gap")
    wanted = sum(1 for at, item in enumerate(ingested) if item - (1 if at == first else 0) > 0)
    if len(offsets) != wanted:
        raise BenchmarkError("gap values are missing for seconds with gaps")
    columns = [0] * seconds
    for part in parts:
        per = part["per_second"]
        if not isinstance(per, list) or len(per) != seconds:
            raise BenchmarkError("a partition lacks one count per second")
        for at, item in enumerate(per):
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise BenchmarkError("a partition holds a value that is not a count")
            columns[at] += item
        if sum(per) != part["rows"]:
            raise BenchmarkError("a partition's seconds do not add up to its rows")
    if columns != ingested:
        raise BenchmarkError("the partitions do not add up to the ingested counts per second")
    return {"start": start, "end": end, "seconds": seconds, "offsets": list(offsets),
            "median": [float(v) for v in medians], "maximum": [float(v) for v in maxima],
            "stalls": list(stall_counts)}


def _diag_ingest_gaps(evidence: "CellEvidence", clock: Mapping[str, Any],
                      clock_valid: Optional[bool]) -> dict[tuple[str, str], Any]:
    """The gaps between consecutive ingests and the partitions' progress (B3J-84).
    The overall gap statistics and the partition totals use only the database's
    own timestamps and counts.  The per-second values sit on the host-aligned time
    axis, so, like the timed series, they are reported only when the clock check
    allows it.  Each part is checked on its own and, when it cannot be, is NOT_MEASURED
    with the reason."""
    overall_spec = (("latency", "ingest_gap_ms_p50", "ms", False),
                    ("latency", "ingest_gap_ms_p90", "ms", False),
                    ("latency", "ingest_gap_ms_p99", "ms", False),
                    ("latency", "ingest_gap_ms_max", "ms", False),
                    ("latency", "ingest_gap_stalls", "gaps", False))
    partition_spec = (("throughput", "partition_rows", "spans", True),
                      ("throughput", "partition_offset_min", "offset", True),
                      ("throughput", "partition_offset_max", "offset", True),
                      ("throughput", "partition_distinct_offsets", "offsets", True))
    second_spec = (("latency", "ingest_gap_series_start_epoch_s", "s", False),
                   ("latency", "ingest_gap_ms_median_by_second", "ms", False),
                   ("latency", "ingest_gap_ms_max_by_second", "ms", False),
                   ("latency", "ingest_gap_stalls_by_second", "gaps", False),
                   ("latency", "ingest_gap_series_offsets_s", "s", False),
                   ("throughput", "partition_ingested_per_second_series", "spans/s", True))
    source = "telemetry_spans.ingested_at (database clock)"

    def missing(spec: Any, reason: str) -> dict[tuple[str, str], Any]:
        return {(sec, name): ({"all": M.not_measured(unit, source, reason).to_dict()} if tree
                              else M.not_measured(unit, source, reason).to_dict())
                for sec, name, unit, tree in spec}

    found: dict[tuple[str, str], Any] = {}
    series = evidence.gap_series
    if series is None:
        reason = "the optional ingest-gap query did not run or failed"
        for spec in (overall_spec, partition_spec, second_spec):
            found.update(missing(spec, reason))
        return found
    db_rows = evidence.database.get("rows") if isinstance(evidence.database, Mapping) else None
    overall: Optional[dict[str, Any]] = None
    parts: Optional[list[dict[str, Any]]] = None
    try:
        overall = _gap_overall_checked(series, db_rows)
        window = None
        method = GAP_METHOD_NOTE + f"; over {overall['gaps']} gaps"
        for name, key in (("ingest_gap_ms_p50", "p50"), ("ingest_gap_ms_p90", "p90"),
                          ("ingest_gap_ms_p99", "p99"), ("ingest_gap_ms_max", "max")):
            found[("latency", name)] = M.Metric(
                overall[key], "ms", "DERIVED", source,
                ("percentile (linear) of the " if key != "max" else "maximum of the ")
                + method, window, overall["gaps"]).to_dict()
        found[("latency", "ingest_gap_stalls")] = M.Metric(
            overall["stalls"], "gaps", "OBSERVATION", source,
            f"gaps longer than {STALL_GAP_MS} ms; " + method, window,
            overall["gaps"]).to_dict()
    except BenchmarkError as exc:
        found.update(missing(overall_spec, str(exc)))
    if overall is not None:
        try:
            parts = _gap_partitions_checked(series, overall["rows"])
            note = ("per Kafka partition, from kafka_partition and kafka_offset; offsets are "
                    "counted, not assumed contiguous (compare rows and distinct offsets with "
                    "max - min + 1)")
            for name, key, unit in (("partition_rows", "rows", "spans"),
                                    ("partition_offset_min", "min", "offset"),
                                    ("partition_offset_max", "max", "offset"),
                                    ("partition_distinct_offsets", "distinct", "offsets")):
                found[("throughput", name)] = {
                    f"p{part['partition']}": M.Metric(
                        part[key], unit, "OBSERVATION", "telemetry_spans.kafka_offset", note,
                        None, part["rows"]).to_dict() for part in parts}
        except BenchmarkError as exc:
            found.update(missing(partition_spec, str(exc)))
    else:
        found.update(missing(partition_spec, "the overall ingest-gap check failed"))
    if overall is None or parts is None:
        found.update(missing(second_spec, "a required ingest-gap check failed"))
        return found
    if clock_valid is not True:
        found.update(missing(second_spec, "clock skew not measured" if clock_valid is None
                             else "clock skew outside its limits: " + "; ".join(clock["reasons"])))
        return found
    try:
        data = _gap_seconds_checked(series, overall, parts)
    except BenchmarkError as exc:
        found.update(missing(second_spec, str(exc)))
        return found
    window = {"start": _iso(data["start"]), "end": _iso(data["end"] + 1), "clock": "host"}
    count = len(data["offsets"])
    where = ("on the axis that starts at ingest_gap_series_start_epoch_s (the whole second of "
             "the earliest span end, as timed_series_start_epoch_s); seconds without a gap are "
             "absent, never 0; offsets in ingest_gap_series_offsets_s; ")
    found[("latency", "ingest_gap_series_start_epoch_s")] = M.Metric(
        data["start"], "s", "OBSERVATION", "telemetry_spans.end_time (host clock)",
        "whole-second epoch of the earliest span end_time of the measured run", window,
        1).to_dict()
    found[("latency", "ingest_gap_ms_median_by_second")] = M.Metric(
        data["median"], "ms", "DERIVED", source, "median gap " + where + GAP_METHOD_NOTE,
        window, count).to_dict()
    found[("latency", "ingest_gap_ms_max_by_second")] = M.Metric(
        data["maximum"], "ms", "DERIVED", source, "maximum gap " + where + GAP_METHOD_NOTE,
        window, count).to_dict()
    found[("latency", "ingest_gap_stalls_by_second")] = M.Metric(
        data["stalls"], "gaps", "OBSERVATION", source,
        f"gaps longer than {STALL_GAP_MS} ms " + where + GAP_METHOD_NOTE, window,
        count).to_dict()
    found[("latency", "ingest_gap_series_offsets_s")] = M.Metric(
        data["offsets"], "s", "OBSERVATION", source,
        "seconds after the series start of each per-second gap value", window, count).to_dict()
    found[("throughput", "partition_ingested_per_second_series")] = {
        f"p{part['partition']}": M.Metric(
            part["per_second"], "spans/s", "OBSERVATION", "telemetry_spans.ingested_at",
            "rows ingested per whole second from this partition, one value per second of the "
            "axis that starts at ingest_gap_series_start_epoch_s, zeros included",
            window, data["seconds"]).to_dict() for part in parts}
    return found


def _diag_cpu(evidence: "CellEvidence") -> dict[tuple[str, str], Any]:
    """The CPU percent of each container from the resource samples the harness
    already took (no new sampling).  A sample or a row that is missing or not a
    plain non-negative number is skipped, never counted as 0."""
    per_container: dict[str, list[tuple[float, float]]] = {}
    taken = 0
    for sample in evidence.resource_samples:
        taken += 1
        try:
            at, rows = sample
            at = float(at)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(at) or not isinstance(rows, (list, tuple)):
            continue
        for row in rows:
            if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
                continue
            value = row.get("cpu_percent")
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(value) or value < 0:
                continue
            per_container.setdefault(row["name"], []).append((at, float(value)))
    names = ("cpu_percent_max", "cpu_percent_series", "cpu_percent_series_times_s")
    if not per_container:
        reason = "no resource samples" if not taken else "no sample held a usable cpu_percent"
        return {("resources", name): {"all": M.not_measured(
            "s" if name.endswith("_s") else "%", "docker stats", reason).to_dict()}
            for name in names}
    maxima: dict[str, Any] = {}
    series: dict[str, Any] = {}
    times: dict[str, Any] = {}
    for name, pairs in sorted(per_container.items()):
        values = [value for _, value in pairs]
        maxima[name] = M.Metric(max(values), "%", "OBSERVATION", "docker stats",
                                "maximum of samples; " + CPU_SERIES_NOTE, None,
                                len(values)).to_dict()
        series[name] = M.Metric(values, "%", "OBSERVATION", "docker stats",
                                "periodic samples in order; a sample without a usable value is "
                                "omitted, never 0; " + CPU_SERIES_NOTE, None,
                                len(values)).to_dict()
        times[name] = M.Metric([round(at, 3) for at, _ in pairs], "s", "OBSERVATION",
                               "harness monotonic clock",
                               "seconds since the samplers started, one per value of "
                               "cpu_percent_series", None, len(pairs)).to_dict()
    return {("resources", "cpu_percent_max"): maxima,
            ("resources", "cpu_percent_series"): series,
            ("resources", "cpu_percent_series_times_s"): times}


HOST_PROCESS_NOTE: str = (
    "a benchmark-owned host process (stream processor or storage consumer); the venv launcher, when "
    "there is one, is a separate entry with the suffix ':launcher' and is never added to its child")


def _host_group(added: dict[tuple[str, str], Any], family: str, extreme: str,
                per_key: Mapping[str, Sequence[tuple[float, float]]], unit: str, source: str,
                what: str, empty_reason: str) -> None:
    """The extreme (max or min), the series and the series times of one family, one entry per key.
    Values are rounded first so the extreme is exactly the extreme of the recorded series."""
    names = (f"{family}_{extreme}", f"{family}_series", f"{family}_series_times_s")
    if not any(per_key.values()):
        for name in names:
            added[("resources", name)] = {"all": M.not_measured(
                "s" if name.endswith("_s") else unit, source, empty_reason).to_dict()}
        return
    extremes: dict[str, Any] = {}
    series: dict[str, Any] = {}
    times: dict[str, Any] = {}
    pick = max if extreme == "max" else min
    for key, pairs in sorted(per_key.items()):
        if not pairs:
            continue
        values = [value for _, value in pairs]
        extremes[key] = M.Metric(pick(values), unit, "OBSERVATION", source,
                                 f"{extreme}imum of samples; {what}", None, len(values)).to_dict()
        series[key] = M.Metric(values, unit, "OBSERVATION", source,
                               f"periodic samples in order; a sample without a usable value is "
                               f"omitted, never 0; {what}", None, len(values)).to_dict()
        times[key] = M.Metric([round(at, 3) for at, _ in pairs], "s", "OBSERVATION",
                              "harness monotonic clock",
                              f"seconds since the samplers started, one per value of {family}_series",
                              None, len(pairs)).to_dict()
    added[("resources", names[0])] = extremes
    added[("resources", names[1])] = series
    added[("resources", names[2])] = times


def _diag_host_resources(evidence: "CellEvidence") -> dict[tuple[str, str], Any]:
    """The host-resource observations (B3J-283) from the samples the host sampler already took.
    Nothing here is read again; an empty dict when no host sampler ran, so a result without them (every
    result before this) keeps exactly its shape."""
    info = evidence.host_resource_info
    if not isinstance(info, Mapping):
        return {}
    samples = list(evidence.host_resource_samples)
    attempted = len(samples)
    cpu: dict[str, list[tuple[float, float]]] = {}
    working: dict[str, list[tuple[float, float]]] = {}
    peaks: dict[str, int] = {}
    counts: dict[str, dict[str, int]] = {key: {"available": 0, "unavailable": 0, "exited": 0}
                                         for key in info.get("keys", ())}
    host_cpu: list[tuple[float, float]] = []
    memory: list[tuple[float, float]] = []
    disk: list[tuple[float, float]] = []
    failed = 0
    last_at = first_at = None

    def usable(value: Any, integer: bool = False) -> bool:
        return (not isinstance(value, bool) and isinstance(value, int if integer else (int, float))
                and math.isfinite(value) and value >= 0)

    for sample in samples:
        try:
            at, snapshot = sample
            at = float(at)
        except (TypeError, ValueError):
            failed += 1
            continue
        if not math.isfinite(at):
            failed += 1
            continue
        first_at = at if first_at is None else first_at
        last_at = at
        if not isinstance(snapshot, Mapping):
            failed += 1
            continue
        for key, row in (snapshot.get("processes") or {}).items():
            if not isinstance(row, Mapping):
                continue
            tally = counts.setdefault(key, {"available": 0, "unavailable": 0, "exited": 0})
            if row.get("status") == "exited":
                tally["exited"] += 1
            elif usable(row.get("working_set_bytes"), integer=True):
                tally["available"] += 1
                working.setdefault(key, []).append((at, int(row["working_set_bytes"])))
                if usable(row.get("peak_working_set_bytes"), integer=True):
                    peaks[key] = max(peaks.get(key, 0), int(row["peak_working_set_bytes"]))
            else:
                tally["unavailable"] += 1
            if usable(row.get("cpu_percent")):
                cpu.setdefault(key, []).append((at, round(float(row["cpu_percent"]), 3)))
        value = snapshot.get("host_cpu_percent")
        if usable(value) and value <= 100.0:
            host_cpu.append((at, round(float(value), 3)))
        if usable(snapshot.get("memory_available_bytes"), integer=True):
            memory.append((at, int(snapshot["memory_available_bytes"])))
        if usable(snapshot.get("disk_free_bytes"), integer=True):
            disk.append((at, int(snapshot["disk_free_bytes"])))

    none = "no host resource samples" if not attempted else "no sample held a usable value"
    process_source = "Windows GetProcessTimes / K32GetProcessMemoryInfo"
    added: dict[tuple[str, str], Any] = {}
    _host_group(added, "host_process_cpu_percent", "max", cpu, "%", process_source,
                "CPU of " + HOST_PROCESS_NOTE + ", as a percent of one core (it can exceed 100): the "
                "change in kernel plus user time between consecutive samples over the time between "
                "them, so the first sample has no value", none)
    _host_group(added, "host_process_working_set_bytes", "max", working, "bytes", process_source,
                "working set (resident memory) of " + HOST_PROCESS_NOTE, none)
    if peaks:
        added[("resources", "host_process_peak_working_set_bytes")] = {
            key: M.Metric(value, "bytes", "OBSERVATION", process_source,
                          "largest PeakWorkingSetSize read, which is the process's peak since it "
                          "started (the warm-up included) of " + HOST_PROCESS_NOTE,
                          None, len(working.get(key, ()))).to_dict()
            for key, value in sorted(peaks.items())}
    else:
        added[("resources", "host_process_peak_working_set_bytes")] = {"all": M.not_measured(
            "bytes", process_source, none).to_dict()}
    _host_group(added, "host_memory_available_bytes", "min", {"host": memory}, "bytes",
                "Windows GlobalMemoryStatusEx",
                "available physical memory of the whole host; the minimum is the smallest headroom "
                "seen between samples", none)
    _host_group(added, "host_cpu_percent", "max", {"host": host_cpu}, "%", "Windows GetSystemTimes",
                "CPU of the whole host over all logical CPUs, 0 to 100: busy time over total time "
                "between consecutive samples, so the first sample has no value", none)
    volume = str(info.get("disk_volume", "unknown"))
    _host_group(added, "disk_free_bytes", "min", {volume: disk}, "bytes", "shutil.disk_usage",
                f"free space of the volume {volume!r} the harness checks before the run; the minimum "
                "is the smallest value seen between samples", none)

    def count(value: int, what: str, unit: str = "samples") -> dict[str, Any]:
        return M.Metric(value, unit, "OBSERVATION", "harness", what, None, attempted).to_dict()

    interval = info.get("interval")
    interval_metric = (M.Metric(float(interval), "s", "OBSERVATION", "harness",
                                "configured sampling interval", None, 1).to_dict()
                       if usable(interval) and interval > 0 else
                       M.not_measured("s", "harness", "the interval was not recorded").to_dict())

    coverage: dict[str, Any] = {
        "samples_attempted": count(attempted, "host resource samples attempted"),
        "samples_failed": count(failed, "samples that failed as a whole (kept as no value, never 0)"),
        "interval_seconds": interval_metric,
        "collection_errors": count(sum(int(v) for v in (info.get("errors") or {}).values()),
                                   "failed individual reads, by kind in the limitations", "reads"),
        "unattributed_descendants": count(int(info.get("unattributed", 0) or 0),
                                          "processes below an owned root that were found and not sampled",
                                          "processes"),
        "host_cpu_samples_available": count(len(host_cpu), "samples with a whole-host CPU value"),
        "host_memory_samples_available": count(len(memory), "samples with an available-memory value"),
        "disk_samples_available": count(len(disk), "samples with a free-disk value"),
        "process_samples_available": {k: count(v["available"], "samples with a working-set value")
                                      for k, v in sorted(counts.items())},
        "process_samples_unavailable": {k: count(v["unavailable"], "samples where the process could not be read")
                                        for k, v in sorted(counts.items())},
        "process_samples_exited": {k: count(v["exited"], "samples taken after the process had exited")
                                   for k, v in sorted(counts.items())},
    }
    if first_at is not None and last_at is not None:
        coverage["first_sample_s"] = M.Metric(round(first_at, 3), "s", "OBSERVATION", "harness monotonic clock",
                                              "seconds since the samplers started, first sample", None, 1).to_dict()
        coverage["last_sample_s"] = M.Metric(round(last_at, 3), "s", "OBSERVATION", "harness monotonic clock",
                                             "seconds since the samplers started, last sample", None, 1).to_dict()
    else:
        coverage["first_sample_s"] = M.not_measured("s", "harness", none).to_dict()
        coverage["last_sample_s"] = M.not_measured("s", "harness", none).to_dict()
    for group in ("process_samples_available", "process_samples_unavailable", "process_samples_exited"):
        if not coverage[group]:
            coverage[group] = {"all": M.not_measured("samples", "harness",
                                                     "no host process was identified").to_dict()}
    added[("resources", "host_sampling_coverage")] = coverage
    return added


# ---------------------------------------------------------------------------
# Host-memory checkpoint (B3J-299): a safety stop between the warm-up and the measured traffic
# ---------------------------------------------------------------------------
#
# This is not one of the post-run resource verdict rules.  It looks at the host's available physical memory
# once the stack is up and warmed, and ends the cell BEFORE any measured traffic when the machine is too low
# on memory to go on.  The cell is already claimed by then, so a stop here spends the repetition (verdict
# STOPPED, through the same controlled-stop and cleanup path as the cell budget).  It is skipped when no
# memory reader is given (older callers, tests, hosts that are not Windows).

#: Provisional: rep9 read 2,975.9 MiB at this boundary and lost a further 300.7 MiB during the measured stage.
HOST_MEMORY_CHECKPOINT_MIN_BYTES: int = 2048 * 1024 ** 2
HOST_MEMORY_CHECKPOINT_READINGS: int = 3
HOST_MEMORY_CHECKPOINT_SPACING_SECONDS: float = 0.25
HOST_MEMORY_OBSERVATION_LABELS: tuple[str, ...] = ("before_startup", "stack_ready")


def read_host_available_memory() -> int:
    """The host's available physical memory in bytes (GlobalMemoryStatusEx, through the same API class the
    host sampler uses).  Raises on any failure.  Tests never call it: they inject a reader."""
    available, _total = WindowsHostResourceApi().memory()
    return available


def _valid_memory_bytes(value: Any) -> Optional[int]:
    """The value when it is a whole, non-negative byte count (not a bool, float, string or None), else None."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def host_memory_checkpoint(read: Callable[[], Any], *, sleep: Callable[[float], None] = time.sleep,
                           threshold: int = HOST_MEMORY_CHECKPOINT_MIN_BYTES,
                           readings: int = HOST_MEMORY_CHECKPOINT_READINGS,
                           spacing: float = HOST_MEMORY_CHECKPOINT_SPACING_SECONDS) -> dict[str, Any]:
    """
    Take `readings` readings of the host's available memory, `spacing` seconds apart, and judge them.
    A reading is valid only as a whole, non-negative byte count; an exception, None, bool, float (NaN and
    infinity included), string or negative number makes that reading unavailable, never 0.

    status  "unavailable"      at least one reading is unavailable (the memory could not be verified)
            "below_threshold"  all are valid and the smallest is below the threshold
            "ok"               all are valid and the smallest is at or above the threshold

    Returns {"readings": [int | None, ...], "minimum": int | None, "threshold": int, "status": str}.  A reader or
    sleep that fails never makes it raise; only an unsupported `readings` (not a whole number of at least 1) does,
    with ValueError, because a count of 0 would leave nothing to judge.
    """
    if isinstance(readings, bool) or not isinstance(readings, int) or readings < 1:
        raise ValueError("the checkpoint needs a whole number of readings, at least 1")
    values: list[Optional[int]] = []
    for index in range(readings):
        if index:
            try:
                sleep(spacing)
            except Exception:  # noqa: BLE001
                pass
        try:
            values.append(_valid_memory_bytes(read()))
        except Exception:  # noqa: BLE001
            values.append(None)
    valid = [v for v in values if v is not None]
    if len(valid) != len(values):
        status, minimum = "unavailable", None
    else:
        minimum = min(valid)
        status = "below_threshold" if minimum < threshold else "ok"
    return {"readings": values, "minimum": minimum, "threshold": int(threshold), "status": status}


#: Added to a cell the checkpoint stopped: the cleanup still copies the consumer's timing summaries, and the
#: consumer ran only during the warm-up.
HOST_MEMORY_CHECKPOINT_WARMUP_ONLY: str = (
    "the cell stopped at the host-memory checkpoint before any measured traffic: the consumer timing sidecar and "
    "the observed commit behaviour in this result, if present, cover the warm-up only and are not measured-stage "
    "throughput")


def host_memory_checkpoint_limitation(outcome: Mapping[str, Any]) -> str:
    """The limitation line of a cell that ran the checkpoint."""
    mib = lambda v: "unavailable" if v is None else f"{v / 1024 ** 2:.1f}"      # noqa: E731
    shown = ", ".join(mib(v) for v in outcome["readings"])
    verdict = {"ok": "passed", "below_threshold": "stopped the cell (below the threshold)",
               "unavailable": "stopped the cell (a reading was unavailable)"}[outcome["status"]]
    return (f"host-memory checkpoint after the warm-up and before the measured run: readings {shown} MiB, "
            f"threshold {outcome['threshold'] / 1024 ** 2:.0f} MiB, {verdict}; it is a safety stop before "
            "measured traffic, separate from the post-run resource rules, and a stop spends the repetition")


def host_memory_checkpoint_stop_reason(outcome: Mapping[str, Any]) -> Optional[str]:
    """The stop reason for a checkpoint outcome, or None when it passed."""
    if outcome["status"] == "unavailable":
        failed = sum(1 for v in outcome["readings"] if v is None)
        return (f"host memory checkpoint: {failed} of {len(outcome['readings'])} readings after the warm-up were "
                "unavailable, so the host's available memory could not be verified")
    if outcome["status"] == "below_threshold":
        return (f"host memory checkpoint: available memory {outcome['minimum'] / 1024 ** 2:.1f} MiB "
                f"({outcome['minimum']} bytes) is below the {outcome['threshold'] / 1024 ** 2:.0f} MiB threshold "
                "after the warm-up and before the measured run")
    return None


DOCKER_RESOURCE_SOURCE = "docker stats"
DOCKER_KEY = "benchmark-containers"
DOCKER_RESOURCE_LIMITATIONS: tuple[str, ...] = (
    "resource-stop semantics differ from SMALL-10 repetition 8 and every earlier cell: the Docker CPU of the "
    "benchmark's containers is added per sampling tick and judged as a percent of the recorded Docker NCPU "
    "(host processes and the host's CPU are not part of it), their reported memory is added per tick and judged "
    "against the recorded Docker MemTotal, and a run whose resource sampling does not cover its window is INVALID",
    "summed Docker container memory is not necessarily the exact physical memory the Docker VM uses, and "
    "sampling about every 10 s (about 12 s observed) cannot see a spike shorter than the interval; "
    "resource stops are still judged only after the measured run",
)


def _docker_resource_view(evidence: "CellEvidence", stops: Mapping[str, Any]) -> dict[str, Any]:
    """What the Docker resource samples say under the B3J-287 rules: the CPU and memory series built from
    complete ticks, their coverage of the sampler's window, the stop reasons they justify and the integrity
    gate.  {"applies": False} when the evidence has no sampler window.  Pure; may raise on malformed samples,
    which the caller turns into a failed gate."""
    window = evidence.resource_window
    if not isinstance(window, Mapping):
        return {"applies": False}
    docker = evidence.machine.get("docker") if isinstance(evidence.machine, Mapping) else None
    docker = docker if isinstance(docker, Mapping) else {}
    ncpu, vm = docker.get("NCPU"), docker.get("MemTotal")
    stop_s, interval, expected = window.get("stop_s"), window.get("interval_s"), window.get("expected_containers")
    expected_ok = isinstance(expected, int) and not isinstance(expected, bool) and expected > 0
    vm_ok = isinstance(vm, int) and not isinstance(vm, bool) and vm > 0
    samples = list(evidence.resource_samples)
    cpu = M.docker_vm_cpu_series(samples, expected_containers=expected if expected_ok else -1, ncpu=ncpu)
    memory = M.docker_memory_ticks(samples, expected_containers=expected if expected_ok else -1)
    cpu_pairs = [(at, round(value, 3)) for at, value in cpu if value is not None]
    memory_pairs = [(at, aggregate) for at, aggregate, _ in memory if aggregate is not None] if vm_ok else []
    lower_only = sum(1 for _, aggregate, bound in memory if aggregate is None and bound is not None)
    failed = sum(1 for _, rows in samples if not isinstance(rows, (list, tuple)))
    cpu_cov = M.usable_coverage([at for at, _ in cpu_pairs], window_seconds=stop_s, interval=interval)
    mem_cov = M.usable_coverage([at for at, _ in memory_pairs], window_seconds=stop_s, interval=interval)
    problems: list[str] = []
    if not expected_ok:
        problems.append("the number of benchmark containers is unknown")
    if not (isinstance(ncpu, int) and not isinstance(ncpu, bool) and ncpu > 0):
        problems.append("cpu: the Docker NCPU was not recorded")
    if not vm_ok:
        problems.append("memory: the Docker MemTotal was not recorded")
    problems += [f"cpu: {text}" for text in cpu_cov.problems]
    problems += [f"memory: {text}" for text in mem_cov.problems]
    reasons: list[str] = []
    interval_ok = isinstance(interval, (int, float)) and not isinstance(interval, bool) and interval > 0
    if interval_ok:
        span = M.sustained_cpu_saturation(
            cpu, percent=stops["cpu_saturation_percent"], seconds=stops["cpu_saturation_seconds"],
            max_gap_seconds=M.DOCKER_CPU_GAP_FACTOR * interval)
        if span is not None:
            reasons.append(f"Docker container CPU at or above {stops['cpu_saturation_percent']}% of {ncpu} "
                           f"CPUs for {span:.0f} s")
    reasons.extend(M.docker_memory_stops(memory, vm_bytes=vm, memory_fraction=stops["memory_fraction"]))
    if problems:
        text = "; ".join(problems)
    else:
        text = (f"cpu: {cpu_cov.usable} usable ticks, {cpu_cov.fraction:.0%} of the window, longest gap "
                f"{cpu_cov.max_gap:.1f} s; memory: {mem_cov.usable} usable ticks, {mem_cov.fraction:.0%}, "
                f"longest gap {mem_cov.max_gap:.1f} s")
    return {"applies": True, "gate": {"name": "docker resource coverage", "ok": not problems, "evidence": text},
            "stop_reasons": reasons, "cpu": cpu_pairs, "memory": memory_pairs, "vm_bytes": vm if vm_ok else None,
            "ncpu": ncpu, "expected": expected, "window": stop_s, "interval": interval, "attempted": len(samples),
            "failed": failed, "lower_only": lower_only, "cpu_coverage": cpu_cov, "memory_coverage": mem_cov}


def _docker_resource_view_safe(evidence: "CellEvidence", stops: Mapping[str, Any]) -> dict[str, Any]:
    """_docker_resource_view that fails closed: malformed samples give a failed gate, not an exception."""
    try:
        return _docker_resource_view(evidence, stops)
    except Exception as exc:  # noqa: BLE001
        return {"applies": True, "error": type(exc).__name__, "stop_reasons": [],
                "gate": {"name": "docker resource coverage", "ok": False,
                         "evidence": f"the resource samples could not be evaluated ({type(exc).__name__})"}}


def _diag_docker_resources(view: Mapping[str, Any]) -> dict[tuple[str, str], Any]:
    """The Docker resource observations of the view as metrics (see metrics.docker_resource_problems).
    Empty when the rules did not apply or could not be evaluated."""
    if not view.get("applies") or "error" in view:
        return {}
    attempted = int(view["attempted"])
    none = "no Docker resource samples" if not attempted else "no complete tick held a usable value"
    added: dict[tuple[str, str], Any] = {}
    _host_group(added, "docker_vm_cpu_percent", "max", {DOCKER_KEY: view["cpu"]}, "%", DOCKER_RESOURCE_SOURCE,
                f"CPU of the benchmark's containers, each a percent of one core, added over a complete tick "
                f"and divided by the Docker NCPU ({view['ncpu']}), so 100 is every CPU of the Docker VM; host "
                "processes are not included", none)
    _host_group(added, "docker_memory_aggregate_bytes", "max", {DOCKER_KEY: view["memory"]}, "bytes",
                DOCKER_RESOURCE_SOURCE,
                "memory the benchmark's containers report, added over a complete tick (one moment, never a sum "
                "of separate peaks); not necessarily the exact physical memory the Docker VM uses", none)
    if view["memory"] and view["vm_bytes"]:
        peak = max(value for _, value in view["memory"])
        added[("resources", "docker_memory_aggregate_fraction_max")] = {DOCKER_KEY: M.Metric(
            peak / view["vm_bytes"], "fraction", "OBSERVATION", DOCKER_RESOURCE_SOURCE,
            f"largest complete-tick aggregate over the recorded Docker MemTotal ({view['vm_bytes']} bytes)",
            None, len(view["memory"])).to_dict()}
    else:
        added[("resources", "docker_memory_aggregate_fraction_max")] = {"all": M.not_measured(
            "fraction", DOCKER_RESOURCE_SOURCE, none).to_dict()}

    def count(value: int, unit: str, what: str) -> dict[str, Any]:
        return M.Metric(value, unit, "OBSERVATION", "harness", what, None, max(attempted, 1)).to_dict()

    def seconds(value: Optional[float], what: str, unit: str = "s") -> dict[str, Any]:
        if value is None:
            return M.not_measured(unit, "harness", none).to_dict()
        return M.Metric(round(float(value), 3), unit, "OBSERVATION", "harness monotonic clock", what, None,
                        max(attempted, 1)).to_dict()

    cpu_cov, mem_cov = view["cpu_coverage"], view["memory_coverage"]
    coverage: dict[str, Any] = {
        "expected_containers": count(int(view["expected"]), "containers", "benchmark containers in each complete tick"),
        "ncpu": count(int(view["ncpu"]), "cpus", "recorded Docker NCPU, the CPU denominator"),
        "vm_memory_bytes": (count(int(view["vm_bytes"]), "bytes", "recorded Docker MemTotal, the memory denominator")
                            if view["vm_bytes"] else M.not_measured("bytes", "harness", "MemTotal was not recorded").to_dict()),
        "ticks_attempted": count(attempted, "ticks", "docker stats samples attempted"),
        "ticks_failed": count(int(view["failed"]), "ticks", "samples that failed as a whole (no rows, never 0)"),
        "cpu_ticks_usable": count(len(view["cpu"]), "ticks", "complete ticks with every CPU value"),
        "memory_ticks_usable": count(len(view["memory"]), "ticks", "complete ticks with every memory value"),
        "memory_ticks_lower_bound_only": count(int(view["lower_only"]), "ticks",
                                               "incomplete ticks that gave only a lower bound"),
        "window_seconds": seconds(view["window"], "the sampler's window, from its start to its stop"),
        "interval_seconds": seconds(view["interval"], "configured sampling interval"),
        "cpu_first_usable_s": seconds(cpu_cov.first, "first usable CPU tick"),
        "cpu_last_usable_s": seconds(cpu_cov.last, "last usable CPU tick"),
        "cpu_max_gap_s": seconds(cpu_cov.max_gap, "longest gap between usable CPU ticks"),
        "cpu_window_fraction": seconds(cpu_cov.fraction, "(last - first usable CPU tick) / window", "fraction"),
        "memory_first_usable_s": seconds(mem_cov.first, "first usable memory tick"),
        "memory_last_usable_s": seconds(mem_cov.last, "last usable memory tick"),
        "memory_max_gap_s": seconds(mem_cov.max_gap, "longest gap between usable memory ticks"),
        "memory_window_fraction": seconds(mem_cov.fraction, "(last - first usable memory tick) / window", "fraction"),
    }
    added[("resources", "docker_resource_coverage")] = coverage
    return added


def _diag_host_memory_checkpoint(evidence: "CellEvidence") -> dict[tuple[str, str], Any]:
    """The checkpoint and the observation-only memory readings as metrics (see
    metrics.host_memory_checkpoint_problems).  Empty when neither was taken, so an older cell keeps its shape."""
    checkpoint = evidence.host_memory_checkpoint
    observed = evidence.host_memory_observations
    if not isinstance(checkpoint, Mapping) and not observed:
        return {}
    source = "Windows GlobalMemoryStatusEx"
    leaves: dict[str, Any] = {}
    for label in HOST_MEMORY_OBSERVATION_LABELS:
        if label not in observed:
            continue
        value = _valid_memory_bytes(observed[label])
        leaves[label] = (M.Metric(value, "bytes", "OBSERVATION", source,
                                  f"available physical memory read once, {label.replace('_', ' ')}; "
                                  "observation only, it never stops a run", None, 1).to_dict()
                         if value is not None else
                         M.not_measured("bytes", source, "the reading was unavailable").to_dict())
    added: dict[tuple[str, str], Any] = {}
    if isinstance(checkpoint, Mapping):
        valid = [v for v in checkpoint["readings"] if v is not None]
        taken = len(checkpoint["readings"])
        leaves["after_warmup"] = (M.Metric(valid, "bytes", "OBSERVATION", source,
                                           f"the valid readings of {taken} taken about "
                                           f"{HOST_MEMORY_CHECKPOINT_SPACING_SECONDS:g} s apart after the warm-up "
                                           "and before the measured run, in order", None, len(valid)).to_dict()
                                  if valid else
                                  M.not_measured("bytes", source, "no reading was available").to_dict())
        added[("resources", "host_memory_checkpoint_minimum_bytes")] = {"after_warmup": (
            M.Metric(checkpoint["minimum"], "bytes", "OBSERVATION", source,
                     "the smallest of the checkpoint readings, which is what the threshold judges",
                     None, len(valid)).to_dict() if checkpoint["minimum"] is not None else
            M.not_measured("bytes", source, "a reading was unavailable, so no minimum was formed").to_dict())}
        added[("resources", "host_memory_checkpoint_threshold_bytes")] = {"after_warmup": M.Metric(
            int(checkpoint["threshold"]), "bytes", "OBSERVATION", "harness configuration",
            "the checkpoint stops the cell when the smallest reading is below this; equal passes",
            None, 1).to_dict()}
        added[("resources", "host_memory_checkpoint_unavailable_readings")] = {"after_warmup": M.Metric(
            taken - len(valid), "readings", "OBSERVATION", "harness",
            "checkpoint readings that failed or were malformed (never counted as 0)", None, taken).to_dict()}
    added[("resources", "host_memory_checkpoint_bytes")] = leaves
    return added


def host_resource_limitations(evidence: "CellEvidence") -> list[str]:
    """The limitation lines of a cell that sampled host resources: what was added, and any bounded
    problem it had.  Empty when no host sampler ran."""
    info = evidence.host_resource_info
    if not isinstance(info, Mapping):
        return []
    lines = [
        f"host resource observations were sampled every {info.get('interval', 0):g} s during the measured "
        "stage in addition to the Docker container metrics: the benchmark-owned storage consumer and "
        "stream processor (CPU and working set), host available memory, whole-host CPU and free disk "
        "space; cells run before this instrumentation recorded Docker resources only, and the added "
        "sampling is a small extra load whose effect was not measured"]
    errors = info.get("errors") or {}
    if errors:
        text = ", ".join(f"{label} x{count}" for label, count in sorted(errors.items()))
        lines.append(f"host resource sampling had {sum(errors.values())} failed reads ({text}); "
                     "a failed read is recorded as unavailable, never as 0")
    if info.get("stop_problem"):
        lines.append(f"host resource sampler stop problem: {info['stop_problem']}")
    return lines


def _check_diagnostic_tree(node: Any, path: str) -> None:
    """Raises unless node is a metric or a non-empty mapping of them."""
    if isinstance(node, Mapping) and "kind" in node:
        M.check_metric(node, path)
        return
    if not isinstance(node, Mapping) or not node:
        raise BenchmarkError(f"{path}: not a metric tree")
    for key, child in node.items():
        _check_diagnostic_tree(child, f"{path}.{key}")


def _add_diagnostics(metrics: dict[str, Any], limitations: list[str],
                     builders: Sequence[tuple[str, Callable[[], dict[tuple[str, str], Any]]]]
                     ) -> None:
    """Adds each optional diagnostic to metrics.  Each one is built and
    validated on its own; one that cannot be is left out and noted in the
    limitations.  It never changes or replaces an existing metric, and the
    required metrics and the result's own validation are not touched."""
    for label, build in builders:
        try:
            added = build()
            for (section, name), leaf in added.items():
                if name in metrics[section]:
                    raise BenchmarkError(f"metrics.{section}.{name} already exists")
                _check_diagnostic_tree(leaf, f"metrics.{section}.{name}")
        except Exception as exc:
            limitations.append(f"diagnostic {label} not recorded: {type(exc).__name__}")
            continue
        for (section, name), leaf in added.items():
            metrics[section][name] = leaf


def _host_interrupted(evidence: "CellEvidence") -> bool:
    return isinstance(evidence.host, Mapping) and evidence.host.get("host_interruption_suspected") is True


def consumer_evidence(evidence: "CellEvidence") -> dict[str, Any]:
    """The storage consumer configuration of the cell.  `commit_batching` and the timing interval
    are what was CONFIGURED; `observed` (only when timing windows were captured) is what was
    MEASURED, and is omitted rather than invented when there is nothing to measure."""
    batch = evidence.consumer_batch_messages
    block: dict[str, Any] = {
        "commit_batching": {
            "enabled": batch > 1, "batch_messages": batch,
            "interval_seconds": evidence.consumer_commit_interval_seconds if batch > 1 else None},
        "timing_diagnostic_interval_seconds": float(evidence.consumer_timing_interval_seconds),
    }
    if evidence.consumer_observed is not None:
        block["observed"] = dict(evidence.consumer_observed)
    return block


def _memory_observations(samples: Sequence[Any]) -> list[tuple[str, int, Optional[int]]]:
    """(container, used bytes, limit bytes or None) for every row of the Docker samples that holds a valid
    name and a valid memory reading.  Valid: a non-empty name; a whole, non-negative `memory_used_bytes` that is
    not a bool; a positive whole `memory_limit_bytes`, else the limit is None (the row is then not judged
    against a limit).  A failed sample, a row that is not a mapping, and any missing, negative, NaN, infinite,
    string or otherwise malformed value is skipped as unavailable, never read as 0."""
    found: list[tuple[str, int, Optional[int]]] = []
    for sample in samples:
        try:
            _, rows = sample
        except (TypeError, ValueError):
            continue
        if not isinstance(rows, (list, tuple)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            name, used, limit = row.get("name"), row.get("memory_used_bytes"), row.get("memory_limit_bytes")
            if not isinstance(name, str) or not name.strip():
                continue
            if isinstance(used, bool) or not isinstance(used, int) or used < 0:
                continue
            valid_limit = None if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0 else limit
            found.append((name, used, valid_limit))
    return found


def assemble_result(evidence: CellEvidence, stops: Mapping[str, Any]) -> dict[str, Any]:
    """
    The result of one cell from its evidence.  Pure: what is missing is
    NOT_MEASURED with a reason; the verdict follows from the integrity gates,
    the stop rules and the load-source check, in that order.
    """
    cell, driver, db = evidence.cell, evidence.driver, evidence.database
    limitations = list(evidence.limitations)
    window_driver = window_db = None
    if driver is not None:
        window_driver = {"start": driver["started"], "end": driver["finished"], "clock": "driver"}
    if db is not None and db.get("first_ingested") is not None:
        window_db = {"start": _iso(db["first_ingested"]), "end": _iso(db["last_ingested"]),
                     "clock": "database"}

    # -- counts ---------------------------------------------------------------
    def count_or_missing(value: Optional[int], source: str, reason: str) -> Any:
        return value if value is not None else M.not_measured("spans", source, reason).to_dict()

    counts: dict[str, Any] = {
        "planned_spans": cell.planned_spans,
        "spans_ended": count_or_missing(_get(driver, "spans_ended"), "driver report",
                                        "the measured run did not produce a driver report"),
        "spans_exported": count_or_missing(_get(driver, "spans_exported_successfully"),
                                           "driver report", "no driver report"),
        "raw_records": count_or_missing(evidence.raw_records, "raw topic offsets",
                                        "raw topic offsets were not read"),
        "canonical_records": count_or_missing(evidence.canonical_records,
                                              "canonical topic offsets",
                                              "canonical topic offsets were not read"),
        "dlq_records": count_or_missing(evidence.dlq_records, "DLQ offsets",
                                        "DLQ offsets were not read"),
        "rows_stored": count_or_missing(_get(db, "rows"), "telemetry_spans",
                                        "the database was not read"),
        "distinct_spans": count_or_missing(_get(db, "distinct_spans"), "telemetry_spans",
                                           "the database was not read"),
    }

    # -- integrity ------------------------------------------------------------
    docker_view = _docker_resource_view_safe(evidence, stops)         # B3J-287; {"applies": False} for older evidence
    gates: list[dict[str, Any]] = []
    integrity_ok: Optional[bool]
    db_complete = db is not None and all(
        db.get(key) is not None for key in ("rows", "distinct_spans", "roots"))
    driver_complete = driver is not None and all(
        driver.get(key) is not None for key in ("spans_ended", "spans_exported_successfully"))
    needed = (evidence.canonical_records, evidence.dlq_records)
    if not (db_complete and driver_complete) or any(item is None for item in needed):
        integrity_ok = None
        gates.append({"name": "evidence complete", "ok": False,
                      "evidence": "driver report, offsets or database counts missing"})
        if evidence.failure is not None:
            gates.append({"name": "run completed", "ok": False, "evidence": evidence.failure})
        if docker_view["applies"]:
            gates.append(docker_view["gate"])
    else:
        rec = M.reconcile(
            planned_spans=cell.planned_spans, spans_ended=driver["spans_ended"],
            spans_exported=driver["spans_exported_successfully"],
            canonical_records=evidence.canonical_records, rows_stored=db["rows"],
            distinct_span_keys=db["distinct_spans"], dlq_records=evidence.dlq_records,
        )
        for name, found, expected, ok in rec.checks:
            gates.append({"name": name, "ok": ok, "evidence": f"{found} (expected {expected})"})
        gates.append({"name": "no missing spans", "ok": rec.missing == 0,
                      "evidence": f"missing {rec.missing}"})
        gates.append({"name": "no duplicate spans", "ok": rec.duplicates == 0,
                      "evidence": f"duplicates {rec.duplicates}"})
        gates.append({"name": "driver exit and status",
                      "ok": driver.get("run_status") == "completed"
                      and driver.get("export_failures") == 0 and driver.get("flush_ok") is True
                      and not driver.get("problems"),
                      "evidence": f"status {driver.get('run_status')}, export failures "
                                  f"{driver.get('export_failures')}, flush "
                                  f"{driver.get('flush_ok')}, problems "
                                  f"{len(driver.get('problems') or [])}"})
        gates.append({"name": "roots = requests", "ok": db.get("roots") == cell.requests,
                      "evidence": f"{db.get('roots')} (expected {cell.requests})"})
        gates.append({"name": "host processes alive", "ok": not evidence.process_exits,
                      "evidence": "; ".join(evidence.process_exits) or "none exited"})
        gates.append({"name": "run completed", "ok": evidence.failure is None,
                      "evidence": evidence.failure or "no failure"})
        if docker_view["applies"]:
            gates.append(docker_view["gate"])
        integrity_ok = all(g["ok"] for g in gates)

    # -- clock ----------------------------------------------------------------
    clock: dict[str, Any]
    clock_valid: Optional[bool] = None
    if evidence.clock_before and evidence.clock_after:
        check = M.clock_check(evidence.clock_before, evidence.clock_after,
                              max_uncertainty_ms=stops["skew_uncertainty_ms"],
                              max_drift_ms=stops["skew_drift_ms"])
        clock, clock_valid = check.to_dict(), check.valid
    else:
        clock = M.not_measured("ms", "clock probe",
                               "no clock samples before and after the run").to_dict()

    # -- metrics --------------------------------------------------------------
    metrics: dict[str, Any] = {"throughput": {}, "latency": {}, "lag": {}, "resources": {},
                               "analytics": {}}
    if driver is not None and driver.get("elapsed_seconds", 0) > 0:
        elapsed = driver["elapsed_seconds"]
        metrics["throughput"]["requests_per_second"] = M.Metric(
            M.rate(driver["executed_attempts"], elapsed), "requests/s", "DERIVED",
            "driver report", "executed attempts / driver elapsed", window_driver,
            driver["executed_attempts"]).to_dict()
        metrics["throughput"]["spans_generated_per_second"] = M.Metric(
            M.rate(driver["spans_ended"], elapsed), "spans/s", "DERIVED", "driver report",
            "spans ended / driver elapsed", window_driver, driver["spans_ended"]).to_dict()
    else:
        for name, unit in (("requests_per_second", "requests/s"),
                           ("spans_generated_per_second", "spans/s")):
            metrics["throughput"][name] = M.not_measured(
                unit, "driver report", "no driver report with a positive elapsed time").to_dict()
    metrics["throughput"]["spans_persisted_per_second"] = _persisted_rate(db, window_db)

    request_ms = list(db.get("request_ms") or []) if db is not None else []
    metrics["latency"]["request_ms"] = {
        k: v.to_dict() for k, v in M.latency_metrics(
            request_ms, unit="ms", kind="MEASURED", source="root span duration_ms",
            method="root span end - start (host clock); includes the planned simulated waits",
            window=window_db, reason_if_empty="no root spans read").items()}
    persistence_ms = list(db.get("persistence_ms") or []) if db is not None else []
    if clock_valid is True:
        metrics["latency"]["persistence_ms"] = {
            k: v.to_dict() for k, v in M.latency_metrics(
                persistence_ms, unit="ms", kind="DERIVED",
                source="ingested_at (database clock) - end_time (host clock)",
                method="per span; includes the driver's export batching delay (up to "
                       "500 ms); valid only within the recorded clock skew",
                window=window_db, reason_if_empty="no spans read").items()}
    else:
        reason = ("clock skew not measured" if clock_valid is None
                  else "clock skew outside its limits: " + "; ".join(clock["reasons"]))
        metrics["latency"]["persistence_ms"] = {
            f"p{q}": M.not_measured("ms", "ingested_at - end_time", reason).to_dict()
            for q in M.PERCENTILES}

    lag_values = [v for _, v in evidence.lag_samples]
    if lag_values and any(v is not None for v in lag_values):
        for group in ("raw", "canonical"):
            series = [v.get(group) if isinstance(v, Mapping) else None for v in lag_values]
            known = [s for s in series if s is not None]
            metrics["lag"][f"{group}_max"] = (M.Metric(
                max(known), "records", "OBSERVATION", "kafka-consumer-groups",
                "maximum of periodic samples", None, len(known)).to_dict() if known else
                M.not_measured("records", "kafka-consumer-groups",
                               "every sample failed").to_dict())
    else:
        for group in ("raw", "canonical"):
            metrics["lag"][f"{group}_max"] = M.not_measured(
                "records", "kafka-consumer-groups", "no lag samples taken").to_dict()
    tail = (evidence.stage_tail_seconds if evidence.stage_tail_seconds is not None
            else evidence.drain_seconds)
    metrics["lag"]["stage_tail_seconds"] = (M.Metric(
        tail, "s", "OBSERVATION", "harness wall clock", STAGE_TAIL_METHOD, None, 1).to_dict()
        if tail is not None else
        M.not_measured("s", "harness wall clock",
                       "the measured stage did not return").to_dict())
    metrics["lag"]["drain_seconds"] = M.not_measured(
        "s", "run_smoke.run_stage",
        "the frozen harness does not expose an isolated drain duration; see "
        "stage_tail_seconds").to_dict()
    metrics["scheduler"], scheduler_evidence = _scheduler(driver)

    memory_peaks: dict[str, int] = {}
    memory_counts: dict[str, int] = {}
    for name, used, _ in _memory_observations(evidence.resource_samples):
        memory_peaks[name] = max(memory_peaks.get(name, 0), used)
        memory_counts[name] = memory_counts.get(name, 0) + 1
    metrics["resources"]["memory_peak_bytes"] = (
        {name: M.Metric(value, "bytes", "OBSERVATION", "docker stats", "maximum of samples",
                        None, memory_counts[name]).to_dict()
         for name, value in sorted(memory_peaks.items())}
        or {"all": M.not_measured(
            "bytes", "docker stats",
            "no resource samples" if not evidence.resource_samples
            else "no sample held a valid memory reading").to_dict()})

    if not cell.refresh_and_detector:
        reason = f"not run at level {cell.level}"
        metrics["analytics"]["refresh_seconds"] = M.not_measured("s", "dbt", reason).to_dict()
        metrics["analytics"]["detector_ms"] = M.not_measured("ms", "detector", reason).to_dict()
    else:
        metrics["analytics"]["refresh_seconds"] = (M.Metric(
            evidence.refresh_seconds, "s", "OBSERVATION", "harness wall clock",
            "around `run --rm analytics-refresh`, container start included", None, 1).to_dict()
            if evidence.refresh_seconds is not None else
            M.not_measured("s", "harness wall clock", "the refresh did not run").to_dict())
        metrics["analytics"]["refresh_dbt_seconds"] = (M.Metric(
            evidence.refresh_dbt_seconds, "s", "MEASURED", "dbt output",
            "dbt 'Finished running ... in X seconds'", None, 1).to_dict()
            if evidence.refresh_dbt_seconds is not None else
            M.not_measured("s", "dbt output",
                           "dbt's own duration did not appear in the refresh output").to_dict())
        metrics["analytics"]["detector_ms"] = (
            {group: M.Metric(value, "ms", "MEASURED", "detector log", "duration_ms per group",
                             None, 1).to_dict()
             for group, value in sorted(evidence.detector_ms.items())}
            if evidence.detector_ms else
            M.not_measured("ms", "detector log", "detector durations not read").to_dict())
    metrics["analytics"]["detection_latency"] = M.not_measured(
        "s", "anomaly_events", "batch detector: detected_at - event_time reflects when the "
        "detector was run, not detector speed").to_dict()
    metrics["throughput"]["otlp_export_latency"] = M.not_measured(
        "ms", "exporter", "export calls are not timed in this version").to_dict()
    _add_diagnostics(metrics, limitations, (
        ("lag series", lambda: _diag_lag_series(evidence)),
        ("sampler start", lambda: _diag_sampler_start(evidence)),
        ("ingestion series", lambda: _diag_ingest_series(db, window_db)),
        ("persistence maximum",
         lambda: _diag_persistence_max(persistence_ms, window_db, clock, clock_valid)),
        ("detector counts", lambda: _diag_detector_counts(evidence)),
        ("timed series", lambda: _diag_timed_series(evidence, clock, clock_valid)),
        ("ingest gaps", lambda: _diag_ingest_gaps(evidence, clock, clock_valid)),
        ("cpu series", lambda: _diag_cpu(evidence)),
        ("host resources", lambda: _diag_host_resources(evidence)),
        ("docker resources", lambda: _diag_docker_resources(docker_view)),
        ("host memory checkpoint", lambda: _diag_host_memory_checkpoint(evidence))))

    # -- stop rules and verdict -------------------------------------------------
    stop_reasons = list(evidence.stop_reasons)
    canonical_lag = [v.get("canonical") if isinstance(v, Mapping) else None
                     for v in lag_values]
    raw_lag = [v.get("raw") if isinstance(v, Mapping) else None for v in lag_values]
    for name, series in (("raw", raw_lag), ("canonical", canonical_lag)):
        if M.lag_growing(series, run=int(stops["lag_growth_samples"])):
            stop_reasons.append(f"{name} lag grew across {stops['lag_growth_samples']} samples")
    memory = [M.MemorySample(name, used, limit)           # only readings that can be judged: valid used, valid limit
              for name, used, limit in _memory_observations(evidence.resource_samples) if limit is not None]
    for reason in M.resource_stops(
            memory=memory, disk_free_bytes=evidence.disk_free_bytes,
            projected_need_bytes=evidence.projected_need_bytes,
            memory_fraction=stops["memory_fraction"],
            disk_free_min_bytes=int(stops["disk_free_min_gb"] * 1024 ** 3),
            disk_projection_factor=stops["disk_projection_factor"]):
        if reason not in stop_reasons:
            stop_reasons.append(reason)
    for reason in docker_view.get("stop_reasons", ()):      # measured violations keep STOPPED semantics
        if reason not in stop_reasons:
            stop_reasons.append(reason)
    if docker_view["applies"]:
        limitations.extend(DOCKER_RESOURCE_LIMITATIONS)
    if evidence.cleanup_verified is False and "cleanup not verified" not in stop_reasons:
        stop_reasons.append("cleanup not verified")
    # The scheduler's own evidence decides whether the load source was the
    # limit; the achieved throughput (wall time includes the final flush)
    # is reported but never used for this.
    bound, bound_reasons = generator_bound_from_evidence(
        scheduler_evidence, late_fraction=stops["late_start_fraction"],
        lag_growth_samples=int(stops["lag_growth_samples"]))
    scheduler_evidence["late_fraction"] = stops["late_start_fraction"]
    scheduler_evidence["lag_growth_samples"] = int(stops["lag_growth_samples"])
    scheduler_evidence["generator_bound"] = bound
    if scheduler_evidence["evaluated"]:
        limitations.append("start lag is available only as a maximum and a mean; the "
                           "growing-start-lag rule had no series to judge")
    else:
        limitations.append("generator-bound check not evaluated: the driver report lacks "
                           + ", ".join(scheduler_evidence["missing"] or ["a report"]))
    value = M.verdict(integrity_ok=integrity_ok, stop_reasons=stop_reasons,
                      generator_bound_run=bound)
    if value == "GENERATOR_BOUND":
        limitations.append("GENERATOR_BOUND: these numbers describe the load source, not "
                           "the platform's capacity")
    limitations.append("one machine, one Docker Desktop VM; results describe this setup only")
    result = {
        "benchmark_id": cell.benchmark_id,
        "git_sha": evidence.git_sha,
        "git_dirty": evidence.git_dirty,
        "timestamps": {"started": _iso(evidence.started), "finished": _iso(evidence.finished)},
        "machine": evidence.machine,
        "workload": {"target": cell.target()},
        "counts": counts,
        "metrics": metrics,
        "clock": clock,
        "integrity": {"ok": integrity_ok, "gates": gates},
        "verdict": value,
        "verdict_reasons": list(bound_reasons) + stop_reasons,
        "stop": {"reasons": stop_reasons, "generator_bound": bound,
                 "generator_bound_evidence": scheduler_evidence},
        "claims": M.claim_eligibility(value, clock_valid, _host_interrupted(evidence)),
        "limitations": limitations,
        "consumer": consumer_evidence(evidence),
    }
    if evidence.host is not None:
        result["host"] = json.loads(json.dumps(evidence.host))
    M.validate_result(result)
    return result


def write_result(result: Mapping[str, Any], output_dir: Path) -> Path:
    """Write one result as JSON to a NEW file outside the repository."""
    output_dir = Path(output_dir).resolve()
    if output_dir == REPO or REPO in output_dir.parents:
        raise BenchmarkError("results are never written inside the repository")
    M.validate_result(result)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = result["timestamps"]["finished"].replace(":", "").replace("-", "")[:15]
    path = output_dir / f"{result['benchmark_id']}-{stamp}.json"
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path


# ---------------------------------------------------------------------------
# Live execution (disabled in this version)
# ---------------------------------------------------------------------------

def _require_live() -> None:
    if not LIVE_ENABLED:
        raise LiveDisabled(
            "live benchmark execution is not enabled in this version; nothing was started")


#: A rough planning budget per span for disk: the stored row with its
#: indexes, the raw and canonical topic records and the collector's debug
#: log line.  Used only for the preflight stop rule, never reported.
DISK_BUDGET_PER_SPAN_BYTES: int = 16 * 1024
#: Fixed disk the cell needs whatever its size: images, the temporary
#: environment, the empty database and broker.
DISK_FIXED_BYTES: int = 3 * 1024 ** 3
#: Written to the output directory when a cell's cleanup could not be
#: verified.  While it exists no further live cell starts.
CLEANUP_MARKER: str = "CLEANUP_UNVERIFIED"
REFRESH_TIMEOUT_SECONDS: float = 600.0


class _Stop(BenchmarkError):
    """A stop rule fired; the cell ends as STOPPED with these reasons."""

    def __init__(self, reasons: Sequence[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


def projected_need_bytes(cell: Cell) -> int:
    spans = (cell.warmup_requests + cell.requests) * M.SPANS_PER_HEALTHY_REQUEST
    return DISK_FIXED_BYTES + spans * DISK_BUDGET_PER_SPAN_BYTES


def _parse_time(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def run_cell(cell: Cell, ladder: Mapping[str, Any], *, expect_head: Optional[str],
             output_dir: Path,
             keep_awake: Optional[Mapping[str, Any]] = None) -> tuple[dict[str, Any], Path, bool]:
    """
    One cell on a fresh isolated stack, for real.  Refused unless live
    execution is enabled; the D3 harness and the E2E helpers are imported
    only after that check.
    """
    _require_live()
    if not is_approved_live_cell(cell):
        raise BenchmarkError(f"{cell.benchmark_id} is not an approved live cell")
    if not cell.live_allowed:
        raise BenchmarkError(f"level {cell.level} is not allowed live")
    check_effective_config(cell, ladder)
    if str(REPO / "workload-generator") not in sys.path:
        sys.path.insert(0, str(REPO / "workload-generator"))
    import run_e2e as e2e  # noqa: E402  imported only here, never at module load
    import run_smoke as smoke  # noqa: E402

    return execute_cell(cell, ladder, smoke=smoke, e2e=e2e, expect_head=expect_head,
                        output_dir=output_dir, keep_awake=keep_awake, disk_free=_live_disk_free,
                        host_resources=lambda **kw: make_host_resource_sampler(
                            disk_volume=_live_disk_volume(), **kw),
                        host_memory=read_host_available_memory if _is_windows() else None)


def _live_disk_volume() -> str:
    """The volume whose free space the harness checks (and the host sampler records)."""
    return REPO.anchor or "/"


def _live_disk_free() -> int:
    import shutil
    return shutil.disk_usage(_live_disk_volume()).free


def execute_cell(
    cell: Cell, ladder: Mapping[str, Any], *, smoke: Any, e2e: Any,
    expect_head: Optional[str], output_dir: Path, disk_free: Callable[[], int],
    clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
    sampler_factory: Callable[..., Any] = None,
    keep_awake: Optional[Mapping[str, Any]] = None,
    host_resources: Optional[Callable[..., Any]] = None,
    host_memory: Optional[Callable[[], Any]] = None,
    host_memory_sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, Any], Path, bool]:
    """
    The body of one cell, with the harness passed in (the real run_smoke
    and run_e2e modules when live; fakes in the offline tests).

    Order: preflight -> stack -> warm-up (excluded) -> clock probe ->
    samplers on -> measured run (exact D3 reconciliation and drain) ->
    samplers off -> offsets, driver report, database, clock probe ->
    [analytics refresh, detector] -> cleanup (always) -> result written
    outside the repository.  Nothing is retried.  Returns the result, its
    path and whether cleanup was verified.
    """
    defaults, stops = ladder["defaults"], ladder["stop_limits"]
    make_sampler = PeriodicSampler if sampler_factory is None else sampler_factory
    smoke.RATE, smoke.SEED, smoke.CONCURRENCY = cell.rate, cell.seed, cell.concurrency
    smoke.T_DRAIN = float(defaults["drain_limit_seconds"])
    smoke.SETTLE_SECONDS = float(defaults["settle_seconds"])
    # Consumer timing is on only for a cell named in DIAGNOSTIC_TIMING_CELLS (none today)
    # and is always set explicitly, so no other cell can inherit it.
    timing_interval = timing_interval_for(cell.benchmark_id)
    timing_enabled = timing_interval > 0
    smoke.CONSUMER_TIMING_INTERVAL = timing_interval
    # Commit batching is likewise always set explicitly: N=1 unless the cell is approved for more.
    batch_messages, commit_interval = commit_batching_for(cell.benchmark_id)
    smoke.CONSUMER_COMMIT_BATCH_MESSAGES = batch_messages
    smoke.CONSUMER_COMMIT_INTERVAL_SECONDS = 1.0 if commit_interval is None else commit_interval
    budget, start = float(defaults["cell_budget_seconds"]), clock()
    evidence = CellEvidence(cell=cell, git_sha="0" * 40, git_dirty=True, started=wall(),
                            finished=wall())
    host_session_start: Optional[dict[str, Any]] = None
    if _is_windows():  # read-only; never raises; the start of the cell's host observation
        try:
            host_session_start = session_state()
        except Exception:  # noqa: BLE001
            host_session_start = None
    evidence.consumer_batch_messages = batch_messages
    evidence.consumer_commit_interval_seconds = commit_interval
    evidence.consumer_timing_interval_seconds = timing_interval
    if batch_messages > 1:
        evidence.limitations.append(
            f"storage consumer offset commits were batched ({batch_messages} messages or "
            f"{commit_interval:g} s): a lag sample includes processed messages whose offsets were not "
            "yet committed, and throughput is not comparable with cells that committed every message")
    if cell.benchmark_id in CELL_LIMITATIONS:
        evidence.limitations.append(CELL_LIMITATIONS[cell.benchmark_id])
    samplers: list[Any] = []
    expected_containers: Optional[int] = None      # B3J-287: how many containers each complete tick holds
    host_sampler: Optional[Any] = None       # B3J-283: optional; never one of `samplers` (indexed below)
    host_stop_problem: Optional[str] = None
    refresh_built = False
    capture = ((lambda: capture_consumer_timing(smoke, output_dir, cell, evidence))
               if timing_enabled else None)
    if timing_enabled:  # recorded whether or not the sidecar is later captured
        evidence.limitations.append(
            f"diagnostic cell: storage consumer timing was enabled at {timing_interval:g} "
            "seconds; the consumer ran with timing instrumentation")

    def within_budget(step: str) -> None:
        if clock() - start > budget:
            raise _Stop([f"cell budget of {budget:.0f} s exceeded before {step}"])

    def observe_memory(label: str) -> None:
        """One observation-only reading of the host's available memory (B3J-299); it never stops a run."""
        if host_memory is None:
            return
        try:
            evidence.host_memory_observations[label] = _valid_memory_bytes(host_memory())
        except Exception:  # noqa: BLE001
            evidence.host_memory_observations[label] = None

    try:
        evidence.git_sha = smoke.git("rev-parse", "HEAD").strip()
        evidence.git_dirty = bool(smoke.repository_state())
        smoke.check_repository(expect_head)
        evidence.disk_free_bytes = int(disk_free())
        evidence.projected_need_bytes = projected_need_bytes(cell)
        preflight = M.resource_stops(
            disk_free_bytes=evidence.disk_free_bytes,
            projected_need_bytes=evidence.projected_need_bytes,
            disk_free_min_bytes=int(stops["disk_free_min_gb"] * 1024 ** 3),
            disk_projection_factor=stops["disk_projection_factor"])
        if preflight:
            raise _Stop(["preflight: " + reason for reason in preflight])
        smoke.check_ports()
        smoke.record_docker_state()
        evidence.machine = collect_machine_baseline(
            lambda command: smoke.checked(list(command), timeout=smoke.T_COMMAND,
                                          what=command[0]),
            platform_info=local_platform_info())
        note = comparability_limitation(cell.benchmark_id, evidence.machine)
        if note:
            evidence.limitations.append(note)
        observe_memory("before_startup")
        smoke.create_workspace()
        smoke.create_virtual_environment()
        smoke.check_render()
        within_budget("the stack")
        smoke.start_kafka()
        smoke.create_topics()
        smoke.start_postgres()
        smoke.run_bootstrap()
        if cell.refresh_and_detector:
            refresh_built = True  # set first: a failed build may still leave an image
            e2e.build_refresh_image()
        smoke.start_collector()
        smoke.start_host_services()
        offsets = smoke.check_baseline()
        observe_memory("stack_ready")
        within_budget("the warm-up run")
        offsets = smoke.run_stage(_stage(smoke, cell, warmup=True), offsets)
        if host_memory is not None:     # the safety checkpoint: after the warm-up, before any measured traffic
            outcome = host_memory_checkpoint(host_memory, sleep=host_memory_sleep)
            evidence.host_memory_checkpoint = outcome       # stored first, so an early stop keeps it
            evidence.limitations.append(host_memory_checkpoint_limitation(outcome))
            reason = host_memory_checkpoint_stop_reason(outcome)
            if reason is not None:
                evidence.limitations.append(HOST_MEMORY_CHECKPOINT_WARMUP_ONLY)
                raise _Stop([reason])
        within_budget("the measured run")
        evidence.clock_before = _clock(smoke)
        ids = [line for line in smoke.compose("ps", "-q").split() if line.strip()]
        if not ids:
            raise BenchmarkError("no container of the isolated project is running")
        expected_containers = len(ids)
        lag = make_sampler(lambda: {
            "raw": smoke.group_lag(smoke.GROUP_STREAM, smoke.TOPIC_RAW),
            "canonical": smoke.group_lag(smoke.GROUP_STORAGE, smoke.TOPIC_SPANS)},
            defaults["sample_interval_seconds"])
        resources = make_sampler(lambda: parse_docker_stats(smoke.checked(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}", *ids],
            timeout=smoke.T_COMMAND, what="docker stats")), defaults["sample_interval_seconds"])
        samplers = [lag, resources]
        evidence.sampler_started = wall()            # diagnostic only: aligns the series times
        for sampler in samplers:
            sampler.start()
        if host_resources is not None:   # optional: its failure is recorded and never fails the cell
            try:
                host_sampler = host_resources(processes=getattr(smoke.RUN, "processes", {}) or {},
                                              disk_free=disk_free,
                                              interval=defaults["sample_interval_seconds"])
                if host_sampler is not None:
                    host_sampler.start()
            except Exception as exc:  # noqa: BLE001
                evidence.limitations.append(
                    f"host resource sampling was not started: {type(exc).__name__}")
        before = dict(offsets)
        after = smoke.run_stage(_stage(smoke, cell, warmup=False), offsets)
        stage_end = wall()
        for sampler in samplers:
            sampler.stop()
        if host_sampler is not None:     # a stop that fails is reported here and again by the cleanup
            try:
                host_sampler.stop()
            except Exception as exc:  # noqa: BLE001
                host_stop_problem = f"{type(exc).__name__}: {exc}"[:200]
        evidence.canonical_records = after[smoke.TOPIC_SPANS] - before[smoke.TOPIC_SPANS]
        evidence.raw_records = after[smoke.TOPIC_RAW] - before[smoke.TOPIC_RAW]
        evidence.dlq_records = after[smoke.TOPIC_DLQ] - before[smoke.TOPIC_DLQ]
        report = json.loads((Path(smoke.RUN.temp) / f"{cell.measured_run_id}.json").read_text(
            encoding="utf-8"))
        evidence.driver = report["execution"]
        tail = stage_end - _parse_time(evidence.driver["finished"])
        evidence.stage_tail_seconds = tail if tail >= 0 else None
        evidence.database = json.loads(smoke.psql(run_metrics_sql(cell.measured_run_id)))
        evidence.clock_after = _clock(smoke)
        try:   # optional (B3J-68): read once, after the run; its failure never fails the cell
            evidence.timed_series = json.loads(smoke.psql(run_series_sql(cell.measured_run_id)))
        except Exception as exc:
            evidence.limitations.append(
                f"diagnostic timed series query not recorded: {type(exc).__name__}")
        try:   # optional (B3J-84): also read once, after the run; never fails the cell
            evidence.gap_series = json.loads(smoke.psql(run_gap_sql(cell.measured_run_id)))
        except Exception as exc:
            evidence.limitations.append(
                f"diagnostic ingest gap query not recorded: {type(exc).__name__}")
        smoke.check_host_processes()
        if cell.refresh_and_detector:
            within_budget("the analytics refresh")
            ledger = e2e.ledger_fingerprint()
            started = clock()
            refresh = smoke.run(e2e.refresh_command("run", "--rm", "-T", e2e.REFRESH_SERVICE),
                                timeout=REFRESH_TIMEOUT_SECONDS, what="analytics refresh")
            elapsed = clock() - started
            if refresh.returncode != 0:
                raise BenchmarkError(f"the analytics refresh failed (exit {refresh.returncode})")
            if e2e.ledger_fingerprint() != ledger:
                raise BenchmarkError("the analytics refresh changed the bootstrap ledger")
            evidence.refresh_seconds = elapsed
            evidence.refresh_dbt_seconds = parse_dbt_seconds(refresh.stdout + refresh.stderr)
            within_budget("the detector")
            groups, _summary = e2e.run_detector("benchmark")
            evidence.detector_ms = {
                f"{g['signal_path']}/{g['operation_name']}": float(g["duration_ms"])
                for g in groups if g.get("duration_ms") is not None}
            evidence.detector_counts = detector_counts_from_groups(groups)   # never raises
        smoke.check_normal_stack("after the cell")
    except _Stop as stop:
        evidence.stop_reasons = list(evidence.stop_reasons) + stop.reasons
    except Exception as exc:  # recorded as evidence; the cell is never retried
        evidence.failure = f"{type(exc).__name__}: {exc}"
    finally:
        clean = _cleanup(smoke, e2e, [*samplers, *([host_sampler] if host_sampler is not None else [])],
                         refresh_built, evidence, capture)
    evidence.lag_samples = list(samplers[0].samples) if samplers else []
    evidence.resource_samples = list(samplers[1].samples) if len(samplers) > 1 else []
    window = getattr(samplers[1], "window", None) if len(samplers) > 1 else None
    if window is not None and expected_containers:     # the real sampler's own start and stop, not sample endpoints
        evidence.resource_window = {"stop_s": float(window[1]),
                                    "interval_s": float(defaults["sample_interval_seconds"]),
                                    "expected_containers": expected_containers}
    if host_sampler is not None:
        try:   # read after the cleanup and unable to affect it
            evidence.host_resource_samples = list(host_sampler.samples)
            evidence.host_resource_info = {
                "interval": float(defaults["sample_interval_seconds"]),
                "disk_volume": host_sampler.collector.disk_volume,
                "keys": host_sampler.collector.keys, "errors": dict(host_sampler.collector.errors),
                "unattributed": host_sampler.collector.unattributed, "stop_problem": host_stop_problem}
            evidence.limitations.extend(host_resource_limitations(evidence))
        except Exception as exc:  # noqa: BLE001
            evidence.host_resource_samples, evidence.host_resource_info = [], None
            evidence.limitations.append(f"host resource observations could not be assembled ({type(exc).__name__})")
    evidence.finished = wall()
    evidence.cleanup_verified = clean
    try:  # after the cleanup, and unable to affect it, the result or the ledger
        evidence.host = collect_host_evidence(started=evidence.started, finished=evidence.finished,
                                              keep_awake=keep_awake, session_start=host_session_start)
        evidence.limitations.extend(host_limitations(evidence.host))
    except Exception as exc:  # noqa: BLE001
        evidence.host = None
        evidence.limitations.append(f"host diagnostics could not be assembled ({type(exc).__name__})")
    if cell.refresh_and_detector is False:
        evidence.limitations.append(f"no analytics refresh or detector at level {cell.level}")
    evidence.limitations.append("resource and lag stops are judged after the measured run; "
                                "a running stage is never interrupted")
    result = assemble_result(evidence, stops)
    path = write_result(result, output_dir)
    if not clean:
        _mark_cleanup_unverified(output_dir, cell)
    return result, path, clean


#: Cells that also record the storage consumer timing summaries: SMALL-10 rep5 (consumed), its
#: replacement rep6, and the N=100 commit batching diagnostics rep7, rep8 and rep9.  A diagnostic cell is added here in a reviewed change, together with its entries in
#: APPROVED_LIVE_CELLS and APPROVED_DIAGNOSTIC_INTERVALS (a live run is refused unless
#: the last agrees with this set); being listed here does not authorize a cell.
DIAGNOSTIC_TIMING_CELLS: frozenset[str] = frozenset({"bm-small-r0010-c32-rep5",
                                                     "bm-small-r0010-c32-rep6",
                                                     "bm-small-r0010-c32-rep7",
                                                     "bm-small-r0010-c32-rep8",
                                                     "bm-small-r0010-c32-rep9"})
#: Seconds between the consumer summaries in a diagnostic cell.
DIAGNOSTIC_TIMING_INTERVAL_SECONDS: float = 5.0
#: The exact prefix of a timing line in the consumer log (storage-consumer/timing.py).
CONSUMER_TIMING_PREFIX: str = "storage-consumer timing "
MAX_TIMING_LINES: int = 5000
_TIMING_TOP = frozenset({"kind", "elapsed_s", "start_epoch_s", "end_epoch_s", "bounds_ms",
                         "counters", "stages"})
_TIMING_COUNTERS = frozenset({"messages", "idle_polls", "inserted", "conflicts"})
_TIMING_STAGES = frozenset({"poll", "decode_validate", "insert_txn", "kafka_commit", "cycle"})
_TIMING_STAGE_KEYS = frozenset({"count", "total_ms", "mean_ms", "max_ms", "hist"})


def _plain_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) \
        and math.isfinite(value)


def _timing_summary_ok(data: Any) -> bool:
    """A consumer timing summary holds only numbers under the known names; anything
    else (an unknown key, a string value) is refused, so nothing but timing is copied."""
    if not isinstance(data, dict) or set(data) != _TIMING_TOP:
        return False
    if data["kind"] not in ("window", "final"):
        return False
    if not all(_plain_number(data[k]) for k in ("elapsed_s", "start_epoch_s", "end_epoch_s")):
        return False
    bounds = data["bounds_ms"]
    if not isinstance(bounds, list) or len(bounds) > 32 or not all(map(_plain_number, bounds)):
        return False
    counters = data["counters"]
    if not isinstance(counters, dict) or set(counters) != _TIMING_COUNTERS \
            or not all(_plain_number(v) and v >= 0 for v in counters.values()):
        return False
    stages = data["stages"]
    if not isinstance(stages, dict) or set(stages) != _TIMING_STAGES:
        return False
    for stage in stages.values():
        if not isinstance(stage, dict) or set(stage) != _TIMING_STAGE_KEYS:
            return False
        if not all(_plain_number(stage[k]) for k in ("count", "total_ms", "mean_ms", "max_ms")):
            return False
        hist = stage["hist"]
        if not isinstance(hist, list) or len(hist) > 33 or not all(map(_plain_number, hist)):
            return False
    return True


def consumer_timing_lines(log_text: str) -> tuple[list[str], int]:
    """The timing summaries in a consumer log, as canonical lines, and the number of
    lines that carried the prefix but were not a valid summary (skipped).  Lines
    without the exact prefix are ignored and never copied."""
    kept: list[str] = []
    malformed = 0
    for line in log_text.splitlines():
        if not line.startswith(CONSUMER_TIMING_PREFIX):
            continue
        try:
            data = json.loads(line[len(CONSUMER_TIMING_PREFIX):])
        except ValueError:
            malformed += 1
            continue
        if not _timing_summary_ok(data) or len(kept) >= MAX_TIMING_LINES:
            malformed += 1
            continue
        kept.append(CONSUMER_TIMING_PREFIX + json.dumps(data, sort_keys=True,
                                                         separators=(",", ":")))
    return kept, malformed


def _exclusive_text(path: Path, text: str) -> None:
    """Create path with text, whole or not at all, never replacing a file (the same
    temporary-file-and-link write as _exclusive_json)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(temp, "x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, path)
    finally:
        try:
            temp.unlink()
        except OSError:
            pass


def observed_commit_behavior(lines: Sequence[str]) -> Optional[dict[str, Any]]:
    """Measured commit behavior from the consumer's periodic timing windows, or None when there is
    nothing to measure.  Only windows count (a final summary would repeat them); a window or stage
    that is missing or malformed is skipped, never inferred."""
    windows = commits = messages = 0
    elapsed = commit_ms = 0.0
    for line in lines:
        try:
            text = line[len(CONSUMER_TIMING_PREFIX):] if line.startswith(CONSUMER_TIMING_PREFIX) else line
            record = json.loads(text)
            if record.get("kind") != "window":
                continue
            stage, counters = record["stages"]["kafka_commit"], record["counters"]
            calls, took = int(stage["count"]), float(stage["total_ms"])
            seen, span = int(counters["messages"]), float(record["elapsed_s"])
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        windows += 1
        commits, messages, elapsed, commit_ms = commits + calls, messages + seen, elapsed + span, commit_ms + took
    if windows == 0:
        return None
    return {"windows": windows, "window_seconds": round(elapsed, 3), "messages": messages,
            "commit_calls": commits,
            "mean_messages_per_commit": round(messages / commits, 3) if commits else None,
            "mean_seconds_between_commits": round(elapsed / commits, 4) if commits else None,
            "mean_commit_ms": round(commit_ms / commits, 3) if commits else None}


def capture_consumer_timing(smoke: Any, output_dir: Path, cell: Cell,
                            evidence: "CellEvidence") -> None:
    """
    Diagnostic cells only.  Copy the storage consumer timing summaries out of its
    temporary log, before that log is deleted, into
    <output dir>/<benchmark id>-consumer-timing.jsonl (one summary per line, exclusive
    creation).  Best effort: it never raises, never changes a verdict, and always leaves
    one limitation in the result saying what was and was not captured.  The consumer is
    stopped by force, so its final summary and the last partial window are not expected.
    """
    label = "consumer timing sidecar"
    try:
        try:
            text = smoke.read_log("storage-consumer")
        except (KeyError, OSError, AttributeError):
            evidence.limitations.append(f"{label} NOT captured: the consumer log was not available")
            return
        lines, malformed = consumer_timing_lines(text)
        skipped = f"; {malformed} malformed timing line(s) skipped" if malformed else ""
        if not lines:
            evidence.limitations.append(
                f"{label} NOT captured: the consumer log held no timing summary{skipped}")
            return
        path = _outside_repository(output_dir) / f"{cell.benchmark_id}-consumer-timing.jsonl"
        _exclusive_text(path, "\n".join(lines) + "\n")
        windows = sum(1 for line in lines if '"kind":"window"' in line)
        evidence.consumer_observed = observed_commit_behavior(lines)
        evidence.limitations.append(
            f"{label} written: {path.name}, {len(lines)} summaries ({windows} windows); "
            f"periodic windows only, the final summary and the last partial window are lost "
            f"when the consumer is stopped by force{skipped}")
    except FileExistsError:
        evidence.limitations.append(f"{label} NOT written: the file already exists and is "
                                    "never replaced")
    except Exception as exc:  # diagnostics never change the outcome of the cell
        evidence.limitations.append(f"{label} NOT captured: {type(exc).__name__}")


def _cleanup(smoke: Any, e2e: Any, samplers: Sequence[Any], refresh_built: bool,
             evidence: CellEvidence, capture: Optional[Callable[[], None]] = None) -> bool:
    """Samplers, host processes, the diagnostic timing capture (when there is one), the
    refresh profile, then the stack.  Every step runs even when an earlier one fails;
    True only if all succeeded and the harness verified the stack is gone and the normal
    stack unchanged.  The capture runs after the host processes stop and before the
    harness deletes their logs; it cannot fail the cleanup."""
    ok = True
    for step, action in (
        ("samplers", lambda: [sampler.stop() for sampler in samplers]),
        ("host processes", smoke.stop_host_processes),
        ("consumer timing capture", capture if capture is not None else (lambda: None)),
        ("refresh profile", e2e.remove_profile_resources if refresh_built else (lambda: None)),
    ):
        try:
            action()
        except Exception as exc:
            ok = False
            evidence.limitations.append(f"cleanup step {step} failed: {type(exc).__name__}")
    try:
        verified = smoke.cleanup() is True
    except Exception as exc:
        verified = False
        evidence.limitations.append(f"cleanup failed: {type(exc).__name__}")
    return ok and verified


def _mark_cleanup_unverified(output_dir: Path, cell: Cell) -> None:
    output_dir = Path(output_dir).resolve()
    if output_dir == REPO or REPO in output_dir.parents:
        raise BenchmarkError("results are never written inside the repository")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / CLEANUP_MARKER).write_text(
        f"cleanup of {cell.benchmark_id} was not verified; inspect Docker and delete this "
        "file before the next live run\n", encoding="utf-8")


def _stage(smoke: Any, cell: Cell, *, warmup: bool) -> Any:
    requests = cell.warmup_requests if warmup else cell.requests
    run_id = cell.warmup_run_id if warmup else cell.measured_run_id
    seconds = max(60, int(math.ceil(requests / cell.rate)) * 2)
    planned = smoke.planned_facts(smoke.Stage(
        run_id=run_id, scenario="normal", traces=requests, max_duration=seconds,
        digest_prefix="", successes=requests, failures=0, failing_indexes=(),
        spans=requests * 7, trace_sizes={"7": requests}, status={"UNSET": requests * 7},
        error_spans={}, error_types={}, scenario_roots={"normal": requests}))
    return smoke.Stage(
        run_id=run_id, scenario="normal", traces=requests, max_duration=seconds,
        digest_prefix=planned["digest"], successes=requests, failures=0, failing_indexes=(),
        spans=requests * 7, trace_sizes={"7": requests}, status={"UNSET": requests * 7},
        error_spans={}, error_types={}, scenario_roots={"normal": requests})


def _clock(smoke: Any) -> list[M.ClockSample]:
    output = smoke.checked(
        [str(smoke.RUN.python), "-c", clock_probe_code(10)], timeout=smoke.T_COMMAND,
        what="clock probe",
        env=smoke.host_environment(PGHOST="127.0.0.1", PGPORT=str(smoke.POSTGRES_PORT),
                                   PGDATABASE="agentops", PGUSER="agentops",
                                   PGPASSWORD=smoke.RUN.generated["POSTGRES_PASSWORD"]))
    return parse_clock_samples(output)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

LEDGER_DIR: str = "ledger"
#: Held by the one benchmark run that owns the output directory.
OWNER_FILE: str = "ACTIVE_RUN"
INTENDED_STATUS_NOTE: str = ("the status this program intends to return; the operating "
                             "system's exit code is recorded by the launcher, not here")


def _outside_repository(output_dir: Path) -> Path:
    output_dir = Path(output_dir).resolve()
    if output_dir == REPO or REPO in output_dir.parents:
        raise BenchmarkError("the ledger and results are never written inside the repository")
    return output_dir


def _exclusive_json(path: Path, payload: Mapping[str, Any]) -> str:
    """Create path with payload, complete or not at all; FileExistsError if it exists,
    and an existing file is never replaced.  The payload is written durably to a private
    temporary file first and then hard-linked into place, so a failure part-way can never
    leave a partial record under the real name.  Returns the text written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(temp, "x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, path)
    finally:
        try:
            temp.unlink()
        except OSError:
            pass
    return text


def _release_own_ownership(owner: Path, written: Optional[str]) -> None:
    """Remove the ownership file only when it still holds exactly what this call wrote."""
    try:
        if written is not None and owner.read_text(encoding="utf-8") == written:
            owner.unlink()
    except OSError:
        pass


def claim_run(
    output_dir: Path, cell: Cell, *, head: str, arguments: Mapping[str, Any],
    binding: Optional[Mapping[str, Any]] = None,
    now: Callable[[], float] = time.time, pid: Callable[[], int] = os.getpid,
) -> Path:
    """
    Take ownership of the output directory and record that this cell has
    started, before anything is imported or started.

    Refused when another run owns the directory (or an earlier one never
    released it), when a result for the cell exists, when the cell was
    started before, or when a record cannot be created.  Returns the
    ledger's .started path.  Nothing here is ever deleted automatically,
    except an ownership taken a moment ago by this call when the cell is
    then refused before its record exists (nothing has started at that
    point); that ownership is removed only if it still holds what this call
    wrote.  A record is created whole or not at all (see _exclusive_json).

    With a binding (branch, ladder_sha256, config_path, effective_config) the record is a
    schema-2 record: the verified head, the approved ladder hash, the effective
    configuration, the run identity and the output directory are written into it, and it
    is validated before it is written and read back and compared after.  Without one the
    record has the historical format.
    """
    output_dir = _outside_repository(output_dir)
    owner = output_dir / OWNER_FILE
    record = {"benchmark_id": cell.benchmark_id, "git_head": head, "pid": pid(),
              "started_utc": _iso(now()), "arguments": dict(arguments)}
    if binding is not None:
        record.update({
            "schema": MARKER_SCHEMA, "nonce": uuid.uuid4().hex, "verified_head": head,
            "branch": binding["branch"], "ladder_sha256": binding["ladder_sha256"],
            "config_path": binding["config_path"], "output_dir": str(output_dir),
            "effective_config": binding["effective_config"]})
        problems = validate_marker(record, cell, output_dir)
        if problems:
            raise BenchmarkError("the claim record is inconsistent (nothing was created): "
                                 + "; ".join(problems))
    try:
        written = _exclusive_json(owner, record)
    except FileExistsError:
        raise BenchmarkError(f"{owner} exists: another benchmark owns this output directory, "
                             "or an earlier run did not release it; review it") from None
    except OSError as exc:
        raise BenchmarkError(f"cannot create {owner}: {type(exc).__name__}") from None
    linked = False
    try:
        existing = sorted(output_dir.glob(f"{cell.benchmark_id}-*.json"))
        if existing:
            raise BenchmarkError(f"a result for {cell.benchmark_id} already exists "
                                 f"({existing[0].name})")
        started = output_dir / LEDGER_DIR / f"{cell.benchmark_id}.started"
        try:
            _exclusive_json(started, record)
            linked = True
        except FileExistsError:
            raise BenchmarkError(f"{started} exists: {cell.benchmark_id} was started "
                                 "before; review it") from None
        except OSError as exc:
            raise BenchmarkError(f"cannot create {started}: {type(exc).__name__}") from None
        if binding is not None:
            try:
                stored = json.loads(started.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                stored = None
            problems = validate_marker(stored, cell, output_dir)
            if stored != record:
                problems.append("the stored record differs from the one written")
            if problems:
                raise BenchmarkError(f"the stored claim record is inconsistent; {started} and "
                                     "the ownership are kept for review: " + "; ".join(problems))
    except BaseException:
        if not linked:
            _release_own_ownership(owner, written)  # taken by this call; nothing has started
        raise
    return started


def finish_run(
    output_dir: Path, cell: Cell, *, result: Mapping[str, Any], result_path: Path,
    cleanup_verified: bool, intended_status: int, now: Callable[[], float] = time.time,
) -> bool:
    """
    Record the cell as done (.done: result path and SHA-256, verdict,
    cleanup verification, intended status) and release ownership, but only
    when cleanup was verified.  Returns whether ownership was released.  If
    recording fails the exception propagates and ownership is kept.
    """
    output_dir = _outside_repository(output_dir)
    digest = hashlib.sha256(Path(result_path).read_bytes()).hexdigest()
    _exclusive_json(output_dir / LEDGER_DIR / f"{cell.benchmark_id}.done", {
        "benchmark_id": cell.benchmark_id, "result_path": str(result_path),
        "result_sha256": digest, "verdict": result["verdict"],
        "cleanup_verified": cleanup_verified, "intended_return_status": intended_status,
        "intended_return_status_note": INTENDED_STATUS_NOTE, "finished_utc": _iso(now()),
    })
    if not cleanup_verified:
        return False
    (output_dir / OWNER_FILE).unlink()
    return True


def _plan_text(cells: Sequence[Cell], output_dir: Path) -> str:
    lines = ["PLAN ONLY - nothing was started, nothing was sent.",
             f"results would be written to: {output_dir}"]
    if (output_dir / CLEANUP_MARKER).exists():
        lines.append(f"WARNING: {CLEANUP_MARKER} is present there; live runs are blocked")
    for cell in cells:
        lines.append(
            f"{cell.benchmark_id}: {cell.requests} requests ({cell.planned_spans} spans) at "
            f"{cell.rate}/s, concurrency {cell.concurrency}, measured "
            f"{cell.measured_seconds:.0f} s, warm-up {cell.warmup_requests} requests; run ids "
            f"{cell.warmup_run_id} / {cell.measured_run_id}; live allowed "
            f"{'yes' if cell.live_allowed else 'no'}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None, *, stdout: Any = None) -> int:
    out = sys.stdout if stdout is None else stdout
    parser = argparse.ArgumentParser(
        prog="run_benchmark",
        description="Pipeline benchmark on a disposable stack. Without --live it only plans.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), metavar="PATH")
    parser.add_argument("--level", required=True, choices=[name for name, _ in M.LEVELS])
    parser.add_argument("--rate", type=int, action="append", default=None,
                        help="one of the level's rates; repeat for several (default: all)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--repetitions", type=int, default=None)
    group.add_argument("--repetition", type=int, default=None, metavar="N",
                       help="plan only repetition N (1-10); required with --live")
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT), metavar="DIR")
    parser.add_argument("--warmup-requests", type=int, default=None, metavar="N",
                        help="warm-up requests per cell (default: rate x the ladder's "
                             "warmup_seconds)")
    parser.add_argument("--expect-head", default=None, metavar="COMMIT")
    parser.add_argument("--authorize", default=None, metavar="BENCHMARK_ID",
                        help="with --live: the approved cell's id")
    parser.add_argument("--live", action="store_true",
                        help="run the approved cell for real (disabled in this version)")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir).resolve()
    if output_dir == REPO or REPO in output_dir.parents:
        parser.error("--output-dir must be outside the repository")
    try:
        ladder, ladder_sha256 = read_ladder(Path(args.config))
        cells = plan_cells(ladder, args.level, rates=args.rate, repetitions=args.repetitions,
                           concurrency=args.concurrency, warmup_requests=args.warmup_requests,
                           repetition=args.repetition)
    except BenchmarkError as exc:
        parser.error(str(exc))

    if not args.live:
        if args.authorize is not None:
            parser.error("--authorize is only used with --live")
        out.write(_plan_text(cells, output_dir))
        return 0
    # The fail-closed gate first, then the exact-cell authorization; both
    # before anything is imported or started.
    try:
        _require_live()
    except LiveDisabled as exc:
        sys.stderr.write(f"run_benchmark: error: {exc}\n")
        return 2
    # 2. the exact approved cell; 3. the approved configuration and its effective values;
    # 4. the canonical output directory; 5. the cleanup marker and existing evidence;
    # 6. the actual repository state.  Nothing is created before all of them hold.
    try:
        cell = check_live_authorization(cells, authorize=args.authorize,
                                        expect_head=args.expect_head,
                                        warmup_requests=args.warmup_requests,
                                        repetition=args.repetition)
        if ladder_sha256 != APPROVED_LADDER_SHA256:
            raise BenchmarkError(f"the configuration's SHA-256 {ladder_sha256} is not the "
                                 f"approved ladder's {APPROVED_LADDER_SHA256}")
        effective = check_effective_config(cell, ladder)
        output_dir = check_live_output_dir(output_dir)
    except BenchmarkError as exc:
        sys.stderr.write(f"run_benchmark: error: {exc}; nothing was started\n")
        return 2
    if (output_dir / CLEANUP_MARKER).exists():  # pragma: no cover - live only
        sys.stderr.write(f"run_benchmark: error: {output_dir / CLEANUP_MARKER} exists: an "
                         "earlier cleanup was not verified; nothing was started\n")
        return 2
    try:
        check_no_prior_evidence(output_dir, cell)
        verified = verify_repository_readonly(args.expect_head)
    except BenchmarkError as exc:
        sys.stderr.write(f"run_benchmark: error: {exc}; nothing was started\n")
        return 2
    # Before the claim and before anything is started: ask Windows to stay awake.  A refusal
    # ends the run here, like every other refusal, so no repetition is consumed.
    keep_awake = KeepAwake()
    try:
        keep_awake.acquire()
    except BenchmarkError as exc:
        sys.stderr.write(f"run_benchmark: error: {exc}; nothing was started\n")
        return 2
    out.write(f"keep-awake: {keep_awake.describe()}\n")
    try:
        try:
            claim_run(output_dir, cell, head=verified["head"], arguments={
                "level": args.level, "rate": args.rate, "repetition": args.repetition,
                "concurrency": args.concurrency, "warmup_requests": args.warmup_requests,
                "authorize": args.authorize, "expect_head": args.expect_head,
                "output_dir": str(output_dir), "live": True},
                binding={"branch": verified["branch"], "ladder_sha256": ladder_sha256,
                         "config_path": str(Path(args.config).resolve()),
                         "effective_config": effective})
        except BenchmarkError as exc:
            sys.stderr.write(f"run_benchmark: error: {exc}; nothing was started\n")
            return 2
        try:
            result, path, clean = run_cell(
                cell, ladder, expect_head=args.expect_head, output_dir=output_dir,
                keep_awake={"acquisition": keep_awake.acquisition, "readback": keep_awake.readback})
        except BaseException:
            sys.stderr.write("run_benchmark: the cell did not complete; the ownership and ledger "
                             "records are kept for review\n")
            raise
        status = 0 if clean and result["verdict"] == "VALID" else 1
        try:
            released = finish_run(output_dir, cell, result=result, result_path=path,
                                  cleanup_verified=clean, intended_status=status)
        except Exception as exc:
            sys.stderr.write(f"run_benchmark: error: could not record completion "
                             f"({type(exc).__name__}); ownership is kept\n")
            return 1
        out.write(f"{cell.benchmark_id}: {result['verdict']} -> {path}\n")
        if not clean:
            out.write("stopping: cleanup was not verified; ownership is kept\n")
        elif not released:  # pragma: no cover - defensive
            out.write("ownership was not released\n")
        return status
    finally:
        keep_awake.release()

if __name__ == "__main__":
    sys.exit(main())

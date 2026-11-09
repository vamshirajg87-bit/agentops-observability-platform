"""
benchmarks/win32_job.py

An isolated, fail-closed Windows Job Object backend for the future staged
AppContainer child.  Nothing calls it: the calibration harness does not
import this module, and no existing process creation, resume, timeout or
termination behaviour changes.

    CtypesJobApi   documented kernel32 job functions through ctypes, every
                   call gated by the harness authorization (closed), the
                   DLL loaded only on first use through an injectable
                   loader; malformed or short native output is an error,
                   never a default.
    JobController  explicit ownership of exactly one unnamed,
                   non-inheritable job: configuration with exact read-back
                   (KILL_ON_JOB_CLOSE, ACTIVE_PROCESS limit 1,
                   DIE_ON_UNHANDLED_EXCEPTION, no breakaway), membership
                   verification of exactly one child (a snapshot, not a
                   guarantee), a termination interface that refuses while
                   the lifecycle TERMINATION_POLICY is design-only, and a
                   close that never closes a job that may hold a live child
                   (closing it would terminate the child).
    planning       pure helpers for the future creation path: the
                   immutable PROC_THREAD_ATTRIBUTE plan (SECURITY_CAPABILITIES,
                   HANDLE_LIST, JOB_LIST) and the attribute-list sizing
                   contract.  A child joins the job only AT creation
                   (JOB_LIST); there is no after-creation assignment API
                   here, so there is nothing to fall back to.
    parent job     inventory through the injected API: IsProcessInJob on
                   the current-process pseudo-handle with a NULL job is the
                   only presence test; a launch may proceed only on a
                   definite FALSE.
    provenance     membership evidence (exactly P.JOB_MEMBERSHIP_FIELDS)
                   exists only with a sealed assignment-at-creation
                   assertion, which cannot be minted while
                   JOB_LIST_CREATION_INTEGRATED is False (the launcher has
                   no JOB_LIST integration); observed membership alone
                   never proves assignment at creation.

There is no automatic retry and no cleanup through object destruction.

Standard library only.
"""

from __future__ import annotations

import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

HERE: Path = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import appcontainer_preflight as P  # noqa: E402
import calibrate_generator as C  # noqa: E402

#: JOBOBJECTINFOCLASS values (documented).
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
#: PROC_THREAD_ATTRIBUTE values (documented) of the future creation path.
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
HANDLE_FLAG_INHERIT = 0x00000001
#: The sizing call of InitializeProcThreadAttributeList must fail with this.
ERROR_INSUFFICIENT_BUFFER = 122
#: Upper bound for an attribute list's size (fail closed beyond it).
ATTRIBUTE_LIST_SIZE_LIMIT = 4096
#: GetCurrentProcess() pseudo-handle; valid only as "this process", never
#: as an owned handle (the handle-validity check rejects it on purpose).
CURRENT_PROCESS = -1
#: The FAILURE_ACTIONS key of every parent-job refusal.
PARENT_JOB_REFUSAL = "nested_job_incompatible"
#: How many member PIDs a membership query can return; more is an error.
PID_LIST_CAPACITY = 8
#: The only lifecycle policy under which termination may be requested.
TERMINATION_ACCEPTED = "accepted"

OWNERSHIP_STATES: tuple[str, ...] = (
    "none",                 # no job created
    "owned_empty",          # job configured, no child verified in it
    "owned_with_child",     # exactly one verified child (a snapshot)
    "child_exited",         # the child's exit was verified; the job is empty
    "retained_unverified",  # a child may live: the handle is never closed here
    "retained_close_failed",  # CloseHandle failed; nothing is retried
    "closed",
)


class JobFailure(C.CalibrationError):
    """A refused or failed job operation, with its FAILURE_ACTIONS key."""

    def __init__(self, key: str, message: str, *, ownership: str) -> None:
        super().__init__(f"{key}: {message}")
        self.key, self.ownership = key, ownership


class TerminationRefused(JobFailure):
    """Termination was requested where it is not permitted."""


_TYPES: Any = None


def _job_types() -> Any:
    """ctypes structures of the documented job types (built on first use)."""
    global _TYPES
    if _TYPES is None:
        import ctypes
        import types
        from ctypes import wintypes as w

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", w.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", w.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", w.DWORD),
                        ("SchedulingClass", w.DWORD)]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                        ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_longlong),
                        ("TotalKernelTime", ctypes.c_longlong),
                        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                        ("TotalPageFaultCount", w.DWORD),
                        ("TotalProcesses", w.DWORD),
                        ("ActiveProcesses", w.DWORD),
                        ("TotalTerminatedProcesses", w.DWORD)]

        class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
            _fields_ = [("NumberOfAssignedProcesses", w.DWORD),
                        ("NumberOfProcessIdsInList", w.DWORD),
                        ("ProcessIdList", ctypes.c_size_t * 1)]

        _TYPES = types.SimpleNamespace(
            ctypes=ctypes, w=w, BASIC=JOBOBJECT_BASIC_LIMIT_INFORMATION, IO=IO_COUNTERS,
            EXTENDED=JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            ACCOUNTING=JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            PID_LIST=JOBOBJECT_BASIC_PROCESS_ID_LIST)
    return _TYPES


def _job_signatures(t: Any) -> dict[str, tuple[Any, list[Any]]]:
    """name -> (restype, argtypes); all in kernel32."""
    c, w = t.ctypes, t.w
    return {
        "CreateJobObjectW": (w.HANDLE, [c.c_void_p, w.LPCWSTR]),
        "SetInformationJobObject": (w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]),
        "QueryInformationJobObject": (w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, w.DWORD,
                                               c.POINTER(w.DWORD)]),
        "IsProcessInJob": (w.BOOL, [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]),
        "TerminateJobObject": (w.BOOL, [w.HANDLE, w.UINT]),
        "GetHandleInformation": (w.BOOL, [w.HANDLE, c.POINTER(w.DWORD)]),
        "CloseHandle": (w.BOOL, [w.HANDLE]),
    }


def _kernel32_loader(name: str) -> Any:
    import ctypes
    return ctypes.WinDLL(name, use_last_error=True)


class CtypesJobApi:
    """The documented job functions; gated per call; kernel32 loaded lazily."""

    def __init__(self, auth: Any, *, loader: Optional[Callable[[str], Any]] = None,
                 last_error: Optional[Callable[[], int]] = None) -> None:
        self.auth = C._require_any_authorization(auth)
        self._loader = loader or _kernel32_loader
        self._kernel32: Any = None
        self._last_error = last_error

    @property
    def loaded(self) -> bool:
        return self._kernel32 is not None

    def _api(self, name: str) -> Any:
        C._require_any_authorization(self.auth)
        restype, argtypes = _job_signatures(_job_types())[name]
        if self._kernel32 is None:
            self._kernel32 = self._loader("kernel32")
        function = getattr(self._kernel32, name)
        function.restype, function.argtypes = restype, argtypes
        return function

    def _error(self, api: str) -> C.Win32Error:
        code = (self._last_error or _job_types().ctypes.get_last_error)()
        return C.Win32Error(api, code)

    def create_job(self) -> int:
        """An unnamed job with default (non-inheritable) security."""
        handle = self._api("CreateJobObjectW")(None, None)
        if not C._valid_handle(handle):
            raise self._error("CreateJobObjectW")
        return int(handle)

    def handle_inheritable(self, handle: int) -> bool:
        t = _job_types()
        flags = t.w.DWORD(0)
        if not self._api("GetHandleInformation")(handle, t.ctypes.byref(flags)):
            raise self._error("GetHandleInformation")
        return bool(flags.value & HANDLE_FLAG_INHERIT)

    def set_limits(self, job: int, limit_flags: int, active_process_limit: int) -> None:
        t = _job_types()
        info = t.EXTENDED()
        info.BasicLimitInformation.LimitFlags = limit_flags
        info.BasicLimitInformation.ActiveProcessLimit = active_process_limit
        if not self._api("SetInformationJobObject")(
                job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, t.ctypes.addressof(info),
                t.ctypes.sizeof(info)):
            raise self._error("SetInformationJobObject")

    def _query(self, job: Optional[int], information_class: int, buffer: Any) -> int:
        t = _job_types()
        returned = t.w.DWORD(0)
        if not self._api("QueryInformationJobObject")(
                job, information_class, t.ctypes.addressof(buffer), t.ctypes.sizeof(buffer),
                t.ctypes.byref(returned)):
            raise self._error("QueryInformationJobObject")
        if returned.value > t.ctypes.sizeof(buffer):
            raise C.Win32Error("QueryInformationJobObject",
                               f"returned length {returned.value} exceeds the buffer")
        return int(returned.value)

    def query_limits(self, job: Optional[int]) -> dict[str, int]:
        t = _job_types()
        info = t.EXTENDED()
        length = self._query(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, info)
        if length != t.ctypes.sizeof(info):
            raise C.Win32Error("QueryInformationJobObject", f"limit length {length}")
        return {"limit_flags": int(info.BasicLimitInformation.LimitFlags),
                "active_process_limit": int(info.BasicLimitInformation.ActiveProcessLimit)}

    def query_accounting(self, job: int) -> dict[str, int]:
        t = _job_types()
        info = t.ACCOUNTING()
        length = self._query(job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, info)
        if length != t.ctypes.sizeof(info):
            raise C.Win32Error("QueryInformationJobObject", f"accounting length {length}")
        return {"active": int(info.ActiveProcesses), "total": int(info.TotalProcesses),
                "terminated": int(info.TotalTerminatedProcesses)}

    def query_pid_list(self, job: int) -> list[int]:
        """The member PIDs; a truncated, inconsistent or short answer is an
        error."""
        t = _job_types()
        c = t.ctypes
        offset = t.PID_LIST.ProcessIdList.offset
        size = offset + PID_LIST_CAPACITY * c.sizeof(c.c_size_t)
        buffer = (c.c_size_t * (-(-size // c.sizeof(c.c_size_t))))()
        length = self._query(job, JOB_OBJECT_BASIC_PROCESS_ID_LIST, buffer)
        if length < offset:
            raise C.Win32Error("QueryInformationJobObject", f"PID list length {length}")
        header = t.PID_LIST.from_buffer(buffer)
        assigned, listed = int(header.NumberOfAssignedProcesses), int(
            header.NumberOfProcessIdsInList)
        if listed > PID_LIST_CAPACITY or listed != assigned \
                or length < offset + listed * c.sizeof(c.c_size_t):
            raise C.Win32Error("QueryInformationJobObject",
                               f"PID list inconsistent ({assigned} assigned, {listed} listed, "
                               f"length {length})")
        ids = (c.c_size_t * listed).from_buffer(buffer, offset) if listed else []
        return [int(pid) for pid in ids]

    def _in_job(self, process: int, job: Optional[int]) -> bool:
        t = _job_types()
        result = t.w.BOOL(0)
        if not self._api("IsProcessInJob")(process, job, t.ctypes.byref(result)):
            raise self._error("IsProcessInJob")
        if result.value not in (0, 1):
            raise C.Win32Error("IsProcessInJob", f"malformed result {result.value}")
        return result.value == 1

    def is_process_in_job(self, process: int, job: int) -> bool:
        return self._in_job(process, job)

    def parent_in_any_job(self) -> bool:
        """IsProcessInJob(GetCurrentProcess(), NULL): documented to report
        whether this process runs under ANY job - the presence test."""
        return self._in_job(CURRENT_PROCESS, None)

    def current_job_limits(self) -> dict[str, int]:
        """Diagnostics only: QueryInformationJobObject with a NULL job reads
        the calling process's immediate job, and is meaningful only when
        there is one.  It is never a presence test."""
        return self.query_limits(None)

    def terminate_job(self, job: int, exit_code: int) -> None:
        if not self._api("TerminateJobObject")(job, exit_code):
            raise self._error("TerminateJobObject")

    def close(self, handle: int) -> None:
        if not self._api("CloseHandle")(handle):
            raise self._error("CloseHandle")


# ---------------------------------------------------------------------------
# Creation planning (pure) and parent-job inventory
# ---------------------------------------------------------------------------

class PlanRefused(C.CalibrationError):
    """A creation plan that must not be used; nothing native was called."""


@dataclass(frozen=True)
class AttributeEntry:
    attribute: int
    name: str
    handles: tuple[int, ...]


@dataclass(frozen=True)
class AttributePlan:
    """The PROC_THREAD_ATTRIBUTE entries of one creation, in update order.
    The attribute-list count is derived from it, never written down."""
    entries: tuple[AttributeEntry, ...]

    @property
    def count(self) -> int:
        return len(self.entries)


def job_list_attribute_plan(job: Any, stdout: Any, stderr: Any) -> AttributePlan:
    """SECURITY_CAPABILITIES, HANDLE_LIST (stdout, stderr) and JOB_LIST
    (job).  Every handle must be valid and distinct, and the job handle is
    never in the inherited handle list."""
    for label, handle in (("job", job), ("stdout", stdout), ("stderr", stderr)):
        if not C._valid_handle(handle):
            raise PlanRefused(f"the {label} handle is invalid")
    if job in (stdout, stderr):
        raise PlanRefused("the job handle must never be in the inherited handle list")
    if stdout == stderr:
        raise PlanRefused("stdout and stderr must be distinct handles")
    return AttributePlan((
        AttributeEntry(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, "security_capabilities", ()),
        AttributeEntry(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, "handle_list", (stdout, stderr)),
        AttributeEntry(PROC_THREAD_ATTRIBUTE_JOB_LIST, "job_list", (job,)),
    ))


def validate_attribute_list_size(first_result: Any, last_error: Any, size: Any) -> int:
    """The sizing call InitializeProcThreadAttributeList(NULL, count, 0,
    &size) must return FALSE with ERROR_INSUFFICIENT_BUFFER and a size in
    (0, ATTRIBUTE_LIST_SIZE_LIMIT]; anything else refuses."""
    if isinstance(first_result, bool):
        failed = first_result is False
    else:
        failed = isinstance(first_result, int) and first_result == 0
    if not failed:
        raise PlanRefused(f"the sizing call returned {first_result!r}, not FALSE")
    if isinstance(last_error, bool) or last_error != ERROR_INSUFFICIENT_BUFFER \
            or not isinstance(last_error, int):
        raise PlanRefused(f"the sizing call failed with {last_error!r}, not "
                          f"ERROR_INSUFFICIENT_BUFFER ({ERROR_INSUFFICIENT_BUFFER})")
    if isinstance(size, bool) or not isinstance(size, int) \
            or not 0 < size <= ATTRIBUTE_LIST_SIZE_LIMIT:
        raise PlanRefused(f"implausible attribute-list size {size!r}")
    return size


@dataclass(frozen=True)
class ParentJobInventory:
    in_job: Optional[bool]                     # None: unknown
    decision: str                              # "proceed" or "refuse"
    key: Optional[str]                         # FAILURE_ACTIONS key when refused
    reason: str
    diagnostics: Optional[Mapping[str, Any]]   # immediate-job limits; informational


def parent_job_decision(in_job: Any, diagnostics: Any = None,
                        error: Optional[str] = None) -> ParentJobInventory:
    """Pure.  Proceed only on a definite False; True, an error or a
    malformed value refuses.  Diagnostics never change the decision."""
    frozen = MappingProxyType(dict(diagnostics)) if isinstance(diagnostics, Mapping) else None
    if in_job is False and error is None:
        return ParentJobInventory(False, "proceed", None, "the parent runs in no job", frozen)
    if in_job is True and error is None:
        return ParentJobInventory(True, "refuse", PARENT_JOB_REFUSAL,
                                  "the parent already runs in a job; nested jobs are not "
                                  "accepted", frozen)
    why = error if error is not None else f"malformed result {in_job!r}"
    return ParentJobInventory(None, "refuse", PARENT_JOB_REFUSAL,
                              f"the parent's job state is unknown ({why})", frozen)


def parent_job_inventory(api: Any) -> ParentJobInventory:
    """Through the injected API.  The immediate job's limits are read only
    after the presence test reported True, and only as diagnostics."""
    try:
        in_job = api.parent_in_any_job()
    except C.ExecutionDisabled:
        raise
    except Exception as exc:
        return parent_job_decision(None, error=f"{type(exc).__name__}: {exc}")
    if in_job is not True:
        return parent_job_decision(in_job)
    try:
        diagnostics = dict(api.current_job_limits())
    except C.ExecutionDisabled:
        raise
    except Exception as exc:
        diagnostics = {"error": f"{type(exc).__name__}: {exc}"}
    return parent_job_decision(True, diagnostics)


def configuration_problems(readback: Any, inheritable: Any) -> list[str]:
    """The job's configuration, judged only by the planner's
    P.job_configuration_problems.  The measured handle inheritance is passed
    in (it overrides anything in the read-back); nothing is defaulted."""
    if not isinstance(readback, Mapping):
        return P.job_configuration_problems(readback)
    return P.job_configuration_problems({**readback, "job_handle_inheritable": inheritable})


# ---------------------------------------------------------------------------
# Assignment-at-creation provenance and membership evidence
# ---------------------------------------------------------------------------

#: The launcher does not create children with PROC_THREAD_ATTRIBUTE_JOB_LIST
#: yet.  Until a reviewed integration changes this, assignment at creation
#: can never be asserted, so no membership evidence can be produced.
JOB_LIST_CREATION_INTEGRATED: bool = False
_CREATION_SEAL = object()


class ProvenanceRefused(C.CalibrationError):
    """Assignment at creation cannot be asserted."""


@dataclass(frozen=True)
class CreationAssertion:
    """The creation path's statement that this child was created with a
    JOB_LIST naming this job.  Only one minted here (sealed) is accepted;
    observed membership alone never produces it."""
    job: int
    pid: int
    creation_time: str
    seal: Any = field(repr=False, compare=False)


def _assert_created_with_job_list(plan: Any, job: Any, pid: Any,
                                  creation_time: Any) -> CreationAssertion:
    """For the future creation path only, after CreateProcessW succeeded
    with this plan; refused while the launcher has no JOB_LIST integration."""
    if JOB_LIST_CREATION_INTEGRATED is not True:
        raise ProvenanceRefused("the launcher has no JOB_LIST integration; assignment at "
                                "creation cannot be asserted")
    if not isinstance(plan, AttributePlan):
        raise ProvenanceRefused("no attribute plan")
    if not C._valid_handle(job):
        raise ProvenanceRefused("the job handle is invalid")
    job_lists = [e for e in plan.entries if e.attribute == PROC_THREAD_ATTRIBUTE_JOB_LIST]
    if len(job_lists) != 1 or job_lists[0].handles != (job,):
        raise ProvenanceRefused("the plan's JOB_LIST does not name exactly this job")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ProvenanceRefused("the created PID is invalid")
    if not isinstance(creation_time, str) or not creation_time:
        raise ProvenanceRefused("the creation time is invalid")
    return CreationAssertion(job, pid, creation_time, _CREATION_SEAL)


def _assertion_problem(creation: Any, job: Any, pid: Any, creation_time: Any) -> Optional[str]:
    """Why the assertion does not authenticate assignment at creation of
    this child into this job; None when it does."""
    if creation is None:
        return ("no assignment-at-creation assertion (observed membership alone does not "
                "prove assignment at creation)")
    if not isinstance(creation, CreationAssertion) or creation.seal is not _CREATION_SEAL:
        return "the assignment-at-creation assertion is not authentic"
    if creation.job != job or creation.pid != pid or creation.creation_time != creation_time:
        return "the assignment-at-creation assertion is about another job or child"
    return None


def _membership_evidence(creation: CreationAssertion, *, in_job: Any, member_pids: Any,
                         active: Any, total: Any) -> Mapping[str, Any]:
    """Exactly P.JOB_MEMBERSHIP_FIELDS: identity from the authenticated
    creation context, everything else as observed; immutable."""
    if not isinstance(creation, CreationAssertion) or creation.seal is not _CREATION_SEAL:
        raise ProvenanceRefused("no authentic assignment-at-creation assertion")
    values = {"job_assignment": P.ACCEPTED_JOB_ASSIGNMENT, "in_job": in_job,
              "pid": creation.pid, "creation_time": creation.creation_time,
              "active_processes": active, "total_processes": total,
              "member_pids": (tuple(member_pids) if isinstance(member_pids, (list, tuple))
                              else member_pids)}
    return MappingProxyType({key: values[key] for key in P.JOB_MEMBERSHIP_FIELDS})


@dataclass(frozen=True)
class Membership:
    """One membership snapshot: exactly this child, at this moment, with
    its complete membership evidence."""
    pid: int
    creation_time: str
    epoch: int
    evidence: Optional[Mapping[str, Any]] = field(default=None, compare=False)


@dataclass
class TerminationOutcome:
    cause: str
    api_ok: bool = False
    signaled: bool = False
    exit_code: Optional[int] = None
    active_after: Optional[int] = None
    verified: bool = False
    errors: list[str] = field(default_factory=list)

    def lifecycle_evidence(self, pid: int, creation_time: str) -> dict[str, Any]:
        """Truthful evidence for appcontainer_preflight.lifecycle_transition
        (the process-level wait and exit code as observed).  Job emptiness is
        tracked by the controller's ownership state."""
        return {"pid": pid, "creation_time": creation_time, "cause": self.cause,
                "api_ok": self.api_ok, "signaled": self.signaled,
                "exit_code": self.exit_code if self.signaled else None}


class JobController:
    """
    Explicit ownership of one job.  Every method refuses outside its
    ownership state; nothing is retried; nothing is cleaned up implicitly.
    """

    def __init__(self, auth: Any, api: Any) -> None:
        self.auth = C._require_any_authorization(auth)
        self.api = api
        self.ownership = "none"
        self.job: Optional[int] = None
        self.membership: Optional[Membership] = None
        self._creation: Optional[CreationAssertion] = None
        self._epoch = 0
        self.errors: list[str] = []

    def _gate(self) -> None:
        C._require_any_authorization(self.auth)

    def _fail(self, key: str, message: str, cls: type = JobFailure) -> JobFailure:
        self.errors.append(f"{key}: {message}")
        return cls(key, message, ownership=self.ownership)

    def _close_empty(self, why: str) -> None:
        """Close a job that cannot hold a process yet (configuration
        failure).  A close failure retains the handle."""
        try:
            self.api.close(self.job)
        except Exception as exc:
            self.ownership = "retained_close_failed"
            self.errors.append(f"close after {why} failed: {exc}")
            return
        self.ownership, self.job = "closed", None

    def configure(self) -> int:
        """Create and configure the job; exact read-back required."""
        self._gate()
        if self.ownership != "none":
            raise self._fail("job_readback_mismatch", f"configure in state {self.ownership}")
        try:
            self.job = self.api.create_job()
        except Exception as exc:
            raise self._fail("create_job_failed", str(exc)) from None
        self.ownership = "owned_empty"
        try:
            inheritable = self.api.handle_inheritable(self.job)
            if inheritable:
                raise self._fail("inheritable_job_handle", "the job handle is inheritable")
            policy = P.JOB_LIMIT_POLICY
            try:
                self.api.set_limits(self.job, policy["required_flags"],
                                    policy["active_process_limit"])
            except Exception as exc:
                raise self._fail("set_job_information_failed", str(exc)) from None
            readback = self.api.query_limits(self.job)
            problems = configuration_problems(readback, inheritable)
            if problems:
                raise self._fail("job_readback_mismatch", "; ".join(problems))
        except JobFailure as failure:
            self._close_empty(failure.key)
            failure.ownership = self.ownership
            raise
        except Exception as exc:
            failure = self._fail("job_readback_mismatch", f"{type(exc).__name__}: {exc}")
            self._close_empty(failure.key)
            failure.ownership = self.ownership
            raise failure from None
        return self.job

    def _snapshot(self, process: int, pid: int, creation_time: str,
                  handle_creation_time: str, creation: Any) -> Membership:
        """Exactly one verified child, now: assigned at creation (an
        authenticated assertion, checked before any native call), its PID
        and creation identity, the only process the job has ever held, the
        job's limits unchanged, and the complete evidence accepted by
        P.job_membership_problems."""
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise self._fail("not_in_job", "the expected PID is invalid")
        if not isinstance(creation_time, str) or creation_time != handle_creation_time:
            raise self._fail("not_in_job", "the process handle's creation time differs from "
                                           "the created child's")
        if not C._valid_handle(process):
            raise self._fail("not_in_job", "no valid process handle")
        why = _assertion_problem(creation, self.job, pid, creation_time)
        if why:
            raise self._fail("assignment_failed", why)
        in_job = self.api.is_process_in_job(process, self.job)
        if not in_job:
            raise self._fail("not_in_job", "IsProcessInJob reports the child outside the job")
        pids = self.api.query_pid_list(self.job)
        if pids != [pid]:
            raise self._fail("not_in_job", f"the job members are {pids}, not [{pid}]")
        accounting = self.api.query_accounting(self.job)
        if accounting["active"] != 1:
            raise self._fail("not_in_job", f"{accounting['active']} active processes, not 1")
        if accounting["total"] != 1:
            raise self._fail("not_in_job", f"{accounting['total']} processes have been in the "
                                           "job, not 1")
        problems = configuration_problems(self.api.query_limits(self.job),
                                          self.api.handle_inheritable(self.job))
        if problems:
            raise self._fail("job_readback_mismatch", "; ".join(problems))
        evidence = _membership_evidence(creation, in_job=in_job, member_pids=pids,
                                        active=accounting["active"], total=accounting["total"])
        refused = P.job_membership_problems(evidence, expected_pid=pid,
                                            expected_creation_time=handle_creation_time)
        if refused:
            raise self._fail("not_in_job", "membership evidence refused: " + "; ".join(refused))
        self._epoch += 1
        return Membership(pid, creation_time, self._epoch, evidence)

    def verify_membership(self, process: int, pid: int, creation_time: str,
                          handle_creation_time: str,
                          creation: Optional[CreationAssertion] = None) -> Membership:
        """A membership snapshot of exactly one child, with its complete,
        immutable membership evidence.  `creation` must be the creation
        path's authenticated assertion of assignment at creation; without
        it nothing is verified.  Not a permanent guarantee: termination
        re-verifies."""
        self._gate()
        if self.ownership not in ("owned_empty", "owned_with_child"):
            raise self._fail("not_in_job", f"membership in state {self.ownership}")
        try:
            self.membership = self._snapshot(process, pid, creation_time, handle_creation_time,
                                             creation)
        except JobFailure:
            # A child may be in the job: never close it here (that would
            # terminate it); the caller discards through its own handle.
            self.ownership, self.membership, self._creation = "retained_unverified", None, None
            raise
        except Exception as exc:
            self.ownership, self.membership, self._creation = "retained_unverified", None, None
            raise self._fail("not_in_job", f"{type(exc).__name__}: {exc}") from None
        self._creation = creation
        self.ownership = "owned_with_child"
        return self.membership

    def terminate(self, cause: str, process: int, membership: Membership,
                  handle_creation_time: str, *, wait: Callable[[int, int], bool],
                  exit_code: Callable[[int], int],
                  wait_milliseconds: int = 5000) -> TerminationOutcome:
        """
        The future termination interface.  Refused - before any native call
        - unless the lifecycle TERMINATION_POLICY is "accepted" (it is
        design-only), the job owns exactly the verified child, and the
        membership evidence is the latest snapshot; membership is then
        re-verified immediately before TerminateJobObject.  Exit proof:
        signalled wait, the cause's exit code, and an empty job.
        """
        self._gate()
        if P.TERMINATION_POLICY != TERMINATION_ACCEPTED:
            raise self._fail("termination_refused", "the termination policy is "
                             f"{P.TERMINATION_POLICY!r}, not accepted", TerminationRefused)
        if cause not in P.TERMINATION_EXIT_CODES:
            raise self._fail("termination_refused", f"unknown cause {cause!r}",
                             TerminationRefused)
        if self.ownership != "owned_with_child" or self.membership is None:
            raise self._fail("termination_refused", f"no verified child (state "
                             f"{self.ownership})", TerminationRefused)
        if membership != self.membership:
            raise self._fail("termination_refused", "stale or foreign membership evidence",
                             TerminationRefused)
        try:
            fresh = self._snapshot(process, membership.pid, membership.creation_time,
                                   handle_creation_time, self._creation)
        except Exception as exc:
            self.ownership, self.membership = "retained_unverified", None
            raise self._fail("termination_refused", f"membership no longer verified: {exc}",
                             TerminationRefused) from None
        self.membership = fresh
        outcome = TerminationOutcome(cause)
        code = P.TERMINATION_EXIT_CODES[cause]
        try:
            try:
                self.api.terminate_job(self.job, code)
                outcome.api_ok = True
            except Exception as exc:
                outcome.errors.append(f"TerminateJobObject: {exc}")
            if outcome.api_ok:
                outcome.signaled = bool(wait(process, wait_milliseconds))
                if outcome.signaled:
                    outcome.exit_code = int(exit_code(process))
                    outcome.active_after = self.api.query_accounting(self.job)["active"]
        except BaseException as exc:          # interrupted: state first, then re-raise
            self.ownership = "retained_unverified"
            self.errors.append(f"termination interrupted: {type(exc).__name__}")
            raise
        outcome.verified = (outcome.api_ok and outcome.signaled
                            and outcome.exit_code == code and outcome.active_after == 0)
        if outcome.verified:
            self.ownership, self.membership = "child_exited", None
        else:
            self.ownership = "retained_unverified"
            outcome.errors.append("exit not verified (signalled wait, exit code "
                                  f"{code:#x} and an empty job are all required)")
            self.errors.extend(outcome.errors)
        return outcome

    def record_natural_exit(self, process: int, *, wait: Callable[[int, int], bool],
                            exit_code: Callable[[int], int]) -> Optional[int]:
        """The child exited by itself: only a signalled wait plus an empty
        job moves ownership to child_exited."""
        self._gate()
        if self.ownership != "owned_with_child":
            raise self._fail("not_in_job", f"natural exit in state {self.ownership}")
        if not wait(process, 0):
            return None
        code = int(exit_code(process))
        if self.api.query_accounting(self.job)["active"] != 0:
            self.ownership = "retained_unverified"
            raise self._fail("not_in_job", "the child exited but the job is not empty")
        self.ownership, self.membership = "child_exited", None
        return code

    def close(self) -> None:
        """Close the job only when it provably holds no live child; never
        retried after a failure."""
        self._gate()
        if self.ownership not in ("owned_empty", "child_exited"):
            raise self._fail("unsafe_close_refused", f"the job may hold a live child or "
                             f"cannot be closed (state {self.ownership})")
        active = self.api.query_accounting(self.job)["active"]
        if active != 0:
            self.ownership = "retained_unverified"
            raise self._fail("unsafe_close_refused", f"{active} active processes in the job")
        try:
            self.api.close(self.job)
        except Exception as exc:
            self.ownership = "retained_close_failed"
            raise self._fail("close_failed", str(exc)) from None
        self.ownership, self.job = "closed", None


# ---------------------------------------------------------------------------
# Offline containment adapter (nothing calls it)
# ---------------------------------------------------------------------------

class ContainmentRefused(C.CalibrationError):
    """The containment preparation was refused; `key` is the FAILURE_ACTIONS
    key.  Nothing is retried, closed or terminated by the refusal."""

    def __init__(self, key: str, message: str) -> None:
        super().__init__(f"{key}: {message}")
        self.key = key


@dataclass(frozen=True)
class ContainmentResult:
    """A verified contained child: its dedicated job, identity, the sealed
    creation assertion and the membership snapshot with its evidence."""
    job: int
    pid: int
    creation_time: str
    assertion: CreationAssertion
    membership: Membership


def receipt_problems(receipt: Any, job: Any) -> list[str]:
    """Why a creation receipt does not show that CreateProcessW ran with
    exactly the planned attributes and a JOB_LIST naming exactly this job;
    empty when it does.  The plan's own rules live in C._validated_plan."""
    if receipt is None:
        return ["no creation receipt"]
    if not isinstance(receipt, C.CreationReceipt):
        return ["the creation receipt is not a CreationReceipt"]
    problems: list[str] = []
    if receipt.planned is not True:
        problems.append("the creation was legacy/unplanned (uncontained)")
    if receipt.create_process_ok is not True:
        problems.append("CreateProcessW success is not established")
    applied = receipt.applied_attributes
    if not isinstance(applied, tuple) or not all(
            isinstance(a, int) and not isinstance(a, bool) for a in applied):
        problems.append("the applied attributes are malformed")
    elif applied != C.PLAN_ATTRIBUTES:
        if PROC_THREAD_ATTRIBUTE_JOB_LIST not in applied:
            problems.append("JOB_LIST was not applied")
        if len(set(applied)) != len(applied):
            problems.append("the applied attributes contain a duplicate")
        if any(a not in C.PLAN_ATTRIBUTES for a in applied):
            problems.append("the applied attributes contain an unexpected attribute")
        if any(a not in applied for a in C.PLAN_ATTRIBUTES):
            problems.append("the applied attribute list is incomplete")
        if sorted(applied) == sorted(C.PLAN_ATTRIBUTES):
            problems.append("the applied attributes are reordered")
    handles = receipt.job_list_handles
    if not isinstance(handles, tuple) or handles != (job,):
        problems.append("the JOB_LIST references another job, or not exactly one job")
    return problems


class ContainmentAdapter:
    """
    Composes the existing pieces into one offline containment preparation:
    parent-job inventory, a dedicated configured job, the JOB_LIST plan, one
    injected creation, receipt validation and identity binding, the sealed
    creation assertion, and membership verification.  Everything native is
    injected: `create(plan)` returns the harness's Win32Handles (its receipt
    is judged against the job this adapter configured, never against a
    receipt the caller supplies) and `process_identity(process)` returns the
    (pid, creation_time) the process handle reports.

    The assertion is minted by the module's own sealed function, so it stays
    refused while JOB_LIST_CREATION_INTEGRATED is False.  No fallback to an
    uncontained creation, no after-creation assignment, no resume, no
    implicit close or termination.
    """

    def __init__(self, auth: Any, api: Any, *, create: Callable[[AttributePlan], Any],
                 process_identity: Callable[[Any], Any]) -> None:
        self.auth = C._require_any_authorization(auth)
        self.api = api
        try:
            inspect.signature(create).bind(None, None)   # (plan, custody); never invoked
        except (TypeError, ValueError):
            raise C.CalibrationError("the creator must accept (plan, custody) as two "
                                     "positional arguments") from None
        self._create, self._identity = create, process_identity
        self.controller: Optional[JobController] = None
        #: The creation's handle custody, allocated before the creator runs
        #: and kept for the adapter's lifetime; never closed or reset.
        self.custody: Optional[C.HandleCustody] = None
        self.errors: list[str] = []
        #: Display-only diagnostics of an uncertain outcome; never consulted
        #: by any decision, and never a claim that a child exists or is known.
        self.retained_reason: Optional[str] = None
        self.retained_evidence: Optional[Mapping[str, Any]] = None

    def _refuse(self, key: str, message: str) -> ContainmentRefused:
        self.errors.append(f"{key}: {message}")
        return ContainmentRefused(key, message)

    def _note_retention(self, stage: str, reason: str, failure_key: Optional[str],
                        cause: Optional[BaseException], before: Any) -> None:
        """Record display-only diagnostics.  Every fact about the child is
        'unknown' or 'unverified': nothing here asserts that a process
        exists or what its identity or membership is.  Never raises: it only
        observes, so even an interruption inside it is absorbed here and
        cannot replace the creator or binding failure being handled."""
        self.retained_reason = reason
        try:
            try:
                seen = self.custody.snapshot() if self.custody is not None else None
            except BaseException:
                seen = None
            self.retained_evidence = MappingProxyType({
                "stage": stage,
                "failure_action_key": failure_key,
                "cause_type": None if cause is None else type(cause).__name__,
                "ownership_before": before,
                "ownership_after": getattr(self.controller, "ownership", None),
                "custody_attached": bool(seen and seen.attached),
                "custody_entered": bool(seen and seen.entered),
                "process_handle_observed": bool(seen and seen.process_handle_observed),
                "thread_handle_observed": bool(seen and seen.thread_handle_observed),
                "custody_readable": bool(seen and seen.readable),
                "custody_inconsistent": bool(seen and seen.inconsistent),
                "child_existence": "unknown",
                "child_identity": "unverified",
                "membership": "unverified",
                "recovery_authorized": False,
            })
        except BaseException:
            self.retained_evidence = None

    def _retain_child(self, cause: Optional[BaseException] = None,
                      stage: str = "creator") -> None:
        """A child may exist and is not verified: the job handle is retained
        (closing it would terminate the child) and nothing is retried.  A
        retention that cannot be confirmed is refused explicitly, never
        assumed safe."""
        controller = self.controller
        try:
            before = controller.ownership if controller is not None else None
        except Exception:
            before = None
        try:
            if controller is not None and controller.ownership in (
                    "owned_empty", "owned_with_child"):
                controller.ownership, controller.membership = "retained_unverified", None
            retained = controller is not None and controller.ownership in (
                "retained_unverified", "retained_close_failed")
        except Exception:
            retained = False
        if not retained:
            self._note_retention(stage, "retention_unconfirmed", "retention_failed", cause,
                                 before)
            raise self._refuse("retention_failed", "the job could not be confirmed retained "
                                                   "after an uncertain creation outcome") from cause
        if stage == "creator":
            self._note_retention(stage, "creator_failed_outcome_unknown", "creation_failed",
                                 cause, before)
        else:
            self._note_retention(stage, "bind_failed_child_may_exist", None, cause, before)

    def prepare(self, stdout: Any, stderr: Any) -> ContainmentResult:
        C._require_any_authorization(self.auth)
        if self.controller is not None:
            raise self._refuse("job_readback_mismatch", "the adapter was already used")
        inventory = parent_job_inventory(self.api)
        if inventory.decision != "proceed" or inventory.in_job is not False:
            raise self._refuse(inventory.key or PARENT_JOB_REFUSAL, inventory.reason)
        self.controller = JobController(self.auth, self.api)
        job = self.controller.configure()       # a failure closes its own empty job
        try:
            plan = job_list_attribute_plan(job, stdout, stderr)
            C._validated_plan(plan, validate_attribute_list_size, stdout, stderr)
        except C.CalibrationError as exc:       # PlanRefused is one
            raise self._refuse("plan_refused", str(exc)) from None
        self.custody = C.HandleCustody()        # before the creator, kept whatever happens
        try:
            created = self._create(plan, self.custody)   # exactly once; never a fallback
        except BaseException as exc:
            # Entered the creator: an exception never proves that no child was created.
            self._retain_child(exc)
            if isinstance(exc, Exception) and not isinstance(exc, C.ExecutionDisabled):
                raise self._refuse("creation_failed", f"{type(exc).__name__}: {exc}") from None
            raise
        try:
            return self._bind(plan, job, created)
        except BaseException as exc:
            self._retain_child(exc, "bind")
            if isinstance(exc, Exception) and not isinstance(exc, (
                    C.ExecutionDisabled, ContainmentRefused, JobFailure, ProvenanceRefused)):
                raise self._refuse("not_in_job", f"{type(exc).__name__}: {exc}") from None
            raise

    def _bind(self, plan: AttributePlan, job: int, created: Any) -> ContainmentResult:
        if not isinstance(created, C.Win32Handles):
            raise self._refuse("assignment_failed", "no creation result")
        problems = receipt_problems(created.receipt, job)
        if problems:
            raise self._refuse("assignment_failed", "; ".join(problems))
        pid, process = created.pid, created.process
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise self._refuse("not_in_job", "the created PID is malformed")
        if not C._valid_handle(process) or not C._valid_handle(created.thread):
            raise self._refuse("not_in_job", "the created process or thread handle is invalid")
        reported_pid, creation_time = self._read_identity(process)
        if reported_pid != pid:
            raise self._refuse("not_in_job", f"the process handle reports PID {reported_pid}, "
                                             f"not the created {pid}")
        _, again = self._read_identity(process)
        if again != creation_time:
            raise self._refuse("not_in_job", "the creation time changed between reads")
        assertion = _assert_created_with_job_list(plan, job, pid, creation_time)
        membership = self.controller.verify_membership(process, pid, creation_time, again,
                                                       assertion)
        return ContainmentResult(job, pid, creation_time, assertion, membership)

    def _read_identity(self, process: Any) -> tuple[int, str]:
        identity = self._identity(process)
        if not isinstance(identity, tuple) or len(identity) != 2:
            raise self._refuse("not_in_job", "the process identity is malformed")
        pid, creation_time = identity
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 \
                or not isinstance(creation_time, str) or not creation_time:
            raise self._refuse("not_in_job", "the process identity is malformed")
        return pid, creation_time

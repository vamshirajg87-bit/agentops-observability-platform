"""
benchmarks/tests/test_win32_job.py

Mocked tests of the isolated Job Object backend.  A fake kernel32 and fake
handles are injected; any real DLL load, process, socket or subprocess
fails the test.  Authorization is opened in memory only.
"""

from __future__ import annotations

import ctypes
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1]
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import appcontainer_preflight as P  # noqa: E402
import calibrate_generator as C  # noqa: E402
import win32_job as W  # noqa: E402

HEAD = "a" * 40
PID, CREATED = 4242, "2026-10-09T12:00:00.000Z"
PROCESS, JOB = 0x101, 0x500
SOURCE = (_BENCH / "win32_job.py").read_text(encoding="utf-8")


class LiveAccessAttempt(AssertionError):
    """A test reached something real."""


@pytest.fixture(autouse=True)
def fail_closed(monkeypatch):
    def refuse(what):
        def call(*args, **kwargs):
            raise LiveAccessAttempt(f"{what} attempted")
        return call

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    monkeypatch.setattr(os, "system", refuse("os.system"))
    monkeypatch.setattr(socket, "create_connection", refuse("a network connection"))
    monkeypatch.setattr(socket.socket, "connect", refuse("a socket connection"))
    monkeypatch.setattr(ctypes, "WinDLL", refuse("a real DLL load"))
    monkeypatch.setattr(W, "_kernel32_loader", refuse("the real kernel32 loader"))


def authorize(monkeypatch):
    """A probe authorization, opened in memory only."""
    monkeypatch.setattr(C, "PROBE_ENABLED", True)
    monkeypatch.setattr(C, "APPROVED_PROBES", frozenset({"probe-01"}))
    monkeypatch.setattr(C, "_git_head", lambda *require: HEAD)
    return C.authorize_probe("probe-01", HEAD)


class FakeFunction:
    def __init__(self, name, implementation, log):
        self.name, self.implementation, self.log = name, implementation, log

    def __call__(self, *args):
        self.log.append(self.name)
        return self.implementation(*args)


class FakeDll:
    def __init__(self, kernel32):
        self._k = kernel32

    def __getattr__(self, name):
        if name.startswith("_") or not hasattr(type(self._k), name):
            raise LiveAccessAttempt(f"unexpected Windows API {name}")
        return FakeFunction(name, getattr(self._k, name), self._k.log)


class FakeKernel32:
    """Fake job functions with scripted state; returns 0 for APIs in fail."""

    def __init__(self, **overrides):
        self.log, self.loads, self.fail = [], [], set()
        self.job, self.inherit_flags, self.in_job = JOB, 0, 1
        self.stored, self.readback, self.limit_length = None, None, None
        self.accounting = {"active": 1, "total": 1, "terminated": 0}
        self.pids, self.assigned, self.pid_length = [PID], None, None
        self.terminated, self.closed, self.created_with = [], [], None
        self.empty_on_terminate, self.last_error = True, 5
        self.parent_in_job, self.parent_limits = 0, (0x2000, 0)
        self.in_job_calls, self.query_jobs = [], []
        self.__dict__.update(overrides)

    def loader(self, name):
        self.loads.append(name)
        return FakeDll(self)

    def CreateJobObjectW(self, attributes, name):
        self.created_with = (attributes, name)
        return 0 if "CreateJobObjectW" in self.fail else self.job

    def GetHandleInformation(self, handle, out):
        if "GetHandleInformation" in self.fail:
            return 0
        out._obj.value = self.inherit_flags
        return 1

    def SetInformationJobObject(self, job, information_class, address, size):
        if "SetInformationJobObject" in self.fail:
            return 0
        t = W._job_types()
        assert information_class == W.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION
        assert size == ctypes.sizeof(t.EXTENDED)
        info = t.EXTENDED.from_address(address)
        self.stored = (info.BasicLimitInformation.LimitFlags,
                       info.BasicLimitInformation.ActiveProcessLimit)
        return 1

    def QueryInformationJobObject(self, job, information_class, address, length, returned):
        self.query_jobs.append(job)
        if "QueryInformationJobObject" in self.fail:
            return 0
        t = W._job_types()
        if job is None:                          # the caller's own job, if any
            assert information_class == W.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION
            if not self.parent_in_job:
                return 0
            info = t.EXTENDED()
            info.BasicLimitInformation.LimitFlags, \
                info.BasicLimitInformation.ActiveProcessLimit = self.parent_limits
            data = bytes(info)
            ctypes.memmove(address, data, len(data))
            returned._obj.value = len(data)
            return 1
        if information_class == W.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION:
            info = t.EXTENDED()
            flags, limit = self.readback or self.stored
            info.BasicLimitInformation.LimitFlags = flags
            info.BasicLimitInformation.ActiveProcessLimit = limit
            data, size = bytes(info), self.limit_length
        elif information_class == W.JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION:
            info = t.ACCOUNTING(ActiveProcesses=self.accounting["active"],
                                TotalProcesses=self.accounting["total"],
                                TotalTerminatedProcesses=self.accounting["terminated"])
            data, size = bytes(info), None
        elif information_class == W.JOB_OBJECT_BASIC_PROCESS_ID_LIST:
            offset = t.PID_LIST.ProcessIdList.offset
            assigned = len(self.pids) if self.assigned is None else self.assigned
            header = (ctypes.c_uint32 * 2)(assigned, len(self.pids))
            pad = b"\0" * (offset - ctypes.sizeof(header))
            data = bytes(header) + pad + bytes((ctypes.c_size_t * len(self.pids))(*self.pids))
            size = self.pid_length
        else:
            raise AssertionError(f"unexpected class {information_class}")
        if len(data) > length:
            return 0
        ctypes.memmove(address, data, len(data))
        returned._obj.value = len(data) if size is None else size
        return 1

    def IsProcessInJob(self, process, job, out):
        self.in_job_calls.append((process, job))
        if "IsProcessInJob" in self.fail:
            return 0
        out._obj.value = self.parent_in_job if job is None else self.in_job
        return 1

    def TerminateJobObject(self, job, code):
        self.terminated.append((job, code))
        if "TerminateJobObject" in self.fail:
            return 0
        if self.empty_on_terminate:
            self.accounting = {**self.accounting, "active": 0, "terminated": 1}
        return 1

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return 0 if "CloseHandle" in self.fail else 1


def make_api(monkeypatch, **overrides):
    kernel32 = FakeKernel32(**overrides)
    api = W.CtypesJobApi(authorize(monkeypatch), loader=kernel32.loader,
                         last_error=lambda: kernel32.last_error)
    return api, kernel32


def make_controller(monkeypatch, **overrides):
    api, kernel32 = make_api(monkeypatch, **overrides)
    return W.JobController(api.auth, api), kernel32


STDOUT_HANDLE, STDERR_HANDLE = 0x204, 0x208


def creation_for(monkeypatch, job=JOB, pid=PID, created=CREATED):
    """An explicit, mocked assignment-at-creation assertion: the integration
    gate is opened in memory only for minting, then closed again."""
    monkeypatch.setattr(W, "JOB_LIST_CREATION_INTEGRATED", True)
    plan = W.job_list_attribute_plan(job, STDOUT_HANDLE, STDERR_HANDLE)
    assertion = W._assert_created_with_job_list(plan, job, pid, created)
    monkeypatch.setattr(W, "JOB_LIST_CREATION_INTEGRATED", False)
    return assertion


def verified(monkeypatch, **overrides):
    controller, kernel32 = make_controller(monkeypatch, **overrides)
    controller.configure()
    membership = controller.verify_membership(PROCESS, PID, CREATED, CREATED,
                                              creation_for(monkeypatch))
    return controller, kernel32, membership


def accept_policy(monkeypatch):
    """In memory only: the policy a future reviewed change could set."""
    monkeypatch.setattr(P, "TERMINATION_POLICY", W.TERMINATION_ACCEPTED)


# ---------------------------------------------------------------------------
# Layouts, signatures, isolation
# ---------------------------------------------------------------------------

class TestLayoutAndSignatures:
    @pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="x64 layouts")
    def test_x64_layouts(self):
        t = W._job_types()
        assert ctypes.sizeof(t.BASIC) == 64 and ctypes.sizeof(t.IO) == 48
        assert ctypes.sizeof(t.EXTENDED) == 144 and ctypes.sizeof(t.ACCOUNTING) == 48
        assert t.PID_LIST.ProcessIdList.offset == 8
        assert t.BASIC.LimitFlags.offset == 16 and t.BASIC.ActiveProcessLimit.offset == 40
        assert t.ACCOUNTING.ActiveProcesses.offset == 40

    def test_signatures(self):
        t = W._job_types()
        signatures = W._job_signatures(t)
        assert set(signatures) == {
            "CreateJobObjectW", "SetInformationJobObject", "QueryInformationJobObject",
            "IsProcessInJob", "TerminateJobObject", "GetHandleInformation", "CloseHandle"}
        assert signatures["CreateJobObjectW"][0] is t.w.HANDLE
        assert len(signatures["QueryInformationJobObject"][1]) == 5
        assert signatures["TerminateJobObject"][1] == [t.w.HANDLE, t.w.UINT]
        assert (W.JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, W.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                W.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, W.PROC_THREAD_ATTRIBUTE_JOB_LIST,
                W.HANDLE_FLAG_INHERIT) == (1, 3, 9, 0x0002000D, 1)

    def test_harness_never_imports_the_backend(self):
        harness = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        planner = (_BENCH / "appcontainer_preflight.py").read_text(encoding="utf-8")
        assert "win32_job" not in harness and "win32_job" not in planner

    def test_source_scope(self):
        code = SOURCE.split('"""', 2)[2]
        for word in ("subprocess", "socket", "TerminateProcess", "OpenProcess",
                     "__del__", "atexit", "weakref", "finalize", "CreateProcess(",
                     "os.kill", "taskkill"):
            assert word not in code, word


class TestGates:
    def test_refuses_while_disabled(self):
        with pytest.raises(C.ExecutionDisabled):
            W.CtypesJobApi(None, loader=FakeKernel32().loader)
        with pytest.raises(C.ExecutionDisabled):
            W.JobController(None, object())

    def test_gate_rechecked_before_loading(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        assert not api.loaded and kernel32.loads == []
        monkeypatch.setattr(C, "APPROVED_PROBES", frozenset())
        with pytest.raises(C.ExecutionDisabled):
            api.create_job()
        assert kernel32.loads == [] and kernel32.log == []

    def test_controller_gate_rechecked(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        monkeypatch.setattr(C, "PROBE_ENABLED", False)
        for call in (controller.configure, controller.close):
            with pytest.raises(C.ExecutionDisabled):
                call()
        assert kernel32.log == []

    def test_real_loader_is_never_used(self, monkeypatch):
        api = W.CtypesJobApi(authorize(monkeypatch))
        with pytest.raises(LiveAccessAttempt, match="real kernel32 loader"):
            api.create_job()


# ---------------------------------------------------------------------------
# Native wrappers
# ---------------------------------------------------------------------------

class TestCtypesJobApi:
    def test_create_job_is_unnamed_and_default_secured(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        assert api.create_job() == JOB and kernel32.created_with == (None, None)
        assert kernel32.loads == ["kernel32"]
        api.handle_inheritable(JOB)
        assert kernel32.loads == ["kernel32"]                     # loaded once

    @pytest.mark.parametrize("name, call", [
        ("CreateJobObjectW", lambda api: api.create_job()),
        ("GetHandleInformation", lambda api: api.handle_inheritable(JOB)),
        ("SetInformationJobObject", lambda api: api.set_limits(JOB, 0x2408, 1)),
        ("QueryInformationJobObject", lambda api: api.query_accounting(JOB)),
        ("IsProcessInJob", lambda api: api.is_process_in_job(PROCESS, JOB)),
        ("IsProcessInJob", lambda api: api.parent_in_any_job()),
        ("TerminateJobObject", lambda api: api.terminate_job(JOB, 0x0BAE)),
        ("CloseHandle", lambda api: api.close(JOB)),
    ])
    def test_native_failures_carry_get_last_error(self, monkeypatch, name, call):
        api, _ = make_api(monkeypatch, fail={name}, last_error=1450)
        with pytest.raises(C.Win32Error, match=f"{name} failed \\(Windows error 1450\\)"):
            call(api)

    def test_limits_round_trip(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        api.set_limits(JOB, 0x2408, 1)
        assert kernel32.stored == (0x2408, 1)
        assert api.query_limits(JOB) == {"limit_flags": 0x2408, "active_process_limit": 1}

    def test_malformed_lengths(self, monkeypatch):
        api, _ = make_api(monkeypatch, stored=(0x2408, 1), limit_length=100)
        with pytest.raises(C.Win32Error, match="limit length 100"):
            api.query_limits(JOB)
        api, _ = make_api(monkeypatch, stored=(0x2408, 1), limit_length=10_000)
        with pytest.raises(C.Win32Error, match="exceeds the buffer"):
            api.query_limits(JOB)

    def test_accounting_and_inheritance(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch, inherit_flags=0x3)
        assert api.query_accounting(JOB) == {"active": 1, "total": 1, "terminated": 0}
        assert api.handle_inheritable(JOB) is True
        kernel32.inherit_flags = 0x2
        assert api.handle_inheritable(JOB) is False

    @pytest.mark.parametrize("overrides, message", [
        ({"pids": [PID, 7], "assigned": 3}, "inconsistent"),
        ({"pids": list(range(1, 10))}, None),
        ({"pids": [PID], "pid_length": 4}, "PID list length 4"),
        ({"pids": [PID, 7], "pid_length": 12}, "inconsistent"),
    ])
    def test_pid_list_malformed(self, monkeypatch, overrides, message):
        api, _ = make_api(monkeypatch, **overrides)
        with pytest.raises(C.Win32Error, match=message or ""):
            api.query_pid_list(JOB)

    def test_pid_list(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch, pids=[PID, 7])
        assert api.query_pid_list(JOB) == [PID, 7]
        kernel32.pids = []
        assert api.query_pid_list(JOB) == []

    def test_is_process_in_job(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        assert api.is_process_in_job(PROCESS, JOB) is True
        kernel32.in_job = 0
        assert api.is_process_in_job(PROCESS, JOB) is False
        kernel32.in_job = 2
        with pytest.raises(C.Win32Error, match="malformed result 2"):
            api.is_process_in_job(PROCESS, JOB)


# ---------------------------------------------------------------------------
# Controller: configuration
# ---------------------------------------------------------------------------

class TestConfigure:
    def test_configured_exactly(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        assert controller.configure() == JOB and controller.ownership == "owned_empty"
        assert kernel32.stored == (P.JOB_LIMIT_POLICY["required_flags"], 1)
        assert kernel32.log == ["CreateJobObjectW", "GetHandleInformation",
                                "SetInformationJobObject", "QueryInformationJobObject"]
        with pytest.raises(W.JobFailure, match="configure in state owned_empty"):
            controller.configure()

    def test_creation_failure(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch, fail={"CreateJobObjectW"})
        with pytest.raises(W.JobFailure) as raised:
            controller.configure()
        assert raised.value.key == "create_job_failed" and controller.ownership == "none"
        assert kernel32.closed == []

    @pytest.mark.parametrize("overrides, key", [
        ({"inherit_flags": 1}, "inheritable_job_handle"),
        ({"fail": {"SetInformationJobObject"}}, "set_job_information_failed"),
        ({"readback": (0x0408, 1)}, "job_readback_mismatch"),
        ({"readback": (0x2408 | 0x800, 1)}, "job_readback_mismatch"),
        ({"readback": (0x2408 | 0x2, 1)}, "job_readback_mismatch"),
        ({"readback": (0x2408, 2)}, "job_readback_mismatch"),
        ({"limit_length": 100}, "job_readback_mismatch"),
        ({"fail": {"GetHandleInformation"}}, "job_readback_mismatch"),
    ])
    def test_refusals_close_the_empty_job_once(self, monkeypatch, overrides, key):
        controller, kernel32 = make_controller(monkeypatch, **overrides)
        with pytest.raises(W.JobFailure) as raised:
            controller.configure()
        assert raised.value.key == key
        assert kernel32.closed == [JOB]                           # no handle leak
        assert controller.ownership == "closed" and raised.value.ownership == "closed"
        assert "TerminateJobObject" not in kernel32.log

    def test_close_failure_during_refusal_retains(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch, inherit_flags=1,
                                               fail={"CloseHandle"})
        with pytest.raises(W.JobFailure) as raised:
            controller.configure()
        assert controller.ownership == "retained_close_failed"
        assert raised.value.ownership == "retained_close_failed"
        assert any("close after" in e for e in controller.errors)


# ---------------------------------------------------------------------------
# Controller: membership
# ---------------------------------------------------------------------------

class TestMembership:
    def test_exactly_one_verified_child(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        assert membership == W.Membership(PID, CREATED, 1)
        assert controller.ownership == "owned_with_child"

    @pytest.mark.parametrize("overrides, args, message", [
        ({"in_job": 0}, None, "outside the job"),
        ({"pids": [PID, 999]}, None, "not \\[4242\\]"),
        ({"pids": []}, None, "not \\[4242\\]"),
        ({"pids": [999]}, None, "not \\[4242\\]"),
        ({"accounting": {"active": 2, "total": 2, "terminated": 0}}, None, "2 active"),
        ({"accounting": {"active": 1, "total": 2, "terminated": 1}}, None,
         "2 processes have been in the job, not 1"),
        ({"accounting": {"active": 1, "total": 0, "terminated": 0}}, None,
         "0 processes have been in the job"),
        ({}, (PROCESS, PID, CREATED, "2026-10-09T12:00:01.000Z"), "creation time differs"),
        ({}, (0, PID, CREATED, CREATED), "no valid process handle"),
        ({}, (PROCESS, 0, CREATED, CREATED), "PID is invalid"),
        ({}, (PROCESS, True, CREATED, CREATED), "PID is invalid"),
    ])
    def test_contradictory_membership(self, monkeypatch, overrides, args, message):
        controller, kernel32 = make_controller(monkeypatch, **overrides)
        controller.configure()
        with pytest.raises(W.JobFailure, match=message) as raised:
            controller.verify_membership(*(args or (PROCESS, PID, CREATED, CREATED)),
                                         creation_for(monkeypatch))
        assert raised.value.key == "not_in_job"
        assert controller.ownership == "retained_unverified" and controller.membership is None
        assert kernel32.closed == []                              # never silently closed

    def test_native_error_during_membership(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        controller.configure()
        kernel32.fail = {"QueryInformationJobObject"}
        with pytest.raises(W.JobFailure, match="Win32Error"):
            controller.verify_membership(PROCESS, PID, CREATED, CREATED, creation_for(monkeypatch))
        assert controller.ownership == "retained_unverified" and kernel32.closed == []

    def test_membership_requires_a_configured_job(self, monkeypatch):
        controller, _ = make_controller(monkeypatch)
        with pytest.raises(W.JobFailure, match="membership in state none"):
            controller.verify_membership(PROCESS, PID, CREATED, CREATED, creation_for(monkeypatch))

    def test_membership_reads_identity_accounting_and_limits(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        controller.configure()
        start = len(kernel32.log)
        controller.verify_membership(PROCESS, PID, CREATED, CREATED, creation_for(monkeypatch))
        assert kernel32.log[start:] == ["IsProcessInJob", "QueryInformationJobObject",
                                        "QueryInformationJobObject",
                                        "QueryInformationJobObject", "GetHandleInformation"]
        assert kernel32.in_job_calls == [(PROCESS, JOB)]

    @pytest.mark.parametrize("change, message", [
        ({"readback": (0x2408 | 0x800, 1)}, "breakaway flags present"),
        ({"readback": (0x0408, 1)}, "required limit flags missing"),
        ({"readback": (0x2408, 2)}, "active process limit is 2"),
        ({"inherit_flags": 1}, "inheritable"),
    ])
    def test_limits_changed_before_membership(self, monkeypatch, change, message):
        controller, kernel32 = make_controller(monkeypatch)
        controller.configure()
        kernel32.__dict__.update(change)
        with pytest.raises(W.JobFailure, match=message) as raised:
            controller.verify_membership(PROCESS, PID, CREATED, CREATED, creation_for(monkeypatch))
        assert raised.value.key == "job_readback_mismatch"
        assert controller.ownership == "retained_unverified" and kernel32.closed == []


# ---------------------------------------------------------------------------
# Configuration policy (no membership placeholder)
# ---------------------------------------------------------------------------

READBACKS = [
    {"limit_flags": 0x2408, "active_process_limit": 1},
    {"limit_flags": 0x0408, "active_process_limit": 1},
    {"limit_flags": 0x2408 | 0x1000, "active_process_limit": 1},
    {"limit_flags": 0x2408 | 0x2, "active_process_limit": 1},
    {"limit_flags": 0x2408, "active_process_limit": 0},
    {"limit_flags": 0x2408, "active_process_limit": True},
    {"limit_flags": -1, "active_process_limit": 1},
    {"limit_flags": None, "active_process_limit": 1},
    {},
]


class TestConfigurationProblems:
    @pytest.mark.parametrize("readback", READBACKS)
    @pytest.mark.parametrize("inheritable", [False, True, None])
    def test_matches_the_planner_policy(self, readback, inheritable):
        planner = P.job_limits_problems({**readback, "job_handle_inheritable": inheritable,
                                         "in_job_before_resume": True})
        assert W.configuration_problems(readback, inheritable) == planner

    def test_membership_is_not_configuration(self):
        assert W.configuration_problems({"limit_flags": 0x2408, "active_process_limit": 1},
                                        False) == []
        assert W.configuration_problems(None, False) == ["no job read-back"]
        code = SOURCE.split('"""', 2)[2]
        assert "in_job_before_resume" not in code and "job_limits_problems" not in code

    def test_configure_uses_the_real_inheritance(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        seen = []
        real = W.configuration_problems
        monkeypatch.setattr(W, "configuration_problems",
                            lambda readback, inheritable: seen.append(inheritable)
                            or real(readback, inheritable))
        controller.configure()
        assert seen == [False]


# ---------------------------------------------------------------------------
# Creation planning (pure)
# ---------------------------------------------------------------------------

OUT, ERR = 0x204, 0x208


class TestAttributePlan:
    def test_constants(self):
        assert (W.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, W.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                W.PROC_THREAD_ATTRIBUTE_JOB_LIST) == (0x00020009, 0x00020002, 0x0002000D)
        assert W.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES == \
            C.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
        assert W.PROC_THREAD_ATTRIBUTE_HANDLE_LIST == C.PROC_THREAD_ATTRIBUTE_HANDLE_LIST
        assert C.CREATION_FLAGS & 0x01000000 == 0                 # no CREATE_BREAKAWAY_FROM_JOB

    def test_exact_immutable_plan(self):
        plan = W.job_list_attribute_plan(JOB, OUT, ERR)
        assert plan.entries == (
            W.AttributeEntry(0x00020009, "security_capabilities", ()),
            W.AttributeEntry(0x00020002, "handle_list", (OUT, ERR)),
            W.AttributeEntry(0x0002000D, "job_list", (JOB,)))
        assert isinstance(plan.entries, tuple)
        assert all(isinstance(entry.handles, tuple) for entry in plan.entries)
        with pytest.raises(AttributeError):
            plan.entries = ()
        with pytest.raises(AttributeError):
            plan.entries[2].handles = (OUT,)
        assert len({entry.attribute for entry in plan.entries}) == 3   # each updated once

    def test_count_is_derived(self):
        plan = W.job_list_attribute_plan(JOB, OUT, ERR)
        assert plan.count == len(plan.entries) == 3
        assert W.AttributePlan(plan.entries[:2]).count == 2
        assert isinstance(type(plan).count, property)

    def test_job_absent_from_the_handle_list(self):
        plan = W.job_list_attribute_plan(JOB, OUT, ERR)
        handle_list = [e for e in plan.entries if e.name == "handle_list"][0]
        job_list = [e for e in plan.entries if e.name == "job_list"][0]
        assert JOB not in handle_list.handles and job_list.handles == (JOB,)

    @pytest.mark.parametrize("bad", [0, -1, None, True, False, "0x500", 1.5,
                                     (1 << 32) - 1, (1 << 64) - 1])
    @pytest.mark.parametrize("position", [0, 1, 2])
    def test_invalid_handles(self, bad, position):
        handles = [JOB, OUT, ERR]
        handles[position] = bad
        label = ("job", "stdout", "stderr")[position]
        with pytest.raises(W.PlanRefused, match=f"the {label} handle is invalid"):
            W.job_list_attribute_plan(*handles)

    @pytest.mark.parametrize("handles, message", [
        ((JOB, JOB, ERR), "never be in the inherited handle list"),
        ((JOB, OUT, JOB), "never be in the inherited handle list"),
        ((JOB, JOB, JOB), "never be in the inherited handle list"),
        ((JOB, OUT, OUT), "distinct"),
    ])
    def test_duplicate_handles(self, handles, message):
        with pytest.raises(W.PlanRefused, match=message):
            W.job_list_attribute_plan(*handles)

    def test_plan_refusal_is_a_calibration_error(self):
        assert issubclass(W.PlanRefused, C.CalibrationError)


class TestAttributeListSizing:
    @pytest.mark.parametrize("first, error, size", [(False, 122, 64), (0, 122, 4096),
                                                    (False, 122, 1)])
    def test_valid(self, first, error, size):
        assert W.validate_attribute_list_size(first, error, size) == size

    @pytest.mark.parametrize("first, error, size, message", [
        (True, 122, 64, "not FALSE"),
        (1, 122, 64, "not FALSE"),
        (None, 122, 64, "not FALSE"),
        ("0", 122, 64, "not FALSE"),
        (False, 0, 64, "not ERROR_INSUFFICIENT_BUFFER"),
        (False, 87, 64, "not ERROR_INSUFFICIENT_BUFFER"),
        (False, 122.0, 64, "not ERROR_INSUFFICIENT_BUFFER"),
        (False, None, 64, "not ERROR_INSUFFICIENT_BUFFER"),
        (False, 122, 0, "implausible"),
        (False, 122, -8, "implausible"),
        (False, 122, 4097, "implausible"),
        (False, 122, True, "implausible"),
        (False, 122, 64.0, "implausible"),
        (False, 122, None, "implausible"),
    ])
    def test_refusals(self, first, error, size, message):
        with pytest.raises(W.PlanRefused, match=message):
            W.validate_attribute_list_size(first, error, size)

    def test_bound(self):
        assert (W.ERROR_INSUFFICIENT_BUFFER, W.ATTRIBUTE_LIST_SIZE_LIMIT) == (122, 4096)


# ---------------------------------------------------------------------------
# Parent-job inventory (mocked)
# ---------------------------------------------------------------------------

class InjectedApi:
    """A scripted parent-job API (no native layer at all)."""

    def __init__(self, in_job=False, limits=None, error=None):
        self.in_job, self.limits, self.error, self.calls = in_job, limits, error, []

    def parent_in_any_job(self):
        self.calls.append("presence")
        if self.error is not None:
            raise self.error
        return self.in_job

    def current_job_limits(self):
        self.calls.append("limits")
        return self.limits or {"limit_flags": 0, "active_process_limit": 0}


class TestParentJobInventory:
    def test_not_in_a_job_proceeds(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        inventory = W.parent_job_inventory(api)
        assert (inventory.in_job, inventory.decision, inventory.key) == (False, "proceed", None)
        assert kernel32.log == ["IsProcessInJob"] and kernel32.query_jobs == []

    def test_pseudo_handle_and_null_job(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        W.parent_job_inventory(api)
        assert kernel32.in_job_calls == [(-1, None)] and W.CURRENT_PROCESS == -1
        assert not C._valid_handle(W.CURRENT_PROCESS)       # never treated as owned

    def test_in_a_job_refuses_with_diagnostics(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch, parent_in_job=1, parent_limits=(0x2000, 0))
        inventory = W.parent_job_inventory(api)
        assert (inventory.in_job, inventory.decision, inventory.key) == (
            True, "refuse", "nested_job_incompatible")
        assert dict(inventory.diagnostics) == {"limit_flags": 0x2000, "active_process_limit": 0}
        assert kernel32.log == ["IsProcessInJob", "QueryInformationJobObject"]
        assert kernel32.query_jobs == [None]
        with pytest.raises(TypeError):
            inventory.diagnostics["limit_flags"] = 0            # read-only

    @pytest.mark.parametrize("limits", [(0, 0), (0x2000, 0), (0x2408, 1), (0x800, 0),
                                        (0xFFFFFFFF, 99)])
    def test_diagnostics_never_change_the_refusal(self, monkeypatch, limits):
        api, _ = make_api(monkeypatch, parent_in_job=1, parent_limits=limits)
        assert W.parent_job_inventory(api).decision == "refuse"

    def test_unreadable_diagnostics_still_refuse(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch, parent_in_job=1,
                                 fail={"QueryInformationJobObject"})
        inventory = W.parent_job_inventory(api)
        assert inventory.decision == "refuse" and inventory.in_job is True
        assert "QueryInformationJobObject failed" in inventory.diagnostics["error"]

    def test_api_error_refuses(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch, fail={"IsProcessInJob"}, last_error=5)
        inventory = W.parent_job_inventory(api)
        assert (inventory.in_job, inventory.decision, inventory.key) == (
            None, "refuse", "nested_job_incompatible")
        assert "IsProcessInJob failed (Windows error 5)" in inventory.reason
        assert kernel32.query_jobs == [] and inventory.diagnostics is None

    @pytest.mark.parametrize("value", [2, -1, 0xFFFFFFFF])
    def test_malformed_native_result_refuses(self, monkeypatch, value):
        api, kernel32 = make_api(monkeypatch, parent_in_job=value)
        inventory = W.parent_job_inventory(api)
        assert inventory.decision == "refuse" and inventory.in_job is None
        assert "malformed result" in inventory.reason and kernel32.query_jobs == []

    @pytest.mark.parametrize("value", [None, 0, 1, "false", "False", [], object()])
    def test_malformed_injected_result_refuses(self, value):
        api = InjectedApi(in_job=value)
        inventory = W.parent_job_inventory(api)
        assert inventory.decision == "refuse" and inventory.key == "nested_job_incompatible"
        assert api.calls == ["presence"]                    # limits never consulted

    def test_query_is_never_the_presence_test(self):
        api = InjectedApi(error=C.Win32Error("IsProcessInJob", 6))
        assert W.parent_job_inventory(api).decision == "refuse"
        assert api.calls == ["presence"]
        api = InjectedApi(in_job=False)
        assert W.parent_job_inventory(api).decision == "proceed"
        assert api.calls == ["presence"]
        api = InjectedApi(in_job=True)
        W.parent_job_inventory(api)
        assert api.calls == ["presence", "limits"]

    def test_pure_decision(self):
        assert W.parent_job_decision(False).decision == "proceed"
        for value in (True, None, 0, 1, "no", 0.0):
            decision = W.parent_job_decision(value)
            assert decision.decision == "refuse" and decision.key == "nested_job_incompatible"
        assert W.parent_job_decision(False, error="boom").decision == "refuse"
        assert W.parent_job_decision(True, {"x": 1}).diagnostics == {"x": 1}
        with pytest.raises(AttributeError):
            W.parent_job_decision(False).decision = "proceed"

    def test_refusal_key_is_a_prelaunch_refusal(self):
        action = P.FAILURE_ACTIONS[W.PARENT_JOB_REFUSAL]
        assert action["action_class"] == "prelaunch_refusal"
        assert action["containment"] == "none"

    def test_gate_closed_propagates_before_any_call(self, monkeypatch):
        api, kernel32 = make_api(monkeypatch)
        monkeypatch.setattr(C, "APPROVED_PROBES", frozenset())
        with pytest.raises(C.ExecutionDisabled):
            W.parent_job_inventory(api)
        assert kernel32.log == [] and kernel32.loads == []


# ---------------------------------------------------------------------------
# No after-creation assignment, no implicit termination
# ---------------------------------------------------------------------------

class TestNoFallback:
    def test_no_assignment_api(self, monkeypatch):
        assert "AssignProcessToJobObject" not in SOURCE
        api, kernel32 = make_api(monkeypatch)
        assert not hasattr(api, "assign") and not hasattr(W.JobController, "assign")
        with pytest.raises(KeyError):
            api._api("AssignProcessToJobObject")
        with pytest.raises(LiveAccessAttempt, match="unexpected Windows API"):
            FakeDll(kernel32).AssignProcessToJobObject
        assert kernel32.loads == []

    @pytest.mark.parametrize("overrides", [
        {"in_job": 0}, {"pids": []}, {"accounting": {"active": 1, "total": 2, "terminated": 1}},
        {"fail": {"IsProcessInJob"}},
    ])
    def test_membership_failure_only_reads(self, monkeypatch, overrides):
        controller, kernel32 = make_controller(monkeypatch)
        controller.configure()
        start = len(kernel32.log)
        kernel32.__dict__.update(overrides)
        with pytest.raises(W.JobFailure):
            controller.verify_membership(PROCESS, PID, CREATED, CREATED, creation_for(monkeypatch))
        assert set(kernel32.log[start:]) <= {"IsProcessInJob", "QueryInformationJobObject",
                                             "GetHandleInformation"}
        assert kernel32.terminated == [] and kernel32.closed == []

    def test_planning_and_inventory_never_terminate(self, monkeypatch):
        W.job_list_attribute_plan(JOB, OUT, ERR)
        W.validate_attribute_list_size(False, 122, 64)
        for parent in (0, 1):
            api, kernel32 = make_api(monkeypatch, parent_in_job=parent)
            W.parent_job_inventory(api)
            assert "TerminateJobObject" not in kernel32.log
            assert "CloseHandle" not in kernel32.log and kernel32.terminated == []

    def test_pure_helpers_load_nothing(self, monkeypatch):
        kernel32 = FakeKernel32()
        W.job_list_attribute_plan(JOB, OUT, ERR)
        W.validate_attribute_list_size(0, 122, 64)
        W.parent_job_decision(False)
        W.configuration_problems({"limit_flags": 0x2408, "active_process_limit": 1}, False)
        assert kernel32.loads == [] and kernel32.log == []


# ---------------------------------------------------------------------------
# Configuration delegated to the planner (J-36)
# ---------------------------------------------------------------------------

GOOD_LIMITS = {"limit_flags": 0x2408, "active_process_limit": 1}


class TestConfigurationDelegation:
    def test_delegates_with_the_measured_inheritance(self, monkeypatch):
        seen = []
        monkeypatch.setattr(P, "job_configuration_problems",
                            lambda readback: seen.append(readback) or ["planner verdict"])
        assert W.configuration_problems(GOOD_LIMITS, False) == ["planner verdict"]
        assert W.configuration_problems({**GOOD_LIMITS, "job_handle_inheritable": False},
                                        True) == ["planner verdict"]
        assert seen == [{**GOOD_LIMITS, "job_handle_inheritable": False},
                        {**GOOD_LIMITS, "job_handle_inheritable": True}]   # measured wins

    def test_configure_and_membership_use_the_planner(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        monkeypatch.setattr(P, "job_configuration_problems", lambda readback: ["planner no"])
        with pytest.raises(W.JobFailure, match="planner no") as raised:
            controller.configure()
        assert raised.value.key == "job_readback_mismatch" and kernel32.closed == [JOB]

    def test_no_second_rule_implementation(self):
        code = SOURCE.split('"""', 2)[2]
        for phrase in ("required limit flags missing", "breakaway flags present",
                       "unexpected limit flags", "active process limit is",
                       "prohibited_flags", "limit_flags missing or malformed"):
            assert phrase not in code, phrase
        assert "P.job_configuration_problems(" in code

    @pytest.mark.parametrize("readback, inheritable, expected", [
        (GOOD_LIMITS, False, []),
        ({"limit_flags": 0x0408, "active_process_limit": 1}, False,
         ["required limit flags missing: 0x2000"]),
        ({"limit_flags": 0x2008, "active_process_limit": 1}, False,
         ["required limit flags missing: 0x400"]),
        ({"limit_flags": 0x2408 | 0x800, "active_process_limit": 1}, False,
         ["breakaway flags present: 0x800"]),
        ({"limit_flags": 0x2408 | 0x1000, "active_process_limit": 1}, False,
         ["breakaway flags present: 0x1000"]),
        ({"limit_flags": 0x2408, "active_process_limit": 2}, False,
         ["active process limit is 2, not 1"]),
        ({"limit_flags": 0x2408, "active_process_limit": 0}, False,
         ["active process limit is 0, not 1"]),
        (GOOD_LIMITS, True, ["the job handle is (or may be) inheritable"]),
        (GOOD_LIMITS, None, ["the job handle is (or may be) inheritable"]),
        (None, False, ["no job read-back"]),
        ({}, False, ["limit_flags missing or malformed"]),
        ({"limit_flags": "x", "active_process_limit": 1}, False,
         ["limit_flags missing or malformed"]),
        ({"limit_flags": 0x2408}, False, ["active process limit is None, not 1"]),
    ])
    def test_acceptance_and_refusal_preserved(self, readback, inheritable, expected):
        assert W.configuration_problems(readback, inheritable) == expected

    @pytest.mark.parametrize("readback", [(0x0408, 1), (0x2408 | 0x800, 1), (0x2408, 2),
                                          (0x2408 | 0x1000, 1)])
    def test_configure_refuses_bad_readback(self, monkeypatch, readback):
        controller, kernel32 = make_controller(monkeypatch, readback=readback)
        with pytest.raises(W.JobFailure) as raised:
            controller.configure()
        assert raised.value.key == "job_readback_mismatch"
        assert controller.ownership == "closed" and kernel32.closed == [JOB]


# ---------------------------------------------------------------------------
# Membership evidence and assignment-at-creation provenance (J-36)
# ---------------------------------------------------------------------------

def configured(monkeypatch, **overrides):
    controller, kernel32 = make_controller(monkeypatch, **overrides)
    controller.configure()
    return controller, kernel32


class TestMembershipEvidence:
    def test_exact_fields_and_values(self, monkeypatch):
        _, _, membership = verified(monkeypatch)
        assert tuple(membership.evidence) == P.JOB_MEMBERSHIP_FIELDS
        assert dict(membership.evidence) == {
            "job_assignment": "assigned_at_creation", "in_job": True, "pid": PID,
            "creation_time": CREATED, "active_processes": 1, "total_processes": 1,
            "member_pids": (PID,)}
        assert P.job_membership_problems(membership.evidence, expected_pid=PID,
                                         expected_creation_time=CREATED) == []

    def test_evidence_is_immutable(self, monkeypatch):
        _, _, membership = verified(monkeypatch)
        with pytest.raises(TypeError):
            membership.evidence["total_processes"] = 2
        assert isinstance(membership.evidence["member_pids"], tuple)
        with pytest.raises(AttributeError):
            membership.evidence = {}

    def test_evidence_drives_the_lifecycle(self, monkeypatch):
        _, _, membership = verified(monkeypatch)
        state = P.lifecycle_transition(P.LifecycleState(), "created", {
            "pid": PID, "creation_time": CREATED, "job_assignment": "assigned_at_creation",
            "job_limits_verified": True})
        state = P.lifecycle_transition(state, "job_assigned", dict(membership.evidence))
        assert state.phase == "job_assigned" and state.execution_history == P.NEVER_EXECUTED

    def _refused(self, controller, kernel32, creation, key, message, *, start=None,
                 args=(PROCESS, PID, CREATED, CREATED)):
        start = len(kernel32.log) if start is None else start
        with pytest.raises(W.JobFailure, match=message) as raised:
            controller.verify_membership(*args, creation)
        assert raised.value.key == key
        assert controller.ownership == "retained_unverified" and controller.membership is None
        assert kernel32.closed == [] and kernel32.terminated == []    # handles retained
        return kernel32.log[start:]

    def test_missing_assertion_refuses_before_any_native_call(self, monkeypatch):
        controller, kernel32 = configured(monkeypatch)
        calls = self._refused(controller, kernel32, None, "assignment_failed",
                              "observed membership alone does not prove")
        assert calls == []

    def test_observed_membership_cannot_prove_assignment(self, monkeypatch):
        controller, kernel32 = configured(monkeypatch)       # the fake reports a perfect member
        assert kernel32.in_job == 1 and kernel32.pids == [PID]
        self._refused(controller, kernel32, None, "assignment_failed", "alone does not prove")
        with pytest.raises(W.ProvenanceRefused):
            W._membership_evidence(None, in_job=True, member_pids=[PID], active=1, total=1)

    def test_assertion_cannot_be_minted_by_default(self):
        assert W.JOB_LIST_CREATION_INTEGRATED is False
        plan = W.job_list_attribute_plan(JOB, STDOUT_HANDLE, STDERR_HANDLE)
        with pytest.raises(W.ProvenanceRefused, match="no JOB_LIST integration"):
            W._assert_created_with_job_list(plan, JOB, PID, CREATED)
        harness = (_BENCH / "calibrate_generator.py").read_text(encoding="utf-8")
        assert "_assert_created_with_job_list" not in harness and "CreationAssertion" not in harness
        code = SOURCE.split('"""', 2)[2]
        assert "JOB_LIST_CREATION_INTEGRATED: bool = False" in code

    @pytest.mark.parametrize("seal", [None, object(), "seal"])
    def test_forged_assertions_refuse(self, monkeypatch, seal):
        controller, kernel32 = configured(monkeypatch)
        forged = W.CreationAssertion(JOB, PID, CREATED, seal)
        self._refused(controller, kernel32, forged, "assignment_failed", "not authentic")
        controller, kernel32 = configured(monkeypatch)
        self._refused(controller, kernel32, {"job": JOB, "pid": PID}, "assignment_failed",
                      "not authentic")

    def test_after_creation_assignment_refuses(self, monkeypatch):
        monkeypatch.setattr(W, "JOB_LIST_CREATION_INTEGRATED", True)
        other_job_plan = W.job_list_attribute_plan(0x900, STDOUT_HANDLE, STDERR_HANDLE)
        with pytest.raises(W.ProvenanceRefused, match="does not name exactly this job"):
            W._assert_created_with_job_list(other_job_plan, JOB, PID, CREATED)
        with pytest.raises(W.ProvenanceRefused, match="no attribute plan"):
            W._assert_created_with_job_list(None, JOB, PID, CREATED)
        no_job_list = W.AttributePlan(other_job_plan.entries[:2])
        with pytest.raises(W.ProvenanceRefused, match="does not name exactly this job"):
            W._assert_created_with_job_list(no_job_list, JOB, PID, CREATED)
        for pid, created in ((0, CREATED), (True, CREATED), (PID, ""), (PID, None)):
            with pytest.raises(W.ProvenanceRefused):
                W._assert_created_with_job_list(
                    W.job_list_attribute_plan(JOB, STDOUT_HANDLE, STDERR_HANDLE), JOB, pid,
                    created)
        monkeypatch.setattr(W, "JOB_LIST_CREATION_INTEGRATED", False)
        assert not hasattr(W.JobController, "assign") and "AssignProcessToJobObject" not in SOURCE

    def test_assertion_for_another_job_refuses(self, monkeypatch):
        controller, kernel32 = configured(monkeypatch)
        self._refused(controller, kernel32, creation_for(monkeypatch, job=0x900),
                      "assignment_failed", "another job or child")

    def test_pid_mismatch_refuses(self, monkeypatch):
        controller, kernel32 = configured(monkeypatch)
        self._refused(controller, kernel32, creation_for(monkeypatch, pid=999),
                      "assignment_failed", "another job or child")
        controller, kernel32 = configured(monkeypatch, pids=[999])
        self._refused(controller, kernel32, creation_for(monkeypatch), "not_in_job",
                      "not \\[4242\\]")

    def test_creation_time_mismatch_refuses(self, monkeypatch):
        controller, kernel32 = configured(monkeypatch)
        self._refused(controller, kernel32,
                      creation_for(monkeypatch, created="2026-10-09T12:00:01.000Z"),
                      "assignment_failed", "another job or child")
        controller, kernel32 = configured(monkeypatch)
        self._refused(controller, kernel32, creation_for(monkeypatch), "not_in_job",
                      "creation time differs",
                      args=(PROCESS, PID, CREATED, "2026-10-09T12:00:01.000Z"))

    @pytest.mark.parametrize("accounting, message", [
        ({"active": 0, "total": 1, "terminated": 1}, "0 active processes"),
        ({"active": 2, "total": 2, "terminated": 0}, "2 active processes"),
        ({"active": 1, "total": 0, "terminated": 0}, "0 processes have been in the job"),
        ({"active": 1, "total": 2, "terminated": 1}, "2 processes have been in the job"),
    ])
    def test_process_counts_refuse(self, monkeypatch, accounting, message):
        controller, kernel32 = configured(monkeypatch, accounting=accounting)
        self._refused(controller, kernel32, creation_for(monkeypatch), "not_in_job", message)

    @pytest.mark.parametrize("pids", [[PID, 7], [], [7], [PID, PID]])
    def test_member_list_refuses(self, monkeypatch, pids):
        controller, kernel32 = configured(monkeypatch, pids=pids)
        self._refused(controller, kernel32, creation_for(monkeypatch), "not_in_job",
                      "job members are")

    def test_planner_validator_is_applied(self, monkeypatch):
        calls = []

        def planner(evidence, *, expected_pid, expected_creation_time):
            calls.append((dict(evidence), expected_pid, expected_creation_time))
            return ["planner rejects"]

        controller, kernel32 = configured(monkeypatch)
        monkeypatch.setattr(P, "job_membership_problems", planner)
        self._refused(controller, kernel32, creation_for(monkeypatch), "not_in_job",
                      "membership evidence refused: planner rejects")
        assert calls == [({"job_assignment": "assigned_at_creation", "in_job": True,
                           "pid": PID, "creation_time": CREATED, "active_processes": 1,
                           "total_processes": 1, "member_pids": (PID,)}, PID, CREATED)]

    @pytest.mark.parametrize("observed, message", [
        ({"member_pids": [PID, 7]}, "job members are"),
        ({"total": 2}, "2 processes have been in the job"),
        ({"active": 0}, "0 active processes"),
        ({"in_job": False}, "not in the job"),
    ])
    def test_planner_rejects_invalid_evidence(self, monkeypatch, observed, message):
        values = {"in_job": True, "member_pids": [PID], "active": 1, "total": 1} | observed
        evidence = W._membership_evidence(creation_for(monkeypatch), **values)
        problems = P.job_membership_problems(evidence, expected_pid=PID,
                                             expected_creation_time=CREATED)
        assert any(message in problem for problem in problems)

    def test_failed_verification_retains_and_never_closes(self, monkeypatch):
        controller, kernel32 = configured(monkeypatch, accounting={"active": 1, "total": 2,
                                                                   "terminated": 1})
        self._refused(controller, kernel32, creation_for(monkeypatch), "not_in_job",
                      "2 processes")
        with pytest.raises(W.JobFailure, match="unsafe_close_refused"):
            controller.close()
        assert kernel32.closed == [] and "TerminateJobObject" not in kernel32.log
        assert "CloseHandle" not in kernel32.log

    def test_termination_reverification_reuses_the_assertion(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        outcome = controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                       wait=_wait(True), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert outcome.verified and controller.ownership == "child_exited"

    def test_only_the_fake_dll_is_loaded(self, monkeypatch):
        _, kernel32, _ = verified(monkeypatch)
        assert kernel32.loads == ["kernel32"]
        with pytest.raises(LiveAccessAttempt):
            ctypes.WinDLL("kernel32")


# ---------------------------------------------------------------------------
# Controller: termination (gated)
# ---------------------------------------------------------------------------

def _wait(signaled=True, log=None):
    def wait(process, milliseconds):
        if log is not None:
            log.append(("wait", process, milliseconds))
        return signaled
    return wait


def _code(value):
    return lambda process: value


class TestTerminationGate:
    def test_design_only_policy_blocks_before_any_native_call(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        assert P.TERMINATION_POLICY == "conditionally_accepted_design_only"
        calls_before = list(kernel32.log)
        with pytest.raises(W.TerminationRefused, match="not accepted"):
            controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                 wait=_wait(), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert kernel32.terminated == [] and kernel32.log == calls_before
        assert controller.ownership == "owned_with_child"

    @pytest.mark.parametrize("policy", ["conditionally_accepted_design_only", "never",
                                        "Accepted", ""])
    def test_every_other_policy_value_refuses(self, monkeypatch, policy):
        controller, kernel32, membership = verified(monkeypatch)
        monkeypatch.setattr(P, "TERMINATION_POLICY", policy)
        with pytest.raises(W.TerminationRefused):
            controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                 wait=_wait(), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert kernel32.terminated == []

    def test_refused_without_authorization_even_with_policy(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        monkeypatch.setattr(C, "PROBE_ENABLED", False)
        with pytest.raises(C.ExecutionDisabled):
            controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                 wait=_wait(), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert kernel32.terminated == []


class TestTerminationInterface:
    """The future interface, reachable only with the policy accepted in
    memory and a fake kernel32."""

    def test_verified_termination(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        waits = []
        outcome = controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                       wait=_wait(True, waits),
                                       exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert outcome.verified and outcome.active_after == 0
        assert kernel32.terminated == [(JOB, P.TIMEOUT_EXIT_CODE)]
        assert waits == [("wait", PROCESS, 5000)]
        assert controller.ownership == "child_exited"
        state = P.LifecycleState(phase="resumed", process_created=True, pid=PID,
                                 creation_time=CREATED, job_assignment="assigned_at_creation",
                                 job_limits_verified=True,
                                 execution_history=P.MAY_HAVE_EXECUTED,
                                 liveness=P.ALIVE_AT_LAST_CHECK, handles_retained=True)
        state = P.lifecycle_transition(state, "terminate_result",
                                       outcome.lifecycle_evidence(PID, CREATED))
        assert (state.liveness, state.termination_cause) == (P.CONFIRMED_EXITED,
                                                             "job_terminated_timeout")
        controller.close()
        assert controller.ownership == "closed" and kernel32.closed == [JOB]

    def test_stale_membership_never_terminates(self, monkeypatch):
        controller, kernel32, old = verified(monkeypatch)
        controller.verify_membership(PROCESS, PID, CREATED, CREATED, creation_for(monkeypatch))       # newer snapshot
        accept_policy(monkeypatch)
        with pytest.raises(W.TerminationRefused, match="stale or foreign"):
            controller.terminate("job_terminated_timeout", PROCESS, old, CREATED,
                                 wait=_wait(), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        foreign = W.Membership(999, CREATED, controller.membership.epoch)
        with pytest.raises(W.TerminationRefused, match="stale or foreign"):
            controller.terminate("job_terminated_timeout", PROCESS, foreign, CREATED,
                                 wait=_wait(), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert kernel32.terminated == []

    @pytest.mark.parametrize("change", [
        {"pids": [PID, 999]}, {"pids": []}, {"in_job": 0},
        {"accounting": {"active": 2, "total": 2, "terminated": 0}},
    ])
    def test_membership_changed_since_the_snapshot(self, monkeypatch, change):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        kernel32.__dict__.update(change)
        with pytest.raises(W.TerminationRefused, match="no longer verified"):
            controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                 wait=_wait(), exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert kernel32.terminated == [] and controller.ownership == "retained_unverified"

    def test_wrong_handle_identity_never_terminates(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        with pytest.raises(W.TerminationRefused):
            controller.terminate("job_terminated_timeout", PROCESS, membership,
                                 "2026-10-09T13:00:00.000Z", wait=_wait(),
                                 exit_code=_code(P.TIMEOUT_EXIT_CODE))
        assert kernel32.terminated == []

    def test_unknown_cause(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        with pytest.raises(W.TerminationRefused, match="unknown cause"):
            controller.terminate("reboot", PROCESS, membership, CREATED, wait=_wait(),
                                 exit_code=_code(0))
        assert kernel32.terminated == []

    @pytest.mark.parametrize("overrides, wait, code, active_reason", [
        ({"fail": {"TerminateJobObject"}}, _wait(True), P.TIMEOUT_EXIT_CODE, "api failure"),
        ({}, _wait(False), P.TIMEOUT_EXIT_CODE, "no signal"),
        ({}, _wait(True), 0, "wrong exit code"),
        ({"empty_on_terminate": False}, _wait(True), P.TIMEOUT_EXIT_CODE, "job not empty"),
    ])
    def test_termination_without_exit_proof(self, monkeypatch, overrides, wait, code,
                                            active_reason):
        controller, kernel32, membership = verified(monkeypatch, **overrides)
        accept_policy(monkeypatch)
        outcome = controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                       wait=wait, exit_code=_code(code))
        assert not outcome.verified, active_reason
        assert controller.ownership == "retained_unverified"
        assert any("exit not verified" in e for e in controller.errors)
        with pytest.raises(W.TerminationRefused, match="no verified child"):
            controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                 wait=wait, exit_code=_code(code))     # never retried
        with pytest.raises(W.JobFailure, match="unsafe_close_refused"):
            controller.close()
        assert kernel32.closed == [] and len(kernel32.terminated) == 1

    def test_lifecycle_evidence_is_truthful(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)
        outcome = controller.terminate("job_terminated_timeout", PROCESS, membership, CREATED,
                                       wait=_wait(True), exit_code=_code(7))
        assert outcome.lifecycle_evidence(PID, CREATED) == {
            "pid": PID, "creation_time": CREATED, "cause": "job_terminated_timeout",
            "api_ok": True, "signaled": True, "exit_code": 7}

    def test_interrupted_termination_retains_ownership(self, monkeypatch):
        controller, kernel32, membership = verified(monkeypatch)
        accept_policy(monkeypatch)

        def interrupted(process, milliseconds):
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            controller.terminate("job_terminated_operator", PROCESS, membership, CREATED,
                                 wait=interrupted, exit_code=_code(P.OPERATOR_EXIT_CODE))
        assert controller.ownership == "retained_unverified"
        assert any("interrupted" in e for e in controller.errors)
        with pytest.raises(W.JobFailure):
            controller.close()
        assert kernel32.closed == []


# ---------------------------------------------------------------------------
# Controller: natural exit and close
# ---------------------------------------------------------------------------

class TestNaturalExitAndClose:
    def test_natural_exit(self, monkeypatch):
        controller, kernel32, _ = verified(monkeypatch)
        assert controller.record_natural_exit(PROCESS, wait=_wait(False),
                                              exit_code=_code(0)) is None
        assert controller.ownership == "owned_with_child"
        kernel32.accounting = {"active": 0, "total": 1, "terminated": 0}
        assert controller.record_natural_exit(PROCESS, wait=_wait(True),
                                              exit_code=_code(0)) == 0
        assert controller.ownership == "child_exited"
        controller.close()
        assert kernel32.closed == [JOB] and "TerminateJobObject" not in kernel32.log

    def test_exit_with_a_non_empty_job(self, monkeypatch):
        controller, kernel32, _ = verified(monkeypatch)
        with pytest.raises(W.JobFailure, match="not empty"):
            controller.record_natural_exit(PROCESS, wait=_wait(True), exit_code=_code(0))
        assert controller.ownership == "retained_unverified"

    def test_close_an_empty_job(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch,
                                               accounting={"active": 0, "total": 0,
                                                           "terminated": 0})
        controller.configure()
        controller.close()
        assert controller.ownership == "closed" and kernel32.closed == [JOB]
        with pytest.raises(W.JobFailure, match="state closed"):
            controller.close()

    def test_live_child_job_is_never_closed(self, monkeypatch):
        controller, kernel32, _ = verified(monkeypatch)
        with pytest.raises(W.JobFailure, match="unsafe_close_refused"):
            controller.close()
        assert kernel32.closed == [] and controller.ownership == "owned_with_child"

    def test_active_process_found_at_close(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch)
        controller.configure()
        with pytest.raises(W.JobFailure, match="1 active processes"):
            controller.close()
        assert controller.ownership == "retained_unverified" and kernel32.closed == []

    def test_close_failure_is_never_retried(self, monkeypatch):
        controller, kernel32 = make_controller(monkeypatch, fail={"CloseHandle"},
                                               accounting={"active": 0, "total": 0,
                                                           "terminated": 0})
        controller.configure()
        with pytest.raises(W.JobFailure, match="close_failed"):
            controller.close()
        assert controller.ownership == "retained_close_failed"
        with pytest.raises(W.JobFailure, match="state retained_close_failed"):
            controller.close()
        assert kernel32.closed == [JOB]

    def test_ownership_states(self):
        assert W.OWNERSHIP_STATES == (
            "none", "owned_empty", "owned_with_child", "child_exited",
            "retained_unverified", "retained_close_failed", "closed")


# ---------------------------------------------------------------------------
# Offline containment adapter
# ---------------------------------------------------------------------------

THREAD = 0x102


def good_receipt(job=JOB, **changes):
    fields = {"applied_attributes": C.PLAN_ATTRIBUTES, "job_list_handles": (job,),
              "create_process_ok": True, "planned": True}
    fields.update(changes)
    return C.CreationReceipt(**fields)


class FakeCreation:
    """An injected creator and identity reader; no native layer."""

    def __init__(self, receipt="good", pid=PID, process=PROCESS, raises=None,
                 identity=None):
        self.receipt, self.pid, self.process, self.raises = receipt, pid, process, raises
        self.plans, self.identity_calls = [], []
        self.identity = identity if identity is not None else (lambda p: (PID, CREATED))

    def create(self, plan, custody=None):
        self.plans.append(plan)
        if self.raises:
            raise self.raises
        receipt = good_receipt(plan.entries[-1].handles[0]) if self.receipt == "good" \
            else self.receipt
        return C.Win32Handles(self.process, THREAD, self.pid, 77, receipt=receipt)

    def process_identity(self, process):
        self.identity_calls.append(process)
        return self.identity(process)


def make_adapter(monkeypatch, *, integrated=True, creation=None, **kernel_overrides):
    api, kernel32 = make_api(monkeypatch, **kernel_overrides)
    creation = creation or FakeCreation()
    monkeypatch.setattr(W, "JOB_LIST_CREATION_INTEGRATED", integrated)
    adapter = W.ContainmentAdapter(api.auth, api, create=creation.create,
                                   process_identity=creation.process_identity)
    return adapter, kernel32, creation


def prepare(adapter):
    return adapter.prepare(STDOUT_HANDLE, STDERR_HANDLE)


class TestContainmentAdapter:
    def test_success_with_in_memory_gate(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch)
        result = prepare(adapter)
        assert (result.job, result.pid, result.creation_time) == (JOB, PID, CREATED)
        assert isinstance(result.assertion, W.CreationAssertion)
        assert result.assertion.seal is W._CREATION_SEAL
        assert result.membership.evidence["job_assignment"] == "assigned_at_creation"
        assert P.job_membership_problems(result.membership.evidence, expected_pid=PID,
                                         expected_creation_time=CREATED) == []
        assert adapter.controller.ownership == "owned_with_child"
        assert len(creation.plans) == 1
        assert [e.name for e in creation.plans[0].entries] == [
            "security_capabilities", "handle_list", "job_list"]
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_no_assertion_while_the_gate_is_closed(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch, integrated=False)
        with pytest.raises(W.ProvenanceRefused, match="no JOB_LIST integration"):
            prepare(adapter)
        assert W.JOB_LIST_CREATION_INTEGRATED is False
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_parent_in_job_refuses_before_any_job_exists(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch, parent_in_job=1)
        with pytest.raises(W.ContainmentRefused) as raised:
            prepare(adapter)
        assert raised.value.key == W.PARENT_JOB_REFUSAL
        assert creation.plans == [] and kernel32.created_with is None
        assert "CreateJobObjectW" not in kernel32.log and adapter.controller is None

    def test_unknown_parent_status_refuses(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch, fail={"IsProcessInJob"})
        with pytest.raises(W.ContainmentRefused, match="unknown") as raised:
            prepare(adapter)
        assert raised.value.key == W.PARENT_JOB_REFUSAL
        assert creation.plans == [] and "CreateJobObjectW" not in kernel32.log

    @pytest.mark.parametrize("fail, key", [
        ({"CreateJobObjectW"}, "create_job_failed"),
        ({"SetInformationJobObject"}, "set_job_information_failed")])
    def test_configuration_failure(self, monkeypatch, fail, key):
        adapter, kernel32, creation = make_adapter(monkeypatch, fail=fail)
        with pytest.raises(W.JobFailure) as raised:
            prepare(adapter)
        assert raised.value.key == key
        assert creation.plans == []

    def test_wrong_readback_refuses(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch, readback=(0, 0))
        with pytest.raises(W.JobFailure) as raised:
            prepare(adapter)
        assert raised.value.key == "job_readback_mismatch" and creation.plans == []

    def test_inheritable_job_handle_refuses(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch, inherit_flags=1)
        with pytest.raises(W.JobFailure) as raised:
            prepare(adapter)
        assert raised.value.key == "inheritable_job_handle" and creation.plans == []

    @pytest.mark.parametrize("stdout, stderr", [
        (JOB, STDERR_HANDLE), (STDOUT_HANDLE, STDOUT_HANDLE), (0, STDERR_HANDLE),
        (STDOUT_HANDLE, None)])
    def test_bad_output_handles_refuse_before_creation(self, monkeypatch, stdout, stderr):
        adapter, kernel32, creation = make_adapter(monkeypatch)
        with pytest.raises(W.ContainmentRefused, match="plan_refused"):
            adapter.prepare(stdout, stderr)
        assert creation.plans == []

    @pytest.mark.parametrize("receipt, message", [
        (None, "no creation receipt"),
        (good_receipt(planned=False, applied_attributes=C.PLAN_ATTRIBUTES[:2],
                      job_list_handles=()), "legacy/unplanned"),
        (good_receipt(applied_attributes=C.PLAN_ATTRIBUTES[:2]), "JOB_LIST was not applied"),
        (good_receipt(applied_attributes=C.PLAN_ATTRIBUTES[1:]), "incomplete"),
        (good_receipt(applied_attributes=(C.PLAN_ATTRIBUTES[1], C.PLAN_ATTRIBUTES[0],
                                          C.PLAN_ATTRIBUTES[2])), "reordered"),
        (good_receipt(applied_attributes=C.PLAN_ATTRIBUTES + (C.PLAN_ATTRIBUTES[0],)),
         "duplicate"),
        (good_receipt(applied_attributes=C.PLAN_ATTRIBUTES + (0x20010,)), "unexpected"),
        (good_receipt(job_list_handles=(0x900,)), "another job"),
        (good_receipt(job_list_handles=(JOB, 0x900)), "another job"),
        (good_receipt(job_list_handles=()), "another job"),
        (good_receipt(create_process_ok=False), "CreateProcessW success"),
        (good_receipt(create_process_ok=1), "CreateProcessW success"),
        (good_receipt(applied_attributes=list(C.PLAN_ATTRIBUTES)), "malformed"),
        (object(), "not a CreationReceipt"),
        ({"applied_attributes": C.PLAN_ATTRIBUTES}, "not a CreationReceipt"),
    ])
    def test_bad_receipts_refuse_without_an_assertion(self, monkeypatch, receipt, message):
        adapter, kernel32, creation = make_adapter(monkeypatch,
                                                   creation=FakeCreation(receipt=receipt))
        minted = []
        real = W._assert_created_with_job_list
        monkeypatch.setattr(W, "_assert_created_with_job_list",
                            lambda *a: minted.append(a) or real(*a))
        with pytest.raises(W.ContainmentRefused, match=message):
            prepare(adapter)
        assert minted == [] and creation.identity_calls == []
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []
        assert len(creation.plans) == 1                  # no retry, no fallback

    def test_a_caller_supplied_receipt_is_never_consulted(self, monkeypatch):
        # prepare() has no receipt parameter: only the creator's own result counts.
        adapter, _, creation = make_adapter(monkeypatch,
                                            creation=FakeCreation(receipt=None))
        with pytest.raises(W.ContainmentRefused, match="no creation receipt"):
            prepare(adapter)
        with pytest.raises(TypeError):
            adapter.prepare(STDOUT_HANDLE, STDERR_HANDLE, receipt=good_receipt())

    @pytest.mark.parametrize("created", [None, object(), "handles"])
    def test_missing_or_foreign_creation_result_refuses(self, monkeypatch, created):
        creation = FakeCreation(receipt=None)
        creation.create = lambda plan, custody=None: created
        adapter, _, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(W.ContainmentRefused, match="no creation result"):
            prepare(adapter)

    def test_failure_before_the_creator_is_entered_keeps_owned_empty(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(monkeypatch)
        with pytest.raises(W.ContainmentRefused, match="plan_refused"):
            adapter.prepare(JOB, STDERR_HANDLE)
        assert creation.plans == []                       # the creator was never entered
        assert adapter.controller.ownership == "owned_empty"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_creation_failure_has_no_fallback(self, monkeypatch):
        adapter, kernel32, creation = make_adapter(
            monkeypatch, creation=FakeCreation(raises=C.Win32Error("CreateProcessW", 5)))
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        assert len(creation.plans) == 1
        assert adapter.controller.ownership == "retained_unverified"   # outcome unknown
        assert adapter.controller.membership is None
        assert kernel32.closed == [] and kernel32.terminated == []
        with pytest.raises(W.ContainmentRefused, match="already used"):
            prepare(adapter)
        assert len(creation.plans) == 1                   # no retry

    def test_side_effect_then_exception_retains_and_blocks_close(self, monkeypatch):
        class SideEffectCreation(FakeCreation):
            child_created = False

            def create(self, plan, custody=None):
                self.plans.append(plan)
                self.child_created = True                 # a suspended child now exists
                raise RuntimeError("failed after the child was created")

        creation = SideEffectCreation()
        # The unsafe case: nothing in the job, so an accounting check alone would pass.
        adapter, kernel32, _ = make_adapter(
            monkeypatch, creation=creation,
            accounting={"active": 0, "total": 0, "terminated": 0})
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        assert creation.child_created and adapter.controller.ownership == "retained_unverified"
        with pytest.raises(W.JobFailure, match="unsafe_close_refused"):
            adapter.controller.close()
        assert kernel32.closed == [] and kernel32.terminated == []
        assert adapter.controller.ownership == "retained_unverified"

    def test_creator_execution_disabled_propagates_and_retains(self, monkeypatch):
        error = C.ExecutionDisabled("gate closed while creating")
        adapter, kernel32, creation = make_adapter(monkeypatch,
                                                   creation=FakeCreation(raises=error))
        with pytest.raises(C.ExecutionDisabled) as raised:
            prepare(adapter)
        assert raised.value is error
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == [] and len(creation.plans) == 1

    @pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit(3),
                                           GeneratorExit()])
    def test_creator_base_exception_propagates_unchanged_and_retains(self, monkeypatch,
                                                                     interrupt):
        adapter, kernel32, creation = make_adapter(monkeypatch,
                                                   creation=FakeCreation(raises=interrupt))
        with pytest.raises(type(interrupt)) as raised:
            prepare(adapter)
        assert raised.value is interrupt
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == [] and len(creation.plans) == 1

    @pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(1),
                                       RuntimeError("bind broke"), C.ExecutionDisabled("x")])
    def test_bind_abnormal_exit_retains(self, monkeypatch, error):
        adapter, kernel32, creation = make_adapter(monkeypatch)

        def broken(self, plan, job, created):
            raise error

        monkeypatch.setattr(W.ContainmentAdapter, "_bind", broken)
        expected = W.ContainmentRefused if type(error) is RuntimeError else type(error)
        with pytest.raises(expected) as raised:
            prepare(adapter)
        if expected is type(error):
            assert raised.value is error                  # propagated unchanged
        else:
            assert raised.value.key == "not_in_job"
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == [] and len(creation.plans) == 1

    def test_unconfirmed_retention_is_an_explicit_failure(self, monkeypatch):
        class StubbornController(W.JobController):
            @property
            def ownership(self):
                return self.__dict__.get("_o", "none")

            @ownership.setter
            def ownership(self, value):
                if value != "retained_unverified":      # retention silently does not stick
                    self.__dict__["_o"] = value

        monkeypatch.setattr(W, "JobController", StubbornController)
        original = RuntimeError("creator failed")
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=original))
        with pytest.raises(W.ContainmentRefused, match="retention_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "retention_failed" and raised.value.__cause__ is original
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_creator_failure_records_unverified_diagnostics(self, monkeypatch):
        original = RuntimeError("secret detail")
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=original))
        assert adapter.retained_reason is None and adapter.retained_evidence is None
        with pytest.raises(W.ContainmentRefused, match="creation_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "creation_failed"
        assert adapter.retained_reason == "creator_failed_outcome_unknown"
        evidence = adapter.retained_evidence
        assert evidence["stage"] == "creator" and evidence["cause_type"] == "RuntimeError"
        assert evidence["failure_action_key"] == "creation_failed"
        assert evidence["ownership_before"] == "owned_empty"
        assert evidence["ownership_after"] == "retained_unverified"
        assert (evidence["child_existence"], evidence["child_identity"],
                evidence["membership"]) == ("unknown", "unverified", "unverified")
        assert evidence["recovery_authorized"] is False
        assert "secret detail" not in repr(dict(evidence))
        assert str(PID) not in repr(dict(evidence))
        assert evidence["failure_action_key"] in P.FAILURE_ACTIONS
        with pytest.raises(TypeError):
            evidence["stage"] = "x"
        assert kernel32.closed == [] and kernel32.terminated == []

    @pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit(3)])
    def test_creator_interrupt_records_diagnostics_and_propagates(self, monkeypatch,
                                                                  interrupt):
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=interrupt))
        with pytest.raises(type(interrupt)) as raised:
            prepare(adapter)
        assert raised.value is interrupt
        assert adapter.retained_reason == "creator_failed_outcome_unknown"
        assert adapter.retained_evidence["cause_type"] == type(interrupt).__name__
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_bind_failure_records_diagnostics_without_proof(self, monkeypatch):
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=FakeCreation(receipt=None))
        with pytest.raises(W.ContainmentRefused, match="assignment_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "assignment_failed"
        assert adapter.retained_reason == "bind_failed_child_may_exist"
        evidence = adapter.retained_evidence
        assert evidence["stage"] == "bind" and evidence["failure_action_key"] is None
        assert evidence["ownership_after"] == "retained_unverified"
        assert (evidence["child_existence"], evidence["child_identity"],
                evidence["membership"]) == ("unknown", "unverified", "unverified")
        assert adapter.controller.membership is None
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_retention_failure_records_diagnostics_and_keeps_key(self, monkeypatch):
        class StubbornController(W.JobController):
            @property
            def ownership(self):
                return self.__dict__.get("_o", "none")

            @ownership.setter
            def ownership(self, value):
                if value != "retained_unverified":
                    self.__dict__["_o"] = value

        monkeypatch.setattr(W, "JobController", StubbornController)
        original = RuntimeError("creator failed")
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=original))
        with pytest.raises(W.ContainmentRefused, match="retention_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "retention_failed" and raised.value.__cause__ is original
        assert adapter.retained_reason == "retention_unconfirmed"
        assert adapter.retained_evidence["failure_action_key"] == "retention_failed"
        assert adapter.retained_evidence["ownership_after"] == "owned_empty"
        assert adapter.retained_evidence["recovery_authorized"] is False
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_diagnostic_failure_never_masks_the_refusal(self, monkeypatch):
        adapter, _, _ = make_adapter(monkeypatch,
                                     creation=FakeCreation(raises=RuntimeError("x")))

        def broken(*args):
            raise RuntimeError("boom")

        monkeypatch.setattr(W, "MappingProxyType", broken)
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        assert adapter.retained_reason == "creator_failed_outcome_unknown"
        assert adapter.retained_evidence is None
        assert adapter.controller.ownership == "retained_unverified"

    def test_pre_creator_and_success_paths_record_no_diagnostics(self, monkeypatch):
        adapter, _, creation = make_adapter(monkeypatch)
        with pytest.raises(W.ContainmentRefused, match="plan_refused"):
            adapter.prepare(JOB, STDERR_HANDLE)
        assert creation.plans == []
        assert adapter.retained_reason is None and adapter.retained_evidence is None
        adapter, _, _ = make_adapter(monkeypatch)
        prepare(adapter)
        assert adapter.retained_reason is None and adapter.retained_evidence is None

    def test_diagnostics_are_additive_only(self):
        for name in ("assign", "close", "terminate", "recover", "retry"):
            assert not hasattr(W.ContainmentAdapter, name)
        assert not any(hasattr(W, n) for n in ("CreationOutcome", "HandleCustody",
                                               "DefiniteNoChild"))
        assert W.OWNERSHIP_STATES == ("none", "owned_empty", "owned_with_child",
                                      "child_exited", "retained_unverified",
                                      "retained_close_failed", "closed")

    # -- handle custody (B3J-47b) -----------------------------------------------

    @staticmethod
    def _populating(*, enter=True, write=True, then=None, result=None, break_it=False):
        """A creator that writes the handles through the custody it is given,
        as the real one would, then raises `then` or returns `result`."""
        class Populating(FakeCreation):
            def create(self, plan, custody):
                self.plans.append(plan)
                self.custody = custody
                info = C._win32_types().PROCESS_INFORMATION()
                custody.attach(info)
                if enter:
                    custody.mark_entered()
                if write:
                    info.hProcess, info.hThread = 101, 102
                    info.dwProcessId, info.dwThreadId = 4242, 77
                if break_it:
                    class Broken:
                        def __getattr__(self, name):
                            raise OSError("unreadable")
                    custody._info = Broken()
                if then is not None:
                    raise then
                return result
        return Populating()

    def test_custody_is_allocated_first_and_passed_to_the_creator(self, monkeypatch):
        adapter, _, creation = make_adapter(monkeypatch)
        assert adapter.custody is None
        seen = {}
        original = creation.create

        def spy(plan, custody):
            seen.update(is_adapters=custody is adapter.custody, type=type(custody),
                        attached=custody.attached, entered=custody.entered)
            return original(plan, custody)

        adapter._create = spy
        prepare(adapter)
        assert seen == {"is_adapters": True, "type": C.HandleCustody,
                        "attached": False, "entered": False}

    def test_the_creator_must_accept_two_positional_arguments(self, monkeypatch):
        api, _ = make_api(monkeypatch)
        called = []
        for bad in (lambda plan: called.append(plan), lambda: called.append(0),
                    lambda plan, custody, extra: called.append(plan),
                    lambda *, plan, custody: called.append(plan)):
            with pytest.raises(C.CalibrationError, match="two positional"):
                W.ContainmentAdapter(api.auth, api, create=bad,
                                     process_identity=lambda p: None)
        for good in (lambda plan, custody: None, lambda *args: None,
                     lambda plan, custody=None: None):
            W.ContainmentAdapter(api.auth, api, create=good, process_identity=lambda p: None)
        assert called == []                               # never invoked by the check

    def test_authorization_is_checked_before_the_creator_signature(self):
        with pytest.raises(C.ExecutionDisabled):
            W.ContainmentAdapter(None, object(), create=lambda p: None,
                                 process_identity=lambda p: None)

    def test_populated_custody_is_observed_not_trusted(self, monkeypatch):
        creation = self._populating(then=RuntimeError("secret detail"))
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        evidence = adapter.retained_evidence
        assert evidence["custody_attached"] is True and evidence["custody_entered"] is True
        assert evidence["process_handle_observed"] is True
        assert evidence["thread_handle_observed"] is True
        assert evidence["custody_readable"] is True and evidence["custody_inconsistent"] is False
        assert (evidence["child_existence"], evidence["child_identity"],
                evidence["membership"]) == ("unknown", "unverified", "unverified")
        assert evidence["recovery_authorized"] is False
        text = repr(dict(evidence))
        for forbidden in ("101", "102", "4242", "77", "secret detail"):
            assert forbidden not in text
        assert adapter.custody is creation.custody
        assert adapter.custody.raw_values() == (101, 102, 4242, 77)    # still reachable
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_unpopulated_custody_is_not_a_no_child_claim(self, monkeypatch):
        creation = self._populating(enter=False, write=False, then=RuntimeError("x"))
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        evidence = adapter.retained_evidence
        assert evidence["custody_attached"] is True and evidence["custody_entered"] is False
        assert evidence["process_handle_observed"] is False
        assert evidence["child_existence"] == "unknown"
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_a_creator_that_never_touches_custody_is_still_retained(self, monkeypatch):
        adapter, _, _ = make_adapter(monkeypatch,
                                     creation=FakeCreation(raises=RuntimeError("x")))
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        evidence = adapter.retained_evidence
        assert (evidence["custody_attached"], evidence["custody_entered"],
                evidence["process_handle_observed"], evidence["thread_handle_observed"],
                evidence["custody_readable"]) == (False, False, False, False, True)

    def test_a_handle_without_entry_is_reported_inconsistent(self, monkeypatch):
        creation = self._populating(enter=False, then=RuntimeError("x"))
        adapter, _, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        evidence = adapter.retained_evidence
        assert evidence["custody_inconsistent"] is True
        assert evidence["custody_entered"] is False and evidence["child_existence"] == "unknown"

    def test_an_unreadable_custody_is_reported_and_changes_nothing(self, monkeypatch):
        creation = self._populating(break_it=True, then=RuntimeError("x"))
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        evidence = adapter.retained_evidence
        assert evidence["custody_readable"] is False
        assert evidence["process_handle_observed"] is False
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_a_snapshot_that_raises_never_masks_the_refusal(self, monkeypatch):
        adapter, _, _ = make_adapter(monkeypatch,
                                     creation=FakeCreation(raises=RuntimeError("x")))

        def broken():
            raise RuntimeError("boom")

        original = C.HandleCustody.snapshot
        monkeypatch.setattr(C.HandleCustody, "snapshot", lambda self: broken())
        with pytest.raises(W.ContainmentRefused, match="creation_failed"):
            prepare(adapter)
        monkeypatch.setattr(C.HandleCustody, "snapshot", original)
        assert adapter.retained_evidence["custody_readable"] is False
        assert adapter.controller.ownership == "retained_unverified"

    @pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit(3), GeneratorExit()])
    def test_interruption_keeps_identity_and_custody(self, monkeypatch, interrupt):
        creation = self._populating(then=interrupt)
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(type(interrupt)) as raised:
            prepare(adapter)
        assert raised.value is interrupt
        assert adapter.retained_evidence["process_handle_observed"] is True
        assert adapter.custody.raw_values() == (101, 102, 4242, 77)
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_bind_failure_retains_custody(self, monkeypatch):
        creation = self._populating(result=C.Win32Handles(PROCESS, THREAD, PID, 77,
                                                          receipt=None))
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=creation)
        with pytest.raises(W.ContainmentRefused, match="assignment_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "assignment_failed"
        evidence = adapter.retained_evidence
        assert evidence["stage"] == "bind" and evidence["process_handle_observed"] is True
        assert evidence["child_existence"] == "unknown" and evidence["membership"] == "unverified"
        assert adapter.custody.raw_values() == (101, 102, 4242, 77)
        assert adapter.controller.membership is None
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_retention_failure_still_records_custody(self, monkeypatch):
        class StubbornController(W.JobController):
            @property
            def ownership(self):
                return self.__dict__.get("_o", "none")

            @ownership.setter
            def ownership(self, value):
                if value != "retained_unverified":
                    self.__dict__["_o"] = value

        monkeypatch.setattr(W, "JobController", StubbornController)
        original = RuntimeError("creator failed")
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=self._populating(then=original))
        with pytest.raises(W.ContainmentRefused, match="retention_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "retention_failed" and raised.value.__cause__ is original
        assert adapter.retained_evidence["process_handle_observed"] is True
        assert adapter.retained_evidence["recovery_authorized"] is False
        assert kernel32.closed == [] and kernel32.terminated == []

    # -- custody observation must never replace the failure being handled ---------

    @pytest.mark.parametrize("observation_failure", [KeyboardInterrupt(), SystemExit(9)])
    @pytest.mark.parametrize("original", [RuntimeError("creator failed"), KeyboardInterrupt(),
                                          SystemExit(3)])
    def test_failing_custody_observation_never_masks_a_creator_failure(
            self, monkeypatch, original, observation_failure):
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=original))

        def broken(self):
            raise observation_failure

        monkeypatch.setattr(C.HandleCustody, "snapshot", broken)
        if isinstance(original, Exception):
            with pytest.raises(W.ContainmentRefused, match="creation_failed") as raised:
                prepare(adapter)
            assert raised.value.key == "creation_failed"
        else:
            with pytest.raises(type(original)) as raised:
                prepare(adapter)
            assert raised.value is original                  # the same object, unwrapped
        assert adapter.controller.ownership == "retained_unverified"
        assert adapter.retained_reason == "creator_failed_outcome_unknown"
        evidence = adapter.retained_evidence
        assert evidence["custody_readable"] is False and evidence["failure_action_key"] == "creation_failed"
        assert evidence["process_handle_observed"] is False
        assert (evidence["child_existence"], evidence["child_identity"],
                evidence["membership"]) == ("unknown", "unverified", "unverified")
        assert kernel32.closed == [] and kernel32.terminated == []

    @pytest.mark.parametrize("observation_failure", [KeyboardInterrupt(), SystemExit(9)])
    def test_failing_custody_observation_never_masks_a_binding_failure(
            self, monkeypatch, observation_failure):
        adapter, kernel32, _ = make_adapter(monkeypatch, creation=FakeCreation(receipt=None))

        def broken(self):
            raise observation_failure

        monkeypatch.setattr(C.HandleCustody, "snapshot", broken)
        with pytest.raises(W.ContainmentRefused, match="assignment_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "assignment_failed"
        assert adapter.retained_reason == "bind_failed_child_may_exist"
        assert adapter.retained_evidence["stage"] == "bind"
        assert adapter.retained_evidence["custody_readable"] is False
        assert adapter.controller.ownership == "retained_unverified"
        assert adapter.controller.membership is None
        assert kernel32.closed == [] and kernel32.terminated == []

    @pytest.mark.parametrize("observation_failure", [KeyboardInterrupt(), SystemExit(9)])
    def test_failing_evidence_construction_never_masks_the_original(
            self, monkeypatch, observation_failure):
        original = KeyboardInterrupt()
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=original))

        def broken(*args):
            raise observation_failure

        monkeypatch.setattr(W, "MappingProxyType", broken)
        with pytest.raises(KeyboardInterrupt) as raised:
            prepare(adapter)
        assert raised.value is original
        assert adapter.retained_reason == "creator_failed_outcome_unknown"
        assert adapter.retained_evidence is None
        assert adapter.controller.ownership == "retained_unverified"
        assert kernel32.closed == [] and kernel32.terminated == []

    @pytest.mark.parametrize("observation_failure", [KeyboardInterrupt(), SystemExit(9)])
    def test_failing_observation_never_masks_a_retention_failure(self, monkeypatch,
                                                                 observation_failure):
        class StubbornController(W.JobController):
            @property
            def ownership(self):
                return self.__dict__.get("_o", "none")

            @ownership.setter
            def ownership(self, value):
                if value != "retained_unverified":
                    self.__dict__["_o"] = value

        monkeypatch.setattr(W, "JobController", StubbornController)

        def broken(self):
            raise observation_failure

        monkeypatch.setattr(C.HandleCustody, "snapshot", broken)
        original = RuntimeError("creator failed")
        adapter, kernel32, _ = make_adapter(monkeypatch,
                                            creation=FakeCreation(raises=original))
        with pytest.raises(W.ContainmentRefused, match="retention_failed") as raised:
            prepare(adapter)
        assert raised.value.key == "retention_failed" and raised.value.__cause__ is original
        assert adapter.retained_reason == "retention_unconfirmed"
        assert adapter.retained_evidence["custody_readable"] is False
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_only_the_observation_paths_absorb_base_exceptions(self):
        code = SOURCE.split('"""', 2)[2]
        assert code.count("except BaseException:") == 2           # snapshot read + evidence
        start = code.index("def _note_retention")
        end = code.index("def _retain_child")
        assert code[start:end].count("except BaseException:") == 2
        for marker in ("def prepare", "def _bind", "def close", "def terminate"):
            body = code[code.index(marker):]
            assert "except BaseException:" not in body.split("\n    def ")[0], marker

    def test_custody_is_never_closed_reset_or_read_raw_by_the_adapter(self):
        code = SOURCE.split('"""', 2)[2]
        for word in ("raw_values", "custody.close", "custody.reset", "custody._info",
                     "mark_entered", ".attach("):
            assert word not in code, word
        assert not any(hasattr(W.ContainmentAdapter, n) for n in ("close", "reset", "recover"))

    def test_gates_stay_closed_with_custody(self):
        assert W.JOB_LIST_CREATION_INTEGRATED is False
        assert P.TERMINATION_POLICY == "conditionally_accepted_design_only"

    @pytest.mark.parametrize("pid, process", [(0, PROCESS), (True, PROCESS), ("1", PROCESS),
                                              (PID, 0), (PID, None), (PID, -1)])
    def test_malformed_process_identity_refuses(self, monkeypatch, pid, process):
        adapter, _, _ = make_adapter(monkeypatch,
                                     creation=FakeCreation(pid=pid, process=process))
        with pytest.raises(W.ContainmentRefused, match="not_in_job"):
            prepare(adapter)
        assert adapter.controller.ownership == "retained_unverified"

    @pytest.mark.parametrize("identity", [
        lambda p: None, lambda p: (PID,), lambda p: (PID, ""), lambda p: (PID, None),
        lambda p: (True, CREATED), lambda p: (0, CREATED)])
    def test_malformed_reported_identity_refuses(self, monkeypatch, identity):
        adapter, _, _ = make_adapter(monkeypatch, creation=FakeCreation(identity=identity))
        with pytest.raises(W.ContainmentRefused, match="malformed"):
            prepare(adapter)

    def test_pid_mismatch_refuses(self, monkeypatch):
        adapter, _, _ = make_adapter(
            monkeypatch, creation=FakeCreation(identity=lambda p: (PID + 1, CREATED)))
        with pytest.raises(W.ContainmentRefused, match="reports PID"):
            prepare(adapter)
        assert adapter.controller.ownership == "retained_unverified"

    def test_creation_time_mismatch_refuses(self, monkeypatch):
        times = iter([CREATED, "2026-10-09T12:00:01.000Z"])
        adapter, _, _ = make_adapter(
            monkeypatch, creation=FakeCreation(identity=lambda p: (PID, next(times))))
        with pytest.raises(W.ContainmentRefused, match="creation time changed"):
            prepare(adapter)
        assert adapter.controller.ownership == "retained_unverified"

    @pytest.mark.parametrize("overrides, message", [
        ({"in_job": 0}, "outside the job"),
        ({"pids": [PID + 1]}, "job members are"),
        ({"pids": [PID, PID + 1]}, "job members are"),
        ({"accounting": {"active": 2, "total": 2, "terminated": 0}}, "active processes"),
        ({"accounting": {"active": 1, "total": 2, "terminated": 1}}, "have been in the job"),
    ])
    def test_incorrect_membership_evidence_refuses(self, monkeypatch, overrides, message):
        adapter, kernel32, _ = make_adapter(monkeypatch, **overrides)
        with pytest.raises(W.JobFailure, match=message):
            prepare(adapter)
        assert adapter.controller.ownership == "retained_unverified"
        assert adapter.controller.membership is None
        assert kernel32.closed == [] and kernel32.terminated == []

    def test_no_implicit_close_or_termination_and_no_native_load(self, monkeypatch):
        adapter, kernel32, _ = make_adapter(monkeypatch)
        prepare(adapter)
        assert kernel32.closed == [] and kernel32.terminated == []
        assert "TerminateJobObject" not in kernel32.log and "CloseHandle" not in kernel32.log
        assert kernel32.loads == ["kernel32"]            # the injected fake only

    def test_adapter_needs_authorization(self):
        with pytest.raises(C.ExecutionDisabled):
            W.ContainmentAdapter(None, object(), create=lambda p: None,
                                 process_identity=lambda p: None)

    def test_gates_and_wiring_stay_closed(self):
        import evidence_store as E
        assert W.JOB_LIST_CREATION_INTEGRATED is False
        assert P.HOST_INVENTORY_ENABLED is False and E.EVIDENCE_WRITES_ENABLED is False
        assert P.TERMINATION_POLICY == "conditionally_accepted_design_only"
        assert C.PROBE_ENABLED is False
        for name in ("calibrate_generator.py", "appcontainer_preflight.py",
                     "evidence_store.py"):
            text = (_BENCH / name).read_text(encoding="utf-8")
            assert "ContainmentAdapter" not in text and "import win32_job" not in text
        assert "AssignProcessToJobObject" not in SOURCE
        for name in ("assign", "close", "terminate"):
            assert not hasattr(W.ContainmentAdapter, name)

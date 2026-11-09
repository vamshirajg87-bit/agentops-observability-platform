"""
benchmarks/tests/test_evidence_store.py

Offline tests of the evidence store (slice E1).  An in-memory fake FsOps
with fault injection is the only "file system"; any real file-system
write, process, socket or subprocess fails the test.
"""

from __future__ import annotations

import copy
import ctypes
import errno
import hashlib
import os
import pathlib
import re
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
import evidence_store as E  # noqa: E402

RUN, HEAD, TOKEN_SHA = "probe-01", "a" * 40, "7" * 64
RUN_DIR = r"C:\Users\u\AppData\Local\agentops-probe\evidence\probe-01"
CREATED = "2026-10-09T12:00:00.000Z"
PROCESS = {"pid": 4242, "creation_time": CREATED}
JOB_ID = "b" * 32
SOURCE = (_BENCH / "evidence_store.py").read_text(encoding="utf-8")


class LiveAccessAttempt(AssertionError):
    """A test reached something real."""


@pytest.fixture(autouse=True)
def fail_closed(monkeypatch):
    def refuse(what):
        def call(*args, **kwargs):
            raise LiveAccessAttempt(f"{what} attempted")
        return call

    for name in ("open", "write", "fsync", "mkdir", "makedirs", "replace", "rename",
                 "remove", "unlink", "rmdir", "system"):
        monkeypatch.setattr(os, name, refuse(f"os.{name}"))
    for name in ("write_text", "write_bytes", "mkdir", "touch", "unlink", "rename",
                 "replace"):
        monkeypatch.setattr(pathlib.Path, name, refuse(f"Path.{name}"))
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    monkeypatch.setattr(socket, "create_connection", refuse("a network connection"))
    monkeypatch.setattr(ctypes, "WinDLL", refuse("a real DLL load"))
    monkeypatch.setattr(E, "_kernel32_loader", refuse("the real kernel32 loader"))


class FakeFs:
    """In-memory FsOps with fault injection."""

    def __init__(self, **overrides):
        self.files, self.calls, self.fail = {}, [], {}
        self.dir = {"exists": True, "reparse": False, "final_path": RUN_DIR,
                    "volume_serial": 77}
        self.write_mode, self.corrupt, self.identity_override = None, False, {}
        self.handles, self.open_handles, self.next_handle = {}, set(), 1
        self.__dict__.update(overrides)

    def _step(self, op):
        self.calls.append(op)
        failure = self.fail.get(op)
        if failure is not None:
            raise failure

    def dir_identity(self, path):
        self._step("dir_identity")
        return dict(self.dir)

    def open_exclusive(self, path):
        self._step("open")
        if path in self.files:
            raise FileExistsError(path)
        handle, self.next_handle = self.next_handle, self.next_handle + 1
        self.handles[handle] = path
        self.files[path] = b""
        self.open_handles.add(handle)
        return handle

    def write(self, handle, data):
        self._step("write")
        if self.write_mode == "zero":
            return 0
        if self.write_mode == "overclaim":
            self.files[self.handles[handle]] += data
            return len(data) + 1
        if self.write_mode == "lie":
            self.files[self.handles[handle]] += data[:-1]
            return len(data)
        count = len(data) if self.write_mode != "chunks" else min(16, len(data))
        self.files[self.handles[handle]] += data[:count]
        return count

    def flush(self, handle):
        self._step("flush")

    def close(self, handle):
        self.open_handles.discard(handle)          # a failed close still ends the handle
        self._step("close")

    def read_all(self, path):
        self._step("read")
        data = self.files[path]
        if self.corrupt:
            data = bytes([data[0] ^ 1]) + data[1:]
        return data

    def file_identity(self, path):
        self._step("identity")
        return {"links": 1, "reparse": False, "volume_serial": 77, "file_index": 9,
                "size": len(self.files[path]), **self.identity_override}


def envelope(**changes):
    base = {
        "run_id": RUN, "series_token_sha256": TOKEN_SHA, "expected_head": HEAD,
        "object_format": "sha1", "repository_manifest_sha256": "1" * 64,
        "runtime_manifest_sha256": "2" * 64,
        "parent": {"pid": 100, "creation_time": "2026-10-09T11:00:00Z"},
        "utc": "2026-10-09T12:00:00Z", "monotonic_ms": 0, "context_sha256": None,
        "job": {"job_id": None, "limits_verified": False, "assignment": "not_created"},
        "process": None, "lifecycle": P.LifecycleState().as_dict(),
        "integrity": {"writer_version": E.WRITER_VERSION},
    }
    base.update(changes)
    return base


def _lifecycle(**changes):
    return {**P.LifecycleState().as_dict(), **changes}


JOB = {"job_id": JOB_ID, "limits_verified": True, "assignment": "assigned_at_creation"}
#: A configured job before any process exists: no assignment yet.
JOB_READY = {"job_id": JOB_ID, "limits_verified": True, "assignment": "not_created"}
CONFIGURED = dict(job=JOB_READY, context_sha256="3" * 64)
RUNNING = dict(job=JOB, context_sha256="3" * 64, process=PROCESS)
EXITED = _lifecycle(phase="exited", process_created=True, pid=4242, creation_time=CREATED,
                    execution_history=P.MAY_HAVE_EXECUTED, liveness=P.CONFIRMED_EXITED)
#: Strict stage bodies (observed values only).
CONFIG_BODY = {"limit_flags": 0x2408, "active_process_limit": 1,
               "job_handle_inheritable": False}
CREATED_BODY = {**PROCESS, "create_process_ok": True,
                "applied_attributes": [0x00020009, 0x00020002, 0x0002000D]}
MEMBERSHIP = {"job_assignment": "assigned_at_creation", "in_job": True, "pid": 4242,
              "creation_time": CREATED, "active_processes": 1, "total_processes": 1,
              "member_pids": [4242]}
VERIFIED_BODY = {"membership": MEMBERSHIP, "token_ok": True, "image_ok": True}

#: A complete, verified strict run: (kind, envelope changes, body).
STEPS = [
    ("prelaunch", {}, {"result": "passed"}),
    ("job_configured", CONFIGURED, CONFIG_BODY),
    ("process_created", RUNNING, CREATED_BODY),
    ("job_verified_and_validated", RUNNING, VERIFIED_BODY),
    ("resume_intent", RUNNING, {}),
    ("resume_result", RUNNING, {"execution_history": P.MAY_HAVE_EXECUTED}),
    ("termination_intent", RUNNING, {"cause": "job_terminated_timeout"}),
    ("termination_result", RUNNING, {"cause": "job_terminated_timeout", "verified": True,
                                     "api_ok": True, "signaled": True,
                                     "exit_code": P.TIMEOUT_EXIT_CODE}),
    ("final_inspection", {**RUNNING, "lifecycle": EXITED}, {"liveness": P.CONFIRMED_EXITED}),
]


def writer(fs=None):
    return E.EvidenceWriter(RUN_DIR, fs or FakeFs(), expected_dir={
        "final_path": RUN_DIR, "volume_serial": 77}, run_id=RUN, expected_head=HEAD,
        token_sha256=TOKEN_SHA)


def write_steps(w, count=None):
    for kind, changes, body in STEPS[:count]:
        w.write(kind, envelope(**changes), body)
    return w


def complete(w, ownership="released"):
    return w.write("complete", envelope(**RUNNING, lifecycle=EXITED), w.complete_body(ownership))


def full_chain():
    w = write_steps(writer())
    complete(w)
    return w


# ---------------------------------------------------------------------------
# Gates and scope
# ---------------------------------------------------------------------------

class TestGatesAndScope:
    def test_no_real_writes(self):
        assert E.EVIDENCE_WRITES_ENABLED is False
        with pytest.raises(E.EvidenceDisabled, match="not enabled"):
            E.require_real_writes()
        with pytest.raises(E.EvidenceDisabled):
            E.FsOps()
        with pytest.raises(E.EvidenceDisabled):
            E.EvidenceWriter(RUN_DIR, None, expected_dir={}, run_id=RUN, expected_head=HEAD,
                             token_sha256=TOKEN_SHA)

    def test_source_has_no_real_io(self):
        code = SOURCE.split('"""', 2)[2]
        assert not re.search(r"(?<![\w.])open\(", code)            # only self._open(...)
        for word in ("os.", "import os", "mkdir", "write_text", "write_bytes", "shutil",
                     "subprocess", "socket", "fsync(", "unlink", "rename(", "replace(path",
                     "CreateDirectory", "DeleteFile", "MoveFile", "RemoveDirectory"):
            assert word not in code, word
        start = code.index("# WindowsFsOps (slice E2)")
        end = code.index("# Recovery classification")
        outside = code[:start] + code[end:]
        for word in ("ctypes", "WinDLL", "calibrate_generator", "kernel32"):
            assert word not in outside, word                       # native code only in E2

    def test_nothing_imports_the_store(self):
        for name in ("calibrate_generator.py", "appcontainer_preflight.py", "win32_job.py"):
            assert "evidence_store" not in (_BENCH / name).read_text(encoding="utf-8")

    def test_existing_gates_unchanged(self):
        assert (C.EXECUTION_ENABLED, C.APPROVED_CALIBRATIONS, C.PROBE_ENABLED,
                C.APPROVED_PROBES, C.AUTHORIZED_APPCONTAINER_SID,
                C.AUTHORIZED_PROFILE_PREFLIGHT_SHA256) == (False, frozenset(), False,
                                                          frozenset(), None, None)
        assert P.HOST_INVENTORY_ENABLED is False
        assert P.TERMINATION_POLICY == "conditionally_accepted_design_only"
        assert P.build_plan({}, expected_head=None)["recommendation"] == "NO-GO"


# ---------------------------------------------------------------------------
# Pure record helpers
# ---------------------------------------------------------------------------

class TestRecords:
    def test_record_name(self):
        assert E.record_name(4, "resume_intent") == "004-resume_intent.json"
        assert E.record_name(999, "complete") == "999-complete.json"
        for sequence, kind in ((-1, "complete"), (1000, "complete"), (True, "complete"),
                               (1.0, "complete"), (1, "bogus"), (1, None)):
            with pytest.raises(E.EvidenceError):
                E.record_name(sequence, kind)

    def test_canonical_serialization_and_digest(self):
        record = E.build_record("prelaunch", envelope(), {"b": 1, "a": 2}, sequence=0,
                                previous_record_sha256=None)
        data = P.canonical_json(record)
        assert data.startswith(b'{"body":{"a":2,"b":1}') and b" " not in data.split(b'"utc"')[0]
        assert E.record_digest(record) == hashlib.sha256(data).hexdigest()

    @pytest.mark.parametrize("changes, message", [
        ({"run_id": "bm-x"}, "run_id"), ({"utc": "noon"}, "utc"),
        ({"monotonic_ms": 1.5}, "monotonic_ms"), ({"monotonic_ms": -1}, "monotonic_ms"),
        ({"series_token_sha256": "x"}, "series_token_sha256"),
        ({"expected_head": "a" * 64}, "sha1 commit id"),
        ({"object_format": "md5"}, "unknown object format"),
        ({"parent": {"pid": 0, "creation_time": CREATED}}, "parent identity"),
        ({"process": {"pid": 1}}, "process identity"),
        ({"job": {"job_id": "x", "limits_verified": True, "assignment": "unknown"}}, "job"),
        ({"lifecycle": {"liveness": "dead"}}, "lifecycle"),
        ({"integrity": {}}, "unsupported schema/version combination"),
        ({"integrity": {"writer_version": E.WRITER_VERSION, "x": 1}}, "integrity"),
        ({"context_sha256": "short"}, "context_sha256"),
    ])
    def test_malformed_envelopes(self, changes, message):
        with pytest.raises(E.EvidenceError, match=message):
            E.build_record("prelaunch", envelope(**changes), {}, sequence=0,
                           previous_record_sha256=None)

    def test_envelope_shape(self):
        bad = envelope()
        del bad["utc"]
        with pytest.raises(E.EvidenceError, match="malformed envelope"):
            E.build_record("prelaunch", bad, {}, sequence=0, previous_record_sha256=None)
        with pytest.raises(E.EvidenceError, match="malformed envelope"):
            E.build_record("prelaunch", {**envelope(), "extra": 1}, {}, sequence=0,
                           previous_record_sha256=None)
        with pytest.raises(E.EvidenceError, match="first record has a previous"):
            E.build_record("prelaunch", envelope(), {}, sequence=0,
                           previous_record_sha256="0" * 64)
        with pytest.raises(E.EvidenceError, match="previous_record_sha256"):
            E.build_record("job_configured", envelope(), {}, sequence=1,
                           previous_record_sha256=None)

    @pytest.mark.parametrize("kind, changes, body, message", [
        ("process_created", {}, dict(PROCESS), "name the process"),
        ("process_created", {"process": PROCESS}, {"pid": 1, "creation_time": CREATED},
         "name the process"),
        ("resume_result", {}, {"execution_history": "ran"}, "execution history"),
        ("termination_result", {}, {"cause": "job_terminated_timeout", "verified": True,
                                    "api_ok": True, "signaled": False, "exit_code": None},
         "without exit proof"),
        ("termination_result", {}, {"cause": "job_terminated_timeout", "verified": True,
                                    "api_ok": True, "signaled": True, "exit_code": 0},
         "without exit proof"),
        ("termination_result", {}, {"cause": "reboot", "verified": False, "api_ok": True,
                                    "signaled": False}, "malformed"),
        ("final_inspection", {}, {"liveness": "gone"}, "needs a liveness"),
        ("evidence_failure", {}, {"operation": "write", "failed_kind": "x"}, "malformed"),
        ("complete", {}, {"ownership": "kept", "chain": []}, "malformed"),
        ("complete", {"process": PROCESS}, {"ownership": "released", "chain": []},
         "without a confirmed exit"),
    ])
    def test_body_rules(self, kind, changes, body, message):
        with pytest.raises(E.EvidenceError, match=message):
            E.build_record(kind, envelope(**changes), body, sequence=1,
                           previous_record_sha256="0" * 64)


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

class TestChain:
    def test_complete_chain(self):
        w = full_chain()
        chain = E.verify_chain(w.records, expected_run_id=RUN, expected_head=HEAD,
                               expected_token_sha256=TOKEN_SHA)
        assert chain.ok and chain.count == 10 and chain.complete
        assert chain.tip_digest == w.state.last_verified_digest == E.record_digest(w.records[-1])
        assert chain.durable_stages == list(P.LIFECYCLE_STAGES)
        assert chain.process == (4242, CREATED) and chain.termination_verified
        assert not w.state.ownership_retained

    def _problem(self, records, **expected):
        chain = E.verify_chain(records, **expected)
        assert not chain.ok
        return chain, " ".join(chain.problems)

    def test_missing_duplicate_and_reordered(self):
        records = full_chain().records
        _, text = self._problem(records[:3] + records[4:])
        assert "sequence" in text
        _, text = self._problem(records[:4] + [records[3]] + records[4:])
        assert "sequence" in text
        swapped = records[:3] + [records[4], records[3]] + records[5:]
        chain, text = self._problem(swapped)
        assert "sequence" in text and chain.count == 3

    def test_broken_previous_digest(self):
        records = copy.deepcopy(full_chain().records)
        records[2]["utc"] = "2026-10-09T12:00:01Z"          # still a well-formed record
        chain, text = self._problem(records)
        assert "record 3: broken previous digest" in text and chain.count == 3

    def test_malformed_final_chain(self):
        records = copy.deepcopy(full_chain().records)
        records[-1]["body"]["chain"].pop()
        chain, text = self._problem(records)
        assert "malformed final chain" in text and chain.count == 9 and not chain.complete

    def test_inconsistent_run_and_owner(self):
        records = copy.deepcopy(full_chain().records)
        records[3]["run_id"] = "probe-02"
        _, text = self._problem(records)
        assert "inconsistent run_id" in text or "broken previous" in text
        records = copy.deepcopy(full_chain().records)
        records[1]["series_token_sha256"] = "8" * 64
        _, text = self._problem(records)
        assert "inconsistent owner digest" in text or "broken previous" in text

    def test_expected_identity(self):
        records = full_chain().records
        assert "unexpected HEAD" in self._problem(records, expected_head="c" * 40)[1]
        assert "unexpected run_id" in self._problem(records, expected_run_id="probe-02")[1]
        assert "unexpected owner digest" in self._problem(
            records, expected_token_sha256="9" * 64)[1]

    def test_process_identity_rules(self):
        w = write_steps(writer(), 2)
        with pytest.raises(E.EvidenceError, match="process identity before process_created"):
            w.write("final_inspection", envelope(**RUNNING), {"liveness": P.STATE_UNKNOWN})
        w = write_steps(writer(), 4)
        moved = {**RUNNING, "process": {"pid": 4243, "creation_time": CREATED}}
        with pytest.raises(E.EvidenceError, match="inconsistent process identity"):
            w.write("resume_intent", envelope(**moved), {})
        with pytest.raises(E.EvidenceError, match="inconsistent process identity"):
            w.write("resume_intent", envelope(**CONFIGURED), {})

    def test_stage_order_is_enforced_by_the_writer(self):
        w = write_steps(writer(), 1)
        before = (w.next_sequence, len(w.fs.files))
        for kind in ("resume_intent", "resume_result", "complete", "termination_result"):
            with pytest.raises(E.EvidenceError, match="may not follow"):
                w.write(kind, envelope(), {"execution_history": P.NEVER_EXECUTED,
                                           "ownership": "retained", "chain": [],
                                           "cause": "job_terminated_timeout",
                                           "verified": False, "api_ok": False,
                                           "signaled": False})
        assert (w.next_sequence, len(w.fs.files)) == before         # nothing consumed
        w2 = writer()
        with pytest.raises(E.EvidenceError, match="does not start with prelaunch"):
            w2.write("job_configured", envelope(**CONFIGURED), CONFIG_BODY)

    def test_hash_chain_is_not_authentication(self):
        rewritten = writer()
        for kind, changes, body in STEPS:
            rewritten.write(kind, envelope(**{**changes, "monotonic_ms": 7}), body)  # forged
        complete(rewritten)
        assert E.verify_chain(rewritten.records).ok                  # recomputed hashes pass
        assert rewritten.state.last_verified_digest != full_chain().state.last_verified_digest

    def test_no_resume_without_durable_intent(self):
        w = write_steps(writer(), 4)
        assert not w.may_resume
        w.write("resume_intent", envelope(**RUNNING), {})
        assert w.may_resume
        w2 = write_steps(writer(), 2)
        assert w2.may_launch and not write_steps(writer(), 1).may_launch


# ---------------------------------------------------------------------------
# Writer failures (fake file system)
# ---------------------------------------------------------------------------

def _fail_at(index, **fs_changes):
    """Write STEPS up to index, then fail writing STEPS[index]."""
    w = write_steps(writer(), index)
    w.fs.__dict__.update(fs_changes)
    kind, changes, body = STEPS[index]
    with pytest.raises(E.EvidenceFailed) as raised:
        w.write(kind, envelope(**changes), body)
    return w, raised.value


class TestWriterFailures:
    def test_protocol_order(self):
        fs = FakeFs()
        writer(fs).write("prelaunch", envelope(), {})
        assert fs.calls == ["dir_identity", "open", "write", "flush", "close", "read",
                            "identity"]
        assert fs.files == {RUN_DIR + r"\000-prelaunch.json": P.canonical_json(
            E.build_record("prelaunch", envelope(), {}, sequence=0,
                           previous_record_sha256=None))}

    def test_chunked_writes_complete(self):
        w = writer(FakeFs(write_mode="chunks"))
        w.write("prelaunch", envelope(), {"x": "y" * 100})
        assert w.state.last_verified_sequence == 0 and not w.state.evidence_failed

    @pytest.mark.parametrize("fs_changes, operation, partial", [
        ({"write_mode": "zero"}, "write_short", True),
        ({"write_mode": "overclaim"}, "write_short", True),
        ({"write_mode": "lie"}, "readback_mismatch", True),
        ({"fail": {"write": OSError(errno.ENOSPC, "disk full")}}, "write:OSError", True),
        ({"fail": {"flush": OSError(errno.EIO, "flush failed")}}, "flush:OSError", True),
        ({"fail": {"close": OSError(errno.EIO, "close failed")}}, "close:OSError", True),
        ({"corrupt": True}, "readback_mismatch", True),
        ({"fail": {"read": OSError(errno.EIO, "read failed")}}, "readback:OSError", True),
        ({"identity_override": {"links": 2}}, "file_identity", True),
        ({"identity_override": {"reparse": True}}, "file_identity", True),
        ({"identity_override": {"volume_serial": 78}}, "file_identity", True),
        ({"identity_override": {"size": 1}}, "file_identity", True),
        ({"fail": {"open": OSError(errno.ENOSPC, "disk full")}}, "create:OSError", False),
        ({"fail": {"open": PermissionError(errno.EACCES, "denied")}},
         "create:PermissionError", False),
        ({"dir": {"exists": False}}, "directory_missing", False),
        ({"dir": {"exists": True, "reparse": True, "final_path": RUN_DIR,
                  "volume_serial": 77}}, "directory_reparse_point", False),
        ({"dir": {"exists": True, "reparse": False, "final_path": r"C:\elsewhere",
                  "volume_serial": 77}}, "directory_path_mismatch", False),
        ({"dir": {"exists": True, "reparse": False, "final_path": RUN_DIR,
                  "volume_serial": 1}}, "directory_volume_mismatch", False),
    ])
    def test_each_failure(self, fs_changes, operation, partial):
        w, error = _fail_at(4, **fs_changes)
        state = w.state
        assert state.evidence_failed and state.failed_operation == operation
        assert state.partial_record_possible is partial
        assert state.failed_name == "004-resume_intent.json"
        assert state.last_verified_sequence == 3 and state.ownership_retained
        assert state.containment_required == "discard_if_created"   # before resume
        assert not w.may_resume and not w.may_launch
        assert w.fs.open_handles == set()                             # no handle leak
        assert w.next_sequence == (5 if partial else 4)               # name consumed
        with pytest.raises(E.EvidenceFailed, match="evidence-failure state"):
            w.write("resume_intent", envelope(**RUNNING), {})          # no retry

    def test_duplicate_creation_leaves_the_existing_file(self):
        fs = FakeFs()
        path = RUN_DIR + r"\000-prelaunch.json"
        fs.files[path] = b"existing"
        w = writer(fs)
        with pytest.raises(E.EvidenceFailed, match="create_duplicate"):
            w.write("prelaunch", envelope(), {})
        assert fs.files[path] == b"existing" and not w.state.partial_record_possible

    def test_failure_after_resume_requires_containment(self):
        w, _ = _fail_at(5, write_mode="zero")
        assert w.state.containment_required == "bounded_termination"
        assert w.state.ownership_retained and not w.may_resume

    def test_failure_before_any_process(self):
        w, _ = _fail_at(1, write_mode="zero")
        assert w.state.containment_required == "none"
        w, _ = _fail_at(2, write_mode="zero")                      # process may exist
        assert w.state.containment_required == "discard_if_created"

    def test_interrupted_write(self):
        w = write_steps(writer(), 2)
        w.fs.fail = {"flush": KeyboardInterrupt()}
        with pytest.raises(KeyboardInterrupt):
            w.write(*STEPS[2][:1], envelope(**STEPS[2][1]), STEPS[2][2])
        assert w.state.evidence_failed and w.state.failed_operation == "interrupted"
        assert w.state.partial_record_possible and w.fs.open_handles == set()

    def test_failure_record_once(self):
        w, _ = _fail_at(4, write_mode="zero")
        w.fs.write_mode = None
        digest = w.write_failure_record(envelope(**RUNNING))
        record = w.records[-1]
        assert digest and record["kind"] == "evidence_failure" and record["sequence"] == 5
        assert record["body"]["operation"] == "write_short"
        assert record["body"]["failed_kind"] == "resume_intent"
        with pytest.raises(E.EvidenceError, match="written once"):
            w.write_failure_record(envelope(**RUNNING))

    def test_failure_record_can_fail_too(self):
        w, _ = _fail_at(4, write_mode="zero")
        assert w.write_failure_record(envelope(**RUNNING)) is None
        assert w.state.failed_operation == "write_short"              # first failure kept
        assert any("failure record" in e for e in w.state.errors)

    def test_failure_record_needs_a_failure(self):
        w = write_steps(writer(), 2)
        with pytest.raises(E.EvidenceError, match="after a failure"):
            w.write_failure_record(envelope())

    def test_no_implicit_termination_or_release(self):
        w = write_steps(writer(), 7)
        with pytest.raises(E.EvidenceError, match="without exit proof"):
            w.write("termination_result", envelope(**RUNNING),
                    {"cause": "job_terminated_timeout", "verified": True, "api_ok": True,
                     "signaled": False, "exit_code": None})
        w.write("termination_result", envelope(**RUNNING),
                {"cause": "job_terminated_timeout", "verified": False, "api_ok": True,
                 "signaled": False, "exit_code": None})
        assert not E.verify_chain(w.records).termination_verified
        w.write("final_inspection", envelope(**RUNNING), {"liveness": P.STATE_UNKNOWN})
        with pytest.raises(E.EvidenceError, match="without a confirmed exit"):
            w.write("complete", envelope(**RUNNING), w.complete_body("released"))
        w.write("complete", envelope(**RUNNING), w.complete_body("retained"))
        assert w.state.ownership_retained


# ---------------------------------------------------------------------------
# Recovery classification
# ---------------------------------------------------------------------------

def chain_after(count):
    return E.verify_chain(write_steps(writer(), count).records)


NOT_FOUND = {"pid": 4242, "result": "not_found"}


class TestRecovery:
    def test_crash_at_every_stage(self):
        expectations = {
            1: (None, "not_applicable"),
            2: (P.STATE_UNKNOWN, P.STATE_UNKNOWN),
            3: (P.NEVER_EXECUTED, P.CONFIRMED_EXITED),
            4: (P.NEVER_EXECUTED, P.CONFIRMED_EXITED),
            5: (P.MAY_HAVE_EXECUTED, P.CONFIRMED_EXITED),
            6: (P.MAY_HAVE_EXECUTED, P.CONFIRMED_EXITED),
            7: (P.MAY_HAVE_EXECUTED, P.CONFIRMED_EXITED),
            8: (P.MAY_HAVE_EXECUTED, P.CONFIRMED_EXITED),
            9: (P.MAY_HAVE_EXECUTED, P.CONFIRMED_EXITED),
        }
        for count, (history, liveness) in expectations.items():
            result = E.classify_recovery(chain_after(count), NOT_FOUND)
            assert (result["execution_history"], result["liveness"]) == (history, liveness), count
            assert result["ownership"] == "retained"

    def test_identity_never_recorded(self):
        result = E.classify_recovery(chain_after(2), {"pid": 4242, "result": "ok",
                                                      "creation_time": CREATED,
                                                      "signaled": True, "exit_code": 0})
        assert result["liveness"] == P.STATE_UNKNOWN and "never durably recorded" in \
            result["reason"]

    def test_recorded_history_after_resume(self):
        w = write_steps(writer(), 5)
        w.write("resume_result", envelope(**RUNNING), {"execution_history": P.NEVER_EXECUTED})
        result = E.classify_recovery(E.verify_chain(w.records), NOT_FOUND)
        assert result["execution_history"] == P.NEVER_EXECUTED

    @pytest.mark.parametrize("inspection, liveness, evidence", [
        ({"pid": 4242, "result": "ok", "creation_time": "2026-10-09T13:00:00.000Z"},
         P.CONFIRMED_EXITED, "absent_from_process_table"),
        ({"pid": 4242, "result": "ok", "creation_time": CREATED, "signaled": True,
          "exit_code": 3}, P.CONFIRMED_EXITED, "wait+exit_code"),
        ({"pid": 4242, "result": "ok", "creation_time": CREATED, "signaled": False,
          "exit_code": None}, P.ALIVE_AT_LAST_CHECK, None),
        ({"pid": 4242, "result": "ok", "creation_time": CREATED, "signaled": None},
         P.STATE_UNKNOWN, None),
        ({"pid": 4242, "result": "access_denied"}, P.STATE_UNKNOWN, None),
        ({"pid": 4242, "result": "error"}, P.STATE_UNKNOWN, None),
        ({"pid": 999, "result": "not_found"}, P.STATE_UNKNOWN, None),
        (None, P.STATE_UNKNOWN, None),
    ])
    def test_inspection_outcomes(self, inspection, liveness, evidence):
        result = E.classify_recovery(chain_after(6), inspection)
        assert (result["liveness"], result["exit_evidence"]) == (liveness, evidence)

    def test_missing_termination_record_never_establishes_termination(self):
        chain = chain_after(7)                                    # termination_intent only
        assert "termination_intent" in chain.kinds and not chain.termination_verified
        result = E.classify_recovery(chain, None)
        assert result["liveness"] == P.STATE_UNKNOWN
        assert result["termination_established"] is False
        result = E.classify_recovery(chain, NOT_FOUND)
        assert result["liveness"] == P.CONFIRMED_EXITED
        assert result["termination_established"] is False           # exited, not "terminated"

    def test_verified_termination_is_reported(self):
        result = E.classify_recovery(chain_after(8), NOT_FOUND)
        assert result["termination_established"] is True

    def test_requires_a_chain_state(self):
        with pytest.raises(E.EvidenceError):
            E.classify_recovery({"durable_stages": []}, NOT_FOUND)


# ---------------------------------------------------------------------------
# WindowsFsOps (E2) over a fake kernel32
# ---------------------------------------------------------------------------

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
        if name.startswith("_") or name not in FakeKernel32Fs.APIS:
            raise LiveAccessAttempt(f"unexpected Windows API {name}")
        return FakeFunction(name, getattr(self._k, name), self._k.log)


class FakeKernel32Fs:
    """A tiny NTFS-like file system behind the eight kernel32 functions."""

    APIS = ("CreateFileW", "WriteFile", "ReadFile", "FlushFileBuffers", "CloseHandle",
            "GetFileInformationByHandle", "GetFinalPathNameByHandleW", "GetHandleInformation")

    def __init__(self, **overrides):
        self.dirs = {RUN_DIR: {"attrs": E.FILE_ATTRIBUTE_DIRECTORY, "volume": 77}}
        self.files, self.handles, self.closed, self.log, self.loads = {}, {}, [], [], []
        self.fail, self.last_error, self.next_handle = {}, 0, 0x100
        self.inherit_flags, self.write_mode, self.read_overclaim = 0, None, False
        self.final_override = self.final_length = None
        self.file_info, self.dir_info, self.calls_args = {}, {}, []
        self.__dict__.update(overrides)

    def loader(self, name):
        self.loads.append(name)
        return FakeDll(self)

    def _failing(self, api):
        code = self.fail.get(api)
        if code is not None:
            self.last_error = code
            return True
        return False

    def CreateFileW(self, path, access, share, attributes, disposition, flags, template):
        self.calls_args.append((path, access, share, attributes, disposition, flags, template))
        assert attributes is None and template is None          # non-inheritable, no template
        if self._failing("CreateFileW"):
            return -1
        if flags & E.FILE_FLAG_BACKUP_SEMANTICS:
            assert flags & E.FILE_FLAG_OPEN_REPARSE_POINT
            if path not in self.dirs:
                self.last_error = 3
                return -1
            kind = "dir"
        elif disposition == E.CREATE_NEW:
            assert (access, share) == (E.GENERIC_WRITE, 0)
            assert flags & E.FILE_FLAG_WRITE_THROUGH
            if path in self.files:
                self.last_error = 80
                return -1
            if path.rsplit("\\", 1)[0] not in self.dirs:
                self.last_error = 3
                return -1
            self.files[path] = {"data": bytearray(), "attrs": E.FILE_ATTRIBUTE_NORMAL,
                                "links": 1, "volume": 77, "index": len(self.files) + 1}
            kind = "write"
        else:
            assert disposition == E.OPEN_EXISTING and flags & E.FILE_FLAG_OPEN_REPARSE_POINT
            if path not in self.files:
                self.last_error = 2
                return -1
            kind = "read" if access == E.GENERIC_READ else "identity"
        handle, self.next_handle = self.next_handle, self.next_handle + 4
        self.handles[handle] = {"path": path, "kind": kind, "pos": 0}
        return handle

    def GetHandleInformation(self, handle, flags):
        if self._failing("GetHandleInformation"):
            return 0
        flags._obj.value = self.inherit_flags
        return 1

    def WriteFile(self, handle, address, length, written, overlapped):
        if self._failing("WriteFile"):
            return 0
        data = ctypes.string_at(address, length)
        claimed = {"zero": 0, "half": max(1, length // 2), "over": length + 1,
                   "lie": length}.get(self.write_mode, length)
        stored = data[:min(claimed, length)] if self.write_mode != "lie" else data[:-1]
        self.files[self.handles[handle]["path"]]["data"] += stored
        written._obj.value = claimed
        return 1

    def FlushFileBuffers(self, handle):
        return 0 if self._failing("FlushFileBuffers") else 1

    def CloseHandle(self, handle):
        self.closed.append(handle)
        self.handles.pop(handle, None)
        return 0 if self._failing("CloseHandle") else 1

    def ReadFile(self, handle, address, length, read, overlapped):
        if self._failing("ReadFile"):
            return 0
        entry = self.handles[handle]
        data = bytes(self.files[entry["path"]]["data"])
        chunk = data[entry["pos"]:entry["pos"] + length]
        if self.read_overclaim and chunk:
            read._obj.value = length + 5
            return 1
        ctypes.memmove(address, chunk, len(chunk))
        entry["pos"] += len(chunk)
        read._obj.value = len(chunk)
        return 1

    def GetFileInformationByHandle(self, handle, info_ref):
        if self._failing("GetFileInformationByHandle"):
            return 0
        entry = self.handles[handle]
        if entry["kind"] == "dir":
            source = self.dirs[entry["path"]]
            values = {"attrs": source["attrs"], "volume": source["volume"], "size": 0,
                      "links": 1, "index": 1, **self.dir_info}
        else:
            source = self.files[entry["path"]]
            values = {"attrs": source["attrs"], "volume": source["volume"],
                      "size": len(source["data"]), "links": source["links"],
                      "index": source["index"], **self.file_info}
        info = info_ref._obj
        info.dwFileAttributes, info.dwVolumeSerialNumber = values["attrs"], values["volume"]
        info.nFileSizeHigh, info.nFileSizeLow = values["size"] >> 32, values["size"] & 0xFFFFFFFF
        info.nNumberOfLinks = values["links"]
        info.nFileIndexHigh, info.nFileIndexLow = 0, values["index"]
        return 1

    def GetFinalPathNameByHandleW(self, handle, address, capacity, flags):
        if self._failing("GetFinalPathNameByHandleW"):
            return 0
        assert flags == E.FINAL_PATH_FLAGS and capacity == E.FINAL_PATH_CAPACITY
        text = self.final_override if self.final_override is not None \
            else "\\\\?\\" + self.handles[handle]["path"]
        encoded = (text + "\0").encode("utf-16-le")
        ctypes.memmove(address, encoded, len(encoded))
        return len(text) if self.final_length is None else self.final_length


def open_gates(monkeypatch):
    """In memory only: the evidence-write flag and a probe authorization."""
    monkeypatch.setattr(E, "EVIDENCE_WRITES_ENABLED", True)
    monkeypatch.setattr(C, "PROBE_ENABLED", True)
    monkeypatch.setattr(C, "APPROVED_PROBES", frozenset({"probe-01"}))
    monkeypatch.setattr(C, "_git_head", lambda *require: HEAD)
    return C.authorize_probe("probe-01", HEAD)


def win_fs(monkeypatch, **overrides):
    kernel32 = FakeKernel32Fs(**overrides)
    fs = E.WindowsFsOps(open_gates(monkeypatch), loader=kernel32.loader,
                        last_error=lambda: kernel32.last_error)
    return fs, kernel32


class TestWindowsFsOpsGates:
    def test_disabled_flag_refuses_before_loading(self):
        kernel32 = FakeKernel32Fs()
        with pytest.raises(E.EvidenceDisabled, match="not enabled"):
            E.WindowsFsOps(object(), loader=kernel32.loader)
        assert kernel32.loads == [] and kernel32.log == []

    def test_flag_alone_is_not_enough(self, monkeypatch):
        monkeypatch.setattr(E, "EVIDENCE_WRITES_ENABLED", True)
        for forged in (None, object(), C.ProbeAuthorization("probe-01", HEAD)):
            with pytest.raises(E.EvidenceDisabled, match="no valid authorization"):
                E.WindowsFsOps(forged, loader=FakeKernel32Fs().loader)

    def test_gates_rechecked_on_every_call(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        monkeypatch.setattr(E, "EVIDENCE_WRITES_ENABLED", False)
        with pytest.raises(E.EvidenceDisabled):
            fs.dir_identity(RUN_DIR)
        monkeypatch.setattr(E, "EVIDENCE_WRITES_ENABLED", True)
        monkeypatch.setattr(C, "PROBE_ENABLED", False)
        with pytest.raises(E.EvidenceDisabled):
            fs.dir_identity(RUN_DIR)
        assert kernel32.loads == [] and kernel32.log == []

    def test_real_loader_is_never_used(self, monkeypatch):
        fs = E.WindowsFsOps(open_gates(monkeypatch))
        assert not fs.loaded
        with pytest.raises(LiveAccessAttempt, match="real kernel32 loader"):
            fs.dir_identity(RUN_DIR)


@pytest.fixture
def no_harness_import(monkeypatch):
    """Any attempt to import the harness (or run_benchmark) or to probe the
    temporary directory fails the test."""
    import builtins
    import importlib
    import tempfile
    real_import = builtins.__import__
    attempts = []

    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in ("calibrate_generator", "run_benchmark"):
            attempts.append(name)
            raise LiveAccessAttempt(f"import of {name} attempted")
        return real_import(name, *args, **kwargs)

    def refuse(what):
        def call(*args, **kwargs):
            attempts.append(what)
            raise LiveAccessAttempt(f"{what} attempted")
        return call

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(importlib, "import_module", refuse("importlib.import_module"))
    monkeypatch.setattr(tempfile, "gettempdir", refuse("tempfile.gettempdir"))
    monkeypatch.setattr(tempfile, "_get_default_tempdir", refuse("the tempdir probe"))
    return attempts


def fake_harness(**attributes):
    """A module object posing as the harness (it can never be the real one)."""
    import importlib.machinery
    import types as pytypes
    module = pytypes.ModuleType(E.HARNESS_MODULE)
    module.__spec__ = importlib.machinery.ModuleSpec(E.HARNESS_MODULE, None)
    module.__spec__._initializing = False
    module.__file__ = C.__file__
    module._require_any_authorization = C._require_any_authorization
    module.CalibrationError = C.CalibrationError
    for name, value in attributes.items():
        setattr(module, name, value)
    return module


class TestHarnessLookup:
    def test_lookup_only_in_source(self):
        code = SOURCE.split('"""', 2)[2]
        section = code[code.index("# WindowsFsOps (slice E2)"):code.index(
            "# Recovery classification")]
        for word in ("import calibrate_generator", "import run_benchmark", "importlib",
                     "__import__", "tempfile", "exec(", "eval("):
            assert word not in section, word
        assert "sys.modules.get(HARNESS_MODULE)" in section

    def test_missing_module_refuses_without_import(self, monkeypatch, no_harness_import):
        auth = open_gates(monkeypatch)
        monkeypatch.delitem(sys.modules, E.HARNESS_MODULE)
        kernel32 = FakeKernel32Fs()
        with pytest.raises(E.EvidenceDisabled, match="not loaded; the evidence adapter never "
                                                     "imports it"):
            E.WindowsFsOps(auth, loader=kernel32.loader)
        assert no_harness_import == [] and kernel32.loads == []
        assert E.HARNESS_MODULE not in sys.modules                 # not preloaded or repaired

    def test_removal_after_construction_blocks_every_call(self, monkeypatch, no_harness_import):
        fs, kernel32 = win_fs(monkeypatch)
        monkeypatch.delitem(sys.modules, E.HARNESS_MODULE)
        for call in (lambda: fs.dir_identity(RUN_DIR), lambda: fs.open_exclusive("x"),
                     lambda: fs.write(1, b"x"), lambda: fs.flush(1), lambda: fs.close(1),
                     lambda: fs.read_all("x"), lambda: fs.file_identity("x")):
            with pytest.raises(E.EvidenceDisabled, match="not loaded"):
                call()
        assert kernel32.log == [] and kernel32.loads == [] and no_harness_import == []

    def test_partially_initialized_module_refuses(self, monkeypatch, no_harness_import):
        auth = open_gates(monkeypatch)
        monkeypatch.setattr(C.__spec__, "_initializing", True, raising=False)
        with pytest.raises(E.EvidenceDisabled, match="partially initialized"):
            E.WindowsFsOps(auth, loader=FakeKernel32Fs().loader)
        monkeypatch.setattr(C.__spec__, "_initializing", False, raising=False)
        monkeypatch.setitem(sys.modules, E.HARNESS_MODULE, fake_harness(__spec__=None))
        with pytest.raises(E.EvidenceDisabled, match="partially initialized"):
            E.WindowsFsOps(auth, loader=FakeKernel32Fs().loader)
        assert no_harness_import == []

    @pytest.mark.parametrize("attributes, message", [
        ({"__name__": "other"}, "unexpected name"),
        ({"__file__": r"C:\elsewhere\calibrate_generator.py"}, "replaced"),
        ({"__file__": None}, "replaced"),
        ({}, "not the module's own"),                         # a perfect-looking impostor
        ({"_require_any_authorization": None}, "missing or not the module's own"),
    ])
    def test_replaced_or_malformed_module_refuses(self, monkeypatch, no_harness_import,
                                                  attributes, message):
        auth = open_gates(monkeypatch)
        monkeypatch.setitem(sys.modules, E.HARNESS_MODULE, fake_harness(**attributes))
        with pytest.raises(E.EvidenceDisabled, match=message):
            E.WindowsFsOps(auth, loader=FakeKernel32Fs().loader)
        assert no_harness_import == []

    def test_tampered_real_module_refuses(self, monkeypatch, no_harness_import):
        auth = open_gates(monkeypatch)
        monkeypatch.setattr(C, "_require_any_authorization", lambda authorization: authorization)
        with pytest.raises(E.EvidenceDisabled, match="not the module's own"):
            E.WindowsFsOps(auth, loader=FakeKernel32Fs().loader)
        monkeypatch.undo()
        auth = open_gates(monkeypatch)
        monkeypatch.setattr(C, "CalibrationError", "not a type")
        with pytest.raises(E.EvidenceDisabled, match="error type"):
            E.WindowsFsOps(auth, loader=FakeKernel32Fs().loader)

    def test_presence_is_not_authorization(self, monkeypatch, no_harness_import):
        monkeypatch.setattr(E, "EVIDENCE_WRITES_ENABLED", True)
        assert sys.modules[E.HARNESS_MODULE] is C
        for forged in (None, object(), C.ProbeAuthorization("probe-01", HEAD)):
            with pytest.raises(E.EvidenceDisabled, match="no valid authorization"):
                E.WindowsFsOps(forged, loader=FakeKernel32Fs().loader)
        assert no_harness_import == []

    def test_valid_authorization_with_the_loaded_harness(self, monkeypatch, no_harness_import):
        fs, kernel32 = win_fs(monkeypatch)
        w = write_steps(win_writer(fs))
        complete(w)
        assert E.verify_chain(w.records).ok and no_harness_import == []
        assert kernel32.loads == ["kernel32"]

    def test_revoked_authorization_refuses_every_operation(self, monkeypatch,
                                                           no_harness_import):
        fs, kernel32 = win_fs(monkeypatch)
        monkeypatch.setattr(C, "APPROVED_PROBES", frozenset())         # revoke
        for call in (lambda: fs.dir_identity(RUN_DIR), lambda: fs.open_exclusive("x"),
                     lambda: fs.write(1, b"x"), lambda: fs.flush(1), lambda: fs.close(1),
                     lambda: fs.read_all("x"), lambda: fs.file_identity("x")):
            with pytest.raises(E.EvidenceDisabled, match="no valid authorization"):
                call()
        assert kernel32.log == [] and kernel32.loads == [] and no_harness_import == []

    def test_disabled_flag_never_looks_up_or_imports(self, monkeypatch, no_harness_import):
        monkeypatch.delitem(sys.modules, E.HARNESS_MODULE)
        with pytest.raises(E.EvidenceDisabled, match="not enabled"):
            E.WindowsFsOps(object(), loader=FakeKernel32Fs().loader)
        assert no_harness_import == []


class TestWindowsFsOpsContracts:
    @pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="x64 layout")
    def test_structure_layout(self):
        t = E._fs_types()
        assert ctypes.sizeof(t.INFO) == 52 and ctypes.sizeof(t.FILETIME) == 8
        assert t.INFO.dwVolumeSerialNumber.offset == 28 and t.INFO.nNumberOfLinks.offset == 40
        assert t.INFO.nFileIndexLow.offset == 48

    def test_signatures(self):
        t = E._fs_types()
        signatures = E._fs_signatures(t)
        assert set(signatures) == set(FakeKernel32Fs.APIS)
        assert signatures["CreateFileW"][0] is t.w.HANDLE
        assert len(signatures["CreateFileW"][1]) == 7
        assert signatures["GetFinalPathNameByHandleW"][0] is t.w.DWORD

    def test_flags(self):
        assert (E.CREATE_NEW, E.OPEN_EXISTING, E.GENERIC_WRITE, E.GENERIC_READ) == (
            1, 3, 0x40000000, 0x80000000)
        assert (E.FILE_FLAG_WRITE_THROUGH, E.FILE_FLAG_BACKUP_SEMANTICS,
                E.FILE_FLAG_OPEN_REPARSE_POINT, E.FILE_ATTRIBUTE_REPARSE_POINT) == (
            0x80000000, 0x02000000, 0x00200000, 0x400)

    @pytest.mark.parametrize("text, expected", [
        ("\\\\?\\C:\\Users\\u\\x", "C:\\Users\\u\\x"),
        ("\\\\?\\UNC\\server\\share\\x", "\\\\server\\share\\x"),
    ])
    def test_final_path_normalization(self, text, expected):
        assert E.normalize_final_path(text) == expected

    @pytest.mark.parametrize("text", ["C:\\x", "\\\\?\\Volume{1}\\x", "", None, "\\\\?\\C:\\a\x00"])
    def test_malformed_final_paths(self, text):
        with pytest.raises(OSError):
            E.normalize_final_path(text)

    def test_windows_error_mapping(self):
        assert isinstance(E.windows_error("x", 80), FileExistsError)
        assert isinstance(E.windows_error("x", 5), PermissionError)
        assert isinstance(E.windows_error("x", 3), FileNotFoundError)
        full = E.windows_error("x", 112)
        assert full.errno == errno.ENOSPC and full.windows_code == 112
        assert type(E.windows_error("x", 1234)) is OSError


def win_writer(fs):
    return E.EvidenceWriter(RUN_DIR, fs, expected_dir={"final_path": RUN_DIR,
                                                       "volume_serial": 77},
                            run_id=RUN, expected_head=HEAD, token_sha256=TOKEN_SHA)


class TestWindowsFsOpsWrites:
    def test_full_chain_matches_the_fake_path(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        w = write_steps(win_writer(fs))
        complete(w)
        chain = E.verify_chain(w.records)
        assert chain.ok and chain.complete
        assert chain.tip_digest == full_chain().state.last_verified_digest
        name = RUN_DIR + "\\000-prelaunch.json"
        assert bytes(kernel32.files[name]["data"]) == P.canonical_json(w.records[0])
        assert kernel32.handles == {} and kernel32.loads == ["kernel32"]
        assert kernel32.dirs == {RUN_DIR: {"attrs": E.FILE_ATTRIBUTE_DIRECTORY, "volume": 77}}

    def test_partial_writes_progress(self, monkeypatch):
        fs, _ = win_fs(monkeypatch, write_mode="half")
        w = win_writer(fs)
        w.write("prelaunch", envelope(), {"x": "y" * 200})
        assert w.state.last_verified_sequence == 0

    def _fails(self, monkeypatch, operation, partial=None, **overrides):
        fs, kernel32 = win_fs(monkeypatch, **overrides)
        w = win_writer(fs)
        with pytest.raises(E.EvidenceFailed):
            w.write("prelaunch", envelope(), {})
        assert w.state.failed_operation == operation, w.state.failed_operation
        if partial is not None:
            assert w.state.partial_record_possible is partial
        assert kernel32.handles == {}                              # every handle closed
        return w, kernel32

    @pytest.mark.parametrize("overrides, operation, partial", [
        ({"write_mode": "zero"}, "write_short", True),
        ({"write_mode": "over"}, "write_short", True),
        ({"write_mode": "lie"}, "readback_mismatch", True),
        ({"fail": {"WriteFile": 112}}, "write:OSError", True),
        ({"fail": {"FlushFileBuffers": 1117}}, "flush:OSError", True),
        ({"fail": {"ReadFile": 23}}, "readback:OSError", True),
        ({"read_overclaim": True}, "readback:OSError", True),
        ({"file_info": {"links": 2}}, "file_identity", True),
        ({"file_info": {"attrs": E.FILE_ATTRIBUTE_NORMAL | E.FILE_ATTRIBUTE_REPARSE_POINT}},
         "file_identity", True),
        ({"file_info": {"volume": 78}}, "file_identity", True),
        ({"file_info": {"attrs": E.FILE_ATTRIBUTE_DIRECTORY}}, "file_identity:OSError", True),
        ({"inherit_flags": 1}, "create_unusable:OSError", True),
        ({"fail": {"GetHandleInformation": 6}}, "create_unusable:OSError", True),
        ({"fail": {"CreateFileW": 112}}, "directory_identity:OSError", False),
        ({"dirs": {}}, "directory_missing", False),
        ({"dir_info": {"attrs": E.FILE_ATTRIBUTE_DIRECTORY | E.FILE_ATTRIBUTE_REPARSE_POINT}},
         "directory_reparse_point", False),
        ({"dir_info": {"attrs": E.FILE_ATTRIBUTE_NORMAL}}, "directory_identity:OSError", False),
        ({"dir_info": {"volume": 78}}, "directory_volume_mismatch", False),
        ({"final_override": "\\\\?\\C:\\elsewhere"}, "directory_path_mismatch", False),
        ({"final_override": "C:\\no-prefix"}, "directory_identity:OSError", False),
        ({"final_length": 0}, "directory_identity:OSError", False),
        ({"final_length": 3}, "directory_identity:OSError", False),
        ({"fail": {"GetFileInformationByHandle": 6}}, "directory_identity:OSError", False),
    ])
    def test_failures(self, monkeypatch, overrides, operation, partial):
        self._fails(monkeypatch, operation, partial, **overrides)

    def test_duplicate_create(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        name = RUN_DIR + "\\000-prelaunch.json"
        kernel32.files[name] = {"data": bytearray(b"existing"), "attrs": 0x80, "links": 1,
                                "volume": 77, "index": 1}
        w = win_writer(fs)
        with pytest.raises(E.EvidenceFailed, match="create_duplicate"):
            w.write("prelaunch", envelope(), {})
        assert bytes(kernel32.files[name]["data"]) == b"existing"
        assert not w.state.partial_record_possible

    @pytest.mark.parametrize("code, operation", [(112, "create:OSError"),
                                                 (5, "create:PermissionError"),
                                                 (3, "create:FileNotFoundError")])
    def test_create_errors(self, monkeypatch, code, operation):
        fs, kernel32 = win_fs(monkeypatch)
        real_create = kernel32.CreateFileW

        def create(path, access, share, attributes, disposition, flags, template):
            if disposition == E.CREATE_NEW:
                kernel32.last_error = code
                return -1
            return real_create(path, access, share, attributes, disposition, flags, template)

        kernel32.CreateFileW = create
        w = win_writer(fs)
        with pytest.raises(E.EvidenceFailed, match=operation):
            w.write("prelaunch", envelope(), {})
        assert kernel32.files == {} and not w.state.partial_record_possible

    def test_close_failure(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        real_close = kernel32.CloseHandle

        def close(handle):
            kind = kernel32.handles.get(handle, {}).get("kind")
            real_close(handle)
            return 0 if kind == "write" else 1

        kernel32.CloseHandle = close
        w = win_writer(fs)
        with pytest.raises(E.EvidenceFailed, match="close:OSError"):
            w.write("prelaunch", envelope(), {})
        assert w.state.partial_record_possible

    def test_short_read_and_growth(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        name = RUN_DIR + "\\x.json"
        kernel32.files[name] = {"data": bytearray(b"abc"), "attrs": 0x80, "links": 1,
                                "volume": 77, "index": 5}
        assert fs.read_all(name) == b"abc"
        kernel32.file_info = {"size": 5}
        with pytest.raises(OSError, match="short read"):
            fs.read_all(name)
        kernel32.file_info = {"size": 2}
        with pytest.raises(OSError, match="grew"):
            fs.read_all(name)
        kernel32.file_info = {"size": E.MAX_RECORD_BYTES + 1}
        with pytest.raises(OSError, match="too large"):
            fs.read_all(name)
        assert kernel32.handles == {}

    def test_file_identity_values(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        name = RUN_DIR + "\\x.json"
        kernel32.files[name] = {"data": bytearray(b"abcd"), "attrs": 0x80, "links": 1,
                                "volume": 77, "index": 9}
        assert fs.file_identity(name) == {"links": 1, "reparse": False, "volume_serial": 77,
                                          "file_index": 9, "size": 4}
        assert fs.dir_identity(RUN_DIR) == {"exists": True, "reparse": False,
                                            "final_path": RUN_DIR, "volume_serial": 77}
        assert kernel32.handles == {}

    def test_open_flags(self, monkeypatch):
        fs, kernel32 = win_fs(monkeypatch)
        win_writer(fs).write("prelaunch", envelope(), {})
        creates = [args for args in kernel32.calls_args if args[4] == E.CREATE_NEW]
        assert len(creates) == 1
        _, access, share, attributes, _, flags, template = creates[0]
        assert (access, share, attributes, template) == (E.GENERIC_WRITE, 0, None, None)
        assert flags == E.FILE_ATTRIBUTE_NORMAL | E.FILE_FLAG_WRITE_THROUGH
        for path, access, share, attributes, disposition, flags, template in kernel32.calls_args:
            if disposition == E.OPEN_EXISTING:
                assert flags & E.FILE_FLAG_OPEN_REPARSE_POINT        # never follow a reparse
        assert "GetHandleInformation" in kernel32.log


# ---------------------------------------------------------------------------
# Strict record contract (J-39): versioning, assignment, job content, resume
# ---------------------------------------------------------------------------

#: The original E1 run, as legacy records carried it.
LEGACY_STEPS = [
    ("prelaunch", {}, {"result": "passed"}),
    ("job_configured", dict(job=JOB, context_sha256="3" * 64), {"limits": "verified"}),
    ("process_created", RUNNING, dict(PROCESS)),
    ("job_verified_and_validated", RUNNING, {"members": [4242]}),
    ("resume_intent", RUNNING, {}),
]


def chain_of(steps, contract=None):
    """Records built purely (no writer, no file system) and digest-chained."""
    contract = contract or E.STRICT
    version = E.WRITER_VERSION if contract == E.STRICT else E.LEGACY_WRITER_VERSION
    records, previous = [], None
    for sequence, (kind, changes, body) in enumerate(steps):
        env = envelope(**{"integrity": {"writer_version": version}, **changes})
        record = E.build_record(kind, env, body, sequence=sequence,
                                previous_record_sha256=previous, contract=contract)
        records.append(record)
        previous = E.record_digest(record)
    return records


def strict_problems(kind, changes, body):
    record = {"schema": E.EVIDENCE_SCHEMA, "kind": kind, "sequence": 1,
              "previous_record_sha256": "0" * 64, "body": body, **envelope(**changes)}
    return E.record_problems(record)


def with_job(**job):
    return {**RUNNING, "job": {**JOB, **job}}


class TestRecordContracts:
    def test_contract_table(self):
        assert E.RECORD_CONTRACTS == {
            ("agentops-evidence/1", "evidence-store/e1"): "legacy",
            ("agentops-evidence/2", "evidence-store/e2"): "strict"}
        assert (E.EVIDENCE_SCHEMA, E.WRITER_VERSION) == ("agentops-evidence/2",
                                                         "evidence-store/e2")

    def test_valid_strict_chain(self):
        w = full_chain()
        chain = E.verify_chain(w.records, expected_run_id=RUN, expected_head=HEAD,
                               expected_token_sha256=TOKEN_SHA)
        assert chain.ok and chain.contract == E.STRICT and chain.complete
        assert all(E.record_contract(r) == E.STRICT for r in w.records)

    def test_valid_legacy_chain_under_its_original_contract(self):
        records = chain_of(LEGACY_STEPS, E.LEGACY)
        chain = E.verify_chain(records)
        assert chain.ok and chain.contract == E.LEGACY and chain.count == 5
        assert chain.durable_stages == list(P.LIFECYCLE_STAGES[:5])
        before_resume = [(k, {**c, "job": {**JOB, "assignment": "assigned_before_resume"}}
                          if c else c, b) for k, c, b in LEGACY_STEPS]
        assert E.verify_chain(chain_of(before_resume, E.LEGACY)).ok   # E1 rules, unchanged

    def test_legacy_records_never_satisfy_the_strict_contract(self):
        for record in chain_of(LEGACY_STEPS, E.LEGACY)[1:4]:
            relabelled = {**copy.deepcopy(record), "schema": E.EVIDENCE_SCHEMA,
                          "integrity": {"writer_version": E.WRITER_VERSION}}
            assert E.record_problems(relabelled)                     # strict content missing
        w = writer()
        w.records = chain_of(LEGACY_STEPS, E.LEGACY)
        assert not w.may_resume and not w.may_launch
        w.next_sequence = 5
        with pytest.raises(E.EvidenceError, match="differs from the chain's legacy contract"):
            w.write("resume_result", envelope(**RUNNING),
                    {"execution_history": P.MAY_HAVE_EXECUTED})

    @pytest.mark.parametrize("schema, version", [
        ("agentops-evidence/1", "evidence-store/e2"), ("agentops-evidence/2", "evidence-store/e1"),
        ("agentops-evidence/3", "evidence-store/e2"), ("agentops-evidence/2", "evidence-store/e3"),
        (None, "evidence-store/e2"), ("agentops-evidence/2", None), (["x"], "evidence-store/e2"),
    ])
    def test_unsupported_schema_version_combinations(self, schema, version):
        record = copy.deepcopy(full_chain().records[0])
        record["schema"], record["integrity"] = schema, {"writer_version": version}
        assert E.record_contract(record) is None
        assert "unsupported schema/version combination" in E.record_problems(record)

    def test_build_record_contract_must_match_the_envelope(self):
        with pytest.raises(E.EvidenceError, match="unknown record contract"):
            E.build_record("prelaunch", envelope(), {}, sequence=0, previous_record_sha256=None,
                           contract="lenient")
        with pytest.raises(E.EvidenceError, match="unsupported schema/version combination"):
            E.build_record("prelaunch", envelope(), {}, sequence=0, previous_record_sha256=None,
                           contract=E.LEGACY)                 # strict envelope, legacy schema

    def test_contracts_never_mix_in_one_chain(self):
        legacy = chain_of(LEGACY_STEPS[:1], E.LEGACY)
        strict = E.build_record("job_configured", envelope(**CONFIGURED), CONFIG_BODY,
                                sequence=1, previous_record_sha256=E.record_digest(legacy[0]))
        chain = E.verify_chain(legacy + [strict])
        assert not chain.ok and "differs from the chain's legacy contract" in chain.problems[0]
        assert chain.count == 1

    def test_writer_writes_strict_only(self):
        w = write_steps(writer(), 2)
        assert {E.record_contract(r) for r in w.records} == {E.STRICT}
        with pytest.raises(E.EvidenceError, match="unsupported schema/version"):
            w.write("process_created",
                    envelope(**RUNNING, integrity={"writer_version": E.LEGACY_WRITER_VERSION}),
                    CREATED_BODY)


class TestStrictAssignment:
    @pytest.mark.parametrize("kind, body", [
        ("process_created", CREATED_BODY), ("job_verified_and_validated", VERIFIED_BODY),
        ("resume_intent", {}), ("final_inspection", {"liveness": P.STATE_UNKNOWN})])
    def test_assigned_before_resume_refused(self, kind, body):
        problems = strict_problems(kind, with_job(assignment="assigned_before_resume"), body)
        assert "assignment after creation (assigned_before_resume) is refused" in problems

    @pytest.mark.parametrize("assignment, message", [
        ("unknown", "not accepted in a strict record"),
        ("assignment_failed", "not accepted in a strict record"),
        ("not_created", "needs job assignment assigned_at_creation"),
        (None, "job identity is malformed"), (1, "job identity is malformed"),
        ("ASSIGNED_AT_CREATION", "job identity is malformed"),
        (["assigned_at_creation"], "job identity is malformed"),
    ])
    def test_malformed_or_unaccepted_assignment(self, assignment, message):
        problems = strict_problems("process_created", with_job(assignment=assignment),
                                   CREATED_BODY)
        assert any(message in p for p in problems)

    def test_missing_assignment(self):
        job = {"job_id": JOB_ID, "limits_verified": True}
        assert "job identity is malformed" in strict_problems(
            "process_created", {**RUNNING, "job": job}, CREATED_BODY)

    def test_contradictory_assignment(self):
        assert "a job assignment without a process is contradictory" in strict_problems(
            "job_configured", dict(job=JOB, context_sha256="3" * 64), CONFIG_BODY)
        for job in ({"limits_verified": False}, {"job_id": None}):
            assert "a record naming a process needs a verified job identity" in strict_problems(
                "process_created", with_job(**job), CREATED_BODY)

    def test_assignment_never_inferred_from_membership(self):
        problems = strict_problems("job_verified_and_validated",
                                   with_job(assignment="not_created"), VERIFIED_BODY)
        assert "a record naming a process needs job assignment assigned_at_creation" in problems


class TestStrictJobConfiguration:
    @pytest.mark.parametrize("field", sorted(CONFIG_BODY))
    def test_missing_field(self, field):
        body = {k: v for k, v in CONFIG_BODY.items() if k != field}
        assert any("exactly the configuration read-back fields" in p
                   for p in strict_problems("job_configured", CONFIGURED, body))

    def test_extra_field(self):
        assert any("exactly the configuration read-back fields" in p for p in strict_problems(
            "job_configured", CONFIGURED, {**CONFIG_BODY, "limits": "verified"}))

    @pytest.mark.parametrize("value", [None, 0, "false"])
    def test_inheritance_must_be_observed(self, value):
        assert "job_configured needs the observed handle inheritance (true or false)" in \
            strict_problems("job_configured", CONFIGURED,
                            {**CONFIG_BODY, "job_handle_inheritable": value})

    @pytest.mark.parametrize("changes, message", [
        ({"limit_flags": 0x0408}, "required limit flags missing: 0x2000"),
        ({"limit_flags": 0x2008}, "required limit flags missing: 0x400"),
        ({"limit_flags": 0x2408 | 0x800}, "breakaway flags present: 0x800"),
        ({"limit_flags": 0x2408 | 0x1000}, "breakaway flags present: 0x1000"),
        ({"limit_flags": 0x2408 | 0x2}, "unexpected limit flags: 0x2"),
        ({"limit_flags": "x"}, "limit_flags missing or malformed"),
        ({"active_process_limit": 2}, "active process limit is 2, not 1"),
        ({"active_process_limit": 0}, "active process limit is 0, not 1"),
        ({"active_process_limit": True}, "active process limit is True, not 1"),
        ({"job_handle_inheritable": True}, "the job handle is (or may be) inheritable"),
    ])
    def test_invalid_configuration(self, changes, message):
        assert f"job_configured: {message}" in strict_problems(
            "job_configured", CONFIGURED, {**CONFIG_BODY, **changes})

    def test_needs_a_verified_job(self):
        for job in ({"limits_verified": False}, {"job_id": None}):
            assert "job_configured needs a verified job identity" in strict_problems(
                "job_configured", {**CONFIGURED, "job": {**JOB_READY, **job}}, CONFIG_BODY)

    def test_delegates_to_the_planner(self, monkeypatch):
        monkeypatch.setattr(P, "job_configuration_problems", lambda body: ["planner refuses"])
        assert "job_configured: planner refuses" in strict_problems("job_configured",
                                                                    CONFIGURED, CONFIG_BODY)
        code = SOURCE.split('"""', 2)[2]
        assert "breakaway flags present" not in code and "required_flags" not in code


class TestStrictProcessCreation:
    def test_constants_match_the_backend(self):
        import win32_job as W
        assert E.CREATION_ATTRIBUTES == (W.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                         W.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                         W.PROC_THREAD_ATTRIBUTE_JOB_LIST)

    @pytest.mark.parametrize("applied", [[0x20009, 0x20002, 0x2000D], [0x2000D, 0x20009, 0x20002]])
    def test_applied_attributes_accepted(self, applied):
        assert strict_problems("process_created", RUNNING,
                               {**CREATED_BODY, "applied_attributes": applied}) == []

    @pytest.mark.parametrize("applied, message", [
        ([0x20009, 0x20002], "not exactly"), ([0x20009, 0x2000D], "not exactly"),
        ([0x20009, 0x20002, 0x2000D, 0x20000], "not exactly"),
        ([0x20009, 0x20002, 0x20002], "duplicates"),
        ([0x20009, 0x20002, 0x2000D, 0x2000D], "duplicates"),
        ([0x20009, 0x20002, True], "malformed"), ([0x20009, 0x20002, "0x2000D"], "malformed"),
        ([], "not exactly"), (None, "malformed"), ({"job_list": 0x2000D}, "malformed"),
        ("0x20009,0x20002,0x2000D", "malformed"),
    ])
    def test_invalid_applied_attributes(self, applied, message):
        problems = strict_problems("process_created", RUNNING,
                                   {**CREATED_BODY, "applied_attributes": applied})
        assert any(message in p for p in problems), problems

    @pytest.mark.parametrize("value", [False, None, 1, "true"])
    def test_needs_a_successful_creation_result(self, value):
        assert "process_created needs a successful CreateProcessW result" in strict_problems(
            "process_created", RUNNING, {**CREATED_BODY, "create_process_ok": value})

    def test_a_plan_is_not_proof(self):
        planned = {k: v for k, v in CREATED_BODY.items() if k != "applied_attributes"}
        planned["planned_attributes"] = [0x20009, 0x20002, 0x2000D]
        for body in (planned, {**CREATED_BODY, "planned_attributes": [0x2000D]},
                     {k: v for k, v in CREATED_BODY.items() if k != "create_process_ok"}):
            assert any("a plan is not proof" in p
                       for p in strict_problems("process_created", RUNNING, body))

    def test_identity_still_required(self):
        assert any("name the process" in p for p in strict_problems(
            "process_created", RUNNING, {**CREATED_BODY, "pid": 1}))


class TestStrictMembership:
    @pytest.mark.parametrize("field", P.JOB_MEMBERSHIP_FIELDS)
    def test_missing_membership_field(self, field):
        membership = {k: v for k, v in MEMBERSHIP.items() if k != field}
        assert any("membership must carry exactly" in p for p in strict_problems(
            "job_verified_and_validated", RUNNING, {**VERIFIED_BODY, "membership": membership}))

    def _membership(self, **changes):
        return strict_problems("job_verified_and_validated", RUNNING,
                               {**VERIFIED_BODY, "membership": {**MEMBERSHIP, **changes}})

    @pytest.mark.parametrize("changes, message", [
        ({"pid": 999}, "the PID 999 is not the expected child's"),
        ({"creation_time": "2026-10-09T12:00:01.000Z"}, "creation time is not the expected"),
        ({"job_assignment": "assigned_before_resume"}, "assigned_before_resume) is refused"),
        ({"in_job": False}, "the child is not in the job"),
        ({"in_job": "true"}, "in_job is malformed"),
    ])
    def test_identity_assignment_and_presence(self, changes, message):
        assert any(message in p for p in self._membership(**changes))

    @pytest.mark.parametrize("field, value, ok", [
        ("active_processes", 0, False), ("active_processes", 1, True),
        ("active_processes", 2, False), ("total_processes", 0, False),
        ("total_processes", 1, True), ("total_processes", 2, False),
        ("total_processes", True, False), ("active_processes", None, False),
    ])
    def test_process_counts(self, field, value, ok):
        assert (self._membership(**{field: value}) == []) is ok

    @pytest.mark.parametrize("members", [[4242, 7], [], [7], [4242, 4242], None])
    def test_member_pids(self, members):
        assert any("member" in p for p in self._membership(member_pids=members))

    @pytest.mark.parametrize("changes", [
        {"token_ok": False}, {"image_ok": False}, {"token_ok": None}, {"image_ok": "true"},
        {"token_ok": 1}])
    def test_token_and_image_must_be_true(self, changes):
        assert "token and image validation must both be explicitly true" in strict_problems(
            "job_verified_and_validated", RUNNING, {**VERIFIED_BODY, **changes})

    @pytest.mark.parametrize("field", ["token_ok", "image_ok", "membership"])
    def test_missing_body_field(self, field):
        body = {k: v for k, v in VERIFIED_BODY.items() if k != field}
        assert any("needs exactly membership, token_ok and image_ok" in p
                   for p in strict_problems("job_verified_and_validated", RUNNING, body))

    def test_needs_the_recorded_identity(self):
        assert "job_verified_and_validated needs the recorded process identity" in \
            strict_problems("job_verified_and_validated", CONFIGURED, VERIFIED_BODY)

    def test_a_stage_name_alone_proves_nothing(self):
        assert strict_problems("job_verified_and_validated", RUNNING, {})
        assert strict_problems("job_verified_and_validated", RUNNING, {"members": [4242]})


class TestStrictResumePrerequisites:
    def test_resume_requires_a_valid_membership_record(self):
        w = write_steps(writer(), 3)                      # up to process_created
        with pytest.raises(E.EvidenceError, match="may not follow"):
            w.write("resume_intent", envelope(**RUNNING), {})
        before = (w.next_sequence, dict(w.fs.files))
        bad = {**VERIFIED_BODY, "membership": {**MEMBERSHIP, "total_processes": 2}}
        with pytest.raises(E.EvidenceError, match="total|processes have been"):
            w.write("job_verified_and_validated", envelope(**RUNNING), bad)
        assert (w.next_sequence, dict(w.fs.files)) == before     # nothing consumed
        assert not w.state.evidence_failed and w.state.ownership_retained
        assert not w.may_resume

    def test_valid_membership_then_intent_allows_resume(self):
        w = write_steps(writer(), 4)
        assert not w.may_resume
        w.write("resume_intent", envelope(**RUNNING), {})
        assert w.may_resume

    def test_explicit_strict_resume_check(self, monkeypatch):
        records = chain_of(STEPS[:3] + [("resume_intent", RUNNING, {})])
        chain = E.verify_chain(records)
        assert not chain.ok and "may not follow" in chain.problems[0] and chain.count == 3
        relaxed = {**E.ALLOWED_NEXT, "process_created": E.ALLOWED_NEXT["process_created"]
                   | {"resume_intent"}}
        monkeypatch.setattr(E, "ALLOWED_NEXT", relaxed)          # order rule bypassed in memory
        chain = E.verify_chain(records)
        assert not chain.ok and chain.count == 3
        assert "resume_intent without a validated job membership record" in chain.problems[0]

    def test_tampered_records_revoke_permissions(self):
        w = write_steps(writer(), 5)
        assert w.may_resume
        w.records[3] = copy.deepcopy(w.records[3])
        w.records[3]["body"]["membership"]["total_processes"] = 2
        assert not w.may_resume and not w.may_launch
        assert not E.verify_chain(w.records).ok

    @pytest.mark.parametrize("mutate, message", [
        (lambda r: r.__setitem__(3, {**r[3], "process": {"pid": 4243,
                                                         "creation_time": CREATED}}),
         "record 3"),
        (lambda r: r.pop(3), "sequence"),
        (lambda r: r.insert(3, r[4]), "sequence"),
        (lambda r: r[3]["body"]["membership"].__setitem__("pid", 4243), "record 3"),
        (lambda r: r[2]["body"].__setitem__("applied_attributes", [0x20009, 0x20002]),
         "record 2"),
    ])
    def test_corrupted_truncated_reordered_or_conflicting(self, mutate, message):
        records = copy.deepcopy(full_chain().records)
        mutate(records)
        chain = E.verify_chain(records)
        assert not chain.ok and message in chain.problems[0]
        assert "resume_intent" not in chain.kinds or chain.count > 4

    def test_truncated_chain_never_permits_resume(self):
        records = full_chain().records[:4]
        w = writer()
        w.records, w.next_sequence = records, 4
        assert E.verify_chain(records).ok and not w.may_resume

    def test_failed_write_retains_ownership(self):
        w = write_steps(writer(FakeFs(fail={"flush": OSError(5, "flush failed")})), 0)
        with pytest.raises(E.EvidenceFailed):
            w.write("prelaunch", envelope(), {"result": "passed"})
        assert w.state.evidence_failed and w.state.ownership_retained
        assert not w.may_resume and not w.may_launch

    def test_strict_contract_needs_no_real_io(self):
        assert E.EVIDENCE_WRITES_ENABLED is False
        fs = FakeFs()
        write_steps(writer(fs))
        assert set(fs.calls) <= {"dir_identity", "open", "write", "flush", "close", "read",
                                 "identity"}

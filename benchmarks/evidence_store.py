"""
benchmarks/evidence_store.py

Offline evidence store (slice E1) for the future isolated AppContainer
runs: the immutable, hash-chained evidence record schema, chain
verification, recovery classification, and a writer that works ONLY
through an injected file-system interface (FsOps).

Nothing here touches a real file system, process or network by default:
the writer only ever calls the FsOps object it is given, and the harness
does not import this module.  WindowsFsOps (slice E2) is the Windows
adapter: kernel32 through ctypes (CreateFileW, WriteFile, ReadFile,
FlushFileBuffers, CloseHandle, GetFileInformationByHandle,
GetFinalPathNameByHandleW, GetHandleInformation), loaded lazily.  It can
only be constructed with EVIDENCE_WRITES_ENABLED True (it is False) AND a
sealed calibration or probe authorization from the harness gates (closed),
and every native call re-checks both.  The harness is never imported from
here: its already initialized module is looked up in sys.modules, and an
absent, partially initialized or replaced module refuses.  It never creates
directories.

Durability limits of WindowsFsOps: the record is created with
FILE_FLAG_WRITE_THROUGH, flushed with FlushFileBuffers, closed, reopened
and re-read; this proves the logical content, not power-loss durability.
Directory entries are not flushed, a device may ignore flushes, and the
re-read may be served from the cache.

Record contracts: a record's (schema, writer_version) pair selects its
contract.  Strict records ("agentops-evidence/2", "evidence-store/e2") carry
the observed job configuration, the applied creation attributes and the
complete job-membership and token evidence, all validated by the planner's
pure validators; job assignment is accepted only AT creation.  Legacy
records ("agentops-evidence/1", "evidence-store/e1") are verified under
their original rules only and never satisfy a strict requirement; one chain
never mixes contracts; any other pair is refused.  The writer writes strict
records only.

Integrity model, stated precisely: a hash chain detects a deleted,
reordered, truncated or altered record.  It is NOT authentication - anyone
able to rewrite every record can recompute every hash.  The verified chain
tip digest is exposed so that it can later be anchored in separately
trusted evidence.  "Verified written" means written, flushed through FsOps,
closed, re-read and matched; it is not a claim of crash durability.

Standard library only.
"""

from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping, Optional, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import appcontainer_preflight as P  # noqa: E402

#: No real file-system adapter exists; this flag does not enable anything.
EVIDENCE_WRITES_ENABLED: bool = False
#: Record contracts, selected by the exact (schema, writer_version) pair.
#: The legacy contract (E1) keeps its original meaning and is only ever
#: verified; it never satisfies a strict requirement.  The writer produces
#: strict records only.
EVIDENCE_SCHEMA: str = "agentops-evidence/2"
WRITER_VERSION: str = "evidence-store/e2"
LEGACY_SCHEMA: str = "agentops-evidence/1"
LEGACY_WRITER_VERSION: str = "evidence-store/e1"
STRICT, LEGACY = "strict", "legacy"
RECORD_CONTRACTS: Mapping[tuple[str, str], str] = {
    (LEGACY_SCHEMA, LEGACY_WRITER_VERSION): LEGACY,
    (EVIDENCE_SCHEMA, WRITER_VERSION): STRICT,
}
#: The PROC_THREAD_ATTRIBUTE identifiers a strict process_created record must
#: show as applied: SECURITY_CAPABILITIES, HANDLE_LIST, JOB_LIST.
CREATION_ATTRIBUTES: tuple[int, ...] = (0x00020009, 0x00020002, 0x0002000D)
#: Job assignments a strict record may carry: none before a process exists,
#: assignment at creation once it does.
STRICT_ASSIGNMENTS: tuple[str, ...] = ("not_created", P.ACCEPTED_JOB_ASSIGNMENT)
JOB_CONFIGURATION_FIELDS: frozenset[str] = frozenset(
    {"limit_flags", "active_process_limit", "job_handle_inheritable"})
PROCESS_CREATED_FIELDS: frozenset[str] = frozenset(
    {"pid", "creation_time", "create_process_ok", "applied_attributes"})
JOB_VERIFIED_FIELDS: frozenset[str] = frozenset({"membership", "token_ok", "image_ok"})
MAX_SEQUENCE: int = 999

RECORD_KINDS: tuple[str, ...] = (
    "prelaunch", "job_configured", "process_created", "job_verified_and_validated",
    "resume_intent", "resume_result", "execution_observation", "termination_intent",
    "termination_result", "final_inspection", "complete", "evidence_failure",
    "recovery_inspection",
)
#: The lifecycle stage each kind makes durable (None: no stage).
KIND_STAGES: Mapping[str, Optional[str]] = {
    "prelaunch": "prelaunch", "job_configured": "job_configured",
    "process_created": "process_created",
    "job_verified_and_validated": "job_verified_and_validated",
    "resume_intent": "resume_intent", "resume_result": "resume_result",
    "execution_observation": None, "termination_intent": "timeout_or_termination",
    "termination_result": "timeout_or_termination", "final_inspection": "final_inspection",
    "complete": "complete", "evidence_failure": None, "recovery_inspection": None,
}
#: Which kind may follow which.  The first record is always "prelaunch".
_AFTER_ANY_RUN = {"evidence_failure", "recovery_inspection"}
ALLOWED_NEXT: Mapping[str, frozenset[str]] = {
    "prelaunch": frozenset({"job_configured", "final_inspection"} | _AFTER_ANY_RUN),
    "job_configured": frozenset({"process_created", "final_inspection"} | _AFTER_ANY_RUN),
    "process_created": frozenset({"job_verified_and_validated", "termination_intent",
                                  "final_inspection"} | _AFTER_ANY_RUN),
    "job_verified_and_validated": frozenset({"resume_intent", "termination_intent",
                                             "final_inspection"} | _AFTER_ANY_RUN),
    "resume_intent": frozenset({"resume_result"} | _AFTER_ANY_RUN),
    "resume_result": frozenset({"execution_observation", "termination_intent",
                                "final_inspection"} | _AFTER_ANY_RUN),
    "execution_observation": frozenset({"execution_observation", "termination_intent",
                                        "final_inspection"} | _AFTER_ANY_RUN),
    "termination_intent": frozenset({"termination_result"} | _AFTER_ANY_RUN),
    "termination_result": frozenset({"final_inspection"} | _AFTER_ANY_RUN),
    "final_inspection": frozenset({"complete"} | _AFTER_ANY_RUN),
    "complete": frozenset(),
    "evidence_failure": frozenset({"recovery_inspection"}),
    "recovery_inspection": frozenset({"recovery_inspection"}),
}

#: Envelope fields that never change within one chain.
CONSTANT_FIELDS: tuple[str, ...] = (
    "run_id", "series_token_sha256", "expected_head", "object_format",
    "repository_manifest_sha256", "runtime_manifest_sha256", "parent",
)
ENVELOPE_FIELDS: tuple[str, ...] = CONSTANT_FIELDS + (
    "utc", "monotonic_ms", "context_sha256", "job", "process", "lifecycle", "integrity",
)
RECORD_FIELDS: frozenset[str] = frozenset(
    ("schema", "kind", "sequence", "previous_record_sha256", "body") + ENVELOPE_FIELDS)
LIFECYCLE_KEYS: frozenset[str] = frozenset(P.LifecycleState().as_dict())

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_NAME_RE = re.compile(r"(\d{3})-([a-z_]+)\.json")


class EvidenceError(P.PreflightError):
    """An evidence record or chain is invalid (nothing was written)."""


class EvidenceDisabled(EvidenceError):
    """Real evidence writes are not available."""


class EvidenceFailed(EvidenceError):
    """A durable write failed; the writer is in the evidence-failure state."""


def require_real_writes() -> None:
    """Always refuses: slice E1 has no real file-system adapter."""
    if not EVIDENCE_WRITES_ENABLED:
        raise EvidenceDisabled("real evidence writes are not enabled "
                               "(EVIDENCE_WRITES_ENABLED is False)")
    raise EvidenceDisabled("no real file-system adapter exists in this slice")


def record_name(sequence: Any, kind: Any) -> str:
    """The immutable file name of one record, e.g. '004-resume_intent.json'."""
    if isinstance(sequence, bool) or not isinstance(sequence, int) \
            or not 0 <= sequence <= MAX_SEQUENCE:
        raise EvidenceError(f"invalid sequence {sequence!r}")
    if kind not in RECORD_KINDS:
        raise EvidenceError(f"unknown record kind {kind!r}")
    return f"{sequence:03d}-{kind}.json"


def record_digest(record: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical record bytes (identifies, never authenticates)."""
    return hashlib.sha256(P.canonical_json(record)).hexdigest()


def _identity(value: Any) -> Optional[tuple[int, str]]:
    if not isinstance(value, Mapping) or set(value) != {"pid", "creation_time"}:
        return None
    pid, creation = value["pid"], value["creation_time"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 \
            or P._parse_utc(creation) is None:
        return None
    return pid, creation


def record_contract(record: Any) -> Optional[str]:
    """STRICT or LEGACY for a supported (schema, writer_version) pair, else
    None (unsupported - never guessed)."""
    if not isinstance(record, Mapping):
        return None
    schema, integrity = record.get("schema"), record.get("integrity")
    version = integrity.get("writer_version") if isinstance(integrity, Mapping) else None
    if not isinstance(schema, str) or not isinstance(version, str):
        return None
    return RECORD_CONTRACTS.get((schema, version))


def record_problems(record: Any) -> list[str]:
    """Why one record is not well-formed (its own content only), under the
    contract its (schema, writer_version) pair selects."""
    if not isinstance(record, Mapping):
        return ["the record is not an object"]
    problems = []
    missing = sorted(RECORD_FIELDS - set(record))
    extra = sorted(set(record) - RECORD_FIELDS)
    if missing:
        problems.append("missing fields: " + ", ".join(missing))
    if extra:
        problems.append("unexpected fields: " + ", ".join(extra))
    if missing:
        return problems
    try:
        P.canonical_json(record)
    except P.PreflightError as exc:
        problems.append(f"not canonical: {exc}")
    contract = record_contract(record)
    if contract is None:
        problems.append("unsupported schema/version combination")
    kind = record["kind"]
    if kind not in RECORD_KINDS:
        problems.append(f"unknown kind {kind!r}")
    sequence = record["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) \
            or not 0 <= sequence <= MAX_SEQUENCE:
        problems.append("invalid sequence")
    previous = record["previous_record_sha256"]
    if sequence == 0 and previous is not None:
        problems.append("the first record has a previous digest")
    if sequence != 0 and (not isinstance(previous, str) or not _HEX64.fullmatch(previous)):
        problems.append("previous_record_sha256 is malformed")
    if not isinstance(record["run_id"], str) or not P._RUN_ID_RE.fullmatch(record["run_id"]):
        problems.append("run_id is not an approved form")
    if P._parse_utc(record["utc"]) is None:
        problems.append("utc is malformed")
    monotonic = record["monotonic_ms"]
    if isinstance(monotonic, bool) or not isinstance(monotonic, int) or monotonic < 0:
        problems.append("monotonic_ms is malformed")
    for name in ("series_token_sha256", "repository_manifest_sha256",
                 "runtime_manifest_sha256"):
        if not isinstance(record[name], str) or not _HEX64.fullmatch(record[name]):
            problems.append(f"{name} is not a SHA-256")
    if record["context_sha256"] is not None and (
            not isinstance(record["context_sha256"], str)
            or not _HEX64.fullmatch(record["context_sha256"])):
        problems.append("context_sha256 is malformed")
    object_format = record["object_format"]
    length = {"sha1": 40, "sha256": 64}.get(object_format)
    if length is None:
        problems.append("unknown object format")
    elif not isinstance(record["expected_head"], str) or not re.fullmatch(
            rf"[0-9a-f]{{{length}}}", record["expected_head"]):
        problems.append(f"expected_head is not a {object_format} commit id")
    if _identity(record["parent"]) is None:
        problems.append("parent identity is malformed")
    if record["process"] is not None and _identity(record["process"]) is None:
        problems.append("process identity is malformed")
    job = record["job"]
    job_ok = isinstance(job, Mapping) and set(job) == {"job_id", "limits_verified", "assignment"}
    if not job_ok or (job["job_id"] is not None and (not isinstance(job["job_id"], str)
                                                     or not _HEX32.fullmatch(job["job_id"]))) \
            or not isinstance(job["limits_verified"], bool) \
            or not isinstance(job["assignment"], str) \
            or job["assignment"] not in P.JOB_ASSIGNMENTS:
        problems.append("job identity is malformed")
    elif contract == STRICT:
        problems.extend(_strict_job_problems(record))
    lifecycle = record["lifecycle"]
    if not isinstance(lifecycle, Mapping) or set(lifecycle) != LIFECYCLE_KEYS \
            or lifecycle.get("execution_history") not in (None,) + P.EXECUTION_HISTORIES \
            or lifecycle.get("liveness") not in (None,) + P.LIVENESS_STATES:
        problems.append("lifecycle is malformed")
    integrity = record["integrity"]
    if not isinstance(integrity, Mapping) or (
            contract == STRICT and set(integrity) != {"writer_version"}):
        problems.append("integrity block is malformed")
    body = record["body"]
    if not isinstance(body, Mapping):
        problems.append("body is not an object")
        return problems
    problems.extend(_body_problems(kind, record, body))
    if contract == STRICT:
        problems.extend(_strict_body_problems(kind, record, body))
    return problems


def _strict_job_problems(record: Mapping[str, Any]) -> list[str]:
    """Strict job block: no assignment before a process exists, assignment
    AT creation (into a verified job) once it does; nothing else."""
    job = record["job"]
    assignment = job["assignment"]
    if assignment == "assigned_before_resume":
        return ["assignment after creation (assigned_before_resume) is refused"]
    if assignment not in STRICT_ASSIGNMENTS:
        return [f"job assignment {assignment!r} is not accepted in a strict record"]
    if record["process"] is not None:
        if assignment != P.ACCEPTED_JOB_ASSIGNMENT:
            return ["a record naming a process needs job assignment assigned_at_creation"]
        if job["limits_verified"] is not True or job["job_id"] is None:
            return ["a record naming a process needs a verified job identity"]
    elif assignment != "not_created":
        return ["a job assignment without a process is contradictory"]
    return []


def _strict_body_problems(kind: str, record: Mapping[str, Any],
                          body: Mapping[str, Any]) -> list[str]:
    """Strict content of the job stages: nothing is defaulted, inferred from
    a stage name, or taken from a plan instead of an observed result."""
    if kind == "job_configured":
        if set(body) != JOB_CONFIGURATION_FIELDS:
            return ["job_configured needs exactly the configuration read-back fields "
                    "(" + ", ".join(sorted(JOB_CONFIGURATION_FIELDS)) + ")"]
        if not isinstance(body["job_handle_inheritable"], bool):
            return ["job_configured needs the observed handle inheritance (true or false)"]
        job = record["job"]
        problems = ["job_configured: " + p for p in P.job_configuration_problems(body)]
        if job["limits_verified"] is not True or job["job_id"] is None:
            problems.append("job_configured needs a verified job identity")
        return problems
    if kind == "process_created":
        if set(body) != PROCESS_CREATED_FIELDS:
            return ["process_created needs exactly " + ", ".join(sorted(PROCESS_CREATED_FIELDS))
                    + " (a plan is not proof that CreateProcessW applied it)"]
        problems = []
        if body["create_process_ok"] is not True:
            problems.append("process_created needs a successful CreateProcessW result")
        applied = body["applied_attributes"]
        if not isinstance(applied, list) or any(
                isinstance(a, bool) or not isinstance(a, int) for a in applied):
            problems.append("applied_attributes is malformed")
        elif len(applied) != len(set(applied)):
            problems.append("applied_attributes has duplicates")
        elif set(applied) != set(CREATION_ATTRIBUTES):
            problems.append("applied_attributes are not exactly SECURITY_CAPABILITIES, "
                            "HANDLE_LIST and JOB_LIST: "
                            + ", ".join(f"{a:#x}" for a in applied))
        return problems
    if kind == "job_verified_and_validated":
        if set(body) != JOB_VERIFIED_FIELDS:
            return ["job_verified_and_validated needs exactly membership, token_ok and "
                    "image_ok"]
        identity = _identity(record["process"]) if record["process"] is not None else None
        if identity is None:
            return ["job_verified_and_validated needs the recorded process identity"]
        problems = []
        membership = body["membership"]
        if not isinstance(membership, Mapping) \
                or set(membership) != set(P.JOB_MEMBERSHIP_FIELDS):
            problems.append("membership must carry exactly "
                            + ", ".join(P.JOB_MEMBERSHIP_FIELDS))
        else:
            problems.extend("membership: " + p for p in P.job_membership_problems(
                membership, expected_pid=identity[0], expected_creation_time=identity[1]))
        if body["token_ok"] is not True or body["image_ok"] is not True:
            problems.append("token and image validation must both be explicitly true")
        return problems
    return []


def _body_problems(kind: str, record: Mapping[str, Any], body: Mapping[str, Any]) -> list[str]:
    problems = []
    if kind == "process_created":
        identity = _identity({k: body.get(k) for k in ("pid", "creation_time")})
        if identity is None or record["process"] is None \
                or _identity(record["process"]) != identity:
            problems.append("process_created must name the process in body and envelope")
    elif kind == "resume_result":
        if body.get("execution_history") not in P.EXECUTION_HISTORIES:
            problems.append("resume_result needs an execution history")
    elif kind == "termination_result":
        if not all(isinstance(body.get(k), bool) for k in ("verified", "api_ok", "signaled")) \
                or body.get("cause") not in P.TERMINATION_EXIT_CODES:
            problems.append("termination_result body is malformed")
        elif body["verified"] and not (body["api_ok"] and body["signaled"]
                                       and body.get("exit_code")
                                       == P.TERMINATION_EXIT_CODES[body["cause"]]):
            problems.append("termination_result claims verification without exit proof")
    elif kind == "final_inspection":
        if body.get("liveness") not in P.LIVENESS_STATES:
            problems.append("final_inspection needs a liveness")
    elif kind == "evidence_failure":
        if not isinstance(body.get("operation"), str) or body.get("failed_kind") \
                not in RECORD_KINDS:
            problems.append("evidence_failure body is malformed")
    elif kind == "complete":
        if body.get("ownership") not in ("released", "retained") \
                or not isinstance(body.get("chain"), list):
            problems.append("complete body is malformed")
        elif body["ownership"] == "released" and record["process"] is not None \
                and record["lifecycle"].get("liveness") != P.CONFIRMED_EXITED:
            problems.append("ownership released without a confirmed exit")
    return problems


def build_record(kind: str, envelope: Mapping[str, Any], body: Mapping[str, Any], *,
                 sequence: int, previous_record_sha256: Optional[str],
                 contract: str = STRICT) -> dict[str, Any]:
    """One validated record (pure), under the named contract; an envelope
    whose writer_version belongs to another contract makes an unsupported
    (schema, writer_version) pair and is refused."""
    schemas = {c: schema for (schema, _), c in RECORD_CONTRACTS.items()}
    if contract not in schemas:
        raise EvidenceError(f"unknown record contract {contract!r}")
    if not isinstance(envelope, Mapping) or set(envelope) != set(ENVELOPE_FIELDS):
        missing = sorted(set(ENVELOPE_FIELDS) - set(envelope or {}))
        extra = sorted(set(envelope or {}) - set(ENVELOPE_FIELDS))
        raise EvidenceError(f"malformed envelope (missing {missing}, unexpected {extra})")
    record = {"schema": schemas[contract], "kind": kind, "sequence": sequence,
              "previous_record_sha256": previous_record_sha256, "body": dict(body),
              **{k: envelope[k] for k in ENVELOPE_FIELDS}}
    problems = record_problems(record)
    if problems:
        raise EvidenceError("invalid record: " + "; ".join(problems))
    return record


@dataclass
class ChainState:
    """The verified prefix of a chain."""
    ok: bool
    problems: list[str]
    count: int
    last_verified_sequence: Optional[int]
    tip_digest: Optional[str]
    kinds: list[str]
    durable_stages: list[str]
    process: Optional[tuple[int, str]]
    complete: bool
    evidence_failure: bool
    resume_result_history: Optional[str]
    termination_verified: bool
    contract: Optional[str] = None      # of every verified record (one per chain)


def verify_chain(records: Sequence[Any], *, expected_run_id: Optional[str] = None,
                 expected_head: Optional[str] = None,
                 expected_token_sha256: Optional[str] = None) -> ChainState:
    """
    Verify an ordered list of parsed records.  Verification stops at the
    first problem; the state describes the verified prefix only.  Every
    record must share the first record's contract (no mixing); in a strict
    chain resume_intent must directly follow a valid
    job_verified_and_validated record.
    """
    problems: list[str] = []
    verified: list[Mapping[str, Any]] = []
    digests: list[str] = []
    first: Optional[Mapping[str, Any]] = None
    process: Optional[tuple[int, str]] = None
    context = job_id = None
    contract: Optional[str] = None
    for index, record in enumerate(records):
        own = record_problems(record)
        if own:
            problems.append(f"record {index}: " + "; ".join(own))
            break
        if contract is None:
            contract = record_contract(record)
        elif record_contract(record) != contract:
            problems.append(f"record {index}: its schema/version differs from the chain's "
                            f"{contract} contract")
            break
        if record["sequence"] != index:
            problems.append(f"record {index}: sequence {record['sequence']} (missing, "
                            "duplicate or reordered records)")
            break
        if index == 0:
            if record["kind"] != "prelaunch":
                problems.append("the chain does not start with prelaunch")
                break
            first = record
            for label, wanted, actual in (
                    ("run_id", expected_run_id, record["run_id"]),
                    ("HEAD", expected_head, record["expected_head"]),
                    ("owner digest", expected_token_sha256, record["series_token_sha256"])):
                if wanted is not None and actual != wanted:
                    problems.append(f"unexpected {label}")
            if problems:
                break
        else:
            if record["previous_record_sha256"] != digests[-1]:
                problems.append(f"record {index}: broken previous digest")
                break
            if record["kind"] not in ALLOWED_NEXT[verified[-1]["kind"]]:
                problems.append(f"record {index}: {record['kind']} may not follow "
                                f"{verified[-1]['kind']}")
                break
            changed = [f for f in CONSTANT_FIELDS if record[f] != first[f]]
            if changed:
                label = ("owner digest" if "series_token_sha256" in changed
                         else ", ".join(changed))
                problems.append(f"record {index}: inconsistent {label}")
                break
        if contract == STRICT and record["kind"] == "resume_intent" and (
                not verified or verified[-1]["kind"] != "job_verified_and_validated"):
            problems.append(f"record {index}: resume_intent without a validated job "
                            "membership record")
            break
        identity = _identity(record["process"]) if record["process"] is not None else None
        if process is None and identity is not None and record["kind"] != "process_created":
            problems.append(f"record {index}: process identity before process_created")
            break
        if process is not None and identity != process:
            problems.append(f"record {index}: inconsistent process identity")
            break
        if record["kind"] == "process_created":
            if process is not None:
                problems.append(f"record {index}: a second process_created")
                break
            process = identity
        if record["context_sha256"] is not None:
            if context is not None and record["context_sha256"] != context:
                problems.append(f"record {index}: inconsistent context digest")
                break
            context = record["context_sha256"]
        elif context is not None:
            problems.append(f"record {index}: context digest disappeared")
            break
        if record["job"]["job_id"] is not None:
            if job_id is not None and record["job"]["job_id"] != job_id:
                problems.append(f"record {index}: inconsistent job identity")
                break
            job_id = record["job"]["job_id"]
        elif job_id is not None:
            problems.append(f"record {index}: job identity disappeared")
            break
        if record["kind"] == "complete":
            expected_chain = [{"sequence": r["sequence"], "kind": r["kind"], "sha256": d}
                              for r, d in zip(verified, digests)]
            if record["body"]["chain"] != expected_chain:
                problems.append(f"record {index}: malformed final chain")
                break
        verified.append(record)
        digests.append(record_digest(record))
    stages: list[str] = []
    for record in verified:
        stage = KIND_STAGES[record["kind"]]
        if stage is not None and stage not in stages:
            stages.append(stage)
    results = [r for r in verified if r["kind"] == "resume_result"]
    terminations = [r for r in verified if r["kind"] == "termination_result"]
    return ChainState(
        ok=not problems, problems=problems, count=len(verified),
        last_verified_sequence=len(verified) - 1 if verified else None,
        tip_digest=digests[-1] if digests else None,
        kinds=[r["kind"] for r in verified], durable_stages=stages, process=process,
        complete=any(r["kind"] == "complete" for r in verified),
        evidence_failure=any(r["kind"] == "evidence_failure" for r in verified),
        resume_result_history=results[-1]["body"]["execution_history"] if results else None,
        termination_verified=bool(terminations and terminations[-1]["body"]["verified"]),
        contract=contract if verified else None)


# ---------------------------------------------------------------------------
# Writer over an injected FsOps
# ---------------------------------------------------------------------------

class FsOps:
    """
    The interface a file-system adapter must provide.  Slice E1 has no real
    implementation; tests inject an in-memory fake.
        dir_identity(path) -> {"exists", "reparse", "final_path", "volume_serial"}
        open_exclusive(path) -> handle   (FileExistsError when it exists)
        write(handle, data) -> int       (bytes written)
        flush(handle) -> None            (FlushFileBuffers)
        close(handle) -> None
        read_all(path) -> bytes
        file_identity(path) -> {"links", "reparse", "volume_serial", "file_index", "size"}
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise EvidenceDisabled("FsOps is an interface; no real adapter exists")


@dataclass
class EvidenceState:
    evidence_failed: bool = False
    last_verified_sequence: Optional[int] = None
    last_verified_digest: Optional[str] = None
    failed_operation: Optional[str] = None
    failed_name: Optional[str] = None
    partial_record_possible: bool = False
    ownership_retained: bool = True
    containment_required: str = "none"
    failure_record_attempted: bool = False
    errors: list[str] = field(default_factory=list)


class EvidenceWriter:
    """
    Writes immutable, chained records into one run directory through the
    injected FsOps only.  Each write: validate, check the directory
    identity, exclusive create, complete write, flush, checked close,
    re-read, byte count and SHA-256, file identity - and only then advance
    the chain.  A failed name stays consumed; nothing is overwritten,
    renamed or retried.
    """

    def __init__(self, run_dir: str, fs: Any, *, expected_dir: Mapping[str, Any],
                 run_id: str, expected_head: str, token_sha256: str) -> None:
        if fs is None:
            require_real_writes()
        if not isinstance(run_dir, str) or not run_dir or not isinstance(expected_dir, Mapping):
            raise EvidenceError("a run directory and its expected identity are required")
        self.run_dir, self.fs, self.expected_dir = run_dir.rstrip("\\"), fs, dict(expected_dir)
        self.expected = {"run_id": run_id, "head": expected_head, "token": token_sha256}
        self.records: list[dict[str, Any]] = []
        self.next_sequence = 0
        self.state = EvidenceState()

    def _durable_stages(self) -> list[str]:
        return verify_chain(self.records).durable_stages

    def stage_permissions(self) -> dict[str, Any]:
        """P.next_stage_allowed over the verified records and failure state.
        Launch and resume are only ever permitted over a fully verified
        strict chain."""
        chain = verify_chain(self.records)
        permissions = P.next_stage_allowed(chain.durable_stages, self.state.evidence_failed)
        if not chain.ok or (self.records and chain.contract != STRICT):
            permissions = {**permissions, "may_launch": False, "may_resume": False}
        return permissions

    @property
    def may_resume(self) -> bool:
        return self.stage_permissions()["may_resume"]

    @property
    def may_launch(self) -> bool:
        return self.stage_permissions()["may_launch"]

    def _check_directory(self) -> None:
        try:
            identity = self.fs.dir_identity(self.run_dir)
        except OSError as exc:
            raise _WriteFailure(f"directory_identity:{type(exc).__name__}", False) from None
        if not isinstance(identity, Mapping) or identity.get("exists") is not True:
            raise _WriteFailure("directory_missing", False)
        if identity.get("reparse") is not False:
            raise _WriteFailure("directory_reparse_point", False)
        final = identity.get("final_path")
        if not isinstance(final, str) or final.casefold() != str(
                self.expected_dir.get("final_path", "")).casefold():
            raise _WriteFailure("directory_path_mismatch", False)
        if identity.get("volume_serial") != self.expected_dir.get("volume_serial"):
            raise _WriteFailure("directory_volume_mismatch", False)

    def write(self, kind: str, envelope: Mapping[str, Any], body: Mapping[str, Any]) -> str:
        """Write the next record; returns its digest.  Raises EvidenceError
        (nothing written, nothing consumed) for an invalid record, and
        EvidenceFailed (the name consumed) for a failed durable write."""
        if self.state.evidence_failed:
            raise EvidenceFailed("the writer is in the evidence-failure state; no further "
                                 "records except one failure record")
        return self._write(kind, envelope, body)

    def write_failure_record(self, envelope: Mapping[str, Any]) -> Optional[str]:
        """One best-effort evidence_failure record after a failure."""
        if not self.state.evidence_failed or self.state.failure_record_attempted:
            raise EvidenceError("a failure record is written once, after a failure")
        self.state.failure_record_attempted = True
        failed_kind = (self.state.failed_name or "000-prelaunch.json").split("-", 1)[1][:-5]
        body = {"operation": self.state.failed_operation, "failed_kind": failed_kind,
                "failed_name": self.state.failed_name,
                "containment_required": self.state.containment_required}
        try:
            return self._write("evidence_failure", envelope, body, after_failure=True)
        except EvidenceFailed:
            return None

    def _write(self, kind: str, envelope: Mapping[str, Any], body: Mapping[str, Any], *,
               after_failure: bool = False) -> str:
        previous = self.records[-1] if self.records else None
        record = build_record(kind, envelope, body, sequence=self.next_sequence,
                              previous_record_sha256=record_digest(previous) if previous else None,
                              contract=STRICT)
        if after_failure:
            chain = verify_chain(self.records, expected_run_id=self.expected["run_id"],
                                 expected_head=self.expected["head"],
                                 expected_token_sha256=self.expected["token"])
        else:
            chain = verify_chain(self.records + [record], expected_run_id=self.expected["run_id"],
                                 expected_head=self.expected["head"],
                                 expected_token_sha256=self.expected["token"])
        if not chain.ok:
            raise EvidenceError("the record would break the chain: " + "; ".join(chain.problems))
        name = record_name(self.next_sequence, kind)
        path = f"{self.run_dir}\\{name}"
        data = P.canonical_json(record)
        digest = hashlib.sha256(data).hexdigest()
        handle = None
        try:
            self._check_directory()
            try:
                handle = self.fs.open_exclusive(path)
            except FileExistsError:
                raise _WriteFailure("create_duplicate", False) from None
            except OSError as exc:
                if getattr(exc, "created_file", False):      # created, then refused
                    self.next_sequence += 1
                    raise _WriteFailure(f"create_unusable:{type(exc).__name__}", True) from None
                raise _WriteFailure(f"create:{type(exc).__name__}", False) from None
            self.next_sequence += 1                       # the name is consumed from here
            written = 0
            while written < len(data):
                try:
                    count = self.fs.write(handle, data[written:])
                except OSError as exc:
                    raise _WriteFailure(f"write:{type(exc).__name__}", True) from None
                if isinstance(count, bool) or not isinstance(count, int) or count <= 0 \
                        or count > len(data) - written:
                    raise _WriteFailure("write_short", True)
                written += count
            try:
                self.fs.flush(handle)
            except OSError as exc:
                raise _WriteFailure(f"flush:{type(exc).__name__}", True) from None
            try:
                closing, handle = handle, None
                self.fs.close(closing)
            except OSError as exc:
                raise _WriteFailure(f"close:{type(exc).__name__}", True) from None
            try:
                back = self.fs.read_all(path)
            except OSError as exc:
                raise _WriteFailure(f"readback:{type(exc).__name__}", True) from None
            if not isinstance(back, (bytes, bytearray)) or len(back) != len(data) \
                    or hashlib.sha256(bytes(back)).hexdigest() != digest:
                raise _WriteFailure("readback_mismatch", True)
            try:
                identity = self.fs.file_identity(path)
            except OSError as exc:
                raise _WriteFailure(f"file_identity:{type(exc).__name__}", True) from None
            if not isinstance(identity, Mapping) or identity.get("links") != 1 \
                    or identity.get("reparse") is not False \
                    or identity.get("volume_serial") != self.expected_dir.get("volume_serial") \
                    or identity.get("size") != len(data):
                raise _WriteFailure("file_identity", True)
        except _WriteFailure as failure:
            self._fail(failure.operation, name, failure.partial, handle)
            raise EvidenceFailed(f"{name}: {failure.operation}") from None
        except BaseException:
            self._fail("interrupted", name, True, handle)
            raise
        self.records.append(record)
        self.state.last_verified_sequence = record["sequence"]
        self.state.last_verified_digest = digest
        if kind == "complete" and body.get("ownership") == "released":
            self.state.ownership_retained = False
        return digest

    def _fail(self, operation: str, name: str, partial: bool, handle: Any) -> None:
        if handle is not None:
            try:
                self.fs.close(handle)
            except Exception as exc:  # recorded; the failure stands
                self.state.errors.append(f"close after failure: {type(exc).__name__}")
        if self.state.evidence_failed:                    # the failure record itself failed
            self.state.errors.append(f"failure record {name}: {operation}")
            return
        self.state.evidence_failed = True
        self.state.failed_operation, self.state.failed_name = operation, name
        self.state.partial_record_possible = partial
        self.state.ownership_retained = True
        self.state.containment_required = P.next_stage_allowed(
            self._durable_stages(), True)["containment"]
        self.state.errors.append(f"{name}: {operation}")

    def complete_body(self, ownership: str) -> dict[str, Any]:
        """The body of the complete record: the full chain listing."""
        return {"ownership": ownership,
                "chain": [{"sequence": r["sequence"], "kind": r["kind"],
                           "sha256": record_digest(r)} for r in self.records]}


class _WriteFailure(Exception):
    def __init__(self, operation: str, partial: bool) -> None:
        super().__init__(operation)
        self.operation, self.partial = operation, partial


# ---------------------------------------------------------------------------
# WindowsFsOps (slice E2): kernel32 through ctypes, gated, lazily loaded
# ---------------------------------------------------------------------------

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_READ_ATTRIBUTES = 0x00000080
FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 0x1, 0x2, 0x4
CREATE_NEW, OPEN_EXISTING = 1, 3
FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL = 0x10, 0x80
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
HANDLE_FLAG_INHERIT = 0x1
#: GetFinalPathNameByHandleW flags: FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
FINAL_PATH_FLAGS = 0x0
FINAL_PATH_CAPACITY = 32768
MAX_RECORD_BYTES = 1 << 20
_ERROR_EXCEPTIONS: Mapping[int, tuple[type, int]] = {
    2: (FileNotFoundError, 2), 3: (FileNotFoundError, 2),                 # not found
    5: (PermissionError, 13), 32: (PermissionError, 13),                  # denied / sharing
    80: (FileExistsError, 17), 183: (FileExistsError, 17),                # exists
    39: (OSError, 28), 112: (OSError, 28),                                # disk full
}
_INVALID_HANDLES = frozenset({0, -1, (1 << 32) - 1, (1 << 64) - 1})


def _valid_handle(handle: Any) -> bool:
    return isinstance(handle, int) and not isinstance(handle, bool) \
        and handle not in _INVALID_HANDLES


def windows_error(api: str, code: Any) -> OSError:
    """The OSError subclass for a Windows error code (errno mapped; the
    Windows code kept in the message and in .windows_code)."""
    cls, number = _ERROR_EXCEPTIONS.get(code, (OSError, 5)) if isinstance(code, int) \
        else (OSError, 5)
    error = cls(number, f"{api} failed (Windows error {code})")
    error.windows_code = code
    return error


_FS_TYPES: Any = None


def _fs_types() -> Any:
    """ctypes structures of the documented file types (built on first use)."""
    global _FS_TYPES
    if _FS_TYPES is None:
        import ctypes
        import types
        from ctypes import wintypes as w

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", w.DWORD), ("dwHighDateTime", w.DWORD)]

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [("dwFileAttributes", w.DWORD), ("ftCreationTime", FILETIME),
                        ("ftLastAccessTime", FILETIME), ("ftLastWriteTime", FILETIME),
                        ("dwVolumeSerialNumber", w.DWORD), ("nFileSizeHigh", w.DWORD),
                        ("nFileSizeLow", w.DWORD), ("nNumberOfLinks", w.DWORD),
                        ("nFileIndexHigh", w.DWORD), ("nFileIndexLow", w.DWORD)]

        _FS_TYPES = types.SimpleNamespace(ctypes=ctypes, w=w, FILETIME=FILETIME,
                                          INFO=BY_HANDLE_FILE_INFORMATION)
    return _FS_TYPES


def _fs_signatures(t: Any) -> dict[str, tuple[Any, list[Any]]]:
    """name -> (restype, argtypes); all in kernel32."""
    c, w = t.ctypes, t.w
    return {
        "CreateFileW": (w.HANDLE, [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD,
                                   w.HANDLE]),
        "WriteFile": (w.BOOL, [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]),
        "ReadFile": (w.BOOL, [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]),
        "FlushFileBuffers": (w.BOOL, [w.HANDLE]),
        "CloseHandle": (w.BOOL, [w.HANDLE]),
        "GetFileInformationByHandle": (w.BOOL, [w.HANDLE, c.POINTER(t.INFO)]),
        "GetFinalPathNameByHandleW": (w.DWORD, [w.HANDLE, c.c_void_p, w.DWORD, w.DWORD]),
        "GetHandleInformation": (w.BOOL, [w.HANDLE, c.POINTER(w.DWORD)]),
    }


def _kernel32_loader(name: str) -> Any:
    import ctypes
    return ctypes.WinDLL(name, use_last_error=True)


#: The harness whose sealed authorizations gate the adapter.  It is only
#: ever LOOKED UP in sys.modules - never imported, initialized or repaired
#: here (importing it has side effects, e.g. the stdlib %TEMP% probe).
HARNESS_MODULE = "calibrate_generator"
HARNESS_FILE = HERE / "calibrate_generator.py"


def _harness_module() -> Any:
    """The already fully initialized harness module, or a refusal.
    Presence alone authorizes nothing: it only supplies the validator."""
    module = sys.modules.get(HARNESS_MODULE)
    if module is None:
        raise EvidenceDisabled(f"the harness module {HARNESS_MODULE} is not loaded; the "
                               "evidence adapter never imports it")
    spec = getattr(module, "__spec__", None)
    if spec is None or getattr(spec, "_initializing", False) is not False:
        raise EvidenceDisabled("the harness module is missing or partially initialized")
    if getattr(module, "__name__", None) != HARNESS_MODULE:
        raise EvidenceDisabled("the harness module has an unexpected name")
    location = getattr(module, "__file__", None)
    same_file = isinstance(location, str) and bool(location) and (
        str(PureWindowsPath(location)).casefold()
        == str(PureWindowsPath(HARNESS_FILE)).casefold())       # string comparison only
    if not same_file:
        raise EvidenceDisabled("the harness module is not the expected file (replaced)")
    validator = getattr(module, "_require_any_authorization", None)
    error = getattr(module, "CalibrationError", None)
    if not callable(validator) or getattr(validator, "__globals__", None) is not \
            getattr(module, "__dict__", None):
        raise EvidenceDisabled("the harness validator is missing or not the module's own")
    if not (isinstance(error, type) and issubclass(error, Exception)):
        raise EvidenceDisabled("the harness error type is missing or malformed")
    return module


def _require_evidence_authorization(authorization: Any) -> Any:
    """Both gates: the evidence-write flag and a sealed harness
    authorization (calibration or probe), validated by the already loaded
    harness's own validator."""
    if not EVIDENCE_WRITES_ENABLED:
        raise EvidenceDisabled("real evidence writes are not enabled "
                               "(EVIDENCE_WRITES_ENABLED is False)")
    harness = _harness_module()
    try:
        return harness._require_any_authorization(authorization)
    except harness.CalibrationError as exc:
        raise EvidenceDisabled(f"no valid authorization for evidence writes: {exc}") from None


def normalize_final_path(text: Any) -> str:
    """A GetFinalPathNameByHandleW result without its \\\\?\\ prefix; anything
    unexpected is malformed."""
    if not isinstance(text, str) or "\x00" in text:
        raise windows_error("GetFinalPathNameByHandleW", "malformed path")
    if text.startswith("\\\\?\\UNC\\"):
        return "\\\\" + text[len("\\\\?\\UNC\\"):]
    if text.startswith("\\\\?\\") and re.fullmatch(r"[A-Za-z]:\\.*", text[4:]):
        return text[4:]
    raise windows_error("GetFinalPathNameByHandleW", "unexpected path form")


class WindowsFsOps:
    """
    The FsOps of a real Windows file system.  Constructed only with
    EVIDENCE_WRITES_ENABLED and a sealed harness authorization; every
    native call re-checks both.  Handles are non-inheritable (NULL security
    attributes; verified with GetHandleInformation); records are created
    with CREATE_NEW and FILE_FLAG_WRITE_THROUGH and opened for checks with
    FILE_FLAG_OPEN_REPARSE_POINT, so a reparse point is reported, never
    followed.  No directory is ever created.
    """

    def __init__(self, authorization: Any, *, loader: Any = None, last_error: Any = None) -> None:
        self.authorization = _require_evidence_authorization(authorization)
        self._loader = loader or _kernel32_loader
        self._kernel32: Any = None
        self._last_error = last_error

    @property
    def loaded(self) -> bool:
        return self._kernel32 is not None

    def _api(self, name: str) -> Any:
        _require_evidence_authorization(self.authorization)
        restype, argtypes = _fs_signatures(_fs_types())[name]
        if self._kernel32 is None:
            self._kernel32 = self._loader("kernel32")
        function = getattr(self._kernel32, name)
        function.restype, function.argtypes = restype, argtypes
        return function

    def _error(self, api: str) -> OSError:
        return windows_error(api, (self._last_error or _fs_types().ctypes.get_last_error)())

    def _open(self, path: str, access: int, share: int, disposition: int, flags: int,
              api_label: str) -> int:
        if not isinstance(path, str) or not path or "\x00" in path:
            raise windows_error(api_label, "invalid path")
        handle = self._api("CreateFileW")(path, access, share, None, disposition, flags, None)
        if not _valid_handle(handle):
            raise self._error(api_label)
        return int(handle)

    def _info(self, handle: int) -> Any:
        t = _fs_types()
        info = t.INFO()
        if not self._api("GetFileInformationByHandle")(handle, t.ctypes.byref(info)):
            raise self._error("GetFileInformationByHandle")
        return info

    def _final_path(self, handle: int) -> str:
        c = _fs_types().ctypes
        buffer = c.create_unicode_buffer(FINAL_PATH_CAPACITY)
        length = self._api("GetFinalPathNameByHandleW")(handle, c.addressof(buffer),
                                                        FINAL_PATH_CAPACITY, FINAL_PATH_FLAGS)
        if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
            raise self._error("GetFinalPathNameByHandleW")
        if length >= FINAL_PATH_CAPACITY or len(buffer.value) != length:
            raise windows_error("GetFinalPathNameByHandleW", "inconsistent length")
        return normalize_final_path(buffer.value)

    def _close_after(self, handle: int, errors: list[str]) -> None:
        try:
            self.close(handle)
        except OSError as exc:
            errors.append(str(exc))

    def dir_identity(self, path: str) -> dict[str, Any]:
        """Identity of the evidence directory, opened without following a
        reparse point.  A missing directory is reported, never created."""
        try:
            handle = self._open(path, FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                "CreateFileW(directory)")
        except FileNotFoundError:
            return {"exists": False, "reparse": None, "final_path": None,
                    "volume_serial": None}
        errors: list[str] = []
        try:
            info = self._info(handle)
            if not info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
                raise windows_error("GetFileInformationByHandle", "not a directory")
            result = {"exists": True,
                      "reparse": bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
                      "final_path": self._final_path(handle),
                      "volume_serial": int(info.dwVolumeSerialNumber)}
        finally:
            self._close_after(handle, errors)
        if errors:
            raise windows_error("CloseHandle", "directory handle: " + "; ".join(errors))
        return result

    def open_exclusive(self, path: str) -> int:
        """CREATE_NEW, write-through, no sharing, non-inheritable."""
        handle = self._open(path, GENERIC_WRITE, 0, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, "CreateFileW")
        t = _fs_types()
        flags = t.w.DWORD(0)
        try:
            if not self._api("GetHandleInformation")(handle, t.ctypes.byref(flags)):
                raise self._error("GetHandleInformation")
            if flags.value & HANDLE_FLAG_INHERIT:
                raise windows_error("GetHandleInformation", "the handle is inheritable")
        except OSError as exc:
            self._close_after(handle, [])
            exc.created_file = True                       # an empty file now exists
            raise
        except BaseException:
            self._close_after(handle, [])
            raise
        return handle

    def write(self, handle: int, data: bytes) -> int:
        t = _fs_types()
        c = t.ctypes
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_RECORD_BYTES:
            raise windows_error("WriteFile", "invalid data")
        buffer = c.create_string_buffer(bytes(data), len(data))
        written = t.w.DWORD(0)
        if not self._api("WriteFile")(handle, c.addressof(buffer), len(data),
                                      c.byref(written), None):
            raise self._error("WriteFile")
        return int(written.value)

    def flush(self, handle: int) -> None:
        if not self._api("FlushFileBuffers")(handle):
            raise self._error("FlushFileBuffers")

    def close(self, handle: int) -> None:
        if not self._api("CloseHandle")(handle):
            raise self._error("CloseHandle")

    def read_all(self, path: str) -> bytes:
        """The whole file through a fresh handle (no reparse following);
        its size must match exactly what can be read."""
        t = _fs_types()
        c = t.ctypes
        handle = self._open(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                            "CreateFileW(read)")
        errors: list[str] = []
        try:
            info = self._info(handle)
            size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
            if size > MAX_RECORD_BYTES:
                raise windows_error("ReadFile", f"record too large ({size} bytes)")
            buffer = c.create_string_buffer(size + 1)
            total = 0
            while True:
                count = t.w.DWORD(0)
                room = size + 1 - total
                if not self._api("ReadFile")(handle, c.addressof(buffer) + total, room,
                                             c.byref(count), None):
                    raise self._error("ReadFile")
                if count.value > room:
                    raise windows_error("ReadFile", "read more than requested")
                if count.value == 0:
                    break
                total += count.value
                if total > size:
                    raise windows_error("ReadFile", "the file grew while being read")
            if total != size:
                raise windows_error("ReadFile", f"short read ({total} of {size} bytes)")
            data = buffer.raw[:size]
        finally:
            self._close_after(handle, errors)
        if errors:
            raise windows_error("CloseHandle", "read handle: " + "; ".join(errors))
        return data

    def file_identity(self, path: str) -> dict[str, Any]:
        """Links, reparse flag, volume serial, file index and size of the
        record itself (not of a reparse target)."""
        handle = self._open(path, FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
                            "CreateFileW(identity)")
        errors: list[str] = []
        try:
            info = self._info(handle)
            if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
                raise windows_error("GetFileInformationByHandle", "the record is a directory")
            result = {"links": int(info.nNumberOfLinks),
                      "reparse": bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
                      "volume_serial": int(info.dwVolumeSerialNumber),
                      "file_index": (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
                      "size": (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)}
        finally:
            self._close_after(handle, errors)
        if errors:
            raise windows_error("CloseHandle", "identity handle: " + "; ".join(errors))
        return result


# ---------------------------------------------------------------------------
# Recovery classification (pure; no file system, no process lookup)
# ---------------------------------------------------------------------------

INSPECTION_RESULTS: tuple[str, ...] = ("ok", "not_found", "access_denied", "error")


def classify_recovery(chain: ChainState, inspection: Optional[Mapping[str, Any]]
                      ) -> dict[str, Any]:
    """
    Execution history and liveness of a crashed run from its verified chain
    and an OS inspection by the RECORDED identity.  Exit is classified only
    with PID and creation-time evidence; a missing record never establishes
    termination; recovery never releases ownership.
    """
    if not isinstance(chain, ChainState):
        raise EvidenceError("classify_recovery needs a ChainState")
    stages = set(chain.durable_stages)
    result: dict[str, Any] = {"execution_history": None, "liveness": None,
                              "exit_evidence": None, "exit_code": None,
                              "termination_established": False, "ownership": "retained",
                              "reason": ""}
    if "job_configured" not in stages:
        result.update(liveness="not_applicable", reason="no job was configured, so no "
                                                        "process could have been created")
        return result
    if chain.process is None:
        result.update(execution_history=P.STATE_UNKNOWN, liveness=P.STATE_UNKNOWN,
                      reason="a process may exist but its identity was never durably "
                             "recorded")
        return result
    if "resume_intent" not in stages:
        result["execution_history"] = P.NEVER_EXECUTED
    elif chain.resume_result_history is not None:
        result["execution_history"] = chain.resume_result_history
    else:
        result["execution_history"] = P.MAY_HAVE_EXECUTED
    result["termination_established"] = chain.termination_verified
    if not isinstance(inspection, Mapping):
        result.update(liveness=P.STATE_UNKNOWN, reason="no inspection")
        return result
    pid, creation = chain.process
    if inspection.get("pid") != pid:
        result.update(liveness=P.STATE_UNKNOWN, reason="the inspection is about another PID")
        return result
    status = inspection.get("result")
    if status == "not_found":
        result.update(liveness=P.CONFIRMED_EXITED, exit_evidence="absent_from_process_table",
                      reason="no process has the recorded PID")
    elif status == "ok" and inspection.get("creation_time") not in (None, creation):
        result.update(liveness=P.CONFIRMED_EXITED, exit_evidence="absent_from_process_table",
                      reason="the PID now belongs to another process (creation time differs)")
    elif status == "ok" and inspection.get("creation_time") == creation:
        signaled, code = inspection.get("signaled"), inspection.get("exit_code")
        if signaled is True and isinstance(code, int) and not isinstance(code, bool):
            result.update(liveness=P.CONFIRMED_EXITED, exit_evidence="wait+exit_code",
                          exit_code=code, reason="signalled with an exit code")
        elif signaled is False and code is None:
            result.update(liveness=P.ALIVE_AT_LAST_CHECK, reason="the child is still alive")
        else:
            result.update(liveness=P.STATE_UNKNOWN, reason="inconclusive wait evidence")
    else:
        result.update(liveness=P.STATE_UNKNOWN,
                      reason=f"inspection {status!r}: identity not established")
    return result

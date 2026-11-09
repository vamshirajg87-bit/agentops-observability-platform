"""
alerting/alert_evaluator.py

Phase 13.4: Batch alert evaluation.

Evaluates every RCA investigation that has no decision under the current
policy version, and records one decision for each:

    register policy -> discover candidates -> for each candidate:
        build subject -> fetch history -> decide -> build decision -> store

The verdict itself comes from alert_engine.decide(), which is used unchanged.
This module supplies its inputs and records its output.

Policy registration
-------------------
The policy version is registered with the hash and the canonical evaluation
object of alert_policy.  A version that is already registered with the same
hash is accepted.  A version registered with a different hash raises
PolicyVersionConflictError before any investigation is evaluated.

Order
-----
Candidates are processed in event_time order, then investigation_id order.
Each decision is committed before the next candidate is read, so a later
candidate sees the alerts raised earlier in the same run.

History
-------
For a candidate with event_time E, converted to UTC first:

    cooldown window starts at  E - cooldown_minutes
    storm window starts at     E - alert_engine.STORM_WINDOW

A start that cannot be represented is clamped to the earliest datetime.  The
store returns the persisted alerts the three rules need.  They are merged by
decision_id, so the engine never receives one decision twice.

Informational fields
--------------------
confidence, limitations and summary are copied into the decision.  They are
never passed to the engine and cannot change a verdict.

Summary
-------
A summary is stored only for an ALERT and only when the policy sets
persist_summary.  It is cut to SUMMARY_MAX_CODE_POINTS Unicode code points.
It is never part of the payload.

Dry run
-------
With dry_run=True nothing is written and nothing is committed.  The policy is
looked up but not registered.  Each ALERT the run would raise is remembered
and added to the history of the later candidates, so the verdicts equal those
of a real run from the same database state.

Failure policy
--------------
A ValueError raised for one candidate — malformed stored data, or input the
models or the engine reject — is recorded as a 'failure' and the run
continues.  Any other exception, a database error in particular, stops the
run and propagates.  The open transaction is rolled back in both cases.

Transactions
------------
This module commits and rolls back on the supplied connection.  It never
closes it.  Database access goes through alert_store; this module contains no
database statement and does not import a database driver.  It reads no clock:
the evaluation time is supplied by the caller.

Public API:
    ADVISORY, SUMMARY_MAX_CODE_POINTS
    STATUS_PERSISTED, STATUS_ALREADY_DECIDED, STATUS_DRY_RUN, STATUS_FAILURE,
    EVALUATION_STATUSES
    POLICY_REGISTERED, POLICY_ALREADY_REGISTERED, POLICY_NOT_REGISTERED
    PolicyVersionConflictError
    format_timestamp()     — UTC text with six fractional digits and 'Z'
    build_payload()        — the notification payload of an ALERT
    persisted_summary()    — the summary to store, and whether it was cut
    EvaluationResult       — what happened for one investigation (frozen)
    EvaluationReport       — all results, with counts (frozen)
    run_evaluation()       — run one evaluation batch
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional, Sequence

import alert_store
from alert_engine import STORM_WINDOW, AlertSubject, PriorAlert, decide
from alert_identity import compute_decision_id
from alert_models import (
    AlertDecision,
    Confidence,
    Decision,
    ReasonCode,
    Severity,
)
from alert_policy import AlertPolicy, evaluation_hash_object
from alert_version import PAYLOAD_VERSION


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Fixed advisory sentence carried by every ALERT payload.
ADVISORY: str = (
    "Automated detection. Advisory only; no action has been taken. "
    "RCA confidence describes evidence quality, not cause."
)

#: A stored summary holds at most this many Unicode code points.
SUMMARY_MAX_CODE_POINTS: int = 2000

#: The decision was written by this run.
STATUS_PERSISTED: str = "persisted"
#: A decision for this investigation and policy version already existed.
STATUS_ALREADY_DECIDED: str = "already_decided"
#: Dry run: the decision was computed and not written.
STATUS_DRY_RUN: str = "dry_run"
#: The candidate raised ValueError; nothing was written for it.
STATUS_FAILURE: str = "failure"

EVALUATION_STATUSES: frozenset[str] = frozenset({
    STATUS_PERSISTED,
    STATUS_ALREADY_DECIDED,
    STATUS_DRY_RUN,
    STATUS_FAILURE,
})

#: The policy version was registered by this run.
POLICY_REGISTERED: str = "registered"
#: The policy version was already registered with the same hash.
POLICY_ALREADY_REGISTERED: str = "already_registered"
#: Dry run: the policy version is not registered and was not written.
POLICY_NOT_REGISTERED: str = "not_registered"

_EARLIEST: datetime = datetime.min.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class PolicyVersionConflictError(Exception):
    """
    Raised when policy_version is already registered with a different hash:
    one policy version must never mean two sets of evaluation rules.
    """

    def __init__(
        self, policy_version: str, stored_sha256: str, policy_sha256: str,
    ) -> None:
        super().__init__(
            f"policy_version {policy_version!r} is already registered with "
            f"policy_sha256 {stored_sha256}; this policy has {policy_sha256}"
        )
        self.policy_version = policy_version
        self.stored_sha256 = stored_sha256
        self.policy_sha256 = policy_sha256


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvaluationResult:
    """
    What happened for one investigation.

    Attributes
    ----------
    investigation_id
        The investigation that was processed.
    status
        One of EVALUATION_STATUSES.
    decision_id
        The decision identity when it could be computed; otherwise None.
    decision, reason_code, related_decision_id
        The verdict when status is 'persisted' or 'dry_run'; otherwise None.
    related_is_hypothetical
        True when related_decision_id names an alert of the same dry run,
        which is not stored.
    error
        "<ExceptionType>: <message>" when status is 'failure'; otherwise None.
    """

    investigation_id: Any
    status: str
    decision_id: Optional[str] = None
    decision: Optional[Decision] = None
    reason_code: Optional[ReasonCode] = None
    related_decision_id: Optional[str] = None
    related_is_hypothetical: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class EvaluationReport:
    """
    Outcome of one run_evaluation() call.

    results holds one EvaluationResult per candidate, in the order they were
    processed (event_time, then investigation_id).
    """

    results: tuple[EvaluationResult, ...]
    policy_status: str
    dry_run: bool

    def count(self, status: str) -> int:
        """Number of results with the given status."""
        return sum(1 for result in self.results if result.status == status)

    def count_decision(self, decision: Decision) -> int:
        """Number of verdicts of this run with the given decision."""
        return sum(1 for result in self.results if result.decision is decision)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def alerts(self) -> int:
        return self.count_decision(Decision.ALERT)

    @property
    def suppressed(self) -> int:
        return self.count_decision(Decision.SUPPRESSED)

    @property
    def not_alertable(self) -> int:
        return self.count_decision(Decision.NOT_ALERTABLE)

    @property
    def already_decided(self) -> int:
        return self.count(STATUS_ALREADY_DECIDED)

    @property
    def failures(self) -> int:
        return self.count(STATUS_FAILURE)

    @property
    def succeeded(self) -> bool:
        """True when no candidate failed."""
        return self.failures == 0


# ---------------------------------------------------------------------------
# Time helpers (pure)
# ---------------------------------------------------------------------------

def _to_utc(value: Any, field: str) -> datetime:
    """Validate an aware datetime and return the same instant in UTC."""
    if not isinstance(value, datetime):
        raise ValueError(f"{field} must be datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError(f"{field} cannot be represented in UTC") from None


def format_timestamp(value: datetime) -> str:
    """
    UTC text of an aware datetime: YYYY-MM-DDTHH:MM:SS.ffffffZ.

    Always six fractional digits and a 'Z' suffix, on every platform.

    Raises:
        ValueError  if value is not a timezone-aware datetime.
    """
    utc = _to_utc(value, "timestamp")
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}"
        f".{utc.microsecond:06d}Z"
    )


def _window_start(event_time: datetime, minutes: Optional[int]) -> datetime:
    """
    Start of a trailing window that ends at event_time (UTC).

    minutes is None for the storm window.  A start earlier than the earliest
    datetime is clamped to it.
    """
    try:
        length = STORM_WINDOW if minutes is None else timedelta(minutes=minutes)
        return event_time - length
    except OverflowError:
        return _EARLIEST


# ---------------------------------------------------------------------------
# Payload and summary (pure)
# ---------------------------------------------------------------------------

def build_payload(
    *,
    decision_id: str,
    investigation_id: str,
    anomaly_id: str,
    anomaly_type: str,
    service_name: Optional[str],
    operation_name: Optional[str],
    event_time: datetime,
    evaluated_at: datetime,
    severity: Severity,
    confidence: Confidence,
    limitations: Sequence[str],
    reason_code: ReasonCode,
    policy_version: str,
) -> dict[str, Any]:
    """
    The notification payload of an ALERT: exactly fifteen keys.

    Holds no summary, no evidence and no reference to another decision.

    Raises:
        ValueError  if event_time or evaluated_at is not timezone-aware.
    """
    return {
        "payload_version": PAYLOAD_VERSION,
        "decision_id": decision_id,
        "investigation_id": investigation_id,
        "anomaly_id": anomaly_id,
        "anomaly_type": anomaly_type,
        "service_name": service_name,
        "operation_name": operation_name,
        "event_time": format_timestamp(event_time),
        "evaluated_at": format_timestamp(evaluated_at),
        "severity": severity.value,
        "confidence": confidence.value,
        "limitations": list(limitations),
        "reason_code": reason_code.value,
        "policy_version": policy_version,
        "advisory": ADVISORY,
    }


def persisted_summary(
    source: Optional[str],
    decision: Decision,
    persist_summary: bool,
) -> tuple[Optional[str], bool]:
    """
    The summary to store for a decision, and whether it was cut.

    Returns (None, False) unless the decision is an ALERT, persist_summary is
    true and source is not None.  A longer source is cut to its first
    SUMMARY_MAX_CODE_POINTS code points.

    Raises:
        ValueError  if source is neither a str nor None.
    """
    if source is not None and not isinstance(source, str):
        raise ValueError(
            f"summary must be str or None, got {type(source).__name__}"
        )
    if not persist_summary or decision is not Decision.ALERT or source is None:
        return None, False
    if len(source) <= SUMMARY_MAX_CODE_POINTS:
        return source, False
    return source[:SUMMARY_MAX_CODE_POINTS], True


# ---------------------------------------------------------------------------
# Row mapping (pure)
# ---------------------------------------------------------------------------

def _enum(enum_type: type, value: Any, field: str) -> Any:
    """Map a stored text value to its enum member; the value is not echoed."""
    try:
        return enum_type(value)
    except ValueError:
        raise ValueError(
            f"{field} is not a known {enum_type.__name__} value"
        ) from None


def _limitations(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError("limitations must be a list of str")
    return tuple(value)


def _subject(row: Mapping[str, Any]) -> AlertSubject:
    return AlertSubject(
        investigation_id=row["investigation_id"],
        anomaly_id=row["anomaly_id"],
        anomaly_type=row["anomaly_type"],
        service_name=row["service_name"],
        operation_name=row["operation_name"],
        event_time=row["event_time"],
        severity=_enum(Severity, row["severity"], "severity"),
    )


def _prior_alert(row: Mapping[str, Any]) -> PriorAlert:
    return PriorAlert(
        decision_id=row["decision_id"],
        anomaly_id=row["anomaly_id"],
        dedup_key=row["dedup_key"],
        event_time=row["event_time"],
        severity=_enum(Severity, row["severity"], "history severity"),
        decision=_enum(Decision, row["decision"], "history decision"),
    )


def _merge_history(
    persisted: Sequence[PriorAlert],
    hypothetical: Sequence[PriorAlert],
) -> tuple[PriorAlert, ...]:
    """One alert per decision_id, ordered by decision_id; persisted wins."""
    merged: dict[str, PriorAlert] = {}
    for alert in (*persisted, *hypothetical):
        merged.setdefault(alert.decision_id, alert)
    return tuple(merged[decision_id] for decision_id in sorted(merged))


# ---------------------------------------------------------------------------
# Policy registration
# ---------------------------------------------------------------------------

def _register_policy(conn: Any, policy: AlertPolicy, dry_run: bool) -> str:
    """Register or check the policy version in its own transaction."""
    version = policy.policy_version
    sha256 = policy.policy_sha256

    try:
        inserted = False
        if not dry_run:
            inserted = alert_store.insert_policy(
                conn,
                policy_version=version,
                policy_sha256=sha256,
                policy_json=evaluation_hash_object(
                    policy.policy_schema_version, version, policy.evaluation,
                ),
            )
        stored = alert_store.fetch_policy_sha256(conn, version)

        if stored is None:
            if not dry_run:
                raise RuntimeError(
                    f"policy_version {version!r} was not found after it was "
                    "registered"
                )
            status = POLICY_NOT_REGISTERED
        elif stored != sha256:
            raise PolicyVersionConflictError(version, stored, sha256)
        else:
            status = POLICY_REGISTERED if inserted else POLICY_ALREADY_REGISTERED

        if dry_run:
            conn.rollback()
        else:
            conn.commit()
    except Exception:
        conn.rollback()
        raise

    return status


# ---------------------------------------------------------------------------
# One candidate
# ---------------------------------------------------------------------------

def _evaluate_one(
    conn: Any,
    policy: AlertPolicy,
    row: Mapping[str, Any],
    evaluated_at: datetime,
    dry_run: bool,
    hypothetical: Sequence[PriorAlert],
) -> tuple[EvaluationResult, Optional[PriorAlert]]:
    """
    Evaluate one candidate.  Does not commit or roll back.

    Returns the result and, for a dry-run ALERT, the alert to add to the
    history of later candidates.
    """
    evaluation = policy.evaluation
    version = policy.policy_version

    # 1. Subject and informational fields
    subject = _subject(row)
    confidence = _enum(Confidence, row["confidence"], "confidence")
    limitations = _limitations(row["limitations"])
    decision_id = compute_decision_id(subject.investigation_id, version)
    dedup_key = subject.dedup_key

    # 2. History.  UTC first: window arithmetic in another zone is wall-clock.
    event_time = _to_utc(subject.event_time, "event_time")
    rows = alert_store.fetch_alert_history(
        conn,
        anomaly_id=subject.anomaly_id,
        dedup_key=dedup_key,
        event_time=event_time,
        cooldown_start=_window_start(event_time, evaluation.cooldown_minutes),
        storm_start=_window_start(event_time, None),
    )
    history = _merge_history([_prior_alert(item) for item in rows], hypothetical)

    # 3. A concurrent writer already decided this investigation.
    if any(alert.decision_id == decision_id for alert in history):
        return EvaluationResult(
            investigation_id=subject.investigation_id,
            status=STATUS_ALREADY_DECIDED,
            decision_id=decision_id,
        ), None

    # 4. Verdict
    verdict = decide(subject, history, evaluation, evaluated_at)

    # 5. Decision record; it checks every constraint of the table.
    is_alert = verdict.decision is Decision.ALERT
    summary, summary_truncated = persisted_summary(
        row["summary"], verdict.decision, evaluation.persist_summary,
    )
    payload = None
    if is_alert:
        payload = build_payload(
            decision_id=decision_id,
            investigation_id=subject.investigation_id,
            anomaly_id=subject.anomaly_id,
            anomaly_type=subject.anomaly_type,
            service_name=subject.service_name,
            operation_name=subject.operation_name,
            event_time=subject.event_time,
            evaluated_at=evaluated_at,
            severity=subject.severity,
            confidence=confidence,
            limitations=limitations,
            reason_code=verdict.reason_code,
            policy_version=version,
        )
    record = AlertDecision(
        decision_id=decision_id,
        investigation_id=subject.investigation_id,
        policy_version=version,
        anomaly_id=subject.anomaly_id,
        anomaly_type=subject.anomaly_type,
        service_name=subject.service_name,
        operation_name=subject.operation_name,
        event_time=subject.event_time,
        severity=subject.severity,
        confidence=confidence,
        limitations=limitations,
        dedup_key=dedup_key,
        decision=verdict.decision,
        reason_code=verdict.reason_code,
        related_decision_id=verdict.related_decision_id,
        evaluated_at=evaluated_at,
        payload=payload,
        summary=summary,
        summary_truncated=summary_truncated,
    )

    # 6. Store; first-write-wins
    if dry_run:
        status = STATUS_DRY_RUN
    elif alert_store.insert_decision(conn, record):
        status = STATUS_PERSISTED
    else:
        # A concurrent writer stored the decision first; it is left untouched.
        return EvaluationResult(
            investigation_id=subject.investigation_id,
            status=STATUS_ALREADY_DECIDED,
            decision_id=decision_id,
        ), None

    result = EvaluationResult(
        investigation_id=subject.investigation_id,
        status=status,
        decision_id=decision_id,
        decision=verdict.decision,
        reason_code=verdict.reason_code,
        related_decision_id=verdict.related_decision_id,
        related_is_hypothetical=any(
            alert.decision_id == verdict.related_decision_id
            for alert in hypothetical
        ),
    )

    remembered = None
    if dry_run and is_alert:
        remembered = PriorAlert(
            decision_id=decision_id,
            anomaly_id=subject.anomaly_id,
            dedup_key=dedup_key,
            event_time=subject.event_time,
            severity=subject.severity,
            decision=Decision.ALERT,
        )
    return result, remembered


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_evaluation(
    conn: Any,
    policy: AlertPolicy,
    *,
    evaluated_at: datetime,
    dry_run: bool = False,
    on_result: Optional[Callable[[EvaluationResult], None]] = None,
) -> EvaluationReport:
    """
    Evaluate every investigation that has no decision under policy's version.

    Parameters
    ----------
    conn
        Open connection for the alert_evaluator role.  The caller owns the
        connection lifecycle; this function does NOT close it.  It must not
        carry uncommitted work of the caller.  For a dry run the caller
        should supply a read-only session.
    policy
        The validated policy.
    evaluated_at
        The evaluation time of this run: one timezone-aware value, used for
        every candidate.
    dry_run
        When True, nothing is written and nothing is committed.
    on_result
        Optional callback invoked with each EvaluationResult as soon as it is
        known, in processing order.

    Returns
    -------
    EvaluationReport
        One result per candidate, in processing order.

    Raises
    ------
    ValueError
        policy is not an AlertPolicy, or evaluated_at is not a timezone-aware
        datetime.  Raised before the database is used.
    PolicyVersionConflictError
        The policy version is registered with a different hash.  No
        investigation is evaluated.
    database error
        Any error of the database driver, at any step.  The run stops;
        decisions committed earlier stay committed.
    KeyboardInterrupt
        Not caught; the run stops.

    A ValueError raised for a single candidate is not propagated; it is
    recorded as a 'failure' result.
    """
    if not isinstance(policy, AlertPolicy):
        raise ValueError(
            f"policy must be AlertPolicy, got {type(policy).__name__}"
        )
    evaluated = _to_utc(evaluated_at, "evaluated_at")

    policy_status = _register_policy(conn, policy, dry_run)

    try:
        candidates = alert_store.fetch_candidates(conn, policy.policy_version)
    except Exception:
        conn.rollback()
        raise

    # End the read-only discovery transaction so that every candidate runs
    # in a transaction of its own.
    conn.rollback()

    hypothetical: list[PriorAlert] = []
    results: list[EvaluationResult] = []
    for row in candidates:
        try:
            result, remembered = _evaluate_one(
                conn, policy, row, evaluated, dry_run, hypothetical,
            )
            if dry_run:
                conn.rollback()
            else:
                conn.commit()
        except ValueError as exc:
            conn.rollback()
            result = EvaluationResult(
                investigation_id=row.get("investigation_id"),
                status=STATUS_FAILURE,
                error=f"{type(exc).__name__}: {exc}",
            )
            remembered = None
        except Exception:
            conn.rollback()
            raise

        if remembered is not None:
            hypothetical.append(remembered)
        results.append(result)
        if on_result is not None:
            on_result(result)

    return EvaluationReport(
        results=tuple(results),
        policy_status=policy_status,
        dry_run=dry_run,
    )

"""
alerting/alert_engine.py

Phase 13.3: Pure alert policy engine.

Decides, for one RCA investigation, whether it becomes an alert:

    decide(subject, history, evaluation, evaluated_at) -> EngineDecision

The engine is a pure function.  The same subject, history, evaluation policy
and evaluated_at always give the same result.  It reads no clock: the
evaluation time is supplied by the caller.

RCA confidence, limitations and summary are not inputs.  No input type has a
field for them, so they cannot influence a decision.

History
-------
history holds prior persisted ALERT decisions, of every policy version.  The
engine does not fetch it; the caller supplies it.  The order of history does
not matter.  The engine applies each window itself, so history may hold more
alerts than a rule needs.

Rules (first match wins)
------------------------
E is the subject's event_time.  E' is the event_time of a prior alert.

    1. kill switch   evaluation.enabled is false
                     -> SUPPRESSED / kill_switch
    2. severity      subject severity below evaluation.min_severity
                     -> NOT_ALERTABLE / below_min_severity
    3. stale         evaluated_at - E > max_alert_age_minutes
                     -> NOT_ALERTABLE / stale
                     Exactly max_alert_age_minutes old is not stale.  An
                     event_time later than evaluated_at is not stale.
    4. duplicate     a prior alert has the same anomaly_id (no time bound)
                     -> SUPPRESSED / duplicate_anomaly
    5. cooldown      W = prior alerts with the same dedup_key and
                         E - cooldown_minutes < E' <= E
                     W empty: the rule does not apply.
                     Otherwise, when escalation_breaks_cooldown is true and
                     the subject's severity is strictly higher than every
                     severity in W, the subject is an escalation and
                     evaluation continues with rule 6.
                     In every other case -> SUPPRESSED / cooldown
    6. storm cap     number of prior alerts, of any dedup_key, with
                         E - 60 minutes < E' <= E
                     is >= max_alerts_per_hour
                     -> SUPPRESSED / storm_cap
                     An escalation is capped like any other alert.
    7. otherwise     -> ALERT / escalation   when rule 5 found an escalation
                     -> ALERT / severity_met otherwise

Both windows are strictly historical: a prior alert whose event_time is later
than E never takes part in rule 5 or rule 6.  The lower bound is exclusive
and the upper bound inclusive.  cooldown_minutes = 0 makes W empty.

Related decision
----------------
    duplicate_anomaly      the smallest decision_id among the matching alerts
    cooldown, escalation   chosen from W: highest severity, then the alert
                           closest in time to E, then the smallest
                           decision_id
    every other reason     None

Time handling
-------------
Every datetime must be timezone-aware; any UTC offset is accepted.  All of
them are converted to UTC before they are compared or subtracted.  This is
required for correctness: Python compares two datetimes that share one tzinfo
object by their wall-clock fields, which is wrong for a zone whose offset
changes.

Fail closed
-----------
All inputs are validated before rule 1.  Anything invalid raises ValueError
and no decision is produced, whatever the policy says.

Standard library only.  No database access, no I/O, no logging.

Public API:
    STORM_WINDOW       — length of the storm-cap window (60 minutes)
    AlertSubject       — the investigation being evaluated (frozen dataclass)
    PriorAlert         — one prior persisted ALERT decision (frozen dataclass)
    EngineDecision     — the verdict (frozen dataclass)
    decide()           — evaluate one subject
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

from alert_identity import compute_dedup_key, is_sha256_hex
from alert_models import (
    REASONS_BY_DECISION,
    REASONS_WITH_RELATED_DECISION,
    Decision,
    ReasonCode,
    Severity,
    severity_rank,
)
from alert_policy import EvaluationPolicy


#: The storm cap counts alerts in this trailing window of event_time.
STORM_WINDOW: timedelta = timedelta(minutes=60)

_ZERO: timedelta = timedelta(0)


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------

def _require_digest(value: Any, field: str) -> None:
    if not is_sha256_hex(value):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")


def _require_optional_str(value: Any, field: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError(
            f"{field} must be str or None, got {type(value).__name__}"
        )


def _require_aware_datetime(value: Any, field: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(
            f"{field} must be datetime, got {type(value).__name__}"
        )
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


def _require_severity(value: Any, field: str) -> None:
    if not isinstance(value, Severity):
        raise ValueError(
            f"{field} must be Severity, got {type(value).__name__}"
        )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AlertSubject:
    """
    The RCA investigation being evaluated.

    investigation_id identifies the subject; it takes no part in any rule and
    is not part of dedup_key.
    """

    investigation_id: str
    anomaly_id: str
    anomaly_type: str
    service_name: Optional[str]
    operation_name: Optional[str]
    event_time: datetime
    severity: Severity

    def __post_init__(self) -> None:
        _require_digest(self.investigation_id, "investigation_id")
        _require_digest(self.anomaly_id, "anomaly_id")
        if not isinstance(self.anomaly_type, str) or self.anomaly_type == "":
            raise ValueError("anomaly_type must be a non-empty str")
        _require_optional_str(self.service_name, "service_name")
        _require_optional_str(self.operation_name, "operation_name")
        _require_aware_datetime(self.event_time, "event_time")
        _require_severity(self.severity, "severity")
        # Rejects a value that cannot be hashed, such as a lone surrogate.
        compute_dedup_key(self.anomaly_type, self.service_name, self.operation_name)

    @property
    def dedup_key(self) -> str:
        """Deduplication key of (anomaly_type, service_name, operation_name)."""
        return compute_dedup_key(
            self.anomaly_type, self.service_name, self.operation_name,
        )


@dataclass(frozen=True)
class PriorAlert:
    """
    One prior persisted decision whose decision is ALERT.

    decision is carried so that a non-ALERT decision passed by mistake is
    rejected instead of being counted.
    """

    decision_id: str
    anomaly_id: str
    dedup_key: str
    event_time: datetime
    severity: Severity
    decision: Decision

    def __post_init__(self) -> None:
        _require_digest(self.decision_id, "decision_id")
        _require_digest(self.anomaly_id, "anomaly_id")
        _require_digest(self.dedup_key, "dedup_key")
        _require_aware_datetime(self.event_time, "event_time")
        _require_severity(self.severity, "severity")
        if self.decision is not Decision.ALERT:
            raise ValueError("a prior alert must have decision ALERT")


@dataclass(frozen=True)
class EngineDecision:
    """
    The verdict for one subject.

    related_decision_id names a prior alert exactly when reason_code is
    cooldown, escalation or duplicate_anomaly.
    """

    decision: Decision
    reason_code: ReasonCode
    related_decision_id: Optional[str]

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            raise ValueError(
                f"decision must be Decision, got {type(self.decision).__name__}"
            )
        if not isinstance(self.reason_code, ReasonCode):
            raise ValueError(
                "reason_code must be ReasonCode, "
                f"got {type(self.reason_code).__name__}"
            )
        if self.reason_code not in REASONS_BY_DECISION[self.decision]:
            raise ValueError(
                f"reason_code {self.reason_code.value!r} is not valid for "
                f"decision {self.decision.value!r}"
            )
        if self.reason_code in REASONS_WITH_RELATED_DECISION:
            _require_digest(self.related_decision_id, "related_decision_id")
        elif self.related_decision_id is not None:
            raise ValueError(
                f"related_decision_id must be None for reason_code "
                f"{self.reason_code.value!r}"
            )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _to_utc(value: Any, field: str) -> datetime:
    """Validate an aware datetime and return the same instant in UTC."""
    _require_aware_datetime(value, field)
    try:
        return value.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError(f"{field} cannot be represented in UTC") from None


def _minutes(value: int, field: str) -> timedelta:
    try:
        return timedelta(minutes=value)
    except OverflowError:
        raise ValueError(f"{field} is too large: {value}") from None


def _validated_history(
    history: Any,
) -> tuple[tuple[PriorAlert, datetime], ...]:
    """Check history and pair every prior alert with its event_time in UTC."""
    if not isinstance(history, (list, tuple)):
        raise ValueError(
            f"history must be a list or tuple, got {type(history).__name__}"
        )

    seen: set[str] = set()
    prior: list[tuple[PriorAlert, datetime]] = []
    for position, item in enumerate(history):
        if not isinstance(item, PriorAlert):
            raise ValueError(
                f"history item {position} must be PriorAlert, "
                f"got {type(item).__name__}"
            )
        if item.decision is not Decision.ALERT:
            raise ValueError(
                f"history item {position} does not have decision ALERT"
            )
        if item.decision_id in seen:
            raise ValueError(
                f"history holds decision {item.decision_id!r} twice"
            )
        seen.add(item.decision_id)
        prior.append(
            (item, _to_utc(item.event_time, f"history item {position} event_time"))
        )
    return tuple(prior)


def _best_related(
    window: Sequence[tuple[PriorAlert, timedelta]],
) -> PriorAlert:
    """
    The alert of a non-empty cooldown window to refer to: highest severity,
    then closest in time to the subject, then smallest decision_id.
    """
    alert, _ = min(
        window,
        key=lambda entry: (
            -severity_rank(entry[0].severity),
            entry[1],
            entry[0].decision_id,
        ),
    )
    return alert


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def decide(
    subject: AlertSubject,
    history: Sequence[PriorAlert],
    evaluation: EvaluationPolicy,
    evaluated_at: datetime,
) -> EngineDecision:
    """
    Decide whether one investigation becomes an alert.

    Parameters
    ----------
    subject
        The investigation being evaluated.
    history
        Prior persisted ALERT decisions, as a list or tuple, in any order.
        It may hold more alerts than the rules need; alerts outside a rule's
        window are ignored by that rule.
    evaluation
        The evaluation section of the policy.
    evaluated_at
        The evaluation time, supplied by the caller.  Only the stale rule
        uses it.

    Returns
    -------
    EngineDecision
        decision, reason_code and related_decision_id.

    Raises
    ------
    ValueError
        subject is not an AlertSubject; history is not a list or tuple of
        PriorAlert, holds a decision that is not ALERT, or holds one
        decision_id twice; evaluation is not an EvaluationPolicy;
        evaluated_at or any event_time is not a timezone-aware datetime or
        cannot be represented in UTC; or a policy duration is too large.
        Raised before any rule is applied.
    """
    # Validate everything first: invalid input never yields a decision.
    if not isinstance(subject, AlertSubject):
        raise ValueError(
            f"subject must be AlertSubject, got {type(subject).__name__}"
        )
    if not isinstance(evaluation, EvaluationPolicy):
        raise ValueError(
            "evaluation must be EvaluationPolicy, "
            f"got {type(evaluation).__name__}"
        )
    _require_severity(subject.severity, "subject severity")

    event_time = _to_utc(subject.event_time, "subject event_time")
    evaluated = _to_utc(evaluated_at, "evaluated_at")
    prior = _validated_history(history)
    max_alert_age = _minutes(
        evaluation.max_alert_age_minutes, "max_alert_age_minutes",
    )
    cooldown = _minutes(evaluation.cooldown_minutes, "cooldown_minutes")
    dedup_key = subject.dedup_key
    subject_rank = severity_rank(subject.severity)

    # 1. Kill switch
    if not evaluation.enabled:
        return EngineDecision(Decision.SUPPRESSED, ReasonCode.KILL_SWITCH, None)

    # 2. Minimum severity
    if subject_rank < severity_rank(evaluation.min_severity):
        return EngineDecision(
            Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY, None,
        )

    # 3. Stale
    if evaluated - event_time > max_alert_age:
        return EngineDecision(Decision.NOT_ALERTABLE, ReasonCode.STALE, None)

    # 4. Duplicate anomaly: no time bound
    duplicates = [
        alert.decision_id for alert, _ in prior
        if alert.anomaly_id == subject.anomaly_id
    ]
    if duplicates:
        return EngineDecision(
            Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, min(duplicates),
        )

    # Age of every prior alert relative to the subject.  A negative age is an
    # alert later than the subject; it takes part in no window.
    aged = [(alert, event_time - alert_time) for alert, alert_time in prior]

    # 5. Cooldown / escalation: E - cooldown < E' <= E, same dedup_key
    window = [
        (alert, age) for alert, age in aged
        if alert.dedup_key == dedup_key and _ZERO <= age < cooldown
    ]
    escalated_over: Optional[PriorAlert] = None
    if window:
        related = _best_related(window)
        highest = max(severity_rank(alert.severity) for alert, _ in window)
        if evaluation.escalation_breaks_cooldown and subject_rank > highest:
            escalated_over = related
        else:
            return EngineDecision(
                Decision.SUPPRESSED, ReasonCode.COOLDOWN, related.decision_id,
            )

    # 6. Storm cap: E - 60 minutes < E' <= E, every dedup_key
    recent = sum(1 for _, age in aged if _ZERO <= age < STORM_WINDOW)
    if recent >= evaluation.max_alerts_per_hour:
        return EngineDecision(Decision.SUPPRESSED, ReasonCode.STORM_CAP, None)

    # 7. Alert
    if escalated_over is not None:
        return EngineDecision(
            Decision.ALERT, ReasonCode.ESCALATION, escalated_over.decision_id,
        )
    return EngineDecision(Decision.ALERT, ReasonCode.SEVERITY_MET, None)

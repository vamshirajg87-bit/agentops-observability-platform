"""
alerting/alert_models.py

Phase 13.1: Vocabulary and immutable data contracts for alerting.

No decision logic, no database access, no I/O.  The models check that a
record is internally consistent; they do not decide anything.

RCA confidence is carried on a decision as information only.  It never takes
part in whether an alert is raised.

Public API:
    Severity, Confidence, Decision, ReasonCode, ChannelType,
    DeliveryOutcome, DeliveryTrigger, GuardrailStatus
    severity_rank()           — INFO < WARNING < CRITICAL
    REASONS_BY_DECISION       — which reason codes each decision may carry
    REASONS_WITH_RELATED_DECISION
    AlertDecision             — one persisted decision (frozen dataclass)
    DeliveryAttempt           — one delivery attempt (frozen dataclass)
    DeliveryOutcomeRecord     — the recorded result of an attempt (frozen)
    GuardrailFinding          — one guardrail check result (frozen dataclass)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Optional

from alert_identity import is_sha256_hex, validate_identifier


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

class Severity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Decision(Enum):
    ALERT = "ALERT"
    SUPPRESSED = "SUPPRESSED"
    NOT_ALERTABLE = "NOT_ALERTABLE"


class ReasonCode(Enum):
    SEVERITY_MET = "severity_met"
    ESCALATION = "escalation"
    KILL_SWITCH = "kill_switch"
    DUPLICATE_ANOMALY = "duplicate_anomaly"
    COOLDOWN = "cooldown"
    STORM_CAP = "storm_cap"
    BELOW_MIN_SEVERITY = "below_min_severity"
    STALE = "stale"


class ChannelType(Enum):
    LOG = "log"
    FILE = "file"
    WEBHOOK = "webhook"


class DeliveryOutcome(Enum):
    SENT = "SENT"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_PERMANENT = "FAILED_PERMANENT"
    UNCERTAIN = "UNCERTAIN"


class DeliveryTrigger(Enum):
    AUTO = "auto"
    OPERATOR = "operator"


class GuardrailStatus(Enum):
    OK = "OK"
    VIOLATION = "VIOLATION"


_SEVERITY_ORDER = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


def severity_rank(severity: Severity) -> int:
    """Ordering of severities: INFO (0) < WARNING (1) < CRITICAL (2)."""
    if not isinstance(severity, Severity):
        raise ValueError(
            f"severity must be Severity, got {type(severity).__name__}"
        )
    return _SEVERITY_ORDER[severity]


#: The reason codes each decision may carry.
REASONS_BY_DECISION: Mapping[Decision, frozenset[ReasonCode]] = MappingProxyType({
    Decision.ALERT: frozenset({
        ReasonCode.SEVERITY_MET,
        ReasonCode.ESCALATION,
    }),
    Decision.SUPPRESSED: frozenset({
        ReasonCode.KILL_SWITCH,
        ReasonCode.DUPLICATE_ANOMALY,
        ReasonCode.COOLDOWN,
        ReasonCode.STORM_CAP,
    }),
    Decision.NOT_ALERTABLE: frozenset({
        ReasonCode.BELOW_MIN_SEVERITY,
        ReasonCode.STALE,
    }),
})

#: Reason codes that name another decision; every other reason carries none.
REASONS_WITH_RELATED_DECISION: frozenset[ReasonCode] = frozenset({
    ReasonCode.ESCALATION,
    ReasonCode.DUPLICATE_ANOMALY,
    ReasonCode.COOLDOWN,
})


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------

def _require_enum(value: Any, enum_type: type, field: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(
            f"{field} must be {enum_type.__name__}, got {type(value).__name__}"
        )


def _require_digest(value: Any, field: str) -> None:
    if not is_sha256_hex(value):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")


def _require_non_empty_str(value: Any, field: str) -> None:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{field} must be a non-empty str")


def _require_optional_str(value: Any, field: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError(
            f"{field} must be str or None, got {type(value).__name__}"
        )


def _require_bool(value: Any, field: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be bool, got {type(value).__name__}")


def _require_aware_datetime(value: Any, field: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(
            f"{field} must be datetime, got {type(value).__name__}"
        )
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AlertDecision:
    """
    One persisted decision about one RCA investigation under one policy
    version.

    severity, confidence and limitations are a snapshot of the investigation.
    confidence and limitations are informational only.

    payload is the notification snapshot.  It is present exactly when
    decision is ALERT, and is stored read-only.  summary is kept apart from
    payload and may be present only on an ALERT.

    related_decision_id names another decision exactly when reason_code is
    cooldown, escalation or duplicate_anomaly.
    """

    decision_id: str
    investigation_id: str
    policy_version: str
    anomaly_id: str
    anomaly_type: str
    service_name: Optional[str]
    operation_name: Optional[str]
    event_time: datetime
    severity: Severity
    confidence: Confidence
    limitations: tuple[str, ...]
    dedup_key: str
    decision: Decision
    reason_code: ReasonCode
    related_decision_id: Optional[str]
    evaluated_at: datetime
    payload: Optional[Mapping[str, Any]]
    summary: Optional[str] = None
    summary_truncated: bool = False

    def __post_init__(self) -> None:
        _require_digest(self.decision_id, "decision_id")
        _require_digest(self.investigation_id, "investigation_id")
        validate_identifier(self.policy_version, "policy_version")
        _require_digest(self.anomaly_id, "anomaly_id")
        _require_non_empty_str(self.anomaly_type, "anomaly_type")
        _require_optional_str(self.service_name, "service_name")
        _require_optional_str(self.operation_name, "operation_name")
        _require_aware_datetime(self.event_time, "event_time")
        _require_enum(self.severity, Severity, "severity")
        _require_enum(self.confidence, Confidence, "confidence")
        if not isinstance(self.limitations, tuple) or not all(
            isinstance(item, str) for item in self.limitations
        ):
            raise ValueError("limitations must be a tuple of str")
        _require_digest(self.dedup_key, "dedup_key")
        _require_enum(self.decision, Decision, "decision")
        _require_enum(self.reason_code, ReasonCode, "reason_code")
        _require_aware_datetime(self.evaluated_at, "evaluated_at")
        _require_bool(self.summary_truncated, "summary_truncated")
        _require_optional_str(self.summary, "summary")

        if self.reason_code not in REASONS_BY_DECISION[self.decision]:
            raise ValueError(
                f"reason_code {self.reason_code.value!r} is not valid for "
                f"decision {self.decision.value!r}"
            )

        if self.reason_code in REASONS_WITH_RELATED_DECISION:
            _require_digest(self.related_decision_id, "related_decision_id")
            if self.related_decision_id == self.decision_id:
                raise ValueError("related_decision_id must not be the decision itself")
        elif self.related_decision_id is not None:
            raise ValueError(
                f"related_decision_id must be None for reason_code "
                f"{self.reason_code.value!r}"
            )

        if self.decision is Decision.ALERT:
            if not isinstance(self.payload, Mapping):
                raise ValueError("payload must be a mapping when decision is ALERT")
            object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))
        else:
            if self.payload is not None:
                raise ValueError("payload must be None unless decision is ALERT")
            if self.summary is not None:
                raise ValueError("summary must be None unless decision is ALERT")

        if self.summary_truncated and self.summary is None:
            raise ValueError("summary_truncated requires a summary")


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeliveryAttempt:
    """
    One attempt to deliver one decision to one channel.

    The attempt's identity does not depend on its result.  An attempt with no
    DeliveryOutcomeRecord is one whose result is unknown.
    """

    attempt_id: str
    decision_id: str
    channel_name: str
    channel_type: ChannelType
    attempt_no: int
    trigger: DeliveryTrigger
    summary_included: bool
    payload_sha256: str
    started_at: datetime

    def __post_init__(self) -> None:
        _require_digest(self.attempt_id, "attempt_id")
        _require_digest(self.decision_id, "decision_id")
        validate_identifier(self.channel_name, "channel_name")
        _require_enum(self.channel_type, ChannelType, "channel_type")
        if isinstance(self.attempt_no, bool) or not isinstance(self.attempt_no, int):
            raise ValueError(
                f"attempt_no must be int, got {type(self.attempt_no).__name__}"
            )
        if self.attempt_no < 1:
            raise ValueError(f"attempt_no must be >= 1, got {self.attempt_no}")
        _require_enum(self.trigger, DeliveryTrigger, "trigger")
        _require_bool(self.summary_included, "summary_included")
        _require_digest(self.payload_sha256, "payload_sha256")
        _require_aware_datetime(self.started_at, "started_at")


@dataclass(frozen=True)
class DeliveryOutcomeRecord:
    """
    The single recorded result of one delivery attempt.

    detail is a short code such as 'http_503'; it never holds a URL, a
    header, or a response body.
    """

    attempt_id: str
    outcome: DeliveryOutcome
    detail: Optional[str]
    recorded_at: datetime

    def __post_init__(self) -> None:
        _require_digest(self.attempt_id, "attempt_id")
        _require_enum(self.outcome, DeliveryOutcome, "outcome")
        _require_optional_str(self.detail, "detail")
        _require_aware_datetime(self.recorded_at, "recorded_at")


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GuardrailFinding:
    """
    Result of one report-only guardrail check.

    count is the number of offending items; it is 0 when status is OK.
    """

    code: str
    status: GuardrailStatus
    count: int
    detail: str

    def __post_init__(self) -> None:
        _require_non_empty_str(self.code, "code")
        _require_enum(self.status, GuardrailStatus, "status")
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise ValueError(f"count must be int, got {type(self.count).__name__}")
        if self.count < 0:
            raise ValueError(f"count must be >= 0, got {self.count}")
        if self.status is GuardrailStatus.OK and self.count != 0:
            raise ValueError("count must be 0 when status is OK")
        if not isinstance(self.detail, str):
            raise ValueError(f"detail must be str, got {type(self.detail).__name__}")

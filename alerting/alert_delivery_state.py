"""
alerting/alert_delivery_state.py

Phase 13.5: Delivery state of one alert on one channel.

The delivery state is never stored.  It is derived from the append-only
delivery records of one (decision_id, channel_name) pair:

    derive_state(attempts, outcomes, evaluated_at=..., now=..., ...)

The functions here are pure.  They read no clock, no environment and no
database: the current time and every setting are supplied by the caller.

States
------
T is the latest attempt, the one with the highest attempt_no.

    SENT                any attempt has the outcome SENT
    NEVER_ATTEMPTED     there is no attempt
    IN_FLIGHT           T has no outcome and
                        now - T.started_at <= timeout_seconds + 30 seconds
    UNCERTAIN           T has no outcome and is older than that, or
                        T has the outcome UNCERTAIN
    PERMANENTLY_FAILED  T has the outcome FAILED_PERMANENT
    RETRYABLE           T has the outcome FAILED_RETRYABLE and
                        T.attempt_no < max_attempts
    EXHAUSTED           T has the outcome FAILED_RETRYABLE and
                        T.attempt_no >= max_attempts
    EXPIRED             the state would be NEVER_ATTEMPTED or RETRYABLE and
                        now - evaluated_at > max_delivery_age_minutes

Exactly max_delivery_age_minutes old is not expired, and an evaluated_at
later than now is not expired.  An attempt that started later than now is
IN_FLIGHT.  Attempts made by an operator count like any other attempt.

Eligibility
-----------
    automatic   NEVER_ATTEMPTED, RETRYABLE
    operator    EXHAUSTED, PERMANENTLY_FAILED, EXPIRED;
                UNCERTAIN only with an explicit confirmation, because the
                alert may already have been delivered
    nobody      SENT, IN_FLIGHT

Fail closed
-----------
A history that cannot have been written by the notifier raises
DeliveryHistoryError and yields no state, so nothing is sent on the basis of
it.  All datetimes must be timezone-aware; they are converted to UTC before
they are compared.

Standard library and the locked alerting contracts only.

Public API:
    DeliveryState               — the eight states
    IN_FLIGHT_GRACE             — 30 seconds
    DeliveryHistoryError        — the delivery records are not consistent
    REFUSAL_*                   — fixed refusal codes
    derive_state()              — the state of one decision on one channel
    next_attempt_no()           — the number of the next attempt
    check_eligibility()         — None when an attempt is allowed
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional, Sequence

from alert_identity import compute_attempt_id
from alert_models import (
    DeliveryAttempt,
    DeliveryOutcome,
    DeliveryOutcomeRecord,
    DeliveryTrigger,
)


class DeliveryState(Enum):
    SENT = "SENT"
    NEVER_ATTEMPTED = "NEVER_ATTEMPTED"
    IN_FLIGHT = "IN_FLIGHT"
    UNCERTAIN = "UNCERTAIN"
    PERMANENTLY_FAILED = "PERMANENTLY_FAILED"
    RETRYABLE = "RETRYABLE"
    EXHAUSTED = "EXHAUSTED"
    EXPIRED = "EXPIRED"


#: An attempt without an outcome is in flight for the channel's timeout plus
#: this margin; after that its result is unknown.
IN_FLIGHT_GRACE: timedelta = timedelta(seconds=30)

#: The alert has been delivered on this channel.
REFUSAL_ALREADY_SENT: str = "already_sent"
#: An attempt is still in flight.
REFUSAL_IN_FLIGHT: str = "in_flight"
#: The state needs an operator; the automatic run does not act on it.
REFUSAL_NOT_AUTO_ELIGIBLE: str = "not_auto_eligible"
#: The alert may already have been delivered; resending must be confirmed.
REFUSAL_CONFIRM_RESEND_REQUIRED: str = "confirm_resend_required"
#: The automatic run handles this state; an operator retry is not needed.
REFUSAL_USE_NOTIFY: str = "use_notify"

_AUTO_ALLOWED = frozenset({
    DeliveryState.NEVER_ATTEMPTED,
    DeliveryState.RETRYABLE,
})
_OPERATOR_ALLOWED = frozenset({
    DeliveryState.EXHAUSTED,
    DeliveryState.PERMANENTLY_FAILED,
    DeliveryState.EXPIRED,
})


class DeliveryHistoryError(ValueError):
    """Raised when delivery records are inconsistent or malformed."""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _to_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise DeliveryHistoryError(
            f"{field} must be datetime, got {type(value).__name__}"
        )
    if value.tzinfo is None or value.utcoffset() is None:
        raise DeliveryHistoryError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError:
        raise DeliveryHistoryError(
            f"{field} cannot be represented in UTC"
        ) from None


def _positive_int(value: Any, field: str) -> int:
    # bool is a subclass of int in Python — must be rejected explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DeliveryHistoryError(f"{field} must be an integer >= 1")
    return value


def _ordered_attempts(
    attempts: Any,
    decision_id: Optional[str],
    channel_name: Optional[str],
) -> list[DeliveryAttempt]:
    """Validate the attempts of one pair and return them by attempt_no."""
    if not isinstance(attempts, (list, tuple)):
        raise DeliveryHistoryError("attempts must be a list or tuple")
    for position, attempt in enumerate(attempts):
        if not isinstance(attempt, DeliveryAttempt):
            raise DeliveryHistoryError(
                f"attempt {position} must be DeliveryAttempt, "
                f"got {type(attempt).__name__}"
            )
    if not attempts:
        return []

    expected_decision = decision_id if decision_id is not None else attempts[0].decision_id
    expected_channel = channel_name if channel_name is not None else attempts[0].channel_name

    ordered = sorted(attempts, key=lambda attempt: attempt.attempt_no)
    for position, attempt in enumerate(ordered, start=1):
        if attempt.decision_id != expected_decision:
            raise DeliveryHistoryError("an attempt belongs to another decision")
        if attempt.channel_name != expected_channel:
            raise DeliveryHistoryError("an attempt belongs to another channel")
        if attempt.attempt_no != position:
            raise DeliveryHistoryError(
                "attempt numbers must be exactly 1..n without repeats or gaps"
            )
        if attempt.attempt_id != compute_attempt_id(
            attempt.decision_id, attempt.channel_name, attempt.attempt_no,
        ):
            raise DeliveryHistoryError(
                f"attempt {attempt.attempt_no} does not carry its own identity"
            )
        _to_utc(attempt.started_at, f"attempt {attempt.attempt_no} started_at")
    return ordered


def _outcomes_by_attempt(
    outcomes: Any,
    ordered: Sequence[DeliveryAttempt],
) -> dict[str, DeliveryOutcomeRecord]:
    if not isinstance(outcomes, (list, tuple)):
        raise DeliveryHistoryError("outcomes must be a list or tuple")
    known = {attempt.attempt_id for attempt in ordered}
    by_attempt: dict[str, DeliveryOutcomeRecord] = {}
    for position, outcome in enumerate(outcomes):
        if not isinstance(outcome, DeliveryOutcomeRecord):
            raise DeliveryHistoryError(
                f"outcome {position} must be DeliveryOutcomeRecord, "
                f"got {type(outcome).__name__}"
            )
        if outcome.attempt_id not in known:
            raise DeliveryHistoryError("an outcome refers to an unknown attempt")
        if outcome.attempt_id in by_attempt:
            raise DeliveryHistoryError("an attempt has more than one outcome")
        _to_utc(outcome.recorded_at, f"outcome {position} recorded_at")
        by_attempt[outcome.attempt_id] = outcome
    return by_attempt


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def derive_state(
    attempts: Sequence[DeliveryAttempt],
    outcomes: Sequence[DeliveryOutcomeRecord],
    *,
    evaluated_at: datetime,
    now: datetime,
    max_attempts: int,
    timeout_seconds: int,
    max_delivery_age_minutes: int,
    decision_id: Optional[str] = None,
    channel_name: Optional[str] = None,
) -> DeliveryState:
    """
    Derive the delivery state of one decision on one channel.

    Parameters
    ----------
    attempts, outcomes
        Every delivery record of the pair, in any order.
    evaluated_at
        The decision's evaluation time; the delivery age is measured from it.
    now
        The current time, supplied by the caller.
    max_attempts, timeout_seconds
        The channel's settings.
    max_delivery_age_minutes
        The delivery policy's setting.
    decision_id, channel_name
        When given, every attempt must belong to this pair.

    Raises
    ------
    DeliveryHistoryError
        A datetime is not timezone-aware; an attempt belongs to another
        decision or channel; attempt numbers are not exactly 1..n; an attempt
        does not carry its own identity; an outcome refers to an unknown
        attempt; an attempt has two outcomes; or a setting is not a positive
        integer.  No state is returned.
    """
    now_utc = _to_utc(now, "now")
    evaluated_utc = _to_utc(evaluated_at, "evaluated_at")
    _positive_int(max_attempts, "max_attempts")
    _positive_int(timeout_seconds, "timeout_seconds")
    _positive_int(max_delivery_age_minutes, "max_delivery_age_minutes")

    ordered = _ordered_attempts(attempts, decision_id, channel_name)
    by_attempt = _outcomes_by_attempt(outcomes, ordered)

    # 1. Delivered: any SENT outcome, whatever came after it.
    if any(
        outcome.outcome is DeliveryOutcome.SENT for outcome in by_attempt.values()
    ):
        return DeliveryState.SENT

    # 2 and 3. Base state from the latest attempt.
    if not ordered:
        base = DeliveryState.NEVER_ATTEMPTED
    else:
        latest = ordered[-1]
        outcome = by_attempt.get(latest.attempt_id)
        if outcome is None:
            age = now_utc - _to_utc(latest.started_at, "started_at")
            limit = timedelta(seconds=timeout_seconds) + IN_FLIGHT_GRACE
            base = (
                DeliveryState.IN_FLIGHT if age <= limit
                else DeliveryState.UNCERTAIN
            )
        elif outcome.outcome is DeliveryOutcome.UNCERTAIN:
            base = DeliveryState.UNCERTAIN
        elif outcome.outcome is DeliveryOutcome.FAILED_PERMANENT:
            base = DeliveryState.PERMANENTLY_FAILED
        elif latest.attempt_no < max_attempts:
            base = DeliveryState.RETRYABLE
        else:
            base = DeliveryState.EXHAUSTED

    # 4. Expiry applies only where the automatic run would still act.
    if base in _AUTO_ALLOWED:
        try:
            max_age = timedelta(minutes=max_delivery_age_minutes)
        except OverflowError:
            return base
        if now_utc - evaluated_utc > max_age:
            return DeliveryState.EXPIRED
    return base


def next_attempt_no(attempts: Sequence[DeliveryAttempt]) -> int:
    """The number of the next attempt: the highest attempt_no plus one."""
    return max((attempt.attempt_no for attempt in attempts), default=0) + 1


def check_eligibility(
    state: DeliveryState,
    trigger: DeliveryTrigger,
    *,
    confirm_resend: bool = False,
) -> Optional[str]:
    """
    Decide whether an attempt may be made.

    Returns None when the attempt is allowed, otherwise one of the REFUSAL_*
    codes.  confirm_resend matters only for an operator attempt on an
    UNCERTAIN delivery.

    Raises:
        ValueError  if state, trigger or confirm_resend has the wrong type.
    """
    if not isinstance(state, DeliveryState):
        raise ValueError(
            f"state must be DeliveryState, got {type(state).__name__}"
        )
    if not isinstance(trigger, DeliveryTrigger):
        raise ValueError(
            f"trigger must be DeliveryTrigger, got {type(trigger).__name__}"
        )
    if not isinstance(confirm_resend, bool):
        raise ValueError(
            f"confirm_resend must be bool, got {type(confirm_resend).__name__}"
        )

    if state is DeliveryState.SENT:
        return REFUSAL_ALREADY_SENT
    if state is DeliveryState.IN_FLIGHT:
        return REFUSAL_IN_FLIGHT

    if trigger is DeliveryTrigger.AUTO:
        if state in _AUTO_ALLOWED:
            return None
        return REFUSAL_NOT_AUTO_ELIGIBLE

    if state in _OPERATOR_ALLOWED:
        return None
    if state is DeliveryState.UNCERTAIN:
        return None if confirm_resend else REFUSAL_CONFIRM_RESEND_REQUIRED
    return REFUSAL_USE_NOTIFY

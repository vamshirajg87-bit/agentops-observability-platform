"""
alerting/alert_notifier.py

Phase 13.5: Alert notification.

Delivers persisted ALERT decisions to the enabled channels of the delivery
policy and records every attempt and its outcome.

Only the decision snapshot is used: the notification body is built from the
payload stored with the decision.  Nothing is read from RCA, anomaly or
telemetry data, and no decision is ever evaluated here.

One attempt
-----------
For one decision on one channel:

    T1   read the delivery records again -> derive the state -> check that
         an attempt is allowed -> take the next attempt number -> build the
         body -> write the attempt row -> commit
    send the body, with no transaction open
    T2   write the outcome row -> commit

The committed attempt row is the durable record that an attempt started.
Nothing is sent unless this process wrote and committed that row itself:

    the attempt is not allowed      nothing is written, nothing is sent
    the attempt row was not written another writer owns that attempt number;
                                    nothing is sent and no other number is
                                    tried ('lost_race')
    T1 fails                        rolled back, nothing is sent

If the outcome cannot be recorded, or the process stops after T1, the attempt
keeps no outcome.  It is then in flight, and later uncertain: the alert may
have been delivered, so only an operator may resend it.

Automatic run
-------------
run_notify() takes every ALERT decision, oldest evaluation first (then
decision_id), and for each the enabled channels in policy order.  It makes at
most one attempt per decision and channel, never waits and never repeats.
It acts only on deliveries that were never attempted or failed retryably,
and not once they have expired.  A decision of any policy version is
delivered under the delivery settings supplied by the caller.

Operator retry
--------------
retry_delivery() makes one attempt for a delivery the automatic run will not
touch: exhausted, permanently failed, expired, or — only with an explicit
confirmation — uncertain.

Dry run
-------
With dry_run=True the state and the body are computed and nothing is written,
committed or sent.  The number the next attempt would get is reported; no
attempt identity is computed.

Failure policy
--------------
Malformed stored data for one decision and channel is reported as
'invalid_data' and the run continues.  A database error stops the run and
propagates; the open transaction is rolled back first.  KeyboardInterrupt is
not caught and no outcome is written for an interrupted delivery.

This module commits and rolls back on the supplied connection and never
closes it.  Database access goes through alert_delivery_store; this module
contains no database statement and does not import a database driver.  It
reads no clock and no environment: the current time and the prepared
channels are supplied by the caller.

Public API:
    STATUS_ATTEMPTED, STATUS_BLOCKED, STATUS_REFUSED, STATUS_LOST_RACE,
    STATUS_INVALID_DATA, STATUS_WOULD_ATTEMPT
    REASON_INVALID_HISTORY, REASON_INVALID_DECISION, REASON_OUTCOME_EXISTS,
    REASON_CHANNEL_DISABLED
    STATE_INVALID                — label for an inconsistent history
    DecisionNotFoundError
    DeliveryResult               — what happened for one decision and channel
    NotifyReport                 — all results of one run, with counts
    AttemptView, AlertView       — read-only views for the admin commands
    run_notify()                 — the automatic run
    retry_delivery()             — one operator attempt
    list_alerts(), show_alert()  — read-only views
    format_result()              — one line of text for a result
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, BinaryIO, Callable, Mapping, Optional, Sequence

import alert_channels
import alert_delivery_store
from alert_channels import DETAIL_BODY_TOO_LARGE, PreparedChannel, build_body
from alert_delivery_state import (
    REFUSAL_USE_NOTIFY,
    DeliveryHistoryError,
    DeliveryState,
    check_eligibility,
    derive_state,
    next_attempt_no,
)
from alert_identity import compute_attempt_id, is_sha256_hex
from alert_models import (
    ChannelType,
    Decision,
    DeliveryAttempt,
    DeliveryOutcome,
    DeliveryOutcomeRecord,
    DeliveryTrigger,
)
from alert_policy import ChannelConfig, DeliveryPolicy


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: An attempt was made by this call; outcome and detail say how it ended.
STATUS_ATTEMPTED: str = "attempted"
#: Automatic run: the delivery state does not allow an attempt.
STATUS_BLOCKED: str = "blocked"
#: Operator retry: the attempt was refused; nothing was written.
STATUS_REFUSED: str = "refused"
#: Another writer owns the attempt number; nothing was sent.
STATUS_LOST_RACE: str = "lost_race"
#: Stored data is malformed; nothing was sent.
STATUS_INVALID_DATA: str = "invalid_data"
#: Dry run: an attempt would be made.
STATUS_WOULD_ATTEMPT: str = "would_attempt"

REASON_INVALID_HISTORY: str = "invalid_history"
REASON_INVALID_DECISION: str = "invalid_decision"
REASON_OUTCOME_EXISTS: str = "outcome_exists"
REASON_CHANNEL_DISABLED: str = "channel_disabled"

#: Shown in place of a state when the delivery records are inconsistent.
STATE_INVALID: str = "INVALID"

SUMMARY_STORED_NO: str = "no"
SUMMARY_STORED_YES: str = "yes"
SUMMARY_STORED_TRUNCATED: str = "truncated"


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class DecisionNotFoundError(Exception):
    """Raised when decision_id does not exist or is not an ALERT decision."""

    def __init__(self, decision_id: str) -> None:
        super().__init__(f"alert decision not found: {decision_id!r}")
        self.decision_id = decision_id


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeliveryResult:
    """
    What happened for one decision on one channel.

    Attributes
    ----------
    status
        One of the STATUS_* values.
    state
        The delivery state the action was based on, when it was derived.
    attempt_no
        The attempt made, or the attempt a dry run would make.
    attempt_id
        The identity of an attempt that was written; never set by a dry run.
    outcome, detail
        How an attempt ended.  For a dry run, detail is 'body_too_large'
        when the attempt would fail for that reason.
    reason
        Fixed code explaining a 'blocked', 'refused' or 'invalid_data'.
    """

    decision_id: Any
    channel_name: str
    status: str
    state: Optional[DeliveryState] = None
    attempt_no: Optional[int] = None
    attempt_id: Optional[str] = None
    outcome: Optional[DeliveryOutcome] = None
    detail: Optional[str] = None
    reason: Optional[str] = None

    @property
    def is_problem(self) -> bool:
        """True when this result makes a run 'completed with problems'."""
        if self.status == STATUS_ATTEMPTED:
            return self.outcome is not DeliveryOutcome.SENT
        if self.status == STATUS_WOULD_ATTEMPT:
            return self.detail is not None
        return self.status in (
            STATUS_REFUSED, STATUS_LOST_RACE, STATUS_INVALID_DATA,
        )


@dataclass(frozen=True)
class NotifyReport:
    """
    Outcome of one run_notify() call: one result per decision and enabled
    channel, in processing order.
    """

    results: tuple[DeliveryResult, ...]
    dry_run: bool

    def count(self, status: str) -> int:
        """Number of results with the given status."""
        return sum(1 for result in self.results if result.status == status)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def attempted(self) -> int:
        return self.count(STATUS_ATTEMPTED)

    @property
    def sent(self) -> int:
        return sum(
            1 for result in self.results
            if result.status == STATUS_ATTEMPTED
            and result.outcome is DeliveryOutcome.SENT
        )

    @property
    def not_sent(self) -> int:
        return self.attempted - self.sent

    @property
    def blocked(self) -> int:
        return self.count(STATUS_BLOCKED)

    @property
    def lost_races(self) -> int:
        return self.count(STATUS_LOST_RACE)

    @property
    def invalid(self) -> int:
        return self.count(STATUS_INVALID_DATA)

    @property
    def would_attempt(self) -> int:
        return self.count(STATUS_WOULD_ATTEMPT)

    @property
    def problems(self) -> int:
        return sum(1 for result in self.results if result.is_problem)

    @property
    def succeeded(self) -> bool:
        """True when no result is a problem."""
        return self.problems == 0


@dataclass(frozen=True)
class AttemptView:
    """One stored attempt with its outcome, as text for display."""

    channel_name: Any
    channel_type: Any
    attempt_no: Any
    trigger: Any
    attempt_id: Any
    summary_included: Any
    payload_sha256: Any
    started_at: Any
    outcome: Any
    detail: Any
    recorded_at: Any


@dataclass(frozen=True)
class AlertView:
    """
    One ALERT decision for display.

    states holds (channel name, state) for every channel given to the view
    function, in that order; the state is a DeliveryState value or
    STATE_INVALID.  summary_stored says only whether a summary is stored.
    The summary text is not part of the view.
    """

    decision_id: Any
    policy_version: Any
    reason_code: Any
    evaluated_at: Any
    payload: Optional[Mapping[str, Any]]
    summary_stored: str
    states: tuple[tuple[str, str], ...]
    attempts: tuple[AttemptView, ...] = ()


# ---------------------------------------------------------------------------
# Row mapping (pure)
# ---------------------------------------------------------------------------

def _to_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{field} must be datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _records(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[tuple[DeliveryAttempt, ...], tuple[DeliveryOutcomeRecord, ...]]:
    """Map stored rows to the locked models; any defect is a history error."""
    attempts: list[DeliveryAttempt] = []
    outcomes: list[DeliveryOutcomeRecord] = []
    try:
        for row in rows:
            attempts.append(DeliveryAttempt(
                attempt_id=row["attempt_id"],
                decision_id=row["decision_id"],
                channel_name=row["channel_name"],
                channel_type=ChannelType(row["channel_type"]),
                attempt_no=row["attempt_no"],
                trigger=DeliveryTrigger(row["trigger"]),
                summary_included=row["summary_included"],
                payload_sha256=row["payload_sha256"],
                started_at=row["started_at"],
            ))
            if row["outcome"] is not None:
                outcomes.append(DeliveryOutcomeRecord(
                    attempt_id=row["attempt_id"],
                    outcome=DeliveryOutcome(row["outcome"]),
                    detail=row["detail"],
                    recorded_at=row["recorded_at"],
                ))
    except DeliveryHistoryError:
        raise
    except ValueError:
        raise DeliveryHistoryError("a stored delivery record is malformed") from None
    return tuple(attempts), tuple(outcomes)


def _check_decision(decision: Mapping[str, Any]) -> None:
    """Raise ValueError unless the row is a usable ALERT decision."""
    if not is_sha256_hex(decision["decision_id"]):
        raise ValueError("decision_id is not a digest")
    if decision["decision"] != Decision.ALERT.value:
        raise ValueError("the decision is not an ALERT")
    _to_utc(decision["evaluated_at"], "evaluated_at")


def _pair_state(
    rows: Sequence[Mapping[str, Any]],
    decision: Mapping[str, Any],
    config: ChannelConfig,
    delivery: DeliveryPolicy,
    now: datetime,
) -> tuple[DeliveryState, tuple[DeliveryAttempt, ...]]:
    attempts, outcomes = _records(rows)
    state = derive_state(
        attempts,
        outcomes,
        evaluated_at=decision["evaluated_at"],
        now=now,
        max_attempts=config.max_attempts,
        timeout_seconds=config.timeout_seconds,
        max_delivery_age_minutes=delivery.max_delivery_age_minutes,
        decision_id=decision["decision_id"],
        channel_name=config.name,
    )
    return state, attempts


def _invalid(decision_id: Any, channel_name: str, exc: ValueError) -> DeliveryResult:
    reason = (
        REASON_INVALID_HISTORY if isinstance(exc, DeliveryHistoryError)
        else REASON_INVALID_DECISION
    )
    return DeliveryResult(
        decision_id=decision_id,
        channel_name=channel_name,
        status=STATUS_INVALID_DATA,
        reason=reason,
    )


def _group(rows: Sequence[Mapping[str, Any]]) -> dict[tuple[Any, Any], list]:
    grouped: dict[tuple[Any, Any], list] = {}
    for row in rows:
        grouped.setdefault((row["decision_id"], row["channel_name"]), []).append(row)
    return grouped


# ---------------------------------------------------------------------------
# One attempt
# ---------------------------------------------------------------------------

def _attempt(
    conn: Any,
    prepared: PreparedChannel,
    delivery: DeliveryPolicy,
    decision: Mapping[str, Any],
    *,
    now: datetime,
    trigger: DeliveryTrigger,
    confirm_resend: bool,
    dry_run: bool,
    log_stream: Optional[BinaryIO],
) -> DeliveryResult:
    """T1, the delivery, and T2 for one decision on one channel."""
    config = prepared.config
    decision_id = decision["decision_id"]
    name = config.name

    # T1: everything up to the committed attempt row.
    try:
        _check_decision(decision)
        rows = alert_delivery_store.fetch_channel_history(conn, decision_id, name)
        state, attempts = _pair_state(rows, decision, config, delivery, now)

        refusal = check_eligibility(state, trigger, confirm_resend=confirm_resend)
        if refusal is not None:
            conn.rollback()
            return DeliveryResult(
                decision_id=decision_id,
                channel_name=name,
                status=(
                    STATUS_BLOCKED if trigger is DeliveryTrigger.AUTO
                    else STATUS_REFUSED
                ),
                state=state,
                reason=refusal,
            )

        attempt_no = next_attempt_no(attempts)
        body = build_body(
            decision["payload"],
            decision["summary"],
            decision["summary_truncated"],
            include_summary=config.include_summary,
        )

        if dry_run:
            conn.rollback()
            return DeliveryResult(
                decision_id=decision_id,
                channel_name=name,
                status=STATUS_WOULD_ATTEMPT,
                state=state,
                attempt_no=attempt_no,
                detail=(
                    DETAIL_BODY_TOO_LARGE
                    if alert_channels.exceeds_webhook_limit(prepared, body)
                    else None
                ),
            )

        attempt_id = compute_attempt_id(decision_id, name, attempt_no)
        inserted = alert_delivery_store.insert_attempt(
            conn,
            attempt_id=attempt_id,
            decision_id=decision_id,
            channel_name=name,
            channel_type=config.type.value,
            attempt_no=attempt_no,
            trigger=trigger.value,
            summary_included=body.summary_included,
            payload_sha256=body.sha256,
        )
        if not inserted:
            # Another writer owns this attempt number.  Nothing is sent and
            # no other number is tried.
            conn.rollback()
            return DeliveryResult(
                decision_id=decision_id,
                channel_name=name,
                status=STATUS_LOST_RACE,
                state=state,
                attempt_no=attempt_no,
            )
        conn.commit()
    except ValueError as exc:
        conn.rollback()
        return _invalid(decision_id, name, exc)
    except Exception:
        conn.rollback()
        raise

    # The delivery: the attempt is durable and no transaction is open.
    result = alert_channels.send(
        prepared,
        body,
        decision_id=decision_id,
        attempt_no=attempt_no,
        log_stream=log_stream,
    )

    # T2: the outcome.
    try:
        recorded = alert_delivery_store.insert_outcome(
            conn, attempt_id=attempt_id, result=result,
        )
        if recorded:
            conn.commit()
        else:
            conn.rollback()
    except Exception:
        conn.rollback()
        raise

    if not recorded:
        # The attempt already has an outcome that this call did not write.
        return DeliveryResult(
            decision_id=decision_id,
            channel_name=name,
            status=STATUS_INVALID_DATA,
            state=state,
            attempt_no=attempt_no,
            attempt_id=attempt_id,
            reason=REASON_OUTCOME_EXISTS,
        )
    return DeliveryResult(
        decision_id=decision_id,
        channel_name=name,
        status=STATUS_ATTEMPTED,
        state=state,
        attempt_no=attempt_no,
        attempt_id=attempt_id,
        outcome=result.outcome,
        detail=result.detail,
    )


# ---------------------------------------------------------------------------
# Automatic run
# ---------------------------------------------------------------------------

def run_notify(
    conn: Any,
    channels: Sequence[PreparedChannel],
    delivery: DeliveryPolicy,
    *,
    now: datetime,
    dry_run: bool = False,
    log_stream: Optional[BinaryIO] = None,
    on_result: Optional[Callable[[DeliveryResult], None]] = None,
) -> NotifyReport:
    """
    Deliver every ALERT decision to every enabled channel that still needs
    it.

    Parameters
    ----------
    conn
        Open connection for the alert_notifier role.  The caller owns the
        connection lifecycle; this function does NOT close it.  It must not
        carry uncommitted work of the caller.  For a dry run the caller
        should supply a read-only session.
    channels
        The prepared channels to deliver to, in policy order.  A disabled
        channel is skipped; an empty sequence delivers nothing.
    delivery
        The delivery section of the policy.
    now
        The time of this run: one timezone-aware value, used for every
        state.
    dry_run
        When True, nothing is written, committed or sent.
    log_stream
        Binary stream of the log channel.
    on_result
        Optional callback invoked with each DeliveryResult as soon as it is
        known, in processing order.

    Returns
    -------
    NotifyReport
        One result per decision and enabled channel.

    Raises
    ------
    ValueError
        now is not a timezone-aware datetime, or delivery is not a
        DeliveryPolicy.  Raised before the database is used.
    database error
        Any error of the database driver.  The run stops; attempts and
        outcomes committed earlier stay committed.
    KeyboardInterrupt
        Not caught; the run stops and no further outcome is written.
    """
    if not isinstance(delivery, DeliveryPolicy):
        raise ValueError(
            f"delivery must be DeliveryPolicy, got {type(delivery).__name__}"
        )
    now_utc = _to_utc(now, "now")
    enabled = [prepared for prepared in channels if prepared.config.enabled]

    results: list[DeliveryResult] = []
    if not enabled:
        return NotifyReport(results=(), dry_run=dry_run)

    try:
        decisions = alert_delivery_store.fetch_alert_decisions(conn)
        history = alert_delivery_store.fetch_delivery_history(
            conn, [decision["decision_id"] for decision in decisions],
        )
    except Exception:
        conn.rollback()
        raise

    # End the read-only discovery transaction: every attempt runs in
    # transactions of its own, and none is open while something is sent.
    conn.rollback()
    grouped = _group(history)

    for decision in decisions:
        decision_id = decision["decision_id"]
        for prepared in enabled:
            name = prepared.config.name
            try:
                _check_decision(decision)
                state, _ = _pair_state(
                    grouped.get((decision_id, name), ()),
                    decision, prepared.config, delivery, now_utc,
                )
                refusal = check_eligibility(state, DeliveryTrigger.AUTO)
            except ValueError as exc:
                result = _invalid(decision_id, name, exc)
            else:
                if refusal is not None:
                    result = DeliveryResult(
                        decision_id=decision_id,
                        channel_name=name,
                        status=STATUS_BLOCKED,
                        state=state,
                        reason=refusal,
                    )
                else:
                    result = _attempt(
                        conn, prepared, delivery, decision,
                        now=now_utc,
                        trigger=DeliveryTrigger.AUTO,
                        confirm_resend=False,
                        dry_run=dry_run,
                        log_stream=log_stream,
                    )

            results.append(result)
            if on_result is not None:
                on_result(result)

    return NotifyReport(results=tuple(results), dry_run=dry_run)


# ---------------------------------------------------------------------------
# Operator retry
# ---------------------------------------------------------------------------

def retry_delivery(
    conn: Any,
    prepared: PreparedChannel,
    delivery: DeliveryPolicy,
    decision_id: str,
    *,
    now: datetime,
    confirm_resend: bool = False,
    dry_run: bool = False,
    log_stream: Optional[BinaryIO] = None,
) -> DeliveryResult:
    """
    Make one operator attempt for one decision on one channel.

    The attempt is allowed only for a delivery that is exhausted,
    permanently failed or expired, or — with confirm_resend — uncertain.
    A refusal writes nothing and sends nothing.

    Raises
    ------
    ValueError
        now is not a timezone-aware datetime, or delivery is not a
        DeliveryPolicy.  Raised before the database is used.
    DecisionNotFoundError
        decision_id does not exist or is not an ALERT decision.
    database error
        Any error of the database driver.
    KeyboardInterrupt
        Not caught.
    """
    if not isinstance(delivery, DeliveryPolicy):
        raise ValueError(
            f"delivery must be DeliveryPolicy, got {type(delivery).__name__}"
        )
    now_utc = _to_utc(now, "now")

    if not prepared.config.enabled:
        return DeliveryResult(
            decision_id=decision_id,
            channel_name=prepared.config.name,
            status=STATUS_REFUSED,
            reason=REASON_CHANNEL_DISABLED,
        )

    decision = _fetch_alert(conn, decision_id)
    return _attempt(
        conn, prepared, delivery, decision,
        now=now_utc,
        trigger=DeliveryTrigger.OPERATOR,
        confirm_resend=confirm_resend,
        dry_run=dry_run,
        log_stream=log_stream,
    )


# ---------------------------------------------------------------------------
# Read-only views
# ---------------------------------------------------------------------------

def _fetch_alert(conn: Any, decision_id: str) -> dict[str, Any]:
    try:
        decision = alert_delivery_store.fetch_decision(conn, decision_id)
    except Exception:
        conn.rollback()
        raise
    conn.rollback()
    if decision is None or decision["decision"] != Decision.ALERT.value:
        raise DecisionNotFoundError(decision_id)
    return decision


def _state_label(
    rows: Sequence[Mapping[str, Any]],
    decision: Mapping[str, Any],
    config: ChannelConfig,
    delivery: DeliveryPolicy,
    now: datetime,
) -> str:
    try:
        _check_decision(decision)
        state, _ = _pair_state(rows, decision, config, delivery, now)
    except ValueError:
        return STATE_INVALID
    return state.value


def _summary_stored(decision: Mapping[str, Any]) -> str:
    if decision["summary"] is None:
        return SUMMARY_STORED_NO
    if decision["summary_truncated"] is True:
        return SUMMARY_STORED_TRUNCATED
    return SUMMARY_STORED_YES


def _view(
    decision: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    channels: Sequence[ChannelConfig],
    delivery: DeliveryPolicy,
    now: datetime,
    *,
    with_attempts: bool,
) -> AlertView:
    grouped = _group(rows)
    decision_id = decision["decision_id"]
    payload = decision["payload"]
    attempts: tuple[AttemptView, ...] = ()
    if with_attempts:
        attempts = tuple(
            AttemptView(
                channel_name=row["channel_name"],
                channel_type=row["channel_type"],
                attempt_no=row["attempt_no"],
                trigger=row["trigger"],
                attempt_id=row["attempt_id"],
                summary_included=row["summary_included"],
                payload_sha256=row["payload_sha256"],
                started_at=row["started_at"],
                outcome=row["outcome"],
                detail=row["detail"],
                recorded_at=row["recorded_at"],
            )
            for row in rows
        )
    return AlertView(
        decision_id=decision_id,
        policy_version=decision["policy_version"],
        reason_code=decision["reason_code"],
        evaluated_at=decision["evaluated_at"],
        payload=dict(payload) if isinstance(payload, Mapping) else None,
        summary_stored=_summary_stored(decision),
        states=tuple(
            (
                config.name,
                _state_label(
                    grouped.get((decision_id, config.name), ()),
                    decision, config, delivery, now,
                ),
            )
            for config in channels
        ),
        attempts=attempts,
    )


def list_alerts(
    conn: Any,
    channels: Sequence[ChannelConfig],
    delivery: DeliveryPolicy,
    *,
    now: datetime,
    limit: int,
) -> list[AlertView]:
    """
    The newest ALERT decisions with their delivery state per channel.

    Read-only: nothing is written and the transaction is rolled back.

    Raises:
        ValueError      now is not a timezone-aware datetime.
        database error  any error of the database driver.
    """
    now_utc = _to_utc(now, "now")
    try:
        decisions = alert_delivery_store.fetch_recent_alert_decisions(conn, limit)
        history = alert_delivery_store.fetch_delivery_history(
            conn, [decision["decision_id"] for decision in decisions],
        )
    except Exception:
        conn.rollback()
        raise
    conn.rollback()

    by_decision: dict[Any, list] = {}
    for row in history:
        by_decision.setdefault(row["decision_id"], []).append(row)
    return [
        _view(
            decision, by_decision.get(decision["decision_id"], ()),
            channels, delivery, now_utc, with_attempts=False,
        )
        for decision in decisions
    ]


def show_alert(
    conn: Any,
    channels: Sequence[ChannelConfig],
    delivery: DeliveryPolicy,
    decision_id: str,
    *,
    now: datetime,
) -> AlertView:
    """
    One ALERT decision with every stored attempt and its delivery state per
    channel.  Attempts of a channel that is not in channels are listed
    without a state.

    Read-only: nothing is written and the transaction is rolled back.

    Raises:
        ValueError             now is not a timezone-aware datetime.
        DecisionNotFoundError  decision_id does not exist or is not an ALERT.
        database error         any error of the database driver.
    """
    now_utc = _to_utc(now, "now")
    decision = _fetch_alert(conn, decision_id)
    try:
        history = alert_delivery_store.fetch_delivery_history(conn, [decision_id])
    except Exception:
        conn.rollback()
        raise
    conn.rollback()
    return _view(decision, history, channels, delivery, now_utc, with_attempts=True)


# ---------------------------------------------------------------------------
# Rendering (pure)
# ---------------------------------------------------------------------------

def _one_line(value: Any) -> str:
    return " ".join(str(value).split())


def format_result(result: DeliveryResult) -> str:
    """
    One line of text for a result: decision_id, channel, then what happened.
    Holds identifiers, states and fixed codes only.
    """
    parts = [_one_line(result.decision_id), _one_line(result.channel_name)]
    state = result.state.value if result.state is not None else None

    if result.status == STATUS_ATTEMPTED:
        parts += [
            f"attempt {result.attempt_no}",
            result.outcome.value,
            _one_line(result.detail),
        ]
    elif result.status == STATUS_WOULD_ATTEMPT:
        parts.append(f"would attempt {result.attempt_no}")
        if result.detail is not None:
            parts.append(f"would fail {_one_line(result.detail)}")
    elif result.status == STATUS_LOST_RACE:
        parts += [result.status, f"attempt {result.attempt_no}"]
    else:
        parts.append(result.status)
        if state is not None:
            parts.append(state)
        if result.reason is not None:
            parts.append(_one_line(result.reason))
        if result.reason == REFUSAL_USE_NOTIFY:
            parts.append("(the automatic run handles this state)")
    return "  ".join(parts)

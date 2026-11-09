"""
alerting/alert_guardrails.py

Phase 13.6: Operational guardrails.

Four report-only checks on the detection, investigation and delivery
pipeline.  They observe and report.  They never write, never retry, never
run a detector or an analysis, and never change anything.

    detector_checkpoint_stale   an expected detection group has no
                                checkpoint, or its checkpoint is too old
    uninvestigated_anomalies    an anomaly has had no investigation for too
                                long
    delivery_uncertain          the delivery of an alert on a channel is
                                UNCERTAIN: it may or may not have arrived
    delivery_exhausted          the delivery of an alert on a channel is
                                EXHAUSTED, PERMANENTLY_FAILED or EXPIRED:
                                the automatic run will not deliver it

Results
-------
Every run returns exactly four GuardrailResult values, in the order above.
A result holds the finding (code, status, full count, fixed text) and the
identifiers of the first violations, at most MAX_DETAIL_IDS of them.

Thresholds come from the guardrails section of the alert policy.  E is the
time of a stored record and now is supplied by the caller:

    checkpoint   stale when now - updated_at  > detector_checkpoint_max_age
    anomaly      overdue when now - detected_at > uninvestigated_anomaly_max_age
    delivery     considered when evaluated_at, or the start of the latest
                 attempt, is at or after now - delivery_lookback_hours

A record exactly at a threshold is not a violation, and neither is one dated
later than now.  A delivery exactly at the lookback start is considered.

Expected detection groups
-------------------------
The policy does not say which checkpoints should exist.  The expected groups
are read from the anomaly detector's runner configuration file by
load_expected_groups(), which reads its "groups" list and nothing else.
Checkpoints of other groups are ignored.

Deliveries
----------
A delivery is one ALERT decision on one channel that is enabled in the
current policy.  Its state is derived by alert_delivery_state.derive_state,
unchanged, with the channel's current settings.  Channels that are disabled
or no longer in the policy are not considered; with no enabled channel both
delivery checks report no violation.

Fail closed
-----------
Stored data that is malformed or inconsistent raises
GuardrailEvaluationError, which carries the affected guardrail codes and a
fixed reason code and nothing else.  No result is returned in that case, so
a check that could not be completed is never reported as passed.

Standard library and the locked alerting contracts only.  Database access
goes through alert_guardrail_store; this module contains no database
statement and does not import a database driver.  It reads no clock and no
environment, and the only file it reads is the detector configuration.

Public API:
    CODE_DETECTOR_CHECKPOINT_STALE, CODE_UNINVESTIGATED_ANOMALIES,
    CODE_DELIVERY_UNCERTAIN, CODE_DELIVERY_EXHAUSTED, GUARDRAIL_CODES
    MAX_DETAIL_IDS, DETAIL_OK
    REASON_INVALID_CHECKPOINT_DATA, REASON_INVALID_ANOMALY_DATA,
    REASON_INVALID_DELIVERY_DATA, REASON_CODES
    GuardrailResult            — one finding with its identifiers (frozen)
    DetectorConfigError        — the detector configuration is not usable
    GuardrailEvaluationError   — stored data could not be evaluated
    parse_expected_groups(), load_expected_groups()
    checkpoint_detail_id(), delivery_detail_id()
    evaluate_checkpoints(), evaluate_uninvestigated(), evaluate_deliveries()
    run_guardrails()           — run all four checks
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Sequence

import alert_guardrail_store
from alert_delivery_state import DeliveryState, derive_state
from alert_identity import is_sha256_hex
from alert_models import (
    ChannelType,
    DeliveryAttempt,
    DeliveryOutcome,
    DeliveryOutcomeRecord,
    DeliveryTrigger,
    GuardrailFinding,
    GuardrailStatus,
)
from alert_policy import AlertPolicy, ChannelConfig, DeliveryPolicy


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CODE_DETECTOR_CHECKPOINT_STALE: str = "detector_checkpoint_stale"
CODE_UNINVESTIGATED_ANOMALIES: str = "uninvestigated_anomalies"
CODE_DELIVERY_UNCERTAIN: str = "delivery_uncertain"
CODE_DELIVERY_EXHAUSTED: str = "delivery_exhausted"

#: The four guardrails, in the order they are evaluated and reported.
GUARDRAIL_CODES: tuple[str, ...] = (
    CODE_DETECTOR_CHECKPOINT_STALE,
    CODE_UNINVESTIGATED_ANOMALIES,
    CODE_DELIVERY_UNCERTAIN,
    CODE_DELIVERY_EXHAUSTED,
)

#: A result names at most this many violations; its count is never capped.
MAX_DETAIL_IDS: int = 20

DETAIL_OK: str = "No violations."

REASON_INVALID_CHECKPOINT_DATA: str = "invalid_checkpoint_data"
REASON_INVALID_ANOMALY_DATA: str = "invalid_anomaly_data"
REASON_INVALID_DELIVERY_DATA: str = "invalid_delivery_data"

REASON_CODES: frozenset[str] = frozenset({
    REASON_INVALID_CHECKPOINT_DATA,
    REASON_INVALID_ANOMALY_DATA,
    REASON_INVALID_DELIVERY_DATA,
})

_GROUP_KEYS: frozenset[str] = frozenset({
    "signal_path",
    "service_name",
    "operation_name",
})

_EXHAUSTED_STATES: frozenset[DeliveryState] = frozenset({
    DeliveryState.EXHAUSTED,
    DeliveryState.PERMANENTLY_FAILED,
    DeliveryState.EXPIRED,
})

_EARLIEST: datetime = datetime.min.replace(tzinfo=timezone.utc)

ExpectedGroup = tuple[str, str, str]


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class DetectorConfigError(ValueError):
    """
    Raised when the detector configuration cannot be used.  The message is a
    fixed phrase; it never quotes a path, a value or parser output.
    """


class GuardrailEvaluationError(Exception):
    """
    Raised when stored data is malformed or inconsistent, so that a guardrail
    could not be evaluated completely.

    Carries the codes of the affected guardrails and one of REASON_CODES.
    It holds no stored value and no message of an underlying error.
    """

    def __init__(self, guardrail_codes: Sequence[str], reason_code: str) -> None:
        codes = tuple(guardrail_codes)
        if not codes or any(code not in GUARDRAIL_CODES for code in codes):
            raise ValueError("guardrail_codes must name known guardrails")
        if reason_code not in REASON_CODES:
            raise ValueError("reason_code is not a known reason code")
        super().__init__(f"{','.join(codes)}: {reason_code}")
        self.guardrail_codes = codes
        self.reason_code = reason_code


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

def violation_detail(count: int, shown: int) -> str:
    """The fixed text of a VIOLATION finding."""
    return f"{count} violation(s); showing {shown} of {count}."


@dataclass(frozen=True)
class GuardrailResult:
    """
    The result of one guardrail.

    finding.count is the full number of violations.  detail_ids names the
    first of them in a deterministic order, at most MAX_DETAIL_IDS.

        OK         count 0, no identifiers, detail DETAIL_OK
        VIOLATION  count >= 1, min(count, MAX_DETAIL_IDS) identifiers,
                   detail violation_detail(count, len(detail_ids))
    """

    finding: GuardrailFinding
    detail_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.finding, GuardrailFinding):
            raise ValueError(
                "finding must be GuardrailFinding, "
                f"got {type(self.finding).__name__}"
            )
        if self.finding.code not in GUARDRAIL_CODES:
            raise ValueError("finding.code is not a known guardrail code")
        if not isinstance(self.detail_ids, tuple) or not all(
            isinstance(item, str) for item in self.detail_ids
        ):
            raise ValueError("detail_ids must be a tuple of str")

        count = self.finding.count
        if self.finding.status is GuardrailStatus.OK:
            if count != 0 or self.detail_ids != ():
                raise ValueError("an OK result has count 0 and no identifiers")
            if self.finding.detail != DETAIL_OK:
                raise ValueError("an OK result has the fixed OK detail")
            return

        if count < 1:
            raise ValueError("a VIOLATION result has count >= 1")
        if len(self.detail_ids) != min(count, MAX_DETAIL_IDS):
            raise ValueError(
                "a VIOLATION result names min(count, MAX_DETAIL_IDS) violations"
            )
        if self.finding.detail != violation_detail(count, len(self.detail_ids)):
            raise ValueError("a VIOLATION result has the fixed violation detail")


def _ok(code: str) -> GuardrailResult:
    return GuardrailResult(
        finding=GuardrailFinding(
            code=code, status=GuardrailStatus.OK, count=0, detail=DETAIL_OK,
        ),
        detail_ids=(),
    )


def _result(code: str, ordered_ids: Sequence[str]) -> GuardrailResult:
    """A result from every violation's identifier, already in final order."""
    count = len(ordered_ids)
    if count == 0:
        return _ok(code)
    shown = tuple(ordered_ids[:MAX_DETAIL_IDS])
    return GuardrailResult(
        finding=GuardrailFinding(
            code=code,
            status=GuardrailStatus.VIOLATION,
            count=count,
            detail=violation_detail(count, len(shown)),
        ),
        detail_ids=shown,
    )


# ---------------------------------------------------------------------------
# Detector configuration
# ---------------------------------------------------------------------------

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DetectorConfigError("a JSON object repeats a key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise DetectorConfigError("the file holds NaN or Infinity")


def _required_name(group: Mapping[str, Any], key: str, index: int) -> str:
    if key not in group:
        raise DetectorConfigError(f"group {index}: '{key}' is required")
    value = group[key]
    if not isinstance(value, str):
        raise DetectorConfigError(f"group {index}: '{key}' must be a string")
    if value.strip() == "":
        raise DetectorConfigError(
            f"group {index}: '{key}' must not be empty or whitespace-only"
        )
    return value


def parse_expected_groups(text: str) -> tuple[ExpectedGroup, ...]:
    """
    Read the expected detection groups from the text of a detector runner
    configuration.

    Only the top-level "groups" list is read; other top-level keys are
    ignored.  Each group must be an object with a non-blank signal_path and
    service_name and an optional operation_name; a missing or null
    operation_name is "".  Values are taken exactly as written: nothing is
    trimmed and signal_path is not checked against the detector's signals.

    Returns the groups as (signal_path, service_name, operation_name), in
    file order.

    Raises:
        DetectorConfigError  for anything else, with a fixed phrase.
    """
    if not isinstance(text, str):
        raise DetectorConfigError("the file is not valid UTF-8 JSON")
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except DetectorConfigError:
        raise
    except (ValueError, RecursionError):
        raise DetectorConfigError("the file is not valid UTF-8 JSON") from None

    if not isinstance(data, dict):
        raise DetectorConfigError("the top level must be a JSON object")
    if "groups" not in data:
        raise DetectorConfigError("'groups' is required")
    raw_groups = data["groups"]
    if not isinstance(raw_groups, list):
        raise DetectorConfigError("'groups' must be a list")
    if not raw_groups:
        raise DetectorConfigError("'groups' must hold at least one group")

    groups: list[ExpectedGroup] = []
    seen: set[ExpectedGroup] = set()
    for index, raw in enumerate(raw_groups):
        if not isinstance(raw, dict):
            raise DetectorConfigError(f"group {index} must be a JSON object")
        if set(raw) - _GROUP_KEYS:
            raise DetectorConfigError(f"group {index} has an unknown key")

        signal_path = _required_name(raw, "signal_path", index)
        service_name = _required_name(raw, "service_name", index)

        operation_name = raw.get("operation_name")
        if operation_name is None:
            operation_name = ""
        elif not isinstance(operation_name, str):
            raise DetectorConfigError(
                f"group {index}: 'operation_name' must be a string or null"
            )
        elif operation_name != "" and operation_name.strip() == "":
            raise DetectorConfigError(
                f"group {index}: 'operation_name' must not be whitespace-only"
            )

        group = (signal_path, service_name, operation_name)
        if group in seen:
            raise DetectorConfigError(f"group {index} repeats an earlier group")
        seen.add(group)
        groups.append(group)
    return tuple(groups)


def load_expected_groups(path: str | os.PathLike) -> tuple[ExpectedGroup, ...]:
    """
    Load the expected detection groups from a detector runner configuration
    file.  See parse_expected_groups().

    Raises:
        OSError              the file cannot be opened or read.
        DetectorConfigError  the file is not UTF-8 JSON or its "groups" list
                             is not acceptable.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise DetectorConfigError("the file is not valid UTF-8 JSON") from None
    return parse_expected_groups(text)


# ---------------------------------------------------------------------------
# Time helpers (pure)
# ---------------------------------------------------------------------------

def _to_utc(value: Any) -> datetime:
    """
    Validate an aware datetime and return the same instant in UTC.

    Raises ValueError for anything else.  A time zone object that fails while
    it is asked for its offset, or while the value is converted, is treated
    the same way; its own error is not passed on.
    """
    if not isinstance(value, datetime):
        raise ValueError("not a datetime")
    try:
        aware = value.tzinfo is not None and value.utcoffset() is not None
        converted = value.astimezone(timezone.utc) if aware else None
    except Exception:  # noqa: BLE001 - a defective time zone fails closed
        raise ValueError("not a usable timezone-aware datetime") from None
    if converted is None:
        raise ValueError("not timezone-aware")
    return converted


def _max_age(minutes: int) -> Optional[timedelta]:
    """The threshold as a duration; None when it cannot be represented."""
    try:
        return timedelta(minutes=minutes)
    except OverflowError:
        return None


def _is_older_than(now: datetime, when: datetime, max_age: Optional[timedelta]) -> bool:
    """now - when > max_age.  An unrepresentable threshold is never exceeded."""
    if max_age is None:
        return False
    return now - when > max_age


def _lookback_start(now: datetime, hours: int) -> datetime:
    """Start of the delivery lookback; the earliest time when it underflows."""
    try:
        return now - timedelta(hours=hours)
    except OverflowError:
        return _EARLIEST


# ---------------------------------------------------------------------------
# Identifiers (pure)
# ---------------------------------------------------------------------------

def checkpoint_detail_id(group: ExpectedGroup) -> str:
    """
    The identifier of a detection group: the compact JSON array of its
    signal_path, service_name and operation_name.  Names are free text, so a
    plain join would be ambiguous.
    """
    return json.dumps(
        list(group),
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def delivery_detail_id(decision_id: str, channel_name: str) -> str:
    """
    The identifier of a delivery: "<decision_id>/<channel_name>".  Neither a
    digest nor a channel name can hold "/".
    """
    return f"{decision_id}/{channel_name}"


# ---------------------------------------------------------------------------
# Guardrail 1: detector_checkpoint_stale
# ---------------------------------------------------------------------------

def _checkpoint_error() -> GuardrailEvaluationError:
    return GuardrailEvaluationError(
        (CODE_DETECTOR_CHECKPOINT_STALE,), REASON_INVALID_CHECKPOINT_DATA,
    )


def _expected_groups(expected_groups: Any) -> tuple[ExpectedGroup, ...]:
    if not isinstance(expected_groups, (list, tuple)) or not expected_groups:
        raise ValueError("expected_groups must be a non-empty list or tuple")
    groups = []
    for group in expected_groups:
        if (
            not isinstance(group, (list, tuple))
            or len(group) != 3
            or not all(isinstance(part, str) for part in group)
        ):
            raise ValueError("an expected group must be three strings")
        groups.append(tuple(group))
    return tuple(groups)


def evaluate_checkpoints(
    rows: Sequence[Mapping[str, Any]],
    expected_groups: Sequence[ExpectedGroup],
    *,
    now: datetime,
    max_age_minutes: int,
) -> GuardrailResult:
    """
    Evaluate detector_checkpoint_stale.

    A violation is an expected group with no checkpoint row, or whose
    updated_at is more than max_age_minutes before now.  Rows of groups that
    are not expected are ignored.  The identifiers name expected groups, so
    they come from the configuration, never from a stored value.

    Raises:
        ValueError                now is not a timezone-aware datetime, or
                                  expected_groups is not usable.
        GuardrailEvaluationError  a row is malformed, whether its group is
                                  expected or not, or two rows have the same
                                  group.
    """
    now_utc = _to_utc(now)
    expected = _expected_groups(expected_groups)

    updated: dict[ExpectedGroup, datetime] = {}
    try:
        for row in rows:
            group = (row["signal_path"], row["service_name"], row["operation_name"])
            if not all(isinstance(part, str) for part in group):
                raise ValueError("a group column is not text")
            if group in updated:
                raise ValueError("a group has two rows")
            updated[group] = _to_utc(row["updated_at"])
    except Exception:  # noqa: BLE001 - any unreadable row fails closed
        raise _checkpoint_error() from None

    max_age = _max_age(max_age_minutes)
    stale = [
        group for group in sorted(set(expected))
        if group not in updated or _is_older_than(now_utc, updated[group], max_age)
    ]
    return _result(
        CODE_DETECTOR_CHECKPOINT_STALE,
        [checkpoint_detail_id(group) for group in stale],
    )


# ---------------------------------------------------------------------------
# Guardrail 2: uninvestigated_anomalies
# ---------------------------------------------------------------------------

def _anomaly_error() -> GuardrailEvaluationError:
    return GuardrailEvaluationError(
        (CODE_UNINVESTIGATED_ANOMALIES,), REASON_INVALID_ANOMALY_DATA,
    )


def evaluate_uninvestigated(
    rows: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    max_age_minutes: int,
) -> GuardrailResult:
    """
    Evaluate uninvestigated_anomalies.

    rows are the anomalies that have no investigation.  A violation is one
    whose detected_at is more than max_age_minutes before now.

    Raises:
        ValueError                now is not a timezone-aware datetime.
        GuardrailEvaluationError  a row is malformed, or an anomaly_id
                                  appears twice.
    """
    now_utc = _to_utc(now)
    max_age = _max_age(max_age_minutes)

    seen: set[str] = set()
    overdue: list[tuple[datetime, str]] = []
    try:
        for row in rows:
            anomaly_id = row["anomaly_id"]
            if not is_sha256_hex(anomaly_id) or anomaly_id in seen:
                raise ValueError("anomaly_id is not a digest, or is repeated")
            seen.add(anomaly_id)
            detected = _to_utc(row["detected_at"])
            if _is_older_than(now_utc, detected, max_age):
                overdue.append((detected, anomaly_id))
    except Exception:  # noqa: BLE001 - any unreadable row fails closed
        raise _anomaly_error() from None

    return _result(
        CODE_UNINVESTIGATED_ANOMALIES,
        [anomaly_id for _, anomaly_id in sorted(overdue)],
    )


# ---------------------------------------------------------------------------
# Guardrails 3 and 4: delivery_uncertain, delivery_exhausted
# ---------------------------------------------------------------------------

def _delivery_error() -> GuardrailEvaluationError:
    return GuardrailEvaluationError(
        (CODE_DELIVERY_UNCERTAIN, CODE_DELIVERY_EXHAUSTED),
        REASON_INVALID_DELIVERY_DATA,
    )


def _history(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[tuple[DeliveryAttempt, ...], tuple[DeliveryOutcomeRecord, ...]]:
    """Map stored rows to the locked delivery models."""
    attempts: list[DeliveryAttempt] = []
    outcomes: list[DeliveryOutcomeRecord] = []
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
            # The outcome's detail text is not read; a state does not
            # depend on it.
            outcomes.append(DeliveryOutcomeRecord(
                attempt_id=row["attempt_id"],
                outcome=DeliveryOutcome(row["outcome"]),
                detail=None,
                recorded_at=row["recorded_at"],
            ))
    return tuple(attempts), tuple(outcomes)


def evaluate_deliveries(
    decisions: Sequence[Mapping[str, Any]],
    history_rows: Sequence[Mapping[str, Any]],
    channels: Sequence[ChannelConfig],
    delivery: DeliveryPolicy,
    *,
    now: datetime,
    lookback_hours: int,
) -> tuple[GuardrailResult, GuardrailResult]:
    """
    Evaluate delivery_uncertain and delivery_exhausted.

    Every decision is paired with every enabled channel.  For each pair the
    history is validated and its state derived by derive_state with the
    channel's current settings.  The pair is then considered only when the
    decision's evaluated_at, or the start of its latest attempt, is at or
    after the lookback start.

    Returns (delivery_uncertain, delivery_exhausted).

    Raises:
        ValueError                now is not a timezone-aware datetime.
        GuardrailEvaluationError  a decision or a history is malformed or
                                  inconsistent, or a decision appears twice.
    """
    now_utc = _to_utc(now)
    start = _lookback_start(now_utc, lookback_hours)
    enabled = [channel for channel in channels if channel.enabled]

    grouped: dict[tuple[Any, Any], list[Mapping[str, Any]]] = {}
    seen: set[str] = set()
    uncertain: list[tuple[datetime, str, str]] = []
    exhausted: list[tuple[datetime, str, str]] = []
    try:
        for row in history_rows:
            grouped.setdefault(
                (row["decision_id"], row["channel_name"]), [],
            ).append(row)

        for decision in decisions:
            decision_id = decision["decision_id"]
            if not is_sha256_hex(decision_id) or decision_id in seen:
                raise ValueError("decision_id is not a digest, or is repeated")
            seen.add(decision_id)
            evaluated = _to_utc(decision["evaluated_at"])

            for channel in enabled:
                attempts, outcomes = _history(
                    grouped.get((decision_id, channel.name), ()),
                )
                state = derive_state(
                    attempts,
                    outcomes,
                    evaluated_at=evaluated,
                    now=now_utc,
                    max_attempts=channel.max_attempts,
                    timeout_seconds=channel.timeout_seconds,
                    max_delivery_age_minutes=delivery.max_delivery_age_minutes,
                    decision_id=decision_id,
                    channel_name=channel.name,
                )
                in_lookback = evaluated >= start
                if not in_lookback and attempts:
                    latest = max(attempts, key=lambda attempt: attempt.attempt_no)
                    in_lookback = _to_utc(latest.started_at) >= start
                if not in_lookback:
                    continue
                entry = (evaluated, decision_id, channel.name)
                if state is DeliveryState.UNCERTAIN:
                    uncertain.append(entry)
                elif state in _EXHAUSTED_STATES:
                    exhausted.append(entry)
    except Exception:  # noqa: BLE001 - any unreadable record fails closed
        # Includes DeliveryHistoryError and anything the locked models reject.
        raise _delivery_error() from None

    def ordered(entries: list[tuple[datetime, str, str]]) -> list[str]:
        return [
            delivery_detail_id(decision_id, channel_name)
            for _, decision_id, channel_name in sorted(entries)
        ]

    return (
        _result(CODE_DELIVERY_UNCERTAIN, ordered(uncertain)),
        _result(CODE_DELIVERY_EXHAUSTED, ordered(exhausted)),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_guardrails(
    conn: Any,
    *,
    policy: AlertPolicy,
    expected_groups: Sequence[ExpectedGroup],
    now: datetime,
) -> tuple[GuardrailResult, ...]:
    """
    Run the four guardrails and return their results.

    Parameters
    ----------
    conn
        Open connection for the evaluator's database role, preferably a
        read-only session.  The caller owns it: this function does not commit, roll
        back or close.
    policy
        The validated policy.  Its guardrails section gives the thresholds
        and its delivery section the channels and their settings.
    expected_groups
        The detection groups that should have a checkpoint, from
        load_expected_groups().
    now
        The time of this run: one timezone-aware value, used for every
        check.

    Returns
    -------
    tuple of GuardrailResult
        Exactly four, in GUARDRAIL_CODES order.

    Raises
    ------
    ValueError
        policy is not an AlertPolicy, now is not a timezone-aware datetime,
        or expected_groups is not usable.  Raised before the database is
        used.
    GuardrailEvaluationError
        Stored data is malformed or inconsistent.  No result is returned.
    database error
        Any error of the database driver, unchanged.
    """
    if not isinstance(policy, AlertPolicy):
        raise ValueError(
            f"policy must be AlertPolicy, got {type(policy).__name__}"
        )
    try:
        now_utc = _to_utc(now)
    except ValueError:
        raise ValueError("now must be a timezone-aware datetime") from None
    expected = _expected_groups(expected_groups)
    thresholds = policy.guardrails

    checkpoints = evaluate_checkpoints(
        alert_guardrail_store.fetch_checkpoints(conn),
        expected,
        now=now_utc,
        max_age_minutes=thresholds.detector_checkpoint_max_age_minutes,
    )

    uninvestigated = evaluate_uninvestigated(
        alert_guardrail_store.fetch_uninvestigated_anomalies(conn),
        now=now_utc,
        max_age_minutes=thresholds.uninvestigated_anomaly_max_age_minutes,
    )

    enabled = [channel for channel in policy.delivery.channels if channel.enabled]
    if not enabled:
        # No channel is enabled: there is no delivery to consider.
        uncertain = _ok(CODE_DELIVERY_UNCERTAIN)
        exhausted = _ok(CODE_DELIVERY_EXHAUSTED)
    else:
        decisions = alert_guardrail_store.fetch_alert_decisions(
            conn,
            lookback_start=_lookback_start(
                now_utc, thresholds.delivery_lookback_hours,
            ),
        )
        try:
            decision_ids = [decision["decision_id"] for decision in decisions]
        except Exception:  # noqa: BLE001 - any unreadable row fails closed
            raise _delivery_error() from None
        history = alert_guardrail_store.fetch_delivery_history(
            conn,
            decision_ids=decision_ids,
            channel_names=[channel.name for channel in enabled],
        )
        uncertain, exhausted = evaluate_deliveries(
            decisions,
            history,
            enabled,
            policy.delivery,
            now=now_utc,
            lookback_hours=thresholds.delivery_lookback_hours,
        )

    return (checkpoints, uninvestigated, uncertain, exhausted)

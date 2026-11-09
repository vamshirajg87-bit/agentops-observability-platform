"""
alerting/tests/unit/test_alert_delivery_state.py

Unit tests for alert_delivery_state.py.

Pure tests: no database, no network, no clock.

Test inventory:
    DS01  Vocabulary and constants
    DS02  The eight states
    DS03  In-flight boundary
    DS04  Expiry overlay
    DS05  SENT dominates; latest attempt decides
    DS06  Operator attempts
    DS07  Invalid history fails closed
    DS08  next_attempt_no
    DS09  Eligibility
    DS10  Purity and module boundary
"""

from __future__ import annotations

import ast
import inspect
import itertools
from datetime import datetime, timedelta, timezone

import pytest

import alert_delivery_state
from alert_delivery_state import (
    IN_FLIGHT_GRACE,
    REFUSAL_ALREADY_SENT,
    REFUSAL_CONFIRM_RESEND_REQUIRED,
    REFUSAL_IN_FLIGHT,
    REFUSAL_NOT_AUTO_ELIGIBLE,
    REFUSAL_USE_NOTIFY,
    DeliveryHistoryError,
    DeliveryState,
    check_eligibility,
    derive_state,
    next_attempt_no,
)
from alert_identity import compute_attempt_id
from alert_models import (
    ChannelType,
    DeliveryAttempt,
    DeliveryOutcome,
    DeliveryOutcomeRecord,
    DeliveryTrigger,
)


_DEC = "d" * 64
_OTHER_DEC = "e" * 64
_CHANNEL = "hook"
_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_US = timedelta(microseconds=1)

S = DeliveryState
O = DeliveryOutcome


def _attempt(
    n: int, *, started=None, decision=_DEC, channel=_CHANNEL,
    trigger=DeliveryTrigger.AUTO, attempt_id=None,
) -> DeliveryAttempt:
    return DeliveryAttempt(
        attempt_id=attempt_id or compute_attempt_id(decision, channel, n),
        decision_id=decision,
        channel_name=channel,
        channel_type=ChannelType.WEBHOOK,
        attempt_no=n,
        trigger=trigger,
        summary_included=False,
        payload_sha256="f" * 64,
        started_at=started if started is not None else _T0,
    )


def _outcome(n: int, outcome: DeliveryOutcome, *, decision=_DEC, channel=_CHANNEL,
             recorded=None) -> DeliveryOutcomeRecord:
    return DeliveryOutcomeRecord(
        attempt_id=compute_attempt_id(decision, channel, n),
        outcome=outcome,
        detail=None,
        recorded_at=recorded if recorded is not None else _T0,
    )


def _history(*outcomes):
    """Attempts 1..n; an entry of None is an attempt without an outcome."""
    attempts = [_attempt(n) for n in range(1, len(outcomes) + 1)]
    records = [
        _outcome(n, outcome)
        for n, outcome in enumerate(outcomes, start=1) if outcome is not None
    ]
    return attempts, records


def _state(attempts=(), outcomes=(), *, now=_T0, evaluated_at=_T0,
           max_attempts=3, timeout_seconds=10, max_age=60, **extra) -> DeliveryState:
    return derive_state(
        list(attempts), list(outcomes),
        evaluated_at=evaluated_at, now=now, max_attempts=max_attempts,
        timeout_seconds=timeout_seconds, max_delivery_age_minutes=max_age,
        **extra,
    )


# ---------------------------------------------------------------------------
# DS01  Vocabulary
# ---------------------------------------------------------------------------

class TestVocabulary:

    def test_exactly_eight_states(self):
        assert [state.value for state in DeliveryState] == [
            "SENT", "NEVER_ATTEMPTED", "IN_FLIGHT", "UNCERTAIN",
            "PERMANENTLY_FAILED", "RETRYABLE", "EXHAUSTED", "EXPIRED",
        ]
        assert all(state.name == state.value for state in DeliveryState)

    def test_grace_is_thirty_seconds(self):
        assert IN_FLIGHT_GRACE == timedelta(seconds=30)

    def test_refusal_codes_are_fixed_and_distinct(self):
        codes = [
            REFUSAL_ALREADY_SENT, REFUSAL_IN_FLIGHT, REFUSAL_NOT_AUTO_ELIGIBLE,
            REFUSAL_CONFIRM_RESEND_REQUIRED, REFUSAL_USE_NOTIFY,
        ]
        assert codes == [
            "already_sent", "in_flight", "not_auto_eligible",
            "confirm_resend_required", "use_notify",
        ]

    def test_history_error_is_a_value_error(self):
        assert issubclass(DeliveryHistoryError, ValueError)


# ---------------------------------------------------------------------------
# DS02  The eight states
# ---------------------------------------------------------------------------

class TestStates:

    def test_never_attempted(self):
        assert _state() is S.NEVER_ATTEMPTED

    def test_sent(self):
        assert _state(*_history(O.SENT)) is S.SENT

    def test_in_flight(self):
        assert _state(*_history(None), now=_T0 + timedelta(seconds=5)) is S.IN_FLIGHT

    def test_uncertain_from_a_missing_outcome(self):
        assert _state(*_history(None), now=_T0 + timedelta(minutes=5)) is S.UNCERTAIN

    def test_uncertain_from_an_explicit_outcome(self):
        assert _state(*_history(O.UNCERTAIN)) is S.UNCERTAIN

    def test_permanently_failed(self):
        assert _state(*_history(O.FAILED_PERMANENT)) is S.PERMANENTLY_FAILED

    def test_retryable(self):
        assert _state(*_history(O.FAILED_RETRYABLE)) is S.RETRYABLE
        assert _state(*_history(O.FAILED_RETRYABLE, O.FAILED_RETRYABLE)) is S.RETRYABLE

    def test_exhausted_at_max_attempts(self):
        history = _history(O.FAILED_RETRYABLE, O.FAILED_RETRYABLE, O.FAILED_RETRYABLE)
        assert _state(*history, max_attempts=3) is S.EXHAUSTED

    def test_exhausted_above_max_attempts(self):
        history = _history(*[O.FAILED_RETRYABLE] * 5)
        assert _state(*history, max_attempts=3) is S.EXHAUSTED

    def test_max_attempts_one(self):
        assert _state(*_history(O.FAILED_RETRYABLE), max_attempts=1) is S.EXHAUSTED

    def test_expired(self):
        assert _state(now=_T0 + timedelta(minutes=61)) is S.EXPIRED

    def test_input_order_does_not_matter(self):
        attempts, outcomes = _history(O.FAILED_RETRYABLE, O.UNCERTAIN, O.FAILED_PERMANENT)
        expected = _state(attempts, outcomes)
        for shuffled in itertools.permutations(attempts):
            assert _state(shuffled, reversed(outcomes)) is expected
        assert expected is S.PERMANENTLY_FAILED

    def test_tuples_are_accepted(self):
        attempts, outcomes = _history(O.SENT)
        assert derive_state(
            tuple(attempts), tuple(outcomes), evaluated_at=_T0, now=_T0,
            max_attempts=3, timeout_seconds=10, max_delivery_age_minutes=60,
        ) is S.SENT


# ---------------------------------------------------------------------------
# DS03  In-flight boundary
# ---------------------------------------------------------------------------

class TestInFlightBoundary:

    @pytest.mark.parametrize("timeout", [1, 10, 30])
    def test_exactly_at_the_boundary_is_in_flight(self, timeout):
        now = _T0 + timedelta(seconds=timeout + 30)
        assert _state(*_history(None), now=now, timeout_seconds=timeout) is S.IN_FLIGHT

    @pytest.mark.parametrize("timeout", [1, 10, 30])
    def test_one_microsecond_past_the_boundary_is_uncertain(self, timeout):
        now = _T0 + timedelta(seconds=timeout + 30) + _US
        assert _state(*_history(None), now=now, timeout_seconds=timeout) is S.UNCERTAIN

    def test_started_at_now_is_in_flight(self):
        assert _state(*_history(None), now=_T0) is S.IN_FLIGHT

    def test_future_started_at_is_in_flight(self):
        attempts = [_attempt(1, started=_T0 + timedelta(hours=3))]
        assert _state(attempts, now=_T0) is S.IN_FLIGHT

    def test_boundary_uses_the_latest_attempt_only(self):
        attempts = [
            _attempt(1, started=_T0 - timedelta(days=1)),
            _attempt(2, started=_T0),
        ]
        outcomes = [_outcome(1, O.FAILED_RETRYABLE)]
        assert _state(attempts, outcomes, now=_T0 + timedelta(seconds=40)) is S.IN_FLIGHT
        assert _state(
            attempts, outcomes, now=_T0 + timedelta(seconds=40) + _US,
        ) is S.UNCERTAIN

    def test_in_flight_is_never_expired(self):
        attempts = [_attempt(1, started=_T0 + timedelta(days=30))]
        assert _state(
            attempts, now=_T0 + timedelta(days=30), evaluated_at=_T0,
        ) is S.IN_FLIGHT

    def test_other_time_zones_are_normalised(self):
        zone = timezone(timedelta(hours=5, minutes=30))
        attempts = [_attempt(1, started=_T0.astimezone(zone))]
        now = (_T0 + timedelta(seconds=40)).astimezone(timezone(timedelta(hours=-8)))
        assert _state(attempts, now=now) is S.IN_FLIGHT
        assert _state(attempts, now=now + _US) is S.UNCERTAIN


# ---------------------------------------------------------------------------
# DS04  Expiry overlay
# ---------------------------------------------------------------------------

class TestExpiry:

    def test_exactly_max_age_is_not_expired(self):
        assert _state(now=_T0 + timedelta(minutes=60)) is S.NEVER_ATTEMPTED

    def test_one_microsecond_past_max_age_is_expired(self):
        assert _state(now=_T0 + timedelta(minutes=60) + _US) is S.EXPIRED

    def test_retryable_expires(self):
        history = _history(O.FAILED_RETRYABLE)
        assert _state(*history, now=_T0 + timedelta(minutes=60)) is S.RETRYABLE
        assert _state(*history, now=_T0 + timedelta(minutes=60) + _US) is S.EXPIRED

    def test_future_evaluated_at_is_not_expired(self):
        assert _state(evaluated_at=_T0 + timedelta(days=2)) is S.NEVER_ATTEMPTED
        assert _state(
            *_history(O.FAILED_RETRYABLE), evaluated_at=_T0 + timedelta(days=2),
        ) is S.RETRYABLE

    @pytest.mark.parametrize("outcomes, expected", [
        ((O.SENT,), S.SENT),
        ((O.UNCERTAIN,), S.UNCERTAIN),
        ((O.FAILED_PERMANENT,), S.PERMANENTLY_FAILED),
        ((O.FAILED_RETRYABLE,) * 3, S.EXHAUSTED),
        ((None,), S.UNCERTAIN),
    ])
    def test_only_never_attempted_and_retryable_expire(self, outcomes, expected):
        history = _history(*outcomes)
        assert _state(*history, now=_T0 + timedelta(days=365)) is expected

    def test_max_age_is_measured_from_evaluated_at_not_from_the_attempt(self):
        attempts = [_attempt(1, started=_T0 + timedelta(minutes=59))]
        outcomes = [_outcome(1, O.FAILED_RETRYABLE)]
        assert _state(attempts, outcomes, now=_T0 + timedelta(minutes=61)) is S.EXPIRED

    def test_max_age_setting_is_used(self):
        now = _T0 + timedelta(minutes=10)
        assert _state(now=now, max_age=10) is S.NEVER_ATTEMPTED
        assert _state(now=now, max_age=9) is S.EXPIRED


# ---------------------------------------------------------------------------
# DS05  SENT dominates; latest attempt decides
# ---------------------------------------------------------------------------

class TestPrecedence:

    @pytest.mark.parametrize("later", [
        O.FAILED_RETRYABLE, O.FAILED_PERMANENT, O.UNCERTAIN, None,
    ])
    def test_sent_dominates_any_later_attempt(self, later):
        history = _history(O.SENT, later)
        assert _state(*history, now=_T0 + timedelta(days=9)) is S.SENT

    def test_sent_dominates_wherever_it_is(self):
        for position in range(4):
            outcomes = [O.FAILED_RETRYABLE] * 4
            outcomes[position] = O.SENT
            assert _state(*_history(*outcomes)) is S.SENT

    def test_sent_is_never_expired(self):
        assert _state(*_history(O.SENT), now=_T0 + timedelta(days=999)) is S.SENT

    @pytest.mark.parametrize("earlier", [
        O.FAILED_PERMANENT, O.UNCERTAIN, O.FAILED_RETRYABLE, None,
    ])
    def test_latest_attempt_decides(self, earlier):
        assert _state(*_history(earlier, O.FAILED_PERMANENT)) is S.PERMANENTLY_FAILED
        assert _state(*_history(earlier, O.UNCERTAIN)) is S.UNCERTAIN
        assert _state(*_history(earlier, O.FAILED_RETRYABLE)) is S.RETRYABLE


# ---------------------------------------------------------------------------
# DS06  Operator attempts
# ---------------------------------------------------------------------------

class TestOperatorAttempts:

    def test_operator_attempts_count_toward_max_attempts(self):
        attempts = [
            _attempt(1), _attempt(2),
            _attempt(3, trigger=DeliveryTrigger.OPERATOR),
        ]
        outcomes = [_outcome(n, O.FAILED_RETRYABLE) for n in (1, 2, 3)]
        assert _state(attempts, outcomes, max_attempts=3) is S.EXHAUSTED

    def test_operator_retry_of_uncertain_can_become_retryable(self):
        # 1 is uncertain; the operator resends; 2 fails retryably below the
        # limit, so the automatic run may act again.
        attempts = [_attempt(1), _attempt(2, trigger=DeliveryTrigger.OPERATOR)]
        outcomes = [_outcome(1, O.UNCERTAIN), _outcome(2, O.FAILED_RETRYABLE)]
        state = _state(attempts, outcomes, max_attempts=3)
        assert state is S.RETRYABLE
        assert check_eligibility(state, DeliveryTrigger.AUTO) is None

    def test_operator_retry_of_a_missing_outcome_can_become_retryable(self):
        attempts = [
            _attempt(1, started=_T0 - timedelta(hours=1)),
            _attempt(2, trigger=DeliveryTrigger.OPERATOR),
        ]
        assert _state(attempts, [_outcome(2, O.FAILED_RETRYABLE)]) is S.RETRYABLE

    def test_operator_retry_of_exhausted_stays_exhausted(self):
        outcomes = [O.FAILED_RETRYABLE] * 4
        assert _state(*_history(*outcomes), max_attempts=3) is S.EXHAUSTED

    def test_trigger_does_not_change_the_state(self):
        for trigger in DeliveryTrigger:
            attempts = [_attempt(1, trigger=trigger)]
            assert _state(attempts, [_outcome(1, O.FAILED_PERMANENT)]) is S.PERMANENTLY_FAILED


# ---------------------------------------------------------------------------
# DS07  Invalid history
# ---------------------------------------------------------------------------

class TestInvalidHistory:

    def test_naive_now(self):
        with pytest.raises(DeliveryHistoryError, match="now"):
            _state(now=datetime(2026, 10, 5, 19, 0))

    def test_naive_evaluated_at(self):
        with pytest.raises(DeliveryHistoryError, match="evaluated_at"):
            _state(evaluated_at=datetime(2026, 10, 5, 19, 0))

    @pytest.mark.parametrize("value", [None, "2026-10-05T19:00:00Z", 0])
    def test_non_datetime_times(self, value):
        with pytest.raises(DeliveryHistoryError):
            _state(now=value)
        with pytest.raises(DeliveryHistoryError):
            _state(evaluated_at=value)

    def test_naive_started_at_cannot_even_be_modelled(self):
        with pytest.raises(ValueError):
            _attempt(1, started=datetime(2026, 10, 5, 19, 0))

    def test_attempt_for_another_decision(self):
        attempts = [_attempt(1), _attempt(2, decision=_OTHER_DEC)]
        with pytest.raises(DeliveryHistoryError, match="another decision"):
            _state(attempts)

    def test_attempt_for_another_channel(self):
        attempts = [_attempt(1), _attempt(2, channel="other")]
        with pytest.raises(DeliveryHistoryError, match="another channel"):
            _state(attempts)

    def test_expected_decision_is_enforced(self):
        with pytest.raises(DeliveryHistoryError, match="another decision"):
            _state([_attempt(1)], decision_id=_OTHER_DEC, channel_name=_CHANNEL)

    def test_expected_channel_is_enforced(self):
        with pytest.raises(DeliveryHistoryError, match="another channel"):
            _state([_attempt(1)], decision_id=_DEC, channel_name="file")

    def test_matching_expected_pair_is_accepted(self):
        assert _state(
            [_attempt(1)], [_outcome(1, O.SENT)],
            decision_id=_DEC, channel_name=_CHANNEL,
        ) is S.SENT

    def test_duplicate_attempt_number(self):
        with pytest.raises(DeliveryHistoryError, match="1..n"):
            _state([_attempt(1), _attempt(1)])

    @pytest.mark.parametrize("numbers", [(2,), (1, 3), (2, 3), (1, 2, 4)])
    def test_gap_in_attempt_numbers(self, numbers):
        with pytest.raises(DeliveryHistoryError, match="1..n"):
            _state([_attempt(n) for n in numbers])

    def test_attempt_with_a_foreign_identity(self):
        forged = _attempt(1, attempt_id=compute_attempt_id(_DEC, _CHANNEL, 2))
        with pytest.raises(DeliveryHistoryError, match="identity"):
            _state([forged])

    def test_attempt_with_another_channels_identity(self):
        forged = _attempt(1, attempt_id=compute_attempt_id(_DEC, "other", 1))
        with pytest.raises(DeliveryHistoryError, match="identity"):
            _state([forged])

    def test_outcome_for_an_unknown_attempt(self):
        with pytest.raises(DeliveryHistoryError, match="unknown attempt"):
            _state([_attempt(1)], [_outcome(2, O.SENT)])

    def test_outcome_without_any_attempt(self):
        with pytest.raises(DeliveryHistoryError, match="unknown attempt"):
            _state([], [_outcome(1, O.SENT)])

    def test_two_outcomes_for_one_attempt(self):
        with pytest.raises(DeliveryHistoryError, match="more than one outcome"):
            _state([_attempt(1)], [_outcome(1, O.FAILED_RETRYABLE), _outcome(1, O.SENT)])

    @pytest.mark.parametrize("attempts", [None, "x", {1: 2}, [object()], [None]])
    def test_attempts_of_the_wrong_type(self, attempts):
        with pytest.raises(DeliveryHistoryError):
            derive_state(
                attempts, [], evaluated_at=_T0, now=_T0, max_attempts=3,
                timeout_seconds=10, max_delivery_age_minutes=60,
            )

    @pytest.mark.parametrize("outcomes", [None, "x", [object()], [O.SENT]])
    def test_outcomes_of_the_wrong_type(self, outcomes):
        with pytest.raises(DeliveryHistoryError):
            derive_state(
                [_attempt(1)], outcomes, evaluated_at=_T0, now=_T0,
                max_attempts=3, timeout_seconds=10, max_delivery_age_minutes=60,
            )

    @pytest.mark.parametrize("field", [
        "max_attempts", "timeout_seconds", "max_age",
    ])
    @pytest.mark.parametrize("value", [0, -1, True, 1.5, "3", None])
    def test_settings_must_be_positive_integers(self, field, value):
        with pytest.raises(DeliveryHistoryError):
            _state(**{field: value})

    def test_invalid_history_yields_no_state_even_when_sent(self):
        attempts = [_attempt(1), _attempt(3)]
        with pytest.raises(DeliveryHistoryError):
            _state(attempts, [_outcome(1, O.SENT)])

    def test_locked_models_reject_malformed_values(self):
        with pytest.raises(ValueError):
            DeliveryAttempt(
                attempt_id="not-a-digest", decision_id=_DEC, channel_name=_CHANNEL,
                channel_type=ChannelType.LOG, attempt_no=1,
                trigger=DeliveryTrigger.AUTO, summary_included=False,
                payload_sha256="f" * 64, started_at=_T0,
            )
        with pytest.raises(ValueError):
            DeliveryOutcomeRecord(
                attempt_id=compute_attempt_id(_DEC, _CHANNEL, 1),
                outcome="SENT", detail=None, recorded_at=_T0,
            )


# ---------------------------------------------------------------------------
# DS08  next_attempt_no
# ---------------------------------------------------------------------------

class TestNextAttemptNo:

    def test_starts_at_one(self):
        assert next_attempt_no([]) == 1

    def test_increments_from_the_highest(self):
        assert next_attempt_no([_attempt(1)]) == 2
        assert next_attempt_no([_attempt(3), _attempt(1), _attempt(2)]) == 4

    def test_identity_of_the_next_attempt_is_deterministic(self):
        number = next_attempt_no([_attempt(1), _attempt(2)])
        assert compute_attempt_id(_DEC, _CHANNEL, number) == compute_attempt_id(
            _DEC, _CHANNEL, 3,
        )


# ---------------------------------------------------------------------------
# DS09  Eligibility
# ---------------------------------------------------------------------------

_AUTO = DeliveryTrigger.AUTO
_OPERATOR = DeliveryTrigger.OPERATOR


class TestEligibility:

    @pytest.mark.parametrize("state, expected", [
        (S.NEVER_ATTEMPTED, None),
        (S.RETRYABLE, None),
        (S.SENT, REFUSAL_ALREADY_SENT),
        (S.IN_FLIGHT, REFUSAL_IN_FLIGHT),
        (S.UNCERTAIN, REFUSAL_NOT_AUTO_ELIGIBLE),
        (S.PERMANENTLY_FAILED, REFUSAL_NOT_AUTO_ELIGIBLE),
        (S.EXHAUSTED, REFUSAL_NOT_AUTO_ELIGIBLE),
        (S.EXPIRED, REFUSAL_NOT_AUTO_ELIGIBLE),
    ])
    def test_automatic(self, state, expected):
        assert check_eligibility(state, _AUTO) == expected

    @pytest.mark.parametrize("state", list(DeliveryState))
    def test_confirmation_never_widens_the_automatic_run(self, state):
        assert check_eligibility(state, _AUTO, confirm_resend=True) == (
            check_eligibility(state, _AUTO, confirm_resend=False)
        )

    def test_automatic_never_resends_uncertain_even_when_confirmed(self):
        assert check_eligibility(
            S.UNCERTAIN, _AUTO, confirm_resend=True,
        ) == REFUSAL_NOT_AUTO_ELIGIBLE

    @pytest.mark.parametrize("state, expected", [
        (S.EXHAUSTED, None),
        (S.PERMANENTLY_FAILED, None),
        (S.EXPIRED, None),
        (S.UNCERTAIN, REFUSAL_CONFIRM_RESEND_REQUIRED),
        (S.SENT, REFUSAL_ALREADY_SENT),
        (S.IN_FLIGHT, REFUSAL_IN_FLIGHT),
        (S.NEVER_ATTEMPTED, REFUSAL_USE_NOTIFY),
        (S.RETRYABLE, REFUSAL_USE_NOTIFY),
    ])
    def test_operator_without_confirmation(self, state, expected):
        assert check_eligibility(state, _OPERATOR) == expected
        assert check_eligibility(state, _OPERATOR, confirm_resend=False) == expected

    @pytest.mark.parametrize("state, expected", [
        (S.EXHAUSTED, None),
        (S.PERMANENTLY_FAILED, None),
        (S.EXPIRED, None),
        (S.UNCERTAIN, None),
        (S.SENT, REFUSAL_ALREADY_SENT),
        (S.IN_FLIGHT, REFUSAL_IN_FLIGHT),
        (S.NEVER_ATTEMPTED, REFUSAL_USE_NOTIFY),
        (S.RETRYABLE, REFUSAL_USE_NOTIFY),
    ])
    def test_operator_with_confirmation(self, state, expected):
        assert check_eligibility(state, _OPERATOR, confirm_resend=True) == expected

    @pytest.mark.parametrize("trigger", list(DeliveryTrigger))
    @pytest.mark.parametrize("confirm", [True, False])
    def test_nobody_may_attempt_sent_or_in_flight(self, trigger, confirm):
        assert check_eligibility(S.SENT, trigger, confirm_resend=confirm) is not None
        assert check_eligibility(S.IN_FLIGHT, trigger, confirm_resend=confirm) is not None

    def test_every_state_is_covered_for_both_triggers(self):
        for state in DeliveryState:
            for trigger in DeliveryTrigger:
                result = check_eligibility(state, trigger)
                assert result is None or isinstance(result, str)

    def test_confirm_resend_is_keyword_only(self):
        with pytest.raises(TypeError):
            check_eligibility(S.UNCERTAIN, _OPERATOR, True)  # noqa: FBT003

    @pytest.mark.parametrize("args, kwargs", [
        (("UNCERTAIN", _OPERATOR), {}),
        ((S.UNCERTAIN, "operator"), {}),
        ((S.UNCERTAIN, _OPERATOR), {"confirm_resend": 1}),
        ((S.UNCERTAIN, _OPERATOR), {"confirm_resend": "yes"}),
        ((S.UNCERTAIN, _OPERATOR), {"confirm_resend": None}),
    ])
    def test_wrong_types_are_rejected(self, args, kwargs):
        with pytest.raises(ValueError):
            check_eligibility(*args, **kwargs)


# ---------------------------------------------------------------------------
# DS10  Purity and module boundary
# ---------------------------------------------------------------------------

class TestModuleBoundary:

    @pytest.fixture(scope="class")
    def tree(self):
        return ast.parse(inspect.getsource(alert_delivery_state))

    def test_imports(self, tree):
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "datetime", "enum", "typing",
            "alert_identity", "alert_models",
        }

    def test_no_clock_environment_or_io(self, tree):
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        forbidden = {
            "now", "utcnow", "today", "time", "environ", "getenv", "open",
            "print", "execute", "commit", "rollback",
        }
        assert forbidden.isdisjoint(attributes)
        assert {"open", "print", "os", "sys"}.isdisjoint(names)

    def test_identity_is_the_locked_function(self):
        import alert_identity
        assert alert_delivery_state.compute_attempt_id is alert_identity.compute_attempt_id
        assert "hashlib" not in inspect.getsource(alert_delivery_state)

    def test_derive_state_is_deterministic(self):
        history = _history(O.FAILED_RETRYABLE, None)
        now = _T0 + timedelta(seconds=41)
        assert {_state(*history, now=now) for _ in range(5)} == {S.UNCERTAIN}

    def test_inputs_are_not_modified(self):
        attempts, outcomes = _history(O.FAILED_RETRYABLE, O.SENT)
        shuffled = [attempts[1], attempts[0]]
        before = list(shuffled)
        _state(shuffled, outcomes)
        assert shuffled == before

    def test_time_and_settings_are_keyword_only(self):
        parameters = inspect.signature(derive_state).parameters
        for name in ("evaluated_at", "now", "max_attempts", "timeout_seconds",
                     "max_delivery_age_minutes"):
            assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
            assert parameters[name].default is inspect.Parameter.empty

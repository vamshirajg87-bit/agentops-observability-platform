"""
Tests for alerting/alert_engine.py

No database, no network, no environment variables, no file written.

Every decision obtained through _decide() is also checked against the
Phase 13.1 pairing tables (REASONS_BY_DECISION and
REASONS_WITH_RELATED_DECISION), so an engine result can always be stored.

Test groups:
    A. Kill switch
    B. Minimum severity
    C. Stale
    D. Duplicate anomaly
    E. Cooldown window
    F. Escalation, including escalation_breaks_cooldown true and false
    G. Storm cap
    H. Normal alert
    I. Related-decision tie-breaking
    J. Determinism, including timezone handling
    K. Informational fields cannot reach the engine
    L. Fail closed
    M. Purity
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import itertools
import random
from datetime import datetime, timedelta, timezone, tzinfo

import pytest

import alert_engine
from alert_engine import (
    STORM_WINDOW,
    AlertSubject,
    EngineDecision,
    PriorAlert,
    decide,
)
from alert_identity import compute_dedup_key, is_sha256_hex
from alert_models import (
    REASONS_BY_DECISION,
    REASONS_WITH_RELATED_DECISION,
    Confidence,
    Decision,
    ReasonCode,
    Severity,
    severity_rank,
)
from alert_policy import AlertPolicy, EvaluationPolicy

INFO, WARNING, CRITICAL = Severity.INFO, Severity.WARNING, Severity.CRITICAL

_US = timedelta(microseconds=1)

#: Event time of the subject in most tests.
_E = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
#: Default evaluation time: one minute after the event.
_NOW = _E + timedelta(minutes=1)

_SAME_KEY = compute_dedup_key("latency", "svc", "op")
_OTHER_KEY = compute_dedup_key("error_rate", "svc", "op")


def _id(n: int) -> str:
    """A valid digest-shaped identifier that sorts like n."""
    return f"{n:064x}"


_SUBJECT_ANOMALY = _id(0xA0)


def _subject(**overrides) -> AlertSubject:
    values = dict(
        investigation_id=_id(0x1),
        anomaly_id=_SUBJECT_ANOMALY,
        anomaly_type="latency",
        service_name="svc",
        operation_name="op",
        event_time=_E,
        severity=CRITICAL,
    )
    values.update(overrides)
    return AlertSubject(**values)


def _prior(
    n: int,
    *,
    before: timedelta = timedelta(minutes=10),
    severity: Severity = WARNING,
    dedup_key: str = _SAME_KEY,
    anomaly_id: str | None = None,
    event_time: datetime | None = None,
) -> PriorAlert:
    """Prior alert number n, `before` earlier than the subject by default."""
    return PriorAlert(
        decision_id=_id(n),
        anomaly_id=anomaly_id if anomaly_id is not None else _id(0xB000 + n),
        dedup_key=dedup_key,
        event_time=event_time if event_time is not None else _E - before,
        severity=severity,
        decision=Decision.ALERT,
    )


def _policy(**overrides) -> EvaluationPolicy:
    return EvaluationPolicy(**overrides)


def _storm(count: int, *, before: timedelta = timedelta(minutes=10), start: int = 500):
    """`count` alerts of another incident stream inside the storm window."""
    return [
        _prior(start + i, before=before, dedup_key=_OTHER_KEY)
        for i in range(count)
    ]


def _conforms(result: EngineDecision) -> None:
    assert isinstance(result, EngineDecision)
    assert result.reason_code in REASONS_BY_DECISION[result.decision]
    if result.reason_code in REASONS_WITH_RELATED_DECISION:
        assert is_sha256_hex(result.related_decision_id)
    else:
        assert result.related_decision_id is None


def _decide(subject=None, history=(), evaluation=None, evaluated_at=_NOW):
    result = decide(
        subject if subject is not None else _subject(),
        history,
        evaluation if evaluation is not None else _policy(),
        evaluated_at,
    )
    _conforms(result)
    return result


def _is(result, decision, reason, related=None) -> None:
    assert (result.decision, result.reason_code, result.related_decision_id) == (
        decision, reason, related,
    )


_ALERT = (Decision.ALERT, ReasonCode.SEVERITY_MET)
_ESCALATION = (Decision.ALERT, ReasonCode.ESCALATION)
_KILL = (Decision.SUPPRESSED, ReasonCode.KILL_SWITCH)
_BELOW = (Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY)
_STALE = (Decision.NOT_ALERTABLE, ReasonCode.STALE)
_DUPLICATE = (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY)
_COOLDOWN = (Decision.SUPPRESSED, ReasonCode.COOLDOWN)
_STORM = (Decision.SUPPRESSED, ReasonCode.STORM_CAP)


# ---------------------------------------------------------------------------
# A. Kill switch
# ---------------------------------------------------------------------------

class TestKillSwitch:
    def test_disabled_suppresses(self):
        _is(_decide(evaluation=_policy(enabled=False)), *_KILL)

    def test_enabled_does_not(self):
        _is(_decide(evaluation=_policy(enabled=True)), *_ALERT)

    def test_wins_over_below_minimum(self):
        _is(_decide(_subject(severity=INFO), evaluation=_policy(enabled=False)), *_KILL)

    def test_wins_over_stale(self):
        result = _decide(
            evaluation=_policy(enabled=False),
            evaluated_at=_E + timedelta(days=30),
        )
        _is(result, *_KILL)

    def test_wins_over_duplicate(self):
        history = [_prior(1, anomaly_id=_SUBJECT_ANOMALY)]
        _is(_decide(history=history, evaluation=_policy(enabled=False)), *_KILL)

    def test_wins_over_cooldown(self):
        history = [_prior(1, severity=CRITICAL)]
        _is(_decide(history=history, evaluation=_policy(enabled=False)), *_KILL)

    def test_wins_over_storm_cap(self):
        result = _decide(
            history=_storm(20), evaluation=_policy(enabled=False),
        )
        _is(result, *_KILL)

    def test_wins_when_every_other_rule_also_applies(self):
        history = _storm(20) + [
            _prior(1, anomaly_id=_SUBJECT_ANOMALY), _prior(2, severity=CRITICAL),
        ]
        result = _decide(
            _subject(severity=INFO), history, _policy(enabled=False),
            _E + timedelta(days=30),
        )
        _is(result, *_KILL)

    def test_related_is_none(self):
        history = [_prior(1, anomaly_id=_SUBJECT_ANOMALY)]
        result = _decide(history=history, evaluation=_policy(enabled=False))
        assert result.related_decision_id is None

    def test_malformed_input_still_raises_when_disabled(self):
        with pytest.raises(ValueError):
            decide(_subject(), "not-a-history", _policy(enabled=False), _NOW)
        with pytest.raises(ValueError):
            decide(_subject(), [], _policy(enabled=False), datetime(2026, 10, 5))


# ---------------------------------------------------------------------------
# B. Minimum severity
# ---------------------------------------------------------------------------

class TestMinimumSeverity:
    @pytest.mark.parametrize("minimum", list(Severity))
    @pytest.mark.parametrize("candidate", list(Severity))
    def test_every_combination(self, minimum, candidate):
        result = _decide(
            _subject(severity=candidate), evaluation=_policy(min_severity=minimum),
        )
        if severity_rank(candidate) < severity_rank(minimum):
            _is(result, *_BELOW)
        else:
            _is(result, *_ALERT)

    def test_equal_to_minimum_proceeds(self):
        result = _decide(
            _subject(severity=WARNING), evaluation=_policy(min_severity=WARNING),
        )
        _is(result, *_ALERT)

    def test_default_minimum_is_warning(self):
        _is(_decide(_subject(severity=INFO)), *_BELOW)
        _is(_decide(_subject(severity=WARNING)), *_ALERT)

    def test_wins_over_stale(self):
        result = _decide(
            _subject(severity=INFO), evaluated_at=_E + timedelta(days=30),
        )
        _is(result, *_BELOW)

    def test_wins_over_duplicate(self):
        history = [_prior(1, anomaly_id=_SUBJECT_ANOMALY)]
        _is(_decide(_subject(severity=INFO), history), *_BELOW)

    def test_wins_over_cooldown(self):
        _is(_decide(_subject(severity=INFO), [_prior(1)]), *_BELOW)

    def test_wins_over_storm_cap(self):
        _is(_decide(_subject(severity=INFO), _storm(20)), *_BELOW)

    def test_related_is_none(self):
        result = _decide(_subject(severity=INFO), [_prior(1)])
        assert result.related_decision_id is None


# ---------------------------------------------------------------------------
# C. Stale
# ---------------------------------------------------------------------------

class TestStale:
    _MAX = timedelta(minutes=60)

    def test_one_microsecond_over_is_stale(self):
        _is(_decide(evaluated_at=_E + self._MAX + _US), *_STALE)

    def test_exactly_the_maximum_is_not_stale(self):
        _is(_decide(evaluated_at=_E + self._MAX), *_ALERT)

    def test_one_microsecond_under_is_not_stale(self):
        _is(_decide(evaluated_at=_E + self._MAX - _US), *_ALERT)

    def test_zero_age_is_not_stale(self):
        _is(_decide(evaluated_at=_E), *_ALERT)

    def test_future_event_time_is_not_stale(self):
        _is(_decide(evaluated_at=_E - timedelta(minutes=5)), *_ALERT)

    def test_far_future_event_time_is_not_stale(self):
        _is(_decide(evaluated_at=_E - timedelta(days=365)), *_ALERT)

    def test_much_older_is_stale(self):
        _is(_decide(evaluated_at=_E + timedelta(days=6)), *_STALE)

    @pytest.mark.parametrize("minutes", [1, 5, 1440])
    def test_boundary_follows_the_policy(self, minutes):
        policy = _policy(max_alert_age_minutes=minutes)
        limit = timedelta(minutes=minutes)
        _is(_decide(evaluation=policy, evaluated_at=_E + limit), *_ALERT)
        _is(_decide(evaluation=policy, evaluated_at=_E + limit + _US), *_STALE)

    def test_wins_over_duplicate(self):
        history = [_prior(1, anomaly_id=_SUBJECT_ANOMALY)]
        _is(_decide(history=history, evaluated_at=_E + timedelta(days=1)), *_STALE)

    def test_wins_over_cooldown(self):
        history = [_prior(1, severity=CRITICAL)]
        _is(_decide(history=history, evaluated_at=_E + timedelta(days=1)), *_STALE)

    def test_wins_over_storm_cap(self):
        _is(_decide(history=_storm(20), evaluated_at=_E + timedelta(days=1)), *_STALE)

    def test_only_this_rule_reads_evaluated_at(self):
        history = [_prior(1, severity=CRITICAL)] + _storm(3)
        earliest = _decide(history=history, evaluated_at=_E - timedelta(days=9))
        latest = _decide(history=history, evaluated_at=_E + timedelta(minutes=60))
        assert earliest == latest
        _is(earliest, *_COOLDOWN, _id(1))


# ---------------------------------------------------------------------------
# D. Duplicate anomaly
# ---------------------------------------------------------------------------

class TestDuplicateAnomaly:
    def test_prior_alert_for_same_anomaly(self):
        history = [_prior(7, anomaly_id=_SUBJECT_ANOMALY)]
        _is(_decide(history=history), *_DUPLICATE, _id(7))

    def test_no_time_bound_far_in_the_past(self):
        history = [
            _prior(7, anomaly_id=_SUBJECT_ANOMALY, before=timedelta(days=400)),
        ]
        _is(_decide(history=history), *_DUPLICATE, _id(7))

    def test_applies_to_an_alert_later_than_the_subject(self):
        history = [
            _prior(7, anomaly_id=_SUBJECT_ANOMALY, before=-timedelta(hours=5)),
        ]
        _is(_decide(history=history), *_DUPLICATE, _id(7))

    def test_applies_across_dedup_keys(self):
        history = [_prior(7, anomaly_id=_SUBJECT_ANOMALY, dedup_key=_OTHER_KEY)]
        _is(_decide(history=history), *_DUPLICATE, _id(7))

    def test_related_is_smallest_decision_id(self):
        history = [
            _prior(30, anomaly_id=_SUBJECT_ANOMALY, severity=CRITICAL,
                   before=timedelta(minutes=1)),
            _prior(10, anomaly_id=_SUBJECT_ANOMALY, severity=INFO,
                   before=timedelta(days=3)),
            _prior(20, anomaly_id=_SUBJECT_ANOMALY),
        ]
        _is(_decide(history=history), *_DUPLICATE, _id(10))

    def test_related_ignores_non_matching_smaller_ids(self):
        history = [_prior(1), _prior(9, anomaly_id=_SUBJECT_ANOMALY)]
        _is(_decide(history=history), *_DUPLICATE, _id(9))

    def test_different_anomaly_is_not_a_duplicate(self):
        history = [_prior(7, before=timedelta(hours=3))]
        _is(_decide(history=history), *_ALERT)

    def test_wins_over_cooldown(self):
        history = [
            _prior(1, severity=CRITICAL),
            _prior(2, anomaly_id=_SUBJECT_ANOMALY, before=timedelta(days=2)),
        ]
        _is(_decide(history=history), *_DUPLICATE, _id(2))

    def test_wins_over_escalation(self):
        history = [
            _prior(1, severity=WARNING),
            _prior(2, anomaly_id=_SUBJECT_ANOMALY, before=timedelta(days=2)),
        ]
        _is(_decide(_subject(severity=CRITICAL), history), *_DUPLICATE, _id(2))

    def test_wins_over_storm_cap(self):
        history = _storm(20) + [
            _prior(2, anomaly_id=_SUBJECT_ANOMALY, before=timedelta(days=2)),
        ]
        _is(_decide(history=history), *_DUPLICATE, _id(2))

    def test_independent_of_severity_of_the_prior_alert(self):
        for severity in Severity:
            history = [_prior(7, anomaly_id=_SUBJECT_ANOMALY, severity=severity)]
            _is(_decide(history=history), *_DUPLICATE, _id(7))


# ---------------------------------------------------------------------------
# E. Cooldown window
# ---------------------------------------------------------------------------

class TestCooldownWindow:
    _C = timedelta(minutes=30)

    def _same(self, before, n=1):
        return [_prior(n, before=before, severity=CRITICAL)]

    def test_inside(self):
        _is(_decide(history=self._same(timedelta(minutes=10))), *_COOLDOWN, _id(1))

    def test_one_microsecond_inside_the_lower_bound(self):
        _is(_decide(history=self._same(self._C - _US)), *_COOLDOWN, _id(1))

    def test_exactly_the_lower_bound_is_outside(self):
        _is(_decide(history=self._same(self._C)), *_ALERT)

    def test_one_microsecond_outside_the_lower_bound(self):
        _is(_decide(history=self._same(self._C + _US)), *_ALERT)

    def test_same_timestamp_is_inside(self):
        _is(_decide(history=self._same(timedelta(0))), *_COOLDOWN, _id(1))

    def test_one_microsecond_later_is_outside(self):
        _is(_decide(history=self._same(-_US)), *_ALERT)

    def test_later_alert_never_suppresses(self):
        _is(_decide(history=self._same(-timedelta(minutes=10))), *_ALERT)

    def test_only_later_alerts_give_no_related_decision(self):
        history = [
            _prior(1, before=-timedelta(minutes=1), severity=CRITICAL),
            _prior(2, before=-timedelta(minutes=20), severity=CRITICAL),
        ]
        _is(_decide(history=history), *_ALERT, None)

    @pytest.mark.parametrize("before", [
        timedelta(0), timedelta(microseconds=1), timedelta(minutes=10),
    ])
    def test_zero_cooldown_never_suppresses(self, before):
        result = _decide(
            history=self._same(before), evaluation=_policy(cooldown_minutes=0),
        )
        _is(result, *_ALERT)

    def test_other_dedup_key_is_ignored(self):
        history = [_prior(1, severity=CRITICAL, dedup_key=_OTHER_KEY)]
        _is(_decide(history=history), *_ALERT)

    @pytest.mark.parametrize("prior, candidate", [
        (CRITICAL, CRITICAL),
        (CRITICAL, WARNING),
        (WARNING, WARNING),
    ])
    def test_equal_or_lower_severity_is_suppressed(self, prior, candidate):
        result = _decide(_subject(severity=candidate), [_prior(1, severity=prior)])
        _is(result, *_COOLDOWN, _id(1))

    @pytest.mark.parametrize("minutes", [1, 5, 120])
    def test_boundary_follows_the_policy(self, minutes):
        policy = _policy(cooldown_minutes=minutes, max_alerts_per_hour=1000)
        limit = timedelta(minutes=minutes)
        _is(_decide(history=self._same(limit - _US), evaluation=policy),
            *_COOLDOWN, _id(1))
        _is(_decide(history=self._same(limit), evaluation=policy), *_ALERT)

    def test_none_and_empty_string_are_different_streams(self):
        prior_key = compute_dedup_key("latency", None, "op")
        history = [_prior(1, severity=CRITICAL, dedup_key=prior_key)]
        _is(_decide(_subject(service_name=""), history), *_ALERT)
        _is(_decide(_subject(service_name=None), history), *_COOLDOWN, _id(1))

    def test_one_inside_among_many_outside(self):
        history = [
            _prior(1, before=timedelta(minutes=45), severity=CRITICAL),
            _prior(2, before=timedelta(minutes=29), severity=CRITICAL),
            _prior(3, before=-timedelta(minutes=5), severity=CRITICAL),
            _prior(4, before=timedelta(minutes=5), severity=CRITICAL,
                   dedup_key=_OTHER_KEY),
        ]
        _is(_decide(history=history), *_COOLDOWN, _id(2))


# ---------------------------------------------------------------------------
# F. Escalation
# ---------------------------------------------------------------------------

class TestEscalation:
    def test_higher_severity_escalates(self):
        result = _decide(_subject(severity=CRITICAL), [_prior(1, severity=WARNING)])
        _is(result, *_ESCALATION, _id(1))

    def test_info_to_warning_with_info_minimum(self):
        result = _decide(
            _subject(severity=WARNING), [_prior(1, severity=INFO)],
            _policy(min_severity=INFO),
        )
        _is(result, *_ESCALATION, _id(1))

    def test_info_to_critical(self):
        result = _decide(_subject(severity=CRITICAL), [_prior(1, severity=INFO)])
        _is(result, *_ESCALATION, _id(1))

    def test_must_be_strictly_higher(self):
        result = _decide(_subject(severity=WARNING), [_prior(1, severity=WARNING)])
        _is(result, *_COOLDOWN, _id(1))

    def test_compared_with_the_highest_severity_in_window(self):
        history = [_prior(1, severity=WARNING), _prior(2, severity=CRITICAL)]
        _is(_decide(_subject(severity=CRITICAL), history), *_COOLDOWN, _id(2))

    def test_escalates_over_the_highest_alert_in_window(self):
        history = [
            _prior(1, severity=INFO, before=timedelta(minutes=1)),
            _prior(2, severity=WARNING, before=timedelta(minutes=20)),
        ]
        _is(_decide(_subject(severity=CRITICAL), history), *_ESCALATION, _id(2))

    def test_later_higher_alert_does_not_block_an_earlier_candidate(self):
        history = [
            _prior(1, severity=INFO),
            _prior(2, severity=CRITICAL, before=-timedelta(minutes=5)),
        ]
        _is(_decide(_subject(severity=WARNING), history), *_ESCALATION, _id(1))

    def test_higher_alert_outside_window_does_not_block(self):
        history = [
            _prior(1, severity=WARNING),
            _prior(2, severity=CRITICAL, before=timedelta(minutes=30)),
        ]
        _is(_decide(_subject(severity=CRITICAL), history), *_ESCALATION, _id(1))

    def test_prior_alert_below_current_minimum_still_counts(self):
        result = _decide(
            _subject(severity=CRITICAL), [_prior(1, severity=INFO)],
            _policy(min_severity=CRITICAL),
        )
        _is(result, *_ESCALATION, _id(1))

    def test_no_escalation_without_a_window(self):
        _is(_decide(_subject(severity=CRITICAL), []), *_ALERT, None)

    def test_other_stream_never_causes_escalation(self):
        history = [_prior(1, severity=INFO, dedup_key=_OTHER_KEY)]
        _is(_decide(_subject(severity=CRITICAL), history), *_ALERT, None)


class TestEscalationDisabled:
    _OFF = dict(escalation_breaks_cooldown=False)

    def test_higher_severity_is_suppressed(self):
        result = _decide(
            _subject(severity=CRITICAL), [_prior(1, severity=WARNING)],
            _policy(**self._OFF),
        )
        _is(result, *_COOLDOWN, _id(1))

    @pytest.mark.parametrize("prior", list(Severity))
    @pytest.mark.parametrize("candidate", [WARNING, CRITICAL])
    def test_any_non_empty_window_suppresses(self, prior, candidate):
        result = _decide(
            _subject(severity=candidate), [_prior(1, severity=prior)],
            _policy(**self._OFF),
        )
        _is(result, *_COOLDOWN, _id(1))

    def test_related_follows_the_same_selection(self):
        history = [
            _prior(1, severity=INFO, before=timedelta(minutes=1)),
            _prior(2, severity=WARNING, before=timedelta(minutes=20)),
        ]
        result = _decide(
            _subject(severity=CRITICAL), history, _policy(**self._OFF),
        )
        _is(result, *_COOLDOWN, _id(2))

    def test_empty_window_still_alerts(self):
        _is(_decide(evaluation=_policy(**self._OFF)), *_ALERT, None)

    def test_window_boundary_unchanged(self):
        policy = _policy(**self._OFF)
        history = [_prior(1, severity=INFO, before=timedelta(minutes=30))]
        _is(_decide(history=history, evaluation=policy), *_ALERT)

    def test_no_result_is_ever_an_escalation(self):
        policy = _policy(min_severity=INFO, **self._OFF)
        for prior, candidate in itertools.product(Severity, Severity):
            result = _decide(
                _subject(severity=candidate), [_prior(1, severity=prior)], policy,
            )
            assert result.reason_code is not ReasonCode.ESCALATION

    def test_flag_only_matters_for_a_strictly_higher_candidate(self):
        for prior, candidate in itertools.product(Severity, Severity):
            history = [_prior(1, severity=prior)]
            on = _decide(
                _subject(severity=candidate), history,
                _policy(min_severity=INFO, escalation_breaks_cooldown=True),
            )
            off = _decide(
                _subject(severity=candidate), history,
                _policy(min_severity=INFO, escalation_breaks_cooldown=False),
            )
            if severity_rank(candidate) > severity_rank(prior):
                _is(on, *_ESCALATION, _id(1))
                _is(off, *_COOLDOWN, _id(1))
            else:
                assert on == off


# ---------------------------------------------------------------------------
# G. Storm cap
# ---------------------------------------------------------------------------

class TestStormCap:
    _CAP3 = dict(max_alerts_per_hour=3)

    def test_window_constant_is_sixty_minutes(self):
        assert STORM_WINDOW == timedelta(minutes=60)

    def test_below_the_cap_alerts(self):
        _is(_decide(history=_storm(2), evaluation=_policy(**self._CAP3)), *_ALERT)

    def test_at_the_cap_is_suppressed(self):
        _is(_decide(history=_storm(3), evaluation=_policy(**self._CAP3)), *_STORM)

    def test_above_the_cap_is_suppressed(self):
        _is(_decide(history=_storm(4), evaluation=_policy(**self._CAP3)), *_STORM)

    def test_default_cap_is_ten(self):
        _is(_decide(history=_storm(9)), *_ALERT)
        _is(_decide(history=_storm(10)), *_STORM)

    def test_exactly_sixty_minutes_is_not_counted(self):
        history = _storm(3, before=timedelta(minutes=60))
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_ALERT)

    def test_one_microsecond_inside_is_counted(self):
        history = _storm(3, before=timedelta(minutes=60) - _US)
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_STORM)

    def test_same_timestamp_is_counted(self):
        history = _storm(3, before=timedelta(0))
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_STORM)

    def test_later_alerts_are_not_counted(self):
        history = _storm(50, before=-_US)
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_ALERT)

    def test_only_alerts_inside_the_window_are_counted(self):
        history = (
            _storm(2, before=timedelta(minutes=5), start=500)
            + _storm(5, before=timedelta(minutes=61), start=600)
            + _storm(5, before=-timedelta(minutes=1), start=700)
        )
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_ALERT)
        history.append(_prior(800, before=timedelta(minutes=59), dedup_key=_OTHER_KEY))
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_STORM)

    def test_every_dedup_key_counts(self):
        keys = [
            compute_dedup_key("error_rate", "svc", f"op-{i}") for i in range(3)
        ]
        history = [
            _prior(500 + i, dedup_key=key) for i, key in enumerate(keys)
        ]
        assert len({alert.dedup_key for alert in history}) == 3
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_STORM)

    def test_own_stream_outside_cooldown_still_counts(self):
        history = [
            _prior(i, before=timedelta(minutes=45), severity=CRITICAL)
            for i in (1, 2, 3)
        ]
        _is(_decide(history=history, evaluation=_policy(**self._CAP3)), *_STORM)

    def test_related_is_none(self):
        result = _decide(history=_storm(3), evaluation=_policy(**self._CAP3))
        assert result.related_decision_id is None

    def test_escalation_is_capped(self):
        history = _storm(2) + [_prior(1, severity=WARNING)]
        result = _decide(
            _subject(severity=CRITICAL), history, _policy(**self._CAP3),
        )
        _is(result, *_STORM, None)

    def test_escalation_below_the_cap_alerts(self):
        history = _storm(1) + [_prior(1, severity=WARNING)]
        result = _decide(
            _subject(severity=CRITICAL), history, _policy(**self._CAP3),
        )
        _is(result, *_ESCALATION, _id(1))

    def test_cooldown_is_reported_before_storm_cap(self):
        history = _storm(20) + [_prior(1, severity=CRITICAL)]
        _is(_decide(history=history), *_COOLDOWN, _id(1))

    def test_cap_of_one_blocks_every_escalation_when_cooldown_fits_the_hour(self):
        result = _decide(
            _subject(severity=CRITICAL), [_prior(1, severity=WARNING)],
            _policy(max_alerts_per_hour=1),
        )
        _is(result, *_STORM, None)

    def test_long_cooldown_window_member_outside_the_storm_window(self):
        policy = _policy(cooldown_minutes=120, max_alerts_per_hour=1)
        history = [_prior(1, severity=WARNING, before=timedelta(minutes=90))]
        _is(_decide(_subject(severity=CRITICAL), history, policy),
            *_ESCALATION, _id(1))
        _is(_decide(_subject(severity=WARNING), history, policy),
            *_COOLDOWN, _id(1))

    @pytest.mark.parametrize("cooldown", [0, 1, 30, 600])
    def test_window_does_not_depend_on_cooldown(self, cooldown):
        policy = _policy(cooldown_minutes=cooldown, max_alerts_per_hour=2)
        _is(_decide(history=_storm(2, before=timedelta(minutes=59)),
                    evaluation=policy), *_STORM)
        _is(_decide(history=_storm(2, before=timedelta(minutes=60)),
                    evaluation=policy), *_ALERT)

    def test_cap_of_one(self):
        policy = _policy(max_alerts_per_hour=1)
        _is(_decide(evaluation=policy), *_ALERT)
        _is(_decide(history=_storm(1), evaluation=policy), *_STORM)


# ---------------------------------------------------------------------------
# H. Normal alert
# ---------------------------------------------------------------------------

class TestNormalAlert:
    def test_empty_history(self):
        _is(_decide(), *_ALERT, None)

    def test_empty_tuple_history(self):
        _is(_decide(history=()), *_ALERT, None)

    def test_history_outside_every_window(self):
        history = [
            _prior(1, before=timedelta(hours=3), severity=CRITICAL),
            _prior(2, before=-timedelta(hours=3), severity=CRITICAL),
            _prior(3, before=timedelta(days=2), dedup_key=_OTHER_KEY),
        ]
        _is(_decide(history=history), *_ALERT, None)

    @pytest.mark.parametrize("severity", [WARNING, CRITICAL])
    def test_alertable_severities(self, severity):
        _is(_decide(_subject(severity=severity)), *_ALERT, None)

    def test_null_service_and_operation(self):
        _is(_decide(_subject(service_name=None, operation_name=None)), *_ALERT, None)


# ---------------------------------------------------------------------------
# I. Related-decision tie-breaking
# ---------------------------------------------------------------------------

class TestRelatedSelection:
    def test_severity_beats_recency(self):
        history = [
            _prior(1, severity=WARNING, before=timedelta(minutes=1)),
            _prior(2, severity=CRITICAL, before=timedelta(minutes=25)),
        ]
        _is(_decide(history=history), *_COOLDOWN, _id(2))

    def test_recency_breaks_a_severity_tie(self):
        history = [
            _prior(1, severity=CRITICAL, before=timedelta(minutes=20)),
            _prior(2, severity=CRITICAL, before=timedelta(minutes=5)),
            _prior(3, severity=CRITICAL, before=timedelta(minutes=12)),
        ]
        _is(_decide(history=history), *_COOLDOWN, _id(2))

    def test_one_microsecond_decides_recency(self):
        history = [
            _prior(1, severity=CRITICAL, before=timedelta(minutes=5)),
            _prior(2, severity=CRITICAL, before=timedelta(minutes=5) - _US),
        ]
        _is(_decide(history=history), *_COOLDOWN, _id(2))

    def test_decision_id_breaks_a_full_tie(self):
        history = [
            _prior(30, severity=CRITICAL),
            _prior(10, severity=CRITICAL),
            _prior(20, severity=CRITICAL),
        ]
        _is(_decide(history=history), *_COOLDOWN, _id(10))

    def test_decision_id_order_is_lexicographic(self):
        low, high = "0" * 63 + "a", "9" * 64
        assert low < high
        history = [
            dataclasses.replace(_prior(1, severity=CRITICAL), decision_id=high),
            dataclasses.replace(_prior(2, severity=CRITICAL), decision_id=low),
        ]
        _is(_decide(history=history), *_COOLDOWN, low)

    def test_only_window_members_are_candidates(self):
        history = [
            _prior(1, severity=CRITICAL, before=timedelta(minutes=31)),
            _prior(2, severity=CRITICAL, before=-timedelta(minutes=1)),
            _prior(3, severity=CRITICAL, dedup_key=_OTHER_KEY),
            _prior(4, severity=WARNING, before=timedelta(minutes=29)),
        ]
        # The three CRITICAL alerts are outside the window, so the subject
        # is compared with the WARNING alone.
        _is(_decide(_subject(severity=CRITICAL), history), *_ESCALATION, _id(4))
        _is(_decide(_subject(severity=WARNING), history), *_COOLDOWN, _id(4))

    def test_escalation_uses_the_same_selection(self):
        history = [
            _prior(30, severity=WARNING, before=timedelta(minutes=5)),
            _prior(10, severity=WARNING, before=timedelta(minutes=5)),
            _prior(20, severity=INFO, before=timedelta(minutes=1)),
        ]
        _is(_decide(_subject(severity=CRITICAL), history), *_ESCALATION, _id(10))

    def test_same_answer_for_every_permutation(self):
        window = [
            _prior(1, severity=WARNING, before=timedelta(minutes=2)),
            _prior(2, severity=CRITICAL, before=timedelta(minutes=9)),
            _prior(3, severity=CRITICAL, before=timedelta(minutes=9)),
            _prior(4, severity=CRITICAL, before=timedelta(minutes=20)),
        ]
        results = {
            _decide(history=list(order)) for order in itertools.permutations(window)
        }
        assert len(results) == 1
        _is(results.pop(), *_COOLDOWN, _id(2))


# ---------------------------------------------------------------------------
# J. Determinism
# ---------------------------------------------------------------------------

def _reference(subject, history, evaluation, evaluated_at):
    """
    A deliberately plain restatement of the rules, written with datetime
    bounds instead of ages, to compare the engine against.
    """
    rank = {INFO: 0, WARNING: 1, CRITICAL: 2}
    e = subject.event_time.astimezone(timezone.utc)
    now = evaluated_at.astimezone(timezone.utc)
    alerts = [(a, a.event_time.astimezone(timezone.utc)) for a in history]

    if not evaluation.enabled:
        return (Decision.SUPPRESSED, ReasonCode.KILL_SWITCH, None)
    if rank[subject.severity] < rank[evaluation.min_severity]:
        return (Decision.NOT_ALERTABLE, ReasonCode.BELOW_MIN_SEVERITY, None)
    if now - e > timedelta(minutes=evaluation.max_alert_age_minutes):
        return (Decision.NOT_ALERTABLE, ReasonCode.STALE, None)

    same_anomaly = sorted(
        a.decision_id for a, _ in alerts if a.anomaly_id == subject.anomaly_id
    )
    if same_anomaly:
        return (Decision.SUPPRESSED, ReasonCode.DUPLICATE_ANOMALY, same_anomaly[0])

    lower = e - timedelta(minutes=evaluation.cooldown_minutes)
    window = [
        (a, t) for a, t in alerts
        if a.dedup_key == subject.dedup_key and lower < t <= e
    ]
    related = None
    escalating = False
    if window:
        ordered = sorted(
            window, key=lambda p: (-rank[p[0].severity], e - p[1], p[0].decision_id),
        )
        related = ordered[0][0].decision_id
        top = max(rank[a.severity] for a, _ in window)
        if evaluation.escalation_breaks_cooldown and rank[subject.severity] > top:
            escalating = True
        else:
            return (Decision.SUPPRESSED, ReasonCode.COOLDOWN, related)

    storm_lower = e - timedelta(minutes=60)
    count = len([1 for _, t in alerts if storm_lower < t <= e])
    if count >= evaluation.max_alerts_per_hour:
        return (Decision.SUPPRESSED, ReasonCode.STORM_CAP, None)
    if escalating:
        return (Decision.ALERT, ReasonCode.ESCALATION, related)
    return (Decision.ALERT, ReasonCode.SEVERITY_MET, None)


class _ShiftingZone(tzinfo):
    """
    A zone whose UTC offset changes at a wall-clock instant, like a
    daylight-saving change.  One instance is shared by every datetime that
    uses it.
    """

    def __init__(self, switch: datetime, before: timedelta, after: timedelta):
        self._switch = switch
        self._before = before
        self._after = after

    def utcoffset(self, dt):
        wall = dt.replace(tzinfo=None)
        return self._before if wall < self._switch else self._after

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "SHIFT"


class TestDeterminism:
    def test_repeated_calls_are_identical(self):
        history = _storm(4) + [_prior(1, severity=WARNING)]
        first = _decide(history=history)
        assert all(_decide(history=history) == first for _ in range(5))

    def test_all_permutations_of_a_mixed_history(self):
        history = [
            _prior(1, severity=WARNING, before=timedelta(minutes=5)),
            _prior(2, severity=WARNING, before=timedelta(minutes=5)),
            _prior(3, severity=INFO, before=timedelta(minutes=29)),
            _prior(4, before=timedelta(minutes=40), dedup_key=_OTHER_KEY),
            _prior(5, before=-timedelta(minutes=3), severity=CRITICAL),
            _prior(6, before=timedelta(minutes=61), dedup_key=_OTHER_KEY),
        ]
        results = {
            _decide(history=list(order))
            for order in itertools.permutations(history)
        }
        assert results == {EngineDecision(*_ESCALATION, _id(1))}

    def test_list_and_tuple_history_agree(self):
        history = _storm(3) + [_prior(1, severity=CRITICAL)]
        assert _decide(history=history) == _decide(history=tuple(history))

    def test_inputs_are_not_mutated(self):
        history = _storm(3) + [_prior(1, severity=CRITICAL)]
        before = list(history)
        subject = _subject()
        snapshot = dataclasses.asdict(subject)
        _decide(subject, history)
        assert history == before
        assert dataclasses.asdict(subject) == snapshot

    def test_matches_reference_on_seeded_random_cases(self):
        rng = random.Random(13_3)
        offsets = [
            timedelta(0), _US, -_US, timedelta(minutes=5), timedelta(minutes=29),
            timedelta(minutes=30) - _US, timedelta(minutes=30),
            timedelta(minutes=30) + _US, timedelta(minutes=45),
            timedelta(minutes=60) - _US, timedelta(minutes=60),
            timedelta(minutes=60) + _US, timedelta(minutes=90),
            -timedelta(minutes=10), timedelta(hours=30),
        ]
        ages = [
            timedelta(0), timedelta(minutes=60), timedelta(minutes=60) + _US,
            timedelta(minutes=1), -timedelta(minutes=5),
        ]
        seen_reasons = set()
        for _ in range(4000):
            policy = _policy(
                enabled=rng.random() > 0.05,
                min_severity=rng.choice(list(Severity)),
                cooldown_minutes=rng.choice([0, 30, 30, 90]),
                escalation_breaks_cooldown=rng.random() > 0.3,
                max_alerts_per_hour=rng.choice([1, 2, 3, 10]),
            )
            subject = _subject(severity=rng.choice(list(Severity)))
            history = []
            for n in range(rng.randint(0, 7)):
                history.append(_prior(
                    n + 1,
                    before=rng.choice(offsets),
                    severity=rng.choice(list(Severity)),
                    dedup_key=rng.choice([_SAME_KEY, _SAME_KEY, _OTHER_KEY]),
                    anomaly_id=_SUBJECT_ANOMALY if rng.random() < 0.04 else None,
                ))
            rng.shuffle(history)
            now = _E + rng.choice(ages)
            result = _decide(subject, history, policy, now)
            expected = _reference(subject, history, policy, now)
            assert (
                result.decision, result.reason_code, result.related_decision_id,
            ) == expected
            seen_reasons.add(result.reason_code)
        assert seen_reasons == set(ReasonCode)

    @pytest.mark.parametrize("far", [
        datetime(1990, 1, 1, tzinfo=timezone.utc),
        datetime(2200, 1, 1, tzinfo=timezone.utc),
    ])
    def test_independent_of_the_real_clock(self, far):
        """Only the supplied times matter, wherever they lie."""
        subject = _subject(event_time=far)
        history = [dataclasses.replace(
            _prior(1, severity=CRITICAL), event_time=far - timedelta(minutes=10),
        )]
        result = _decide(subject, history, evaluated_at=far + timedelta(minutes=1))
        _is(result, *_COOLDOWN, _id(1))
        stale = _decide(subject, history, evaluated_at=far + timedelta(minutes=61))
        _is(stale, *_STALE)

    @pytest.mark.parametrize("hours", [-11, -5, 0, 5.5, 14])
    def test_same_instants_in_any_offset_give_one_result(self, hours):
        zone = timezone(timedelta(hours=hours))
        base_history = _storm(2) + [
            _prior(1, severity=WARNING, before=timedelta(minutes=30) - _US),
        ]
        expected = _decide(_subject(severity=CRITICAL), base_history)
        _is(expected, *_ESCALATION, _id(1))

        shifted_history = [
            dataclasses.replace(a, event_time=a.event_time.astimezone(zone))
            for a in base_history
        ]
        shifted = _decide(
            _subject(severity=CRITICAL, event_time=_E.astimezone(zone)),
            shifted_history,
            evaluated_at=_NOW.astimezone(zone),
        )
        assert shifted == expected

    def test_mixed_offsets_within_one_call(self):
        east = timezone(timedelta(hours=9))
        west = timezone(timedelta(hours=-8))
        history = [dataclasses.replace(
            _prior(1, severity=CRITICAL, before=timedelta(minutes=30)),
            event_time=(_E - timedelta(minutes=30)).astimezone(west),
        )]
        result = _decide(
            _subject(event_time=_E.astimezone(east)), history,
            evaluated_at=_NOW,
        )
        _is(result, *_ALERT)

    def test_offset_falls_back_between_prior_and_subject(self):
        """
        Wall clocks 11:50 and 12:10 look 20 minutes apart, but the zone's
        offset drops from +2h to +1h at 12:00, so they are 80 minutes apart.
        The prior alert is outside the cooldown and storm windows.
        """
        zone = _ShiftingZone(
            datetime(2026, 10, 5, 12, 0), timedelta(hours=2), timedelta(hours=1),
        )
        prior_time = datetime(2026, 10, 5, 11, 50, tzinfo=zone)
        subject_time = datetime(2026, 10, 5, 12, 10, tzinfo=zone)
        assert subject_time - prior_time == timedelta(minutes=20)
        assert (
            subject_time.astimezone(timezone.utc)
            - prior_time.astimezone(timezone.utc)
        ) == timedelta(minutes=80)

        history = [dataclasses.replace(
            _prior(1, severity=CRITICAL), event_time=prior_time,
        )]
        result = _decide(
            _subject(event_time=subject_time), history,
            _policy(max_alerts_per_hour=1),
            evaluated_at=subject_time,
        )
        _is(result, *_ALERT)

    def test_offset_springs_forward_between_prior_and_subject(self):
        """
        Wall clocks 11:50 and 13:10 look 80 minutes apart, but the offset
        rises from +1h to +2h at 12:00, so they are 20 minutes apart.  The
        prior alert is inside the cooldown window.
        """
        zone = _ShiftingZone(
            datetime(2026, 10, 5, 12, 0), timedelta(hours=1), timedelta(hours=2),
        )
        prior_time = datetime(2026, 10, 5, 11, 50, tzinfo=zone)
        subject_time = datetime(2026, 10, 5, 13, 10, tzinfo=zone)
        assert subject_time - prior_time == timedelta(minutes=80)

        history = [dataclasses.replace(
            _prior(1, severity=CRITICAL), event_time=prior_time,
        )]
        result = _decide(
            _subject(event_time=subject_time), history, evaluated_at=subject_time,
        )
        _is(result, *_COOLDOWN, _id(1))

    def test_stale_uses_instants_across_an_offset_change(self):
        zone = _ShiftingZone(
            datetime(2026, 10, 5, 12, 0), timedelta(hours=2), timedelta(hours=1),
        )
        event = datetime(2026, 10, 5, 11, 50, tzinfo=zone)
        evaluated = datetime(2026, 10, 5, 12, 10, tzinfo=zone)
        _is(_decide(_subject(event_time=event), evaluated_at=evaluated), *_STALE)


# ---------------------------------------------------------------------------
# K. Informational fields cannot reach the engine
# ---------------------------------------------------------------------------

_INFORMATIONAL = {"confidence", "limitations", "summary", "summary_truncated", "payload"}


class TestInformationalFields:
    def test_decide_signature(self):
        parameters = list(inspect.signature(decide).parameters)
        assert parameters == ["subject", "history", "evaluation", "evaluated_at"]

    @pytest.mark.parametrize("model", [AlertSubject, PriorAlert, EngineDecision])
    def test_models_have_no_informational_field(self, model):
        names = {field.name for field in dataclasses.fields(model)}
        assert names.isdisjoint(_INFORMATIONAL)

    def test_exact_model_fields(self):
        assert [f.name for f in dataclasses.fields(AlertSubject)] == [
            "investigation_id", "anomaly_id", "anomaly_type", "service_name",
            "operation_name", "event_time", "severity",
        ]
        assert [f.name for f in dataclasses.fields(PriorAlert)] == [
            "decision_id", "anomaly_id", "dedup_key", "event_time", "severity",
            "decision",
        ]
        assert [f.name for f in dataclasses.fields(EngineDecision)] == [
            "decision", "reason_code", "related_decision_id",
        ]

    def test_subject_rejects_a_confidence_argument(self):
        with pytest.raises(TypeError):
            _subject(confidence=Confidence.HIGH)

    def test_engine_source_never_mentions_confidence_in_code(self):
        tree = ast.parse(inspect.getsource(alert_engine))
        names = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        } | {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert names.isdisjoint(_INFORMATIONAL | {"Confidence"})

    def test_persist_summary_has_no_effect(self):
        scenarios = [
            (_subject(), []),
            (_subject(severity=INFO), []),
            (_subject(), [_prior(1, severity=CRITICAL)]),
            (_subject(severity=CRITICAL), [_prior(1, severity=WARNING)]),
            (_subject(), _storm(10)),
            (_subject(), [_prior(1, anomaly_id=_SUBJECT_ANOMALY)]),
        ]
        for subject, history in scenarios:
            off = _decide(subject, history, _policy(persist_summary=False))
            on = _decide(subject, history, _policy(persist_summary=True))
            assert on == off

    def test_history_has_no_policy_version(self):
        for model in (AlertSubject, PriorAlert, EngineDecision):
            names = {field.name for field in dataclasses.fields(model)}
            assert "policy_version" not in names

    def test_whole_policy_is_not_accepted(self):
        from alert_policy import DeliveryPolicy, GuardrailPolicy

        whole = AlertPolicy(
            policy_schema_version="1.0.0",
            policy_version="1.0.0",
            evaluation=_policy(),
            delivery=DeliveryPolicy(channels=()),
            guardrails=GuardrailPolicy(),
        )
        with pytest.raises(ValueError, match="EvaluationPolicy"):
            decide(_subject(), [], whole, _NOW)


class TestInvestigationIdIsInert:
    _IDS = [_id(0x1), _id(0x2), "f" * 64, "0" * 64]

    def test_does_not_affect_dedup_key(self):
        keys = {_subject(investigation_id=i).dedup_key for i in self._IDS}
        assert keys == {_SAME_KEY}

    def test_dedup_key_is_the_identity_function_of_three_fields(self):
        subject = _subject(
            anomaly_type="tool_failure", service_name=None,
            operation_name="tool.execute/TimeoutError",
        )
        assert subject.dedup_key == compute_dedup_key(
            "tool_failure", None, "tool.execute/TimeoutError",
        )

    def test_dedup_key_ignores_every_other_field(self):
        base = _subject().dedup_key
        assert _subject(anomaly_id=_id(0xEE)).dedup_key == base
        assert _subject(severity=INFO).dedup_key == base
        assert _subject(event_time=_E + timedelta(days=1)).dedup_key == base

    @pytest.mark.parametrize("scenario", [
        "alert", "below", "stale", "duplicate", "cooldown", "escalation", "storm",
        "kill",
    ])
    def test_does_not_affect_the_decision(self, scenario):
        subject_kwargs, history, policy, now = {
            "alert": ({}, [], _policy(), _NOW),
            "below": ({"severity": INFO}, [], _policy(), _NOW),
            "stale": ({}, [], _policy(), _E + timedelta(days=1)),
            "duplicate": (
                {}, [_prior(1, anomaly_id=_SUBJECT_ANOMALY)], _policy(), _NOW,
            ),
            "cooldown": ({}, [_prior(1, severity=CRITICAL)], _policy(), _NOW),
            "escalation": ({}, [_prior(1, severity=WARNING)], _policy(), _NOW),
            "storm": ({}, _storm(10), _policy(), _NOW),
            "kill": ({}, [], _policy(enabled=False), _NOW),
        }[scenario]
        results = {
            _decide(
                _subject(investigation_id=i, **subject_kwargs), history, policy, now,
            )
            for i in self._IDS
        }
        assert len(results) == 1

    def test_investigation_id_equal_to_a_history_decision_id_is_irrelevant(self):
        history = [_prior(1, severity=CRITICAL)]
        same = _decide(_subject(investigation_id=_id(1)), history)
        other = _decide(_subject(investigation_id=_id(0x77)), history)
        assert same == other


# ---------------------------------------------------------------------------
# L. Fail closed
# ---------------------------------------------------------------------------

_NAIVE = datetime(2026, 10, 5, 12, 0, 0)
_BAD_DIGESTS = ["", "abc", "A" * 64, "a" * 63, "a" * 65, "g" * 64, None, 5, b"a" * 64]


class TestSubjectValidation:
    @pytest.mark.parametrize("field", ["investigation_id", "anomaly_id"])
    @pytest.mark.parametrize("bad", _BAD_DIGESTS)
    def test_digest_fields(self, field, bad):
        with pytest.raises(ValueError, match=field):
            _subject(**{field: bad})

    @pytest.mark.parametrize("bad", ["", None, 5, b"latency"])
    def test_anomaly_type(self, bad):
        with pytest.raises(ValueError, match="anomaly_type"):
            _subject(anomaly_type=bad)

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    @pytest.mark.parametrize("bad", [5, 1.5, b"x", ["x"], True])
    def test_names_must_be_str_or_none(self, field, bad):
        with pytest.raises(ValueError, match=field):
            _subject(**{field: bad})

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    def test_names_may_be_none_or_empty(self, field):
        assert getattr(_subject(**{field: None}), field) is None
        assert getattr(_subject(**{field: ""}), field) == ""

    @pytest.mark.parametrize("field", ["anomaly_type", "service_name", "operation_name"])
    def test_lone_surrogate_rejected(self, field):
        with pytest.raises(ValueError, match="surrogate"):
            _subject(**{field: "bad\ud800"})

    def test_names_are_not_normalized(self):
        assert _subject(service_name="svc ").service_name == "svc "
        assert _subject(service_name="svc ").dedup_key != _SAME_KEY
        assert _subject(service_name="SVC").dedup_key != _SAME_KEY

    def test_naive_event_time(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            _subject(event_time=_NAIVE)

    @pytest.mark.parametrize("bad", ["2026-10-05T12:00:00Z", 0, None, 1.5])
    def test_event_time_must_be_datetime(self, bad):
        with pytest.raises(ValueError, match="event_time"):
            _subject(event_time=bad)

    @pytest.mark.parametrize("bad", [
        "CRITICAL", "critical", "FATAL", None, 2, Confidence.HIGH, Decision.ALERT,
    ])
    def test_severity_must_be_a_severity(self, bad):
        with pytest.raises(ValueError, match="severity"):
            _subject(severity=bad)

    @pytest.mark.parametrize("bad", [
        None, {}, "subject", 5, _prior(1),
    ])
    def test_decide_rejects_a_non_subject(self, bad):
        with pytest.raises(ValueError, match="AlertSubject"):
            decide(bad, [], _policy(), _NOW)

    def test_decide_rejects_a_look_alike(self):
        @dataclasses.dataclass(frozen=True)
        class Fake:
            investigation_id: str = _id(1)
            anomaly_id: str = _SUBJECT_ANOMALY
            anomaly_type: str = "latency"
            service_name: str = "svc"
            operation_name: str = "op"
            event_time: datetime = _E
            severity: Severity = CRITICAL
            dedup_key: str = _SAME_KEY

        with pytest.raises(ValueError, match="AlertSubject"):
            decide(Fake(), [], _policy(), _NOW)


class TestPriorAlertValidation:
    @pytest.mark.parametrize("field", ["decision_id", "anomaly_id", "dedup_key"])
    @pytest.mark.parametrize("bad", _BAD_DIGESTS)
    def test_digest_fields(self, field, bad):
        with pytest.raises(ValueError, match=field):
            dataclasses.replace(_prior(1), **{field: bad})

    def test_naive_event_time(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            dataclasses.replace(_prior(1), event_time=_NAIVE)

    @pytest.mark.parametrize("bad", ["2026-10-05", 0, None])
    def test_event_time_must_be_datetime(self, bad):
        with pytest.raises(ValueError, match="event_time"):
            dataclasses.replace(_prior(1), event_time=bad)

    @pytest.mark.parametrize("bad", ["WARNING", None, 1, Decision.ALERT])
    def test_severity_must_be_a_severity(self, bad):
        with pytest.raises(ValueError, match="severity"):
            dataclasses.replace(_prior(1), severity=bad)

    @pytest.mark.parametrize("bad", [
        Decision.SUPPRESSED, Decision.NOT_ALERTABLE, "ALERT", None, True,
    ])
    def test_decision_must_be_alert(self, bad):
        with pytest.raises(ValueError, match="ALERT"):
            dataclasses.replace(_prior(1), decision=bad)

    def test_alert_is_accepted(self):
        assert _prior(1).decision is Decision.ALERT


class TestHistoryValidation:
    @pytest.mark.parametrize("bad", [
        None, "history", b"history", {}, set(), frozenset(), 5,
    ])
    def test_container_must_be_list_or_tuple(self, bad):
        with pytest.raises(ValueError, match="list or tuple"):
            decide(_subject(), bad, _policy(), _NOW)

    def test_generator_rejected(self):
        with pytest.raises(ValueError, match="list or tuple"):
            decide(_subject(), (a for a in [_prior(1)]), _policy(), _NOW)

    def test_dict_values_view_rejected(self):
        with pytest.raises(ValueError, match="list or tuple"):
            decide(_subject(), {"a": _prior(1)}.values(), _policy(), _NOW)

    @pytest.mark.parametrize("bad", [
        None, "x", 5, {}, _subject(), EngineDecision(*_ALERT, None),
        ("id", "anomaly"),
    ])
    def test_item_must_be_a_prior_alert(self, bad):
        with pytest.raises(ValueError, match="history item 1 must be PriorAlert"):
            decide(_subject(), [_prior(1), bad], _policy(), _NOW)

    def test_duplicate_decision_id_rejected(self):
        with pytest.raises(ValueError, match="twice"):
            decide(_subject(), [_prior(1), _prior(1)], _policy(), _NOW)

    def test_duplicate_decision_id_rejected_even_when_rows_differ(self):
        second = dataclasses.replace(
            _prior(1), severity=CRITICAL, dedup_key=_OTHER_KEY,
            event_time=_E - timedelta(days=3),
        )
        with pytest.raises(ValueError, match="twice"):
            decide(_subject(), [_prior(1), second], _policy(), _NOW)

    def test_duplicate_rejected_before_any_rule(self):
        for policy in (_policy(enabled=False), _policy(min_severity=CRITICAL)):
            with pytest.raises(ValueError, match="twice"):
                decide(
                    _subject(severity=WARNING), [_prior(1), _prior(1)], policy, _NOW,
                )

    def test_non_alert_item_smuggled_past_construction_is_rejected(self):
        tampered = _prior(1)
        object.__setattr__(tampered, "decision", Decision.SUPPRESSED)
        with pytest.raises(ValueError, match="ALERT"):
            decide(_subject(), [tampered], _policy(), _NOW)

    def test_distinct_ids_with_equal_content_are_accepted(self):
        history = [_prior(1, dedup_key=_OTHER_KEY), _prior(2, dedup_key=_OTHER_KEY)]
        _is(_decide(history=history), *_ALERT)


class TestEvaluationAndClockValidation:
    @pytest.mark.parametrize("bad", [
        None, {}, {"enabled": True}, "policy", 5,
    ])
    def test_evaluation_must_be_an_evaluation_policy(self, bad):
        with pytest.raises(ValueError, match="EvaluationPolicy"):
            decide(_subject(), [], bad, _NOW)

    def test_naive_evaluated_at(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            decide(_subject(), [], _policy(), _NAIVE)

    @pytest.mark.parametrize("bad", ["2026-10-05T12:01:00Z", None, 0, 1.5])
    def test_evaluated_at_must_be_datetime(self, bad):
        with pytest.raises(ValueError, match="evaluated_at"):
            decide(_subject(), [], _policy(), bad)

    def test_evaluated_at_is_required(self):
        with pytest.raises(TypeError):
            decide(_subject(), [], _policy())

    @pytest.mark.parametrize("field", ["max_alert_age_minutes", "cooldown_minutes"])
    def test_overflowing_duration_is_a_value_error(self, field):
        policy = _policy(**{field: 10**20})
        with pytest.raises(ValueError, match=field):
            decide(_subject(), [], policy, _NOW)

    def test_overflow_is_reported_even_when_the_kill_switch_is_on(self):
        policy = _policy(enabled=False, cooldown_minutes=10**20)
        with pytest.raises(ValueError, match="cooldown_minutes"):
            decide(_subject(), [], policy, _NOW)

    def test_largest_representable_duration_is_accepted(self):
        policy = _policy(max_alert_age_minutes=999_999_999 * 1440)
        _is(_decide(evaluation=policy, evaluated_at=_E + timedelta(days=9000)), *_ALERT)

    def test_event_time_not_representable_in_utc_is_a_value_error(self):
        edge = datetime(1, 1, 1, 0, 0, tzinfo=timezone(timedelta(hours=5)))
        with pytest.raises(ValueError, match="UTC"):
            decide(_subject(event_time=edge), [], _policy(), _NOW)

    def test_history_time_not_representable_in_utc_is_a_value_error(self):
        edge = datetime(9999, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=-5)))
        history = [dataclasses.replace(_prior(1), event_time=edge)]
        with pytest.raises(ValueError, match="UTC"):
            decide(_subject(), history, _policy(), _NOW)

    def test_extreme_but_valid_times_do_not_overflow(self):
        low = datetime(1, 1, 1, tzinfo=timezone.utc)
        high = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        history = [dataclasses.replace(_prior(1), event_time=high)]
        result = _decide(
            _subject(event_time=low), history,
            _policy(cooldown_minutes=10**9), evaluated_at=low,
        )
        _is(result, *_ALERT)
        reverse = [dataclasses.replace(_prior(1, severity=CRITICAL), event_time=low)]
        capped = _decide(
            _subject(event_time=high), reverse,
            _policy(cooldown_minutes=10**10), evaluated_at=high,
        )
        _is(capped, *_COOLDOWN, _id(1))


class TestEngineDecisionModel:
    @pytest.mark.parametrize("decision, reason", [
        (decision, reason)
        for decision in Decision for reason in ReasonCode
        if reason not in REASONS_BY_DECISION[decision]
    ])
    def test_invalid_pairs_rejected(self, decision, reason):
        related = _id(1) if reason in REASONS_WITH_RELATED_DECISION else None
        with pytest.raises(ValueError, match="is not valid for decision"):
            EngineDecision(decision, reason, related)

    @pytest.mark.parametrize("decision, reason", [
        (decision, reason)
        for decision in Decision for reason in REASONS_BY_DECISION[decision]
    ])
    def test_valid_pairs_accepted(self, decision, reason):
        related = _id(1) if reason in REASONS_WITH_RELATED_DECISION else None
        assert EngineDecision(decision, reason, related).reason_code is reason

    @pytest.mark.parametrize("reason", sorted(
        REASONS_WITH_RELATED_DECISION, key=lambda r: r.value,
    ))
    def test_related_required(self, reason):
        decision = next(d for d in Decision if reason in REASONS_BY_DECISION[d])
        with pytest.raises(ValueError, match="related_decision_id"):
            EngineDecision(decision, reason, None)

    @pytest.mark.parametrize("reason", sorted(
        set(ReasonCode) - REASONS_WITH_RELATED_DECISION, key=lambda r: r.value,
    ))
    def test_related_forbidden(self, reason):
        decision = next(d for d in Decision if reason in REASONS_BY_DECISION[d])
        with pytest.raises(ValueError, match="must be None"):
            EngineDecision(decision, reason, _id(1))

    def test_related_must_be_a_digest(self):
        with pytest.raises(ValueError, match="related_decision_id"):
            EngineDecision(*_COOLDOWN, "abc")

    @pytest.mark.parametrize("decision, reason", [
        ("ALERT", ReasonCode.SEVERITY_MET),
        (Decision.ALERT, "severity_met"),
    ])
    def test_enums_required(self, decision, reason):
        with pytest.raises(ValueError):
            EngineDecision(decision, reason, None)


class TestImmutability:
    def test_models_are_frozen_dataclasses(self):
        for model in (AlertSubject, PriorAlert, EngineDecision):
            assert dataclasses.is_dataclass(model)
            assert model.__dataclass_params__.frozen is True

    def test_subject_is_frozen(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            _subject().severity = INFO

    def test_prior_alert_is_frozen(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            _prior(1).event_time = _E

    def test_result_is_frozen(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            _decide().decision = Decision.SUPPRESSED

    def test_dedup_key_is_read_only(self):
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            _subject().dedup_key = _OTHER_KEY

    def test_results_are_hashable_and_comparable(self):
        assert _decide() == EngineDecision(*_ALERT, None)
        assert len({_decide(), _decide()}) == 1


# ---------------------------------------------------------------------------
# M. Purity
# ---------------------------------------------------------------------------

_ALLOWED_MODULES = {
    "__future__", "dataclasses", "datetime", "typing",
    "alert_identity", "alert_models", "alert_policy",
}
_ALLOWED_DATETIME_NAMES = {"datetime", "timedelta", "timezone"}
_FORBIDDEN_NAMES = {
    "now", "utcnow", "today", "fromtimestamp", "open", "print", "input",
    "getenv", "environ", "putenv", "system", "exec", "eval", "compile",
    "__import__", "globals", "locals", "setattr",
}
_FORBIDDEN_MODULES = {
    "os", "sys", "io", "pathlib", "time", "random", "secrets", "uuid",
    "logging", "socket", "ssl", "http", "urllib", "requests", "subprocess",
    "psycopg", "psycopg2", "sqlite3", "json", "argparse", "threading",
    "asyncio", "similarity_search", "historical_context", "embedding_store",
    "embedding_pipeline", "embedding_provider", "incident_document",
    "retrieval_db",
}


class TestPurity:
    @pytest.fixture(scope="class")
    def tree(self):
        return ast.parse(inspect.getsource(alert_engine))

    def _imported_modules(self, tree) -> set[str]:
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0
                modules.add(node.module)
        return modules

    def test_imports_are_exactly_the_allowed_set(self, tree):
        assert self._imported_modules(tree) == _ALLOWED_MODULES

    def test_no_forbidden_module_is_imported(self, tree):
        roots = {name.split(".")[0] for name in self._imported_modules(tree)}
        assert roots.isdisjoint(_FORBIDDEN_MODULES)

    def test_imports_are_all_at_module_level(self, tree):
        nested = [
            node for scope in ast.walk(tree)
            if isinstance(scope, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
            for node in ast.walk(scope)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert nested == []

    def test_only_safe_names_from_datetime(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "datetime":
                assert {a.name for a in node.names} <= _ALLOWED_DATETIME_NAMES

    def test_only_pure_names_from_alert_policy(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "alert_policy":
                assert {a.name for a in node.names} == {"EvaluationPolicy"}

    def test_no_clock_io_or_environment_access(self, tree):
        used = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        } | {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert used.isdisjoint(_FORBIDDEN_NAMES)

    def test_no_global_or_nonlocal_statement(self, tree):
        assert not any(
            isinstance(node, (ast.Global, ast.Nonlocal)) for node in ast.walk(tree)
        )

    def test_module_level_state_is_constant(self, tree):
        assigned = set()
        for node in tree.body:
            if isinstance(node, ast.AnnAssign):
                assigned.add(node.target.id)
            elif isinstance(node, ast.Assign):
                assigned.update(t.id for t in node.targets)
        assert assigned == {"STORM_WINDOW", "_ZERO"}
        assert isinstance(alert_engine.STORM_WINDOW, timedelta)

    def test_no_with_try_finally_or_loops_over_external_resources(self, tree):
        assert not any(
            isinstance(node, (ast.With, ast.AsyncWith, ast.Await, ast.Yield))
            for node in ast.walk(tree)
        )

    def test_decide_does_not_read_the_clock(self, monkeypatch):
        class _Clockless(datetime):
            @classmethod
            def now(cls, tz=None):
                raise AssertionError("the engine read the clock")

            @classmethod
            def utcnow(cls):
                raise AssertionError("the engine read the clock")

            @classmethod
            def today(cls):
                raise AssertionError("the engine read the clock")

        # Every datetime handed to the engine is a _Clockless, so the engine's
        # own type checks still pass while its clock methods are booby-trapped.
        event = _Clockless(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(alert_engine, "datetime", _Clockless)
        history = [
            _prior(n, event_time=event - timedelta(minutes=10), severity=severity,
                   dedup_key=key)
            for n, severity, key in (
                (1, WARNING, _SAME_KEY), (500, WARNING, _OTHER_KEY),
                (501, WARNING, _OTHER_KEY),
            )
        ]
        assert all(type(a.event_time) is _Clockless for a in history)
        result = decide(
            _subject(event_time=event), history, _policy(),
            event + timedelta(minutes=1),
        )
        _is(result, *_ESCALATION, _id(1))

    def test_public_surface(self):
        public = {
            name for name, value in vars(alert_engine).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == alert_engine.__name__
        }
        assert public == {"AlertSubject", "PriorAlert", "EngineDecision", "decide"}

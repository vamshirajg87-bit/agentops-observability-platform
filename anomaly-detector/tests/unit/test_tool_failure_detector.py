"""
Tests for ToolFailureDetector.

All input records represent tool.execute spans.  The caller (Phase 10.4) is
responsible for filtering to span_name='tool.execute' before calling this
detector.

Group key: (service_name, error_type).
Rate numerator:   errors of this error_type in the window.
Rate denominator: ALL tool.execute spans (OK + ERROR) in the window.
"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from detector import Severity
from detector.anomaly_types import ErrorDetectorConfig, ToolRecord
from detector.tool_failure_detector import ToolFailureDetector

T0 = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tr(
    days_before: float,
    is_error: bool = False,
    error_type: str | None = None,
    service: str = "svc-a",
) -> ToolRecord:
    return ToolRecord(
        trace_id=f"t-{days_before}",
        span_id=f"s-{days_before}",
        service_name=service,
        is_error=is_error,
        error_type=error_type if is_error else None,
        start_time=T0 - timedelta(days=days_before),
    )


def _ok(days_before: float, **kwargs) -> ToolRecord:
    return _tr(days_before, is_error=False, **kwargs)


def _err(days_before: float, error_type: str = "ToolTimeout", **kwargs) -> ToolRecord:
    return _tr(days_before, is_error=True, error_type=error_type, **kwargs)


def _default_cfg(**overrides) -> ErrorDetectorConfig:
    base = dict(
        recent_window_hours=24,
        baseline_window_days=7,
        persistence_k=5,
        min_sample_for_info=10,
        min_sample_for_warning=30,
    )
    base.update(overrides)
    return ErrorDetectorConfig(**base)


def _baseline_days(n: int) -> list[float]:
    return [1.05 + 5.9 * i / max(n - 1, 1) for i in range(n)]


def _recent_days(n: int) -> list[float]:
    return [0.01 + 0.97 * i / max(n - 1, 1) for i in range(n)]


# ---------------------------------------------------------------------------
# Guards: non-qualifying current spans
# ---------------------------------------------------------------------------

class TestGuards:

    def test_success_span_returns_empty(self):
        current = _ok(0.01)
        events = ToolFailureDetector().detect(current, [])
        assert events == []

    def test_error_span_with_null_error_type_returns_empty(self):
        # error_type=None means we can't classify this failure
        current = _tr(0.01, is_error=True, error_type=None)
        events = ToolFailureDetector().detect(current, [])
        assert events == []


# ---------------------------------------------------------------------------
# First occurrence
# ---------------------------------------------------------------------------

class TestFirstOccurrence:

    def test_first_failure_clean_history_is_info(self):
        history = [_ok(d) for d in _baseline_days(30)]
        current = _err(0.01)
        events = ToolFailureDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_first_failure_no_history_is_info(self):
        current = _err(0.01)
        events = ToolFailureDetector().detect(current, [])
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_explanation_mentions_first_occurrence(self):
        current = _err(0.01)
        events = ToolFailureDetector().detect(current, [])
        assert "is_first_occurrence=True" in events[0].explanation

    def test_explanation_mentions_error_type(self):
        current = _err(0.01, error_type="NetworkError")
        events = ToolFailureDetector().detect(current, [])
        assert "NetworkError" in events[0].explanation


# ---------------------------------------------------------------------------
# Novel error type
# ---------------------------------------------------------------------------

class TestNovelType:

    def test_novel_type_with_prior_failures_is_info(self):
        # 5 prior failures of type TypeA; current is TypeB (novel)
        history = (
            [_ok(d) for d in _baseline_days(25)]
            + [_err(d, "TypeA") for d in _baseline_days(5)]
        )
        current = _err(0.01, "TypeB")
        events = ToolFailureDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_same_type_as_prior_not_novel(self):
        # TypeA failures in baseline; current is TypeA → not novel, not first
        # baseline_errors_this_type=5, baseline_total=30 → rate=5/30
        # recent: only current → rate=1/1=1.0
        # rate_ratio = (1/1) / (5/30) = 6.0 > 5.0 but n_recent=1 < 30 → check rules
        # rate_ratio=6.0, n_recent=1 < 10 → rate rule 4 (>3 AND n>=10) fails → no rate rule
        # is_first=False (prior TypeA errors); is_novel=False → None
        history = (
            [_ok(d) for d in _baseline_days(25)]
            + [_err(d, "TypeA") for d in _baseline_days(5)]
        )
        current = _err(0.01, "TypeA")
        events = ToolFailureDetector().detect(current, history)
        # n_recent=1, rate rules need n>=10; first=False; novel=False → no event
        assert events == []


# ---------------------------------------------------------------------------
# Rate-based rules
# ---------------------------------------------------------------------------

class TestRateRules:

    def test_rate_above_3_info(self):
        # baseline: 30 OK + 2 TypeA errors → type rate = 2/32
        # recent prior: 7 OK + 2 TypeA errors; current = TypeA error → 3 TypeA / 10 total
        # rate_ratio = (3/10) / (2/32) = 4.8 > 3.0 → INFO (n_recent=10 ≥ 10)
        bl_ok = [_ok(d) for d in _baseline_days(30)]
        bl_err = [_err(d, "TypeA") for d in _baseline_days(2)]
        rc_ok = [_ok(d) for d in _recent_days(7)]
        rc_err = [_err(d, "TypeA") for d in _recent_days(2)]
        history = bl_ok + bl_err + rc_ok + rc_err
        current = _err(0.005, "TypeA")
        events = ToolFailureDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_rate_above_5_warning(self):
        # baseline: 30 OK + 2 TypeA errors → type rate = 2/32
        # recent: 16 OK + 13 TypeA prior + current TypeA = 30 total, 14 TypeA
        # rate_ratio = (14/30) / (2/32) = 7.47 > 5.0 → WARNING (n=30 ≥ 30)
        bl_ok = [_ok(d) for d in _baseline_days(30)]
        bl_err = [_err(d, "TypeA") for d in _baseline_days(2)]
        rc_ok = [_ok(d) for d in _recent_days(16)]
        rc_err = [_err(d, "TypeA") for d in _recent_days(13)]
        history = bl_ok + bl_err + rc_ok + rc_err
        current = _err(0.005, "TypeA")
        events = ToolFailureDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.WARNING

    def test_rate_above_10_critical(self):
        # baseline: 30 OK + 1 TypeA error → type rate = 1/31
        # recent: 19 OK + 10 TypeA prior + current = 30 total, 11 TypeA
        # rate_ratio = (11/30) / (1/31) = 11.37 > 10.0 → CRITICAL
        bl_ok = [_ok(d) for d in _baseline_days(30)]
        bl_err = [_err(d, "TypeA") for d in _baseline_days(1)]
        rc_ok = [_ok(d) for d in _recent_days(19)]
        rc_err = [_err(d, "TypeA") for d in _recent_days(10)]
        history = bl_ok + bl_err + rc_ok + rc_err
        current = _err(0.005, "TypeA")
        events = ToolFailureDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_no_baseline_errors_this_type_no_rate_ratio(self):
        # baseline has TypeB errors but NOT TypeA → baseline_errors_this_type=0
        # rate_ratio = None → rate rules don't fire
        bl_ok = [_ok(d) for d in _baseline_days(25)]
        bl_err = [_err(d, "TypeB") for d in _baseline_days(5)]
        # recent: no prior TypeA errors → is_first? Yes for TypeA errors (first time ANY error)
        history = bl_ok + bl_err
        current = _err(0.01, "TypeA")
        events = ToolFailureDetector().detect(current, history)
        # is_first = False (TypeB errors exist); is_novel = True (TypeA not seen)
        # rate_ratio = None; persistent = False → INFO via is_novel_type
        assert len(events) == 1
        assert events[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistence:

    def test_persistence_k3_all_errors_critical(self):
        cfg = _default_cfg(persistence_k=3)
        history = [_err(0.5, "TypeA"), _err(0.25, "TypeA")]
        current = _err(0.01, "TypeA")
        events = ToolFailureDetector(cfg).detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_one_ok_breaks_persistence(self):
        cfg = _default_cfg(persistence_k=3)
        # last 3: error, ok, error(current) → not all errors → not persistent
        history = [_err(0.5, "TypeA"), _ok(0.25)]
        current = _err(0.01, "TypeA")
        events = ToolFailureDetector(cfg).detect(current, history)
        if events:
            assert events[0].severity != Severity.CRITICAL

    def test_persistence_counts_any_error_type(self):
        # K consecutive errors of DIFFERENT types still satisfies persistence
        cfg = _default_cfg(persistence_k=3)
        history = [_err(0.5, "TypeA"), _err(0.25, "TypeB")]
        current = _err(0.01, "TypeC")
        events = ToolFailureDetector(cfg).detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Error type grouping (different types scored independently)
# ---------------------------------------------------------------------------

class TestErrorTypeGrouping:

    def test_high_rate_of_type_a_does_not_affect_type_b_score(self):
        # Lots of TypeA failures (high rate), but current is TypeB (novel/first)
        bl_ok = [_ok(d) for d in _baseline_days(20)]
        bl_typeA = [_err(d, "TypeA") for d in _baseline_days(10)]
        history = bl_ok + bl_typeA
        current_b = _err(0.01, "TypeB")
        events = ToolFailureDetector().detect(current_b, history)
        # TypeB: is_novel=True (TypeA errors exist but not TypeB) → INFO
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_operation_name_encodes_error_type(self):
        current = _err(0.01, error_type="NetworkTimeout")
        events = ToolFailureDetector().detect(current, [])
        assert events[0].operation_name == "tool.execute/NetworkTimeout"


# ---------------------------------------------------------------------------
# Service isolation
# ---------------------------------------------------------------------------

class TestServiceIsolation:

    def test_different_service_isolated(self):
        # svc-b has lots of errors; svc-a should be independent
        svc_b_errors = [_err(d, "TypeA", service="svc-b") for d in _baseline_days(30)]
        svc_a_ok = [_ok(d, service="svc-a") for d in _baseline_days(30)]
        current = _err(0.01, "TypeA", service="svc-a")
        events = ToolFailureDetector().detect(current, svc_b_errors + svc_a_ok)
        # svc-a group: no prior errors → first occurrence → INFO
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_event_carries_correct_service_name(self):
        current = _err(0.01, service="my-service")
        events = ToolFailureDetector().detect(current, [])
        assert events[0].service_name == "my-service"


# ---------------------------------------------------------------------------
# Leakage prevention
# ---------------------------------------------------------------------------

class TestLeakagePrevention:

    def test_future_records_excluded(self):
        ok_history = [_ok(d) for d in _baseline_days(30)]
        future = [_err(-1.0, "TypeA")]   # T0 + 1 day
        current = _err(0.01, "TypeA")
        events_a = ToolFailureDetector().detect(current, ok_history)
        events_b = ToolFailureDetector().detect(current, ok_history + future)
        assert events_a == events_b


# ---------------------------------------------------------------------------
# Input-order determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_shuffled_history_same_result(self):
        history = (
            [_ok(d) for d in _baseline_days(30)]
            + [_err(d, "TypeA") for d in _baseline_days(2)]
            + [_ok(d) for d in _recent_days(16)]
            + [_err(d, "TypeA") for d in _recent_days(13)]
        )
        current = _err(0.005, "TypeA")
        events_a = ToolFailureDetector().detect(current, history)

        shuffled = history[:]
        random.Random(77).shuffle(shuffled)
        events_b = ToolFailureDetector().detect(current, shuffled)

        assert len(events_a) == len(events_b)
        if events_a:
            assert events_a[0].severity == events_b[0].severity

    def test_repeated_call_same_result(self):
        history = [_ok(d) for d in _baseline_days(30)]
        current = _err(0.01)
        det = ToolFailureDetector()
        assert det.detect(current, history) == det.detect(current, history)


# ---------------------------------------------------------------------------
# AnomalyEvent fields
# ---------------------------------------------------------------------------

class TestEventFields:

    def test_event_type_is_tool_failure(self):
        current = _err(0.01)
        events = ToolFailureDetector().detect(current, [])
        assert events[0].anomaly_type == "tool_failure"
        assert events[0].signal_name == "tool_error_rate"
        assert events[0].detector_name == "ToolFailureDetector"

    def test_baseline_fields_are_none(self):
        current = _err(0.01)
        events = ToolFailureDetector().detect(current, [])
        ev = events[0]
        assert ev.baseline_median is None
        assert ev.baseline_mad is None

    def test_explanation_contains_span_name(self):
        current = _err(0.01)
        events = ToolFailureDetector().detect(current, [])
        assert "tool.execute" in events[0].explanation

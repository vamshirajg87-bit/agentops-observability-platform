"""
Tests for ErrorRateDetector.

Time model:
    T0 = current observation time
    recent window  = [T0 - 24h, T0)
    baseline window = [T0 - 7 days, T0 - 24h)

Windows use the config defaults (recent_window_hours=24, baseline_window_days=7).
"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from detector import Severity
from detector.anomaly_types import ErrorDetectorConfig, ErrorRecord
from detector.error_rate_detector import ErrorRateDetector

T0 = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _er(
    days_before: float,
    is_error: bool = False,
    error_type: str | None = None,
    service: str = "svc",
    operation: str = "research.plan",
) -> ErrorRecord:
    return ErrorRecord(
        trace_id=f"t-{days_before}",
        span_id=f"s-{days_before}",
        service_name=service,
        operation_name=operation,
        is_error=is_error,
        error_type=error_type if is_error else None,
        start_time=T0 - timedelta(days=days_before),
    )


def _ok(days_before: float, **kwargs) -> ErrorRecord:
    return _er(days_before, is_error=False, **kwargs)


def _err(days_before: float, error_type: str = "ErrA", **kwargs) -> ErrorRecord:
    return _er(days_before, is_error=True, error_type=error_type, **kwargs)


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


# baseline window: days 1..7 before T0 (exclusive at T0-24h end)
# recent window:   hours 0..24 before T0
def _baseline_range(n: int) -> list[float]:
    """n days_before values spread across [1.05, 6.95]."""
    return [1.05 + 5.9 * i / max(n - 1, 1) for i in range(n)]


def _recent_range(n: int) -> list[float]:
    """n days_before values spread across [0.01, 0.99] (recent window, before current)."""
    return [0.01 + 0.97 * i / max(n - 1, 1) for i in range(n)]


# ---------------------------------------------------------------------------
# Non-error events are ignored
# ---------------------------------------------------------------------------

class TestNonErrorEventsIgnored:

    def test_ok_span_returns_empty(self):
        current = _ok(0.01)
        events = ErrorRateDetector().detect(current, [])
        assert events == []

    def test_ok_span_with_full_history_returns_empty(self):
        history = [_err(d) for d in _baseline_range(30)]
        current = _ok(0.01)
        events = ErrorRateDetector().detect(current, history)
        assert events == []


# ---------------------------------------------------------------------------
# First occurrence
# ---------------------------------------------------------------------------

class TestFirstOccurrence:

    def test_first_error_clean_baseline_is_info(self):
        # All prior records are OK → no prior errors anywhere
        history = [_ok(d) for d in _baseline_range(30)]
        current = _err(0.01)
        events = ErrorRateDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_first_error_empty_history_is_info(self):
        current = _err(0.01)
        events = ErrorRateDetector().detect(current, [])
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_first_error_explanation_mentions_first_occurrence(self):
        current = _err(0.01)
        events = ErrorRateDetector().detect(current, [])
        assert "is_first_occurrence=True" in events[0].explanation


# ---------------------------------------------------------------------------
# Novel error type
# ---------------------------------------------------------------------------

class TestNovelType:

    def test_novel_error_type_with_prior_errors_is_info(self):
        # 30 prior errors of type ErrA in baseline → ErrB is novel
        history = [_ok(d) for d in _baseline_range(20)] + [_err(d, "ErrA") for d in _baseline_range(10)]
        current = _err(0.01, "ErrB")
        events = ErrorRateDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_same_type_as_prior_not_novel(self):
        # Prior errors all ErrA; current is also ErrA → not novel, not first.
        # Use only 3 prior ErrA errors so persistence (k=5) cannot fire:
        # last_k = [baseline_ok, ErrA, ErrA, ErrA, current] → first is OK → not persistent.
        history = (
            [_ok(d) for d in _baseline_range(30)]
            + [_err(d, "ErrA") for d in _recent_range(3)]
        )
        # baseline had no errors → rate_ratio = None
        # is_novel = False (ErrA seen before); is_first = False; is_persistent = False
        # → no rule fires → []
        current = _err(0.01, "ErrA")
        events = ErrorRateDetector().detect(current, history)
        assert events == []


# ---------------------------------------------------------------------------
# Rate-based rules
# ---------------------------------------------------------------------------

class TestRateRules:

    def test_rate_above_3_info(self):
        # baseline: 10 records, 1 error → baseline_rate = 0.1
        # recent (prior): 9 OK, current error → 10 total, 1 error → rate = 0.1
        # rate_ratio = 0.1/0.1 = 1.0 → no rate rule (≤ 3)
        # Use a higher ratio: baseline 30 OK+2 error, recent 9 OK + current error
        # baseline_rate = 2/32 = 0.0625
        # recent_rate = 1/10 = 0.1
        # rate_ratio = 0.1/0.0625 = 1.6 → no rule
        # Need ratio > 3: baseline_rate must be small enough
        # baseline: 30 OK + 2 errors → rate = 2/32
        # recent: 5 prior + current → if all errors: 6/6 = 1.0
        # rate_ratio = 1.0 / (2/32) = 16 → CRITICAL
        # Let's pick a combo that gives exactly INFO (3 < ratio ≤ 5):
        # baseline: 30 records, 2 errors → rate=0.0667
        # recent prior: 9 OK, current error → n=10, 1 error → rate=0.1
        # ratio = 0.1/0.0667 = 1.5 → not enough
        # Need ratio > 3: recent_rate / 0.0667 > 3 → recent_rate > 0.2 → need ≥ 3 errors out of 10
        # 3/10 = 0.3 → ratio = 0.3/0.0667 = 4.5 → INFO (3 < 4.5 ≤ 5? No, 4.5 > 3 and n=10 → INFO)
        baseline_ok = [_ok(d) for d in _baseline_range(28)]
        baseline_err = [_err(d, "ErrA") for d in _baseline_range(2)]
        recent_ok = [_ok(d) for d in _recent_range(7)]
        recent_err = [_err(d, "ErrA") for d in _recent_range(2)]
        history = baseline_ok + baseline_err + recent_ok + recent_err
        # n_recent=10, recent_errors=3 (2 prior + current), baseline=30, baseline_errors=2
        # rate_ratio = (3/10) / (2/30) = 0.3/0.0667 = 4.5 > 3 → INFO
        current = _err(0.005, "ErrA")
        events = ErrorRateDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_rate_above_5_with_n30_warning(self):
        # baseline: 30 records, 2 errors → rate = 0.0667
        # recent prior: 29 records, 13 errors (including current = 14 errors / 30 total)
        # rate_ratio = (14/30) / (2/30) = 7.0 > 5.0 → WARNING (n=30 ≥ 30)
        baseline_ok = [_ok(d) for d in _baseline_range(28)]
        baseline_err = [_err(d, "ErrA") for d in _baseline_range(2)]
        recent_ok = [_ok(d) for d in _recent_range(16)]
        recent_err = [_err(d, "ErrA") for d in _recent_range(13)]
        history = baseline_ok + baseline_err + recent_ok + recent_err
        current = _err(0.005, "ErrA")
        events = ErrorRateDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.WARNING

    def test_rate_above_10_with_n30_critical(self):
        # baseline: 30 records, 1 error → rate = 1/30
        # recent prior: 29 records, 10 errors + current error = 11 errors / 30 total
        # rate_ratio = (11/30) / (1/30) = 11.0 > 10.0 → CRITICAL
        baseline_ok = [_ok(d) for d in _baseline_range(29)]
        baseline_err = [_err(d, "ErrA") for d in _baseline_range(1)]
        recent_ok = [_ok(d) for d in _recent_range(19)]
        recent_err = [_err(d, "ErrA") for d in _recent_range(10)]
        history = baseline_ok + baseline_err + recent_ok + recent_err
        current = _err(0.005, "ErrA")
        events = ErrorRateDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_zero_baseline_errors_no_rate_ratio(self):
        # All baseline records are OK → baseline_error_rate = 0 → rate_ratio = None.
        # Use only 3 prior ErrX errors so persistence (k=5) cannot fire:
        # last_k = [baseline_ok, ErrX, ErrX, ErrX, current] → first is OK → not persistent.
        history = [_ok(d) for d in _baseline_range(30)]  # no errors in baseline
        recent_err = [_err(d, "ErrX") for d in _recent_range(3)]
        current = _err(0.005, "ErrX")
        events = ErrorRateDetector().detect(current, history + recent_err)
        # rate_ratio=None → no rate rule; is_novel=False (ErrX seen before in recent)
        # is_first=False; is_persistent=False → no event
        assert events == []

    def test_baseline_clean_first_error_in_recent_is_info(self):
        # baseline: 30 OK; recent: all OK; current = first error anywhere → INFO
        history = (
            [_ok(d) for d in _baseline_range(30)]
            + [_ok(d) for d in _recent_range(5)]
        )
        current = _err(0.005)
        events = ErrorRateDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistence:

    def test_persistence_k3_all_errors_critical(self):
        # Last 3 consecutive spans (including current) all errors → CRITICAL
        cfg = _default_cfg(persistence_k=3)
        history = [_err(0.5, "ErrA"), _err(0.25, "ErrA")]
        current = _err(0.01, "ErrA")
        events = ErrorRateDetector(cfg).detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_persistence_k3_not_met_no_persistence(self):
        # k=3 but only 2 errors before current (one is OK in between)
        cfg = _default_cfg(persistence_k=3)
        history = [_err(0.5, "ErrA"), _ok(0.25), _err(0.1, "ErrA")]
        # last 3: [_ok(0.25), _err(0.1), current] → not all errors
        current = _err(0.01, "ErrA")
        events = ErrorRateDetector(cfg).detect(current, history)
        # is_first=False (prior errors exist); is_novel=False; rate_ratio = ?
        # baseline_recs = [] (0.5, 0.25, 0.1 days < 1 day recent, so all in recent window)
        # Actually: recent window is [T0-24h, T0) = days_before < 1.0
        # 0.5, 0.25, 0.1 are all < 1.0 → in recent window, not baseline
        # baseline_total = 0 → rate_ratio = None
        # is_first_occurrence = True (no baseline errors, no prior recent errors? no: 0.5 and 0.1 are errors)
        # Wait: baseline has 0 records, recent prior has [0.5, 0.25, 0.1] → recent prior errors = 2
        # is_first = False; is_novel = False (ErrA seen before)
        # rate_ratio = None → no severity
        # is_persistent = False → no event
        assert len(events) == 0 or events[0].severity != Severity.CRITICAL

    def test_persistence_beats_first_occurrence(self):
        # Even though is_first_occurrence=True, persistence should win
        # But persistence requires k consecutive errors, and first_occurrence means no prior errors
        # So they can't both be true for k>1. Just verify: if persistence fires, result is CRITICAL
        cfg = _default_cfg(persistence_k=1)
        current = _err(0.01, "ErrA")
        events = ErrorRateDetector(cfg).detect(current, [])
        # k=1: last 1 record (current) is error → persistent=True; first=True
        # persistent → CRITICAL wins over INFO
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Group isolation
# ---------------------------------------------------------------------------

class TestGroupIsolation:

    def test_different_operation_isolated(self):
        # Lots of errors for operation op-B; current is for op-A with no prior errors
        err_history = [
            _err(d, "ErrA", operation="op-B")
            for d in _baseline_range(30)
        ]
        ok_history = [_ok(d, operation="op-A") for d in _baseline_range(30)]
        current = _err(0.01, "ErrA", operation="op-A")
        events = ErrorRateDetector().detect(current, err_history + ok_history)
        # group op-A: only ok history → is_first=True → INFO
        assert len(events) == 1
        assert events[0].severity == Severity.INFO
        assert events[0].operation_name == "op-A"

    def test_different_service_isolated(self):
        err_history = [_err(d, "ErrA", service="svc-b") for d in _baseline_range(30)]
        ok_history = [_ok(d, service="svc-a") for d in _baseline_range(30)]
        current = _err(0.01, "ErrA", service="svc-a")
        events = ErrorRateDetector().detect(current, err_history + ok_history)
        # svc-a group: only ok → first occurrence → INFO
        assert len(events) == 1
        assert events[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Leakage prevention
# ---------------------------------------------------------------------------

class TestLeakagePrevention:

    def test_future_records_excluded(self):
        future = [_err(-1.0, "ErrA")]   # T0 + 1 day
        ok_history = [_ok(d) for d in _baseline_range(30)]
        current = _err(0.01, "ErrA")
        events_with_future = ErrorRateDetector().detect(current, ok_history + future)
        events_without = ErrorRateDetector().detect(current, ok_history)
        # Future record must not affect the result
        assert events_with_future == events_without


# ---------------------------------------------------------------------------
# Input-order determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_shuffled_history_same_result(self):
        history = (
            [_ok(d) for d in _baseline_range(28)]
            + [_err(d, "ErrA") for d in _baseline_range(2)]
            + [_ok(d) for d in _recent_range(16)]
            + [_err(d, "ErrA") for d in _recent_range(13)]
        )
        current = _err(0.005, "ErrA")
        events_a = ErrorRateDetector().detect(current, history)

        shuffled = history[:]
        random.Random(13).shuffle(shuffled)
        events_b = ErrorRateDetector().detect(current, shuffled)

        assert len(events_a) == len(events_b)
        if events_a:
            assert events_a[0].severity == events_b[0].severity

    def test_repeated_call_same_result(self):
        history = [_ok(d) for d in _baseline_range(30)]
        current = _err(0.01)
        det = ErrorRateDetector()
        assert det.detect(current, history) == det.detect(current, history)


# ---------------------------------------------------------------------------
# AnomalyEvent fields
# ---------------------------------------------------------------------------

class TestEventFields:

    def test_event_type_is_error_rate(self):
        current = _err(0.01, "ErrA")
        events = ErrorRateDetector().detect(current, [])
        assert events[0].anomaly_type == "error_rate"
        assert events[0].detector_name == "ErrorRateDetector"
        assert events[0].signal_name == "error_rate"

    def test_baseline_fields_are_none_for_error_rate(self):
        current = _err(0.01, "ErrA")
        events = ErrorRateDetector().detect(current, [])
        ev = events[0]
        assert ev.baseline_median is None
        assert ev.baseline_mad is None
        assert ev.baseline_n is None

    def test_explanation_contains_operation(self):
        current = _err(0.01, "ErrA", operation="tool.execute")
        events = ErrorRateDetector().detect(current, [])
        assert "tool.execute" in events[0].explanation

    def test_explanation_contains_error_type(self):
        current = _err(0.01, "TimeoutError")
        events = ErrorRateDetector().detect(current, [])
        assert "TimeoutError" in events[0].explanation

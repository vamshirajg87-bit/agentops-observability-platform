"""
Tests for LatencyDetector.

Baseline construction uses 15 copies of 90 ms and 15 copies of 110 ms,
giving median=100 and MAD=10 for all group-level baselines unless stated
otherwise.  The z-score formula is:
    z = 0.6745 * (observed - median) / MAD

With T=3.5 (default threshold):
    INFO band    : 3.5 < z < 7.0    → observed in (152, 203.7)
    WARNING band : 7.0 ≤ z < 14.0   → observed in [203.7, 307.4)
    CRITICAL band: z ≥ 14.0          → observed ≥ 307.4

With floor=50 (default): practical gate passes when observed-median > 50.
"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from detector import (
    DetectorConfig,
    Severity,
)
from detector.anomaly_types import AnomalyEvent, LatencyRecord
from detector.latency_detector import LatencyDetector

T0 = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lr(
    duration_ms: float,
    days_before: float = 1.0,
    service: str = "svc-a",
    operation: str = "research/plan",
    is_error: bool = False,
    trace_id: str = "trace-001",
    span_id: str = "span-001",
) -> LatencyRecord:
    return LatencyRecord(
        trace_id=trace_id,
        span_id=span_id,
        service_name=service,
        operation_name=operation,
        duration_ms=duration_ms,
        start_time=T0 - timedelta(days=days_before),
        is_error=is_error,
    )


def _normal_history(n: int = 30, service: str = "svc-a", operation: str = "research/plan") -> list[LatencyRecord]:
    """
    n records with predictable median=100, MAD=10:
    floor(n/2) copies of 90 ms and ceil(n/2) copies of 110 ms, spread
    evenly across [T0 - 6.8 days, T0 - 0.2 days].
    """
    low_count = n // 2
    high_count = n - low_count
    values = [90.0] * low_count + [110.0] * high_count
    records = []
    for i, v in enumerate(values):
        days = 0.2 + 6.6 * i / max(n - 1, 1)
        records.append(_lr(v, days_before=days, service=service, operation=operation))
    return records


def _cfg(**kwargs) -> DetectorConfig:
    defaults = dict(
        direction="HIGH",
        z_threshold=3.5,
        absolute_floor=50.0,
        min_baseline_n=30,
        min_baseline_n_low_confidence=10,
        baseline_window_days=7,
    )
    defaults.update(kwargs)
    return DetectorConfig(**defaults)


# ---------------------------------------------------------------------------
# Normal (non-anomalous) paths
# ---------------------------------------------------------------------------

class TestNormalPaths:

    def test_normal_latency_no_event(self):
        history = _normal_history(30)
        current = _lr(105.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert events == []

    def test_below_floor_no_event(self):
        # deviation = 149 - 100 = 49 < floor=50 → practical gate fails
        history = _normal_history(30)
        current = _lr(149.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert events == []

    def test_fast_latency_not_flagged_by_high_direction(self):
        # HIGH only flags slow; observed < median never anomalous
        history = _normal_history(30)
        current = _lr(50.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert events == []

    def test_error_span_not_scored_as_latency(self):
        history = _normal_history(30)
        current = _lr(9999.0, days_before=0.1, is_error=True)
        events = LatencyDetector().detect(current, history)
        assert events == []

    def test_insufficient_history_no_event(self):
        # n=9 < min_low_confidence=10 → INSUFFICIENT_HISTORY
        history = _normal_history(9)
        current = _lr(9999.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert events == []

    def test_empty_history_no_event(self):
        current = _lr(9999.0, days_before=0.1)
        events = LatencyDetector().detect(current, [])
        assert events == []


# ---------------------------------------------------------------------------
# Anomaly detection and severity
# ---------------------------------------------------------------------------

class TestAnomalyDetection:

    def test_obvious_slowness_returns_one_event(self):
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1)  # z ≈ 26.98 → CRITICAL
        events = LatencyDetector().detect(current, history)
        assert len(events) == 1

    def test_critical_severity(self):
        # z = 0.6745 * (500-100) / 10 = 26.98 ≥ 14 → CRITICAL
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert events[0].severity == Severity.CRITICAL

    def test_warning_severity(self):
        # z = 0.6745 * (215-100) / 10 = 7.757 → WARNING
        history = _normal_history(30)
        current = _lr(215.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.WARNING

    def test_info_severity(self):
        # z = 0.6745 * (200-100) / 10 = 6.745, 3.5 < 6.745 < 7.0 → INFO
        history = _normal_history(30)
        current = _lr(200.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_low_confidence_caps_critical_to_info(self):
        # n=10 is in [min_low=10, min_n=30) → low confidence → cap at INFO
        history = _normal_history(10)
        current = _lr(500.0, days_before=0.1)
        cfg = _cfg(min_baseline_n_low_confidence=10, min_baseline_n=30)
        events = LatencyDetector(cfg).detect(current, history)
        assert len(events) == 1
        assert events[0].severity == Severity.INFO

    def test_full_confidence_at_min_n(self):
        # n=30 ≥ min_n=30 → full confidence → CRITICAL
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert events[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Error exclusion from latency baselines
# ---------------------------------------------------------------------------

class TestErrorExclusion:

    def test_error_observations_excluded_from_baseline(self):
        # 30 normal records with 15@90, 15@110 → median=100, MAD=10
        # Add 5 error records with extreme values; baseline should not change
        normal_history = _normal_history(30)
        error_records = [
            _lr(9999.0, days_before=d, is_error=True)
            for d in [1.0, 2.0, 3.0, 4.0, 5.0]
        ]
        history = normal_history + error_records
        current = _lr(500.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        # If errors weren't excluded, baseline would shift and z would differ
        assert len(events) == 1
        assert events[0].baseline_median == pytest.approx(100.0)
        assert events[0].baseline_mad == pytest.approx(10.0)

    def test_all_history_errors_yields_no_event(self):
        # All history is errors → baseline excludes them → no qualifying obs
        history = [_lr(100.0, days_before=float(i), is_error=True) for i in range(1, 36)]
        current = _lr(9999.0, days_before=0.1)
        events = LatencyDetector().detect(current, [])
        assert events == []


# ---------------------------------------------------------------------------
# Group isolation
# ---------------------------------------------------------------------------

class TestGroupIsolation:

    def test_different_operation_uses_own_baseline(self):
        # Group A (research/plan): 30 records with median=100
        # Group B (supervisor/start): 30 records with median=500
        # Scoring a research/plan observation should use only group A's baseline
        history_a = _normal_history(30, operation="research/plan")
        history_b = [
            _lr(500.0 + (i % 10), days_before=0.2 + i * 0.2, operation="supervisor/start")
            for i in range(30)
        ]
        current = _lr(200.0, days_before=0.05, operation="research/plan")
        events = LatencyDetector().detect(current, history_a + history_b)
        # baseline should reflect group A (median≈100), not contaminated by group B
        assert len(events) == 1
        assert events[0].baseline_median == pytest.approx(100.0)

    def test_different_service_isolated(self):
        history_a = _normal_history(30, service="svc-a")
        history_b = [
            _lr(1000.0, days_before=float(i), service="svc-b")
            for i in range(1, 31)
        ]
        current = _lr(200.0, days_before=0.05, service="svc-a")
        events = LatencyDetector().detect(current, history_a + history_b)
        assert len(events) == 1
        assert events[0].baseline_n == 30

    def test_wrong_group_gives_no_baseline_no_event(self):
        # history for operation="op-B" only; current asks for "op-A"
        history = _normal_history(30, operation="op-B")
        current = _lr(9999.0, days_before=0.1, operation="op-A")
        events = LatencyDetector().detect(current, history)
        assert events == []


# ---------------------------------------------------------------------------
# Leakage prevention
# ---------------------------------------------------------------------------

class TestLeakagePrevention:

    def test_current_start_time_excluded_from_baseline(self):
        # An observation with start_time == current.start_time must not enter
        # its own baseline (exclusive upper bound in compute_baseline).
        base_obs = [
            _lr(9999.0, days_before=0.0)  # start_time == T0 - 0 == T0 (current)
        ]
        base_obs += _normal_history(30)
        current = _lr(120.0, days_before=0.0)
        events = LatencyDetector().detect(current, base_obs)
        # If 9999 entered baseline the median/MAD would be distorted
        assert len(events) == 0 or events[0].baseline_mad == pytest.approx(10.0)

    def test_future_observations_excluded(self):
        # Observations after current.start_time must not enter baseline
        future = [_lr(9999.0, days_before=-1.0)]   # T0 + 1 day
        normal = _normal_history(30)
        current = _lr(200.0, days_before=0.1)
        events = LatencyDetector().detect(current, normal + future)
        assert len(events) == 1
        assert events[0].baseline_n == 30   # future record excluded


# ---------------------------------------------------------------------------
# Input-order determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_shuffled_history_same_result(self):
        history = _normal_history(30)
        current = _lr(300.0, days_before=0.1)
        events_a = LatencyDetector().detect(current, history)

        shuffled = history[:]
        random.Random(99).shuffle(shuffled)
        events_b = LatencyDetector().detect(current, shuffled)

        assert len(events_a) == len(events_b) == 1
        assert events_a[0].severity == events_b[0].severity
        assert events_a[0].anomaly_score == pytest.approx(events_b[0].anomaly_score)

    def test_repeated_call_same_result(self):
        history = _normal_history(30)
        current = _lr(300.0, days_before=0.1)
        det = LatencyDetector()
        result_a = det.detect(current, history)
        result_b = det.detect(current, history)
        assert result_a == result_b


# ---------------------------------------------------------------------------
# AnomalyEvent fields
# ---------------------------------------------------------------------------

class TestEventFields:

    def test_event_fields_populated(self):
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1, trace_id="tr-x", span_id="sp-y")
        events = LatencyDetector().detect(current, history)
        assert len(events) == 1
        ev = events[0]
        assert ev.anomaly_type == "latency"
        assert ev.signal_name == "duration_ms"
        assert ev.detector_name == "LatencyDetector"
        assert ev.detector_version == "1.0"
        assert ev.trace_id == "tr-x"
        assert ev.span_id == "sp-y"
        assert ev.service_name == "svc-a"
        assert ev.observed_value == pytest.approx(500.0)
        assert ev.baseline_median == pytest.approx(100.0)
        assert ev.baseline_n == 30
        assert ev.anomaly_score is not None
        assert ev.severity == Severity.CRITICAL

    def test_explanation_contains_observed_value(self):
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        assert "500" in events[0].explanation

    def test_explanation_contains_baseline_stats(self):
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        expl = events[0].explanation
        assert "baseline_median" in expl
        assert "MAD" in expl
        assert "modified_z" in expl

    def test_explanation_contains_no_causal_language(self):
        history = _normal_history(30)
        current = _lr(500.0, days_before=0.1)
        events = LatencyDetector().detect(current, history)
        expl = events[0].explanation.lower()
        for word in ("cause", "because", "due to", "slowdown", "degraded"):
            assert word not in expl, f"causal word '{word}' found in explanation"

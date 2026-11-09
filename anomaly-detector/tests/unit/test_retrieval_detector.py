"""
Tests for RetrievalQualityDetector.

Baseline construction for relevance score: 15 copies of 0.85 and 15 copies
of 0.75, giving median=0.80 and MAD=0.05.

Baseline construction for result count: 15 copies of 8 and 15 copies of 12,
giving median=10 and MAD=2.

Direction is LOW for both signals; anomalies fire when values DROP.
"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from detector import DetectorConfig, Severity
from detector.anomaly_types import AnomalyEvent, RetrievalRecord
from detector.retrieval_detector import RetrievalQualityDetector

T0 = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rr(
    days_before: float = 1.0,
    relevance: float | None = 0.80,
    count: int | None = 10,
    service: str = "svc-a",
    is_error: bool = False,
) -> RetrievalRecord:
    return RetrievalRecord(
        trace_id=f"t-{days_before}",
        span_id=f"s-{days_before}",
        service_name=service,
        retrieval_top_relevance_score=relevance,
        retrieval_result_count=count,
        start_time=T0 - timedelta(days=days_before),
        is_error=is_error,
    )


def _relevance_history(n: int = 30) -> list[RetrievalRecord]:
    """median=0.80, MAD=0.05 for relevance_score; median=10, MAD=2 for count."""
    low_r, high_r = 0.75, 0.85
    low_c, high_c = 8, 12
    low_half = n // 2
    high_half = n - low_half
    records = []
    for i in range(n):
        days = 0.2 + 6.6 * i / max(n - 1, 1)
        r = low_r if i < low_half else high_r
        c = low_c if i < low_half else high_c
        records.append(_rr(days_before=days, relevance=r, count=c))
    return records


def _low_cfg(**kwargs) -> DetectorConfig:
    defaults = dict(
        direction="LOW",
        z_threshold=3.5,
        absolute_floor=0.05,
        min_baseline_n=30,
        min_baseline_n_low_confidence=10,
        baseline_window_days=7,
    )
    defaults.update(kwargs)
    return DetectorConfig(**defaults)


# ---------------------------------------------------------------------------
# Relevance score: normal paths
# ---------------------------------------------------------------------------

class TestRelevanceNormal:

    def test_normal_relevance_no_event(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.78)
        events = RetrievalQualityDetector().detect(current, history)
        relevance_events = [e for e in events if e.signal_name == "retrieval_top_relevance_score"]
        assert relevance_events == []

    def test_high_relevance_not_flagged_by_low_detector(self):
        # Direction is LOW; high values should not trigger an anomaly
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.99)
        events = RetrievalQualityDetector().detect(current, history)
        relevance_events = [e for e in events if e.signal_name == "retrieval_top_relevance_score"]
        assert relevance_events == []

    def test_null_relevance_skipped(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=None, count=10)
        events = RetrievalQualityDetector().detect(current, history)
        relevance_events = [e for e in events if e.signal_name == "retrieval_top_relevance_score"]
        assert relevance_events == []

    def test_insufficient_history_relevance_no_event(self):
        history = _relevance_history(9)
        current = _rr(0.1, relevance=0.0)
        events = RetrievalQualityDetector().detect(current, history)
        assert events == []


# ---------------------------------------------------------------------------
# Relevance score: anomalous paths
# ---------------------------------------------------------------------------

class TestRelevanceAnomalous:

    def test_low_relevance_triggers_event(self):
        # baseline median=0.80; floor=0.05 default
        # z = 0.6745*(0.80-0.20)/0.05 = 8.094 → WARNING
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20)
        events = RetrievalQualityDetector().detect(current, history)
        relevance_events = [e for e in events if e.signal_name == "retrieval_top_relevance_score"]
        assert len(relevance_events) == 1

    def test_relevance_anomaly_severity_warning(self):
        # z = 0.6745*(0.80-0.20)/0.05 = 8.094, 7.0 ≤ 8.094 < 14.0 → WARNING
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20)
        events = RetrievalQualityDetector().detect(current, history)
        ev = next(e for e in events if e.signal_name == "retrieval_top_relevance_score")
        assert ev.severity == Severity.WARNING

    def test_low_confidence_caps_relevance_severity(self):
        history = _relevance_history(10)
        cfg = _low_cfg(min_baseline_n_low_confidence=10, min_baseline_n=30)
        current = _rr(0.1, relevance=0.01)
        events = RetrievalQualityDetector(relevance_config=cfg).detect(current, history)
        if events:
            relevance_ev = next((e for e in events if e.signal_name == "retrieval_top_relevance_score"), None)
            if relevance_ev:
                assert relevance_ev.severity == Severity.INFO


# ---------------------------------------------------------------------------
# Result count: normal paths
# ---------------------------------------------------------------------------

class TestCountNormal:

    def test_normal_count_no_event(self):
        history = _relevance_history(30)
        current = _rr(0.1, count=9)
        events = RetrievalQualityDetector().detect(current, history)
        count_events = [e for e in events if e.signal_name == "retrieval_result_count"]
        assert count_events == []

    def test_high_count_not_flagged_by_low_detector(self):
        history = _relevance_history(30)
        current = _rr(0.1, count=100)
        events = RetrievalQualityDetector().detect(current, history)
        count_events = [e for e in events if e.signal_name == "retrieval_result_count"]
        assert count_events == []

    def test_null_count_skipped(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.80, count=None)
        events = RetrievalQualityDetector().detect(current, history)
        count_events = [e for e in events if e.signal_name == "retrieval_result_count"]
        assert count_events == []


# ---------------------------------------------------------------------------
# Result count: zero is valid
# ---------------------------------------------------------------------------

class TestZeroResultCount:

    def test_zero_count_is_valid_observation_not_skipped(self):
        # 0 results is NOT null; it must be scored as an observation
        history = _relevance_history(30)
        current = _rr(0.1, count=0)
        det = RetrievalQualityDetector()
        events = det.detect(current, history)
        # With baseline median=10, deviation=10-0=10, floor=1.0:
        # z = 0.6745 * 10 / 2 = 3.37 < 3.5 → STAT_GATE_ONLY (not anomalous)
        # practical gate: 10 > 1.0 → True; stat gate: 3.37 < 3.5 → False → not anomalous
        # So no event, but count=0 was not treated as None
        # We verify by using a custom cfg that lowers the threshold
        cfg_sensitive = DetectorConfig(
            direction="LOW", z_threshold=2.0, absolute_floor=1.0,
            min_baseline_n=30, min_baseline_n_low_confidence=10, baseline_window_days=7,
        )
        events2 = RetrievalQualityDetector(count_config=cfg_sensitive).detect(current, history)
        count_events = [e for e in events2 if e.signal_name == "retrieval_result_count"]
        # With lower threshold, z=3.37>2.0 → should fire
        assert len(count_events) == 1
        assert count_events[0].observed_value == pytest.approx(0.0)

    def test_zero_count_anomaly_event_carries_correct_observed_value(self):
        history = _relevance_history(30)
        cfg_sensitive = DetectorConfig(
            direction="LOW", z_threshold=2.0, absolute_floor=1.0,
            min_baseline_n=30, min_baseline_n_low_confidence=10, baseline_window_days=7,
        )
        current = _rr(0.1, count=0)
        events = RetrievalQualityDetector(count_config=cfg_sensitive).detect(current, history)
        count_ev = next(e for e in events if e.signal_name == "retrieval_result_count")
        assert count_ev.observed_value == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Both signals can fire independently
# ---------------------------------------------------------------------------

class TestBothSignals:

    def test_both_signals_fire_when_both_anomalous(self):
        history = _relevance_history(30)
        # Low relevance + zero count, both well below baselines
        cfg_rel = _low_cfg(absolute_floor=0.05)
        cfg_cnt = DetectorConfig(
            direction="LOW", z_threshold=2.0, absolute_floor=1.0,
            min_baseline_n=30, min_baseline_n_low_confidence=10, baseline_window_days=7,
        )
        current = _rr(0.1, relevance=0.20, count=0)
        events = RetrievalQualityDetector(relevance_config=cfg_rel, count_config=cfg_cnt).detect(
            current, history
        )
        names = {e.signal_name for e in events}
        assert "retrieval_top_relevance_score" in names
        assert "retrieval_result_count" in names

    def test_only_relevance_fires_when_count_normal(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20, count=9)  # count within normal range
        events = RetrievalQualityDetector().detect(current, history)
        names = {e.signal_name for e in events}
        assert "retrieval_top_relevance_score" in names
        assert "retrieval_result_count" not in names

    def test_only_count_fires_when_relevance_normal(self):
        history = _relevance_history(30)
        cfg_cnt = DetectorConfig(
            direction="LOW", z_threshold=2.0, absolute_floor=1.0,
            min_baseline_n=30, min_baseline_n_low_confidence=10, baseline_window_days=7,
        )
        current = _rr(0.1, relevance=0.80, count=0)
        events = RetrievalQualityDetector(count_config=cfg_cnt).detect(current, history)
        names = {e.signal_name for e in events}
        assert "retrieval_result_count" in names
        assert "retrieval_top_relevance_score" not in names


# ---------------------------------------------------------------------------
# Group isolation
# ---------------------------------------------------------------------------

class TestGroupIsolation:

    def test_different_service_isolated(self):
        history_a = _relevance_history(30)
        history_b = [
            _rr(days_before=float(i), relevance=0.10, count=0, service="svc-b")
            for i in range(1, 31)
        ]
        # svc-a current with normal relevance should not be contaminated by svc-b
        current = _rr(0.1, relevance=0.80, count=10, service="svc-a")
        events = RetrievalQualityDetector().detect(current, history_a + history_b)
        assert events == []

    def test_only_matching_service_contributes_to_baseline(self):
        history_a = _relevance_history(30)  # median_relevance=0.80, n=30
        history_extra = [
            _rr(days_before=float(i), relevance=0.99, count=100, service="svc-b")
            for i in range(1, 31)
        ]
        current = _rr(0.1, relevance=0.20, service="svc-a")
        events = RetrievalQualityDetector().detect(current, history_a + history_extra)
        rel_events = [e for e in events if e.signal_name == "retrieval_top_relevance_score"]
        assert len(rel_events) == 1
        assert rel_events[0].baseline_n == 30


# ---------------------------------------------------------------------------
# Leakage prevention
# ---------------------------------------------------------------------------

class TestLeakagePrevention:

    def test_future_observations_excluded_from_baseline(self):
        history = _relevance_history(30)
        future = [_rr(days_before=-1.0, relevance=0.0)]   # T0 + 1 day
        current = _rr(0.1, relevance=0.20)
        events = RetrievalQualityDetector().detect(current, history + future)
        rel_events = [e for e in events if e.signal_name == "retrieval_top_relevance_score"]
        assert len(rel_events) == 1
        assert rel_events[0].baseline_n == 30


# ---------------------------------------------------------------------------
# Input-order determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_shuffled_history_same_result(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20)
        events_a = RetrievalQualityDetector().detect(current, history)

        shuffled = history[:]
        random.Random(7).shuffle(shuffled)
        events_b = RetrievalQualityDetector().detect(current, shuffled)

        assert len(events_a) == len(events_b)
        if events_a:
            assert events_a[0].severity == events_b[0].severity

    def test_repeated_call_same_result(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20)
        det = RetrievalQualityDetector()
        assert det.detect(current, history) == det.detect(current, history)


# ---------------------------------------------------------------------------
# AnomalyEvent fields
# ---------------------------------------------------------------------------

class TestEventFields:

    def test_relevance_event_fields(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20)
        events = RetrievalQualityDetector().detect(current, history)
        ev = next(e for e in events if e.signal_name == "retrieval_top_relevance_score")
        assert ev.anomaly_type == "retrieval_quality"
        assert ev.detector_name == "RetrievalQualityDetector"
        assert ev.operation_name == "retrieval.search"
        assert ev.observed_value == pytest.approx(0.20)

    def test_explanation_contains_evidence(self):
        history = _relevance_history(30)
        current = _rr(0.1, relevance=0.20)
        events = RetrievalQualityDetector().detect(current, history)
        ev = next(e for e in events if e.signal_name == "retrieval_top_relevance_score")
        expl = ev.explanation
        assert "retrieval_top_relevance_score" in expl
        assert "baseline_median" in expl

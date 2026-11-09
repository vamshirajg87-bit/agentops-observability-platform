"""
tests/unit/test_rca_confidence.py

Unit tests for rca_confidence — Phase 11.4 confidence classification.

Coverage:
  INSUFFICIENT_DATA
    - trace_id is None
    - zero spans in evidence
    - one span in evidence
    - precedence over a high evidence score

  LOW
    - each signal-specific top-score threshold (strict <)
    - exact threshold boundary (score == threshold → NOT LOW from this rule)
    - retrieval anomaly with no retrieval telemetry in evidence
    - missing required direct subject for span-specific signals
    - orphan_fraction > 0.50
    - LOW precedence over MEDIUM

  MEDIUM
    - top-two gap clearly < 0.10 → MEDIUM
    - top-two gap mathematical boundary 0.10 (0.60-0.50 in IEEE 754) → NOT MEDIUM
    - top-two gap clearly > 0.10 → NOT MEDIUM from gap rule
    - orphan_fraction 0.10, 0.50
    - known telemetry gap: cycle detected
    - known telemetry gap: malformed timestamp (fraction > 1.0)
    - natural root absent
    - trace_latency deep single-span outlier (condition 21E): 6 cases

  HIGH
    - clean complete trace, large separation, direct subject present
    - locked E2E fixture → HIGH (trace_latency, large gap, no telemetry gaps)
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from typing import Optional

from rca_confidence import (
    assess_confidence,
    derive_signal,
    signal_threshold,
    SPAN_SPECIFIC_SIGNALS,
    orphan_fraction,
    _derive_signal,
    _SIGNAL_THRESHOLDS,
    _SPAN_SPECIFIC_SIGNALS,
    _orphan_fraction,
)
from rca_models import SpanEvidence
from rca_ranker import score_and_rank
from rca_evidence import UnscoredSpanFacts
from rca_source import RcaAnomalyRecord
from rca_trace import SpanRecord, TraceReconstruction, TraceNode, build_trace_tree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_anomaly(
    anomaly_type: str = "latency",
    operation_name: Optional[str] = "trace",
    trace_id: Optional[str] = "trace-1",
    subject_span_id: Optional[str] = None,
    signal_name: str = "duration_ms",
) -> RcaAnomalyRecord:
    return RcaAnomalyRecord(
        anomaly_id="anom-1",
        anomaly_type=anomaly_type,
        signal_name=signal_name,
        detector_name="TestDetector",
        detector_version="1.0",
        trace_id=trace_id,
        subject_span_id=subject_span_id,
        service_name="svc",
        operation_name=operation_name,
        observed_value=1000.0,
        event_time=_T0,
        baseline_median=200.0,
        baseline_mad=20.0,
        baseline_n=30,
        anomaly_score=4.0,
        severity="WARNING",
        detector_explanation="test anomaly",
    )


def _make_span_record(
    span_id: str,
    parent_span_id: Optional[str],
    duration_ms: float = 100.0,
    status_code: str = "OK",
    start_offset_ms: float = 0.0,
    trace_id: str = "trace-1",
) -> SpanRecord:
    t = _T0 + timedelta(milliseconds=start_offset_ms)
    return SpanRecord(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_id,
        service_name="svc",
        start_time=t,
        end_time=t + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        status_code=status_code,
        trace_id=trace_id,
    )


def _make_facts(
    span_id: str = "s1",
    parent_span_id: Optional[str] = "root",
    is_root_span: bool = False,
    is_error_span: bool = False,
    is_direct_subject: bool = False,
    trace_duration_fraction: Optional[float] = 0.5,
    evidence_score: float = 0.6,
    retrieval_result_count: Optional[int] = None,
    retrieval_top_relevance_score: Optional[float] = None,
    start_time: Optional[datetime] = None,
    depth: int = 1,
) -> UnscoredSpanFacts:
    t = start_time or _T0
    dur = (trace_duration_fraction or 0.5) * 200.0
    return UnscoredSpanFacts(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_id,
        service_name="svc",
        start_time=t,
        end_time=t + timedelta(milliseconds=dur),
        duration_ms=dur,
        status_code="ERROR" if is_error_span else "OK",
        status_message=None,
        error_type=None,
        error_message=None,
        tool_name=None,
        tool_status=None,
        agent_name=None,
        agent_operation=None,
        retrieval_result_count=retrieval_result_count,
        retrieval_top_relevance_score=retrieval_top_relevance_score,
        is_root_span=is_root_span,
        is_error_span=is_error_span,
        is_direct_subject=is_direct_subject,
        trace_duration_fraction=trace_duration_fraction,
        depth=depth,
    )


def _minimal_reconstruction(
    span_count: int = 2,
    has_cycle: bool = False,
    n_orphans: int = 0,
    n_roots: int = 1,
) -> TraceReconstruction:
    """Build a minimal mock TraceReconstruction with controlled properties."""
    # Build dummy TraceNodes for orphans
    orphan_nodes: list[TraceNode] = []
    for i in range(n_orphans):
        span = _make_span_record(f"orphan-{i}", parent_span_id="absent")
        orphan_nodes.append(TraceNode(span=span, children=[], depth=0))

    root_nodes: list[TraceNode] = []
    for i in range(n_roots):
        span = _make_span_record(f"root-{i}", parent_span_id=None)
        root_nodes.append(TraceNode(span=span, children=[], depth=0))

    return TraceReconstruction(
        roots=root_nodes,
        orphans=orphan_nodes,
        cycle_members=[],
        has_cycle=has_cycle,
        span_count=span_count,
        trace_duration_ms=200.0,
    )


def _make_span_evidence(
    span_id: str = "s1",
    evidence_score: float = 0.6,
    is_direct_subject: bool = False,
    trace_duration_fraction: Optional[float] = 0.5,
    retrieval_result_count: Optional[int] = None,
    retrieval_top_relevance_score: Optional[float] = None,
    start_time: Optional[datetime] = None,
    is_root_span: bool = False,
    depth: int = 1,
) -> SpanEvidence:
    t = start_time or _T0
    return SpanEvidence(
        span_id=span_id,
        parent_span_id="root",
        span_name=span_id,
        service_name="svc",
        start_time=t,
        end_time=t + timedelta(milliseconds=100),
        duration_ms=100.0,
        status_code="OK",
        status_message=None,
        error_type=None,
        error_message=None,
        tool_name=None,
        tool_status=None,
        agent_name=None,
        agent_operation=None,
        retrieval_result_count=retrieval_result_count,
        retrieval_top_relevance_score=retrieval_top_relevance_score,
        is_root_span=is_root_span,
        is_error_span=False,
        is_direct_subject=is_direct_subject,
        trace_duration_fraction=trace_duration_fraction,
        depth=depth,
        evidence_score=evidence_score,
        evidence_score_breakdown="duration=0.500,error=0.000,direct_subject=0.000,signal_specific=0.000",
        evidence_type="duration",
        explanation="Span occupied 50.0% of the trace wall-clock envelope",
    )


# ---------------------------------------------------------------------------
# INSUFFICIENT_DATA
# ---------------------------------------------------------------------------

class TestInsufficientData:
    def test_trace_id_none(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _minimal_reconstruction(span_count=5)
        ev = (_make_span_evidence("s1", 0.9), _make_span_evidence("s2", 0.1))
        assert assess_confidence(anomaly, ev, recon) == "INSUFFICIENT_DATA"

    def test_zero_spans(self):
        anomaly = _make_anomaly()
        recon = _minimal_reconstruction(span_count=0, n_roots=0)
        assert assess_confidence(anomaly, (), recon) == "INSUFFICIENT_DATA"

    def test_one_span(self):
        anomaly = _make_anomaly()
        recon = _minimal_reconstruction(span_count=1)
        ev = (_make_span_evidence("s1", 0.95),)
        assert assess_confidence(anomaly, ev, recon) == "INSUFFICIENT_DATA"

    def test_high_score_does_not_override_insufficient_data(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _minimal_reconstruction()
        ev = (_make_span_evidence("s1", 1.0), _make_span_evidence("s2", 0.0))
        assert assess_confidence(anomaly, ev, recon) == "INSUFFICIENT_DATA"

    def test_one_span_high_score_still_insufficient(self):
        anomaly = _make_anomaly()
        recon = _minimal_reconstruction(span_count=1)
        ev = (_make_span_evidence("s1", 1.0),)
        assert assess_confidence(anomaly, ev, recon) == "INSUFFICIENT_DATA"


# ---------------------------------------------------------------------------
# LOW
# ---------------------------------------------------------------------------

class TestLow:
    def _ev_pair(self, top: float, second: float = 0.0) -> tuple[SpanEvidence, ...]:
        return (
            _make_span_evidence("s1", top),
            _make_span_evidence("s2", second),
        )

    def _clean_recon(self):
        return _minimal_reconstruction(span_count=2)

    def test_trace_latency_below_threshold(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        assert assess_confidence(anomaly, self._ev_pair(0.49), self._clean_recon()) == "LOW"

    def test_trace_latency_at_threshold_not_low(self):
        # Exactly 0.50 is NOT < threshold → not LOW from this rule
        # With gap=0.50 >= 0.10 → need gap check... 0.50-0.0=0.50 ≥ 0.10 → not MEDIUM
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        result = assess_confidence(anomaly, self._ev_pair(0.50), self._clean_recon())
        assert result != "LOW"

    def test_agent_latency_below_threshold(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="research/plan",
                                subject_span_id="s1")
        ev = (
            _make_span_evidence("s1", 0.39, is_direct_subject=True),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_agent_latency_at_threshold_not_low(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="research/plan",
                                subject_span_id="s1")
        ev = (
            _make_span_evidence("s1", 0.40, is_direct_subject=True),
            _make_span_evidence("s2", 0.0),
        )
        result = assess_confidence(anomaly, ev, self._clean_recon())
        assert result != "LOW"

    def test_tool_latency_below_threshold(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="tool.execute",
                                subject_span_id="s1")
        ev = (
            _make_span_evidence("s1", 0.39, is_direct_subject=True),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_retrieval_quality_below_threshold(self):
        anomaly = _make_anomaly(anomaly_type="retrieval_quality",
                                operation_name="retrieval.search", subject_span_id="s1",
                                signal_name="retrieval_top_relevance_score")
        ev = (
            _make_span_evidence("s1", 0.49, is_direct_subject=True,
                                retrieval_top_relevance_score=0.30),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_error_rate_below_threshold(self):
        anomaly = _make_anomaly(anomaly_type="error_rate", operation_name="some_op",
                                subject_span_id="s1")
        ev = (
            _make_span_evidence("s1", 0.39, is_direct_subject=True),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_tool_failure_below_threshold(self):
        anomaly = _make_anomaly(anomaly_type="tool_failure",
                                operation_name="tool.execute/Timeout", subject_span_id="s1")
        ev = (
            _make_span_evidence("s1", 0.39, is_direct_subject=True),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_retrieval_anomaly_no_retrieval_evidence(self):
        anomaly = _make_anomaly(anomaly_type="retrieval_quality",
                                operation_name="retrieval.search",
                                signal_name="retrieval_top_relevance_score")
        # No retrieval fields in evidence
        ev = (
            _make_span_evidence("s1", 0.60),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_retrieval_anomaly_with_retrieval_evidence_passes_low_check(self):
        anomaly = _make_anomaly(anomaly_type="retrieval_quality",
                                operation_name="retrieval.search",
                                signal_name="retrieval_top_relevance_score",
                                subject_span_id="s1")
        ev = (
            _make_span_evidence("s1", 0.60, is_direct_subject=True,
                                retrieval_top_relevance_score=0.30),
            _make_span_evidence("s2", 0.0),
        )
        result = assess_confidence(anomaly, ev, self._clean_recon())
        assert result != "LOW"

    def test_missing_direct_subject_agent_latency(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="research/plan")
        ev = (
            _make_span_evidence("s1", 0.60, is_direct_subject=False),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_missing_direct_subject_tool_latency(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="tool.execute")
        ev = (
            _make_span_evidence("s1", 0.60, is_direct_subject=False),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_missing_direct_subject_error_rate(self):
        anomaly = _make_anomaly(anomaly_type="error_rate", operation_name="op")
        ev = (
            _make_span_evidence("s1", 0.60, is_direct_subject=False),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"

    def test_trace_latency_no_direct_subject_check(self):
        # trace_latency is NOT span-specific; missing direct subject does NOT cause LOW
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.60, is_direct_subject=False),
            _make_span_evidence("s2", 0.0),
        )
        result = assess_confidence(anomaly, ev, self._clean_recon())
        assert result != "LOW"

    def test_orphan_fraction_above_50_pct(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        # 3 spans, 2 orphans → orphan_frac = 2/3 > 0.50
        orphan1 = TraceNode(
            span=_make_span_record("orphan-1", parent_span_id="absent-1"),
            children=[], depth=0,
        )
        orphan2 = TraceNode(
            span=_make_span_record("orphan-2", parent_span_id="absent-2"),
            children=[], depth=0,
        )
        root = TraceNode(
            span=_make_span_record("root", parent_span_id=None),
            children=[], depth=0,
        )
        recon = TraceReconstruction(
            roots=[root], orphans=[orphan1, orphan2], cycle_members=[],
            has_cycle=False, span_count=3, trace_duration_ms=200.0,
        )
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, recon) == "LOW"

    def test_low_takes_precedence_over_medium_gap(self):
        # Top score below threshold AND gap < 0.10 → LOW wins
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.30),
            _make_span_evidence("s2", 0.25),  # gap = 0.05 < 0.10
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "LOW"


# ---------------------------------------------------------------------------
# MEDIUM
# ---------------------------------------------------------------------------

class TestMedium:
    def _clean_recon(self):
        return _minimal_reconstruction(span_count=2)

    def _ev_above_threshold(
        self, top: float = 0.60, second: float = 0.10,
        is_direct_subject: bool = True,
        with_retrieval: bool = False,
    ) -> tuple[SpanEvidence, ...]:
        """Evidence that passes all LOW checks for span-specific signals."""
        rrs = 0.30 if with_retrieval else None
        return (
            _make_span_evidence("s1", top, is_direct_subject=is_direct_subject,
                                retrieval_top_relevance_score=rrs),
            _make_span_evidence("s2", second),
        )

    def test_top_two_gap_below_010(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.60),
            _make_span_evidence("s2", 0.51),  # gap = 0.09 < 0.10
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "MEDIUM"

    def test_gap_clearly_below_010_triggers_medium(self):
        # 0.70 - 0.61 ≈ 0.09000 < 0.10, not close to 0.10 → MEDIUM from gap rule
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.61),  # gap ≈ 0.09000
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "MEDIUM"

    def test_gap_mathematical_boundary_010_not_medium(self):
        # 0.60 - 0.50 = 0.09999... in IEEE 754; math.isclose identifies it as ≈0.10
        # → gap rule does NOT fire → not MEDIUM from gap
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.60),
            _make_span_evidence("s2", 0.50),  # gap = 0.09999... ≈ 0.10
        )
        result = assess_confidence(anomaly, ev, self._clean_recon())
        assert result != "MEDIUM"

    def test_gap_clearly_above_011_not_medium_from_gap_rule(self):
        # 0.70 - 0.59 ≈ 0.11000 > 0.10 → gap < 0.10 is False → not MEDIUM from gap
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.59),  # gap ≈ 0.11000
        )
        result = assess_confidence(anomaly, ev, self._clean_recon())
        assert result != "MEDIUM"

    def test_orphan_fraction_exactly_010(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        # 10 spans, 1 orphan → orphan_frac = 0.10
        orphan = TraceNode(
            span=_make_span_record("orphan-1", parent_span_id="absent"),
            children=[], depth=0,
        )
        root = TraceNode(
            span=_make_span_record("root", parent_span_id=None),
            children=[], depth=0,
        )
        recon = TraceReconstruction(
            roots=[root], orphans=[orphan], cycle_members=[],
            has_cycle=False, span_count=10, trace_duration_ms=200.0,
        )
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, recon) == "MEDIUM"

    def test_orphan_fraction_exactly_050(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        # 2 spans, 1 orphan → orphan_frac = 0.50
        orphan = TraceNode(
            span=_make_span_record("orphan-1", parent_span_id="absent"),
            children=[], depth=0,
        )
        root = TraceNode(
            span=_make_span_record("root", parent_span_id=None),
            children=[], depth=0,
        )
        recon = TraceReconstruction(
            roots=[root], orphans=[orphan], cycle_members=[],
            has_cycle=False, span_count=2, trace_duration_ms=200.0,
        )
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, recon) == "MEDIUM"

    def test_cycle_detected(self):
        # Use build_trace_tree to generate a real cyclic reconstruction
        span_b = SpanRecord(
            span_id="B", parent_span_id="C",
            span_name="B", service_name="svc",
            start_time=_T0, end_time=_T0 + timedelta(milliseconds=100),
            duration_ms=100.0, status_code="OK",
        )
        span_c = SpanRecord(
            span_id="C", parent_span_id="B",
            span_name="C", service_name="svc",
            start_time=_T0 + timedelta(milliseconds=10),
            end_time=_T0 + timedelta(milliseconds=90),
            duration_ms=80.0, status_code="OK",
        )
        recon = build_trace_tree([span_b, span_c])
        assert recon.has_cycle is True

        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, recon) == "MEDIUM"

    def test_malformed_fraction_gt_1(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.70, trace_duration_fraction=1.5),  # > 1.0
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon()) == "MEDIUM"

    def test_natural_root_absent(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        recon = TraceReconstruction(
            roots=[],  # no natural roots
            orphans=[],
            cycle_members=[],
            has_cycle=False,
            span_count=2,
            trace_duration_ms=200.0,
        )
        ev = (
            _make_span_evidence("s1", 0.70),
            _make_span_evidence("s2", 0.0),
        )
        assert assess_confidence(anomaly, ev, recon) == "MEDIUM"


# ---------------------------------------------------------------------------
# MEDIUM — deep single-span outlier (condition 21E, trace_latency only)
# ---------------------------------------------------------------------------

class TestDeepSingleSpanOutlier:
    """
    MEDIUM condition 21E: trace_latency + non-root top span at depth >= 2 +
    exactly one non-root span with evidence_score >= 0.50.
    """

    def _anomaly(self):
        return _make_anomaly(anomaly_type="latency", operation_name="trace")

    def _clean_recon(self):
        return _minimal_reconstruction(span_count=3)

    def test_trace_latency_deep_single_span_outlier_medium(self):
        # non-root, depth=2, score=0.70 (>= 0.50): exactly 1 qualifying → MEDIUM
        ev = (
            _make_span_evidence("s1", 0.70, is_root_span=False, depth=2),
            _make_span_evidence("s2", 0.10, is_root_span=True, depth=0),
        )
        assert assess_confidence(self._anomaly(), ev, self._clean_recon()) == "MEDIUM"

    def test_deep_single_span_outlier_top_is_root_no_trigger(self):
        # Artificial: top span is root (is_root_span=True); condition checks
        # not evidence[0].is_root_span → False → outlier condition not met → HIGH
        ev = (
            _make_span_evidence("s1", 0.70, is_root_span=True, depth=0),
            _make_span_evidence("s2", 0.55, is_root_span=False, depth=2),
        )
        # gap = 0.15 >= 0.10, no cycle/orphan → HIGH
        assert assess_confidence(self._anomaly(), ev, self._clean_recon()) == "HIGH"

    def test_deep_single_span_outlier_depth_1_no_trigger(self):
        # depth=1 < 2 → condition False → HIGH
        ev = (
            _make_span_evidence("s1", 0.70, is_root_span=False, depth=1),
            _make_span_evidence("s2", 0.10, is_root_span=True, depth=0),
        )
        assert assess_confidence(self._anomaly(), ev, self._clean_recon()) == "HIGH"

    def test_deep_single_span_outlier_two_qualifying_no_trigger(self):
        # Two non-root spans with score >= 0.50 → len(qualifying) == 2 → no trigger
        ev = (
            _make_span_evidence("s1", 0.70, is_root_span=False, depth=3),
            _make_span_evidence("s2", 0.55, is_root_span=False, depth=2),
        )
        # gap = 0.15 >= 0.10, no other MEDIUM conditions → HIGH
        assert assess_confidence(self._anomaly(), ev, self._clean_recon()) == "HIGH"

    def test_deep_single_span_outlier_score_exactly_050_triggers(self):
        # score exactly 0.50 counts as qualifying (>= 0.50) → MEDIUM
        ev = (
            _make_span_evidence("s1", 0.50, is_root_span=False, depth=2),
            _make_span_evidence("s2", 0.00, is_root_span=True, depth=0),
        )
        assert assess_confidence(self._anomaly(), ev, self._clean_recon()) == "MEDIUM"

    def test_deep_single_span_outlier_low_wins_before(self):
        # top_score = 0.49 < threshold (0.50) → LOW fires before outlier check
        ev = (
            _make_span_evidence("s1", 0.49, is_root_span=False, depth=2),
            _make_span_evidence("s2", 0.20, is_root_span=False, depth=3),
        )
        assert assess_confidence(self._anomaly(), ev, self._clean_recon()) == "LOW"


# ---------------------------------------------------------------------------
# HIGH
# ---------------------------------------------------------------------------

class TestHigh:
    def _clean_recon_with_root(self):
        root = TraceNode(
            span=_make_span_record("root", parent_span_id=None),
            children=[], depth=0,
        )
        return TraceReconstruction(
            roots=[root], orphans=[], cycle_members=[],
            has_cycle=False, span_count=3, trace_duration_ms=1850.0,
        )

    def test_clean_trace_large_separation(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        ev = (
            _make_span_evidence("s1", 0.88),
            _make_span_evidence("s2", 0.04),  # gap = 0.84 >> 0.10
        )
        assert assess_confidence(anomaly, ev, self._clean_recon_with_root()) == "HIGH"

    def test_span_specific_with_direct_subject(self):
        anomaly = _make_anomaly(
            anomaly_type="latency", operation_name="research/plan",
            subject_span_id="s1",
        )
        ev = (
            _make_span_evidence("s1", 0.70, is_direct_subject=True),
            _make_span_evidence("s2", 0.01),  # gap = 0.69 > 0.10
        )
        assert assess_confidence(anomaly, ev, self._clean_recon_with_root()) == "HIGH"

    def test_retrieval_with_evidence_and_direct_subject(self):
        anomaly = _make_anomaly(
            anomaly_type="retrieval_quality",
            operation_name="retrieval.search",
            signal_name="retrieval_top_relevance_score",
            subject_span_id="s1",
        )
        ev = (
            _make_span_evidence("s1", 0.70, is_direct_subject=True,
                                retrieval_top_relevance_score=0.30),
            _make_span_evidence("s2", 0.01),
        )
        assert assess_confidence(anomaly, ev, self._clean_recon_with_root()) == "HIGH"

    def test_locked_e2e_fixture_high_confidence(self):
        """
        Locked E2E fixture: trace_latency, tool.execute 1480ms / 1850ms trace.
        Score = 0.88 for tool.execute, ~0.0 for root (excluded).
        Expected confidence: HIGH.
        """
        # Build the trace spans
        root_span = _make_span_record("root", None, duration_ms=1850.0, start_offset_ms=0.0)
        tool_span = _make_span_record(
            "tool-1", "root",
            duration_ms=1480.0,
            status_code="ERROR",
            start_offset_ms=200.0,
        )
        spans = [root_span, tool_span]
        recon = build_trace_tree(spans)

        anomaly = _make_anomaly(
            anomaly_type="latency",
            operation_name="trace",
            trace_id="trace-1",
        )

        # Use extract_evidence + score_and_rank for a full pipeline test
        from rca_evidence import extract_evidence
        from rca_source import RcaAnomalyRecord

        facts = extract_evidence(anomaly, recon)
        evidence = score_and_rank(anomaly, facts)

        assert evidence[0].evidence_score == pytest.approx(0.88, abs=1e-9)
        assert assess_confidence(anomaly, evidence, recon) == "HIGH"


# ---------------------------------------------------------------------------
# Public signal API (Phase 11.6 interface-only additions)
# ---------------------------------------------------------------------------

class TestPublicSignalAPI:
    """
    Regression tests for the four public symbols extracted in Phase 11.6.
    Each public symbol must delegate faithfully to the private canonical
    implementation it wraps; no new logic is permitted.
    """

    # ----- derive_signal -----

    def test_derive_signal_trace_latency(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="trace")
        assert derive_signal(a) == "trace_latency"

    def test_derive_signal_tool_latency(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="tool.execute")
        assert derive_signal(a) == "tool_latency"

    def test_derive_signal_agent_latency(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="research/plan")
        assert derive_signal(a) == "agent_latency"

    def test_derive_signal_retrieval_quality(self):
        a = _make_anomaly(anomaly_type="retrieval_quality",
                          operation_name="retrieval.search")
        assert derive_signal(a) == "retrieval_quality"

    def test_derive_signal_error_rate(self):
        a = _make_anomaly(anomaly_type="error_rate", operation_name="some_op")
        assert derive_signal(a) == "error_rate"

    def test_derive_signal_tool_failure(self):
        a = _make_anomaly(anomaly_type="tool_failure",
                          operation_name="tool.execute/Timeout")
        assert derive_signal(a) == "tool_failure"

    def test_derive_signal_agrees_with_private(self):
        cases = [
            ("latency", "trace"),
            ("latency", "tool.execute"),
            ("latency", "research/plan"),
            ("retrieval_quality", None),
            ("error_rate", None),
            ("tool_failure", "tool.execute/TypeError"),
        ]
        for atype, op in cases:
            a = _make_anomaly(anomaly_type=atype, operation_name=op)
            assert derive_signal(a) == _derive_signal(a), f"Mismatch for {atype}/{op}"

    # ----- signal_threshold -----

    def test_signal_threshold_all_known_signals(self):
        expected = {
            "trace_latency": 0.50,
            "agent_latency": 0.40,
            "tool_latency": 0.40,
            "retrieval_quality": 0.50,
            "error_rate": 0.40,
            "tool_failure": 0.40,
        }
        for sig, thr in expected.items():
            assert signal_threshold(sig) == pytest.approx(thr), f"Signal: {sig}"

    def test_signal_threshold_unknown_defaults_to_040(self):
        assert signal_threshold("nonexistent_signal") == pytest.approx(0.40)

    # ----- SPAN_SPECIFIC_SIGNALS -----

    def test_span_specific_signals_membership(self):
        expected = frozenset({
            "agent_latency", "tool_latency", "retrieval_quality",
            "error_rate", "tool_failure",
        })
        assert SPAN_SPECIFIC_SIGNALS == expected

    def test_span_specific_signals_is_private_alias(self):
        assert SPAN_SPECIFIC_SIGNALS is _SPAN_SPECIFIC_SIGNALS

    # ----- orphan_fraction -----

    def test_orphan_fraction_empty_reconstruction(self):
        recon = _minimal_reconstruction(span_count=0, n_roots=0, n_orphans=0)
        assert orphan_fraction(recon) == pytest.approx(0.0)

    def test_orphan_fraction_no_orphans(self):
        recon = _minimal_reconstruction(span_count=3, n_orphans=0, n_roots=1)
        assert orphan_fraction(recon) == pytest.approx(0.0)

    def test_orphan_fraction_with_orphans(self):
        # 1 orphan node (no children), 1 root → span_count=2 → fraction = 0.50
        orphan = TraceNode(
            span=_make_span_record("o1", "absent"), children=[], depth=0,
        )
        root = TraceNode(
            span=_make_span_record("root", None), children=[], depth=0,
        )
        recon = TraceReconstruction(
            roots=[root], orphans=[orphan], cycle_members=[],
            has_cycle=False, span_count=2, trace_duration_ms=100.0,
        )
        assert orphan_fraction(recon) == pytest.approx(0.50)

    def test_orphan_fraction_agrees_with_private(self):
        orphan = TraceNode(
            span=_make_span_record("o1", "absent"), children=[], depth=0,
        )
        root = TraceNode(
            span=_make_span_record("root", None), children=[], depth=0,
        )
        recon = TraceReconstruction(
            roots=[root], orphans=[orphan], cycle_members=[],
            has_cycle=False, span_count=2, trace_duration_ms=100.0,
        )
        assert orphan_fraction(recon) == pytest.approx(_orphan_fraction(recon))

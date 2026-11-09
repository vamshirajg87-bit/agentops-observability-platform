"""
tests/unit/test_rca_ranker.py

Unit tests for rca_ranker — Phase 11.4 signal-aware scoring and ranking.

Coverage:
  - _derive_signal routing (all six signals)
  - _decode_tool_error_type
  - trace_latency scoring (non-root, root, error, root+error, None fraction, >1)
  - agent_latency scoring
  - tool_latency scoring (same structure, independent test)
  - retrieval_quality scoring (all D-component combinations, NULL semantics)
  - error_rate scoring
  - tool_failure scoring (matching, non-matching, missing error type)
  - score cap at 1.0
  - evidence_score_breakdown format (stable, deterministic)
  - evidence_type classification
  - explanation content (evidence-only language, no causal claims)
  - deterministic ranking (tie-breaking)
  - locked E2E math fixture (trace_latency, tool.execute 1480ms/1850ms → 0.88)
  - malformed fraction > 1.0 preserved in SpanEvidence
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from typing import Optional

from rca_evidence import UnscoredSpanFacts
from rca_models import SpanEvidence
from rca_ranker import (
    _decode_tool_error_type,
    _derive_signal,
    score_and_rank,
)
from rca_source import RcaAnomalyRecord


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_facts(
    span_id: str = "s1",
    parent_span_id: Optional[str] = "root",
    span_name: str = "test.span",
    service_name: str = "svc",
    duration_ms: float = 100.0,
    status_code: str = "OK",
    is_root_span: bool = False,
    is_error_span: bool = False,
    is_direct_subject: bool = False,
    trace_duration_fraction: Optional[float] = 0.1,
    depth: int = 1,
    error_type: Optional[str] = None,
    retrieval_result_count: Optional[int] = None,
    retrieval_top_relevance_score: Optional[float] = None,
    start_time: Optional[datetime] = None,
) -> UnscoredSpanFacts:
    t = start_time or _T0
    return UnscoredSpanFacts(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_name,
        service_name=service_name,
        start_time=t,
        end_time=t + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        status_code=status_code,
        status_message=None,
        error_type=error_type,
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


def _make_anomaly(
    anomaly_type: str = "latency",
    signal_name: str = "duration_ms",
    operation_name: Optional[str] = "trace",
    subject_span_id: Optional[str] = None,
    trace_id: str = "trace-1",
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


def _rank_one(anomaly: RcaAnomalyRecord, fact: UnscoredSpanFacts) -> SpanEvidence:
    return score_and_rank(anomaly, (fact,))[0]


# ---------------------------------------------------------------------------
# _derive_signal
# ---------------------------------------------------------------------------

class TestDeriveSignal:
    def test_trace_latency(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="trace")
        assert _derive_signal(a) == "trace_latency"

    def test_tool_latency(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="tool.execute")
        assert _derive_signal(a) == "tool_latency"

    def test_agent_latency_research(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="research/plan")
        assert _derive_signal(a) == "agent_latency"

    def test_agent_latency_other(self):
        a = _make_anomaly(anomaly_type="latency", operation_name="agent.run")
        assert _derive_signal(a) == "agent_latency"

    def test_agent_latency_none_operation(self):
        a = _make_anomaly(anomaly_type="latency", operation_name=None)
        assert _derive_signal(a) == "agent_latency"

    def test_retrieval_quality(self):
        a = _make_anomaly(anomaly_type="retrieval_quality", operation_name="retrieval.search")
        assert _derive_signal(a) == "retrieval_quality"

    def test_error_rate(self):
        a = _make_anomaly(anomaly_type="error_rate", operation_name="some_op")
        assert _derive_signal(a) == "error_rate"

    def test_tool_failure(self):
        a = _make_anomaly(anomaly_type="tool_failure", operation_name="tool.execute/Timeout")
        assert _derive_signal(a) == "tool_failure"


# ---------------------------------------------------------------------------
# _decode_tool_error_type
# ---------------------------------------------------------------------------

class TestDecodeToolErrorType:
    def test_normal(self):
        assert _decode_tool_error_type("tool.execute/ConnectionTimeout") == "ConnectionTimeout"

    def test_simple_type(self):
        assert _decode_tool_error_type("tool.execute/ValueError") == "ValueError"

    def test_empty_error_type(self):
        assert _decode_tool_error_type("tool.execute/") == ""

    def test_no_slash(self):
        assert _decode_tool_error_type("tool.execute") is None

    def test_none(self):
        assert _decode_tool_error_type(None) is None

    def test_wrong_prefix(self):
        assert _decode_tool_error_type("other_op/Timeout") is None

    def test_error_type_with_slash(self):
        # Only the first occurrence of the prefix is stripped; remaining content preserved
        assert _decode_tool_error_type("tool.execute/A/B") == "A/B"


# ---------------------------------------------------------------------------
# TRACE_LATENCY scoring
# ---------------------------------------------------------------------------

class TestTraceLatencyScoring:
    def _anomaly(self):
        return _make_anomaly(anomaly_type="latency", operation_name="trace")

    def test_non_root_duration_only(self):
        f = _make_facts(is_root_span=False, is_error_span=False, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.60 * 0.5, abs=1e-9)

    def test_non_root_error_only(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_non_root_duration_and_error(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.60 * 0.5 + 0.40, abs=1e-9)

    def test_root_duration_excluded(self):
        # Root span: A=0 regardless of fraction
        f = _make_facts(is_root_span=True, is_error_span=False,
                        trace_duration_fraction=1.0, parent_span_id=None)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_root_duration_excluded_large_fraction(self):
        f = _make_facts(is_root_span=True, is_error_span=False,
                        trace_duration_fraction=0.99, parent_span_id=None)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_root_error_retained(self):
        # Root span: A=0 but B=0.40 when error
        f = _make_facts(is_root_span=True, is_error_span=True,
                        trace_duration_fraction=1.0, parent_span_id=None)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_none_fraction_treated_as_zero(self):
        f = _make_facts(is_root_span=False, is_error_span=False, trace_duration_fraction=None)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_none_fraction_with_error(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=None)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_score_cap_at_1(self):
        # Fraction > 1.0: A = 0.60 * 1.5 = 0.90; B = 0.40; sum = 1.30 → capped at 1.0
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=1.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(1.0, abs=1e-9)

    def test_raw_fraction_preserved_when_gt_1(self):
        f = _make_facts(is_root_span=False, trace_duration_fraction=1.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.trace_duration_fraction == pytest.approx(1.5, abs=1e-9)

    def test_breakdown_format(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        # A = 0.60*0.5=0.300, B=0.400
        assert ev.evidence_score_breakdown == "duration=0.300,error=0.400,direct_subject=0.000,signal_specific=0.000"

    def test_evidence_type_mixed(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_type == "mixed"

    def test_evidence_type_duration_only(self):
        f = _make_facts(is_root_span=False, is_error_span=False, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_type == "duration"

    def test_evidence_type_error_only(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_type == "error"

    def test_evidence_type_telemetry_when_zero(self):
        f = _make_facts(is_root_span=True, is_error_span=False,
                        trace_duration_fraction=1.0, parent_span_id=None)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_type == "telemetry"

    def test_root_explanation_mentions_exclusion(self):
        f = _make_facts(is_root_span=True, is_error_span=False,
                        trace_duration_fraction=1.0, parent_span_id=None)
        ev = _rank_one(self._anomaly(), f)
        assert "Root span" in ev.explanation
        assert "excluded" in ev.explanation

    def test_error_explanation_mentions_error(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        assert "ERROR" in ev.explanation

    def test_explanation_no_causal_language(self):
        f = _make_facts(is_root_span=False, is_error_span=True, trace_duration_fraction=0.8)
        ev = _rank_one(self._anomaly(), f)
        for forbidden in ("caused", "root cause", "responsible", "culprit", "probability"):
            assert forbidden not in ev.explanation.lower()

    def test_none_fraction_explanation_mentions_zero_width(self):
        f = _make_facts(is_root_span=False, is_error_span=False, trace_duration_fraction=None)
        ev = _rank_one(self._anomaly(), f)
        assert "zero-width" in ev.explanation or "unavailable" in ev.explanation


# ---------------------------------------------------------------------------
# LOCKED E2E MATH FIXTURE (Phase 11.4 spec Section 28)
# ---------------------------------------------------------------------------

class TestLockedE2EMathFixture:
    """
    Trace duration: 1850 ms
    tool.execute span: duration=1480ms, status=ERROR, non-root
    Signal: trace_latency

    trace_duration_fraction = 1480 / 1850 = 0.8
    A = 0.60 * 0.8 = 0.48
    B = 0.40
    score = min(1.0, 0.88) = 0.88
    """

    def test_locked_evidence_score(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        tool_span = _make_facts(
            span_id="tool-1",
            span_name="tool.execute",
            is_root_span=False,
            is_error_span=True,
            trace_duration_fraction=1480 / 1850,
        )
        ev = _rank_one(anomaly, tool_span)
        assert ev.evidence_score == pytest.approx(0.88, abs=1e-9)

    def test_locked_breakdown(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        tool_span = _make_facts(
            span_id="tool-1",
            span_name="tool.execute",
            is_root_span=False,
            is_error_span=True,
            trace_duration_fraction=1480 / 1850,
        )
        ev = _rank_one(anomaly, tool_span)
        assert ev.evidence_score_breakdown == (
            "duration=0.480,error=0.400,direct_subject=0.000,signal_specific=0.000"
        )

    def test_locked_explanation_mentions_80_percent(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        tool_span = _make_facts(
            span_id="tool-1",
            span_name="tool.execute",
            is_root_span=False,
            is_error_span=True,
            trace_duration_fraction=1480 / 1850,
        )
        ev = _rank_one(anomaly, tool_span)
        assert "80.0%" in ev.explanation

    def test_locked_explanation_mentions_error(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        tool_span = _make_facts(
            span_id="tool-1",
            span_name="tool.execute",
            is_root_span=False,
            is_error_span=True,
            trace_duration_fraction=1480 / 1850,
        )
        ev = _rank_one(anomaly, tool_span)
        assert "ERROR" in ev.explanation

    def test_locked_explanation_no_causal_claims(self):
        anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
        tool_span = _make_facts(
            span_id="tool-1",
            span_name="tool.execute",
            is_root_span=False,
            is_error_span=True,
            trace_duration_fraction=1480 / 1850,
        )
        ev = _rank_one(anomaly, tool_span)
        for forbidden in ("caused", "root cause", "responsible", "probability"):
            assert forbidden not in ev.explanation.lower()


# ---------------------------------------------------------------------------
# AGENT_LATENCY scoring
# ---------------------------------------------------------------------------

class TestAgentLatencyScoring:
    def _anomaly(self, subject: Optional[str] = None):
        return _make_anomaly(
            anomaly_type="latency",
            operation_name="research/plan",
            subject_span_id=subject,
        )

    def test_duration_only(self):
        f = _make_facts(is_error_span=False, is_direct_subject=False, trace_duration_fraction=0.4)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.30 * 0.4, abs=1e-9)

    def test_error_only(self):
        f = _make_facts(is_error_span=True, is_direct_subject=False, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.30, abs=1e-9)

    def test_direct_subject_only(self):
        f = _make_facts(is_error_span=False, is_direct_subject=True, trace_duration_fraction=0.0,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_all_components(self):
        f = _make_facts(is_error_span=True, is_direct_subject=True, trace_duration_fraction=0.5,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        expected = 0.30 * 0.5 + 0.30 + 0.40
        assert ev.evidence_score == pytest.approx(expected, abs=1e-9)

    def test_exact_expected_score(self):
        f = _make_facts(is_error_span=True, is_direct_subject=True, trace_duration_fraction=1.0,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        # 0.30 + 0.30 + 0.40 = 1.00
        assert ev.evidence_score == pytest.approx(1.0, abs=1e-9)

    def test_direct_subject_explanation(self):
        f = _make_facts(is_error_span=False, is_direct_subject=True, trace_duration_fraction=0.0,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        assert "direct subject" in ev.explanation.lower()


# ---------------------------------------------------------------------------
# TOOL_LATENCY scoring
# ---------------------------------------------------------------------------

class TestToolLatencyScoring:
    def _anomaly(self, subject: Optional[str] = None):
        return _make_anomaly(
            anomaly_type="latency",
            operation_name="tool.execute",
            subject_span_id=subject,
        )

    def test_duration_only(self):
        f = _make_facts(is_error_span=False, is_direct_subject=False, trace_duration_fraction=0.6)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.30 * 0.6, abs=1e-9)

    def test_error_component(self):
        f = _make_facts(is_error_span=True, is_direct_subject=False, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.30, abs=1e-9)

    def test_direct_subject(self):
        f = _make_facts(is_error_span=False, is_direct_subject=True, trace_duration_fraction=0.0,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_direct_subject_by_is_direct_subject_field_only(self):
        # Must use is_direct_subject fact only, not infer from span_name or tool_name
        f = _make_facts(span_name="tool.execute", is_direct_subject=False, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_combined_all(self):
        f = _make_facts(is_error_span=True, is_direct_subject=True, trace_duration_fraction=0.5,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        expected = min(1.0, 0.30 * 0.5 + 0.30 + 0.40)
        assert ev.evidence_score == pytest.approx(expected, abs=1e-9)


# ---------------------------------------------------------------------------
# RETRIEVAL_QUALITY scoring
# ---------------------------------------------------------------------------

class TestRetrievalQualityScoring:
    def _anomaly(self, subject: Optional[str] = None):
        return _make_anomaly(
            anomaly_type="retrieval_quality",
            signal_name="retrieval_top_relevance_score",
            operation_name="retrieval.search",
            subject_span_id=subject,
        )

    def test_zero_results_bonus(self):
        f = _make_facts(retrieval_result_count=0, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.20, abs=1e-9)

    def test_low_relevance_bonus(self):
        f = _make_facts(retrieval_top_relevance_score=0.30, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.20, abs=1e-9)

    def test_both_bonuses(self):
        f = _make_facts(retrieval_result_count=0, retrieval_top_relevance_score=0.30,
                        trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_none_result_count_no_bonus(self):
        f = _make_facts(retrieval_result_count=None, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_none_relevance_no_bonus(self):
        f = _make_facts(retrieval_top_relevance_score=None, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_relevance_exactly_050_no_bonus(self):
        # Threshold is strict <0.50; exactly 0.50 does NOT receive the bonus
        f = _make_facts(retrieval_top_relevance_score=0.50, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_relevance_just_below_050(self):
        f = _make_facts(retrieval_top_relevance_score=0.499, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.20, abs=1e-9)

    def test_non_zero_results_no_bonus(self):
        f = _make_facts(retrieval_result_count=5, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.0, abs=1e-9)

    def test_direct_subject(self):
        f = _make_facts(is_direct_subject=True, trace_duration_fraction=0.0, span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        assert ev.evidence_score == pytest.approx(0.30, abs=1e-9)

    def test_error_component(self):
        f = _make_facts(is_error_span=True, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.20, abs=1e-9)

    def test_all_components(self):
        f = _make_facts(
            is_error_span=True, is_direct_subject=True, trace_duration_fraction=0.5,
            retrieval_result_count=0, retrieval_top_relevance_score=0.20,
            span_id="s1",
        )
        ev = _rank_one(self._anomaly(subject="s1"), f)
        expected = min(1.0, 0.10 * 0.5 + 0.20 + 0.30 + 0.40)
        assert ev.evidence_score == pytest.approx(expected, abs=1e-9)

    def test_evidence_type_retrieval_when_only_d(self):
        f = _make_facts(retrieval_result_count=0, trace_duration_fraction=0.0,
                        is_error_span=False, is_direct_subject=False)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_type == "retrieval"

    def test_zero_results_explanation(self):
        f = _make_facts(retrieval_result_count=0, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert "zero retrieval results" in ev.explanation

    def test_low_relevance_explanation(self):
        f = _make_facts(retrieval_top_relevance_score=0.30, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert "0.300" in ev.explanation
        assert "below 0.50" in ev.explanation


# ---------------------------------------------------------------------------
# ERROR_RATE scoring
# ---------------------------------------------------------------------------

class TestErrorRateScoring:
    def _anomaly(self, subject: Optional[str] = None):
        return _make_anomaly(
            anomaly_type="error_rate",
            signal_name="error_rate",
            operation_name="some_op",
            subject_span_id=subject,
        )

    def test_duration_only(self):
        f = _make_facts(is_error_span=False, is_direct_subject=False, trace_duration_fraction=0.5)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.20 * 0.5, abs=1e-9)

    def test_error_component(self):
        f = _make_facts(is_error_span=True, is_direct_subject=False, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.50, abs=1e-9)

    def test_direct_subject(self):
        f = _make_facts(is_error_span=False, is_direct_subject=True, trace_duration_fraction=0.0,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        assert ev.evidence_score == pytest.approx(0.30, abs=1e-9)

    def test_all_components(self):
        f = _make_facts(is_error_span=True, is_direct_subject=True, trace_duration_fraction=0.5,
                        span_id="s1")
        ev = _rank_one(self._anomaly(subject="s1"), f)
        expected = min(1.0, 0.20 * 0.5 + 0.50 + 0.30)
        assert ev.evidence_score == pytest.approx(expected, abs=1e-9)

    def test_no_retrieval_or_tool_inference(self):
        # error_rate does not use D; retrieval fields ignored
        f = _make_facts(is_error_span=True, retrieval_result_count=0, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.50, abs=1e-9)


# ---------------------------------------------------------------------------
# TOOL_FAILURE scoring
# ---------------------------------------------------------------------------

class TestToolFailureScoring:
    def _anomaly(self, error_type: str = "TimeoutError", subject: Optional[str] = None):
        return _make_anomaly(
            anomaly_type="tool_failure",
            signal_name="tool_error_rate",
            operation_name=f"tool.execute/{error_type}",
            subject_span_id=subject,
        )

    def test_matching_error_type_bonus(self):
        f = _make_facts(error_type="TimeoutError", is_error_span=True,
                        trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly("TimeoutError"), f)
        # B=0.40 + D=0.20
        assert ev.evidence_score == pytest.approx(0.60, abs=1e-9)

    def test_non_matching_error_type_no_bonus(self):
        f = _make_facts(error_type="ConnectionError", is_error_span=True,
                        trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly("TimeoutError"), f)
        # B=0.40, no D
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_none_error_type_no_bonus(self):
        f = _make_facts(error_type=None, is_error_span=True, trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly("TimeoutError"), f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_missing_operation_name_no_bonus(self):
        anomaly = _make_anomaly(
            anomaly_type="tool_failure",
            signal_name="tool_error_rate",
            operation_name="tool.execute",  # no slash → no error_type
        )
        f = _make_facts(error_type="TimeoutError", is_error_span=True,
                        trace_duration_fraction=0.0)
        ev = _rank_one(anomaly, f)
        assert ev.evidence_score == pytest.approx(0.40, abs=1e-9)

    def test_direct_subject_component(self):
        f = _make_facts(is_direct_subject=True, trace_duration_fraction=0.0,
                        span_id="s1", error_type=None)
        ev = _rank_one(self._anomaly(subject="s1"), f)
        assert ev.evidence_score == pytest.approx(0.30, abs=1e-9)

    def test_duration_component(self):
        f = _make_facts(trace_duration_fraction=0.5, is_error_span=False)
        ev = _rank_one(self._anomaly(), f)
        assert ev.evidence_score == pytest.approx(0.10 * 0.5, abs=1e-9)

    def test_all_components(self):
        f = _make_facts(
            error_type="TimeoutError", is_error_span=True, is_direct_subject=True,
            trace_duration_fraction=0.5, span_id="s1",
        )
        ev = _rank_one(self._anomaly("TimeoutError", subject="s1"), f)
        expected = min(1.0, 0.10 * 0.5 + 0.40 + 0.30 + 0.20)
        assert ev.evidence_score == pytest.approx(expected, abs=1e-9)

    def test_evidence_type_tool_error_match_when_only_d(self):
        f = _make_facts(error_type="Timeout", is_error_span=False, is_direct_subject=False,
                        trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly("Timeout"), f)
        assert ev.evidence_type == "tool_error_match"

    def test_matching_error_type_explanation(self):
        f = _make_facts(error_type="TimeoutError", is_error_span=True,
                        trace_duration_fraction=0.0)
        ev = _rank_one(self._anomaly("TimeoutError"), f)
        assert "tool-failure error type" in ev.explanation


# ---------------------------------------------------------------------------
# Deterministic ranking
# ---------------------------------------------------------------------------

class TestDeterministicRanking:
    def _anomaly(self):
        return _make_anomaly(anomaly_type="latency", operation_name="trace")

    def test_ranked_by_score_desc(self):
        f_high = _make_facts(span_id="high", is_error_span=True, trace_duration_fraction=0.8,
                             start_time=_T0 + timedelta(seconds=2))
        f_low = _make_facts(span_id="low", is_error_span=False, trace_duration_fraction=0.1,
                            start_time=_T0)
        result = score_and_rank(self._anomaly(), (f_low, f_high))
        assert result[0].span_id == "high"
        assert result[1].span_id == "low"

    def test_tiebreak_by_start_time_asc(self):
        # Same score, different start times
        f1 = _make_facts(span_id="later", is_error_span=False, trace_duration_fraction=0.0,
                         start_time=_T0 + timedelta(seconds=10))
        f2 = _make_facts(span_id="earlier", is_error_span=False, trace_duration_fraction=0.0,
                         start_time=_T0)
        result = score_and_rank(self._anomaly(), (f1, f2))
        assert result[0].span_id == "earlier"
        assert result[1].span_id == "later"

    def test_tiebreak_by_span_id_asc(self):
        # Same score, same start time, different span_ids
        f1 = _make_facts(span_id="zzz", is_error_span=False, trace_duration_fraction=0.0,
                         start_time=_T0)
        f2 = _make_facts(span_id="aaa", is_error_span=False, trace_duration_fraction=0.0,
                         start_time=_T0)
        result = score_and_rank(self._anomaly(), (f1, f2))
        assert result[0].span_id == "aaa"
        assert result[1].span_id == "zzz"

    def test_empty_input(self):
        result = score_and_rank(self._anomaly(), ())
        assert result == ()

    def test_single_span(self):
        f = _make_facts(span_id="only", trace_duration_fraction=0.5)
        result = score_and_rank(self._anomaly(), (f,))
        assert len(result) == 1
        assert result[0].span_id == "only"

    def test_returns_tuple(self):
        f = _make_facts(trace_duration_fraction=0.5)
        result = score_and_rank(self._anomaly(), (f,))
        assert isinstance(result, tuple)

    def test_all_section_a_fields_preserved(self):
        f = _make_facts(
            span_id="sid",
            parent_span_id="pid",
            span_name="my.span",
            service_name="my-svc",
            duration_ms=250.0,
            status_code="OK",
            trace_duration_fraction=0.3,
            depth=2,
        )
        ev = _rank_one(self._anomaly(), f)
        assert ev.span_id == "sid"
        assert ev.parent_span_id == "pid"
        assert ev.span_name == "my.span"
        assert ev.service_name == "my-svc"
        assert ev.duration_ms == 250.0
        assert ev.status_code == "OK"
        assert ev.depth == 2

    def test_evidence_score_breakdown_deterministic_for_same_input(self):
        f = _make_facts(is_error_span=True, trace_duration_fraction=0.5)
        ev1 = _rank_one(self._anomaly(), f)
        ev2 = _rank_one(self._anomaly(), f)
        assert ev1.evidence_score_breakdown == ev2.evidence_score_breakdown

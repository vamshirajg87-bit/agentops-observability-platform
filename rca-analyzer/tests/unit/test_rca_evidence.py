"""
rca-analyzer/tests/unit/test_rca_evidence.py

Unit tests for rca_evidence.py.

All tests are pure Python — no database, no network, no I/O.
Uses SpanRecord and build_trace_tree from rca_trace to build realistic inputs.

Verification checklist:
    A. every reconstructed span becomes exactly one UnscoredSpanFacts
    B. orphan/cycle handling does not duplicate or drop spans
    C. evidence output ordering is deterministic (start_time ASC, span_id ASC)
    D. trace_duration_fraction uses the full trace wall-clock envelope
    E. sum of fractions across concurrent spans may exceed 1.0
    F. individual fraction > 1.0 preserved for malformed telemetry
    G. zero-duration trace → trace_duration_fraction = None
    H. no Phase 11.4 scoring/confidence fields on UnscoredSpanFacts

Test inventory:
    MODEL (TestUnscoredSpanFactsModel):
        M01  frozen=True — mutation raises
        M02  Section A fields present
        M03  Section B fields present
        M04  No Section C fields (evidence_score, evidence_score_breakdown, evidence_type)
        M05  No Section D fields (explanation, confidence)

    EMPTY TRACE (TestExtractEvidenceEmpty):
        E01  empty reconstruction → empty tuple

    SINGLE SPAN (TestExtractEvidenceSingleSpan):
        S01  single root span → one UnscoredSpanFacts
        S02  all Section A raw facts copied correctly
        S03  is_root_span True for root span
        S04  is_error_span False for OK status
        S05  is_error_span True for ERROR status
        S06  is_direct_subject False when no subject_span_id
        S07  is_direct_subject True when span_id matches subject_span_id
        S08  trace_duration_fraction = 1.0 for sole span in non-zero trace
        S09  depth = 0 for root span

    MULTI-SPAN TREE (TestExtractEvidenceTree):
        T01  root → child → grandchild: depths 0, 1, 2
        T02  is_root_span: True only for natural root
        T03  child depth = 1, grandchild depth = 2
        T04  every span included exactly once (completeness invariant)
        T05  output ordered start_time ASC, span_id ASC

    ROOT vs ORPHAN (TestExtractEvidenceOrphanRoot):
        O01  orphan root: is_root_span = False (has non-null parent_span_id)
        O02  orphan included in output (not dropped)
        O03  orphan descendant included (not dropped)
        O04  orphan root depth = 0, orphan child depth = 1

    CYCLE MEMBERS (TestExtractEvidenceCycles):
        C01  cycle member spans included in output
        C02  no duplicate spans when cycle present
        C03  span count matches reconstruction.span_count

    IS_DIRECT_SUBJECT (TestExtractEvidenceDirectSubject):
        D01  exactly one span flagged when subject_span_id present in trace
        D02  no span flagged when subject_span_id not present in trace
        D03  no span flagged when anomaly.subject_span_id is None

    TRACE DURATION FRACTION (TestExtractEvidenceTraceDurationFraction):
        F01  fraction = duration_ms / trace_duration_ms
        F02  trace_duration_ms is the wall-clock envelope (not sum of durations)
        F03  sum of fractions > 1.0 for concurrent spans (E: valid observation)
        F04  individual fraction > 1.0 preserved for malformed duration_ms (F)
        F05  None for zero-duration trace (G)
        F06  None propagated correctly: all spans get None for zero-duration trace

    OUTPUT ORDERING (TestExtractEvidenceOrdering):
        R01  same result regardless of reconstruction input order (idempotent)
        R02  tie-break by span_id ASC when start_time equal
        R03  mixed-topology (roots + orphans + cycle members) output is sorted
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from rca_evidence import UnscoredSpanFacts, extract_evidence
from rca_source import RcaAnomalyRecord
from rca_trace import SpanRecord, build_trace_tree


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_BASE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_ANOMALY_ID = "a" * 64
_TRACE_ID = "f" * 32


def _dt(ms: int = 0) -> datetime:
    """Return UTC datetime at BASE + ms milliseconds."""
    return _BASE + timedelta(milliseconds=ms)


def _span(
    span_id: str,
    parent_span_id: Optional[str] = None,
    start_ms: int = 0,
    duration_ms: float = 100.0,
    status_code: str = "OK",
    service_name: str = "svc",
    span_name: str = "op",
    trace_id: Optional[str] = _TRACE_ID,
    **kwargs: object,
) -> SpanRecord:
    start = _dt(start_ms)
    end = _dt(start_ms) + timedelta(milliseconds=duration_ms)
    return SpanRecord(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_name,
        service_name=service_name,
        start_time=start,
        end_time=end,
        duration_ms=duration_ms,
        status_code=status_code,
        trace_id=trace_id,
        **kwargs,
    )


def _anomaly(
    subject_span_id: Optional[str] = None,
    anomaly_type: str = "latency",
) -> RcaAnomalyRecord:
    return RcaAnomalyRecord(
        anomaly_id=_ANOMALY_ID,
        anomaly_type=anomaly_type,
        signal_name="trace_latency_p95",
        detector_name="LatencyDetector",
        detector_version="1.0",
        trace_id=_TRACE_ID,
        subject_span_id=subject_span_id,
        service_name="svc",
        operation_name="op",
        observed_value=1500.0,
        event_time=_dt(0),
        baseline_median=200.0,
        baseline_mad=30.0,
        baseline_n=100,
        anomaly_score=8.5,
        severity="WARNING",
        detector_explanation="p95 exceeded 3× baseline",
    )


def _span_ids(facts: tuple[UnscoredSpanFacts, ...]) -> list[str]:
    return [f.span_id for f in facts]


# ---------------------------------------------------------------------------
# M: Model
# ---------------------------------------------------------------------------

class TestUnscoredSpanFactsModel:

    def _make_facts(self, **overrides: object) -> UnscoredSpanFacts:
        defaults: dict = dict(
            span_id="s1",
            parent_span_id=None,
            span_name="op",
            service_name="svc",
            start_time=_dt(0),
            end_time=_dt(100),
            duration_ms=100.0,
            status_code="OK",
            status_message=None,
            error_type=None,
            error_message=None,
            tool_name=None,
            tool_status=None,
            agent_name=None,
            agent_operation=None,
            retrieval_result_count=None,
            retrieval_top_relevance_score=None,
            is_root_span=True,
            is_error_span=False,
            is_direct_subject=False,
            trace_duration_fraction=1.0,
            depth=0,
        )
        defaults.update(overrides)
        return UnscoredSpanFacts(**defaults)

    def test_frozen_mutation_raises(self):
        facts = self._make_facts()
        with pytest.raises((AttributeError, TypeError)):
            facts.span_id = "mutated"  # type: ignore[misc]

    def test_section_a_field_span_id(self):
        facts = self._make_facts(span_id="x")
        assert facts.span_id == "x"

    def test_section_a_field_is_root_span(self):
        facts = self._make_facts(is_root_span=False)
        assert facts.is_root_span is False

    def test_section_a_field_is_error_span(self):
        facts = self._make_facts(is_error_span=True)
        assert facts.is_error_span is True

    def test_section_a_field_is_direct_subject(self):
        facts = self._make_facts(is_direct_subject=True)
        assert facts.is_direct_subject is True

    def test_section_b_field_trace_duration_fraction(self):
        facts = self._make_facts(trace_duration_fraction=0.5)
        assert facts.trace_duration_fraction == 0.5

    def test_section_b_field_depth(self):
        facts = self._make_facts(depth=3)
        assert facts.depth == 3

    def test_no_evidence_score_field(self):
        facts = self._make_facts()
        assert not hasattr(facts, "evidence_score")

    def test_no_evidence_score_breakdown_field(self):
        facts = self._make_facts()
        assert not hasattr(facts, "evidence_score_breakdown")

    def test_no_evidence_type_field(self):
        facts = self._make_facts()
        assert not hasattr(facts, "evidence_type")

    def test_no_explanation_field(self):
        facts = self._make_facts()
        assert not hasattr(facts, "explanation")

    def test_no_confidence_field(self):
        facts = self._make_facts()
        assert not hasattr(facts, "confidence")


# ---------------------------------------------------------------------------
# E: Empty trace
# ---------------------------------------------------------------------------

class TestExtractEvidenceEmpty:

    def test_empty_reconstruction_returns_empty_tuple(self):
        recon = build_trace_tree([])
        result = extract_evidence(_anomaly(), recon)
        assert result == ()

    def test_result_is_tuple(self):
        recon = build_trace_tree([])
        result = extract_evidence(_anomaly(), recon)
        assert isinstance(result, tuple)


# ---------------------------------------------------------------------------
# S: Single span
# ---------------------------------------------------------------------------

class TestExtractEvidenceSingleSpan:

    def test_single_root_produces_one_fact(self):
        spans = [_span("root")]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert len(result) == 1

    def test_section_a_raw_facts_copied(self):
        spans = [_span(
            "root",
            status_code="ERROR",
            service_name="my_svc",
            span_name="my_op",
            start_ms=10,
            duration_ms=200.0,
            agent_name="planner",
            agent_operation="plan",
            tool_name="search",
            tool_status="FAIL",
            error_type="RuntimeError",
            error_message="oops",
            retrieval_result_count=3,
            retrieval_top_relevance_score=0.8,
        )]
        fact = extract_evidence(_anomaly(), build_trace_tree(spans))[0]
        assert fact.span_id == "root"
        assert fact.status_code == "ERROR"
        assert fact.service_name == "my_svc"
        assert fact.span_name == "my_op"
        assert fact.duration_ms == 200.0
        assert fact.agent_name == "planner"
        assert fact.agent_operation == "plan"
        assert fact.tool_name == "search"
        assert fact.tool_status == "FAIL"
        assert fact.error_type == "RuntimeError"
        assert fact.error_message == "oops"
        assert fact.retrieval_result_count == 3
        assert fact.retrieval_top_relevance_score == 0.8

    def test_is_root_span_true_for_parentless_span(self):
        fact = extract_evidence(_anomaly(), build_trace_tree([_span("root")]))[0]
        assert fact.is_root_span is True

    def test_is_error_span_false_for_ok_status(self):
        fact = extract_evidence(_anomaly(), build_trace_tree([_span("root", status_code="OK")]))[0]
        assert fact.is_error_span is False

    def test_is_error_span_true_for_error_status(self):
        fact = extract_evidence(_anomaly(), build_trace_tree([_span("root", status_code="ERROR")]))[0]
        assert fact.is_error_span is True

    def test_is_direct_subject_false_when_no_subject(self):
        fact = extract_evidence(_anomaly(subject_span_id=None), build_trace_tree([_span("root")]))[0]
        assert fact.is_direct_subject is False

    def test_is_direct_subject_true_when_ids_match(self):
        fact = extract_evidence(_anomaly(subject_span_id="root"), build_trace_tree([_span("root")]))[0]
        assert fact.is_direct_subject is True

    def test_is_direct_subject_false_when_ids_differ(self):
        fact = extract_evidence(_anomaly(subject_span_id="other"), build_trace_tree([_span("root")]))[0]
        assert fact.is_direct_subject is False

    def test_trace_duration_fraction_is_one_for_sole_span(self):
        # Single span: trace_duration_ms == span's own window
        spans = [_span("root", start_ms=0, duration_ms=500.0)]
        fact = extract_evidence(_anomaly(), build_trace_tree(spans))[0]
        assert fact.trace_duration_fraction == pytest.approx(1.0)

    def test_depth_is_zero_for_root(self):
        fact = extract_evidence(_anomaly(), build_trace_tree([_span("root")]))[0]
        assert fact.depth == 0


# ---------------------------------------------------------------------------
# T: Multi-span tree
# ---------------------------------------------------------------------------

class TestExtractEvidenceTree:

    def _three_span_trace(self):
        """root(0→500ms) → child(0→300ms) → grandchild(100→200ms)"""
        spans = [
            _span("root",       start_ms=0,   duration_ms=500.0),
            _span("child",      "root",        start_ms=0,   duration_ms=300.0),
            _span("grandchild", "child",       start_ms=100, duration_ms=100.0),
        ]
        return spans

    def test_all_three_spans_included(self):
        spans = self._three_span_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert len(result) == 3
        assert set(_span_ids(result)) == {"root", "child", "grandchild"}

    def test_root_is_root_span(self):
        spans = self._three_span_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["root"].is_root_span is True

    def test_non_roots_not_is_root_span(self):
        spans = self._three_span_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["child"].is_root_span is False
        assert facts["grandchild"].is_root_span is False

    def test_depths_correct(self):
        spans = self._three_span_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["root"].depth == 0
        assert facts["child"].depth == 1
        assert facts["grandchild"].depth == 2

    def test_output_ordered_start_time_asc_span_id_asc(self):
        spans = self._three_span_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        # root start=0, child start=0, grandchild start=100
        # tie-break root vs child by span_id: "child" < "grandchild" < "root"
        assert result[0].span_id == "child"
        assert result[1].span_id == "root"
        assert result[2].span_id == "grandchild"

    def test_completeness_count_matches_span_count(self):
        spans = self._three_span_trace()
        recon = build_trace_tree(spans)
        result = extract_evidence(_anomaly(), recon)
        assert len(result) == recon.span_count

    def test_no_duplicate_span_ids(self):
        spans = self._three_span_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        ids = _span_ids(result)
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# O: Orphan handling
# ---------------------------------------------------------------------------

class TestExtractEvidenceOrphanRoot:

    def _orphan_trace(self):
        """orphan has parent 'missing' (not in span list); orphan_child is its child."""
        spans = [
            _span("root",         start_ms=0, duration_ms=500.0),
            _span("orphan",       "missing",  start_ms=0, duration_ms=200.0),
            _span("orphan_child", "orphan",   start_ms=50, duration_ms=100.0),
        ]
        return spans

    def test_orphan_is_not_root_span(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["orphan"].is_root_span is False

    def test_orphan_included_in_output(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert "orphan" in _span_ids(result)

    def test_orphan_child_included_in_output(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert "orphan_child" in _span_ids(result)

    def test_orphan_root_depth_is_zero(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["orphan"].depth == 0

    def test_orphan_child_depth_is_one(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["orphan_child"].depth == 1

    def test_all_spans_present(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert set(_span_ids(result)) == {"root", "orphan", "orphan_child"}

    def test_no_duplicates_with_orphan(self):
        spans = self._orphan_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        ids = _span_ids(result)
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# C: Cycle members
# ---------------------------------------------------------------------------

class TestExtractEvidenceCycles:

    def _cycle_trace(self):
        """Two-node cycle (a ↔ b) with no natural root."""
        return [
            _span("aaa", "bbb", start_ms=0, duration_ms=100.0),
            _span("bbb", "aaa", start_ms=0, duration_ms=100.0),
        ]

    def test_cycle_spans_included(self):
        spans = self._cycle_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert set(_span_ids(result)) == {"aaa", "bbb"}

    def test_no_duplicate_spans_in_cycle(self):
        spans = self._cycle_trace()
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        ids = _span_ids(result)
        assert len(ids) == len(set(ids))

    def test_span_count_matches_reconstruction(self):
        spans = self._cycle_trace()
        recon = build_trace_tree(spans)
        result = extract_evidence(_anomaly(), recon)
        assert len(result) == recon.span_count

    def test_cycle_with_natural_root_all_included(self):
        """Natural root + separate two-node cycle."""
        spans = [
            _span("root",  start_ms=0, duration_ms=500.0),
            _span("cycle_a", "cycle_b", start_ms=0, duration_ms=100.0),
            _span("cycle_b", "cycle_a", start_ms=0, duration_ms=100.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert set(_span_ids(result)) == {"root", "cycle_a", "cycle_b"}
        ids = _span_ids(result)
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# D: is_direct_subject semantics
# ---------------------------------------------------------------------------

class TestExtractEvidenceDirectSubject:

    def test_exactly_one_span_flagged_when_subject_in_trace(self):
        spans = [
            _span("root",  start_ms=0),
            _span("child", "root", start_ms=10),
        ]
        result = extract_evidence(_anomaly(subject_span_id="child"), build_trace_tree(spans))
        direct = [f for f in result if f.is_direct_subject]
        assert len(direct) == 1
        assert direct[0].span_id == "child"

    def test_no_span_flagged_when_subject_absent_from_trace(self):
        spans = [_span("root"), _span("child", "root", start_ms=10)]
        result = extract_evidence(_anomaly(subject_span_id="missing_span"), build_trace_tree(spans))
        assert all(not f.is_direct_subject for f in result)

    def test_no_span_flagged_when_anomaly_has_no_subject(self):
        spans = [_span("root"), _span("child", "root", start_ms=10)]
        result = extract_evidence(_anomaly(subject_span_id=None), build_trace_tree(spans))
        assert all(not f.is_direct_subject for f in result)

    def test_root_can_be_direct_subject(self):
        spans = [_span("root")]
        result = extract_evidence(_anomaly(subject_span_id="root"), build_trace_tree(spans))
        assert result[0].is_direct_subject is True


# ---------------------------------------------------------------------------
# F: trace_duration_fraction
# ---------------------------------------------------------------------------

class TestExtractEvidenceTraceDurationFraction:

    def test_fraction_equals_duration_over_trace_envelope(self):
        # root: 0→500ms; child: 0→200ms
        # trace_duration_ms = 500ms
        # child fraction = 200/500 = 0.4
        spans = [
            _span("root",  start_ms=0, duration_ms=500.0),
            _span("child", "root", start_ms=0, duration_ms=200.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["child"].trace_duration_fraction == pytest.approx(0.4)

    def test_fraction_uses_wall_clock_envelope_not_sum(self):
        # root: 0→500ms  child: 0→500ms  (concurrent siblings)
        # sum of durations = 1000ms, but wall-clock envelope = 500ms
        # both fractions = 500/500 = 1.0
        spans = [
            _span("root",  start_ms=0, duration_ms=500.0),
            _span("child", "root", start_ms=0, duration_ms=500.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        facts = {f.span_id: f for f in result}
        assert facts["root"].trace_duration_fraction == pytest.approx(1.0)
        assert facts["child"].trace_duration_fraction == pytest.approx(1.0)

    def test_concurrent_spans_sum_of_fractions_exceeds_one(self):
        # Verification E: overlapping spans → sum > 1.0
        # root: 0→500ms  child_a: 0→400ms  child_b: 100→500ms
        # trace_duration_ms = 500ms
        # root fraction = 1.0, child_a = 0.8, child_b = 0.8  → sum = 2.6
        spans = [
            _span("root",    start_ms=0,   duration_ms=500.0),
            _span("child_a", "root", start_ms=0,   duration_ms=400.0),
            _span("child_b", "root", start_ms=100, duration_ms=400.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        total = sum(f.trace_duration_fraction for f in result)  # type: ignore[misc]
        assert total > 1.0

    def test_malformed_duration_ms_preserved_not_clamped(self):
        # Verification F: if duration_ms > trace_duration_ms, fraction > 1.0
        # root: start=0, end=100ms (span envelope = 100ms)
        # child: start=0, end=100ms BUT duration_ms set to 200.0 (inconsistent)
        # trace_duration_ms = 100ms → fraction = 200/100 = 2.0
        root = SpanRecord(
            span_id="root",
            parent_span_id=None,
            span_name="op",
            service_name="svc",
            start_time=_dt(0),
            end_time=_dt(100),
            duration_ms=100.0,
            status_code="OK",
            trace_id=_TRACE_ID,
        )
        child = SpanRecord(
            span_id="child",
            parent_span_id="root",
            span_name="op",
            service_name="svc",
            start_time=_dt(0),
            end_time=_dt(100),
            duration_ms=200.0,   # malformed: exceeds envelope
            status_code="OK",
            trace_id=_TRACE_ID,
        )
        recon = build_trace_tree([root, child])
        assert recon.trace_duration_ms == pytest.approx(100.0)
        result = extract_evidence(_anomaly(), recon)
        facts = {f.span_id: f for f in result}
        assert facts["child"].trace_duration_fraction == pytest.approx(2.0)

    def test_zero_duration_trace_gives_none_fraction(self):
        # Verification G: trace_duration_ms = 0 → fraction = None
        # Build a zero-width trace: start == end for all spans
        root = SpanRecord(
            span_id="root",
            parent_span_id=None,
            span_name="op",
            service_name="svc",
            start_time=_dt(0),
            end_time=_dt(0),
            duration_ms=0.0,
            status_code="OK",
            trace_id=_TRACE_ID,
        )
        recon = build_trace_tree([root])
        assert recon.trace_duration_ms == pytest.approx(0.0)
        result = extract_evidence(_anomaly(), recon)
        assert result[0].trace_duration_fraction is None

    def test_all_spans_get_none_for_zero_duration_trace(self):
        root = SpanRecord(
            span_id="root",
            parent_span_id=None,
            span_name="op",
            service_name="svc",
            start_time=_dt(0),
            end_time=_dt(0),
            duration_ms=0.0,
            status_code="OK",
            trace_id=_TRACE_ID,
        )
        child = SpanRecord(
            span_id="child",
            parent_span_id="root",
            span_name="op",
            service_name="svc",
            start_time=_dt(0),
            end_time=_dt(0),
            duration_ms=0.0,
            status_code="OK",
            trace_id=_TRACE_ID,
        )
        recon = build_trace_tree([root, child])
        result = extract_evidence(_anomaly(), recon)
        assert all(f.trace_duration_fraction is None for f in result)


# ---------------------------------------------------------------------------
# R: Output ordering
# ---------------------------------------------------------------------------

class TestExtractEvidenceOrdering:

    def test_output_sorted_by_start_time_asc(self):
        spans = [
            _span("late",  start_ms=300, duration_ms=100.0),
            _span("early", start_ms=0,   duration_ms=100.0),
            _span("mid",   start_ms=100, duration_ms=100.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert _span_ids(result) == ["early", "mid", "late"]

    def test_tie_break_by_span_id_asc(self):
        # Two spans with the same start_time; "aaa" < "zzz"
        spans = [
            _span("zzz", start_ms=0, duration_ms=100.0),
            _span("aaa", start_ms=0, duration_ms=100.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert result[0].span_id == "aaa"
        assert result[1].span_id == "zzz"

    def test_mixed_topology_output_is_sorted(self):
        """Roots, orphans, and cycle members all sorted together."""
        spans = [
            _span("natural_root",  start_ms=500, duration_ms=100.0),
            _span("orphan",        "missing",    start_ms=200, duration_ms=100.0),
            _span("cycle_a",       "cycle_b",    start_ms=0,   duration_ms=100.0),
            _span("cycle_b",       "cycle_a",    start_ms=50,  duration_ms=100.0),
        ]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        times = [f.start_time for f in result]
        assert times == sorted(times), "Output is not sorted by start_time"

    def test_result_is_always_a_tuple(self):
        spans = [_span("root")]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert isinstance(result, tuple)

    def test_idempotent_on_repeated_calls(self):
        spans = [
            _span("root",  start_ms=0, duration_ms=500.0),
            _span("child", "root", start_ms=100, duration_ms=100.0),
        ]
        recon = build_trace_tree(spans)
        anomaly = _anomaly(subject_span_id="child")
        result1 = extract_evidence(anomaly, recon)
        result2 = extract_evidence(anomaly, recon)
        assert result1 == result2


# ---------------------------------------------------------------------------
# H: No Phase 11.4 scoring fields (structural guard)
# ---------------------------------------------------------------------------

class TestNoScoringFields:

    def test_unscoredspanfacts_fields_are_only_sections_a_and_b(self):
        field_names = {f.name for f in dataclasses.fields(UnscoredSpanFacts)}
        forbidden = {"evidence_score", "evidence_score_breakdown", "evidence_type",
                     "explanation", "confidence"}
        overlap = field_names & forbidden
        assert overlap == set(), f"Forbidden Phase 11.4 fields present: {overlap}"

    def test_extract_evidence_returns_only_unscored_facts(self):
        spans = [_span("root")]
        result = extract_evidence(_anomaly(), build_trace_tree(spans))
        assert all(isinstance(f, UnscoredSpanFacts) for f in result)

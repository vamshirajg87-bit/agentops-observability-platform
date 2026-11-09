"""
rca-analyzer/tests/unit/test_rca_models.py

Unit tests for rca_models.py.

All tests are pure Python — no database, no network, no I/O.

Test inventory:
    M01  SpanEvidence is frozen (immutable)
    M02  SpanEvidence optional fields accept None
    M03  SpanEvidence trace_duration_fraction accepts None
    M04  SpanEvidence tuple identity (two objects with same fields are equal)
    M05  RCAResult is frozen (immutable)
    M06  RCAResult all_evidence and top_contributors are tuples
    M07  RCAResult with zero evidence (INSUFFICIENT_DATA case)
    M08  RCAResult limitations is a tuple
    M09  SpanEvidence evidence_type strings (vocabulary smoke-test)
    M10  RCAResult confidence value smoke-test
    M11  RCAResult tuple immutability (cannot append to tuple fields)
    M12  SpanEvidence with is_direct_subject=True and is_root_span=False
    M13  SpanEvidence depth is non-negative int (structural, not a score input)
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from rca_models import RCAResult, SpanEvidence


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc)


def _evidence(
    span_id: str = "span0001",
    evidence_type: str = "background_span",
    evidence_score: float = 0.0,
    is_error_span: bool = False,
    is_direct_subject: bool = False,
    trace_duration_fraction: float | None = None,
    depth: int = 0,
) -> SpanEvidence:
    return SpanEvidence(
        span_id=span_id,
        parent_span_id=None,
        span_name="agentops.request",
        service_name="agentops-demo-app",
        start_time=_T0,
        end_time=_T1,
        duration_ms=1000.0,
        status_code="ERROR" if is_error_span else "OK",
        status_message=None,
        error_type="SomeError" if is_error_span else None,
        error_message=None,
        tool_name=None,
        tool_status=None,
        agent_name=None,
        agent_operation=None,
        retrieval_result_count=None,
        retrieval_top_relevance_score=None,
        is_root_span=(depth == 0 and not is_direct_subject),
        is_error_span=is_error_span,
        is_direct_subject=is_direct_subject,
        trace_duration_fraction=trace_duration_fraction,
        depth=depth,
        evidence_score=evidence_score,
        evidence_score_breakdown=f"score={evidence_score}",
        evidence_type=evidence_type,
        explanation="Test span.",
    )


def _rca_result(
    confidence: str = "INSUFFICIENT_DATA",
    all_evidence: tuple[SpanEvidence, ...] = (),
    top_contributors: tuple[SpanEvidence, ...] = (),
    limitations: tuple[str, ...] = ("no_trace_id",),
) -> RCAResult:
    return RCAResult(
        anomaly_id="a" * 64,
        anomaly_type="latency",
        signal_name="duration_ms",
        detector_name="LatencyDetector",
        detector_version="1.0",
        observed_value=1850.0,
        baseline_median=None,
        baseline_mad=None,
        baseline_n=None,
        anomaly_score=None,
        severity="WARNING",
        detector_explanation="Trace latency anomaly.",
        investigated_at=_T0,
        analyzer_version="1.0",
        investigation_id="b" * 64,
        trace_id=None,
        subject_span_id=None,
        service_name=None,
        operation_name=None,
        event_time=_T0,
        trace_span_count=0,
        all_evidence=all_evidence,
        top_contributors=top_contributors,
        confidence=confidence,
        summary="No trace data available.",
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# M01 — SpanEvidence is frozen
# ---------------------------------------------------------------------------

class TestSpanEvidenceFrozen:
    def test_cannot_set_attribute(self):
        ev = _evidence()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            ev.span_id = "changed"  # type: ignore[misc]

    def test_cannot_delete_attribute(self):
        ev = _evidence()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            del ev.span_id  # type: ignore[misc]

    def test_is_hashable(self):
        ev = _evidence()
        assert hash(ev) is not None
        assert isinstance(hash(ev), int)

    def test_can_be_used_in_set(self):
        ev1 = _evidence(span_id="span0001")
        ev2 = _evidence(span_id="span0002")
        s = {ev1, ev2}
        assert len(s) == 2


# ---------------------------------------------------------------------------
# M02 — SpanEvidence optional fields accept None
# ---------------------------------------------------------------------------

class TestSpanEvidenceOptionalFields:
    def test_all_optional_none(self):
        ev = _evidence()
        assert ev.parent_span_id is None
        assert ev.status_message is None
        assert ev.error_type is None
        assert ev.error_message is None
        assert ev.tool_name is None
        assert ev.tool_status is None
        assert ev.agent_name is None
        assert ev.agent_operation is None
        assert ev.retrieval_result_count is None
        assert ev.retrieval_top_relevance_score is None

    def test_populated_optional_fields(self):
        ev = SpanEvidence(
            span_id="span0001",
            parent_span_id="parent0",
            span_name="tool.execute",
            service_name="svc",
            start_time=_T0,
            end_time=_T1,
            duration_ms=500.0,
            status_code="OK",
            status_message="ok",
            error_type=None,
            error_message=None,
            tool_name="calculator",
            tool_status="SUCCESS",
            agent_name="tool_agent",
            agent_operation="execute",
            retrieval_result_count=5,
            retrieval_top_relevance_score=0.82,
            is_root_span=False,
            is_error_span=False,
            is_direct_subject=True,
            trace_duration_fraction=0.30,
            depth=1,
            evidence_score=0.40,
            evidence_score_breakdown="direct_subject=0.40 → 0.40",
            evidence_type="direct_subject",
            explanation="The named anomalous span.",
        )
        assert ev.tool_name == "calculator"
        assert ev.retrieval_result_count == 5
        assert ev.retrieval_top_relevance_score == 0.82


# ---------------------------------------------------------------------------
# M03 — trace_duration_fraction accepts None
# ---------------------------------------------------------------------------

class TestTraceDurationFractionNone:
    def test_none_fraction(self):
        ev = _evidence(trace_duration_fraction=None)
        assert ev.trace_duration_fraction is None

    def test_zero_fraction(self):
        ev = _evidence(trace_duration_fraction=0.0)
        assert ev.trace_duration_fraction == 0.0

    def test_fraction_above_one_accepted(self):
        # Fractions > 1.0 are not produced by concurrency (concurrent spans share
        # the same wall-clock envelope, so no individual fraction exceeds 1.0).
        # They can arise from inconsistent span timestamps (clock skew, rounding,
        # export bugs).  The model preserves them rather than clamping so the RCA
        # layer can still analyze and flag the anomaly.
        ev = _evidence(trace_duration_fraction=1.2)
        assert ev.trace_duration_fraction == 1.2


# ---------------------------------------------------------------------------
# M04 — SpanEvidence equality (value semantics)
# ---------------------------------------------------------------------------

class TestSpanEvidenceEquality:
    def test_equal_instances(self):
        ev1 = _evidence(span_id="span0001")
        ev2 = _evidence(span_id="span0001")
        assert ev1 == ev2

    def test_different_span_id_not_equal(self):
        ev1 = _evidence(span_id="span0001")
        ev2 = _evidence(span_id="span0002")
        assert ev1 != ev2

    def test_different_score_not_equal(self):
        ev1 = _evidence(evidence_score=0.5)
        ev2 = _evidence(evidence_score=0.9)
        assert ev1 != ev2


# ---------------------------------------------------------------------------
# M05 — RCAResult is frozen
# ---------------------------------------------------------------------------

class TestRCAResultFrozen:
    def test_cannot_set_attribute(self):
        result = _rca_result()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            result.confidence = "HIGH"  # type: ignore[misc]

    def test_cannot_delete_attribute(self):
        result = _rca_result()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            del result.anomaly_id  # type: ignore[misc]

    def test_is_hashable(self):
        result = _rca_result()
        assert isinstance(hash(result), int)


# ---------------------------------------------------------------------------
# M06 — all_evidence and top_contributors are tuples
# ---------------------------------------------------------------------------

class TestRCAResultTupleFields:
    def test_all_evidence_is_tuple(self):
        ev = _evidence()
        result = _rca_result(all_evidence=(ev,), top_contributors=(ev,))
        assert isinstance(result.all_evidence, tuple)
        assert isinstance(result.top_contributors, tuple)

    def test_all_evidence_empty_tuple(self):
        result = _rca_result()
        assert result.all_evidence == ()
        assert isinstance(result.all_evidence, tuple)

    def test_all_evidence_multiple_entries(self):
        ev1 = _evidence(span_id="span0001", evidence_score=0.88)
        ev2 = _evidence(span_id="span0002", evidence_score=0.04)
        result = _rca_result(
            all_evidence=(ev1, ev2),
            top_contributors=(ev1,),
            confidence="HIGH",
        )
        assert len(result.all_evidence) == 2
        assert result.all_evidence[0].span_id == "span0001"
        assert len(result.top_contributors) == 1


# ---------------------------------------------------------------------------
# M07 — RCAResult with zero evidence (INSUFFICIENT_DATA)
# ---------------------------------------------------------------------------

class TestInsufficientData:
    def test_insufficient_data_construction(self):
        result = _rca_result(
            confidence="INSUFFICIENT_DATA",
            all_evidence=(),
            top_contributors=(),
            limitations=("no_trace_id",),
        )
        assert result.confidence == "INSUFFICIENT_DATA"
        assert result.trace_span_count == 0
        assert result.all_evidence == ()
        assert result.top_contributors == ()
        assert "no_trace_id" in result.limitations

    def test_trace_id_is_none(self):
        result = _rca_result()
        assert result.trace_id is None

    def test_subject_span_id_is_none(self):
        result = _rca_result()
        assert result.subject_span_id is None


# ---------------------------------------------------------------------------
# M08 — limitations is a tuple
# ---------------------------------------------------------------------------

class TestLimitationsTuple:
    def test_limitations_is_tuple(self):
        result = _rca_result(limitations=("trace_not_found", "no_error_spans"))
        assert isinstance(result.limitations, tuple)
        assert len(result.limitations) == 2

    def test_empty_limitations(self):
        result = _rca_result(limitations=())
        assert result.limitations == ()

    def test_known_limitation_codes(self):
        known = {
            "no_trace_id",
            "trace_not_found",
            "partial_trace",
            "no_error_spans",
            "no_dominant_latency",
            "single_span_trace",
            "tool_name_absent",
            "direct_subject_absent",
        }
        for code in known:
            result = _rca_result(limitations=(code,))
            assert result.limitations == (code,)


# ---------------------------------------------------------------------------
# M09 — evidence_type vocabulary smoke-test
# ---------------------------------------------------------------------------

class TestEvidenceTypeVocabulary:
    VALID_TYPES = [
        "dominant_duration_and_error",
        "dominant_duration",
        "correlated_error",
        "direct_subject",
        "direct_subject_and_error",
        "retrieval_quality_signal",
        "background_span",
    ]

    def test_all_valid_types_constructable(self):
        for ev_type in self.VALID_TYPES:
            ev = _evidence(evidence_type=ev_type)
            assert ev.evidence_type == ev_type


# ---------------------------------------------------------------------------
# M10 — RCAResult confidence values smoke-test
# ---------------------------------------------------------------------------

class TestConfidenceValues:
    VALID_CONFIDENCE = ["HIGH", "MEDIUM", "LOW", "INSUFFICIENT_DATA"]

    def test_all_confidence_values_constructable(self):
        for conf in self.VALID_CONFIDENCE:
            result = _rca_result(confidence=conf)
            assert result.confidence == conf


# ---------------------------------------------------------------------------
# M11 — tuple fields are immutable (cannot append)
# ---------------------------------------------------------------------------

class TestTupleImmutability:
    def test_cannot_append_to_all_evidence(self):
        ev = _evidence()
        result = _rca_result(all_evidence=(ev,))
        with pytest.raises(AttributeError):
            result.all_evidence.append(ev)  # type: ignore[attr-defined]

    def test_cannot_append_to_limitations(self):
        result = _rca_result(limitations=("no_trace_id",))
        with pytest.raises(AttributeError):
            result.limitations.append("another")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# M12 — SpanEvidence with is_direct_subject=True
# ---------------------------------------------------------------------------

class TestDirectSubjectEvidence:
    def test_direct_subject_flag(self):
        ev = _evidence(
            span_id="tool0001",
            is_direct_subject=True,
            depth=1,
            evidence_type="direct_subject_and_error",
            evidence_score=0.70,
        )
        assert ev.is_direct_subject is True
        assert ev.is_root_span is False
        assert ev.depth == 1

    def test_root_and_direct_subject_can_coexist(self):
        ev = SpanEvidence(
            span_id="root0001",
            parent_span_id=None,
            span_name="agentops.request",
            service_name="svc",
            start_time=_T0,
            end_time=_T1,
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
            is_direct_subject=True,
            trace_duration_fraction=1.0,
            depth=0,
            evidence_score=0.40,
            evidence_score_breakdown="direct_subject=0.40 → 0.40",
            evidence_type="direct_subject",
            explanation="Root is the direct subject.",
        )
        assert ev.is_root_span is True
        assert ev.is_direct_subject is True


# ---------------------------------------------------------------------------
# M13 — depth is non-negative int (structural context only)
# ---------------------------------------------------------------------------

class TestDepthField:
    def test_depth_zero_for_root(self):
        ev = _evidence(depth=0)
        assert ev.depth == 0

    def test_depth_positive_for_child(self):
        ev = _evidence(depth=1)
        assert ev.depth == 1

    def test_depth_deep_value(self):
        ev = _evidence(depth=5)
        assert ev.depth == 5

    def test_depth_is_int(self):
        ev = _evidence(depth=2)
        assert isinstance(ev.depth, int)

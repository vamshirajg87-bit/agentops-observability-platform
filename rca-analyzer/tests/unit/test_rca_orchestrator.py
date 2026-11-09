"""
tests/unit/test_rca_orchestrator.py

Unit tests for rca_orchestrator — Phase 11.6.

Coverage:
    AnomalyNotFoundError        — exception class, str, attribute
    SourceDataIntegrityError    — class, wraps ValueError, chains
    _build_summary              — all confidence paths, language rules
    _derive_limitations         — all 7 limitation codes, boundary conditions
    run_investigation           — full happy paths, INSUFFICIENT_DATA x 3,
                                  error paths, call order, connection ownership
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest
import psycopg

from rca_orchestrator import (
    AnomalyNotFoundError,
    SourceDataIntegrityError,
    _build_summary,
    _derive_limitations,
    run_investigation,
)
from rca_confidence import SPAN_SPECIFIC_SIGNALS, signal_threshold
from rca_models import RCAResult, SpanEvidence
from rca_persist import PersistenceResult, compute_investigation_id
from rca_source import RcaAnomalyRecord
from rca_trace import SpanRecord, TraceNode, TraceReconstruction
from rca_version import RCA_ANALYZER_VERSION


# ---------------------------------------------------------------------------
# Shared factories
# ---------------------------------------------------------------------------

_T0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_anomaly(
    anomaly_id: str = "anom-1",
    anomaly_type: str = "latency",
    operation_name: Optional[str] = "trace",
    trace_id: Optional[str] = "trace-1",
    subject_span_id: Optional[str] = None,
    severity: str = "WARNING",
) -> RcaAnomalyRecord:
    return RcaAnomalyRecord(
        anomaly_id=anomaly_id,
        anomaly_type=anomaly_type,
        signal_name="duration_ms",
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
        severity=severity,
        detector_explanation="test anomaly",
    )


def _make_span_rec(
    span_id: str,
    parent_span_id: Optional[str],
    duration_ms: float = 100.0,
) -> SpanRecord:
    t = _T0
    return SpanRecord(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_id,
        service_name="svc",
        start_time=t,
        end_time=t + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        status_code="OK",
        trace_id="trace-1",
    )


def _make_reconstruction(
    span_count: int = 2,
    orphan_count: int = 0,
    n_roots: int = 1,
    has_cycle: bool = False,
    trace_duration_ms: float = 200.0,
) -> TraceReconstruction:
    roots = [
        TraceNode(span=_make_span_rec(f"root-{i}", None), children=[], depth=0)
        for i in range(n_roots)
    ]
    orphans = [
        TraceNode(span=_make_span_rec(f"orph-{i}", "absent"), children=[], depth=0)
        for i in range(orphan_count)
    ]
    return TraceReconstruction(
        roots=roots,
        orphans=orphans,
        cycle_members=[],
        has_cycle=has_cycle,
        span_count=span_count,
        trace_duration_ms=trace_duration_ms,
    )


def _make_span_evidence(
    span_id: str = "s1",
    evidence_score: float = 0.80,
    is_direct_subject: bool = False,
    is_error_span: bool = False,
    tool_name: Optional[str] = None,
    span_name: str = "test-span",
    service_name: str = "test-svc",
) -> SpanEvidence:
    return SpanEvidence(
        span_id=span_id,
        parent_span_id=None,
        span_name=span_name,
        service_name=service_name,
        start_time=_T0,
        end_time=_T0 + timedelta(milliseconds=100),
        duration_ms=100.0,
        status_code="ERROR" if is_error_span else "OK",
        status_message=None,
        error_type=None,
        error_message=None,
        tool_name=tool_name,
        tool_status=None,
        agent_name=None,
        agent_operation=None,
        retrieval_result_count=None,
        retrieval_top_relevance_score=None,
        is_root_span=False,
        is_error_span=is_error_span,
        is_direct_subject=is_direct_subject,
        trace_duration_fraction=0.50,
        depth=1,
        evidence_score=evidence_score,
        evidence_score_breakdown="duration=0.500",
        evidence_type="dominant_duration",
        explanation="Span occupied 50.0% of the trace wall-clock envelope",
    )


def _make_persistence_result(
    investigation_id: str = "a" * 64,
    investigation_inserted: bool = True,
    evidence_rows_inserted: int = 2,
) -> PersistenceResult:
    return PersistenceResult(
        investigation_id=investigation_id,
        investigation_inserted=investigation_inserted,
        evidence_rows_inserted=evidence_rows_inserted,
    )


# ---------------------------------------------------------------------------
# TestAnomalyNotFoundError
# ---------------------------------------------------------------------------

class TestAnomalyNotFoundError:
    def test_is_value_error_subclass(self):
        assert issubclass(AnomalyNotFoundError, ValueError)

    def test_str_contains_anomaly_id(self):
        err = AnomalyNotFoundError("my-anom-id")
        assert "my-anom-id" in str(err)

    def test_anomaly_id_attribute(self):
        err = AnomalyNotFoundError("some-uuid")
        assert err.anomaly_id == "some-uuid"


# ---------------------------------------------------------------------------
# TestSourceDataIntegrityError
# ---------------------------------------------------------------------------

class TestSourceDataIntegrityError:
    def test_is_value_error_subclass(self):
        assert issubclass(SourceDataIntegrityError, ValueError)

    def test_str_preserved(self):
        err = SourceDataIntegrityError("bad anomaly_type 'unknown'")
        assert "bad anomaly_type" in str(err)

    def test_exception_chaining(self):
        original = ValueError("domain validation failed")
        try:
            raise SourceDataIntegrityError("wrapped") from original
        except SourceDataIntegrityError as exc:
            assert exc.__cause__ is original


# ---------------------------------------------------------------------------
# TestBuildSummary
# ---------------------------------------------------------------------------

class TestBuildSummary:
    def test_insufficient_data_no_trace_id(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _make_reconstruction(span_count=0, n_roots=0)
        s = _build_summary("INSUFFICIENT_DATA", anomaly, recon, ())
        assert "no trace ID" in s
        assert s.startswith("Insufficient telemetry was available for evidence analysis:")

    def test_insufficient_data_zero_spans(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=0, n_roots=0)
        s = _build_summary("INSUFFICIENT_DATA", anomaly, recon, ())
        assert "no spans" in s
        assert s.startswith("Insufficient telemetry was available for evidence analysis:")

    def test_insufficient_data_one_span(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=1)
        s = _build_summary("INSUFFICIENT_DATA", anomaly, recon, ())
        assert "only one span" in s
        assert s.startswith("Insufficient telemetry was available for evidence analysis:")

    def test_low_contains_anomaly_type(self):
        anomaly = _make_anomaly(anomaly_type="error_rate")
        recon = _make_reconstruction()
        s = _build_summary("LOW", anomaly, recon, ())
        assert "error_rate" in s

    def test_low_no_strong_signal(self):
        anomaly = _make_anomaly()
        recon = _make_reconstruction()
        s = _build_summary("LOW", anomaly, recon, ())
        assert "no strong contributing signal" in s

    def test_medium_uses_top_span(self):
        anomaly = _make_anomaly()
        recon = _make_reconstruction()
        top = _make_span_evidence("s1", 0.75, span_name="agent-plan", service_name="planner")
        other = _make_span_evidence("s2", 0.10)
        ev = (top, other)
        s = _build_summary("MEDIUM", anomaly, recon, ev)
        assert "agent-plan" in s
        assert "planner" in s
        assert "0.75" in s

    def test_high_uses_top_span(self):
        anomaly = _make_anomaly()
        recon = _make_reconstruction()
        top = _make_span_evidence("s1", 0.88, span_name="tool-exec", service_name="tools")
        ev = (top, _make_span_evidence("s2", 0.02))
        s = _build_summary("HIGH", anomaly, recon, ev)
        assert "tool-exec" in s
        assert "tools" in s
        assert "0.88" in s

    def test_no_root_cause_language_any_confidence(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _make_reconstruction(span_count=0, n_roots=0)
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        cases = [
            ("INSUFFICIENT_DATA", anomaly, recon, ()),
            ("LOW", anomaly, recon, ()),
            ("MEDIUM", anomaly, recon, ev),
            ("HIGH", anomaly, recon, ev),
        ]
        banned = ["root cause", "caused by", "responsible for",
                  "investigation could not proceed"]
        for confidence, a, r, e in cases:
            s = _build_summary(confidence, a, r, e)
            for phrase in banned:
                assert phrase not in s.lower(), (
                    f"Banned phrase {phrase!r} found in {confidence} summary: {s!r}"
                )

    def test_medium_high_include_explanation(self):
        anomaly = _make_anomaly()
        recon = _make_reconstruction()
        top = _make_span_evidence("s1", 0.88)
        ev = (top, _make_span_evidence("s2", 0.02))
        for confidence in ("MEDIUM", "HIGH"):
            s = _build_summary(confidence, anomaly, recon, ev)
            assert top.explanation in s


# ---------------------------------------------------------------------------
# TestDeriveLimitations
# ---------------------------------------------------------------------------

class TestDeriveLimitations:
    def _no_evidence(self):
        return ()

    def test_no_trace_id(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _make_reconstruction(span_count=0, n_roots=0)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "INSUFFICIENT_DATA")
        assert "no_trace_id" in codes

    def test_trace_not_found(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=0, n_roots=0)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "INSUFFICIENT_DATA")
        assert "trace_not_found" in codes
        assert "no_trace_id" not in codes

    def test_single_span_trace(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=1)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "INSUFFICIENT_DATA")
        assert "single_span_trace" in codes

    def test_partial_trace_zero_fraction(self):
        # 0 orphans, span_count=2 → fraction = 0.0 → no partial_trace
        anomaly = _make_anomaly()
        recon = _make_reconstruction(span_count=2, orphan_count=0)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "HIGH")
        assert "partial_trace" not in codes

    def test_partial_trace_below_threshold(self):
        # 1 orphan, span_count=11 → fraction = 1/11 ≈ 0.0909 < 0.10 → no partial_trace
        anomaly = _make_anomaly()
        recon = _make_reconstruction(span_count=11, orphan_count=1)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "HIGH")
        assert "partial_trace" not in codes

    def test_partial_trace_exactly_threshold(self):
        # 1 orphan, span_count=10 → fraction = 1/10 = 0.10 → partial_trace (inclusive)
        anomaly = _make_anomaly()
        recon = _make_reconstruction(span_count=10, orphan_count=1)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "HIGH")
        assert "partial_trace" in codes

    def test_partial_trace_at_050(self):
        # 1 orphan, span_count=2 → fraction = 0.50 → partial_trace
        anomaly = _make_anomaly()
        recon = _make_reconstruction(span_count=2, orphan_count=1)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "HIGH")
        assert "partial_trace" in codes

    def test_partial_trace_above_050(self):
        # 2 orphans, span_count=3 → fraction = 2/3 ≈ 0.667 → partial_trace
        anomaly = _make_anomaly()
        recon = _make_reconstruction(span_count=3, orphan_count=2)
        codes = _derive_limitations(anomaly, recon, (), "trace_latency", "HIGH")
        assert "partial_trace" in codes

    def test_no_error_spans_for_error_rate(self):
        anomaly = _make_anomaly(anomaly_type="error_rate")
        recon = _make_reconstruction()
        ev = (
            _make_span_evidence("s1", is_error_span=False),
            _make_span_evidence("s2", is_error_span=False),
        )
        codes = _derive_limitations(anomaly, recon, ev, "error_rate", "LOW")
        assert "no_error_spans" in codes

    def test_no_error_spans_for_tool_failure(self):
        anomaly = _make_anomaly(anomaly_type="tool_failure")
        recon = _make_reconstruction()
        ev = (
            _make_span_evidence("s1", is_error_span=False),
            _make_span_evidence("s2", is_error_span=False),
        )
        codes = _derive_limitations(anomaly, recon, ev, "tool_failure", "LOW")
        assert "no_error_spans" in codes

    def test_direct_subject_absent(self):
        anomaly = _make_anomaly(anomaly_type="error_rate")
        recon = _make_reconstruction()
        ev = (
            _make_span_evidence("s1", is_direct_subject=False),
            _make_span_evidence("s2", is_direct_subject=False),
        )
        codes = _derive_limitations(anomaly, recon, ev, "error_rate", "LOW")
        assert "direct_subject_absent" in codes

    def test_tool_name_absent(self):
        anomaly = _make_anomaly(anomaly_type="tool_failure")
        recon = _make_reconstruction()
        ev = (
            # direct subject with no tool_name — known telemetry gap
            _make_span_evidence("s1", is_direct_subject=True, tool_name=None),
            _make_span_evidence("s2"),
        )
        codes = _derive_limitations(anomaly, recon, ev, "tool_failure", "MEDIUM")
        assert "tool_name_absent" in codes

    def test_evidence_limitations_skipped_when_insufficient_data(self):
        # confidence == INSUFFICIENT_DATA → no evidence-based limitations
        anomaly = _make_anomaly(anomaly_type="error_rate")
        recon = _make_reconstruction(span_count=1)
        ev = (_make_span_evidence("s1", is_error_span=False, is_direct_subject=False),)
        codes = _derive_limitations(anomaly, recon, ev, "error_rate", "INSUFFICIENT_DATA")
        assert "no_error_spans" not in codes
        assert "direct_subject_absent" not in codes

    def test_no_no_dominant_latency_ever(self):
        # This code was explicitly omitted — must never appear
        for confidence in ("HIGH", "MEDIUM", "LOW", "INSUFFICIENT_DATA"):
            anomaly = _make_anomaly(anomaly_type="latency", operation_name="trace")
            recon = _make_reconstruction()
            ev = (_make_span_evidence("s1"), _make_span_evidence("s2", 0.10))
            codes = _derive_limitations(anomaly, recon, ev, "trace_latency", confidence)
            assert "no_dominant_latency" not in codes


# ---------------------------------------------------------------------------
# TestTopContributors (integration through run_investigation)
# ---------------------------------------------------------------------------

class TestTopContributors:
    """Verify top_contributors threshold and ordering via run_investigation mocks."""

    def _run_with_confidence_and_evidence(self, confidence, evidence):
        anomaly = _make_anomaly()
        recon = _make_reconstruction()
        pr = _make_persistence_result()
        conn = MagicMock(spec=psycopg.Connection)

        mock_persist = MagicMock(return_value=pr)

        with patch.multiple(
            "rca_orchestrator",
            fetch_anomaly=MagicMock(return_value=anomaly),
            fetch_spans=MagicMock(return_value=[]),
            build_trace_tree=MagicMock(return_value=recon),
            extract_evidence=MagicMock(return_value=()),
            score_and_rank=MagicMock(return_value=evidence),
            assess_confidence=MagicMock(return_value=confidence),
            persist_investigation=mock_persist,
        ):
            result, _ = run_investigation(conn, "anom-1")
        return result

    def test_above_threshold_included(self):
        # trace_latency threshold = 0.50; evidence_score 0.80 > 0.50
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        result = self._run_with_confidence_and_evidence("HIGH", ev)
        assert any(e.span_id == "s1" for e in result.top_contributors)

    def test_exactly_threshold_included(self):
        # evidence_score == 0.50 == threshold → included (inclusive >=)
        ev = (_make_span_evidence("s1", 0.50), _make_span_evidence("s2", 0.10))
        result = self._run_with_confidence_and_evidence("HIGH", ev)
        assert any(e.span_id == "s1" for e in result.top_contributors)

    def test_below_threshold_excluded(self):
        # s2 score 0.10 < 0.50 threshold → not in top_contributors
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        result = self._run_with_confidence_and_evidence("HIGH", ev)
        assert not any(e.span_id == "s2" for e in result.top_contributors)

    def test_order_preserved(self):
        ev = (
            _make_span_evidence("s1", 0.90),
            _make_span_evidence("s2", 0.70),
            _make_span_evidence("s3", 0.51),
            _make_span_evidence("s4", 0.10),
        )
        result = self._run_with_confidence_and_evidence("HIGH", ev)
        ids = [e.span_id for e in result.top_contributors]
        assert ids == ["s1", "s2", "s3"]


# ---------------------------------------------------------------------------
# TestRunInvestigation
# ---------------------------------------------------------------------------

class TestRunInvestigation:
    def _standard_patches(self, anomaly, confidence, evidence, recon=None, pr=None):
        """Return a dict of mock objects for patch.multiple."""
        if recon is None:
            recon = _make_reconstruction()
        if pr is None:
            pr = _make_persistence_result()
        return {
            "fetch_anomaly": MagicMock(return_value=anomaly),
            "fetch_spans": MagicMock(return_value=[]),
            "build_trace_tree": MagicMock(return_value=recon),
            "extract_evidence": MagicMock(return_value=()),
            "score_and_rank": MagicMock(return_value=evidence),
            "assess_confidence": MagicMock(return_value=confidence),
            "persist_investigation": MagicMock(return_value=pr),
        }

    def test_anomaly_not_found(self):
        conn = MagicMock(spec=psycopg.Connection)
        with patch.multiple(
            "rca_orchestrator",
            fetch_anomaly=MagicMock(return_value=None),
        ):
            with pytest.raises(AnomalyNotFoundError) as exc_info:
                run_investigation(conn, "missing-id")
        assert exc_info.value.anomaly_id == "missing-id"

    def test_source_data_integrity_error(self):
        conn = MagicMock(spec=psycopg.Connection)
        original = ValueError("unrecognised anomaly_type 'bogus'")
        with patch.multiple(
            "rca_orchestrator",
            fetch_anomaly=MagicMock(side_effect=original),
        ):
            with pytest.raises(SourceDataIntegrityError) as exc_info:
                run_investigation(conn, "anom-1")
        assert exc_info.value.__cause__ is original

    def test_high_confidence_result(self):
        anomaly = _make_anomaly()
        ev = (_make_span_evidence("s1", 0.88), _make_span_evidence("s2", 0.04))
        pr = _make_persistence_result()
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "HIGH", ev, pr=pr)
        with patch.multiple("rca_orchestrator", **patches):
            result, result_pr = run_investigation(conn, "anom-1")

        assert result.confidence == "HIGH"
        assert len(result.all_evidence) == 2
        assert result_pr is pr

    def test_low_confidence_empty_top_contributors(self):
        anomaly = _make_anomaly()
        ev = (_make_span_evidence("s1", 0.30), _make_span_evidence("s2", 0.10))
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "LOW", ev)
        with patch.multiple("rca_orchestrator", **patches):
            result, _ = run_investigation(conn, "anom-1")

        assert result.confidence == "LOW"
        # score 0.30 < 0.50 threshold for trace_latency → no top contributors
        assert result.top_contributors == ()

    def test_insufficient_data_no_trace_id(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _make_reconstruction(span_count=0, n_roots=0)
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", (), recon=recon)
        with patch.multiple("rca_orchestrator", **patches):
            result, _ = run_investigation(conn, "anom-1")

        assert result.confidence == "INSUFFICIENT_DATA"
        assert result.all_evidence == ()
        assert result.top_contributors == ()

    def test_insufficient_data_zero_spans(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=0, n_roots=0)
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", (), recon=recon)
        with patch.multiple("rca_orchestrator", **patches):
            result, _ = run_investigation(conn, "anom-1")

        assert result.all_evidence == ()
        assert result.top_contributors == ()
        assert "no spans" in result.summary

    def test_insufficient_data_one_span(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=1)
        single_ev = (_make_span_evidence("s1", 0.90),)
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", single_ev, recon=recon)
        with patch.multiple("rca_orchestrator", **patches):
            result, _ = run_investigation(conn, "anom-1")

        assert result.all_evidence == ()
        assert result.top_contributors == ()
        assert "only one span" in result.summary

    def test_assess_confidence_always_called_trace_id_none(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _make_reconstruction(span_count=0, n_roots=0)
        mock_assess = MagicMock(return_value="INSUFFICIENT_DATA")
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", (), recon=recon)
        patches["assess_confidence"] = mock_assess
        with patch.multiple("rca_orchestrator", **patches):
            run_investigation(conn, "anom-1")

        mock_assess.assert_called_once()

    def test_assess_confidence_always_called_zero_spans(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=0, n_roots=0)
        mock_assess = MagicMock(return_value="INSUFFICIENT_DATA")
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", (), recon=recon)
        patches["assess_confidence"] = mock_assess
        with patch.multiple("rca_orchestrator", **patches):
            run_investigation(conn, "anom-1")

        mock_assess.assert_called_once()

    def test_assess_confidence_always_called_one_span(self):
        anomaly = _make_anomaly(trace_id="trace-1")
        recon = _make_reconstruction(span_count=1)
        mock_assess = MagicMock(return_value="INSUFFICIENT_DATA")
        conn = MagicMock(spec=psycopg.Connection)

        single_ev = (_make_span_evidence("s1", 0.90),)
        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", single_ev, recon=recon)
        patches["assess_confidence"] = mock_assess
        with patch.multiple("rca_orchestrator", **patches):
            run_investigation(conn, "anom-1")

        mock_assess.assert_called_once()

    def test_fetch_spans_not_called_when_no_trace_id(self):
        anomaly = _make_anomaly(trace_id=None)
        recon = _make_reconstruction(span_count=0, n_roots=0)
        mock_fetch_spans = MagicMock(return_value=[])
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "INSUFFICIENT_DATA", (), recon=recon)
        patches["fetch_spans"] = mock_fetch_spans
        with patch.multiple("rca_orchestrator", **patches):
            run_investigation(conn, "anom-1")

        mock_fetch_spans.assert_not_called()

    def test_persist_called_exactly_once(self):
        anomaly = _make_anomaly()
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        mock_persist = MagicMock(return_value=_make_persistence_result())
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "HIGH", ev)
        patches["persist_investigation"] = mock_persist
        with patch.multiple("rca_orchestrator", **patches):
            run_investigation(conn, "anom-1")

        mock_persist.assert_called_once()

    def test_correct_investigation_id_passed_to_persist(self):
        anomaly = _make_anomaly(anomaly_id="anom-99")
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        expected_id = compute_investigation_id("anom-99", RCA_ANALYZER_VERSION)
        mock_persist = MagicMock(return_value=_make_persistence_result(
            investigation_id=expected_id,
        ))
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "HIGH", ev)
        patches["persist_investigation"] = mock_persist
        with patch.multiple("rca_orchestrator", **patches):
            result, _ = run_investigation(conn, "anom-99")

        called_result = mock_persist.call_args[0][1]
        assert called_result.investigation_id == expected_id
        assert called_result.analyzer_version == RCA_ANALYZER_VERSION
        assert called_result.anomaly_id == "anom-99"

    def test_connection_not_closed_by_orchestrator(self):
        anomaly = _make_anomaly()
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "HIGH", ev)
        with patch.multiple("rca_orchestrator", **patches):
            run_investigation(conn, "anom-1")

        conn.close.assert_not_called()

    def test_connection_not_closed_on_not_found(self):
        conn = MagicMock(spec=psycopg.Connection)
        with patch.multiple(
            "rca_orchestrator",
            fetch_anomaly=MagicMock(return_value=None),
        ):
            with pytest.raises(AnomalyNotFoundError):
                run_investigation(conn, "missing")

        conn.close.assert_not_called()

    def test_result_anomaly_fields_copied(self):
        anomaly = _make_anomaly(anomaly_id="anom-42", anomaly_type="error_rate",
                                operation_name="op", trace_id="trace-x",
                                severity="CRITICAL")
        ev = (_make_span_evidence("s1", 0.80), _make_span_evidence("s2", 0.10))
        recon = _make_reconstruction(span_count=2)
        conn = MagicMock(spec=psycopg.Connection)

        patches = self._standard_patches(anomaly, "HIGH", ev, recon=recon)
        with patch.multiple("rca_orchestrator", **patches):
            result, _ = run_investigation(conn, "anom-42")

        assert result.anomaly_id == "anom-42"
        assert result.anomaly_type == "error_rate"
        assert result.operation_name == "op"
        assert result.trace_id == "trace-x"
        assert result.severity == "CRITICAL"
        assert result.trace_span_count == 2

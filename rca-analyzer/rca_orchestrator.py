"""
rca-analyzer/rca_orchestrator.py

Phase 11.6: RCA investigation orchestration.

Drives the full RCA pipeline for a single anomaly:
  fetch anomaly → fetch spans → reconstruct trace → extract evidence →
  score & rank → assess confidence → derive signal → build result →
  persist → return

The caller supplies an open psycopg.Connection; the orchestrator never
opens or closes it.  Connection lifecycle is the caller's responsibility.

Transaction ownership belongs to persist_investigation() (in rca_persist).

Public API:
    AnomalyNotFoundError       — anomaly_id not in public.anomaly_events
    SourceDataIntegrityError   — anomaly row failed domain validation
    run_investigation()        — execute the full pipeline for one anomaly_id
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import psycopg

from rca_confidence import (
    assess_confidence,
    derive_signal,
    orphan_fraction,
    signal_threshold,
    SPAN_SPECIFIC_SIGNALS,
)
from rca_evidence import extract_evidence
from rca_models import RCAResult, SpanEvidence
from rca_persist import PersistenceResult, compute_investigation_id, persist_investigation
from rca_ranker import score_and_rank
from rca_source import RcaAnomalyRecord, fetch_anomaly, fetch_spans
from rca_trace import SpanRecord, TraceReconstruction, build_trace_tree
from rca_version import RCA_ANALYZER_VERSION


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class AnomalyNotFoundError(ValueError):
    """Raised when the requested anomaly_id does not exist in the database."""

    def __init__(self, anomaly_id: str) -> None:
        super().__init__(f"Anomaly not found: {anomaly_id!r}")
        self.anomaly_id = anomaly_id


class SourceDataIntegrityError(ValueError):
    """Raised when a fetched anomaly row fails domain validation in rca_source."""


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _build_summary(
    confidence: str,
    anomaly: RcaAnomalyRecord,
    reconstruction: TraceReconstruction,
    all_evidence: tuple[SpanEvidence, ...],
) -> str:
    """
    Build a one-sentence summary for a completed RCA investigation.

    Language rules (enforced by tests):
      - No "root cause", "caused by", "responsible for"
      - No "investigation could not proceed"
      - INSUFFICIENT_DATA prefix: "Insufficient telemetry was available for
        evidence analysis:"
    """
    if confidence == "INSUFFICIENT_DATA":
        if anomaly.trace_id is None:
            return (
                "Insufficient telemetry was available for evidence analysis: "
                "no trace ID was associated with this anomaly."
            )
        if reconstruction.span_count == 0:
            return (
                "Insufficient telemetry was available for evidence analysis: "
                "the associated trace contained no spans."
            )
        return (
            "Insufficient telemetry was available for evidence analysis: "
            "the associated trace contained only one span."
        )

    if confidence == "LOW":
        return (
            f"No span scored above the evidence threshold for this "
            f"{anomaly.anomaly_type} anomaly; no strong contributing signal "
            f"was found."
        )

    # MEDIUM or HIGH — all_evidence is non-empty here
    top = all_evidence[0]
    return (
        f"Span '{top.span_name}' in service '{top.service_name}' showed the "
        f"strongest contributing evidence (score {top.evidence_score:.2f}): "
        f"{top.explanation}."
    )


def _derive_limitations(
    anomaly: RcaAnomalyRecord,
    reconstruction: TraceReconstruction,
    evidence: tuple[SpanEvidence, ...],
    signal: str,
    confidence: str,
) -> tuple[str, ...]:
    """
    Return a tuple of limitation codes for the completed investigation.

    ``evidence`` must be all_evidence_scored (the pre-zeroing value) so that
    evidence-based limitation checks can inspect actual span data.

    Structural limitations are always evaluated.  Evidence-based limitations
    are skipped when confidence == 'INSUFFICIENT_DATA'.
    """
    codes: list[str] = []

    # Structural — always evaluated
    if anomaly.trace_id is None:
        codes.append("no_trace_id")

    if anomaly.trace_id is not None and reconstruction.span_count == 0:
        codes.append("trace_not_found")

    if reconstruction.span_count == 1:
        codes.append("single_span_trace")

    if orphan_fraction(reconstruction) >= 0.10:
        codes.append("partial_trace")

    # Evidence-based — skipped for INSUFFICIENT_DATA
    if confidence != "INSUFFICIENT_DATA":
        if signal in ("error_rate", "tool_failure") and not any(
            e.is_error_span for e in evidence
        ):
            codes.append("no_error_spans")

        if signal in SPAN_SPECIFIC_SIGNALS and not any(
            e.is_direct_subject for e in evidence
        ):
            codes.append("direct_subject_absent")

        if signal == "tool_failure" and any(
            e.is_direct_subject and e.tool_name is None for e in evidence
        ):
            codes.append("tool_name_absent")

    return tuple(codes)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_investigation(
    conn: psycopg.Connection,
    anomaly_id: str,
) -> tuple[RCAResult, PersistenceResult]:
    """
    Execute the full RCA pipeline for a single anomaly and persist the result.

    Parameters
    ----------
    conn
        Open psycopg connection.  The caller owns the connection lifecycle;
        this function never opens or closes it.
    anomaly_id
        Primary key of the anomaly row in public.anomaly_events.

    Returns
    -------
    (RCAResult, PersistenceResult)

    Raises
    ------
    AnomalyNotFoundError
        anomaly_id does not exist in public.anomaly_events.
    SourceDataIntegrityError
        The anomaly row exists but fails domain validation in rca_source
        (unrecognised anomaly_type or severity).  Wraps the original
        ValueError with exception chaining.
    psycopg.OperationalError
        Any database connectivity failure.
    """
    # 1. Fetch anomaly — wrap source domain validation errors
    try:
        anomaly = fetch_anomaly(conn, anomaly_id)
    except ValueError as exc:
        raise SourceDataIntegrityError(str(exc)) from exc

    if anomaly is None:
        raise AnomalyNotFoundError(anomaly_id)

    # 2. Investigation metadata (Python-side timestamp; DB stores NOW() separately)
    investigated_at = datetime.now(tz=timezone.utc)
    investigation_id = compute_investigation_id(anomaly.anomaly_id, RCA_ANALYZER_VERSION)

    # 3. Fetch spans — only when trace_id is present (API precondition)
    spans: list[SpanRecord] = []
    if anomaly.trace_id is not None:
        spans = fetch_spans(conn, anomaly.trace_id)

    # 4-7. Full pipeline — assess_confidence is always the authoritative source
    reconstruction = build_trace_tree(spans)
    facts = extract_evidence(anomaly, reconstruction)
    all_evidence_scored = score_and_rank(anomaly, facts)
    confidence = assess_confidence(anomaly, all_evidence_scored, reconstruction)

    # 8. Canonical signal name (needed for top_contributors and limitations)
    signal = derive_signal(anomaly)

    # 9. Apply RCAResult contract: INSUFFICIENT_DATA → empty evidence
    if confidence == "INSUFFICIENT_DATA":
        all_evidence: tuple[SpanEvidence, ...] = ()
        top_contributors: tuple[SpanEvidence, ...] = ()
    else:
        all_evidence = all_evidence_scored
        threshold = signal_threshold(signal)
        top_contributors = tuple(
            e for e in all_evidence if e.evidence_score >= threshold
        )

    # 10. Limitations and summary
    # Pass all_evidence_scored (pre-zeroing) so evidence-based checks see real spans
    limitations = _derive_limitations(
        anomaly, reconstruction, all_evidence_scored, signal, confidence
    )
    summary = _build_summary(confidence, anomaly, reconstruction, all_evidence)

    # 11. Construct immutable RCAResult
    result = RCAResult(
        anomaly_id=anomaly.anomaly_id,
        anomaly_type=anomaly.anomaly_type,
        signal_name=anomaly.signal_name,
        detector_name=anomaly.detector_name,
        detector_version=anomaly.detector_version,
        observed_value=anomaly.observed_value,
        baseline_median=anomaly.baseline_median,
        baseline_mad=anomaly.baseline_mad,
        baseline_n=anomaly.baseline_n,
        anomaly_score=anomaly.anomaly_score,
        severity=anomaly.severity,
        detector_explanation=anomaly.detector_explanation,
        investigated_at=investigated_at,
        analyzer_version=RCA_ANALYZER_VERSION,
        investigation_id=investigation_id,
        trace_id=anomaly.trace_id,
        subject_span_id=anomaly.subject_span_id,
        service_name=anomaly.service_name,
        operation_name=anomaly.operation_name,
        event_time=anomaly.event_time,
        trace_span_count=reconstruction.span_count,
        all_evidence=all_evidence,
        top_contributors=top_contributors,
        confidence=confidence,
        summary=summary,
        limitations=limitations,
    )

    # 12. Persist — owns the transaction (commit or rollback)
    pr = persist_investigation(conn, result)

    return result, pr

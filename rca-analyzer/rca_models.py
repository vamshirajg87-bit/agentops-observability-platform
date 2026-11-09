"""
rca-analyzer/rca_models.py

Phase 11.2: Immutable data contracts for RCA evidence and results.

No scoring logic, no database access, no I/O.

Public API:
    SpanEvidence    — one span's evidence record (frozen dataclass)
    RCAResult       — full result of one RCA investigation (frozen dataclass)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class SpanEvidence:
    """
    Evidence record for one span within an RCA investigation.

    Structured in four sections to enforce a strict separation between raw
    facts, derived measurements, heuristic scores, and human-readable output.
    No section may make causal claims.

    The evidence_score is a heuristic signal [0.0, 1.0].  A high score means
    the span is a strong suspicious contributor to the anomaly — not that it
    caused it.
    """

    # ------------------------------------------------------------------
    # Section A: raw span facts (directly from stg_telemetry_spans)
    # ------------------------------------------------------------------

    span_id: str
    parent_span_id: Optional[str]
    span_name: str
    service_name: str
    start_time: datetime
    end_time: datetime
    duration_ms: float
    status_code: str
    status_message: Optional[str]

    # Domain-specific raw facts (None when not applicable to this span type)
    error_type: Optional[str]
    error_message: Optional[str]
    tool_name: Optional[str]        # None on error tool spans — known telemetry gap
    tool_status: Optional[str]
    agent_name: Optional[str]
    agent_operation: Optional[str]
    retrieval_result_count: Optional[int]
    retrieval_top_relevance_score: Optional[float]

    # Structural flags (derived from raw facts; kept here for evidence readability)
    is_root_span: bool              # parent_span_id is None
    is_error_span: bool             # status_code == 'ERROR'
    is_direct_subject: bool         # span_id matches the anomaly's subject span_id

    # ------------------------------------------------------------------
    # Section B: derived measurements (computed from raw + trace context)
    # ------------------------------------------------------------------

    trace_duration_fraction: Optional[float]
    # span.duration_ms / trace_duration_ms.
    # What fraction of the trace's wall-clock window this span occupied.
    # Conceptually in [0.0, 1.0] for internally consistent telemetry: a single
    # span cannot exceed the wall-clock envelope it belongs to.
    # The SUM across concurrent spans may exceed 1.0 — this fraction must not
    # be interpreted as an additive latency decomposition.
    # Values > 1.0 for an individual span indicate inconsistent span timestamps
    # in the source telemetry (clock skew, rounding errors, export bugs); the
    # Python layer preserves them rather than clamping, so callers must guard.
    # None when trace_duration_ms == 0 or the trace could not be reconstructed.

    depth: int
    # 0 = root, 1 = direct child of root, etc.
    # Structural context only — never increases evidence_score.
    # A deeper error may itself be a downstream consequence, not the origin.

    # ------------------------------------------------------------------
    # Section C: heuristic evidence output (no causal claims)
    # ------------------------------------------------------------------

    evidence_score: float
    # Heuristic score in [0.0, 1.0].  Higher means stronger signal for this
    # anomaly type.  Components and weights are signal-specific.

    evidence_score_breakdown: str
    # Auditable decomposition, e.g.:
    # "duration_fraction=0.80→0.480 error_status=0.40 → 0.88"

    evidence_type: str
    # One of:
    #   "dominant_duration_and_error"  — large trace_duration_fraction + ERROR status
    #   "dominant_duration"            — large fraction, no error
    #   "correlated_error"             — ERROR status, modest fraction
    #   "direct_subject"               — the named anomalous span, no error
    #   "direct_subject_and_error"     — the named anomalous span + ERROR
    #   "retrieval_quality_signal"     — low result count or low relevance score
    #   "background_span"              — no notable signal for this anomaly type

    # ------------------------------------------------------------------
    # Section D: human-readable explanation (no causal claims)
    # ------------------------------------------------------------------

    explanation: str
    # Language rules:
    #   ✓ "occupied 80% of the trace's wall-clock duration"
    #   ✓ "Correlated error span"
    #   ✓ "strongest contributing evidence"
    #   ✗ "caused 80% of trace latency"
    #   ✗ "root cause"
    #   ✗ "responsible for"


@dataclass(frozen=True)
class RCAResult:
    """
    Full result of one RCA investigation.

    Immutable snapshot of the investigation: what anomaly was examined,
    what trace evidence was found, how evidence was ranked, and the
    confidence assessment.

    Confidence semantics:
        HIGH             — strong, unambiguous evidence for the anomaly type
        MEDIUM           — evidence found but weakened by a qualifying factor
        LOW              — trace found but no clear contributing signal
        INSUFFICIENT_DATA — no trace data; investigation could not proceed

    Confidence is a statement about the quality of the evidence, NOT a
    probability that any span caused the anomaly.
    """

    # ------------------------------------------------------------------
    # Anomaly identity (snapshot from public.anomaly_events)
    # ------------------------------------------------------------------

    anomaly_id: str
    anomaly_type: str               # "latency" | "retrieval_quality" | "error_rate" | "tool_failure"
    signal_name: str
    detector_name: str
    detector_version: str
    observed_value: float
    baseline_median: Optional[float]
    baseline_mad: Optional[float]
    baseline_n: Optional[int]
    anomaly_score: Optional[float]
    severity: str                   # "INFO" | "WARNING" | "CRITICAL"
    detector_explanation: str       # the explanation field from anomaly_events

    # ------------------------------------------------------------------
    # Investigation metadata
    # ------------------------------------------------------------------

    investigated_at: datetime       # UTC wall-clock when this investigation ran
    analyzer_version: str           # e.g. "1.0"
    investigation_id: str           # deterministic SHA-256 of (anomaly_id, analyzer_version)

    # ------------------------------------------------------------------
    # Trace context
    # ------------------------------------------------------------------

    trace_id: Optional[str]
    subject_span_id: Optional[str]  # the anomaly's span_id; None for trace-level latency
    service_name: Optional[str]
    operation_name: Optional[str]
    event_time: datetime            # copied from anomaly_events.event_time

    trace_span_count: int           # 0 when confidence == 'INSUFFICIENT_DATA'

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    all_evidence: tuple[SpanEvidence, ...]
    # All spans from the trace reconstruction, in evidence_score DESC order.
    # Empty tuple when confidence == 'INSUFFICIENT_DATA'.

    top_contributors: tuple[SpanEvidence, ...]
    # Subset of all_evidence with evidence_score above the signal threshold.
    # At most N entries (N defined by config).  Subset of all_evidence.

    # ------------------------------------------------------------------
    # Confidence and limitations
    # ------------------------------------------------------------------

    confidence: str
    # "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT_DATA"

    summary: str
    # One human-readable sentence describing the strongest evidence found.
    # No causal claims.  No "caused by" or "root cause" language.

    limitations: tuple[str, ...]
    # Coded strings describing evidence quality gaps, e.g.:
    #   "no_trace_id"           — anomaly carried no trace_id
    #   "trace_not_found"       — trace_id present but no spans in DB
    #   "partial_trace"         — orphan_fraction > threshold
    #   "no_error_spans"        — trace has no error spans
    #   "no_dominant_latency"   — no span with large trace_duration_fraction
    #   "single_span_trace"     — fewer than 2 spans; no comparative evidence
    #   "tool_name_absent"      — tool_name NULL on tool failure subject span
    #   "direct_subject_absent" — known span_id not found in trace reconstruction

"""
rca-analyzer/rca_confidence.py

Phase 11.4: Confidence classification.

Classifies the overall confidence of an RCA investigation as one of:

    INSUFFICIENT_DATA  — too little data to reason about
    LOW                — evidence exists but is weak or incomplete
    MEDIUM             — evidence is present but has notable caveats
    HIGH               — evidence is strong and telemetry is sufficiently clean

Confidence means "how well the available telemetry evidence explains the
anomaly."  It is NOT a probability that any span caused the incident.

Checks are evaluated in precedence order; the first match wins:
    1. INSUFFICIENT_DATA
    2. LOW
    3. MEDIUM
    4. HIGH

No database access, no I/O.

Public API:
    assess_confidence()  — anomaly + evidence + reconstruction → confidence str
"""

from __future__ import annotations

import math

from rca_models import SpanEvidence
from rca_source import RcaAnomalyRecord
from rca_trace import TraceNode, TraceReconstruction


# ---------------------------------------------------------------------------
# Signal routing (independent copy — avoids importing from rca_ranker)
# ---------------------------------------------------------------------------

def _derive_signal(anomaly: RcaAnomalyRecord) -> str:
    if anomaly.anomaly_type == "latency":
        op = anomaly.operation_name or ""
        if op == "trace":
            return "trace_latency"
        if op == "tool.execute":
            return "tool_latency"
        return "agent_latency"
    return anomaly.anomaly_type


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Absorbs only IEEE 754 arithmetic noise (~2e-17 for 0.60-0.50); does not
# widen the boundary to cover genuine sub-threshold gaps.
_GAP_TOLERANCE: float = 1e-9

# Minimum top evidence_score for a signal before confidence degrades to LOW.
_SIGNAL_THRESHOLDS: dict[str, float] = {
    "trace_latency": 0.50,
    "agent_latency": 0.40,
    "tool_latency": 0.40,
    "retrieval_quality": 0.50,
    "error_rate": 0.40,
    "tool_failure": 0.40,
}

# Signals that require a direct subject span in the evidence.
_SPAN_SPECIFIC_SIGNALS: frozenset[str] = frozenset({
    "agent_latency",
    "tool_latency",
    "retrieval_quality",
    "error_rate",
    "tool_failure",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_subtree_spans(node: TraceNode) -> int:
    """Count the node itself and all its descendants."""
    return 1 + sum(_count_subtree_spans(c) for c in node.children)


def _orphan_fraction(reconstruction: TraceReconstruction) -> float:
    """
    Fraction of total spans belonging to orphan subtrees.

    An orphan is a span whose parent_span_id is non-None but whose parent is
    absent from the trace input.  Includes both orphan subtree roots and all
    their descendants.  Returns 0.0 for an empty reconstruction.
    """
    if reconstruction.span_count == 0:
        return 0.0
    orphan_count = sum(_count_subtree_spans(o) for o in reconstruction.orphans)
    return orphan_count / reconstruction.span_count


def _has_malformed_fractions(evidence: tuple[SpanEvidence, ...]) -> bool:
    """True when any span's trace_duration_fraction exceeds 1.0."""
    return any(
        e.trace_duration_fraction is not None and e.trace_duration_fraction > 1.0
        for e in evidence
    )


def _has_direct_subject(evidence: tuple[SpanEvidence, ...]) -> bool:
    return any(e.is_direct_subject for e in evidence)


def _has_retrieval_evidence(evidence: tuple[SpanEvidence, ...]) -> bool:
    """True when at least one span carries retrieval telemetry fields."""
    return any(
        e.retrieval_result_count is not None or e.retrieval_top_relevance_score is not None
        for e in evidence
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def assess_confidence(
    anomaly: RcaAnomalyRecord,
    evidence: tuple[SpanEvidence, ...],
    reconstruction: TraceReconstruction,
) -> str:
    """
    Classify investigation confidence.

    Parameters
    ----------
    anomaly
        The anomaly being investigated; supplies signal routing and trace_id.
    evidence
        Scored, ranked SpanEvidence from score_and_rank() — must be in
        evidence_score DESC order for gap calculations to be correct.
    reconstruction
        The trace reconstruction; supplies orphan/cycle/root metadata.

    Returns
    -------
    str
        One of 'INSUFFICIENT_DATA', 'LOW', 'MEDIUM', 'HIGH'.
    """
    signal = _derive_signal(anomaly)
    span_count = len(evidence)

    # ------------------------------------------------------------------
    # 1. INSUFFICIENT_DATA — takes precedence over all other conditions
    # ------------------------------------------------------------------
    if anomaly.trace_id is None or span_count < 2:
        return "INSUFFICIENT_DATA"

    # ------------------------------------------------------------------
    # 2. LOW
    # ------------------------------------------------------------------
    top_score = evidence[0].evidence_score

    # Top score below signal-specific threshold
    threshold = _SIGNAL_THRESHOLDS.get(signal, 0.40)
    if top_score < threshold:
        return "LOW"

    # Retrieval anomaly but no span carries retrieval telemetry
    if signal == "retrieval_quality" and not _has_retrieval_evidence(evidence):
        return "LOW"

    # Span-specific signal without a direct subject span in evidence
    if signal in _SPAN_SPECIFIC_SIGNALS and not _has_direct_subject(evidence):
        return "LOW"

    # Majority of spans are orphans
    orphan_frac = _orphan_fraction(reconstruction)
    if orphan_frac > 0.50:
        return "LOW"

    # ------------------------------------------------------------------
    # 3. MEDIUM
    # ------------------------------------------------------------------
    # Top-two evidence score gap is small.
    # math.isclose guards the 0.10 boundary: 0.60-0.50 yields 0.09999...
    # in IEEE 754; isclose correctly treats that as ≈0.10, not < 0.10.
    gap = evidence[0].evidence_score - evidence[1].evidence_score
    if gap < 0.10 and not math.isclose(gap, 0.10, rel_tol=0.0, abs_tol=_GAP_TOLERANCE):
        return "MEDIUM"

    # Moderate orphan fraction
    if 0.10 <= orphan_frac <= 0.50:
        return "MEDIUM"

    # Known telemetry gap: detected cycle or malformed timestamps
    if reconstruction.has_cycle or _has_malformed_fractions(evidence):
        return "MEDIUM"

    # Natural trace root is absent
    if len(reconstruction.roots) == 0:
        return "MEDIUM"

    # trace_latency deep single-span outlier (MEDIUM condition 21E):
    #   top-ranked span is non-root AND depth >= 2 AND exactly one non-root
    #   span has evidence_score >= 0.50.  A single deep outlier is suspicious
    #   but lacks corroborating evidence from peer spans.
    if signal == "trace_latency":
        qualifying = [
            e for e in evidence
            if not e.is_root_span and e.evidence_score >= 0.50
        ]
        if (
            len(qualifying) == 1
            and not evidence[0].is_root_span
            and evidence[0].depth >= 2
        ):
            return "MEDIUM"

    # ------------------------------------------------------------------
    # 4. HIGH
    # ------------------------------------------------------------------
    return "HIGH"


# ---------------------------------------------------------------------------
# Public signal interface (Phase 11.6 additions — interface-only; no new logic)
# ---------------------------------------------------------------------------
# Each public symbol below delegates to or aliases the canonical private
# constant or helper defined above.  All existing private symbols are
# unchanged; no confidence semantics are altered.

def derive_signal(anomaly: RcaAnomalyRecord) -> str:
    """
    Map anomaly to its canonical signal name.

    Public delegation to _derive_signal.  Behavior is identical.

    Returns one of: 'trace_latency', 'agent_latency', 'tool_latency',
    'retrieval_quality', 'error_rate', 'tool_failure'.
    """
    return _derive_signal(anomaly)


def signal_threshold(signal: str) -> float:
    """
    Return the minimum evidence_score for MEDIUM or HIGH confidence.

    This is the inclusive lower bound used in assess_confidence() to
    distinguish LOW from not-LOW for the given signal.  An unknown signal
    returns 0.40 (the _SIGNAL_THRESHOLDS.get default).
    """
    return _SIGNAL_THRESHOLDS.get(signal, 0.40)


#: Public alias for the frozenset of signal names that require a direct
#: subject span to reach MEDIUM or HIGH confidence.
#: ``_SPAN_SPECIFIC_SIGNALS`` is the single source of truth.
SPAN_SPECIFIC_SIGNALS: frozenset[str] = _SPAN_SPECIFIC_SIGNALS


def orphan_fraction(reconstruction: TraceReconstruction) -> float:
    """
    Fraction of total spans belonging to orphan subtrees.

    Public delegation to _orphan_fraction.  Behavior is identical.
    Returns 0.0 for an empty reconstruction.
    """
    return _orphan_fraction(reconstruction)

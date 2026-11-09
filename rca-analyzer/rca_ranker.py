"""
rca-analyzer/rca_ranker.py

Phase 11.4: Signal-aware scoring and deterministic ranking.

Converts UnscoredSpanFacts (Phase 11.3) into scored SpanEvidence objects
ranked by evidence_score DESC.

Scores are HEURISTICS that rank telemetry evidence associated with an anomaly.
They are NOT causal probabilities, ML probabilities, or certainty percentages.

Architecture:
    UnscoredSpanFacts + RcaAnomalyRecord → score_and_rank() → SpanEvidence

No database access, no I/O.

Public API:
    score_and_rank()  — score and rank unscored facts for a given anomaly
"""

from __future__ import annotations

from typing import Optional

from rca_evidence import UnscoredSpanFacts
from rca_models import SpanEvidence
from rca_source import RcaAnomalyRecord


# ---------------------------------------------------------------------------
# Signal routing
# ---------------------------------------------------------------------------

def _derive_signal(anomaly: RcaAnomalyRecord) -> str:
    """
    Map an anomaly record to one of the six scoring signal names.

    Signal names:
        trace_latency     — latency anomaly at trace level (operation_name='trace')
        agent_latency     — latency anomaly on an agent span
        tool_latency      — latency anomaly on a tool.execute span
        retrieval_quality — retrieval quality anomaly
        error_rate        — error rate anomaly
        tool_failure      — tool failure anomaly
    """
    if anomaly.anomaly_type == "latency":
        op = anomaly.operation_name or ""
        if op == "trace":
            return "trace_latency"
        if op == "tool.execute":
            return "tool_latency"
        return "agent_latency"
    return anomaly.anomaly_type  # "retrieval_quality", "error_rate", "tool_failure"


def _decode_tool_error_type(operation_name: Optional[str]) -> Optional[str]:
    """
    Extract the error_type from a tool_failure anomaly's operation_name.

    ToolFailureDetector encodes: operation_name = "tool.execute/{error_type}"
    Returns the error_type substring after the first slash, or None when the
    encoding prefix is absent.
    """
    prefix = "tool.execute/"
    if operation_name and operation_name.startswith(prefix):
        return operation_name[len(prefix):]
    return None


# ---------------------------------------------------------------------------
# Component scoring — each function returns (A, B, C, D)
# ---------------------------------------------------------------------------

def _score_trace_latency(f: UnscoredSpanFacts) -> tuple[float, float, float, float]:
    """
    Weights: A=0.60, B=0.40.

    Root spans have their duration component A excluded.  A natural root
    structurally spans approximately the entire trace, so giving it duration
    credit would make it trivially dominate RCA.  The error component B is
    retained for root spans.
    """
    frac = f.trace_duration_fraction if f.trace_duration_fraction is not None else 0.0
    a = 0.0 if f.is_root_span else 0.60 * frac
    b = 0.40 if f.is_error_span else 0.0
    return a, b, 0.0, 0.0


def _score_agent_latency(f: UnscoredSpanFacts) -> tuple[float, float, float, float]:
    """Weights: A=0.30, B=0.30, C=0.40."""
    frac = f.trace_duration_fraction if f.trace_duration_fraction is not None else 0.0
    a = 0.30 * frac
    b = 0.30 if f.is_error_span else 0.0
    c = 0.40 if f.is_direct_subject else 0.0
    return a, b, c, 0.0


def _score_tool_latency(f: UnscoredSpanFacts) -> tuple[float, float, float, float]:
    """Weights: A=0.30, B=0.30, C=0.40.  Same structure as agent_latency."""
    frac = f.trace_duration_fraction if f.trace_duration_fraction is not None else 0.0
    a = 0.30 * frac
    b = 0.30 if f.is_error_span else 0.0
    c = 0.40 if f.is_direct_subject else 0.0
    return a, b, c, 0.0


def _score_retrieval_quality(f: UnscoredSpanFacts) -> tuple[float, float, float, float]:
    """
    Weights: A=0.10, B=0.20, C=0.30, D=up to 0.40.

    D component rules:
        +0.20 if retrieval_result_count == 0
        +0.20 if retrieval_top_relevance_score is not None AND < 0.50

    Missing telemetry (None) is NOT equivalent to bad telemetry.
    """
    frac = f.trace_duration_fraction if f.trace_duration_fraction is not None else 0.0
    a = 0.10 * frac
    b = 0.20 if f.is_error_span else 0.0
    c = 0.30 if f.is_direct_subject else 0.0
    d = 0.0
    if f.retrieval_result_count == 0:
        d += 0.20
    if (
        f.retrieval_top_relevance_score is not None
        and f.retrieval_top_relevance_score < 0.50
    ):
        d += 0.20
    return a, b, c, d


def _score_error_rate(f: UnscoredSpanFacts) -> tuple[float, float, float, float]:
    """Weights: A=0.20, B=0.50, C=0.30."""
    frac = f.trace_duration_fraction if f.trace_duration_fraction is not None else 0.0
    a = 0.20 * frac
    b = 0.50 if f.is_error_span else 0.0
    c = 0.30 if f.is_direct_subject else 0.0
    return a, b, c, 0.0


def _score_tool_failure(
    f: UnscoredSpanFacts,
    anomaly_error_type: Optional[str],
) -> tuple[float, float, float, float]:
    """
    Weights: A=0.10, B=0.40, C=0.30, D=0.20.

    D = +0.20 only when span.error_type matches the error_type decoded from
    the anomaly's operation_name ("tool.execute/{error_type}").
    """
    frac = f.trace_duration_fraction if f.trace_duration_fraction is not None else 0.0
    a = 0.10 * frac
    b = 0.40 if f.is_error_span else 0.0
    c = 0.30 if f.is_direct_subject else 0.0
    d = 0.0
    if (
        anomaly_error_type is not None
        and f.error_type is not None
        and f.error_type == anomaly_error_type
    ):
        d = 0.20
    return a, b, c, d


# ---------------------------------------------------------------------------
# Evidence type classification
# ---------------------------------------------------------------------------

def _evidence_type(a: float, b: float, c: float, d: float, signal: str) -> str:
    """
    Neutral evidence type label.

    Single active component → its label.
    Multiple active components → "mixed".
    No active components → "telemetry" (observed; no positive evidence).
    """
    active = sum(1 for x in (a, b, c, d) if x > 0.0)
    if active == 0:
        return "telemetry"
    if active > 1:
        return "mixed"
    if a > 0.0:
        return "duration"
    if b > 0.0:
        return "error"
    if c > 0.0:
        return "direct_subject"
    # d > 0 only
    if signal == "retrieval_quality":
        return "retrieval"
    if signal == "tool_failure":
        return "tool_error_match"
    return "signal_specific"


# ---------------------------------------------------------------------------
# Score breakdown
# ---------------------------------------------------------------------------

def _breakdown(a: float, b: float, c: float, d: float) -> str:
    """
    Compact, stable component breakdown.

    Format: duration=X.XXX,error=X.XXX,direct_subject=X.XXX,signal_specific=X.XXX

    Component values sum to the pre-cap score.
    """
    return (
        f"duration={a:.3f},error={b:.3f},"
        f"direct_subject={c:.3f},signal_specific={d:.3f}"
    )


# ---------------------------------------------------------------------------
# Explanation
# ---------------------------------------------------------------------------

def _explanation(
    f: UnscoredSpanFacts,
    signal: str,
    a: float,
    b: float,
    c: float,
    d: float,
    anomaly_error_type: Optional[str],
) -> str:
    """
    Deterministic, evidence-only explanation.

    Describes what was observed.  Does not claim causality.
    """
    parts: list[str] = []

    # Duration evidence
    if signal == "trace_latency" and f.is_root_span:
        parts.append("Root span: duration excluded from trace_latency scoring")
    elif f.trace_duration_fraction is None:
        parts.append("Trace envelope is zero-width; duration fraction unavailable")
    elif a > 0.0:
        pct = f.trace_duration_fraction * 100
        parts.append(f"Span occupied {pct:.1f}% of the trace wall-clock envelope")

    # Error evidence
    if b > 0.0:
        parts.append("Had ERROR status")

    # Direct-subject evidence
    if c > 0.0:
        parts.append("Is the anomaly's direct subject span")

    # Signal-specific evidence (D component)
    if signal == "retrieval_quality":
        if f.retrieval_result_count == 0:
            parts.append("Returned zero retrieval results")
        if (
            f.retrieval_top_relevance_score is not None
            and f.retrieval_top_relevance_score < 0.50
        ):
            parts.append(
                f"Top retrieval relevance score was {f.retrieval_top_relevance_score:.3f},"
                f" below 0.50"
            )
    elif signal == "tool_failure" and d > 0.0:
        parts.append(
            "Error type matched the anomaly's encoded tool-failure error type"
        )

    if not parts:
        parts.append("No positive evidence components for this span")

    return "; ".join(parts)


# ---------------------------------------------------------------------------
# UnscoredSpanFacts → SpanEvidence
# ---------------------------------------------------------------------------

def _build_span_evidence(
    f: UnscoredSpanFacts,
    signal: str,
    anomaly_error_type: Optional[str],
) -> SpanEvidence:
    """Score one span and return a SpanEvidence."""
    if signal == "trace_latency":
        a, b, c, d = _score_trace_latency(f)
    elif signal == "agent_latency":
        a, b, c, d = _score_agent_latency(f)
    elif signal == "tool_latency":
        a, b, c, d = _score_tool_latency(f)
    elif signal == "retrieval_quality":
        a, b, c, d = _score_retrieval_quality(f)
    elif signal == "error_rate":
        a, b, c, d = _score_error_rate(f)
    elif signal == "tool_failure":
        a, b, c, d = _score_tool_failure(f, anomaly_error_type)
    else:
        raise ValueError(f"Unknown signal: {signal!r}")

    score = min(1.0, a + b + c + d)
    return SpanEvidence(
        # Section A — raw span facts
        span_id=f.span_id,
        parent_span_id=f.parent_span_id,
        span_name=f.span_name,
        service_name=f.service_name,
        start_time=f.start_time,
        end_time=f.end_time,
        duration_ms=f.duration_ms,
        status_code=f.status_code,
        status_message=f.status_message,
        error_type=f.error_type,
        error_message=f.error_message,
        tool_name=f.tool_name,
        tool_status=f.tool_status,
        agent_name=f.agent_name,
        agent_operation=f.agent_operation,
        retrieval_result_count=f.retrieval_result_count,
        retrieval_top_relevance_score=f.retrieval_top_relevance_score,
        is_root_span=f.is_root_span,
        is_error_span=f.is_error_span,
        is_direct_subject=f.is_direct_subject,
        # Section B — derived measurements
        trace_duration_fraction=f.trace_duration_fraction,
        depth=f.depth,
        # Section C — heuristic evidence output
        evidence_score=score,
        evidence_score_breakdown=_breakdown(a, b, c, d),
        evidence_type=_evidence_type(a, b, c, d, signal),
        # Section D — human-readable explanation
        explanation=_explanation(f, signal, a, b, c, d, anomaly_error_type),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def score_and_rank(
    anomaly: RcaAnomalyRecord,
    facts: tuple[UnscoredSpanFacts, ...],
) -> tuple[SpanEvidence, ...]:
    """
    Score each span for the given anomaly signal and return a ranked tuple.

    Ranking is deterministic:
        1. evidence_score DESC
        2. start_time ASC
        3. span_id ASC

    Returns an empty tuple when facts is empty.
    """
    signal = _derive_signal(anomaly)
    anomaly_error_type = (
        _decode_tool_error_type(anomaly.operation_name)
        if signal == "tool_failure"
        else None
    )

    scored = [
        _build_span_evidence(f, signal, anomaly_error_type)
        for f in facts
    ]
    scored.sort(key=lambda e: (-e.evidence_score, e.start_time, e.span_id))
    return tuple(scored)

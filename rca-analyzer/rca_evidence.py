"""
rca-analyzer/rca_evidence.py

Phase 11.3: Pure evidence extraction for the RCA analyzer.

Converts a TraceReconstruction into a tuple of UnscoredSpanFacts —
one per span — containing raw Section A facts and derived Section B
measurements.  No heuristic scoring, no confidence classification.
Those belong in Phase 11.4.

Architecture boundary:
    PostgreSQL rows → SpanRecord → TraceReconstruction → UnscoredSpanFacts [11.3]
                                                        → SpanEvidence      [11.4]

No database access, no I/O.

Public API:
    UnscoredSpanFacts   — immutable intermediate type (Sections A + B only)
    extract_evidence()  — anomaly + reconstruction → ordered evidence tuple
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from rca_source import RcaAnomalyRecord
from rca_trace import TraceNode, TraceReconstruction


# ---------------------------------------------------------------------------
# Intermediate evidence type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UnscoredSpanFacts:
    """
    Raw facts and derived measurements for one span within a trace.

    Section A fields are copied directly from the source SpanRecord.
    Section B fields are derived from the SpanRecord and the
    TraceReconstruction envelope.

    No heuristic scores, no evidence_type classification, no confidence
    assessment, no human-readable explanation.  Phase 11.4 converts
    UnscoredSpanFacts → SpanEvidence by adding Sections C and D.
    """

    # ------------------------------------------------------------------
    # Section A: raw span facts (from stg_telemetry_spans via SpanRecord)
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
    tool_name: Optional[str]
    tool_status: Optional[str]
    agent_name: Optional[str]
    agent_operation: Optional[str]
    retrieval_result_count: Optional[int]
    retrieval_top_relevance_score: Optional[float]

    # Structural flags derived from Section A facts
    is_root_span: bool          # parent_span_id is None
    is_error_span: bool         # status_code == 'ERROR'
    is_direct_subject: bool     # span_id == anomaly.subject_span_id

    # ------------------------------------------------------------------
    # Section B: derived measurements (from SpanRecord + trace context)
    # ------------------------------------------------------------------

    trace_duration_fraction: Optional[float]
    # span.duration_ms / trace_duration_ms.
    # Conceptually in [0.0, 1.0] for internally consistent telemetry: a
    # single span cannot exceed the wall-clock envelope it belongs to.
    # The SUM of trace_duration_fraction across concurrent spans may exceed
    # 1.0 — this fraction must not be interpreted as an additive latency
    # decomposition.
    # An individual value > 1.0 indicates inconsistent span timestamps in
    # the source telemetry (clock skew, rounding errors, export bugs).
    # Such values are preserved rather than clamped so downstream phases
    # and callers can detect and report the telemetry inconsistency.
    # None when trace_duration_ms == 0 (empty or zero-width trace envelope).

    depth: int
    # 0 = natural root or local root of an orphan/cycle subtree.
    # Increases by 1 for each parent-child hop in the reconstruction.
    # Structural context only — not an evidence signal for scoring.


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_all_nodes(node: TraceNode, result: list[TraceNode]) -> None:
    """Append node and all descendants (pre-order DFS) to result."""
    result.append(node)
    for child in node.children:
        _collect_all_nodes(child, result)


def _build_facts(
    node: TraceNode,
    subject_span_id: Optional[str],
    trace_duration_ms: float,
) -> UnscoredSpanFacts:
    span = node.span
    trace_duration_fraction: Optional[float] = (
        span.duration_ms / trace_duration_ms
        if trace_duration_ms != 0.0
        else None
    )
    return UnscoredSpanFacts(
        span_id=span.span_id,
        parent_span_id=span.parent_span_id,
        span_name=span.span_name,
        service_name=span.service_name,
        start_time=span.start_time,
        end_time=span.end_time,
        duration_ms=span.duration_ms,
        status_code=span.status_code,
        status_message=span.status_message,
        error_type=span.error_type,
        error_message=span.error_message,
        tool_name=span.tool_name,
        tool_status=span.tool_status,
        agent_name=span.agent_name,
        agent_operation=span.agent_operation,
        retrieval_result_count=span.retrieval_result_count,
        retrieval_top_relevance_score=span.retrieval_top_relevance_score,
        is_root_span=(span.parent_span_id is None),
        is_error_span=(span.status_code == "ERROR"),
        is_direct_subject=(
            subject_span_id is not None
            and span.span_id == subject_span_id
        ),
        trace_duration_fraction=trace_duration_fraction,
        depth=node.depth,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_evidence(
    anomaly: RcaAnomalyRecord,
    reconstruction: TraceReconstruction,
) -> tuple[UnscoredSpanFacts, ...]:
    """
    Extract one UnscoredSpanFacts per span from the reconstruction.

    Every span in the reconstruction (roots, orphans, cycle members, and
    all their descendants) appears exactly once in the output.

    Output is ordered start_time ASC, span_id ASC — matching the source
    query ordering — for deterministic, reproducible results.

    Returns an empty tuple when reconstruction.span_count == 0.
    """
    all_nodes: list[TraceNode] = []
    for root in reconstruction.roots:
        _collect_all_nodes(root, all_nodes)
    for orphan in reconstruction.orphans:
        _collect_all_nodes(orphan, all_nodes)
    for cycle_node in reconstruction.cycle_members:
        _collect_all_nodes(cycle_node, all_nodes)

    subject_span_id = anomaly.subject_span_id
    trace_duration_ms = reconstruction.trace_duration_ms

    facts = [
        _build_facts(node, subject_span_id, trace_duration_ms)
        for node in all_nodes
    ]

    facts.sort(key=lambda f: (f.start_time, f.span_id))
    return tuple(facts)

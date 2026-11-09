"""
rca-analyzer/rca_trace.py

Phase 11.2: RCA-owned trace reconstruction.

Pure-Python, database-independent trace reconstruction for the RCA analyzer.
Reconstructs parent-child relationships from a flat list of SpanRecord objects.
No database access, no I/O.

Behavioral reference: trace-viewer/reconstruction.py (same 3-color DFS
semantics for cycle detection, same orphan handling, same sibling ordering).
Differences from the trace-viewer implementation:
  - TraceNode carries a depth field (0 = root, 1 = direct child, etc.)
  - TraceReconstruction carries trace_duration_ms (wall-clock envelope)
  - SpanRecord promotes service_name as a non-defaulted required field
    (stg_telemetry_spans guarantees it is NOT NULL)
  - The rca-analyzer does not import trace-viewer as a production dependency

This file is the sole implementation of trace reconstruction in rca-analyzer.
A future telemetry-common package may merge both implementations once both
usages are stable.

Public API:
    SpanRecord          — input: one span from any source
    TraceNode           — output: a span positioned within the tree
    TraceReconstruction — output: the full reconstruction result
    build_trace_tree()  — entry point

Raises:
    ValueError  if any span_id appears more than once in the input.
    ValueError  if spans carry trace_id values from more than one trace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SpanRecord:
    """One span record as received from any source.

    Required fields are sufficient for reconstruction.
    Optional fields mirror the promoted business columns in
    analytics.stg_telemetry_spans and are available for evidence extraction.
    """

    # Required — always provided
    span_id: str
    parent_span_id: Optional[str]
    span_name: str
    service_name: str
    start_time: datetime
    end_time: datetime
    duration_ms: float
    status_code: str

    # Optional — populated when the source provides them
    trace_id: Optional[str] = None
    span_kind: Optional[str] = None
    status_message: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    gen_ai_operation: Optional[str] = None
    agent_name: Optional[str] = None
    agent_operation: Optional[str] = None
    tool_name: Optional[str] = None
    tool_status: Optional[str] = None
    retrieval_result_count: Optional[int] = None
    retrieval_top_relevance_score: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class TraceNode:
    """A span positioned within the reconstructed tree.

    depth is 0 for natural roots (parent_span_id is None), 1 for direct
    children of the root, and so on.  For orphan roots and synthetic cycle
    roots, depth is 0 at their local root.

    depth is structural context for evidence display only.  It does not
    affect evidence_score — a deeper error span may itself be a downstream
    consequence of a shallower one.

    is_cycle_member is True ONLY for spans that participate in a detected
    cycle (a back-edge points to them or to one of their ancestors).  Spans
    merely connected to a cycle component are NOT flagged.
    """

    span: SpanRecord
    children: list[TraceNode] = field(default_factory=list)
    depth: int = 0
    is_cycle_member: bool = False


@dataclass
class TraceReconstruction:
    """Full result of build_trace_tree().

    Every input span appears exactly once across roots, orphans, and
    cycle_members.

    trace_duration_ms is the wall-clock envelope:
        max(span.end_time) - min(span.start_time), converted to milliseconds.
    For a single-span trace this equals that span's duration_ms.
    For overlapping spans this is less than the sum of individual durations.
    0.0 when the input is empty.
    """

    # Subtrees rooted at spans whose parent_span_id is None.
    roots: list[TraceNode]

    # Subtrees rooted at spans whose parent_span_id is not in the input.
    orphans: list[TraceNode]

    # Synthetic subtrees for spans unreachable from any natural root.
    # Each entry is the lexicographically-smallest span in its disconnected
    # component, chosen as a deterministic synthetic root.
    cycle_members: list[TraceNode]

    # True if any back-edge was detected during DFS in any phase.
    has_cycle: bool

    span_count: int             # equals len(input spans)

    trace_duration_ms: float    # wall-clock envelope in milliseconds


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sort_key(span: SpanRecord) -> tuple[datetime, str]:
    """Deterministic ordering: start_time ASC, span_id ASC as tie-breaker."""
    return (span.start_time, span.span_id)


def _build_children_map(spans: list[SpanRecord]) -> dict[str, list[SpanRecord]]:
    """Map parent_span_id → list of child SpanRecord objects."""
    result: dict[str, list[SpanRecord]] = {}
    for span in spans:
        if span.parent_span_id is not None:
            result.setdefault(span.parent_span_id, []).append(span)
    return result


# 3-color DFS state constants
_WHITE = "white"    # not yet entered
_GRAY  = "gray"     # on the active recursion path
_BLACK = "black"    # fully processed


def _dfs(
    span_id: str,
    children_map: dict[str, list[SpanRecord]],
    span_by_id: dict[str, SpanRecord],
    color: dict[str, str],
    path: list[str],
    cycle_ids: set[str],
    depth: int,
) -> TraceNode:
    """
    Build a TraceNode for span_id and all its unvisited descendants using
    3-color DFS for precise cycle-member identification.

    Color transitions:
        WHITE → GRAY  when a span is entered (added to active path)
        GRAY  → BLACK when a span is exited  (removed from active path)

    Child dispatch:
        WHITE child  → not yet visited; recurse normally
        GRAY  child  → back-edge detected; every span from that child's
                       position in path through the current end is marked
                       as a cycle member.  The back-edge is NOT rendered
                       as a tree child (cycle broken at this point).
        BLACK child  → cross/forward edge; already claimed by another
                       subtree; skip to avoid duplicates.

    depth tracks the position in the tree (0 = local root of this DFS call).
    path and cycle_ids are shared and mutated within a single top-level call.
    """
    color[span_id] = _GRAY
    path.append(span_id)

    child_nodes: list[TraceNode] = []
    for child_span in sorted(children_map.get(span_id, []), key=_sort_key):
        cid = child_span.span_id
        state = color[cid]
        if state == _WHITE:
            child_nodes.append(
                _dfs(cid, children_map, span_by_id, color, path, cycle_ids, depth + 1)
            )
        elif state == _GRAY:
            # Back-edge: cid is an ancestor still on the active path.
            # Mark every span from cid's position onward as cycle members.
            idx = path.index(cid)
            cycle_ids.update(path[idx:])
        # _BLACK: already fully processed (cross/forward edge) — skip.

    path.pop()
    color[span_id] = _BLACK

    return TraceNode(
        span=span_by_id[span_id],
        children=child_nodes,
        depth=depth,
        is_cycle_member=(span_id in cycle_ids),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_trace_tree(spans: list[SpanRecord]) -> TraceReconstruction:
    """
    Reconstruct parent-child relationships from an unordered flat list of spans.

    The result covers every input span exactly once across roots, orphans,
    and cycle_members.  Input order is irrelevant; sibling order is
    deterministic (start_time ASC, span_id ASC).

    Raises:
        ValueError  if any span_id appears more than once in the input.
        ValueError  if spans carry trace_id values from more than one trace.

    Returns an empty TraceReconstruction (trace_duration_ms=0.0) for an
    empty input.
    """
    if not spans:
        return TraceReconstruction(
            roots=[], orphans=[], cycle_members=[],
            has_cycle=False, span_count=0, trace_duration_ms=0.0,
        )

    # Validate: no duplicate span_ids
    seen_ids: set[str] = set()
    for s in spans:
        if s.span_id in seen_ids:
            raise ValueError(f"Duplicate span_id in input: {s.span_id!r}")
        seen_ids.add(s.span_id)

    # Validate: single trace (only enforced when trace_id is provided)
    trace_ids = {s.trace_id for s in spans if s.trace_id is not None}
    if len(trace_ids) > 1:
        raise ValueError(
            f"Spans from multiple traces in a single reconstruction call: "
            f"{sorted(trace_ids)}"
        )

    span_by_id: dict[str, SpanRecord] = {s.span_id: s for s in spans}
    children_map = _build_children_map(spans)

    # Shared 3-color state across all phases.
    color: dict[str, str] = {s.span_id: _WHITE for s in spans}
    cycle_ids: set[str] = set()

    # --- Phase 1: natural roots (parent_span_id is None) ---
    natural_roots = sorted(
        [s for s in spans if s.parent_span_id is None],
        key=_sort_key,
    )
    root_nodes = [
        _dfs(r.span_id, children_map, span_by_id, color, [], cycle_ids, depth=0)
        for r in natural_roots
    ]

    # --- Phase 2: orphans (parent referenced but absent from input) ---
    orphan_roots = sorted(
        [
            s for s in spans
            if color[s.span_id] == _WHITE
            and s.parent_span_id is not None
            and s.parent_span_id not in span_by_id
        ],
        key=_sort_key,
    )
    orphan_nodes = [
        _dfs(o.span_id, children_map, span_by_id, color, [], cycle_ids, depth=0)
        for o in orphan_roots
    ]

    # --- Phase 3: cycle members ---
    # Every still-WHITE span has a parent in span_by_id but no path to any
    # natural root — it is in a disconnected cycle component.
    # Synthetic root = lexicographically smallest span_id in the component.
    cycle_nodes: list[TraceNode] = []
    while True:
        remaining = [s for s in spans if color[s.span_id] == _WHITE]
        if not remaining:
            break
        synthetic_root = min(remaining, key=lambda s: s.span_id)
        node = _dfs(
            synthetic_root.span_id, children_map, span_by_id,
            color, [], cycle_ids, depth=0,
        )
        cycle_nodes.append(node)

    # Wall-clock envelope: max(end_time) - min(start_time) in milliseconds.
    min_start = min(s.start_time for s in spans)
    max_end = max(s.end_time for s in spans)
    trace_duration_ms = (max_end - min_start).total_seconds() * 1000.0

    return TraceReconstruction(
        roots=root_nodes,
        orphans=orphan_nodes,
        cycle_members=cycle_nodes,
        has_cycle=bool(cycle_ids),
        span_count=len(spans),
        trace_duration_ms=trace_duration_ms,
    )

"""
rca-analyzer/tests/unit/test_rca_trace.py

Unit tests for rca_trace.py.

All tests are pure Python — no database, no network, no I/O.

Behavioral reference: trace-viewer/tests/unit/test_reconstruction.py.
The rca_trace implementation must behave identically to trace-viewer for all
shared semantics (DFS algorithm, orphan detection, cycle detection, sibling
ordering, coverage invariant, duplicate span_id, multi-trace validation).

Additional tests cover rca_trace-specific features:
  - depth field computation (not present in trace-viewer TraceNode)
  - trace_duration_ms wall-clock calculation (not present in trace-viewer)
  - overlapping spans (trace_duration_ms < sum of durations)

Test inventory:
    R01  Normal AgentOps star topology (7 spans: root + 6 children)
    R02  Input order independence (reversed + shuffled)
    R03  Nested hierarchy → depth calculation
    R04  Root-only trace
    R05  Multiple natural roots
    R06  Missing-parent orphan
    R07  Two-node cycle (A↔B, no natural root)
    R08  Longer cycle (A→B→C→A)
    R09  Duplicate span_id → ValueError
    R10  Multiple trace_ids → ValueError
    R11  Equal start_time tie-breaking by span_id
    R12  Empty input → empty TraceReconstruction (trace_duration_ms=0.0)
    R13  Coverage invariant (all spans accounted for exactly once)
    R14  Orphan with descendant
    R15  Cycle member with non-cycle tail (T16 in trace-viewer: cccc not flagged)
    R16  trace_duration_ms: single span
    R17  trace_duration_ms: sequential spans
    R18  trace_duration_ms: overlapping spans
    R19  trace_duration_ms: single-span trace equals span duration
    R20  Depth: star topology (all children depth=1)
    R21  Depth: nested chain (depths 0,1,2,3)
    R22  Depth: orphan root has depth=0, its child has depth=1
    R23  Depth: cycle synthetic root has depth=0
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from rca_trace import (
    SpanRecord,
    TraceNode,
    TraceReconstruction,
    build_trace_tree,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dt(second: int = 0, ms: int = 0) -> datetime:
    """Return a UTC datetime for 2026-01-01T00:00:<second>.<ms>Z."""
    return datetime(2026, 1, 1, 0, 0, second, ms * 1000, tzinfo=timezone.utc)


def _span(
    span_id: str,
    parent_span_id: Optional[str] = None,
    span_name: str = "op",
    service_name: str = "svc",
    start_second: int = 0,
    duration_ms: float = 0.0,
    trace_id: Optional[str] = None,
    status_code: str = "OK",
) -> SpanRecord:
    start = _dt(start_second)
    end = start + timedelta(milliseconds=duration_ms)
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
    )


def _all_span_ids(node: TraceNode) -> list[str]:
    """Flatten all span_ids in a subtree (depth-first)."""
    result = [node.span.span_id]
    for child in node.children:
        result.extend(_all_span_ids(child))
    return result


def _all_ids_in(r: TraceReconstruction) -> list[str]:
    """Collect every span_id across roots, orphans, and cycle_members."""
    ids: list[str] = []
    for node in r.roots + r.orphans + r.cycle_members:
        ids.extend(_all_span_ids(node))
    return ids


def _find_node(nodes: list[TraceNode], span_id: str) -> Optional[TraceNode]:
    """Return the first TraceNode whose span.span_id matches, or None."""
    for node in nodes:
        if node.span.span_id == span_id:
            return node
        found = _find_node(node.children, span_id)
        if found is not None:
            return found
    return None


# ---------------------------------------------------------------------------
# R01 — Normal AgentOps star topology
# ---------------------------------------------------------------------------

class TestAgentOpsStarTopology:
    """7-span star: one root (agentops.request) + 6 direct children."""

    SPAN_NAMES = [
        "agentops.request",
        "supervisor.start",
        "research.plan",
        "retrieval.search",
        "tool.execute",
        "research.synthesize",
        "supervisor.finalize",
    ]

    def _build_spans(self) -> list[SpanRecord]:
        root = _span("root0000", parent_span_id=None, span_name="agentops.request",
                     start_second=0)
        children = [
            _span(f"child00{i}", parent_span_id="root0000",
                  span_name=self.SPAN_NAMES[i + 1], start_second=i + 1)
            for i in range(6)
        ]
        return [root] + children

    def test_single_root(self):
        r = build_trace_tree(self._build_spans())
        assert len(r.roots) == 1

    def test_root_span_name(self):
        r = build_trace_tree(self._build_spans())
        assert r.roots[0].span.span_name == "agentops.request"

    def test_six_children_of_root(self):
        r = build_trace_tree(self._build_spans())
        assert len(r.roots[0].children) == 6

    def test_no_orphans_no_cycles(self):
        r = build_trace_tree(self._build_spans())
        assert r.orphans == []
        assert r.cycle_members == []
        assert r.has_cycle is False

    def test_span_count(self):
        spans = self._build_spans()
        r = build_trace_tree(spans)
        assert r.span_count == 7

    def test_children_sorted_by_start_time(self):
        r = build_trace_tree(self._build_spans())
        child_names = [c.span.span_name for c in r.roots[0].children]
        assert child_names == self.SPAN_NAMES[1:]

    def test_no_cycle_member_flags(self):
        r = build_trace_tree(self._build_spans())

        def all_not_cycle(node: TraceNode) -> bool:
            if node.is_cycle_member:
                return False
            return all(all_not_cycle(c) for c in node.children)

        assert all_not_cycle(r.roots[0])


# ---------------------------------------------------------------------------
# R02 — Input order independence
# ---------------------------------------------------------------------------

class TestInputOrderIndependence:
    def _canonical_spans(self) -> list[SpanRecord]:
        root = _span("root0000", parent_span_id=None, start_second=0)
        return [root] + [
            _span(f"child00{i}", parent_span_id="root0000", start_second=i + 1)
            for i in range(3)
        ]

    def _child_order(self, spans: list[SpanRecord]) -> list[str]:
        r = build_trace_tree(spans)
        return [c.span.span_id for c in r.roots[0].children]

    def test_reversed_order_same_result(self):
        spans = self._canonical_spans()
        assert self._child_order(list(reversed(spans))) == self._child_order(spans)

    def test_shuffled_order_same_result(self):
        spans = self._canonical_spans()
        shuffled = list(spans)
        random.seed(42)
        random.shuffle(shuffled)
        assert self._child_order(shuffled) == self._child_order(spans)


# ---------------------------------------------------------------------------
# R03 — Nested hierarchy (root → A → B → C)
# ---------------------------------------------------------------------------

class TestNestedHierarchy:
    def _spans(self) -> list[SpanRecord]:
        return [
            _span("root0000", parent_span_id=None, start_second=0),
            _span("aaaa0001", parent_span_id="root0000", start_second=1),
            _span("bbbb0002", parent_span_id="aaaa0001", start_second=2),
            _span("cccc0003", parent_span_id="bbbb0002", start_second=3),
        ]

    def test_single_root(self):
        r = build_trace_tree(self._spans())
        assert len(r.roots) == 1

    def test_chain_structure(self):
        r = build_trace_tree(self._spans())
        root_node = r.roots[0]
        a_node = root_node.children[0]
        b_node = a_node.children[0]
        c_node = b_node.children[0]
        assert root_node.span.span_id == "root0000"
        assert a_node.span.span_id == "aaaa0001"
        assert b_node.span.span_id == "bbbb0002"
        assert c_node.span.span_id == "cccc0003"
        assert c_node.children == []

    def test_no_orphans_no_cycles(self):
        r = build_trace_tree(self._spans())
        assert r.orphans == []
        assert r.cycle_members == []
        assert r.has_cycle is False


# ---------------------------------------------------------------------------
# R04 — Root-only trace
# ---------------------------------------------------------------------------

class TestRootOnlyTrace:
    def test_single_root_no_children(self):
        spans = [_span("root0000", parent_span_id=None)]
        r = build_trace_tree(spans)
        assert len(r.roots) == 1
        assert r.roots[0].children == []
        assert r.orphans == []
        assert r.cycle_members == []
        assert r.has_cycle is False
        assert r.span_count == 1

    def test_root_not_cycle_member(self):
        spans = [_span("root0000", parent_span_id=None)]
        r = build_trace_tree(spans)
        assert r.roots[0].is_cycle_member is False


# ---------------------------------------------------------------------------
# R05 — Multiple natural roots
# ---------------------------------------------------------------------------

class TestMultipleNaturalRoots:
    def test_two_roots_produced(self):
        spans = [
            _span("root0001", parent_span_id=None, start_second=0),
            _span("root0002", parent_span_id=None, start_second=1),
        ]
        r = build_trace_tree(spans)
        assert len(r.roots) == 2

    def test_roots_sorted_by_start_time(self):
        spans = [
            _span("root0002", parent_span_id=None, start_second=5),
            _span("root0001", parent_span_id=None, start_second=1),
        ]
        r = build_trace_tree(spans)
        assert r.roots[0].span.span_id == "root0001"
        assert r.roots[1].span.span_id == "root0002"

    def test_no_orphans_no_cycles(self):
        spans = [
            _span("root0001", parent_span_id=None),
            _span("root0002", parent_span_id=None),
        ]
        r = build_trace_tree(spans)
        assert r.orphans == []
        assert r.has_cycle is False


# ---------------------------------------------------------------------------
# R06 — Missing-parent orphan
# ---------------------------------------------------------------------------

class TestMissingParentOrphan:
    def test_orphan_appears_in_orphans_list(self):
        spans = [_span("orphan0a", parent_span_id="missing1")]
        r = build_trace_tree(spans)
        assert len(r.orphans) == 1
        assert r.orphans[0].span.span_id == "orphan0a"

    def test_roots_and_cycles_empty(self):
        spans = [_span("orphan0a", parent_span_id="missing1")]
        r = build_trace_tree(spans)
        assert r.roots == []
        assert r.cycle_members == []
        assert r.has_cycle is False

    def test_orphan_is_not_cycle_member(self):
        spans = [_span("orphan0a", parent_span_id="missing1")]
        r = build_trace_tree(spans)
        assert r.orphans[0].is_cycle_member is False

    def test_span_count_includes_orphan(self):
        spans = [_span("orphan0a", parent_span_id="missing1")]
        r = build_trace_tree(spans)
        assert r.span_count == 1


# ---------------------------------------------------------------------------
# R07 — Two-node cycle (A↔B, no natural root)
# ---------------------------------------------------------------------------

class TestTwoNodeCycle:
    def _spans(self) -> list[SpanRecord]:
        return [
            _span("aaaa0000", parent_span_id="bbbb0000", start_second=0),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=1),
        ]

    def test_cycle_detected(self):
        r = build_trace_tree(self._spans())
        assert r.has_cycle is True

    def test_no_natural_roots_no_orphans(self):
        r = build_trace_tree(self._spans())
        assert r.roots == []
        assert r.orphans == []

    def test_one_cycle_root_produced(self):
        r = build_trace_tree(self._spans())
        assert len(r.cycle_members) == 1

    def test_all_spans_accounted_for(self):
        spans = self._spans()
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)

    def test_synthetic_root_is_lexicographically_smallest(self):
        r = build_trace_tree(self._spans())
        assert r.cycle_members[0].span.span_id == "aaaa0000"

    def test_both_spans_flagged_as_cycle_members(self):
        r = build_trace_tree(self._spans())
        for sid in ["aaaa0000", "bbbb0000"]:
            node = _find_node(r.cycle_members, sid)
            assert node is not None
            assert node.is_cycle_member is True


# ---------------------------------------------------------------------------
# R08 — Longer cycle (A→B→C→A)
# ---------------------------------------------------------------------------

class TestLongerCycle:
    def _spans(self) -> list[SpanRecord]:
        return [
            _span("aaaa0000", parent_span_id="cccc0000", start_second=0),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=1),
            _span("cccc0000", parent_span_id="bbbb0000", start_second=2),
        ]

    def test_cycle_detected(self):
        r = build_trace_tree(self._spans())
        assert r.has_cycle is True

    def test_all_three_spans_present(self):
        spans = self._spans()
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)

    def test_all_cycle_flagged(self):
        r = build_trace_tree(self._spans())
        for sid in ["aaaa0000", "bbbb0000", "cccc0000"]:
            node = _find_node(r.cycle_members, sid)
            assert node is not None
            assert node.is_cycle_member is True


# ---------------------------------------------------------------------------
# R09 — Duplicate span_id raises ValueError
# ---------------------------------------------------------------------------

class TestDuplicateSpanId:
    def test_duplicate_raises_value_error(self):
        spans = [
            _span("aaaa0000", parent_span_id=None, start_second=0),
            _span("aaaa0000", parent_span_id=None, start_second=1),
        ]
        with pytest.raises(ValueError, match="Duplicate span_id"):
            build_trace_tree(spans)

    def test_error_message_contains_span_id(self):
        spans = [
            _span("aaaa0000", parent_span_id=None),
            _span("aaaa0000", parent_span_id=None),
        ]
        with pytest.raises(ValueError, match="aaaa0000"):
            build_trace_tree(spans)


# ---------------------------------------------------------------------------
# R10 — Multiple trace_ids raise ValueError
# ---------------------------------------------------------------------------

class TestMultipleTraceIds:
    def test_two_trace_ids_raises(self):
        spans = [
            _span("aaaa0000", trace_id="trace001"),
            _span("bbbb0000", trace_id="trace002"),
        ]
        with pytest.raises(ValueError, match="multiple traces"):
            build_trace_tree(spans)

    def test_single_trace_id_accepted(self):
        spans = [
            _span("aaaa0000", trace_id="trace001"),
            _span("bbbb0000", trace_id="trace001"),
        ]
        r = build_trace_tree(spans)
        assert r.span_count == 2

    def test_none_trace_id_ignored(self):
        spans = [
            _span("aaaa0000", trace_id="trace001"),
            _span("bbbb0000", trace_id=None),
        ]
        r = build_trace_tree(spans)
        assert r.span_count == 2


# ---------------------------------------------------------------------------
# R11 — Equal start_time tie-breaking by span_id
# ---------------------------------------------------------------------------

class TestEqualStartTimeTieBreaking:
    def test_siblings_sorted_by_span_id_when_times_equal(self):
        same_time = _dt(5)
        root = _span("root0000", parent_span_id=None, start_second=0)
        c_z = SpanRecord(
            span_id="zzzz0000", parent_span_id="root0000",
            span_name="z", service_name="svc",
            start_time=same_time, end_time=same_time,
            duration_ms=0.0, status_code="OK",
        )
        c_a = SpanRecord(
            span_id="aaaa0000", parent_span_id="root0000",
            span_name="a", service_name="svc",
            start_time=same_time, end_time=same_time,
            duration_ms=0.0, status_code="OK",
        )
        c_m = SpanRecord(
            span_id="mmmm0000", parent_span_id="root0000",
            span_name="m", service_name="svc",
            start_time=same_time, end_time=same_time,
            duration_ms=0.0, status_code="OK",
        )
        spans = [root, c_z, c_m, c_a]
        r = build_trace_tree(spans)
        child_ids = [c.span.span_id for c in r.roots[0].children]
        assert child_ids == ["aaaa0000", "mmmm0000", "zzzz0000"]


# ---------------------------------------------------------------------------
# R12 — Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_returns_empty_reconstruction(self):
        r = build_trace_tree([])
        assert r.roots == []
        assert r.orphans == []
        assert r.cycle_members == []
        assert r.has_cycle is False
        assert r.span_count == 0

    def test_empty_trace_duration_ms_is_zero(self):
        r = build_trace_tree([])
        assert r.trace_duration_ms == 0.0

    def test_empty_does_not_raise(self):
        build_trace_tree([])


# ---------------------------------------------------------------------------
# R13 — Coverage invariant
# ---------------------------------------------------------------------------

class TestCoverageInvariant:
    def _check(self, spans: list[SpanRecord]) -> None:
        r = build_trace_tree(spans)
        all_ids = _all_ids_in(r)
        input_ids = [s.span_id for s in spans]
        assert sorted(all_ids) == sorted(input_ids)
        assert len(all_ids) == len(set(all_ids)), "Duplicate span_id in output"

    def test_star_topology(self):
        root = _span("root0000", parent_span_id=None, start_second=0)
        children = [_span(f"c000{i}", parent_span_id="root0000", start_second=i + 1)
                    for i in range(6)]
        self._check([root] + children)

    def test_with_orphan(self):
        self._check([
            _span("root0000", parent_span_id=None),
            _span("child001", parent_span_id="root0000"),
            _span("orphan0a", parent_span_id="missing1"),
        ])

    def test_with_two_node_cycle(self):
        self._check([
            _span("aaaa0000", parent_span_id="bbbb0000"),
            _span("bbbb0000", parent_span_id="aaaa0000"),
        ])

    def test_mixed_roots_orphans_cycles(self):
        self._check([
            _span("root0000", parent_span_id=None, start_second=0),
            _span("child001", parent_span_id="root0000", start_second=1),
            _span("orphan0a", parent_span_id="missing1", start_second=2),
            _span("aaaa0000", parent_span_id="bbbb0000", start_second=3),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=4),
        ])


# ---------------------------------------------------------------------------
# R14 — Orphan with descendant
# ---------------------------------------------------------------------------

class TestOrphanWithDescendant:
    def test_descendant_attached_to_orphan(self):
        spans = [
            _span("orphan0a", parent_span_id="missing1", start_second=0),
            _span("child001", parent_span_id="orphan0a", start_second=1),
        ]
        r = build_trace_tree(spans)
        assert len(r.orphans) == 1
        assert r.orphans[0].span.span_id == "orphan0a"
        assert len(r.orphans[0].children) == 1
        assert r.orphans[0].children[0].span.span_id == "child001"

    def test_only_one_orphan_root(self):
        spans = [
            _span("orphan0a", parent_span_id="missing1"),
            _span("child001", parent_span_id="orphan0a"),
        ]
        r = build_trace_tree(spans)
        assert len(r.orphans) == 1

    def test_coverage(self):
        spans = [
            _span("orphan0a", parent_span_id="missing1"),
            _span("child001", parent_span_id="orphan0a"),
        ]
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)


# ---------------------------------------------------------------------------
# R15 — Non-cycle node connected to cycle must NOT be flagged
# (C.parent=A, A↔B cycle; C is not in the cycle)
# ---------------------------------------------------------------------------

class TestNonCycleNodeConnectedToCycle:
    def _spans(self) -> list[SpanRecord]:
        return [
            _span("aaaa0000", parent_span_id="bbbb0000", start_second=0),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=1),
            _span("cccc0000", parent_span_id="aaaa0000", start_second=2),
        ]

    def test_cycle_detected(self):
        r = build_trace_tree(self._spans())
        assert r.has_cycle is True

    def test_aaaa_is_cycle_member(self):
        r = build_trace_tree(self._spans())
        node = _find_node(r.cycle_members, "aaaa0000")
        assert node is not None
        assert node.is_cycle_member is True

    def test_bbbb_is_cycle_member(self):
        r = build_trace_tree(self._spans())
        node = _find_node(r.cycle_members, "bbbb0000")
        assert node is not None
        assert node.is_cycle_member is True

    def test_cccc_is_not_cycle_member(self):
        r = build_trace_tree(self._spans())
        node = _find_node(r.cycle_members, "cccc0000")
        assert node is not None, "cccc0000 must appear in reconstruction"
        assert node.is_cycle_member is False, (
            "cccc0000 is connected to a cycle but is not inside it"
        )

    def test_all_spans_present(self):
        spans = self._spans()
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)


# ---------------------------------------------------------------------------
# R16–R19 — trace_duration_ms calculation
# ---------------------------------------------------------------------------

class TestTraceDurationMs:
    def test_single_span_equals_duration_ms(self):
        spans = [_span("root0000", parent_span_id=None,
                       start_second=0, duration_ms=1850.0)]
        r = build_trace_tree(spans)
        assert abs(r.trace_duration_ms - 1850.0) < 0.001

    def test_sequential_spans_wall_clock(self):
        # root: 0ms–1850ms; children are within that window
        # Wall-clock = max(end) - min(start) = 1850ms
        root = _span("root0000", parent_span_id=None,
                     start_second=0, duration_ms=1850.0)
        c1 = _span("c0000001", parent_span_id="root0000",
                   start_second=0, duration_ms=12.0)
        c2 = _span("c0000002", parent_span_id="root0000",
                   start_second=1, duration_ms=95.0)
        r = build_trace_tree([root, c1, c2])
        assert abs(r.trace_duration_ms - 1850.0) < 0.001

    def test_overlapping_spans_less_than_sum(self):
        # span_a: T+0ms to T+1000ms (1000ms)
        # span_b: T+500ms to T+1200ms (700ms)
        # Wall-clock envelope: T+0ms to T+1200ms = 1200ms
        # Sum of durations = 1700ms > wall-clock
        t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        span_a = SpanRecord(
            span_id="aaaa0000", parent_span_id=None,
            span_name="op_a", service_name="svc",
            start_time=t0,
            end_time=t0 + timedelta(milliseconds=1000),
            duration_ms=1000.0,
            status_code="OK",
        )
        span_b = SpanRecord(
            span_id="bbbb0000", parent_span_id=None,
            span_name="op_b", service_name="svc",
            start_time=t0 + timedelta(milliseconds=500),
            end_time=t0 + timedelta(milliseconds=1200),
            duration_ms=700.0,
            status_code="OK",
        )
        r = build_trace_tree([span_a, span_b])
        assert abs(r.trace_duration_ms - 1200.0) < 0.001

    def test_empty_trace_duration_is_zero(self):
        r = build_trace_tree([])
        assert r.trace_duration_ms == 0.0

    def test_zero_duration_spans(self):
        # Both spans have duration=0 and start=end=T0
        t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        span_a = SpanRecord(
            span_id="aaaa0000", parent_span_id=None,
            span_name="op", service_name="svc",
            start_time=t0, end_time=t0, duration_ms=0.0, status_code="OK",
        )
        span_b = SpanRecord(
            span_id="bbbb0000", parent_span_id=None,
            span_name="op", service_name="svc",
            start_time=t0, end_time=t0, duration_ms=0.0, status_code="OK",
        )
        r = build_trace_tree([span_a, span_b])
        assert r.trace_duration_ms == 0.0


# ---------------------------------------------------------------------------
# R20–R23 — Depth calculation
# ---------------------------------------------------------------------------

class TestDepthCalculation:
    def test_star_topology_root_depth_zero(self):
        root = _span("root0000", parent_span_id=None, start_second=0)
        children = [_span(f"c000{i}", parent_span_id="root0000", start_second=i + 1)
                    for i in range(3)]
        r = build_trace_tree([root] + children)
        assert r.roots[0].depth == 0

    def test_star_topology_children_depth_one(self):
        root = _span("root0000", parent_span_id=None, start_second=0)
        children = [_span(f"c000{i}", parent_span_id="root0000", start_second=i + 1)
                    for i in range(3)]
        r = build_trace_tree([root] + children)
        for child in r.roots[0].children:
            assert child.depth == 1

    def test_nested_chain_depths(self):
        spans = [
            _span("root0000", parent_span_id=None, start_second=0),
            _span("aaaa0001", parent_span_id="root0000", start_second=1),
            _span("bbbb0002", parent_span_id="aaaa0001", start_second=2),
            _span("cccc0003", parent_span_id="bbbb0002", start_second=3),
        ]
        r = build_trace_tree(spans)
        root_node = r.roots[0]
        a_node = root_node.children[0]
        b_node = a_node.children[0]
        c_node = b_node.children[0]
        assert root_node.depth == 0
        assert a_node.depth == 1
        assert b_node.depth == 2
        assert c_node.depth == 3

    def test_orphan_root_has_depth_zero(self):
        spans = [
            _span("orphan0a", parent_span_id="missing1", start_second=0),
            _span("child001", parent_span_id="orphan0a", start_second=1),
        ]
        r = build_trace_tree(spans)
        orphan_node = r.orphans[0]
        assert orphan_node.depth == 0
        assert orphan_node.children[0].depth == 1

    def test_cycle_synthetic_root_has_depth_zero(self):
        spans = [
            _span("aaaa0000", parent_span_id="bbbb0000", start_second=0),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=1),
        ]
        r = build_trace_tree(spans)
        # Synthetic root is lexicographically smallest: "aaaa0000"
        assert r.cycle_members[0].depth == 0

    def test_multiple_roots_each_depth_zero(self):
        spans = [
            _span("root0001", parent_span_id=None, start_second=0),
            _span("root0002", parent_span_id=None, start_second=1),
        ]
        r = build_trace_tree(spans)
        assert r.roots[0].depth == 0
        assert r.roots[1].depth == 0

    def test_depth_independent_of_input_order(self):
        spans = [
            _span("root0000", parent_span_id=None, start_second=0),
            _span("aaaa0001", parent_span_id="root0000", start_second=1),
            _span("bbbb0002", parent_span_id="aaaa0001", start_second=2),
        ]
        for seed in range(5):
            shuffled = list(spans)
            random.seed(seed)
            random.shuffle(shuffled)
            r = build_trace_tree(shuffled)
            a_node = _find_node(r.roots, "aaaa0001")
            b_node = _find_node(r.roots, "bbbb0002")
            assert a_node is not None and a_node.depth == 1
            assert b_node is not None and b_node.depth == 2

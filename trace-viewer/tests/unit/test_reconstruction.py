"""
trace-viewer/tests/unit/test_reconstruction.py

Unit tests for reconstruction.py.

All tests are pure Python — no database, no network, no I/O.

Test inventory (13 required cases + extras):
    T01  Normal AgentOps star topology (7 spans: root + 6 children)
    T02  Shuffled / reversed input order → same tree as T01
    T03  Nested arbitrary-depth hierarchy (root → A → B → C)
    T04  Root-only trace (single span, parent_span_id=None)
    T05  Multiple natural roots
    T06  Missing-parent orphan
    T07  Two-node cycle (A↔B, no natural root)
    T08  Longer cycle (A→B→C→A, no natural root)
    T09  Duplicate span_id → ValueError
    T10  Multiple trace_id → ValueError
    T11  Equal start_time tie-breaking by span_id (deterministic sibling order)
    T12  Empty input → empty TraceReconstruction
    T13  All spans accounted for exactly once (coverage invariant)
    T14  Orphan with descendant: missing parent, but the orphan has a child
    T15  Cycle member with non-cycle tail attached
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Optional

import pytest

from reconstruction import (
    SpanRecord,
    TraceNode,
    TraceReconstruction,
    build_trace_tree,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dt(minute: int = 0, second: int = 0) -> datetime:
    """Return a UTC datetime for 2026-01-01T00:<minute>:<second>Z."""
    return datetime(2026, 1, 1, 0, minute, second, tzinfo=timezone.utc)


def _span(
    span_id: str,
    parent_span_id: Optional[str] = None,
    span_name: str = "op",
    start_minute: int = 0,
    start_second: int = 0,
    trace_id: Optional[str] = None,
) -> SpanRecord:
    start = _dt(start_minute, start_second)
    return SpanRecord(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name=span_name,
        start_time=start,
        end_time=start,
        duration_ms=0.0,
        status_code="OK",
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
# T01 — Normal AgentOps star topology
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
# T02 — Input order independence
# ---------------------------------------------------------------------------

class TestInputOrderIndependence:
    """Reversed and shuffled input must produce the same tree."""

    def _canonical_spans(self) -> list[SpanRecord]:
        root = _span("root0000", parent_span_id=None, start_second=0)
        c1 = _span("child001", parent_span_id="root0000", start_second=1)
        c2 = _span("child002", parent_span_id="root0000", start_second=2)
        c3 = _span("child003", parent_span_id="root0000", start_second=3)
        return [root, c1, c2, c3]

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

    def test_root_identified_regardless_of_position(self):
        spans = self._canonical_spans()
        for i in range(len(spans)):
            reordered = spans[i:] + spans[:i]
            r = build_trace_tree(reordered)
            assert len(r.roots) == 1
            assert r.roots[0].span.span_id == "root0000"


# ---------------------------------------------------------------------------
# T03 — Nested arbitrary-depth hierarchy
# ---------------------------------------------------------------------------

class TestNestedHierarchy:
    """Linear chain: root → A → B → C (4 levels deep)."""

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

    def test_depth_4_chain(self):
        r = build_trace_tree(self._spans())
        root_node = r.roots[0]
        assert len(root_node.children) == 1
        a_node = root_node.children[0]
        assert a_node.span.span_id == "aaaa0001"
        assert len(a_node.children) == 1
        b_node = a_node.children[0]
        assert b_node.span.span_id == "bbbb0002"
        assert len(b_node.children) == 1
        c_node = b_node.children[0]
        assert c_node.span.span_id == "cccc0003"
        assert c_node.children == []

    def test_no_orphans_no_cycles(self):
        r = build_trace_tree(self._spans())
        assert r.orphans == []
        assert r.cycle_members == []
        assert r.has_cycle is False

    def test_span_count(self):
        r = build_trace_tree(self._spans())
        assert r.span_count == 4


# ---------------------------------------------------------------------------
# T04 — Root-only trace
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

    def test_root_node_not_cycle_member(self):
        spans = [_span("root0000", parent_span_id=None)]
        r = build_trace_tree(spans)
        assert r.roots[0].is_cycle_member is False


# ---------------------------------------------------------------------------
# T05 — Multiple natural roots
# ---------------------------------------------------------------------------

class TestMultipleNaturalRoots:
    """Two independent root spans in the same reconstruction call."""

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

    def test_children_attached_to_correct_root(self):
        spans = [
            _span("root0001", parent_span_id=None, start_second=0),
            _span("root0002", parent_span_id=None, start_second=1),
            _span("child001", parent_span_id="root0001", start_second=2),
            _span("child002", parent_span_id="root0002", start_second=3),
        ]
        r = build_trace_tree(spans)
        r1 = next(n for n in r.roots if n.span.span_id == "root0001")
        r2 = next(n for n in r.roots if n.span.span_id == "root0002")
        assert [c.span.span_id for c in r1.children] == ["child001"]
        assert [c.span.span_id for c in r2.children] == ["child002"]

    def test_no_orphans_no_cycles(self):
        spans = [
            _span("root0001", parent_span_id=None),
            _span("root0002", parent_span_id=None),
        ]
        r = build_trace_tree(spans)
        assert r.orphans == []
        assert r.has_cycle is False


# ---------------------------------------------------------------------------
# T06 — Missing-parent orphan
# ---------------------------------------------------------------------------

class TestMissingParentOrphan:
    """Span whose parent_span_id references a span not present in the input."""

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

    def test_orphan_with_valid_root_in_same_call(self):
        """Orphan and natural root coexist without contaminating each other."""
        spans = [
            _span("root0000", parent_span_id=None, start_second=0),
            _span("child001", parent_span_id="root0000", start_second=1),
            _span("orphan0a", parent_span_id="missing1", start_second=2),
        ]
        r = build_trace_tree(spans)
        assert len(r.roots) == 1
        assert len(r.roots[0].children) == 1
        assert len(r.orphans) == 1

    def test_span_count_includes_orphan(self):
        spans = [_span("orphan0a", parent_span_id="missing1")]
        r = build_trace_tree(spans)
        assert r.span_count == 1


# ---------------------------------------------------------------------------
# T07 — Two-node cycle, no natural root
# ---------------------------------------------------------------------------

class TestTwoNodeCycle:
    """A.parent=B, B.parent=A — pure cycle with no escape to a NULL root."""

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

    def test_cycle_members_flagged(self):
        r = build_trace_tree(self._spans())

        def all_flagged(node: TraceNode) -> bool:
            if not node.is_cycle_member:
                return False
            return all(all_flagged(c) for c in node.children)

        assert all(all_flagged(n) for n in r.cycle_members)

    def test_synthetic_root_is_lexicographically_smallest(self):
        r = build_trace_tree(self._spans())
        # "aaaa0000" < "bbbb0000"
        assert r.cycle_members[0].span.span_id == "aaaa0000"

    def test_exact_cycle_membership(self):
        """Both spans are cycle members; no non-cycle bystanders exist here."""
        r = build_trace_tree(self._spans())
        all_nodes = _all_span_ids(r.cycle_members[0])
        assert sorted(all_nodes) == ["aaaa0000", "bbbb0000"]
        for sid in all_nodes:
            node = _find_node(r.cycle_members, sid)
            assert node is not None
            assert node.is_cycle_member is True, (
                f"{sid} should be a cycle member in a pure A↔B cycle"
            )


# ---------------------------------------------------------------------------
# T08 — Longer cycle (A→B→C→A)
# ---------------------------------------------------------------------------

class TestLongerCycle:
    """Three-span cycle: aaaa.parent=cccc, bbbb.parent=aaaa, cccc.parent=bbbb."""

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
        ids = sorted(_all_ids_in(r))
        for sid in ids:
            node = _find_node(r.cycle_members, sid)
            assert node is not None
            assert node.is_cycle_member is True

    def test_span_count(self):
        r = build_trace_tree(self._spans())
        assert r.span_count == 3

    def test_exact_cycle_membership(self):
        """All three spans in the A→B→C→A cycle are cycle members."""
        r = build_trace_tree(self._spans())
        for sid in ["aaaa0000", "bbbb0000", "cccc0000"]:
            node = _find_node(r.cycle_members, sid)
            assert node is not None, f"{sid} not found in cycle_members tree"
            assert node.is_cycle_member is True, (
                f"{sid} should be a cycle member in A→B→C→A"
            )


# ---------------------------------------------------------------------------
# T09 — Duplicate span_id raises ValueError
# ---------------------------------------------------------------------------

class TestDuplicateSpanId:
    def test_duplicate_raises_value_error(self):
        spans = [
            _span("aaaa0000", parent_span_id=None, start_second=0),
            _span("aaaa0000", parent_span_id=None, start_second=1),
        ]
        with pytest.raises(ValueError, match="Duplicate span_id"):
            build_trace_tree(spans)

    def test_duplicate_message_includes_span_id(self):
        spans = [
            _span("aaaa0000", parent_span_id=None),
            _span("aaaa0000", parent_span_id=None),
        ]
        with pytest.raises(ValueError, match="aaaa0000"):
            build_trace_tree(spans)

    def test_no_false_positive_with_unique_ids(self):
        spans = [
            _span("aaaa0000", parent_span_id=None),
            _span("bbbb0000", parent_span_id=None),
        ]
        r = build_trace_tree(spans)
        assert r.span_count == 2


# ---------------------------------------------------------------------------
# T10 — Multiple trace_ids raise ValueError
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

    def test_none_trace_id_ignored_in_validation(self):
        """Spans without trace_id don't count toward the cross-trace check."""
        spans = [
            _span("aaaa0000", trace_id="trace001"),
            _span("bbbb0000", trace_id=None),
        ]
        r = build_trace_tree(spans)
        assert r.span_count == 2


# ---------------------------------------------------------------------------
# T11 — Equal start_time tie-breaking by span_id
# ---------------------------------------------------------------------------

class TestEqualStartTimeTieBreaking:
    """When siblings share start_time, the sort falls back to span_id ASC."""

    def test_siblings_sorted_by_span_id_when_times_equal(self):
        same_time = _dt(0, 5)
        root = _span("root0000", parent_span_id=None, start_second=0)
        # Deliberately build in reverse span_id order
        c_z = SpanRecord(
            span_id="zzzz0000", parent_span_id="root0000",
            span_name="z", start_time=same_time, end_time=same_time,
            duration_ms=0.0, status_code="OK",
        )
        c_a = SpanRecord(
            span_id="aaaa0000", parent_span_id="root0000",
            span_name="a", start_time=same_time, end_time=same_time,
            duration_ms=0.0, status_code="OK",
        )
        c_m = SpanRecord(
            span_id="mmmm0000", parent_span_id="root0000",
            span_name="m", start_time=same_time, end_time=same_time,
            duration_ms=0.0, status_code="OK",
        )
        spans = [root, c_z, c_m, c_a]
        r = build_trace_tree(spans)
        child_ids = [c.span.span_id for c in r.roots[0].children]
        assert child_ids == ["aaaa0000", "mmmm0000", "zzzz0000"]

    def test_tie_breaking_is_stable_across_input_orders(self):
        """Shuffled input must produce the same sibling order."""
        same_time = _dt(0, 5)
        root = _span("root0000", parent_span_id=None, start_second=0)
        siblings = [
            SpanRecord(
                span_id=f"sid{i:04d}", parent_span_id="root0000",
                span_name="s", start_time=same_time, end_time=same_time,
                duration_ms=0.0, status_code="OK",
            )
            for i in range(5, 0, -1)
        ]
        expected_order = sorted(s.span_id for s in siblings)

        for seed in range(5):
            shuffled = [root] + list(siblings)
            random.seed(seed)
            random.shuffle(shuffled)
            r = build_trace_tree(shuffled)
            child_ids = [c.span.span_id for c in r.roots[0].children]
            assert child_ids == expected_order, f"seed={seed}"


# ---------------------------------------------------------------------------
# T12 — Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_returns_empty_reconstruction(self):
        r = build_trace_tree([])
        assert r.roots == []
        assert r.orphans == []
        assert r.cycle_members == []
        assert r.has_cycle is False
        assert r.span_count == 0

    def test_empty_does_not_raise(self):
        build_trace_tree([])  # must not raise


# ---------------------------------------------------------------------------
# T13 — All spans accounted for exactly once (coverage invariant)
# ---------------------------------------------------------------------------

class TestCoverageInvariant:
    """Every span in the input appears exactly once in the output."""

    def _check(self, spans: list[SpanRecord]) -> None:
        r = build_trace_tree(spans)
        all_ids = _all_ids_in(r)
        input_ids = [s.span_id for s in spans]
        assert sorted(all_ids) == sorted(input_ids), (
            f"Coverage mismatch.\n  input:  {sorted(input_ids)}\n"
            f"  output: {sorted(all_ids)}"
        )
        # No duplicates in output
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

    def test_with_longer_cycle(self):
        self._check([
            _span("aaaa0000", parent_span_id="cccc0000"),
            _span("bbbb0000", parent_span_id="aaaa0000"),
            _span("cccc0000", parent_span_id="bbbb0000"),
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
# T14 — Orphan with a valid descendant
# ---------------------------------------------------------------------------

class TestOrphanWithDescendant:
    """Orphan's parent is missing, but the orphan itself has children."""

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

    def test_descendant_not_in_orphans_list_directly(self):
        """The descendant must appear as a child, not as a separate orphan root."""
        spans = [
            _span("orphan0a", parent_span_id="missing1"),
            _span("child001", parent_span_id="orphan0a"),
        ]
        r = build_trace_tree(spans)
        assert len(r.orphans) == 1  # only the actual orphan root

    def test_coverage(self):
        spans = [
            _span("orphan0a", parent_span_id="missing1"),
            _span("child001", parent_span_id="orphan0a"),
        ]
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)


# ---------------------------------------------------------------------------
# T16 — Exact cycle membership: connected non-cycle node must NOT be flagged
# ---------------------------------------------------------------------------

class TestNonCycleNodeConnectedToCycle:
    """
    C.parent = A
    A.parent = B   ← A and B form the cycle
    B.parent = A

    A and B are cycle members.
    C must NOT be flagged as a cycle member even though it shares the
    same disconnected component.

    This is the canonical case that distinguishes correct 3-color DFS
    cycle detection from the incorrect approach of marking every node
    in a disconnected component as a cycle member.
    """

    def _spans(self) -> list[SpanRecord]:
        return [
            _span("aaaa0000", parent_span_id="bbbb0000", start_second=0),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=1),
            _span("cccc0000", parent_span_id="aaaa0000", start_second=2),
        ]

    def test_cycle_detected(self):
        r = build_trace_tree(self._spans())
        assert r.has_cycle is True

    def test_no_natural_roots_no_orphans(self):
        r = build_trace_tree(self._spans())
        assert r.roots == []
        assert r.orphans == []

    def test_all_spans_present(self):
        spans = self._spans()
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)

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
        """C hangs off A but is not in the A↔B cycle itself."""
        r = build_trace_tree(self._spans())
        node = _find_node(r.cycle_members, "cccc0000")
        assert node is not None, "cccc0000 must appear in the reconstruction"
        assert node.is_cycle_member is False, (
            "cccc0000 is connected to a cycle but is not inside it"
        )

    def test_span_count(self):
        r = build_trace_tree(self._spans())
        assert r.span_count == 3


# ---------------------------------------------------------------------------
# T15 — Cycle member with a non-cycle "tail" attached
# ---------------------------------------------------------------------------

class TestCycleMemberWithTail:
    """
    Cycle: aaaa.parent=bbbb, bbbb.parent=aaaa
    Tail:  tail0000.parent=aaaa (not in the cycle itself)

    After reconstruction, tail0000 should appear as a child of aaaa
    within the cycle component.
    """

    def _spans(self) -> list[SpanRecord]:
        return [
            _span("aaaa0000", parent_span_id="bbbb0000", start_second=0),
            _span("bbbb0000", parent_span_id="aaaa0000", start_second=1),
            _span("tail0000", parent_span_id="aaaa0000", start_second=2),
        ]

    def test_cycle_detected(self):
        r = build_trace_tree(self._spans())
        assert r.has_cycle is True

    def test_all_spans_accounted_for(self):
        spans = self._spans()
        r = build_trace_tree(spans)
        assert sorted(_all_ids_in(r)) == sorted(s.span_id for s in spans)

    def test_tail_is_child_of_cycle_member(self):
        r = build_trace_tree(self._spans())
        aaaa_node = _find_node(r.cycle_members, "aaaa0000")
        assert aaaa_node is not None
        child_ids = [c.span.span_id for c in aaaa_node.children]
        assert "tail0000" in child_ids or _find_node(r.cycle_members, "tail0000") is not None

    def test_exact_cycle_membership_tail_not_flagged(self):
        """aaaa and bbbb form the cycle; tail hangs off aaaa but is NOT in it."""
        r = build_trace_tree(self._spans())
        # Cycle participants must be flagged
        aaaa = _find_node(r.cycle_members, "aaaa0000")
        bbbb = _find_node(r.cycle_members, "bbbb0000")
        assert aaaa is not None and aaaa.is_cycle_member is True
        assert bbbb is not None and bbbb.is_cycle_member is True
        # Tail is connected to the component but is NOT inside the cycle
        tail = _find_node(r.cycle_members, "tail0000")
        assert tail is not None, "tail0000 must still appear in the tree"
        assert tail.is_cycle_member is False, (
            "tail0000 connects to a cycle member but is not itself in the cycle"
        )


# ===========================================================================
# Phase 14.6.1: the depth-first walk is iterative (no recursion limit)
#
# _dfs used to call itself once per level, so a trace nested about a thousand
# spans deep raised RecursionError (an HTTP 500 in the viewer).  It now uses an
# explicit stack.  These tests pin that the result is exactly the recursive
# definition's, by comparing with a copy of the original recursive code.
# ===========================================================================

import reconstruction as _reconstruction


def _dfs_recursive_reference(span_id, children_map, span_by_id, color, path, cycle_ids):
    """A verbatim copy of the recursive _dfs that this module used before 14.6.1."""
    color[span_id] = "gray"
    path.append(span_id)
    child_nodes = []
    for child_span in sorted(children_map.get(span_id, []), key=_reconstruction._sort_key):
        cid = child_span.span_id
        state = color[cid]
        if state == "white":
            child_nodes.append(
                _dfs_recursive_reference(cid, children_map, span_by_id, color, path, cycle_ids))
        elif state == "gray":
            idx = path.index(cid)
            cycle_ids.update(path[idx:])
    path.pop()
    color[span_id] = "black"
    return TraceNode(span=span_by_id[span_id], children=child_nodes, is_cycle_member=(span_id in cycle_ids))


def _shape(nodes: list[TraceNode]):
    """Nested (span_id, is_cycle_member, children) tuples, built without recursion."""
    root = []
    work = [(n, root) for n in nodes]
    while work:
        node, out = work.pop()
        entry = (node.span.span_id, node.is_cycle_member, [])
        out.append(entry)
        work.extend((c, entry[2]) for c in node.children)
    return root


def _summary(result: TraceReconstruction):
    return (_shape(result.roots), _shape(result.orphans), _shape(result.cycle_members),
            result.has_cycle, result.span_count)


def _equal_shapes(a, b) -> bool:
    stack = [(a, b)]
    while stack:
        x, y = stack.pop()
        if isinstance(x, list):
            if not isinstance(y, list) or len(x) != len(y):
                return False
            stack.extend(zip(x, y))
        elif isinstance(x, tuple):
            if not isinstance(y, tuple) or x[:2] != y[:2]:
                return False
            stack.append((x[2], y[2]))
        elif x != y:
            return False
    return True


class TestIterativeWalkMatchesTheRecursiveDefinition:
    @pytest.mark.parametrize("seed", range(60))
    def test_random_graphs_give_identical_trees(self, seed, monkeypatch):
        rng = random.Random(seed)
        n = rng.randint(1, 14)
        ids = [f"{i + 1:016x}" for i in range(n)]
        spans = []
        for i, span_id in enumerate(ids):
            kind = rng.random()
            if kind < 0.15:
                parent = None                                   # a root
            elif kind < 0.25:
                parent = "ffffffffffffffff"                     # an orphan (parent absent)
            else:
                parent = rng.choice(ids)                        # anything: cross edges, cycles, self-parent
            spans.append(_span(span_id, parent, start_minute=rng.randint(0, 3), start_second=rng.randint(0, 5)))
        rng.shuffle(spans)
        iterative = _summary(build_trace_tree(spans))
        monkeypatch.setattr(_reconstruction, "_dfs", _dfs_recursive_reference)
        recursive = _summary(build_trace_tree(spans))
        assert _equal_shapes(iterative, recursive), seed

    def test_known_cycle_cases_are_identical(self, monkeypatch):
        cases = [
            [_span("a", "a")],                                                    # self-parent
            [_span("a", "b"), _span("b", "a")],                                   # two-cycle, disconnected
            [_span("r"), _span("a", "r"), _span("b", "a"), _span("c", "b"), _span("b2", "c")],
            [_span("r"), _span("a", "r"), _span("b", "a"), _span("a2", "b")],
        ]
        for spans in cases:
            iterative = _summary(build_trace_tree(spans))
            monkeypatch.setattr(_reconstruction, "_dfs", _dfs_recursive_reference)
            recursive = _summary(build_trace_tree(spans))
            monkeypatch.undo()
            assert _equal_shapes(iterative, recursive)


class TestDeepTraces:
    def _chain(self, n: int) -> list[SpanRecord]:
        return [_span(f"{i + 1:016x}", None if i == 0 else f"{i:016x}", start_minute=(i // 60) % 60, start_second=i % 60)
                for i in range(n)]

    @pytest.mark.parametrize("n", [500, 2000, 10000])
    def test_a_chain_far_deeper_than_the_recursion_limit_is_reconstructed(self, n):
        result = build_trace_tree(self._chain(n))
        assert result.span_count == n and result.has_cycle is False
        assert len(result.roots) == 1 and result.orphans == [] and result.cycle_members == []
        depth, node = 1, result.roots[0]
        while node.children:
            assert len(node.children) == 1
            node, depth = node.children[0], depth + 1
        assert depth == n and node.span.span_id == f"{n:016x}"

    def test_a_long_cycle_is_detected_without_recursion_error(self):
        n = 3000
        spans = [_span(f"{i + 1:016x}", f"{(i - 1) % n + 1:016x}") for i in range(n)]   # a ring: no root at all
        result = build_trace_tree(spans)
        assert result.span_count == n and result.has_cycle is True and result.roots == [] and result.orphans == []
        assert len(result.cycle_members) == 1
        ids = []
        stack = list(result.cycle_members)
        while stack:
            node = stack.pop()
            ids.append(node.span.span_id)
            assert node.is_cycle_member is True
            stack.extend(node.children)
        assert sorted(ids) == sorted(s.span_id for s in spans)

    def test_a_deep_chain_of_orphans_is_reconstructed(self):
        spans = self._chain(1500)
        spans[0] = _span(spans[0].span_id, "ffffffffffffffff")          # the first span's parent is missing
        result = build_trace_tree(spans)
        assert result.roots == [] and len(result.orphans) == 1 and result.span_count == 1500

    def test_the_wide_trace_is_unchanged(self):
        spans = [_span("ffffffffffffff00")] + [_span(f"{i + 1:016x}", "ffffffffffffff00", start_second=i % 60) for i in range(2000)]
        result = build_trace_tree(spans)
        assert len(result.roots) == 1 and len(result.roots[0].children) == 2000 and not result.has_cycle

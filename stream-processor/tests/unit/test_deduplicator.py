"""
tests/unit/test_deduplicator.py

Unit tests for deduplicator.py.

No demo-app/ on PYTHONPATH is required — SpanDeduplicator has no
demo-app dependency.
"""

from __future__ import annotations

import pytest

from deduplicator import SpanDeduplicator

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

TID_A = "0102030405060708090a0b0c0d0e0f10"
TID_B = "1112131415161718191a1b1c1d1e1f20"
SID_A = "0102030405060708"
SID_B = "1112131415161718"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_positive_max_size_succeeds(self):
        d = SpanDeduplicator(max_size=10)
        assert d is not None

    def test_zero_max_size_succeeds(self):
        d = SpanDeduplicator(max_size=0)
        assert d is not None

    def test_negative_max_size_raises_value_error(self):
        with pytest.raises(ValueError, match="max_size"):
            SpanDeduplicator(max_size=-1)

    def test_large_max_size_succeeds(self):
        d = SpanDeduplicator(max_size=1_000_000)
        assert d is not None


# ---------------------------------------------------------------------------
# First-seen behavior
# ---------------------------------------------------------------------------


class TestFirstSeen:
    def test_new_span_returns_false(self):
        d = SpanDeduplicator(max_size=10)
        assert d.is_duplicate(TID_A, SID_A) is False

    def test_second_distinct_span_also_returns_false(self):
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        assert d.is_duplicate(TID_B, SID_B) is False

    def test_multiple_distinct_spans_all_return_false_on_first_call(self):
        d = SpanDeduplicator(max_size=100)
        results = [d.is_duplicate(TID_A, f"{i:016x}") for i in range(50)]
        assert all(r is False for r in results)


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------


class TestDuplicate:
    def test_same_span_on_second_call_returns_true(self):
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        assert d.is_duplicate(TID_A, SID_A) is True

    def test_repeated_duplicate_calls_all_return_true(self):
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        for _ in range(5):
            assert d.is_duplicate(TID_A, SID_A) is True


# ---------------------------------------------------------------------------
# Identity: both trace_id and span_id participate
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_same_trace_id_different_span_id_are_distinct(self):
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        # Same trace_id, different span_id — must NOT be a duplicate
        assert d.is_duplicate(TID_A, SID_B) is False

    def test_different_trace_id_same_span_id_are_distinct(self):
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        # Different trace_id, same span_id — must NOT be a duplicate
        assert d.is_duplicate(TID_B, SID_A) is False

    def test_both_fields_must_match_to_be_duplicate(self):
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        assert d.is_duplicate(TID_B, SID_B) is False   # neither matches
        assert d.is_duplicate(TID_A, SID_B) is False   # trace matches, span does not
        assert d.is_duplicate(TID_B, SID_A) is False   # span matches, trace does not
        assert d.is_duplicate(TID_A, SID_A) is True    # both match — duplicate

    def test_extra_context_fields_are_irrelevant_to_api(self):
        """
        Callers may have other fields on the span; only the two string
        arguments passed to is_duplicate matter.
        """
        d = SpanDeduplicator(max_size=10)
        d.is_duplicate(TID_A, SID_A)
        # Call with same identity regardless of any other event-level context
        assert d.is_duplicate(TID_A, SID_A) is True


# ---------------------------------------------------------------------------
# LRU eviction
# ---------------------------------------------------------------------------


class TestLRUEviction:
    def test_lru_entry_evicted_at_capacity(self):
        d = SpanDeduplicator(max_size=3)
        # Insert three entries: A, B, C (A is LRU)
        d.is_duplicate(TID_A, SID_A)  # key 0 — LRU
        d.is_duplicate(TID_A, SID_B)  # key 1
        d.is_duplicate(TID_B, SID_A)  # key 2 — MRU
        # Adding a fourth evicts key 0 (LRU = TID_A, SID_A)
        d.is_duplicate(TID_B, SID_B)  # key 3, triggers eviction of key 0
        # key 0 should now be gone — returns False (new)
        assert d.is_duplicate(TID_A, SID_A) is False

    def test_non_evicted_entries_still_detected_as_duplicate(self):
        d = SpanDeduplicator(max_size=3)
        d.is_duplicate(TID_A, SID_A)  # LRU
        d.is_duplicate(TID_A, SID_B)
        d.is_duplicate(TID_B, SID_A)  # MRU
        d.is_duplicate(TID_B, SID_B)  # evicts TID_A/SID_A
        # The other two inserted entries survived
        assert d.is_duplicate(TID_A, SID_B) is True
        assert d.is_duplicate(TID_B, SID_A) is True

    def test_exactly_one_entry_evicted_per_new_insertion(self):
        """Each new insertion beyond capacity evicts exactly one entry, not more."""
        d = SpanDeduplicator(max_size=2)
        d.is_duplicate(TID_A, SID_A)  # LRU
        d.is_duplicate(TID_A, SID_B)  # MRU — at capacity
        # Insert a third entry: only the LRU (TID_A/SID_A) is evicted;
        # TID_A/SID_B must survive — confirming exactly one eviction.
        d.is_duplicate(TID_B, SID_A)
        assert d.is_duplicate(TID_A, SID_B) is True


# ---------------------------------------------------------------------------
# Duplicate-hit LRU promotion
# ---------------------------------------------------------------------------


class TestLRUPromotion:
    def test_duplicate_hit_promotes_entry_preventing_eviction(self):
        d = SpanDeduplicator(max_size=3)
        # Insert A (LRU), B, C (MRU)
        d.is_duplicate(TID_A, SID_A)
        d.is_duplicate(TID_A, SID_B)
        d.is_duplicate(TID_B, SID_A)
        # Promote A to MRU by accessing it
        d.is_duplicate(TID_A, SID_A)
        # Now insert a new entry — should evict B (now LRU), not A
        d.is_duplicate(TID_B, SID_B)
        # A was promoted so it should still be present
        assert d.is_duplicate(TID_A, SID_A) is True
        # B (TID_A, SID_B) was LRU and should be evicted
        assert d.is_duplicate(TID_A, SID_B) is False

    def test_repeated_access_keeps_entry_alive_through_many_evictions(self):
        d = SpanDeduplicator(max_size=2)
        d.is_duplicate(TID_A, SID_A)  # anchor entry
        for i in range(20):
            # Each iteration: refresh anchor, then insert a new entry that
            # evicts the previous non-anchor entry
            d.is_duplicate(TID_A, SID_A)           # promote anchor
            d.is_duplicate(TID_B, f"{i:016x}")     # new entry evicts old non-anchor
        # Anchor must still be present after 20 eviction cycles
        assert d.is_duplicate(TID_A, SID_A) is True


# ---------------------------------------------------------------------------
# Edge cases: max_size=1 and max_size=0
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_max_size_1_second_distinct_span_evicts_first(self):
        d = SpanDeduplicator(max_size=1)
        d.is_duplicate(TID_A, SID_A)   # first entry
        d.is_duplicate(TID_A, SID_B)   # second — evicts first (max_size=1)
        # Second entry is now the sole entry; confirm it is detected as duplicate.
        # (If the first had not been evicted, max_size=1 would be violated.)
        assert d.is_duplicate(TID_A, SID_B) is True

    def test_max_size_1_duplicate_is_detected(self):
        d = SpanDeduplicator(max_size=1)
        d.is_duplicate(TID_A, SID_A)
        assert d.is_duplicate(TID_A, SID_A) is True

    def test_max_size_0_always_returns_false(self):
        d = SpanDeduplicator(max_size=0)
        assert d.is_duplicate(TID_A, SID_A) is False
        assert d.is_duplicate(TID_A, SID_A) is False  # second call also False
        assert d.is_duplicate(TID_B, SID_B) is False

    def test_max_size_0_never_accumulates_state(self):
        """max_size=0 should not grow without bound across many calls."""
        d = SpanDeduplicator(max_size=0)
        for i in range(10_000):
            d.is_duplicate(TID_A, f"{i:016x}")
        # No assertion on internal structure; just ensure no exception
        # and all calls returned False (checked via a fresh call)
        assert d.is_duplicate(TID_B, SID_A) is False


# ---------------------------------------------------------------------------
# Bounded size behavior (without inspecting internals)
# ---------------------------------------------------------------------------


class TestBoundedSize:
    def test_size_does_not_grow_beyond_max_size(self):
        """
        Insert 3x max_size distinct spans. The deduplicator must not
        accumulate more than max_size entries; verified indirectly by
        confirming LRU eviction occurred (early entries are no longer
        seen as duplicates) and the most-recently inserted entry remains.

        Verification is limited to two single calls because each
        is_duplicate call that returns False is itself an insertion that
        can trigger further eviction — a loop of "gone" checks would
        displace the entries being checked next.
        """
        max_size = 5
        d = SpanDeduplicator(max_size=max_size)
        ids = [f"{i:016x}" for i in range(max_size * 3)]
        for sid in ids:
            d.is_duplicate(TID_A, sid)
        # The most-recently inserted entry must still be present
        assert d.is_duplicate(TID_A, ids[-1]) is True
        # The first entry must have been evicted by LRU
        assert d.is_duplicate(TID_A, ids[0]) is False


# ---------------------------------------------------------------------------
# Deterministic fixed-sequence test
# ---------------------------------------------------------------------------


class TestDeterministicSequence:
    def test_known_sequence_produces_exact_results(self):
        """
        Fixed sequence of calls with a known pattern of duplicates.
        The expected result list is derived by hand and must match exactly.
        """
        d = SpanDeduplicator(max_size=3)
        calls = [
            (TID_A, SID_A),  # 0: new   → False
            (TID_A, SID_B),  # 1: new   → False
            (TID_B, SID_A),  # 2: new   → False  (capacity reached)
            (TID_A, SID_A),  # 3: dup   → True   (promote A/A to MRU)
            (TID_B, SID_B),  # 4: new   → False  (evicts A/B — was LRU)
            (TID_A, SID_B),  # 5: new   → False  (evicts B/A — was LRU)
            (TID_A, SID_A),  # 6: dup   → True
            (TID_B, SID_B),  # 7: dup   → True
            (TID_A, SID_B),  # 8: dup   → True
        ]
        expected = [False, False, False, True, False, False, True, True, True]
        results = [d.is_duplicate(tid, sid) for tid, sid in calls]
        assert results == expected


# ---------------------------------------------------------------------------
# contains() — pure membership check
# ---------------------------------------------------------------------------


class TestContains:
    def test_contains_unknown_returns_false(self):
        d = SpanDeduplicator(max_size=10)
        assert d.contains(TID_A, SID_A) is False

    def test_contains_after_mark_returns_true(self):
        d = SpanDeduplicator(max_size=10)
        d.mark(TID_A, SID_A)
        assert d.contains(TID_A, SID_A) is True

    def test_contains_does_not_insert(self):
        """contains() on an absent span must not insert it."""
        d = SpanDeduplicator(max_size=10)
        d.contains(TID_A, SID_A)
        # Still absent — a second contains() should still be False
        assert d.contains(TID_A, SID_A) is False

    def test_contains_does_not_change_lru_order(self):
        """contains() must not promote; mark() drives LRU ordering."""
        d = SpanDeduplicator(max_size=2)
        d.mark(TID_A, SID_A)  # (A,A) → LRU
        d.mark(TID_A, SID_B)  # (A,B) → MRU; at capacity

        # contains() on the LRU entry — must not promote it
        assert d.contains(TID_A, SID_A) is True

        # Adding a new entry should evict LRU = (A,A), not (A,B)
        d.mark(TID_B, SID_A)

        assert d.contains(TID_A, SID_A) is False   # was LRU; evicted
        assert d.contains(TID_A, SID_B) is True    # was MRU; survived

    def test_contains_returns_false_for_different_pair(self):
        d = SpanDeduplicator(max_size=10)
        d.mark(TID_A, SID_A)
        # Same trace, different span — distinct key
        assert d.contains(TID_A, SID_B) is False
        # Different trace, same span — distinct key
        assert d.contains(TID_B, SID_A) is False

    def test_contains_max_size_zero_always_false(self):
        d = SpanDeduplicator(max_size=0)
        # mark() is a no-op with max_size=0, so contains() is always False
        d.mark(TID_A, SID_A)
        assert d.contains(TID_A, SID_A) is False
        assert d.contains(TID_B, SID_B) is False


# ---------------------------------------------------------------------------
# mark() — insert / promote with LRU eviction
# ---------------------------------------------------------------------------


class TestMark:
    def test_mark_inserts_new_entry(self):
        d = SpanDeduplicator(max_size=10)
        d.mark(TID_A, SID_A)
        assert d.contains(TID_A, SID_A) is True

    def test_mark_idempotent_membership(self):
        """Calling mark() multiple times keeps the entry present."""
        d = SpanDeduplicator(max_size=10)
        d.mark(TID_A, SID_A)
        d.mark(TID_A, SID_A)
        assert d.contains(TID_A, SID_A) is True

    def test_mark_existing_promotes_to_mru(self):
        """mark() on an existing entry promotes it, preventing eviction."""
        d = SpanDeduplicator(max_size=2)
        d.mark(TID_A, SID_A)  # (A,A) → LRU
        d.mark(TID_A, SID_B)  # (A,B) → MRU; at capacity

        # Re-mark LRU entry — promotes to MRU
        d.mark(TID_A, SID_A)  # now (A,B) is LRU, (A,A) is MRU

        # Adding a new entry should evict the new LRU = (A,B)
        d.mark(TID_B, SID_A)

        assert d.contains(TID_A, SID_B) is False   # was LRU; evicted
        assert d.contains(TID_A, SID_A) is True    # was promoted; survived

    def test_mark_evicts_lru_at_capacity(self):
        d = SpanDeduplicator(max_size=2)
        d.mark(TID_A, SID_A)  # (A,A) → LRU
        d.mark(TID_A, SID_B)  # (A,B) → MRU; at capacity

        d.mark(TID_B, SID_A)  # evicts (A,A), inserts (B,A)

        assert d.contains(TID_A, SID_A) is False   # evicted
        assert d.contains(TID_A, SID_B) is True    # survived
        assert d.contains(TID_B, SID_A) is True    # just marked

    def test_mark_max_size_zero_is_noop(self):
        d = SpanDeduplicator(max_size=0)
        d.mark(TID_A, SID_A)
        # contains() is always False with max_size=0
        assert d.contains(TID_A, SID_A) is False

    def test_mark_multiple_distinct_entries(self):
        d = SpanDeduplicator(max_size=10)
        d.mark(TID_A, SID_A)
        d.mark(TID_A, SID_B)
        d.mark(TID_B, SID_A)
        assert d.contains(TID_A, SID_A) is True
        assert d.contains(TID_A, SID_B) is True
        assert d.contains(TID_B, SID_A) is True
        assert d.contains(TID_B, SID_B) is False

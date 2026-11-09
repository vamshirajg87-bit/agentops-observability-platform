"""
stream-processor/deduplicator.py

Bounded in-memory deduplication for canonical span events.

PURPOSE
-------
Kafka delivers messages at-least-once. A span may be redelivered if the
consumer crashes after publishing output but before committing its offset.
SpanDeduplicator suppresses within-process duplicate deliveries so the
downstream publish step is not called redundantly for the same logical span.

SCOPE AND LIMITATIONS
---------------------
- Process-lifetime only. Restarting the process clears the deduplicator;
  any span replayed across a restart passes through as new.
- This component does NOT provide exactly-once processing. It is a
  best-effort within-process guard.
- Durable idempotent uniqueness is enforced in Phase 6 via a PostgreSQL
  UNIQUE(trace_id, span_id) constraint with ON CONFLICT DO NOTHING.

IDENTITY
--------
Logical identity is exactly (trace_id, span_id). No other fields
(service_name, span_name, attributes, Kafka offset, etc.) affect identity.

MEMORY
------
Memory usage is bounded by max_size. Actual consumption depends on Python
object and container overhead per entry; it grows until max_size entries
are held and stays there under LRU eviction.

THREAD SAFETY
-------------
SpanDeduplicator is NOT thread-safe. It is designed for use from a single
consumer thread. If the processor loop is parallelised, add external locking
at the call site.

DEPENDENCIES
------------
None beyond the Python standard library. No Kafka, DLQ, or demo-app
knowledge.
"""

from __future__ import annotations

from collections import OrderedDict


class SpanDeduplicator:
    """
    Bounded LRU deduplication set keyed on (trace_id, span_id).

    Eviction policy: when max_size is exceeded, the least-recently-seen
    entry is evicted (LRU). A duplicate hit refreshes the entry's position,
    so frequently-replayed spans are not prematurely evicted.

    Setting max_size=0 disables deduplication: is_duplicate always returns
    False and no state is maintained.
    """

    def __init__(self, max_size: int) -> None:
        """
        Args:
            max_size: Maximum number of (trace_id, span_id) pairs to track.
                      0 disables deduplication (is_duplicate always returns False).

        Raises:
            ValueError: if max_size is negative.
        """
        if max_size < 0:
            raise ValueError(
                f"max_size must be >= 0; got {max_size}. "
                "Use max_size=0 to disable deduplication."
            )
        self._max_size = max_size
        self._store: OrderedDict[tuple[str, str], None] = OrderedDict()

    def is_duplicate(self, trace_id: str, span_id: str) -> bool:
        """
        Return True if (trace_id, span_id) has been seen before in this
        process lifetime, False if it is new.

        A True result means the span was already processed by this process
        instance and should be skipped. A False result records the span as
        seen and returns control to the caller to process it.

        Duplicate hits refresh the LRU position of the entry so that a span
        under active replay is not evicted while replays are still arriving.

        When max_size is 0, always returns False without recording anything.

        Args:
            trace_id: Hex trace ID from the canonical span event.
            span_id:  Hex span ID from the canonical span event.

        Returns:
            True if duplicate, False if new.
        """
        if self._max_size == 0:
            return False

        key: tuple[str, str] = (trace_id, span_id)

        if key in self._store:
            self._store.move_to_end(key)
            return True

        if len(self._store) >= self._max_size:
            self._store.popitem(last=False)

        self._store[key] = None
        return False

    def contains(self, trace_id: str, span_id: str) -> bool:
        """
        Return True if (trace_id, span_id) is present in the cache; False otherwise.

        Pure read: no insertion, no LRU promotion, no state change.
        A check must not change cache state — LRU ordering must reflect
        successful mark() activity only.
        When max_size is 0, always returns False.
        """
        if self._max_size == 0:
            return False
        return (trace_id, span_id) in self._store

    def mark(self, trace_id: str, span_id: str) -> None:
        """
        Record (trace_id, span_id) as successfully published.

        Called only after publish_span() returns normally (positive broker ack).

        - max_size == 0: no-op.
        - Existing key: promote to MRU.
        - New key at capacity: evict LRU, then insert.
        - New key below capacity: insert.
        """
        if self._max_size == 0:
            return
        key: tuple[str, str] = (trace_id, span_id)
        if key in self._store:
            self._store.move_to_end(key)
            return
        if len(self._store) >= self._max_size:
            self._store.popitem(last=False)
        self._store[key] = None

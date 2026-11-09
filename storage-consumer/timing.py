"""
storage-consumer/timing.py

Opt-in timing of the storage consumer's per-message stages.

Purpose: show where one message's time goes (Kafka poll, decode and validation,
the PostgreSQL insert transaction, the synchronous Kafka offset commit) so that a
later change can be judged on measured shares rather than on assumption.

This module only measures.  It never changes what the consumer does, never
reads message contents, and writes nothing but numbers: stage names, counts and
durations.  No message body, trace id, span id, credential or connection string
reaches it.  There is one summary line per interval, never one line per message.

Disabled by default (config.TIMING_INTERVAL_SECONDS == 0): the consumer then
holds no recorder and does no timing work.

Memory is bounded: a fixed set of stages, each with a count, a total, a maximum
and a fixed-size histogram.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Callable, Optional

#: The measured stages, in the order of one message's life.
#:   poll             the consumer.poll() call that returned a message
#:   decode_validate  UTF-8 decode, JSON parse and CanonicalSpanEvent validation
#:   insert_txn       the repository.insert_span() call (parameters, BEGIN, INSERT, COMMIT)
#:   kafka_commit     the synchronous consumer.commit() of that message's offset
#:   cycle            from the start of that poll to the end of that commit
#: A stage that raised is not recorded for that message.  Polls that returned no
#: message are counted (idle_polls) and not timed.
STAGES: tuple[str, ...] = ("poll", "decode_validate", "insert_txn", "kafka_commit", "cycle")

#: Upper bounds of the histogram buckets, in milliseconds; a final bucket holds
#: everything above the last bound.  Roughly doubling, so relative shares and a
#: heavy tail are visible without storing samples.
BUCKET_BOUNDS_MS: tuple[float, ...] = (
    0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1000.0, 2000.0)

#: Plain counters kept beside the stages.
COUNTERS: tuple[str, ...] = ("messages", "idle_polls", "inserted", "conflicts")

LINE_PREFIX = "storage-consumer timing "


class _Stage:
    __slots__ = ("count", "total", "maximum", "buckets")

    def __init__(self) -> None:
        self.count = 0
        self.total = 0.0
        self.maximum = 0.0
        self.buckets = [0] * (len(BUCKET_BOUNDS_MS) + 1)

    def add(self, seconds: float) -> None:
        self.count += 1
        self.total += seconds
        if seconds > self.maximum:
            self.maximum = seconds
        milliseconds = seconds * 1000.0
        for index, bound in enumerate(BUCKET_BOUNDS_MS):
            if milliseconds <= bound:
                self.buckets[index] += 1
                return
        self.buckets[-1] += 1

    def as_dict(self) -> dict[str, Any]:
        mean = (self.total / self.count) if self.count else 0.0
        return {"count": self.count, "total_ms": round(self.total * 1000.0, 3),
                "mean_ms": round(mean * 1000.0, 3),
                "max_ms": round(self.maximum * 1000.0, 3), "hist": list(self.buckets)}


class _Accumulator:
    def __init__(self) -> None:
        self.stages = {name: _Stage() for name in STAGES}
        self.counters = {name: 0 for name in COUNTERS}


def _write_line(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


class TimingRecorder:
    """Accumulates stage durations and emits aggregate summaries.

    summary lines (one JSON object after LINE_PREFIX):
      kind "window"  the interval since the previous summary, every interval_seconds
      kind "final"   the whole run, once, when the consumer stops (not written when the
                     process is killed, as the benchmark harness stops it)
    start_epoch_s / end_epoch_s are wall-clock (time.time()) seconds of the window's
    start and end, so a summary can be aligned with benchmark stages; durations are
    always measured with the monotonic clock.
    """

    def __init__(self, interval_seconds: float, *,
                 clock: Callable[[], float] = time.perf_counter,
                 emit: Callable[[str], None] = _write_line,
                 wall: Callable[[], float] = time.time) -> None:
        if not interval_seconds > 0:
            raise ValueError("a TimingRecorder needs a positive interval")
        self.clock = clock
        self._interval = float(interval_seconds)
        self._emit = emit
        self._total = _Accumulator()
        self._window = _Accumulator()
        self._wall = wall
        self._started = clock()
        self._window_started = self._started
        self._started_epoch = wall()          # wall clock, only to align summaries with
        self._window_started_epoch = self._started_epoch   # other evidence; never a duration
        self._final_done = False

    @classmethod
    def from_interval(cls, interval_seconds: float) -> Optional["TimingRecorder"]:
        """None when timing is disabled (interval 0), else a recorder."""
        return cls(interval_seconds) if interval_seconds > 0 else None

    def record(self, stage: str, seconds: float) -> None:
        seconds = seconds if seconds > 0.0 else 0.0
        self._total.stages[stage].add(seconds)
        self._window.stages[stage].add(seconds)

    def count(self, name: str) -> None:
        self._total.counters[name] += 1
        self._window.counters[name] += 1

    def maybe_emit(self) -> None:
        """Emit the window summary when the interval has elapsed.  Never raises."""
        try:
            now = self.clock()
            if now - self._window_started < self._interval:
                return
            epoch = self._wall()
            if self._window.counters["messages"] or self._window.counters["idle_polls"]:
                self._emit(self._line("window", self._window, now - self._window_started,
                                      self._window_started_epoch, epoch))
            self._window = _Accumulator()
            self._window_started = now
            self._window_started_epoch = epoch
        except Exception:  # instrumentation must never disturb processing
            pass

    def final(self) -> None:
        """Emit the whole-run summary once.  Never raises."""
        if self._final_done:
            return
        self._final_done = True
        try:
            self._emit(self._line("final", self._total, self.clock() - self._started,
                                  self._started_epoch, self._wall()))
        except Exception:  # instrumentation must never replace a processing error
            pass

    @staticmethod
    def _line(kind: str, accumulator: _Accumulator, elapsed: float,
              start_epoch: float, end_epoch: float) -> str:
        payload = {
            "kind": kind, "elapsed_s": round(elapsed, 3),
            "start_epoch_s": round(start_epoch, 3), "end_epoch_s": round(end_epoch, 3),
            "bounds_ms": list(BUCKET_BOUNDS_MS),
            "counters": dict(accumulator.counters),
            "stages": {name: stage.as_dict() for name, stage in accumulator.stages.items()},
        }
        return LINE_PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":"))

"""
benchmarks/metrics.py

The arithmetic and the rules of the pipeline benchmark: percentiles, rates,
count reconciliation, clock skew, stop rules, verdicts, and the shape of a
result.

Every function here is pure and deterministic.  Nothing here opens a socket,
a file, a process or a database connection; the orchestrator
(run_benchmark.py) gathers the numbers and hands them in.

Kinds of value
--------------
    MEASURED      read directly from a counter or timestamp of the system
    DERIVED       computed from measured values (a rate, a difference)
    OBSERVATION   sampled while the run was going on; coarse, and affected
                  by the sampling itself
    NOT_MEASURED  not available; carries the reason, and never a value.
                  An unavailable number is never reported as 0.

Verdicts
--------
    VALID            every integrity gate passed and no stop rule fired
    INVALID          an integrity gate failed, or was never evaluated
    STOPPED          a stop rule ended the run before it could complete
    GENERATOR_BOUND  complete and correct, but the load source could not
                     keep the requested rate; describes the load source,
                     never the platform's capacity

Precedence: INVALID > STOPPED > GENERATOR_BOUND > VALID.

Standard library only.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Optional, Sequence

KINDS: tuple[str, ...] = ("MEASURED", "DERIVED", "OBSERVATION", "NOT_MEASURED")
VERDICTS: tuple[str, ...] = ("VALID", "INVALID", "GENERATOR_BOUND", "STOPPED")
PERCENTILES: tuple[int, ...] = (50, 95, 99)

#: Defaults of the stop and validity limits; the ladder file can set its own.
SKEW_UNCERTAINTY_MAX_MS: float = 10.0
SKEW_DRIFT_MAX_MS: float = 5.0
GENERATOR_RATE_FRACTION: float = 0.95
LATE_START_FRACTION: float = 0.05
LAG_GROWTH_SAMPLES: int = 6
MEMORY_FRACTION_MAX: float = 0.90
DISK_FREE_MIN_BYTES: int = 10 * 1024 ** 3
DISK_PROJECTION_FACTOR: float = 2.0
CPU_SATURATION_PERCENT: float = 99.5
CPU_SATURATION_SECONDS: float = 60.0

RESULT_KEYS: frozenset[str] = frozenset({
    "benchmark_id", "git_sha", "git_dirty", "timestamps", "machine", "workload",
    "counts", "metrics", "clock", "integrity", "verdict", "limitations",
})
#: Keys a result may carry besides the required ones.
RESULT_OPTIONAL_KEYS: frozenset[str] = frozenset({"verdict_reasons", "stop", "claims", "consumer", "host"})
#: The storage consumer block of a result (B3J-257).  Results written before it existed have no
#: block, which means one Kafka commit per message; they stay valid as they are.
CONSUMER_KEYS: frozenset[str] = frozenset({"commit_batching", "timing_diagnostic_interval_seconds"})
CONSUMER_OPTIONAL_KEYS: frozenset[str] = frozenset({"observed"})
COMMIT_BATCHING_KEYS: frozenset[str] = frozenset({"enabled", "batch_messages", "interval_seconds"})
OBSERVED_COMMIT_KEYS: frozenset[str] = frozenset({
    "windows", "window_seconds", "messages", "commit_calls", "mean_messages_per_commit",
    "mean_seconds_between_commits", "mean_commit_ms"})
COMMIT_BATCH_RANGE: tuple[int, int] = (1, 1000)
COMMIT_INTERVAL_RANGE: tuple[float, float] = (0.05, 30.0)
METRIC_KEYS: frozenset[str] = frozenset({
    "value", "unit", "kind", "source", "method", "window", "n", "reason",
})
BENCHMARK_ID_RE = re.compile(r"bm-[a-z]+-r[0-9]{4}-c[0-9]{2}-rep[0-9]+")
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


class MetricError(ValueError):
    """Input that cannot be turned into a trustworthy number."""


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------

def _finite(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MetricError(f"{name} must be a number, got {type(value).__name__}")
    if not math.isfinite(value):
        raise MetricError(f"{name} must be finite, got {value!r}")
    return float(value)


def _count(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MetricError(f"{name} must be an integer count, got {type(value).__name__}")
    if value < 0:
        raise MetricError(f"{name} must not be negative, got {value}")
    return value


def percentile(values: Sequence[float], q: float) -> float:
    """
    The q-th percentile, 0 <= q <= 100, by linear interpolation between the
    two nearest ranks (the "linear" method; numpy's default).  One value is
    its own percentile at every q.

    Raises:
        MetricError  no values, a value that is not a finite number, or q out
                     of range.  An empty sample has no percentile; the caller
                     reports it as NOT_MEASURED.
    """
    q = _finite(q, "q")
    if not 0.0 <= q <= 100.0:
        raise MetricError(f"q must be between 0 and 100, got {q}")
    if len(values) == 0:
        raise MetricError("no values: a percentile of an empty sample does not exist")
    ordered = sorted(_finite(v, "value") for v in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q / 100.0
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def percentiles(values: Sequence[float]) -> dict[str, float]:
    """{"p50": ..., "p95": ..., "p99": ...}; raises MetricError on an empty sample."""
    return {f"p{q}": percentile(values, q) for q in PERCENTILES}


def rate(count: int, seconds: float) -> float:
    """
    Events per second over a window.

    Raises:
        MetricError  a negative or non-integer count, or a window that is not
                     a positive finite number of seconds (a zero-length window
                     has no rate).
    """
    count = _count(count, "count")
    seconds = _finite(seconds, "seconds")
    if seconds <= 0.0:
        raise MetricError(f"the window must be longer than 0 seconds, got {seconds}")
    return count / seconds


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Metric:
    """
    One reported number and how it was obtained.

    window   {"start": ISO-8601, "end": ISO-8601, "clock": "host" | "database" |
             "driver"} or None when the value is not tied to a time window
    n        how many observations the value rests on; None only for
             NOT_MEASURED
    reason   why a NOT_MEASURED value is missing; None otherwise
    """

    value: Any
    unit: str
    kind: str
    source: str
    method: str
    window: Optional[Mapping[str, str]] = None
    n: Optional[int] = None
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        check_metric(self.to_dict(), "metric")

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value, "unit": self.unit, "kind": self.kind,
            "source": self.source, "method": self.method,
            "window": None if self.window is None else dict(self.window),
            "n": self.n, "reason": self.reason,
        }


def not_measured(unit: str, source: str, reason: str) -> Metric:
    """A value that is not available, with the reason.  Never 0."""
    return Metric(value=None, unit=unit, kind="NOT_MEASURED", source=source,
                  method="not measured", window=None, n=None, reason=reason)


def check_metric(data: Any, where: str) -> None:
    """
    Raises MetricError unless data is one well-formed metric.

    A NOT_MEASURED metric has value None, n None and a reason.  Every other
    kind has a finite numeric value (or a list of them), a non-negative
    integer n, and no reason.
    """
    if not isinstance(data, Mapping):
        raise MetricError(f"{where}: a metric must be a mapping")
    keys = set(data)
    if keys != METRIC_KEYS:
        missing, extra = sorted(METRIC_KEYS - keys), sorted(keys - METRIC_KEYS)
        raise MetricError(f"{where}: keys differ (missing {missing}, unexpected {extra})")
    kind = data["kind"]
    if kind not in KINDS:
        raise MetricError(f"{where}: kind {kind!r} is not one of {list(KINDS)}")
    for name in ("unit", "source", "method"):
        if not isinstance(data[name], str) or not data[name].strip():
            raise MetricError(f"{where}: {name} must be a non-empty string")
    window = data["window"]
    if window is not None:
        if not isinstance(window, Mapping) or set(window) != {"start", "end", "clock"}:
            raise MetricError(f"{where}: window must hold exactly start, end and clock")
        if not all(isinstance(window[k], str) and window[k] for k in ("start", "end", "clock")):
            raise MetricError(f"{where}: window values must be non-empty strings")
    if kind == "NOT_MEASURED":
        if data["value"] is not None:
            raise MetricError(f"{where}: a NOT_MEASURED metric has no value")
        if data["n"] is not None:
            raise MetricError(f"{where}: a NOT_MEASURED metric has no n")
        if not isinstance(data["reason"], str) or not data["reason"].strip():
            raise MetricError(f"{where}: a NOT_MEASURED metric needs a reason")
        return
    if data["reason"] is not None:
        raise MetricError(f"{where}: only a NOT_MEASURED metric carries a reason")
    value = data["value"]
    if value is None:
        raise MetricError(f"{where}: a {kind} metric needs a value; use NOT_MEASURED instead")
    if isinstance(value, list):
        if not value:
            raise MetricError(f"{where}: an empty series is NOT_MEASURED, not a value")
        for item in value:
            _finite(item, f"{where} value item")
    else:
        _finite(value, f"{where} value")
    _count(data["n"], f"{where} n")


def latency_metrics(
    values: Sequence[float], *, unit: str, kind: str, source: str, method: str,
    window: Optional[Mapping[str, str]], reason_if_empty: str,
) -> dict[str, Metric]:
    """p50 / p95 / p99 as metrics, or three NOT_MEASURED metrics for an
    empty sample."""
    if not values:
        return {f"p{q}": not_measured(unit, source, reason_if_empty) for q in PERCENTILES}
    found = percentiles(values)
    return {
        name: Metric(value=value, unit=unit, kind=kind, source=source, method=method,
                     window=window, n=len(values))
        for name, value in found.items()
    }


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reconciliation:
    ok: bool
    missing: int
    duplicates: int
    checks: tuple[tuple[str, Any, Any, bool], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "missing": self.missing, "duplicates": self.duplicates,
            "checks": [
                {"name": n, "found": f, "expected": e, "ok": o} for n, f, e, o in self.checks
            ],
        }


def reconcile(
    *, planned_spans: int, spans_ended: int, spans_exported: int, canonical_records: int,
    rows_stored: int, distinct_span_keys: int, dlq_records: int,
) -> Reconciliation:
    """
    Every span planned is ended, exported, published once to the canonical
    topic and stored once; nothing goes to the DLQ.

    missing     planned spans with no stored row
    duplicates  canonical records or rows beyond one per distinct span
    """
    values = {
        "planned_spans": planned_spans, "spans_ended": spans_ended,
        "spans_exported": spans_exported, "canonical_records": canonical_records,
        "rows_stored": rows_stored, "distinct_span_keys": distinct_span_keys,
        "dlq_records": dlq_records,
    }
    for name, value in values.items():
        _count(value, name)
    checks = (
        ("spans ended = planned", spans_ended, planned_spans),
        ("spans exported = ended", spans_exported, spans_ended),
        ("canonical records = ended", canonical_records, spans_ended),
        ("rows stored = canonical records", rows_stored, canonical_records),
        ("distinct spans stored = rows", distinct_span_keys, rows_stored),
        ("DLQ records", dlq_records, 0),
    )
    rows = tuple((name, found, expected, found == expected) for name, found, expected in checks)
    missing = max(0, planned_spans - distinct_span_keys)
    duplicates = max(0, canonical_records - distinct_span_keys) + max(
        0, rows_stored - distinct_span_keys)
    return Reconciliation(
        ok=all(row[3] for row in rows) and missing == 0 and duplicates == 0,
        missing=missing, duplicates=duplicates, checks=rows,
    )


# ---------------------------------------------------------------------------
# Clock skew between the host and the database
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClockSample:
    """A database clock reading bracketed by two host clock readings, all
    in seconds since the epoch."""

    host_before: float
    database: float
    host_after: float

    def __post_init__(self) -> None:
        for name in ("host_before", "database", "host_after"):
            _finite(getattr(self, name), name)
        if self.host_after < self.host_before:
            raise MetricError("host_after is earlier than host_before")

    @property
    def skew_ms(self) -> float:
        """database - host, taking the host time as the middle of the bracket."""
        return (self.database - (self.host_before + self.host_after) / 2.0) * 1000.0

    @property
    def uncertainty_ms(self) -> float:
        return (self.host_after - self.host_before) / 2.0 * 1000.0


def best_sample(samples: Sequence[ClockSample]) -> ClockSample:
    """The sample with the narrowest bracket; MetricError when there is none."""
    if not samples:
        raise MetricError("no clock samples")
    return min(samples, key=lambda s: (s.uncertainty_ms, s.host_before))


@dataclass(frozen=True)
class ClockCheck:
    skew_ms: float
    uncertainty_ms: float
    drift_ms: float
    valid: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"skew_ms": self.skew_ms, "uncertainty_ms": self.uncertainty_ms,
                "drift_ms": self.drift_ms, "valid": self.valid, "reasons": list(self.reasons)}


def clock_check(
    before: Sequence[ClockSample], after: Sequence[ClockSample], *,
    max_uncertainty_ms: float = SKEW_UNCERTAINTY_MAX_MS,
    max_drift_ms: float = SKEW_DRIFT_MAX_MS,
) -> ClockCheck:
    """
    The host-to-database skew, measured before and after a run.  Latencies
    that cross the two clocks are valid only when both brackets are at most
    max_uncertainty_ms wide (half-width) and the skew moved by at most
    max_drift_ms during the run.
    """
    first, last = best_sample(before), best_sample(after)
    uncertainty = max(first.uncertainty_ms, last.uncertainty_ms)
    drift = abs(last.skew_ms - first.skew_ms)
    reasons = []
    if uncertainty > max_uncertainty_ms:
        reasons.append(f"skew uncertainty {uncertainty:.3f} ms > {max_uncertainty_ms} ms")
    if drift > max_drift_ms:
        reasons.append(f"skew drift {drift:.3f} ms > {max_drift_ms} ms")
    return ClockCheck(skew_ms=(first.skew_ms + last.skew_ms) / 2.0, uncertainty_ms=uncertainty,
                      drift_ms=drift, valid=not reasons, reasons=tuple(reasons))


# ---------------------------------------------------------------------------
# Stop and classification rules
# ---------------------------------------------------------------------------

def generator_bound(
    *, late_starts: int, started_requests: int, not_started_requests: int = 0,
    deadline_reached: bool = False, start_lag_series: Sequence[float] = (),
    late_fraction: float = LATE_START_FRACTION,
    lag_growth_samples: int = LAG_GROWTH_SAMPLES,
) -> tuple[bool, tuple[str, ...]]:
    """
    True when the load source's SCHEDULER could not keep the planned start
    times, so the run describes the load source rather than the platform:

        more than late_fraction of the started requests started late
        (the driver's own definition of late), or
        planned requests never started, or the deadline was reached, or
        the start lag grew across lag_growth_samples consecutive samples
        (when such a series is available).

    The achieved throughput (requests / wall time) is deliberately NOT used:
    it includes the last request's run time and the final flush, so a short
    run on time would look slow.  It is reported separately.
    """
    late_starts = _count(late_starts, "late_starts")
    started_requests = _count(started_requests, "started_requests")
    not_started_requests = _count(not_started_requests, "not_started_requests")
    if not isinstance(deadline_reached, bool):
        raise MetricError("deadline_reached must be true or false")
    if started_requests == 0 and not_started_requests == 0:
        raise MetricError("no request was planned to start: the load source cannot be judged")
    if late_starts > started_requests:
        raise MetricError("more late starts than started requests")
    reasons = []
    if started_requests:
        share = late_starts / started_requests
        if share > late_fraction:
            reasons.append(f"{share:.1%} of requests started late > {late_fraction:.0%}")
    if not_started_requests:
        reasons.append(f"{not_started_requests} planned requests never started")
    if deadline_reached:
        reasons.append("the deadline was reached before every request started")
    lags = [_finite(value, "start lag") for value in start_lag_series]
    if lag_growth_samples < 2:
        raise MetricError("lag_growth_samples must be at least 2")
    streak = 1
    for previous, current in zip(lags, lags[1:]):
        streak = streak + 1 if current > previous else 1
        if streak >= lag_growth_samples:
            reasons.append(f"start lag grew across {lag_growth_samples} consecutive samples")
            break
    return bool(reasons), tuple(reasons)


def lag_growing(samples: Sequence[Optional[int]], *, run: int = LAG_GROWTH_SAMPLES) -> bool:
    """
    True when `run` consecutive lag samples each exceed the one before
    (run - 1 increases in a row).  An unknown sample (None) breaks a run;
    it neither proves nor disproves growth.
    """
    if run < 2:
        raise MetricError("run must be at least 2")
    streak = 1
    previous: Optional[int] = None
    for sample in samples:
        if sample is not None:
            _count(sample, "lag sample")
        if sample is not None and previous is not None and sample > previous:
            streak += 1
            if streak >= run:
                return True
        else:
            streak = 1
        previous = sample
    return False


@dataclass(frozen=True)
class MemorySample:
    container: str
    used_bytes: int
    limit_bytes: int


def resource_stops(
    *,
    memory: Sequence[MemorySample] = (),
    disk_free_bytes: Optional[int] = None,
    projected_need_bytes: Optional[int] = None,
    cpu_percent: Sequence[tuple[float, float]] = (),
    memory_fraction: float = MEMORY_FRACTION_MAX,
    disk_free_min_bytes: int = DISK_FREE_MIN_BYTES,
    disk_projection_factor: float = DISK_PROJECTION_FACTOR,
    cpu_saturation_percent: float = CPU_SATURATION_PERCENT,
    cpu_saturation_seconds: float = CPU_SATURATION_SECONDS,
) -> tuple[str, ...]:
    """
    Reasons to stop for resources; empty when none applies.

    memory          a container above memory_fraction of its limit
    disk            free space below the larger of disk_free_min_bytes and
                    disk_projection_factor x the projected need
    cpu_percent     (seconds since start, percent) samples in time order;
                    stop when every sample over cpu_saturation_seconds or
                    more is at or above cpu_saturation_percent
    """
    reasons = []
    for sample in memory:
        used = _count(sample.used_bytes, "used_bytes")
        limit = _count(sample.limit_bytes, "limit_bytes")
        if limit == 0:
            raise MetricError(f"{sample.container}: a memory limit of 0 cannot be judged")
        if used / limit > memory_fraction:
            reasons.append(f"{sample.container} memory {used / limit:.1%} of its limit "
                           f"> {memory_fraction:.0%}")
    if disk_free_bytes is not None:
        free = _count(disk_free_bytes, "disk_free_bytes")
        need = 0 if projected_need_bytes is None else _count(projected_need_bytes,
                                                              "projected_need_bytes")
        floor = max(disk_free_min_bytes, int(disk_projection_factor * need))
        if free < floor:
            reasons.append(f"disk free {free} bytes < required {floor} bytes")
    saturated_since: Optional[float] = None
    last_time: Optional[float] = None
    for at, percent in cpu_percent:
        at = _finite(at, "cpu sample time")
        percent = _finite(percent, "cpu percent")
        if last_time is not None and at < last_time:
            raise MetricError("cpu samples must be in time order")
        last_time = at
        if percent >= cpu_saturation_percent:
            saturated_since = at if saturated_since is None else saturated_since
            if at - saturated_since >= cpu_saturation_seconds:
                reasons.append(f"CPU at or above {cpu_saturation_percent}% for "
                               f"{at - saturated_since:.0f} s")
                break
        else:
            saturated_since = None
    return tuple(reasons)


def verdict(
    *, integrity_ok: Optional[bool], stop_reasons: Sequence[str], generator_bound_run: bool,
) -> str:
    """
    INVALID > STOPPED > GENERATOR_BOUND > VALID.

    integrity_ok None means the gates were never evaluated: STOPPED when a
    stop rule explains why, INVALID otherwise.  A failed gate is INVALID
    even when the run was also stopped.
    """
    if integrity_ok is False:
        return "INVALID"
    if stop_reasons:
        return "STOPPED"
    if integrity_ok is None:
        return "INVALID"
    if generator_bound_run:
        return "GENERATOR_BOUND"
    return "VALID"


def claim_eligibility(verdict_value: str, clock_valid: Optional[bool],
                      host_interruption: bool = False) -> dict[str, bool]:
    """
    Which kinds of statement a later reviewer MAY consider for this result.
    It produces no claim text; it only records what the evidence allows.  When the host
    reported an interruption during the run (Windows Modern Standby), the two claims that rest on
    timing, platform throughput and persistence latency, are withdrawn; the verdict itself and
    every other claim follow from the evidence exactly as before.
    """
    if verdict_value not in VERDICTS:
        raise MetricError(f"unknown verdict {verdict_value!r}")
    valid = verdict_value == "VALID"
    clean = valid and not host_interruption
    return {
        "platform_throughput": clean,
        "span_volume_handled": valid,
        "persistence_latency": clean and clock_valid is True,
        "no_loss_for_this_run": valid,
        "load_source_limit_only": verdict_value == "GENERATOR_BOUND",
    }


# ---------------------------------------------------------------------------
# Ladder configuration
# ---------------------------------------------------------------------------

LEVELS: tuple[tuple[str, int], ...] = (
    ("SMOKE", 100), ("SMALL", 1000), ("MEDIUM", 10000), ("LARGE", 100000), ("STRESS", 500000),
)
_LADDER_KEYS = frozenset({"kind", "note", "schema_version", "defaults", "stop_limits", "levels"})
_DEFAULT_KEYS = frozenset({
    "scenario", "seed", "concurrency", "warmup_seconds", "min_measured_seconds",
    "repetitions", "drain_limit_seconds", "settle_seconds", "sample_interval_seconds",
    "cell_budget_seconds",
})
_STOP_KEYS = frozenset({
    "memory_fraction", "disk_free_min_gb", "disk_projection_factor",
    "cpu_saturation_percent", "cpu_saturation_seconds", "lag_growth_samples",
    "generator_rate_fraction", "late_start_fraction", "skew_uncertainty_ms", "skew_drift_ms",
})
_LEVEL_KEYS = frozenset({
    "name", "target_requests", "target_spans", "rates", "live_allowed",
    "refresh_and_detector", "note",
})
SPANS_PER_HEALTHY_REQUEST: int = 7


def check_ladder(data: Any) -> None:
    """Raises MetricError unless data is a complete, consistent ladder of
    TARGETS (it must hold no result)."""
    if not isinstance(data, Mapping) or set(data) != _LADDER_KEYS:
        raise MetricError(f"the ladder must hold exactly {sorted(_LADDER_KEYS)}")
    if data["kind"] != "TARGETS":
        raise MetricError("the ladder's kind must be TARGETS: it describes targets, not results")
    if data["schema_version"] != 1:
        raise MetricError("unsupported ladder schema_version")
    defaults, stops = data["defaults"], data["stop_limits"]
    if not isinstance(defaults, Mapping) or set(defaults) != _DEFAULT_KEYS:
        raise MetricError(f"defaults must hold exactly {sorted(_DEFAULT_KEYS)}")
    if defaults["scenario"] != "normal":
        raise MetricError("throughput benchmarks use the normal scenario only")
    for name in _DEFAULT_KEYS - {"scenario"}:
        _finite(defaults[name], f"defaults.{name}")
        if defaults[name] < (0 if name in ("seed", "warmup_seconds") else 1):
            raise MetricError(f"defaults.{name} is out of range")
    if not 1 <= defaults["concurrency"] <= 64:
        raise MetricError("defaults.concurrency must be 1-64 (the generator's limit)")
    if not isinstance(stops, Mapping) or set(stops) != _STOP_KEYS:
        raise MetricError(f"stop_limits must hold exactly {sorted(_STOP_KEYS)}")
    for name in _STOP_KEYS:
        if _finite(stops[name], f"stop_limits.{name}") <= 0:
            raise MetricError(f"stop_limits.{name} must be positive")
    for name in ("memory_fraction", "generator_rate_fraction", "late_start_fraction"):
        if stops[name] > 1:
            raise MetricError(f"stop_limits.{name} is a fraction")
    levels = data["levels"]
    if not isinstance(levels, list) or [lv.get("name") for lv in levels] != [n for n, _ in LEVELS]:
        raise MetricError(f"levels must be, in order, {[n for n, _ in LEVELS]}")
    for level, (name, requests) in zip(levels, LEVELS):
        if set(level) != _LEVEL_KEYS:
            raise MetricError(f"level {name} must hold exactly {sorted(_LEVEL_KEYS)}")
        if level["target_requests"] != requests:
            raise MetricError(f"level {name} targets {requests} requests")
        if level["target_spans"] != requests * SPANS_PER_HEALTHY_REQUEST:
            raise MetricError(f"level {name}: target_spans must be "
                              f"{SPANS_PER_HEALTHY_REQUEST} x target_requests")
        rates = level["rates"]
        if not rates or rates != sorted(set(rates)) or not all(
                isinstance(r, int) and not isinstance(r, bool) and 1 <= r <= 10000 for r in rates):
            raise MetricError(f"level {name}: rates must be ascending distinct integers 1-10000")
        if requests / rates[-1] < defaults["min_measured_seconds"]:
            raise MetricError(f"level {name}: {requests} requests at {rates[-1]}/s are shorter "
                              f"than the minimum measured period")
        for flag in ("live_allowed", "refresh_and_detector"):
            if not isinstance(level[flag], bool):
                raise MetricError(f"level {name}: {flag} must be true or false")
    if any(level["live_allowed"] for level in levels if level["name"] in ("LARGE", "STRESS")):
        raise MetricError("LARGE and STRESS need their own authorization; live_allowed must be false")
    if any(level["refresh_and_detector"] for level in levels
           if level["name"] in ("LARGE", "STRESS")):
        raise MetricError("the detector is quadratic in history; not above MEDIUM")


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")


def _walk_metrics(node: Any, path: str) -> Iterable[tuple[str, Any]]:
    if isinstance(node, Mapping) and "kind" in node:
        yield path, node
        return
    if not isinstance(node, Mapping) or not node:
        raise MetricError(f"{path}: metrics must be nested mappings ending in metrics")
    for key, child in node.items():
        yield from _walk_metrics(child, f"{path}.{key}")


# ---------------------------------------------------------------------------
# The optional `host` block of a result (B3J-275): what Windows reported about the machine itself
# ---------------------------------------------------------------------------

HOST_KEYS: frozenset[str] = frozenset({
    "platform", "keep_awake", "session", "window", "power_events", "host_interruption_suspected"})
HOST_KEEP_AWAKE_ACQUISITION = ("acquired", "failed", "not_applicable", "unknown")
HOST_KEEP_AWAKE_READBACK = ("consistent", "inconsistent", "unavailable", "skipped", "unknown")
HOST_POWER_STATUSES = ("ok", "failed")
HOST_POWER_EVENT_IDS = (506, 507)
HOST_MAX_EVENTS = 50
HOST_ERROR_LIMIT = 120
_HOST_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z")


def _host_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or _HOST_TIME_RE.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _session_state_problems(state: Any, where: str) -> list[str]:
    if state is None:
        return []
    if not isinstance(state, Mapping) or set(state) != {"flags", "locked", "idle_seconds"}:
        return [f"{where} must be null or hold exactly flags, locked and idle_seconds"]
    problems = []
    flags, locked, idle = state["flags"], state["locked"], state["idle_seconds"]
    if flags is not None and (isinstance(flags, bool) or flags not in (0, 1)):
        problems.append(f"{where}.flags must be 0, 1 or null")
    elif flags is None and locked is not None:
        problems.append(f"{where}.locked must be null when flags is null")
    elif flags is not None and locked is not (flags == 0):
        problems.append(f"{where}.locked does not follow from flags (0 = locked, 1 = unlocked)")
    if idle is not None and (isinstance(idle, bool) or not isinstance(idle, (int, float))
                             or idle != idle or idle < 0 or idle == float("inf")):
        problems.append(f"{where}.idle_seconds must be a non-negative number or null")
    return problems


# ---------------------------------------------------------------------------
# The host-resource observations under metrics.resources (B3J-283)
# ---------------------------------------------------------------------------
#
# Optional: results written before B3J-283 have none of these names and stay valid as they are.  When
# any is present they must all be consistent with each other: every family has its extreme, series and
# times for the same keys; the extreme is the extreme of the series; the times are in order; and the
# coverage counts agree with the series.  A value is a finite, non-negative number or the metric is
# NOT_MEASURED; there is no zero for "unavailable".

#: family -> (unit, extreme).  The recorded names are <family>_<extreme>, <family>_series and
#: <family>_series_times_s.
HOST_RESOURCE_FAMILIES: Mapping[str, tuple[str, str]] = {
    "host_process_cpu_percent": ("%", "max"),
    "host_process_working_set_bytes": ("bytes", "max"),
    "host_memory_available_bytes": ("bytes", "min"),
    "host_cpu_percent": ("%", "max"),
    "disk_free_bytes": ("bytes", "min"),
}
HOST_RESOURCE_PEAK = "host_process_peak_working_set_bytes"
HOST_RESOURCE_COVERAGE = "host_sampling_coverage"
HOST_COVERAGE_SCALARS: Mapping[str, str] = {
    "samples_attempted": "samples", "samples_failed": "samples", "interval_seconds": "s",
    "collection_errors": "reads", "unattributed_descendants": "processes",
    "host_cpu_samples_available": "samples", "host_memory_samples_available": "samples",
    "disk_samples_available": "samples", "first_sample_s": "s", "last_sample_s": "s"}
HOST_COVERAGE_PER_PROCESS: tuple[str, ...] = (
    "process_samples_available", "process_samples_unavailable", "process_samples_exited")
#: The whole-host CPU is a percent of all logical CPUs; a process's is a percent of one core.
HOST_CPU_PERCENT_LIMIT = 100.0
HOST_PROCESS_CPU_PERCENT_LIMIT = 100.0 * 4096
_HOST_RESOURCE_PREFIXES = ("host_", "disk_free_bytes")

#: The host-memory checkpoint group (B3J-299).  Optional on its own: a cell stopped by the checkpoint has these
#: and no host sampler, so they never require the sampler's families or its coverage block.
HOST_MEMORY_CHECKPOINT_BYTES = "host_memory_checkpoint_bytes"
HOST_MEMORY_CHECKPOINT_NAMES: frozenset[str] = frozenset({
    HOST_MEMORY_CHECKPOINT_BYTES, "host_memory_checkpoint_minimum_bytes",
    "host_memory_checkpoint_threshold_bytes", "host_memory_checkpoint_unavailable_readings"})
HOST_MEMORY_CHECKPOINT_READINGS = 3
HOST_MEMORY_OBSERVATION_KEYS: tuple[str, ...] = ("before_startup", "stack_ready")


def _measured_leaf(leaf: Any) -> Optional[Mapping[str, Any]]:
    """The leaf when it is a measured (not NOT_MEASURED) metric mapping, else None."""
    if isinstance(leaf, Mapping) and leaf.get("kind") not in (None, "NOT_MEASURED"):
        return leaf
    return None


def host_resource_problems(resources: Any) -> list[str]:
    """Everything wrong with the host-resource observations of a result's metrics.resources; an empty
    list when there are none (a result from before they existed) or when they are consistent."""
    if not isinstance(resources, Mapping):
        return []
    problems: list[str] = []
    known = {HOST_RESOURCE_PEAK, HOST_RESOURCE_COVERAGE}
    for family, (_, extreme) in HOST_RESOURCE_FAMILIES.items():
        known.update({f"{family}_{extreme}", f"{family}_series", f"{family}_series_times_s"})
    present = {name for name in resources if isinstance(name, str) and name.startswith(_HOST_RESOURCE_PREFIXES)
               and name not in HOST_MEMORY_CHECKPOINT_NAMES}     # the checkpoint group is judged on its own
    if not present:
        return []
    for name in sorted(present - known):
        problems.append(f"metrics.resources.{name}: not a host resource observation")
    if HOST_RESOURCE_COVERAGE not in resources:
        problems.append(f"metrics.resources.{HOST_RESOURCE_COVERAGE} is required with host resource observations")
    series_lengths: dict[tuple[str, str], int] = {}
    for family, (unit, extreme) in HOST_RESOURCE_FAMILIES.items():
        limit = (HOST_CPU_PERCENT_LIMIT if family == "host_cpu_percent" else
                 HOST_PROCESS_CPU_PERCENT_LIMIT if unit == "%" else math.inf)
        _family_problems(resources, family, unit, extreme, limit, series_lengths, problems, "host")
    peak = resources.get(HOST_RESOURCE_PEAK)
    if HOST_RESOURCE_PEAK in resources:
        if not isinstance(peak, Mapping):
            problems.append(f"metrics.resources.{HOST_RESOURCE_PEAK}: must map a key to a metric")
        else:
            for key, leaf in peak.items():
                if _measured_leaf(leaf) is None:
                    continue
                value = leaf.get("value")
                if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "bytes" \
                        or isinstance(value, (bool, list)) or not isinstance(value, (int, float)) \
                        or not math.isfinite(value) or value < 0:
                    problems.append(f"metrics.resources.{HOST_RESOURCE_PEAK}.{key}: a non-negative byte count")
    problems.extend(_host_coverage_problems(resources.get(HOST_RESOURCE_COVERAGE), series_lengths))
    return problems


def _host_coverage_problems(coverage: Any, series_lengths: Mapping[tuple[str, str], int]) -> list[str]:
    if coverage is None:
        return []
    where = f"metrics.resources.{HOST_RESOURCE_COVERAGE}"
    if not isinstance(coverage, Mapping):
        return [f"{where}: must be a mapping"]
    problems: list[str] = []
    allowed = set(HOST_COVERAGE_SCALARS) | set(HOST_COVERAGE_PER_PROCESS)
    for name in sorted(set(coverage) - allowed):
        problems.append(f"{where}.{name}: not a coverage entry")
    for name in sorted(allowed - set(coverage)):
        problems.append(f"{where}.{name}: missing")
    scalars: dict[str, float] = {}
    for name, unit in HOST_COVERAGE_SCALARS.items():
        leaf = coverage.get(name)
        if _measured_leaf(leaf) is None:
            continue
        value = leaf.get("value")
        if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != unit or isinstance(value, (bool, list)) \
                or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            problems.append(f"{where}.{name}: a non-negative {unit} observation")
            continue
        if name not in ("interval_seconds", "first_sample_s", "last_sample_s") and not isinstance(value, int):
            problems.append(f"{where}.{name}: a whole number of {unit}")
            continue
        scalars[name] = value
    if "interval_seconds" in scalars and scalars["interval_seconds"] <= 0:
        problems.append(f"{where}.interval_seconds: must be positive")
    attempted = scalars.get("samples_attempted")
    if attempted is not None:
        for name in ("samples_failed", "host_cpu_samples_available", "host_memory_samples_available",
                     "disk_samples_available"):
            if name in scalars and scalars[name] > attempted:
                problems.append(f"{where}.{name}: more than the samples attempted")
    if "first_sample_s" in scalars and "last_sample_s" in scalars \
            and scalars["first_sample_s"] > scalars["last_sample_s"]:
        problems.append(f"{where}: the first sample is after the last")
    for family, name in (("host_cpu_percent", "host_cpu_samples_available"),
                         ("host_memory_available_bytes", "host_memory_samples_available")):
        length = series_lengths.get((family, "host"))
        if name in scalars and length is not None and scalars[name] != length:
            problems.append(f"{where}.{name}: differs from the length of {family}_series")
    disk_lengths = [length for (family, _), length in series_lengths.items() if family == "disk_free_bytes"]
    if "disk_samples_available" in scalars and disk_lengths and scalars["disk_samples_available"] != disk_lengths[0]:
        problems.append(f"{where}.disk_samples_available: differs from the length of disk_free_bytes_series")
    per_process: dict[str, dict[str, int]] = {}
    for group in HOST_COVERAGE_PER_PROCESS:
        entries = coverage.get(group)
        if entries is None:
            continue
        if not isinstance(entries, Mapping):
            problems.append(f"{where}.{group}: must map a process to a count")
            continue
        for key, leaf in entries.items():
            if _measured_leaf(leaf) is None:
                continue
            value = leaf.get("value")
            if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "samples" \
                    or isinstance(value, (bool, list)) or not isinstance(value, int) or value < 0:
                problems.append(f"{where}.{group}.{key}: a non-negative whole number of samples")
                continue
            per_process.setdefault(key, {})[group] = value
    for key, counts in per_process.items():
        if attempted is not None and sum(counts.values()) > attempted:
            problems.append(f"{where}: process {key!r} has more samples than were attempted")
        length = series_lengths.get(("host_process_working_set_bytes", key))
        if length is not None and counts.get("process_samples_available") != length:
            problems.append(f"{where}.process_samples_available.{key}: differs from the length of "
                            "host_process_working_set_bytes_series")
    return problems


HOST_MEMORY_CHECKPOINT_REASON_PREFIX = "host memory checkpoint:"
HOST_MEMORY_CHECKPOINT_COMPANIONS: tuple[str, ...] = (
    "host_memory_checkpoint_minimum_bytes", "host_memory_checkpoint_threshold_bytes",
    "host_memory_checkpoint_unavailable_readings")


def _checkpoint_facts(resources: Mapping[str, Any], problems: list[str]) -> dict[str, Any]:
    """Read the checkpoint group of metrics.resources into plain facts, appending every structural problem
    to `problems`: readings (the valid after-warm-up readings, or None when the group is absent), count (the
    unavailable readings), threshold, minimum and has_after (the after_warmup reading is in the group)."""
    where = "metrics.resources"
    facts: dict[str, Any] = {"readings": None, "count": None, "threshold": None, "minimum": None, "has_after": False}
    group = resources.get(HOST_MEMORY_CHECKPOINT_BYTES)
    if HOST_MEMORY_CHECKPOINT_BYTES in resources:
        if not isinstance(group, Mapping):
            problems.append(f"{where}.{HOST_MEMORY_CHECKPOINT_BYTES}: must map a label to a metric")
        else:
            facts["has_after"] = "after_warmup" in group
            for label, leaf in group.items():
                if label not in (*HOST_MEMORY_OBSERVATION_KEYS, "after_warmup"):
                    problems.append(f"{where}.{HOST_MEMORY_CHECKPOINT_BYTES}.{label}: not a known reading point")
                    continue
                if _measured_leaf(leaf) is None:
                    if label == "after_warmup":
                        facts["readings"] = []
                    continue
                value = leaf.get("value")
                items = value if isinstance(value, list) else [value]
                limit = HOST_MEMORY_CHECKPOINT_READINGS if label == "after_warmup" else 1
                if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "bytes" or not items \
                        or len(items) > limit or any(isinstance(v, bool) or not isinstance(v, int) or v < 0
                                                    for v in items):
                    problems.append(f"{where}.{HOST_MEMORY_CHECKPOINT_BYTES}.{label}: "
                                    f"{limit} or fewer whole, non-negative byte counts")
                    continue
                if leaf.get("n") != len(items):
                    problems.append(f"{where}.{HOST_MEMORY_CHECKPOINT_BYTES}.{label}: n must equal the readings")
                if label == "after_warmup":
                    facts["readings"] = items

    def companion(name: str) -> tuple[bool, Optional[Mapping[str, Any]]]:
        """(present, the measured after_warmup leaf or None); a present companion must map after_warmup."""
        if name not in resources:
            return False, None
        entry = resources[name]
        if not isinstance(entry, Mapping) or "after_warmup" not in entry:
            problems.append(f"{where}.{name}: must map after_warmup to a metric")
            return True, None
        return True, _measured_leaf(entry["after_warmup"])

    _, leaf = companion("host_memory_checkpoint_unavailable_readings")
    if leaf is not None:
        value = leaf.get("value")
        if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "readings" \
                or isinstance(value, (bool, list)) or not isinstance(value, int) \
                or not 0 <= value <= HOST_MEMORY_CHECKPOINT_READINGS:
            problems.append(f"{where}.host_memory_checkpoint_unavailable_readings: 0 to "
                            f"{HOST_MEMORY_CHECKPOINT_READINGS} readings")
        else:
            facts["count"] = value
    elif "host_memory_checkpoint_unavailable_readings" in resources \
            and isinstance(resources["host_memory_checkpoint_unavailable_readings"], Mapping) \
            and "after_warmup" in resources["host_memory_checkpoint_unavailable_readings"]:
        problems.append(f"{where}.host_memory_checkpoint_unavailable_readings: a count is measured, not NOT_MEASURED")
    _, leaf = companion("host_memory_checkpoint_threshold_bytes")
    if leaf is not None:
        value = leaf.get("value")
        if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "bytes" \
                or isinstance(value, (bool, list)) or not isinstance(value, int) or value <= 0:
            problems.append(f"{where}.host_memory_checkpoint_threshold_bytes: a positive byte count")
        else:
            facts["threshold"] = value
    elif "host_memory_checkpoint_threshold_bytes" in resources \
            and isinstance(resources["host_memory_checkpoint_threshold_bytes"], Mapping) \
            and "after_warmup" in resources["host_memory_checkpoint_threshold_bytes"]:
        problems.append(f"{where}.host_memory_checkpoint_threshold_bytes: a positive byte count")
    present, leaf = companion("host_memory_checkpoint_minimum_bytes")
    if leaf is not None:
        value = leaf.get("value")
        if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "bytes" \
                or isinstance(value, (bool, list)) or not isinstance(value, int) or value < 0:
            problems.append(f"{where}.host_memory_checkpoint_minimum_bytes: a non-negative byte count")
        else:
            facts["minimum"] = value
    facts["minimum_present"] = present and leaf is not None
    return facts


def host_memory_checkpoint_problems(resources: Any) -> list[str]:
    """Everything wrong with the host-memory checkpoint group of a result's metrics.resources; empty when the
    group is absent (an older result) or consistent.  Consistent means: known names only; each leaf a measured
    OBSERVATION in bytes (or readings) that is finite and non-negative; the three companions (minimum,
    threshold, unavailable count) present whenever the after_warmup reading or any companion is; companions
    never present without the after_warmup reading; the valid and unavailable readings adding up to the three
    that were taken; the minimum equal to the smallest valid reading, present when none failed and absent
    (NOT_MEASURED) when one did."""
    if not isinstance(resources, Mapping):
        return []
    names = {n for n in resources if isinstance(n, str) and n.startswith("host_memory_checkpoint")}
    if not names:
        return []
    where = "metrics.resources"
    problems = [f"{where}.{n}: not a host-memory checkpoint observation"
                for n in sorted(names - HOST_MEMORY_CHECKPOINT_NAMES)]
    facts = _checkpoint_facts(resources, problems)
    companions = names & set(HOST_MEMORY_CHECKPOINT_COMPANIONS)
    if companions or facts["has_after"]:
        for required in HOST_MEMORY_CHECKPOINT_COMPANIONS:
            if required not in names:
                problems.append(f"{where}.{required}: required with the after_warmup checkpoint reading")
    if companions and not facts["has_after"]:
        problems.append(f"{where}: checkpoint companion metrics without the after_warmup reading")
    readings, count, minimum = facts["readings"], facts["count"], facts["minimum"]
    if facts["minimum_present"]:
        if readings and minimum != min(readings):
            problems.append(f"{where}.host_memory_checkpoint_minimum_bytes: not the smallest reading")
        elif count not in (None, 0):
            problems.append(f"{where}.host_memory_checkpoint_minimum_bytes: present although a reading failed")
    elif "host_memory_checkpoint_minimum_bytes" in names and count == 0:
        problems.append(f"{where}.host_memory_checkpoint_minimum_bytes: missing although every reading was valid")
    if count is not None and readings is not None and len(readings) + count != HOST_MEMORY_CHECKPOINT_READINGS:
        problems.append(f"{where}: valid and unavailable checkpoint readings do not add up to "
                        f"{HOST_MEMORY_CHECKPOINT_READINGS}")
    return problems


def host_memory_checkpoint_consistency_problems(resources: Any, reasons: Any, verdict_value: Any) -> list[str]:
    """The checkpoint evidence against the stop reasons and the verdict.  A checkpoint FAILS when a reading was
    unavailable or the smallest reading is below the threshold.  Then the verdict may not be VALID or
    GENERATOR_BOUND, and a checkpoint stop reason of the matching kind must be recorded.  A checkpoint stop reason
    (one starting "host memory checkpoint:") requires evidence of a failure, and of the kind it names.  A result
    with no checkpoint evidence and no such reason is untouched."""
    texts = [r for r in reasons if isinstance(r, str)] if isinstance(reasons, list) else []
    given = [r for r in texts if r.startswith(HOST_MEMORY_CHECKPOINT_REASON_PREFIX)]
    facts = {"readings": None, "count": None, "threshold": None, "minimum": None, "has_after": False}
    if isinstance(resources, Mapping) and any(isinstance(n, str) and n.startswith("host_memory_checkpoint")
                                              for n in resources):
        facts = _checkpoint_facts(resources, [])         # structure is judged by host_memory_checkpoint_problems
    unavailable = facts["count"] is not None and facts["count"] > 0
    below = (not unavailable and facts["minimum"] is not None and facts["threshold"] is not None
             and facts["minimum"] < facts["threshold"])
    failing = unavailable or below
    problems: list[str] = []
    if failing and verdict_value in ("VALID", "GENERATOR_BOUND"):
        problems.append(f"the host-memory checkpoint failed but the verdict is {verdict_value}")
    kinds = {"unavailable": [r for r in given if "unavailable" in r],
             "below": [r for r in given if "is below the" in r]}
    if failing:
        want = "unavailable" if unavailable else "below"
        other = "below" if unavailable else "unavailable"
        if not kinds[want]:
            problems.append("the host-memory checkpoint failed ("
                            + ("a reading was unavailable" if unavailable else "the minimum is below the threshold")
                            + ") but no matching checkpoint stop reason is recorded")
        if kinds[other]:
            problems.append("a checkpoint stop reason names a failure the checkpoint evidence does not show")
    elif given:
        problems.append("a checkpoint stop reason is recorded but the checkpoint evidence shows no failure")
    for reason in given:
        if not any(reason in group for group in kinds.values()):
            problems.append(f"unrecognised checkpoint stop reason {reason!r}")
    return problems


def _family_problems(resources: Mapping[str, Any], family: str, unit: str, extreme: str, limit: float,
                     series_lengths: dict[tuple[str, str], int], problems: list[str], label: str) -> None:
    """The consistency of one family (<family>_<extreme>, _series, _series_times_s) of optional resource
    observations: all three present, the same keys, the right unit and kind, finite non-negative values within
    `limit`, one in-order time per value, and the extreme equal to the extreme of the series.  `label` names the
    kind of observation in the messages.  The length of each series is recorded in series_lengths."""
    names = (f"{family}_{extreme}", f"{family}_series", f"{family}_series_times_s")
    found = [name for name in names if name in resources]
    if not found:
        problems.append(f"metrics.resources.{family}: missing ({label} resource observations come as a whole)")
        return
    if len(found) != 3:
        problems.append(f"metrics.resources.{family}: incomplete, has {found} of {list(names)}")
        return
    groups = [resources[name] for name in names]
    if not all(isinstance(group, Mapping) for group in groups):
        problems.append(f"metrics.resources.{family}: each entry must map a key to a metric")
        return
    extremes, series, times = groups
    keys = [{k for k, leaf in group.items() if _measured_leaf(leaf) is not None} for group in groups]
    if not (keys[0] == keys[1] == keys[2]):
        problems.append(f"metrics.resources.{family}: the extreme, series and times cover different keys")
    for key in sorted(keys[1]):
        where = f"metrics.resources.{family}_series.{key}"
        values_leaf, times_leaf = series[key], times.get(key)
        values = values_leaf.get("value")
        for leaf, text, want in ((values_leaf, where, unit),
                                 (times_leaf, f"metrics.resources.{family}_series_times_s.{key}", "s"),
                                 (extremes.get(key), f"metrics.resources.{family}_{extreme}.{key}", unit)):
            if _measured_leaf(leaf) is None:
                continue
            if leaf.get("kind") != "OBSERVATION":
                problems.append(f"{text}: a {label} observation is OBSERVATION, not {leaf.get('kind')}")
            if leaf.get("unit") != want:
                problems.append(f"{text}: unit must be {want!r}, not {leaf.get('unit')!r}")
        if not isinstance(values, list):
            problems.append(f"{where}: a series is a list")
            continue
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
               or v < 0 or v > limit for v in values):
            problems.append(f"{where}: values must be finite, non-negative and at most {limit:g}")
            continue
        series_lengths[(family, key)] = len(values)
        if values_leaf.get("n") != len(values):
            problems.append(f"{where}: n must equal the number of values")
        moments = times_leaf.get("value") if _measured_leaf(times_leaf) is not None else None
        if not isinstance(moments, list) or len(moments) != len(values):
            problems.append(f"{where}: there must be one time per value")
        elif any(isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0
                 for t in moments) or any(b < a for a, b in zip(moments, moments[1:])):
            problems.append(f"{where}: times must be finite, non-negative and in order")
        extreme_leaf = extremes.get(key)
        if _measured_leaf(extreme_leaf) is not None and values:
            want_value = max(values) if extreme == "max" else min(values)
            if extreme_leaf.get("value") != want_value:
                problems.append(f"metrics.resources.{family}_{extreme}.{key}: not the {extreme}imum of the series")


# ---------------------------------------------------------------------------
# Docker container resources: aggregate CPU and memory, and coverage (B3J-287)
# ---------------------------------------------------------------------------
#
# Applied by the harness to the `docker stats` samples of the benchmark's own containers, after the
# run.  A SAMPLE is (seconds since the sampler started, rows or None); rows is one dict per container
# (name, cpu_percent, memory_used_bytes) and None means the sample failed.  A TICK is complete when it
# holds exactly `expected_containers` rows with distinct names and valid numbers; only complete ticks
# are summed, so a value is never built from different moments and a missing reading is never 0.
# resource_stops() above is not changed: these functions are new and separate.

DOCKER_COVERAGE_MIN_TICKS: int = 5
DOCKER_COVERAGE_MIN_FRACTION: float = 0.80
DOCKER_COVERAGE_EDGE_FACTOR: float = 2.0        # first / last usable tick within this x interval of the window edges
DOCKER_COVERAGE_GAP_FACTOR: float = 3.0         # largest gap between usable ticks, x interval
DOCKER_CPU_GAP_FACTOR: float = 2.0              # a gap above this x interval ends a saturation run
_COVERAGE_EPSILON = 1e-9


def _row_name(row: Any) -> Optional[str]:
    name = row.get("name") if isinstance(row, Mapping) else None
    return name if isinstance(name, str) and name.strip() else None


def _plain(value: Any, *, integer: bool = False) -> bool:
    if isinstance(value, bool) or not isinstance(value, int if integer else (int, float)):
        return False
    return math.isfinite(value) and value >= 0


def _sample_time(sample: Any, previous: Optional[float]) -> tuple[float, Any]:
    try:
        at, rows = sample
    except (TypeError, ValueError):
        raise MetricError("a resource sample is (seconds, rows)") from None
    at = _finite(at, "sample time")
    if previous is not None and at < previous:
        raise MetricError("resource samples must be in time order")
    return at, rows


def docker_vm_cpu_series(samples: Sequence[Any], *, expected_containers: int,
                         ncpu: Any) -> list[tuple[float, Optional[float]]]:
    """
    (time, percent of the Docker VM's CPUs) per sample: the CPU of the benchmark's containers, each a
    percent of ONE core, added over a complete tick and divided by the recorded Docker NCPU, so 100 means
    every CPU of the VM is fully used.  None for a failed or incomplete tick and when NCPU is not a
    positive whole number.  Host processes and the host's CPU are not part of this.
    """
    usable_cpu = isinstance(ncpu, int) and not isinstance(ncpu, bool) and ncpu > 0
    series: list[tuple[float, Optional[float]]] = []
    previous: Optional[float] = None
    for sample in samples:
        at, rows = _sample_time(sample, previous)
        previous = at
        value: Optional[float] = None
        if usable_cpu and isinstance(rows, (list, tuple)) and len(rows) == expected_containers:
            names = [_row_name(row) for row in rows]
            if None not in names and len(set(names)) == len(names) \
                    and all(_plain(row.get("cpu_percent")) for row in rows):
                value = sum(float(row["cpu_percent"]) for row in rows) / ncpu
        series.append((at, value))
    return series


def docker_memory_ticks(samples: Sequence[Any], *, expected_containers: int
                        ) -> list[tuple[float, Optional[int], Optional[int]]]:
    """
    (time, complete aggregate, lower bound) per sample.  The aggregate is the memory the benchmark's
    containers report, added over a complete tick (the same moment for every container), or None.  The
    lower bound is the sum of the valid distinct rows of a tick that is not complete (what was measured is
    at least this much), or None when nothing valid was read.  Independent per-container peaks are never added.
    """
    ticks: list[tuple[float, Optional[int], Optional[int]]] = []
    previous: Optional[float] = None
    for sample in samples:
        at, rows = _sample_time(sample, previous)
        previous = at
        aggregate: Optional[int] = None
        bound: Optional[int] = None
        if isinstance(rows, (list, tuple)):
            seen: dict[str, int] = {}
            for row in rows:
                name = _row_name(row)
                if name is not None and name not in seen and _plain(row.get("memory_used_bytes"), integer=True):
                    seen[name] = int(row["memory_used_bytes"])
            if seen:
                bound = sum(seen.values())
                if len(rows) == expected_containers and len(seen) == expected_containers:
                    aggregate = bound
        ticks.append((at, aggregate, bound))
    return ticks


def sustained_cpu_saturation(series: Sequence[tuple[float, Optional[float]]], *, percent: float,
                             seconds: float, max_gap_seconds: float) -> Optional[float]:
    """
    The span in seconds of the first run of consecutive usable ticks, all at or above `percent`, that lasts
    at least `seconds`; None when there is none.  A failed or incomplete tick (value None) ends a run, and so
    does a gap of more than max_gap_seconds between consecutive ticks, because nothing is known about the
    time between them.  The span is last minus first tick time (>= is enough, as in resource_stops).
    """
    percent = _finite(percent, "percent")
    seconds = _finite(seconds, "seconds")
    max_gap_seconds = _finite(max_gap_seconds, "max_gap_seconds")
    started: Optional[float] = None
    previous: Optional[float] = None
    for at, value in series:
        at = _finite(at, "tick time")
        if previous is not None:
            if at < previous:
                raise MetricError("cpu ticks must be in time order")
            if at - previous > max_gap_seconds + _COVERAGE_EPSILON:
                started = None
        previous = at
        if value is None or value < percent:
            started = None
            continue
        started = at if started is None else started
        if at - started >= seconds - _COVERAGE_EPSILON:
            return at - started
    return None


def docker_memory_stops(ticks: Sequence[tuple[float, Optional[int], Optional[int]]], *, vm_bytes: Any,
                        memory_fraction: float = MEMORY_FRACTION_MAX) -> tuple[str, ...]:
    """
    A stop reason when the containers' summed memory exceeds memory_fraction of the Docker VM's memory.  A
    complete tick is judged by its aggregate.  A tick that is not complete is judged by its lower bound, which
    is conclusive only when it already exceeds the limit; otherwise it proves nothing and is ignored here (the
    coverage rule decides whether enough complete ticks exist).  Empty when vm_bytes is not a positive count.
    """
    if not isinstance(vm_bytes, int) or isinstance(vm_bytes, bool) or vm_bytes <= 0:
        return ()
    worst: Optional[tuple[float, bool]] = None
    for _, aggregate, bound in ticks:
        value, lower = (aggregate, False) if aggregate is not None else (bound, True)
        if value is None:
            continue
        share = value / vm_bytes
        if share > memory_fraction and (worst is None or share > worst[0]):
            worst = (share, lower)
    if worst is None:
        return ()
    note = " (a measured lower bound)" if worst[1] else ""
    return (f"Docker containers memory {worst[0]:.1%} of the Docker VM's {vm_bytes} bytes "
            f"> {memory_fraction:.0%}{note}",)


@dataclass(frozen=True)
class UsableCoverage:
    """How well the usable ticks of one resource cover the sampler's window."""
    usable: int
    first: Optional[float]
    last: Optional[float]
    max_gap: Optional[float]
    fraction: Optional[float]
    problems: tuple[str, ...]


def usable_coverage(times: Sequence[float], *, window_seconds: Any, interval: Any,
                    min_ticks: int = DOCKER_COVERAGE_MIN_TICKS,
                    min_fraction: float = DOCKER_COVERAGE_MIN_FRACTION,
                    edge_factor: float = DOCKER_COVERAGE_EDGE_FACTOR,
                    gap_factor: float = DOCKER_COVERAGE_GAP_FACTOR) -> UsableCoverage:
    """
    Whether `times` (the usable ticks of one resource, in the sampler's own seconds) cover the window from the
    sampler's start (0) to its stop (`window_seconds`): at least min_ticks of them; (last - first) / window at
    least min_fraction; the first within edge_factor x interval of the start and the last within that of the
    stop; and no gap above gap_factor x interval.  Every shortfall is a problem; none means adequate.
    """
    problems: list[str] = []
    ordered = sorted(float(t) for t in times)
    usable = len(ordered)
    window_ok = _plain(window_seconds) and window_seconds > 0
    interval_ok = _plain(interval) and interval > 0
    if not window_ok:
        problems.append("the sampler's observation window is unknown or empty")
    if not interval_ok:
        problems.append("the sampling interval is unknown")
    if usable < min_ticks:
        problems.append(f"{usable} usable ticks, fewer than {min_ticks}")
    first = ordered[0] if ordered else None
    last = ordered[-1] if ordered else None
    gaps = [b - a for a, b in zip(ordered, ordered[1:])]
    max_gap = max(gaps) if gaps else None
    fraction = None
    if window_ok and first is not None and last is not None:
        fraction = (last - first) / window_seconds
        if fraction < min_fraction - _COVERAGE_EPSILON:
            problems.append(f"usable ticks cover {fraction:.0%} of the window, less than {min_fraction:.0%}")
    if window_ok and interval_ok and first is not None and last is not None:
        if first > edge_factor * interval + _COVERAGE_EPSILON:
            problems.append(f"the first usable tick came {first:.1f} s after the window start "
                            f"(more than {edge_factor:g} x the interval)")
        if window_seconds - last > edge_factor * interval + _COVERAGE_EPSILON:
            problems.append(f"the last usable tick came {window_seconds - last:.1f} s before the window end "
                            f"(more than {edge_factor:g} x the interval)")
    if interval_ok and max_gap is not None and max_gap > gap_factor * interval + _COVERAGE_EPSILON:
        problems.append(f"a gap of {max_gap:.1f} s between usable ticks (more than {gap_factor:g} x the interval)")
    return UsableCoverage(usable, first, last, max_gap, fraction, tuple(problems))


#: The optional Docker-resource names under metrics.resources and their units.  Optional: results written
#: before B3J-287 have none, and keep validating as they are.
DOCKER_RESOURCE_FAMILIES: Mapping[str, tuple[str, str]] = {
    "docker_vm_cpu_percent": ("%", "max"),
    "docker_memory_aggregate_bytes": ("bytes", "max"),
}
DOCKER_RESOURCE_FRACTION = "docker_memory_aggregate_fraction_max"
DOCKER_RESOURCE_COVERAGE = "docker_resource_coverage"
DOCKER_VM_CPU_PERCENT_LIMIT = 150.0
DOCKER_COVERAGE_COUNTS: Mapping[str, str] = {
    "expected_containers": "containers", "ncpu": "cpus", "vm_memory_bytes": "bytes", "ticks_attempted": "ticks",
    "ticks_failed": "ticks", "cpu_ticks_usable": "ticks", "memory_ticks_usable": "ticks",
    "memory_ticks_lower_bound_only": "ticks"}
DOCKER_COVERAGE_SECONDS: tuple[str, ...] = (
    "window_seconds", "interval_seconds", "cpu_first_usable_s", "cpu_last_usable_s", "cpu_max_gap_s",
    "memory_first_usable_s", "memory_last_usable_s", "memory_max_gap_s")
DOCKER_COVERAGE_FRACTIONS: tuple[str, ...] = ("cpu_window_fraction", "memory_window_fraction")


def docker_resource_problems(resources: Any) -> list[str]:
    """Everything wrong with the Docker-resource observations of a result's metrics.resources; empty when
    there are none (an older result) or when they are consistent."""
    if not isinstance(resources, Mapping):
        return []
    present = {n for n in resources if isinstance(n, str) and n.startswith("docker_")}
    if not present:
        return []
    problems: list[str] = []
    known = {DOCKER_RESOURCE_FRACTION, DOCKER_RESOURCE_COVERAGE}
    for family, (_, extreme) in DOCKER_RESOURCE_FAMILIES.items():
        known.update({f"{family}_{extreme}", f"{family}_series", f"{family}_series_times_s"})
    for name in sorted(present - known):
        problems.append(f"metrics.resources.{name}: not a Docker resource observation")
    if DOCKER_RESOURCE_COVERAGE not in resources:
        problems.append(f"metrics.resources.{DOCKER_RESOURCE_COVERAGE} is required with Docker resource observations")
    lengths: dict[tuple[str, str], int] = {}
    for family, (unit, extreme) in DOCKER_RESOURCE_FAMILIES.items():
        limit = DOCKER_VM_CPU_PERCENT_LIMIT if unit == "%" else math.inf
        _family_problems(resources, family, unit, extreme, limit, lengths, problems, "Docker")
    fraction = resources.get(DOCKER_RESOURCE_FRACTION)
    if DOCKER_RESOURCE_FRACTION in resources:
        for key, leaf in (fraction.items() if isinstance(fraction, Mapping) else []):
            if _measured_leaf(leaf) is None:
                continue
            value = leaf.get("value")
            if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != "fraction" or not _plain(value):
                problems.append(f"metrics.resources.{DOCKER_RESOURCE_FRACTION}.{key}: a non-negative fraction")
    coverage = resources.get(DOCKER_RESOURCE_COVERAGE)
    if coverage is not None:
        problems.extend(_docker_coverage_problems(coverage, resources, lengths))
    return problems


def _docker_coverage_problems(coverage: Any, resources: Mapping[str, Any],
                              lengths: Mapping[tuple[str, str], int]) -> list[str]:
    where = f"metrics.resources.{DOCKER_RESOURCE_COVERAGE}"
    if not isinstance(coverage, Mapping):
        return [f"{where}: must be a mapping"]
    problems: list[str] = []
    allowed = {**DOCKER_COVERAGE_COUNTS, **{n: "s" for n in DOCKER_COVERAGE_SECONDS},
               **{n: "fraction" for n in DOCKER_COVERAGE_FRACTIONS}}
    for name in sorted(set(coverage) - set(allowed)):
        problems.append(f"{where}.{name}: not a coverage entry")
    for name in sorted(set(allowed) - set(coverage)):
        problems.append(f"{where}.{name}: missing")
    values: dict[str, float] = {}
    for name, unit in allowed.items():
        leaf = coverage.get(name)
        if _measured_leaf(leaf) is None:
            continue
        value = leaf.get("value")
        whole = name in DOCKER_COVERAGE_COUNTS
        if leaf.get("kind") != "OBSERVATION" or leaf.get("unit") != unit or isinstance(value, (bool, list)) \
                or not _plain(value, integer=whole):
            problems.append(f"{where}.{name}: a non-negative {unit} observation"
                            + (" (a whole number)" if whole else ""))
            continue
        values[name] = value
    if "window_seconds" in values and values["window_seconds"] <= 0:
        problems.append(f"{where}.window_seconds: must be positive")
    if "interval_seconds" in values and values["interval_seconds"] <= 0:
        problems.append(f"{where}.interval_seconds: must be positive")
    attempted = values.get("ticks_attempted")
    if attempted is not None:
        for name in ("ticks_failed", "cpu_ticks_usable", "memory_ticks_usable", "memory_ticks_lower_bound_only"):
            if name in values and values[name] > attempted:
                problems.append(f"{where}.{name}: more than the ticks attempted")
        if "memory_ticks_usable" in values and "memory_ticks_lower_bound_only" in values \
                and values["memory_ticks_usable"] + values["memory_ticks_lower_bound_only"] > attempted:
            problems.append(f"{where}: complete and lower-bound-only memory ticks exceed the ticks attempted")
    for prefix in ("cpu", "memory"):
        first, last = values.get(f"{prefix}_first_usable_s"), values.get(f"{prefix}_last_usable_s")
        if first is not None and last is not None and first > last:
            problems.append(f"{where}: the first {prefix} tick is after the last")
        if f"{prefix}_window_fraction" in values and values[f"{prefix}_window_fraction"] > 1 + 1e-9:
            problems.append(f"{where}.{prefix}_window_fraction: more than 1")
    for family, key_name, count_name in (("docker_vm_cpu_percent", "benchmark-containers", "cpu_ticks_usable"),
                                         ("docker_memory_aggregate_bytes", "benchmark-containers",
                                          "memory_ticks_usable")):
        length = lengths.get((family, key_name))
        if count_name in values and length is not None and values[count_name] != length:
            problems.append(f"{where}.{count_name}: differs from the length of {family}_series")
    peak = resources.get("docker_memory_aggregate_bytes_max")
    share = resources.get(DOCKER_RESOURCE_FRACTION)
    if isinstance(peak, Mapping) and isinstance(share, Mapping) and "vm_memory_bytes" in values:
        a, b = _measured_leaf(peak.get("benchmark-containers")), _measured_leaf(share.get("benchmark-containers"))
        if a is not None and b is not None and values["vm_memory_bytes"] > 0 \
                and abs(a["value"] / values["vm_memory_bytes"] - b["value"]) > 1e-6:
            problems.append(f"metrics.resources.{DOCKER_RESOURCE_FRACTION}: not the peak over vm_memory_bytes")
    return problems


def host_block_problems(block: Any) -> list[str]:
    """What is wrong with a result's `host` block.  Strict: every field is checked, and the
    interruption indicator must follow from the query status and the events, so that a failed
    query can never read as 'no events'."""
    if not isinstance(block, Mapping):
        return ["host must be a mapping"]
    if set(block) != HOST_KEYS:
        return [f"host must hold exactly {sorted(HOST_KEYS)}"]
    problems: list[str] = []
    if block["platform"] != "windows":
        problems.append("host.platform must be 'windows'")
    keep = block["keep_awake"]
    if not isinstance(keep, Mapping) or set(keep) != {"acquisition", "readback"}:
        problems.append("host.keep_awake must hold exactly acquisition and readback")
    else:
        if keep["acquisition"] not in HOST_KEEP_AWAKE_ACQUISITION:
            problems.append("host.keep_awake.acquisition is not a known status")
        if keep["readback"] not in HOST_KEEP_AWAKE_READBACK:
            problems.append("host.keep_awake.readback is not a known status")
    session = block["session"]
    if not isinstance(session, Mapping) or set(session) != {"start", "end"}:
        problems.append("host.session must hold exactly start and end")
    else:
        problems += _session_state_problems(session["start"], "host.session.start")
        problems += _session_state_problems(session["end"], "host.session.end")
    window = block["window"]
    start = end = None
    if not isinstance(window, Mapping) or set(window) != {"start_utc", "end_utc"}:
        problems.append("host.window must hold exactly start_utc and end_utc")
    else:
        start, end = _host_time(window["start_utc"]), _host_time(window["end_utc"])
        if start is None or end is None:
            problems.append("host.window times must be UTC ISO-8601 with a trailing Z")
        elif end < start:
            problems.append("host.window ends before it starts")
    events_problem_free = False
    power = block["power_events"]
    expected_flag: Optional[bool] = None
    if not isinstance(power, Mapping) or set(power) != {
            "status", "error", "query_seconds", "truncated", "events", "episodes"}:
        problems.append("host.power_events must hold exactly status, error, query_seconds, truncated, "
                        "events and episodes")
    else:
        status, error = power["status"], power["error"]
        if status not in HOST_POWER_STATUSES:
            problems.append("host.power_events.status must be 'ok' or 'failed'")
        elif status == "ok" and error is not None:
            problems.append("host.power_events.error must be null when the query succeeded")
        elif status == "failed" and (not isinstance(error, str) or not error.strip() or len(error) > HOST_ERROR_LIMIT):
            problems.append(f"host.power_events.error must be a text of 1-{HOST_ERROR_LIMIT} characters when the query failed")
        seconds = power["query_seconds"]
        if seconds is not None and (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                                    or seconds != seconds or seconds < 0 or seconds == float("inf")):
            problems.append("host.power_events.query_seconds must be a non-negative number or null")
        if not isinstance(power["truncated"], bool):
            problems.append("host.power_events.truncated must be true or false")
        events, episodes = power["events"], power["episodes"]
        if not isinstance(events, list) or len(events) > HOST_MAX_EVENTS:
            problems.append(f"host.power_events.events must be a list of at most {HOST_MAX_EVENTS}")
        elif status == "failed" and events:
            problems.append("host.power_events.events must be empty when the query failed")
        else:
            previous = None
            events_problem_free = True
            for index, event in enumerate(events):
                where = f"host.power_events.events[{index}]"
                if not isinstance(event, Mapping) or set(event) != {"time_utc", "id", "reason"}:
                    problems.append(f"{where} must hold exactly time_utc, id and reason")
                    events_problem_free = False
                    continue
                moment = _host_time(event["time_utc"])
                if moment is None or isinstance(event["id"], bool) or event["id"] not in HOST_POWER_EVENT_IDS:
                    problems.append(f"{where} needs a UTC time and id 506 or 507")
                    events_problem_free = False
                    continue
                if event["reason"] is not None and (isinstance(event["reason"], bool) or not isinstance(event["reason"], int)):
                    problems.append(f"{where}.reason must be a whole number or null")
                if start is not None and end is not None and not start <= moment <= end:
                    problems.append(f"{where} lies outside the window")
                if previous is not None and moment < previous:
                    problems.append(f"{where} is out of order")
                previous = moment
        if not isinstance(episodes, list) or len(episodes) > HOST_MAX_EVENTS:
            problems.append(f"host.power_events.episodes must be a list of at most {HOST_MAX_EVENTS}")
        else:
            if status == "failed" and episodes:
                problems.append("host.power_events.episodes must be empty when the query failed")
            for index, episode in enumerate(episodes):
                where = f"host.power_events.episodes[{index}]"
                if not isinstance(episode, Mapping) or set(episode) != {"entered_utc", "exited_utc", "seconds"}:
                    problems.append(f"{where} must hold exactly entered_utc, exited_utc and seconds")
                    continue
                entered, exited = episode["entered_utc"], episode["exited_utc"]
                if entered is None and exited is None:
                    problems.append(f"{where} needs an entry or an exit")
                if (entered is not None and _host_time(entered) is None) or (exited is not None and _host_time(exited) is None):
                    problems.append(f"{where} times must be UTC ISO-8601 with a trailing Z")
                seconds_value = episode["seconds"]
                if (entered is None or exited is None) != (seconds_value is None):
                    problems.append(f"{where}.seconds must be present exactly for a complete episode")
                elif seconds_value is not None and (isinstance(seconds_value, bool) or not isinstance(seconds_value, (int, float))
                                                    or seconds_value < 0 or seconds_value != seconds_value):
                    problems.append(f"{where}.seconds must be a non-negative number")
        if status == "ok" and events_problem_free and isinstance(events, list):
            expected_flag = bool(events)
        elif status == "failed":
            expected_flag = None
    flag = block["host_interruption_suspected"]
    if flag is not None and not isinstance(flag, bool):
        problems.append("host.host_interruption_suspected must be true, false or null")
    elif isinstance(power, Mapping) and power.get("status") in HOST_POWER_STATUSES and events_problem_free \
            and flag is not expected_flag:
        problems.append("host.host_interruption_suspected does not follow from the query: false only for a "
                        "successful query with no events, true for events, null for a failed query")
    return problems


def _plain_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _plain_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value \
        and abs(value) != float("inf")


def consumer_block_problems(block: Any) -> list[str]:
    """What is wrong with a result's `consumer` block.  CONFIGURED values (commit_batching, the
    timing interval) must be consistent with each other; `observed` holds measurements and is
    optional; nothing is inferred for a field that is not there."""
    if not isinstance(block, Mapping):
        return ["consumer must be a mapping"]
    keys = set(block)
    problems = [f"consumer is missing {sorted(CONSUMER_KEYS - keys)}"] if CONSUMER_KEYS - keys else []
    extra = keys - CONSUMER_KEYS - CONSUMER_OPTIONAL_KEYS
    if extra:
        problems.append(f"consumer has unexpected keys {sorted(extra)}")
    if problems:
        return problems
    batching = block["commit_batching"]
    if not isinstance(batching, Mapping) or set(batching) != COMMIT_BATCHING_KEYS:
        problems.append("consumer.commit_batching must hold exactly enabled, batch_messages and interval_seconds")
    else:
        enabled, size, interval = batching["enabled"], batching["batch_messages"], batching["interval_seconds"]
        low, high = COMMIT_BATCH_RANGE
        if not isinstance(enabled, bool):
            problems.append("consumer.commit_batching.enabled must be true or false")
        if isinstance(size, bool) or not isinstance(size, int) or not low <= size <= high:
            problems.append(f"consumer.commit_batching.batch_messages must be a whole number from {low} to {high}")
        elif isinstance(enabled, bool):
            if enabled != (size > 1):
                problems.append("consumer.commit_batching.enabled does not match batch_messages > 1")
            elif enabled:
                low_s, high_s = COMMIT_INTERVAL_RANGE
                if not _plain_number(interval) or not low_s <= interval <= high_s:
                    problems.append(f"consumer.commit_batching.interval_seconds must be a number from {low_s:g} to {high_s:g}")
            elif interval is not None:
                problems.append("consumer.commit_batching.interval_seconds must be null when batching is disabled")
    timing = block["timing_diagnostic_interval_seconds"]
    if not _plain_number(timing) or timing < 0:
        problems.append("consumer.timing_diagnostic_interval_seconds must be a non-negative number")
    if "observed" in block:
        observed = block["observed"]
        if not isinstance(observed, Mapping) or set(observed) != OBSERVED_COMMIT_KEYS:
            problems.append("consumer.observed must hold exactly " + ", ".join(sorted(OBSERVED_COMMIT_KEYS)))
        else:
            for name in ("windows", "messages", "commit_calls"):
                if not _plain_count(observed[name]):
                    problems.append(f"consumer.observed.{name} must be a non-negative integer")
            if not _plain_number(observed["window_seconds"]) or observed["window_seconds"] < 0:
                problems.append("consumer.observed.window_seconds must be a non-negative number")
            for name in ("mean_messages_per_commit", "mean_seconds_between_commits", "mean_commit_ms"):
                value = observed[name]
                if value is not None and (not _plain_number(value) or value < 0):
                    problems.append(f"consumer.observed.{name} must be a non-negative number or null")
            if _plain_count(observed["windows"]) and observed["windows"] < 1:
                problems.append("consumer.observed.windows must be at least 1 (otherwise there is nothing observed)")
            if _plain_count(observed["messages"]) and _plain_count(observed["commit_calls"]):
                if observed["commit_calls"] > observed["messages"]:
                    problems.append("consumer.observed.commit_calls exceeds messages")
                if (observed["commit_calls"] == 0) != (observed["mean_messages_per_commit"] is None):
                    problems.append("consumer.observed means must be null exactly when there was no commit")
    return problems


def validate_result(result: Any) -> None:
    """
    Raises MetricError listing every problem of a benchmark result; returns
    None for a well-formed one.  A result is checked for its shape and for
    the consistency of its verdict, never for whether its numbers are good.
    """
    problems: list[str] = []

    def problem(text: str) -> None:
        problems.append(text)

    if not isinstance(result, Mapping):
        raise MetricError("a result must be a mapping")
    keys = set(result)
    if not RESULT_KEYS <= keys:
        problem(f"missing keys {sorted(RESULT_KEYS - keys)}")
    if keys - RESULT_KEYS - RESULT_OPTIONAL_KEYS:
        problem(f"unexpected keys {sorted(keys - RESULT_KEYS - RESULT_OPTIONAL_KEYS)}")
    if problems:
        raise MetricError("; ".join(problems))

    if not isinstance(result["benchmark_id"], str) or not BENCHMARK_ID_RE.fullmatch(
            result["benchmark_id"]):
        problem("benchmark_id does not match bm-<level>-r<rate>-c<concurrency>-rep<n>")
    if not isinstance(result["git_sha"], str) or not GIT_SHA_RE.fullmatch(result["git_sha"]):
        problem("git_sha must be 40 lowercase hex characters")
    if not isinstance(result["git_dirty"], bool):
        problem("git_dirty must be true or false")
    stamps = result["timestamps"]
    if not isinstance(stamps, Mapping) or not {"started", "finished"} <= set(stamps):
        problem("timestamps must hold started and finished")
    else:
        for name, value in stamps.items():
            if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
                problem(f"timestamps.{name} is not an ISO-8601 time with a zone")
    if not isinstance(result["machine"], Mapping):
        problem("machine must be a mapping")
    if "consumer" in result:
        for text in consumer_block_problems(result["consumer"]):
            problem(text)
    if "host" in result:
        for text in host_block_problems(result["host"]):
            problem(text)
    if isinstance(result.get("metrics"), Mapping):
        for text in host_resource_problems(result["metrics"].get("resources")):
            problem(text)
        for text in host_memory_checkpoint_problems(result["metrics"].get("resources")):
            problem(text)
        for text in docker_resource_problems(result["metrics"].get("resources")):
            problem(text)

    workload = result["workload"]
    if not isinstance(workload, Mapping) or "target" not in workload:
        problem("workload must hold its target")
    elif any(key in workload for key in ("achieved", "results", "metrics")):
        problem("workload holds targets only; what was achieved belongs in counts and metrics")

    counts = result["counts"]
    if not isinstance(counts, Mapping):
        problem("counts must be a mapping")
    else:
        for name, value in counts.items():
            if isinstance(value, Mapping):
                try:
                    check_metric(value, f"counts.{name}")
                except MetricError as exc:
                    problem(str(exc))
                else:
                    if value["kind"] != "NOT_MEASURED":
                        problem(f"counts.{name}: a count is an integer or NOT_MEASURED")
            elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
                problem(f"counts.{name} must be a non-negative integer or NOT_MEASURED")

    try:
        for path, metric in _walk_metrics(result["metrics"], "metrics"):
            try:
                check_metric(metric, path)
            except MetricError as exc:
                problem(str(exc))
    except MetricError as exc:
        problem(str(exc))

    clock = result["clock"]
    if isinstance(clock, Mapping) and clock.get("kind") == "NOT_MEASURED":
        try:
            check_metric(clock, "clock")
        except MetricError as exc:
            problem(str(exc))
        clock_valid: Optional[bool] = None
    elif isinstance(clock, Mapping) and {"skew_ms", "uncertainty_ms", "drift_ms", "valid",
                                         "reasons"} == set(clock):
        clock_valid = clock["valid"] if isinstance(clock["valid"], bool) else None
        if clock_valid is None:
            problem("clock.valid must be true or false")
    else:
        problem("clock must be a clock check or NOT_MEASURED")
        clock_valid = None

    integrity = result["integrity"]
    if not isinstance(integrity, Mapping) or "ok" not in integrity or "gates" not in integrity:
        problem("integrity must hold ok and gates")
        integrity_ok: Optional[bool] = None
    else:
        integrity_ok = integrity["ok"]
        if integrity_ok not in (True, False, None):
            problem("integrity.ok must be true, false or null")
        gates = integrity["gates"]
        if not isinstance(gates, list) or any(
                not isinstance(g, Mapping) or set(g) != {"name", "ok", "evidence"} for g in gates):
            problem("integrity.gates must be a list of {name, ok, evidence}")
        elif integrity_ok is True and (not gates or not all(g["ok"] is True for g in gates)):
            problem("integrity.ok is true but a gate did not pass")

    value = result["verdict"]
    if value not in VERDICTS:
        problem(f"verdict {value!r} is not one of {list(VERDICTS)}")
    else:
        stop = result.get("stop", {"reasons": [], "generator_bound": False})
        reasons = stop.get("reasons", []) if isinstance(stop, Mapping) else None
        bound = stop.get("generator_bound", False) if isinstance(stop, Mapping) else None
        if not isinstance(reasons, list) or not isinstance(bound, bool):
            problem("stop must hold a reasons list and generator_bound")
        else:
            expected = verdict(integrity_ok=integrity_ok if integrity_ok in (True, False) else None,
                               stop_reasons=reasons, generator_bound_run=bound)
            if expected != value:
                problem(f"verdict {value} contradicts the evidence, which gives {expected}")
            metrics_block = result.get("metrics")
            for text in host_memory_checkpoint_consistency_problems(
                    metrics_block.get("resources") if isinstance(metrics_block, Mapping) else None, reasons, value):
                problem(text)
        claims = result.get("claims")
        host = result.get("host")
        interrupted = isinstance(host, Mapping) and host.get("host_interruption_suspected") is True
        if claims is not None and claims != claim_eligibility(value, clock_valid, interrupted):
            problem("claims do not follow from the verdict and the clock check")

    limitations = result["limitations"]
    if not isinstance(limitations, list) or not all(
            isinstance(item, str) and item.strip() for item in limitations):
        problem("limitations must be a list of non-empty strings")

    if problems:
        raise MetricError("; ".join(problems))

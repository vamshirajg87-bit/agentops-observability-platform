from __future__ import annotations

from typing import Optional, Sequence

from .anomaly_types import AnomalyEvent, LatencyRecord
from .baselines import Observation, compute_baseline
from .config import DetectorConfig
from .scoring import ScoringResult, score_observation

_DEFAULT_CONFIG = DetectorConfig(
    direction="HIGH",
    z_threshold=3.5,
    absolute_floor=50.0,    # ms: practical minimum for a significant latency deviation
    min_baseline_n=30,
    min_baseline_n_low_confidence=10,
    baseline_window_days=7,
)


class LatencyDetector:
    """
    Detects anomalously HIGH latency using the modified z-score approach from
    the Phase 10.2 statistical core.

    Each call to detect() scores one (current) LatencyRecord against the
    matching group in the provided history.  Groups are defined by
    (service_name, operation_name).  ERROR observations are excluded from
    latency baselines because their duration reflects failure overhead, not
    healthy operation latency.  ERROR spans are never emitted as latency
    anomalies; error detection belongs to ErrorRateDetector.
    """

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config if config is not None else _DEFAULT_CONFIG

    def detect(
        self,
        current: LatencyRecord,
        history: Sequence[LatencyRecord],
    ) -> list[AnomalyEvent]:
        """
        Score current against its group's baseline derived from history.

        Returns a list with one AnomalyEvent when the observation is anomalous,
        or an empty list otherwise (including when current.is_error is True).
        """
        if current.is_error:
            return []

        group = [
            r for r in history
            if r.service_name == current.service_name
            and r.operation_name == current.operation_name
        ]
        observations = [
            Observation(value=r.duration_ms, start_time=r.start_time, is_error=r.is_error)
            for r in group
        ]
        baseline = compute_baseline(
            observations,
            current.start_time,
            self.config.baseline_window_days,
            exclude_errors=True,
        )
        result = score_observation(current.duration_ms, baseline, self.config)
        if result.severity is None:
            return []
        return [_build_event(current, result)]


def _build_event(rec: LatencyRecord, result: ScoringResult) -> AnomalyEvent:
    b = result.baseline
    return AnomalyEvent(
        anomaly_type="latency",
        signal_name="duration_ms",
        detector_name="LatencyDetector",
        detector_version="1.0",
        trace_id=rec.trace_id,
        span_id=rec.span_id,
        service_name=rec.service_name,
        operation_name=rec.operation_name,
        observed_value=rec.duration_ms,
        observed_at=rec.start_time,
        baseline_median=b.median if b else None,
        baseline_mad=b.mad if b else None,
        baseline_n=b.n if b else None,
        baseline_window_start=b.window_start if b else None,
        baseline_window_end=b.window_end if b else None,
        anomaly_score=result.modified_z,
        severity=result.severity,
        explanation=_explain(rec.duration_ms, result),
    )


def _explain(observed: float, result: ScoringResult) -> str:
    b = result.baseline
    if b is None:
        return f"duration_ms={observed:.1f}; insufficient_history"
    parts = [f"duration_ms={observed:.1f}"]
    parts.append(f"baseline_median={b.median:.1f} MAD={b.mad:.1f} n={b.n}")
    if result.modified_z is not None:
        parts.append(f"modified_z={result.modified_z:.2f} direction=HIGH")
    else:
        parts.append(f"deviation={result.absolute_deviation:.1f} (zero-MAD)")
    return "; ".join(parts)

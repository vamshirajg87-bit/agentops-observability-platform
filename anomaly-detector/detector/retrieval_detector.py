from __future__ import annotations

from typing import Optional, Sequence

from .anomaly_types import AnomalyEvent, RetrievalRecord
from .baselines import Observation, compute_baseline
from .config import DetectorConfig
from .scoring import ScoringResult, score_observation

_DEFAULT_RELEVANCE_CONFIG = DetectorConfig(
    direction="LOW",
    z_threshold=3.5,
    absolute_floor=0.05,    # 5 pp on the 0-1 relevance scale
    min_baseline_n=30,
    min_baseline_n_low_confidence=10,
    baseline_window_days=7,
)

_DEFAULT_COUNT_CONFIG = DetectorConfig(
    direction="LOW",
    z_threshold=3.5,
    absolute_floor=1.0,     # must differ from baseline by at least 1 result
    min_baseline_n=30,
    min_baseline_n_low_confidence=10,
    baseline_window_days=7,
)


class RetrievalQualityDetector:
    """
    Detects anomalously LOW retrieval quality using the Phase 10.2 statistical core.

    Signals:
        retrieval_top_relevance_score  — direction=LOW; floor=0.05
        retrieval_result_count         — direction=LOW; floor=1.0 (0 is a valid count)

    Both signals are NULL-safe: a None value skips that signal silently.  The
    detector never flags HIGH values; elevated relevance or result count is
    never an anomaly under this design.

    Groups are isolated by service_name.  One call may return 0, 1, or 2 events
    depending on how many signals are present and anomalous.
    """

    def __init__(
        self,
        relevance_config: Optional[DetectorConfig] = None,
        count_config: Optional[DetectorConfig] = None,
    ) -> None:
        self.relevance_config = (
            relevance_config if relevance_config is not None else _DEFAULT_RELEVANCE_CONFIG
        )
        self.count_config = (
            count_config if count_config is not None else _DEFAULT_COUNT_CONFIG
        )

    def detect(
        self,
        current: RetrievalRecord,
        history: Sequence[RetrievalRecord],
    ) -> list[AnomalyEvent]:
        group = [r for r in history if r.service_name == current.service_name]
        events: list[AnomalyEvent] = []

        # --- Relevance score ---
        if current.retrieval_top_relevance_score is not None:
            relevance_obs = [
                Observation(
                    value=r.retrieval_top_relevance_score,
                    start_time=r.start_time,
                    is_error=r.is_error,
                )
                for r in group
                if r.retrieval_top_relevance_score is not None
            ]
            baseline = compute_baseline(
                relevance_obs,
                current.start_time,
                self.relevance_config.baseline_window_days,
            )
            result = score_observation(
                current.retrieval_top_relevance_score, baseline, self.relevance_config
            )
            if result.severity is not None:
                events.append(
                    _build_event(
                        rec=current,
                        signal="retrieval_top_relevance_score",
                        observed_value=current.retrieval_top_relevance_score,
                        result=result,
                    )
                )

        # --- Result count ---
        if current.retrieval_result_count is not None:
            count_val = float(current.retrieval_result_count)
            count_obs = [
                Observation(
                    value=float(r.retrieval_result_count),
                    start_time=r.start_time,
                    is_error=r.is_error,
                )
                for r in group
                if r.retrieval_result_count is not None
            ]
            baseline = compute_baseline(
                count_obs,
                current.start_time,
                self.count_config.baseline_window_days,
            )
            result = score_observation(count_val, baseline, self.count_config)
            if result.severity is not None:
                events.append(
                    _build_event(
                        rec=current,
                        signal="retrieval_result_count",
                        observed_value=count_val,
                        result=result,
                    )
                )

        return events


def _build_event(
    rec: RetrievalRecord,
    signal: str,
    observed_value: float,
    result: ScoringResult,
) -> AnomalyEvent:
    b = result.baseline
    return AnomalyEvent(
        anomaly_type="retrieval_quality",
        signal_name=signal,
        detector_name="RetrievalQualityDetector",
        detector_version="1.0",
        trace_id=rec.trace_id,
        span_id=rec.span_id,
        service_name=rec.service_name,
        operation_name="retrieval.search",
        observed_value=observed_value,
        observed_at=rec.start_time,
        baseline_median=b.median if b else None,
        baseline_mad=b.mad if b else None,
        baseline_n=b.n if b else None,
        baseline_window_start=b.window_start if b else None,
        baseline_window_end=b.window_end if b else None,
        anomaly_score=result.modified_z,
        severity=result.severity,
        explanation=_explain(signal, observed_value, result),
    )


def _explain(signal: str, observed: float, result: ScoringResult) -> str:
    b = result.baseline
    if b is None:
        return f"{signal}={observed}; insufficient_history"
    parts = [f"{signal}={observed}"]
    parts.append(f"baseline_median={b.median} MAD={b.mad} n={b.n}")
    if result.modified_z is not None:
        parts.append(f"modified_z={result.modified_z:.2f} direction=LOW")
    else:
        parts.append(f"deviation={result.absolute_deviation} (zero-MAD)")
    return "; ".join(parts)

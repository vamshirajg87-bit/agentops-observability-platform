from __future__ import annotations

from datetime import timedelta
from typing import Optional, Sequence

from .anomaly_types import AnomalyEvent, ErrorDetectorConfig, ToolRecord
from .severity import assign_error_severity

_DEFAULT_CONFIG = ErrorDetectorConfig()


class ToolFailureDetector:
    """
    Detects anomalous tool execution failures using novelty, rate, and persistence
    signals – specifically for spans where span_name='tool.execute'.

    Phase 10.4 is responsible for filtering input records to tool.execute spans
    before calling this detector.  tool_name is absent from ToolRecord because it
    is NULL on error spans in the real schema; error_type is used as the
    discriminating key instead.

    Groups are isolated by (service_name, error_type): each distinct error_type
    on tool.execute spans is scored independently.

    Rate computation:
        numerator   = tool.execute spans with this error_type in the recent window
        denominator = ALL tool.execute spans in the window (error + success)
        This answers: "Is this error type occurring more often than usual as a
        fraction of all tool executions?"

    Returns an empty list when current.is_error is False or current.error_type
    is None; both conditions must hold for meaningful tool-failure scoring.
    """

    def __init__(self, config: Optional[ErrorDetectorConfig] = None) -> None:
        self.config = config if config is not None else _DEFAULT_CONFIG

    def detect(
        self,
        current: ToolRecord,
        history: Sequence[ToolRecord],
    ) -> list[AnomalyEvent]:
        if not current.is_error or current.error_type is None:
            return []

        is_first, is_novel, rate_ratio, n_recent, is_persistent = _analyse(
            current, history, self.config
        )
        severity = assign_error_severity(
            is_first_occurrence=is_first,
            is_novel_type=is_novel,
            rate_ratio=rate_ratio,
            n_recent=n_recent,
            is_persistent=is_persistent,
            min_sample_for_info=self.config.min_sample_for_info,
            min_sample_for_warning=self.config.min_sample_for_warning,
        )
        if severity is None:
            return []

        return [
            AnomalyEvent(
                anomaly_type="tool_failure",
                signal_name="tool_error_rate",
                detector_name="ToolFailureDetector",
                detector_version="1.0",
                trace_id=current.trace_id,
                span_id=current.span_id,
                service_name=current.service_name,
                operation_name=f"tool.execute/{current.error_type}",
                observed_value=1.0,
                observed_at=current.start_time,
                baseline_median=None,
                baseline_mad=None,
                baseline_n=None,
                baseline_window_start=None,
                baseline_window_end=None,
                anomaly_score=rate_ratio,
                severity=severity,
                explanation=_explain(
                    current, is_first, is_novel, rate_ratio, n_recent, is_persistent
                ),
            )
        ]


def _analyse(
    current: ToolRecord,
    history: Sequence[ToolRecord],
    config: ErrorDetectorConfig,
) -> tuple[bool, bool, Optional[float], int, bool]:
    recent_start = current.start_time - timedelta(hours=config.recent_window_hours)
    baseline_start = current.start_time - timedelta(days=config.baseline_window_days)

    # Scope to the same service; all records are tool.execute by caller convention
    service_recs = [r for r in history if r.service_name == current.service_name]

    baseline_recs = [
        r for r in service_recs
        if baseline_start <= r.start_time < recent_start
    ]
    recent_prior_recs = [
        r for r in service_recs
        if recent_start <= r.start_time < current.start_time
    ]

    baseline_total = len(baseline_recs)
    baseline_errors_any = sum(1 for r in baseline_recs if r.is_error)
    baseline_errors_this_type = sum(
        1 for r in baseline_recs
        if r.is_error and r.error_type == current.error_type
    )
    recent_prior_errors_any = sum(1 for r in recent_prior_recs if r.is_error)
    recent_errors_this_type = sum(
        1 for r in recent_prior_recs
        if r.is_error and r.error_type == current.error_type
    )
    n_recent = len(recent_prior_recs) + 1   # current counts in recent window

    is_first_occurrence = (baseline_errors_any == 0 and recent_prior_errors_any == 0)

    prior_error_types = {
        r.error_type
        for r in baseline_recs + recent_prior_recs
        if r.is_error and r.error_type is not None
    }
    is_novel_type = current.error_type not in prior_error_types

    if baseline_total > 0 and baseline_errors_this_type > 0:
        baseline_rate = baseline_errors_this_type / baseline_total
        recent_type_count = recent_errors_this_type + 1     # include current
        recent_rate = recent_type_count / n_recent
        rate_ratio: Optional[float] = recent_rate / baseline_rate
    else:
        rate_ratio = None

    # Persistence: last K tool.execute spans (any error_type) are all errors
    all_prior_sorted = sorted(
        (r for r in service_recs if r.start_time < current.start_time),
        key=lambda r: r.start_time,
    )
    last_k = (all_prior_sorted + [current])[-config.persistence_k:]
    is_persistent = (
        len(last_k) == config.persistence_k
        and all(r.is_error for r in last_k)
    )

    return is_first_occurrence, is_novel_type, rate_ratio, n_recent, is_persistent


def _explain(
    current: ToolRecord,
    is_first: bool,
    is_novel: bool,
    rate_ratio: Optional[float],
    n_recent: int,
    is_persistent: bool,
) -> str:
    parts = [f"span_name=tool.execute error_type={current.error_type}"]
    parts.append(f"is_first_occurrence={is_first} is_novel_type={is_novel}")
    if rate_ratio is not None:
        parts.append(f"rate_ratio={rate_ratio:.2f}")
    parts.append(f"n_recent={n_recent} is_persistent={is_persistent}")
    return "; ".join(parts)

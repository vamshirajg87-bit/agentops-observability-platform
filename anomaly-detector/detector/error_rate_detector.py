from __future__ import annotations

from datetime import timedelta
from typing import Optional, Sequence

from .anomaly_types import AnomalyEvent, ErrorDetectorConfig, ErrorRecord
from .severity import assign_error_severity

_DEFAULT_CONFIG = ErrorDetectorConfig()


class ErrorRateDetector:
    """
    Detects error-rate anomalies using novelty, rate, and persistence signals.

    One call to detect() scores a single ErrorRecord (the current observation)
    against the history for its group.  Groups are defined by
    (service_name, operation_name).

    Time windows:
        recent   = [current.start_time - recent_window_hours, current.start_time)
        baseline = [current.start_time - baseline_window_days, start of recent window)

    The current observation is counted as part of the recent window for rate
    computation (it IS the new error we're characterising).

    Signals:
        is_first_occurrence  – no prior errors in baseline + recent windows
        is_novel_type        – error_type not seen before in prior records
        rate_ratio           – recent_error_rate / baseline_error_rate
                               None when baseline had no errors (div-by-zero guard)
        is_persistent        – last persistence_k consecutive observations all errors
                               (evaluated over the full history, not just the windows)

    Returns an empty list when current.is_error is False; only error events
    are meaningful to analyse here.
    """

    def __init__(self, config: Optional[ErrorDetectorConfig] = None) -> None:
        self.config = config if config is not None else _DEFAULT_CONFIG

    def detect(
        self,
        current: ErrorRecord,
        history: Sequence[ErrorRecord],
    ) -> list[AnomalyEvent]:
        if not current.is_error:
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
                anomaly_type="error_rate",
                signal_name="error_rate",
                detector_name="ErrorRateDetector",
                detector_version="1.0",
                trace_id=current.trace_id,
                span_id=current.span_id,
                service_name=current.service_name,
                operation_name=current.operation_name,
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
    current: ErrorRecord,
    history: Sequence[ErrorRecord],
    config: ErrorDetectorConfig,
) -> tuple[bool, bool, Optional[float], int, bool]:
    recent_start = current.start_time - timedelta(hours=config.recent_window_hours)
    baseline_start = current.start_time - timedelta(days=config.baseline_window_days)

    group = [
        r for r in history
        if r.service_name == current.service_name
        and r.operation_name == current.operation_name
    ]

    baseline_recs = [
        r for r in group
        if baseline_start <= r.start_time < recent_start
    ]
    recent_prior_recs = [
        r for r in group
        if recent_start <= r.start_time < current.start_time
    ]

    baseline_errors = [r for r in baseline_recs if r.is_error]
    baseline_total = len(baseline_recs)
    recent_prior_errors = [r for r in recent_prior_recs if r.is_error]
    n_recent = len(recent_prior_recs) + 1   # current is part of the recent window

    is_first_occurrence = (
        len(baseline_errors) == 0 and len(recent_prior_errors) == 0
    )

    if current.error_type is not None:
        prior_types = {
            r.error_type
            for r in baseline_recs + recent_prior_recs
            if r.is_error and r.error_type is not None
        }
        is_novel_type = current.error_type not in prior_types
    else:
        is_novel_type = False

    if baseline_total > 0 and len(baseline_errors) > 0:
        baseline_rate = len(baseline_errors) / baseline_total
        recent_error_count = len(recent_prior_errors) + 1   # include current
        recent_rate = recent_error_count / n_recent
        rate_ratio: Optional[float] = recent_rate / baseline_rate
    else:
        rate_ratio = None

    # Persistence: last K consecutive records across the full history are all errors
    all_prior_sorted = sorted(
        (r for r in group if r.start_time < current.start_time),
        key=lambda r: r.start_time,
    )
    last_k = (all_prior_sorted + [current])[-config.persistence_k:]
    is_persistent = (
        len(last_k) == config.persistence_k
        and all(r.is_error for r in last_k)
    )

    return is_first_occurrence, is_novel_type, rate_ratio, n_recent, is_persistent


def _explain(
    current: ErrorRecord,
    is_first: bool,
    is_novel: bool,
    rate_ratio: Optional[float],
    n_recent: int,
    is_persistent: bool,
) -> str:
    parts = [f"operation={current.operation_name}"]
    if current.error_type:
        parts.append(f"error_type={current.error_type}")
    parts.append(f"is_first_occurrence={is_first} is_novel_type={is_novel}")
    if rate_ratio is not None:
        parts.append(f"rate_ratio={rate_ratio:.2f}")
    parts.append(f"n_recent={n_recent} is_persistent={is_persistent}")
    return "; ".join(parts)

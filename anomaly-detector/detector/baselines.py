from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Sequence


@dataclass(frozen=True)
class Observation:
    """
    A single historical data point used for baseline computation.

    value
        The numeric measurement.  None values are skipped during baseline
        computation; this supports nullable mart columns such as
        retrieval_top_relevance_score.

    start_time
        When the operation began.  Used for baseline window filtering.
        Must be consistently timezone-aware or timezone-naive across all
        observations passed to compute_baseline in a single call.

    is_error
        True when this span had status_code = 'ERROR'.  Callers may pass
        exclude_errors=True to omit error observations from latency baselines
        so that slow-then-fail spans do not contaminate normal-operation durations.
    """

    value: Optional[float]
    start_time: datetime
    is_error: bool = False


@dataclass(frozen=True)
class BaselineStats:
    """
    Pre-computed baseline statistics for one observation group and window.

    Stored alongside each anomaly record so every row is self-auditable
    without replaying the full history.

    median       central tendency; robust to outliers
    mad          median absolute deviation; 0.0 when all qualifying values identical
    n            number of qualifying observations used
    window_start inclusive lower bound of the baseline window
    window_end   exclusive upper bound (== scored observation's start_time)
    """

    median: float
    mad: float
    n: int
    window_start: datetime
    window_end: datetime


def compute_baseline(
    history: Sequence[Observation],
    obs_start_time: datetime,
    window_days: int,
    exclude_errors: bool = False,
) -> Optional[BaselineStats]:
    """
    Compute median and MAD from observations in the baseline window.

    Baseline window: [obs_start_time - window_days, obs_start_time)

    The current observation is excluded by the strict exclusive upper bound
    (obs_start_time itself is NOT included).  Observations in the future
    relative to obs_start_time are also excluded.

    Returns None when there are no qualifying observations.

    Args:
        history:        All historical Observation objects for this group.
                        May be in any order; result is order-independent.
        obs_start_time: start_time of the observation being scored.
                        Timezone-awareness must match history entries.
        window_days:    Lookback window length in integer days (>= 1).
        exclude_errors: When True, skip observations with is_error=True.
                        Use for latency baselines to exclude error-span durations.
    """
    window_start = obs_start_time - timedelta(days=window_days)
    window_end = obs_start_time  # exclusive upper bound

    qualifying: list[float] = [
        o.value
        for o in history
        if window_start <= o.start_time < window_end
        and not (exclude_errors and o.is_error)
        and o.value is not None
    ]

    if not qualifying:
        return None

    n = len(qualifying)
    med = statistics.median(qualifying)
    deviations = [abs(v - med) for v in qualifying]
    mad = statistics.median(deviations)

    return BaselineStats(
        median=float(med),
        mad=float(mad),
        n=n,
        window_start=window_start,
        window_end=window_end,
    )

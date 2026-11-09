from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class DetectorConfig:
    """
    Configuration for a single anomaly detector.

    direction
        "HIGH"  – flag only when observed > baseline (latency spikes, error rates)
        "LOW"   – flag only when observed < baseline (relevance score drops)
        "BOTH"  – flag deviation in either direction

    z_threshold
        Modified z-score required for the statistical gate to pass.
        Gate uses strict greater-than: z > z_threshold.
        At exactly z_threshold the gate FAILS (not anomalous).
        Default 3.5 is the standard threshold for Iglewicz-Hoaglin modified z-scores.

    absolute_floor
        Minimum direction-aware absolute deviation (in the signal's natural units,
        e.g. milliseconds for latency) required for the practical gate to pass.
        Gate uses strict greater-than: deviation > absolute_floor.
        At exactly absolute_floor the gate FAILS (not anomalous).
        Setting floor=0.0 means any deviation passes – use a meaningful value in
        production to suppress operationally-trivial alerts.

    min_baseline_n
        Observations required for full-confidence detection.  When baseline.n is
        in [min_baseline_n_low_confidence, min_baseline_n) detection proceeds but
        severity is capped at INFO.

    min_baseline_n_low_confidence
        Minimum observations for low-confidence detection.  When baseline.n is
        below this threshold, detection is skipped (INSUFFICIENT_HISTORY).
        Must be <= min_baseline_n.

    baseline_window_days
        Lookback window length in integer days.
        Effective window: [obs.start_time − window_days days, obs.start_time)
        The strict exclusive upper bound prevents the current observation from
        entering its own baseline.
    """

    direction: Literal["HIGH", "LOW", "BOTH"]
    z_threshold: float = 3.5
    absolute_floor: float = 50.0
    min_baseline_n: int = 30
    min_baseline_n_low_confidence: int = 10
    baseline_window_days: int = 7

    def __post_init__(self) -> None:
        if self.direction not in ("HIGH", "LOW", "BOTH"):
            raise ValueError(
                f"direction must be 'HIGH', 'LOW', or 'BOTH'; got {self.direction!r}"
            )
        if self.z_threshold <= 0:
            raise ValueError(
                f"z_threshold must be positive; got {self.z_threshold}"
            )
        if self.absolute_floor < 0:
            raise ValueError(
                f"absolute_floor must be non-negative; got {self.absolute_floor}"
            )
        if self.min_baseline_n < 1:
            raise ValueError(
                f"min_baseline_n must be >= 1; got {self.min_baseline_n}"
            )
        if self.min_baseline_n_low_confidence < 1:
            raise ValueError(
                f"min_baseline_n_low_confidence must be >= 1; "
                f"got {self.min_baseline_n_low_confidence}"
            )
        if self.min_baseline_n_low_confidence > self.min_baseline_n:
            raise ValueError(
                f"min_baseline_n_low_confidence ({self.min_baseline_n_low_confidence}) "
                f"must be <= min_baseline_n ({self.min_baseline_n})"
            )
        if self.baseline_window_days < 1:
            raise ValueError(
                f"baseline_window_days must be >= 1; got {self.baseline_window_days}"
            )

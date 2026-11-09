from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .baselines import BaselineStats
from .config import DetectorConfig
from .severity import Severity, assign_continuous_severity, assign_zero_mad_severity

# Scaling constant that makes the modified z-score consistent with the
# standard normal: for a normal distribution MAD ≈ 0.6745 × σ, so the
# modified z-score approximates the standard z-score.
# Source: Iglewicz & Hoaglin (1993), "How to Detect and Handle Outliers".
_CONSISTENCY_FACTOR = 0.6745


class ScoringStatus(Enum):
    """
    Outcome category for a single scored observation.

    INSUFFICIENT_HISTORY
        baseline.n < min_baseline_n_low_confidence; detection skipped entirely.

    NORMAL
        MAD > 0; both gates evaluated; neither fired.

    STAT_GATE_ONLY
        MAD > 0; statistical gate passed (z > threshold) but practical gate
        failed (|deviation| <= floor).  Not classified as anomalous.

    PRACTICAL_ONLY
        MAD > 0; practical gate passed (|deviation| > floor) but statistical
        gate failed (z <= threshold).  Not classified as anomalous.

    ANOMALY
        MAD > 0; BOTH gates passed.  severity is set.

    ZERO_MAD_NORMAL
        MAD == 0; direction-aware deviation <= floor.  Not anomalous.

    ZERO_MAD_ANOMALY
        MAD == 0; direction-aware deviation > floor.  severity is set.
    """
    INSUFFICIENT_HISTORY = "insufficient_history"
    NORMAL = "normal"
    STAT_GATE_ONLY = "stat_gate_only"
    PRACTICAL_ONLY = "practical_only"
    ANOMALY = "anomaly"
    ZERO_MAD_NORMAL = "zero_mad_normal"
    ZERO_MAD_ANOMALY = "zero_mad_anomaly"


@dataclass(frozen=True)
class ScoringResult:
    """
    Complete result of scoring one observation against a pre-computed baseline.

    Fields are self-auditable: every value needed to reconstruct the scoring
    decision is present, supporting both logging and deterministic replay.

    status
        Outcome category; see ScoringStatus.

    observed
        The measured value that was scored.

    baseline
        BaselineStats used for scoring, or None if insufficient history.

    modified_z
        Modified z-score (0.6745 × directional_deviation / MAD).
        None when MAD == 0 (z is undefined) or when baseline is absent.

    absolute_deviation
        Direction-aware deviation from the baseline median:
          HIGH: observed − median   (negative when observed < median)
          LOW:  median − observed   (negative when observed > median)
          BOTH: |observed − median| (always non-negative)
        None when baseline is absent.
        The practical gate fires when absolute_deviation > absolute_floor.

    stat_gate_passed
        True when modified_z > z_threshold.  Always False when MAD == 0.

    practical_gate_passed
        True when absolute_deviation > absolute_floor.

    low_confidence
        True when baseline.n is in [min_baseline_n_low_confidence, min_baseline_n).
        When True, severity is capped at INFO regardless of the computed z-score.

    severity
        Assigned severity level.  None when the observation is not anomalous.
    """
    status: ScoringStatus
    observed: float
    baseline: Optional[BaselineStats]
    modified_z: Optional[float]
    absolute_deviation: Optional[float]
    stat_gate_passed: bool
    practical_gate_passed: bool
    low_confidence: bool
    severity: Optional[Severity]


def _directional_deviation(observed: float, median: float, direction: str) -> float:
    """Compute the direction-aware deviation used for the practical gate."""
    if direction == "HIGH":
        return observed - median
    if direction == "LOW":
        return median - observed
    # BOTH
    return abs(observed - median)


def _directional_z(observed: float, median: float, mad: float, direction: str) -> float:
    """Compute the modified z-score for the statistical gate."""
    if direction == "HIGH":
        return _CONSISTENCY_FACTOR * (observed - median) / mad
    if direction == "LOW":
        return _CONSISTENCY_FACTOR * (median - observed) / mad
    # BOTH
    return _CONSISTENCY_FACTOR * abs(observed - median) / mad


def _cap_severity(raw: Severity, low_confidence: bool) -> Severity:
    """Cap severity at INFO when the baseline sample is too small."""
    if low_confidence and raw != Severity.INFO:
        return Severity.INFO
    return raw


def score_observation(
    observed: float,
    baseline: Optional[BaselineStats],
    config: DetectorConfig,
) -> ScoringResult:
    """
    Score a single observation against a pre-computed baseline.

    Gate semantics (both use strict greater-than):
        Statistical gate:  modified_z > config.z_threshold
        Practical gate:    absolute_deviation > config.absolute_floor

    ANOMALY requires BOTH gates to pass.  Passing only one gate returns
    STAT_GATE_ONLY or PRACTICAL_ONLY – informational but not anomalous.

    Zero-MAD path (baseline.mad == 0):
        The statistical gate is undefined (division by zero).  The practical
        gate alone decides the outcome.  Severity is assigned by
        assign_zero_mad_severity with its own graduated bands.

    Low-confidence path (baseline.n in [min_baseline_n_low_confidence, min_baseline_n)):
        Detection proceeds normally but severity is capped at INFO.

    Insufficient-history path (baseline is None or baseline.n < min_baseline_n_low_confidence):
        Returns INSUFFICIENT_HISTORY immediately; no gates are evaluated.
    """
    # ── Insufficient history ────────────────────────────────────────────────
    if baseline is None or baseline.n < config.min_baseline_n_low_confidence:
        return ScoringResult(
            status=ScoringStatus.INSUFFICIENT_HISTORY,
            observed=observed,
            baseline=baseline,
            modified_z=None,
            absolute_deviation=None,
            stat_gate_passed=False,
            practical_gate_passed=False,
            low_confidence=False,
            severity=None,
        )

    low_confidence = baseline.n < config.min_baseline_n
    abs_dev = _directional_deviation(observed, baseline.median, config.direction)

    # ── Zero-MAD fallback ───────────────────────────────────────────────────
    if baseline.mad == 0.0:
        practical = abs_dev > config.absolute_floor
        if not practical:
            return ScoringResult(
                status=ScoringStatus.ZERO_MAD_NORMAL,
                observed=observed,
                baseline=baseline,
                modified_z=None,
                absolute_deviation=abs_dev,
                stat_gate_passed=False,
                practical_gate_passed=False,
                low_confidence=low_confidence,
                severity=None,
            )
        raw_severity = assign_zero_mad_severity(abs_dev, config.absolute_floor)
        return ScoringResult(
            status=ScoringStatus.ZERO_MAD_ANOMALY,
            observed=observed,
            baseline=baseline,
            modified_z=None,
            absolute_deviation=abs_dev,
            stat_gate_passed=False,
            practical_gate_passed=True,
            low_confidence=low_confidence,
            severity=_cap_severity(raw_severity, low_confidence),
        )

    # ── Normal path (MAD > 0) ───────────────────────────────────────────────
    z = _directional_z(observed, baseline.median, baseline.mad, config.direction)
    stat_gate = z > config.z_threshold
    practical_gate = abs_dev > config.absolute_floor

    if stat_gate and practical_gate:
        raw_severity = assign_continuous_severity(z, config.z_threshold)
        return ScoringResult(
            status=ScoringStatus.ANOMALY,
            observed=observed,
            baseline=baseline,
            modified_z=z,
            absolute_deviation=abs_dev,
            stat_gate_passed=True,
            practical_gate_passed=True,
            low_confidence=low_confidence,
            severity=_cap_severity(raw_severity, low_confidence),
        )

    if stat_gate and not practical_gate:
        return ScoringResult(
            status=ScoringStatus.STAT_GATE_ONLY,
            observed=observed,
            baseline=baseline,
            modified_z=z,
            absolute_deviation=abs_dev,
            stat_gate_passed=True,
            practical_gate_passed=False,
            low_confidence=low_confidence,
            severity=None,
        )

    if not stat_gate and practical_gate:
        return ScoringResult(
            status=ScoringStatus.PRACTICAL_ONLY,
            observed=observed,
            baseline=baseline,
            modified_z=z,
            absolute_deviation=abs_dev,
            stat_gate_passed=False,
            practical_gate_passed=True,
            low_confidence=low_confidence,
            severity=None,
        )

    # Neither gate passed
    return ScoringResult(
        status=ScoringStatus.NORMAL,
        observed=observed,
        baseline=baseline,
        modified_z=z,
        absolute_deviation=abs_dev,
        stat_gate_passed=False,
        practical_gate_passed=False,
        low_confidence=low_confidence,
        severity=None,
    )

from __future__ import annotations

from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


def assign_continuous_severity(modified_z: float, z_threshold: float) -> Severity:
    """
    Assign severity for a continuous signal that has passed both gates.

    Caller guarantees modified_z > z_threshold (gate already passed).

    Bands – upper boundaries are exclusive, lower boundaries of WARNING/CRITICAL
    are inclusive:
        z_threshold < z < 2*z_threshold   →  INFO
        2*z_threshold <= z < 4*z_threshold →  WARNING
        z >= 4*z_threshold                 →  CRITICAL

    Exact boundary semantics:
        z == 2*z_threshold → WARNING   (not INFO)
        z == 4*z_threshold → CRITICAL  (not WARNING)
    """
    if modified_z >= 4.0 * z_threshold:
        return Severity.CRITICAL
    if modified_z >= 2.0 * z_threshold:
        return Severity.WARNING
    return Severity.INFO


def assign_zero_mad_severity(absolute_deviation: float, absolute_floor: float) -> Severity:
    """
    Assign severity for the zero-MAD fallback path.

    Caller guarantees absolute_deviation > absolute_floor.

    Bands:
        absolute_floor < deviation < 2*floor   →  INFO
        2*floor <= deviation <= 5*floor         →  WARNING
        deviation > 5*floor                     →  CRITICAL

    Exact boundary semantics:
        deviation == 2*floor → WARNING   (not INFO)
        deviation == 5*floor → WARNING   (not CRITICAL; > 5×floor required for CRITICAL)
    """
    if absolute_deviation > 5.0 * absolute_floor:
        return Severity.CRITICAL
    if absolute_deviation >= 2.0 * absolute_floor:
        return Severity.WARNING
    return Severity.INFO


_SEVERITY_ORDER = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


def assign_error_severity(
    is_first_occurrence: bool,
    is_novel_type: bool,
    rate_ratio: Optional[float],
    n_recent: int,
    is_persistent: bool,
    min_sample_for_info: int = 10,
    min_sample_for_warning: int = 30,
) -> Optional[Severity]:
    """
    Assign severity for error-rate anomaly evidence.

    All applicable rules are collected and the highest severity is returned
    (CRITICAL > WARNING > INFO).  Returns None when no rule fires.

    Args:
        is_first_occurrence:    True when there is no prior error for this group.
        is_novel_type:          True when this error_type has not been seen before.
        rate_ratio:             recent_error_rate / baseline_error_rate.
                                Pass None when the baseline error rate is 0
                                (first-occurrence / baseline-clean cases).
        n_recent:               Number of observations in the recent window used
                                to compute recent_error_rate.
        is_persistent:          True when the last K consecutive observations all
                                had errors (default K=5 in the calling detector).
        min_sample_for_info:    Minimum n_recent for rate-based INFO rule.
        min_sample_for_warning: Minimum n_recent for rate-based WARNING/CRITICAL rules.

    Rules (applied with CRITICAL > WARNING > INFO precedence):
        1. is_persistent                                                → CRITICAL
        2. rate_ratio > 10  AND  n_recent >= min_sample_for_warning     → CRITICAL
        3. rate_ratio > 5   AND  n_recent >= min_sample_for_warning     → WARNING
        4. rate_ratio > 3   AND  n_recent >= min_sample_for_info        → INFO
        5. is_first_occurrence                                          → INFO
        6. is_novel_type                                                → INFO

    Boundary semantics (strict greater-than for rate comparisons):
        rate_ratio == 10 with sufficient n  → WARNING (rule 3), not CRITICAL
        rate_ratio == 5  with sufficient n  → INFO    (rule 4), not WARNING
        rate_ratio == 3  with sufficient n  → None    (no rule fires)
    """
    candidates: list[Severity] = []

    if is_persistent:
        candidates.append(Severity.CRITICAL)

    if rate_ratio is not None:
        if rate_ratio > 10.0 and n_recent >= min_sample_for_warning:
            candidates.append(Severity.CRITICAL)
        elif rate_ratio > 5.0 and n_recent >= min_sample_for_warning:
            candidates.append(Severity.WARNING)
        elif rate_ratio > 3.0 and n_recent >= min_sample_for_info:
            candidates.append(Severity.INFO)

    if is_first_occurrence:
        candidates.append(Severity.INFO)

    if is_novel_type:
        candidates.append(Severity.INFO)

    if not candidates:
        return None

    return max(candidates, key=lambda s: _SEVERITY_ORDER[s])

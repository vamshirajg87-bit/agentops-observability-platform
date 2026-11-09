"""
Unit tests for score_observation.

Arithmetic reference:
    modified_z (HIGH) = 0.6745 × (observed − median) / MAD
    modified_z (LOW)  = 0.6745 × (median − observed) / MAD
    modified_z (BOTH) = 0.6745 × |observed − median| / MAD

Tests use deliberately chosen parameter values so expected z-scores can
be verified by hand; see inline comments.
"""
import pytest
from datetime import datetime, timedelta, timezone

from detector.baselines import BaselineStats
from detector.config import DetectorConfig
from detector.scoring import ScoringStatus, score_observation
from detector.severity import Severity

_CONSISTENCY_FACTOR = 0.6745

T0 = datetime(2024, 1, 10, 12, 0, 0, tzinfo=timezone.utc)


def _baseline(median: float, mad: float, n: int = 50) -> BaselineStats:
    return BaselineStats(
        median=median,
        mad=mad,
        n=n,
        window_start=T0 - timedelta(days=7),
        window_end=T0,
    )


def _cfg(direction="HIGH", threshold=3.5, floor=0.0, min_n=30, min_low=10):
    return DetectorConfig(
        direction=direction,
        z_threshold=threshold,
        absolute_floor=floor,
        min_baseline_n=min_n,
        min_baseline_n_low_confidence=min_low,
    )


# ── Insufficient history ─────────────────────────────────────────────────────

def test_none_baseline_gives_insufficient_history():
    result = score_observation(100.0, None, _cfg())
    assert result.status == ScoringStatus.INSUFFICIENT_HISTORY
    assert result.severity is None
    assert result.modified_z is None
    assert result.absolute_deviation is None


def test_n_below_low_confidence_gives_insufficient_history():
    # min_low_confidence=10; n=5 → INSUFFICIENT_HISTORY
    result = score_observation(100.0, _baseline(50.0, 10.0, n=5), _cfg(min_low=10))
    assert result.status == ScoringStatus.INSUFFICIENT_HISTORY
    assert result.severity is None


def test_n_at_low_confidence_boundary_proceeds(self=None):
    # n == min_baseline_n_low_confidence → low-confidence detection, not skipped
    result = score_observation(100.0, _baseline(50.0, 10.0, n=10), _cfg(min_low=10, min_n=30))
    assert result.status != ScoringStatus.INSUFFICIENT_HISTORY


# ── HIGH direction: normal observations ──────────────────────────────────────

def test_high_normal_below_threshold():
    # median=50, mad=10, observed=100, floor=100
    # z = 0.6745 × (100−50) / 10 = 3.3725 < 3.5 → stat gate fails
    # abs_dev = 50 < floor=100 → practical gate fails
    # → NORMAL
    result = score_observation(100.0, _baseline(50.0, 10.0), _cfg(direction="HIGH", threshold=3.5, floor=100.0))
    assert result.status == ScoringStatus.NORMAL
    assert result.severity is None
    assert result.stat_gate_passed is False
    assert result.practical_gate_passed is False
    assert abs(result.modified_z - _CONSISTENCY_FACTOR * 50.0 / 10.0) < 1e-9


def test_high_does_not_flag_low_values():
    # observed=10 < median=50 → z_HIGH = 0.6745×(10−50)/10 = −2.698 < 3.5
    result = score_observation(10.0, _baseline(50.0, 10.0), _cfg(direction="HIGH", floor=0.0))
    assert result.status == ScoringStatus.NORMAL
    assert result.modified_z < 0


# ── HIGH direction: anomaly ───────────────────────────────────────────────────

def test_high_anomaly_both_gates_pass():
    # median=50, mad=10, observed=150
    # z = 0.6745×100/10 = 6.745 > 3.5; abs_dev=100 > 0.0 → ANOMALY
    result = score_observation(150.0, _baseline(50.0, 10.0), _cfg(direction="HIGH", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY
    assert result.severity is not None
    assert result.stat_gate_passed is True
    assert result.practical_gate_passed is True
    assert abs(result.modified_z - _CONSISTENCY_FACTOR * 100.0 / 10.0) < 1e-9
    assert result.absolute_deviation == pytest.approx(100.0)


# ── LOW direction ─────────────────────────────────────────────────────────────

def test_low_does_not_flag_high_values():
    # z_LOW = 0.6745×(50−150)/10 = −6.745 < 3.5 → NORMAL
    result = score_observation(150.0, _baseline(50.0, 10.0), _cfg(direction="LOW", floor=0.0))
    assert result.status == ScoringStatus.NORMAL
    assert result.modified_z < 0


def test_low_flags_low_values():
    # observed=−50, median=50, mad=10
    # z_LOW = 0.6745×(50−(−50))/10 = 0.6745×10 = 6.745 > 3.5 → ANOMALY
    result = score_observation(-50.0, _baseline(50.0, 10.0), _cfg(direction="LOW", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY
    assert result.absolute_deviation == pytest.approx(100.0)  # median − observed = 50−(−50) = 100


# ── BOTH direction ────────────────────────────────────────────────────────────

def test_both_flags_high_values():
    # BOTH uses abs(observed − median), so 150 → same z as HIGH path
    result = score_observation(150.0, _baseline(50.0, 10.0), _cfg(direction="BOTH", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY


def test_both_flags_low_values():
    # BOTH also catches downward deviations
    result = score_observation(-50.0, _baseline(50.0, 10.0), _cfg(direction="BOTH", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY


def test_both_at_median_is_normal():
    result = score_observation(50.0, _baseline(50.0, 10.0), _cfg(direction="BOTH", floor=0.0))
    assert result.status == ScoringStatus.NORMAL


# ── Two-gate requirement ──────────────────────────────────────────────────────

def test_stat_gate_only_when_practical_fails():
    # median=0, mad=1, z_threshold=3.5, floor=1000.0
    # observed=6: z=0.6745×6=4.047 > 3.5 ✓; abs_dev=6 ≤ 1000 → STAT_GATE_ONLY
    result = score_observation(6.0, _baseline(0.0, 1.0), _cfg(direction="HIGH", threshold=3.5, floor=1000.0))
    assert result.status == ScoringStatus.STAT_GATE_ONLY
    assert result.stat_gate_passed is True
    assert result.practical_gate_passed is False
    assert result.severity is None


def test_practical_gate_only_when_stat_fails():
    # median=0, mad=100, z_threshold=3.5, floor=50.0
    # observed=100: z=0.6745×100/100=0.6745 < 3.5; abs_dev=100 > 50 → PRACTICAL_ONLY
    result = score_observation(100.0, _baseline(0.0, 100.0), _cfg(direction="HIGH", threshold=3.5, floor=50.0))
    assert result.status == ScoringStatus.PRACTICAL_ONLY
    assert result.stat_gate_passed is False
    assert result.practical_gate_passed is True
    assert result.severity is None


def test_neither_gate_gives_normal():
    # z < threshold AND abs_dev <= floor → NORMAL
    result = score_observation(51.0, _baseline(50.0, 10.0), _cfg(direction="HIGH", threshold=3.5, floor=1000.0))
    assert result.status == ScoringStatus.NORMAL
    assert result.stat_gate_passed is False
    assert result.practical_gate_passed is False


# ── Exact threshold boundary semantics ───────────────────────────────────────

def test_z_exactly_at_threshold_does_not_pass_gate():
    # With median=0, mad=1, z_threshold=0.6745:
    # z = 0.6745 × obs / 1 = 0.6745 when obs = 1.0
    # Gate is STRICT > ; at exactly threshold → fails.
    cfg = _cfg(direction="HIGH", threshold=0.6745, floor=0.0)
    result = score_observation(1.0, _baseline(0.0, 1.0), cfg)
    # z == threshold: stat gate FAILS
    assert result.stat_gate_passed is False
    # abs_dev = 1.0 > 0.0 → practical passes, but stat fails → PRACTICAL_ONLY
    assert result.status == ScoringStatus.PRACTICAL_ONLY


def test_z_just_above_threshold_passes_gate():
    cfg = _cfg(direction="HIGH", threshold=0.6745, floor=0.0)
    result = score_observation(1.0001, _baseline(0.0, 1.0), cfg)
    assert result.stat_gate_passed is True


def test_deviation_exactly_at_floor_does_not_pass_practical_gate():
    # median=0, mad=1, threshold=0.001 (very low so stat always passes),
    # floor=100.0; observed=100 → abs_dev=100 == floor → practical FAILS
    cfg = _cfg(direction="HIGH", threshold=0.001, floor=100.0)
    result = score_observation(100.0, _baseline(0.0, 1.0), cfg)
    assert result.practical_gate_passed is False
    assert result.stat_gate_passed is True
    assert result.status == ScoringStatus.STAT_GATE_ONLY


def test_deviation_just_above_floor_passes_practical_gate():
    cfg = _cfg(direction="HIGH", threshold=0.001, floor=100.0)
    result = score_observation(100.0001, _baseline(0.0, 1.0), cfg)
    assert result.practical_gate_passed is True
    assert result.status == ScoringStatus.ANOMALY


# ── Zero MAD ──────────────────────────────────────────────────────────────────

def test_zero_mad_at_median_is_zero_mad_normal():
    # Observed == median; abs_dev=0 ≤ floor=50 → ZERO_MAD_NORMAL
    result = score_observation(42.0, _baseline(42.0, 0.0), _cfg(floor=50.0))
    assert result.status == ScoringStatus.ZERO_MAD_NORMAL
    assert result.modified_z is None
    assert result.severity is None


def test_zero_mad_deviation_at_floor_is_zero_mad_normal():
    # abs_dev == floor; practical gate STRICT > → fails → ZERO_MAD_NORMAL
    result = score_observation(92.0, _baseline(42.0, 0.0), _cfg(floor=50.0))
    # abs_dev = 92−42 = 50.0 == floor → gate fails
    assert result.status == ScoringStatus.ZERO_MAD_NORMAL
    assert result.practical_gate_passed is False


def test_zero_mad_deviation_above_floor_is_zero_mad_anomaly():
    # abs_dev = 51 > 50 → ZERO_MAD_ANOMALY
    result = score_observation(93.0, _baseline(42.0, 0.0), _cfg(floor=50.0))
    assert result.status == ScoringStatus.ZERO_MAD_ANOMALY
    assert result.practical_gate_passed is True
    assert result.stat_gate_passed is False
    assert result.severity is not None


def test_zero_mad_low_direction_does_not_flag_high():
    # LOW direction; observed > median → abs_dev = median − observed < 0 → practical fails
    result = score_observation(200.0, _baseline(42.0, 0.0), _cfg(direction="LOW", floor=50.0))
    assert result.status == ScoringStatus.ZERO_MAD_NORMAL
    assert result.practical_gate_passed is False


def test_zero_mad_stat_gate_always_false():
    result = score_observation(9999.0, _baseline(42.0, 0.0), _cfg(floor=0.0))
    assert result.stat_gate_passed is False


# ── Severity band assignment ──────────────────────────────────────────────────

def test_anomaly_severity_info_band():
    # median=0, mad=1, threshold=3.5, floor=0
    # z=0.6745×5=3.3725 < 3.5... need a value in INFO band (3.5 < z < 7.0)
    # z=4.5 → obs = 4.5 / 0.6745 ≈ 6.67
    obs = 4.5 / _CONSISTENCY_FACTOR  # z ≈ 4.5
    result = score_observation(obs, _baseline(0.0, 1.0), _cfg(direction="HIGH", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY
    assert result.severity == Severity.INFO


def test_anomaly_severity_warning_band():
    # z=8.0 → obs = 8.0 / 0.6745 → in [7.0, 14.0) → WARNING
    obs = 8.0 / _CONSISTENCY_FACTOR
    result = score_observation(obs, _baseline(0.0, 1.0), _cfg(direction="HIGH", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY
    assert result.severity == Severity.WARNING


def test_anomaly_severity_critical_band():
    # z=15.0 → obs = 15.0 / 0.6745 → >= 14.0 → CRITICAL
    obs = 15.0 / _CONSISTENCY_FACTOR
    result = score_observation(obs, _baseline(0.0, 1.0), _cfg(direction="HIGH", threshold=3.5, floor=0.0))
    assert result.status == ScoringStatus.ANOMALY
    assert result.severity == Severity.CRITICAL


# ── Low-confidence cap ────────────────────────────────────────────────────────

def test_low_confidence_caps_severity_at_info():
    # n=15 ∈ [10, 30) → low confidence; raw severity would be WARNING or CRITICAL
    # Use z in WARNING band (8.0 / 0.6745 obs)
    obs = 8.0 / _CONSISTENCY_FACTOR
    result = score_observation(obs, _baseline(0.0, 1.0, n=15), _cfg(direction="HIGH", threshold=3.5, min_low=10, min_n=30))
    assert result.low_confidence is True
    assert result.status == ScoringStatus.ANOMALY
    assert result.severity == Severity.INFO  # capped from WARNING


def test_full_confidence_does_not_cap():
    obs = 8.0 / _CONSISTENCY_FACTOR
    result = score_observation(obs, _baseline(0.0, 1.0, n=30), _cfg(direction="HIGH", threshold=3.5, min_low=10, min_n=30))
    assert result.low_confidence is False
    assert result.severity == Severity.WARNING


def test_low_confidence_flag_correct_when_n_at_boundary():
    # n == min_baseline_n: NOT low confidence
    result = score_observation(150.0, _baseline(50.0, 10.0, n=30), _cfg(min_low=10, min_n=30))
    assert result.low_confidence is False


def test_low_confidence_flag_one_below_boundary():
    # n == min_baseline_n - 1: IS low confidence
    result = score_observation(150.0, _baseline(50.0, 10.0, n=29), _cfg(min_low=10, min_n=30))
    assert result.low_confidence is True


# ── Result field completeness ─────────────────────────────────────────────────

def test_result_carries_observed_value():
    result = score_observation(42.0, _baseline(50.0, 10.0), _cfg())
    assert result.observed == 42.0


def test_result_carries_baseline():
    b = _baseline(50.0, 10.0)
    result = score_observation(42.0, b, _cfg())
    assert result.baseline is b


def test_insufficient_history_carries_baseline_when_n_too_low():
    b = _baseline(50.0, 10.0, n=3)
    result = score_observation(42.0, b, _cfg(min_low=10))
    assert result.status == ScoringStatus.INSUFFICIENT_HISTORY
    assert result.baseline is b


def test_deterministic_same_inputs_same_output():
    b = _baseline(50.0, 10.0)
    cfg = _cfg(direction="HIGH", threshold=3.5, floor=0.0)
    r1 = score_observation(150.0, b, cfg)
    r2 = score_observation(150.0, b, cfg)
    assert r1.status == r2.status
    assert r1.modified_z == r2.modified_z
    assert r1.severity == r2.severity


# ── Exact n-boundary confidence tests ────────────────────────────────────────
# These tests pin the behaviour at every boundary value of the confidence
# tiers.  Default config: min_baseline_n_low_confidence=10, min_baseline_n=30.
#
# "Extreme anomaly" observation: z ≈ 15 (CRITICAL band, z >= 4*3.5 = 14).
# Constructed with median=0, mad=1, observed = 15/0.6745 so that
#   z = 0.6745 × observed / 1 = 15.0
# This ensures that if the INFO cap were absent, severity would be CRITICAL.

_EXTREME_OBS = 15.0 / _CONSISTENCY_FACTOR  # z ≈ 15.0 against (median=0, mad=1)


def test_n_1_extreme_anomaly_is_insufficient_history():
    # n=1 < min_low_confidence(10): detection must be skipped entirely
    result = score_observation(_EXTREME_OBS, _baseline(0.0, 1.0, n=1), _cfg(floor=0.0))
    assert result.status == ScoringStatus.INSUFFICIENT_HISTORY
    assert result.severity is None


def test_n_9_extreme_anomaly_is_insufficient_history():
    # n=9 is the last value below min_low_confidence; must still be INSUFFICIENT_HISTORY
    result = score_observation(_EXTREME_OBS, _baseline(0.0, 1.0, n=9), _cfg(floor=0.0))
    assert result.status == ScoringStatus.INSUFFICIENT_HISTORY
    assert result.severity is None


def test_n_10_extreme_anomaly_is_anomaly_info_capped():
    # n=10 == min_low_confidence: detection proceeds; low_confidence=True; capped at INFO
    result = score_observation(_EXTREME_OBS, _baseline(0.0, 1.0, n=10), _cfg(floor=0.0, min_low=10, min_n=30))
    assert result.status == ScoringStatus.ANOMALY
    assert result.low_confidence is True
    assert result.severity == Severity.INFO  # raw would be CRITICAL; capped


def test_n_29_extreme_anomaly_is_anomaly_info_capped():
    # n=29 is the last value below min_baseline_n; still low_confidence=True; capped at INFO
    result = score_observation(_EXTREME_OBS, _baseline(0.0, 1.0, n=29), _cfg(floor=0.0, min_low=10, min_n=30))
    assert result.status == ScoringStatus.ANOMALY
    assert result.low_confidence is True
    assert result.severity == Severity.INFO  # raw would be CRITICAL; capped


def test_n_30_extreme_anomaly_full_severity():
    # n=30 == min_baseline_n: low_confidence=False; full severity rules apply
    result = score_observation(_EXTREME_OBS, _baseline(0.0, 1.0, n=30), _cfg(floor=0.0, min_low=10, min_n=30))
    assert result.status == ScoringStatus.ANOMALY
    assert result.low_confidence is False
    assert result.severity == Severity.CRITICAL  # z≈15 >= 4*3.5=14 → CRITICAL


# ── Zero-MAD n-boundary tests ─────────────────────────────────────────────────
# Confirm that the zero-MAD path obeys the same insufficient-history and
# low-confidence rules as the normal (MAD > 0) path.
# Uses obs=9999.0, median=42.0, floor=50: abs_dev=9957 >> 5*floor=250 → raw CRITICAL.

def test_zero_mad_n_9_is_insufficient_history():
    result = score_observation(9999.0, _baseline(42.0, 0.0, n=9), _cfg(floor=50.0, min_low=10))
    assert result.status == ScoringStatus.INSUFFICIENT_HISTORY
    assert result.severity is None


def test_zero_mad_n_10_extreme_anomaly_is_info_capped():
    # n=10 == min_low_confidence; zero-MAD anomaly must also be capped at INFO
    result = score_observation(9999.0, _baseline(42.0, 0.0, n=10), _cfg(floor=50.0, min_low=10, min_n=30))
    assert result.status == ScoringStatus.ZERO_MAD_ANOMALY
    assert result.low_confidence is True
    assert result.severity == Severity.INFO  # raw would be CRITICAL; capped


def test_zero_mad_n_29_extreme_anomaly_is_info_capped():
    result = score_observation(9999.0, _baseline(42.0, 0.0, n=29), _cfg(floor=50.0, min_low=10, min_n=30))
    assert result.status == ScoringStatus.ZERO_MAD_ANOMALY
    assert result.low_confidence is True
    assert result.severity == Severity.INFO


def test_zero_mad_n_30_full_severity():
    # n=30: full confidence; raw CRITICAL should not be capped
    result = score_observation(9999.0, _baseline(42.0, 0.0, n=30), _cfg(floor=50.0, min_low=10, min_n=30))
    assert result.status == ScoringStatus.ZERO_MAD_ANOMALY
    assert result.low_confidence is False
    assert result.severity == Severity.CRITICAL

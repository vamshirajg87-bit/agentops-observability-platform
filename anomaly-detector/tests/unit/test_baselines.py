import random
import pytest
from datetime import datetime, timedelta, timezone

from detector.baselines import Observation, BaselineStats, compute_baseline

# Reference point: all test observations are expressed as offsets from T0.
T0 = datetime(2024, 1, 10, 12, 0, 0, tzinfo=timezone.utc)


def _obs(value, days_before=1.0, is_error=False):
    """Create an Observation at T0 - days_before days."""
    return Observation(
        value=value,
        start_time=T0 - timedelta(days=days_before),
        is_error=is_error,
    )


# ── Median and MAD correctness ──────────────────────────────────────────────

def test_median_odd_count():
    history = [_obs(10), _obs(20), _obs(30)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.median == 20.0
    assert result.n == 3


def test_median_even_count():
    # median([10, 20, 30, 40]) = (20 + 30) / 2 = 25
    history = [_obs(10), _obs(20), _obs(30), _obs(40)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.median == 25.0


def test_mad_basic():
    # values = [10, 20, 30]; median = 20
    # deviations = [10, 0, 10]; MAD = median([0, 10, 10]) = 10
    history = [_obs(10), _obs(20), _obs(30)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.mad == 10.0


def test_mad_zero_when_all_values_identical():
    history = [_obs(42.0) for _ in range(5)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.mad == 0.0
    assert result.median == 42.0


def test_single_observation():
    history = [_obs(100.0)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.n == 1
    assert result.median == 100.0
    assert result.mad == 0.0  # single-element: deviation=[0], MAD=0


# ── Leakage prevention ───────────────────────────────────────────────────────

def test_obs_at_exactly_obs_start_time_is_excluded():
    # Upper bound is exclusive: an observation at T0 must NOT enter the baseline.
    at_boundary = Observation(value=9999.0, start_time=T0, is_error=False)
    history = [_obs(10), _obs(20), _obs(30), at_boundary]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    # 9999 must not have influenced the median/MAD
    assert result.n == 3
    assert result.median == 20.0


def test_obs_one_microsecond_before_obs_start_time_is_included():
    just_before = Observation(
        value=1000.0,
        start_time=T0 - timedelta(microseconds=1),
        is_error=False,
    )
    history = [just_before]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.n == 1
    assert result.median == 1000.0


def test_future_obs_after_obs_start_time_excluded():
    future = Observation(
        value=9999.0,
        start_time=T0 + timedelta(hours=1),
        is_error=False,
    )
    history = [_obs(50), future]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.n == 1
    assert result.median == 50.0


# ── Window boundaries ────────────────────────────────────────────────────────

def test_obs_at_window_start_is_included():
    # window_start = T0 - 7 days; inclusive lower bound
    at_window_start = Observation(
        value=55.0,
        start_time=T0 - timedelta(days=7),
        is_error=False,
    )
    history = [_obs(45.0), at_window_start]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.n == 2


def test_obs_before_window_start_is_excluded():
    before_window = Observation(
        value=9999.0,
        start_time=T0 - timedelta(days=7, microseconds=1),
        is_error=False,
    )
    history = [_obs(50.0), before_window]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.n == 1
    assert result.median == 50.0


def test_window_start_and_end_stored_correctly():
    history = [_obs(42.0)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is not None
    assert result.window_start == T0 - timedelta(days=7)
    assert result.window_end == T0


# ── Empty / None results ─────────────────────────────────────────────────────

def test_empty_history_returns_none():
    result = compute_baseline([], T0, window_days=7)
    assert result is None


def test_all_obs_outside_window_returns_none():
    too_old = Observation(value=100.0, start_time=T0 - timedelta(days=30), is_error=False)
    result = compute_baseline([too_old], T0, window_days=7)
    assert result is None


def test_obs_with_none_value_excluded():
    none_obs = Observation(value=None, start_time=T0 - timedelta(days=1), is_error=False)
    valid_obs = _obs(42.0)
    result = compute_baseline([none_obs, valid_obs], T0, window_days=7)
    assert result is not None
    assert result.n == 1
    assert result.median == 42.0


def test_all_none_values_returns_none():
    history = [Observation(value=None, start_time=T0 - timedelta(days=1), is_error=False)]
    result = compute_baseline(history, T0, window_days=7)
    assert result is None


# ── Error exclusion ───────────────────────────────────────────────────────────

def test_error_obs_excluded_when_exclude_errors_true():
    normal = _obs(50.0, is_error=False)
    error_obs = _obs(9999.0, is_error=True)
    result = compute_baseline([normal, error_obs], T0, window_days=7, exclude_errors=True)
    assert result is not None
    assert result.n == 1
    assert result.median == 50.0


def test_error_obs_included_when_exclude_errors_false():
    normal = _obs(50.0, is_error=False)
    error_obs = _obs(9999.0, is_error=True)
    result = compute_baseline([normal, error_obs], T0, window_days=7, exclude_errors=False)
    assert result is not None
    assert result.n == 2


def test_exclude_errors_default_is_false():
    # Default behavior: error observations are included.
    error_obs = _obs(9999.0, is_error=True)
    result = compute_baseline([error_obs], T0, window_days=7)
    assert result is not None
    assert result.n == 1


# ── Determinism ───────────────────────────────────────────────────────────────

def test_order_does_not_affect_result():
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    history = [_obs(v) for v in values]

    result_a = compute_baseline(history, T0, window_days=7)

    shuffled = history[:]
    random.shuffle(shuffled)
    result_b = compute_baseline(shuffled, T0, window_days=7)

    assert result_a is not None
    assert result_b is not None
    assert result_a.median == result_b.median
    assert result_a.mad == result_b.mad
    assert result_a.n == result_b.n


# ── Count tracking ────────────────────────────────────────────────────────────

def test_n_reflects_qualifying_count_not_total():
    in_window = [_obs(float(i)) for i in range(10)]
    # Add observations that should be excluded.
    out_of_window = [Observation(value=9999.0, start_time=T0 - timedelta(days=30), is_error=False)]
    at_boundary = [Observation(value=9999.0, start_time=T0, is_error=False)]
    result = compute_baseline(in_window + out_of_window + at_boundary, T0, window_days=7)
    assert result is not None
    assert result.n == 10

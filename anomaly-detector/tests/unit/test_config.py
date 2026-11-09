import pytest
from detector.config import DetectorConfig


def test_default_config_created_successfully():
    cfg = DetectorConfig(direction="HIGH")
    assert cfg.direction == "HIGH"
    assert cfg.z_threshold == 3.5
    assert cfg.absolute_floor == 50.0
    assert cfg.min_baseline_n == 30
    assert cfg.min_baseline_n_low_confidence == 10
    assert cfg.baseline_window_days == 7


def test_custom_valid_config():
    cfg = DetectorConfig(
        direction="LOW",
        z_threshold=2.0,
        absolute_floor=0.05,
        min_baseline_n=50,
        min_baseline_n_low_confidence=15,
        baseline_window_days=14,
    )
    assert cfg.direction == "LOW"
    assert cfg.z_threshold == 2.0
    assert cfg.absolute_floor == 0.05
    assert cfg.min_baseline_n == 50
    assert cfg.min_baseline_n_low_confidence == 15
    assert cfg.baseline_window_days == 14


def test_direction_both_valid():
    cfg = DetectorConfig(direction="BOTH")
    assert cfg.direction == "BOTH"


def test_all_three_directions_accepted():
    for d in ("HIGH", "LOW", "BOTH"):
        cfg = DetectorConfig(direction=d)
        assert cfg.direction == d


def test_invalid_direction_raises():
    with pytest.raises(ValueError, match="direction"):
        DetectorConfig(direction="UP")


def test_direction_lowercase_raises():
    with pytest.raises(ValueError, match="direction"):
        DetectorConfig(direction="high")


def test_zero_z_threshold_raises():
    with pytest.raises(ValueError, match="z_threshold"):
        DetectorConfig(direction="HIGH", z_threshold=0.0)


def test_negative_z_threshold_raises():
    with pytest.raises(ValueError, match="z_threshold"):
        DetectorConfig(direction="HIGH", z_threshold=-1.0)


def test_negative_absolute_floor_raises():
    with pytest.raises(ValueError, match="absolute_floor"):
        DetectorConfig(direction="HIGH", absolute_floor=-0.01)


def test_zero_absolute_floor_is_valid():
    cfg = DetectorConfig(direction="HIGH", absolute_floor=0.0)
    assert cfg.absolute_floor == 0.0


def test_min_baseline_n_zero_raises():
    with pytest.raises(ValueError, match="min_baseline_n"):
        DetectorConfig(direction="HIGH", min_baseline_n=0)


def test_min_baseline_n_low_confidence_zero_raises():
    with pytest.raises(ValueError, match="min_baseline_n_low_confidence"):
        DetectorConfig(
            direction="HIGH",
            min_baseline_n=30,
            min_baseline_n_low_confidence=0,
        )


def test_low_confidence_exceeds_min_n_raises():
    with pytest.raises(ValueError, match="min_baseline_n_low_confidence"):
        DetectorConfig(
            direction="HIGH",
            min_baseline_n=10,
            min_baseline_n_low_confidence=20,
        )


def test_low_confidence_equal_to_min_n_is_valid():
    # Equal means no low-confidence zone: go directly from insufficient to full.
    cfg = DetectorConfig(
        direction="HIGH",
        min_baseline_n=30,
        min_baseline_n_low_confidence=30,
    )
    assert cfg.min_baseline_n_low_confidence == cfg.min_baseline_n


def test_baseline_window_days_zero_raises():
    with pytest.raises(ValueError, match="baseline_window_days"):
        DetectorConfig(direction="HIGH", baseline_window_days=0)


def test_baseline_window_days_negative_raises():
    with pytest.raises(ValueError, match="baseline_window_days"):
        DetectorConfig(direction="HIGH", baseline_window_days=-7)


def test_config_is_immutable():
    cfg = DetectorConfig(direction="HIGH")
    with pytest.raises((AttributeError, TypeError)):
        cfg.direction = "LOW"  # type: ignore[misc]

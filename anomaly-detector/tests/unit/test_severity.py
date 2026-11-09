import pytest
from detector.severity import Severity, assign_continuous_severity, assign_zero_mad_severity, assign_error_severity


# ── assign_continuous_severity ───────────────────────────────────────────────
# Gate is z > threshold; caller guarantees this before calling severity.
# Bands with threshold T:
#   T < z < 2T  → INFO
#   2T ≤ z < 4T → WARNING   (2T inclusive)
#   z ≥ 4T      → CRITICAL  (4T inclusive)

class TestContinuousSeverity:

    def test_just_above_threshold_is_info(self):
        # z = 1.001, threshold = 1.0 → INFO
        assert assign_continuous_severity(1.001, 1.0) == Severity.INFO

    def test_just_below_two_threshold_is_info(self):
        assert assign_continuous_severity(1.999, 1.0) == Severity.INFO

    def test_exactly_two_threshold_is_warning_not_info(self):
        # Boundary: 2T inclusive → WARNING
        assert assign_continuous_severity(2.0, 1.0) == Severity.WARNING

    def test_just_above_two_threshold_is_warning(self):
        assert assign_continuous_severity(2.001, 1.0) == Severity.WARNING

    def test_just_below_four_threshold_is_warning(self):
        assert assign_continuous_severity(3.999, 1.0) == Severity.WARNING

    def test_exactly_four_threshold_is_critical_not_warning(self):
        # Boundary: 4T inclusive → CRITICAL
        assert assign_continuous_severity(4.0, 1.0) == Severity.CRITICAL

    def test_just_above_four_threshold_is_critical(self):
        assert assign_continuous_severity(4.001, 1.0) == Severity.CRITICAL

    def test_large_z_is_critical(self):
        assert assign_continuous_severity(100.0, 3.5) == Severity.CRITICAL

    def test_works_with_default_threshold_3_5(self):
        # z=5.0, threshold=3.5: 5.0 < 2*3.5=7.0 → INFO
        assert assign_continuous_severity(5.0, 3.5) == Severity.INFO

    def test_warning_band_with_3_5_threshold(self):
        # z=8.0, threshold=3.5: 7.0 <= 8.0 < 14.0 → WARNING
        assert assign_continuous_severity(8.0, 3.5) == Severity.WARNING

    def test_critical_band_with_3_5_threshold(self):
        # z=15.0, threshold=3.5: 15.0 >= 14.0 → CRITICAL
        assert assign_continuous_severity(15.0, 3.5) == Severity.CRITICAL


# ── assign_zero_mad_severity ─────────────────────────────────────────────────
# Caller guarantees absolute_deviation > absolute_floor.
# Bands with floor F:
#   F < d < 2F  → INFO
#   2F ≤ d ≤ 5F → WARNING   (2F inclusive; 5F inclusive)
#   d > 5F      → CRITICAL  (strictly > 5F)

class TestZeroMadSeverity:

    def test_just_above_floor_is_info(self):
        # d=10.001, floor=10 → INFO
        assert assign_zero_mad_severity(10.001, 10.0) == Severity.INFO

    def test_just_below_two_floor_is_info(self):
        assert assign_zero_mad_severity(19.999, 10.0) == Severity.INFO

    def test_exactly_two_floor_is_warning_not_info(self):
        # 2*floor inclusive → WARNING
        assert assign_zero_mad_severity(20.0, 10.0) == Severity.WARNING

    def test_just_above_two_floor_is_warning(self):
        assert assign_zero_mad_severity(20.001, 10.0) == Severity.WARNING

    def test_middle_of_warning_band(self):
        assert assign_zero_mad_severity(35.0, 10.0) == Severity.WARNING

    def test_exactly_five_floor_is_warning_not_critical(self):
        # 5*floor: still WARNING, not CRITICAL (> 5×floor needed for CRITICAL)
        assert assign_zero_mad_severity(50.0, 10.0) == Severity.WARNING

    def test_just_above_five_floor_is_critical(self):
        assert assign_zero_mad_severity(50.001, 10.0) == Severity.CRITICAL

    def test_large_deviation_is_critical(self):
        assert assign_zero_mad_severity(1000.0, 10.0) == Severity.CRITICAL


# ── assign_error_severity ─────────────────────────────────────────────────────
# Rules (CRITICAL > WARNING > INFO precedence):
#   1. is_persistent                            → CRITICAL
#   2. rate_ratio > 10 AND n >= warning_sample  → CRITICAL
#   3. rate_ratio > 5  AND n >= warning_sample  → WARNING
#   4. rate_ratio > 3  AND n >= info_sample     → INFO
#   5. is_first_occurrence                      → INFO
#   6. is_novel_type                            → INFO
# Boundary: rate comparisons use strict > (==10 not CRITICAL via rule 2, etc.)

class TestErrorSeverity:

    def _call(self, **kwargs):
        defaults = dict(
            is_first_occurrence=False,
            is_novel_type=False,
            rate_ratio=None,
            n_recent=0,
            is_persistent=False,
        )
        defaults.update(kwargs)
        return assign_error_severity(**defaults)

    def test_persistent_is_critical(self):
        assert self._call(is_persistent=True) == Severity.CRITICAL

    def test_rate_above_10_with_sufficient_n_is_critical(self):
        assert self._call(rate_ratio=11.0, n_recent=30) == Severity.CRITICAL

    def test_rate_above_10_with_insufficient_n_for_critical_falls_to_info(self):
        # n=29 < 30: rules 2 and 3 don't fire (need n >= 30)
        # Rule 4: 11 > 3 AND n=29 >= 10 → INFO
        assert self._call(rate_ratio=11.0, n_recent=29) == Severity.INFO

    def test_rate_exactly_10_is_not_critical_via_rule_2(self):
        # > 10 is strict; rate==10 falls to rule 3 (> 5, n >= 30) → WARNING
        assert self._call(rate_ratio=10.0, n_recent=30) == Severity.WARNING

    def test_rate_above_5_with_sufficient_n_is_warning(self):
        assert self._call(rate_ratio=6.0, n_recent=30) == Severity.WARNING

    def test_rate_exactly_5_is_not_warning_via_rule_3(self):
        # > 5 is strict; rate==5 falls to rule 4 (> 3, n >= 10) → INFO
        assert self._call(rate_ratio=5.0, n_recent=30) == Severity.INFO

    def test_rate_above_3_with_sufficient_n_is_info(self):
        assert self._call(rate_ratio=4.0, n_recent=10) == Severity.INFO

    def test_rate_above_3_with_insufficient_n_is_none(self):
        # n < 10 for info rule → no rule fires
        assert self._call(rate_ratio=4.0, n_recent=9) is None

    def test_rate_exactly_3_is_none(self):
        # > 3 is strict; rate==3 → no rate rule fires, others also false
        assert self._call(rate_ratio=3.0, n_recent=30) is None

    def test_first_occurrence_is_info(self):
        assert self._call(is_first_occurrence=True) == Severity.INFO

    def test_novel_type_is_info(self):
        assert self._call(is_novel_type=True) == Severity.INFO

    def test_no_conditions_is_none(self):
        assert self._call() is None

    def test_rate_none_does_not_fire_rate_rules(self):
        # rate_ratio=None means baseline had zero errors
        assert self._call(rate_ratio=None) is None

    # ── Precedence ──────────────────────────────────────────────────────────

    def test_persistent_beats_first_occurrence(self):
        # Both is_persistent and is_first_occurrence → CRITICAL wins
        assert self._call(is_persistent=True, is_first_occurrence=True) == Severity.CRITICAL

    def test_persistent_beats_high_rate(self):
        assert self._call(is_persistent=True, rate_ratio=11.0, n_recent=30) == Severity.CRITICAL

    def test_high_rate_beats_novel_type(self):
        # rate > 5 → WARNING; is_novel_type → INFO; WARNING wins
        assert self._call(rate_ratio=6.0, n_recent=30, is_novel_type=True) == Severity.WARNING

    def test_first_occurrence_combined_with_novel_type_is_info(self):
        # Both → INFO; same level, still INFO
        assert self._call(is_first_occurrence=True, is_novel_type=True) == Severity.INFO

    def test_moderate_rate_with_novel_type_is_info(self):
        # rate > 3 with n=10 → INFO; novel type → INFO; stays INFO
        assert self._call(rate_ratio=4.0, n_recent=10, is_novel_type=True) == Severity.INFO

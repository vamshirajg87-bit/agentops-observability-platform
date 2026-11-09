"""
Tests for the candidate_after boundary and history_days_for() additions
to AnomalyOrchestrator (Phase 10.5A).

All tests use the real _orchestrate path with a trivial identity mapper and
a controlled mock detector so the boundary logic itself is exercised without
requiring a live database.

Correct invocation from repo root:
    PYTHONPATH=anomaly-detector python -m pytest \
        anomaly-detector/tests/unit/test_orchestrator_candidate_after.py -q
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock, call

import psycopg
import pytest

from anomaly_repository import AnomalyRepository
from detector.anomaly_types import ErrorDetectorConfig
from detector.config import DetectorConfig
from orchestrator import AnomalyOrchestrator, OrchestrationResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UTC = timezone.utc

# A reference point used to build relative timestamps throughout.
_BASE = datetime(2024, 9, 1, 12, 0, 0, tzinfo=_UTC)

_T_HIST_1 = _BASE - timedelta(hours=5)   # deep history
_T_HIST_2 = _BASE - timedelta(hours=3)   # history
_T_CAND_BOUNDARY = _BASE - timedelta(hours=2)  # exactly at candidate_after
_T_CAND_1 = _BASE - timedelta(hours=1)   # candidate
_T_CAND_2 = _BASE                         # candidate


# ---------------------------------------------------------------------------
# Minimal record type for boundary tests
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rec:
    """Minimal record with a start_time, sufficient for _orchestrate boundary logic."""
    start_time: datetime
    label: str = ""


def _identity_mapper(row: Any) -> _Rec:
    """Pass-through: rows are already _Rec instances."""
    return row


def _make_orch(
    *,
    trace_latency_config: Optional[DetectorConfig] = None,
    agent_latency_config: Optional[DetectorConfig] = None,
    tool_latency_config: Optional[DetectorConfig] = None,
    retrieval_relevance_config: Optional[DetectorConfig] = None,
    retrieval_count_config: Optional[DetectorConfig] = None,
    error_rate_config: Optional[ErrorDetectorConfig] = None,
    tool_failure_config: Optional[ErrorDetectorConfig] = None,
) -> tuple[AnomalyOrchestrator, MagicMock, MagicMock]:
    mock_conn = MagicMock(spec=psycopg.Connection)
    mock_repo = MagicMock(spec=AnomalyRepository)
    orch = AnomalyOrchestrator(
        mock_conn,
        mock_repo,
        trace_latency_config=trace_latency_config,
        agent_latency_config=agent_latency_config,
        tool_latency_config=tool_latency_config,
        retrieval_relevance_config=retrieval_relevance_config,
        retrieval_count_config=retrieval_count_config,
        error_rate_config=error_rate_config,
        tool_failure_config=tool_failure_config,
    )
    return orch, mock_conn, mock_repo


def _make_detector_no_anomalies() -> MagicMock:
    """Mock detector that never produces anomalies."""
    det = MagicMock()
    det.detect.return_value = []
    return det


# ---------------------------------------------------------------------------
# TestCandidateAfterBoundary — core semantics of _orchestrate
# ---------------------------------------------------------------------------

class TestCandidateAfterBoundary:

    def test_history_only_rows_are_not_candidates(self):
        """Records before candidate_after must never be passed as current."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()
        rows = [
            _Rec(_T_HIST_1, "h1"),
            _Rec(_T_HIST_2, "h2"),
            _Rec(_T_CAND_1, "c1"),
        ]
        orch._orchestrate(rows, _identity_mapper, det, candidate_after=_T_CAND_1)

        called_as_current = [c.args[0] for c in det.detect.call_args_list]
        labels = [r.label for r in called_as_current]
        assert "h1" not in labels
        assert "h2" not in labels
        assert "c1" in labels

    def test_history_only_rows_remain_available_as_baseline_context(self):
        """History-only records must appear in the history argument passed to detect."""
        orch, _, _ = _make_orch()
        captured_histories: list[list[_Rec]] = []

        def _capturing_detect(current, history):
            captured_histories.append(list(history))
            return []

        det = MagicMock()
        det.detect.side_effect = _capturing_detect

        rows = [
            _Rec(_T_HIST_1, "h1"),
            _Rec(_T_HIST_2, "h2"),
            _Rec(_T_CAND_1, "c1"),
        ]
        orch._orchestrate(rows, _identity_mapper, det, candidate_after=_T_CAND_1)

        # detect was called once for c1
        assert len(captured_histories) == 1
        history_labels = {r.label for r in captured_histories[0]}
        # Both history-only records must be in the baseline for c1
        assert "h1" in history_labels
        assert "h2" in history_labels
        # c1 must not be in its own history
        assert "c1" not in history_labels

    def test_candidate_at_exactly_candidate_after_is_evaluated(self):
        """Records with start_time == candidate_after are candidates (>= boundary)."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()

        rows = [
            _Rec(_T_HIST_1, "h1"),
            _Rec(_T_CAND_BOUNDARY, "boundary"),   # start_time == candidate_after
            _Rec(_T_CAND_1, "c1"),
        ]
        orch._orchestrate(
            rows, _identity_mapper, det, candidate_after=_T_CAND_BOUNDARY
        )

        called_labels = [c.args[0].label for c in det.detect.call_args_list]
        assert "boundary" in called_labels
        assert "c1" in called_labels
        assert "h1" not in called_labels

    def test_candidate_after_none_all_records_are_candidates(self):
        """candidate_after=None: every record is a candidate — Phase 10.4E behavior."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()

        rows = [
            _Rec(_T_HIST_1, "h1"),
            _Rec(_T_HIST_2, "h2"),
            _Rec(_T_CAND_1, "c1"),
        ]
        result = orch._orchestrate(rows, _identity_mapper, det, candidate_after=None)

        called_labels = {c.args[0].label for c in det.detect.call_args_list}
        assert called_labels == {"h1", "h2", "c1"}
        assert result.processed_observations == 3

    def test_processed_observations_counts_candidates_only(self):
        """processed_observations must equal the number of candidate records."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()

        rows = [
            _Rec(_T_HIST_1, "h1"),   # history
            _Rec(_T_HIST_2, "h2"),   # history
            _Rec(_T_CAND_1, "c1"),   # candidate
            _Rec(_T_CAND_2, "c2"),   # candidate
        ]
        result = orch._orchestrate(
            rows, _identity_mapper, det, candidate_after=_T_CAND_1
        )

        assert result.processed_observations == 2   # only c1 and c2

    def test_processed_observations_none_counts_all_rows(self):
        """Without candidate_after, processed_observations == len(rows)."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()

        rows = [_Rec(_T_HIST_1), _Rec(_T_HIST_2), _Rec(_T_CAND_1), _Rec(_T_CAND_2)]
        result = orch._orchestrate(rows, _identity_mapper, det)

        assert result.processed_observations == 4

    def test_history_for_each_candidate_includes_all_earlier_records(self):
        """For any candidate C, history must be all records with start_time < C.start_time."""
        orch, _, _ = _make_orch()
        captured: dict[str, list[_Rec]] = {}

        def _side_effect(current, history):
            captured[current.label] = list(history)
            return []

        det = MagicMock()
        det.detect.side_effect = _side_effect

        rows = [
            _Rec(_T_HIST_1, "h1"),
            _Rec(_T_HIST_2, "h2"),
            _Rec(_T_CAND_1, "c1"),
            _Rec(_T_CAND_2, "c2"),
        ]
        orch._orchestrate(rows, _identity_mapper, det, candidate_after=_T_CAND_1)

        # c1's history: h1, h2 (both before c1)
        assert {r.label for r in captured["c1"]} == {"h1", "h2"}
        # c2's history: h1, h2, c1 (all before c2)
        assert {r.label for r in captured["c2"]} == {"h1", "h2", "c1"}

    def test_same_timestamp_history_rule_preserved(self):
        """Two candidates with identical start_time are neither in the other's history."""
        orch, _, _ = _make_orch()
        captured: dict[str, set[str]] = {}

        def _side_effect(current, history):
            captured[current.label] = {r.label for r in history}
            return []

        det = MagicMock()
        det.detect.side_effect = _side_effect

        # Two candidates with the SAME start_time
        same_t = _T_CAND_1
        rows = [
            _Rec(_T_HIST_1, "h1"),
            _Rec(same_t, "c_same_a"),
            _Rec(same_t, "c_same_b"),
        ]
        orch._orchestrate(rows, _identity_mapper, det, candidate_after=same_t)

        # Neither contemporary candidate appears in the other's history
        assert "c_same_a" not in captured["c_same_b"]
        assert "c_same_b" not in captured["c_same_a"]
        # Both have the history-only record in their baseline
        assert "h1" in captured["c_same_a"]
        assert "h1" in captured["c_same_b"]

    def test_same_timestamp_history_rule_preserved_none(self):
        """Same-timestamp rule also holds when candidate_after=None."""
        orch, _, _ = _make_orch()
        captured: dict[str, set[str]] = {}

        def _side_effect(current, history):
            captured[current.label] = {r.label for r in history}
            return []

        det = MagicMock()
        det.detect.side_effect = _side_effect

        same_t = _T_CAND_1
        rows = [
            _Rec(same_t, "x"),
            _Rec(same_t, "y"),
        ]
        orch._orchestrate(rows, _identity_mapper, det, candidate_after=None)

        assert "x" not in captured["y"]
        assert "y" not in captured["x"]

    def test_empty_rows_returns_zero_result(self):
        """No rows → zero result regardless of candidate_after."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()

        result = orch._orchestrate([], _identity_mapper, det, candidate_after=_T_CAND_1)

        assert result.processed_observations == 0
        assert result.detected_anomalies == 0
        assert result.inserted_anomalies == 0
        assert result.duplicate_anomalies == 0
        det.detect.assert_not_called()

    def test_all_rows_before_candidate_after_produces_zero_candidates(self):
        """All records are history-only → no evaluation, zero processed_observations."""
        orch, _, _ = _make_orch()
        det = _make_detector_no_anomalies()

        future_boundary = _T_CAND_2 + timedelta(hours=10)
        rows = [_Rec(_T_HIST_1), _Rec(_T_HIST_2), _Rec(_T_CAND_1)]
        result = orch._orchestrate(
            rows, _identity_mapper, det, candidate_after=future_boundary
        )

        assert result.processed_observations == 0
        det.detect.assert_not_called()

    def test_detected_and_persistence_counts_use_candidates_only(self):
        """Anomaly counting is consistent: only candidate evaluations contribute."""
        orch, _, mock_repo = _make_orch()
        # Detector fires one event for every record it sees as current
        from detector.anomaly_types import AnomalyEvent
        from detector.severity import Severity

        dummy_event = MagicMock(spec=AnomalyEvent)
        det = MagicMock()
        det.detect.return_value = [dummy_event]
        mock_repo.save.return_value = True   # all inserts succeed

        rows = [
            _Rec(_T_HIST_1, "h1"),   # history-only — must NOT trigger an anomaly
            _Rec(_T_CAND_1, "c1"),   # candidate — triggers one anomaly
        ]
        result = orch._orchestrate(
            rows, _identity_mapper, det, candidate_after=_T_CAND_1
        )

        assert result.processed_observations == 1
        assert result.detected_anomalies == 1
        assert result.inserted_anomalies == 1
        assert result.duplicate_anomalies == 0


# ---------------------------------------------------------------------------
# TestHistoryDaysFor — history_days_for() coverage
# ---------------------------------------------------------------------------

_DEFAULT_DAYS = 7   # matches DetectorConfig.baseline_window_days default

_ALL_SIGNAL_PATHS = [
    "trace_latency",
    "agent_latency",
    "tool_latency",
    "retrieval",
    "error_rate",
    "tool_failure",
]


class TestHistoryDaysFor:

    def test_default_config_all_paths_return_seven(self):
        """All six paths return 7 when the orchestrator uses default detector configs."""
        orch, _, _ = _make_orch()
        for path in _ALL_SIGNAL_PATHS:
            assert orch.history_days_for(path) == _DEFAULT_DAYS, (
                f"expected {_DEFAULT_DAYS} for '{path}'"
            )

    @pytest.mark.parametrize("path", _ALL_SIGNAL_PATHS)
    def test_all_six_signal_paths_accepted(self, path: str):
        """history_days_for() accepts every valid signal path without raising."""
        orch, _, _ = _make_orch()
        result = orch.history_days_for(path)
        assert isinstance(result, int)
        assert result >= 1

    def test_unknown_signal_path_raises_value_error(self):
        """An unknown signal_path must raise ValueError explicitly."""
        orch, _, _ = _make_orch()
        with pytest.raises(ValueError, match="unknown signal_path"):
            orch.history_days_for("not_a_real_path")

    def test_unknown_signal_path_empty_string_raises(self):
        orch, _, _ = _make_orch()
        with pytest.raises(ValueError):
            orch.history_days_for("")

    def test_custom_trace_latency_config_respected(self):
        """Custom baseline_window_days is returned for trace_latency."""
        custom = DetectorConfig(direction="HIGH", baseline_window_days=14)
        orch, _, _ = _make_orch(trace_latency_config=custom)
        assert orch.history_days_for("trace_latency") == 14

    def test_custom_agent_latency_config_respected(self):
        custom = DetectorConfig(direction="HIGH", baseline_window_days=10)
        orch, _, _ = _make_orch(agent_latency_config=custom)
        assert orch.history_days_for("agent_latency") == 10

    def test_custom_tool_latency_config_respected(self):
        custom = DetectorConfig(direction="HIGH", baseline_window_days=3)
        orch, _, _ = _make_orch(tool_latency_config=custom)
        assert orch.history_days_for("tool_latency") == 3

    def test_custom_error_rate_config_respected(self):
        custom = ErrorDetectorConfig(baseline_window_days=21)
        orch, _, _ = _make_orch(error_rate_config=custom)
        assert orch.history_days_for("error_rate") == 21

    def test_custom_tool_failure_config_respected(self):
        custom = ErrorDetectorConfig(baseline_window_days=2)
        orch, _, _ = _make_orch(tool_failure_config=custom)
        assert orch.history_days_for("tool_failure") == 2

    def test_retrieval_returns_max_of_relevance_and_count(self):
        """For 'retrieval', the maximum of the two detector configs is returned."""
        relevance_cfg = DetectorConfig(direction="LOW", baseline_window_days=5)
        count_cfg = DetectorConfig(direction="LOW", baseline_window_days=12)
        orch, _, _ = _make_orch(
            retrieval_relevance_config=relevance_cfg,
            retrieval_count_config=count_cfg,
        )
        assert orch.history_days_for("retrieval") == 12

    def test_retrieval_returns_max_when_relevance_is_larger(self):
        relevance_cfg = DetectorConfig(direction="LOW", baseline_window_days=30)
        count_cfg = DetectorConfig(direction="LOW", baseline_window_days=7)
        orch, _, _ = _make_orch(
            retrieval_relevance_config=relevance_cfg,
            retrieval_count_config=count_cfg,
        )
        assert orch.history_days_for("retrieval") == 30

    def test_retrieval_equal_configs_returns_that_value(self):
        """When both retrieval configs have the same value, that value is returned."""
        cfg = DetectorConfig(direction="LOW", baseline_window_days=9)
        orch, _, _ = _make_orch(
            retrieval_relevance_config=cfg,
            retrieval_count_config=cfg,
        )
        assert orch.history_days_for("retrieval") == 9

    def test_custom_configs_do_not_affect_other_paths(self):
        """Changing one path's config does not affect other paths."""
        custom = DetectorConfig(direction="HIGH", baseline_window_days=30)
        orch, _, _ = _make_orch(trace_latency_config=custom)

        # trace_latency uses custom value
        assert orch.history_days_for("trace_latency") == 30
        # All others remain at default
        for path in _ALL_SIGNAL_PATHS:
            if path != "trace_latency":
                assert orch.history_days_for(path) == _DEFAULT_DAYS, path

    def test_history_days_for_does_not_hardcode_seven(self):
        """Explicitly verify that a non-default value flows through correctly."""
        custom = DetectorConfig(direction="HIGH", baseline_window_days=1)
        orch, _, _ = _make_orch(tool_latency_config=custom)
        assert orch.history_days_for("tool_latency") == 1
        # Default paths are unaffected
        assert orch.history_days_for("trace_latency") == 7

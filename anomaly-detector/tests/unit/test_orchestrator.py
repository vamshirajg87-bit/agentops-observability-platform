"""
Tests for anomaly-detector/orchestrator.py

No live PostgreSQL required.  All telemetry queries, mappers, and detectors
are mocked; psycopg.Connection and AnomalyRepository are replaced with
MagicMock instances.

Correct invocation from repo root:
    PYTHONPATH=anomaly-detector python -m pytest anomaly-detector/tests/unit/test_orchestrator.py -q

Coverage:
    TestOrchestrationResult       — frozen dataclass, fields, invariant
    TestQueryRouting              — each run_* calls correct query with exact args
    TestMapperRouting             — each path uses correct mapper function
    TestDetectorRouting           — each path uses correct detector instance
    TestConfigInjection           — configs independently stored per detector
    TestTemporalSemantics         — strict start_time ordering, same-timestamp,
                                    non-chronological input order
    TestPersistence               — save() wiring, True/False counting, invariant
    TestEmptyCases                — zero rows, zero anomalies, non-error pass-through
    TestFailurePropagation        — query / mapper / detector / repo exceptions
    TestConnectionOwnership       — no commit, rollback, close, or psycopg.connect
    TestBoundaries                — no scheduling or checkpoint tables in source
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest

from anomaly_repository import AnomalyRepository
from detector.anomaly_types import (
    ErrorDetectorConfig,
    LatencyRecord,
)
from detector.config import DetectorConfig
from orchestrator import AnomalyOrchestrator, OrchestrationResult

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_T0 = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
_T1 = _T0 - timedelta(hours=3)
_T2 = _T0 - timedelta(hours=2)
_T3 = _T0 - timedelta(hours=1)
_WS = _T0 - timedelta(days=7)
_WE = _T0
_SVC = "research-service"
_OP = "agent.run"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_orch() -> tuple[AnomalyOrchestrator, MagicMock, MagicMock]:
    mock_conn = MagicMock(spec=psycopg.Connection)
    mock_repo = MagicMock(spec=AnomalyRepository)
    mock_repo.save.return_value = True
    orch = AnomalyOrchestrator(mock_conn, mock_repo)
    return orch, mock_conn, mock_repo


def _lr(start_time: datetime, *, trace_id: str = "t1", span_id=None) -> LatencyRecord:
    return LatencyRecord(
        trace_id=trace_id, span_id=span_id, service_name=_SVC,
        operation_name=_OP, duration_ms=100.0,
        start_time=start_time, is_error=False,
    )


def _mock_rec(start_time: datetime) -> MagicMock:
    """MagicMock with an explicit start_time so datetime comparisons behave correctly."""
    r = MagicMock()
    r.start_time = start_time
    return r


def _all_det_mocked(orch: AnomalyOrchestrator) -> dict[str, MagicMock]:
    """Replace every detector on orch with a silent MagicMock; return them keyed by attr."""
    det_attrs = (
        "_trace_latency_detector", "_agent_latency_detector",
        "_tool_latency_detector", "_retrieval_detector",
        "_error_rate_detector", "_tool_failure_detector",
    )
    dets: dict[str, MagicMock] = {}
    for attr in det_attrs:
        m = MagicMock()
        m.detect.return_value = []
        setattr(orch, attr, m)
        dets[attr] = m
    return dets


# ---------------------------------------------------------------------------
# TestOrchestrationResult
# ---------------------------------------------------------------------------

class TestOrchestrationResult:

    def test_is_frozen_dataclass(self):
        result = OrchestrationResult(
            processed_observations=10, detected_anomalies=3,
            inserted_anomalies=2, duplicate_anomalies=1,
        )
        with pytest.raises((AttributeError, TypeError)):
            result.processed_observations = 99  # type: ignore[misc]

    def test_invariant_satisfied_in_normal_result(self):
        result = OrchestrationResult(
            processed_observations=5, detected_anomalies=4,
            inserted_anomalies=3, duplicate_anomalies=1,
        )
        assert result.inserted_anomalies + result.duplicate_anomalies == result.detected_anomalies

    def test_all_zero_valid(self):
        result = OrchestrationResult(0, 0, 0, 0)
        assert result.processed_observations == 0
        assert result.detected_anomalies == 0
        assert result.inserted_anomalies == 0
        assert result.duplicate_anomalies == 0


# ---------------------------------------------------------------------------
# TestQueryRouting
# ---------------------------------------------------------------------------

class TestQueryRouting:

    def test_run_trace_latency_calls_fetch_trace_latency_history(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_trace_latency_history", return_value=[]) as q:
            orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        q.assert_called_once_with(
            orch._conn,
            service_name=_SVC, operation_name=_OP,
            window_start=_WS, window_end=_WE,
        )

    def test_run_agent_latency_calls_fetch_agent_latency_history(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_agent_latency_history", return_value=[]) as q:
            orch.run_agent_latency(_SVC, _OP, _WS, _WE)
        q.assert_called_once_with(
            orch._conn,
            service_name=_SVC, operation_name=_OP,
            window_start=_WS, window_end=_WE,
        )

    def test_run_tool_latency_calls_fetch_tool_latency_history(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_tool_latency_history", return_value=[]) as q:
            orch.run_tool_latency(_SVC, _WS, _WE)
        q.assert_called_once_with(
            orch._conn,
            service_name=_SVC,
            window_start=_WS, window_end=_WE,
        )

    def test_run_tool_latency_does_not_pass_operation_name(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_tool_latency_history", return_value=[]) as q:
            orch.run_tool_latency(_SVC, _WS, _WE)
        assert "operation_name" not in q.call_args.kwargs

    def test_run_retrieval_calls_fetch_retrieval_history(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_retrieval_history", return_value=[]) as q:
            orch.run_retrieval(_SVC, _WS, _WE)
        q.assert_called_once_with(
            orch._conn,
            service_name=_SVC,
            window_start=_WS, window_end=_WE,
        )

    def test_run_retrieval_does_not_pass_operation_name(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_retrieval_history", return_value=[]) as q:
            orch.run_retrieval(_SVC, _WS, _WE)
        assert "operation_name" not in q.call_args.kwargs

    def test_run_error_rate_calls_fetch_error_rate_history(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_error_rate_history", return_value=[]) as q:
            orch.run_error_rate(_SVC, _OP, _WS, _WE)
        q.assert_called_once_with(
            orch._conn,
            service_name=_SVC, operation_name=_OP,
            window_start=_WS, window_end=_WE,
        )

    def test_run_tool_failure_calls_fetch_tool_failure_history(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_tool_failure_history", return_value=[]) as q:
            orch.run_tool_failure(_SVC, _WS, _WE)
        q.assert_called_once_with(
            orch._conn,
            service_name=_SVC,
            window_start=_WS, window_end=_WE,
        )

    def test_run_tool_failure_does_not_pass_operation_name(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_tool_failure_history", return_value=[]) as q:
            orch.run_tool_failure(_SVC, _WS, _WE)
        assert "operation_name" not in q.call_args.kwargs

    def test_conn_passed_as_first_positional_to_query(self):
        orch, mock_conn, _ = _make_orch()
        with patch("orchestrator.fetch_trace_latency_history", return_value=[]) as q:
            orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert q.call_args.args[0] is mock_conn


# ---------------------------------------------------------------------------
# TestMapperRouting
# ---------------------------------------------------------------------------

class TestMapperRouting:
    """Each signal path must call the correct mapper, not any other."""

    def _run_with_one_row_capture_mapper(
        self, run_method, query_patch, mapper_patch, *args
    ) -> tuple[MagicMock, dict]:
        orch, _, _ = _make_orch()
        _all_det_mocked(orch)  # silence all detectors
        row = {"col": "value"}
        rec = _mock_rec(_T0)
        with patch(query_patch, return_value=[row]):
            with patch(mapper_patch, return_value=rec) as mock_mapper:
                getattr(orch, run_method)(*args)
        return mock_mapper, row

    def test_run_trace_latency_uses_row_to_trace_latency_record(self):
        mock_mapper, row = self._run_with_one_row_capture_mapper(
            "run_trace_latency",
            "orchestrator.fetch_trace_latency_history",
            "orchestrator.row_to_trace_latency_record",
            _SVC, _OP, _WS, _WE,
        )
        mock_mapper.assert_called_once_with(row)

    def test_run_agent_latency_uses_row_to_span_latency_record(self):
        mock_mapper, row = self._run_with_one_row_capture_mapper(
            "run_agent_latency",
            "orchestrator.fetch_agent_latency_history",
            "orchestrator.row_to_span_latency_record",
            _SVC, _OP, _WS, _WE,
        )
        mock_mapper.assert_called_once_with(row)

    def test_run_tool_latency_uses_row_to_span_latency_record(self):
        mock_mapper, row = self._run_with_one_row_capture_mapper(
            "run_tool_latency",
            "orchestrator.fetch_tool_latency_history",
            "orchestrator.row_to_span_latency_record",
            _SVC, _WS, _WE,
        )
        mock_mapper.assert_called_once_with(row)

    def test_run_retrieval_uses_row_to_retrieval_record(self):
        mock_mapper, row = self._run_with_one_row_capture_mapper(
            "run_retrieval",
            "orchestrator.fetch_retrieval_history",
            "orchestrator.row_to_retrieval_record",
            _SVC, _WS, _WE,
        )
        mock_mapper.assert_called_once_with(row)

    def test_run_error_rate_uses_row_to_error_record(self):
        mock_mapper, row = self._run_with_one_row_capture_mapper(
            "run_error_rate",
            "orchestrator.fetch_error_rate_history",
            "orchestrator.row_to_error_record",
            _SVC, _OP, _WS, _WE,
        )
        mock_mapper.assert_called_once_with(row)

    def test_run_tool_failure_uses_row_to_tool_record(self):
        mock_mapper, row = self._run_with_one_row_capture_mapper(
            "run_tool_failure",
            "orchestrator.fetch_tool_failure_history",
            "orchestrator.row_to_tool_record",
            _SVC, _WS, _WE,
        )
        mock_mapper.assert_called_once_with(row)


# ---------------------------------------------------------------------------
# TestDetectorRouting
# ---------------------------------------------------------------------------

class TestDetectorRouting:

    def test_run_trace_latency_uses_trace_latency_detector(self):
        orch, _, _ = _make_orch()
        dets = _all_det_mocked(orch)
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        dets["_trace_latency_detector"].detect.assert_called_once()
        dets["_agent_latency_detector"].detect.assert_not_called()
        dets["_tool_latency_detector"].detect.assert_not_called()

    def test_run_agent_latency_uses_agent_latency_detector(self):
        orch, _, _ = _make_orch()
        dets = _all_det_mocked(orch)
        with patch("orchestrator.fetch_agent_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_span_latency_record", return_value=_mock_rec(_T0)):
                orch.run_agent_latency(_SVC, _OP, _WS, _WE)
        dets["_agent_latency_detector"].detect.assert_called_once()
        dets["_trace_latency_detector"].detect.assert_not_called()
        dets["_tool_latency_detector"].detect.assert_not_called()

    def test_run_tool_latency_uses_tool_latency_detector(self):
        orch, _, _ = _make_orch()
        dets = _all_det_mocked(orch)
        with patch("orchestrator.fetch_tool_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_span_latency_record", return_value=_mock_rec(_T0)):
                orch.run_tool_latency(_SVC, _WS, _WE)
        dets["_tool_latency_detector"].detect.assert_called_once()
        dets["_trace_latency_detector"].detect.assert_not_called()
        dets["_agent_latency_detector"].detect.assert_not_called()

    def test_run_retrieval_uses_retrieval_detector(self):
        orch, _, _ = _make_orch()
        dets = _all_det_mocked(orch)
        with patch("orchestrator.fetch_retrieval_history", return_value=[{}]):
            with patch("orchestrator.row_to_retrieval_record", return_value=_mock_rec(_T0)):
                orch.run_retrieval(_SVC, _WS, _WE)
        dets["_retrieval_detector"].detect.assert_called_once()
        dets["_error_rate_detector"].detect.assert_not_called()

    def test_run_error_rate_uses_error_rate_detector(self):
        orch, _, _ = _make_orch()
        dets = _all_det_mocked(orch)
        with patch("orchestrator.fetch_error_rate_history", return_value=[{}]):
            with patch("orchestrator.row_to_error_record", return_value=_mock_rec(_T0)):
                orch.run_error_rate(_SVC, _OP, _WS, _WE)
        dets["_error_rate_detector"].detect.assert_called_once()
        dets["_tool_failure_detector"].detect.assert_not_called()

    def test_run_tool_failure_uses_tool_failure_detector(self):
        orch, _, _ = _make_orch()
        dets = _all_det_mocked(orch)
        with patch("orchestrator.fetch_tool_failure_history", return_value=[{}]):
            with patch("orchestrator.row_to_tool_record", return_value=_mock_rec(_T0)):
                orch.run_tool_failure(_SVC, _WS, _WE)
        dets["_tool_failure_detector"].detect.assert_called_once()
        dets["_error_rate_detector"].detect.assert_not_called()

    def test_three_latency_detectors_are_distinct_instances(self):
        orch, _, _ = _make_orch()
        assert orch._trace_latency_detector is not orch._agent_latency_detector
        assert orch._trace_latency_detector is not orch._tool_latency_detector
        assert orch._agent_latency_detector is not orch._tool_latency_detector

    def test_error_rate_and_tool_failure_detectors_are_distinct(self):
        orch, _, _ = _make_orch()
        assert orch._error_rate_detector is not orch._tool_failure_detector

    def test_retrieval_detector_is_distinct_from_latency_detectors(self):
        orch, _, _ = _make_orch()
        assert orch._retrieval_detector is not orch._trace_latency_detector
        assert orch._retrieval_detector is not orch._agent_latency_detector
        assert orch._retrieval_detector is not orch._tool_latency_detector


# ---------------------------------------------------------------------------
# TestConfigInjection
# ---------------------------------------------------------------------------

def _make_det_cfg(**kwargs) -> DetectorConfig:
    defaults = dict(direction="HIGH", z_threshold=3.5, absolute_floor=50.0,
                    min_baseline_n=30, min_baseline_n_low_confidence=10,
                    baseline_window_days=7)
    defaults.update(kwargs)
    return DetectorConfig(**defaults)


class TestConfigInjection:

    def test_trace_latency_config_stored_on_trace_detector(self):
        cfg = _make_det_cfg(absolute_floor=200.0)
        mock_conn = MagicMock(spec=psycopg.Connection)
        mock_repo = MagicMock(spec=AnomalyRepository)
        orch = AnomalyOrchestrator(mock_conn, mock_repo, trace_latency_config=cfg)
        assert orch._trace_latency_detector.config is cfg

    def test_trace_latency_config_not_propagated_to_agent_detector(self):
        cfg = _make_det_cfg(absolute_floor=200.0)
        mock_conn = MagicMock(spec=psycopg.Connection)
        mock_repo = MagicMock(spec=AnomalyRepository)
        orch = AnomalyOrchestrator(mock_conn, mock_repo, trace_latency_config=cfg)
        assert orch._agent_latency_detector.config is not cfg
        assert orch._tool_latency_detector.config is not cfg

    def test_agent_latency_config_stored_independently(self):
        cfg = _make_det_cfg(absolute_floor=75.0)
        mock_conn = MagicMock(spec=psycopg.Connection)
        mock_repo = MagicMock(spec=AnomalyRepository)
        orch = AnomalyOrchestrator(mock_conn, mock_repo, agent_latency_config=cfg)
        assert orch._agent_latency_detector.config is cfg
        assert orch._trace_latency_detector.config is not cfg

    def test_error_rate_config_stored(self):
        cfg = ErrorDetectorConfig(recent_window_hours=12)
        mock_conn = MagicMock(spec=psycopg.Connection)
        mock_repo = MagicMock(spec=AnomalyRepository)
        orch = AnomalyOrchestrator(mock_conn, mock_repo, error_rate_config=cfg)
        assert orch._error_rate_detector.config is cfg

    def test_tool_failure_config_independent_from_error_rate_config(self):
        error_cfg = ErrorDetectorConfig(recent_window_hours=24)
        tool_cfg = ErrorDetectorConfig(recent_window_hours=6)
        mock_conn = MagicMock(spec=psycopg.Connection)
        mock_repo = MagicMock(spec=AnomalyRepository)
        orch = AnomalyOrchestrator(
            mock_conn, mock_repo,
            error_rate_config=error_cfg, tool_failure_config=tool_cfg,
        )
        assert orch._error_rate_detector.config is error_cfg
        assert orch._tool_failure_detector.config is tool_cfg

    def test_retrieval_relevance_and_count_configs_independent(self):
        rel_cfg = _make_det_cfg(direction="LOW", absolute_floor=0.01)
        cnt_cfg = _make_det_cfg(direction="LOW", absolute_floor=2.0)
        mock_conn = MagicMock(spec=psycopg.Connection)
        mock_repo = MagicMock(spec=AnomalyRepository)
        orch = AnomalyOrchestrator(
            mock_conn, mock_repo,
            retrieval_relevance_config=rel_cfg, retrieval_count_config=cnt_cfg,
        )
        assert orch._retrieval_detector.relevance_config is rel_cfg
        assert orch._retrieval_detector.count_config is cnt_cfg


# ---------------------------------------------------------------------------
# TestTemporalSemantics
# ---------------------------------------------------------------------------

class TestTemporalSemantics:
    """
    Verify the locked history rule:
        history = [r for r in records if r.start_time < current.start_time]

    All tests patch fetch + mapper to inject controlled record sequences, then
    inspect the history argument captured from mock detect() calls.
    """

    def _detect_calls(self, records):
        """
        Run run_trace_latency with the given record sequence via patched mapper.
        Returns the detect call_args_list.
        """
        orch, _, _ = _make_orch()
        mock_det = MagicMock()
        mock_det.detect.return_value = []
        orch._trace_latency_detector = mock_det
        rows = [{} for _ in records]
        with patch("orchestrator.fetch_trace_latency_history", return_value=rows):
            with patch("orchestrator.row_to_trace_latency_record", side_effect=records):
                orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        return mock_det.detect.call_args_list

    def test_first_record_has_empty_history(self):
        r1, r2 = _lr(_T1), _lr(_T2)
        calls = self._detect_calls([r1, r2])
        current, history = calls[0].args
        assert current is r1
        assert history == []

    def test_second_record_has_first_as_history(self):
        r1, r2 = _lr(_T1), _lr(_T2)
        calls = self._detect_calls([r1, r2])
        current, history = calls[1].args
        assert current is r2
        assert history == [r1]

    def test_third_record_has_both_prior_records_in_history(self):
        r1, r2, r3 = _lr(_T1), _lr(_T2), _lr(_T3)
        calls = self._detect_calls([r1, r2, r3])
        current, history = calls[2].args
        assert current is r3
        assert r1 in history
        assert r2 in history
        assert r3 not in history

    def test_same_timestamp_records_excluded_from_each_others_history(self):
        T_SAME = _T1
        r1 = _lr(T_SAME, trace_id="t-a")
        r2 = _lr(T_SAME, trace_id="t-b")   # same start_time, different trace
        r3 = _lr(_T2)
        calls = self._detect_calls([r1, r2, r3])
        # r1: no prior record with start_time < T_SAME
        _, hist_r1 = calls[0].args
        assert hist_r1 == []
        # r2: r1.start_time == r2.start_time, so NOT strictly prior
        _, hist_r2 = calls[1].args
        assert r1 not in hist_r2
        assert hist_r2 == []
        # r3: both r1 and r2 have start_time == T_SAME < T_2
        _, hist_r3 = calls[2].args
        assert r1 in hist_r3
        assert r2 in hist_r3

    def test_non_chronological_input_order_history_still_time_based(self):
        """
        Rows arrive in reverse order (r3, r2, r1 — latest first).
        History must still be computed from start_time, not list position.
        """
        r1 = _lr(_T1, trace_id="t1")
        r2 = _lr(_T2, trace_id="t2")
        r3 = _lr(_T3, trace_id="t3")
        calls = self._detect_calls([r3, r2, r1])   # intentionally reversed

        # First in list is r3 (latest timestamp) — its history must be r1 and r2
        cur_r3, hist_r3 = calls[0].args
        assert cur_r3 is r3
        assert r1 in hist_r3
        assert r2 in hist_r3
        assert r3 not in hist_r3

        # Second in list is r2 — its history must be only r1
        cur_r2, hist_r2 = calls[1].args
        assert cur_r2 is r2
        assert r1 in hist_r2
        assert r3 not in hist_r2

        # Last in list is r1 (earliest) — no prior records
        cur_r1, hist_r1 = calls[2].args
        assert cur_r1 is r1
        assert hist_r1 == []


# ---------------------------------------------------------------------------
# TestPersistence
# ---------------------------------------------------------------------------

class TestPersistence:

    def test_each_anomaly_event_passed_to_save_once(self):
        orch, _, mock_repo = _make_orch()
        ev1, ev2 = MagicMock(), MagicMock()
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = [ev1, ev2]
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert mock_repo.save.call_count == 2
        saved = [c.args[0] for c in mock_repo.save.call_args_list]
        assert ev1 in saved
        assert ev2 in saved

    def test_save_true_counted_as_inserted(self):
        orch, _, mock_repo = _make_orch()
        mock_repo.save.return_value = True
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = [MagicMock()]
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                result = orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert result.inserted_anomalies == 1
        assert result.duplicate_anomalies == 0

    def test_save_false_counted_as_duplicate(self):
        orch, _, mock_repo = _make_orch()
        mock_repo.save.return_value = False
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = [MagicMock()]
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                result = orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert result.inserted_anomalies == 0
        assert result.duplicate_anomalies == 1

    def test_mixed_save_results_counted_correctly(self):
        orch, _, mock_repo = _make_orch()
        mock_repo.save.side_effect = [True, False, True]
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = [MagicMock(), MagicMock(), MagicMock()]
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                result = orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert result.detected_anomalies == 3
        assert result.inserted_anomalies == 2
        assert result.duplicate_anomalies == 1

    def test_invariant_inserted_plus_duplicate_equals_detected(self):
        orch, _, mock_repo = _make_orch()
        mock_repo.save.side_effect = [True, False]
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = [MagicMock(), MagicMock()]
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                result = orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert result.inserted_anomalies + result.duplicate_anomalies == result.detected_anomalies

    def test_retrieval_two_events_from_one_record_both_saved(self):
        orch, _, mock_repo = _make_orch()
        mock_repo.save.return_value = True
        ev1, ev2 = MagicMock(), MagicMock()
        orch._retrieval_detector = MagicMock()
        orch._retrieval_detector.detect.return_value = [ev1, ev2]
        with patch("orchestrator.fetch_retrieval_history", return_value=[{}]):
            with patch("orchestrator.row_to_retrieval_record", return_value=_mock_rec(_T0)):
                result = orch.run_retrieval(_SVC, _WS, _WE)
        assert result.detected_anomalies == 2
        assert result.inserted_anomalies == 2
        assert mock_repo.save.call_count == 2

    def test_processed_observations_count_equals_number_of_rows(self):
        orch, _, _ = _make_orch()
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = []
        rows = [{}, {}, {}]
        records = [_mock_rec(_T0 - timedelta(hours=3 - i)) for i in range(3)]
        with patch("orchestrator.fetch_trace_latency_history", return_value=rows):
            with patch("orchestrator.row_to_trace_latency_record", side_effect=records):
                result = orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert result.processed_observations == 3


# ---------------------------------------------------------------------------
# TestEmptyCases
# ---------------------------------------------------------------------------

class TestEmptyCases:

    def test_zero_rows_returns_all_zero_result(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_trace_latency_history", return_value=[]):
            result = orch.run_trace_latency(_SVC, _OP, _WS, _WE)
        assert result == OrchestrationResult(0, 0, 0, 0)

    def test_n_rows_zero_anomalies_returns_correct_counts(self):
        orch, _, _ = _make_orch()
        orch._agent_latency_detector = MagicMock()
        orch._agent_latency_detector.detect.return_value = []
        records = [_mock_rec(_T1), _mock_rec(_T2)]
        with patch("orchestrator.fetch_agent_latency_history", return_value=[{}, {}]):
            with patch("orchestrator.row_to_span_latency_record", side_effect=records):
                result = orch.run_agent_latency(_SVC, _OP, _WS, _WE)
        assert result.processed_observations == 2
        assert result.detected_anomalies == 0
        assert result.inserted_anomalies == 0
        assert result.duplicate_anomalies == 0

    def test_non_error_error_record_processed_but_yields_no_event(self):
        orch, _, _ = _make_orch()
        orch._error_rate_detector = MagicMock()
        orch._error_rate_detector.detect.return_value = []
        rec = _mock_rec(_T0)
        with patch("orchestrator.fetch_error_rate_history", return_value=[{}]):
            with patch("orchestrator.row_to_error_record", return_value=rec):
                result = orch.run_error_rate(_SVC, _OP, _WS, _WE)
        assert result.processed_observations == 1
        assert result.detected_anomalies == 0
        orch._error_rate_detector.detect.assert_called_once()

    def test_non_error_tool_record_processed_but_yields_no_event(self):
        orch, _, _ = _make_orch()
        orch._tool_failure_detector = MagicMock()
        orch._tool_failure_detector.detect.return_value = []
        rec = _mock_rec(_T0)
        with patch("orchestrator.fetch_tool_failure_history", return_value=[{}]):
            with patch("orchestrator.row_to_tool_record", return_value=rec):
                result = orch.run_tool_failure(_SVC, _WS, _WE)
        assert result.processed_observations == 1
        assert result.detected_anomalies == 0
        orch._tool_failure_detector.detect.assert_called_once()


# ---------------------------------------------------------------------------
# TestFailurePropagation
# ---------------------------------------------------------------------------

class TestFailurePropagation:

    def test_query_exception_propagates(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_trace_latency_history", side_effect=psycopg.Error("db error")):
            with pytest.raises(psycopg.Error):
                orch.run_trace_latency(_SVC, _OP, _WS, _WE)

    def test_mapper_exception_propagates(self):
        orch, _, _ = _make_orch()
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{"col": 1}]):
            with patch("orchestrator.row_to_trace_latency_record", side_effect=KeyError("missing_col")):
                with pytest.raises(KeyError):
                    orch.run_trace_latency(_SVC, _OP, _WS, _WE)

    def test_detector_exception_propagates(self):
        orch, _, _ = _make_orch()
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.side_effect = RuntimeError("detector bug")
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                with pytest.raises(RuntimeError, match="detector bug"):
                    orch.run_trace_latency(_SVC, _OP, _WS, _WE)

    def test_repository_exception_propagates(self):
        orch, _, mock_repo = _make_orch()
        mock_repo.save.side_effect = psycopg.Error("constraint violation")
        orch._trace_latency_detector = MagicMock()
        orch._trace_latency_detector.detect.return_value = [MagicMock()]
        with patch("orchestrator.fetch_trace_latency_history", return_value=[{}]):
            with patch("orchestrator.row_to_trace_latency_record", return_value=_mock_rec(_T0)):
                with pytest.raises(psycopg.Error):
                    orch.run_trace_latency(_SVC, _OP, _WS, _WE)


# ---------------------------------------------------------------------------
# TestConnectionOwnership
# ---------------------------------------------------------------------------

class TestConnectionOwnership:

    def _run_trace_empty(self, orch: AnomalyOrchestrator) -> None:
        with patch("orchestrator.fetch_trace_latency_history", return_value=[]):
            orch.run_trace_latency(_SVC, _OP, _WS, _WE)

    def test_no_commit_called(self):
        orch, mock_conn, _ = _make_orch()
        self._run_trace_empty(orch)
        mock_conn.commit.assert_not_called()

    def test_no_rollback_called(self):
        orch, mock_conn, _ = _make_orch()
        self._run_trace_empty(orch)
        mock_conn.rollback.assert_not_called()

    def test_no_close_called(self):
        orch, mock_conn, _ = _make_orch()
        self._run_trace_empty(orch)
        mock_conn.close.assert_not_called()

    def test_no_psycopg_connect_in_source(self):
        source = (Path(__file__).parents[2] / "orchestrator.py").read_text()
        assert "psycopg.connect(" not in source


# ---------------------------------------------------------------------------
# TestBoundaries
# ---------------------------------------------------------------------------

class TestBoundaries:

    def test_no_scheduling_code_in_source(self):
        source = (Path(__file__).parents[2] / "orchestrator.py").read_text()
        assert "time.sleep" not in source
        assert "import schedule" not in source
        assert "asyncio.sleep" not in source
        assert "threading.Timer" not in source

    def test_no_checkpoint_or_watermark_table_references_in_source(self):
        source = (Path(__file__).parents[2] / "orchestrator.py").read_text()
        assert "processed_windows" not in source
        assert "watermark_table" not in source

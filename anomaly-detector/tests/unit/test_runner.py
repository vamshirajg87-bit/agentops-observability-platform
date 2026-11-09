"""
Tests for anomaly-detector/runner.py

No live PostgreSQL required.  All database collaborators (psycopg connections,
AnomalyRepository, AnomalyOrchestrator, read_checkpoint, write_checkpoint) are
replaced with mocks patched at runner module boundaries.

Correct invocation from repo root:
    PYTHONPATH=anomaly-detector python -m pytest \
        anomaly-detector/tests/unit/test_runner.py -q

Coverage categories (matching Phase 10.5C2 specification):
    1.  Query-end / now parameter resolution
    2.  Three-boundary window computation
    3.  Orchestrator dispatch (all six signal paths; argument verification)
    4.  Successful transaction (read, orchestrate, write, commit)
    5.  Empty successful window (checkpoint still advanced)
    6.  Pre-commit failure (rollback, status error, next group continues)
    7.  Checkpoint write failure (orchestration counts preserved, status error)
    8.  Commit failure (status uncertain, rollback attempted)
    9.  Commit failure + successful rollback (same connection reused)
    10. Commit failure + rollback failure (connection replaced, new repo/orch)
    11. Pre-commit failure + rollback failure (same replacement behavior)
    12. Initial connect_fn failure (raises immediately, no fabricated results)
    13. Replacement connect_fn failure (early termination, no fake results)
    14. Connection ownership (open, replacement, final close)
    15. Result type contracts (frozen, order, aggregates, invariants)
    16. Unknown signal_path dispatch raises loudly
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest

from orchestrator import OrchestrationResult
from run_config import GroupConfig, RunConfig
from runner import RunGroupResult, RunResult, run_all_groups

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_QUERY_END = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_conn():
    conn = MagicMock()
    conn.commit.return_value = None
    conn.rollback.return_value = None
    conn.close.return_value = None
    return conn


def _make_orch_result(processed=1, detected=2, inserted=2, duplicate=0):
    return OrchestrationResult(
        processed_observations=processed,
        detected_anomalies=detected,
        inserted_anomalies=inserted,
        duplicate_anomalies=duplicate,
    )


def _trace_group(service_name="svc", operation_name="chat"):
    return GroupConfig(
        signal_path="trace_latency",
        service_name=service_name,
        operation_name=operation_name,
    )


def _agent_group(service_name="svc", operation_name="run"):
    return GroupConfig(
        signal_path="agent_latency",
        service_name=service_name,
        operation_name=operation_name,
    )


def _tool_latency_group(service_name="svc"):
    return GroupConfig(signal_path="tool_latency", service_name=service_name, operation_name="")


def _retrieval_group(service_name="svc"):
    return GroupConfig(signal_path="retrieval", service_name=service_name, operation_name="")


def _error_rate_group(service_name="svc", operation_name="query"):
    return GroupConfig(
        signal_path="error_rate",
        service_name=service_name,
        operation_name=operation_name,
    )


def _tool_failure_group(service_name="svc"):
    return GroupConfig(signal_path="tool_failure", service_name=service_name, operation_name="")


def _make_config(groups=None, overlap_minutes=5, initial_lookback_hours=24):
    if groups is None:
        groups = [_trace_group()]
    return RunConfig(
        overlap_minutes=overlap_minutes,
        initial_lookback_hours=initial_lookback_hours,
        groups=tuple(groups),
    )


# ---------------------------------------------------------------------------
# 1. Query-end / now parameter resolution
# ---------------------------------------------------------------------------

class TestQueryEndResolution:

    def test_naive_now_raises(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        naive = datetime(2024, 6, 15, 12, 0, 0)  # no tzinfo
        with patch("runner.AnomalyOrchestrator"), patch("runner.AnomalyRepository"):
            with pytest.raises(ValueError, match="naive"):
                run_all_groups(config, connect_fn, now=naive)

    def test_tzinfo_with_none_utcoffset_raises(self):
        from datetime import tzinfo as _TZInfo

        class _BadTZ(_TZInfo):
            def utcoffset(self, dt):
                return None
            def tzname(self, dt):
                return "bad"
            def dst(self, dt):
                return None

        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        bad_dt = datetime(2024, 6, 15, 12, 0, 0, tzinfo=_BadTZ())
        with patch("runner.AnomalyOrchestrator"), patch("runner.AnomalyRepository"):
            with pytest.raises(ValueError, match="utcoffset"):
                run_all_groups(config, connect_fn, now=bad_dt)

    def test_non_utc_aware_now_normalised_to_utc(self):
        tz_plus5 = timezone(timedelta(hours=5))
        now_plus5 = datetime(2024, 6, 15, 17, 0, 0, tzinfo=tz_plus5)  # = 12:00 UTC
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None) as mock_read, \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=now_plus5)
        expected_query_end = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert result.group_results[0].query_end == expected_query_end

    def test_none_now_uses_utc_wall_clock(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn)
        qe = result.group_results[0].query_end
        assert qe.tzinfo is not None
        assert qe.utcoffset().total_seconds() == 0.0


# ---------------------------------------------------------------------------
# 2. Window computation
# ---------------------------------------------------------------------------

class TestWindowComputation:

    def _run_one_group(self, group, overlap_minutes=5, initial_lookback_hours=24,
                       prior_checkpoint=None, history_days=30):
        config = _make_config(groups=[group],
                              overlap_minutes=overlap_minutes,
                              initial_lookback_hours=initial_lookback_hours)
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=prior_checkpoint), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = history_days
            for method in ("run_trace_latency", "run_agent_latency", "run_tool_latency",
                           "run_retrieval", "run_error_rate", "run_tool_failure"):
                getattr(MockOrch.return_value, method).return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        return result.group_results[0]

    def test_first_run_candidate_after(self):
        gr = self._run_one_group(_trace_group(), initial_lookback_hours=24)
        expected = _QUERY_END - timedelta(hours=24)
        assert gr.candidate_after == expected

    def test_first_run_history_start(self):
        gr = self._run_one_group(_trace_group(), initial_lookback_hours=24, history_days=30)
        expected_ca = _QUERY_END - timedelta(hours=24)
        expected_hs = expected_ca - timedelta(days=30)
        assert gr.history_start == expected_hs

    def test_subsequent_run_candidate_after_uses_overlap(self):
        checkpoint = datetime(2024, 6, 14, 12, 0, 0, tzinfo=timezone.utc)
        gr = self._run_one_group(_trace_group(), overlap_minutes=10,
                                 prior_checkpoint=checkpoint)
        expected = checkpoint - timedelta(minutes=10)
        assert gr.candidate_after == expected

    def test_subsequent_run_history_start(self):
        checkpoint = datetime(2024, 6, 14, 12, 0, 0, tzinfo=timezone.utc)
        gr = self._run_one_group(_trace_group(), overlap_minutes=10,
                                 prior_checkpoint=checkpoint, history_days=14)
        expected_ca = checkpoint - timedelta(minutes=10)
        expected_hs = expected_ca - timedelta(days=14)
        assert gr.history_start == expected_hs

    def test_same_query_end_for_all_groups(self):
        groups = [_trace_group(), _tool_latency_group()]
        config = _make_config(groups=groups)
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            MockOrch.return_value.run_tool_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        qe0 = result.group_results[0].query_end
        qe1 = result.group_results[1].query_end
        assert qe0 == qe1 == _QUERY_END

    def test_prior_checkpoint_stored_in_result(self):
        checkpoint = datetime(2024, 6, 14, 0, 0, 0, tzinfo=timezone.utc)
        gr = self._run_one_group(_trace_group(), prior_checkpoint=checkpoint)
        assert gr.prior_checkpoint == checkpoint

    def test_no_prior_checkpoint_stored_as_none_in_result(self):
        gr = self._run_one_group(_trace_group(), prior_checkpoint=None)
        assert gr.prior_checkpoint is None


# ---------------------------------------------------------------------------
# 3. Orchestrator dispatch
# ---------------------------------------------------------------------------

class TestDispatch:

    def _dispatch_call_args(self, group, prior_checkpoint=None, history_days=30):
        config = _make_config(groups=[group])
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=prior_checkpoint), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            mock_orch = MockOrch.return_value
            mock_orch.history_days_for.return_value = history_days
            for method in ("run_trace_latency", "run_agent_latency", "run_tool_latency",
                           "run_retrieval", "run_error_rate", "run_tool_failure"):
                getattr(mock_orch, method).return_value = _make_orch_result()
            run_all_groups(config, connect_fn, now=_QUERY_END)
            return mock_orch

    def test_trace_latency_dispatches_correct_method(self):
        orch = self._dispatch_call_args(_trace_group())
        orch.run_trace_latency.assert_called_once()
        orch.run_agent_latency.assert_not_called()

    def test_agent_latency_dispatches_correct_method(self):
        orch = self._dispatch_call_args(_agent_group())
        orch.run_agent_latency.assert_called_once()
        orch.run_trace_latency.assert_not_called()

    def test_tool_latency_dispatches_correct_method(self):
        orch = self._dispatch_call_args(_tool_latency_group())
        orch.run_tool_latency.assert_called_once()

    def test_retrieval_dispatches_correct_method(self):
        orch = self._dispatch_call_args(_retrieval_group())
        orch.run_retrieval.assert_called_once()

    def test_error_rate_dispatches_correct_method(self):
        orch = self._dispatch_call_args(_error_rate_group())
        orch.run_error_rate.assert_called_once()

    def test_tool_failure_dispatches_correct_method(self):
        orch = self._dispatch_call_args(_tool_failure_group())
        orch.run_tool_failure.assert_called_once()

    def test_trace_latency_receives_operation_name(self):
        orch = self._dispatch_call_args(_trace_group(operation_name="chat"))
        args, kwargs = orch.run_trace_latency.call_args
        # positional: service_name, operation_name, history_start, window_end
        assert args[1] == "chat"

    def test_tool_latency_does_not_receive_operation_name(self):
        orch = self._dispatch_call_args(_tool_latency_group())
        args, kwargs = orch.run_tool_latency.call_args
        # positional: service_name, history_start, window_end  (no operation_name)
        assert len(args) == 3

    def test_retrieval_does_not_receive_operation_name(self):
        orch = self._dispatch_call_args(_retrieval_group())
        args, kwargs = orch.run_retrieval.call_args
        assert len(args) == 3

    def test_tool_failure_does_not_receive_operation_name(self):
        orch = self._dispatch_call_args(_tool_failure_group())
        args, kwargs = orch.run_tool_failure.call_args
        assert len(args) == 3

    def test_history_start_used_as_window_start_not_candidate_after(self):
        # First run: candidate_after = query_end - 24h; history_start = candidate_after - 30d
        orch = self._dispatch_call_args(_trace_group(), history_days=30)
        args, kwargs = orch.run_trace_latency.call_args
        expected_ca = _QUERY_END - timedelta(hours=24)
        expected_hs = expected_ca - timedelta(days=30)
        # positional arg index 2 is window_start → must be history_start, not candidate_after
        assert args[2] == expected_hs
        assert args[2] != expected_ca
        assert kwargs["candidate_after"] == expected_ca

    def test_candidate_after_passed_as_keyword_arg(self):
        orch = self._dispatch_call_args(_trace_group())
        _, kwargs = orch.run_trace_latency.call_args
        assert "candidate_after" in kwargs

    def test_query_end_passed_as_window_end(self):
        orch = self._dispatch_call_args(_trace_group())
        args, _ = orch.run_trace_latency.call_args
        assert args[3] == _QUERY_END


# ---------------------------------------------------------------------------
# 4. Successful transaction
# ---------------------------------------------------------------------------

class TestSuccessfulTransaction:

    def _run_happy(self, group=None, prior_checkpoint=None):
        if group is None:
            group = _trace_group()
        config = _make_config(groups=[group])
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=prior_checkpoint) as mock_read, \
             patch("runner.write_checkpoint") as mock_write, \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 14
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            MockOrch.return_value.run_tool_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        return result, conn, mock_read, mock_write

    def test_read_checkpoint_called(self):
        _, _, mock_read, _ = self._run_happy()
        mock_read.assert_called_once()

    def test_write_checkpoint_called_with_query_end(self):
        _, _, _, mock_write = self._run_happy()
        _, kwargs = mock_write.call_args
        # last positional arg to write_checkpoint is checkpoint_at = query_end
        pos_args = mock_write.call_args[0]
        assert pos_args[-1] == _QUERY_END

    def test_commit_called(self):
        _, conn, _, _ = self._run_happy()
        conn.commit.assert_called_once()

    def test_rollback_not_called_on_success(self):
        _, conn, _, _ = self._run_happy()
        conn.rollback.assert_not_called()

    def test_result_status_ok(self):
        result, _, _, _ = self._run_happy()
        assert result.group_results[0].status == "ok"

    def test_checkpoint_advanced_true(self):
        result, _, _, _ = self._run_happy()
        assert result.group_results[0].checkpoint_advanced is True

    def test_new_checkpoint_equals_query_end(self):
        result, _, _, _ = self._run_happy()
        assert result.group_results[0].new_checkpoint == _QUERY_END

    def test_error_field_is_none(self):
        result, _, _, _ = self._run_happy()
        assert result.group_results[0].error is None


# ---------------------------------------------------------------------------
# 5. Empty successful window
# ---------------------------------------------------------------------------

class TestEmptySuccessfulWindow:

    def test_empty_window_checkpoint_still_written(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint") as mock_write, \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result(
                processed=0, detected=0, inserted=0, duplicate=0
            )
            run_all_groups(config, connect_fn, now=_QUERY_END)
        mock_write.assert_called_once()

    def test_empty_window_commit_called(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result(
                processed=0, detected=0, inserted=0, duplicate=0
            )
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        conn.commit.assert_called_once()
        assert result.group_results[0].status == "ok"
        assert result.group_results[0].checkpoint_advanced is True

    def test_empty_window_counts_are_zero(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result(
                processed=0, detected=0, inserted=0, duplicate=0
            )
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        gr = result.group_results[0]
        assert gr.candidate_count == 0
        assert gr.anomaly_events_emitted == 0


# ---------------------------------------------------------------------------
# 6. Pre-commit failure
# ---------------------------------------------------------------------------

class TestPreCommitFailure:

    def test_rollback_called_on_pre_commit_failure(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", side_effect=Exception("DB error")), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator"):
            run_all_groups(config, connect_fn, now=_QUERY_END)
        conn.rollback.assert_called_once()

    def test_status_error_on_pre_commit_failure(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", side_effect=Exception("oops")), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator"):
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert result.group_results[0].status == "error"

    def test_new_checkpoint_none_on_failure(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", side_effect=Exception("oops")), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator"):
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert result.group_results[0].new_checkpoint is None
        assert result.group_results[0].checkpoint_advanced is False

    def test_next_group_proceeds_after_failure_with_successful_rollback(self):
        groups = [_trace_group(operation_name="op1"), _trace_group(operation_name="op2")]
        config = _make_config(groups=groups)
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        call_count = {"n": 0}

        def read_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise Exception("first group fails")
            return None

        with patch("runner.read_checkpoint", side_effect=read_side_effect), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)

        assert result.groups_attempted == 2
        assert result.group_results[0].status == "error"
        assert result.group_results[1].status == "ok"
        assert result.completed_all_groups is True

    def test_error_message_captured(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", side_effect=Exception("something broke")), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator"):
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert "something broke" in result.group_results[0].error


# ---------------------------------------------------------------------------
# 7. Checkpoint write failure (orchestration counts preserved)
# ---------------------------------------------------------------------------

class TestCheckpointWriteFailure:

    def _run_write_failure(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        orch_result = _make_orch_result(processed=5, detected=3, inserted=2, duplicate=1)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint", side_effect=Exception("write failed")), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = orch_result
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        return result, conn

    def test_orchestration_counts_preserved_on_write_failure(self):
        result, _ = self._run_write_failure()
        gr = result.group_results[0]
        assert gr.candidate_count == 5
        assert gr.anomaly_events_emitted == 3
        assert gr.anomaly_events_inserted == 2
        assert gr.anomaly_events_duplicate == 1

    def test_rollback_called_after_write_failure(self):
        _, conn = self._run_write_failure()
        conn.rollback.assert_called_once()

    def test_status_error_after_write_failure(self):
        result, _ = self._run_write_failure()
        assert result.group_results[0].status == "error"

    def test_checkpoint_not_advanced_after_write_failure(self):
        result, _ = self._run_write_failure()
        assert result.group_results[0].checkpoint_advanced is False
        assert result.group_results[0].new_checkpoint is None


# ---------------------------------------------------------------------------
# 8. Commit failure → status uncertain
# ---------------------------------------------------------------------------

class TestCommitFailure:

    def _run_commit_failure(self, rollback_raises=False):
        config = _make_config()
        conn = _make_mock_conn()
        conn.commit.side_effect = Exception("commit exploded")
        if rollback_raises:
            conn.rollback.side_effect = Exception("rollback dead")
        connect_fn = MagicMock(return_value=conn)

        new_conn = _make_mock_conn()
        if rollback_raises:
            connect_fn.side_effect = [conn, new_conn]

        orch_result = _make_orch_result(processed=3, detected=1, inserted=1, duplicate=0)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = orch_result
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        return result, conn

    def test_status_uncertain_on_commit_failure(self):
        result, _ = self._run_commit_failure()
        assert result.group_results[0].status == "uncertain"

    def test_checkpoint_not_advanced_on_commit_failure(self):
        result, _ = self._run_commit_failure()
        assert result.group_results[0].checkpoint_advanced is False
        assert result.group_results[0].new_checkpoint is None

    def test_rollback_attempted_after_commit_failure(self):
        _, conn = self._run_commit_failure()
        conn.rollback.assert_called_once()

    def test_orchestration_counts_preserved_on_commit_failure(self):
        result, _ = self._run_commit_failure()
        gr = result.group_results[0]
        assert gr.candidate_count == 3
        assert gr.anomaly_events_emitted == 1
        assert gr.anomaly_events_inserted == 1


# ---------------------------------------------------------------------------
# 9. Commit failure + successful rollback → same connection reused
# ---------------------------------------------------------------------------

class TestCommitFailureRollbackSucceeds:

    def test_same_connection_reused_after_commit_failure_and_successful_rollback(self):
        groups = [_trace_group(operation_name="op1"), _trace_group(operation_name="op2")]
        config = _make_config(groups=groups)
        conn = _make_mock_conn()
        # First commit fails, second succeeds
        conn.commit.side_effect = [Exception("commit 1 failed"), None]
        connect_fn = MagicMock(return_value=conn)

        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)

        # connect_fn called only once (initial); connection not replaced
        connect_fn.assert_called_once()
        assert result.group_results[0].status == "uncertain"
        assert result.group_results[1].status == "ok"


# ---------------------------------------------------------------------------
# 10. Commit failure + rollback failure → connection replaced
# ---------------------------------------------------------------------------

class TestCommitFailureRollbackFails:

    def test_old_connection_closed_and_new_connection_obtained(self):
        groups = [_trace_group(operation_name="op1"), _trace_group(operation_name="op2")]
        config = _make_config(groups=groups)

        conn1 = _make_mock_conn()
        conn1.commit.side_effect = Exception("commit failed")
        conn1.rollback.side_effect = Exception("rollback dead")

        conn2 = _make_mock_conn()
        connect_fn = MagicMock(side_effect=[conn1, conn2])

        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository") as MockRepo, \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)

        # connect_fn called twice: initial + replacement
        assert connect_fn.call_count == 2
        # Dead connection close attempted
        conn1.close.assert_called()
        # Second group should be ok (uses conn2)
        assert result.group_results[1].status == "ok"

    def test_new_repo_and_orch_constructed_with_replacement_connection(self):
        groups = [_trace_group(operation_name="op1"), _trace_group(operation_name="op2")]
        config = _make_config(groups=groups)

        conn1 = _make_mock_conn()
        conn1.commit.side_effect = Exception("commit failed")
        conn1.rollback.side_effect = Exception("dead")

        conn2 = _make_mock_conn()
        connect_fn = MagicMock(side_effect=[conn1, conn2])

        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository") as MockRepo, \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            run_all_groups(config, connect_fn, now=_QUERY_END)

        # AnomalyRepository constructed twice — once with conn1, once with conn2
        assert MockRepo.call_count == 2
        assert MockRepo.call_args_list[0] == call(conn1)
        assert MockRepo.call_args_list[1] == call(conn2)

        # AnomalyOrchestrator constructed twice
        assert MockOrch.call_count == 2


# ---------------------------------------------------------------------------
# 11. Pre-commit failure + rollback failure → same replacement behavior
# ---------------------------------------------------------------------------

class TestPreCommitFailureRollbackFails:

    def test_replacement_on_precommit_rollback_failure(self):
        groups = [_trace_group(operation_name="a"), _trace_group(operation_name="b")]
        config = _make_config(groups=groups)

        conn1 = _make_mock_conn()
        conn1.rollback.side_effect = Exception("dead")

        conn2 = _make_mock_conn()
        connect_fn = MagicMock(side_effect=[conn1, conn2])

        call_count = {"n": 0}

        def read_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise Exception("read failed")
            return None

        with patch("runner.read_checkpoint", side_effect=read_side_effect), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)

        assert connect_fn.call_count == 2
        conn1.close.assert_called()
        assert result.group_results[0].status == "error"
        assert result.group_results[1].status == "ok"

    def test_precommit_rollback_failure_status_is_error_not_uncertain(self):
        config = _make_config()
        conn = _make_mock_conn()
        conn.rollback.side_effect = Exception("dead")
        conn2 = _make_mock_conn()
        connect_fn = MagicMock(side_effect=[conn, conn2])

        with patch("runner.read_checkpoint", side_effect=Exception("read broken")), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator"):
            result = run_all_groups(config, connect_fn, now=_QUERY_END)

        # commit was never attempted → status must be "error" not "uncertain"
        assert result.group_results[0].status == "error"


# ---------------------------------------------------------------------------
# 12. Initial connect_fn failure
# ---------------------------------------------------------------------------

class TestInitialConnectFailure:

    def test_initial_connect_failure_raises(self):
        config = _make_config()
        connect_fn = MagicMock(side_effect=Exception("cannot connect"))
        with pytest.raises(Exception, match="cannot connect"):
            run_all_groups(config, connect_fn, now=_QUERY_END)

    def test_initial_connect_failure_produces_no_group_results(self):
        config = _make_config()
        connect_fn = MagicMock(side_effect=Exception("no DB"))
        with pytest.raises(Exception):
            run_all_groups(config, connect_fn, now=_QUERY_END)
        # No RunResult is returned; exception propagated before group loop


# ---------------------------------------------------------------------------
# 13. Replacement connect_fn failure
# ---------------------------------------------------------------------------

class TestReplacementConnectFailure:

    def _run_replacement_fails(self, n_groups=3):
        # First group: commit fails → rollback fails → reconnect fails
        # Groups 2+ should never be attempted
        groups = [_trace_group(operation_name=f"op{i}") for i in range(n_groups)]
        config = _make_config(groups=groups)

        conn1 = _make_mock_conn()
        conn1.commit.side_effect = Exception("commit fails")
        conn1.rollback.side_effect = Exception("dead")

        connect_fn = MagicMock(side_effect=[conn1, Exception("no replacement")])

        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        return result

    def test_completed_all_groups_false(self):
        result = self._run_replacement_fails()
        assert result.completed_all_groups is False

    def test_terminal_error_populated(self):
        result = self._run_replacement_fails()
        assert result.terminal_error is not None
        assert len(result.terminal_error) > 0

    def test_no_fake_results_for_unattempted_groups(self):
        result = self._run_replacement_fails(n_groups=3)
        # Only the first group was attempted; the other two were never started
        assert result.groups_attempted == 1
        assert len(result.group_results) == 1

    def test_attempted_group_result_is_uncertain(self):
        result = self._run_replacement_fails()
        assert result.group_results[0].status == "uncertain"


# ---------------------------------------------------------------------------
# 14. Connection ownership
# ---------------------------------------------------------------------------

class TestConnectionOwnership:

    def test_initial_connection_closed_at_end(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            run_all_groups(config, connect_fn, now=_QUERY_END)
        conn.close.assert_called()

    def test_dead_connection_closed_before_replacement(self):
        config = _make_config()
        conn1 = _make_mock_conn()
        conn1.rollback.side_effect = Exception("dead")
        conn2 = _make_mock_conn()
        connect_fn = MagicMock(side_effect=[conn1, conn2])

        with patch("runner.read_checkpoint", side_effect=Exception("query failed")), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator"):
            run_all_groups(config, connect_fn, now=_QUERY_END)

        # Old dead connection should have been closed
        conn1.close.assert_called()

    def test_replacement_connection_closed_at_end(self):
        groups = [_trace_group(operation_name="a"), _trace_group(operation_name="b")]
        config = _make_config(groups=groups)

        conn1 = _make_mock_conn()
        conn1.rollback.side_effect = Exception("dead")
        conn2 = _make_mock_conn()
        connect_fn = MagicMock(side_effect=[conn1, conn2])

        with patch("runner.read_checkpoint", side_effect=[Exception("fail"), None]), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            run_all_groups(config, connect_fn, now=_QUERY_END)

        # Replacement connection must be closed at end
        conn2.close.assert_called()

    def test_connect_fn_called_exactly_once_in_normal_run(self):
        config = _make_config(groups=[_trace_group(), _tool_latency_group()])
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            MockOrch.return_value.run_tool_latency.return_value = _make_orch_result()
            run_all_groups(config, connect_fn, now=_QUERY_END)
        connect_fn.assert_called_once()


# ---------------------------------------------------------------------------
# 15. Result type contracts
# ---------------------------------------------------------------------------

class TestResultContracts:

    def _run_two_groups_one_fail(self):
        groups = [_trace_group(operation_name="a"), _trace_group(operation_name="b")]
        config = _make_config(groups=groups)
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        call_n = {"n": 0}

        def read_side(*args, **kwargs):
            call_n["n"] += 1
            if call_n["n"] == 1:
                raise Exception("first fails")
            return None

        with patch("runner.read_checkpoint", side_effect=read_side), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result(
                processed=4, detected=2, inserted=1, duplicate=1
            )
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        return result

    def test_run_result_is_frozen(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        with pytest.raises((AttributeError, TypeError)):
            result.groups_ok = 99  # type: ignore[misc]

    def test_run_group_result_is_frozen(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        with pytest.raises((AttributeError, TypeError)):
            result.group_results[0].status = "error"  # type: ignore[misc]

    def test_group_results_is_tuple(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert isinstance(result.group_results, tuple)

    def test_config_order_preserved_in_group_results(self):
        groups = [
            _trace_group(operation_name="first"),
            _trace_group(operation_name="second"),
            _tool_latency_group(),
        ]
        config = _make_config(groups=groups)
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            MockOrch.return_value.run_tool_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert result.group_results[0].operation_name == "first"
        assert result.group_results[1].operation_name == "second"
        assert result.group_results[2].signal_path == "tool_latency"

    def test_status_count_invariant(self):
        result = self._run_two_groups_one_fail()
        total = result.groups_ok + result.groups_uncertain + result.groups_error
        assert total == result.groups_attempted

    def test_aggregate_totals_include_failed_group_counts(self):
        # Uncertain/error groups with non-zero orch counts should still be summed
        groups = [_trace_group(operation_name="a"), _trace_group(operation_name="b")]
        config = _make_config(groups=groups)
        conn = _make_mock_conn()
        conn.commit.side_effect = [Exception("uncertain"), None]
        connect_fn = MagicMock(return_value=conn)

        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result(
                processed=3, detected=1, inserted=1, duplicate=0
            )
            result = run_all_groups(config, connect_fn, now=_QUERY_END)

        # Both groups ran orchestration; counts from uncertain group included in totals
        assert result.total_candidates == 6  # 3 + 3
        assert result.total_anomalies_emitted == 2  # 1 + 1

    def test_completed_all_groups_true_on_normal_run(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert result.completed_all_groups is True
        assert result.terminal_error is None

    def test_run_start_before_run_end(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert result.run_start <= result.run_end

    def test_duration_ms_is_positive(self):
        config = _make_config()
        conn = _make_mock_conn()
        connect_fn = MagicMock(return_value=conn)
        with patch("runner.read_checkpoint", return_value=None), \
             patch("runner.write_checkpoint"), \
             patch("runner.AnomalyRepository"), \
             patch("runner.AnomalyOrchestrator") as MockOrch:
            MockOrch.return_value.history_days_for.return_value = 7
            MockOrch.return_value.run_trace_latency.return_value = _make_orch_result()
            result = run_all_groups(config, connect_fn, now=_QUERY_END)
        assert result.group_results[0].duration_ms >= 0.0


# ---------------------------------------------------------------------------
# 16. Unknown signal_path raises loudly
# ---------------------------------------------------------------------------

class TestUnknownDispatch:

    def test_unknown_signal_path_recorded_as_error(self):
        # RunConfig validation prevents unknown paths in practice, but _dispatch
        # must still fail loudly rather than silently fall through.
        from runner import _dispatch
        from unittest.mock import MagicMock as MM
        bad_group = GroupConfig(
            signal_path="not_a_real_signal",
            service_name="svc",
            operation_name="",
        )
        mock_orch = MM()
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="not_a_real_signal"):
            _dispatch(mock_orch, bad_group, ts, ts, ts)

"""
Tests for anomaly-detector/main.py

No live database required.  All external collaborators
(load_config, run_all_groups, db.connect) are mocked.

Run from repo root:
    PYTHONPATH=anomaly-detector python -m pytest \
        anomaly-detector/tests/unit/test_main.py -v

Coverage:
    TestExitCodes
        1   all groups ok                   → exit 0
        2   one group status=error          → exit 1
        3   one group status=uncertain      → exit 1
        4   mixed ok + error                → exit 1
        5   completed_all_groups=False      → exit 2
        6   completed_false beats error     → exit 2 (not 1)
        7   config file not found           → exit 3
        8   config file malformed JSON      → exit 3
        9   invalid RunConfig value         → exit 3
        10  psycopg.OperationalError        → exit 4
        11  RuntimeError (missing password) → exit 4
        12  KeyboardInterrupt               → exit 130

    TestConfigPathForwarding
        13  --config value forwarded verbatim to load_config()
        14  missing --config argument       → non-zero exit

    TestLogging
        15  successful run logs key group fields
        16  successful run logs key summary fields
        17  DB password env var value never appears in log output
        18  gr.error value logged at ERROR level
        19  terminal_error logged at ERROR level
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

import psycopg
import pytest

from run_config import GroupConfig, RunConfig
from runner import RunGroupResult, RunResult

import main


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_NOW = datetime(2024, 1, 8, 12, 0, 0, tzinfo=timezone.utc)
_HISTORY = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Test data builders
# ---------------------------------------------------------------------------

def _make_group_result(
    *,
    status: str = "ok",
    candidate_count: int = 1,
    anomaly_events_emitted: int = 1,
    anomaly_events_inserted: int = 1,
    anomaly_events_duplicate: int = 0,
    checkpoint_advanced: bool = True,
    error: str | None = None,
) -> RunGroupResult:
    return RunGroupResult(
        signal_path="trace_latency",
        service_name="agentops-demo-app",
        operation_name="agentops.request",
        history_start=_HISTORY,
        candidate_after=_NOW,
        query_end=_NOW,
        candidate_count=candidate_count,
        anomaly_events_emitted=anomaly_events_emitted,
        anomaly_events_inserted=anomaly_events_inserted,
        anomaly_events_duplicate=anomaly_events_duplicate,
        prior_checkpoint=None,
        new_checkpoint=_NOW if checkpoint_advanced else None,
        checkpoint_advanced=checkpoint_advanced,
        duration_ms=42.0,
        status=status,
        error=error,
    )


def _make_run_result(
    *,
    group_results: list[RunGroupResult] | None = None,
    completed_all_groups: bool = True,
    terminal_error: str | None = None,
) -> RunResult:
    if group_results is None:
        group_results = [_make_group_result()]
    n_ok = sum(1 for r in group_results if r.status == "ok")
    n_uncertain = sum(1 for r in group_results if r.status == "uncertain")
    n_error = sum(1 for r in group_results if r.status == "error")
    return RunResult(
        run_start=_NOW,
        run_end=_NOW,
        groups_attempted=len(group_results),
        groups_ok=n_ok,
        groups_uncertain=n_uncertain,
        groups_error=n_error,
        total_candidates=sum(r.candidate_count for r in group_results),
        total_anomalies_emitted=sum(r.anomaly_events_emitted for r in group_results),
        total_anomalies_inserted=sum(r.anomaly_events_inserted for r in group_results),
        total_anomalies_duplicate=sum(r.anomaly_events_duplicate for r in group_results),
        group_results=tuple(group_results),
        completed_all_groups=completed_all_groups,
        terminal_error=terminal_error,
    )


def _make_config() -> RunConfig:
    return RunConfig(
        overlap_minutes=10,
        initial_lookback_hours=24,
        groups=(GroupConfig(
            signal_path="trace_latency",
            service_name="agentops-demo-app",
            operation_name="agentops.request",
        ),),
    )


def _run_mocked(
    argv: list[str],
    *,
    mock_config: RunConfig | None = None,
    mock_result: RunResult | None = None,
) -> int:
    """Invoke main.main(argv) with load_config and run_all_groups mocked.

    Returns the SystemExit code.
    """
    if mock_config is None:
        mock_config = _make_config()
    if mock_result is None:
        mock_result = _make_run_result()
    with patch("main.load_config", return_value=mock_config), \
         patch("main.run_all_groups", return_value=mock_result):
        with pytest.raises(SystemExit) as exc_info:
            main.main(argv)
    return exc_info.value.code


# ---------------------------------------------------------------------------
# 1-12: Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_all_groups_ok_exits_0(self):
        result = _make_run_result(group_results=[_make_group_result(status="ok")])
        assert _run_mocked(["--config", "cfg.json"], mock_result=result) == 0

    def test_group_error_exits_1(self):
        result = _make_run_result(group_results=[
            _make_group_result(status="error", checkpoint_advanced=False, error="boom")
        ])
        assert _run_mocked(["--config", "cfg.json"], mock_result=result) == 1

    def test_group_uncertain_exits_1(self):
        result = _make_run_result(group_results=[
            _make_group_result(status="uncertain", checkpoint_advanced=False, error="commit raised")
        ])
        assert _run_mocked(["--config", "cfg.json"], mock_result=result) == 1

    def test_mixed_ok_and_error_exits_1(self):
        result = _make_run_result(group_results=[
            _make_group_result(status="ok"),
            _make_group_result(status="error", checkpoint_advanced=False, error="psycopg"),
        ])
        assert _run_mocked(["--config", "cfg.json"], mock_result=result) == 1

    def test_completed_all_groups_false_exits_2(self):
        result = _make_run_result(
            completed_all_groups=False,
            terminal_error="replacement connection failed",
        )
        assert _run_mocked(["--config", "cfg.json"], mock_result=result) == 2

    def test_completed_false_takes_priority_over_group_error(self):
        result = _make_run_result(
            group_results=[
                _make_group_result(status="error", checkpoint_advanced=False, error="x")
            ],
            completed_all_groups=False,
            terminal_error="reconnect failed",
        )
        assert _run_mocked(["--config", "cfg.json"], mock_result=result) == 2

    def test_missing_config_file_exits_3(self):
        with pytest.raises(SystemExit) as exc_info:
            main.main(["--config", "/nonexistent/__no_such_file__.json"])
        assert exc_info.value.code == 3

    def test_malformed_json_exits_3(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{not valid json")
            path = f.name
        try:
            with pytest.raises(SystemExit) as exc_info:
                main.main(["--config", path])
            assert exc_info.value.code == 3
        finally:
            os.unlink(path)

    def test_invalid_runconfig_value_exits_3(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"run": {"overlap_minutes": -1, "initial_lookback_hours": 1},
                 "groups": []},
                f,
            )
            path = f.name
        try:
            with pytest.raises(SystemExit) as exc_info:
                main.main(["--config", path])
            assert exc_info.value.code == 3
        finally:
            os.unlink(path)

    def test_psycopg_operational_error_exits_4(self):
        with patch("main.load_config", return_value=_make_config()), \
             patch("main.run_all_groups",
                   side_effect=psycopg.OperationalError("connection refused")):
            with pytest.raises(SystemExit) as exc_info:
                main.main(["--config", "cfg.json"])
        assert exc_info.value.code == 4

    def test_runtime_error_missing_password_exits_4(self):
        with patch("main.load_config", return_value=_make_config()), \
             patch("main.run_all_groups",
                   side_effect=RuntimeError("ANOMALY_DETECTOR_DB_PASSWORD not set")):
            with pytest.raises(SystemExit) as exc_info:
                main.main(["--config", "cfg.json"])
        assert exc_info.value.code == 4

    def test_keyboard_interrupt_exits_130(self):
        with patch("main.load_config", return_value=_make_config()), \
             patch("main.run_all_groups", side_effect=KeyboardInterrupt):
            with pytest.raises(SystemExit) as exc_info:
                main.main(["--config", "cfg.json"])
        assert exc_info.value.code == 130

    def test_startup_db_error_raw_message_not_logged(self, caplog):
        raw_msg = "FATAL: password authentication failed for user 'anomaly_detector'"
        with caplog.at_level(logging.ERROR):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups",
                       side_effect=psycopg.OperationalError(raw_msg)):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert raw_msg not in caplog.text

    def test_startup_db_error_logs_exception_type(self, caplog):
        with caplog.at_level(logging.ERROR):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups",
                       side_effect=RuntimeError("ANOMALY_DETECTOR_DB_PASSWORD not set")):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert "RuntimeError" in caplog.text

    def test_startup_db_error_logs_env_var_guidance(self, caplog):
        with caplog.at_level(logging.ERROR):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups",
                       side_effect=psycopg.OperationalError("conn refused")):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert "ANOMALY_DETECTOR_DB_" in caplog.text


# ---------------------------------------------------------------------------
# 13-14: Config path forwarding
# ---------------------------------------------------------------------------

class TestConfigPathForwarding:

    def test_config_path_forwarded_verbatim_to_load_config(self):
        with patch("main.load_config", return_value=_make_config()) as mock_load, \
             patch("main.run_all_groups", return_value=_make_run_result()):
            with pytest.raises(SystemExit):
                main.main(["--config", "/specific/path/runner_config.json"])
        mock_load.assert_called_once_with("/specific/path/runner_config.json")

    def test_missing_config_argument_is_nonzero(self):
        with pytest.raises(SystemExit) as exc_info:
            main.main([])
        assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# 15-19: Logging content
# ---------------------------------------------------------------------------

class TestLogging:

    def test_successful_run_logs_key_group_fields(self, caplog):
        result = _make_run_result()
        with caplog.at_level(logging.INFO):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups", return_value=result):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert "trace_latency" in caplog.text
        assert "agentops-demo-app" in caplog.text
        assert "agentops.request" in caplog.text
        assert "status" in caplog.text
        assert "candidates" in caplog.text
        assert "checkpoint_advanced" in caplog.text

    def test_successful_run_logs_summary_fields(self, caplog):
        result = _make_run_result()
        with caplog.at_level(logging.INFO):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups", return_value=result):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert "groups_ok" in caplog.text
        assert "groups_error" in caplog.text
        assert "total_candidates" in caplog.text
        assert "completed_all_groups" in caplog.text

    def test_db_password_value_not_logged(self, caplog):
        fake_password = "s3cr3t_p4ssword_xyz_unique"
        with caplog.at_level(logging.DEBUG):
            with patch.dict(os.environ, {"ANOMALY_DETECTOR_DB_PASSWORD": fake_password}):
                with patch("main.load_config", return_value=_make_config()), \
                     patch("main.run_all_groups", return_value=_make_run_result()):
                    with pytest.raises(SystemExit):
                        main.main(["--config", "cfg.json"])
        assert fake_password not in caplog.text

    def test_group_error_field_logged_at_error_level(self, caplog):
        error_msg = "unique_error_text_xyz_abc"
        result = _make_run_result(group_results=[
            _make_group_result(status="error", checkpoint_advanced=False, error=error_msg)
        ])
        with caplog.at_level(logging.ERROR):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups", return_value=result):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert error_msg in caplog.text

    def test_terminal_error_logged_at_error_level(self, caplog):
        terminal_msg = "terminal_connection_failure_xyz"
        result = _make_run_result(
            completed_all_groups=False,
            terminal_error=terminal_msg,
        )
        with caplog.at_level(logging.ERROR):
            with patch("main.load_config", return_value=_make_config()), \
                 patch("main.run_all_groups", return_value=result):
                with pytest.raises(SystemExit):
                    main.main(["--config", "cfg.json"])
        assert terminal_msg in caplog.text

"""
tests/unit/test_rca_main.py

Unit tests for main.py — Phase 11.6 CLI entry point.

Coverage:
    _parse_args         — --anomaly-id required, accepted, missing error
    main() exit codes   — 0/1/2/3/4, KeyboardInterrupt propagates
    connection lifecycle — conn.close() called after successful connect()
    logging             — format configured, INFO line on success
    error isolation     — unexpected ValueError propagates (not wrapped as exit 2)
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import psycopg

from main import main, _parse_args
from rca_orchestrator import AnomalyNotFoundError, SourceDataIntegrityError
from rca_persist import PersistenceResult


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def _make_pr(
    investigation_id: str = "a" * 64,
    investigation_inserted: bool = True,
    evidence_rows_inserted: int = 2,
) -> PersistenceResult:
    return PersistenceResult(
        investigation_id=investigation_id,
        investigation_inserted=investigation_inserted,
        evidence_rows_inserted=evidence_rows_inserted,
    )


def _mock_result(confidence: str = "HIGH"):
    r = MagicMock()
    r.confidence = confidence
    return r


# ---------------------------------------------------------------------------
# TestArgParsing
# ---------------------------------------------------------------------------

class TestArgParsing:
    def test_anomaly_id_required(self):
        with pytest.raises(SystemExit):
            _parse_args([])

    def test_anomaly_id_accepted(self):
        args = _parse_args(["--anomaly-id", "some-uuid"])
        assert args.anomaly_id == "some-uuid"

    def test_missing_flag_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc_info:
            _parse_args([])
        assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# TestExitCodes
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_success_returns_0(self):
        mock_conn = MagicMock()
        result = _mock_result("HIGH")
        pr = _make_pr()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation", return_value=(result, pr)):
            code = main(["--anomaly-id", "anom-1"])
        assert code == 0

    def test_anomaly_not_found_returns_1(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation",
                   side_effect=AnomalyNotFoundError("missing-id")):
            code = main(["--anomaly-id", "missing-id"])
        assert code == 1

    def test_source_data_integrity_returns_2(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation",
                   side_effect=SourceDataIntegrityError("bad type")):
            code = main(["--anomaly-id", "anom-1"])
        assert code == 2

    def test_runtime_error_from_connect_returns_3(self):
        with patch("main.connect",
                   side_effect=RuntimeError("RCA_ANALYZER_DB_PASSWORD not set")):
            code = main(["--anomaly-id", "anom-1"])
        assert code == 3

    def test_operational_error_from_connect_returns_4(self):
        with patch("main.connect",
                   side_effect=psycopg.OperationalError("connection refused")):
            code = main(["--anomaly-id", "anom-1"])
        assert code == 4

    def test_operational_error_from_investigation_returns_4(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation",
                   side_effect=psycopg.OperationalError("query failed")):
            code = main(["--anomaly-id", "anom-1"])
        assert code == 4

    def test_keyboard_interrupt_propagates_through_main(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation", side_effect=KeyboardInterrupt()):
            with pytest.raises(KeyboardInterrupt):
                main(["--anomaly-id", "anom-1"])

    def test_unexpected_value_error_not_converted_to_exit_2(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation",
                   side_effect=ValueError("programming error")):
            with pytest.raises(ValueError, match="programming error"):
                main(["--anomaly-id", "anom-1"])


# ---------------------------------------------------------------------------
# TestConnectionLifecycle
# ---------------------------------------------------------------------------

class TestConnectionLifecycle:
    def test_conn_close_called_on_success(self):
        mock_conn = MagicMock()
        result = _mock_result("HIGH")
        pr = _make_pr()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation", return_value=(result, pr)):
            main(["--anomaly-id", "anom-1"])
        mock_conn.close.assert_called_once()

    def test_conn_close_called_on_anomaly_not_found(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation",
                   side_effect=AnomalyNotFoundError("x")):
            main(["--anomaly-id", "anom-1"])
        mock_conn.close.assert_called_once()

    def test_conn_close_called_on_keyboard_interrupt(self):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation", side_effect=KeyboardInterrupt()):
            with pytest.raises(KeyboardInterrupt):
                main(["--anomaly-id", "anom-1"])
        mock_conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestLogging
# ---------------------------------------------------------------------------

class TestLogging:
    def test_info_logged_on_success(self, caplog):
        mock_conn = MagicMock()
        result = _mock_result("HIGH")
        pr = _make_pr(investigation_id="b" * 64, investigation_inserted=True,
                      evidence_rows_inserted=3)
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation", return_value=(result, pr)), \
             caplog.at_level(logging.INFO, logger="main"):
            main(["--anomaly-id", "anom-1"])
        assert any("investigation_id" in r.message for r in caplog.records)

    def test_error_logged_on_not_found(self, caplog):
        mock_conn = MagicMock()
        with patch("main.connect", return_value=mock_conn), \
             patch("main.run_investigation",
                   side_effect=AnomalyNotFoundError("bad-id")), \
             caplog.at_level(logging.ERROR, logger="main"):
            main(["--anomaly-id", "bad-id"])
        assert any("bad-id" in r.message for r in caplog.records)

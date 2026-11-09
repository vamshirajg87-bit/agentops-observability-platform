"""
Tests for anomaly-detector/watermark.py

No live PostgreSQL required.  All DB access is mocked with MagicMock.

Coverage:
    TestReadCheckpoint:
        - returns None when no row exists
        - returns checkpoint_at when row exists
        - returned value is taken from fetchone() row[0]
        - timezone-aware datetime is preserved as-is
        - operation_name=None normalises to ''
        - explicit operation_name is preserved unchanged
        - read SQL is parameterised (%(name)s style; no string interpolation)
        - read SQL targets the correct table and WHERE columns

    TestWriteCheckpoint:
        - write SQL is parameterised (%(name)s style; no string interpolation)
        - INSERT targets public.anomaly_detector_runs
        - ON CONFLICT targets the exact composite key
        - DO UPDATE SET clause is present
        - forward-only WHERE condition is present
        - updated_at is refreshed in DO UPDATE SET
        - operation_name=None normalises to ''
        - explicit operation_name is preserved unchanged
        - checkpoint_at is passed as a parameter (not interpolated)

    TestConnectionOwnership:
        - read never calls conn.commit()
        - read never calls conn.rollback()
        - read never closes the connection
        - write never calls conn.commit()
        - write never calls conn.rollback()
        - write never closes the connection

    TestNoRewindBehavior:
        - no DELETE or TRUNCATE statement in write SQL
        - no rewind function is exported from the module
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import psycopg
import pytest

import watermark
from watermark import _READ_SQL, _WRITE_SQL, read_checkpoint, write_checkpoint

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC = timezone.utc
_TS = datetime(2024, 9, 1, 14, 55, 0, tzinfo=_UTC)
_SVC = "research-service"
_OP = "agent.run"
_PATH = "trace_latency"


def _make_conn_no_row() -> MagicMock:
    """Connection whose cursor returns no row from fetchone()."""
    mock_conn = MagicMock(spec=psycopg.Connection)
    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = None
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    return mock_conn


def _make_conn_with_row(checkpoint: datetime) -> MagicMock:
    """Connection whose cursor returns one row from fetchone()."""
    mock_conn = MagicMock(spec=psycopg.Connection)
    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = (checkpoint,)
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    return mock_conn


def _make_write_conn() -> tuple[MagicMock, MagicMock]:
    """Connection and cursor MagicMocks for write_checkpoint calls."""
    mock_conn = MagicMock(spec=psycopg.Connection)
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    return mock_conn, mock_cur


# ---------------------------------------------------------------------------
# TestReadCheckpoint
# ---------------------------------------------------------------------------

class TestReadCheckpoint:

    def test_returns_none_when_no_row(self):
        conn = _make_conn_no_row()
        result = read_checkpoint(conn, _PATH, _SVC, _OP)
        assert result is None

    def test_returns_checkpoint_when_row_exists(self):
        conn = _make_conn_with_row(_TS)
        result = read_checkpoint(conn, _PATH, _SVC, _OP)
        assert result == _TS

    def test_returned_value_is_row_zero(self):
        """read_checkpoint returns row[0], not the whole row tuple."""
        sentinel = datetime(2024, 1, 1, tzinfo=_UTC)
        conn = _make_conn_with_row(sentinel)
        assert read_checkpoint(conn, _PATH, _SVC, _OP) is sentinel

    def test_timezone_aware_datetime_preserved(self):
        """A timezone-aware datetime is returned without modification."""
        aware_ts = datetime(2024, 6, 15, 9, 30, 0, tzinfo=_UTC)
        conn = _make_conn_with_row(aware_ts)
        result = read_checkpoint(conn, _PATH, _SVC, _OP)
        assert result is not None
        assert result.tzinfo is not None

    def test_operation_name_none_normalised_to_empty_string(self):
        """None operation_name must be normalised to '' before the DB call."""
        conn = _make_conn_no_row()
        read_checkpoint(conn, _PATH, _SVC, operation_name=None)
        # Extract the params passed to cursor.execute()
        mock_cur = conn.cursor.return_value.__enter__.return_value
        _, params = mock_cur.execute.call_args
        passed_params = params if params else mock_cur.execute.call_args[0][1]
        assert passed_params["operation_name"] == ""

    def test_explicit_operation_name_preserved(self):
        conn = _make_conn_no_row()
        read_checkpoint(conn, _PATH, _SVC, operation_name="research/plan")
        mock_cur = conn.cursor.return_value.__enter__.return_value
        _, params = mock_cur.execute.call_args
        passed_params = params if params else mock_cur.execute.call_args[0][1]
        assert passed_params["operation_name"] == "research/plan"

    def test_read_sql_uses_named_parameter_binding(self):
        """_READ_SQL must use %(name)s style — no f-strings or % interpolation."""
        assert "%(signal_path)s" in _READ_SQL
        assert "%(service_name)s" in _READ_SQL
        assert "%(operation_name)s" in _READ_SQL
        # Ensure no unsafe string interpolation patterns
        assert "{" not in _READ_SQL
        assert "'" + "%" not in _READ_SQL  # no '% style

    def test_read_sql_targets_correct_table(self):
        assert "public.anomaly_detector_runs" in _READ_SQL

    def test_read_sql_where_covers_all_three_key_columns(self):
        assert "signal_path" in _READ_SQL
        assert "service_name" in _READ_SQL
        assert "operation_name" in _READ_SQL

    def test_all_three_params_passed_to_execute(self):
        conn = _make_conn_no_row()
        read_checkpoint(conn, _PATH, _SVC, _OP)
        mock_cur = conn.cursor.return_value.__enter__.return_value
        assert mock_cur.execute.call_count == 1
        args = mock_cur.execute.call_args[0]
        params = args[1]
        assert set(params.keys()) >= {"signal_path", "service_name", "operation_name"}
        assert params["signal_path"] == _PATH
        assert params["service_name"] == _SVC
        assert params["operation_name"] == _OP


# ---------------------------------------------------------------------------
# TestWriteCheckpoint
# ---------------------------------------------------------------------------

class TestWriteCheckpoint:

    def test_write_sql_uses_named_parameter_binding(self):
        assert "%(signal_path)s" in _WRITE_SQL
        assert "%(service_name)s" in _WRITE_SQL
        assert "%(operation_name)s" in _WRITE_SQL
        assert "%(checkpoint_at)s" in _WRITE_SQL
        assert "{" not in _WRITE_SQL

    def test_write_sql_targets_correct_table(self):
        assert "public.anomaly_detector_runs" in _WRITE_SQL

    def test_write_sql_contains_insert(self):
        assert "INSERT INTO" in _WRITE_SQL.upper()

    def test_write_sql_contains_on_conflict(self):
        assert "ON CONFLICT" in _WRITE_SQL.upper()

    def test_on_conflict_targets_composite_primary_key(self):
        """ON CONFLICT must name all three key columns."""
        upper = _WRITE_SQL.upper()
        assert "SIGNAL_PATH" in upper
        assert "SERVICE_NAME" in upper
        assert "OPERATION_NAME" in upper
        # The composite key appears inside the ON CONFLICT (...) clause
        conflict_clause = _WRITE_SQL[_WRITE_SQL.upper().index("ON CONFLICT"):]
        assert "signal_path" in conflict_clause
        assert "service_name" in conflict_clause
        assert "operation_name" in conflict_clause

    def test_write_sql_contains_do_update(self):
        assert "DO UPDATE" in _WRITE_SQL.upper()

    def test_write_sql_is_forward_only(self):
        """
        The DO UPDATE WHERE clause must be exactly:

            public.anomaly_detector_runs.checkpoint_at < EXCLUDED.checkpoint_at

        (whitespace-normalized).  The test fails if '<' is replaced with any
        other comparator (<=, >, >=, =) or if the WHERE predicate is removed.
        """
        import re
        # Collapse all runs of whitespace to a single space, strip leading/trailing.
        normalised = re.sub(r"\s+", " ", _WRITE_SQL).strip()
        expected_predicate = (
            "public.anomaly_detector_runs.checkpoint_at < EXCLUDED.checkpoint_at"
        )
        assert expected_predicate in normalised, (
            f"Forward-only predicate not found.\n"
            f"Expected: {expected_predicate!r}\n"
            f"Normalised SQL:\n{normalised}"
        )

    def test_write_sql_refreshes_updated_at(self):
        upper = _WRITE_SQL.upper()
        assert "UPDATED_AT" in upper
        assert "NOW()" in upper

    def test_operation_name_none_normalised_to_empty_string(self):
        conn, mock_cur = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, None, _TS)
        params = mock_cur.execute.call_args[0][1]
        assert params["operation_name"] == ""

    def test_explicit_operation_name_preserved(self):
        conn, mock_cur = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, "tool.execute", _TS)
        params = mock_cur.execute.call_args[0][1]
        assert params["operation_name"] == "tool.execute"

    def test_checkpoint_at_passed_as_parameter(self):
        """checkpoint_at must be bound as a parameter, never interpolated."""
        conn, mock_cur = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, _OP, _TS)
        params = mock_cur.execute.call_args[0][1]
        assert params["checkpoint_at"] is _TS

    def test_all_four_params_passed_to_execute(self):
        conn, mock_cur = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, _OP, _TS)
        assert mock_cur.execute.call_count == 1
        params = mock_cur.execute.call_args[0][1]
        assert params["signal_path"] == _PATH
        assert params["service_name"] == _SVC
        assert params["operation_name"] == _OP
        assert params["checkpoint_at"] is _TS


# ---------------------------------------------------------------------------
# TestCheckpointAtValidation
# ---------------------------------------------------------------------------

class TestCheckpointAtValidation:
    """
    write_checkpoint() must reject any checkpoint_at that is not an
    unambiguous absolute instant.

    Accepted:  tzinfo is set AND utcoffset() returns a timedelta.
    Rejected:  tzinfo is None  (naive datetime)
               tzinfo is set but utcoffset() returns None  (abstract/stub tzinfo)
    """

    def test_naive_datetime_raises_value_error(self):
        """A naive datetime (no tzinfo) must be rejected with ValueError."""
        conn, _ = _make_write_conn()
        naive = datetime(2024, 9, 1, 12, 0, 0)  # no tzinfo
        with pytest.raises(ValueError, match="timezone-aware"):
            write_checkpoint(conn, _PATH, _SVC, _OP, naive)

    def test_abstract_tzinfo_utcoffset_none_raises_value_error(self):
        """
        A datetime whose tzinfo.utcoffset() returns None must also be rejected.

        A minimal tzinfo subclass that returns None from utcoffset() represents
        an incomplete or abstract timezone — it cannot be mapped to an absolute
        instant and must not be stored as a checkpoint boundary.
        """
        from datetime import tzinfo as TzInfo, timedelta

        class _StubTz(TzInfo):
            def utcoffset(self, dt):
                return None  # deliberately returns None, not a timedelta
            def tzname(self, dt):
                return "STUB"
            def dst(self, dt):
                return None

        conn, _ = _make_write_conn()
        stub_aware = datetime(2024, 9, 1, 12, 0, 0, tzinfo=_StubTz())
        with pytest.raises(ValueError, match="utcoffset"):
            write_checkpoint(conn, _PATH, _SVC, _OP, stub_aware)

    def test_utc_aware_checkpoint_is_accepted(self):
        """UTC-aware datetime must not raise and must reach cursor.execute()."""
        conn, mock_cur = _make_write_conn()
        utc_ts = datetime(2024, 9, 1, 12, 0, 0, tzinfo=_UTC)
        write_checkpoint(conn, _PATH, _SVC, _OP, utc_ts)  # must not raise
        mock_cur.execute.assert_called_once()

    def test_non_utc_aware_checkpoint_is_accepted(self):
        """A non-UTC aware datetime (with a concrete utcoffset) must also be accepted."""
        from datetime import timedelta, timezone as tz
        plus5 = tz(timedelta(hours=5, minutes=30))  # IST
        conn, mock_cur = _make_write_conn()
        ist_ts = datetime(2024, 9, 1, 17, 30, 0, tzinfo=plus5)
        write_checkpoint(conn, _PATH, _SVC, _OP, ist_ts)  # must not raise
        mock_cur.execute.assert_called_once()

    def test_original_datetime_passed_unchanged_to_psycopg(self):
        """
        write_checkpoint must never mutate or replace checkpoint_at.
        The exact object supplied by the caller must be the one passed to execute().
        """
        conn, mock_cur = _make_write_conn()
        utc_ts = datetime(2024, 6, 15, 9, 0, 0, tzinfo=_UTC)
        write_checkpoint(conn, _PATH, _SVC, _OP, utc_ts)
        params = mock_cur.execute.call_args[0][1]
        assert params["checkpoint_at"] is utc_ts

    def test_naive_datetime_causes_zero_execute_calls(self):
        """Validation must happen BEFORE any DB interaction."""
        conn, mock_cur = _make_write_conn()
        naive = datetime(2024, 9, 1, 12, 0, 0)
        with pytest.raises(ValueError):
            write_checkpoint(conn, _PATH, _SVC, _OP, naive)
        mock_cur.execute.assert_not_called()

    def test_abstract_tzinfo_causes_zero_execute_calls(self):
        """Abstract tzinfo validation must also happen before any DB interaction."""
        from datetime import tzinfo as TzInfo

        class _StubTz(TzInfo):
            def utcoffset(self, dt):
                return None
            def tzname(self, dt):
                return "STUB"
            def dst(self, dt):
                return None

        conn, mock_cur = _make_write_conn()
        stub_aware = datetime(2024, 9, 1, 12, 0, 0, tzinfo=_StubTz())
        with pytest.raises(ValueError):
            write_checkpoint(conn, _PATH, _SVC, _OP, stub_aware)
        mock_cur.execute.assert_not_called()


# ---------------------------------------------------------------------------
# TestConnectionOwnership
# ---------------------------------------------------------------------------

class TestConnectionOwnership:

    def test_read_does_not_commit(self):
        conn = _make_conn_no_row()
        read_checkpoint(conn, _PATH, _SVC, _OP)
        conn.commit.assert_not_called()

    def test_read_does_not_rollback(self):
        conn = _make_conn_no_row()
        read_checkpoint(conn, _PATH, _SVC, _OP)
        conn.rollback.assert_not_called()

    def test_read_does_not_close(self):
        conn = _make_conn_no_row()
        read_checkpoint(conn, _PATH, _SVC, _OP)
        conn.close.assert_not_called()

    def test_write_does_not_commit(self):
        conn, _ = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, _OP, _TS)
        conn.commit.assert_not_called()

    def test_write_does_not_rollback(self):
        conn, _ = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, _OP, _TS)
        conn.rollback.assert_not_called()

    def test_write_does_not_close(self):
        conn, _ = _make_write_conn()
        write_checkpoint(conn, _PATH, _SVC, _OP, _TS)
        conn.close.assert_not_called()

    def test_no_psycopg_connect_in_module_source(self):
        """watermark.py must not open its own connections."""
        source = inspect.getsource(watermark)
        assert "psycopg.connect(" not in source


# ---------------------------------------------------------------------------
# TestNoRewindBehavior
# ---------------------------------------------------------------------------

class TestNoRewindBehavior:

    def test_write_sql_contains_no_delete(self):
        assert "DELETE" not in _WRITE_SQL.upper()

    def test_write_sql_contains_no_truncate(self):
        assert "TRUNCATE" not in _WRITE_SQL.upper()

    def test_no_rewind_function_exported(self):
        """The module must not export any rewind / reset / backdating function."""
        public_names = [n for n in dir(watermark) if not n.startswith("_")]
        for name in public_names:
            assert "rewind" not in name.lower()
            assert "reset" not in name.lower()
            assert "backdate" not in name.lower()

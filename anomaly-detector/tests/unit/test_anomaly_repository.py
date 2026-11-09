"""
Tests for anomaly-detector/anomaly_repository.py

No live PostgreSQL required.  DB access is mocked with MagicMock.

Coverage:
    IDENTITY (TestComputeAnomalyId):
        output is 64 lowercase hex characters
        deterministic — same event → same ID on repeated calls
        stable — same logical event in a new object → same ID
        UTC equivalence — different timezone offsets for the same instant → same ID
        naive datetime → ValueError
        None ≠ "" for trace_id, span_id, operation_name, service_name
        each identity field individually changes the ID when varied
        non-identity fields (result/baseline/score) do NOT change the ID

    DB MAPPING (TestAnomalyToDbParams):
        all 19 required INSERT fields present; detected_at absent
        anomaly_id matches compute_anomaly_id output
        observed_at field name maps to event_time key
        severity enum → literal string value; not "Severity.WARNING" etc.
        None values remain None; zero numeric values remain zero
        baseline_n integer preserved; datetime objects preserved
        naive observed_at → ValueError (propagated from compute_anomaly_id)
        no bool/float/int/str coercions in mapping source

    REPOSITORY (TestAnomalyRepository):
        INSERT targets public.anomaly_events
        INSERT uses %(name)s parameterized binding
        all 19 parameters supplied; detected_at omitted
        SQL includes ON CONFLICT (anomaly_id) DO NOTHING
        SQL contains no UPDATE, no DELETE, no SELECT
        rowcount == 1  → True  (inserted)
        rowcount == 0  → False (duplicate)
        caller connection is not closed by save()
        no hidden psycopg.connect() in source
        detected_at absent from INSERT column list
        table name is a static literal; ON CONFLICT targets anomaly_id

    RERUN SEMANTICS (TestRerunSemantics):
        changing result fields alone does not change anomaly_id
        rerun semantics are documented in module source
"""

from __future__ import annotations

import dataclasses
import inspect
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from anomaly_repository import (
    AnomalyRepository,
    _INSERT_SQL,
    anomaly_to_db_params,
    compute_anomaly_id,
)
from detector.anomaly_types import AnomalyEvent
from detector.severity import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
_TS_WINDOW_START = datetime(2024, 6, 8, 12, 0, 0, tzinfo=timezone.utc)
_TS_WINDOW_END = datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc)

_TRACE = "a" * 32
_SPAN = "b" * 16


def _make_event(**overrides) -> AnomalyEvent:
    """Construct a fully-populated AnomalyEvent with all fields set."""
    defaults: dict = dict(
        anomaly_type="latency",
        signal_name="duration_ms",
        detector_name="LatencyDetector",
        detector_version="1.0",
        trace_id=_TRACE,
        span_id=_SPAN,
        service_name="research-service",
        operation_name="agent.run",
        observed_value=450.0,
        observed_at=_TS,
        baseline_median=200.0,
        baseline_mad=20.0,
        baseline_n=50,
        baseline_window_start=_TS_WINDOW_START,
        baseline_window_end=_TS_WINDOW_END,
        anomaly_score=5.5,
        severity=Severity.WARNING,
        explanation="duration_ms=450.0; baseline_median=200.0 MAD=20.0 n=50; modified_z=5.50 direction=HIGH",
    )
    defaults.update(overrides)
    return AnomalyEvent(**defaults)


def _make_mock_conn(rowcount: int = 1):
    """Return (mock_conn, mock_cur) with cursor().rowcount preset."""
    mock_cur = MagicMock()
    mock_cur.rowcount = rowcount
    mock_cur.__enter__ = MagicMock(return_value=mock_cur)
    mock_cur.__exit__ = MagicMock(return_value=False)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    return mock_conn, mock_cur


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

class TestComputeAnomalyId:

    def test_output_is_64_hex_chars(self):
        anomaly_id = compute_anomaly_id(_make_event())
        assert len(anomaly_id) == 64

    def test_output_is_lowercase_hex(self):
        anomaly_id = compute_anomaly_id(_make_event())
        assert anomaly_id == anomaly_id.lower()
        assert all(c in "0123456789abcdef" for c in anomaly_id)

    def test_deterministic_same_event_same_id(self):
        event = _make_event()
        assert compute_anomaly_id(event) == compute_anomaly_id(event)

    def test_same_logical_event_new_object_same_id(self):
        event1 = _make_event()
        event2 = _make_event()
        assert event1 is not event2
        assert compute_anomaly_id(event1) == compute_anomaly_id(event2)

    def test_equivalent_utc_offsets_produce_same_id(self):
        ts_utc = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts_plus_five = datetime(2024, 6, 15, 17, 0, 0,
                                tzinfo=timezone(timedelta(hours=5)))
        event_utc = _make_event(observed_at=ts_utc)
        event_offset = _make_event(observed_at=ts_plus_five)
        assert compute_anomaly_id(event_utc) == compute_anomaly_id(event_offset)

    def test_naive_datetime_raises_value_error(self):
        event = _make_event(observed_at=datetime(2024, 6, 15, 12, 0, 0))
        with pytest.raises(ValueError, match="timezone-aware"):
            compute_anomaly_id(event)

    def test_utcoffset_none_raises_value_error(self):
        from datetime import tzinfo as _TzInfoBase

        class _NullOffsetTzInfo(_TzInfoBase):
            def utcoffset(self, dt): return None
            def tzname(self, dt): return "NullOffset"
            def dst(self, dt): return None

        event = _make_event(
            observed_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=_NullOffsetTzInfo())
        )
        with pytest.raises(ValueError):
            compute_anomaly_id(event)

    def test_utc_aware_datetime_produces_valid_id(self):
        event = _make_event(
            observed_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        )
        anomaly_id = compute_anomaly_id(event)
        assert len(anomaly_id) == 64
        assert all(c in "0123456789abcdef" for c in anomaly_id)

    def test_non_utc_offset_datetime_produces_valid_id(self):
        ts = datetime(2024, 6, 15, 17, 0, 0, tzinfo=timezone(timedelta(hours=5)))
        event = _make_event(observed_at=ts)
        anomaly_id = compute_anomaly_id(event)
        assert len(anomaly_id) == 64
        assert all(c in "0123456789abcdef" for c in anomaly_id)

    def test_observed_at_not_mutated_after_id_computation(self):
        ts = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = _make_event(observed_at=ts)
        compute_anomaly_id(event)
        assert event.observed_at is ts
        assert event.observed_at.tzinfo is timezone.utc

    # None vs "" distinctness

    def test_none_trace_id_differs_from_empty_string_trace_id(self):
        id_none = compute_anomaly_id(_make_event(trace_id=None))
        id_empty = compute_anomaly_id(_make_event(trace_id=""))
        assert id_none != id_empty

    def test_none_span_id_differs_from_empty_string_span_id(self):
        id_none = compute_anomaly_id(_make_event(span_id=None))
        id_empty = compute_anomaly_id(_make_event(span_id=""))
        assert id_none != id_empty

    def test_none_operation_name_differs_from_empty_string(self):
        id_none = compute_anomaly_id(_make_event(operation_name=None))
        id_empty = compute_anomaly_id(_make_event(operation_name=""))
        assert id_none != id_empty

    def test_none_service_name_differs_from_empty_string(self):
        id_none = compute_anomaly_id(_make_event(service_name=None))
        id_empty = compute_anomaly_id(_make_event(service_name=""))
        assert id_none != id_empty

    # Each identity field individually changes the ID

    def test_trace_id_change_changes_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(_make_event(trace_id="c" * 32))
        assert base != other

    def test_span_id_change_changes_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(_make_event(span_id="d" * 16))
        assert base != other

    def test_service_name_change_changes_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(_make_event(service_name="other-service"))
        assert base != other

    def test_operation_name_change_changes_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(_make_event(operation_name="other.op"))
        assert base != other

    def test_event_time_change_changes_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(
            _make_event(observed_at=datetime(2024, 7, 1, 0, 0, 0, tzinfo=timezone.utc))
        )
        assert base != other

    def test_anomaly_type_change_changes_id(self):
        base = compute_anomaly_id(_make_event(anomaly_type="latency"))
        other = compute_anomaly_id(_make_event(anomaly_type="error_rate"))
        assert base != other

    def test_signal_name_change_changes_id(self):
        base = compute_anomaly_id(_make_event(signal_name="duration_ms"))
        other = compute_anomaly_id(_make_event(signal_name="retrieval_top_relevance_score"))
        assert base != other

    def test_detector_name_change_changes_id(self):
        base = compute_anomaly_id(_make_event(detector_name="LatencyDetector"))
        other = compute_anomaly_id(_make_event(detector_name="OtherDetector"))
        assert base != other

    def test_detector_version_change_changes_id(self):
        base = compute_anomaly_id(_make_event(detector_version="1.0"))
        other = compute_anomaly_id(_make_event(detector_version="2.0"))
        assert base != other

    # Non-identity fields — changing them must NOT change anomaly_id

    def test_observed_value_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(observed_value=450.0))
        other = compute_anomaly_id(_make_event(observed_value=9999.0))
        assert base == other

    def test_baseline_median_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(baseline_median=200.0))
        other = compute_anomaly_id(_make_event(baseline_median=999.0))
        assert base == other

    def test_baseline_mad_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(baseline_mad=20.0))
        other = compute_anomaly_id(_make_event(baseline_mad=99.0))
        assert base == other

    def test_baseline_n_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(baseline_n=50))
        other = compute_anomaly_id(_make_event(baseline_n=200))
        assert base == other

    def test_baseline_window_start_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(
            _make_event(baseline_window_start=datetime(2024, 1, 1, tzinfo=timezone.utc))
        )
        assert base == other

    def test_baseline_window_end_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event())
        other = compute_anomaly_id(
            _make_event(baseline_window_end=datetime(2024, 1, 1, tzinfo=timezone.utc))
        )
        assert base == other

    def test_anomaly_score_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(anomaly_score=5.5))
        other = compute_anomaly_id(_make_event(anomaly_score=1.0))
        assert base == other

    def test_severity_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(severity=Severity.WARNING))
        other = compute_anomaly_id(_make_event(severity=Severity.CRITICAL))
        assert base == other

    def test_explanation_change_does_not_change_id(self):
        base = compute_anomaly_id(_make_event(explanation="original explanation"))
        other = compute_anomaly_id(_make_event(explanation="completely different text"))
        assert base == other


# ---------------------------------------------------------------------------
# DB parameter mapping
# ---------------------------------------------------------------------------

_INSERT_COLUMNS = {
    "anomaly_id", "anomaly_type", "signal_name", "detector_name", "detector_version",
    "trace_id", "span_id", "service_name", "operation_name", "observed_value",
    "event_time", "baseline_median", "baseline_mad", "baseline_n",
    "baseline_window_start", "baseline_window_end", "anomaly_score",
    "severity", "explanation",
}


class TestAnomalyToDbParams:

    def test_all_19_insert_fields_present(self):
        params = anomaly_to_db_params(_make_event())
        assert set(params.keys()) == _INSERT_COLUMNS

    def test_detected_at_not_in_params(self):
        params = anomaly_to_db_params(_make_event())
        assert "detected_at" not in params

    def test_anomaly_id_matches_compute_anomaly_id(self):
        event = _make_event()
        params = anomaly_to_db_params(event)
        assert params["anomaly_id"] == compute_anomaly_id(event)

    def test_observed_at_field_maps_to_event_time_key(self):
        event = _make_event(observed_at=_TS)
        params = anomaly_to_db_params(event)
        assert "event_time" in params
        assert params["event_time"] is _TS

    def test_observed_at_field_absent_from_params(self):
        params = anomaly_to_db_params(_make_event())
        assert "observed_at" not in params

    def test_severity_info_maps_to_string_info(self):
        params = anomaly_to_db_params(_make_event(severity=Severity.INFO))
        assert params["severity"] == "INFO"
        assert isinstance(params["severity"], str)

    def test_severity_warning_maps_to_string_warning(self):
        params = anomaly_to_db_params(_make_event(severity=Severity.WARNING))
        assert params["severity"] == "WARNING"
        assert isinstance(params["severity"], str)

    def test_severity_critical_maps_to_string_critical(self):
        params = anomaly_to_db_params(_make_event(severity=Severity.CRITICAL))
        assert params["severity"] == "CRITICAL"
        assert isinstance(params["severity"], str)

    def test_severity_is_not_enum_repr(self):
        params = anomaly_to_db_params(_make_event(severity=Severity.WARNING))
        assert "Severity" not in params["severity"]
        assert "." not in params["severity"]

    def test_none_values_remain_none(self):
        event = _make_event(
            trace_id=None,
            span_id=None,
            service_name=None,
            operation_name=None,
            baseline_median=None,
            baseline_mad=None,
            baseline_n=None,
            baseline_window_start=None,
            baseline_window_end=None,
            anomaly_score=None,
        )
        params = anomaly_to_db_params(event)
        assert params["trace_id"] is None
        assert params["span_id"] is None
        assert params["service_name"] is None
        assert params["operation_name"] is None
        assert params["baseline_median"] is None
        assert params["baseline_mad"] is None
        assert params["baseline_n"] is None
        assert params["baseline_window_start"] is None
        assert params["baseline_window_end"] is None
        assert params["anomaly_score"] is None

    def test_zero_numeric_values_preserved(self):
        event = _make_event(observed_value=0.0, anomaly_score=0.0, baseline_median=0.0)
        params = anomaly_to_db_params(event)
        assert params["observed_value"] == 0.0
        assert params["anomaly_score"] == 0.0
        assert params["baseline_median"] == 0.0

    def test_baseline_n_integer_preserved(self):
        event = _make_event(baseline_n=42)
        params = anomaly_to_db_params(event)
        assert params["baseline_n"] == 42
        assert isinstance(params["baseline_n"], int)

    def test_datetime_objects_preserved(self):
        event = _make_event(
            observed_at=_TS,
            baseline_window_start=_TS_WINDOW_START,
            baseline_window_end=_TS_WINDOW_END,
        )
        params = anomaly_to_db_params(event)
        assert params["event_time"] is _TS
        assert params["baseline_window_start"] is _TS_WINDOW_START
        assert params["baseline_window_end"] is _TS_WINDOW_END

    def test_naive_observed_at_raises_value_error(self):
        event = _make_event(observed_at=datetime(2024, 6, 15, 12, 0, 0))
        with pytest.raises(ValueError):
            anomaly_to_db_params(event)

    def test_no_coercions_in_mapping_source(self):
        import anomaly_repository
        source = inspect.getsource(anomaly_to_db_params)
        assert "bool(" not in source, "anomaly_to_db_params must not call bool()"
        assert "int(" not in source, "anomaly_to_db_params must not call int()"
        assert "str(" not in source, "anomaly_to_db_params must not call str()"
        # float() is also prohibited as a coercion
        assert "float(" not in source, "anomaly_to_db_params must not call float()"


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class TestAnomalyRepository:

    def test_insert_targets_public_anomaly_events(self):
        assert "public.anomaly_events" in _INSERT_SQL

    def test_insert_uses_named_parameter_binding(self):
        assert "%(anomaly_id)s" in _INSERT_SQL
        assert "%(event_time)s" in _INSERT_SQL
        assert "%(severity)s" in _INSERT_SQL

    def test_all_19_parameters_in_insert_sql(self):
        for col in _INSERT_COLUMNS:
            assert f"%({col})s" in _INSERT_SQL, f"Parameter %({col})s missing from INSERT SQL"

    def test_detected_at_not_in_insert_column_list(self):
        # detected_at must not appear in the INSERT column list (DB DEFAULT)
        # Extract the column list section of the INSERT
        lines_before_values = _INSERT_SQL.split("VALUES")[0]
        assert "detected_at" not in lines_before_values

    def test_sql_includes_on_conflict_do_nothing(self):
        assert "ON CONFLICT (anomaly_id) DO NOTHING" in _INSERT_SQL

    def test_sql_contains_no_update_dml(self):
        upper = _INSERT_SQL.upper()
        # ON CONFLICT DO NOTHING must not be ON CONFLICT ... DO UPDATE
        assert "DO UPDATE" not in upper

    def test_sql_contains_no_delete_dml(self):
        assert "DELETE" not in _INSERT_SQL.upper()

    def test_no_select_in_insert_sql(self):
        # No SELECT subquery or SELECT-before-INSERT pattern
        assert "SELECT" not in _INSERT_SQL.upper()

    def test_table_name_is_static_literal(self):
        import anomaly_repository
        source = inspect.getsource(anomaly_repository)
        # Table name must appear as a literal string, not be caller-controllable
        assert "public.anomaly_events" in source

    def test_on_conflict_targets_anomaly_id(self):
        assert "ON CONFLICT (anomaly_id)" in _INSERT_SQL

    def test_inserted_row_returns_true(self):
        mock_conn, mock_cur = _make_mock_conn(rowcount=1)
        repo = AnomalyRepository(mock_conn)
        result = repo.save(_make_event())
        assert result is True

    def test_duplicate_row_returns_false(self):
        mock_conn, mock_cur = _make_mock_conn(rowcount=0)
        repo = AnomalyRepository(mock_conn)
        result = repo.save(_make_event())
        assert result is False

    def test_save_calls_execute_exactly_once(self):
        mock_conn, mock_cur = _make_mock_conn()
        repo = AnomalyRepository(mock_conn)
        repo.save(_make_event())
        assert mock_cur.execute.call_count == 1

    def test_save_passes_all_parameters(self):
        mock_conn, mock_cur = _make_mock_conn()
        repo = AnomalyRepository(mock_conn)
        event = _make_event()
        repo.save(event)
        _, call_args, _ = mock_cur.execute.mock_calls[0]
        sql_arg, params_arg = call_args
        assert set(params_arg.keys()) == _INSERT_COLUMNS

    def test_caller_connection_not_closed(self):
        mock_conn, _ = _make_mock_conn()
        repo = AnomalyRepository(mock_conn)
        repo.save(_make_event())
        mock_conn.close.assert_not_called()

    def test_no_hidden_psycopg_connect_in_source(self):
        import anomaly_repository
        source = inspect.getsource(anomaly_repository)
        # psycopg.connect must not be called inside the repository;
        # the caller supplies the connection via __init__
        assert "psycopg.connect(" not in source


# ---------------------------------------------------------------------------
# Rerun semantics
# ---------------------------------------------------------------------------

class TestRerunSemantics:

    def test_result_field_changes_do_not_affect_anomaly_id(self):
        """
        A rerun may compute different baseline/score/severity/explanation for
        the same logical event.  None of those result fields must change
        anomaly_id.  The first persisted row wins (ON CONFLICT DO NOTHING).
        """
        original = _make_event(
            observed_value=450.0,
            baseline_median=200.0,
            baseline_mad=20.0,
            baseline_n=50,
            anomaly_score=5.5,
            severity=Severity.WARNING,
            explanation="original explanation",
        )
        rerun = _make_event(
            observed_value=460.0,          # different — rerun measurement
            baseline_median=210.0,         # different — rerun baseline
            baseline_mad=22.0,             # different
            baseline_n=55,                 # different
            anomaly_score=4.8,             # different
            severity=Severity.INFO,        # different
            explanation="rerun explanation",  # different
        )
        assert compute_anomaly_id(original) == compute_anomaly_id(rerun)

    def test_rerun_semantics_documented_in_module_source(self):
        import anomaly_repository
        source = inspect.getsource(anomaly_repository)
        assert "DO NOTHING" in source
        assert "first" in source.lower() or "wins" in source.lower()

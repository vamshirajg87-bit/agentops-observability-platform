"""
Tests for rca-analyzer/rca_persist.py

No live PostgreSQL required.  DB access is mocked with MagicMock.

Coverage:
    INVESTIGATION ID (TestComputeInvestigationId):
        output is 64 lowercase hex characters
        deterministic — same inputs → same ID on repeated calls
        different anomaly_id → different investigation_id
        different analyzer_version → different investigation_id
        separator prevents prefix-ambiguity — ("ab","c") ≠ ("a","bc")
        SQL special characters in anomaly_id produce valid 64-char hex

    INVESTIGATION PARAMS (TestInvestigationParams):
        all 17 required INSERT keys present
        investigated_at absent (DB DEFAULT NOW())
        signal_name, detector_name, detector_version, baseline_mad, baseline_n,
          detector_explanation not in params (absent from rca_investigations schema)
        limitations tuple → list for TEXT[] binding
        empty limitations tuple → empty list
        None values preserved as None
        zero numeric values preserved as zero

    INVESTIGATION SQL (TestInsertInvestigationSql):
        targets public.rca_investigations
        uses %(name)s named parameter binding
        all 17 parameter names present in SQL
        investigated_at absent from column list
        ON CONFLICT (investigation_id) DO NOTHING
        no DO UPDATE, no DELETE, no SELECT *

    EVIDENCE PARAMS (TestEvidenceParams):
        all 25 required INSERT keys present
        BIGSERIAL id absent
        status_message absent (SpanEvidence field not in rca_evidence)
        start_time absent (SpanEvidence field not in rca_evidence)
        end_time absent (SpanEvidence field not in rca_evidence)
        rank_position == 1 for first evidence span
        rank_position == 2 for second evidence span
        investigation_id taken from argument, not from SpanEvidence

    EVIDENCE SQL (TestInsertEvidenceSql):
        targets public.rca_evidence
        uses %(name)s named parameter binding
        all 25 parameter names present in SQL
        id absent from column list (BIGSERIAL)
        ON CONFLICT (investigation_id, span_id) DO NOTHING
        no DO UPDATE, no DELETE

    PERSIST INVESTIGATION (TestPersistInvestigation):
        new investigation → investigation_inserted=True
        duplicate investigation → investigation_inserted=False
        all evidence inserted → evidence_rows_inserted == len(all_evidence)
        duplicate evidence skipped → evidence_rows_inserted excludes conflicts
        INSUFFICIENT_DATA (empty evidence) → inserted=True, evidence_count=0
        partial-state repair → investigation conflict, evidence rows inserted
        commit called on success
        rollback called on DB error
        exception re-raised after rollback
        connection not closed by persist_investigation

    FIRST-WRITE-WINS (TestFirstWriteWins):
        second call → investigation_inserted=False, evidence_rows_inserted=0
        PersistenceResult is a frozen dataclass

    SQL SAFETY (TestSqlSafety):
        no f-string SQL construction in source
        no string .format() SQL construction in source
        no psycopg.connect() call in source
        all %(name)s bindings in INSERT SQL (no % substitution)
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

from rca_models import RCAResult, SpanEvidence
from rca_persist import (
    PersistenceResult,
    _INSERT_EVIDENCE_SQL,
    _INSERT_INVESTIGATION_SQL,
    _evidence_params,
    _investigation_params,
    compute_investigation_id,
    persist_investigation,
)

# ---------------------------------------------------------------------------
# Expected column sets (authoritative contract)
# ---------------------------------------------------------------------------

_INVESTIGATION_COLUMNS = {
    "investigation_id", "anomaly_id", "analyzer_version", "trace_id",
    "subject_span_id", "service_name", "operation_name", "event_time",
    "trace_span_count", "anomaly_type", "observed_value", "baseline_median",
    "anomaly_score", "severity", "confidence", "summary", "limitations",
}

_EVIDENCE_COLUMNS = {
    "investigation_id", "span_id", "parent_span_id", "span_name",
    "service_name", "duration_ms", "status_code", "error_type", "error_message",
    "tool_name", "tool_status", "agent_name", "agent_operation",
    "retrieval_result_count", "retrieval_top_relevance_score",
    "is_root_span", "is_error_span", "is_direct_subject",
    "depth", "trace_duration_fraction",
    "evidence_type", "evidence_score", "evidence_score_breakdown",
    "explanation", "rank_position",
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TS = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
_TS_END = datetime(2025, 1, 15, 10, 0, 1, tzinfo=timezone.utc)


def _make_span_evidence(
    span_id: str = "span-001",
    parent_span_id: str | None = "span-000",
    service_name: str = "research-service",
    evidence_score: float = 0.75,
    is_root_span: bool = False,
    is_direct_subject: bool = False,
    rank_offset: int = 0,
) -> SpanEvidence:
    return SpanEvidence(
        span_id=span_id,
        parent_span_id=parent_span_id,
        span_name="agent.run",
        service_name=service_name,
        start_time=_TS,
        end_time=_TS_END,
        duration_ms=1000.0 - rank_offset * 100,
        status_code="OK",
        status_message=None,
        error_type=None,
        error_message=None,
        tool_name=None,
        tool_status=None,
        agent_name="ResearchAgent",
        agent_operation="run",
        retrieval_result_count=None,
        retrieval_top_relevance_score=None,
        is_root_span=is_root_span,
        is_error_span=False,
        is_direct_subject=is_direct_subject,
        trace_duration_fraction=0.80 - rank_offset * 0.10,
        depth=1 if not is_root_span else 0,
        evidence_score=evidence_score,
        evidence_score_breakdown="duration_fraction=0.80→0.480",
        evidence_type="dominant_duration",
        explanation="occupied 80% of the trace wall-clock duration",
    )


def _make_rca_result(
    anomaly_id: str = "anomaly-abc-123",
    analyzer_version: str = "1.0.0",
    all_evidence: tuple[SpanEvidence, ...] | None = None,
    confidence: str = "HIGH",
    limitations: tuple[str, ...] = (),
) -> RCAResult:
    inv_id = compute_investigation_id(anomaly_id, analyzer_version)
    evidence = all_evidence if all_evidence is not None else (
        _make_span_evidence("span-001"),
        _make_span_evidence("span-002", evidence_score=0.55, rank_offset=1),
    )
    return RCAResult(
        anomaly_id=anomaly_id,
        anomaly_type="latency",
        signal_name="trace_latency",
        detector_name="LatencyDetector",
        detector_version="1.0",
        observed_value=2500.0,
        baseline_median=800.0,
        baseline_mad=50.0,
        baseline_n=100,
        anomaly_score=6.8,
        severity="WARNING",
        detector_explanation="duration_ms=2500; baseline_median=800",
        investigated_at=_TS,
        analyzer_version=analyzer_version,
        investigation_id=inv_id,
        trace_id="trace-" + "a" * 32,
        subject_span_id=None,
        service_name="research-service",
        operation_name="trace",
        event_time=_TS,
        trace_span_count=len(evidence),
        all_evidence=evidence,
        top_contributors=evidence[:1],
        confidence=confidence,
        summary="Span span-001 occupied 80% of the trace wall-clock duration.",
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# Mock connection helpers
# ---------------------------------------------------------------------------

def _make_mock_conn(rowcount: int = 1):
    """Single mock cursor returned for every cursor() call."""
    mock_cur = MagicMock()
    mock_cur.rowcount = rowcount
    mock_cur.__enter__ = MagicMock(return_value=mock_cur)
    mock_cur.__exit__ = MagicMock(return_value=False)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    return mock_conn, mock_cur


def _make_mock_conn_sequence(*rowcounts: int):
    """Each successive cursor() call gets the next rowcount in the sequence."""
    cursors = []
    for rc in rowcounts:
        cur = MagicMock()
        cur.rowcount = rc
        cur.__enter__ = MagicMock(return_value=cur)
        cur.__exit__ = MagicMock(return_value=False)
        cursors.append(cur)
    mock_conn = MagicMock()
    mock_conn.cursor.side_effect = cursors
    return mock_conn, cursors


# ---------------------------------------------------------------------------
# Investigation identity
# ---------------------------------------------------------------------------

class TestComputeInvestigationId:

    def test_output_is_64_hex_chars(self):
        result = compute_investigation_id("anomaly-001", "1.0.0")
        assert len(result) == 64

    def test_output_is_lowercase_hex(self):
        result = compute_investigation_id("anomaly-001", "1.0.0")
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_same_inputs_same_id(self):
        id1 = compute_investigation_id("anomaly-001", "1.0.0")
        id2 = compute_investigation_id("anomaly-001", "1.0.0")
        assert id1 == id2

    def test_different_anomaly_id_produces_different_investigation_id(self):
        id1 = compute_investigation_id("anomaly-001", "1.0.0")
        id2 = compute_investigation_id("anomaly-002", "1.0.0")
        assert id1 != id2

    def test_different_analyzer_version_produces_different_investigation_id(self):
        id1 = compute_investigation_id("anomaly-001", "1.0.0")
        id2 = compute_investigation_id("anomaly-001", "2.0.0")
        assert id1 != id2

    def test_separator_prevents_prefix_ambiguity(self):
        # ("ab", "c") and ("a", "bc") must produce different IDs
        id_ab_c = compute_investigation_id("ab", "c")
        id_a_bc = compute_investigation_id("a", "bc")
        assert id_ab_c != id_a_bc

    def test_sql_special_chars_in_anomaly_id_produce_valid_hex(self):
        injection_attempt = "'; DROP TABLE rca_investigations; --"
        result = compute_investigation_id(injection_attempt, "1.0.0")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_matches_manual_sha256_computation(self):
        anomaly_id = "anomaly-xyz"
        version = "1.0.0"
        expected = hashlib.sha256(
            f"{anomaly_id}|{version}".encode("utf-8")
        ).hexdigest()
        assert compute_investigation_id(anomaly_id, version) == expected


# ---------------------------------------------------------------------------
# Investigation parameter mapping
# ---------------------------------------------------------------------------

class TestInvestigationParams:

    def test_all_17_insert_keys_present(self):
        result = _make_rca_result()
        params = _investigation_params(result)
        assert set(params.keys()) == _INVESTIGATION_COLUMNS

    def test_investigated_at_absent(self):
        params = _investigation_params(_make_rca_result())
        assert "investigated_at" not in params

    def test_signal_name_absent(self):
        params = _investigation_params(_make_rca_result())
        assert "signal_name" not in params

    def test_detector_name_absent(self):
        params = _investigation_params(_make_rca_result())
        assert "detector_name" not in params

    def test_detector_version_absent(self):
        params = _investigation_params(_make_rca_result())
        assert "detector_version" not in params

    def test_baseline_mad_absent(self):
        params = _investigation_params(_make_rca_result())
        assert "baseline_mad" not in params

    def test_baseline_n_absent(self):
        params = _investigation_params(_make_rca_result())
        assert "baseline_n" not in params

    def test_limitations_tuple_converted_to_list(self):
        result = _make_rca_result(limitations=("partial_trace", "no_error_spans"))
        params = _investigation_params(result)
        assert isinstance(params["limitations"], list)
        assert params["limitations"] == ["partial_trace", "no_error_spans"]

    def test_empty_limitations_tuple_maps_to_empty_list(self):
        result = _make_rca_result(limitations=())
        params = _investigation_params(result)
        assert params["limitations"] == []
        assert isinstance(params["limitations"], list)

    def test_none_values_preserved(self):
        result = _make_rca_result()
        result = dataclasses.replace(
            result,
            subject_span_id=None,
            baseline_median=None,
            anomaly_score=None,
        )
        params = _investigation_params(result)
        assert params["subject_span_id"] is None
        assert params["baseline_median"] is None
        assert params["anomaly_score"] is None

    def test_zero_numeric_values_preserved(self):
        result = dataclasses.replace(
            _make_rca_result(),
            observed_value=0.0,
            baseline_median=0.0,
            anomaly_score=0.0,
            trace_span_count=0,
        )
        params = _investigation_params(result)
        assert params["observed_value"] == 0.0
        assert params["baseline_median"] == 0.0
        assert params["anomaly_score"] == 0.0
        assert params["trace_span_count"] == 0

    def test_investigation_id_matches_result_field(self):
        result = _make_rca_result()
        params = _investigation_params(result)
        assert params["investigation_id"] == result.investigation_id


# ---------------------------------------------------------------------------
# Investigation INSERT SQL
# ---------------------------------------------------------------------------

class TestInsertInvestigationSql:

    def test_targets_public_rca_investigations(self):
        assert "public.rca_investigations" in _INSERT_INVESTIGATION_SQL

    def test_uses_named_parameter_binding(self):
        assert "%(investigation_id)s" in _INSERT_INVESTIGATION_SQL
        assert "%(anomaly_id)s" in _INSERT_INVESTIGATION_SQL
        assert "%(limitations)s" in _INSERT_INVESTIGATION_SQL

    def test_all_17_parameter_names_in_sql(self):
        for col in _INVESTIGATION_COLUMNS:
            assert f"%({col})s" in _INSERT_INVESTIGATION_SQL, (
                f"Parameter %({col})s missing from INSERT SQL"
            )

    def test_investigated_at_not_in_column_list(self):
        column_section = _INSERT_INVESTIGATION_SQL.split("VALUES")[0]
        assert "investigated_at" not in column_section

    def test_on_conflict_investigation_id_do_nothing(self):
        assert "ON CONFLICT (investigation_id) DO NOTHING" in _INSERT_INVESTIGATION_SQL

    def test_no_do_update(self):
        assert "DO UPDATE" not in _INSERT_INVESTIGATION_SQL.upper()

    def test_no_delete_dml(self):
        assert "DELETE" not in _INSERT_INVESTIGATION_SQL.upper()

    def test_no_select_star(self):
        assert "SELECT *" not in _INSERT_INVESTIGATION_SQL.upper()


# ---------------------------------------------------------------------------
# Evidence parameter mapping
# ---------------------------------------------------------------------------

class TestEvidenceParams:

    def test_all_25_insert_keys_present(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert set(params.keys()) == _EVIDENCE_COLUMNS

    def test_bigserial_id_absent(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert "id" not in params

    def test_status_message_absent(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert "status_message" not in params

    def test_start_time_absent(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert "start_time" not in params

    def test_end_time_absent(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert "end_time" not in params

    def test_rank_position_1_for_first_evidence(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert params["rank_position"] == 1

    def test_rank_position_2_for_second_evidence(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 2)
        assert params["rank_position"] == 2

    def test_investigation_id_from_argument_not_span_evidence(self):
        ev = _make_span_evidence(span_id="s1")
        params = _evidence_params("explicit-inv-id", ev, 1)
        assert params["investigation_id"] == "explicit-inv-id"

    def test_none_optional_fields_preserved(self):
        ev = _make_span_evidence()
        params = _evidence_params("inv-001", ev, 1)
        assert params["error_type"] is None
        assert params["tool_name"] is None
        assert params["retrieval_result_count"] is None
        assert params["retrieval_top_relevance_score"] is None


# ---------------------------------------------------------------------------
# Evidence INSERT SQL
# ---------------------------------------------------------------------------

class TestInsertEvidenceSql:

    def test_targets_public_rca_evidence(self):
        assert "public.rca_evidence" in _INSERT_EVIDENCE_SQL

    def test_uses_named_parameter_binding(self):
        assert "%(investigation_id)s" in _INSERT_EVIDENCE_SQL
        assert "%(span_id)s" in _INSERT_EVIDENCE_SQL
        assert "%(rank_position)s" in _INSERT_EVIDENCE_SQL

    def test_all_25_parameter_names_in_sql(self):
        for col in _EVIDENCE_COLUMNS:
            assert f"%({col})s" in _INSERT_EVIDENCE_SQL, (
                f"Parameter %({col})s missing from evidence INSERT SQL"
            )

    def test_id_not_in_evidence_column_list(self):
        column_section = _INSERT_EVIDENCE_SQL.split("VALUES")[0]
        # "id," or "    id\n" but not "investigation_id" etc.
        import re
        matches = re.findall(r"\bid\b", column_section)
        assert not matches, "BIGSERIAL 'id' must not appear in evidence column list"

    def test_on_conflict_investigation_id_span_id_do_nothing(self):
        assert "ON CONFLICT (investigation_id, span_id) DO NOTHING" in _INSERT_EVIDENCE_SQL

    def test_no_do_update(self):
        assert "DO UPDATE" not in _INSERT_EVIDENCE_SQL.upper()

    def test_no_delete_dml(self):
        assert "DELETE" not in _INSERT_EVIDENCE_SQL.upper()


# ---------------------------------------------------------------------------
# persist_investigation()
# ---------------------------------------------------------------------------

class TestPersistInvestigation:

    def test_new_investigation_returns_investigation_inserted_true(self):
        result = _make_rca_result()
        # investigation rowcount=1, then evidence rows also rowcount=1
        mock_conn, _ = _make_mock_conn(rowcount=1)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_inserted is True

    def test_duplicate_investigation_returns_investigation_inserted_false(self):
        result = _make_rca_result()
        mock_conn, _ = _make_mock_conn(rowcount=0)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_inserted is False

    def test_evidence_rows_inserted_counts_new_rows(self):
        evidence = (
            _make_span_evidence("s1"),
            _make_span_evidence("s2", evidence_score=0.55, rank_offset=1),
        )
        result = _make_rca_result(all_evidence=evidence)
        # investigation=1, evidence1=1, evidence2=1
        mock_conn, _ = _make_mock_conn_sequence(1, 1, 1)
        pr = persist_investigation(mock_conn, result)
        assert pr.evidence_rows_inserted == 2

    def test_evidence_rows_inserted_excludes_conflicts(self):
        evidence = (
            _make_span_evidence("s1"),
            _make_span_evidence("s2", evidence_score=0.55, rank_offset=1),
        )
        result = _make_rca_result(all_evidence=evidence)
        # investigation=1, evidence1=0 (conflict), evidence2=1
        mock_conn, _ = _make_mock_conn_sequence(1, 0, 1)
        pr = persist_investigation(mock_conn, result)
        assert pr.evidence_rows_inserted == 1

    def test_insufficient_data_zero_evidence_rows_inserted(self):
        result = _make_rca_result(all_evidence=(), confidence="INSUFFICIENT_DATA")
        # Only investigation cursor called (rowcount=1), no evidence cursors
        mock_conn, _ = _make_mock_conn(rowcount=1)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_inserted is True
        assert pr.evidence_rows_inserted == 0

    def test_partial_state_repair_investigation_conflict_evidence_inserted(self):
        evidence = (
            _make_span_evidence("s1"),
            _make_span_evidence("s2", evidence_score=0.55, rank_offset=1),
        )
        result = _make_rca_result(all_evidence=evidence)
        # investigation already exists (rowcount=0), both evidence rows new
        mock_conn, _ = _make_mock_conn_sequence(0, 1, 1)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_inserted is False
        assert pr.evidence_rows_inserted == 2

    def test_commit_called_on_success(self):
        result = _make_rca_result(all_evidence=())
        mock_conn, _ = _make_mock_conn(rowcount=1)
        persist_investigation(mock_conn, result)
        mock_conn.commit.assert_called_once()

    def test_rollback_called_on_db_error(self):
        result = _make_rca_result(all_evidence=())
        mock_conn = MagicMock()
        mock_conn.cursor.side_effect = RuntimeError("simulated DB error")
        with pytest.raises(RuntimeError):
            persist_investigation(mock_conn, result)
        mock_conn.rollback.assert_called_once()

    def test_exception_reraised_after_rollback(self):
        result = _make_rca_result(all_evidence=())
        mock_conn = MagicMock()
        mock_conn.cursor.side_effect = ValueError("bad state")
        with pytest.raises(ValueError, match="bad state"):
            persist_investigation(mock_conn, result)

    def test_connection_not_closed_by_persist_investigation(self):
        result = _make_rca_result(all_evidence=())
        mock_conn, _ = _make_mock_conn(rowcount=1)
        persist_investigation(mock_conn, result)
        mock_conn.close.assert_not_called()

    def test_returns_persistence_result_with_correct_investigation_id(self):
        result = _make_rca_result()
        mock_conn, _ = _make_mock_conn(rowcount=1)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_id == result.investigation_id

    def test_evidence_rank_positions_are_1_based(self):
        """rank_position for first evidence == 1, second == 2."""
        evidence = (
            _make_span_evidence("s1"),
            _make_span_evidence("s2", evidence_score=0.55, rank_offset=1),
        )
        result = _make_rca_result(all_evidence=evidence)
        execute_calls = []

        def capturing_cursor():
            cur = MagicMock()
            cur.rowcount = 1
            cur.__enter__ = MagicMock(return_value=cur)
            cur.__exit__ = MagicMock(return_value=False)

            def capture_execute(sql, params):
                execute_calls.append(params)

            cur.execute.side_effect = capture_execute
            return cur

        mock_conn = MagicMock()
        mock_conn.cursor.side_effect = capturing_cursor
        persist_investigation(mock_conn, result)

        # First call: investigation (no rank_position)
        # Second call: evidence rank 1
        # Third call: evidence rank 2
        assert execute_calls[1]["rank_position"] == 1
        assert execute_calls[2]["rank_position"] == 2


# ---------------------------------------------------------------------------
# First-write-wins
# ---------------------------------------------------------------------------

class TestFirstWriteWins:

    def test_second_call_investigation_inserted_false(self):
        """Second call for the same investigation must return inserted=False."""
        result = _make_rca_result(all_evidence=())
        # First call: investigation inserted (rowcount=1)
        # Second call: conflict (rowcount=0) — simulates DB state after first write
        mock_conn_first, _ = _make_mock_conn(rowcount=1)
        pr_first = persist_investigation(mock_conn_first, result)
        assert pr_first.investigation_inserted is True

        mock_conn_second, _ = _make_mock_conn(rowcount=0)
        pr_second = persist_investigation(mock_conn_second, result)
        assert pr_second.investigation_inserted is False

    def test_second_call_all_evidence_conflict_evidence_rows_zero(self):
        """Second call when all evidence already exists → evidence_rows_inserted==0."""
        evidence = (
            _make_span_evidence("s1"),
            _make_span_evidence("s2", evidence_score=0.55, rank_offset=1),
        )
        result = _make_rca_result(all_evidence=evidence)
        # All conflicts (investigation + both evidence rows)
        mock_conn, _ = _make_mock_conn_sequence(0, 0, 0)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_inserted is False
        assert pr.evidence_rows_inserted == 0

    def test_persistence_result_is_frozen_dataclass(self):
        pr = PersistenceResult(
            investigation_id="abc",
            investigation_inserted=True,
            evidence_rows_inserted=3,
        )
        assert dataclasses.is_dataclass(pr)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            pr.investigation_inserted = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# SQL safety
# ---------------------------------------------------------------------------

class TestSqlSafety:

    def _source(self) -> str:
        import rca_persist
        return inspect.getsource(rca_persist)

    def test_no_fstring_sql_construction_in_source(self):
        source = self._source()
        # f-strings that interpolate into SQL strings are disallowed.
        # We check that no f"... INSERT ..." or f"... SELECT ..." patterns exist.
        # The safest proxy: look for f"INSERT or f"UPDATE inside SQL strings.
        # We check no f-string appears adjacent to SQL keywords.
        lines = source.splitlines()
        for line in lines:
            stripped = line.strip()
            # Skip comment lines
            if stripped.startswith("#"):
                continue
            # An f-string that contains SQL keywords would be a violation.
            if 'f"' in stripped or "f'" in stripped:
                assert "INSERT" not in stripped.upper() and "SELECT" not in stripped.upper(), (
                    f"f-string SQL construction detected: {stripped!r}"
                )

    def test_no_string_format_sql_construction_in_source(self):
        source = self._source()
        # .format() on SQL strings is disallowed
        # Check that no .format( follows a string containing SQL keywords
        assert '.format(' not in source.lower() or (
            # Allow .format in comments or non-SQL contexts;
            # strictly: no .format( in the entire module
            False
        ), "String .format() SQL construction detected"

    def test_no_psycopg_connect_in_source(self):
        source = self._source()
        assert "psycopg.connect(" not in source, (
            "persist.py must not open connections; caller supplies the connection"
        )

    def test_investigation_sql_uses_only_parameterized_binding(self):
        # No % string interpolation (as opposed to %(name)s psycopg binding)
        # Detect patterns like % "value" or % (value,) that are NOT %(name)s style
        import re
        # Strip all %(name)s patterns first, then check for bare % operators
        stripped = re.sub(r"%\([^)]+\)s", "", _INSERT_INVESTIGATION_SQL)
        assert "%" not in stripped, (
            "Non-parameterized % found in investigation SQL after removing %(name)s"
        )

    def test_evidence_sql_uses_only_parameterized_binding(self):
        import re
        stripped = re.sub(r"%\([^)]+\)s", "", _INSERT_EVIDENCE_SQL)
        assert "%" not in stripped, (
            "Non-parameterized % found in evidence SQL after removing %(name)s"
        )


# ---------------------------------------------------------------------------
# Investigation ID pre-validation (before any DB interaction)
# ---------------------------------------------------------------------------

class TestInvestigationIdValidation:
    """
    persist_investigation() must verify that result.investigation_id equals
    compute_investigation_id(result.anomaly_id, result.analyzer_version)
    BEFORE opening any cursor, executing any SQL, committing, or rolling back.
    """

    def _result_with_correct_id(self, anomaly_id="anomaly-abc", version="1.0.0"):
        """RCAResult whose investigation_id is consistent with anomaly_id + version."""
        return _make_rca_result(anomaly_id=anomaly_id, analyzer_version=version)

    def _result_with_wrong_id(self, anomaly_id="anomaly-abc", version="1.0.0"):
        """RCAResult whose investigation_id was computed from a DIFFERENT anomaly_id."""
        wrong_id = compute_investigation_id("completely-different-anomaly", version)
        result = _make_rca_result(anomaly_id=anomaly_id, analyzer_version=version)
        return dataclasses.replace(result, investigation_id=wrong_id)

    def test_correct_id_does_not_raise(self):
        result = self._result_with_correct_id()
        mock_conn, _ = _make_mock_conn(rowcount=1)
        persist_investigation(mock_conn, result)  # must not raise

    def test_mismatched_id_raises_value_error(self):
        result = self._result_with_wrong_id()
        mock_conn, _ = _make_mock_conn(rowcount=1)
        with pytest.raises(ValueError, match="investigation_id does not match"):
            persist_investigation(mock_conn, result)

    def test_mismatch_opens_no_cursor(self):
        result = self._result_with_wrong_id()
        mock_conn, _ = _make_mock_conn(rowcount=1)
        with pytest.raises(ValueError):
            persist_investigation(mock_conn, result)
        mock_conn.cursor.assert_not_called()

    def test_mismatch_executes_no_sql(self):
        result = self._result_with_wrong_id()
        mock_conn, mock_cur = _make_mock_conn(rowcount=1)
        with pytest.raises(ValueError):
            persist_investigation(mock_conn, result)
        mock_cur.execute.assert_not_called()

    def test_mismatch_causes_no_commit(self):
        result = self._result_with_wrong_id()
        mock_conn, _ = _make_mock_conn(rowcount=1)
        with pytest.raises(ValueError):
            persist_investigation(mock_conn, result)
        mock_conn.commit.assert_not_called()

    def test_mismatch_causes_no_rollback(self):
        result = self._result_with_wrong_id()
        mock_conn, _ = _make_mock_conn(rowcount=1)
        with pytest.raises(ValueError):
            persist_investigation(mock_conn, result)
        mock_conn.rollback.assert_not_called()

    def test_valid_historical_version_succeeds(self):
        """
        A historical version "0.9.0" is valid as long as investigation_id was
        computed from SHA256(anomaly_id + "|0.9.0").  No version whitelist check.
        """
        anomaly_id = "anomaly-historical-001"
        old_version = "0.9.0"
        correct_id = compute_investigation_id(anomaly_id, old_version)
        result = _make_rca_result(
            anomaly_id=anomaly_id,
            analyzer_version=old_version,
            all_evidence=(),
            confidence="INSUFFICIENT_DATA",
        )
        result = dataclasses.replace(result, investigation_id=correct_id)
        mock_conn, _ = _make_mock_conn(rowcount=1)
        pr = persist_investigation(mock_conn, result)
        assert pr.investigation_id == correct_id
        assert pr.investigation_inserted is True

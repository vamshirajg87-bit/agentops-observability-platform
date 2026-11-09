"""
alerting/tests/unit/test_alert_store.py

Unit tests for alert_store.py.

No live PostgreSQL required.  DB access is mocked.  The SQL constants are
read from the module and inspected as text, and the granted columns are read
from migration 013 on disk.

Test inventory:
    ST01  SQL shape: explicit columns, granted columns only, bound parameters
    ST02  SQL safety: no UPDATE / DELETE / TRUNCATE / SELECT * / DDL
    ST03  Candidate discovery statement
    ST04  History statements: predicates and boundaries
    ST05  Insert statements: conflict targets, server defaults
    ST06  fetch_policy_sha256 / insert_policy
    ST07  fetch_candidates
    ST08  fetch_alert_history
    ST09  insert_decision
    ST10  Transactions: the store never commits or rolls back
    ST11  Import boundary
"""

from __future__ import annotations

import ast
import os
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import psycopg.rows
import pytest
from psycopg.types.json import Jsonb

import alert_store
from alert_identity import compute_decision_id, compute_dedup_key
from alert_models import (
    AlertDecision,
    Confidence,
    Decision,
    ReasonCode,
    Severity,
)
from alert_store import (
    fetch_alert_history,
    fetch_candidates,
    fetch_policy_sha256,
    insert_decision,
    insert_policy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "alert_store.py")
_MIGRATIONS = os.path.join(_COMPONENT_DIR, "..", "storage-consumer", "migrations")
_MIGRATION_012 = os.path.join(_MIGRATIONS, "012_create_alert_tables.sql")
_MIGRATION_013 = os.path.join(_MIGRATIONS, "013_create_alert_evaluator_role.sql")

_INV = "a" * 64
_ANOMALY = "b" * 64
_KEY = compute_dedup_key("latency", "svc", "op")
_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)

_HISTORY_SQL = {
    "duplicate": alert_store._SQL_FETCH_HISTORY_DUPLICATE,
    "cooldown": alert_store._SQL_FETCH_HISTORY_COOLDOWN,
    "storm": alert_store._SQL_FETCH_HISTORY_STORM,
}

_ALL_SQL = {
    "fetch_policy_sha256": alert_store._SQL_FETCH_POLICY_SHA256,
    "insert_policy": alert_store._SQL_INSERT_POLICY,
    "fetch_candidates": alert_store._SQL_FETCH_CANDIDATES,
    "history_duplicate": alert_store._SQL_FETCH_HISTORY_DUPLICATE,
    "history_cooldown": alert_store._SQL_FETCH_HISTORY_COOLDOWN,
    "history_storm": alert_store._SQL_FETCH_HISTORY_STORM,
    "insert_decision": alert_store._SQL_INSERT_DECISION,
}

_CANDIDATE_COLUMNS = [
    "investigation_id", "anomaly_id", "anomaly_type", "service_name",
    "operation_name", "event_time", "severity", "confidence", "limitations",
    "summary",
]

_HISTORY_COLUMNS = [
    "decision_id", "anomaly_id", "dedup_key", "event_time", "severity", "decision",
]

_DECISION_INSERT_COLUMNS = [
    "decision_id", "investigation_id", "policy_version", "anomaly_id",
    "anomaly_type", "service_name", "operation_name", "event_time", "severity",
    "confidence", "limitations", "dedup_key", "decision", "reason_code",
    "related_decision_id", "evaluated_at", "payload", "summary",
    "summary_truncated",
]

_POLICY_INSERT_COLUMNS = ["policy_version", "policy_sha256", "policy_json"]


def _normalise(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _select_columns(sql: str) -> list[str]:
    match = re.search(r"SELECT\s+(.*?)\s+FROM\s", sql, re.DOTALL | re.IGNORECASE)
    assert match, f"SELECT ... FROM not found in: {sql!r}"
    return [c.strip() for c in match.group(1).split(",")]


def _insert_columns(sql: str) -> list[str]:
    match = re.search(r"INSERT INTO \S+ \((.*?)\) VALUES", _normalise(sql))
    assert match, f"INSERT column list not found in: {sql!r}"
    return [c.strip() for c in match.group(1).split(",")]


def _insert_values(sql: str) -> list[str]:
    match = re.search(r"VALUES \((.*?)\) ON CONFLICT", _normalise(sql))
    assert match, f"VALUES list not found in: {sql!r}"
    return [c.strip() for c in match.group(1).split(",")]


def _migration_sql(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return "\n".join(line.split("--")[0] for line in fh.read().splitlines())


def _granted_columns(table: str) -> set[str]:
    """Columns granted to alert_evaluator on a table, read from migration 013."""
    match = re.search(
        r"GRANT\s+SELECT\s*\(([^)]*)\)\s*ON\s+" + re.escape(table)
        + r"\s+TO\s+alert_evaluator",
        _migration_sql(_MIGRATION_013), re.IGNORECASE,
    )
    assert match, f"column grant on {table} not found in migration 013"
    columns = [c.strip() for c in match.group(1).split(",")]
    assert len(columns) == len(set(columns))
    return set(columns)


def _table_columns(table: str) -> set[str]:
    """Column names of a table, read from migration 012."""
    sql = _migration_sql(_MIGRATION_012)
    match = re.search(
        r"CREATE TABLE " + re.escape(table) + r" \((.*?)\n\);", sql, re.DOTALL,
    )
    assert match, f"CREATE TABLE {table} not found in migration 012"
    columns = set()
    for line in match.group(1).splitlines():
        found = re.match(r"\s{4}([a-z0-9_]+)\s+[A-Z]", line)
        if found:
            columns.add(found.group(1))
    return columns


def _make_conn(fetchone=None, fetchall=None, rowcount: int = 1):
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchone.return_value = fetchone
    cur.fetchall.return_value = fetchall if fetchall is not None else []
    cur.rowcount = rowcount
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def _history_row(decision_id: str, **overrides) -> dict:
    row = {
        "decision_id": decision_id,
        "anomaly_id": _ANOMALY,
        "dedup_key": _KEY,
        "event_time": _T0,
        "severity": "WARNING",
        "decision": "ALERT",
    }
    row.update(overrides)
    return row


def _decision(**overrides) -> AlertDecision:
    values = dict(
        decision_id=compute_decision_id(_INV, "1.0.0"),
        investigation_id=_INV,
        policy_version="1.0.0",
        anomaly_id=_ANOMALY,
        anomaly_type="latency",
        service_name="svc",
        operation_name="op",
        event_time=_T0,
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        limitations=("one", "two"),
        dedup_key=_KEY,
        decision=Decision.ALERT,
        reason_code=ReasonCode.SEVERITY_MET,
        related_decision_id=None,
        evaluated_at=_T0 + timedelta(minutes=1),
        payload={"payload_version": "1.0.0", "limitations": ["one", "two"]},
        summary=None,
        summary_truncated=False,
    )
    values.update(overrides)
    return AlertDecision(**values)


# ---------------------------------------------------------------------------
# ST01  SQL shape
# ---------------------------------------------------------------------------

class TestSqlShape:

    def test_candidate_columns_are_exact(self):
        columns = _select_columns(alert_store._SQL_FETCH_CANDIDATES)
        assert columns == [f"i.{name}" for name in _CANDIDATE_COLUMNS]

    def test_candidate_columns_are_exactly_the_granted_columns(self):
        granted = _granted_columns("public.rca_investigations")
        assert set(_CANDIDATE_COLUMNS) == granted
        assert len(granted) == 10

    def test_every_investigation_column_reference_is_granted(self):
        granted = _granted_columns("public.rca_investigations")
        referenced = set(re.findall(r"\bi\.([a-z_]+)", alert_store._SQL_FETCH_CANDIDATES))
        assert referenced <= granted

    @pytest.mark.parametrize("name", sorted(_HISTORY_SQL))
    def test_history_columns_are_exact(self, name):
        assert _select_columns(_HISTORY_SQL[name]) == _HISTORY_COLUMNS

    def test_policy_lookup_selects_only_the_hash(self):
        assert _select_columns(alert_store._SQL_FETCH_POLICY_SHA256) == ["policy_sha256"]

    def test_decision_insert_columns_are_exact(self):
        assert _insert_columns(alert_store._SQL_INSERT_DECISION) == _DECISION_INSERT_COLUMNS

    def test_decision_insert_covers_every_column_but_the_server_default(self):
        table = _table_columns("public.alert_decisions")
        assert set(_DECISION_INSERT_COLUMNS) == table - {"decided_at"}

    def test_policy_insert_columns_are_exact(self):
        assert _insert_columns(alert_store._SQL_INSERT_POLICY) == _POLICY_INSERT_COLUMNS
        table = _table_columns("public.alert_policies")
        assert set(_POLICY_INSERT_COLUMNS) == table - {"registered_at"}

    @pytest.mark.parametrize("sql, columns", [
        (alert_store._SQL_INSERT_DECISION, _DECISION_INSERT_COLUMNS),
        (alert_store._SQL_INSERT_POLICY, _POLICY_INSERT_COLUMNS),
    ])
    def test_insert_values_are_named_parameters_in_column_order(self, sql, columns):
        assert _insert_values(sql) == [f"%({name})s" for name in columns]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_named_bound_parameters(self, name):
        sql = _ALL_SQL[name]
        without_named = re.sub(r"%\([a-z0-9_]+\)s", "", sql)
        assert "%" not in without_named
        assert "{" not in sql and "}" not in sql
        assert "$" not in sql

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_the_expected_literal(self, name):
        literals = set(re.findall(r"'([^']*)'", _ALL_SQL[name]))
        assert literals <= {"ALERT"}

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_tables_are_schema_qualified_and_expected(self, name):
        tables = set(re.findall(r"(?:FROM|INTO)\s+(\S+)", _ALL_SQL[name]))
        assert tables <= {
            "public.rca_investigations",
            "public.alert_policies",
            "public.alert_decisions",
        }
        assert tables


# ---------------------------------------------------------------------------
# ST02  SQL safety
# ---------------------------------------------------------------------------

class TestSqlSafety:

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("word", [
        "UPDATE", "DELETE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT",
        "REVOKE", "SET ROLE", "NEXTVAL", "RETURNING", "LIMIT", "COPY",
    ])
    def test_forbidden_word_is_absent(self, name, word):
        assert re.search(rf"\b{word}\b", _ALL_SQL[name].upper()) is None

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_select_star(self, name):
        assert "*" not in _ALL_SQL[name]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_single_statement(self, name):
        assert ";" not in _ALL_SQL[name]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("table", [
        "rca_evidence", "rca_investigation_embeddings", "telemetry_spans",
        "analytics.", "anomaly_events", "anomaly_detector_runs",
        "alert_delivery_attempts", "alert_delivery_outcomes",
    ])
    def test_out_of_scope_table_is_never_read(self, name, table):
        assert table not in _ALL_SQL[name]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_time_arithmetic_or_server_clock(self, name):
        upper = _ALL_SQL[name].upper()
        for word in ("NOW()", "INTERVAL", "CURRENT_TIMESTAMP", "CLOCK_TIMESTAMP"):
            assert word not in upper

    def test_only_two_insert_statements_exist(self):
        inserts = [n for n, sql in _ALL_SQL.items() if "INSERT" in sql.upper()]
        assert sorted(inserts) == ["insert_decision", "insert_policy"]

    def test_module_defines_no_other_statement(self):
        constants = {
            name for name in vars(alert_store) if name.startswith("_SQL_")
        }
        assert len(constants) == len(_ALL_SQL)
        assert {getattr(alert_store, name) for name in constants} == set(_ALL_SQL.values())


# ---------------------------------------------------------------------------
# ST03  Candidate discovery statement
# ---------------------------------------------------------------------------

class TestCandidateStatement:

    def test_excludes_decisions_of_the_given_policy_version_only(self):
        sql = _normalise(alert_store._SQL_FETCH_CANDIDATES)
        assert (
            "WHERE NOT EXISTS ( SELECT d.decision_id "
            "FROM public.alert_decisions AS d "
            "WHERE d.investigation_id = i.investigation_id "
            "AND d.policy_version = %(policy_version)s )"
        ) in sql

    def test_order_is_event_time_then_investigation_id(self):
        sql = _normalise(alert_store._SQL_FETCH_CANDIDATES)
        assert sql.endswith("ORDER BY i.event_time ASC, i.investigation_id ASC")

    def test_no_staleness_or_severity_filter(self):
        sql = _normalise(alert_store._SQL_FETCH_CANDIDATES)
        where = sql.split("WHERE", 1)[1].split("ORDER BY")[0]
        outer = where.replace(
            "NOT EXISTS ( SELECT d.decision_id FROM public.alert_decisions AS d "
            "WHERE d.investigation_id = i.investigation_id "
            "AND d.policy_version = %(policy_version)s )", "",
        )
        assert outer.strip() == ""

    def test_only_parameter_is_policy_version(self):
        assert set(re.findall(r"%\(([a-z_]+)\)s", alert_store._SQL_FETCH_CANDIDATES)) == {
            "policy_version",
        }

    def test_decision_filter_does_not_depend_on_the_verdict(self):
        # Any decision under the policy version excludes the investigation,
        # not only an ALERT.
        assert "'ALERT'" not in alert_store._SQL_FETCH_CANDIDATES


# ---------------------------------------------------------------------------
# ST04  History statements
# ---------------------------------------------------------------------------

class TestHistoryStatements:

    @pytest.mark.parametrize("name", sorted(_HISTORY_SQL))
    def test_reads_alert_decisions_only(self, name):
        sql = _normalise(_HISTORY_SQL[name])
        assert "FROM public.alert_decisions WHERE decision = 'ALERT' AND" in sql

    @pytest.mark.parametrize("name", sorted(_HISTORY_SQL))
    def test_no_policy_version_filter(self, name):
        assert "policy_version" not in _HISTORY_SQL[name]

    def test_duplicate_has_no_time_bound(self):
        sql = _normalise(alert_store._SQL_FETCH_HISTORY_DUPLICATE)
        assert sql.endswith("WHERE decision = 'ALERT' AND anomaly_id = %(anomaly_id)s")
        assert "event_time >" not in sql and "event_time <" not in sql
        assert "dedup_key =" not in sql

    def test_cooldown_predicate(self):
        sql = _normalise(alert_store._SQL_FETCH_HISTORY_COOLDOWN)
        assert sql.endswith(
            "WHERE decision = 'ALERT' AND dedup_key = %(dedup_key)s "
            "AND event_time > %(cooldown_start)s AND event_time <= %(event_time)s"
        )
        assert "anomaly_id =" not in sql

    def test_storm_predicate_covers_every_dedup_key(self):
        sql = _normalise(alert_store._SQL_FETCH_HISTORY_STORM)
        assert sql.endswith(
            "WHERE decision = 'ALERT' "
            "AND event_time > %(storm_start)s AND event_time <= %(event_time)s"
        )
        assert "dedup_key =" not in sql and "anomaly_id =" not in sql

    @pytest.mark.parametrize("name", ["cooldown", "storm"])
    def test_lower_bound_exclusive_upper_bound_inclusive(self, name):
        sql = _HISTORY_SQL[name]
        assert "event_time >=" not in sql
        assert re.search(r"event_time <(?!=)", sql) is None
        assert "BETWEEN" not in sql.upper()

    def test_parameters(self):
        def names(sql):
            return set(re.findall(r"%\(([a-z_]+)\)s", sql))

        assert names(alert_store._SQL_FETCH_HISTORY_DUPLICATE) == {"anomaly_id"}
        assert names(alert_store._SQL_FETCH_HISTORY_COOLDOWN) == {
            "dedup_key", "cooldown_start", "event_time",
        }
        assert names(alert_store._SQL_FETCH_HISTORY_STORM) == {
            "storm_start", "event_time",
        }


# ---------------------------------------------------------------------------
# ST05  Insert statements
# ---------------------------------------------------------------------------

class TestInsertStatements:

    def test_decision_conflict_target_is_the_frozen_unique_key(self):
        sql = _normalise(alert_store._SQL_INSERT_DECISION)
        assert sql.endswith("ON CONFLICT (investigation_id, policy_version) DO NOTHING")

    def test_policy_conflict_target_is_the_primary_key(self):
        sql = _normalise(alert_store._SQL_INSERT_POLICY)
        assert sql.endswith("ON CONFLICT (policy_version) DO NOTHING")

    @pytest.mark.parametrize("sql", [
        alert_store._SQL_INSERT_DECISION, alert_store._SQL_INSERT_POLICY,
    ])
    def test_never_overwrites(self, sql):
        assert "DO UPDATE" not in sql.upper()
        assert sql.upper().count("ON CONFLICT") == 1

    def test_server_timestamps_are_not_supplied(self):
        assert "decided_at" not in alert_store._SQL_INSERT_DECISION
        assert "registered_at" not in alert_store._SQL_INSERT_POLICY


# ---------------------------------------------------------------------------
# ST06  Policy registry
# ---------------------------------------------------------------------------

class TestPolicyRegistry:

    def test_fetch_returns_the_stored_hash(self):
        conn, cur = _make_conn(fetchone={"policy_sha256": "c" * 64})
        assert fetch_policy_sha256(conn, "1.0.0") == "c" * 64
        cur.execute.assert_called_once_with(
            alert_store._SQL_FETCH_POLICY_SHA256, {"policy_version": "1.0.0"},
        )
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_fetch_returns_none_when_absent(self):
        conn, _ = _make_conn(fetchone=None)
        assert fetch_policy_sha256(conn, "1.0.0") is None

    def test_insert_binds_the_three_values(self):
        conn, cur = _make_conn(rowcount=1)
        document = {"policy_version": "1.0.0", "evaluation": {"enabled": True}}
        assert insert_policy(
            conn, policy_version="1.0.0", policy_sha256="c" * 64,
            policy_json=document,
        ) is True
        sql, params = cur.execute.call_args.args
        assert sql == alert_store._SQL_INSERT_POLICY
        assert set(params) == set(_POLICY_INSERT_COLUMNS)
        assert params["policy_version"] == "1.0.0"
        assert params["policy_sha256"] == "c" * 64
        assert isinstance(params["policy_json"], Jsonb)
        assert params["policy_json"].obj == document

    def test_insert_reports_an_existing_version(self):
        conn, _ = _make_conn(rowcount=0)
        assert insert_policy(
            conn, policy_version="1.0.0", policy_sha256="c" * 64, policy_json={},
        ) is False

    def test_insert_arguments_are_keyword_only(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            insert_policy(conn, "1.0.0", "c" * 64, {})


# ---------------------------------------------------------------------------
# ST07  fetch_candidates
# ---------------------------------------------------------------------------

class TestFetchCandidates:

    def test_returns_rows_in_database_order(self):
        rows = [{"investigation_id": "b" * 64}, {"investigation_id": "a" * 64}]
        conn, cur = _make_conn(fetchall=rows)
        result = fetch_candidates(conn, "1.0.0")
        assert result == rows
        assert all(type(row) is dict for row in result)
        cur.execute.assert_called_once_with(
            alert_store._SQL_FETCH_CANDIDATES, {"policy_version": "1.0.0"},
        )

    def test_no_candidates(self):
        conn, _ = _make_conn(fetchall=[])
        assert fetch_candidates(conn, "1.0.0") == []

    def test_uses_a_dict_row_cursor(self):
        conn, _ = _make_conn()
        fetch_candidates(conn, "1.0.0")
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)


# ---------------------------------------------------------------------------
# ST08  fetch_alert_history
# ---------------------------------------------------------------------------

def _history_conn(duplicate=(), cooldown=(), storm=()):
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchall.side_effect = [list(duplicate), list(cooldown), list(storm)]
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def _fetch_history(conn):
    return fetch_alert_history(
        conn,
        anomaly_id=_ANOMALY,
        dedup_key=_KEY,
        event_time=_T0,
        cooldown_start=_T0 - timedelta(minutes=30),
        storm_start=_T0 - timedelta(minutes=60),
    )


class TestFetchAlertHistory:

    def test_runs_the_three_statements_with_their_parameters(self):
        conn, cur = _history_conn()
        assert _fetch_history(conn) == []
        calls = [call.args for call in cur.execute.call_args_list]
        assert calls == [
            (alert_store._SQL_FETCH_HISTORY_DUPLICATE, {"anomaly_id": _ANOMALY}),
            (alert_store._SQL_FETCH_HISTORY_COOLDOWN, {
                "dedup_key": _KEY,
                "cooldown_start": _T0 - timedelta(minutes=30),
                "event_time": _T0,
            }),
            (alert_store._SQL_FETCH_HISTORY_STORM, {
                "storm_start": _T0 - timedelta(minutes=60),
                "event_time": _T0,
            }),
        ]

    def test_all_three_run_even_when_the_first_returns_rows(self):
        conn, cur = _history_conn(duplicate=[_history_row("1" * 64)])
        _fetch_history(conn)
        assert cur.execute.call_count == 3

    def test_union_of_the_three_results(self):
        conn, _ = _history_conn(
            duplicate=[_history_row("3" * 64)],
            cooldown=[_history_row("1" * 64)],
            storm=[_history_row("2" * 64)],
        )
        assert [row["decision_id"] for row in _fetch_history(conn)] == [
            "1" * 64, "2" * 64, "3" * 64,
        ]

    def test_a_decision_returned_by_every_statement_appears_once(self):
        row = _history_row("1" * 64)
        conn, _ = _history_conn(duplicate=[row], cooldown=[row], storm=[row])
        result = _fetch_history(conn)
        assert len(result) == 1
        assert result[0] == row

    def test_result_is_ordered_by_decision_id(self):
        ids = ["f" * 64, "0" * 64, "7" * 64, "a" * 64]
        conn, _ = _history_conn(storm=[_history_row(i) for i in ids])
        assert [r["decision_id"] for r in _fetch_history(conn)] == sorted(ids)

    def test_result_does_not_depend_on_row_order(self):
        rows = [_history_row(c * 64) for c in "9a3"]
        first, _ = _history_conn(duplicate=rows[:1], cooldown=rows[1:], storm=rows)
        second, _ = _history_conn(
            duplicate=rows[:1], cooldown=rows[:0:-1], storm=rows[::-1],
        )
        assert _fetch_history(first) == _fetch_history(second)

    def test_rows_are_plain_dicts_with_the_history_columns(self):
        conn, _ = _history_conn(storm=[_history_row("1" * 64)])
        (row,) = _fetch_history(conn)
        assert type(row) is dict
        assert list(row) == _HISTORY_COLUMNS

    def test_arguments_are_keyword_only(self):
        conn, _ = _history_conn()
        with pytest.raises(TypeError):
            fetch_alert_history(conn, _ANOMALY, _KEY, _T0, _T0, _T0)


# ---------------------------------------------------------------------------
# ST09  insert_decision
# ---------------------------------------------------------------------------

class TestInsertDecision:

    def _params(self, decision: AlertDecision) -> dict:
        conn, cur = _make_conn()
        insert_decision(conn, decision)
        sql, params = cur.execute.call_args.args
        assert sql == alert_store._SQL_INSERT_DECISION
        return params

    def test_inserted(self):
        conn, _ = _make_conn(rowcount=1)
        assert insert_decision(conn, _decision()) is True

    def test_existing_decision_is_reported_and_left_alone(self):
        conn, cur = _make_conn(rowcount=0)
        assert insert_decision(conn, _decision()) is False
        assert cur.execute.call_count == 1

    def test_parameter_names_match_the_columns(self):
        assert list(self._params(_decision())) == _DECISION_INSERT_COLUMNS

    def test_enums_are_bound_as_their_text_values(self):
        params = self._params(_decision())
        assert params["severity"] == "CRITICAL"
        assert params["confidence"] == "MEDIUM"
        assert params["decision"] == "ALERT"
        assert params["reason_code"] == "severity_met"
        for name in ("severity", "confidence", "decision", "reason_code"):
            assert type(params[name]) is str

    def test_limitations_are_bound_as_a_list(self):
        params = self._params(_decision())
        assert params["limitations"] == ["one", "two"]
        assert type(params["limitations"]) is list

    def test_alert_payload_is_bound_as_jsonb(self):
        params = self._params(_decision())
        assert isinstance(params["payload"], Jsonb)
        assert params["payload"].obj == {
            "payload_version": "1.0.0", "limitations": ["one", "two"],
        }
        assert type(params["payload"].obj) is dict

    @pytest.mark.parametrize("decision, reason", [
        (Decision.SUPPRESSED, ReasonCode.STORM_CAP),
        (Decision.NOT_ALERTABLE, ReasonCode.STALE),
    ])
    def test_missing_payload_is_sql_null_not_json_null(self, decision, reason):
        params = self._params(
            _decision(decision=decision, reason_code=reason, payload=None),
        )
        assert params["payload"] is None

    def test_identity_and_snapshot_values_pass_through(self):
        decision = _decision(service_name=None, operation_name=None)
        params = self._params(decision)
        assert params["decision_id"] == decision.decision_id
        assert params["investigation_id"] == _INV
        assert params["policy_version"] == "1.0.0"
        assert params["anomaly_id"] == _ANOMALY
        assert params["dedup_key"] == _KEY
        assert params["service_name"] is None
        assert params["operation_name"] is None
        assert params["event_time"] == _T0
        assert params["evaluated_at"] == _T0 + timedelta(minutes=1)

    def test_related_decision_and_summary(self):
        related = "d" * 64
        params = self._params(_decision(
            reason_code=ReasonCode.ESCALATION, related_decision_id=related,
            summary="text", summary_truncated=True,
        ))
        assert params["related_decision_id"] == related
        assert params["summary"] == "text"
        assert params["summary_truncated"] is True

    def test_database_error_propagates(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.IntegrityError("violation")
        with pytest.raises(psycopg.IntegrityError):
            insert_decision(conn, _decision())


# ---------------------------------------------------------------------------
# ST10  Transactions
# ---------------------------------------------------------------------------

class TestTransactions:

    def test_no_function_commits_or_rolls_back(self):
        conn, _ = _make_conn(fetchone={"policy_sha256": "c" * 64})
        fetch_policy_sha256(conn, "1.0.0")
        insert_policy(conn, policy_version="1.0.0", policy_sha256="c" * 64, policy_json={})
        fetch_candidates(conn, "1.0.0")
        insert_decision(conn, _decision())
        history_conn, _ = _history_conn()
        _fetch_history(history_conn)
        for used in (conn, history_conn):
            used.commit.assert_not_called()
            used.rollback.assert_not_called()
            used.close.assert_not_called()

    def test_source_has_no_transaction_call(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert attributes.isdisjoint({"commit", "rollback", "close", "autocommit"})


# ---------------------------------------------------------------------------
# ST11  Import boundary
# ---------------------------------------------------------------------------

class TestImportBoundary:

    def test_imports(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {
            "__future__", "datetime", "typing", "psycopg", "psycopg.rows",
            "psycopg.types.json", "alert_models",
        }

    def test_public_api(self):
        public = {
            name for name, value in vars(alert_store).items()
            if callable(value) and not name.startswith("_")
            and getattr(value, "__module__", None) == "alert_store"
        }
        assert public == {
            "fetch_policy_sha256", "insert_policy", "fetch_candidates",
            "fetch_alert_history", "insert_decision",
        }

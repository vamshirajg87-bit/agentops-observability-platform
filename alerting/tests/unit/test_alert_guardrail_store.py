"""
alerting/tests/unit/test_alert_guardrail_store.py

Unit tests for alert_guardrail_store.py.

No live PostgreSQL required.  DB access is mocked.  The SQL constants are
read from the module and inspected as text, and the granted columns are read
from migration 013 on disk.

Test inventory:
    GS01  Exactly four statements, all SELECT
    GS02  Columns: exact lists, all within the alert_evaluator grants
    GS03  Nothing sensitive and nothing out of scope is read
    GS04  Statement shape: filters, ordering, parameters
    GS05  Functions
    GS06  Empty inputs
    GS07  Transactions, clock, environment
    GS08  Import boundary
"""

from __future__ import annotations

import ast
import os
import re
from datetime import datetime, timezone
from unittest.mock import MagicMock

import psycopg
import psycopg.rows
import pytest

import alert_guardrail_store
from alert_guardrail_store import (
    fetch_alert_decisions,
    fetch_checkpoints,
    fetch_delivery_history,
    fetch_uninvestigated_anomalies,
)


_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "alert_guardrail_store.py")
_MIGRATIONS = os.path.join(_COMPONENT_DIR, "..", "storage-consumer", "migrations")
_MIGRATION_012 = os.path.join(_MIGRATIONS, "012_create_alert_tables.sql")
_MIGRATION_013 = os.path.join(_MIGRATIONS, "013_create_alert_evaluator_role.sql")

_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)
_DEC = "d" * 64

_ALL_SQL = {
    "fetch_checkpoints": alert_guardrail_store._SQL_FETCH_CHECKPOINTS,
    "fetch_uninvestigated_anomalies":
        alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES,
    "fetch_alert_decisions": alert_guardrail_store._SQL_FETCH_ALERT_DECISIONS,
    "fetch_delivery_history": alert_guardrail_store._SQL_FETCH_DELIVERY_HISTORY,
}

_HISTORY_COLUMNS = [
    "a.attempt_id", "a.decision_id", "a.channel_name", "a.channel_type",
    "a.attempt_no", "a.trigger", "a.summary_included", "a.payload_sha256",
    "a.started_at", "o.outcome", "o.recorded_at",
]


def _normalise(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _select_columns(sql: str) -> list[str]:
    match = re.search(r"SELECT\s+(.*?)\s+FROM\s", sql, re.DOTALL)
    assert match, f"SELECT ... FROM not found in: {sql!r}"
    return [c.strip() for c in match.group(1).split(",")]


def _migration_sql(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return "\n".join(line.split("--")[0] for line in fh.read().splitlines())


def _granted_columns(table: str) -> set[str]:
    """Columns granted to alert_evaluator on a table, from migration 013."""
    match = re.search(
        r"GRANT\s+SELECT\s*\(([^)]*)\)\s*ON\s+" + re.escape(table)
        + r"\s+TO\s+alert_evaluator",
        _migration_sql(_MIGRATION_013),
    )
    assert match, f"column grant on {table} not found in migration 013"
    return {c.strip() for c in match.group(1).split(",")}


def _table_privileges(table: str) -> set[str]:
    match = re.search(
        r"GRANT\s+([A-Z, ]+?)\s+ON\s+" + re.escape(table) + r"\s+TO\s+alert_evaluator",
        _migration_sql(_MIGRATION_013),
    )
    assert match, f"table grant on {table} not found in migration 013"
    return {word.strip() for word in match.group(1).split(",")}


def _table_columns(table: str) -> set[str]:
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


def _alias_columns(sql: str, alias: str) -> set[str]:
    return set(re.findall(rf"\b{alias}\.([a-z0-9_]+)", sql))


def _make_conn(fetchall=None):
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchall.return_value = fetchall if fetchall is not None else []
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


# ---------------------------------------------------------------------------
# GS01  Exactly four statements, all SELECT
# ---------------------------------------------------------------------------

class TestStatements:

    def test_module_defines_exactly_four_statements(self):
        constants = {
            name for name in vars(alert_guardrail_store) if name.startswith("_SQL_")
        }
        assert len(constants) == 4
        assert {
            getattr(alert_guardrail_store, name) for name in constants
        } == set(_ALL_SQL.values())

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_statement_is_a_single_select(self, name):
        sql = _ALL_SQL[name]
        assert sql.lstrip().startswith("SELECT")
        assert ";" not in sql

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("word", [
        "INSERT", "UPDATE", "DELETE", "TRUNCATE", "MERGE", "DROP", "ALTER",
        "CREATE", "GRANT", "REVOKE", "RETURNING", "COPY", "ON CONFLICT",
        "FOR UPDATE", "FOR SHARE", "LOCK", "SET ROLE", "NEXTVAL", "INTO",
        "CALL", "DO",
    ])
    def test_no_writing_or_locking_word(self, name, word):
        assert re.search(rf"\b{word}\b", _ALL_SQL[name].upper()) is None

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_select_star(self, name):
        assert "*" not in _ALL_SQL[name]

    def test_every_execute_uses_a_module_constant(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        executes = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
        ]
        assert len(executes) == 1
        assert isinstance(executes[0].args[0], ast.Name)
        assert executes[0].args[0].id == "sql"
        # _fetch_all is only ever called with one of the four constants.
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_fetch_all"
        ]
        assert sorted(call.args[1].id for call in calls) == sorted(
            name for name in vars(alert_guardrail_store) if name.startswith("_SQL_")
        )

    def test_no_statement_text_outside_the_constants_and_docstrings(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        docstrings = {ast.get_docstring(tree, clean=False)} | {
            ast.get_docstring(node, clean=False)
            for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        strings = {
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", node.value)
        }
        assert strings - docstrings == set(_ALL_SQL.values())


# ---------------------------------------------------------------------------
# GS02  Columns
# ---------------------------------------------------------------------------

class TestColumns:

    def test_checkpoint_columns_are_exactly_the_granted_columns(self):
        columns = _select_columns(alert_guardrail_store._SQL_FETCH_CHECKPOINTS)
        assert columns == [
            "signal_path", "service_name", "operation_name", "updated_at",
        ]
        assert set(columns) == _granted_columns("public.anomaly_detector_runs")

    def test_anomaly_columns_are_exactly_the_granted_columns(self):
        sql = alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES
        assert _select_columns(sql) == ["e.anomaly_id", "e.detected_at"]
        assert _alias_columns(sql, "e") == _granted_columns("public.anomaly_events")
        assert _alias_columns(sql, "e") == {"anomaly_id", "detected_at"}

    def test_investigation_columns_are_granted(self):
        sql = alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES
        used = _alias_columns(sql, "i")
        assert used == {"investigation_id", "anomaly_id"}
        assert used <= _granted_columns("public.rca_investigations")

    def test_decision_columns(self):
        sql = alert_guardrail_store._SQL_FETCH_ALERT_DECISIONS
        assert _select_columns(sql) == ["d.decision_id", "d.evaluated_at"]
        assert _alias_columns(sql, "d") == {"decision_id", "evaluated_at", "decision"}
        assert _alias_columns(sql, "d") <= _table_columns("public.alert_decisions")
        assert _alias_columns(sql, "a") == {"attempt_id", "decision_id", "started_at"}

    def test_history_columns_are_exact(self):
        sql = alert_guardrail_store._SQL_FETCH_DELIVERY_HISTORY
        assert _select_columns(sql) == _HISTORY_COLUMNS
        assert _alias_columns(sql, "a") == _table_columns(
            "public.alert_delivery_attempts",
        )
        assert _alias_columns(sql, "o") == {"attempt_id", "outcome", "recorded_at"}

    def test_role_may_read_the_alert_tables(self):
        assert "SELECT" in _table_privileges("public.alert_decisions")
        assert _table_privileges("public.alert_delivery_attempts") == {"SELECT"}
        assert _table_privileges("public.alert_delivery_outcomes") == {"SELECT"}

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_the_six_granted_tables(self, name):
        tables = set(re.findall(r"(?:FROM|JOIN)\s+(public\.\S+)", _ALL_SQL[name]))
        assert tables
        assert tables <= {
            "public.anomaly_detector_runs",
            "public.anomaly_events",
            "public.rca_investigations",
            "public.alert_decisions",
            "public.alert_delivery_attempts",
            "public.alert_delivery_outcomes",
        }

    def test_tables_per_statement(self):
        def tables(name):
            return set(re.findall(r"(?:FROM|JOIN)\s+public\.(\S+)", _ALL_SQL[name]))

        assert tables("fetch_checkpoints") == {"anomaly_detector_runs"}
        assert tables("fetch_uninvestigated_anomalies") == {
            "anomaly_events", "rca_investigations",
        }
        assert tables("fetch_alert_decisions") == {
            "alert_decisions", "alert_delivery_attempts",
        }
        assert tables("fetch_delivery_history") == {
            "alert_delivery_attempts", "alert_delivery_outcomes",
        }


# ---------------------------------------------------------------------------
# GS03  Nothing sensitive, nothing out of scope
# ---------------------------------------------------------------------------

class TestNothingSensitive:

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("word", [
        "summary", "limitations", "payload", "explanation", "detail",
        "error_message", "checkpoint_at", "confidence", "severity",
        "observed_value", "trace_id", "span_id", "attributes", "policy_json",
        "reason_code", "related_decision_id", "dedup_key",
    ])
    def test_sensitive_or_unneeded_column_is_not_read(self, name, word):
        # summary_included and payload_sha256 are attempt metadata, not content.
        text = _ALL_SQL[name].replace("summary_included", "").replace(
            "payload_sha256", "",
        )
        assert re.search(rf"\b{word}\b", text) is None

    def test_outcome_detail_is_not_selected(self):
        sql = alert_guardrail_store._SQL_FETCH_DELIVERY_HISTORY
        assert "o.detail" not in sql and "detail" not in sql

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("table", [
        "rca_evidence", "rca_investigation_embeddings", "telemetry_spans",
        "analytics.", "stg_telemetry_spans", "alert_policies",
    ])
    def test_out_of_scope_object_is_never_read(self, name, table):
        assert table not in _ALL_SQL[name]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_server_clock_or_time_arithmetic(self, name):
        upper = _ALL_SQL[name].upper()
        for word in ("NOW()", "INTERVAL", "CURRENT_TIMESTAMP", "CLOCK_TIMESTAMP",
                     "CURRENT_DATE", "LOCALTIMESTAMP", "AGE("):
            assert word not in upper

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_named_bound_parameters_and_one_literal(self, name):
        sql = _ALL_SQL[name]
        assert "%" not in re.sub(r"%\([a-z0-9_]+\)s", "", sql)
        assert "{" not in sql and "}" not in sql and "$" not in sql
        assert set(re.findall(r"'([^']*)'", sql)) <= {"ALERT"}


# ---------------------------------------------------------------------------
# GS04  Statement shape
# ---------------------------------------------------------------------------

class TestShape:

    def test_checkpoints(self):
        sql = _normalise(alert_guardrail_store._SQL_FETCH_CHECKPOINTS)
        assert sql.endswith(
            "FROM public.anomaly_detector_runs "
            "ORDER BY signal_path ASC, service_name ASC, operation_name ASC"
        )
        assert "WHERE" not in sql
        assert re.findall(r"%\(([a-z0-9_]+)\)s", sql) == []

    def test_uninvestigated_anomalies(self):
        sql = _normalise(alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES)
        assert sql.endswith(
            "FROM public.anomaly_events AS e WHERE NOT EXISTS ( "
            "SELECT i.investigation_id FROM public.rca_investigations AS i "
            "WHERE i.anomaly_id = e.anomaly_id ) "
            "ORDER BY e.detected_at ASC, e.anomaly_id ASC"
        )

    def test_uninvestigated_anomalies_has_no_age_or_quality_predicate(self):
        sql = alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES
        assert re.findall(r"%\(([a-z0-9_]+)\)s", sql) == []
        assert "detected_at <" not in sql and "detected_at >" not in sql
        assert "INSUFFICIENT_DATA" not in sql and "'" not in sql

    def test_alert_decisions(self):
        sql = _normalise(alert_guardrail_store._SQL_FETCH_ALERT_DECISIONS)
        assert sql.endswith(
            "FROM public.alert_decisions AS d WHERE d.decision = 'ALERT' AND ( "
            "d.evaluated_at >= %(lookback_start)s OR EXISTS ( "
            "SELECT a.attempt_id FROM public.alert_delivery_attempts AS a "
            "WHERE a.decision_id = d.decision_id "
            "AND a.started_at >= %(lookback_start)s ) ) "
            "ORDER BY d.evaluated_at ASC, d.decision_id ASC"
        )

    def test_alert_decisions_boundary_is_inclusive(self):
        sql = alert_guardrail_store._SQL_FETCH_ALERT_DECISIONS
        assert sql.count(">= %(lookback_start)s") == 2
        assert re.search(r"(evaluated_at|started_at) >(?!=)", sql) is None
        assert set(re.findall(r"%\(([a-z0-9_]+)\)s", sql)) == {"lookback_start"}

    def test_alert_decisions_has_no_version_filter_or_limit(self):
        sql = alert_guardrail_store._SQL_FETCH_ALERT_DECISIONS
        assert "policy_version" not in sql
        assert "LIMIT" not in sql.upper()
        assert "recorded_at" not in sql
        assert "SUPPRESSED" not in sql and "NOT_ALERTABLE" not in sql

    def test_delivery_history(self):
        sql = _normalise(alert_guardrail_store._SQL_FETCH_DELIVERY_HISTORY)
        assert (
            "FROM public.alert_delivery_attempts AS a "
            "LEFT JOIN public.alert_delivery_outcomes AS o "
            "ON o.attempt_id = a.attempt_id "
            "WHERE a.decision_id = ANY(%(decision_ids)s) "
            "AND a.channel_name = ANY(%(channel_names)s) "
            "ORDER BY a.decision_id ASC, a.channel_name ASC, a.attempt_no ASC"
        ) in sql
        assert set(re.findall(r"%\(([a-z0-9_]+)\)s", sql)) == {
            "decision_ids", "channel_names",
        }

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_every_statement_has_a_deterministic_order(self, name):
        assert "ORDER BY" in _ALL_SQL[name]
        assert "LIMIT" not in _ALL_SQL[name].upper()


# ---------------------------------------------------------------------------
# GS05  Functions
# ---------------------------------------------------------------------------

class TestFunctions:

    def test_fetch_checkpoints(self):
        rows = [{"signal_path": "trace_latency", "updated_at": _T0}]
        conn, cur = _make_conn(fetchall=rows)
        result = fetch_checkpoints(conn)
        assert result == rows and all(type(row) is dict for row in result)
        cur.execute.assert_called_once_with(
            alert_guardrail_store._SQL_FETCH_CHECKPOINTS, None,
        )
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_fetch_uninvestigated_anomalies(self):
        rows = [{"anomaly_id": "a" * 64, "detected_at": _T0}]
        conn, cur = _make_conn(fetchall=rows)
        assert fetch_uninvestigated_anomalies(conn) == rows
        cur.execute.assert_called_once_with(
            alert_guardrail_store._SQL_FETCH_UNINVESTIGATED_ANOMALIES, None,
        )

    def test_fetch_alert_decisions_binds_the_lookback_start(self):
        rows = [{"decision_id": _DEC, "evaluated_at": _T0}]
        conn, cur = _make_conn(fetchall=rows)
        assert fetch_alert_decisions(conn, lookback_start=_T0) == rows
        cur.execute.assert_called_once_with(
            alert_guardrail_store._SQL_FETCH_ALERT_DECISIONS,
            {"lookback_start": _T0},
        )

    def test_fetch_delivery_history_binds_lists(self):
        rows = [{"attempt_id": "a" * 64, "outcome": None, "recorded_at": None}]
        conn, cur = _make_conn(fetchall=rows)
        result = fetch_delivery_history(
            conn, decision_ids=(_DEC, "e" * 64), channel_names=("log", "hook"),
        )
        assert result == rows
        cur.execute.assert_called_once_with(
            alert_guardrail_store._SQL_FETCH_DELIVERY_HISTORY,
            {"decision_ids": [_DEC, "e" * 64], "channel_names": ["log", "hook"]},
        )

    def test_rows_are_returned_in_database_order(self):
        rows = [{"n": 2}, {"n": 1}]
        conn, _ = _make_conn(fetchall=rows)
        assert fetch_checkpoints(conn) == rows

    def test_arguments_are_keyword_only(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            fetch_alert_decisions(conn, _T0)
        with pytest.raises(TypeError):
            fetch_delivery_history(conn, [_DEC], ["log"])

    def test_checkpoint_and_anomaly_reads_take_no_filter(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            fetch_checkpoints(conn, "trace_latency")
        with pytest.raises(TypeError):
            fetch_uninvestigated_anomalies(conn, 60)

    def test_database_error_propagates(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.OperationalError("down")
        with pytest.raises(psycopg.OperationalError):
            fetch_checkpoints(conn)


# ---------------------------------------------------------------------------
# GS06  Empty inputs
# ---------------------------------------------------------------------------

class TestEmptyInputs:

    @pytest.mark.parametrize("decision_ids, channel_names", [
        ([], ["log"]),
        ([_DEC], []),
        ([], []),
        ((), ("log",)),
    ])
    def test_empty_history_input_runs_no_statement(self, decision_ids, channel_names):
        conn, cur = _make_conn()
        assert fetch_delivery_history(
            conn, decision_ids=decision_ids, channel_names=channel_names,
        ) == []
        conn.cursor.assert_not_called()
        cur.execute.assert_not_called()

    def test_no_rows(self):
        conn, _ = _make_conn(fetchall=[])
        assert fetch_checkpoints(conn) == []
        assert fetch_uninvestigated_anomalies(conn) == []
        assert fetch_alert_decisions(conn, lookback_start=_T0) == []


# ---------------------------------------------------------------------------
# GS07  Transactions, clock, environment
# ---------------------------------------------------------------------------

class TestNoSideEffects:

    def test_no_function_commits_rolls_back_or_closes(self):
        conn, _ = _make_conn(fetchall=[{"decision_id": _DEC}])
        fetch_checkpoints(conn)
        fetch_uninvestigated_anomalies(conn)
        fetch_alert_decisions(conn, lookback_start=_T0)
        fetch_delivery_history(conn, decision_ids=[_DEC], channel_names=["log"])
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    def test_source_has_no_transaction_clock_environment_or_output(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert attributes.isdisjoint({
            "commit", "rollback", "close", "autocommit", "environ", "getenv",
            "now", "utcnow", "today", "connect", "write",
        })
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert names.isdisjoint({"open", "print", "os", "sys", "time", "socket"})


# ---------------------------------------------------------------------------
# GS08  Import boundary
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
        }

    def test_public_api(self):
        public = {
            name for name, value in vars(alert_guardrail_store).items()
            if callable(value) and not name.startswith("_")
            and getattr(value, "__module__", None) == "alert_guardrail_store"
        }
        assert public == {
            "fetch_checkpoints", "fetch_uninvestigated_anomalies",
            "fetch_alert_decisions", "fetch_delivery_history",
        }

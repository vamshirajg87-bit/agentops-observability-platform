"""
alerting/tests/unit/test_alert_delivery_store.py

Unit tests for alert_delivery_store.py.

No live PostgreSQL required.  DB access is mocked.  The SQL constants are
read from the module and inspected as text, and the granted columns are read
from migration 014 on disk.

Test inventory:
    DL01  SQL shape: explicit columns, granted columns only, bound parameters
    DL02  SQL safety: no UPDATE / DELETE / TRUNCATE / SELECT * / DDL
    DL03  Discovery statements: filters and ordering
    DL04  History statements
    DL05  Insert statements: conflict targets, server defaults
    DL06  Decision functions
    DL07  History functions
    DL08  insert_attempt / insert_outcome
    DL09  Transactions: the store never commits or rolls back
    DL10  Import boundary
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

import alert_delivery_store
from alert_channels import SendResult
from alert_delivery_store import (
    fetch_alert_decisions,
    fetch_channel_history,
    fetch_decision,
    fetch_delivery_history,
    fetch_recent_alert_decisions,
    insert_attempt,
    insert_outcome,
)
from alert_models import ChannelType, DeliveryOutcome


_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "alert_delivery_store.py")
_MIGRATIONS = os.path.join(_COMPONENT_DIR, "..", "storage-consumer", "migrations")
_MIGRATION_012 = os.path.join(_MIGRATIONS, "012_create_alert_tables.sql")
_MIGRATION_014 = os.path.join(_MIGRATIONS, "014_create_alert_notifier_role.sql")

_DEC = "d" * 64
_ATT = "a" * 64
_T0 = datetime(2026, 10, 5, 19, 0, 0, tzinfo=timezone.utc)

_DECISION_SQL = {
    "fetch_alert_decisions": alert_delivery_store._SQL_FETCH_ALERT_DECISIONS,
    "fetch_recent_alert_decisions":
        alert_delivery_store._SQL_FETCH_RECENT_ALERT_DECISIONS,
    "fetch_decision": alert_delivery_store._SQL_FETCH_DECISION,
}
_HISTORY_SQL = {
    "fetch_delivery_history": alert_delivery_store._SQL_FETCH_DELIVERY_HISTORY,
    "fetch_channel_history": alert_delivery_store._SQL_FETCH_CHANNEL_HISTORY,
}
_INSERT_SQL = {
    "insert_attempt": alert_delivery_store._SQL_INSERT_ATTEMPT,
    "insert_outcome": alert_delivery_store._SQL_INSERT_OUTCOME,
}
_ALL_SQL = {**_DECISION_SQL, **_HISTORY_SQL, **_INSERT_SQL}

_DECISION_COLUMNS = [
    "decision_id", "decision", "reason_code", "policy_version", "evaluated_at",
    "payload", "summary", "summary_truncated",
]
_HISTORY_COLUMNS = [
    "a.attempt_id", "a.decision_id", "a.channel_name", "a.channel_type",
    "a.attempt_no", "a.trigger", "a.summary_included", "a.payload_sha256",
    "a.started_at", "o.outcome", "o.detail", "o.recorded_at",
]
_ATTEMPT_INSERT_COLUMNS = [
    "attempt_id", "decision_id", "channel_name", "channel_type", "attempt_no",
    "trigger", "summary_included", "payload_sha256",
]
_OUTCOME_INSERT_COLUMNS = ["attempt_id", "outcome", "detail"]


def _normalise(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _select_columns(sql: str) -> list[str]:
    match = re.search(r"SELECT\s+(.*?)\s+FROM\s", sql, re.DOTALL)
    assert match, f"SELECT ... FROM not found in: {sql!r}"
    return [c.strip() for c in match.group(1).split(",")]


def _insert_columns(sql: str) -> list[str]:
    match = re.search(r"INSERT INTO \S+ \((.*?)\) VALUES", _normalise(sql))
    assert match
    return [c.strip() for c in match.group(1).split(",")]


def _insert_values(sql: str) -> list[str]:
    match = re.search(r"VALUES \((.*?)\) ON CONFLICT", _normalise(sql))
    assert match
    return [c.strip() for c in match.group(1).split(",")]


def _migration_sql(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return "\n".join(line.split("--")[0] for line in fh.read().splitlines())


def _granted_decision_columns() -> set[str]:
    match = re.search(
        r"GRANT\s+SELECT\s*\(([^)]*)\)\s*ON\s+public\.alert_decisions\s+TO\s+alert_notifier",
        _migration_sql(_MIGRATION_014),
    )
    assert match, "column grant on alert_decisions not found in migration 014"
    columns = [c.strip() for c in match.group(1).split(",")]
    assert len(columns) == len(set(columns))
    return set(columns)


def _table_privileges(table: str) -> set[str]:
    match = re.search(
        r"GRANT\s+([A-Z, ]+?)\s+ON\s+" + re.escape(table) + r"\s+TO\s+alert_notifier",
        _migration_sql(_MIGRATION_014),
    )
    assert match, f"table grant on {table} not found in migration 014"
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


def _make_conn(fetchall=None, rowcount: int = 1):
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchall.return_value = fetchall if fetchall is not None else []
    cur.rowcount = rowcount
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def _attempt_kwargs(**overrides) -> dict:
    values = dict(
        attempt_id=_ATT, decision_id=_DEC, channel_name="hook",
        channel_type="webhook", attempt_no=2, trigger="auto",
        summary_included=True, payload_sha256="f" * 64,
    )
    values.update(overrides)
    return values


# ---------------------------------------------------------------------------
# DL01  SQL shape
# ---------------------------------------------------------------------------

class TestSqlShape:

    @pytest.mark.parametrize("name", sorted(_DECISION_SQL))
    def test_decision_columns_are_exact(self, name):
        assert _select_columns(_DECISION_SQL[name]) == _DECISION_COLUMNS

    def test_decision_columns_are_exactly_the_granted_columns(self):
        granted = _granted_decision_columns()
        assert set(_DECISION_COLUMNS) == granted
        assert len(granted) == 8

    @pytest.mark.parametrize("name", sorted(_DECISION_SQL))
    def test_no_ungranted_decision_column_is_referenced(self, name):
        ungranted = _table_columns("public.alert_decisions") - _granted_decision_columns()
        assert len(ungranted) == 12
        for column in ungranted:
            assert re.search(rf"\b{column}\b", _DECISION_SQL[name]) is None, column

    @pytest.mark.parametrize("name", sorted(_HISTORY_SQL))
    def test_history_columns_are_exact(self, name):
        assert _select_columns(_HISTORY_SQL[name]) == _HISTORY_COLUMNS

    def test_history_reads_every_attempt_and_outcome_column(self):
        attempts = {c[2:] for c in _HISTORY_COLUMNS if c.startswith("a.")}
        outcomes = {c[2:] for c in _HISTORY_COLUMNS if c.startswith("o.")}
        assert attempts == _table_columns("public.alert_delivery_attempts")
        assert outcomes | {"attempt_id"} == _table_columns(
            "public.alert_delivery_outcomes",
        )

    def test_role_may_read_and_append_the_delivery_tables(self):
        for table in ("public.alert_delivery_attempts",
                      "public.alert_delivery_outcomes"):
            assert _table_privileges(table) == {"INSERT", "SELECT"}

    def test_attempt_insert_columns(self):
        sql = alert_delivery_store._SQL_INSERT_ATTEMPT
        assert _insert_columns(sql) == _ATTEMPT_INSERT_COLUMNS
        assert set(_ATTEMPT_INSERT_COLUMNS) == (
            _table_columns("public.alert_delivery_attempts") - {"started_at"}
        )

    def test_outcome_insert_columns(self):
        sql = alert_delivery_store._SQL_INSERT_OUTCOME
        assert _insert_columns(sql) == _OUTCOME_INSERT_COLUMNS
        assert set(_OUTCOME_INSERT_COLUMNS) == (
            _table_columns("public.alert_delivery_outcomes") - {"recorded_at"}
        )

    @pytest.mark.parametrize("sql, columns", [
        (alert_delivery_store._SQL_INSERT_ATTEMPT, _ATTEMPT_INSERT_COLUMNS),
        (alert_delivery_store._SQL_INSERT_OUTCOME, _OUTCOME_INSERT_COLUMNS),
    ])
    def test_insert_values_are_named_parameters_in_column_order(self, sql, columns):
        assert _insert_values(sql) == [f"%({name})s" for name in columns]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_named_bound_parameters(self, name):
        sql = _ALL_SQL[name]
        assert "%" not in re.sub(r"%\([a-z0-9_]+\)s", "", sql)
        assert "{" not in sql and "}" not in sql and "$" not in sql

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_the_expected_literal(self, name):
        assert set(re.findall(r"'([^']*)'", _ALL_SQL[name])) <= {"ALERT"}

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_only_the_three_notifier_tables(self, name):
        tables = set(re.findall(r"(?:FROM|INTO|JOIN)\s+(public\.\S+)", _ALL_SQL[name]))
        assert tables
        assert tables <= {
            "public.alert_decisions",
            "public.alert_delivery_attempts",
            "public.alert_delivery_outcomes",
        }


# ---------------------------------------------------------------------------
# DL02  SQL safety
# ---------------------------------------------------------------------------

class TestSqlSafety:

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("word", [
        "UPDATE", "DELETE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT",
        "REVOKE", "SET ROLE", "NEXTVAL", "RETURNING", "COPY", "DO UPDATE",
    ])
    def test_forbidden_word_is_absent(self, name, word):
        assert re.search(rf"\b{word}\b", _ALL_SQL[name].upper()) is None

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_select_star_and_single_statement(self, name):
        assert "*" not in _ALL_SQL[name]
        assert ";" not in _ALL_SQL[name]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize("table", [
        "rca_investigations", "rca_evidence", "rca_investigation_embeddings",
        "telemetry_spans", "analytics.", "anomaly_events",
        "anomaly_detector_runs", "alert_policies",
    ])
    def test_out_of_scope_table_is_never_read(self, name, table):
        assert table not in _ALL_SQL[name]

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_server_clock_or_time_arithmetic(self, name):
        upper = _ALL_SQL[name].upper()
        for word in ("NOW()", "INTERVAL", "CURRENT_TIMESTAMP", "CLOCK_TIMESTAMP"):
            assert word not in upper

    def test_only_two_insert_statements_exist(self):
        inserts = sorted(n for n, sql in _ALL_SQL.items() if "INSERT" in sql.upper())
        assert inserts == ["insert_attempt", "insert_outcome"]

    def test_module_defines_no_other_statement(self):
        constants = {
            name for name in vars(alert_delivery_store) if name.startswith("_SQL_")
        }
        assert len(constants) == len(_ALL_SQL) == 7
        assert {
            getattr(alert_delivery_store, name) for name in constants
        } == set(_ALL_SQL.values())

    def test_every_execute_uses_a_module_constant(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
            ):
                first = node.args[0]
                assert isinstance(first, ast.Name)
                assert first.id == "sql" or first.id.startswith("_SQL_")
        strings = [
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", node.value)
        ]
        docstring = ast.get_docstring(tree, clean=False)
        assert set(strings) - {docstring} <= set(_ALL_SQL.values()) | {
            ast.get_docstring(node, clean=False)
            for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }


# ---------------------------------------------------------------------------
# DL03  Discovery statements
# ---------------------------------------------------------------------------

class TestDiscoveryStatements:

    def test_automatic_discovery_is_alert_only_and_unfiltered(self):
        sql = _normalise(alert_delivery_store._SQL_FETCH_ALERT_DECISIONS)
        assert sql.endswith(
            "FROM public.alert_decisions WHERE decision = 'ALERT' "
            "ORDER BY evaluated_at ASC, decision_id ASC"
        )

    def test_automatic_discovery_has_no_version_age_or_limit(self):
        sql = alert_delivery_store._SQL_FETCH_ALERT_DECISIONS
        where = _normalise(sql).split("WHERE", 1)[1].split("ORDER BY")[0].strip()
        assert where == "decision = 'ALERT'"
        assert "LIMIT" not in sql.upper()
        assert re.findall(r"%\(([a-z0-9_]+)\)s", sql) == []
        assert "policy_version =" not in sql and "evaluated_at >" not in sql
        assert "evaluated_at <" not in sql

    def test_ordering_does_not_use_the_payload(self):
        for name in ("fetch_alert_decisions", "fetch_recent_alert_decisions"):
            order = _normalise(_DECISION_SQL[name]).split("ORDER BY", 1)[1]
            assert "payload" not in order and "->" not in order
            assert "event_time" not in _DECISION_SQL[name]

    def test_list_is_newest_first_with_a_bound_limit(self):
        sql = _normalise(alert_delivery_store._SQL_FETCH_RECENT_ALERT_DECISIONS)
        assert sql.endswith(
            "WHERE decision = 'ALERT' "
            "ORDER BY evaluated_at DESC, decision_id ASC LIMIT %(limit)s"
        )
        assert re.findall(r"%\(([a-z0-9_]+)\)s", sql) == ["limit"]

    def test_single_decision_lookup_does_not_filter_the_verdict(self):
        sql = _normalise(alert_delivery_store._SQL_FETCH_DECISION)
        assert sql.endswith(
            "FROM public.alert_decisions WHERE decision_id = %(decision_id)s"
        )
        assert "'ALERT'" not in sql


# ---------------------------------------------------------------------------
# DL04  History statements
# ---------------------------------------------------------------------------

class TestHistoryStatements:

    @pytest.mark.parametrize("name", sorted(_HISTORY_SQL))
    def test_attempts_left_join_outcomes(self, name):
        sql = _normalise(_HISTORY_SQL[name])
        assert (
            "FROM public.alert_delivery_attempts AS a "
            "LEFT JOIN public.alert_delivery_outcomes AS o "
            "ON o.attempt_id = a.attempt_id WHERE"
        ) in sql
        assert "alert_decisions" not in sql

    def test_bulk_history(self):
        sql = _normalise(alert_delivery_store._SQL_FETCH_DELIVERY_HISTORY)
        assert sql.endswith(
            "WHERE a.decision_id = ANY(%(decision_ids)s) "
            "ORDER BY a.decision_id ASC, a.channel_name ASC, a.attempt_no ASC"
        )

    def test_channel_history(self):
        sql = _normalise(alert_delivery_store._SQL_FETCH_CHANNEL_HISTORY)
        assert sql.endswith(
            "WHERE a.decision_id = %(decision_id)s "
            "AND a.channel_name = %(channel_name)s ORDER BY a.attempt_no ASC"
        )

    @pytest.mark.parametrize("name", sorted(_HISTORY_SQL))
    def test_history_is_not_filtered_by_outcome_or_time(self, name):
        sql = _HISTORY_SQL[name]
        assert "o.outcome =" not in sql and "started_at >" not in sql
        assert "LIMIT" not in sql.upper()


# ---------------------------------------------------------------------------
# DL05  Insert statements
# ---------------------------------------------------------------------------

class TestInsertStatements:

    def test_attempt_conflict_target_is_the_attempt_number_key(self):
        sql = _normalise(alert_delivery_store._SQL_INSERT_ATTEMPT)
        assert sql.endswith(
            "ON CONFLICT (decision_id, channel_name, attempt_no) DO NOTHING"
        )

    def test_outcome_conflict_target_is_the_attempt(self):
        sql = _normalise(alert_delivery_store._SQL_INSERT_OUTCOME)
        assert sql.endswith("ON CONFLICT (attempt_id) DO NOTHING")

    @pytest.mark.parametrize("name", sorted(_INSERT_SQL))
    def test_never_overwrites(self, name):
        sql = _INSERT_SQL[name].upper()
        assert "DO UPDATE" not in sql and sql.count("ON CONFLICT") == 1

    def test_server_timestamps_are_not_supplied(self):
        assert "started_at" not in alert_delivery_store._SQL_INSERT_ATTEMPT
        assert "recorded_at" not in alert_delivery_store._SQL_INSERT_OUTCOME


# ---------------------------------------------------------------------------
# DL06  Decision functions
# ---------------------------------------------------------------------------

class TestDecisionFunctions:

    def test_fetch_alert_decisions(self):
        rows = [{"decision_id": "1" * 64}, {"decision_id": "2" * 64}]
        conn, cur = _make_conn(fetchall=rows)
        result = fetch_alert_decisions(conn)
        assert result == rows and all(type(row) is dict for row in result)
        cur.execute.assert_called_once_with(
            alert_delivery_store._SQL_FETCH_ALERT_DECISIONS, None,
        )
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_fetch_alert_decisions_takes_no_filter_argument(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            fetch_alert_decisions(conn, "1.0.0")

    def test_fetch_recent_alert_decisions_binds_the_limit(self):
        conn, cur = _make_conn(fetchall=[{"decision_id": _DEC}])
        assert fetch_recent_alert_decisions(conn, 50) == [{"decision_id": _DEC}]
        cur.execute.assert_called_once_with(
            alert_delivery_store._SQL_FETCH_RECENT_ALERT_DECISIONS, {"limit": 50},
        )

    def test_fetch_decision_found(self):
        row = {"decision_id": _DEC, "decision": "SUPPRESSED"}
        conn, cur = _make_conn(fetchall=[row])
        assert fetch_decision(conn, _DEC) == row
        cur.execute.assert_called_once_with(
            alert_delivery_store._SQL_FETCH_DECISION, {"decision_id": _DEC},
        )

    def test_fetch_decision_absent(self):
        conn, _ = _make_conn(fetchall=[])
        assert fetch_decision(conn, _DEC) is None


# ---------------------------------------------------------------------------
# DL07  History functions
# ---------------------------------------------------------------------------

class TestHistoryFunctions:

    def test_bulk_history_binds_a_list(self):
        rows = [{"attempt_id": _ATT, "outcome": None}]
        conn, cur = _make_conn(fetchall=rows)
        assert fetch_delivery_history(conn, (_DEC, "e" * 64)) == rows
        cur.execute.assert_called_once_with(
            alert_delivery_store._SQL_FETCH_DELIVERY_HISTORY,
            {"decision_ids": [_DEC, "e" * 64]},
        )

    def test_bulk_history_with_no_decisions_runs_no_statement(self):
        conn, cur = _make_conn()
        assert fetch_delivery_history(conn, []) == []
        conn.cursor.assert_not_called()
        cur.execute.assert_not_called()

    def test_channel_history(self):
        rows = [{"attempt_id": _ATT, "attempt_no": 1}]
        conn, cur = _make_conn(fetchall=rows)
        assert fetch_channel_history(conn, _DEC, "hook") == rows
        cur.execute.assert_called_once_with(
            alert_delivery_store._SQL_FETCH_CHANNEL_HISTORY,
            {"decision_id": _DEC, "channel_name": "hook"},
        )

    def test_rows_are_returned_in_database_order(self):
        rows = [{"attempt_no": 2}, {"attempt_no": 1}]
        conn, _ = _make_conn(fetchall=rows)
        assert fetch_channel_history(conn, _DEC, "hook") == rows


# ---------------------------------------------------------------------------
# DL08  insert_attempt / insert_outcome
# ---------------------------------------------------------------------------

class TestInserts:

    def test_attempt_inserted(self):
        conn, cur = _make_conn(rowcount=1)
        assert insert_attempt(conn, **_attempt_kwargs()) is True
        sql, params = cur.execute.call_args.args
        assert sql == alert_delivery_store._SQL_INSERT_ATTEMPT
        assert params == _attempt_kwargs()
        assert list(params) == _ATTEMPT_INSERT_COLUMNS

    def test_attempt_conflict_reports_not_inserted(self):
        conn, cur = _make_conn(rowcount=0)
        assert insert_attempt(conn, **_attempt_kwargs()) is False
        assert cur.execute.call_count == 1

    def test_attempt_arguments_are_keyword_only(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            insert_attempt(conn, *_attempt_kwargs().values())

    def test_attempt_has_no_started_at_argument(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            insert_attempt(conn, **_attempt_kwargs(), started_at=_T0)

    def test_outcome_inserted_from_a_send_result(self):
        conn, cur = _make_conn(rowcount=1)
        result = SendResult(ChannelType.WEBHOOK, DeliveryOutcome.FAILED_RETRYABLE, "http_503")
        assert insert_outcome(conn, attempt_id=_ATT, result=result) is True
        sql, params = cur.execute.call_args.args
        assert sql == alert_delivery_store._SQL_INSERT_OUTCOME
        assert params == {
            "attempt_id": _ATT, "outcome": "FAILED_RETRYABLE", "detail": "http_503",
        }
        assert type(params["outcome"]) is str

    def test_outcome_conflict_reports_not_inserted(self):
        conn, _ = _make_conn(rowcount=0)
        result = SendResult(ChannelType.LOG, DeliveryOutcome.SENT, "log_written")
        assert insert_outcome(conn, attempt_id=_ATT, result=result) is False

    @pytest.mark.parametrize("result", [
        "http_200",
        ("SENT", "http_200"),
        {"outcome": "SENT", "detail": "anything at all"},
        None,
    ])
    def test_outcome_accepts_only_a_send_result(self, result):
        conn, cur = _make_conn()
        with pytest.raises(ValueError, match="SendResult"):
            insert_outcome(conn, attempt_id=_ATT, result=result)
        conn.cursor.assert_not_called()
        cur.execute.assert_not_called()

    def test_outcome_has_no_free_text_argument(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            insert_outcome(conn, attempt_id=_ATT, outcome="SENT", detail="free text")

    def test_database_error_propagates(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.IntegrityError("violation")
        with pytest.raises(psycopg.IntegrityError):
            insert_attempt(conn, **_attempt_kwargs())


# ---------------------------------------------------------------------------
# DL09  Transactions
# ---------------------------------------------------------------------------

class TestTransactions:

    def test_no_function_commits_rolls_back_or_closes(self):
        conn, _ = _make_conn(fetchall=[{"decision_id": _DEC}])
        fetch_alert_decisions(conn)
        fetch_recent_alert_decisions(conn, 10)
        fetch_decision(conn, _DEC)
        fetch_delivery_history(conn, [_DEC])
        fetch_channel_history(conn, _DEC, "hook")
        insert_attempt(conn, **_attempt_kwargs())
        insert_outcome(
            conn, attempt_id=_ATT,
            result=SendResult(ChannelType.LOG, DeliveryOutcome.SENT, "log_written"),
        )
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    def test_source_has_no_transaction_environment_or_io_call(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            source = fh.read()
        tree = ast.parse(source)
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert attributes.isdisjoint({
            "commit", "rollback", "close", "autocommit", "environ", "getenv",
            "send", "connect",
        })
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert names.isdisjoint({"open", "print", "os", "socket"})


# ---------------------------------------------------------------------------
# DL10  Import boundary
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
            "__future__", "typing", "psycopg", "psycopg.rows", "alert_channels",
        }

    def test_public_api(self):
        public = {
            name for name, value in vars(alert_delivery_store).items()
            if callable(value) and not name.startswith("_")
            and getattr(value, "__module__", None) == "alert_delivery_store"
        }
        assert public == {
            "fetch_alert_decisions", "fetch_recent_alert_decisions",
            "fetch_decision", "fetch_delivery_history", "fetch_channel_history",
            "insert_attempt", "insert_outcome",
        }

"""
incident-retrieval/tests/unit/test_retrieval_db.py

Unit tests for retrieval_db.py.

No live PostgreSQL required.  psycopg.connect is replaced by a MagicMock, so
no connection is ever attempted.

Test inventory:
    DB01  Password is required
    DB02  Defaults
    DB03  Environment overrides
    DB04  Return value and error propagation
    DB05  Import boundary
"""

from __future__ import annotations

import ast
import os
from unittest.mock import MagicMock

import psycopg
import pytest

import retrieval_db
from retrieval_db import connect


_MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "retrieval_db.py")
)

_ENV_VARS = [
    "INCIDENT_RETRIEVAL_DB_HOST",
    "INCIDENT_RETRIEVAL_DB_PORT",
    "INCIDENT_RETRIEVAL_DB_NAME",
    "INCIDENT_RETRIEVAL_DB_USER",
    "INCIDENT_RETRIEVAL_DB_PASSWORD",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake_connect(monkeypatch) -> MagicMock:
    mock = MagicMock(return_value=MagicMock(name="connection"))
    monkeypatch.setattr(retrieval_db.psycopg, "connect", mock)
    return mock


# ---------------------------------------------------------------------------
# DB01  Password is required
# ---------------------------------------------------------------------------

class TestPasswordRequired:

    def test_missing_password_raises(self, fake_connect):
        with pytest.raises(RuntimeError, match="INCIDENT_RETRIEVAL_DB_PASSWORD"):
            connect()

    def test_empty_password_raises(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "")
        with pytest.raises(RuntimeError, match="INCIDENT_RETRIEVAL_DB_PASSWORD"):
            connect()

    def test_no_connection_attempt_without_password(self, fake_connect):
        with pytest.raises(RuntimeError):
            connect()
        fake_connect.assert_not_called()

    def test_other_variables_do_not_substitute_for_the_password(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_USER", "incident_retrieval")
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "other-role-password")
        monkeypatch.setenv("PG_PASSWORD", "admin-password")
        with pytest.raises(RuntimeError):
            connect()
        fake_connect.assert_not_called()

    def test_error_message_does_not_contain_a_password(self, fake_connect, monkeypatch):
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "s3cret-value")
        with pytest.raises(RuntimeError) as excinfo:
            connect()
        assert "s3cret-value" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# DB02  Defaults
# ---------------------------------------------------------------------------

class TestDefaults:

    def test_defaults(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        connect()
        fake_connect.assert_called_once_with(
            host="localhost",
            port=5432,
            dbname="agentops",
            user="incident_retrieval",
            password="pw",
        )

    def test_default_user_is_the_dedicated_role(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        connect()
        assert fake_connect.call_args.kwargs["user"] == "incident_retrieval"

    def test_default_port_is_an_int(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        connect()
        assert type(fake_connect.call_args.kwargs["port"]) is int

    def test_keyword_set_exact(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        connect()
        assert fake_connect.call_args.args == ()
        assert set(fake_connect.call_args.kwargs) == {"host", "port", "dbname", "user", "password"}


# ---------------------------------------------------------------------------
# DB03  Environment overrides
# ---------------------------------------------------------------------------

class TestOverrides:

    def test_all_overrides(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_HOST", "db.internal")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PORT", "6543")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_NAME", "agentops_test")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_USER", "another_role")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        connect()
        fake_connect.assert_called_once_with(
            host="db.internal",
            port=6543,
            dbname="agentops_test",
            user="another_role",
            password="pw",
        )

    @pytest.mark.parametrize(
        "variable, keyword, value, expected",
        [
            ("INCIDENT_RETRIEVAL_DB_HOST", "host", "10.0.0.5", "10.0.0.5"),
            ("INCIDENT_RETRIEVAL_DB_PORT", "port", "15432", 15432),
            ("INCIDENT_RETRIEVAL_DB_NAME", "dbname", "other", "other"),
            ("INCIDENT_RETRIEVAL_DB_USER", "user", "someone", "someone"),
        ],
    )
    def test_each_override_alone(self, fake_connect, monkeypatch, variable, keyword, value, expected):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        monkeypatch.setenv(variable, value)
        connect()
        assert fake_connect.call_args.kwargs[keyword] == expected

    def test_port_is_parsed_as_int(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PORT", "6543")
        connect()
        assert fake_connect.call_args.kwargs["port"] == 6543
        assert type(fake_connect.call_args.kwargs["port"]) is int

    def test_non_numeric_port_raises_before_connecting(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PORT", "not-a-port")
        with pytest.raises(ValueError):
            connect()
        fake_connect.assert_not_called()

    def test_password_passed_through_unchanged(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", " p@ss word'\"\\ ")
        connect()
        assert fake_connect.call_args.kwargs["password"] == " p@ss word'\"\\ "

    @pytest.mark.parametrize(
        "foreign",
        ["RCA_ANALYZER_DB_HOST", "ANOMALY_DETECTOR_DB_HOST", "TRACE_VIEWER_DB_HOST", "PG_HOST"],
    )
    def test_other_components_variables_are_ignored(self, fake_connect, monkeypatch, foreign):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        monkeypatch.setenv(foreign, "elsewhere")
        connect()
        assert fake_connect.call_args.kwargs["host"] == "localhost"


# ---------------------------------------------------------------------------
# DB04  Return value and errors
# ---------------------------------------------------------------------------

class TestReturnAndErrors:

    def test_returns_the_psycopg_connection(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        assert connect() is fake_connect.return_value

    def test_connection_is_not_closed_or_committed(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        conn = connect()
        conn.close.assert_not_called()
        conn.commit.assert_not_called()

    def test_each_call_opens_a_new_connection(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        connect()
        connect()
        assert fake_connect.call_count == 2

    def test_operational_error_propagates(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        fake_connect.side_effect = psycopg.OperationalError("connection refused")
        with pytest.raises(psycopg.OperationalError):
            connect()

    def test_environment_read_at_call_time(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "first")
        connect()
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "second")
        connect()
        assert [c.kwargs["password"] for c in fake_connect.call_args_list] == ["first", "second"]


# ---------------------------------------------------------------------------
# DB05  Import boundary
# ---------------------------------------------------------------------------

class TestImportBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(retrieval_db.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add((node.module or "").split(".")[0])
        assert modules == {"__future__", "os", "psycopg"}

    def test_module_contains_no_sql_and_no_password_literal(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"execute", "cursor", "commit", "rollback"})
        defaults = [
            node.args[1].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get" and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
        ]
        assert sorted(defaults) == ["5432", "agentops", "incident_retrieval", "localhost"]

    def test_database_error_is_the_driver_base_error(self):
        """Callers catch database errors through this name without importing the driver."""
        assert retrieval_db.DatabaseError is psycopg.Error

    @pytest.mark.parametrize(
        "error_type",
        [psycopg.OperationalError, psycopg.DatabaseError, psycopg.InterfaceError,
         psycopg.ProgrammingError, psycopg.IntegrityError, psycopg.DataError],
    )
    def test_database_error_catches_every_driver_error(self, error_type):
        assert issubclass(error_type, retrieval_db.DatabaseError)
        with pytest.raises(retrieval_db.DatabaseError):
            raise error_type("boom")

    def test_database_error_does_not_catch_unrelated_errors(self):
        for unrelated in (RuntimeError, ValueError, KeyError, OSError):
            assert not issubclass(unrelated, retrieval_db.DatabaseError)

    def test_connect_error_is_catchable_through_the_alias(self, fake_connect, monkeypatch):
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_PASSWORD", "pw")
        fake_connect.side_effect = psycopg.OperationalError("connection refused")
        with pytest.raises(retrieval_db.DatabaseError):
            connect()

    def test_missing_password_is_not_a_database_error(self, fake_connect):
        with pytest.raises(RuntimeError) as excinfo:
            connect()
        assert not isinstance(excinfo.value, retrieval_db.DatabaseError)

    def test_public_names(self):
        public = {name for name in vars(retrieval_db) if not name.startswith("_")}
        assert public == {"annotations", "os", "psycopg", "DatabaseError", "connect"}

    def test_only_environment_variables_with_the_component_prefix(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        names = [
            node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get" and node.args
            and isinstance(node.args[0], ast.Constant)
        ]
        assert sorted(names) == sorted(_ENV_VARS)

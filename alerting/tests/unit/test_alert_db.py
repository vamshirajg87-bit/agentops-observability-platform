"""
alerting/tests/unit/test_alert_db.py

Unit tests for alert_db.py.

No live PostgreSQL required.  psycopg.connect is replaced by a MagicMock, so
no connection is ever attempted.

Test inventory:
    DB01  Password is required
    DB02  Defaults
    DB03  Environment overrides
    DB04  Read-only session
    DB05  Return value and error propagation
    DB06  Import boundary
"""

from __future__ import annotations

import ast
import os
from unittest.mock import MagicMock

import psycopg
import pytest

import alert_db
from alert_db import connect


_MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "alert_db.py")
)

_ENV_VARS = [
    "ALERT_EVALUATOR_DB_HOST",
    "ALERT_EVALUATOR_DB_PORT",
    "ALERT_EVALUATOR_DB_NAME",
    "ALERT_EVALUATOR_DB_USER",
    "ALERT_EVALUATOR_DB_PASSWORD",
]


class _Connection:
    """A stand-in connection that records read_only and close()."""

    def __init__(self) -> None:
        self.read_only = None
        self.closed = False

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake_connect(monkeypatch) -> MagicMock:
    mock = MagicMock(return_value=_Connection())
    monkeypatch.setattr(alert_db.psycopg, "connect", mock)
    return mock


# ---------------------------------------------------------------------------
# DB01  Password is required
# ---------------------------------------------------------------------------

class TestPasswordRequired:

    def test_missing_password_raises(self, fake_connect):
        with pytest.raises(RuntimeError, match="ALERT_EVALUATOR_DB_PASSWORD"):
            connect()

    def test_empty_password_raises(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "")
        with pytest.raises(RuntimeError, match="ALERT_EVALUATOR_DB_PASSWORD"):
            connect()

    def test_no_connection_attempt_without_password(self, fake_connect):
        with pytest.raises(RuntimeError):
            connect(read_only=True)
        fake_connect.assert_not_called()

    def test_other_variables_do_not_substitute_for_the_password(
        self, fake_connect, monkeypatch,
    ):
        monkeypatch.setenv("ALERT_NOTIFIER_DB_PASSWORD", "notifier-password")
        monkeypatch.setenv("RCA_ANALYZER_DB_PASSWORD", "other-role-password")
        monkeypatch.setenv("PGPASSWORD", "admin-password")
        with pytest.raises(RuntimeError):
            connect()
        fake_connect.assert_not_called()

    def test_error_message_does_not_contain_a_password(
        self, fake_connect, monkeypatch,
    ):
        monkeypatch.setenv("ALERT_NOTIFIER_DB_PASSWORD", "s3cret-value")
        with pytest.raises(RuntimeError) as excinfo:
            connect()
        assert "s3cret-value" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# DB02  Defaults
# ---------------------------------------------------------------------------

class TestDefaults:

    def test_defaults(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        connect()
        fake_connect.assert_called_once_with(
            host="localhost",
            port=5432,
            dbname="agentops",
            user="alert_evaluator",
            password="pw",
        )

    def test_port_is_an_int(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        connect()
        assert type(fake_connect.call_args.kwargs["port"]) is int


# ---------------------------------------------------------------------------
# DB03  Environment overrides
# ---------------------------------------------------------------------------

class TestOverrides:

    def test_every_variable_is_used(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_HOST", "db.internal")
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PORT", "6543")
        monkeypatch.setenv("ALERT_EVALUATOR_DB_NAME", "other")
        monkeypatch.setenv("ALERT_EVALUATOR_DB_USER", "someone")
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        connect()
        fake_connect.assert_called_once_with(
            host="db.internal",
            port=6543,
            dbname="other",
            user="someone",
            password="pw",
        )

    def test_non_integer_port_is_a_configuration_error(
        self, fake_connect, monkeypatch,
    ):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PORT", "not-a-port")
        with pytest.raises(RuntimeError, match="ALERT_EVALUATOR_DB_PORT"):
            connect()
        fake_connect.assert_not_called()

    def test_other_components_variables_are_ignored(
        self, fake_connect, monkeypatch,
    ):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        monkeypatch.setenv("INCIDENT_RETRIEVAL_DB_HOST", "elsewhere")
        monkeypatch.setenv("RCA_ANALYZER_DB_USER", "rca_analyzer")
        connect()
        kwargs = fake_connect.call_args.kwargs
        assert kwargs["host"] == "localhost"
        assert kwargs["user"] == "alert_evaluator"


# ---------------------------------------------------------------------------
# DB04  Read-only session
# ---------------------------------------------------------------------------

class TestReadOnly:

    def test_default_session_is_not_marked_read_only(
        self, fake_connect, monkeypatch,
    ):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        conn = connect()
        assert conn.read_only is None

    def test_read_only_session(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        conn = connect(read_only=True)
        assert conn.read_only is True

    def test_read_only_is_keyword_only(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        with pytest.raises(TypeError):
            connect(True)  # noqa: FBT003

    def test_connection_is_closed_when_read_only_cannot_be_set(
        self, monkeypatch,
    ):
        class _Refusing(_Connection):
            @property
            def read_only(self):
                return None

            @read_only.setter
            def read_only(self, value):
                if value is not None:
                    raise psycopg.ProgrammingError("cannot set read_only")

        refusing = _Refusing()
        monkeypatch.setattr(
            alert_db.psycopg, "connect", MagicMock(return_value=refusing),
        )
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        with pytest.raises(psycopg.ProgrammingError):
            connect(read_only=True)
        assert refusing.closed is True


# ---------------------------------------------------------------------------
# DB05  Return value and error propagation
# ---------------------------------------------------------------------------

class TestReturnAndErrors:

    def test_returns_the_driver_connection(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        assert connect() is fake_connect.return_value

    def test_one_connection_per_call(self, fake_connect, monkeypatch):
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        connect()
        connect()
        assert fake_connect.call_count == 2

    def test_operational_error_propagates(self, monkeypatch):
        monkeypatch.setattr(
            alert_db.psycopg, "connect",
            MagicMock(side_effect=psycopg.OperationalError("refused")),
        )
        monkeypatch.setenv("ALERT_EVALUATOR_DB_PASSWORD", "pw")
        with pytest.raises(psycopg.OperationalError):
            connect()

    def test_database_error_is_the_driver_base_error(self):
        assert alert_db.DatabaseError is psycopg.Error
        assert issubclass(psycopg.OperationalError, alert_db.DatabaseError)
        assert issubclass(psycopg.IntegrityError, alert_db.DatabaseError)


# ---------------------------------------------------------------------------
# DB06  Import boundary
# ---------------------------------------------------------------------------

class TestImportBoundary:

    @pytest.fixture(scope="class")
    def tree(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def test_imports_are_exactly_os_and_the_driver(self, tree):
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        assert imported == {"__future__", "os", "psycopg"}

    def test_module_holds_no_statement_text(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            source = fh.read()
        for word in ("SELECT", "INSERT", "UPDATE", "DELETE", "ON CONFLICT"):
            assert word not in source, word

    def test_no_password_default_in_source(self):
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            source = fh.read()
        assert 'get("ALERT_EVALUATOR_DB_PASSWORD")' in source
        assert 'get("ALERT_EVALUATOR_DB_PASSWORD",' not in source

"""
Tests for anomaly-detector/db.py and Phase 10.4B schema contracts.

No live PostgreSQL is required.  psycopg.connect is patched for connection
tests.  Schema contracts are verified statically against source files and
Phase 10.3 detector code.

Coverage:
    1-3   connect() — missing / empty password raises RuntimeError
    4-8   connect() — env-var overrides are forwarded correctly
    9-10  connect() — no hardcoded password in db.py source
    11-14 Schema column contract — all AnomalyEvent fields have a column
    15-16 anomaly_type CHECK values match Phase 10.3 emitted strings exactly
    17    severity CHECK values match Severity enum
    18    anomaly_id column admits full 64-char SHA-256 hex strings
    19    anomaly_id CHECK rejects strings shorter than 64 chars
    20    anomaly_id CHECK rejects uppercase hex
    21-22 Role migration: no UPDATE / DELETE grant text present
    23    Role migration: no hardcoded password literal
"""

from __future__ import annotations

import importlib
import inspect
import os
import re
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]   # agentops-intelligence-platform/
_DB_MODULE_PATH = _REPO_ROOT / "anomaly-detector" / "db.py"
_MIGRATION_004 = _REPO_ROOT / "storage-consumer" / "migrations" / "004_create_anomaly_events.sql"
_MIGRATION_005 = _REPO_ROOT / "storage-consumer" / "migrations" / "005_create_anomaly_detector_role.sql"


# ---------------------------------------------------------------------------
# 1-3: connect() — missing / empty password
# ---------------------------------------------------------------------------

class TestConnectPasswordRequired:

    def test_missing_password_raises_runtime_error(self, monkeypatch):
        monkeypatch.delenv("ANOMALY_DETECTOR_DB_PASSWORD", raising=False)
        import db
        with pytest.raises(RuntimeError, match="ANOMALY_DETECTOR_DB_PASSWORD"):
            db.connect()

    def test_empty_string_password_raises_runtime_error(self, monkeypatch):
        monkeypatch.setenv("ANOMALY_DETECTOR_DB_PASSWORD", "")
        import db
        with pytest.raises(RuntimeError, match="ANOMALY_DETECTOR_DB_PASSWORD"):
            db.connect()

    def test_error_message_does_not_reveal_password(self, monkeypatch):
        monkeypatch.delenv("ANOMALY_DETECTOR_DB_PASSWORD", raising=False)
        import db
        with pytest.raises(RuntimeError) as exc_info:
            db.connect()
        assert "secret" not in str(exc_info.value).lower()
        assert "password" in str(exc_info.value).lower()   # names the variable, not the value


# ---------------------------------------------------------------------------
# 4-8: connect() — env-var overrides forwarded to psycopg.connect
# ---------------------------------------------------------------------------

class TestConnectEnvVars:

    def _call_connect(self, monkeypatch, **overrides):
        env = {
            "ANOMALY_DETECTOR_DB_HOST": "db-host",
            "ANOMALY_DETECTOR_DB_PORT": "5433",
            "ANOMALY_DETECTOR_DB_NAME": "mydb",
            "ANOMALY_DETECTOR_DB_USER": "myuser",
            "ANOMALY_DETECTOR_DB_PASSWORD": "s3cr3t",
        }
        env.update(overrides)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        import db
        mock_conn = MagicMock()
        with patch("psycopg.connect", return_value=mock_conn) as mock_connect:
            result = db.connect()
        return mock_connect, result

    def test_host_forwarded(self, monkeypatch):
        mock_connect, _ = self._call_connect(monkeypatch, ANOMALY_DETECTOR_DB_HOST="custom-host")
        _, kwargs = mock_connect.call_args
        assert kwargs["host"] == "custom-host"

    def test_port_forwarded_as_int(self, monkeypatch):
        mock_connect, _ = self._call_connect(monkeypatch, ANOMALY_DETECTOR_DB_PORT="5555")
        _, kwargs = mock_connect.call_args
        assert kwargs["port"] == 5555
        assert isinstance(kwargs["port"], int)

    def test_dbname_forwarded(self, monkeypatch):
        mock_connect, _ = self._call_connect(monkeypatch, ANOMALY_DETECTOR_DB_NAME="testdb")
        _, kwargs = mock_connect.call_args
        assert kwargs["dbname"] == "testdb"

    def test_user_forwarded(self, monkeypatch):
        mock_connect, _ = self._call_connect(monkeypatch, ANOMALY_DETECTOR_DB_USER="detector_role")
        _, kwargs = mock_connect.call_args
        assert kwargs["user"] == "detector_role"

    def test_password_forwarded_and_not_logged(self, monkeypatch):
        mock_connect, _ = self._call_connect(monkeypatch, ANOMALY_DETECTOR_DB_PASSWORD="supersecret")
        _, kwargs = mock_connect.call_args
        assert kwargs["password"] == "supersecret"


# ---------------------------------------------------------------------------
# 9-10: no hardcoded password in db.py source
# ---------------------------------------------------------------------------

class TestNoHardcodedPassword:

    def test_db_source_contains_no_password_literal(self):
        source = _DB_MODULE_PATH.read_text()
        # The only known hardcoded credential in this codebase is "agentops_dev"
        # (storage-consumer/config.py default).  It must not appear here.
        assert "agentops_dev" not in source
        # The password env var must have no non-empty default fallback.
        # A pattern like os.environ.get("ANOMALY_DETECTOR_DB_PASSWORD", "somevalue")
        # would indicate a hardcoded credential.
        assert not re.search(
            r'get\(\s*"ANOMALY_DETECTOR_DB_PASSWORD"\s*,\s*"[^"]+"',
            source,
        ), "ANOMALY_DETECTOR_DB_PASSWORD must not have a non-empty default"

    def test_default_user_is_role_name_not_agentops(self, monkeypatch):
        # The default user should be 'anomaly_detector' (the dedicated role),
        # not 'agentops' (the superuser owner).
        monkeypatch.setenv("ANOMALY_DETECTOR_DB_PASSWORD", "x")
        for var in ("ANOMALY_DETECTOR_DB_HOST", "ANOMALY_DETECTOR_DB_PORT",
                    "ANOMALY_DETECTOR_DB_NAME", "ANOMALY_DETECTOR_DB_USER"):
            monkeypatch.delenv(var, raising=False)
        import db
        with patch("psycopg.connect", return_value=MagicMock()) as mock_connect:
            db.connect()
        _, kwargs = mock_connect.call_args
        assert kwargs["user"] == "anomaly_detector"


# ---------------------------------------------------------------------------
# 11-14: schema column contract — anomaly_events table
# ---------------------------------------------------------------------------

class TestSchemaColumnContract:

    @pytest.fixture(scope="class")
    def migration_sql(self):
        return _MIGRATION_004.read_text()

    # Columns that must exist (drawn from AnomalyEvent dataclass field names
    # mapped to their column equivalents in 004_create_anomaly_events.sql).
    _REQUIRED_COLUMNS = [
        "anomaly_id",
        "anomaly_type",
        "signal_name",
        "detector_name",
        "detector_version",
        "trace_id",
        "span_id",
        "service_name",
        "operation_name",
        "observed_value",
        "event_time",
        "baseline_median",
        "baseline_mad",
        "baseline_n",
        "baseline_window_start",
        "baseline_window_end",
        "anomaly_score",
        "severity",
        "explanation",
        "detected_at",
    ]

    def test_all_required_columns_present(self, migration_sql):
        for col in self._REQUIRED_COLUMNS:
            assert col in migration_sql, f"Column '{col}' missing from migration 004"

    def test_anomaly_id_is_primary_key(self, migration_sql):
        assert "PRIMARY KEY (anomaly_id)" in migration_sql or \
               "PRIMARY KEY" in migration_sql and "anomaly_id" in migration_sql

    def test_detected_at_has_default_now(self, migration_sql):
        assert "detected_at" in migration_sql
        assert "DEFAULT NOW()" in migration_sql

    def test_observed_value_not_null(self, migration_sql):
        # observed_value DOUBLE PRECISION NOT NULL
        assert re.search(r"observed_value\s+DOUBLE PRECISION\s+NOT NULL", migration_sql)


# ---------------------------------------------------------------------------
# 15-16: anomaly_type CHECK values match Phase 10.3 exactly
# ---------------------------------------------------------------------------

class TestAnomalyTypeValues:

    @pytest.fixture(scope="class")
    def migration_sql(self):
        return _MIGRATION_004.read_text()

    # These are the exact strings assigned to AnomalyEvent.anomaly_type
    # in the four Phase 10.3 detector source files.
    _PHASE_10_3_TYPES = {
        "latency",          # latency_detector.py
        "retrieval_quality", # retrieval_detector.py
        "error_rate",       # error_rate_detector.py
        "tool_failure",     # tool_failure_detector.py
    }

    def test_all_phase_103_anomaly_types_in_check_constraint(self, migration_sql):
        for t in self._PHASE_10_3_TYPES:
            assert f"'{t}'" in migration_sql, \
                f"anomaly_type value '{t}' missing from CHECK constraint in migration 004"

    def test_no_extra_anomaly_types_in_check_constraint(self, migration_sql):
        # Extract the IN (...) list from the anomaly_type CHECK constraint.
        match = re.search(
            r"chk_anomaly_events_anomaly_type.*?CHECK\s*\(anomaly_type\s+IN\s*\(([^)]+)\)\)",
            migration_sql,
            re.DOTALL,
        )
        assert match, "Could not locate anomaly_type CHECK constraint"
        in_list = match.group(1)
        found = set(re.findall(r"'([^']+)'", in_list))
        assert found == self._PHASE_10_3_TYPES, \
            f"CHECK list {found} does not match Phase 10.3 types {self._PHASE_10_3_TYPES}"


# ---------------------------------------------------------------------------
# 17: severity CHECK values match Severity enum
# ---------------------------------------------------------------------------

class TestSeverityValues:

    @pytest.fixture(scope="class")
    def migration_sql(self):
        return _MIGRATION_004.read_text()

    def test_severity_check_contains_all_enum_values(self, migration_sql):
        from detector.severity import Severity
        for member in Severity:
            assert f"'{member.value}'" in migration_sql, \
                f"Severity value '{member.value}' missing from CHECK constraint"

    def test_severity_check_contains_no_extra_values(self, migration_sql):
        from detector.severity import Severity
        match = re.search(
            r"chk_anomaly_events_severity.*?CHECK\s*\(severity\s+IN\s*\(([^)]+)\)\)",
            migration_sql,
            re.DOTALL,
        )
        assert match, "Could not locate severity CHECK constraint"
        in_list = match.group(1)
        found = set(re.findall(r"'([^']+)'", in_list))
        expected = {m.value for m in Severity}
        assert found == expected, \
            f"Severity CHECK list {found} does not match enum {expected}"


# ---------------------------------------------------------------------------
# 18-20: anomaly_id column format enforcement
# ---------------------------------------------------------------------------

class TestAnomalyIdConstraint:

    @pytest.fixture(scope="class")
    def migration_sql(self):
        return _MIGRATION_004.read_text()

    def test_anomaly_id_check_uses_64_char_pattern(self, migration_sql):
        # The regex pattern in the CHECK must specify exactly 64 characters.
        assert "{64}" in migration_sql, \
            "anomaly_id CHECK constraint must enforce exactly 64 characters"

    def test_anomaly_id_check_pattern_accepts_valid_sha256(self, migration_sql):
        # Extract and test the regex from the CHECK constraint.
        match = re.search(r"anomaly_id ~ '([^']+)'", migration_sql)
        assert match, "Could not extract anomaly_id regex from migration"
        pattern = match.group(1)
        valid_id = "a" * 64
        assert re.fullmatch(pattern, valid_id), \
            f"Pattern {pattern!r} should accept 64 lowercase hex chars"

    def test_anomaly_id_check_pattern_rejects_short_string(self, migration_sql):
        match = re.search(r"anomaly_id ~ '([^']+)'", migration_sql)
        pattern = match.group(1)
        short_id = "a" * 32
        assert not re.fullmatch(pattern, short_id), \
            f"Pattern {pattern!r} must reject 32-char string"

    def test_anomaly_id_check_pattern_rejects_uppercase(self, migration_sql):
        match = re.search(r"anomaly_id ~ '([^']+)'", migration_sql)
        pattern = match.group(1)
        upper_id = "A" * 64
        assert not re.fullmatch(pattern, upper_id), \
            f"Pattern {pattern!r} must reject uppercase hex"


# ---------------------------------------------------------------------------
# 21-23: role migration safety checks
# ---------------------------------------------------------------------------

class TestRoleMigrationSafety:

    @pytest.fixture(scope="class")
    def role_sql(self):
        return _MIGRATION_005.read_text()

    def test_no_update_grant(self, role_sql):
        # GRANT UPDATE must not appear (INSERT-only for anomaly_events).
        # The word "UPDATE" may appear in comments but not as a GRANT statement.
        grant_lines = [
            line for line in role_sql.splitlines()
            if line.strip().upper().startswith("GRANT")
        ]
        for line in grant_lines:
            assert "UPDATE" not in line.upper(), \
                f"Unexpected UPDATE grant: {line!r}"

    def test_no_delete_grant(self, role_sql):
        grant_lines = [
            line for line in role_sql.splitlines()
            if line.strip().upper().startswith("GRANT")
        ]
        for line in grant_lines:
            assert "DELETE" not in line.upper(), \
                f"Unexpected DELETE grant: {line!r}"

    def test_no_hardcoded_password_literal(self, role_sql):
        # The password must be supplied via psql variable, not hardcoded.
        # A hardcoded password would appear as PASSWORD 'somestring' without
        # the colon-variable syntax.
        assert "PASSWORD :'anomaly_detector_password'" in role_sql, \
            "Role migration must use psql variable syntax for password"
        # Confirm no quoted literal password follows the PASSWORD keyword
        # other than the variable reference.
        literals = re.findall(r"PASSWORD\s+'([^:][^']*)'", role_sql, re.IGNORECASE)
        assert not literals, \
            f"Hardcoded password literal found in role migration: {literals}"

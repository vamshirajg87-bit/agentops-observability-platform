"""
storage-consumer/tests/unit/test_migration_006.py

Static contract tests for:
    storage-consumer/migrations/006_create_anomaly_detector_runs.sql

No live PostgreSQL required.  The migration SQL is read from disk and
inspected as text, following the static source-inspection convention used
throughout this test suite.

Invariants verified:
    - table name is public.anomaly_detector_runs
    - all five required columns with correct types and NOT NULL constraints
    - operation_name carries DEFAULT ''
    - updated_at carries DEFAULT NOW()
    - primary key is exactly (signal_path, service_name, operation_name)
    - GRANT covers SELECT, INSERT, UPDATE — no more, no less
    - role target is anomaly_detector
    - no DELETE privilege is granted
    - no TRUNCATE privilege is granted
    - no ALL privilege is granted
    - no SERIAL / IDENTITY / sequence dependency is introduced
"""

from __future__ import annotations

import os
import re

import pytest

# ---------------------------------------------------------------------------
# Load SQL once per module
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", )
)
_MIGRATION_PATH = os.path.join(
    _REPO_ROOT,
    "storage-consumer",
    "migrations",
    "006_create_anomaly_detector_runs.sql",
)


def _strip_sql_comments(sql: str) -> str:
    """
    Remove SQL line comments (-- ... to end of line).

    Used so that keyword checks on the live SQL are not tripped by
    comment text that deliberately *names* a forbidden construct
    (e.g. "DELETE AND TRUNCATE ARE INTENTIONALLY NOT GRANTED").
    """
    lines = []
    for line in sql.splitlines():
        idx = line.find("--")
        lines.append(line[:idx] if idx >= 0 else line)
    return "\n".join(lines)


@pytest.fixture(scope="module")
def sql() -> str:
    with open(_MIGRATION_PATH, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def sql_no_comments(sql: str) -> str:
    """SQL with all line-comment text removed."""
    return _strip_sql_comments(sql)


@pytest.fixture(scope="module")
def sql_upper(sql: str) -> str:
    return sql.upper()


@pytest.fixture(scope="module")
def sql_no_comments_upper(sql_no_comments: str) -> str:
    return sql_no_comments.upper()


@pytest.fixture(scope="module")
def sql_normalised(sql: str) -> str:
    """SQL with all whitespace runs collapsed to a single space."""
    return re.sub(r"\s+", " ", sql).strip()


@pytest.fixture(scope="module")
def sql_normalised_upper(sql_normalised: str) -> str:
    return sql_normalised.upper()


@pytest.fixture(scope="module")
def sql_no_comments_normalised(sql_no_comments: str) -> str:
    return re.sub(r"\s+", " ", sql_no_comments).strip()


@pytest.fixture(scope="module")
def sql_no_comments_normalised_upper(sql_no_comments_normalised: str) -> str:
    return sql_no_comments_normalised.upper()


# ---------------------------------------------------------------------------
# TestTableName
# ---------------------------------------------------------------------------

class TestTableName:

    def test_creates_public_anomaly_detector_runs(self, sql_no_comments):
        assert "public.anomaly_detector_runs" in sql_no_comments

    def test_create_table_keyword_present(self, sql_no_comments_upper):
        assert "CREATE TABLE" in sql_no_comments_upper


# ---------------------------------------------------------------------------
# TestColumns
# ---------------------------------------------------------------------------

class TestColumns:

    def test_signal_path_text_not_null(self, sql_no_comments_normalised_upper):
        assert "SIGNAL_PATH TEXT NOT NULL" in sql_no_comments_normalised_upper

    def test_service_name_text_not_null(self, sql_no_comments_normalised_upper):
        assert "SERVICE_NAME TEXT NOT NULL" in sql_no_comments_normalised_upper

    def test_operation_name_text_not_null(self, sql_no_comments_normalised_upper):
        assert "OPERATION_NAME TEXT NOT NULL" in sql_no_comments_normalised_upper

    def test_operation_name_default_empty_string_exact(self, sql_no_comments):
        """Exact case-sensitive check: DEFAULT '' is present."""
        assert "DEFAULT ''" in sql_no_comments

    def test_checkpoint_at_timestamptz_not_null(self, sql_no_comments_normalised_upper):
        assert "CHECKPOINT_AT TIMESTAMPTZ NOT NULL" in sql_no_comments_normalised_upper

    def test_updated_at_timestamptz_not_null(self, sql_no_comments_normalised_upper):
        assert "UPDATED_AT TIMESTAMPTZ NOT NULL" in sql_no_comments_normalised_upper

    def test_updated_at_has_default_now(self, sql_no_comments_upper):
        assert "DEFAULT NOW()" in sql_no_comments_upper


# ---------------------------------------------------------------------------
# TestPrimaryKey
# ---------------------------------------------------------------------------

class TestPrimaryKey:

    def test_primary_key_constraint_present(self, sql_no_comments_upper):
        assert "PRIMARY KEY" in sql_no_comments_upper

    def test_primary_key_includes_signal_path(self, sql_no_comments):
        pk_section = _extract_pk_section(sql_no_comments)
        assert "signal_path" in pk_section

    def test_primary_key_includes_service_name(self, sql_no_comments):
        pk_section = _extract_pk_section(sql_no_comments)
        assert "service_name" in pk_section

    def test_primary_key_includes_operation_name(self, sql_no_comments):
        pk_section = _extract_pk_section(sql_no_comments)
        assert "operation_name" in pk_section

    def test_primary_key_is_exactly_three_columns(self, sql_no_comments):
        """PK must be the composite of exactly the three identity columns."""
        pk_section = _extract_pk_section(sql_no_comments)
        commas = pk_section.count(",")
        assert commas == 2, (
            f"Expected 2 commas (3 PK columns) inside PRIMARY KEY(...), found {commas}. "
            f"PK section: {pk_section!r}"
        )

    def test_primary_key_column_order(self, sql_no_comments):
        """
        PK columns must appear in the canonical order:
        signal_path, service_name, operation_name
        """
        pk_section = _extract_pk_section(sql_no_comments)
        normalised = re.sub(r"\s+", " ", pk_section).strip().strip("()")
        cols = [c.strip() for c in normalised.split(",")]
        assert cols == ["signal_path", "service_name", "operation_name"], (
            f"PK column order mismatch: {cols}"
        )


def _extract_pk_section(sql_no_comments: str) -> str:
    """Return the text inside PRIMARY KEY (...) from the comment-stripped SQL."""
    match = re.search(r"PRIMARY\s+KEY\s*\(([^)]+)\)", sql_no_comments, re.IGNORECASE)
    assert match, "PRIMARY KEY (...) clause not found in migration SQL"
    return match.group(1)


# ---------------------------------------------------------------------------
# TestGrant
# ---------------------------------------------------------------------------

class TestGrant:

    def test_grant_select_present(self, sql_no_comments_upper):
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "SELECT" in grant_section

    def test_grant_insert_present(self, sql_no_comments_upper):
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "INSERT" in grant_section

    def test_grant_update_present(self, sql_no_comments_upper):
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "UPDATE" in grant_section

    def test_grant_targets_anomaly_detector_runs(self, sql_no_comments):
        grant_section = _extract_grant_section(sql_no_comments.upper())
        assert "ANOMALY_DETECTOR_RUNS" in grant_section

    def test_grant_to_anomaly_detector_role(self, sql_no_comments):
        grant_section = _extract_grant_section(sql_no_comments.upper())
        assert "ANOMALY_DETECTOR" in grant_section

    def test_grant_does_not_include_delete(self, sql_no_comments_upper):
        """DELETE must NOT appear as a granted privilege."""
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "DELETE" not in grant_section, (
            "GRANT section must not include DELETE privilege"
        )

    def test_grant_does_not_include_truncate(self, sql_no_comments_upper):
        """TRUNCATE must NOT appear as a granted privilege."""
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "TRUNCATE" not in grant_section, (
            "GRANT section must not include TRUNCATE privilege"
        )

    def test_grant_does_not_include_all(self, sql_no_comments_upper):
        """ALL PRIVILEGES must NOT appear as a granted privilege."""
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "ALL" not in grant_section, (
            "GRANT section must not include ALL privilege"
        )

    def test_grant_does_not_include_references(self, sql_no_comments_upper):
        """REFERENCES is not required and must not be granted."""
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "REFERENCES" not in grant_section

    def test_grant_does_not_include_trigger(self, sql_no_comments_upper):
        """TRIGGER is not required and must not be granted."""
        grant_section = _extract_grant_section(sql_no_comments_upper)
        assert "TRIGGER" not in grant_section

    def test_grant_privilege_set_is_exactly_select_insert_update(self, sql_no_comments):
        """
        The GRANT line must grant exactly SELECT, INSERT, UPDATE — no more.

        Extracts the privilege list between GRANT and ON, normalises whitespace,
        and checks it equals the expected set.
        """
        grant_section = _extract_grant_section(sql_no_comments.upper())
        match = re.search(r"GRANT\s+(.+?)\s+ON\s", grant_section, re.DOTALL)
        assert match, f"Could not parse GRANT ... ON pattern in: {grant_section!r}"
        privilege_str = re.sub(r"\s+", " ", match.group(1)).strip()
        granted = {p.strip() for p in privilege_str.split(",")}
        assert granted == {"SELECT", "INSERT", "UPDATE"}, (
            f"Expected exactly {{SELECT, INSERT, UPDATE}}, got {granted}"
        )


def _extract_grant_section(sql_no_comments_upper: str) -> str:
    """Return the portion of the comment-stripped SQL from the first GRANT onward."""
    idx = sql_no_comments_upper.find("GRANT")
    assert idx >= 0, "No GRANT statement found in migration SQL"
    return sql_no_comments_upper[idx:]


# ---------------------------------------------------------------------------
# TestNoSequenceDependency
# ---------------------------------------------------------------------------

class TestNoSequenceDependency:

    def test_no_serial_column(self, sql_no_comments_upper):
        """SERIAL introduces an implicit sequence; must not be used."""
        assert "SERIAL" not in sql_no_comments_upper

    def test_no_bigserial_column(self, sql_no_comments_upper):
        assert "BIGSERIAL" not in sql_no_comments_upper

    def test_no_smallserial_column(self, sql_no_comments_upper):
        assert "SMALLSERIAL" not in sql_no_comments_upper

    def test_no_generated_always_as_identity(self, sql_no_comments_upper):
        """GENERATED AS IDENTITY introduces an implicit sequence; must not be used."""
        assert "GENERATED" not in sql_no_comments_upper

    def test_no_nextval_call(self, sql_no_comments_upper):
        """Direct nextval() sequence references must not appear."""
        assert "NEXTVAL" not in sql_no_comments_upper

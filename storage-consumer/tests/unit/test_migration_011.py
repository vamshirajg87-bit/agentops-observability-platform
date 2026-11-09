"""
storage-consumer/tests/unit/test_migration_011.py

Static contract tests for:
    storage-consumer/migrations/011_create_incident_retrieval_role.sql

No live PostgreSQL required.  The migration SQL is read from disk and
inspected as text, following the static source-inspection convention used
throughout this test suite.

Invariants verified:
    - dedicated incident_retrieval role created WITH LOGIN
    - password supplied through the incident_retrieval_password psql variable
    - CREATE ROLE does not use IF NOT EXISTS
    - no SUPERUSER / CREATEDB / CREATEROLE / REPLICATION / BYPASSRLS attributes
    - CONNECT on database agentops, USAGE on schema public
    - column-level SELECT on exactly 10 public.rca_investigations columns
    - column-level SELECT on exactly 17 public.rca_evidence columns
    - INSERT, SELECT on public.rca_investigation_embeddings — no more, no less
    - no UPDATE / DELETE / TRUNCATE / ALL / CREATE privilege is granted
    - no write privilege on the Phase 11 tables
    - no anomaly_events access, no analytics schema access
    - excluded investigation and evidence columns are not granted
    - no sequence privileges
    - the cosine retrieval metric contract is documented
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
    "011_create_incident_retrieval_role.sql",
)

_ROLE = "incident_retrieval"

_INVESTIGATIONS = "public.rca_investigations"
_EVIDENCE = "public.rca_evidence"
_EMBEDDINGS = "public.rca_investigation_embeddings"

_INVESTIGATION_COLUMNS = [
    "investigation_id",
    "anomaly_type",
    "service_name",
    "operation_name",
    "confidence",
    "severity",
    "event_time",
    "summary",
    "limitations",
    "trace_span_count",
]

_EVIDENCE_COLUMNS = [
    "investigation_id",
    "rank_position",
    "evidence_type",
    "evidence_score",
    "span_name",
    "service_name",
    "status_code",
    "error_type",
    "tool_name",
    "tool_status",
    "agent_name",
    "agent_operation",
    "retrieval_result_count",
    "retrieval_top_relevance_score",
    "is_direct_subject",
    "is_root_span",
    "trace_duration_fraction",
]

_EXCLUDED_INVESTIGATION_COLUMNS = [
    "anomaly_id",
    "analyzer_version",
    "investigated_at",
    "trace_id",
    "subject_span_id",
    "observed_value",
    "baseline_median",
    "anomaly_score",
]

_EXCLUDED_EVIDENCE_COLUMNS = [
    "error_message",
    "explanation",
    "id",
    "span_id",
    "parent_span_id",
    "is_error_span",
    "duration_ms",
    "depth",
    "evidence_score_breakdown",
]


def _strip_sql_comments(sql: str) -> str:
    """
    Remove SQL line comments (-- ... to end of line).

    Used so that keyword checks on the live SQL are not tripped by
    comment text that deliberately *names* a forbidden construct
    (e.g. "UPDATE / DELETE / TRUNCATE on any table" in the NOT granted block).
    """
    lines = []
    for line in sql.splitlines():
        idx = line.find("--")
        lines.append(line[:idx] if idx >= 0 else line)
    return "\n".join(lines)


def _normalise(text: str) -> str:
    """Collapse all whitespace runs to a single space."""
    return re.sub(r"\s+", " ", text).strip()


class _Grant:
    """One parsed GRANT statement."""

    def __init__(self, statement: str) -> None:
        match = re.fullmatch(
            r"GRANT\s+(?P<privs>.+?)\s+ON\s+(?P<target>.+?)\s+TO\s+(?P<grantee>.+)",
            statement,
            re.IGNORECASE | re.DOTALL,
        )
        assert match, f"Could not parse GRANT ... ON ... TO ... in: {statement!r}"
        self.statement = statement
        self.target = _normalise(match.group("target"))
        self.grantee = _normalise(match.group("grantee"))

        privs = _normalise(match.group("privs"))
        # Column-level form: "<PRIVILEGE> ( col, col, ... )"
        col_match = re.fullmatch(r"(\w+)\s*\((.*)\)", privs, re.DOTALL)
        if col_match:
            self.privileges = {col_match.group(1).upper()}
            self.columns = [c.strip() for c in col_match.group(2).split(",")]
        else:
            assert "(" not in privs, f"Unsupported privilege list: {privs!r}"
            self.privileges = {p.strip().upper() for p in privs.split(",")}
            self.columns = None


@pytest.fixture(scope="module")
def sql() -> str:
    with open(_MIGRATION_PATH, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def sql_no_comments(sql: str) -> str:
    """SQL with all line-comment text removed."""
    return _strip_sql_comments(sql)


@pytest.fixture(scope="module")
def sql_no_comments_upper(sql_no_comments: str) -> str:
    return sql_no_comments.upper()


@pytest.fixture(scope="module")
def statements(sql_no_comments: str) -> list[str]:
    """Executable statements, whitespace-normalised, without the trailing ';'."""
    return [_normalise(s) for s in sql_no_comments.split(";") if s.strip()]


@pytest.fixture(scope="module")
def grants(statements: list[str]) -> list[_Grant]:
    return [_Grant(s) for s in statements if s.upper().startswith("GRANT")]


def _grants_on(grants: list[_Grant], target: str) -> list[_Grant]:
    return [g for g in grants if g.target.lower() == target.lower()]


def _only_grant_on(grants: list[_Grant], target: str) -> _Grant:
    matching = _grants_on(grants, target)
    assert len(matching) == 1, (
        f"Expected exactly one GRANT on {target}, found {len(matching)}: "
        f"{[g.statement for g in matching]}"
    )
    return matching[0]


# ---------------------------------------------------------------------------
# TestRoleCreation
# ---------------------------------------------------------------------------

class TestRoleCreation:

    def test_create_role_statement_exact(self, statements):
        assert (
            "CREATE ROLE incident_retrieval "
            "WITH LOGIN PASSWORD :'incident_retrieval_password'"
        ) in statements

    def test_exactly_one_create_role(self, sql_no_comments_upper):
        assert len(re.findall(r"CREATE\s+ROLE", sql_no_comments_upper)) == 1

    def test_role_is_first_statement(self, statements):
        """Grants name the role, so it must exist before any of them run."""
        assert statements[0].upper().startswith("CREATE ROLE")

    def test_role_has_login(self, statements):
        assert re.search(r"\bWITH\s+LOGIN\b", statements[0])
        assert not re.search(r"\bNOLOGIN\b", statements[0], re.IGNORECASE)

    def test_password_is_psql_variable(self, statements):
        """The password is interpolated by psql, never written in the file."""
        assert "PASSWORD :'incident_retrieval_password'" in statements[0]

    def test_no_literal_password(self, sql_no_comments):
        assert not re.search(r"PASSWORD\s+'", sql_no_comments, re.IGNORECASE)

    def test_create_role_does_not_use_if_not_exists(self, sql_no_comments_upper):
        assert "IF NOT EXISTS" not in sql_no_comments_upper

    def test_no_create_user(self, sql_no_comments_upper):
        assert not re.search(r"CREATE\s+USER", sql_no_comments_upper)

    def test_no_alter_or_drop_role(self, sql_no_comments_upper):
        assert not re.search(r"\b(ALTER|DROP)\b", sql_no_comments_upper)

    def test_statement_set_is_role_plus_five_grants(self, statements):
        assert len(statements) == 6, statements
        assert all(s.upper().startswith("GRANT") for s in statements[1:])


# ---------------------------------------------------------------------------
# TestNoElevatedRoleAttributes
# ---------------------------------------------------------------------------

class TestNoElevatedRoleAttributes:

    @pytest.mark.parametrize(
        "attribute",
        ["SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS"],
    )
    def test_role_attribute_not_set(self, sql_no_comments_upper, attribute):
        assert not re.search(rf"\b{attribute}\b", sql_no_comments_upper)

    def test_no_role_membership_granted(self, grants, statements):
        """
        Every GRANT must be a privilege grant (GRANT ... ON ... TO ...).
        A membership grant (GRANT some_role TO incident_retrieval) has no ON
        clause and would fail to parse in the `grants` fixture.
        """
        grant_statements = [s for s in statements if s.upper().startswith("GRANT")]
        assert len(grants) == len(grant_statements) == 5

    @pytest.mark.parametrize("role", ["agentops", "rca_analyzer", "anomaly_detector",
                                      "pg_read_all_data", "pg_write_all_data"])
    def test_no_other_role_referenced(self, sql_no_comments, role):
        """`agentops` may appear only as the database name."""
        text = sql_no_comments.replace("ON DATABASE agentops", "")
        assert not re.search(rf"\b{role}\b", text)

    def test_no_with_grant_option(self, sql_no_comments_upper):
        assert "GRANT OPTION" not in sql_no_comments_upper

    def test_no_set_role_or_security_definer(self, sql_no_comments_upper):
        assert "SET ROLE" not in sql_no_comments_upper
        assert "SECURITY DEFINER" not in sql_no_comments_upper

    def test_no_default_privileges(self, sql_no_comments_upper):
        assert "DEFAULT PRIVILEGES" not in sql_no_comments_upper


# ---------------------------------------------------------------------------
# TestGrantees
# ---------------------------------------------------------------------------

class TestGrantees:

    def test_every_grant_targets_incident_retrieval_only(self, grants):
        assert [g.grantee for g in grants] == [_ROLE] * len(grants)

    def test_nothing_granted_to_public(self, grants):
        assert all(g.grantee.upper() != "PUBLIC" for g in grants)


# ---------------------------------------------------------------------------
# TestConnectAndUsage
# ---------------------------------------------------------------------------

class TestConnectAndUsage:

    def test_connect_on_database_agentops(self, statements):
        assert "GRANT CONNECT ON DATABASE agentops TO incident_retrieval" in statements

    def test_usage_on_schema_public(self, statements):
        assert "GRANT USAGE ON SCHEMA public TO incident_retrieval" in statements

    def test_database_privilege_is_connect_only(self, grants):
        grant = _only_grant_on(grants, "DATABASE agentops")
        assert grant.privileges == {"CONNECT"}

    def test_schema_privilege_is_usage_only(self, grants):
        """CREATE on the schema would let the role own objects."""
        grant = _only_grant_on(grants, "SCHEMA public")
        assert grant.privileges == {"USAGE"}

    def test_public_is_the_only_schema_granted(self, grants):
        schema_targets = [g.target for g in grants if g.target.upper().startswith("SCHEMA")]
        assert schema_targets == ["SCHEMA public"]


# ---------------------------------------------------------------------------
# TestInvestigationColumnGrant
# ---------------------------------------------------------------------------

class TestInvestigationColumnGrant:

    def test_privilege_is_select_only(self, grants):
        assert _only_grant_on(grants, _INVESTIGATIONS).privileges == {"SELECT"}

    def test_grant_is_column_level(self, grants):
        """A table-level SELECT would expose every excluded column."""
        assert _only_grant_on(grants, _INVESTIGATIONS).columns is not None

    def test_exactly_ten_columns(self, grants):
        assert len(_only_grant_on(grants, _INVESTIGATIONS).columns) == 10

    def test_column_set_exact(self, grants):
        columns = _only_grant_on(grants, _INVESTIGATIONS).columns
        assert sorted(columns) == sorted(_INVESTIGATION_COLUMNS)

    def test_no_duplicate_columns(self, grants):
        columns = _only_grant_on(grants, _INVESTIGATIONS).columns
        assert len(columns) == len(set(columns))

    @pytest.mark.parametrize("column", _INVESTIGATION_COLUMNS)
    def test_column_granted(self, grants, column):
        assert column in _only_grant_on(grants, _INVESTIGATIONS).columns

    @pytest.mark.parametrize("column", _EXCLUDED_INVESTIGATION_COLUMNS)
    def test_excluded_column_not_granted(self, grants, column):
        assert column not in _only_grant_on(grants, _INVESTIGATIONS).columns


# ---------------------------------------------------------------------------
# TestEvidenceColumnGrant
# ---------------------------------------------------------------------------

class TestEvidenceColumnGrant:

    def test_privilege_is_select_only(self, grants):
        assert _only_grant_on(grants, _EVIDENCE).privileges == {"SELECT"}

    def test_grant_is_column_level(self, grants):
        """A table-level SELECT would expose every excluded column."""
        assert _only_grant_on(grants, _EVIDENCE).columns is not None

    def test_exactly_seventeen_columns(self, grants):
        assert len(_only_grant_on(grants, _EVIDENCE).columns) == 17

    def test_column_set_exact(self, grants):
        columns = _only_grant_on(grants, _EVIDENCE).columns
        assert sorted(columns) == sorted(_EVIDENCE_COLUMNS)

    def test_no_duplicate_columns(self, grants):
        columns = _only_grant_on(grants, _EVIDENCE).columns
        assert len(columns) == len(set(columns))

    @pytest.mark.parametrize("column", _EVIDENCE_COLUMNS)
    def test_column_granted(self, grants, column):
        assert column in _only_grant_on(grants, _EVIDENCE).columns

    @pytest.mark.parametrize("column", _EXCLUDED_EVIDENCE_COLUMNS)
    def test_excluded_column_not_granted(self, grants, column):
        assert column not in _only_grant_on(grants, _EVIDENCE).columns

    @pytest.mark.parametrize("column", ["error_message", "explanation"])
    def test_free_text_column_absent_from_executable_sql(self, sql_no_comments, column):
        """Free-text evidence fields must not be reachable through any statement."""
        assert not re.search(rf"\b{column}\b", sql_no_comments)


# ---------------------------------------------------------------------------
# TestEmbeddingsGrant
# ---------------------------------------------------------------------------

class TestEmbeddingsGrant:

    def test_grant_statement_exact(self, statements):
        assert (
            "GRANT INSERT, SELECT ON public.rca_investigation_embeddings "
            "TO incident_retrieval"
        ) in statements

    def test_privilege_set_is_exactly_insert_select(self, grants):
        assert _only_grant_on(grants, _EMBEDDINGS).privileges == {"INSERT", "SELECT"}

    def test_grant_is_table_level(self, grants):
        assert _only_grant_on(grants, _EMBEDDINGS).columns is None


# ---------------------------------------------------------------------------
# TestNoForbiddenPrivileges
# ---------------------------------------------------------------------------

class TestNoForbiddenPrivileges:

    @pytest.mark.parametrize(
        "privilege",
        ["UPDATE", "DELETE", "TRUNCATE", "ALL", "CREATE", "REFERENCES",
         "TRIGGER", "TEMPORARY", "TEMP", "EXECUTE"],
    )
    def test_privilege_not_granted_anywhere(self, grants, privilege):
        for grant in grants:
            assert privilege not in grant.privileges, grant.statement

    @pytest.mark.parametrize("keyword", ["UPDATE", "DELETE", "TRUNCATE"])
    def test_keyword_absent_from_executable_sql(self, sql_no_comments_upper, keyword):
        assert not re.search(rf"\b{keyword}\b", sql_no_comments_upper)

    def test_no_all_privileges(self, sql_no_comments_upper):
        assert not re.search(r"\bALL\b", sql_no_comments_upper)

    def test_granted_privilege_universe(self, grants):
        """Across the whole migration only these privileges are ever granted."""
        granted = set().union(*(g.privileges for g in grants))
        assert granted == {"CONNECT", "USAGE", "SELECT", "INSERT"}

    def test_grant_target_set_exact(self, grants):
        assert sorted(g.target for g in grants) == sorted([
            "DATABASE agentops",
            "SCHEMA public",
            _INVESTIGATIONS,
            _EVIDENCE,
            _EMBEDDINGS,
        ])


# ---------------------------------------------------------------------------
# TestNoPhase11Writes
# ---------------------------------------------------------------------------

class TestNoPhase11Writes:

    @pytest.mark.parametrize("table", [_INVESTIGATIONS, _EVIDENCE])
    def test_phase_11_table_is_read_only(self, grants, table):
        for grant in _grants_on(grants, table):
            assert grant.privileges == {"SELECT"}, grant.statement

    def test_insert_granted_only_on_embeddings(self, grants):
        insert_targets = [g.target for g in grants if "INSERT" in g.privileges]
        assert insert_targets == [_EMBEDDINGS]

    def test_no_ddl_on_phase_11_tables(self, sql_no_comments_upper):
        for keyword in ("CREATE TABLE", "CREATE INDEX", "ALTER TABLE", "DROP"):
            assert keyword not in sql_no_comments_upper


# ---------------------------------------------------------------------------
# TestNoOutOfScopeAccess
# ---------------------------------------------------------------------------

class TestNoOutOfScopeAccess:

    def test_no_anomaly_events_access(self, sql_no_comments):
        assert "anomaly_events" not in sql_no_comments.lower()

    def test_no_anomaly_detector_runs_access(self, sql_no_comments):
        assert "anomaly_detector_runs" not in sql_no_comments.lower()

    def test_no_telemetry_spans_access(self, sql_no_comments):
        assert "telemetry_spans" not in sql_no_comments.lower()

    def test_no_analytics_schema_access(self, sql_no_comments):
        assert "analytics" not in sql_no_comments.lower()

    def test_no_all_tables_in_schema(self, sql_no_comments_upper):
        assert "ALL TABLES" not in sql_no_comments_upper
        assert "IN SCHEMA" not in sql_no_comments_upper

    def test_every_relation_is_schema_qualified_public(self, grants):
        relation_targets = [
            g.target for g in grants
            if not g.target.upper().startswith(("DATABASE", "SCHEMA"))
        ]
        assert relation_targets
        assert all(t.startswith("public.") for t in relation_targets)


# ---------------------------------------------------------------------------
# TestNoSequenceGrants
# ---------------------------------------------------------------------------

class TestNoSequenceGrants:

    def test_no_sequence_keyword(self, sql_no_comments_upper):
        assert "SEQUENCE" not in sql_no_comments_upper

    def test_no_sequence_object_named(self, sql_no_comments):
        """e.g. rca_evidence_id_seq, which backs the excluded rca_evidence.id."""
        assert not re.search(r"\w+_seq\b", sql_no_comments, re.IGNORECASE)

    def test_usage_granted_only_on_schema(self, grants):
        usage_targets = [g.target for g in grants if "USAGE" in g.privileges]
        assert usage_targets == ["SCHEMA public"]


# ---------------------------------------------------------------------------
# TestRetrievalMetricDocumentation
# ---------------------------------------------------------------------------

class TestRetrievalMetricDocumentation:

    def test_cosine_distance_operator_documented(self, sql):
        assert "<=>" in sql

    def test_similarity_formula_documented(self, sql):
        assert "similarity = 1.0 - (embedding <=> query_vector)" in sql

    def test_future_hnsw_operator_class_documented(self, sql):
        assert "vector_cosine_ops" in sql

    def test_no_hnsw_in_executable_sql(self, sql_no_comments_upper):
        assert "HNSW" not in sql_no_comments_upper
        assert "IVFFLAT" not in sql_no_comments_upper
        assert "VECTOR_COSINE_OPS" not in sql_no_comments_upper

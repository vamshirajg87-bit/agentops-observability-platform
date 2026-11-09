"""
storage-consumer/tests/unit/test_migration_010.py

Static contract tests for:
    storage-consumer/migrations/010_create_rca_investigation_embeddings.sql

No live PostgreSQL required.  The migration SQL is read from disk and
inspected as text, following the static source-inspection convention used
throughout this test suite.

Invariants verified:
    - CREATE EXTENSION IF NOT EXISTS vector, before the table is created
    - table name is public.rca_investigation_embeddings
    - exactly eight columns with correct types and NOT NULL constraints
    - embedding is vector(384)
    - embedded_at is TIMESTAMPTZ NOT NULL DEFAULT NOW()
    - no model_version column
    - primary key is exactly (embedding_id)
    - UNIQUE is exactly (investigation_id, doc_version, model_name, model_revision)
    - FK to public.rca_investigations (investigation_id) ON DELETE RESTRICT
    - CHECK enforces the 64-character lowercase hexadecimal embedding_id format
    - contract/model index on (doc_version, model_name, model_revision)
    - no HNSW / IVFFlat index
    - no SERIAL / IDENTITY / sequence dependency is introduced
    - no privileges are granted (grants belong to migration 011)
    - the embedding identity formula and retrieval metric are documented
"""

from __future__ import annotations

import hashlib
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
    "010_create_rca_investigation_embeddings.sql",
)

_TABLE = "public.rca_investigation_embeddings"

_EXPECTED_COLUMNS = {
    "embedding_id": "TEXT NOT NULL",
    "investigation_id": "TEXT NOT NULL",
    "doc_version": "TEXT NOT NULL",
    "model_name": "TEXT NOT NULL",
    "model_revision": "TEXT NOT NULL",
    "document_text": "TEXT NOT NULL",
    "embedding": "vector(384) NOT NULL",
    "embedded_at": "TIMESTAMPTZ NOT NULL DEFAULT NOW()",
}

_INITIAL_DOC_VERSION = "1.0.0"
_INITIAL_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def _strip_sql_comments(sql: str) -> str:
    """
    Remove SQL line comments (-- ... to end of line).

    Used so that keyword checks on the live SQL are not tripped by
    comment text that deliberately *names* a forbidden construct
    (e.g. "a future HNSW index would use vector_cosine_ops").
    """
    lines = []
    for line in sql.splitlines():
        idx = line.find("--")
        lines.append(line[:idx] if idx >= 0 else line)
    return "\n".join(lines)


def _normalise(text: str) -> str:
    """Collapse all whitespace runs to a single space."""
    return re.sub(r"\s+", " ", text).strip()


def _split_top_level(body: str) -> list[str]:
    """Split a CREATE TABLE body on commas that are not nested in parentheses."""
    parts, depth, current = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [_normalise(p) for p in parts if p.strip()]


def _embedding_id(
    investigation_id: str, doc_version: str, model_name: str, model_revision: str
) -> str:
    """Reference implementation of the embedding identity contract."""
    material = "|".join([investigation_id, doc_version, model_name, model_revision])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


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
def sql_no_comments_normalised(sql_no_comments: str) -> str:
    return _normalise(sql_no_comments)


@pytest.fixture(scope="module")
def statements(sql_no_comments: str) -> list[str]:
    """Executable statements, whitespace-normalised, without the trailing ';'."""
    return [_normalise(s) for s in sql_no_comments.split(";") if s.strip()]


@pytest.fixture(scope="module")
def table_items(sql_no_comments: str) -> list[str]:
    """Top-level items (columns and constraints) of the CREATE TABLE body."""
    match = re.search(
        r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+"
        + re.escape(_TABLE)
        + r"\s*\((.*?)\)\s*;",
        sql_no_comments,
        re.DOTALL,
    )
    assert match, f"CREATE TABLE IF NOT EXISTS {_TABLE} (...) not found"
    return _split_top_level(match.group(1))


@pytest.fixture(scope="module")
def columns(table_items: list[str]) -> dict[str, str]:
    """Mapping of column name -> normalised column definition."""
    result = {}
    for item in table_items:
        if item.upper().startswith("CONSTRAINT"):
            continue
        name, _, definition = item.partition(" ")
        result[name] = definition
    return result


@pytest.fixture(scope="module")
def constraints(table_items: list[str]) -> dict[str, str]:
    """Mapping of constraint name -> normalised constraint definition."""
    result = {}
    for item in table_items:
        match = re.match(r"CONSTRAINT\s+(\S+)\s+(.*)", item, re.IGNORECASE)
        if match:
            result[match.group(1)] = match.group(2)
    return result


# ---------------------------------------------------------------------------
# TestExtension
# ---------------------------------------------------------------------------

class TestExtension:

    def test_create_extension_if_not_exists_vector(self, statements):
        assert "CREATE EXTENSION IF NOT EXISTS vector" in statements

    def test_exactly_one_create_extension(self, sql_no_comments_upper):
        assert sql_no_comments_upper.count("CREATE EXTENSION") == 1

    def test_extension_created_before_table(self, sql_no_comments_upper):
        """vector(384) cannot be resolved until the extension exists."""
        assert sql_no_comments_upper.index("CREATE EXTENSION") < (
            sql_no_comments_upper.index("CREATE TABLE")
        )


# ---------------------------------------------------------------------------
# TestTableName
# ---------------------------------------------------------------------------

class TestTableName:

    def test_creates_public_rca_investigation_embeddings(
        self, sql_no_comments_normalised
    ):
        assert (
            f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
            in sql_no_comments_normalised
        )

    def test_exactly_one_create_table(self, sql_no_comments_upper):
        assert sql_no_comments_upper.count("CREATE TABLE") == 1

    def test_statement_set_is_extension_table_index(self, statements):
        """The migration contains exactly three statements, in order."""
        assert len(statements) == 3, statements
        assert statements[0].upper().startswith("CREATE EXTENSION")
        assert statements[1].upper().startswith("CREATE TABLE")
        assert statements[2].upper().startswith("CREATE INDEX")


# ---------------------------------------------------------------------------
# TestColumns
# ---------------------------------------------------------------------------

class TestColumns:

    @pytest.mark.parametrize("name, definition", sorted(_EXPECTED_COLUMNS.items()))
    def test_column_definition_exact(self, columns, name, definition):
        assert name in columns, f"column {name} missing; found {sorted(columns)}"
        assert columns[name] == definition

    def test_column_set_is_exactly_the_eight_contract_columns(self, columns):
        assert set(columns) == set(_EXPECTED_COLUMNS)

    def test_column_order(self, columns):
        assert list(columns) == list(_EXPECTED_COLUMNS)

    def test_embedding_is_vector_384(self, columns):
        assert columns["embedding"].startswith("vector(384)")

    def test_only_one_vector_dimension_declared(self, sql_no_comments):
        dims = re.findall(r"vector\s*\(\s*(\d+)\s*\)", sql_no_comments, re.IGNORECASE)
        assert dims == ["384"]

    def test_document_text_not_null(self, columns):
        assert columns["document_text"] == "TEXT NOT NULL"

    def test_model_revision_not_null(self, columns):
        assert columns["model_revision"] == "TEXT NOT NULL"

    def test_embedded_at_timestamptz_not_null_default_now(self, columns):
        assert columns["embedded_at"] == "TIMESTAMPTZ NOT NULL DEFAULT NOW()"

    def test_no_model_version_column(self, columns, sql_no_comments):
        assert "model_version" not in columns
        assert "model_version" not in sql_no_comments.lower()

    def test_every_column_is_not_null(self, columns):
        nullable = [n for n, d in columns.items() if "NOT NULL" not in d.upper()]
        assert nullable == []

    def test_only_embedded_at_has_a_default(self, columns):
        """Contract values (doc_version, model_*) come from the application."""
        defaulted = [n for n, d in columns.items() if "DEFAULT" in d.upper()]
        assert defaulted == ["embedded_at"]


# ---------------------------------------------------------------------------
# TestPrimaryKey
# ---------------------------------------------------------------------------

class TestPrimaryKey:

    def test_primary_key_is_exactly_embedding_id(self, constraints):
        assert (
            constraints["rca_investigation_embeddings_pkey"]
            == "PRIMARY KEY (embedding_id)"
        )

    def test_exactly_one_primary_key(self, sql_no_comments_upper):
        assert len(re.findall(r"PRIMARY\s+KEY", sql_no_comments_upper)) == 1


# ---------------------------------------------------------------------------
# TestUniqueContract
# ---------------------------------------------------------------------------

class TestUniqueContract:

    def test_unique_is_exactly_the_four_contract_columns(self, constraints):
        assert (
            constraints["rca_investigation_embeddings_inv_contract_model_uniq"]
            == "UNIQUE (investigation_id, doc_version, model_name, model_revision)"
        )

    def test_exactly_one_unique_constraint(self, sql_no_comments_upper):
        assert len(re.findall(r"\bUNIQUE\b", sql_no_comments_upper)) == 1

    def test_unique_columns_match_identity_inputs(self, constraints):
        """The UNIQUE columns are the inputs of the embedding_id digest, in order."""
        definition = constraints[
            "rca_investigation_embeddings_inv_contract_model_uniq"
        ]
        cols = [c.strip() for c in definition[len("UNIQUE ("):-1].split(",")]
        assert cols == [
            "investigation_id", "doc_version", "model_name", "model_revision",
        ]


# ---------------------------------------------------------------------------
# TestForeignKey
# ---------------------------------------------------------------------------

class TestForeignKey:

    def test_fk_references_rca_investigations_on_delete_restrict(self, constraints):
        assert constraints["rca_investigation_embeddings_investigation_fk"] == (
            "FOREIGN KEY (investigation_id) "
            "REFERENCES public.rca_investigations (investigation_id) "
            "ON DELETE RESTRICT"
        )

    def test_exactly_one_foreign_key(self, sql_no_comments_upper):
        assert len(re.findall(r"FOREIGN\s+KEY", sql_no_comments_upper)) == 1
        assert len(re.findall(r"\bREFERENCES\b", sql_no_comments_upper)) == 1

    def test_no_cascade_or_set_null(self, sql_no_comments_upper):
        assert "CASCADE" not in sql_no_comments_upper
        assert "SET NULL" not in sql_no_comments_upper
        assert "SET DEFAULT" not in sql_no_comments_upper


# ---------------------------------------------------------------------------
# TestEmbeddingIdFormatCheck
# ---------------------------------------------------------------------------

class TestEmbeddingIdFormatCheck:

    _NAME = "rca_investigation_embeddings_embedding_id_format"

    def test_check_definition_exact(self, constraints):
        assert constraints[self._NAME] == "CHECK (embedding_id ~ '^[0-9a-f]{64}$')"

    def test_exactly_one_check_constraint(self, sql_no_comments_upper):
        """The database validates the format only — nothing else is checked."""
        assert len(re.findall(r"\bCHECK\b", sql_no_comments_upper)) == 1

    def test_check_is_case_sensitive_match(self, constraints):
        """~* would accept uppercase hex; only ~ is allowed."""
        assert "~*" not in constraints[self._NAME]

    def _pattern(self, constraints) -> re.Pattern:
        match = re.search(r"~\s*'([^']+)'", constraints[self._NAME])
        assert match, "regex literal not found in CHECK constraint"
        return re.compile(match.group(1))

    def test_pattern_accepts_64_lowercase_hex(self, constraints):
        assert self._pattern(constraints).search("0123456789abcdef" * 4)

    @pytest.mark.parametrize(
        "value",
        [
            "0123456789ABCDEF" * 4,          # uppercase
            "0123456789abcdef" * 4 + "0",    # 65 chars
            ("0123456789abcdef" * 4)[:-1],   # 63 chars
            "g" * 64,                        # non-hex
            "",
        ],
    )
    def test_pattern_rejects_malformed_ids(self, constraints, value):
        assert not self._pattern(constraints).search(value)


# ---------------------------------------------------------------------------
# TestContractIndex
# ---------------------------------------------------------------------------

class TestContractIndex:

    def test_contract_index_exact(self, statements):
        assert (
            "CREATE INDEX IF NOT EXISTS rca_investigation_embeddings_contract_idx "
            f"ON {_TABLE} (doc_version, model_name, model_revision)"
        ) in statements

    def test_exactly_one_index(self, sql_no_comments_upper):
        assert len(re.findall(r"CREATE\s+(UNIQUE\s+)?INDEX", sql_no_comments_upper)) == 1


# ---------------------------------------------------------------------------
# TestNoApproximateIndex
# ---------------------------------------------------------------------------

class TestNoApproximateIndex:

    def test_no_hnsw(self, sql_no_comments_upper):
        assert "HNSW" not in sql_no_comments_upper

    def test_no_ivfflat(self, sql_no_comments_upper):
        assert "IVFFLAT" not in sql_no_comments_upper

    def test_no_index_access_method_clause(self, sql_no_comments_upper):
        """Any USING <method> would select a non-default index type."""
        assert not re.search(r"\bUSING\b", sql_no_comments_upper)

    def test_no_vector_operator_class(self, sql_no_comments_upper):
        for opclass in ("VECTOR_COSINE_OPS", "VECTOR_L2_OPS", "VECTOR_IP_OPS"):
            assert opclass not in sql_no_comments_upper

    def test_embedding_column_is_not_indexed(self, statements):
        index_statements = [s for s in statements if s.upper().startswith("CREATE INDEX")]
        for stmt in index_statements:
            cols = stmt[stmt.rindex("(") + 1 : stmt.rindex(")")]
            assert "embedding" not in [c.strip() for c in cols.split(",")]


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

    def test_no_create_sequence(self, sql_no_comments_upper):
        assert "SEQUENCE" not in sql_no_comments_upper

    def test_primary_key_column_is_text(self, columns):
        assert columns["embedding_id"] == "TEXT NOT NULL"


# ---------------------------------------------------------------------------
# TestNoPrivilegeChanges
# ---------------------------------------------------------------------------

class TestNoPrivilegeChanges:

    def test_no_grant(self, sql_no_comments_upper):
        """Privileges are granted by migration 011, not here."""
        assert not re.search(r"\bGRANT\b", sql_no_comments_upper)

    def test_no_role_statements(self, sql_no_comments_upper):
        assert not re.search(r"\bROLE\b", sql_no_comments_upper)

    def test_no_destructive_statements(self, sql_no_comments_upper):
        for keyword in ("DROP", "ALTER", "TRUNCATE"):
            assert not re.search(rf"\b{keyword}\b", sql_no_comments_upper)
        assert not re.search(r"\bDELETE\s+FROM\b", sql_no_comments_upper)


# ---------------------------------------------------------------------------
# TestIdentityContract
# ---------------------------------------------------------------------------

class TestIdentityContract:

    def test_identity_formula_documented(self, sql):
        """The header documents the digest inputs and their order."""
        documented = _normalise(
            " ".join(line.lstrip("- ") for line in sql.splitlines() if line.startswith("--"))
        )
        assert (
            'lowercase(hex(SHA-256(UTF-8( investigation_id + "|" + '
            'doc_version + "|" + model_name + "|" + model_revision ))))'
        ) in documented

    def test_initial_doc_version_documented(self, sql):
        assert _INITIAL_DOC_VERSION in sql

    def test_initial_model_name_documented(self, sql):
        assert _INITIAL_MODEL_NAME in sql

    def test_no_model_revision_invented(self, sql, sql_no_comments):
        """model_revision is pinned in a later phase; none may appear here."""
        assert not re.search(r"\b[0-9a-f]{40}\b", sql)
        assert _INITIAL_MODEL_NAME not in sql_no_comments
        assert _INITIAL_DOC_VERSION not in sql_no_comments

    def test_reference_identity_golden_vector(self):
        """Pins the formula: separator, field order, encoding, and hex case."""
        assert _embedding_id(
            "a" * 64, _INITIAL_DOC_VERSION, _INITIAL_MODEL_NAME, "test-revision"
        ) == "0f60177b37fba45c6b54755636ffccc6362aeebe761dcd24b1fa5deabab2e28b"

    def test_reference_identity_satisfies_format_check(self, constraints):
        check = constraints["rca_investigation_embeddings_embedding_id_format"]
        pattern = re.compile(re.search(r"~\s*'([^']+)'", check).group(1))
        value = _embedding_id(
            "a" * 64, _INITIAL_DOC_VERSION, _INITIAL_MODEL_NAME, "test-revision"
        )
        assert pattern.search(value)

    @pytest.mark.parametrize(
        "field", ["investigation_id", "doc_version", "model_name", "model_revision"]
    )
    def test_each_identity_input_changes_the_digest(self, field):
        base = {
            "investigation_id": "a" * 64,
            "doc_version": _INITIAL_DOC_VERSION,
            "model_name": _INITIAL_MODEL_NAME,
            "model_revision": "test-revision",
        }
        changed = dict(base, **{field: base[field] + "x"})
        assert _embedding_id(**base) != _embedding_id(**changed)


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

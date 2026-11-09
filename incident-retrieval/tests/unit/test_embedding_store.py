"""
incident-retrieval/tests/unit/test_embedding_store.py

Unit tests for embedding_store.py.

No live PostgreSQL required.  DB access is mocked with MagicMock.  The SQL
constants are read from the module and inspected as text, and the granted
columns are read from migration 011 on disk.

Test inventory:
    ST01  SQL shape: explicit columns, granted columns only, bound parameters
    ST02  SQL safety: no UPDATE / DELETE / TRUNCATE / SELECT * / DDL
    ST03  fetch_investigation
    ST04  fetch_evidence
    ST05  fetch_stored_document_text
    ST06  insert_embedding
    ST07  Transactions: the store never commits or rolls back
    ST08  Import boundary
    ST09  Similarity SELECT (Phase 12.6): shape, filters, ordering
    ST10  fetch_similar_investigations (Phase 12.6)
    ST11  Investigation-context SELECT (Phase 12.7): shape, grants
    ST12  fetch_investigation_contexts (Phase 12.7)
    ST13  Discovery SELECT (Phase 12.8): shape, no eligibility filter
    ST14  fetch_investigation_ids (Phase 12.8)
"""

from __future__ import annotations

import ast
import os
import re
from unittest.mock import MagicMock

import psycopg.rows
import pytest

import embedding_store
from embedding_store import (
    EMBEDDING_COLUMN_DIMENSION,
    fetch_evidence,
    fetch_investigation,
    fetch_investigation_contexts,
    fetch_investigation_ids,
    fetch_similar_investigations,
    fetch_stored_document_text,
    insert_embedding,
)
from incident_document import EvidenceRow, InvestigationRow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "embedding_store.py")
_MIGRATION_011 = os.path.join(
    _COMPONENT_DIR, "..", "storage-consumer", "migrations",
    "011_create_incident_retrieval_role.sql",
)
_MIGRATION_010 = os.path.join(
    _COMPONENT_DIR, "..", "storage-consumer", "migrations",
    "010_create_rca_investigation_embeddings.sql",
)

_INV = "a" * 64
_EMB = "e" * 64

_ALL_SQL = {
    "fetch_investigation": embedding_store._SQL_FETCH_INVESTIGATION,
    "fetch_evidence": embedding_store._SQL_FETCH_EVIDENCE,
    "fetch_stored_document_text": embedding_store._SQL_FETCH_STORED_DOCUMENT_TEXT,
    "insert_embedding": embedding_store._SQL_INSERT_EMBEDDING,
    "fetch_similar_investigations": embedding_store._SQL_FETCH_SIMILAR_INVESTIGATIONS,
    "fetch_investigation_contexts": embedding_store._SQL_FETCH_INVESTIGATION_CONTEXTS,
    "fetch_investigation_ids": embedding_store._SQL_FETCH_INVESTIGATION_IDS,
}

_INVESTIGATION_COLUMNS = [
    "investigation_id", "anomaly_type", "service_name", "operation_name", "confidence",
]

_EVIDENCE_COLUMNS = [
    "investigation_id", "rank_position", "evidence_type", "evidence_score",
    "span_name", "service_name", "status_code", "error_type", "tool_name",
    "tool_status", "agent_name", "agent_operation", "retrieval_result_count",
    "retrieval_top_relevance_score", "is_direct_subject", "is_root_span",
    "trace_duration_fraction",
]

_INSERT_COLUMNS = [
    "embedding_id", "investigation_id", "doc_version", "model_name",
    "model_revision", "document_text", "embedding",
]


def _normalise(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _select_columns(sql: str) -> list[str]:
    match = re.search(r"SELECT\s+(.*?)\s+FROM\s", sql, re.DOTALL | re.IGNORECASE)
    assert match, f"SELECT ... FROM not found in: {sql!r}"
    return [c.strip() for c in match.group(1).split(",")]


def _granted_columns(table: str) -> set[str]:
    """Columns granted to incident_retrieval on a table, read from migration 011."""
    with open(_MIGRATION_011, encoding="utf-8") as fh:
        sql = "\n".join(line.split("--")[0] for line in fh.read().splitlines())
    match = re.search(
        r"GRANT\s+SELECT\s*\(([^)]*)\)\s*ON\s+" + re.escape(table) + r"\s+TO\s+incident_retrieval",
        sql, re.IGNORECASE,
    )
    assert match, f"column grant on {table} not found in migration 011"
    columns = [c.strip() for c in match.group(1).split(",")]
    assert len(columns) == len(set(columns))
    return set(columns)


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


def _investigation_row(**overrides) -> dict:
    row = {
        "investigation_id": _INV,
        "anomaly_type": "tool_failure",
        "service_name": "agentops-demo-app",
        "operation_name": "tool.execute/ToolExecutionError",
        "confidence": "HIGH",
    }
    row.update(overrides)
    return row


def _evidence_row(rank: int = 1, **overrides) -> dict:
    row = {
        "investigation_id": _INV,
        "rank_position": rank,
        "evidence_type": "mixed",
        "evidence_score": 0.9,
        "span_name": "tool.execute",
        "service_name": "agentops-demo-app",
        "status_code": "ERROR",
        "error_type": "ToolExecutionError",
        "tool_name": None,
        "tool_status": None,
        "agent_name": "tool_agent",
        "agent_operation": "execute",
        "retrieval_result_count": None,
        "retrieval_top_relevance_score": None,
        "is_direct_subject": True,
        "is_root_span": False,
        "trace_duration_fraction": 0.0103,
    }
    row.update(overrides)
    return row


def _vector(dimension: int = 384) -> tuple[float, ...]:
    return tuple([0.05] * dimension)


def _insert(conn, **overrides) -> bool:
    kwargs = dict(
        embedding_id=_EMB,
        investigation_id=_INV,
        doc_version="1.0.0",
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        document_text="anomaly: tool_failure\nevidence: none",
        vector=_vector(),
    )
    kwargs.update(overrides)
    return insert_embedding(conn, **kwargs)


# ---------------------------------------------------------------------------
# ST01  SQL shape
# ---------------------------------------------------------------------------

class TestSqlShape:

    def test_investigation_columns_exact(self):
        assert _select_columns(_ALL_SQL["fetch_investigation"]) == _INVESTIGATION_COLUMNS

    def test_evidence_columns_exact(self):
        assert _select_columns(_ALL_SQL["fetch_evidence"]) == _EVIDENCE_COLUMNS

    def test_stored_text_columns_exact(self):
        assert _select_columns(_ALL_SQL["fetch_stored_document_text"]) == ["document_text"]

    def test_granted_column_counts_read_from_migration_011(self):
        """Guards the grant parser itself: 10 investigation and 17 evidence columns."""
        assert len(_granted_columns("public.rca_investigations")) == 10
        assert len(_granted_columns("public.rca_evidence")) == 17

    def test_investigation_columns_are_all_granted(self):
        assert set(_INVESTIGATION_COLUMNS) <= _granted_columns("public.rca_investigations")

    def test_evidence_columns_are_all_granted(self):
        assert set(_EVIDENCE_COLUMNS) <= _granted_columns("public.rca_evidence")

    def test_evidence_columns_are_exactly_the_granted_seventeen(self):
        assert set(_EVIDENCE_COLUMNS) == _granted_columns("public.rca_evidence")
        assert len(_EVIDENCE_COLUMNS) == 17

    def test_investigation_columns_match_investigation_row_fields(self):
        import dataclasses
        assert _INVESTIGATION_COLUMNS == [f.name for f in dataclasses.fields(InvestigationRow)]

    def test_evidence_columns_match_evidence_row_fields(self):
        import dataclasses
        assert _EVIDENCE_COLUMNS == [f.name for f in dataclasses.fields(EvidenceRow)]

    @pytest.mark.parametrize(
        "excluded",
        ["error_message", "explanation", "span_id", "parent_span_id", "is_error_span",
         "duration_ms", "depth", "evidence_score_breakdown", "anomaly_id",
         "analyzer_version", "investigated_at", "trace_id", "subject_span_id",
         "observed_value", "baseline_median", "anomaly_score"],
    )
    def test_ungranted_column_never_referenced(self, excluded):
        for name, sql in _ALL_SQL.items():
            assert not re.search(rf"\b{excluded}\b", sql), name

    def test_tables_are_schema_qualified(self):
        assert "FROM public.rca_investigations" in _ALL_SQL["fetch_investigation"]
        assert "FROM public.rca_evidence" in _ALL_SQL["fetch_evidence"]
        assert "FROM public.rca_investigation_embeddings" in _ALL_SQL["fetch_stored_document_text"]
        assert "INSERT INTO public.rca_investigation_embeddings" in _ALL_SQL["insert_embedding"]

    def test_only_the_three_expected_tables(self):
        tables = set()
        for sql in _ALL_SQL.values():
            tables.update(re.findall(r"\b(?:FROM|INTO|JOIN)\s+([\w.]+)", sql, re.IGNORECASE))
        assert tables == {
            "public.rca_investigations",
            "public.rca_evidence",
            "public.rca_investigation_embeddings",
        }

    def test_evidence_ordered_by_rank_position(self):
        assert _normalise(_ALL_SQL["fetch_evidence"]).endswith("ORDER BY rank_position ASC")

    def test_lookups_filter_by_bound_parameter(self):
        assert "WHERE investigation_id = %(investigation_id)s" in _ALL_SQL["fetch_investigation"]
        assert "WHERE investigation_id = %(investigation_id)s" in _ALL_SQL["fetch_evidence"]
        assert "WHERE embedding_id = %(embedding_id)s" in _ALL_SQL["fetch_stored_document_text"]

    def test_insert_columns_exact(self):
        match = re.search(r"INSERT INTO [\w.]+\s*\((.*?)\)\s*VALUES", _ALL_SQL["insert_embedding"], re.DOTALL)
        assert [c.strip() for c in match.group(1).split(",")] == _INSERT_COLUMNS

    def test_insert_values_are_bound_parameters_in_column_order(self):
        match = re.search(r"VALUES\s*\((.*?)\)\s*ON CONFLICT", _ALL_SQL["insert_embedding"], re.DOTALL)
        values = [v.strip() for v in match.group(1).split(",")]
        assert values == [
            "%(embedding_id)s", "%(investigation_id)s", "%(doc_version)s",
            "%(model_name)s", "%(model_revision)s", "%(document_text)s",
            "%(embedding)s::vector",
        ]

    def test_insert_casts_embedding_to_vector(self):
        assert "%(embedding)s::vector" in _ALL_SQL["insert_embedding"]

    def test_insert_does_not_supply_embedded_at(self):
        assert "embedded_at" not in _ALL_SQL["insert_embedding"]

    def test_insert_conflict_clause_is_the_four_column_contract(self):
        assert _normalise(_ALL_SQL["insert_embedding"]).endswith(
            "ON CONFLICT (investigation_id, doc_version, model_name, model_revision) DO NOTHING"
        )

    def test_conflict_columns_match_migration_010_unique_constraint(self):
        with open(_MIGRATION_010, encoding="utf-8") as fh:
            migration = _normalise(fh.read())
        assert "UNIQUE (investigation_id, doc_version, model_name, model_revision)" in migration

    def test_insert_columns_exist_in_migration_010(self):
        with open(_MIGRATION_010, encoding="utf-8") as fh:
            migration = fh.read()
        for column in _INSERT_COLUMNS:
            assert re.search(rf"^\s*{column}\s+\S+", migration, re.MULTILINE), column

    def test_column_dimension_matches_migration_010(self):
        with open(_MIGRATION_010, encoding="utf-8") as fh:
            assert f"vector({EMBEDDING_COLUMN_DIMENSION})" in fh.read()
        assert EMBEDDING_COLUMN_DIMENSION == 384

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_every_placeholder_is_a_named_parameter(self, name):
        sql = _ALL_SQL[name]
        assert "%s" not in re.sub(r"%\(\w+\)s", "", sql)
        assert "{" not in sql and "}" not in sql


# ---------------------------------------------------------------------------
# ST02  SQL safety
# ---------------------------------------------------------------------------

class TestSqlSafety:

    @pytest.fixture(scope="class")
    def module_source(self) -> str:
        with open(_MODULE_PATH, encoding="utf-8") as fh:
            return fh.read()

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    @pytest.mark.parametrize(
        "keyword",
        ["UPDATE", "DELETE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT", "COPY"],
    )
    def test_forbidden_keyword_absent(self, name, keyword):
        assert not re.search(rf"\b{keyword}\b", _ALL_SQL[name], re.IGNORECASE)

    @pytest.mark.parametrize("name", sorted(_ALL_SQL))
    def test_no_select_star(self, name):
        assert not re.search(r"SELECT\s+\*", _ALL_SQL[name], re.IGNORECASE)
        assert "*" not in _ALL_SQL[name]

    def test_no_do_update(self):
        assert "DO UPDATE" not in _normalise(_ALL_SQL["insert_embedding"]).upper()

    def test_exactly_seven_sql_statements_in_module(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        constants = [
            node.targets[0].id for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.startswith("_SQL_")
        ]
        assert sorted(constants) == [
            "_SQL_FETCH_EVIDENCE", "_SQL_FETCH_INVESTIGATION",
            "_SQL_FETCH_INVESTIGATION_CONTEXTS",
            "_SQL_FETCH_INVESTIGATION_IDS",
            "_SQL_FETCH_SIMILAR_INVESTIGATIONS",
            "_SQL_FETCH_STORED_DOCUMENT_TEXT", "_SQL_INSERT_EMBEDDING",
        ]
        assert sorted(constants) == sorted(
            name for name in vars(embedding_store) if name.startswith("_SQL_")
        )
        assert len(_ALL_SQL) == 7

    def test_exactly_one_write_statement(self):
        writes = [n for n, sql in _ALL_SQL.items() if re.search(r"\bINSERT\b", sql, re.IGNORECASE)]
        assert writes == ["insert_embedding"]

    def test_no_f_string_or_format_sql(self, module_source):
        tree = ast.parse(module_source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "execute":
                    assert isinstance(node.args[0], ast.Name), "execute() must take a SQL constant"
                    assert node.args[0].id.startswith("_SQL_")

    def test_no_out_of_scope_relations(self, module_source):
        executable = "\n".join(_ALL_SQL.values()).lower()
        for name in ("anomaly_events", "telemetry_spans", "analytics.", "anomaly_detector_runs", "_seq"):
            assert name not in executable


# ---------------------------------------------------------------------------
# ST03  fetch_investigation
# ---------------------------------------------------------------------------

class TestFetchInvestigation:

    def test_returns_investigation_row(self):
        conn, _ = _make_conn(fetchone=_investigation_row())
        assert fetch_investigation(conn, _INV) == InvestigationRow(
            investigation_id=_INV,
            anomaly_type="tool_failure",
            service_name="agentops-demo-app",
            operation_name="tool.execute/ToolExecutionError",
            confidence="HIGH",
        )

    def test_returns_none_when_absent(self):
        conn, _ = _make_conn(fetchone=None)
        assert fetch_investigation(conn, _INV) is None

    def test_null_service_and_operation_preserved(self):
        conn, _ = _make_conn(fetchone=_investigation_row(service_name=None, operation_name=None))
        row = fetch_investigation(conn, _INV)
        assert row.service_name is None and row.operation_name is None

    def test_executes_the_sql_constant_with_bound_id(self):
        conn, cur = _make_conn(fetchone=_investigation_row())
        fetch_investigation(conn, _INV)
        cur.execute.assert_called_once_with(
            embedding_store._SQL_FETCH_INVESTIGATION, {"investigation_id": _INV},
        )

    def test_uses_dict_row_cursor(self):
        conn, _ = _make_conn(fetchone=_investigation_row())
        fetch_investigation(conn, _INV)
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_values_are_not_modified(self):
        conn, _ = _make_conn(fetchone=_investigation_row(service_name="  Padded  ", confidence="LOW"))
        row = fetch_investigation(conn, _INV)
        assert row.service_name == "  Padded  " and row.confidence == "LOW"

    def test_database_error_propagates(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.OperationalError("boom")
        with pytest.raises(psycopg.OperationalError):
            fetch_investigation(conn, _INV)


# ---------------------------------------------------------------------------
# ST04  fetch_evidence
# ---------------------------------------------------------------------------

class TestFetchEvidence:

    def test_returns_evidence_rows_in_cursor_order(self):
        conn, _ = _make_conn(fetchall=[_evidence_row(1), _evidence_row(2, span_name="b"), _evidence_row(3)])
        rows = fetch_evidence(conn, _INV)
        assert [type(r) for r in rows] == [EvidenceRow] * 3
        assert [r.rank_position for r in rows] == [1, 2, 3]
        assert rows[1].span_name == "b"

    def test_empty_list_when_no_evidence(self):
        conn, _ = _make_conn(fetchall=[])
        assert fetch_evidence(conn, _INV) == []

    def test_full_row_mapping(self):
        conn, _ = _make_conn(fetchall=[_evidence_row(
            7, evidence_type="duration", evidence_score=0.25, span_name="s", service_name="svc",
            status_code="UNSET", error_type=None, tool_name="t", tool_status="ok",
            agent_name="a", agent_operation="op", retrieval_result_count=3,
            retrieval_top_relevance_score=0.4, is_direct_subject=False, is_root_span=True,
            trace_duration_fraction=1.2,
        )])
        assert fetch_evidence(conn, _INV) == [EvidenceRow(
            investigation_id=_INV, rank_position=7, evidence_type="duration",
            evidence_score=0.25, span_name="s", service_name="svc", status_code="UNSET",
            error_type=None, tool_name="t", tool_status="ok", agent_name="a",
            agent_operation="op", retrieval_result_count=3,
            retrieval_top_relevance_score=0.4, is_direct_subject=False, is_root_span=True,
            trace_duration_fraction=1.2,
        )]

    def test_nulls_preserved(self):
        conn, _ = _make_conn(fetchall=[_evidence_row()])
        row = fetch_evidence(conn, _INV)[0]
        assert row.tool_name is None and row.retrieval_result_count is None

    def test_executes_the_sql_constant_with_bound_id(self):
        conn, cur = _make_conn(fetchall=[])
        fetch_evidence(conn, _INV)
        cur.execute.assert_called_once_with(
            embedding_store._SQL_FETCH_EVIDENCE, {"investigation_id": _INV},
        )

    def test_uses_dict_row_cursor(self):
        conn, _ = _make_conn(fetchall=[])
        fetch_evidence(conn, _INV)
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_returns_a_list(self):
        conn, _ = _make_conn(fetchall=[_evidence_row()])
        assert type(fetch_evidence(conn, _INV)) is list


# ---------------------------------------------------------------------------
# ST05  fetch_stored_document_text
# ---------------------------------------------------------------------------

class TestFetchStoredDocumentText:

    def test_returns_text(self):
        conn, _ = _make_conn(fetchone={"document_text": "anomaly: latency\nevidence: none"})
        assert fetch_stored_document_text(conn, _EMB) == "anomaly: latency\nevidence: none"

    def test_returns_none_when_absent(self):
        conn, _ = _make_conn(fetchone=None)
        assert fetch_stored_document_text(conn, _EMB) is None

    def test_text_returned_unmodified(self):
        text = "  café \U0001F680\nline two  "
        conn, _ = _make_conn(fetchone={"document_text": text})
        assert fetch_stored_document_text(conn, _EMB) == text

    def test_executes_the_sql_constant_with_bound_id(self):
        conn, cur = _make_conn(fetchone=None)
        fetch_stored_document_text(conn, _EMB)
        cur.execute.assert_called_once_with(
            embedding_store._SQL_FETCH_STORED_DOCUMENT_TEXT, {"embedding_id": _EMB},
        )


# ---------------------------------------------------------------------------
# ST06  insert_embedding
# ---------------------------------------------------------------------------

class TestInsertEmbedding:

    def test_returns_true_when_row_inserted(self):
        conn, _ = _make_conn(rowcount=1)
        assert _insert(conn) is True

    def test_returns_false_on_conflict(self):
        conn, _ = _make_conn(rowcount=0)
        assert _insert(conn) is False

    def test_executes_the_sql_constant(self):
        conn, cur = _make_conn()
        _insert(conn)
        assert cur.execute.call_count == 1
        assert cur.execute.call_args.args[0] is embedding_store._SQL_INSERT_EMBEDDING

    def test_parameter_keys_exact(self):
        conn, cur = _make_conn()
        _insert(conn)
        assert set(cur.execute.call_args.args[1]) == set(_INSERT_COLUMNS)

    def test_parameters_passed_through_unchanged(self):
        conn, cur = _make_conn()
        _insert(conn, document_text="  text \U0001F680\nline  ")
        params = cur.execute.call_args.args[1]
        assert params["embedding_id"] == _EMB
        assert params["investigation_id"] == _INV
        assert params["doc_version"] == "1.0.0"
        assert params["model_name"] == "sentence-transformers/all-MiniLM-L6-v2"
        assert params["model_revision"] == "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
        assert params["document_text"] == "  text \U0001F680\nline  "

    def test_embedding_bound_as_vector_literal(self):
        vector = tuple((i - 192) / 1000.0 for i in range(384))
        conn, cur = _make_conn()
        _insert(conn, vector=vector)
        literal = cur.execute.call_args.args[1]["embedding"]
        assert type(literal) is str
        assert literal.startswith("[") and literal.endswith("]")
        assert tuple(float(x) for x in literal[1:-1].split(",")) == vector

    def test_no_embedded_at_parameter(self):
        conn, cur = _make_conn()
        _insert(conn)
        assert "embedded_at" not in cur.execute.call_args.args[1]

    @pytest.mark.parametrize("dimension", [0, 1, 383, 385, 768])
    def test_wrong_dimension_raises_before_any_sql(self, dimension):
        conn, cur = _make_conn()
        with pytest.raises(ValueError, match="384 elements"):
            _insert(conn, vector=_vector(dimension))
        conn.cursor.assert_not_called()
        cur.execute.assert_not_called()

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), None, True, "0.1"],
                             ids=["nan", "inf", "none", "bool", "str"])
    def test_bad_vector_value_raises_before_any_sql(self, bad):
        vector = list(_vector())
        vector[5] = bad
        conn, cur = _make_conn()
        with pytest.raises(ValueError):
            _insert(conn, vector=vector)
        cur.execute.assert_not_called()

    def test_arguments_are_keyword_only(self):
        conn, _ = _make_conn()
        with pytest.raises(TypeError):
            insert_embedding(conn, _EMB, _INV, "1.0.0", "m", "r", "text", _vector())  # type: ignore[misc]

    def test_vector_is_not_mutated(self):
        vector = list(_vector())
        snapshot = list(vector)
        conn, _ = _make_conn()
        _insert(conn, vector=vector)
        assert vector == snapshot

    def test_database_error_propagates(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.errors.ForeignKeyViolation("fk")
        with pytest.raises(psycopg.Error):
            _insert(conn)


# ---------------------------------------------------------------------------
# ST07  Transactions
# ---------------------------------------------------------------------------

class TestNoTransactionControl:

    def test_fetches_never_commit_or_rollback(self):
        conn, _ = _make_conn(fetchone=_investigation_row(), fetchall=[_evidence_row()])
        fetch_investigation(conn, _INV)
        fetch_evidence(conn, _INV)
        text_conn, _ = _make_conn(fetchone={"document_text": "text"})
        fetch_stored_document_text(text_conn, _EMB)
        for used in (conn, text_conn):
            used.commit.assert_not_called()
            used.rollback.assert_not_called()
            used.close.assert_not_called()

    def test_insert_never_commits_or_rolls_back(self):
        conn, _ = _make_conn()
        _insert(conn)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    def test_insert_error_does_not_roll_back_here(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.OperationalError("boom")
        with pytest.raises(psycopg.OperationalError):
            _insert(conn)
        conn.rollback.assert_not_called()

    def test_module_never_calls_commit_rollback_connect_or_close(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"commit", "rollback", "connect", "close"})


# ---------------------------------------------------------------------------
# ST08  Import boundary
# ---------------------------------------------------------------------------

def _imported_modules(path: str) -> set[str]:
    tree = ast.parse(open(path, encoding="utf-8").read())
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestImportBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(embedding_store.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules(_MODULE_PATH) == {
            "__future__", "typing", "psycopg", "embedding_record", "incident_document",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["rca_persist", "rca_source", "rca_models", "rca_confidence", "rca_ranker",
         "pgvector", "numpy", "torch", "sentence_transformers",
         "sentence_transformer_backend", "embedding_provider", "embedding_pipeline",
         "retrieval_db", "os"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules(_MODULE_PATH)

    @pytest.mark.parametrize(
        "module", ["incident_signal.py", "embedding_record.py", "embedding_pipeline.py",
                   "embedding_provider.py", "incident_document.py",
                   "sentence_transformer_backend.py"],
    )
    def test_other_modules_do_not_import_psycopg(self, module):
        assert "psycopg" not in _imported_modules(os.path.join(_COMPONENT_DIR, module))

    def test_only_store_and_db_modules_import_psycopg(self):
        importers = sorted(
            name for name in os.listdir(_COMPONENT_DIR)
            if name.endswith(".py")
            and "psycopg" in _imported_modules(os.path.join(_COMPONENT_DIR, name))
        )
        assert importers == ["embedding_store.py", "retrieval_db.py"]

    def test_only_the_store_contains_sql(self):
        for name in os.listdir(_COMPONENT_DIR):
            if not name.endswith(".py") or name == "embedding_store.py":
                continue
            tree = ast.parse(open(os.path.join(_COMPONENT_DIR, name), encoding="utf-8").read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in {"execute", "executemany"}, name


# ---------------------------------------------------------------------------
# ST09  Similarity SELECT (Phase 12.6)
# ---------------------------------------------------------------------------

_SIMILAR_SQL = embedding_store._SQL_FETCH_SIMILAR_INVESTIGATIONS

_APPROVED_SIMILAR_SQL = """\
SELECT
    c.investigation_id,
    1.0 - (c.embedding <=> q.embedding) AS similarity
FROM public.rca_investigation_embeddings AS c
JOIN public.rca_investigation_embeddings AS q
  ON q.embedding_id = %(query_embedding_id)s
 AND q.investigation_id = %(investigation_id)s
 AND q.doc_version = c.doc_version
 AND q.model_name = c.model_name
 AND q.model_revision = c.model_revision
WHERE c.doc_version = %(doc_version)s
  AND c.model_name = %(model_name)s
  AND c.model_revision = %(model_revision)s
  AND c.investigation_id <> %(investigation_id)s
ORDER BY c.embedding <=> q.embedding ASC, c.investigation_id ASC
LIMIT %(top_k)s
"""

_SIMILAR_PARAMS = {
    "query_embedding_id", "investigation_id", "doc_version",
    "model_name", "model_revision", "top_k",
}


def _similar(conn, **overrides):
    kwargs = dict(
        query_embedding_id=_EMB,
        investigation_id=_INV,
        doc_version="1.0.0",
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        top_k=5,
    )
    kwargs.update(overrides)
    return fetch_similar_investigations(conn, **kwargs)


def _where_clause(sql: str) -> str:
    return sql.split("WHERE")[1].split("ORDER BY")[0]


class TestSimilaritySqlShape:

    def test_matches_the_approved_statement(self):
        assert _normalise(_SIMILAR_SQL) == _normalise(_APPROVED_SIMILAR_SQL)

    def test_select_list_exact(self):
        assert _select_columns(_SIMILAR_SQL) == [
            "c.investigation_id",
            "1.0 - (c.embedding <=> q.embedding) AS similarity",
        ]

    def test_similarity_is_one_minus_cosine_distance(self):
        assert "1.0 - (c.embedding <=> q.embedding) AS similarity" in _SIMILAR_SQL

    def test_uses_cosine_distance_operator_only(self):
        assert _SIMILAR_SQL.count("<=>") == 2
        for operator in ("<->", "<#>", "<+>"):
            assert operator not in _SIMILAR_SQL

    def test_candidate_and_query_are_the_embeddings_table(self):
        normalised = _normalise(_SIMILAR_SQL)
        assert "FROM public.rca_investigation_embeddings AS c" in normalised
        assert "JOIN public.rca_investigation_embeddings AS q" in normalised
        tables = set(re.findall(r"\b(?:FROM|JOIN)\s+([\w.]+)", _SIMILAR_SQL))
        assert tables == {"public.rca_investigation_embeddings"}

    def test_query_row_is_selected_by_embedding_id(self):
        assert "q.embedding_id = %(query_embedding_id)s" in _SIMILAR_SQL

    def test_query_row_must_belong_to_the_query_investigation(self):
        assert "q.investigation_id = %(investigation_id)s" in _SIMILAR_SQL

    @pytest.mark.parametrize("column", ["doc_version", "model_name", "model_revision"])
    def test_candidate_filtered_by_bound_identity(self, column):
        assert f"c.{column} = %({column})s" in _SIMILAR_SQL

    @pytest.mark.parametrize("column", ["doc_version", "model_name", "model_revision"])
    def test_query_and_candidate_share_identity(self, column):
        assert f"q.{column} = c.{column}" in _SIMILAR_SQL

    @pytest.mark.parametrize("column", ["doc_version", "model_name", "model_revision"])
    def test_each_identity_column_is_constrained_twice(self, column):
        """Embeddings from different document contracts or models are never compared."""
        assert _SIMILAR_SQL.count(f"c.{column}") == 2
        assert _SIMILAR_SQL.count(f"q.{column}") == 1

    def test_self_match_excluded_by_investigation_id(self):
        assert "c.investigation_id <> %(investigation_id)s" in _where_clause(_SIMILAR_SQL)

    def test_self_match_not_excluded_by_embedding_id(self):
        assert "c.embedding_id" not in _SIMILAR_SQL

    def test_order_by_distance_then_investigation_id(self):
        match = re.search(r"ORDER BY\s+(.*?)\s+LIMIT", _SIMILAR_SQL, re.DOTALL)
        assert _normalise(match.group(1)) == (
            "c.embedding <=> q.embedding ASC, c.investigation_id ASC"
        )

    def test_no_descending_or_time_based_ordering(self):
        assert "DESC" not in _SIMILAR_SQL.upper()
        assert "embedded_at" not in _SIMILAR_SQL

    def test_limit_is_a_bound_parameter(self):
        assert _normalise(_SIMILAR_SQL).endswith("LIMIT %(top_k)s")
        assert not re.search(r"LIMIT\s+\d", _SIMILAR_SQL)

    def test_named_parameters_exact(self):
        assert set(re.findall(r"%\((\w+)\)s", _SIMILAR_SQL)) == _SIMILAR_PARAMS

    def test_no_literal_values(self):
        """Only the constant 1.0 of the similarity formula appears as a literal."""
        assert "'" not in _SIMILAR_SQL
        assert re.findall(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])", _SIMILAR_SQL) == ["1.0"]

    def test_no_vector_sent_from_python(self):
        assert "::vector" not in _SIMILAR_SQL
        assert "%(embedding)s" not in _SIMILAR_SQL
        assert "%(vector)s" not in _SIMILAR_SQL

    def test_no_similarity_threshold(self):
        where = _where_clause(_SIMILAR_SQL)
        assert "<=>" not in where
        assert "similarity" not in where
        assert "HAVING" not in _SIMILAR_SQL.upper()

    def test_no_approximate_index_hints(self):
        upper = _SIMILAR_SQL.upper()
        for word in ("HNSW", "IVFFLAT", "PROBES", "EF_SEARCH"):
            assert word not in upper

    def test_read_only(self):
        upper = _SIMILAR_SQL.upper()
        for keyword in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "FOR UPDATE", "FOR SHARE", "LOCK"):
            assert keyword not in upper
        assert upper.lstrip().startswith("SELECT")

    def test_columns_used_exist_in_migration_010(self):
        with open(_MIGRATION_010, encoding="utf-8") as fh:
            migration = fh.read()
        for column in ("embedding_id", "investigation_id", "doc_version",
                       "model_name", "model_revision", "embedding"):
            assert re.search(rf"^\s*{column}\s+\S+", migration, re.MULTILINE), column

    def test_document_text_is_not_selected(self):
        """Presentation fields belong to a later phase."""
        assert "document_text" not in _SIMILAR_SQL

    def test_embeddings_table_select_is_granted_to_the_role(self):
        with open(_MIGRATION_011, encoding="utf-8") as fh:
            migration = _normalise(
                "\n".join(line.split("--")[0] for line in fh.read().splitlines())
            )
        assert (
            "GRANT INSERT, SELECT ON public.rca_investigation_embeddings TO incident_retrieval"
            in migration
        )


# ---------------------------------------------------------------------------
# ST10  fetch_similar_investigations (Phase 12.6)
# ---------------------------------------------------------------------------

class TestFetchSimilarInvestigations:

    def test_returns_pairs_in_cursor_order(self):
        conn, _ = _make_conn(fetchall=[
            {"investigation_id": "b" * 64, "similarity": 0.91},
            {"investigation_id": "c" * 64, "similarity": 0.42},
            {"investigation_id": "d" * 64, "similarity": 0.42},
        ])
        assert _similar(conn) == [("b" * 64, 0.91), ("c" * 64, 0.42), ("d" * 64, 0.42)]

    def test_order_is_not_changed_by_the_store(self):
        rows = [
            {"investigation_id": "z", "similarity": 0.1},
            {"investigation_id": "a", "similarity": 0.9},
        ]
        conn, _ = _make_conn(fetchall=rows)
        assert [pair[0] for pair in _similar(conn)] == ["z", "a"]

    def test_empty_list_when_no_candidates(self):
        conn, _ = _make_conn(fetchall=[])
        assert _similar(conn) == []

    def test_returns_a_list_of_tuples(self):
        conn, _ = _make_conn(fetchall=[{"investigation_id": "b", "similarity": 0.5}])
        result = _similar(conn)
        assert type(result) is list
        assert all(type(pair) is tuple and len(pair) == 2 for pair in result)

    def test_values_are_passed_through_unmodified(self):
        value = 0.123456789012345678
        conn, _ = _make_conn(fetchall=[{"investigation_id": " padded ", "similarity": value}])
        assert _similar(conn) == [(" padded ", value)]

    def test_similarity_is_not_rounded_or_validated_here(self):
        nan = float("nan")
        conn, _ = _make_conn(fetchall=[{"investigation_id": "b", "similarity": nan}])
        assert _similar(conn)[0][1] is nan

    def test_executes_the_sql_constant(self):
        conn, cur = _make_conn(fetchall=[])
        _similar(conn)
        assert cur.execute.call_count == 1
        assert cur.execute.call_args.args[0] is embedding_store._SQL_FETCH_SIMILAR_INVESTIGATIONS

    def test_parameter_keys_exact(self):
        conn, cur = _make_conn(fetchall=[])
        _similar(conn)
        assert set(cur.execute.call_args.args[1]) == _SIMILAR_PARAMS

    def test_parameters_bound_exactly(self):
        conn, cur = _make_conn(fetchall=[])
        _similar(conn, top_k=17)
        assert cur.execute.call_args.args[1] == {
            "query_embedding_id": _EMB,
            "investigation_id": _INV,
            "doc_version": "1.0.0",
            "model_name": "sentence-transformers/all-MiniLM-L6-v2",
            "model_revision": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            "top_k": 17,
        }

    def test_no_vector_parameter(self):
        conn, cur = _make_conn(fetchall=[])
        _similar(conn)
        params = cur.execute.call_args.args[1]
        assert "embedding" not in params and "vector" not in params
        assert not any(isinstance(v, (list, tuple)) for v in params.values())

    def test_uses_dict_row_cursor(self):
        conn, _ = _make_conn(fetchall=[])
        _similar(conn)
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_arguments_are_keyword_only(self):
        conn, _ = _make_conn(fetchall=[])
        with pytest.raises(TypeError):
            fetch_similar_investigations(conn, _EMB, _INV, "1.0.0", "m", "r", 5)  # type: ignore[misc]

    def test_no_commit_rollback_or_close(self):
        conn, _ = _make_conn(fetchall=[{"investigation_id": "b", "similarity": 0.5}])
        _similar(conn)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    def test_database_error_propagates_without_transaction_management(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.OperationalError("boom")
        with pytest.raises(psycopg.OperationalError):
            _similar(conn)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()

    def test_one_statement_per_call(self):
        conn, cur = _make_conn(fetchall=[])
        _similar(conn)
        _similar(conn)
        assert cur.execute.call_count == 2


# ---------------------------------------------------------------------------
# ST11  Investigation-context SELECT (Phase 12.7)
# ---------------------------------------------------------------------------

_CONTEXT_SQL = embedding_store._SQL_FETCH_INVESTIGATION_CONTEXTS

_APPROVED_CONTEXT_SQL = """\
SELECT
    investigation_id,
    anomaly_type,
    service_name,
    operation_name,
    confidence,
    severity,
    event_time,
    summary,
    limitations
FROM public.rca_investigations
WHERE investigation_id = ANY(%(investigation_ids)s)
ORDER BY investigation_id ASC
"""

_CONTEXT_COLUMNS = [
    "investigation_id", "anomaly_type", "service_name", "operation_name",
    "confidence", "severity", "event_time", "summary", "limitations",
]


def _context_row(investigation_id: str = _INV, **overrides) -> dict:
    import datetime

    row = {
        "investigation_id": investigation_id,
        "anomaly_type": "tool_failure",
        "service_name": "agentops-demo-app",
        "operation_name": "tool.execute/ToolExecutionError",
        "confidence": "HIGH",
        "severity": "CRITICAL",
        "event_time": datetime.datetime(2026, 9, 28, 14, 2, 11, tzinfo=datetime.timezone.utc),
        "summary": "Span 'tool.execute' showed the strongest contributing evidence.",
        "limitations": ["tool_name_absent"],
    }
    row.update(overrides)
    return row


class TestContextSqlShape:

    def test_matches_the_approved_statement(self):
        assert _normalise(_CONTEXT_SQL) == _normalise(_APPROVED_CONTEXT_SQL)

    def test_columns_exact(self):
        assert _select_columns(_CONTEXT_SQL) == _CONTEXT_COLUMNS

    def test_exactly_nine_columns(self):
        assert len(_select_columns(_CONTEXT_SQL)) == 9

    def test_every_column_is_granted_by_migration_011(self):
        assert set(_CONTEXT_COLUMNS) <= _granted_columns("public.rca_investigations")

    def test_only_trace_span_count_of_the_granted_columns_is_unused(self):
        assert _granted_columns("public.rca_investigations") - set(_CONTEXT_COLUMNS) == {
            "trace_span_count",
        }

    @pytest.mark.parametrize(
        "ungranted",
        ["anomaly_id", "analyzer_version", "investigated_at", "trace_id",
         "subject_span_id", "observed_value", "baseline_median", "anomaly_score",
         "trace_span_count"],
    )
    def test_excluded_column_not_selected(self, ungranted):
        assert not re.search(rf"\b{ungranted}\b", _CONTEXT_SQL)

    def test_columns_exist_in_migration_007(self):
        migration_007 = os.path.join(
            _COMPONENT_DIR, "..", "storage-consumer", "migrations",
            "007_create_rca_tables.sql",
        )
        with open(migration_007, encoding="utf-8") as fh:
            table = fh.read().split("CREATE TABLE public.rca_evidence")[0]
        for column in _CONTEXT_COLUMNS:
            assert re.search(rf"^\s+{column}\s+[A-Z]", table, re.MULTILINE), column

    def test_reads_only_rca_investigations(self):
        tables = set(re.findall(r"\b(?:FROM|JOIN)\s+([\w.]+)", _CONTEXT_SQL))
        assert tables == {"public.rca_investigations"}

    def test_no_evidence_or_embedding_table(self):
        assert "rca_evidence" not in _CONTEXT_SQL
        assert "rca_investigation_embeddings" not in _CONTEXT_SQL

    def test_batch_filter_uses_any_with_one_bound_parameter(self):
        assert "WHERE investigation_id = ANY(%(investigation_ids)s)" in _CONTEXT_SQL
        assert re.findall(r"%\((\w+)\)s", _CONTEXT_SQL) == ["investigation_ids"]

    def test_deterministic_order(self):
        assert _normalise(_CONTEXT_SQL).endswith("ORDER BY investigation_id ASC")

    def test_no_limit_or_literals(self):
        assert not re.search(r"\bLIMIT\b", _CONTEXT_SQL, re.IGNORECASE)
        assert "'" not in _CONTEXT_SQL
        assert not re.search(r"\d", _CONTEXT_SQL)

    def test_read_only(self):
        upper = _CONTEXT_SQL.upper()
        for keyword in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "FOR UPDATE", "FOR SHARE", "LOCK"):
            assert keyword not in upper
        assert upper.lstrip().startswith("SELECT")

    def test_no_similarity_or_vector_content(self):
        for fragment in ("<=>", "similarity", "embedding", "::vector"):
            assert fragment not in _CONTEXT_SQL


# ---------------------------------------------------------------------------
# ST12  fetch_investigation_contexts (Phase 12.7)
# ---------------------------------------------------------------------------

class TestFetchInvestigationContexts:

    def test_returns_one_dict_per_row(self):
        rows = [_context_row("b" * 64), _context_row("c" * 64, confidence="LOW")]
        conn, _ = _make_conn(fetchall=rows)
        result = fetch_investigation_contexts(conn, ["b" * 64, "c" * 64])
        assert result == rows
        assert type(result) is list
        assert all(type(row) is dict for row in result)

    def test_rows_are_copies_with_exactly_the_nine_keys(self):
        row = _context_row()
        conn, _ = _make_conn(fetchall=[row])
        result = fetch_investigation_contexts(conn, [_INV])
        assert result[0] is not row
        assert list(result[0]) == _CONTEXT_COLUMNS

    def test_cursor_order_is_preserved(self):
        rows = [_context_row("c" * 64), _context_row("b" * 64)]
        conn, _ = _make_conn(fetchall=rows)
        result = fetch_investigation_contexts(conn, ["b" * 64, "c" * 64])
        assert [row["investigation_id"] for row in result] == ["c" * 64, "b" * 64]

    def test_values_are_not_modified(self):
        row = _context_row(
            service_name=None, operation_name=None, summary="  padded \n text ",
            limitations=[],
        )
        conn, _ = _make_conn(fetchall=[row])
        assert fetch_investigation_contexts(conn, [_INV]) == [row]

    def test_empty_result(self):
        conn, _ = _make_conn(fetchall=[])
        assert fetch_investigation_contexts(conn, [_INV]) == []

    def test_missing_ids_are_simply_absent(self):
        conn, _ = _make_conn(fetchall=[_context_row("b" * 64)])
        result = fetch_investigation_contexts(conn, ["b" * 64, "c" * 64])
        assert [row["investigation_id"] for row in result] == ["b" * 64]

    def test_executes_the_sql_constant_once(self):
        conn, cur = _make_conn(fetchall=[])
        fetch_investigation_contexts(conn, [_INV, "b" * 64, "c" * 64])
        assert cur.execute.call_count == 1
        assert cur.execute.call_args.args[0] is embedding_store._SQL_FETCH_INVESTIGATION_CONTEXTS

    def test_ids_bound_as_one_list_parameter(self):
        conn, cur = _make_conn(fetchall=[])
        fetch_investigation_contexts(conn, [_INV, "b" * 64])
        assert cur.execute.call_args.args[1] == {"investigation_ids": [_INV, "b" * 64]}
        assert type(cur.execute.call_args.args[1]["investigation_ids"]) is list

    def test_tuple_of_ids_is_bound_as_a_list(self):
        conn, cur = _make_conn(fetchall=[])
        fetch_investigation_contexts(conn, (_INV, "b" * 64))
        assert cur.execute.call_args.args[1] == {"investigation_ids": [_INV, "b" * 64]}

    def test_id_order_and_duplicates_are_passed_through(self):
        conn, cur = _make_conn(fetchall=[])
        fetch_investigation_contexts(conn, ["c", "a", "c"])
        assert cur.execute.call_args.args[1]["investigation_ids"] == ["c", "a", "c"]

    def test_input_sequence_is_not_mutated(self):
        ids = [_INV, "b" * 64]
        conn, _ = _make_conn(fetchall=[])
        fetch_investigation_contexts(conn, ids)
        assert ids == [_INV, "b" * 64]

    def test_uses_dict_row_cursor(self):
        conn, _ = _make_conn(fetchall=[])
        fetch_investigation_contexts(conn, [_INV])
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_no_commit_rollback_or_close(self):
        conn, _ = _make_conn(fetchall=[_context_row()])
        fetch_investigation_contexts(conn, [_INV])
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    def test_database_error_propagates_without_transaction_management(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.OperationalError("boom")
        with pytest.raises(psycopg.OperationalError):
            fetch_investigation_contexts(conn, [_INV])
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()


# ---------------------------------------------------------------------------
# ST13  Discovery SELECT (Phase 12.8)
# ---------------------------------------------------------------------------

_IDS_SQL = embedding_store._SQL_FETCH_INVESTIGATION_IDS

_APPROVED_IDS_SQL = """\
SELECT investigation_id
FROM public.rca_investigations
ORDER BY investigation_id ASC
"""


class TestDiscoverySqlShape:

    def test_matches_the_approved_statement(self):
        assert _normalise(_IDS_SQL) == _normalise(_APPROVED_IDS_SQL)

    def test_selects_only_investigation_id(self):
        assert _select_columns(_IDS_SQL) == ["investigation_id"]

    def test_column_is_granted_by_migration_011(self):
        assert "investigation_id" in _granted_columns("public.rca_investigations")

    def test_reads_only_rca_investigations(self):
        tables = set(re.findall(r"\b(?:FROM|JOIN)\s+([\w.]+)", _IDS_SQL))
        assert tables == {"public.rca_investigations"}

    def test_no_eligibility_filter(self):
        """Eligibility is decided by the document builder, never by this query."""
        upper = _IDS_SQL.upper()
        assert "WHERE" not in upper
        assert "CONFIDENCE" not in upper
        assert "INSUFFICIENT_DATA" not in upper

    def test_already_embedded_investigations_are_not_excluded(self):
        lowered = _IDS_SQL.lower()
        for fragment in ("rca_investigation_embeddings", "not exists", "left join",
                         "except", " join "):
            assert fragment not in lowered

    def test_deterministic_ascending_order(self):
        assert _normalise(_IDS_SQL).endswith("ORDER BY investigation_id ASC")
        assert "DESC" not in _IDS_SQL.upper()

    def test_no_limit_parameters_or_literals(self):
        assert not re.search(r"\bLIMIT\b", _IDS_SQL, re.IGNORECASE)
        assert "%" not in _IDS_SQL
        assert "'" not in _IDS_SQL
        assert not re.search(r"\d", _IDS_SQL)

    def test_read_only(self):
        upper = _IDS_SQL.upper()
        for keyword in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "FOR UPDATE", "FOR SHARE", "LOCK"):
            assert keyword not in upper
        assert upper.lstrip().startswith("SELECT")

    def test_still_exactly_one_write_statement_in_the_store(self):
        writes = [
            name for name, sql in _ALL_SQL.items()
            if re.search(r"\b(INSERT|UPDATE|DELETE|TRUNCATE)\b", sql, re.IGNORECASE)
        ]
        assert writes == ["insert_embedding"]


# ---------------------------------------------------------------------------
# ST14  fetch_investigation_ids (Phase 12.8)
# ---------------------------------------------------------------------------

class TestFetchInvestigationIds:

    def test_returns_ids_in_cursor_order(self):
        conn, _ = _make_conn(fetchall=[
            {"investigation_id": "a" * 64},
            {"investigation_id": "b" * 64},
            {"investigation_id": "c" * 64},
        ])
        assert fetch_investigation_ids(conn) == ["a" * 64, "b" * 64, "c" * 64]

    def test_order_is_not_changed_by_the_store(self):
        conn, _ = _make_conn(fetchall=[{"investigation_id": "z"}, {"investigation_id": "a"}])
        assert fetch_investigation_ids(conn) == ["z", "a"]

    def test_empty_list_when_no_investigations(self):
        conn, _ = _make_conn(fetchall=[])
        assert fetch_investigation_ids(conn) == []

    def test_returns_a_plain_list(self):
        conn, _ = _make_conn(fetchall=[{"investigation_id": "a"}])
        assert type(fetch_investigation_ids(conn)) is list

    def test_values_are_passed_through_unmodified(self):
        conn, _ = _make_conn(fetchall=[{"investigation_id": " padded "}])
        assert fetch_investigation_ids(conn) == [" padded "]

    def test_executes_the_sql_constant_once_without_parameters(self):
        conn, cur = _make_conn(fetchall=[])
        fetch_investigation_ids(conn)
        cur.execute.assert_called_once_with(embedding_store._SQL_FETCH_INVESTIGATION_IDS)

    def test_uses_dict_row_cursor(self):
        conn, _ = _make_conn(fetchall=[])
        fetch_investigation_ids(conn)
        conn.cursor.assert_called_once_with(row_factory=psycopg.rows.dict_row)

    def test_takes_only_the_connection(self):
        conn, _ = _make_conn(fetchall=[])
        with pytest.raises(TypeError):
            fetch_investigation_ids(conn, "extra")  # type: ignore[call-arg]

    def test_no_commit_rollback_or_close(self):
        conn, _ = _make_conn(fetchall=[{"investigation_id": "a"}])
        fetch_investigation_ids(conn)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    def test_database_error_propagates_without_transaction_management(self):
        conn, cur = _make_conn()
        cur.execute.side_effect = psycopg.OperationalError("boom")
        with pytest.raises(psycopg.OperationalError):
            fetch_investigation_ids(conn)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()

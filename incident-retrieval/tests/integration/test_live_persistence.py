"""
incident-retrieval/tests/integration/test_live_persistence.py

Opt-in integration tests for embedding persistence (Phase 12.5).

Everything here is skipped by default.  There are two independent switches.

1. Real model, fake store — no database:

       INCIDENT_RETRIEVAL_RUN_MODEL_TESTS=1

   Requires incident-retrieval/requirements.txt and the locked model revision
   in the local Hugging Face cache.  Nothing is downloaded.

2. Live PostgreSQL, fake model:

       INCIDENT_RETRIEVAL_RUN_DB_TESTS=1
       INCIDENT_RETRIEVAL_DB_PASSWORD=<password of the incident_retrieval role>

   Requires migrations 010 and 011 to be applied and the incident_retrieval
   role to have a known password.

   These tests never leave a row behind.  embed_investigation() commits, so
   the tests hand it a connection wrapper whose commit() is a no-op, and the
   real transaction is rolled back at the end of every test.  The embeddings
   written inside the transaction use a clearly non-production model identity
   and a fake backend, never the real model.

No test here updates or deletes anything, and none touches a Phase 11 table
except to read the columns the incident_retrieval role is granted.

Test inventory:
    LM01  Real model + fake store: inserted outcome, unit vector, token usage
    LD01  Live database: inserted, then already_present on replay
    LD02  Live database: text_mismatch leaves the stored row untouched
    LD03  Live database: not_eligible investigation writes nothing
    LD04  Live database: nothing persists after rollback; baseline unchanged
"""

from __future__ import annotations

import math
import os

import pytest

import embedding_store
from embedding_pipeline import InvestigationNotFoundError, embed_investigation
from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider
from embedding_record import (
    STATUS_ALREADY_PRESENT,
    STATUS_INSERTED,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
    compute_embedding_id,
)
from incident_document import DOC_VERSION, EvidenceRow, InvestigationRow

_MODEL_SWITCH = "INCIDENT_RETRIEVAL_RUN_MODEL_TESTS"
_DB_SWITCH = "INCIDENT_RETRIEVAL_RUN_DB_TESTS"

_requires_model = pytest.mark.skipif(
    os.environ.get(_MODEL_SWITCH) != "1",
    reason=f"real-model tests are opt-in; set {_MODEL_SWITCH}=1",
)
_requires_db = pytest.mark.skipif(
    os.environ.get(_DB_SWITCH) != "1",
    reason=f"live-database tests are opt-in; set {_DB_SWITCH}=1",
)

# Identity used for rows written (and rolled back) by the live-database tests.
_TEST_MODEL_NAME = "phase-12.5-live-test/not-a-real-model"
_TEST_MODEL_REVISION = "live-test-only-not-a-real-revision"

_INV = "a" * 64


# ---------------------------------------------------------------------------
# LM01  Real model + fake store
# ---------------------------------------------------------------------------

class _InMemoryStore:
    def __init__(self, investigation, evidence) -> None:
        self.investigation = investigation
        self.evidence = evidence
        self.rows: dict[str, dict] = {}

    def fetch_investigation(self, conn, investigation_id):
        return self.investigation

    def fetch_evidence(self, conn, investigation_id):
        return list(self.evidence)

    def fetch_stored_document_text(self, conn, embedding_id):
        row = self.rows.get(embedding_id)
        return None if row is None else row["document_text"]

    def insert_embedding(self, conn, **kwargs):
        if kwargs["embedding_id"] in self.rows:
            return False
        self.rows[kwargs["embedding_id"]] = dict(kwargs)
        return True


class _NullConnection:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


@_requires_model
class TestRealModelWithFakeStore:

    @pytest.fixture
    def store(self, monkeypatch) -> _InMemoryStore:
        investigation = InvestigationRow(
            investigation_id=_INV,
            anomaly_type="tool_failure",
            service_name="agentops-demo-app",
            operation_name="tool.execute/ToolExecutionError",
            confidence="HIGH",
        )
        evidence = [
            EvidenceRow(
                investigation_id=_INV, rank_position=1, evidence_type="mixed",
                evidence_score=0.9, span_name="tool.execute",
                service_name="agentops-demo-app", status_code="ERROR",
                error_type="ToolExecutionError", tool_name=None, tool_status=None,
                agent_name="tool_agent", agent_operation="execute",
                retrieval_result_count=None, retrieval_top_relevance_score=None,
                is_direct_subject=True, is_root_span=False, trace_duration_fraction=0.01,
            ),
        ]
        fake = _InMemoryStore(investigation, evidence)
        for name in ("fetch_investigation", "fetch_evidence",
                     "fetch_stored_document_text", "insert_embedding"):
            monkeypatch.setattr(embedding_store, name, getattr(fake, name))
        return fake

    def test_inserted_with_unit_vector_and_token_usage(self, store):
        from sentence_transformer_backend import (
            MODEL_NAME, MODEL_REVISION, TokenUsage, create_default_provider,
        )

        conn = _NullConnection()
        provider = create_default_provider()
        outcome = embed_investigation(conn, provider, _INV)

        assert outcome.status == STATUS_INSERTED
        assert outcome.embedding_id == compute_embedding_id(
            _INV, DOC_VERSION, MODEL_NAME, MODEL_REVISION,
        )
        assert isinstance(outcome.token_usage, TokenUsage)
        assert outcome.token_usage.token_limit == 256
        assert outcome.token_usage.truncated is False

        row = store.rows[outcome.embedding_id]
        assert row["model_name"] == MODEL_NAME
        assert row["model_revision"] == MODEL_REVISION
        assert row["doc_version"] == "1.0.0"
        vector = row["vector"]
        assert len(vector) == 384
        assert all(math.isfinite(x) for x in vector)
        assert abs(math.hypot(*vector) - 1.0) <= 1e-12
        assert (conn.commits, conn.rollbacks) == (1, 0)

    def test_replay_does_not_use_the_model_again(self, store):
        from sentence_transformer_backend import create_default_provider

        provider = create_default_provider()
        first = embed_investigation(_NullConnection(), provider, _INV)
        fresh = create_default_provider()
        second = embed_investigation(_NullConnection(), fresh, _INV)

        assert first.status == STATUS_INSERTED
        assert second.status == STATUS_ALREADY_PRESENT
        assert fresh.backend.is_loaded is False
        assert len(store.rows) == 1


# ---------------------------------------------------------------------------
# Live database helpers
# ---------------------------------------------------------------------------

class _NoCommitConnection:
    """
    Wraps a real connection so that embed_investigation()'s commit() does not
    make anything durable.  rollback() is passed through.  The fixture rolls
    the real transaction back when the test ends.
    """

    def __init__(self, real) -> None:
        self._real = real
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, *args, **kwargs):
        return self._real.cursor(*args, **kwargs)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        self._real.rollback()


def _fake_backend(text: str) -> list[float]:
    """Deterministic non-model vector; depends only on the text length."""
    base = (len(text) % 7) + 1
    return [float(base + (i % 5)) for i in range(384)]


def _scalar(conn, sql: str, params: dict | None = None):
    with conn.cursor() as cur:
        cur.execute(sql, params or {})
        return cur.fetchone()[0]


_SQL_COUNT_EMBEDDINGS = "SELECT COUNT(embedding_id) FROM public.rca_investigation_embeddings"
_SQL_COUNT_INVESTIGATIONS = "SELECT COUNT(investigation_id) FROM public.rca_investigations"
_SQL_COUNT_EVIDENCE = "SELECT COUNT(investigation_id) FROM public.rca_evidence"
_SQL_COUNT_TEST_ROWS = (
    "SELECT COUNT(embedding_id) FROM public.rca_investigation_embeddings "
    "WHERE model_name = %(model_name)s"
)
_SQL_FIND_INVESTIGATION = (
    "SELECT investigation_id FROM public.rca_investigations "
    "WHERE confidence {op} 'INSUFFICIENT_DATA' ORDER BY investigation_id LIMIT 1"
)


@pytest.fixture
def real_conn():
    import retrieval_db

    conn = retrieval_db.connect()
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def conn(real_conn) -> _NoCommitConnection:
    return _NoCommitConnection(real_conn)


@pytest.fixture
def provider() -> EmbeddingProvider:
    identity = EmbeddingModelIdentity(_TEST_MODEL_NAME, _TEST_MODEL_REVISION, 384)
    return EmbeddingProvider(identity, _fake_backend)


@pytest.fixture
def eligible_id(real_conn) -> str:
    value = None
    with real_conn.cursor() as cur:
        cur.execute(_SQL_FIND_INVESTIGATION.format(op="<>"))
        row = cur.fetchone()
        value = None if row is None else row[0]
    if value is None:
        pytest.skip("no eligible investigation in the database")
    return value


@pytest.fixture
def ineligible_id(real_conn) -> str:
    value = None
    with real_conn.cursor() as cur:
        cur.execute(_SQL_FIND_INVESTIGATION.format(op="="))
        row = cur.fetchone()
        value = None if row is None else row[0]
    if value is None:
        pytest.skip("no INSUFFICIENT_DATA investigation in the database")
    return value


# ---------------------------------------------------------------------------
# LD01–LD04  Live database
# ---------------------------------------------------------------------------

@_requires_db
class TestLivePersistence:

    def test_connects_as_the_dedicated_role(self, real_conn):
        assert _scalar(real_conn, "SELECT current_user") == "incident_retrieval"

    def test_insert_then_replay(self, conn, real_conn, provider, eligible_id):
        before = _scalar(real_conn, _SQL_COUNT_EMBEDDINGS)

        first = embed_investigation(conn, provider, eligible_id)
        assert first.status == STATUS_INSERTED
        assert first.embedding_id == compute_embedding_id(
            eligible_id, DOC_VERSION, _TEST_MODEL_NAME, _TEST_MODEL_REVISION,
        )
        assert _scalar(real_conn, _SQL_COUNT_EMBEDDINGS) == before + 1

        second = embed_investigation(conn, provider, eligible_id)
        assert second.status == STATUS_ALREADY_PRESENT
        assert second.embedding_id == first.embedding_id
        assert _scalar(real_conn, _SQL_COUNT_EMBEDDINGS) == before + 1
        assert (conn.commits, conn.rollbacks) == (2, 0)

    def test_stored_row_contents(self, conn, real_conn, provider, eligible_id):
        outcome = embed_investigation(conn, provider, eligible_id)
        with real_conn.cursor() as cur:
            cur.execute(
                "SELECT investigation_id, doc_version, model_name, model_revision, "
                "document_text, vector_dims(embedding), embedded_at IS NOT NULL "
                "FROM public.rca_investigation_embeddings "
                "WHERE embedding_id = %(embedding_id)s",
                {"embedding_id": outcome.embedding_id},
            )
            row = cur.fetchone()
        assert row[0] == eligible_id
        assert row[1] == "1.0.0"
        assert row[2] == _TEST_MODEL_NAME
        assert row[3] == _TEST_MODEL_REVISION
        assert row[4].startswith("anomaly: ")
        assert row[4] == embedding_store.fetch_stored_document_text(real_conn, outcome.embedding_id)
        assert row[5] == 384
        assert row[6] is True

    def test_stored_vector_is_unit_length_and_self_similar(self, conn, real_conn, provider, eligible_id):
        outcome = embed_investigation(conn, provider, eligible_id)
        with real_conn.cursor() as cur:
            cur.execute(
                "SELECT vector_norm(embedding), embedding <=> embedding "
                "FROM public.rca_investigation_embeddings "
                "WHERE embedding_id = %(embedding_id)s",
                {"embedding_id": outcome.embedding_id},
            )
            norm, self_distance = cur.fetchone()
        assert abs(norm - 1.0) <= 1e-5
        assert abs(self_distance) <= 1e-6

    def test_text_mismatch_leaves_row_untouched(self, conn, real_conn, provider, eligible_id):
        embedding_id = compute_embedding_id(
            eligible_id, DOC_VERSION, _TEST_MODEL_NAME, _TEST_MODEL_REVISION,
        )
        embedding_store.insert_embedding(
            real_conn,
            embedding_id=embedding_id,
            investigation_id=eligible_id,
            doc_version=DOC_VERSION,
            model_name=_TEST_MODEL_NAME,
            model_revision=_TEST_MODEL_REVISION,
            document_text="Phase 12.5 live test: deliberately different text",
            vector=[1.0] + [0.0] * 383,
        )
        outcome = embed_investigation(conn, provider, eligible_id)
        assert outcome.status == STATUS_TEXT_MISMATCH
        assert outcome.embedding_id == embedding_id
        assert embedding_store.fetch_stored_document_text(real_conn, embedding_id) == (
            "Phase 12.5 live test: deliberately different text"
        )

    def test_not_eligible_writes_nothing(self, conn, real_conn, provider, ineligible_id):
        before = _scalar(real_conn, _SQL_COUNT_EMBEDDINGS)
        outcome = embed_investigation(conn, provider, ineligible_id)
        assert outcome.status == STATUS_NOT_ELIGIBLE
        assert outcome.embedding_id is None
        assert _scalar(real_conn, _SQL_COUNT_EMBEDDINGS) == before

    def test_unknown_investigation_raises(self, conn, provider):
        with pytest.raises(InvestigationNotFoundError):
            embed_investigation(conn, provider, "f" * 64)
        assert conn.rollbacks == 1

    def test_store_reads_match_granted_columns(self, real_conn, eligible_id):
        investigation = embedding_store.fetch_investigation(real_conn, eligible_id)
        evidence = embedding_store.fetch_evidence(real_conn, eligible_id)
        assert isinstance(investigation, InvestigationRow)
        assert investigation.investigation_id == eligible_id
        assert all(isinstance(row, EvidenceRow) for row in evidence)
        ranks = [row.rank_position for row in evidence]
        assert ranks == sorted(ranks)

    def test_nothing_persists_after_rollback(self, conn, real_conn, provider, eligible_id):
        investigations = _scalar(real_conn, _SQL_COUNT_INVESTIGATIONS)
        evidence = _scalar(real_conn, _SQL_COUNT_EVIDENCE)
        embeddings = _scalar(real_conn, _SQL_COUNT_EMBEDDINGS)

        assert embed_investigation(conn, provider, eligible_id).status == STATUS_INSERTED
        assert _scalar(real_conn, _SQL_COUNT_EMBEDDINGS) == embeddings + 1

        real_conn.rollback()

        assert _scalar(real_conn, _SQL_COUNT_EMBEDDINGS) == embeddings
        assert _scalar(real_conn, _SQL_COUNT_INVESTIGATIONS) == investigations
        assert _scalar(real_conn, _SQL_COUNT_EVIDENCE) == evidence
        assert _scalar(real_conn, _SQL_COUNT_TEST_ROWS, {"model_name": _TEST_MODEL_NAME}) == 0

    def test_no_test_rows_exist_at_start(self, real_conn):
        """A previous run must not have leaked a row."""
        assert _scalar(real_conn, _SQL_COUNT_TEST_ROWS, {"model_name": _TEST_MODEL_NAME}) == 0

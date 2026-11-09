"""
incident-retrieval/tests/integration/test_live_e2e.py

Opt-in end-to-end test against live PostgreSQL + pgvector and the real,
locally cached embedding model (Phase 12.8, Tier A).

Path proven:
    Phase 11 investigation -> deterministic incident document -> pinned local
    model -> 384-dimensional embedding -> pgvector persistence -> idempotent
    replay -> cosine retrieval -> historical context service and CLI

Skipped by default.  It runs only when BOTH switches are set:

    INCIDENT_RETRIEVAL_RUN_MODEL_TESTS=1
    INCIDENT_RETRIEVAL_RUN_DB_TESTS=1

and an administrator password is supplied through the environment:

    INCIDENT_RETRIEVAL_E2E_ADMIN_PASSWORD   required; there is no default
    INCIDENT_RETRIEVAL_E2E_ADMIN_USER       default: agentops

Host, port and database come from INCIDENT_RETRIEVAL_DB_HOST / _PORT / _NAME
(defaults localhost / 5432 / agentops).  The incident_retrieval password is
NOT needed.

Nothing is ever committed
-------------------------
The whole module runs inside ONE transaction on ONE administrator connection,
and that transaction is rolled back when the module finishes:

  1. Record baseline row counts (and the evidence id sequence position).
  2. Insert two fixture investigations as the administrator.
  3. SET LOCAL ROLE incident_retrieval.  From here on every statement is
     permission-checked as the restricted role.
  4. Run the real pipeline, backfill, retrieval, historical context and the
     CLI's main() on this same connection.
  5. ROLLBACK, then require the counts to equal the baseline.

The product code calls commit() and rollback() itself.  It is given a wrapper
(_SavepointConnection) that maps those calls onto a savepoint inside the
outer transaction, so a product commit never makes anything durable and a
product rollback never discards the fixtures.  Production transaction
semantics are not changed.

Fixtures
--------
Two investigations that reference the existing real anomaly, identified by
fixture analyzer_version values, with investigation_id computed by the real
Phase 11 formula SHA-256(anomaly_id | analyzer_version):

    fixture A   a copy of the real eligible investigation and its evidence,
                so its incident document is identical to the real one
    fixture B   deliberately different content

Fixture evidence rows carry explicit negative ids, so the evidence id
sequence is not advanced.  No DELETE, TRUNCATE, or reset is used anywhere.

The fixture SQL below exists only in this test.  Production SQL lives only in
embedding_store.py.

Test inventory (the checks of the approved E2E contract):
    E01  pgvector version, table, vector(384)                       (1, 2, 3)
    E02  restricted-role privileges are enforced                         (4)
    E03  pinned model loads locally and offline                       (5, 9)
    E04  eligible investigation persists exactly one embedding  (6, 8-11)
    E05  replay is idempotent                                           (12)
    E06  backfill processes every investigation                     (6, 13)
    E07  INSUFFICIENT_DATA persists nothing                              (7)
    E08  backfill rerun stores nothing new                              (12)
    E09  retrieval: self excluded, raw cosine, ordering        (13, 14, 16)
    E10  compatibility filtering is exact                               (15)
    E11  historical context keeps retrieval order                       (17)
    E12  CLI: disclaimer and exit code 0 for domain statuses        (18, 19)
    E13  only the expected rows were written                            (20)
    (teardown) outer rollback restores the baseline                     (20)
"""

from __future__ import annotations

import hashlib
import math
import os

import pytest

_MODEL_SWITCH = "INCIDENT_RETRIEVAL_RUN_MODEL_TESTS"
_DB_SWITCH = "INCIDENT_RETRIEVAL_RUN_DB_TESTS"
_ADMIN_PASSWORD_ENV = "INCIDENT_RETRIEVAL_E2E_ADMIN_PASSWORD"
_ADMIN_USER_ENV = "INCIDENT_RETRIEVAL_E2E_ADMIN_USER"

pytestmark = pytest.mark.skipif(
    os.environ.get(_MODEL_SWITCH) != "1" or os.environ.get(_DB_SWITCH) != "1",
    reason=(
        f"live E2E is opt-in; set both {_MODEL_SWITCH}=1 and {_DB_SWITCH}=1 "
        f"and provide {_ADMIN_PASSWORD_ENV}"
    ),
)

import embedding_store  # noqa: E402
import historical_context_cli  # noqa: E402
from embedding_backfill import backfill_embeddings  # noqa: E402
from embedding_pipeline import embed_investigation  # noqa: E402
from embedding_provider import EmbeddingModelIdentity  # noqa: E402
from embedding_record import compute_embedding_id  # noqa: E402
from historical_context import (  # noqa: E402
    HISTORICAL_CONTEXT_DISCLAIMER,
    get_historical_context,
)
from incident_document import DOC_VERSION, build_incident_document  # noqa: E402
from incident_signal import derive_signal  # noqa: E402
from sentence_transformer_backend import (  # noqa: E402
    EMBEDDING_DIMENSION,
    MODEL_MAX_SEQUENCE_LENGTH,
    MODEL_NAME,
    MODEL_REVISION,
    create_default_provider,
)
from similarity_search import find_similar_investigations  # noqa: E402


_ROLE = "incident_retrieval"
_FIXTURE_VERSION_A = "phase-12.8-fixture-a"
_FIXTURE_VERSION_B = "phase-12.8-fixture-b"
_FIXTURE_SERVICE_B = "phase-12-8-fixture-service"
_OTHER_REVISION = "phase-12.8-other-revision-not-a-real-revision"

_SAVEPOINT = "phase_12_8_product_tx"


# ---------------------------------------------------------------------------
# Fixture SQL (administrator; never committed)
# ---------------------------------------------------------------------------

_SQL_BASELINE = {
    "telemetry_spans": "SELECT count(*) FROM public.telemetry_spans",
    "anomaly_events": "SELECT count(*) FROM public.anomaly_events",
    "rca_investigations": "SELECT count(*) FROM public.rca_investigations",
    "rca_evidence": "SELECT count(*) FROM public.rca_evidence",
    "rca_investigation_embeddings":
        "SELECT count(*) FROM public.rca_investigation_embeddings",
    "rca_evidence_id_seq": "SELECT last_value FROM public.rca_evidence_id_seq",
    "fixture_investigations":
        "SELECT count(*) FROM public.rca_investigations "
        "WHERE analyzer_version LIKE 'phase-12.8-fixture-%'",
}

_SQL_FIND_ELIGIBLE = """\
SELECT investigation_id, anomaly_id
FROM public.rca_investigations
WHERE confidence <> 'INSUFFICIENT_DATA'
  AND analyzer_version NOT LIKE 'phase-12.8-fixture-%'
ORDER BY investigation_id ASC
LIMIT 1
"""

_SQL_FIND_INELIGIBLE = """\
SELECT investigation_id
FROM public.rca_investigations
WHERE confidence = 'INSUFFICIENT_DATA'
ORDER BY investigation_id ASC
LIMIT 1
"""

_SQL_COPY_INVESTIGATION = """\
INSERT INTO public.rca_investigations (
    investigation_id, anomaly_id, analyzer_version, trace_id, subject_span_id,
    service_name, operation_name, event_time, trace_span_count, anomaly_type,
    observed_value, baseline_median, anomaly_score, severity, confidence,
    summary, limitations
)
SELECT
    %(new_id)s, anomaly_id, %(version)s, trace_id, subject_span_id,
    service_name, operation_name, event_time, trace_span_count, anomaly_type,
    observed_value, baseline_median, anomaly_score, severity, confidence,
    summary, limitations
FROM public.rca_investigations
WHERE investigation_id = %(source_id)s
"""

_SQL_COPY_EVIDENCE = """\
INSERT INTO public.rca_evidence (
    id, investigation_id, span_id, parent_span_id, span_name, service_name,
    duration_ms, status_code, error_type, error_message, tool_name,
    tool_status, agent_name, agent_operation, retrieval_result_count,
    retrieval_top_relevance_score, is_root_span, is_error_span,
    is_direct_subject, depth, trace_duration_fraction, evidence_type,
    evidence_score, evidence_score_breakdown, explanation, rank_position
)
SELECT
    -(1000000 + row_number() OVER (ORDER BY rank_position, span_id)),
    %(new_id)s, span_id, parent_span_id, span_name, service_name,
    duration_ms, status_code, error_type, error_message, tool_name,
    tool_status, agent_name, agent_operation, retrieval_result_count,
    retrieval_top_relevance_score, is_root_span, is_error_span,
    is_direct_subject, depth, trace_duration_fraction, evidence_type,
    evidence_score, evidence_score_breakdown, explanation, rank_position
FROM public.rca_evidence
WHERE investigation_id = %(source_id)s
"""

_SQL_INSERT_INVESTIGATION_B = """\
INSERT INTO public.rca_investigations (
    investigation_id, anomaly_id, analyzer_version, trace_id, subject_span_id,
    service_name, operation_name, event_time, trace_span_count, anomaly_type,
    observed_value, baseline_median, anomaly_score, severity, confidence,
    summary, limitations
)
SELECT
    %(new_id)s, anomaly_id, %(version)s, trace_id, subject_span_id,
    %(service)s, 'trace', event_time, 2, 'latency',
    observed_value, baseline_median, anomaly_score, severity, 'MEDIUM',
    'Phase 12.8 fixture B: temporary validation row, never committed.',
    '{}'::text[]
FROM public.rca_investigations
WHERE investigation_id = %(source_id)s
"""

_SQL_INSERT_EVIDENCE_B = """\
INSERT INTO public.rca_evidence (
    id, investigation_id, span_id, parent_span_id, span_name, service_name,
    duration_ms, status_code, agent_name, agent_operation, is_root_span,
    is_error_span, is_direct_subject, depth, trace_duration_fraction,
    evidence_type, evidence_score, evidence_score_breakdown, explanation,
    rank_position
) VALUES (
    %(id)s, %(investigation_id)s, %(span_id)s, %(parent_span_id)s,
    %(span_name)s, %(service_name)s, %(duration_ms)s, %(status_code)s,
    %(agent_name)s, %(agent_operation)s, %(is_root_span)s, false, false,
    %(depth)s, %(trace_duration_fraction)s, %(evidence_type)s,
    %(evidence_score)s, 'phase-12.8 fixture', 'phase-12.8 fixture',
    %(rank_position)s
)
"""

_EVIDENCE_B = [
    dict(id=-2000001, span_id="phase-12-8-fixture-b-span-1", parent_span_id=None,
         span_name="checkout.request", duration_ms=1200.0, status_code="OK",
         agent_name=None, agent_operation=None, is_root_span=True, depth=0,
         trace_duration_fraction=1.0, evidence_type="telemetry", evidence_score=0.0,
         rank_position=1),
    dict(id=-2000002, span_id="phase-12-8-fixture-b-span-2",
         parent_span_id="phase-12-8-fixture-b-span-1",
         span_name="llm.generate", duration_ms=900.0, status_code="OK",
         agent_name="writer", agent_operation="draft", is_root_span=False, depth=1,
         trace_duration_fraction=0.75, evidence_type="duration", evidence_score=0.45,
         rank_position=2),
]

# Read-only verification SQL (run as the restricted role)
_SQL_EMBEDDING_ROW = """\
SELECT
    investigation_id, doc_version, model_name, model_revision, document_text,
    vector_dims(embedding) AS dims,
    array_length(embedding::real[], 1) AS length,
    vector_norm(embedding) AS norm,
    (SELECT count(*) FROM unnest(embedding::real[]) AS v
      WHERE v = 'NaN'::real OR v = 'Infinity'::real OR v = '-Infinity'::real
    ) AS non_finite,
    embedded_at IS NOT NULL AS has_timestamp
FROM public.rca_investigation_embeddings
WHERE embedding_id = %(embedding_id)s
"""

_SQL_COUNT_EMBEDDINGS_FOR = """\
SELECT count(embedding_id)
FROM public.rca_investigation_embeddings
WHERE investigation_id = %(investigation_id)s
"""

_SQL_PAIR_SIMILARITY = """\
SELECT 1.0 - (a.embedding <=> b.embedding)
FROM public.rca_investigation_embeddings AS a,
     public.rca_investigation_embeddings AS b
WHERE a.embedding_id = %(a)s AND b.embedding_id = %(b)s
"""

_DENIED_STATEMENTS = [
    "UPDATE public.rca_investigation_embeddings SET document_text = document_text WHERE false",
    "DELETE FROM public.rca_investigation_embeddings WHERE false",
    "TRUNCATE public.rca_investigation_embeddings",
    "UPDATE public.rca_investigations SET summary = summary WHERE false",
    "DELETE FROM public.rca_evidence WHERE false",
    "INSERT INTO public.rca_investigations (investigation_id) VALUES ('x')",
    "SELECT anomaly_id FROM public.rca_investigations LIMIT 1",
    "SELECT explanation FROM public.rca_evidence LIMIT 1",
    "SELECT count(*) FROM public.anomaly_events",
]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _SavepointConnection:
    """
    Gives the product code commit / rollback semantics inside one outer
    transaction that is never committed.

        commit()    release the savepoint and open a new one
        rollback()  roll back to the savepoint (the fixtures, created before
                    it, survive)
        close()     no-op; the test owns the real connection
    """

    def __init__(self, real) -> None:
        self._real = real
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self._execute(f"SAVEPOINT {_SAVEPOINT}")

    def _execute(self, sql: str) -> None:
        with self._real.cursor() as cur:
            cur.execute(sql)

    def cursor(self, *args, **kwargs):
        return self._real.cursor(*args, **kwargs)

    def commit(self) -> None:
        self.commits += 1
        self._execute(f"RELEASE SAVEPOINT {_SAVEPOINT}")
        self._execute(f"SAVEPOINT {_SAVEPOINT}")

    def rollback(self) -> None:
        self.rollbacks += 1
        self._execute(f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}")

    def close(self) -> None:
        self.closes += 1


class _State:
    """Shared between the ordered tests of this module."""

    def __init__(self) -> None:
        self.conn = None
        self.admin_user = ""
        self.baseline: dict = {}
        self.eligible_id = ""
        self.ineligible_id = None
        self.fixture_a = ""
        self.fixture_b = ""
        self.copied_evidence_rows = 0
        self.embeddings_written = 0
        self.retrieval_ids: list = []
        self.retrieval_similarities: list = []


# params is passed through as None when a statement has no parameters, so
# that a literal "%" in the SQL (LIKE patterns) is not read as a placeholder.

def _scalar(conn, sql: str, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return None if row is None else row[0]


def _row(conn, sql: str, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def _execute(conn, sql: str, params=None) -> int:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def _read_baseline(conn) -> dict:
    return {name: _scalar(conn, sql) for name, sql in _SQL_BASELINE.items()}


def _fixture_id(anomaly_id: str, analyzer_version: str) -> str:
    """The Phase 11 investigation identity formula."""
    return hashlib.sha256(f"{anomaly_id}|{analyzer_version}".encode("utf-8")).hexdigest()


def _canonical_text(conn, investigation_id: str) -> str:
    investigation = embedding_store.fetch_investigation(conn, investigation_id)
    evidence = embedding_store.fetch_evidence(conn, investigation_id)
    signal = derive_signal(investigation.anomaly_type, investigation.operation_name)
    document = build_incident_document(investigation, evidence, derived_signal=signal)
    assert document.eligible is True
    return document.text


def _locked_embedding_id(investigation_id: str) -> str:
    return compute_embedding_id(investigation_id, DOC_VERSION, MODEL_NAME, MODEL_REVISION)


def _cosine(a, b) -> float:
    dot = math.fsum(x * y for x, y in zip(a, b))
    return dot / (math.hypot(*a) * math.hypot(*b))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def state():
    import psycopg

    password = os.environ.get(_ADMIN_PASSWORD_ENV)
    if not password:
        pytest.fail(
            f"{_ADMIN_PASSWORD_ENV} must be set to run the live E2E test; "
            "there is no default"
        )
    admin_user = os.environ.get(_ADMIN_USER_ENV, "agentops")

    real = psycopg.connect(
        host=os.environ.get("INCIDENT_RETRIEVAL_DB_HOST", "localhost"),
        port=int(os.environ.get("INCIDENT_RETRIEVAL_DB_PORT", "5432")),
        dbname=os.environ.get("INCIDENT_RETRIEVAL_DB_NAME", "agentops"),
        user=admin_user,
        password=password,
    )
    assert real.autocommit is False

    shared = _State()
    shared.admin_user = admin_user
    baseline = None
    after = None
    try:
        # 1. Baseline (this also opens the single outer transaction).
        baseline = _read_baseline(real)
        shared.baseline = baseline
        assert baseline["fixture_investigations"] == 0, (
            "fixture investigations already exist; a previous run leaked rows"
        )

        eligible = _row(real, _SQL_FIND_ELIGIBLE)
        if eligible is None:
            pytest.skip("the database holds no eligible investigation")
        shared.eligible_id, anomaly_id = eligible
        shared.ineligible_id = _scalar(real, _SQL_FIND_INELIGIBLE)

        # 2. Fixtures, as the administrator.  Never committed.
        shared.fixture_a = _fixture_id(anomaly_id, _FIXTURE_VERSION_A)
        shared.fixture_b = _fixture_id(anomaly_id, _FIXTURE_VERSION_B)

        assert _execute(real, _SQL_COPY_INVESTIGATION, {
            "new_id": shared.fixture_a, "version": _FIXTURE_VERSION_A,
            "source_id": shared.eligible_id,
        }) == 1
        shared.copied_evidence_rows = _execute(real, _SQL_COPY_EVIDENCE, {
            "new_id": shared.fixture_a, "source_id": shared.eligible_id,
        })
        assert _execute(real, _SQL_INSERT_INVESTIGATION_B, {
            "new_id": shared.fixture_b, "version": _FIXTURE_VERSION_B,
            "service": _FIXTURE_SERVICE_B, "source_id": shared.eligible_id,
        }) == 1
        for evidence in _EVIDENCE_B:
            assert _execute(real, _SQL_INSERT_EVIDENCE_B, dict(
                evidence, investigation_id=shared.fixture_b,
                service_name=_FIXTURE_SERVICE_B,
            )) == 1

        # 3. Everything after this is permission-checked as the restricted role.
        _execute(real, f"SET LOCAL ROLE {_ROLE}")

        # 4. Product code gets savepoint-backed commit / rollback.
        shared.conn = _SavepointConnection(real)

        yield shared
    finally:
        # 5. Nothing is ever committed.
        real.rollback()
        try:
            after = _read_baseline(real)
        finally:
            real.rollback()
            real.close()

    if baseline is not None and after is not None:
        assert after == baseline, (
            f"the outer rollback did not restore the baseline: "
            f"before={baseline} after={after}"
        )


@pytest.fixture(scope="module")
def provider():
    return create_default_provider()


@pytest.fixture(scope="module")
def other_identity() -> EmbeddingModelIdentity:
    return EmbeddingModelIdentity(MODEL_NAME, _OTHER_REVISION, EMBEDDING_DIMENSION)


# ---------------------------------------------------------------------------
# Ordered E2E tests.  They share one transaction and build on each other.
# ---------------------------------------------------------------------------

class TestLiveE2E:

    # E01 ------------------------------------------------------------------
    def test_01_pgvector_and_schema(self, state):
        conn = state.conn
        assert _scalar(conn, "SELECT extversion FROM pg_extension WHERE extname = 'vector'") == "0.8.6"
        assert _scalar(
            conn, "SELECT to_regclass('public.rca_investigation_embeddings')::text",
        ) == "rca_investigation_embeddings"
        assert _scalar(
            conn,
            "SELECT format_type(atttypid, atttypmod) FROM pg_attribute "
            "WHERE attrelid = 'public.rca_investigation_embeddings'::regclass "
            "AND attname = 'embedding'",
        ) == "vector(384)"
        assert embedding_store.EMBEDDING_COLUMN_DIMENSION == EMBEDDING_DIMENSION == 384

    # E02 ------------------------------------------------------------------
    def test_02_restricted_role_privileges_are_enforced(self, state):
        import psycopg

        conn = state.conn
        assert _scalar(conn, "SELECT current_user") == _ROLE
        assert _scalar(conn, "SELECT session_user") == state.admin_user

        granted = {
            privilege: _scalar(
                conn,
                "SELECT has_table_privilege(current_user, "
                "'public.rca_investigation_embeddings', %(p)s)",
                {"p": privilege},
            )
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
        }
        assert granted == {
            "SELECT": True, "INSERT": True,
            "UPDATE": False, "DELETE": False, "TRUNCATE": False,
        }

        for statement in _DENIED_STATEMENTS:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                _execute(conn, statement)
            conn.rollback()        # back to the savepoint; fixtures survive

        # The role is still in effect and the fixtures are still visible.
        assert _scalar(conn, "SELECT current_user") == _ROLE
        assert embedding_store.fetch_investigation(conn, state.fixture_a) is not None
        assert embedding_store.fetch_investigation(conn, state.fixture_b) is not None

    # E03 ------------------------------------------------------------------
    def test_03_pinned_model_loads_locally_and_offline(self, provider):
        backend = provider.backend
        assert backend.is_loaded is False
        assert backend.local_files_only is True
        backend.load()
        assert backend.is_loaded is True
        assert os.environ["HF_HUB_OFFLINE"] == "1"

        import huggingface_hub.constants
        assert huggingface_hub.constants.HF_HUB_OFFLINE is True

        assert provider.identity == EmbeddingModelIdentity(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            dimension=384,
        )
        assert backend.token_usage("probe").token_limit == MODEL_MAX_SEQUENCE_LENGTH == 256

    # E04 ------------------------------------------------------------------
    def test_04_eligible_investigation_persists_exactly_one_embedding(self, state, provider):
        conn = state.conn
        assert _scalar(conn, _SQL_COUNT_EMBEDDINGS_FOR, {"investigation_id": state.fixture_a}) == 0
        commits_before = conn.commits

        outcome = embed_investigation(conn, provider, state.fixture_a)

        assert outcome.status == "inserted"
        assert outcome.embedding_id == _locked_embedding_id(state.fixture_a)
        assert outcome.token_usage is not None
        assert outcome.token_usage.token_limit == 256
        assert conn.commits == commits_before + 1
        state.embeddings_written += 1

        assert _scalar(conn, _SQL_COUNT_EMBEDDINGS_FOR, {"investigation_id": state.fixture_a}) == 1

        (investigation_id, doc_version, model_name, model_revision, document_text,
         dims, length, norm, non_finite, has_timestamp) = _row(
            conn, _SQL_EMBEDDING_ROW, {"embedding_id": outcome.embedding_id},
        )
        assert investigation_id == state.fixture_a
        # exact document / model identity
        assert doc_version == DOC_VERSION == "1.0.0"
        assert model_name == MODEL_NAME
        assert model_revision == MODEL_REVISION
        # stored text is exactly the deterministic builder output
        assert document_text == _canonical_text(conn, state.fixture_a)
        # 384 finite values, unit length
        assert dims == 384 and length == 384
        assert non_finite == 0
        assert abs(norm - 1.0) <= 1e-5
        assert has_timestamp is True

    # E05 ------------------------------------------------------------------
    def test_05_replay_is_idempotent(self, state, provider):
        conn = state.conn
        replay = embed_investigation(conn, provider, state.fixture_a)
        assert replay.status == "already_present"
        assert replay.embedding_id == _locked_embedding_id(state.fixture_a)
        assert replay.token_usage is None
        assert _scalar(conn, _SQL_COUNT_EMBEDDINGS_FOR, {"investigation_id": state.fixture_a}) == 1

    # E06 ------------------------------------------------------------------
    def test_06_backfill_processes_every_investigation(self, state, provider):
        conn = state.conn
        expected_ids = embedding_store.fetch_investigation_ids(conn)
        assert expected_ids == sorted(expected_ids)
        for needed in (state.eligible_id, state.fixture_a, state.fixture_b):
            assert needed in expected_ids

        seen = []
        report = backfill_embeddings(conn, provider, on_result=seen.append)

        assert [r.investigation_id for r in report.results] == expected_ids
        assert tuple(seen) == report.results
        statuses = {r.investigation_id: r.status for r in report.results}
        assert statuses[state.fixture_a] == "already_present"
        assert statuses[state.fixture_b] == "inserted"
        # The real investigation is new unless a manual backfill ran earlier.
        assert statuses[state.eligible_id] in ("inserted", "already_present")
        if state.ineligible_id is not None:
            assert statuses[state.ineligible_id] == "not_eligible"
        assert report.failures == 0, [r for r in report.results if r.status == "failure"]
        assert report.text_mismatch == 0
        assert report.succeeded is True
        state.embeddings_written += report.inserted

        for investigation_id in (state.eligible_id, state.fixture_a, state.fixture_b):
            assert _scalar(
                conn, _SQL_COUNT_EMBEDDINGS_FOR, {"investigation_id": investigation_id},
            ) == 1

        # The real investigation's stored text is the builder's text too.
        assert embedding_store.fetch_stored_document_text(
            conn, _locked_embedding_id(state.eligible_id),
        ) == _canonical_text(conn, state.eligible_id)

    # E07 ------------------------------------------------------------------
    def test_07_insufficient_data_persists_nothing(self, state, provider):
        if state.ineligible_id is None:
            pytest.skip("the database holds no INSUFFICIENT_DATA investigation")
        conn = state.conn
        outcome = embed_investigation(conn, provider, state.ineligible_id)
        assert outcome.status == "not_eligible"
        assert outcome.embedding_id is None
        assert _scalar(
            conn, _SQL_COUNT_EMBEDDINGS_FOR, {"investigation_id": state.ineligible_id},
        ) == 0

    # E08 ------------------------------------------------------------------
    def test_08_backfill_rerun_stores_nothing_new(self, state, provider):
        conn = state.conn
        before = _scalar(conn, "SELECT count(embedding_id) FROM public.rca_investigation_embeddings")
        rerun = backfill_embeddings(conn, provider)
        assert rerun.inserted == 0
        assert rerun.failures == 0 and rerun.text_mismatch == 0
        assert rerun.succeeded is True
        statuses = {r.investigation_id: r.status for r in rerun.results}
        for investigation_id in (state.eligible_id, state.fixture_a, state.fixture_b):
            assert statuses[investigation_id] == "already_present"
        assert _scalar(
            conn, "SELECT count(embedding_id) FROM public.rca_investigation_embeddings",
        ) == before

    # E09 ------------------------------------------------------------------
    def test_09_retrieval_excludes_self_and_returns_raw_cosine(self, state, provider):
        conn = state.conn
        outcome = find_similar_investigations(
            conn, provider.identity, state.eligible_id, top_k=50,
        )
        assert outcome.status == "ok"
        assert outcome.embedding_id == _locked_embedding_id(state.eligible_id)

        ids = [m.investigation_id for m in outcome.matches]
        similarity = {m.investigation_id: m.similarity for m in outcome.matches}

        # at least two eligible candidates, and never the query itself
        assert len(ids) >= 2
        assert state.eligible_id not in ids
        assert state.fixture_a in ids and state.fixture_b in ids
        assert len(ids) == len(set(ids))

        # fixture A has the identical document; fixture B does not
        assert similarity[state.fixture_a] >= 1.0 - 1e-5
        assert similarity[state.fixture_b] < similarity[state.fixture_a]
        assert ids.index(state.fixture_a) < ids.index(state.fixture_b)
        values = [m.similarity for m in outcome.matches]
        assert all(a >= b - 1e-12 for a, b in zip(values, values[1:]))
        assert all(-1.0 - 1e-6 <= v <= 1.0 + 1e-6 for v in values)

        # raw cosine similarity: equals 1 - cosine distance of the stored
        # vectors, and agrees with the cosine of freshly computed embeddings
        query_embedding_id = _locked_embedding_id(state.eligible_id)
        query_vector = provider.embed(_canonical_text(conn, state.eligible_id))
        for candidate in (state.fixture_a, state.fixture_b):
            stored = _scalar(conn, _SQL_PAIR_SIMILARITY, {
                "a": _locked_embedding_id(candidate), "b": query_embedding_id,
            })
            assert abs(similarity[candidate] - stored) <= 1e-12
            fresh = _cosine(query_vector, provider.embed(_canonical_text(conn, candidate)))
            assert abs(similarity[candidate] - fresh) <= 1e-5

        state.retrieval_ids = ids
        state.retrieval_similarities = values

    # E10 ------------------------------------------------------------------
    def test_10_compatibility_filtering_is_exact(self, state, provider, other_identity):
        conn = state.conn
        query_text = _canonical_text(conn, state.eligible_id)

        # Store an embedding for fixture B under a DIFFERENT model_revision,
        # with the query's own vector.  If revisions were not filtered it
        # would be compared, score ~1.0, and appear as a second B row.
        other_embedding_id = compute_embedding_id(
            state.fixture_b, DOC_VERSION, MODEL_NAME, _OTHER_REVISION,
        )
        assert embedding_store.insert_embedding(
            conn,
            embedding_id=other_embedding_id,
            investigation_id=state.fixture_b,
            doc_version=DOC_VERSION,
            model_name=MODEL_NAME,
            model_revision=_OTHER_REVISION,
            document_text=_canonical_text(conn, state.fixture_b),
            vector=provider.embed(query_text),
        ) is True
        conn.commit()
        state.embeddings_written += 1
        assert _scalar(conn, _SQL_COUNT_EMBEDDINGS_FOR, {"investigation_id": state.fixture_b}) == 2

        # Locked identity: unchanged result; the other revision is invisible.
        again = find_similar_investigations(
            conn, provider.identity, state.eligible_id, top_k=50,
        )
        assert [m.investigation_id for m in again.matches] == state.retrieval_ids
        assert [m.similarity for m in again.matches] == state.retrieval_similarities

        # Other identity: the query has no embedding there.
        missing = find_similar_investigations(conn, other_identity, state.eligible_id)
        assert missing.status == "query_not_embedded"
        assert missing.matches == ()

        # Other identity, queried from B: its only row has no compatible peer.
        alone = find_similar_investigations(conn, other_identity, state.fixture_b)
        assert alone.status == "ok"
        assert alone.embedding_id == other_embedding_id
        assert alone.matches == ()

    # E11 ------------------------------------------------------------------
    def test_11_historical_context_preserves_retrieval_order(self, state, provider):
        conn = state.conn
        context = get_historical_context(
            conn, provider.identity, state.eligible_id, top_k=50,
        )
        assert context.status == "ok"
        assert context.current.investigation_id == state.eligible_id
        assert [m.investigation.investigation_id for m in context.matches] == state.retrieval_ids
        assert [m.similarity for m in context.matches] == state.retrieval_similarities
        assert context.disclaimer == HISTORICAL_CONTEXT_DISCLAIMER

        by_id = {m.investigation.investigation_id: m.investigation for m in context.matches}
        assert by_id[state.fixture_a].anomaly_type == context.current.anomaly_type
        assert by_id[state.fixture_a].summary == context.current.summary
        assert by_id[state.fixture_b].anomaly_type == "latency"
        assert by_id[state.fixture_b].service_name == _FIXTURE_SERVICE_B
        assert by_id[state.fixture_b].confidence == "MEDIUM"
        assert by_id[state.fixture_b].limitations == ()

    # E12 ------------------------------------------------------------------
    def test_12_cli_prints_disclaimer_and_exits_zero(self, state, other_identity, monkeypatch, capsys):
        conn = state.conn
        note = f"Note: {HISTORICAL_CONTEXT_DISCLAIMER}"
        monkeypatch.setattr(historical_context_cli.retrieval_db, "connect", lambda: conn)
        commits_before = conn.commits

        # ok, with matches
        assert historical_context_cli.main([state.eligible_id, "--top-k", "50"]) == 0
        out = capsys.readouterr().out
        assert "Retrieval status: ok\n" in out
        positions = [out.index(f"investigation: {i}") for i in state.retrieval_ids]
        assert positions == sorted(positions)
        assert out.index(f"investigation: {state.eligible_id}") < positions[0]
        assert out.rstrip("\n").split("\n")[-1] == note

        # not_eligible
        if state.ineligible_id is not None:
            assert historical_context_cli.main([state.ineligible_id]) == 0
            out = capsys.readouterr().out
            assert "Retrieval status: not_eligible\n" in out
            assert out.rstrip("\n").split("\n")[-1] == note

        # query_not_embedded (no embedding under the other identity)
        monkeypatch.setattr(historical_context_cli, "_locked_identity", lambda: other_identity)
        assert historical_context_cli.main([state.eligible_id]) == 0
        out = capsys.readouterr().out
        assert "Retrieval status: query_not_embedded\n" in out
        assert out.rstrip("\n").split("\n")[-1] == note

        # investigation not found
        assert historical_context_cli.main(["f" * 64]) == 1
        assert "investigation not found" in capsys.readouterr().err

        # The CLI never commits; it rolled back and "closed" each time.
        assert conn.commits == commits_before
        assert conn.closes >= 3
        assert _scalar(conn, "SELECT current_user") == _ROLE

    # E13 ------------------------------------------------------------------
    def test_13_only_the_expected_rows_were_written(self, state):
        conn = state.conn
        baseline = state.baseline
        assert _scalar(
            conn, "SELECT count(investigation_id) FROM public.rca_investigations",
        ) == baseline["rca_investigations"] + 2
        assert _scalar(
            conn, "SELECT count(investigation_id) FROM public.rca_evidence",
        ) == baseline["rca_evidence"] + state.copied_evidence_rows + len(_EVIDENCE_B)
        assert _scalar(
            conn, "SELECT count(embedding_id) FROM public.rca_investigation_embeddings",
        ) == baseline["rca_investigation_embeddings"] + state.embeddings_written
        # Still inside the one outer transaction; nothing has been committed.
        # The module fixture now rolls back and re-checks the full baseline,
        # including the tables this role cannot read and the id sequence.

"""
incident-retrieval/tests/unit/test_similarity_search.py

Unit tests for similarity_search.py.

No database, no model, no network.  The store functions are replaced by an
in-memory fake, and the connection is a MagicMock used only to prove that
retrieval never touches it.

Test inventory:
    SS01  Constants, statuses, and result models
    SS02  Input validation: investigation_id, top_k, identity
    SS03  Outcome: ok (with and without matches)
    SS04  Outcome: not_eligible
    SS05  Outcome: query_not_embedded
    SS06  Outcome: text_mismatch
    SS07  Investigation not found
    SS08  Identity guards
    SS09  Arguments passed to the similarity query
    SS10  Result validation
    SS11  Ordering and values preserved
    SS12  Transaction ownership: no commit, no rollback
    SS13  Read-only, model-free, import boundary
"""

from __future__ import annotations

import ast
import dataclasses
import math
import os
from unittest.mock import MagicMock

import pytest

import embedding_store
import similarity_search
from embedding_pipeline import InvestigationNotFoundError
from embedding_provider import EmbeddingModelIdentity
from embedding_record import compute_embedding_id
from incident_document import (
    DOC_VERSION,
    EvidenceRow,
    IncidentDocument,
    InvestigationRow,
    build_incident_document,
)
from similarity_search import (
    DEFAULT_TOP_K,
    MAX_TOP_K,
    MIN_TOP_K,
    RETRIEVAL_STATUSES,
    STATUS_NOT_ELIGIBLE,
    STATUS_OK,
    STATUS_QUERY_NOT_EMBEDDED,
    STATUS_TEXT_MISMATCH,
    RetrievalOutcome,
    SimilarInvestigation,
    find_similar_investigations,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "similarity_search.py")

_INV = "a" * 64
_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_REV = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"

_B, _C, _D, _E, _F = ("b" * 64, "c" * 64, "d" * 64, "e" * 64, "f" * 64)


def _investigation(**overrides) -> InvestigationRow:
    kwargs = dict(
        investigation_id=_INV,
        anomaly_type="tool_failure",
        service_name="agentops-demo-app",
        operation_name="tool.execute/ToolExecutionError",
        confidence="HIGH",
    )
    kwargs.update(overrides)
    return InvestigationRow(**kwargs)


def _evidence(rank: int = 1, **overrides) -> EvidenceRow:
    kwargs = dict(
        investigation_id=_INV, rank_position=rank, evidence_type="mixed",
        evidence_score=0.9, span_name=f"span-{rank}", service_name="agentops-demo-app",
        status_code="ERROR", error_type="ToolExecutionError", tool_name=None,
        tool_status=None, agent_name="tool_agent", agent_operation="execute",
        retrieval_result_count=None, retrieval_top_relevance_score=None,
        is_direct_subject=(rank == 1), is_root_span=False, trace_duration_fraction=0.01,
    )
    kwargs.update(overrides)
    return EvidenceRow(**kwargs)


class FakeStore:
    """In-memory stand-in for the embedding_store functions."""

    def __init__(self) -> None:
        self.investigation = _investigation()
        self.evidence = [_evidence(1), _evidence(2)]
        self.stored_text: dict[str, str] = {}
        self.similar_rows: object = []
        self.calls: list[str] = []
        self.conns: list[object] = []
        self.similar_kwargs: dict = {}
        self.errors: dict[str, Exception] = {}

    def _record(self, name: str, conn) -> None:
        self.calls.append(name)
        self.conns.append(conn)
        if name in self.errors:
            raise self.errors[name]

    def fetch_investigation(self, conn, investigation_id):
        self._record("fetch_investigation", conn)
        self.fetch_investigation_id = investigation_id
        return self.investigation

    def fetch_evidence(self, conn, investigation_id):
        self._record("fetch_evidence", conn)
        self.fetch_evidence_id = investigation_id
        return list(self.evidence)

    def fetch_stored_document_text(self, conn, embedding_id):
        self._record("fetch_stored_document_text", conn)
        self.lookup_embedding_id = embedding_id
        return self.stored_text.get(embedding_id)

    def fetch_similar_investigations(self, conn, **kwargs):
        self._record("fetch_similar_investigations", conn)
        self.similar_kwargs = kwargs
        return self.similar_rows

    def insert_embedding(self, conn, **kwargs):
        self._record("insert_embedding", conn)
        raise AssertionError("retrieval must never write")


_STORE_FUNCTIONS = (
    "fetch_investigation", "fetch_evidence", "fetch_stored_document_text",
    "fetch_similar_investigations", "insert_embedding",
)


def _canonical_text(store: FakeStore) -> str:
    return build_incident_document(
        store.investigation, store.evidence, derived_signal="tool_failure",
    ).text


def _query_id(model: str = _MODEL, revision: str = _REV) -> str:
    return compute_embedding_id(_INV, DOC_VERSION, model, revision)


@pytest.fixture
def store(monkeypatch) -> FakeStore:
    """A store in which the query investigation is embedded and current."""
    fake = FakeStore()
    fake.stored_text[_query_id()] = _canonical_text(fake)
    for name in _STORE_FUNCTIONS:
        monkeypatch.setattr(embedding_store, name, getattr(fake, name))
    return fake


@pytest.fixture
def identity() -> EmbeddingModelIdentity:
    return EmbeddingModelIdentity(_MODEL, _REV, 384)


@pytest.fixture
def conn() -> MagicMock:
    return MagicMock()


def _find(conn, identity, investigation_id=_INV, **kwargs) -> RetrievalOutcome:
    return find_similar_investigations(conn, identity, investigation_id, **kwargs)


# ---------------------------------------------------------------------------
# SS01  Constants, statuses, result models
# ---------------------------------------------------------------------------

class TestConstantsAndModels:

    def test_top_k_constants(self):
        assert (DEFAULT_TOP_K, MIN_TOP_K, MAX_TOP_K) == (5, 1, 50)
        assert all(type(v) is int for v in (DEFAULT_TOP_K, MIN_TOP_K, MAX_TOP_K))

    def test_status_values(self):
        assert STATUS_OK == "ok"
        assert STATUS_NOT_ELIGIBLE == "not_eligible"
        assert STATUS_QUERY_NOT_EMBEDDED == "query_not_embedded"
        assert STATUS_TEXT_MISMATCH == "text_mismatch"

    def test_status_set_is_exactly_the_four(self):
        assert RETRIEVAL_STATUSES == {
            "ok", "not_eligible", "query_not_embedded", "text_mismatch",
        }
        assert isinstance(RETRIEVAL_STATUSES, frozenset)

    def test_shared_statuses_are_the_phase_12_5_constants(self):
        import embedding_record
        assert similarity_search.STATUS_NOT_ELIGIBLE is embedding_record.STATUS_NOT_ELIGIBLE
        assert similarity_search.STATUS_TEXT_MISMATCH is embedding_record.STATUS_TEXT_MISMATCH

    @pytest.mark.parametrize("cls", [SimilarInvestigation, RetrievalOutcome])
    def test_models_are_frozen_dataclasses(self, cls):
        assert dataclasses.is_dataclass(cls)
        assert cls.__dataclass_params__.frozen is True

    def test_similar_investigation_fields_exact(self):
        assert [(f.name, f.type) for f in dataclasses.fields(SimilarInvestigation)] == [
            ("investigation_id", "str"), ("similarity", "float"),
        ]

    def test_retrieval_outcome_fields_exact(self):
        assert [f.name for f in dataclasses.fields(RetrievalOutcome)] == [
            "investigation_id", "status", "embedding_id", "top_k", "matches",
        ]

    @pytest.mark.parametrize(
        "field",
        ["document_text", "doc_version", "model_name", "model_revision",
         "embedding_id", "embedded_at", "created_at", "summary", "severity",
         "confidence", "root_cause", "explanation"],
    )
    def test_match_has_no_presentation_or_rca_fields(self, field):
        assert field not in {f.name for f in dataclasses.fields(SimilarInvestigation)}

    def test_models_are_immutable(self):
        match = SimilarInvestigation(_B, 0.5)
        outcome = RetrievalOutcome(_INV, STATUS_OK, "e" * 64, 5, (match,))
        with pytest.raises(dataclasses.FrozenInstanceError):
            match.similarity = 0.9  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            outcome.matches = ()  # type: ignore[misc]

    def test_models_are_hashable_and_equal_by_value(self):
        a = RetrievalOutcome(_INV, STATUS_OK, "e" * 64, 5, (SimilarInvestigation(_B, 0.5),))
        b = RetrievalOutcome(_INV, STATUS_OK, "e" * 64, 5, (SimilarInvestigation(_B, 0.5),))
        assert a == b and hash(a) == hash(b)


# ---------------------------------------------------------------------------
# SS02  Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:

    @pytest.mark.parametrize("value", [None, 123, b"a", "", "   ", "\t\n", ["a"]],
                             ids=["none", "int", "bytes", "empty", "blank", "tab-lf", "list"])
    def test_invalid_investigation_id_raises(self, conn, identity, store, value):
        with pytest.raises(ValueError, match="investigation_id"):
            _find(conn, identity, value)
        assert store.calls == []

    def test_default_top_k_is_five(self, conn, identity, store):
        outcome = _find(conn, identity)
        assert outcome.top_k == 5
        assert store.similar_kwargs["top_k"] == 5

    @pytest.mark.parametrize("top_k", [1, 2, 5, 49, 50])
    def test_valid_top_k_accepted_and_passed_through(self, conn, identity, store, top_k):
        outcome = _find(conn, identity, top_k=top_k)
        assert outcome.top_k == top_k
        assert store.similar_kwargs["top_k"] == top_k

    @pytest.mark.parametrize("top_k", [0, -1, -50, 51, 100, 10 ** 9])
    def test_out_of_range_top_k_raises(self, conn, identity, store, top_k):
        with pytest.raises(ValueError, match="top_k must be between 1 and 50"):
            _find(conn, identity, top_k=top_k)
        assert store.calls == []

    @pytest.mark.parametrize("top_k", [True, False])
    def test_bool_top_k_raises(self, conn, identity, store, top_k):
        with pytest.raises(ValueError, match="top_k must be int"):
            _find(conn, identity, top_k=top_k)
        assert store.calls == []

    @pytest.mark.parametrize("top_k", [5.0, 1.5, "5", None, [5], (5,), b"5"],
                             ids=["float", "fraction", "str", "none", "list", "tuple", "bytes"])
    def test_non_int_top_k_raises(self, conn, identity, store, top_k):
        with pytest.raises(ValueError, match="top_k must be int"):
            _find(conn, identity, top_k=top_k)
        assert store.calls == []

    def test_top_k_is_never_clamped(self, conn, identity, store):
        for bad in (0, 51):
            with pytest.raises(ValueError):
                _find(conn, identity, top_k=bad)
        assert store.calls == []

    def test_top_k_is_keyword_only(self, conn, identity, store):
        with pytest.raises(TypeError):
            find_similar_investigations(conn, identity, _INV, 5)  # type: ignore[misc]

    @pytest.mark.parametrize(
        "bad_identity",
        [None, "model", (_MODEL, _REV, 384), {"model_name": _MODEL}, MagicMock()],
        ids=["none", "str", "tuple", "dict", "mock"],
    )
    def test_non_identity_raises(self, conn, store, bad_identity):
        with pytest.raises(ValueError, match="identity"):
            find_similar_investigations(conn, bad_identity, _INV)
        assert store.calls == []

    def test_a_provider_is_not_accepted_in_place_of_an_identity(self, conn, store):
        from embedding_provider import EmbeddingProvider
        provider = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 384), lambda t: [1.0] * 384)
        with pytest.raises(ValueError, match="identity"):
            find_similar_investigations(conn, provider, _INV)

    def test_invalid_input_never_touches_the_connection(self, conn, identity, store):
        with pytest.raises(ValueError):
            _find(conn, identity, "", top_k=0)
        assert conn.mock_calls == []


# ---------------------------------------------------------------------------
# SS03  Outcome: ok
# ---------------------------------------------------------------------------

class TestOk:

    def test_outcome_with_matches(self, conn, identity, store):
        store.similar_rows = [(_B, 0.91), (_C, 0.5), (_D, 0.25)]
        assert _find(conn, identity) == RetrievalOutcome(
            investigation_id=_INV,
            status=STATUS_OK,
            embedding_id=_query_id(),
            top_k=5,
            matches=(
                SimilarInvestigation(_B, 0.91),
                SimilarInvestigation(_C, 0.5),
                SimilarInvestigation(_D, 0.25),
            ),
        )

    def test_no_historical_matches_is_still_ok(self, conn, identity, store):
        store.similar_rows = []
        outcome = _find(conn, identity)
        assert outcome.status == STATUS_OK
        assert outcome.matches == ()
        assert outcome.embedding_id == _query_id()

    def test_matches_is_a_tuple_of_similar_investigation(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9), (_C, 0.8)]
        outcome = _find(conn, identity)
        assert type(outcome.matches) is tuple
        assert all(type(m) is SimilarInvestigation for m in outcome.matches)

    def test_fewer_rows_than_top_k_is_normal(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9)]
        outcome = _find(conn, identity, top_k=50)
        assert outcome.status == STATUS_OK and len(outcome.matches) == 1

    def test_exactly_top_k_rows(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9), (_C, 0.8), (_D, 0.7)]
        assert len(_find(conn, identity, top_k=3).matches) == 3

    def test_step_order(self, conn, identity, store):
        _find(conn, identity)
        assert store.calls == [
            "fetch_investigation", "fetch_evidence",
            "fetch_stored_document_text", "fetch_similar_investigations",
        ]

    def test_store_rows_as_lists_are_accepted(self, conn, identity, store):
        store.similar_rows = [[_B, 0.9], [_C, 0.8]]
        assert [m.investigation_id for m in _find(conn, identity).matches] == [_B, _C]

    def test_store_result_as_tuple_is_accepted(self, conn, identity, store):
        store.similar_rows = ((_B, 0.9),)
        assert len(_find(conn, identity).matches) == 1

    def test_zero_informative_evidence_proceeds_normally(self, conn, identity, store):
        store.evidence = []
        store.stored_text[_query_id()] = _canonical_text(store)
        assert _canonical_text(store).endswith("evidence: none")
        store.similar_rows = [(_B, 0.7)]
        outcome = _find(conn, identity)
        assert outcome.status == STATUS_OK and len(outcome.matches) == 1

    @pytest.mark.parametrize("confidence", ["HIGH", "MEDIUM", "LOW"])
    def test_every_other_confidence_is_retrievable(self, conn, identity, store, confidence):
        store.investigation = _investigation(confidence=confidence)
        assert _find(conn, identity).status == STATUS_OK

    def test_repeated_calls_are_deterministic(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9), (_C, 0.8)]
        assert _find(conn, identity) == _find(conn, identity) == _find(conn, identity)

    def test_store_rows_are_not_mutated(self, conn, identity, store):
        rows = [(_B, 0.9), (_C, 0.8)]
        store.similar_rows = rows
        _find(conn, identity)
        assert rows == [(_B, 0.9), (_C, 0.8)]


# ---------------------------------------------------------------------------
# SS04  Outcome: not_eligible
# ---------------------------------------------------------------------------

class TestNotEligible:

    @pytest.fixture(autouse=True)
    def _ineligible(self, store):
        store.investigation = _investigation(confidence="INSUFFICIENT_DATA")
        store.evidence = []

    def test_outcome(self, conn, identity, store):
        assert _find(conn, identity) == RetrievalOutcome(
            _INV, STATUS_NOT_ELIGIBLE, None, 5, (),
        )

    def test_no_embeddings_query_is_issued(self, conn, identity, store):
        _find(conn, identity)
        assert store.calls == ["fetch_investigation", "fetch_evidence"]

    def test_top_k_is_echoed(self, conn, identity, store):
        assert _find(conn, identity, top_k=17).top_k == 17

    def test_identity_guards_are_not_reached(self, conn, store):
        wrong = EmbeddingModelIdentity(_MODEL, _REV, 3)
        assert _find(conn, wrong).status == STATUS_NOT_ELIGIBLE

    @pytest.mark.parametrize("confidence", [" INSUFFICIENT_DATA", "insufficient_data"])
    def test_only_the_exact_value_is_not_eligible(self, conn, identity, store, confidence):
        store.investigation = _investigation(confidence=confidence)
        store.stored_text[_query_id()] = _canonical_text(store)
        assert _find(conn, identity).status == STATUS_OK


# ---------------------------------------------------------------------------
# SS05  Outcome: query_not_embedded
# ---------------------------------------------------------------------------

class TestQueryNotEmbedded:

    def test_outcome(self, conn, identity, store):
        store.stored_text.clear()
        assert _find(conn, identity) == RetrievalOutcome(
            _INV, STATUS_QUERY_NOT_EMBEDDED, _query_id(), 5, (),
        )

    def test_similarity_query_is_not_issued(self, conn, identity, store):
        store.stored_text.clear()
        _find(conn, identity)
        assert store.calls == [
            "fetch_investigation", "fetch_evidence", "fetch_stored_document_text",
        ]

    def test_nothing_is_embedded_or_persisted(self, conn, identity, store):
        store.stored_text.clear()
        _find(conn, identity)
        assert "insert_embedding" not in store.calls
        assert store.stored_text == {}

    def test_embedding_under_another_model_revision_does_not_count(self, conn, identity, store):
        store.stored_text.clear()
        store.stored_text[_query_id(revision="0" * 40)] = _canonical_text(store)
        assert _find(conn, identity).status == STATUS_QUERY_NOT_EMBEDDED

    def test_embedding_under_another_model_name_does_not_count(self, conn, identity, store):
        store.stored_text.clear()
        store.stored_text[_query_id(model="other/model")] = _canonical_text(store)
        assert _find(conn, identity).status == STATUS_QUERY_NOT_EMBEDDED

    def test_embedding_under_another_doc_version_does_not_count(self, conn, identity, store):
        store.stored_text.clear()
        store.stored_text[compute_embedding_id(_INV, "0.9.0", _MODEL, _REV)] = _canonical_text(store)
        assert _find(conn, identity).status == STATUS_QUERY_NOT_EMBEDDED

    def test_lookup_uses_the_compatible_embedding_id(self, conn, identity, store):
        _find(conn, identity)
        assert store.lookup_embedding_id == _query_id()

    def test_repeat_calls_keep_reporting_it(self, conn, identity, store):
        store.stored_text.clear()
        for _ in range(3):
            assert _find(conn, identity).status == STATUS_QUERY_NOT_EMBEDDED


# ---------------------------------------------------------------------------
# SS06  Outcome: text_mismatch
# ---------------------------------------------------------------------------

class TestTextMismatch:

    def test_outcome(self, conn, identity, store):
        store.stored_text[_query_id()] = "anomaly: tool_failure\nolder text"
        assert _find(conn, identity) == RetrievalOutcome(
            _INV, STATUS_TEXT_MISMATCH, _query_id(), 5, (),
        )

    def test_stale_embedding_is_never_used_for_retrieval(self, conn, identity, store):
        store.stored_text[_query_id()] = "older text"
        store.similar_rows = [(_B, 0.99)]
        outcome = _find(conn, identity)
        assert outcome.matches == ()
        assert "fetch_similar_investigations" not in store.calls

    def test_stored_text_is_not_changed(self, conn, identity, store):
        store.stored_text[_query_id()] = "older text"
        _find(conn, identity)
        assert store.stored_text[_query_id()] == "older text"
        assert "insert_embedding" not in store.calls

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda t: t + "\n",
            lambda t: t + " ",
            lambda t: " " + t,
            lambda t: t.upper(),
            lambda t: t.replace("\n", "\r\n"),
            lambda t: t[:-1],
        ],
        ids=["trailing-newline", "trailing-space", "leading-space", "case", "crlf", "truncated"],
    )
    def test_comparison_is_exact(self, conn, identity, store, mutate):
        store.stored_text[_query_id()] = mutate(_canonical_text(store))
        assert _find(conn, identity).status == STATUS_TEXT_MISMATCH

    def test_identical_text_proceeds(self, conn, identity, store):
        assert _find(conn, identity).status == STATUS_OK

    def test_is_returned_not_raised(self, conn, identity, store):
        store.stored_text[_query_id()] = "older text"
        assert _find(conn, identity).status == STATUS_TEXT_MISMATCH


# ---------------------------------------------------------------------------
# SS07  Investigation not found
# ---------------------------------------------------------------------------

class TestNotFound:

    def test_missing_investigation_raises_the_reused_error(self, conn, identity, store):
        import embedding_pipeline
        store.investigation = None
        with pytest.raises(InvestigationNotFoundError) as excinfo:
            _find(conn, identity)
        assert excinfo.value.investigation_id == _INV
        assert type(excinfo.value) is embedding_pipeline.InvestigationNotFoundError

    def test_stops_immediately(self, conn, identity, store):
        store.investigation = None
        with pytest.raises(InvestigationNotFoundError):
            _find(conn, identity)
        assert store.calls == ["fetch_investigation"]

    def test_looked_up_by_the_given_id(self, conn, identity, store):
        _find(conn, identity)
        assert store.fetch_investigation_id == _INV
        assert store.fetch_evidence_id == _INV


# ---------------------------------------------------------------------------
# SS08  Identity guards
# ---------------------------------------------------------------------------

class TestIdentityGuards:

    @pytest.mark.parametrize("dimension", [1, 383, 385, 768])
    def test_wrong_dimension_raises(self, conn, store, dimension):
        wrong = EmbeddingModelIdentity(_MODEL, _REV, dimension)
        with pytest.raises(RuntimeError, match="identity dimension"):
            _find(conn, wrong)

    def test_wrong_dimension_stops_before_any_embeddings_query(self, conn, store):
        with pytest.raises(RuntimeError):
            _find(conn, EmbeddingModelIdentity(_MODEL, _REV, 3))
        assert store.calls == ["fetch_investigation", "fetch_evidence"]

    def test_wrong_doc_version_raises(self, conn, identity, store, monkeypatch):
        def fake_builder(investigation, evidence, *, derived_signal):
            return IncidentDocument(_INV, "9.9.9", True, "anomaly: x")

        monkeypatch.setattr(similarity_search, "build_incident_document", fake_builder)
        with pytest.raises(RuntimeError, match="doc_version"):
            _find(conn, identity)
        assert "fetch_similar_investigations" not in store.calls
        assert "fetch_stored_document_text" not in store.calls

    def test_doc_version_is_the_locked_constant(self):
        assert similarity_search.DOC_VERSION == DOC_VERSION == "1.0.0"

    def test_builder_error_propagates(self, conn, identity, store):
        store.evidence = [_evidence(1), _evidence(1)]
        with pytest.raises(ValueError, match="rank_position"):
            _find(conn, identity)
        assert store.calls == ["fetch_investigation", "fetch_evidence"]


# ---------------------------------------------------------------------------
# SS09  Arguments passed to the similarity query
# ---------------------------------------------------------------------------

class TestSimilarityQueryArguments:

    def test_keyword_set_exact(self, conn, identity, store):
        _find(conn, identity)
        assert set(store.similar_kwargs) == {
            "query_embedding_id", "investigation_id", "doc_version",
            "model_name", "model_revision", "top_k",
        }

    def test_values_exact(self, conn, identity, store):
        _find(conn, identity, top_k=7)
        assert store.similar_kwargs == {
            "query_embedding_id": _query_id(),
            "investigation_id": _INV,
            "doc_version": "1.0.0",
            "model_name": _MODEL,
            "model_revision": _REV,
            "top_k": 7,
        }

    def test_no_vector_is_passed(self, conn, identity, store):
        _find(conn, identity)
        assert not any(k in store.similar_kwargs for k in ("vector", "embedding", "query_vector"))
        assert not any(isinstance(v, (list, tuple)) for v in store.similar_kwargs.values())

    def test_query_embedding_id_matches_the_text_lookup(self, conn, identity, store):
        _find(conn, identity)
        assert store.similar_kwargs["query_embedding_id"] == store.lookup_embedding_id

    def test_identity_drives_the_compatibility_filters(self, conn, store):
        other = EmbeddingModelIdentity("other/model", "other-revision", 384)
        other_id = compute_embedding_id(_INV, DOC_VERSION, "other/model", "other-revision")
        store.stored_text[other_id] = _canonical_text(store)
        outcome = _find(conn, other)
        assert outcome.embedding_id == other_id != _query_id()
        assert store.similar_kwargs["model_name"] == "other/model"
        assert store.similar_kwargs["model_revision"] == "other-revision"
        assert store.similar_kwargs["query_embedding_id"] == other_id

    def test_doc_version_comes_from_the_document(self, conn, identity, store):
        _find(conn, identity)
        assert store.similar_kwargs["doc_version"] == DOC_VERSION

    def test_same_connection_passed_to_every_store_call(self, conn, identity, store):
        _find(conn, identity)
        assert len(store.conns) == 4
        assert all(c is conn for c in store.conns)

    def test_similarity_query_issued_exactly_once(self, conn, identity, store):
        _find(conn, identity)
        assert store.calls.count("fetch_similar_investigations") == 1


# ---------------------------------------------------------------------------
# SS10  Result validation
# ---------------------------------------------------------------------------

class TestResultValidation:

    def _raises(self, conn, identity, store, rows, match, top_k=5):
        store.similar_rows = rows
        with pytest.raises(RuntimeError, match=match):
            _find(conn, identity, top_k=top_k)

    @pytest.mark.parametrize(
        "rows", [None, "rows", 5, {"a": 1}, iter([(_B, 0.5)])],
        ids=["none", "str", "int", "dict", "iterator"],
    )
    def test_non_list_result_raises(self, conn, identity, store, rows):
        self._raises(conn, identity, store, rows, "expected a list")

    @pytest.mark.parametrize(
        "row",
        [(_B,), (_B, 0.5, "extra"), (), _B, 0.5, None, {"investigation_id": _B, "similarity": 0.5}],
        ids=["one-element", "three-elements", "empty", "bare-str", "bare-float", "none", "dict"],
    )
    def test_malformed_row_shape_raises(self, conn, identity, store, row):
        self._raises(conn, identity, store, [row], "malformed")

    def test_malformed_row_reports_its_position(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, 0.9), (_C,)], "row 1 is malformed")

    @pytest.mark.parametrize(
        "bad_id", [None, 123, b"b", "", "   ", ["b"], 1.5],
        ids=["none", "int", "bytes", "empty", "blank", "list", "float"],
    )
    def test_invalid_returned_investigation_id_raises(self, conn, identity, store, bad_id):
        self._raises(conn, identity, store, [(bad_id, 0.5)], "invalid investigation_id")

    @pytest.mark.parametrize("value", [True, False])
    def test_bool_similarity_raises(self, conn, identity, store, value):
        self._raises(conn, identity, store, [(_B, value)], "real number")

    @pytest.mark.parametrize(
        "value", [None, "0.5", b"0.5", [0.5], 0.5 + 0j],
        ids=["none", "str", "bytes", "list", "complex"],
    )
    def test_non_numeric_similarity_raises(self, conn, identity, store, value):
        self._raises(conn, identity, store, [(_B, value)], "real number")

    def test_nan_similarity_raises(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, float("nan"))], "not finite")

    def test_positive_infinity_raises(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, float("inf"))], "not finite")

    def test_negative_infinity_raises(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, float("-inf"))], "not finite")

    def test_non_finite_error_names_the_investigation(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, float("nan"))], _B)

    @pytest.mark.parametrize("value", [1.001, 1.5, 2.0, -1.001, -2.0, 1e9, 2, -2, 10 ** 400])
    def test_out_of_range_similarity_raises(self, conn, identity, store, value):
        self._raises(conn, identity, store, [(_B, value)], r"outside \[-1, 1\]")

    @pytest.mark.parametrize(
        "value", [1.0, -1.0, 0.0, 0.5, -0.5, 1, -1, 0, 1.0 + 5e-7, -1.0 - 5e-7, 1.0000009],
    )
    def test_valid_similarity_is_accepted(self, conn, identity, store, value):
        store.similar_rows = [(_B, value)]
        assert _find(conn, identity).matches[0].similarity == value

    def test_tolerance_is_small(self, conn, identity, store):
        assert similarity_search._SIMILARITY_TOLERANCE == 1e-6
        self._raises(conn, identity, store, [(_B, 1.0 + 2e-6)], "outside")

    def test_slightly_above_one_is_not_clamped(self, conn, identity, store):
        value = 1.0 + 5e-7
        store.similar_rows = [(_B, value)]
        assert _find(conn, identity).matches[0].similarity == value

    def test_more_rows_than_top_k_raises(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, 0.9), (_C, 0.8), (_D, 0.7)], "3 rows for top_k=2", top_k=2)

    def test_self_match_raises(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, 0.9), (_INV, 1.0)], "query investigation itself")

    def test_duplicate_investigation_raises(self, conn, identity, store):
        self._raises(conn, identity, store, [(_B, 0.9), (_C, 0.8), (_B, 0.7)], "twice")

    def test_no_partial_result_on_invalid_row(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9), (_C, float("nan"))]
        outcome = None
        with pytest.raises(RuntimeError):
            outcome = _find(conn, identity)
        assert outcome is None

    def test_similarity_becomes_a_plain_float(self, conn, identity, store):
        class Scalar(float):
            pass

        store.similar_rows = [(_B, 1), (_C, Scalar(0.5))]
        matches = _find(conn, identity).matches
        assert [type(m.similarity) for m in matches] == [float, float]
        assert [m.similarity for m in matches] == [1.0, 0.5]


# ---------------------------------------------------------------------------
# SS11  Ordering and values preserved
# ---------------------------------------------------------------------------

class TestOrderingPreserved:

    def test_store_order_is_preserved(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9), (_C, 0.8), (_D, 0.7), (_E, 0.6)]
        assert [m.investigation_id for m in _find(conn, identity).matches] == [_B, _C, _D, _E]

    def test_results_are_not_re_sorted_by_similarity(self, conn, identity, store):
        """Even an order that looks wrong is returned exactly as the database gave it."""
        store.similar_rows = [(_B, 0.1), (_C, 0.9), (_D, 0.5)]
        outcome = _find(conn, identity)
        assert [m.investigation_id for m in outcome.matches] == [_B, _C, _D]
        assert [m.similarity for m in outcome.matches] == [0.1, 0.9, 0.5]

    def test_results_are_not_re_sorted_by_investigation_id(self, conn, identity, store):
        store.similar_rows = [(_F, 0.5), (_B, 0.5), (_D, 0.5)]
        assert [m.investigation_id for m in _find(conn, identity).matches] == [_F, _B, _D]

    def test_ties_are_kept_in_store_order(self, conn, identity, store):
        store.similar_rows = [(_B, 0.75), (_C, 0.75), (_D, 0.75)]
        assert [m.investigation_id for m in _find(conn, identity).matches] == [_B, _C, _D]

    def test_similarity_is_not_rounded(self, conn, identity, store):
        value = 0.12345678901234568
        store.similar_rows = [(_B, value)]
        similarity = _find(conn, identity).matches[0].similarity
        assert similarity == value
        assert repr(similarity) == repr(value)

    def test_no_threshold_is_applied(self, conn, identity, store):
        store.similar_rows = [(_B, 0.01), (_C, 0.0), (_D, -0.4), (_E, -1.0)]
        outcome = _find(conn, identity)
        assert [m.similarity for m in outcome.matches] == [0.01, 0.0, -0.4, -1.0]

    def test_no_rows_are_dropped(self, conn, identity, store):
        rows = [(f"{i:064x}", 1.0 - i / 100.0) for i in range(1, 51)]
        store.similar_rows = rows
        outcome = _find(conn, identity, top_k=50)
        assert [(m.investigation_id, m.similarity) for m in outcome.matches] == rows

    def test_returned_ids_are_unmodified(self, conn, identity, store):
        store.similar_rows = [(" padded-id ", 0.5), ("UPPER", 0.4)]
        assert [m.investigation_id for m in _find(conn, identity).matches] == [" padded-id ", "UPPER"]


# ---------------------------------------------------------------------------
# SS12  Transaction ownership
# ---------------------------------------------------------------------------

def _set_state(store: FakeStore, state: str) -> None:
    if state == "ok_with_matches":
        store.similar_rows = [(_B, 0.9), (_C, 0.8)]
    elif state == "ok_empty":
        store.similar_rows = []
    elif state == "not_eligible":
        store.investigation = _investigation(confidence="INSUFFICIENT_DATA")
        store.evidence = []
    elif state == "query_not_embedded":
        store.stored_text.clear()
    elif state == "text_mismatch":
        store.stored_text[_query_id()] = "older text"


_OUTCOME_STATES = ["ok_with_matches", "ok_empty", "not_eligible", "query_not_embedded", "text_mismatch"]
_STORE_STEPS = ["fetch_investigation", "fetch_evidence",
                "fetch_stored_document_text", "fetch_similar_investigations"]


class TestTransactionOwnership:

    @pytest.mark.parametrize("state", _OUTCOME_STATES)
    def test_no_commit_on_any_outcome(self, conn, identity, store, state):
        _set_state(store, state)
        _find(conn, identity)
        conn.commit.assert_not_called()

    @pytest.mark.parametrize("state", _OUTCOME_STATES)
    def test_no_rollback_on_any_outcome(self, conn, identity, store, state):
        _set_state(store, state)
        _find(conn, identity)
        conn.rollback.assert_not_called()

    @pytest.mark.parametrize("state", _OUTCOME_STATES)
    def test_connection_is_never_touched_directly(self, conn, identity, store, state):
        """Retrieval hands the connection to the store and does nothing else with it."""
        _set_state(store, state)
        _find(conn, identity)
        assert conn.mock_calls == []

    def test_successful_retrieval_leaves_transaction_to_the_caller(self, conn, identity, store):
        store.similar_rows = [(_B, 0.9)]
        outcome = _find(conn, identity)
        assert outcome.status == STATUS_OK
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()
        conn.cursor.assert_not_called()
        assert not hasattr(outcome, "connection")

    def test_no_autocommit_or_transaction_attributes_are_set(self, identity, store):
        class StrictConnection:
            """Any attribute access or assignment fails the test."""

            def __getattr__(self, name):
                raise AssertionError(f"retrieval accessed conn.{name}")

            def __setattr__(self, name, value):
                raise AssertionError(f"retrieval set conn.{name}")

        outcome = find_similar_investigations(StrictConnection(), identity, _INV)
        assert outcome.status == STATUS_OK

    @pytest.mark.parametrize("step", _STORE_STEPS)
    def test_database_error_propagates_unchanged(self, conn, identity, store, step):
        import psycopg
        boom = psycopg.OperationalError(f"failure in {step}")
        store.errors[step] = boom
        with pytest.raises(psycopg.OperationalError) as excinfo:
            _find(conn, identity)
        assert excinfo.value is boom

    @pytest.mark.parametrize("step", _STORE_STEPS)
    def test_database_error_triggers_no_transaction_management(self, conn, identity, store, step):
        store.errors[step] = RuntimeError("database failure")
        with pytest.raises(RuntimeError, match="database failure"):
            _find(conn, identity)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()
        assert conn.mock_calls == []

    @pytest.mark.parametrize("step", _STORE_STEPS)
    def test_database_error_stops_at_the_failing_step(self, conn, identity, store, step):
        store.errors[step] = RuntimeError("database failure")
        with pytest.raises(RuntimeError):
            _find(conn, identity)
        assert store.calls == _STORE_STEPS[: _STORE_STEPS.index(step) + 1]

    def test_validation_error_triggers_no_transaction_management(self, conn, identity, store):
        store.similar_rows = [(_B, float("nan"))]
        with pytest.raises(RuntimeError):
            _find(conn, identity)
        assert conn.mock_calls == []

    def test_not_found_triggers_no_transaction_management(self, conn, identity, store):
        store.investigation = None
        with pytest.raises(InvestigationNotFoundError):
            _find(conn, identity)
        assert conn.mock_calls == []

    def test_module_source_has_no_transaction_or_connection_calls(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({
            "commit", "rollback", "close", "connect", "cursor", "execute",
            "executemany", "autocommit", "transaction",
        })

    def test_module_has_no_try_except(self):
        """Errors are never caught, so nothing can be swallowed or retried."""
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        assert not any(isinstance(n, (ast.Try, ast.With)) for n in ast.walk(tree))


# ---------------------------------------------------------------------------
# SS13  Read-only, model-free, import boundary
# ---------------------------------------------------------------------------

def _module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _imported_modules() -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestBoundaries:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(similarity_search.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules() == {
            "__future__", "math", "dataclasses", "typing",
            "embedding_store", "embedding_pipeline", "embedding_provider",
            "embedding_record", "incident_document", "incident_signal",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "sentence_transformer_backend", "sentence_transformers", "torch",
         "transformers", "numpy", "retrieval_db", "rca_confidence", "rca_ranker",
         "rca_source", "rca_models", "rca_persist", "os", "sys", "logging", "socket"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules()

    @pytest.mark.parametrize("state", _OUTCOME_STATES)
    def test_never_writes(self, conn, identity, store, state):
        """FakeStore.insert_embedding raises if it is ever called."""
        _set_state(store, state)
        _find(conn, identity)
        assert "insert_embedding" not in store.calls

    def test_write_and_embedding_functions_are_not_referenced(self):
        tree = _module_tree()
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        referenced = names | attributes
        for forbidden in ("insert_embedding", "embed_investigation", "embed",
                          "create_default_provider", "EmbeddingProvider",
                          "format_vector_literal", "load", "token_usage"):
            assert forbidden not in referenced

    def test_only_the_not_found_error_is_imported_from_the_pipeline(self):
        imported = []
        for node in ast.walk(_module_tree()):
            if isinstance(node, ast.ImportFrom) and node.module == "embedding_pipeline":
                imported.extend(alias.name for alias in node.names)
        assert imported == ["InvestigationNotFoundError"]

    def test_only_read_functions_of_the_store_are_used(self):
        used = {
            node.attr for node in ast.walk(_module_tree())
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "embedding_store"
        }
        assert used == {
            "fetch_investigation", "fetch_evidence", "fetch_stored_document_text",
            "fetch_similar_investigations", "EMBEDDING_COLUMN_DIMENSION",
        }

    def test_model_library_is_not_loaded_by_retrieval(self, conn, identity, store):
        import sys
        before = {m for m in ("sentence_transformers", "torch", "transformers") if m in sys.modules}
        _find(conn, identity)
        after = {m for m in ("sentence_transformers", "torch", "transformers") if m in sys.modules}
        assert after == before

    def test_module_contains_no_sql(self):
        strings = [
            n.value for n in ast.walk(_module_tree())
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and "\n" not in n.value
        ]
        for text in strings:
            words = set(text.upper().replace(",", " ").split())
            assert words.isdisjoint({"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"}), text

    def test_public_names(self):
        defined_here = {
            name for name, value in vars(similarity_search).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == "similarity_search"
        }
        assert defined_here == {
            "SimilarInvestigation", "RetrievalOutcome", "find_similar_investigations",
        }

    def test_no_threshold_backfill_or_presentation_functions(self):
        names = {
            n.name.lower() for n in ast.walk(_module_tree())
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        }
        for word in ("threshold", "backfill", "summar", "explain", "context",
                     "root_cause", "recommend", "remediat"):
            assert not any(word in name for name in names)

    def test_no_threshold_constant(self):
        constants = {
            node.targets[0].id for node in _module_tree().body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        }
        constants |= {
            node.target.id for node in _module_tree().body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        assert not any("THRESHOLD" in name.upper() or "MIN_SIMILARITY" in name.upper()
                       for name in constants)
        assert {"DEFAULT_TOP_K", "MIN_TOP_K", "MAX_TOP_K"} <= constants

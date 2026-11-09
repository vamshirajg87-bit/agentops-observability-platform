"""
incident-retrieval/tests/unit/test_embedding_pipeline.py

Unit tests for embedding_pipeline.py.

No database, no model, no network.  The store functions are replaced by an
in-memory fake, the provider wraps a fake backend, and the connection is a
MagicMock used only to observe commit / rollback.

Test inventory:
    PL01  Outcome: inserted
    PL02  Outcome: already_present
    PL03  Outcome: not_eligible
    PL04  Outcome: text_mismatch
    PL05  Concurrent insert conflict
    PL06  Investigation not found / invalid investigation_id
    PL07  Identity guards
    PL08  Error propagation, rollback, and commit semantics
    PL09  Text and identity passed through exactly
    PL10  Token usage
    PL11  Import boundary and exclusions
"""

from __future__ import annotations

import ast
import math
import os
from unittest.mock import MagicMock

import pytest

import embedding_pipeline
import embedding_store
from embedding_pipeline import InvestigationNotFoundError, embed_investigation
from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider
from embedding_record import (
    STATUS_ALREADY_PRESENT,
    STATUS_INSERTED,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
    EmbeddingOutcome,
    compute_embedding_id,
)
from incident_document import (
    DOC_VERSION,
    EvidenceRow,
    IncidentDocument,
    InvestigationRow,
    build_incident_document,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "embedding_pipeline.py")

_INV = "a" * 64
_MODEL = "fake/model"
_REV = "fake-revision"


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

    def __init__(self, investigation=None, evidence=None) -> None:
        self.investigation = investigation
        self.evidence = list(evidence or [])
        self.rows: dict[str, dict] = {}
        self.calls: list[str] = []
        self.conns: list[object] = []
        self.insert_result: bool | None = None      # None = behave like the table
        self.insert_side_effect = None              # callable run before the insert
        self.insert_kwargs: dict = {}
        self.errors: dict[str, Exception] = {}

    def _record(self, name: str, conn) -> None:
        self.calls.append(name)
        self.conns.append(conn)
        if name in self.errors:
            raise self.errors[name]

    def fetch_investigation(self, conn, investigation_id):
        self._record("fetch_investigation", conn)
        return self.investigation

    def fetch_evidence(self, conn, investigation_id):
        self._record("fetch_evidence", conn)
        return list(self.evidence)

    def fetch_stored_document_text(self, conn, embedding_id):
        self._record("fetch_stored_document_text", conn)
        row = self.rows.get(embedding_id)
        return None if row is None else row["document_text"]

    def insert_embedding(self, conn, **kwargs):
        self._record("insert_embedding", conn)
        self.insert_kwargs = kwargs
        if self.insert_side_effect is not None:
            self.insert_side_effect(kwargs)
        if self.insert_result is not None:
            return self.insert_result
        if kwargs["embedding_id"] in self.rows:
            return False
        self.rows[kwargs["embedding_id"]] = dict(kwargs)
        return True


class FakeBackend:
    def __init__(self, dimension: int = 384, with_token_usage: bool = True) -> None:
        self.dimension = dimension
        self.calls: list[str] = []
        self.token_usage_calls: list[str] = []
        self.error: Exception | None = None
        if with_token_usage:
            self.token_usage = self._token_usage

    def __call__(self, text: str) -> list[float]:
        self.calls.append(text)
        if self.error is not None:
            raise self.error
        return [float(i + 1) for i in range(self.dimension)]

    def _token_usage(self, text: str):
        self.token_usage_calls.append(text)
        return ("usage", len(text))


@pytest.fixture
def store(monkeypatch) -> FakeStore:
    fake = FakeStore(_investigation(), [_evidence(1), _evidence(2)])
    for name in ("fetch_investigation", "fetch_evidence",
                 "fetch_stored_document_text", "insert_embedding"):
        monkeypatch.setattr(embedding_store, name, getattr(fake, name))
    return fake


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def provider(backend) -> EmbeddingProvider:
    return EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 384), backend)


@pytest.fixture
def conn() -> MagicMock:
    return MagicMock()


def _expected_text(store: FakeStore) -> str:
    return build_incident_document(
        store.investigation, store.evidence, derived_signal="tool_failure",
    ).text


def _expected_id() -> str:
    return compute_embedding_id(_INV, DOC_VERSION, _MODEL, _REV)


def _concurrent_writer(store: FakeStore, text=None):
    """Simulate another process storing the row just before our insert."""
    def write(kwargs):
        store.rows[kwargs["embedding_id"]] = {
            "document_text": kwargs["document_text"] if text is None else text,
        }
    return write


# ---------------------------------------------------------------------------
# PL01  inserted
# ---------------------------------------------------------------------------

class TestInserted:

    def test_outcome(self, conn, provider, store):
        outcome = embed_investigation(conn, provider, _INV)
        assert isinstance(outcome, EmbeddingOutcome)
        assert outcome.investigation_id == _INV
        assert outcome.status == STATUS_INSERTED
        assert outcome.embedding_id == _expected_id()

    def test_row_is_stored(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert list(store.rows) == [_expected_id()]

    def test_step_order(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert store.calls == [
            "fetch_investigation", "fetch_evidence",
            "fetch_stored_document_text", "insert_embedding",
        ]

    def test_model_called_exactly_once(self, conn, provider, store, backend):
        embed_investigation(conn, provider, _INV)
        assert len(backend.calls) == 1

    def test_existence_check_precedes_the_model(self, conn, provider, store, backend, monkeypatch):
        events = []
        lookup = embedding_store.fetch_stored_document_text

        def recording_lookup(conn_, embedding_id):
            events.append("lookup")
            return lookup(conn_, embedding_id)

        def recording_backend(text):
            events.append("model")
            return [1.0] * 384

        monkeypatch.setattr(embedding_store, "fetch_stored_document_text", recording_lookup)
        recording = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 384), recording_backend)
        embed_investigation(conn, recording, _INV)
        assert events == ["lookup", "model"]

    def test_commits_once_and_does_not_roll_back(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        conn.commit.assert_called_once_with()
        conn.rollback.assert_not_called()

    def test_connection_is_not_closed(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        conn.close.assert_not_called()

    def test_same_connection_passed_to_every_store_call(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert len(store.conns) == 4
        assert all(c is conn for c in store.conns)

    def test_stored_vector_is_the_provider_output(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        vector = store.insert_kwargs["vector"]
        assert type(vector) is tuple and len(vector) == 384
        assert math.isclose(math.hypot(*vector), 1.0, rel_tol=0.0, abs_tol=1e-12)
        assert vector == provider.embed(_expected_text(store))

    def test_zero_evidence_investigation_is_still_embedded(self, conn, provider, store):
        store.evidence = []
        outcome = embed_investigation(conn, provider, _INV)
        assert outcome.status == STATUS_INSERTED
        assert store.insert_kwargs["document_text"].endswith("evidence: none")

    @pytest.mark.parametrize("confidence", ["HIGH", "MEDIUM", "LOW"])
    def test_every_other_confidence_is_embedded(self, conn, provider, store, confidence):
        store.investigation = _investigation(confidence=confidence)
        assert embed_investigation(conn, provider, _INV).status == STATUS_INSERTED


# ---------------------------------------------------------------------------
# PL02  already_present
# ---------------------------------------------------------------------------

class TestAlreadyPresent:

    def _seed(self, store: FakeStore) -> None:
        store.rows[_expected_id()] = {"document_text": _expected_text(store)}

    def test_outcome(self, conn, provider, store):
        self._seed(store)
        outcome = embed_investigation(conn, provider, _INV)
        assert outcome == EmbeddingOutcome(_INV, STATUS_ALREADY_PRESENT, _expected_id(), None)

    def test_model_is_not_called(self, conn, provider, store, backend):
        self._seed(store)
        embed_investigation(conn, provider, _INV)
        assert backend.calls == []
        assert backend.token_usage_calls == []

    def test_insert_is_not_called(self, conn, provider, store):
        self._seed(store)
        embed_investigation(conn, provider, _INV)
        assert "insert_embedding" not in store.calls

    def test_transaction_is_ended_without_rollback(self, conn, provider, store):
        self._seed(store)
        embed_investigation(conn, provider, _INV)
        conn.commit.assert_called_once_with()
        conn.rollback.assert_not_called()

    def test_replay_is_idempotent(self, conn, provider, store, backend):
        first = embed_investigation(conn, provider, _INV)
        second = embed_investigation(conn, provider, _INV)
        third = embed_investigation(conn, provider, _INV)
        assert first.status == STATUS_INSERTED
        assert second.status == third.status == STATUS_ALREADY_PRESENT
        assert second.embedding_id == first.embedding_id
        assert len(store.rows) == 1
        assert len(backend.calls) == 1
        assert store.calls.count("insert_embedding") == 1

    def test_stored_row_is_unchanged_by_replay(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        snapshot = dict(store.rows[_expected_id()])
        embed_investigation(conn, provider, _INV)
        assert store.rows[_expected_id()] == snapshot


# ---------------------------------------------------------------------------
# PL03  not_eligible
# ---------------------------------------------------------------------------

class TestNotEligible:

    @pytest.fixture(autouse=True)
    def _ineligible(self, store):
        store.investigation = _investigation(confidence="INSUFFICIENT_DATA")
        store.evidence = []

    def test_outcome(self, conn, provider, store):
        assert embed_investigation(conn, provider, _INV) == EmbeddingOutcome(
            _INV, STATUS_NOT_ELIGIBLE, None, None,
        )

    def test_model_is_not_called(self, conn, provider, store, backend):
        embed_investigation(conn, provider, _INV)
        assert backend.calls == []
        assert backend.token_usage_calls == []

    def test_no_lookup_and_no_insert(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert store.calls == ["fetch_investigation", "fetch_evidence"]
        assert store.rows == {}

    def test_transaction_is_ended_without_rollback(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        conn.commit.assert_called_once_with()
        conn.rollback.assert_not_called()

    def test_identity_guards_are_not_reached(self, conn, store):
        """A wrong-dimension provider is irrelevant when nothing is embedded."""
        wrong = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 3), FakeBackend(3))
        assert embed_investigation(conn, wrong, _INV).status == STATUS_NOT_ELIGIBLE

    def test_re_evaluated_on_every_call(self, conn, provider, store):
        for _ in range(3):
            assert embed_investigation(conn, provider, _INV).status == STATUS_NOT_ELIGIBLE
        assert store.calls.count("fetch_investigation") == 3

    @pytest.mark.parametrize("confidence", [" INSUFFICIENT_DATA", "insufficient_data"])
    def test_only_the_exact_value_is_not_eligible(self, conn, provider, store, confidence):
        store.investigation = _investigation(confidence=confidence)
        assert embed_investigation(conn, provider, _INV).status == STATUS_INSERTED


# ---------------------------------------------------------------------------
# PL04  text_mismatch
# ---------------------------------------------------------------------------

class TestTextMismatch:

    def _seed(self, store: FakeStore, text: str) -> None:
        store.rows[_expected_id()] = {"document_text": text}

    def test_outcome(self, conn, provider, store):
        self._seed(store, "anomaly: tool_failure\nsomething older")
        assert embed_investigation(conn, provider, _INV) == EmbeddingOutcome(
            _INV, STATUS_TEXT_MISMATCH, _expected_id(), None,
        )

    def test_stored_row_is_never_overwritten(self, conn, provider, store):
        self._seed(store, "older text")
        embed_investigation(conn, provider, _INV)
        assert store.rows[_expected_id()] == {"document_text": "older text"}
        assert "insert_embedding" not in store.calls

    def test_model_is_not_called(self, conn, provider, store, backend):
        self._seed(store, "older text")
        embed_investigation(conn, provider, _INV)
        assert backend.calls == []

    def test_is_returned_not_raised(self, conn, provider, store):
        self._seed(store, "older text")
        outcome = embed_investigation(conn, provider, _INV)
        assert outcome.status == STATUS_TEXT_MISMATCH
        conn.commit.assert_called_once_with()
        conn.rollback.assert_not_called()

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
    def test_comparison_is_exact(self, conn, provider, store, mutate):
        self._seed(store, mutate(_expected_text(store)))
        assert embed_investigation(conn, provider, _INV).status == STATUS_TEXT_MISMATCH

    def test_identical_text_is_not_a_mismatch(self, conn, provider, store):
        self._seed(store, _expected_text(store))
        assert embed_investigation(conn, provider, _INV).status == STATUS_ALREADY_PRESENT


# ---------------------------------------------------------------------------
# PL05  Concurrent insert conflict
# ---------------------------------------------------------------------------

class TestConcurrentConflict:

    def test_lost_race_with_identical_text_is_already_present(self, conn, provider, store):
        store.insert_side_effect = _concurrent_writer(store)
        outcome = embed_investigation(conn, provider, _INV)
        assert outcome.status == STATUS_ALREADY_PRESENT
        assert outcome.embedding_id == _expected_id()

    def test_lost_race_with_different_text_is_text_mismatch(self, conn, provider, store):
        store.insert_side_effect = _concurrent_writer(store, "another writer's text")
        outcome = embed_investigation(conn, provider, _INV)
        assert outcome.status == STATUS_TEXT_MISMATCH
        assert store.rows[_expected_id()] == {"document_text": "another writer's text"}

    def test_lost_race_rereads_the_stored_text(self, conn, provider, store):
        store.insert_side_effect = _concurrent_writer(store)
        embed_investigation(conn, provider, _INV)
        assert store.calls == [
            "fetch_investigation", "fetch_evidence", "fetch_stored_document_text",
            "insert_embedding", "fetch_stored_document_text",
        ]

    def test_lost_race_still_reports_token_usage(self, conn, provider, store):
        store.insert_side_effect = _concurrent_writer(store)
        assert embed_investigation(conn, provider, _INV).token_usage is not None

    def test_lost_race_commits(self, conn, provider, store):
        store.insert_side_effect = _concurrent_writer(store)
        embed_investigation(conn, provider, _INV)
        conn.commit.assert_called_once_with()
        conn.rollback.assert_not_called()

    def test_conflict_without_a_row_is_an_error(self, conn, provider, store):
        store.insert_result = False
        with pytest.raises(RuntimeError, match="no row was found"):
            embed_investigation(conn, provider, _INV)
        conn.rollback.assert_called_once_with()
        conn.commit.assert_not_called()


# ---------------------------------------------------------------------------
# PL06  Not found / invalid id
# ---------------------------------------------------------------------------

class TestNotFound:

    def test_missing_investigation_raises(self, conn, provider, store):
        store.investigation = None
        with pytest.raises(InvestigationNotFoundError) as excinfo:
            embed_investigation(conn, provider, _INV)
        assert excinfo.value.investigation_id == _INV
        assert _INV in str(excinfo.value)

    def test_not_found_is_a_value_error(self):
        assert issubclass(InvestigationNotFoundError, ValueError)

    def test_missing_investigation_stops_immediately(self, conn, provider, store, backend):
        store.investigation = None
        with pytest.raises(InvestigationNotFoundError):
            embed_investigation(conn, provider, _INV)
        assert store.calls == ["fetch_investigation"]
        assert backend.calls == []

    def test_missing_investigation_rolls_back(self, conn, provider, store):
        store.investigation = None
        with pytest.raises(InvestigationNotFoundError):
            embed_investigation(conn, provider, _INV)
        conn.rollback.assert_called_once_with()
        conn.commit.assert_not_called()

    @pytest.mark.parametrize("value", [None, 123, b"a", "", "   ", ["a"]],
                             ids=["none", "int", "bytes", "empty", "blank", "list"])
    def test_invalid_investigation_id_raises_before_any_database_call(
        self, conn, provider, store, value,
    ):
        with pytest.raises(ValueError, match="investigation_id"):
            embed_investigation(conn, provider, value)
        assert store.calls == []
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()


# ---------------------------------------------------------------------------
# PL07  Identity guards
# ---------------------------------------------------------------------------

class TestIdentityGuards:

    @pytest.mark.parametrize("dimension", [1, 383, 385, 768])
    def test_wrong_provider_dimension_raises(self, conn, store, dimension):
        wrong = EmbeddingProvider(
            EmbeddingModelIdentity(_MODEL, _REV, dimension), FakeBackend(dimension),
        )
        with pytest.raises(RuntimeError, match="provider dimension"):
            embed_investigation(conn, wrong, _INV)

    def test_wrong_dimension_stops_before_lookup_and_model(self, conn, store):
        backend = FakeBackend(3)
        wrong = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 3), backend)
        with pytest.raises(RuntimeError):
            embed_investigation(conn, wrong, _INV)
        assert store.calls == ["fetch_investigation", "fetch_evidence"]
        assert backend.calls == []
        conn.rollback.assert_called_once_with()
        conn.commit.assert_not_called()

    def test_wrong_doc_version_raises(self, conn, provider, store, monkeypatch):
        def fake_builder(investigation, evidence, *, derived_signal):
            return IncidentDocument(_INV, "9.9.9", True, "anomaly: x")

        monkeypatch.setattr(embedding_pipeline, "build_incident_document", fake_builder)
        with pytest.raises(RuntimeError, match="doc_version"):
            embed_investigation(conn, provider, _INV)
        assert "insert_embedding" not in store.calls
        conn.rollback.assert_called_once_with()

    def test_doc_version_is_the_locked_constant(self):
        assert embedding_pipeline.DOC_VERSION == DOC_VERSION == "1.0.0"

    def test_dimension_guard_uses_the_column_dimension(self):
        assert embedding_store.EMBEDDING_COLUMN_DIMENSION == 384


# ---------------------------------------------------------------------------
# PL08  Errors, rollback, commit
# ---------------------------------------------------------------------------

class TestErrorsAndTransactions:

    @pytest.mark.parametrize(
        "step", ["fetch_investigation", "fetch_evidence",
                 "fetch_stored_document_text", "insert_embedding"],
    )
    def test_store_error_propagates_with_rollback(self, conn, provider, store, step):
        boom = RuntimeError(f"database failure in {step}")
        store.errors[step] = boom
        with pytest.raises(RuntimeError) as excinfo:
            embed_investigation(conn, provider, _INV)
        assert excinfo.value is boom
        conn.rollback.assert_called_once_with()
        conn.commit.assert_not_called()

    def test_provider_error_propagates_with_rollback(self, conn, provider, store, backend):
        backend.error = RuntimeError("model unavailable")
        with pytest.raises(RuntimeError, match="model unavailable"):
            embed_investigation(conn, provider, _INV)
        assert "insert_embedding" not in store.calls
        assert store.rows == {}
        conn.rollback.assert_called_once_with()
        conn.commit.assert_not_called()

    def test_provider_output_error_propagates_with_rollback(self, conn, store):
        bad = EmbeddingProvider(
            EmbeddingModelIdentity(_MODEL, _REV, 384), lambda text: [0.0] * 384,
        )
        with pytest.raises(ValueError, match="zero norm"):
            embed_investigation(conn, bad, _INV)
        assert store.rows == {}
        conn.rollback.assert_called_once_with()

    def test_builder_error_propagates_with_rollback(self, conn, provider, store, backend):
        store.evidence = [_evidence(1), _evidence(1)]      # duplicate rank
        with pytest.raises(ValueError, match="rank_position"):
            embed_investigation(conn, provider, _INV)
        assert backend.calls == []
        assert store.calls == ["fetch_investigation", "fetch_evidence"]
        conn.rollback.assert_called_once_with()
        conn.commit.assert_not_called()

    def test_commit_failure_rolls_back_and_propagates(self, conn, provider, store):
        conn.commit.side_effect = RuntimeError("commit failed")
        with pytest.raises(RuntimeError, match="commit failed"):
            embed_investigation(conn, provider, _INV)
        conn.rollback.assert_called_once_with()

    def test_commit_happens_after_the_insert(self, provider, store):
        events = []
        conn = MagicMock()
        conn.commit.side_effect = lambda: events.append("commit")
        store.insert_side_effect = lambda kwargs: events.append("insert")
        embed_investigation(conn, provider, _INV)
        assert events == ["insert", "commit"]

    def test_exactly_one_commit_per_successful_call(self, conn, provider, store):
        for _ in range(3):
            embed_investigation(conn, provider, _INV)
        assert conn.commit.call_count == 3
        conn.rollback.assert_not_called()

    def test_no_outcome_on_error(self, conn, provider, store, backend):
        backend.error = RuntimeError("x")
        outcome = None
        with pytest.raises(RuntimeError):
            outcome = embed_investigation(conn, provider, _INV)
        assert outcome is None


# ---------------------------------------------------------------------------
# PL09  Text and identity pass-through
# ---------------------------------------------------------------------------

class TestPassThrough:

    def test_provider_receives_document_text_exactly(self, conn, provider, store, backend):
        embed_investigation(conn, provider, _INV)
        assert backend.calls == [_expected_text(store)]

    def test_stored_text_equals_document_text_exactly(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert store.insert_kwargs["document_text"] == _expected_text(store)

    def test_stored_text_equals_text_sent_to_the_model(self, conn, provider, store, backend):
        embed_investigation(conn, provider, _INV)
        assert store.insert_kwargs["document_text"] == backend.calls[0]

    def test_insert_identity_fields(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        kwargs = store.insert_kwargs
        assert kwargs["embedding_id"] == _expected_id()
        assert kwargs["investigation_id"] == _INV
        assert kwargs["doc_version"] == "1.0.0"
        assert kwargs["model_name"] == _MODEL
        assert kwargs["model_revision"] == _REV

    def test_insert_keyword_set_exact(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert set(store.insert_kwargs) == {
            "embedding_id", "investigation_id", "doc_version", "model_name",
            "model_revision", "document_text", "vector",
        }

    def test_embedding_id_uses_provider_identity(self, conn, store):
        other = EmbeddingProvider(
            EmbeddingModelIdentity("other/model", "other-revision", 384), FakeBackend(),
        )
        outcome = embed_investigation(conn, other, _INV)
        assert outcome.embedding_id == compute_embedding_id(
            _INV, DOC_VERSION, "other/model", "other-revision",
        )
        assert outcome.embedding_id != _expected_id()

    def test_different_model_revision_gives_a_second_row(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        other = EmbeddingProvider(
            EmbeddingModelIdentity(_MODEL, "newer-revision", 384), FakeBackend(),
        )
        assert embed_investigation(conn, other, _INV).status == STATUS_INSERTED
        assert len(store.rows) == 2

    @pytest.mark.parametrize(
        "anomaly_type, operation, signal",
        [
            ("latency", "trace", "trace_latency"),
            ("latency", "tool.execute", "tool_latency"),
            ("latency", "research/plan", "agent_latency"),
            ("latency", None, "agent_latency"),
            ("retrieval_quality", None, "retrieval_quality"),
            ("error_rate", "payment/authorize", "error_rate"),
            ("tool_failure", "tool.execute/ToolExecutionError", "tool_failure"),
        ],
    )
    def test_signal_line_is_derived_from_the_investigation(
        self, conn, provider, store, anomaly_type, operation, signal,
    ):
        store.investigation = _investigation(anomaly_type=anomaly_type, operation_name=operation)
        embed_investigation(conn, provider, _INV)
        lines = store.insert_kwargs["document_text"].split("\n")
        assert lines[0] == f"anomaly: {anomaly_type}"
        assert lines[1] == f"signal: {signal}"

    def test_document_matches_the_phase_12_3_builder(self, conn, provider, store):
        embed_investigation(conn, provider, _INV)
        assert store.insert_kwargs["document_text"] == _expected_text(store)

    def test_evidence_order_from_the_store_does_not_matter(self, conn, provider, store):
        store.evidence = [_evidence(2), _evidence(1)]
        embed_investigation(conn, provider, _INV)
        assert store.insert_kwargs["document_text"] == build_incident_document(
            store.investigation, [_evidence(1), _evidence(2)], derived_signal="tool_failure",
        ).text


# ---------------------------------------------------------------------------
# PL10  Token usage
# ---------------------------------------------------------------------------

class TestTokenUsage:

    def test_present_when_backend_offers_it(self, conn, provider, store, backend):
        outcome = embed_investigation(conn, provider, _INV)
        text = _expected_text(store)
        assert outcome.token_usage == ("usage", len(text))
        assert backend.token_usage_calls == [text]

    def test_none_when_backend_has_no_token_usage(self, conn, store):
        plain = EmbeddingProvider(
            EmbeddingModelIdentity(_MODEL, _REV, 384), FakeBackend(with_token_usage=False),
        )
        outcome = embed_investigation(conn, plain, _INV)
        assert outcome.status == STATUS_INSERTED
        assert outcome.token_usage is None

    def test_none_when_backend_is_a_plain_function(self, conn, store):
        plain = EmbeddingProvider(
            EmbeddingModelIdentity(_MODEL, _REV, 384), lambda text: [1.0] * 384,
        )
        assert embed_investigation(conn, plain, _INV).token_usage is None

    def test_none_when_token_usage_attribute_is_not_callable(self, conn, store):
        backend = FakeBackend(with_token_usage=False)
        backend.token_usage = "not callable"
        plain = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 384), backend)
        assert embed_investigation(conn, plain, _INV).token_usage is None

    def test_truncation_never_blocks(self, conn, store):
        class Usage:
            truncated = True

        backend = FakeBackend(with_token_usage=False)
        backend.token_usage = lambda text: Usage()
        truncating = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 384), backend)
        outcome = embed_investigation(conn, truncating, _INV)
        assert outcome.status == STATUS_INSERTED
        assert outcome.token_usage.truncated is True
        assert len(store.rows) == 1

    def test_not_requested_for_existing_rows(self, conn, provider, store, backend):
        embed_investigation(conn, provider, _INV)
        backend.token_usage_calls.clear()
        outcome = embed_investigation(conn, provider, _INV)
        assert outcome.token_usage is None
        assert backend.token_usage_calls == []

    def test_token_usage_error_propagates_with_rollback(self, conn, store):
        backend = FakeBackend(with_token_usage=False)

        def failing(text):
            raise RuntimeError("tokenizer unavailable")

        backend.token_usage = failing
        provider = EmbeddingProvider(EmbeddingModelIdentity(_MODEL, _REV, 384), backend)
        with pytest.raises(RuntimeError, match="tokenizer unavailable"):
            embed_investigation(conn, provider, _INV)
        conn.rollback.assert_called_once_with()
        assert store.rows == {}


# ---------------------------------------------------------------------------
# PL11  Import boundary and exclusions
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


class TestImportBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(embedding_pipeline.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules() == {
            "__future__", "typing", "embedding_store", "embedding_provider",
            "embedding_record", "incident_document", "incident_signal",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "rca_confidence", "rca_ranker", "rca_source", "rca_models",
         "rca_persist", "rca_orchestrator", "sentence_transformers", "torch",
         "sentence_transformer_backend", "retrieval_db", "os", "sys", "logging"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules()

    def test_pipeline_issues_no_sql_itself(self):
        attributes = {n.attr for n in ast.walk(_module_tree()) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"execute", "executemany", "cursor"})

    def test_pipeline_never_opens_or_closes_a_connection(self):
        attributes = {n.attr for n in ast.walk(_module_tree()) if isinstance(n, ast.Attribute)}
        assert {"commit", "rollback"} <= attributes
        assert attributes.isdisjoint({"close", "connect"})

    def test_public_names(self):
        defined_here = {
            name for name, value in vars(embedding_pipeline).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == "embedding_pipeline"
        }
        assert defined_here == {"InvestigationNotFoundError", "embed_investigation"}

    def test_no_backfill_or_retrieval_functions(self):
        names = {
            n.name.lower() for n in ast.walk(_module_tree())
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        }
        for word in ("backfill", "search", "retrieve", "similar", "top_k", "nearest"):
            assert not any(word in name for name in names)

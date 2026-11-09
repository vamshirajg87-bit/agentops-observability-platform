"""
incident-retrieval/tests/unit/test_embedding_backfill.py

Unit tests for embedding_backfill.py.

No database, no model, no network.  Discovery and the single-investigation
pipeline are replaced by fakes; the connection is a MagicMock used only to
observe transaction calls.

Test inventory:
    BF01  Statuses and result models
    BF02  Discovery and deterministic processing order
    BF03  Outcome counting
    BF04  Per-investigation failure: recorded, backfill continues
    BF05  Database error and KeyboardInterrupt: stop immediately
    BF06  Transactions: discovery transaction ended, never commit or close
    BF07  Idempotent rerun and lazy model use
    BF08  on_result callback
    BF09  End-to-end with the real pipeline over a fake store
    BF10  Import boundary and exclusions
"""

from __future__ import annotations

import ast
import dataclasses
import os
from unittest.mock import MagicMock

import pytest

import embedding_backfill
import embedding_pipeline
import embedding_store
from embedding_backfill import (
    BACKFILL_STATUSES,
    STATUS_FAILURE,
    BackfillReport,
    BackfillResult,
    backfill_embeddings,
)
from embedding_pipeline import InvestigationNotFoundError
from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider
from embedding_record import (
    STATUS_ALREADY_PRESENT,
    STATUS_INSERTED,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
    EmbeddingOutcome,
)
from incident_document import EvidenceRow, InvestigationRow


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "embedding_backfill.py")

_A, _B, _C, _D, _E = ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64)


class DatabaseBoom(Exception):
    """Stands in for a driver error: not a ValueError and not a RuntimeError."""


class Fakes:
    """Stand-ins for fetch_investigation_ids and embed_investigation."""

    def __init__(self) -> None:
        self.ids: list = [_A, _B, _C]
        self.behaviour: dict = {}            # id -> status str | Exception | EmbeddingOutcome
        self.events: list[tuple] = []
        self.discovery_error: BaseException | None = None

    def fetch_investigation_ids(self, conn):
        self.events.append(("discover", conn))
        if self.discovery_error is not None:
            raise self.discovery_error
        return list(self.ids)

    def embed_investigation(self, conn, provider, investigation_id):
        self.events.append(("embed", conn, provider, investigation_id))
        behaviour = self.behaviour.get(investigation_id, STATUS_INSERTED)
        if isinstance(behaviour, BaseException):
            raise behaviour
        if isinstance(behaviour, EmbeddingOutcome):
            return behaviour
        embedding_id = None if behaviour == STATUS_NOT_ELIGIBLE else f"emb-{investigation_id[:4]}"
        return EmbeddingOutcome(investigation_id, behaviour, embedding_id, None)

    @property
    def embedded_ids(self) -> list:
        return [e[3] for e in self.events if e[0] == "embed"]


@pytest.fixture
def fakes(monkeypatch) -> Fakes:
    fake = Fakes()
    monkeypatch.setattr(embedding_store, "fetch_investigation_ids", fake.fetch_investigation_ids)
    monkeypatch.setattr(embedding_pipeline, "embed_investigation", fake.embed_investigation)
    return fake


@pytest.fixture
def conn() -> MagicMock:
    return MagicMock()


@pytest.fixture
def provider() -> MagicMock:
    return MagicMock(name="provider")


# ---------------------------------------------------------------------------
# BF01  Statuses and models
# ---------------------------------------------------------------------------

class TestStatusesAndModels:

    def test_failure_status_value(self):
        assert STATUS_FAILURE == "failure"

    def test_backfill_statuses_are_exactly_the_five(self):
        assert BACKFILL_STATUSES == {
            "inserted", "already_present", "not_eligible", "text_mismatch", "failure",
        }
        assert isinstance(BACKFILL_STATUSES, frozenset)

    def test_pipeline_statuses_are_reused_unchanged(self):
        import embedding_record
        assert BACKFILL_STATUSES - {STATUS_FAILURE} == embedding_record.EMBEDDING_STATUSES

    @pytest.mark.parametrize("cls", [BackfillResult, BackfillReport])
    def test_models_are_frozen_dataclasses(self, cls):
        assert dataclasses.is_dataclass(cls)
        assert cls.__dataclass_params__.frozen is True

    def test_result_fields_exact(self):
        assert [f.name for f in dataclasses.fields(BackfillResult)] == [
            "investigation_id", "status", "embedding_id", "token_usage", "error",
        ]

    def test_report_fields_exact(self):
        assert [f.name for f in dataclasses.fields(BackfillReport)] == ["results"]

    def test_models_are_immutable(self):
        result = BackfillResult(_A, STATUS_INSERTED, "e", None, None)
        report = BackfillReport((result,))
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.status = STATUS_FAILURE  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.results = ()  # type: ignore[misc]

    def test_empty_report(self):
        report = BackfillReport(())
        assert (report.total, report.inserted, report.already_present, report.not_eligible,
                report.text_mismatch, report.failures) == (0, 0, 0, 0, 0, 0)
        assert report.succeeded is True

    @pytest.mark.parametrize(
        "statuses, succeeded",
        [
            ([STATUS_INSERTED], True),
            ([STATUS_ALREADY_PRESENT, STATUS_NOT_ELIGIBLE], True),
            ([STATUS_INSERTED, STATUS_ALREADY_PRESENT, STATUS_NOT_ELIGIBLE], True),
            ([STATUS_FAILURE], False),
            ([STATUS_TEXT_MISMATCH], False),
            ([STATUS_INSERTED, STATUS_TEXT_MISMATCH], False),
            ([STATUS_INSERTED, STATUS_FAILURE, STATUS_NOT_ELIGIBLE], False),
            ([STATUS_FAILURE, STATUS_TEXT_MISMATCH], False),
        ],
    )
    def test_succeeded_requires_no_failure_and_no_text_mismatch(self, statuses, succeeded):
        report = BackfillReport(tuple(
            BackfillResult(str(i), s, None, None, None) for i, s in enumerate(statuses)
        ))
        assert report.succeeded is succeeded


# ---------------------------------------------------------------------------
# BF02  Discovery and order
# ---------------------------------------------------------------------------

class TestDiscoveryAndOrder:

    def test_discovery_called_once_with_the_connection(self, conn, provider, fakes):
        backfill_embeddings(conn, provider)
        assert [e for e in fakes.events if e[0] == "discover"] == [("discover", conn)]

    def test_discovery_happens_before_any_processing(self, conn, provider, fakes):
        backfill_embeddings(conn, provider)
        assert fakes.events[0][0] == "discover"

    def test_every_discovered_investigation_is_processed_once(self, conn, provider, fakes):
        fakes.ids = [_A, _B, _C, _D, _E]
        backfill_embeddings(conn, provider)
        assert fakes.embedded_ids == [_A, _B, _C, _D, _E]

    def test_processing_follows_discovery_order_exactly(self, conn, provider, fakes):
        fakes.ids = [_C, _A, _E, _B]
        report = backfill_embeddings(conn, provider)
        assert fakes.embedded_ids == [_C, _A, _E, _B]
        assert [r.investigation_id for r in report.results] == [_C, _A, _E, _B]

    def test_order_is_not_re_sorted(self, conn, provider, fakes):
        """Ordering is the discovery query's job; the loop does not sort."""
        fakes.ids = [_E, _D, _C]
        assert [r.investigation_id for r in backfill_embeddings(conn, provider).results] == [_E, _D, _C]

    def test_no_investigations(self, conn, provider, fakes):
        fakes.ids = []
        report = backfill_embeddings(conn, provider)
        assert report == BackfillReport(())
        assert fakes.embedded_ids == []
        assert report.succeeded is True

    def test_pipeline_receives_the_same_connection_and_provider(self, conn, provider, fakes):
        backfill_embeddings(conn, provider)
        for event in fakes.events:
            if event[0] == "embed":
                assert event[1] is conn and event[2] is provider

    def test_ineligible_investigations_are_not_filtered_before_the_pipeline(self, conn, provider, fakes):
        """Eligibility is the pipeline's decision; every id is handed to it."""
        fakes.behaviour = {_B: STATUS_NOT_ELIGIBLE}
        report = backfill_embeddings(conn, provider)
        assert _B in fakes.embedded_ids
        assert [r.status for r in report.results] == [
            STATUS_INSERTED, STATUS_NOT_ELIGIBLE, STATUS_INSERTED,
        ]

    def test_results_is_a_tuple_of_backfill_result(self, conn, provider, fakes):
        report = backfill_embeddings(conn, provider)
        assert type(report.results) is tuple
        assert all(type(r) is BackfillResult for r in report.results)

    def test_deterministic(self, conn, provider, fakes):
        fakes.behaviour = {_B: STATUS_NOT_ELIGIBLE, _C: ValueError("bad")}
        assert backfill_embeddings(conn, provider) == backfill_embeddings(conn, provider)


# ---------------------------------------------------------------------------
# BF03  Outcome counting
# ---------------------------------------------------------------------------

class TestOutcomeCounting:

    def test_every_status_is_distinguished_and_counted(self, conn, provider, fakes):
        fakes.ids = [_A, _B, _C, _D, _E]
        fakes.behaviour = {
            _A: STATUS_INSERTED,
            _B: STATUS_ALREADY_PRESENT,
            _C: STATUS_NOT_ELIGIBLE,
            _D: STATUS_TEXT_MISMATCH,
            _E: RuntimeError("broken"),
        }
        report = backfill_embeddings(conn, provider)
        assert [r.status for r in report.results] == [
            "inserted", "already_present", "not_eligible", "text_mismatch", "failure",
        ]
        assert (report.total, report.inserted, report.already_present, report.not_eligible,
                report.text_mismatch, report.failures) == (5, 1, 1, 1, 1, 1)
        assert report.succeeded is False

    def test_counts_sum_to_total(self, conn, provider, fakes):
        fakes.ids = [_A, _B, _C, _D, _E]
        fakes.behaviour = {_B: STATUS_NOT_ELIGIBLE, _D: ValueError("x")}
        report = backfill_embeddings(conn, provider)
        assert sum(report.count(s) for s in BACKFILL_STATUSES) == report.total == 5

    def test_result_carries_pipeline_embedding_id_and_token_usage(self, conn, provider, fakes):
        usage = object()
        fakes.ids = [_A]
        fakes.behaviour = {_A: EmbeddingOutcome(_A, STATUS_INSERTED, "e" * 64, usage)}
        result = backfill_embeddings(conn, provider).results[0]
        assert result == BackfillResult(_A, STATUS_INSERTED, "e" * 64, usage, None)
        assert result.token_usage is usage

    def test_not_eligible_has_no_embedding_id(self, conn, provider, fakes):
        fakes.ids = [_A]
        fakes.behaviour = {_A: STATUS_NOT_ELIGIBLE}
        result = backfill_embeddings(conn, provider).results[0]
        assert result.embedding_id is None and result.error is None

    def test_text_mismatch_is_reported_not_raised(self, conn, provider, fakes):
        fakes.ids = [_A, _B]
        fakes.behaviour = {_A: STATUS_TEXT_MISMATCH}
        report = backfill_embeddings(conn, provider)
        assert report.results[0].status == STATUS_TEXT_MISMATCH
        assert report.results[0].error is None
        assert report.results[1].status == STATUS_INSERTED

    def test_text_mismatch_alone_makes_the_backfill_unsuccessful(self, conn, provider, fakes):
        fakes.ids = [_A, _B]
        fakes.behaviour = {_A: STATUS_TEXT_MISMATCH}
        report = backfill_embeddings(conn, provider)
        assert report.failures == 0 and report.text_mismatch == 1
        assert report.succeeded is False

    def test_all_good_outcomes_succeed(self, conn, provider, fakes):
        fakes.behaviour = {_A: STATUS_INSERTED, _B: STATUS_ALREADY_PRESENT, _C: STATUS_NOT_ELIGIBLE}
        assert backfill_embeddings(conn, provider).succeeded is True

    def test_unknown_pipeline_status_is_a_failure(self, conn, provider, fakes):
        fakes.ids = [_A, _B]
        fakes.behaviour = {_A: EmbeddingOutcome(_A, "something_new", None, None)}
        report = backfill_embeddings(conn, provider)
        assert report.results[0].status == STATUS_FAILURE
        assert "something_new" in report.results[0].error
        assert report.results[1].status == STATUS_INSERTED

    def test_only_known_statuses_appear(self, conn, provider, fakes):
        fakes.ids = [_A, _B, _C, _D]
        fakes.behaviour = {_B: STATUS_NOT_ELIGIBLE, _C: ValueError("x"), _D: STATUS_TEXT_MISMATCH}
        report = backfill_embeddings(conn, provider)
        assert {r.status for r in report.results} <= BACKFILL_STATUSES


# ---------------------------------------------------------------------------
# BF04  Per-investigation failure
# ---------------------------------------------------------------------------

class TestPerInvestigationFailure:

    @pytest.mark.parametrize(
        "error",
        [ValueError("duplicate rank_position 2"), RuntimeError("model unavailable"),
         InvestigationNotFoundError(_B)],
        ids=["value-error", "runtime-error", "not-found"],
    )
    def test_failure_is_recorded_and_processing_continues(self, conn, provider, fakes, error):
        fakes.behaviour = {_B: error}
        report = backfill_embeddings(conn, provider)
        assert fakes.embedded_ids == [_A, _B, _C]
        assert [r.status for r in report.results] == [STATUS_INSERTED, STATUS_FAILURE, STATUS_INSERTED]

    def test_failure_records_type_and_message(self, conn, provider, fakes):
        fakes.behaviour = {_B: ValueError("duplicate rank_position 2")}
        failure = backfill_embeddings(conn, provider).results[1]
        assert failure == BackfillResult(
            _B, STATUS_FAILURE, None, None, "ValueError: duplicate rank_position 2",
        )

    def test_runtime_error_type_is_recorded(self, conn, provider, fakes):
        fakes.behaviour = {_A: RuntimeError("provider dimension is 3")}
        assert backfill_embeddings(conn, provider).results[0].error == (
            "RuntimeError: provider dimension is 3"
        )

    def test_first_investigation_failing_does_not_stop_the_rest(self, conn, provider, fakes):
        fakes.behaviour = {_A: ValueError("x")}
        report = backfill_embeddings(conn, provider)
        assert [r.status for r in report.results] == [STATUS_FAILURE, STATUS_INSERTED, STATUS_INSERTED]

    def test_every_investigation_failing_is_still_a_report(self, conn, provider, fakes):
        fakes.behaviour = {_A: ValueError("a"), _B: RuntimeError("b"), _C: ValueError("c")}
        report = backfill_embeddings(conn, provider)
        assert report.failures == 3 and report.succeeded is False
        assert fakes.embedded_ids == [_A, _B, _C]

    def test_failure_does_not_raise(self, conn, provider, fakes):
        fakes.behaviour = {_B: RuntimeError("x")}
        assert isinstance(backfill_embeddings(conn, provider), BackfillReport)

    def test_failure_does_not_add_transaction_calls(self, conn, provider, fakes):
        """The pipeline already rolled back; the backfill adds nothing per failure."""
        fakes.behaviour = {_A: ValueError("a"), _B: RuntimeError("b")}
        backfill_embeddings(conn, provider)
        assert conn.rollback.call_count == 1          # the discovery rollback only
        conn.commit.assert_not_called()

    def test_invalid_discovered_id_is_a_recorded_failure(self, conn, provider, fakes):
        fakes.ids = [None, _A]
        fakes.behaviour = {None: ValueError("investigation_id must be a non-empty str")}
        report = backfill_embeddings(conn, provider)
        assert [r.status for r in report.results] == [STATUS_FAILURE, STATUS_INSERTED]
        assert report.results[0].investigation_id is None


# ---------------------------------------------------------------------------
# BF05  Database error and KeyboardInterrupt
# ---------------------------------------------------------------------------

class TestStopImmediately:

    def test_database_error_stops_and_propagates(self, conn, provider, fakes):
        boom = DatabaseBoom("server closed the connection")
        fakes.behaviour = {_B: boom}
        with pytest.raises(DatabaseBoom) as excinfo:
            backfill_embeddings(conn, provider)
        assert excinfo.value is boom
        assert fakes.embedded_ids == [_A, _B]

    def test_real_driver_error_stops_and_propagates(self, conn, provider, fakes):
        import psycopg
        boom = psycopg.OperationalError("connection lost")
        fakes.behaviour = {_B: boom}
        with pytest.raises(psycopg.OperationalError) as excinfo:
            backfill_embeddings(conn, provider)
        assert excinfo.value is boom
        assert _C not in fakes.embedded_ids

    def test_driver_error_is_not_recorded_as_a_failure_result(self, conn, provider, fakes):
        import psycopg
        seen = []
        fakes.behaviour = {_B: psycopg.OperationalError("x")}
        with pytest.raises(psycopg.OperationalError):
            backfill_embeddings(conn, provider, on_result=seen.append)
        assert [r.investigation_id for r in seen] == [_A]
        assert all(r.status != STATUS_FAILURE for r in seen)

    def test_database_error_during_discovery_propagates(self, conn, provider, fakes):
        fakes.discovery_error = DatabaseBoom("cannot connect")
        with pytest.raises(DatabaseBoom):
            backfill_embeddings(conn, provider)
        assert fakes.embedded_ids == []
        conn.rollback.assert_not_called()
        conn.commit.assert_not_called()

    def test_keyboard_interrupt_stops_immediately(self, conn, provider, fakes):
        fakes.behaviour = {_B: KeyboardInterrupt()}
        with pytest.raises(KeyboardInterrupt):
            backfill_embeddings(conn, provider)
        assert fakes.embedded_ids == [_A, _B]

    @pytest.mark.parametrize("error", [KeyError("k"), TypeError("t"), OSError("o"), AssertionError("a")])
    def test_other_exceptions_are_not_swallowed(self, conn, provider, fakes, error):
        fakes.behaviour = {_A: error}
        with pytest.raises(type(error)):
            backfill_embeddings(conn, provider)
        assert fakes.embedded_ids == [_A]

    def test_only_value_error_and_runtime_error_are_caught(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        handlers = [
            ast.unparse(h.type) for h in ast.walk(tree)
            if isinstance(h, ast.ExceptHandler) and h.type is not None
        ]
        assert handlers == ["(ValueError, RuntimeError)"]
        assert not any(
            isinstance(h, ast.ExceptHandler) and h.type is None for h in ast.walk(tree)
        )


# ---------------------------------------------------------------------------
# BF06  Transactions
# ---------------------------------------------------------------------------

class TestTransactions:

    def test_discovery_transaction_is_ended_before_the_loop(self, provider, fakes):
        events = []
        conn = MagicMock()
        conn.rollback.side_effect = lambda: events.append("rollback")
        original = fakes.embed_investigation

        def recording(c, p, i):
            events.append(f"embed:{i[:1]}")
            return original(c, p, i)

        import embedding_pipeline as pipeline
        pipeline.embed_investigation = recording
        try:
            backfill_embeddings(conn, provider)
        finally:
            pipeline.embed_investigation = fakes.embed_investigation
        assert events == ["rollback", "embed:a", "embed:b", "embed:c"]

    def test_exactly_one_rollback_and_it_follows_discovery(self, conn, provider, fakes):
        backfill_embeddings(conn, provider)
        conn.rollback.assert_called_once_with()

    def test_discovery_rollback_happens_even_with_no_investigations(self, conn, provider, fakes):
        fakes.ids = []
        backfill_embeddings(conn, provider)
        conn.rollback.assert_called_once_with()

    def test_backfill_never_commits(self, conn, provider, fakes):
        fakes.behaviour = {_B: STATUS_NOT_ELIGIBLE, _C: ValueError("x")}
        backfill_embeddings(conn, provider)
        conn.commit.assert_not_called()

    def test_backfill_never_closes_the_connection(self, conn, provider, fakes):
        backfill_embeddings(conn, provider)
        conn.close.assert_not_called()

    def test_connection_is_used_only_for_the_discovery_rollback(self, conn, provider, fakes):
        backfill_embeddings(conn, provider)
        assert [c[0] for c in conn.mock_calls] == ["rollback"]

    def test_module_source_transaction_calls(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        assert attributes.count("rollback") == 1
        assert set(attributes).isdisjoint({"commit", "close", "connect", "cursor", "execute"})


# ---------------------------------------------------------------------------
# BF07  Idempotent rerun and lazy model
# ---------------------------------------------------------------------------

class TestIdempotencyAndLazyModel:

    def test_provider_is_never_touched_by_the_backfill_itself(self, conn, fakes):
        class StrictProvider:
            def __getattr__(self, name):
                raise AssertionError(f"backfill accessed provider.{name}")

        fakes.behaviour = {_A: STATUS_ALREADY_PRESENT, _B: STATUS_NOT_ELIGIBLE, _C: STATUS_ALREADY_PRESENT}
        report = backfill_embeddings(conn, StrictProvider())
        assert report.succeeded is True and report.inserted == 0

    def test_module_never_loads_or_calls_the_provider(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"embed", "load", "backend", "token_usage"} - {"token_usage"})
        assert "load" not in attributes and "embed" not in attributes and "backend" not in attributes


# ---------------------------------------------------------------------------
# BF08  on_result callback
# ---------------------------------------------------------------------------

class TestOnResult:

    def test_called_once_per_investigation_in_order(self, conn, provider, fakes):
        seen = []
        fakes.behaviour = {_B: STATUS_NOT_ELIGIBLE}
        report = backfill_embeddings(conn, provider, on_result=seen.append)
        assert tuple(seen) == report.results

    def test_called_as_soon_as_each_result_is_known(self, conn, provider, fakes):
        order = []
        original = fakes.embed_investigation

        def recording(c, p, i):
            order.append(f"embed:{i[:1]}")
            return original(c, p, i)

        import embedding_pipeline as pipeline
        pipeline.embed_investigation = recording
        try:
            backfill_embeddings(conn, provider, on_result=lambda r: order.append(f"result:{r.investigation_id[:1]}"))
        finally:
            pipeline.embed_investigation = fakes.embed_investigation
        assert order == ["embed:a", "result:a", "embed:b", "result:b", "embed:c", "result:c"]

    def test_called_for_failures_too(self, conn, provider, fakes):
        seen = []
        fakes.behaviour = {_A: ValueError("x")}
        backfill_embeddings(conn, provider, on_result=seen.append)
        assert [r.status for r in seen] == [STATUS_FAILURE, STATUS_INSERTED, STATUS_INSERTED]

    def test_optional(self, conn, provider, fakes):
        assert backfill_embeddings(conn, provider).total == 3

    def test_is_keyword_only(self, conn, provider, fakes):
        with pytest.raises(TypeError):
            backfill_embeddings(conn, provider, print)  # type: ignore[misc]

    def test_not_called_when_there_are_no_investigations(self, conn, provider, fakes):
        seen = []
        fakes.ids = []
        backfill_embeddings(conn, provider, on_result=seen.append)
        assert seen == []


# ---------------------------------------------------------------------------
# BF09  End-to-end with the real pipeline over a fake store
# ---------------------------------------------------------------------------

class InMemoryStore:
    def __init__(self) -> None:
        self.investigations: dict[str, InvestigationRow] = {}
        self.evidence: dict[str, list[EvidenceRow]] = {}
        self.rows: dict[str, dict] = {}

    def add(self, investigation_id: str, confidence: str = "HIGH", evidence=None) -> None:
        self.investigations[investigation_id] = InvestigationRow(
            investigation_id, "tool_failure", "svc", "tool.execute/Err", confidence,
        )
        self.evidence[investigation_id] = list(evidence or [])

    def fetch_investigation_ids(self, conn):
        return sorted(self.investigations)

    def fetch_investigation(self, conn, investigation_id):
        return self.investigations.get(investigation_id)

    def fetch_evidence(self, conn, investigation_id):
        return list(self.evidence.get(investigation_id, []))

    def fetch_stored_document_text(self, conn, embedding_id):
        row = self.rows.get(embedding_id)
        return None if row is None else row["document_text"]

    def insert_embedding(self, conn, **kwargs):
        if kwargs["embedding_id"] in self.rows:
            return False
        self.rows[kwargs["embedding_id"]] = dict(kwargs)
        return True


class CountingBackend:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, text: str):
        self.calls += 1
        return [float(i + 1) for i in range(384)]


@pytest.fixture
def real_pipeline(monkeypatch):
    store = InMemoryStore()
    for name in ("fetch_investigation_ids", "fetch_investigation", "fetch_evidence",
                 "fetch_stored_document_text", "insert_embedding"):
        monkeypatch.setattr(embedding_store, name, getattr(store, name))
    backend = CountingBackend()
    provider = EmbeddingProvider(EmbeddingModelIdentity("fake/model", "rev", 384), backend)
    return store, backend, provider


def _bad_evidence(investigation_id: str) -> list[EvidenceRow]:
    row = EvidenceRow(
        investigation_id=investigation_id, rank_position=1, evidence_type="mixed",
        evidence_score=0.9, span_name="s", service_name="svc", status_code="OK",
        error_type=None, tool_name=None, tool_status=None, agent_name=None,
        agent_operation=None, retrieval_result_count=None,
        retrieval_top_relevance_score=None, is_direct_subject=False, is_root_span=False,
        trace_duration_fraction=None,
    )
    return [row, row]          # duplicate rank_position -> builder ValueError


class TestWithRealPipeline:

    def test_mixed_database(self, real_pipeline):
        store, backend, provider = real_pipeline
        store.add(_A)
        store.add(_B, confidence="INSUFFICIENT_DATA")
        store.add(_C)
        store.add(_D, evidence=_bad_evidence(_D))
        conn = MagicMock()
        report = backfill_embeddings(conn, provider)
        assert [(r.investigation_id, r.status) for r in report.results] == [
            (_A, "inserted"), (_B, "not_eligible"), (_C, "inserted"), (_D, "failure"),
        ]
        assert report.results[3].error.startswith("ValueError: duplicate rank_position")
        assert len(store.rows) == 2
        assert backend.calls == 2
        assert report.succeeded is False

    def test_one_commit_per_successful_investigation(self, real_pipeline):
        store, _, provider = real_pipeline
        store.add(_A)
        store.add(_B, confidence="INSUFFICIENT_DATA")
        store.add(_C, evidence=_bad_evidence(_C))
        conn = MagicMock()
        backfill_embeddings(conn, provider)
        assert conn.commit.call_count == 2            # _A inserted, _B not_eligible
        assert conn.rollback.call_count == 2          # discovery + _C failure

    def test_rerun_is_idempotent_and_does_not_use_the_model(self, real_pipeline):
        store, backend, provider = real_pipeline
        store.add(_A)
        store.add(_B, confidence="INSUFFICIENT_DATA")
        store.add(_C)
        first = backfill_embeddings(MagicMock(), provider)
        calls_after_first = backend.calls
        snapshot = {k: dict(v) for k, v in store.rows.items()}

        second = backfill_embeddings(MagicMock(), provider)
        third = backfill_embeddings(MagicMock(), provider)

        assert (first.inserted, first.not_eligible) == (2, 1)
        for rerun in (second, third):
            assert (rerun.inserted, rerun.already_present, rerun.not_eligible) == (0, 2, 1)
            assert rerun.succeeded is True
        assert backend.calls == calls_after_first == 2
        assert store.rows == snapshot

    def test_text_mismatch_is_non_destructive(self, real_pipeline):
        store, backend, provider = real_pipeline
        store.add(_A)
        backfill_embeddings(MagicMock(), provider)
        (embedding_id, row), = store.rows.items()
        row["document_text"] = "older text"
        before = dict(row)

        report = backfill_embeddings(MagicMock(), provider)

        assert [r.status for r in report.results] == ["text_mismatch"]
        assert report.succeeded is False
        assert store.rows == {embedding_id: before}
        assert backend.calls == 1

    def test_newly_added_investigation_is_picked_up_on_rerun(self, real_pipeline):
        store, backend, provider = real_pipeline
        store.add(_A)
        backfill_embeddings(MagicMock(), provider)
        store.add(_B)
        report = backfill_embeddings(MagicMock(), provider)
        assert [(r.investigation_id, r.status) for r in report.results] == [
            (_A, "already_present"), (_B, "inserted"),
        ]
        assert backend.calls == 2

    def test_zero_informative_evidence_is_still_embedded(self, real_pipeline):
        store, _, provider = real_pipeline
        store.add(_A, confidence="LOW")
        report = backfill_embeddings(MagicMock(), provider)
        assert report.inserted == 1
        assert list(store.rows.values())[0]["document_text"].endswith("evidence: none")


# ---------------------------------------------------------------------------
# BF10  Import boundary and exclusions
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
        assert os.path.abspath(embedding_backfill.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules() == {
            "__future__", "dataclasses", "typing",
            "embedding_pipeline", "embedding_store", "embedding_provider", "embedding_record",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "retrieval_db", "sentence_transformer_backend", "sentence_transformers",
         "torch", "transformers", "numpy", "incident_document", "incident_signal",
         "similarity_search", "historical_context", "rca_models", "rca_persist",
         "os", "sys", "logging", "socket", "argparse"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules()

    def test_module_contains_no_sql(self):
        tree = _module_tree()
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({"execute", "executemany", "cursor"})
        strings = [
            n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and "\n" not in n.value
        ]
        for text in strings:
            words = set(text.upper().replace(",", " ").split())
            assert words.isdisjoint({"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"}), text

    def test_only_discovery_is_used_from_the_store(self):
        used = {
            node.attr for node in ast.walk(_module_tree())
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "embedding_store"
        }
        assert used == {"fetch_investigation_ids"}

    def test_only_the_pipeline_entry_point_is_used(self):
        used = {
            node.attr for node in ast.walk(_module_tree())
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "embedding_pipeline"
        }
        assert used == {"embed_investigation"}

    def test_no_write_function_is_referenced_directly(self):
        tree = _module_tree()
        referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        referenced |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for forbidden in ("insert_embedding", "build_incident_document",
                          "compute_embedding_id", "derive_signal",
                          "find_similar_investigations", "get_historical_context"):
            assert forbidden not in referenced

    def test_public_names(self):
        defined_here = {
            name for name, value in vars(embedding_backfill).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == "embedding_backfill"
        }
        assert defined_here == {"BackfillResult", "BackfillReport", "backfill_embeddings"}

    def test_no_retrieval_threshold_or_reasoning_functions(self):
        names = {
            n.name.lower() for n in ast.walk(_module_tree())
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        }
        for word in ("search", "similar", "retriev", "threshold", "root_cause",
                     "recommend", "delete", "update", "overwrite"):
            assert not any(word in name for name in names)

    def test_existing_pipeline_module_is_unchanged_by_import(self):
        assert callable(embedding_pipeline.embed_investigation)
        assert embedding_pipeline.embed_investigation.__module__ == "embedding_pipeline"

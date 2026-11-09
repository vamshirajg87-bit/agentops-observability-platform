"""
incident-retrieval/tests/unit/test_historical_context.py

Unit tests for historical_context.py.

No database, no model, no network.  Retrieval (Phase 12.6) and the store's
batch fetch are replaced by fakes, and the connection is a MagicMock used
only to prove that the service never touches it.

Test inventory:
    HC01  Disclaimer and result models
    HC02  Composition: retrieval is delegated, not duplicated
    HC03  Status propagation for every retrieval status
    HC04  Similarity is passed through unchanged
    HC05  Ordering follows retrieval, never the fetched rows
    HC06  Batch fetch: one query, current + matches
    HC07  Fail closed: missing, duplicate, unexpected rows
    HC08  Fail closed: malformed stored data
    HC09  Errors from retrieval and the store propagate
    HC10  Connection / transaction ownership
    HC11  Read-only, model-free, import boundary
"""

from __future__ import annotations

import ast
import dataclasses
import datetime
import os
from unittest.mock import MagicMock

import pytest

import embedding_store
import historical_context
import similarity_search
from embedding_pipeline import InvestigationNotFoundError
from embedding_provider import EmbeddingModelIdentity
from historical_context import (
    HISTORICAL_CONTEXT_DISCLAIMER,
    HistoricalContext,
    HistoricalMatch,
    InvestigationContext,
    get_historical_context,
)
from similarity_search import (
    STATUS_NOT_ELIGIBLE,
    STATUS_OK,
    STATUS_QUERY_NOT_EMBEDDED,
    STATUS_TEXT_MISMATCH,
    RetrievalOutcome,
    SimilarInvestigation,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "historical_context.py")

_INV = "a" * 64
_B, _C, _D, _E = ("b" * 64, "c" * 64, "d" * 64, "e" * 64)
_EMB = "9" * 64

_T0 = datetime.datetime(2026, 9, 28, 14, 2, 11, tzinfo=datetime.timezone.utc)


def _row(investigation_id: str, **overrides) -> dict:
    row = {
        "investigation_id": investigation_id,
        "anomaly_type": "tool_failure",
        "service_name": "agentops-demo-app",
        "operation_name": "tool.execute/ToolExecutionError",
        "confidence": "HIGH",
        "severity": "CRITICAL",
        "event_time": _T0,
        "summary": f"summary of {str(investigation_id)[:4]}",
        "limitations": ["tool_name_absent"],
    }
    row.update(overrides)
    return row


def _outcome(status: str = STATUS_OK, matches=(), top_k: int = 5, embedding_id=_EMB) -> RetrievalOutcome:
    return RetrievalOutcome(
        investigation_id=_INV,
        status=status,
        embedding_id=embedding_id,
        top_k=top_k,
        matches=tuple(SimilarInvestigation(i, s) for i, s in matches),
    )


class Fakes:
    """Stand-ins for find_similar_investigations and fetch_investigation_contexts."""

    def __init__(self) -> None:
        self.outcome: RetrievalOutcome = _outcome()
        self.rows: object = None            # None = build rows for the requested ids
        self.row_overrides: dict[str, dict] = {}
        self.retrieval_calls: list[tuple] = []
        self.fetch_calls: list[tuple] = []
        self.retrieval_error: Exception | None = None
        self.fetch_error: Exception | None = None

    def find_similar_investigations(self, conn, identity, investigation_id, *, top_k=5):
        self.retrieval_calls.append((conn, identity, investigation_id, top_k))
        if self.retrieval_error is not None:
            raise self.retrieval_error
        return self.outcome

    def fetch_investigation_contexts(self, conn, investigation_ids):
        self.fetch_calls.append((conn, list(investigation_ids)))
        if self.fetch_error is not None:
            raise self.fetch_error
        if self.rows is not None:
            return self.rows
        return [
            _row(i, **self.row_overrides.get(i, {}))
            for i in sorted(set(investigation_ids))
        ]


@pytest.fixture
def fakes(monkeypatch) -> Fakes:
    fake = Fakes()
    monkeypatch.setattr(
        similarity_search, "find_similar_investigations", fake.find_similar_investigations,
    )
    monkeypatch.setattr(
        embedding_store, "fetch_investigation_contexts", fake.fetch_investigation_contexts,
    )
    return fake


@pytest.fixture
def identity() -> EmbeddingModelIdentity:
    return EmbeddingModelIdentity(
        "sentence-transformers/all-MiniLM-L6-v2",
        "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        384,
    )


@pytest.fixture
def conn() -> MagicMock:
    return MagicMock()


def _get(conn, identity, **kwargs) -> HistoricalContext:
    return get_historical_context(conn, identity, _INV, **kwargs)


# ---------------------------------------------------------------------------
# HC01  Disclaimer and result models
# ---------------------------------------------------------------------------

class TestDisclaimerAndModels:

    def test_disclaimer_text_exact(self):
        assert HISTORICAL_CONTEXT_DISCLAIMER == (
            "Historical similarity provides context only. It does not prove that the "
            "current incident has the same root cause as any historical investigation."
        )

    def test_disclaimer_is_a_single_line(self):
        assert "\n" not in HISTORICAL_CONTEXT_DISCLAIMER
        assert "  " not in HISTORICAL_CONTEXT_DISCLAIMER

    def test_disclaimer_is_in_the_module_documentation(self):
        doc = " ".join(historical_context.__doc__.split())
        assert "Historical similarity provides context only." in doc
        assert "does not prove" in doc

    @pytest.mark.parametrize("cls", [InvestigationContext, HistoricalMatch, HistoricalContext])
    def test_models_are_frozen_dataclasses(self, cls):
        assert dataclasses.is_dataclass(cls)
        assert cls.__dataclass_params__.frozen is True

    def test_investigation_context_fields_exact(self):
        assert [f.name for f in dataclasses.fields(InvestigationContext)] == [
            "investigation_id", "anomaly_type", "service_name", "operation_name",
            "confidence", "severity", "event_time", "summary", "limitations",
        ]

    def test_historical_match_fields_exact(self):
        assert [f.name for f in dataclasses.fields(HistoricalMatch)] == [
            "similarity", "investigation",
        ]

    def test_historical_context_fields_exact(self):
        assert [f.name for f in dataclasses.fields(HistoricalContext)] == [
            "status", "embedding_id", "top_k", "current", "matches", "disclaimer",
        ]

    @pytest.mark.parametrize(
        "excluded",
        ["trace_span_count", "investigated_at", "trace_id", "anomaly_id",
         "analyzer_version", "subject_span_id", "observed_value", "baseline_median",
         "anomaly_score", "evidence", "explanation", "error_message", "document_text"],
    )
    def test_context_has_no_excluded_field(self, excluded):
        assert excluded not in {f.name for f in dataclasses.fields(InvestigationContext)}

    @pytest.mark.parametrize(
        "forbidden",
        ["confidence", "probability", "likelihood", "score_band", "similarity_level",
         "similarity_label", "is_similar", "above_threshold", "root_cause", "rank"],
    )
    def test_match_has_no_interpretation_field(self, forbidden):
        assert forbidden not in {f.name for f in dataclasses.fields(HistoricalMatch)}

    def test_models_are_immutable(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        result = _get(conn, identity)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.status = "x"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.matches[0].similarity = 1.0  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.current.summary = "x"  # type: ignore[misc]

    def test_sequences_are_tuples(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        result = _get(conn, identity)
        assert type(result.matches) is tuple
        assert type(result.current.limitations) is tuple
        assert type(result.matches[0].investigation.limitations) is tuple

    def test_result_is_hashable(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        assert isinstance(hash(_get(conn, identity)), int)

    def test_disclaimer_on_every_result(self, conn, identity, fakes):
        for status in (STATUS_OK, STATUS_NOT_ELIGIBLE, STATUS_QUERY_NOT_EMBEDDED, STATUS_TEXT_MISMATCH):
            fakes.outcome = _outcome(status=status)
            assert _get(conn, identity).disclaimer == HISTORICAL_CONTEXT_DISCLAIMER


# ---------------------------------------------------------------------------
# HC02  Composition
# ---------------------------------------------------------------------------

class TestComposition:

    def test_retrieval_called_exactly_once(self, conn, identity, fakes):
        _get(conn, identity)
        assert len(fakes.retrieval_calls) == 1

    def test_retrieval_receives_the_same_arguments(self, conn, identity, fakes):
        _get(conn, identity, top_k=17)
        assert fakes.retrieval_calls == [(conn, identity, _INV, 17)]
        assert fakes.retrieval_calls[0][1] is identity

    def test_default_top_k_is_the_retrieval_default(self, conn, identity, fakes):
        _get(conn, identity)
        assert fakes.retrieval_calls[0][3] == similarity_search.DEFAULT_TOP_K == 5

    def test_top_k_is_keyword_only(self, conn, identity, fakes):
        with pytest.raises(TypeError):
            get_historical_context(conn, identity, _INV, 5)  # type: ignore[misc]

    def test_top_k_is_not_validated_here(self, conn, identity, fakes):
        """Validation belongs to retrieval; the value is handed over untouched."""
        fakes.outcome = _outcome(top_k=0)
        _get(conn, identity, top_k=0)
        assert fakes.retrieval_calls[0][3] == 0

    def test_retrieval_runs_before_the_context_fetch(self, conn, identity, fakes, monkeypatch):
        order = []
        retrieval, fetch = fakes.find_similar_investigations, fakes.fetch_investigation_contexts

        def recording_retrieval(*a, **k):
            order.append("retrieval")
            return retrieval(*a, **k)

        def recording_fetch(*a, **k):
            order.append("fetch")
            return fetch(*a, **k)

        monkeypatch.setattr(similarity_search, "find_similar_investigations", recording_retrieval)
        monkeypatch.setattr(embedding_store, "fetch_investigation_contexts", recording_fetch)
        _get(conn, identity)
        assert order == ["retrieval", "fetch"]

    def test_no_retrieval_logic_is_duplicated(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        referenced |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for name in ("build_incident_document", "derive_signal", "compute_embedding_id",
                     "fetch_investigation", "fetch_evidence", "fetch_stored_document_text",
                     "fetch_similar_investigations", "DOC_VERSION"):
            assert name not in referenced


# ---------------------------------------------------------------------------
# HC03  Status propagation
# ---------------------------------------------------------------------------

class TestStatusPropagation:

    def test_ok_with_matches(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.82), (_C, 0.76)], top_k=7)
        result = _get(conn, identity, top_k=7)
        assert result.status == "ok"
        assert result.embedding_id == _EMB
        assert result.top_k == 7
        assert [m.investigation.investigation_id for m in result.matches] == [_B, _C]
        assert result.current.investigation_id == _INV

    def test_ok_with_zero_matches(self, conn, identity, fakes):
        result = _get(conn, identity)
        assert result.status == "ok"
        assert result.matches == ()
        assert result.current.investigation_id == _INV

    def test_not_eligible(self, conn, identity, fakes):
        fakes.outcome = _outcome(status=STATUS_NOT_ELIGIBLE, embedding_id=None)
        result = _get(conn, identity)
        assert result.status == "not_eligible"
        assert result.embedding_id is None
        assert result.matches == ()
        assert result.current.investigation_id == _INV

    def test_query_not_embedded(self, conn, identity, fakes):
        fakes.outcome = _outcome(status=STATUS_QUERY_NOT_EMBEDDED)
        result = _get(conn, identity)
        assert result.status == "query_not_embedded"
        assert result.embedding_id == _EMB
        assert result.matches == ()

    def test_text_mismatch(self, conn, identity, fakes):
        fakes.outcome = _outcome(status=STATUS_TEXT_MISMATCH)
        result = _get(conn, identity)
        assert result.status == "text_mismatch"
        assert result.matches == ()

    @pytest.mark.parametrize(
        "status", [STATUS_OK, STATUS_NOT_ELIGIBLE, STATUS_QUERY_NOT_EMBEDDED, STATUS_TEXT_MISMATCH],
    )
    def test_status_embedding_id_and_top_k_are_verbatim(self, conn, identity, fakes, status):
        fakes.outcome = _outcome(status=status, top_k=23, embedding_id="f" * 64)
        result = _get(conn, identity, top_k=23)
        assert result.status is fakes.outcome.status
        assert result.embedding_id == "f" * 64
        assert result.top_k == 23

    @pytest.mark.parametrize(
        "status", [STATUS_NOT_ELIGIBLE, STATUS_QUERY_NOT_EMBEDDED, STATUS_TEXT_MISMATCH],
    )
    def test_current_context_is_always_present(self, conn, identity, fakes, status):
        fakes.outcome = _outcome(status=status)
        result = _get(conn, identity)
        assert isinstance(result.current, InvestigationContext)
        assert result.current.summary == f"summary of {_INV[:4]}"

    def test_statuses_are_not_renamed_or_merged(self, conn, identity, fakes):
        seen = set()
        for status in similarity_search.RETRIEVAL_STATUSES:
            fakes.outcome = _outcome(status=status)
            seen.add(_get(conn, identity).status)
        assert seen == set(similarity_search.RETRIEVAL_STATUSES)

    def test_current_context_fields(self, conn, identity, fakes):
        fakes.row_overrides[_INV] = dict(
            anomaly_type="latency", service_name=None, operation_name=None,
            confidence="LOW", severity="INFO", summary="a summary", limitations=[],
        )
        assert _get(conn, identity).current == InvestigationContext(
            investigation_id=_INV, anomaly_type="latency", service_name=None,
            operation_name=None, confidence="LOW", severity="INFO", event_time=_T0,
            summary="a summary", limitations=(),
        )


# ---------------------------------------------------------------------------
# HC04  Similarity unchanged
# ---------------------------------------------------------------------------

class TestSimilarityUnchanged:

    @pytest.mark.parametrize(
        "value", [0.8214567890123456, 1.0, 0.0, -0.25, -1.0, 1.0000005, 0.1 + 0.2, 1e-12],
    )
    def test_value_is_identical(self, conn, identity, fakes, value):
        fakes.outcome = _outcome(matches=[(_B, value)])
        similarity = _get(conn, identity).matches[0].similarity
        assert similarity == value
        assert repr(similarity) == repr(value)

    def test_same_float_object_is_passed_through(self, conn, identity, fakes):
        value = 0.123456789
        fakes.outcome = _outcome(matches=[(_B, value)])
        assert _get(conn, identity).matches[0].similarity is fakes.outcome.matches[0].similarity

    def test_not_rounded(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.82149999)])
        assert _get(conn, identity).matches[0].similarity != 0.8215

    def test_no_threshold_low_and_negative_matches_are_kept(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.02), (_C, 0.0), (_D, -0.5)])
        assert [m.similarity for m in _get(conn, identity).matches] == [0.02, 0.0, -0.5]

    def test_similarity_is_separate_from_rca_confidence(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.99)])
        fakes.row_overrides[_B] = {"confidence": "LOW"}
        match = _get(conn, identity).matches[0]
        assert match.similarity == 0.99
        assert match.investigation.confidence == "LOW"

    def test_no_threshold_or_band_constants_in_module(self):
        names = {name.upper() for name in vars(historical_context)}
        assert not any(
            word in name for name in names
            for word in ("THRESHOLD", "MIN_SIMILARITY", "HIGH_", "MEDIUM_", "LOW_", "BAND")
        )


# ---------------------------------------------------------------------------
# HC05  Ordering
# ---------------------------------------------------------------------------

class TestOrdering:

    def test_matches_follow_retrieval_order(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_D, 0.9), (_B, 0.8), (_E, 0.7), (_C, 0.6)])
        assert [m.investigation.investigation_id for m in _get(conn, identity).matches] == [
            _D, _B, _E, _C,
        ]

    def test_fetched_row_order_does_not_affect_the_result(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_D, 0.9), (_B, 0.8), (_C, 0.7)])
        expected = _get(conn, identity)
        for rows in (
            [_row(_INV), _row(_B), _row(_C), _row(_D)],
            [_row(_D), _row(_C), _row(_B), _row(_INV)],
            [_row(_C), _row(_INV), _row(_D), _row(_B)],
        ):
            fakes.rows = rows
            assert _get(conn, identity) == expected

    def test_not_re_sorted_by_similarity(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.1), (_C, 0.9), (_D, 0.5)])
        result = _get(conn, identity)
        assert [m.similarity for m in result.matches] == [0.1, 0.9, 0.5]
        assert [m.investigation.investigation_id for m in result.matches] == [_B, _C, _D]

    def test_ties_keep_retrieval_order(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_E, 0.7), (_B, 0.7), (_D, 0.7)])
        assert [m.investigation.investigation_id for m in _get(conn, identity).matches] == [
            _E, _B, _D,
        ]

    def test_each_similarity_stays_with_its_investigation(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_D, 0.91), (_B, 0.52)])
        fakes.row_overrides[_D] = {"summary": "about D"}
        fakes.row_overrides[_B] = {"summary": "about B"}
        pairs = [(m.similarity, m.investigation.summary) for m in _get(conn, identity).matches]
        assert pairs == [(0.91, "about D"), (0.52, "about B")]

    def test_no_match_is_dropped(self, conn, identity, fakes):
        ids = [f"{i:064x}" for i in range(1, 51)]
        fakes.outcome = _outcome(matches=[(i, 1.0 - n / 100.0) for n, i in enumerate(ids)], top_k=50)
        result = _get(conn, identity, top_k=50)
        assert [m.investigation.investigation_id for m in result.matches] == ids


# ---------------------------------------------------------------------------
# HC06  Batch fetch
# ---------------------------------------------------------------------------

class TestBatchFetch:

    def test_exactly_one_context_fetch(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9), (_C, 0.8), (_D, 0.7)])
        _get(conn, identity)
        assert len(fakes.fetch_calls) == 1

    def test_ids_are_current_then_matches_in_order(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_D, 0.9), (_B, 0.8)])
        _get(conn, identity)
        assert fakes.fetch_calls[0][1] == [_INV, _D, _B]

    @pytest.mark.parametrize(
        "status", [STATUS_NOT_ELIGIBLE, STATUS_QUERY_NOT_EMBEDDED, STATUS_TEXT_MISMATCH],
    )
    def test_only_the_current_id_for_non_ok_statuses(self, conn, identity, fakes, status):
        fakes.outcome = _outcome(status=status)
        _get(conn, identity)
        assert fakes.fetch_calls == [(conn, [_INV])]

    def test_only_the_current_id_for_zero_matches(self, conn, identity, fakes):
        _get(conn, identity)
        assert fakes.fetch_calls == [(conn, [_INV])]

    def test_one_fetch_for_fifty_matches(self, conn, identity, fakes):
        ids = [f"{i:064x}" for i in range(1, 51)]
        fakes.outcome = _outcome(matches=[(i, 0.5) for i in ids], top_k=50)
        _get(conn, identity, top_k=50)
        assert len(fakes.fetch_calls) == 1
        assert len(fakes.fetch_calls[0][1]) == 51

    def test_same_connection_used_for_retrieval_and_fetch(self, conn, identity, fakes):
        _get(conn, identity)
        assert fakes.retrieval_calls[0][0] is conn
        assert fakes.fetch_calls[0][0] is conn

    def test_match_context_fields(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.82)])
        fakes.row_overrides[_B] = dict(
            anomaly_type="latency", service_name="payments", operation_name="trace",
            confidence="MEDIUM", severity="WARNING", summary="historic summary",
            limitations=["partial_trace", "no_error_spans"],
            event_time=datetime.datetime(2026, 9, 21, 9, 40, 3, tzinfo=datetime.timezone.utc),
        )
        assert _get(conn, identity).matches == (
            HistoricalMatch(
                similarity=0.82,
                investigation=InvestigationContext(
                    investigation_id=_B, anomaly_type="latency", service_name="payments",
                    operation_name="trace", confidence="MEDIUM", severity="WARNING",
                    event_time=datetime.datetime(2026, 9, 21, 9, 40, 3, tzinfo=datetime.timezone.utc),
                    summary="historic summary",
                    limitations=("partial_trace", "no_error_spans"),
                ),
            ),
        )

    def test_stored_values_are_not_altered(self, conn, identity, fakes):
        fakes.row_overrides[_INV] = {"summary": "  spaced \n summary  ", "service_name": " Padded "}
        current = _get(conn, identity).current
        assert current.summary == "  spaced \n summary  "
        assert current.service_name == " Padded "

    def test_fetched_rows_are_not_mutated(self, conn, identity, fakes):
        rows = [_row(_INV), _row(_B)]
        snapshot = [dict(r) for r in rows]
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        fakes.rows = rows
        _get(conn, identity)
        assert rows == snapshot
        assert type(rows[0]["limitations"]) is list


# ---------------------------------------------------------------------------
# HC07  Fail closed: missing / duplicate / unexpected
# ---------------------------------------------------------------------------

class TestFailClosedRows:

    def test_missing_current_context_raises(self, conn, identity, fakes):
        fakes.rows = []
        with pytest.raises(RuntimeError, match="current investigation"):
            _get(conn, identity)

    def test_missing_current_context_names_the_id(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        fakes.rows = [_row(_B)]
        with pytest.raises(RuntimeError, match=_INV):
            _get(conn, identity)

    def test_missing_historical_context_raises(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9), (_C, 0.8)])
        fakes.rows = [_row(_INV), _row(_B)]
        with pytest.raises(RuntimeError, match="historical investigation") as excinfo:
            _get(conn, identity)
        assert _C in str(excinfo.value)

    def test_a_missing_match_is_never_silently_dropped(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9), (_C, 0.8), (_D, 0.7)])
        fakes.rows = [_row(_INV), _row(_B), _row(_D)]
        result = None
        with pytest.raises(RuntimeError):
            result = _get(conn, identity)
        assert result is None

    def test_duplicate_context_row_raises(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        fakes.rows = [_row(_INV), _row(_B), _row(_B)]
        with pytest.raises(RuntimeError, match="twice"):
            _get(conn, identity)

    def test_duplicate_current_row_raises(self, conn, identity, fakes):
        fakes.rows = [_row(_INV), _row(_INV)]
        with pytest.raises(RuntimeError, match="twice"):
            _get(conn, identity)

    def test_unexpected_context_row_raises(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        fakes.rows = [_row(_INV), _row(_B), _row(_E)]
        with pytest.raises(RuntimeError, match="unexpected") as excinfo:
            _get(conn, identity)
        assert _E in str(excinfo.value)

    def test_unexpected_row_for_non_ok_status_raises(self, conn, identity, fakes):
        fakes.outcome = _outcome(status=STATUS_NOT_ELIGIBLE, embedding_id=None)
        fakes.rows = [_row(_INV), _row(_B)]
        with pytest.raises(RuntimeError, match="unexpected"):
            _get(conn, identity)

    @pytest.mark.parametrize(
        "rows", [None, "rows", 7, {"a": 1}, iter([])],
        ids=["none", "str", "int", "dict", "iterator"],
    )
    def test_non_list_result_raises(self, conn, identity, fakes, rows):
        class Holder:
            pass

        fakes.rows = rows if rows is not None else Holder()
        with pytest.raises(RuntimeError, match="expected a list"):
            _get(conn, identity)

    def test_tuple_of_rows_is_accepted(self, conn, identity, fakes):
        fakes.rows = (_row(_INV),)
        assert _get(conn, identity).current.investigation_id == _INV


# ---------------------------------------------------------------------------
# HC08  Fail closed: malformed stored data
# ---------------------------------------------------------------------------

def _without(row: dict, key: str) -> dict:
    return {k: v for k, v in row.items() if k != key}


class TestFailClosedMalformedData:

    @pytest.mark.parametrize(
        "row", [None, "row", 5, (_INV, "x"), [_INV]],
        ids=["none", "str", "int", "tuple", "list"],
    )
    def test_non_mapping_row_raises(self, conn, identity, fakes, row):
        fakes.rows = [row]
        with pytest.raises(RuntimeError, match="malformed"):
            _get(conn, identity)

    @pytest.mark.parametrize(
        "key",
        ["investigation_id", "anomaly_type", "service_name", "operation_name",
         "confidence", "severity", "event_time", "summary", "limitations"],
    )
    def test_missing_field_raises(self, conn, identity, fakes, key):
        fakes.rows = [_without(_row(_INV), key)]
        with pytest.raises(RuntimeError, match="malformed"):
            _get(conn, identity)

    @pytest.mark.parametrize("extra", ["trace_span_count", "trace_id", "evidence", "explanation"])
    def test_extra_field_raises(self, conn, identity, fakes, extra):
        fakes.rows = [dict(_row(_INV), **{extra: "x"})]
        with pytest.raises(RuntimeError, match="malformed"):
            _get(conn, identity)

    @pytest.mark.parametrize("value", [None, 123, b"a", "", "   "],
                             ids=["none", "int", "bytes", "empty", "blank"])
    def test_invalid_investigation_id_raises(self, conn, identity, fakes, value):
        fakes.rows = [_row(value)]
        with pytest.raises(RuntimeError, match="invalid investigation_id"):
            _get(conn, identity)

    @pytest.mark.parametrize("field", ["anomaly_type", "confidence", "severity"])
    @pytest.mark.parametrize("value", [None, 123, "", "   ", ["x"]],
                             ids=["none", "int", "empty", "blank", "list"])
    def test_invalid_required_text_raises(self, conn, identity, fakes, field, value):
        fakes.rows = [_row(_INV, **{field: value})]
        with pytest.raises(RuntimeError, match=f"invalid {field}"):
            _get(conn, identity)

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    @pytest.mark.parametrize("value", [123, b"x", ["x"], 1.5], ids=["int", "bytes", "list", "float"])
    def test_invalid_optional_text_raises(self, conn, identity, fakes, field, value):
        fakes.rows = [_row(_INV, **{field: value})]
        with pytest.raises(RuntimeError, match=f"invalid {field}"):
            _get(conn, identity)

    @pytest.mark.parametrize("field", ["service_name", "operation_name"])
    def test_null_optional_text_is_valid(self, conn, identity, fakes, field):
        fakes.rows = [_row(_INV, **{field: None})]
        assert getattr(_get(conn, identity).current, field) is None

    @pytest.mark.parametrize(
        "value", [None, "2026-09-28T14:02:11+00:00", 1759068131, datetime.date(2026, 9, 28)],
        ids=["none", "iso-string", "epoch", "date"],
    )
    def test_invalid_event_time_raises(self, conn, identity, fakes, value):
        fakes.rows = [_row(_INV, event_time=value)]
        with pytest.raises(RuntimeError, match="invalid event_time"):
            _get(conn, identity)

    @pytest.mark.parametrize("value", [None, 123, ["s"], b"s"], ids=["none", "int", "list", "bytes"])
    def test_invalid_summary_raises(self, conn, identity, fakes, value):
        fakes.rows = [_row(_INV, summary=value)]
        with pytest.raises(RuntimeError, match="invalid summary"):
            _get(conn, identity)

    def test_empty_summary_is_valid(self, conn, identity, fakes):
        fakes.rows = [_row(_INV, summary="")]
        assert _get(conn, identity).current.summary == ""

    @pytest.mark.parametrize(
        "value", [None, "tool_name_absent", 5, [1, 2], ["ok", None], {"a"}],
        ids=["none", "str", "int", "ints", "mixed", "set"],
    )
    def test_invalid_limitations_raises(self, conn, identity, fakes, value):
        fakes.rows = [_row(_INV, limitations=value)]
        with pytest.raises(RuntimeError, match="invalid limitations"):
            _get(conn, identity)

    @pytest.mark.parametrize("value", [[], ["a"], ["a", "b"], ("a", "b")])
    def test_valid_limitations_become_a_tuple(self, conn, identity, fakes, value):
        fakes.rows = [_row(_INV, limitations=value)]
        assert _get(conn, identity).current.limitations == tuple(value)

    def test_malformed_match_row_raises_and_names_the_investigation(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        fakes.rows = [_row(_INV), _row(_B, severity=None)]
        with pytest.raises(RuntimeError, match="invalid severity") as excinfo:
            _get(conn, identity)
        assert _B in str(excinfo.value)

    def test_no_partial_result_on_malformed_data(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9), (_C, 0.8)])
        fakes.rows = [_row(_INV), _row(_B), _row(_C, event_time="yesterday")]
        result = None
        with pytest.raises(RuntimeError):
            result = _get(conn, identity)
        assert result is None


# ---------------------------------------------------------------------------
# HC09  Error propagation
# ---------------------------------------------------------------------------

class TestErrorPropagation:

    @pytest.mark.parametrize(
        "error",
        [InvestigationNotFoundError(_INV), ValueError("top_k must be between 1 and 50, got 0"),
         RuntimeError("similarity query returned the query investigation itself")],
        ids=["not-found", "value-error", "runtime-error"],
    )
    def test_retrieval_error_propagates_as_the_same_object(self, conn, identity, fakes, error):
        fakes.retrieval_error = error
        with pytest.raises(type(error)) as excinfo:
            _get(conn, identity)
        assert excinfo.value is error

    def test_no_context_fetch_after_a_retrieval_error(self, conn, identity, fakes):
        fakes.retrieval_error = InvestigationNotFoundError(_INV)
        with pytest.raises(InvestigationNotFoundError):
            _get(conn, identity)
        assert fakes.fetch_calls == []

    def test_database_error_from_retrieval_propagates(self, conn, identity, fakes):
        import psycopg
        boom = psycopg.OperationalError("connection lost")
        fakes.retrieval_error = boom
        with pytest.raises(psycopg.OperationalError) as excinfo:
            _get(conn, identity)
        assert excinfo.value is boom

    def test_database_error_from_the_context_fetch_propagates(self, conn, identity, fakes):
        import psycopg
        boom = psycopg.OperationalError("connection lost")
        fakes.fetch_error = boom
        with pytest.raises(psycopg.OperationalError) as excinfo:
            _get(conn, identity)
        assert excinfo.value is boom

    def test_module_catches_nothing(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        assert not any(isinstance(n, (ast.Try, ast.With)) for n in ast.walk(tree))


# ---------------------------------------------------------------------------
# HC10  Connection / transaction ownership
# ---------------------------------------------------------------------------

_STATUSES = [STATUS_OK, STATUS_NOT_ELIGIBLE, STATUS_QUERY_NOT_EMBEDDED, STATUS_TEXT_MISMATCH]


class TestOwnership:

    @pytest.mark.parametrize("status", _STATUSES)
    def test_no_commit_rollback_or_close_on_any_status(self, conn, identity, fakes, status):
        fakes.outcome = _outcome(status=status)
        _get(conn, identity)
        conn.commit.assert_not_called()
        conn.rollback.assert_not_called()
        conn.close.assert_not_called()

    @pytest.mark.parametrize("status", _STATUSES)
    def test_connection_is_never_touched_directly(self, conn, identity, fakes, status):
        fakes.outcome = _outcome(status=status)
        _get(conn, identity)
        assert conn.mock_calls == []

    def test_ok_with_matches_does_not_touch_the_connection(self, conn, identity, fakes):
        fakes.outcome = _outcome(matches=[(_B, 0.9), (_C, 0.8)])
        _get(conn, identity)
        assert conn.mock_calls == []

    def test_strict_connection_is_never_accessed(self, identity, fakes):
        class StrictConnection:
            def __getattr__(self, name):
                raise AssertionError(f"service accessed conn.{name}")

            def __setattr__(self, name, value):
                raise AssertionError(f"service set conn.{name}")

        fakes.outcome = _outcome(matches=[(_B, 0.9)])
        assert get_historical_context(StrictConnection(), identity, _INV).status == "ok"

    @pytest.mark.parametrize("where", ["retrieval", "fetch", "validation"])
    def test_error_triggers_no_transaction_management(self, conn, identity, fakes, where):
        if where == "retrieval":
            fakes.retrieval_error = RuntimeError("boom")
        elif where == "fetch":
            fakes.fetch_error = RuntimeError("boom")
        else:
            fakes.rows = []
        with pytest.raises(RuntimeError):
            _get(conn, identity)
        assert conn.mock_calls == []

    def test_module_source_has_no_transaction_or_connection_calls(self):
        tree = ast.parse(open(_MODULE_PATH, encoding="utf-8").read())
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert attributes.isdisjoint({
            "commit", "rollback", "close", "connect", "cursor", "execute",
            "executemany", "autocommit", "transaction",
        })


# ---------------------------------------------------------------------------
# HC11  Read-only, model-free, import boundary
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
        assert os.path.abspath(historical_context.__file__) == _MODULE_PATH

    def test_imports_exact(self):
        assert _imported_modules() == {
            "__future__", "dataclasses", "datetime", "typing",
            "embedding_store", "similarity_search", "embedding_provider",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "retrieval_db", "sentence_transformer_backend", "sentence_transformers",
         "torch", "transformers", "numpy", "embedding_pipeline", "incident_document",
         "incident_signal", "embedding_record", "rca_models", "rca_confidence",
         "rca_ranker", "os", "sys", "logging", "socket", "argparse"],
    )
    def test_forbidden_module_not_imported(self, forbidden):
        assert forbidden not in _imported_modules()

    def test_only_the_batch_fetch_of_the_store_is_used(self):
        used = {
            node.attr for node in ast.walk(_module_tree())
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "embedding_store"
        }
        assert used == {"fetch_investigation_contexts"}

    def test_only_the_retrieval_entry_point_is_called(self):
        used = {
            node.attr for node in ast.walk(_module_tree())
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "similarity_search"
        }
        assert used == {"find_similar_investigations"}

    def test_no_write_or_embedding_function_is_referenced(self):
        tree = _module_tree()
        referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        referenced |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for forbidden in ("insert_embedding", "embed_investigation", "embed",
                          "create_default_provider", "EmbeddingProvider", "load",
                          "fetch_evidence"):
            assert forbidden not in referenced

    def test_module_contains_no_sql(self):
        strings = [
            n.value for n in ast.walk(_module_tree())
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and "\n" not in n.value
        ]
        for text in strings:
            words = set(text.upper().replace(",", " ").split())
            assert words.isdisjoint({"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"}), text

    def test_model_library_is_not_loaded(self, conn, identity, fakes):
        import sys
        watched = ("sentence_transformers", "torch", "transformers")
        before = {m for m in watched if m in sys.modules}
        _get(conn, identity)
        assert {m for m in watched if m in sys.modules} == before

    def test_public_names(self):
        defined_here = {
            name for name, value in vars(historical_context).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == "historical_context"
        }
        assert defined_here == {
            "InvestigationContext", "HistoricalMatch", "HistoricalContext",
            "get_historical_context",
        }
        assert isinstance(historical_context.HISTORICAL_CONTEXT_DISCLAIMER, str)

    def test_no_reasoning_or_generation_functions(self):
        names = {
            n.name.lower() for n in ast.walk(_module_tree())
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        }
        for word in ("root_cause", "diagnos", "infer", "predict", "recommend",
                     "remediat", "summar", "generate", "explain", "threshold", "backfill"):
            assert not any(word in name for name in names)

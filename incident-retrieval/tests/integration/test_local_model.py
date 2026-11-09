"""
incident-retrieval/tests/integration/test_local_model.py

Opt-in integration tests against the real, locally cached embedding model.

Skipped by default.  Enable with:

    INCIDENT_RETRIEVAL_RUN_MODEL_TESTS=1

Requirements when enabled:
    - incident-retrieval/requirements.txt is installed
    - the locked model revision is already in the local Hugging Face cache
      (see the one-time acquisition command in sentence_transformer_backend.py)

These tests never download anything.  The model is loaded with
local_files_only=True, and all socket connections are blocked for the
duration of the module so that an accidental network call fails loudly.

No database access.  Nothing is persisted.

Float results are compared within tolerances; bit-identical output across
machines or library versions is not asserted.

Test inventory:
    I01  Offline load of the locked revision
    I02  Dimension and sequence limit
    I03  Representative Phase 12.3 document embedding
    I04  Repeatability within tolerance
    I05  Emoji / non-BMP input
    I06  Token counts for the Phase 12.3 golden documents
    I07  Oversized document: truncation reported, still embedded
    I08  Missing revision fails locally
"""

from __future__ import annotations

import ast
import math
import os
import socket

import pytest

from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider
from incident_document import EvidenceRow, InvestigationRow, build_incident_document
from sentence_transformer_backend import (
    EMBEDDING_DIMENSION,
    MODEL_MAX_SEQUENCE_LENGTH,
    MODEL_NAME,
    MODEL_REVISION,
    SentenceTransformerBackend,
    TokenUsage,
    create_default_provider,
)

_ENV_SWITCH = "INCIDENT_RETRIEVAL_RUN_MODEL_TESTS"

pytestmark = pytest.mark.skipif(
    os.environ.get(_ENV_SWITCH) != "1",
    reason=f"real-model tests are opt-in; set {_ENV_SWITCH}=1",
)

_PHASE_12_3_TESTS = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "unit", "test_incident_document.py")
)

# Token counts measured with the locked tokenizer revision.  They are exact
# integers and depend only on the pinned tokenizer files, not on float math.
_GOLDEN_TOKENS_WITH_SPECIAL = {
    "test_tool_failure_modelled_on_live_investigation": 216,
    "test_trace_latency": 72,
    "test_retrieval_quality": 96,
    "test_error_rate_with_unusual_text": 58,
    "test_zero_informative_evidence": 24,
}

_REPEAT_MAX_ABS_DIFF = 1e-6
_REPEAT_MIN_COSINE = 1.0 - 1e-9
_UNIT_NORM_TOLERANCE = 1e-12


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm(vector) -> float:
    return math.sqrt(math.fsum(x * x for x in vector))


def _cosine(a, b) -> float:
    return math.fsum(x * y for x, y in zip(a, b)) / (_norm(a) * _norm(b))


def _max_abs_diff(a, b) -> float:
    return max(abs(x - y) for x, y in zip(a, b))


def _golden_documents() -> dict[str, str]:
    """
    The expected texts of the Phase 12.3 golden-document tests.

    Read from the test source without importing or modifying it: each golden
    test asserts `_text(...) == <expected>`, and <expected> is a constant
    string expression.
    """
    with open(_PHASE_12_3_TESTS, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    golden_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "TestGoldenDocuments"
    )
    documents: dict[str, str] = {}
    for function in golden_class.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare):
                expression = ast.Expression(node.test.comparators[0])
                ast.fix_missing_locations(expression)
                documents[function.name] = eval(  # constant string expression
                    compile(expression, "<golden>", "eval"), {"__builtins__": {}}, {}
                )
    return documents


_INV_ID = "a" * 64


def _oversized_document(tail_tag: str) -> str:
    """A Phase 12.3 document whose evidence lines are long enough to exceed the limit."""

    def row(rank: int, tag: str) -> EvidenceRow:
        return EvidenceRow(
            investigation_id=_INV_ID,
            rank_position=rank,
            evidence_type="mixed",
            evidence_score=0.9,
            span_name=f"{tag}.payment.authorization.gateway.retry.handler.execute.step",
            service_name=f"{tag}-checkout-orchestration-service-primary-region",
            status_code="ERROR",
            error_type=f"{tag}UpstreamGatewayTimeoutExecutionError",
            tool_name=f"{tag}_external_payment_provider_lookup_tool",
            tool_status="failed_after_retries",
            agent_name=f"{tag}_payment_reconciliation_agent",
            agent_operation="authorize_and_capture_payment",
            retrieval_result_count=0,
            retrieval_top_relevance_score=0.1,
            is_direct_subject=True,
            is_root_span=True,
            trace_duration_fraction=0.9,
        )

    investigation = InvestigationRow(
        investigation_id=_INV_ID,
        anomaly_type="tool_failure",
        service_name="checkout-orchestration-service",
        operation_name="tool.execute/UpstreamGatewayTimeoutExecutionError",
        confidence="HIGH",
    )
    rows = [row(1, "alpha"), row(2, "bravo"), row(3, "charlie"), row(4, "delta"), row(5, tail_tag)]
    document = build_incident_document(investigation, rows, derived_signal="tool_failure")
    assert document.eligible is True and document.text is not None
    return document.text


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _no_network():
    """Block every socket connection while this module runs."""
    attempts: list[str] = []

    def blocked(name):
        def _raise(*args, **kwargs):
            attempts.append(name)
            raise OSError(f"network access blocked in model tests ({name})")
        return _raise

    saved = {
        "connect": socket.socket.connect,
        "connect_ex": socket.socket.connect_ex,
        "create_connection": socket.create_connection,
        "getaddrinfo": socket.getaddrinfo,
    }
    socket.socket.connect = blocked("socket.connect")
    socket.socket.connect_ex = blocked("socket.connect_ex")
    socket.create_connection = blocked("create_connection")
    socket.getaddrinfo = blocked("getaddrinfo")
    try:
        yield attempts
    finally:
        socket.socket.connect = saved["connect"]
        socket.socket.connect_ex = saved["connect_ex"]
        socket.create_connection = saved["create_connection"]
        socket.getaddrinfo = saved["getaddrinfo"]


@pytest.fixture(scope="module")
def provider() -> EmbeddingProvider:
    return create_default_provider()


@pytest.fixture(scope="module")
def backend(provider) -> SentenceTransformerBackend:
    return provider.backend


@pytest.fixture(scope="module")
def golden() -> dict[str, str]:
    documents = _golden_documents()
    assert set(documents) == set(_GOLDEN_TOKENS_WITH_SPECIAL)
    return documents


@pytest.fixture(scope="module")
def representative(golden) -> str:
    return golden["test_tool_failure_modelled_on_live_investigation"]


# ---------------------------------------------------------------------------
# I01  Offline load
# ---------------------------------------------------------------------------

class TestOfflineLoad:

    def test_provider_is_not_loaded_until_used(self):
        assert create_default_provider().backend.is_loaded is False

    def test_locked_revision_loads_offline(self, backend, _no_network):
        backend.load()
        assert backend.is_loaded is True
        assert backend.model_name == MODEL_NAME
        assert backend.revision == MODEL_REVISION
        assert backend.local_files_only is True
        assert _no_network == []

    def test_load_puts_the_library_in_offline_mode(self, backend):
        import huggingface_hub.constants

        backend.load()
        assert os.environ["HF_HUB_OFFLINE"] == "1"
        assert huggingface_hub.constants.HF_HUB_OFFLINE is True

    def test_identity_is_the_locked_identity(self, provider):
        assert provider.identity == EmbeddingModelIdentity(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            dimension=384,
        )


# ---------------------------------------------------------------------------
# I02  Dimension and sequence limit
# ---------------------------------------------------------------------------

class TestModelShape:

    def test_dimension_is_384(self, backend):
        assert len(backend("dimension probe")) == EMBEDDING_DIMENSION == 384

    def test_max_seq_length_is_256(self, backend):
        assert backend.token_usage("limit probe").token_limit == MODEL_MAX_SEQUENCE_LENGTH == 256

    def test_raw_backend_output_is_plain_floats(self, backend):
        raw = backend("type probe")
        assert type(raw) is list
        assert all(type(x) is float for x in raw)


# ---------------------------------------------------------------------------
# I03  Representative document
# ---------------------------------------------------------------------------

class TestRepresentativeDocument:

    def test_embeds_to_384_finite_values(self, provider, representative):
        vector = provider.embed(representative)
        assert type(vector) is tuple
        assert len(vector) == 384
        assert all(type(x) is float for x in vector)
        assert all(math.isfinite(x) for x in vector)

    def test_provider_output_has_unit_norm(self, provider, representative):
        assert abs(_norm(provider.embed(representative)) - 1.0) <= _UNIT_NORM_TOLERANCE

    def test_native_model_output_is_already_close_to_unit_norm(self, backend, representative):
        assert abs(_norm(backend(representative)) - 1.0) <= 1e-5

    def test_provider_preserves_the_model_direction(self, provider, backend, representative):
        assert _cosine(provider.embed(representative), backend(representative)) >= 1.0 - 1e-12

    def test_vector_is_not_degenerate(self, provider, representative):
        vector = provider.embed(representative)
        assert len({round(x, 6) for x in vector}) > 300

    def test_every_golden_document_embeds(self, provider, golden):
        for name, text in golden.items():
            vector = provider.embed(text)
            assert len(vector) == 384, name
            assert abs(_norm(vector) - 1.0) <= _UNIT_NORM_TOLERANCE, name

    def test_different_documents_give_different_vectors(self, provider, golden):
        a = provider.embed(golden["test_trace_latency"])
        b = provider.embed(golden["test_retrieval_quality"])
        assert _cosine(a, b) < 0.99

    def test_similar_documents_are_closer_than_dissimilar_ones(self, provider, golden):
        """Both latency documents vs a latency and a retrieval-quality document."""
        latency = provider.embed(golden["test_trace_latency"])
        latency_none = provider.embed(golden["test_zero_informative_evidence"])
        retrieval = provider.embed(golden["test_retrieval_quality"])
        assert _cosine(latency, latency_none) > _cosine(latency, retrieval)


# ---------------------------------------------------------------------------
# I04  Repeatability
# ---------------------------------------------------------------------------

class TestRepeatability:

    def test_same_text_twice_is_stable(self, provider, representative):
        first = provider.embed(representative)
        second = provider.embed(representative)
        assert _max_abs_diff(first, second) <= _REPEAT_MAX_ABS_DIFF
        assert _cosine(first, second) >= _REPEAT_MIN_COSINE

    def test_stable_across_backend_instances(self, provider, representative):
        other = create_default_provider()
        first = provider.embed(representative)
        second = other.embed(representative)
        assert _max_abs_diff(first, second) <= _REPEAT_MAX_ABS_DIFF
        assert _cosine(first, second) >= _REPEAT_MIN_COSINE

    def test_stable_after_embedding_other_texts(self, provider, representative, golden):
        first = provider.embed(representative)
        for text in golden.values():
            provider.embed(text)
        second = provider.embed(representative)
        assert _max_abs_diff(first, second) <= _REPEAT_MAX_ABS_DIFF


# ---------------------------------------------------------------------------
# I05  Emoji / non-BMP
# ---------------------------------------------------------------------------

class TestNonBmpInput:

    def test_emoji_and_non_bmp_text_embeds(self, provider, representative):
        text = representative.replace(
            'span "tool.execute"', 'span "deploy \U0001F680 \U00020000 \U0001F600"',
        )
        assert text != representative
        vector = provider.embed(text)
        assert len(vector) == 384
        assert all(math.isfinite(x) for x in vector)
        assert abs(_norm(vector) - 1.0) <= _UNIT_NORM_TOLERANCE

    def test_emoji_only_text_embeds(self, provider):
        vector = provider.embed("\U0001F680\U0001F600")
        assert len(vector) == 384
        assert all(math.isfinite(x) for x in vector)

    def test_token_usage_works_for_non_bmp_text(self, backend):
        usage = backend.token_usage("deploy \U0001F680 \U00020000")
        assert usage.tokens_without_special >= 1
        assert usage.truncated is False


# ---------------------------------------------------------------------------
# I06  Golden document token counts
# ---------------------------------------------------------------------------

class TestGoldenTokenCounts:

    @pytest.mark.parametrize("name", sorted(_GOLDEN_TOKENS_WITH_SPECIAL))
    def test_token_counts_can_be_inspected(self, backend, golden, name):
        usage = backend.token_usage(golden[name])
        assert isinstance(usage, TokenUsage)
        assert usage.token_limit == 256
        assert usage.tokens_with_special == usage.tokens_without_special + 2

    @pytest.mark.parametrize("name, expected", sorted(_GOLDEN_TOKENS_WITH_SPECIAL.items()))
    def test_measured_token_counts(self, backend, golden, name, expected):
        assert backend.token_usage(golden[name]).tokens_with_special == expected

    @pytest.mark.parametrize("name", sorted(_GOLDEN_TOKENS_WITH_SPECIAL))
    def test_golden_documents_are_not_truncated(self, backend, golden, name):
        assert backend.token_usage(golden[name]).truncated is False

    def test_token_usage_is_deterministic(self, backend, representative):
        assert backend.token_usage(representative) == backend.token_usage(representative)

    def test_tokenizer_is_case_insensitive(self, backend, representative):
        """The locked model is uncased; Phase 12.3 text is passed through unchanged."""
        assert backend.token_usage(representative) == backend.token_usage(representative.lower())


# ---------------------------------------------------------------------------
# I07  Oversized document
# ---------------------------------------------------------------------------

class TestOversizedDocument:

    def test_reports_truncation(self, backend):
        usage = backend.token_usage(_oversized_document("zulutailmarker"))
        assert usage.tokens_with_special > 256
        assert usage.token_limit == 256
        assert usage.truncated is True

    def test_still_embeds_without_error(self, provider):
        vector = provider.embed(_oversized_document("zulutailmarker"))
        assert len(vector) == 384
        assert all(math.isfinite(x) for x in vector)
        assert abs(_norm(vector) - 1.0) <= _UNIT_NORM_TOLERANCE

    def test_truncation_is_deterministic(self, provider):
        text = _oversized_document("zulutailmarker")
        assert _max_abs_diff(provider.embed(text), provider.embed(text)) <= _REPEAT_MAX_ABS_DIFF

    def test_truncated_tail_does_not_affect_the_embedding(self, provider):
        """Two documents that differ only beyond the limit embed the same."""
        a = provider.embed(_oversized_document("zulutailmarker"))
        b = provider.embed(_oversized_document("yankeetailmarker"))
        assert _max_abs_diff(a, b) <= _REPEAT_MAX_ABS_DIFF

    def test_header_still_affects_the_embedding(self, provider):
        text = _oversized_document("zulutailmarker")
        changed = text.replace("anomaly: tool_failure", "anomaly: latency", 1)
        assert changed != text
        assert _cosine(provider.embed(text), provider.embed(changed)) < 0.9999

    def test_limit_is_not_changed_by_oversized_input(self, backend):
        backend(_oversized_document("zulutailmarker"))
        assert backend.token_usage("probe").token_limit == 256


# ---------------------------------------------------------------------------
# I08  Missing revision
# ---------------------------------------------------------------------------

class TestMissingRevision:

    def test_unknown_revision_fails_locally(self, _no_network):
        before = len(_no_network)
        missing = SentenceTransformerBackend(revision="0" * 40)
        with pytest.raises(RuntimeError) as excinfo:
            missing.load()
        message = str(excinfo.value)
        assert MODEL_NAME in message
        assert "0" * 40 in message
        assert "local_files_only=True" in message
        assert missing.is_loaded is False
        assert len(_no_network) == before

    def test_no_network_attempts_in_this_module(self, _no_network):
        assert _no_network == []

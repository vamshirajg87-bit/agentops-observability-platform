"""
incident-retrieval/tests/unit/test_embedding_provider.py

Unit tests for embedding_provider.py.

All tests are pure Python — no model library, no network, no database, no I/O
beyond reading the module source for the import-boundary check.  Every
backend used here is a fake.

Test inventory:
    P01  EmbeddingModelIdentity and provider construction
    P02  Input validation; invalid input never reaches the backend
    P03  Exact text pass-through
    P04  Output dimension
    P05  Output element types and finiteness
    P06  L2 normalization and direction preservation
    P07  Zero and degenerate vectors
    P08  Return type and backend output immutability
    P09  Determinism
    P10  Purity / import boundary
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import math
import os

import pytest

import embedding_provider
from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DIM = 384

_MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "embedding_provider.py")
)


def _identity(dimension: int = _DIM) -> EmbeddingModelIdentity:
    return EmbeddingModelIdentity(
        model_name="fake/model",
        model_revision="fake-revision",
        dimension=dimension,
    )


class _RecordingBackend:
    """Fake backend that records every text and returns a fixed output."""

    def __init__(self, output) -> None:
        self.output = output
        self.calls: list[str] = []

    def __call__(self, text: str):
        self.calls.append(text)
        return self.output


def _unit_vector(dimension: int = _DIM) -> list[float]:
    """A unit vector with every element non-zero."""
    value = 1.0 / math.sqrt(dimension)
    return [value] * dimension


def _ramp(dimension: int = _DIM) -> list[float]:
    """A non-unit vector with distinct, signed elements."""
    return [(i - dimension / 2.0) * 0.37 + 0.11 for i in range(dimension)]


def _provider(output, dimension: int = _DIM) -> tuple[EmbeddingProvider, _RecordingBackend]:
    backend = _RecordingBackend(output)
    return EmbeddingProvider(_identity(dimension), backend), backend


def _embed(output, dimension: int = _DIM, text: str = "some text"):
    provider, _ = _provider(output, dimension)
    return provider.embed(text)


def _norm(vector) -> float:
    return math.sqrt(math.fsum(x * x for x in vector))


def _cosine(a, b) -> float:
    return math.fsum(x * y for x, y in zip(a, b)) / (_norm(a) * _norm(b))


def _hash_backend(dimension: int = _DIM):
    """Deterministic fake: the vector depends only on the text."""

    def backend(text: str) -> list[float]:
        values = []
        counter = 0
        while len(values) < dimension:
            digest = hashlib.sha256(f"{counter}|{text}".encode("utf-8")).digest()
            values.extend((byte - 127.5) / 127.5 for byte in digest)
            counter += 1
        return values[:dimension]

    return backend


# ---------------------------------------------------------------------------
# P01  Identity and construction
# ---------------------------------------------------------------------------

class TestIdentity:

    def test_identity_is_frozen_dataclass(self):
        assert dataclasses.is_dataclass(EmbeddingModelIdentity)
        assert EmbeddingModelIdentity.__dataclass_params__.frozen is True

    def test_identity_is_immutable(self):
        identity = _identity()
        with pytest.raises(dataclasses.FrozenInstanceError):
            identity.model_revision = "other"  # type: ignore[misc]

    def test_identity_fields_exact(self):
        assert [f.name for f in dataclasses.fields(EmbeddingModelIdentity)] == [
            "model_name",
            "model_revision",
            "dimension",
        ]

    def test_identity_equality_by_value(self):
        assert _identity() == _identity()
        assert _identity(3) != _identity(4)

    def test_provider_exposes_identity_unchanged(self):
        identity = _identity()
        provider = EmbeddingProvider(identity, _RecordingBackend(_unit_vector()))
        assert provider.identity is identity
        assert provider.identity == EmbeddingModelIdentity("fake/model", "fake-revision", _DIM)

    def test_provider_exposes_backend(self):
        backend = _RecordingBackend(_unit_vector())
        assert EmbeddingProvider(_identity(), backend).backend is backend

    def test_identity_property_is_read_only(self):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(AttributeError):
            provider.identity = _identity(3)  # type: ignore[misc]

    def test_construction_does_not_call_backend(self):
        backend = _RecordingBackend(_unit_vector())
        EmbeddingProvider(_identity(), backend)
        assert backend.calls == []

    @pytest.mark.parametrize(
        "identity",
        [None, "fake/model", ("fake/model", "rev", 384), {"model_name": "x"}],
        ids=["none", "str", "tuple", "dict"],
    )
    def test_non_identity_raises(self, identity):
        with pytest.raises(ValueError, match="identity"):
            EmbeddingProvider(identity, _RecordingBackend(_unit_vector()))

    @pytest.mark.parametrize("field", ["model_name", "model_revision"])
    @pytest.mark.parametrize("value", ["", "   ", None, 123], ids=["empty", "blank", "none", "int"])
    def test_identity_text_fields_must_be_non_empty_str(self, field, value):
        kwargs = {"model_name": "m", "model_revision": "r", "dimension": 3}
        kwargs[field] = value
        with pytest.raises(ValueError, match=field):
            EmbeddingProvider(EmbeddingModelIdentity(**kwargs), _RecordingBackend([1.0, 0.0, 0.0]))

    @pytest.mark.parametrize(
        "dimension", [0, -1, True, 384.0, "384", None],
        ids=["zero", "negative", "bool", "float", "str", "none"],
    )
    def test_identity_dimension_must_be_positive_int(self, dimension):
        identity = EmbeddingModelIdentity("m", "r", dimension)
        with pytest.raises(ValueError, match="dimension"):
            EmbeddingProvider(identity, _RecordingBackend([1.0]))

    @pytest.mark.parametrize("backend", [None, "backend", 42, [1.0]], ids=["none", "str", "int", "list"])
    def test_backend_must_be_callable(self, backend):
        with pytest.raises(ValueError, match="backend"):
            EmbeddingProvider(_identity(), backend)

    def test_plain_function_backend_is_accepted(self):
        provider = EmbeddingProvider(_identity(3), lambda text: [3.0, 0.0, 4.0])
        assert provider.embed("x") == (0.6, 0.0, 0.8)


# ---------------------------------------------------------------------------
# P02  Input validation
# ---------------------------------------------------------------------------

_NON_STR = [None, 123, 1.5, True, b"text", ["text"], ("text",), {"text": 1}, object()]
_NON_STR_IDS = ["none", "int", "float", "bool", "bytes", "list", "tuple", "dict", "object"]

_BLANK = ["", " ", "   ", "\t", "\n", "\r\n", " \t\n ", " ", " 　"]
_BLANK_IDS = ["empty", "space", "spaces", "tab", "lf", "crlf", "mixed", "nbsp", "wide"]

_HIGH = "\ud83d"
_LOW = "\ude00"
_SURROGATES = [_HIGH, _LOW, "abc" + _HIGH, _LOW + "abc", "a" + _HIGH + "b", _LOW + _HIGH]
_SURROGATE_IDS = ["lone-high", "lone-low", "trailing-high", "leading-low", "inner-high", "reversed-pair"]


class TestInputValidation:

    @pytest.mark.parametrize("text", _NON_STR, ids=_NON_STR_IDS)
    def test_non_str_raises(self, text):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError, match="text"):
            provider.embed(text)

    def test_empty_raises(self):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError, match="empty"):
            provider.embed("")

    @pytest.mark.parametrize("text", _BLANK[1:], ids=_BLANK_IDS[1:])
    def test_whitespace_only_raises(self, text):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError, match="whitespace"):
            provider.embed(text)

    def test_lone_high_surrogate_raises(self):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError, match="surrogate"):
            provider.embed("doc " + _HIGH)

    def test_lone_low_surrogate_raises(self):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError, match="surrogate"):
            provider.embed("doc " + _LOW)

    @pytest.mark.parametrize("text", _SURROGATES, ids=_SURROGATE_IDS)
    def test_every_surrogate_shape_raises(self, text):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError, match="surrogate"):
            provider.embed(text)

    def test_surrogate_error_is_plain_value_error(self):
        provider, _ = _provider(_unit_vector())
        with pytest.raises(ValueError) as excinfo:
            provider.embed(_HIGH)
        assert type(excinfo.value) is ValueError

    @pytest.mark.parametrize(
        "text",
        _NON_STR + _BLANK + _SURROGATES,
        ids=_NON_STR_IDS + _BLANK_IDS + _SURROGATE_IDS,
    )
    def test_invalid_input_never_calls_backend(self, text):
        provider, backend = _provider(_unit_vector())
        with pytest.raises(ValueError):
            provider.embed(text)
        assert backend.calls == []

    def test_str_subclass_is_accepted(self):
        class Text(str):
            pass

        provider, backend = _provider(_unit_vector())
        provider.embed(Text("hello"))
        assert backend.calls == ["hello"]


# ---------------------------------------------------------------------------
# P03  Exact text pass-through
# ---------------------------------------------------------------------------

_INCIDENT_TEXT = (
    "anomaly: tool_failure\n"
    "signal: tool_failure\n"
    "service: agentops-demo-app\n"
    "operation: tool.execute/ToolExecutionError\n"
    "evidence:\n"
    '  span "tool.execute" service "agentops-demo-app" status ERROR direct-subject '
    'error-type "ToolExecutionError" evidence-type mixed'
)


class TestTextPassThrough:

    @pytest.mark.parametrize(
        "text",
        [
            "plain",
            _INCIDENT_TEXT,
            "  leading spaces",
            "trailing spaces   ",
            "\tleading tab and trailing newline\n",
            "\n\nblank lines around\n\n",
            "inner   runs\tof \n whitespace",
            "MiXeD CaSe ERROR",
            "café decomposed",          # not NFC; must not be composed
            "café composed",
            "deploy \U0001F680 rocket",       # non-BMP emoji
            "\U00020000 cjk extension b",
            'quotes " and \\ backslashes',
            "x" * 10_000,
        ],
        ids=[
            "plain", "incident-document", "leading-spaces", "trailing-spaces",
            "tab-newline", "blank-lines", "inner-whitespace", "mixed-case",
            "decomposed", "composed", "emoji", "cjk-ext-b", "quotes", "long",
        ],
    )
    def test_backend_receives_exact_text(self, text):
        provider, backend = _provider(_unit_vector())
        provider.embed(text)
        assert backend.calls == [text]
        assert backend.calls[0].encode("utf-8") == text.encode("utf-8")

    def test_leading_and_trailing_spaces_preserved(self):
        provider, backend = _provider(_unit_vector())
        provider.embed("  padded  ")
        assert backend.calls == ["  padded  "]

    def test_text_is_not_nfc_normalized(self):
        provider, backend = _provider(_unit_vector())
        provider.embed("é")
        assert backend.calls == ["é"]
        assert backend.calls != ["é"]

    def test_text_is_not_lowercased(self):
        provider, backend = _provider(_unit_vector())
        provider.embed("ERROR ToolExecutionError")
        assert backend.calls == ["ERROR ToolExecutionError"]

    def test_text_is_not_truncated(self):
        text = "word " * 5000
        provider, backend = _provider(_unit_vector())
        provider.embed(text)
        assert len(backend.calls[0]) == len(text)

    def test_valid_emoji_and_non_bmp_accepted(self):
        result = _embed(_unit_vector(), text="\U0001F680\U0001F600\U00020000")
        assert len(result) == _DIM

    def test_backend_called_exactly_once_per_embed(self):
        provider, backend = _provider(_unit_vector())
        provider.embed("a")
        provider.embed("b")
        assert backend.calls == ["a", "b"]

    def test_backend_exception_propagates(self):
        def failing(text: str):
            raise RuntimeError("model unavailable")

        provider = EmbeddingProvider(_identity(), failing)
        with pytest.raises(RuntimeError, match="model unavailable"):
            provider.embed("text")


# ---------------------------------------------------------------------------
# P04  Output dimension
# ---------------------------------------------------------------------------

class TestOutputDimension:

    @pytest.mark.parametrize("length", [0, 1, 383, 385, 768])
    def test_wrong_dimension_raises(self, length):
        with pytest.raises(ValueError, match="384 elements"):
            _embed([0.5] * length)

    def test_exact_dimension_passes(self):
        assert len(_embed([0.5] * 384)) == 384

    @pytest.mark.parametrize("dimension", [1, 3, 8, 384, 1024])
    def test_dimension_comes_from_identity(self, dimension):
        assert len(_embed([1.0] * dimension, dimension)) == dimension
        with pytest.raises(ValueError, match=f"{dimension} elements"):
            _embed([1.0] * (dimension + 1), dimension)

    @pytest.mark.parametrize(
        "output", [None, 1.5, 7, object()], ids=["none", "float", "int", "object"],
    )
    def test_non_sequence_output_raises(self, output):
        with pytest.raises(ValueError, match="backend output"):
            _embed(output)

    def test_nested_output_raises(self):
        with pytest.raises(ValueError, match="backend output"):
            _embed([[0.5] * 384])

    def test_generator_output_is_accepted(self):
        result = _embed((x for x in [3.0, 0.0, 4.0]), 3)
        assert result == (0.6, 0.0, 0.8)


# ---------------------------------------------------------------------------
# P05  Output element types and finiteness
# ---------------------------------------------------------------------------

def _with(index: int, value, dimension: int = _DIM) -> list:
    values: list = _unit_vector(dimension)
    values[index] = value
    return values


class TestOutputValues:

    @pytest.mark.parametrize("value", [True, False])
    @pytest.mark.parametrize("index", [0, 191, 383])
    def test_bool_element_raises(self, value, index):
        with pytest.raises(ValueError, match=f"element {index}"):
            _embed(_with(index, value))

    @pytest.mark.parametrize("value", ["0.5", "", "nan"], ids=["numeric-str", "empty-str", "nan-str"])
    def test_str_element_raises(self, value):
        with pytest.raises(ValueError, match="real number"):
            _embed(_with(5, value))

    def test_none_element_raises(self):
        with pytest.raises(ValueError, match="real number"):
            _embed(_with(5, None))

    @pytest.mark.parametrize(
        "value", [b"1", [0.5], (0.5,), 1 + 0j, object()],
        ids=["bytes", "list", "tuple", "complex", "object"],
    )
    def test_other_non_numeric_element_raises(self, value):
        with pytest.raises(ValueError, match="real number"):
            _embed(_with(5, value))

    def test_nan_element_raises(self):
        with pytest.raises(ValueError, match="not finite"):
            _embed(_with(7, float("nan")))

    def test_positive_infinity_element_raises(self):
        with pytest.raises(ValueError, match="not finite"):
            _embed(_with(7, float("inf")))

    def test_negative_infinity_element_raises(self):
        with pytest.raises(ValueError, match="not finite"):
            _embed(_with(7, float("-inf")))

    def test_huge_int_element_raises(self):
        """An int too large for a float is not a finite float."""
        with pytest.raises(ValueError, match="not finite"):
            _embed(_with(7, 10 ** 400))

    def test_all_bool_vector_raises(self):
        with pytest.raises(ValueError, match="real number"):
            _embed([True] * 384)

    def test_string_output_raises(self):
        """A 384-character string has the right length but no numeric elements."""
        with pytest.raises(ValueError, match="real number"):
            _embed("x" * 384)

    def test_int_elements_are_accepted(self):
        assert _embed([3, 0, 4], 3) == (0.6, 0.0, 0.8)

    def test_mixed_int_and_float_elements_are_accepted(self):
        assert _embed([3, 0.0, 4.0], 3) == (0.6, 0.0, 0.8)

    def test_negative_elements_are_accepted(self):
        assert _embed([-3.0, 0.0, 4.0], 3) == (-0.6, 0.0, 0.8)

    def test_float_subclass_is_accepted(self):
        class Scalar(float):
            pass

        result = _embed([Scalar(3.0), Scalar(0.0), Scalar(4.0)], 3)
        assert result == (0.6, 0.0, 0.8)
        assert all(type(x) is float for x in result)

    def test_error_reports_first_bad_index(self):
        values = _unit_vector()
        values[10] = float("nan")
        values[20] = None
        with pytest.raises(ValueError, match="element 10 "):
            _embed(values)


# ---------------------------------------------------------------------------
# P06  L2 normalization
# ---------------------------------------------------------------------------

class TestNormalization:

    def test_non_unit_vector_is_normalized(self):
        result = _embed(_ramp())
        assert _norm(_ramp()) > 10.0
        assert math.isclose(_norm(result), 1.0, rel_tol=0.0, abs_tol=1e-12)

    def test_simple_3_4_5(self):
        assert _embed([3.0, 0.0, 4.0], 3) == (0.6, 0.0, 0.8)

    def test_direction_preserved(self):
        raw = _ramp()
        result = _embed(raw)
        assert math.isclose(_cosine(raw, result), 1.0, rel_tol=0.0, abs_tol=1e-12)

    def test_elements_are_raw_divided_by_norm(self):
        raw = _ramp()
        norm = math.hypot(*raw)
        assert _embed(raw) == tuple(x / norm for x in raw)

    def test_signs_and_zeros_preserved(self):
        raw = [0.0] * 384
        raw[0], raw[1], raw[2] = -2.0, 0.0, 2.0
        result = _embed(raw)
        assert result[0] < 0.0 and result[1] == 0.0 and result[2] > 0.0
        assert all(x == 0.0 for x in result[3:])

    def test_already_unit_vector_is_valid_and_stays_unit(self):
        raw = _unit_vector()
        result = _embed(raw)
        assert math.isclose(_norm(result), 1.0, rel_tol=0.0, abs_tol=1e-12)
        assert max(abs(a - b) for a, b in zip(raw, result)) < 1e-15

    def test_basis_vector_is_unchanged(self):
        raw = [0.0] * 384
        raw[17] = 1.0
        assert _embed(raw) == tuple(raw)

    @pytest.mark.parametrize("scale", [1e-30, 1e-3, 0.5, 2.0, 37.5, 1e6, 1e30, -1.0])
    def test_scaling_the_backend_output_does_not_change_the_result(self, scale):
        base = _embed(_ramp())
        scaled = _embed([x * abs(scale) for x in _ramp()])
        assert max(abs(a - b) for a, b in zip(base, scaled)) < 1e-12

    def test_negative_scaling_flips_direction(self):
        base = _embed(_ramp())
        flipped = _embed([-x for x in _ramp()])
        assert flipped == tuple(-x for x in base)

    def test_normalization_is_idempotent_within_rounding(self):
        once = _embed(_ramp())
        twice = _embed(list(once))
        assert max(abs(a - b) for a, b in zip(once, twice)) < 1e-15

    def test_large_components_do_not_overflow(self):
        """1e200 squared overflows a float; the norm must still be computed."""
        result = _embed([1e200, 0.0, 1e200], 3)
        assert math.isclose(result[0], 1.0 / math.sqrt(2.0), rel_tol=1e-12)
        assert math.isclose(_norm(result), 1.0, rel_tol=0.0, abs_tol=1e-12)

    def test_tiny_components_do_not_underflow_to_zero(self):
        """1e-200 squared underflows to 0; the vector is still normalizable."""
        result = _embed([1e-200, 0.0, 1e-200], 3)
        assert math.isclose(result[0], 1.0 / math.sqrt(2.0), rel_tol=1e-12)
        assert math.isclose(_norm(result), 1.0, rel_tol=0.0, abs_tol=1e-12)

    def test_subnormal_nonzero_vector_is_normalized(self):
        result = _embed([5e-324, 0.0, 0.0], 3)
        assert result == (1.0, 0.0, 0.0)

    def test_every_output_element_is_finite(self):
        assert all(math.isfinite(x) for x in _embed(_ramp()))

    def test_output_elements_within_unit_interval(self):
        assert all(-1.0 <= x <= 1.0 for x in _embed(_ramp()))


# ---------------------------------------------------------------------------
# P07  Zero and degenerate vectors
# ---------------------------------------------------------------------------

class TestDegenerateVectors:

    def test_384_zeros_raises(self):
        with pytest.raises(ValueError, match="zero norm"):
            _embed([0.0] * 384)

    def test_384_integer_zeros_raises(self):
        with pytest.raises(ValueError, match="zero norm"):
            _embed([0] * 384)

    def test_negative_zeros_raises(self):
        with pytest.raises(ValueError, match="zero norm"):
            _embed([-0.0] * 384)

    def test_zero_vector_is_never_returned(self):
        provider, _ = _provider([0.0] * 384)
        result = None
        with pytest.raises(ValueError):
            result = provider.embed("text")
        assert result is None

    def test_non_finite_norm_raises(self):
        """Every element is finite, but the norm overflows to infinity."""
        with pytest.raises(ValueError, match="non-finite norm"):
            _embed([1e308] * 384)

    def test_single_max_float_is_still_normalizable(self):
        raw = [0.0] * 384
        raw[0] = 1.7976931348623157e308
        assert _embed(raw)[0] == 1.0

    @pytest.mark.parametrize("dimension", [1, 3, 384])
    def test_zero_vector_rejected_for_any_dimension(self, dimension):
        with pytest.raises(ValueError, match="zero norm"):
            _embed([0.0] * dimension, dimension)


# ---------------------------------------------------------------------------
# P08  Return type and immutability
# ---------------------------------------------------------------------------

class _ArrayLike:
    """Sequence-like object that is neither list nor tuple."""

    def __init__(self, values):
        self._values = list(values)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


class TestReturnType:

    @pytest.mark.parametrize(
        "make",
        [list, tuple, _ArrayLike, lambda v: (x for x in v)],
        ids=["list", "tuple", "array-like", "generator"],
    )
    def test_output_is_tuple_for_any_backend_container(self, make):
        result = _embed(make(_ramp()))
        assert type(result) is tuple
        assert len(result) == 384

    def test_elements_are_plain_python_floats(self):
        assert all(type(x) is float for x in _embed(_ramp()))

    def test_int_input_elements_become_floats(self):
        assert all(type(x) is float for x in _embed([3, 0, 4], 3))

    def test_backend_list_output_is_not_mutated(self):
        raw = _ramp()
        snapshot = list(raw)
        provider, _ = _provider(raw)
        provider.embed("text")
        assert raw == snapshot

    def test_result_is_a_new_object(self):
        raw = tuple(_unit_vector())
        provider, _ = _provider(raw)
        assert provider.embed("text") is not raw

    def test_repeated_calls_do_not_accumulate_changes(self):
        raw = _ramp()
        provider, _ = _provider(raw)
        first = provider.embed("text")
        second = provider.embed("text")
        assert first == second
        assert raw == _ramp()

    def test_result_is_hashable(self):
        assert isinstance(hash(_embed(_ramp())), int)


# ---------------------------------------------------------------------------
# P09  Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_same_text_gives_identical_result(self):
        provider = EmbeddingProvider(_identity(), _hash_backend())
        assert provider.embed(_INCIDENT_TEXT) == provider.embed(_INCIDENT_TEXT)

    def test_identical_across_provider_instances(self):
        a = EmbeddingProvider(_identity(), _hash_backend())
        b = EmbeddingProvider(_identity(), _hash_backend())
        assert a.embed(_INCIDENT_TEXT) == b.embed(_INCIDENT_TEXT)

    def test_repeated_calls_are_stable(self):
        provider = EmbeddingProvider(_identity(), _hash_backend())
        results = {provider.embed(_INCIDENT_TEXT) for _ in range(20)}
        assert len(results) == 1

    def test_different_text_gives_different_result(self):
        provider = EmbeddingProvider(_identity(), _hash_backend())
        assert provider.embed("alpha") != provider.embed("beta")

    def test_whitespace_differences_are_visible_to_the_backend(self):
        """The provider does not normalize, so padded text is a different input."""
        provider = EmbeddingProvider(_identity(), _hash_backend())
        assert provider.embed("alpha") != provider.embed(" alpha")

    def test_every_result_is_unit_length(self):
        provider = EmbeddingProvider(_identity(), _hash_backend())
        for text in ("a", "b", _INCIDENT_TEXT, "\U0001F680"):
            assert math.isclose(_norm(provider.embed(text)), 1.0, rel_tol=0.0, abs_tol=1e-12)


# ---------------------------------------------------------------------------
# P10  Purity / import boundary
# ---------------------------------------------------------------------------

_ALLOWED_IMPORTS = {"__future__", "dataclasses", "math", "typing"}


@pytest.fixture(scope="module")
def module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            modules.add((node.module or "").split(".")[0])
    return modules


class TestPurityBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(embedding_provider.__file__) == _MODULE_PATH

    def test_imports_are_standard_library_allowlist_only(self, module_tree):
        assert _imported_modules(module_tree) <= _ALLOWED_IMPORTS

    @pytest.mark.parametrize(
        "forbidden",
        [
            "sentence_transformers", "transformers", "torch", "tokenizers",
            "huggingface_hub", "numpy", "scipy", "sklearn",
            "incident_document", "sentence_transformer_backend",
            "psycopg", "psycopg2", "pgvector", "sqlalchemy",
            "rca_models", "rca_confidence", "rca_ranker", "rca_persist",
            "os", "sys", "io", "pathlib", "socket", "subprocess", "urllib",
            "requests", "httpx", "logging",
        ],
    )
    def test_forbidden_module_not_imported(self, module_tree, forbidden):
        assert forbidden not in _imported_modules(module_tree)

    def test_no_io_or_dynamic_import_calls(self, module_tree):
        forbidden_calls = {"open", "print", "input", "exec", "eval", "__import__", "compile"}
        called = {
            node.func.id
            for node in ast.walk(module_tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert called.isdisjoint(forbidden_calls)

    def test_source_does_not_mention_incident_document_types(self, module_tree):
        names = {node.id for node in ast.walk(module_tree) if isinstance(node, ast.Name)}
        assert names.isdisjoint({"IncidentDocument", "InvestigationRow", "EvidenceRow", "DOC_VERSION"})

    def test_public_names(self):
        defined_here = {
            name for name, value in vars(embedding_provider).items()
            if not name.startswith("_")
            and getattr(value, "__module__", None) == "embedding_provider"
        }
        assert defined_here == {"EmbeddingModelIdentity", "EmbeddingProvider"}
        assert hasattr(embedding_provider, "EmbeddingBackend")

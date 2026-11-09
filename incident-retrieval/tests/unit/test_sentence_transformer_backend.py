"""
incident-retrieval/tests/unit/test_sentence_transformer_backend.py

Unit tests for sentence_transformer_backend.py.

Every test uses fake model, factory, and tokenizer objects.  No real model is
loaded, no network is used, and no model library is required.

Test inventory:
    B01  Locked constants
    B02  Import boundary: importing the module loads no model library
    B03  Lazy loading and reuse
    B04  Load arguments: name, revision, local-only, device
    B05  Evaluation mode
    B06  Encoding: one text per call, plain Python floats
    B07  Token usage and truncation detection
    B08  Missing library / missing local model -> RuntimeError, no fallback
    B09  create_default_provider()
    B10  Offline enforcement: HF_HUB_OFFLINE set and verified on local-only load
"""

from __future__ import annotations

import ast
import dataclasses
import os
import subprocess
import sys

import pytest

import sentence_transformer_backend as stb
from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider
from sentence_transformer_backend import (
    EMBEDDING_DIMENSION,
    MODEL_MAX_SEQUENCE_LENGTH,
    MODEL_NAME,
    MODEL_REVISION,
    SentenceTransformerBackend,
    TokenUsage,
    create_default_provider,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_COMPONENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MODULE_PATH = os.path.join(_COMPONENT_DIR, "sentence_transformer_backend.py")

_ML_MODULES = (
    "sentence_transformers", "transformers", "torch", "tokenizers",
    "huggingface_hub", "numpy",
)


class FakeArray:
    """Stands in for a numpy array: exposes tolist() and is not a list."""

    def __init__(self, values) -> None:
        self._values = list(values)
        self.tolist_calls = 0

    def tolist(self):
        self.tolist_calls += 1
        return list(self._values)


class FakeScalar:
    """Stands in for a numpy scalar: convertible with float(), not a float."""

    def __init__(self, value: float) -> None:
        self._value = value

    def __float__(self) -> float:
        return self._value


class FakeTokenizer:
    """One token per whitespace-separated word; two special tokens."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, text, **kwargs):
        self.calls.append((text, kwargs))
        count = len(text.split())
        if kwargs.get("add_special_tokens", True):
            count += 2
        return {"input_ids": list(range(count))}


class FakeModel:
    def __init__(self, output=None, max_seq_length: int = 256) -> None:
        self.max_seq_length = max_seq_length
        self.tokenizer = FakeTokenizer()
        self.training = True
        self.eval_calls = 0
        self.encode_calls: list[tuple[tuple, dict]] = []
        self.output = output if output is not None else FakeArray([0.25] * 384)

    def eval(self):
        self.eval_calls += 1
        self.training = False
        return self

    def encode(self, *args, **kwargs):
        self.encode_calls.append((args, kwargs))
        return self.output

    def tokenize(self, *args, **kwargs):  # deprecated API; must never be used
        raise AssertionError("SentenceTransformer.tokenize must not be called")


class FakeFactory:
    def __init__(self, model=None, error: Exception | None = None) -> None:
        self.model = model if model is not None else FakeModel()
        self.error = error
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self.model


def _backend(model=None, **kwargs) -> tuple[SentenceTransformerBackend, FakeFactory]:
    factory = FakeFactory(model)
    return SentenceTransformerBackend(model_factory=factory, **kwargs), factory


def _words(n: int) -> str:
    return " ".join(["w"] * n)


@pytest.fixture(autouse=True)
def _isolated_offline_state(monkeypatch):
    """
    Start every test with HF_HUB_OFFLINE unset and huggingface-hub not
    imported, and restore both afterwards.  load() changes the environment,
    so without this one test would leak into the next.
    """
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    monkeypatch.delitem(sys.modules, "huggingface_hub.constants", raising=False)


# ---------------------------------------------------------------------------
# B01  Locked constants
# ---------------------------------------------------------------------------

class TestLockedConstants:

    def test_model_name(self):
        assert MODEL_NAME == "sentence-transformers/all-MiniLM-L6-v2"

    def test_model_revision(self):
        assert MODEL_REVISION == "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"

    def test_model_revision_is_full_commit_hash(self):
        assert len(MODEL_REVISION) == 40
        assert set(MODEL_REVISION) <= set("0123456789abcdef")

    def test_model_revision_is_not_a_branch_or_tag(self):
        assert MODEL_REVISION not in {"main", "master", "latest", ""}

    def test_embedding_dimension(self):
        assert EMBEDDING_DIMENSION == 384
        assert type(EMBEDDING_DIMENSION) is int

    def test_model_max_sequence_length(self):
        assert MODEL_MAX_SEQUENCE_LENGTH == 256
        assert type(MODEL_MAX_SEQUENCE_LENGTH) is int

    def test_max_sequence_length_is_not_the_architecture_limit(self):
        assert MODEL_MAX_SEQUENCE_LENGTH != 512

    def test_model_name_matches_phase_12_2_migration(self):
        migration = os.path.join(
            _COMPONENT_DIR, "..", "storage-consumer", "migrations",
            "010_create_rca_investigation_embeddings.sql",
        )
        with open(migration, encoding="utf-8") as fh:
            assert MODEL_NAME in fh.read()


# ---------------------------------------------------------------------------
# B02  Import boundary
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def module_tree() -> ast.Module:
    with open(_MODULE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _run_isolated(code: str) -> str:
    """Run code in a fresh interpreter with incident-retrieval/ importable."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_COMPONENT_DIR, env=env, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


_REPORT_LOADED = (
    "import sys; "
    f"print(sorted(m for m in {_ML_MODULES!r} if m in sys.modules))"
)


class TestImportBoundary:

    def test_tested_module_is_the_incident_retrieval_one(self):
        assert os.path.abspath(stb.__file__) == _MODULE_PATH

    def test_no_top_level_model_library_import(self, module_tree):
        top_level: set[str] = set()
        for node in module_tree.body:
            if isinstance(node, ast.Import):
                top_level.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                top_level.add((node.module or "").split(".")[0])
        assert top_level == {
            "__future__", "os", "sys", "dataclasses", "typing", "embedding_provider",
        }

    def test_model_library_imported_only_inside_default_factory(self, module_tree):
        locations = []
        for func in ast.walk(module_tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(func):
                if isinstance(node, ast.ImportFrom) and node.module == "sentence_transformers":
                    locations.append(func.name)
                if isinstance(node, ast.Import):
                    assert not any(a.name.split(".")[0] in _ML_MODULES for a in node.names)
        assert locations == ["_default_model_factory"]

    @pytest.mark.parametrize("forbidden", ["torch", "transformers", "tokenizers",
                                           "huggingface_hub", "numpy", "psycopg",
                                           "incident_document", "socket", "urllib",
                                           "requests", "httpx", "subprocess"])
    def test_forbidden_module_never_imported(self, module_tree, forbidden):
        imported: set[str] = set()
        for node in ast.walk(module_tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        assert forbidden not in imported

    def test_deprecated_tokenize_api_is_not_used(self, module_tree):
        attributes = {
            node.attr for node in ast.walk(module_tree) if isinstance(node, ast.Attribute)
        }
        assert "tokenize" not in attributes
        assert "tokenizer" in attributes

    def test_importing_module_loads_no_model_library(self):
        out = _run_isolated("import sentence_transformer_backend; " + _REPORT_LOADED)
        assert out == "[]"

    def test_constructing_backend_loads_no_model_library(self):
        out = _run_isolated(
            "import sentence_transformer_backend as s; b = s.SentenceTransformerBackend(); "
            "assert not b.is_loaded; " + _REPORT_LOADED
        )
        assert out == "[]"

    def test_create_default_provider_loads_no_model_library(self):
        out = _run_isolated(
            "import sentence_transformer_backend as s; p = s.create_default_provider(); "
            "assert not p.backend.is_loaded; " + _REPORT_LOADED
        )
        assert out == "[]"

    def test_import_construct_and_factory_leave_environment_unchanged(self):
        """Only load() switches the process to offline mode."""
        out = _run_isolated(
            "import os; os.environ.pop('HF_HUB_OFFLINE', None); "
            "import sentence_transformer_backend as s; "
            "s.SentenceTransformerBackend(); s.create_default_provider(); "
            "print(os.environ.get('HF_HUB_OFFLINE'))"
        )
        assert out == "None"

    def test_module_importable_when_model_library_is_absent(self):
        """With sentence_transformers made unimportable, import and construction work."""
        out = _run_isolated(
            "import sys; sys.modules['sentence_transformers'] = None; "
            "sys.modules['torch'] = None; "
            "import sentence_transformer_backend as s, embedding_provider; "
            "p = s.create_default_provider(); print(p.identity.dimension)"
        )
        assert out == "384"


# ---------------------------------------------------------------------------
# B03  Lazy loading and reuse
# ---------------------------------------------------------------------------

class TestLazyLoading:

    def test_constructor_does_not_load(self):
        backend, factory = _backend()
        assert factory.calls == []
        assert backend.is_loaded is False

    def test_property_access_does_not_load(self):
        backend, factory = _backend()
        _ = (backend.model_name, backend.revision, backend.local_files_only, backend.is_loaded)
        assert factory.calls == []

    def test_first_call_loads_once(self):
        backend, factory = _backend()
        backend("text")
        assert len(factory.calls) == 1
        assert backend.is_loaded is True

    def test_later_calls_reuse_model(self):
        backend, factory = _backend()
        for text in ("a", "b", "c", "a"):
            backend(text)
        assert len(factory.calls) == 1
        assert len(factory.model.encode_calls) == 4

    def test_explicit_load_loads_once(self):
        backend, factory = _backend()
        backend.load()
        backend.load()
        backend.load()
        assert len(factory.calls) == 1
        assert backend.is_loaded is True

    def test_load_then_call_reuses_model(self):
        backend, factory = _backend()
        backend.load()
        backend("text")
        assert len(factory.calls) == 1

    def test_load_does_not_encode(self):
        backend, factory = _backend()
        backend.load()
        assert factory.model.encode_calls == []

    def test_token_usage_loads_once_and_reuses(self):
        backend, factory = _backend()
        backend.token_usage("a b c")
        backend.token_usage("d e")
        backend("text")
        assert len(factory.calls) == 1

    def test_each_backend_instance_loads_its_own_model(self):
        first, factory_a = _backend()
        second, factory_b = _backend()
        first("x")
        assert len(factory_a.calls) == 1
        assert factory_b.calls == []
        assert second.is_loaded is False

    def test_load_returns_none(self):
        backend, _ = _backend()
        assert backend.load() is None


# ---------------------------------------------------------------------------
# B04  Load arguments
# ---------------------------------------------------------------------------

class TestLoadArguments:

    def test_exact_model_name(self):
        backend, factory = _backend()
        backend.load()
        args, _ = factory.calls[0]
        assert args == ("sentence-transformers/all-MiniLM-L6-v2",)

    def test_exact_revision(self):
        backend, factory = _backend()
        backend.load()
        _, kwargs = factory.calls[0]
        assert kwargs["revision"] == "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"

    def test_local_files_only_true_by_default(self):
        backend, factory = _backend()
        backend.load()
        _, kwargs = factory.calls[0]
        assert kwargs["local_files_only"] is True
        assert backend.local_files_only is True

    def test_cpu_device(self):
        backend, factory = _backend()
        backend.load()
        _, kwargs = factory.calls[0]
        assert kwargs["device"] == "cpu"

    def test_exact_keyword_set(self):
        backend, factory = _backend()
        backend.load()
        _, kwargs = factory.calls[0]
        assert set(kwargs) == {"revision", "local_files_only", "device"}

    def test_defaults_are_the_locked_constants(self):
        backend = SentenceTransformerBackend()
        assert backend.model_name == MODEL_NAME
        assert backend.revision == MODEL_REVISION
        assert backend.local_files_only is True

    def test_explicit_overrides_are_passed_through(self):
        backend, factory = _backend(
            model_name="other/model", revision="f" * 40, local_files_only=False,
        )
        backend.load()
        args, kwargs = factory.calls[0]
        assert args == ("other/model",)
        assert kwargs["revision"] == "f" * 40
        assert kwargs["local_files_only"] is False

    def test_constructor_arguments_are_keyword_only(self):
        with pytest.raises(TypeError):
            SentenceTransformerBackend("some/model")  # type: ignore[misc]

    def test_default_factory_passes_arguments_to_sentence_transformer(self, monkeypatch):
        """The real load path, with the library itself replaced by a fake."""
        import types

        created = []

        class FakeSentenceTransformer(FakeModel):
            def __init__(self, *args, **kwargs):
                super().__init__()
                created.append((args, kwargs))

        fake_module = types.ModuleType("sentence_transformers")
        fake_module.SentenceTransformer = FakeSentenceTransformer
        monkeypatch.setitem(sys.modules, "sentence_transformers", fake_module)

        backend = SentenceTransformerBackend()
        backend.load()
        assert created == [(
            ("sentence-transformers/all-MiniLM-L6-v2",),
            {
                "revision": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
                "local_files_only": True,
                "device": "cpu",
            },
        )]
        assert backend.is_loaded is True


# ---------------------------------------------------------------------------
# B05  Evaluation mode
# ---------------------------------------------------------------------------

class TestEvaluationMode:

    def test_eval_called_on_load(self):
        backend, factory = _backend()
        assert factory.model.training is True
        backend.load()
        assert factory.model.eval_calls == 1
        assert factory.model.training is False

    def test_eval_called_before_first_encode(self):
        order = []

        class OrderedModel(FakeModel):
            def eval(self):
                order.append("eval")
                return super().eval()

            def encode(self, *args, **kwargs):
                order.append("encode")
                return super().encode(*args, **kwargs)

        backend, _ = _backend(OrderedModel())
        backend("text")
        assert order == ["eval", "encode"]

    def test_eval_called_once_across_many_calls(self):
        backend, factory = _backend()
        for _ in range(5):
            backend("text")
        assert factory.model.eval_calls == 1


# ---------------------------------------------------------------------------
# B06  Encoding
# ---------------------------------------------------------------------------

class TestEncoding:

    def test_one_text_passed_to_encode(self):
        backend, factory = _backend()
        backend("the incident document")
        args, _ = factory.model.encode_calls[0]
        assert args == ("the incident document",)

    def test_encode_receives_a_str_not_a_batch(self):
        backend, factory = _backend()
        backend("text")
        args, _ = factory.model.encode_calls[0]
        assert type(args[0]) is str
        assert not isinstance(args[0], (list, tuple))

    def test_one_encode_call_per_text(self):
        backend, factory = _backend()
        backend("a")
        backend("b")
        assert [args for args, _ in factory.model.encode_calls] == [("a",), ("b",)]

    def test_text_is_passed_unchanged(self):
        text = "  ERROR ToolExecutionError\ncafé \U0001F680  "
        backend, factory = _backend()
        backend(text)
        args, _ = factory.model.encode_calls[0]
        assert args[0] == text

    def test_encode_keyword_arguments(self):
        backend, factory = _backend()
        backend("text")
        _, kwargs = factory.model.encode_calls[0]
        assert kwargs == {"convert_to_numpy": True, "show_progress_bar": False}

    def test_no_batch_size_or_normalize_argument(self):
        backend, factory = _backend()
        backend("text")
        _, kwargs = factory.model.encode_calls[0]
        assert "batch_size" not in kwargs
        assert "normalize_embeddings" not in kwargs

    @pytest.mark.parametrize(
        "text", [["a", "b"], ("a",), None, 123, b"text"],
        ids=["list", "tuple", "none", "int", "bytes"],
    )
    def test_non_str_input_raises_and_does_not_encode(self, text):
        backend, factory = _backend()
        with pytest.raises(ValueError, match="single str"):
            backend(text)
        assert factory.model.encode_calls == []

    def test_array_output_converted_with_tolist(self):
        output = FakeArray([0.5, -0.25, 0.125])
        backend, _ = _backend(FakeModel(output))
        assert backend("text") == [0.5, -0.25, 0.125]
        assert output.tolist_calls == 1

    def test_output_is_list_of_plain_python_floats(self):
        backend, _ = _backend(FakeModel(FakeArray([1, 2.5, FakeScalar(0.75)])))
        result = backend("text")
        assert type(result) is list
        assert result == [1.0, 2.5, 0.75]
        assert all(type(x) is float for x in result)

    def test_plain_sequence_output_is_converted(self):
        backend, _ = _backend(FakeModel((FakeScalar(0.5), FakeScalar(0.25))))
        result = backend("text")
        assert result == [0.5, 0.25]
        assert all(type(x) is float for x in result)

    def test_full_dimension_output(self):
        backend, _ = _backend()
        result = backend("text")
        assert len(result) == 384
        assert all(type(x) is float for x in result)

    def test_backend_does_not_normalize(self):
        """Normalization belongs to the provider; the backend returns raw values."""
        backend, _ = _backend(FakeModel(FakeArray([3.0, 0.0, 4.0])))
        assert backend("text") == [3.0, 0.0, 4.0]

    def test_two_dimensional_output_raises(self):
        backend, _ = _backend(FakeModel(FakeArray([[0.5, 0.5], [0.5, 0.5]])))
        with pytest.raises(ValueError, match="one-dimensional"):
            backend("text")

    def test_deprecated_tokenize_never_called_during_encode(self):
        backend, _ = _backend()
        backend("text")  # FakeModel.tokenize raises if it is called


# ---------------------------------------------------------------------------
# B07  Token usage
# ---------------------------------------------------------------------------

class TestTokenUsage:

    def test_token_usage_is_frozen_dataclass(self):
        assert dataclasses.is_dataclass(TokenUsage)
        assert TokenUsage.__dataclass_params__.frozen is True
        assert [f.name for f in dataclasses.fields(TokenUsage)] == [
            "tokens_without_special",
            "tokens_with_special",
            "token_limit",
            "truncated",
        ]

    def test_counts_with_and_without_special_tokens(self):
        backend, _ = _backend()
        usage = backend.token_usage(_words(10))
        assert usage.tokens_without_special == 10
        assert usage.tokens_with_special == 12

    def test_limit_is_256(self):
        backend, _ = _backend()
        assert backend.token_usage("a").token_limit == 256

    def test_limit_comes_from_loaded_model(self):
        backend, factory = _backend()
        backend.load()
        assert backend.token_usage("a").token_limit == factory.model.max_seq_length

    def test_below_limit_not_truncated(self):
        backend, _ = _backend()
        usage = backend.token_usage(_words(100))
        assert usage == TokenUsage(100, 102, 256, False)

    def test_one_below_limit_not_truncated(self):
        backend, _ = _backend()
        usage = backend.token_usage(_words(253))
        assert usage == TokenUsage(253, 255, 256, False)

    def test_exactly_at_limit_not_truncated(self):
        backend, _ = _backend()
        usage = backend.token_usage(_words(254))
        assert usage == TokenUsage(254, 256, 256, False)

    def test_one_above_limit_truncated(self):
        backend, _ = _backend()
        usage = backend.token_usage(_words(255))
        assert usage == TokenUsage(255, 257, 256, True)

    def test_far_above_limit_truncated(self):
        backend, _ = _backend()
        usage = backend.token_usage(_words(677))
        assert usage == TokenUsage(677, 679, 256, True)

    def test_limit_counts_special_tokens(self):
        """256 content tokens exceed the limit once special tokens are added."""
        backend, _ = _backend()
        usage = backend.token_usage(_words(256))
        assert usage.tokens_without_special == 256
        assert usage.truncated is True

    def test_uses_the_models_tokenizer_directly(self):
        backend, factory = _backend()
        backend.token_usage("a b c")
        calls = factory.model.tokenizer.calls
        assert [text for text, _ in calls] == ["a b c", "a b c"]

    def test_tokenizer_called_with_truncation_disabled(self):
        backend, factory = _backend()
        backend.token_usage("a b c")
        for _, kwargs in factory.model.tokenizer.calls:
            assert kwargs["truncation"] is False

    def test_tokenizer_called_with_and_without_special_tokens(self):
        backend, factory = _backend()
        backend.token_usage("a b c")
        flags = [kwargs["add_special_tokens"] for _, kwargs in factory.model.tokenizer.calls]
        assert flags == [False, True]

    def test_token_usage_does_not_encode(self):
        backend, factory = _backend()
        backend.token_usage(_words(500))
        assert factory.model.encode_calls == []

    def test_token_usage_does_not_use_deprecated_tokenize(self):
        backend, _ = _backend()
        backend.token_usage("a b c")  # FakeModel.tokenize raises if it is called

    def test_text_passed_to_tokenizer_unchanged(self):
        text = "  ERROR  Tool\n\U0001F680 "
        backend, factory = _backend()
        backend.token_usage(text)
        assert all(seen == text for seen, _ in factory.model.tokenizer.calls)

    def test_token_usage_is_deterministic(self):
        backend, _ = _backend()
        assert backend.token_usage(_words(300)) == backend.token_usage(_words(300))

    def test_oversized_text_is_still_embedded(self):
        """Truncation is allowed: no rejection, one encode call, full text passed."""
        text = _words(1000)
        backend, factory = _backend()
        assert backend.token_usage(text).truncated is True
        result = backend(text)
        assert len(result) == 384
        assert factory.model.encode_calls[0][0] == (text,)

    def test_call_returns_only_the_vector(self):
        backend, _ = _backend()
        assert type(backend(_words(1000))) is list

    @pytest.mark.parametrize("text", [None, 123, ["a"], b"a"], ids=["none", "int", "list", "bytes"])
    def test_non_str_raises(self, text):
        backend, _ = _backend()
        with pytest.raises(ValueError, match="text must be str"):
            backend.token_usage(text)

    def test_max_seq_length_is_never_modified(self):
        backend, factory = _backend()
        backend.load()
        backend(_words(1000))
        backend.token_usage(_words(1000))
        assert factory.model.max_seq_length == 256

    @pytest.mark.parametrize("limit", [128, 512, 255, 257])
    def test_unexpected_model_limit_raises_on_load(self, limit):
        backend, _ = _backend(FakeModel(max_seq_length=limit))
        with pytest.raises(RuntimeError, match="max_seq_length"):
            backend.load()
        assert backend.is_loaded is False


# ---------------------------------------------------------------------------
# B08  Missing library / missing local model
# ---------------------------------------------------------------------------

def _failing_backend(error: Exception, **kwargs) -> tuple[SentenceTransformerBackend, FakeFactory]:
    factory = FakeFactory(error=error)
    return SentenceTransformerBackend(model_factory=factory, **kwargs), factory


class TestLoadFailures:

    def test_missing_library_raises_runtime_error(self):
        backend, _ = _failing_backend(ImportError("No module named 'sentence_transformers'"))
        with pytest.raises(RuntimeError, match="sentence-transformers is not installed"):
            backend.load()

    def test_missing_library_message_identifies_model_and_revision(self):
        backend, _ = _failing_backend(ModuleNotFoundError("sentence_transformers"))
        with pytest.raises(RuntimeError) as excinfo:
            backend("text")
        message = str(excinfo.value)
        assert MODEL_NAME in message
        assert MODEL_REVISION in message
        assert "requirements.txt" in message

    def test_missing_library_via_real_import_path(self, monkeypatch):
        """sys.modules[name] = None makes the import raise ImportError."""
        monkeypatch.setitem(sys.modules, "sentence_transformers", None)
        backend = SentenceTransformerBackend()
        with pytest.raises(RuntimeError, match="sentence-transformers is not installed"):
            backend.load()
        assert backend.is_loaded is False

    def test_missing_library_preserves_cause(self):
        cause = ImportError("boom")
        backend, _ = _failing_backend(cause)
        with pytest.raises(RuntimeError) as excinfo:
            backend.load()
        assert excinfo.value.__cause__ is cause

    def test_missing_local_model_raises_runtime_error(self):
        backend, _ = _failing_backend(OSError("couldn't find them in the cached files"))
        with pytest.raises(RuntimeError, match="not available in the local Hugging Face cache"):
            backend.load()

    def test_missing_local_model_message_is_complete(self):
        backend, _ = _failing_backend(OSError("not cached"))
        with pytest.raises(RuntimeError) as excinfo:
            backend("text")
        message = str(excinfo.value)
        assert MODEL_NAME in message
        assert MODEL_REVISION in message
        assert "local_files_only=True" in message
        assert "Local-only loading was requested" in message
        assert "model acquisition" in message
        assert "network was not used" in message

    def test_missing_local_model_preserves_cause(self):
        cause = FileNotFoundError("snapshot missing")
        backend, _ = _failing_backend(cause)
        with pytest.raises(RuntimeError) as excinfo:
            backend.load()
        assert excinfo.value.__cause__ is cause

    def test_error_names_the_requested_revision(self):
        backend, _ = _failing_backend(OSError("x"), revision="0" * 40)
        with pytest.raises(RuntimeError) as excinfo:
            backend.load()
        assert "0" * 40 in str(excinfo.value)

    @pytest.mark.parametrize(
        "error", [ImportError("x"), OSError("x")], ids=["missing-library", "missing-model"],
    )
    def test_no_network_fallback(self, error):
        """One load attempt, local-only; never retried with the network enabled."""
        backend, factory = _failing_backend(error)
        with pytest.raises(RuntimeError):
            backend.load()
        assert len(factory.calls) == 1
        assert [kwargs["local_files_only"] for _, kwargs in factory.calls] == [True]

    def test_failed_load_leaves_backend_unloaded(self):
        backend, _ = _failing_backend(OSError("x"))
        with pytest.raises(RuntimeError):
            backend.load()
        assert backend.is_loaded is False

    def test_each_call_after_failure_tries_local_only_again(self):
        backend, factory = _failing_backend(OSError("x"))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                backend("text")
        assert [kwargs["local_files_only"] for _, kwargs in factory.calls] == [True, True, True]

    def test_token_usage_raises_the_same_error(self):
        backend, _ = _failing_backend(OSError("x"))
        with pytest.raises(RuntimeError, match="local Hugging Face cache"):
            backend.token_usage("a b")

    def test_explicit_network_mode_failure_has_distinct_message(self):
        backend, factory = _failing_backend(OSError("x"), local_files_only=False)
        with pytest.raises(RuntimeError, match="local_files_only=False"):
            backend.load()
        assert len(factory.calls) == 1

    def test_unrelated_errors_are_not_swallowed(self):
        backend, _ = _failing_backend(KeyError("unexpected"))
        with pytest.raises(KeyError):
            backend.load()

    def test_failure_propagates_through_provider(self):
        identity = EmbeddingModelIdentity(MODEL_NAME, MODEL_REVISION, EMBEDDING_DIMENSION)
        backend, _ = _failing_backend(OSError("x"))
        provider = EmbeddingProvider(identity, backend)
        with pytest.raises(RuntimeError, match="local Hugging Face cache"):
            provider.embed("text")


# ---------------------------------------------------------------------------
# B10  Offline enforcement
# ---------------------------------------------------------------------------

def _fake_hub_constants(offline) -> object:
    import types

    module = types.ModuleType("huggingface_hub.constants")
    if offline is not None:
        module.HF_HUB_OFFLINE = offline
    return module


class TestOfflineEnforcement:

    def test_environment_starts_unset(self):
        assert "HF_HUB_OFFLINE" not in os.environ

    def test_load_sets_offline_env(self):
        backend, _ = _backend()
        backend.load()
        assert os.environ["HF_HUB_OFFLINE"] == "1"

    def test_env_is_set_before_the_model_is_loaded(self):
        """The library reads the variable at import, so it must be set first."""
        seen = []

        def factory(*args, **kwargs):
            seen.append(os.environ.get("HF_HUB_OFFLINE"))
            return FakeModel()

        SentenceTransformerBackend(model_factory=factory).load()
        assert seen == ["1"]

    @pytest.mark.parametrize("existing", ["0", "false", "", "no", "1", "true"])
    def test_existing_value_is_overridden_to_1(self, monkeypatch, existing):
        monkeypatch.setenv("HF_HUB_OFFLINE", existing)
        backend, _ = _backend()
        backend.load()
        assert os.environ["HF_HUB_OFFLINE"] == "1"

    def test_first_call_sets_offline_env(self):
        backend, _ = _backend()
        backend("text")
        assert os.environ["HF_HUB_OFFLINE"] == "1"

    def test_token_usage_sets_offline_env(self):
        backend, _ = _backend()
        backend.token_usage("a b")
        assert os.environ["HF_HUB_OFFLINE"] == "1"

    def test_constructor_does_not_set_env(self):
        _backend()
        SentenceTransformerBackend()
        assert "HF_HUB_OFFLINE" not in os.environ

    def test_create_default_provider_does_not_set_env(self):
        create_default_provider()
        assert "HF_HUB_OFFLINE" not in os.environ

    def test_explicit_network_mode_does_not_touch_env(self):
        backend, _ = _backend(local_files_only=False)
        backend.load()
        assert "HF_HUB_OFFLINE" not in os.environ

    def test_explicit_network_mode_keeps_existing_env(self, monkeypatch):
        monkeypatch.setenv("HF_HUB_OFFLINE", "0")
        backend, _ = _backend(local_files_only=False)
        backend.load()
        assert os.environ["HF_HUB_OFFLINE"] == "0"

    def test_hub_already_online_raises_before_loading(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "huggingface_hub.constants", _fake_hub_constants(False))
        backend, factory = _backend()
        with pytest.raises(RuntimeError, match="online mode"):
            backend.load()
        assert factory.calls == []
        assert backend.is_loaded is False

    def test_hub_already_online_message_names_the_variable(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "huggingface_hub.constants", _fake_hub_constants(False))
        backend, _ = _backend()
        with pytest.raises(RuntimeError) as excinfo:
            backend("text")
        assert "HF_HUB_OFFLINE=1" in str(excinfo.value)

    @pytest.mark.parametrize("value", [None, 0, "1", "true", 1], ids=["missing", "0", "str-1", "str-true", "int-1"])
    def test_only_a_true_offline_flag_is_accepted(self, monkeypatch, value):
        """Anything other than the library's own boolean True counts as online."""
        monkeypatch.setitem(sys.modules, "huggingface_hub.constants", _fake_hub_constants(value))
        backend, factory = _backend()
        with pytest.raises(RuntimeError, match="online mode"):
            backend.load()
        assert factory.calls == []

    def test_hub_already_offline_loads(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "huggingface_hub.constants", _fake_hub_constants(True))
        backend, factory = _backend()
        backend.load()
        assert backend.is_loaded is True
        assert len(factory.calls) == 1

    def test_hub_not_imported_loads(self):
        assert "huggingface_hub.constants" not in sys.modules
        backend, _ = _backend()
        backend.load()
        assert backend.is_loaded is True

    def test_hub_imported_online_during_load_raises(self, monkeypatch):
        """Verified again after the library is imported by the load itself."""

        def factory(*args, **kwargs):
            monkeypatch.setitem(
                sys.modules, "huggingface_hub.constants", _fake_hub_constants(False),
            )
            return FakeModel()

        backend = SentenceTransformerBackend(model_factory=factory)
        with pytest.raises(RuntimeError, match="online mode"):
            backend.load()
        assert backend.is_loaded is False

    def test_hub_imported_offline_during_load_succeeds(self, monkeypatch):
        def factory(*args, **kwargs):
            monkeypatch.setitem(
                sys.modules, "huggingface_hub.constants", _fake_hub_constants(True),
            )
            return FakeModel()

        backend = SentenceTransformerBackend(model_factory=factory)
        backend.load()
        assert backend.is_loaded is True

    def test_explicit_network_mode_skips_the_online_check(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "huggingface_hub.constants", _fake_hub_constants(False))
        backend, factory = _backend(local_files_only=False)
        backend.load()
        assert backend.is_loaded is True
        assert len(factory.calls) == 1

    def test_online_check_never_imports_the_library(self):
        backend, _ = _backend()
        backend.load()
        assert "huggingface_hub.constants" not in sys.modules

    def test_reused_model_does_not_recheck(self, monkeypatch):
        """Once loaded, later calls do not re-run enforcement."""
        backend, factory = _backend()
        backend.load()
        monkeypatch.setitem(sys.modules, "huggingface_hub.constants", _fake_hub_constants(False))
        backend("text")
        assert len(factory.calls) == 1

    def test_real_import_path_starts_the_library_offline(self, monkeypatch):
        """The default factory runs after the variable is set."""
        import types

        seen = []

        class FakeSentenceTransformer(FakeModel):
            def __init__(self, *args, **kwargs):
                super().__init__()
                seen.append(os.environ.get("HF_HUB_OFFLINE"))

        fake_module = types.ModuleType("sentence_transformers")
        fake_module.SentenceTransformer = FakeSentenceTransformer
        monkeypatch.setitem(sys.modules, "sentence_transformers", fake_module)

        SentenceTransformerBackend().load()
        assert seen == ["1"]


# ---------------------------------------------------------------------------
# B09  create_default_provider()
# ---------------------------------------------------------------------------

class TestDefaultProvider:

    def test_returns_embedding_provider(self):
        assert isinstance(create_default_provider(), EmbeddingProvider)

    def test_locked_identity(self):
        assert create_default_provider().identity == EmbeddingModelIdentity(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            dimension=384,
        )

    def test_backend_is_lazy_sentence_transformer_backend(self):
        backend = create_default_provider().backend
        assert isinstance(backend, SentenceTransformerBackend)
        assert backend.is_loaded is False

    def test_backend_uses_locked_model_and_local_only(self):
        backend = create_default_provider().backend
        assert backend.model_name == MODEL_NAME
        assert backend.revision == MODEL_REVISION
        assert backend.local_files_only is True

    def test_does_not_load(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            stb, "_default_model_factory",
            lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        provider = create_default_provider()
        assert calls == []
        assert provider.backend.is_loaded is False

    def test_each_call_returns_independent_objects(self):
        first, second = create_default_provider(), create_default_provider()
        assert first is not second
        assert first.backend is not second.backend
        assert first.identity == second.identity

    def test_takes_no_arguments(self):
        with pytest.raises(TypeError):
            create_default_provider("other/model")  # type: ignore[call-arg]

    def test_provider_normalizes_backend_output_end_to_end(self):
        """Fake model behind the real provider and backend classes."""
        identity = EmbeddingModelIdentity(MODEL_NAME, MODEL_REVISION, EMBEDDING_DIMENSION)
        values = [0.0] * 384
        values[0], values[1] = 3.0, 4.0
        backend, factory = _backend(FakeModel(FakeArray(values)))
        result = EmbeddingProvider(identity, backend).embed("incident text")
        assert type(result) is tuple
        assert result[0] == 0.6 and result[1] == 0.8
        assert all(x == 0.0 for x in result[2:])
        assert factory.model.encode_calls[0][0] == ("incident text",)

    def test_provider_rejects_wrong_dimension_from_model(self):
        identity = EmbeddingModelIdentity(MODEL_NAME, MODEL_REVISION, EMBEDDING_DIMENSION)
        backend, _ = _backend(FakeModel(FakeArray([0.5] * 383)))
        with pytest.raises(ValueError, match="384 elements"):
            EmbeddingProvider(identity, backend).embed("text")

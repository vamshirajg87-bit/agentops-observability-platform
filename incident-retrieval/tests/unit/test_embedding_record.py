"""
incident-retrieval/tests/unit/test_embedding_record.py

Unit tests for embedding_record.py.

All tests are pure Python — no database, no network, no I/O beyond reading
the module source for the import-boundary check.

Test inventory:
    R01  compute_embedding_id: formula, golden digest, format
    R02  compute_embedding_id: sensitivity and separator behaviour
    R03  compute_embedding_id: input validation
    R04  format_vector_literal: format and round-trip
    R05  format_vector_literal: rejection of bad values
    R06  EmbeddingOutcome and status constants
    R07  Purity / import boundary
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import math
import os
import re

import pytest

import embedding_record
from embedding_record import (
    EMBEDDING_STATUSES,
    STATUS_ALREADY_PRESENT,
    STATUS_INSERTED,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
    EmbeddingOutcome,
    compute_embedding_id,
    format_vector_literal,
)


_MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "embedding_record.py")
)

_INV = "a" * 64
_DOC = "1.0.0"
_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_REV = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"


# ---------------------------------------------------------------------------
# R01  Formula, golden digest, format
# ---------------------------------------------------------------------------

class TestEmbeddingIdFormula:

    def test_phase_12_2_golden_digest(self):
        """The same vector locked by storage-consumer/tests/unit/test_migration_010.py."""
        assert compute_embedding_id(
            "a" * 64, "1.0.0", "sentence-transformers/all-MiniLM-L6-v2", "test-revision",
        ) == "0f60177b37fba45c6b54755636ffccc6362aeebe761dcd24b1fa5deabab2e28b"

    def test_matches_reference_formula(self):
        expected = hashlib.sha256(
            f"{_INV}|{_DOC}|{_MODEL}|{_REV}".encode("utf-8")
        ).hexdigest()
        assert compute_embedding_id(_INV, _DOC, _MODEL, _REV) == expected

    def test_is_64_lowercase_hex(self):
        value = compute_embedding_id(_INV, _DOC, _MODEL, _REV)
        assert re.fullmatch(r"[0-9a-f]{64}", value)

    def test_satisfies_database_check_pattern(self):
        """The migration 010 CHECK is embedding_id ~ '^[0-9a-f]{64}$'."""
        assert re.search(r"^[0-9a-f]{64}$", compute_embedding_id(_INV, _DOC, _MODEL, _REV))

    def test_returns_plain_str(self):
        assert type(compute_embedding_id(_INV, _DOC, _MODEL, _REV)) is str

    def test_deterministic(self):
        assert len({compute_embedding_id(_INV, _DOC, _MODEL, _REV) for _ in range(10)}) == 1

    def test_utf8_encoding_of_non_ascii_input(self):
        expected = hashlib.sha256("café|1.0.0|m\U0001F680|r".encode("utf-8")).hexdigest()
        assert compute_embedding_id("café", "1.0.0", "m\U0001F680", "r") == expected

    def test_differs_from_investigation_id(self):
        assert compute_embedding_id(_INV, _DOC, _MODEL, _REV) != _INV


# ---------------------------------------------------------------------------
# R02  Sensitivity and separator
# ---------------------------------------------------------------------------

class TestEmbeddingIdSensitivity:

    @pytest.mark.parametrize("position", [0, 1, 2, 3], ids=[
        "investigation_id", "doc_version", "model_name", "model_revision",
    ])
    def test_each_input_changes_the_digest(self, position):
        base = [_INV, _DOC, _MODEL, _REV]
        changed = list(base)
        changed[position] += "x"
        assert compute_embedding_id(*base) != compute_embedding_id(*changed)

    def test_new_doc_version_is_a_distinct_identity(self):
        assert compute_embedding_id(_INV, "1.0.0", _MODEL, _REV) != compute_embedding_id(_INV, "1.0.1", _MODEL, _REV)

    def test_new_model_revision_is_a_distinct_identity(self):
        assert compute_embedding_id(_INV, _DOC, _MODEL, _REV) != compute_embedding_id(_INV, _DOC, _MODEL, "0" * 40)

    def test_argument_order_matters(self):
        assert compute_embedding_id("a", "b", "c", "d") != compute_embedding_id("b", "a", "c", "d")

    def test_separator_prevents_ambiguous_concatenation(self):
        assert compute_embedding_id("ab", "c", "m", "r") != compute_embedding_id("a", "bc", "m", "r")

    def test_separator_is_a_pipe(self):
        expected = hashlib.sha256(b"a|b|c|d").hexdigest()
        assert compute_embedding_id("a", "b", "c", "d") == expected

    def test_inputs_are_not_normalized(self):
        assert compute_embedding_id(_INV, _DOC, _MODEL, _REV) != compute_embedding_id(_INV.upper(), _DOC, _MODEL, _REV)
        assert compute_embedding_id(_INV, _DOC, _MODEL, _REV) != compute_embedding_id(_INV + " ", _DOC, _MODEL, _REV)


# ---------------------------------------------------------------------------
# R03  Input validation
# ---------------------------------------------------------------------------

class TestEmbeddingIdValidation:

    @pytest.mark.parametrize("position, field", [
        (0, "investigation_id"), (1, "doc_version"), (2, "model_name"), (3, "model_revision"),
    ])
    @pytest.mark.parametrize("value", [None, 123, 1.0, True, b"x", ["x"]],
                             ids=["none", "int", "float", "bool", "bytes", "list"])
    def test_non_str_raises(self, position, field, value):
        args = [_INV, _DOC, _MODEL, _REV]
        args[position] = value
        with pytest.raises(ValueError, match=field):
            compute_embedding_id(*args)


# ---------------------------------------------------------------------------
# R04  Vector literal format
# ---------------------------------------------------------------------------

def _parse(literal: str) -> list[float]:
    assert literal.startswith("[") and literal.endswith("]")
    return [float(part) for part in literal[1:-1].split(",")]


class TestVectorLiteralFormat:

    def test_simple(self):
        assert format_vector_literal([0.5, -0.25, 1.0]) == "[0.5,-0.25,1.0]"

    def test_brackets_and_commas_no_spaces(self):
        literal = format_vector_literal([0.1, 0.2, 0.3])
        assert literal.startswith("[") and literal.endswith("]")
        assert " " not in literal
        assert literal.count(",") == 2

    def test_384_elements(self):
        vector = [(i - 192) / 1000.0 for i in range(384)]
        literal = format_vector_literal(vector)
        assert literal.count(",") == 383
        assert len(_parse(literal)) == 384

    def test_round_trips_exactly(self):
        vector = [1.0 / 3.0, -2.0 / 7.0, 1e-12, 123456.789, 5e-324, 0.1 + 0.2]
        assert _parse(format_vector_literal(vector)) == vector

    def test_unit_vector_round_trips(self):
        value = 1.0 / math.sqrt(384)
        vector = (value,) * 384
        assert tuple(_parse(format_vector_literal(vector))) == vector

    def test_uses_repr_of_each_float(self):
        vector = [0.1, 1e-05, 1e+20, -0.0]
        assert format_vector_literal(vector) == "[" + ",".join(repr(x) for x in vector) + "]"

    def test_int_elements_rendered_as_floats(self):
        assert format_vector_literal([1, 0, -2]) == "[1.0,0.0,-2.0]"

    def test_accepts_tuple_and_list(self):
        assert format_vector_literal((0.5, 0.25)) == format_vector_literal([0.5, 0.25])

    def test_single_element(self):
        assert format_vector_literal([0.5]) == "[0.5]"

    def test_input_is_not_mutated(self):
        vector = [0.5, 0.25]
        format_vector_literal(vector)
        assert vector == [0.5, 0.25]

    def test_no_nan_or_inf_text_for_valid_input(self):
        literal = format_vector_literal([(i - 192) / 1000.0 for i in range(384)]).lower()
        assert "nan" not in literal and "inf" not in literal

    def test_only_expected_characters(self):
        literal = format_vector_literal([0.1, -1e-05, 1e+20, 3.0])
        assert re.fullmatch(r"\[[0-9eE+\-.,]+\]", literal)


# ---------------------------------------------------------------------------
# R05  Vector literal rejection
# ---------------------------------------------------------------------------

class TestVectorLiteralRejection:

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            format_vector_literal([])

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")],
                             ids=["nan", "+inf", "-inf"])
    def test_non_finite_raises(self, value):
        with pytest.raises(ValueError, match="not finite"):
            format_vector_literal([0.5, value, 0.5])

    @pytest.mark.parametrize("value", [True, False, None, "0.5", b"1", [0.5], 1 + 0j],
                             ids=["true", "false", "none", "str", "bytes", "list", "complex"])
    def test_non_numeric_raises(self, value):
        with pytest.raises(ValueError, match="real number"):
            format_vector_literal([0.5, value])

    def test_error_names_the_element_index(self):
        with pytest.raises(ValueError, match="element 2 "):
            format_vector_literal([0.1, 0.2, float("nan"), 0.4])


# ---------------------------------------------------------------------------
# R06  Outcome and statuses
# ---------------------------------------------------------------------------

class TestOutcome:

    def test_status_values(self):
        assert STATUS_INSERTED == "inserted"
        assert STATUS_ALREADY_PRESENT == "already_present"
        assert STATUS_NOT_ELIGIBLE == "not_eligible"
        assert STATUS_TEXT_MISMATCH == "text_mismatch"

    def test_status_set_is_exactly_the_four(self):
        assert EMBEDDING_STATUSES == {
            "inserted", "already_present", "not_eligible", "text_mismatch",
        }
        assert isinstance(EMBEDDING_STATUSES, frozenset)

    def test_outcome_is_frozen_dataclass(self):
        assert dataclasses.is_dataclass(EmbeddingOutcome)
        assert EmbeddingOutcome.__dataclass_params__.frozen is True

    def test_outcome_fields_exact(self):
        assert [f.name for f in dataclasses.fields(EmbeddingOutcome)] == [
            "investigation_id", "status", "embedding_id", "token_usage",
        ]

    def test_outcome_is_immutable(self):
        outcome = EmbeddingOutcome(_INV, STATUS_INSERTED, "e" * 64, None)
        with pytest.raises(dataclasses.FrozenInstanceError):
            outcome.status = STATUS_NOT_ELIGIBLE  # type: ignore[misc]

    def test_outcome_equality_by_value(self):
        assert EmbeddingOutcome(_INV, STATUS_INSERTED, "e" * 64, None) == EmbeddingOutcome(
            _INV, STATUS_INSERTED, "e" * 64, None,
        )

    def test_outcome_allows_none_embedding_id_and_token_usage(self):
        outcome = EmbeddingOutcome(_INV, STATUS_NOT_ELIGIBLE, None, None)
        assert outcome.embedding_id is None and outcome.token_usage is None


# ---------------------------------------------------------------------------
# R07  Purity / import boundary
# ---------------------------------------------------------------------------

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
        assert os.path.abspath(embedding_record.__file__) == _MODULE_PATH

    def test_imports_are_standard_library_only(self, module_tree):
        assert _imported_modules(module_tree) <= {
            "__future__", "hashlib", "math", "dataclasses", "typing",
        }

    @pytest.mark.parametrize(
        "forbidden",
        ["psycopg", "incident_document", "embedding_provider", "embedding_store",
         "sentence_transformer_backend", "rca_persist", "rca_models", "numpy", "os", "sys"],
    )
    def test_forbidden_module_not_imported(self, module_tree, forbidden):
        assert forbidden not in _imported_modules(module_tree)

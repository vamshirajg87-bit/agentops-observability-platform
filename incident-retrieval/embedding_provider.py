"""
incident-retrieval/embedding_provider.py

Phase 12.4: Generic embedding provider contract.

Wraps an injected backend callable (text -> vector) with input validation,
output validation, and L2 normalization.  The provider knows nothing about
how the vector is produced; the model lives entirely behind the backend.

The provider accepts text only.  It does not know about incident documents,
RCA, or storage, and it passes valid text to the backend exactly as supplied:
no stripping, no Unicode normalization, no case change, no prefix or suffix,
no truncation.

Input contract (ValueError on violation; the backend is not called):
    text must be a str
    text must contain at least one non-whitespace character
    text must be strict UTF-8 encodable (no unpaired surrogate)

Backend output contract (ValueError on violation):
    exactly identity.dimension elements
    every element an int or float; bool is rejected
    every element finite
    the vector must have a finite, non-zero L2 norm

Normalization:
    The provider owns L2 normalization.  The backend may return any finite,
    non-zero vector of the right dimension; the provider divides it by its
    L2 norm.  Cosine distance is unaffected by this scaling.

Return value:
    tuple[float, ...] of plain Python floats with unit L2 norm.  The backend
    output is never mutated.

Standard library only.  No database access, no I/O, no model library.

Public API:
    EmbeddingModelIdentity  — what produced an embedding (frozen dataclass)
    EmbeddingBackend        — type of the injected backend callable
    EmbeddingProvider       — validated, normalized text -> vector
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Sequence


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmbeddingModelIdentity:
    """
    Stable identity of the model that produces an embedding.

    model_name and model_revision are the values later recorded with a
    persisted embedding; dimension is the fixed vector length.
    """

    model_name: str
    model_revision: str
    dimension: int


#: A backend maps one text to one vector.  It may return any finite,
#: non-zero vector of the identity's dimension; it need not be unit length.
EmbeddingBackend = Callable[[str], Sequence[float]]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_identity(identity: EmbeddingModelIdentity) -> EmbeddingModelIdentity:
    if not isinstance(identity, EmbeddingModelIdentity):
        raise ValueError(
            "identity must be an EmbeddingModelIdentity, "
            f"got {type(identity).__name__}"
        )
    for field_name in ("model_name", "model_revision"):
        value = getattr(identity, field_name)
        if not isinstance(value, str) or value.strip() == "":
            raise ValueError(f"identity.{field_name} must be a non-empty str")
    dimension = identity.dimension
    if isinstance(dimension, bool) or not isinstance(dimension, int) or dimension < 1:
        raise ValueError("identity.dimension must be an int >= 1")
    return identity


def _validate_text(text: str) -> str:
    """Return text unchanged; ValueError when it must not be embedded."""
    if not isinstance(text, str):
        raise ValueError(f"text must be str, got {type(text).__name__}")
    if text.strip() == "":
        raise ValueError("text must not be empty or whitespace-only")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(
            "text is not UTF-8 encodable (unpaired surrogate)"
        ) from None
    return text


def _validated_values(raw: Sequence[float], dimension: int) -> list[float]:
    """Copy the backend output into a list of finite Python floats."""
    try:
        elements = tuple(raw)
    except TypeError:
        raise ValueError(
            f"backend output must be a sequence, got {type(raw).__name__}"
        ) from None

    if len(elements) != dimension:
        raise ValueError(
            f"backend output must have {dimension} elements, got {len(elements)}"
        )

    values: list[float] = []
    for index, element in enumerate(elements):
        if isinstance(element, bool) or not isinstance(element, (int, float)):
            raise ValueError(
                f"backend output element {index} must be a real number, "
                f"got {type(element).__name__}"
            )
        try:
            value = float(element)
        except OverflowError:
            raise ValueError(
                f"backend output element {index} is not finite"
            ) from None
        if not math.isfinite(value):
            raise ValueError(f"backend output element {index} is not finite")
        values.append(value)
    return values


def _l2_normalize(values: list[float]) -> tuple[float, ...]:
    """
    Divide values by their L2 norm.

    math.hypot scales its arguments internally, so the norm does not overflow
    or underflow for representable vectors the way a sum of squares would.
    """
    norm = math.hypot(*values)
    if norm == 0.0:
        raise ValueError("backend output has zero norm; it cannot be normalized")
    if not math.isfinite(norm):
        raise ValueError("backend output has a non-finite norm")
    return tuple(value / norm for value in values)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class EmbeddingProvider:
    """
    Validated, normalized text embedding around an injected backend.

    Parameters
    ----------
    identity
        What produces the embeddings.  Its dimension is enforced on every
        backend output.
    backend
        Callable mapping one text to one vector.
    """

    def __init__(
        self,
        identity: EmbeddingModelIdentity,
        backend: EmbeddingBackend,
    ) -> None:
        self._identity = _validate_identity(identity)
        if not callable(backend):
            raise ValueError("backend must be callable")
        self._backend = backend

    @property
    def identity(self) -> EmbeddingModelIdentity:
        return self._identity

    @property
    def backend(self) -> EmbeddingBackend:
        """The injected backend, e.g. for token-usage inspection."""
        return self._backend

    def embed(self, text: str) -> tuple[float, ...]:
        """
        Embed one text.

        Returns
        -------
        tuple[float, ...]
            identity.dimension plain Python floats with unit L2 norm.

        Raises
        ------
        ValueError
            text is not a str, is empty or whitespace-only, or contains an
            unpaired surrogate (the backend is not called); or the backend
            output has the wrong length, a non-numeric, bool, or non-finite
            element, or a zero or non-finite norm.
        """
        raw = self._backend(_validate_text(text))
        values = _validated_values(raw, self._identity.dimension)
        return _l2_normalize(values)

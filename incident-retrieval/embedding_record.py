"""
incident-retrieval/embedding_record.py

Phase 12.5: Pure helpers for one persisted embedding.

Embedding identity (locked by migration 010):

    embedding_id =
    lowercase(hex(SHA-256(UTF-8(
        investigation_id + "|" +
        doc_version + "|" +
        model_name + "|" +
        model_revision
    ))))

A new doc_version, model_name, or model_revision therefore produces a
distinct embedding_id and a distinct row.

Vector literal:
    The embedding is sent to PostgreSQL as text in pgvector's input format,
    "[v1,v2,...]", and cast with ::vector by the store.  Each value is
    written with repr(float), which round-trips exactly.

Outcome:
    EmbeddingOutcome reports what embed_investigation() did.  status is one
    of the STATUS_* constants.

Standard library only.  No database access, no I/O.

Public API:
    compute_embedding_id()    — pure: four identity inputs -> SHA-256 hex
    format_vector_literal()   — pure: sequence of floats -> "[...]" text
    EmbeddingOutcome          — frozen dataclass: result of one pipeline call
    STATUS_INSERTED, STATUS_ALREADY_PRESENT, STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH, EMBEDDING_STATUSES
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Optional, Sequence


# ---------------------------------------------------------------------------
# Outcome statuses
# ---------------------------------------------------------------------------

#: A new embedding row was stored.
STATUS_INSERTED: str = "inserted"

#: A row with this identity already exists and holds the same document text.
STATUS_ALREADY_PRESENT: str = "already_present"

#: The investigation must not be embedded (confidence INSUFFICIENT_DATA).
STATUS_NOT_ELIGIBLE: str = "not_eligible"

#: A row with this identity exists but holds different document text.
#: The stored row is left untouched.
STATUS_TEXT_MISMATCH: str = "text_mismatch"

EMBEDDING_STATUSES: frozenset[str] = frozenset({
    STATUS_INSERTED,
    STATUS_ALREADY_PRESENT,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
})


# ---------------------------------------------------------------------------
# Embedding identity
# ---------------------------------------------------------------------------

def compute_embedding_id(
    investigation_id: str,
    doc_version: str,
    model_name: str,
    model_revision: str,
) -> str:
    """
    Deterministic 64-character SHA-256 hex embedding identity.

    Payload: UTF-8 encoding of
    "{investigation_id}|{doc_version}|{model_name}|{model_revision}".

    Returns
    -------
    str
        64 lowercase hexadecimal characters (full SHA-256 digest).

    Raises
    ------
    ValueError
        Any argument is not a str.
    """
    parts = {
        "investigation_id": investigation_id,
        "doc_version": doc_version,
        "model_name": model_name,
        "model_revision": model_revision,
    }
    for field_name, value in parts.items():
        if not isinstance(value, str):
            raise ValueError(
                f"{field_name} must be str, got {type(value).__name__}"
            )
    payload = "|".join(parts.values()).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Vector literal
# ---------------------------------------------------------------------------

def format_vector_literal(vector: Sequence[float]) -> str:
    """
    Render a vector in pgvector's text input format: "[v1,v2,...]".

    Raises
    ------
    ValueError
        The vector is empty, or an element is not an int or float, is a
        bool, or is not finite.
    """
    elements = tuple(vector)
    if not elements:
        raise ValueError("vector must not be empty")

    rendered: list[str] = []
    for index, element in enumerate(elements):
        if isinstance(element, bool) or not isinstance(element, (int, float)):
            raise ValueError(
                f"vector element {index} must be a real number, "
                f"got {type(element).__name__}"
            )
        value = float(element)
        if not math.isfinite(value):
            raise ValueError(f"vector element {index} is not finite")
        rendered.append(repr(value))
    return "[" + ",".join(rendered) + "]"


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmbeddingOutcome:
    """
    Outcome of one embed_investigation() call.

    Attributes
    ----------
    investigation_id
        The investigation that was processed.
    status
        One of EMBEDDING_STATUSES.
    embedding_id
        The embedding identity; None when status is 'not_eligible'.
    token_usage
        Token counts and truncation flag for the document, when the model was
        consulted and its backend reports them; otherwise None.
    """

    investigation_id: str
    status: str
    embedding_id: Optional[str]
    token_usage: Optional[Any]

"""
incident-retrieval/embedding_pipeline.py

Phase 12.5: Embedding persistence for one investigation.

Drives the full path for a single investigation_id:
  fetch investigation -> fetch evidence -> derive signal -> build document ->
  eligibility -> identity guards -> embedding_id -> existing-row check ->
  token usage -> embed -> insert -> commit

The document text is taken from incident_document.build_incident_document()
and passed to the provider exactly as produced.  The same text is stored in
document_text.

Outcomes (returned as EmbeddingOutcome.status):
    inserted         a new row was stored
    already_present  a row with this identity exists with the same text
    not_eligible     confidence is INSUFFICIENT_DATA; nothing embedded
    text_mismatch    a row with this identity exists with different text;
                     it is left untouched

The existing-row check runs before the model is used, so a repeated call for
an investigation that is already embedded does no model work.

Truncation never blocks an embedding.  When the provider's backend exposes
token_usage(), its result is returned in the outcome.

Transaction semantics
---------------------
embed_investigation() owns exactly one transaction on the supplied
connection: it commits when it returns an outcome (including outcomes that
write nothing, so the connection is not left in an open transaction) and
rolls back before re-raising on any error.  The caller opens and closes the
connection.

This module contains no SQL; database access goes through embedding_store.

Out of scope: backfill over many investigations, retrieval, similarity
search.

Public API:
    InvestigationNotFoundError  — investigation_id not in rca_investigations
    embed_investigation()       — run the pipeline for one investigation_id
"""

from __future__ import annotations

from typing import Any, Optional

import embedding_store
from embedding_provider import EmbeddingProvider
from embedding_record import (
    STATUS_ALREADY_PRESENT,
    STATUS_INSERTED,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
    EmbeddingOutcome,
    compute_embedding_id,
)
from incident_document import DOC_VERSION, build_incident_document
from incident_signal import derive_signal


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class InvestigationNotFoundError(ValueError):
    """Raised when the requested investigation_id does not exist in the database."""

    def __init__(self, investigation_id: str) -> None:
        super().__init__(f"Investigation not found: {investigation_id!r}")
        self.investigation_id = investigation_id


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _token_usage(provider: EmbeddingProvider, text: str) -> Optional[Any]:
    """Token usage from the provider's backend, or None if it has none."""
    usage_fn = getattr(provider.backend, "token_usage", None)
    if not callable(usage_fn):
        return None
    return usage_fn(text)


def _existing_row_outcome(
    investigation_id: str,
    embedding_id: str,
    stored_text: str,
    document_text: str,
    token_usage: Optional[Any],
) -> EmbeddingOutcome:
    """Classify an existing row by comparing its stored text exactly."""
    status = (
        STATUS_ALREADY_PRESENT if stored_text == document_text
        else STATUS_TEXT_MISMATCH
    )
    return EmbeddingOutcome(
        investigation_id=investigation_id,
        status=status,
        embedding_id=embedding_id,
        token_usage=token_usage,
    )


def _run(
    conn: Any,
    provider: EmbeddingProvider,
    investigation_id: str,
) -> EmbeddingOutcome:
    # 1. Fetch investigation
    investigation = embedding_store.fetch_investigation(conn, investigation_id)
    if investigation is None:
        raise InvestigationNotFoundError(investigation_id)

    # 2. Fetch evidence
    evidence = embedding_store.fetch_evidence(conn, investigation_id)

    # 3. Derive signal and build the document
    signal = derive_signal(investigation.anomaly_type, investigation.operation_name)
    document = build_incident_document(
        investigation, evidence, derived_signal=signal,
    )

    # 4. Eligibility
    if not document.eligible:
        return EmbeddingOutcome(
            investigation_id=investigation_id,
            status=STATUS_NOT_ELIGIBLE,
            embedding_id=None,
            token_usage=None,
        )

    # 5. Identity guards
    identity = provider.identity
    if identity.dimension != embedding_store.EMBEDDING_COLUMN_DIMENSION:
        raise RuntimeError(
            f"provider dimension is {identity.dimension!r}; the embedding "
            f"column requires {embedding_store.EMBEDDING_COLUMN_DIMENSION}"
        )
    if document.doc_version != DOC_VERSION:
        raise RuntimeError(
            f"document doc_version is {document.doc_version!r}; "
            f"expected {DOC_VERSION!r}"
        )

    # 6. Embedding identity
    embedding_id = compute_embedding_id(
        investigation_id,
        document.doc_version,
        identity.model_name,
        identity.model_revision,
    )

    # 7. Existing row: no model work
    stored_text = embedding_store.fetch_stored_document_text(conn, embedding_id)
    if stored_text is not None:
        return _existing_row_outcome(
            investigation_id, embedding_id, stored_text, document.text, None,
        )

    # 8. Token usage (never blocks)
    token_usage = _token_usage(provider, document.text)

    # 9. Embed the document text exactly as produced
    vector = provider.embed(document.text)

    # 10. Insert; first-write-wins
    inserted = embedding_store.insert_embedding(
        conn,
        embedding_id=embedding_id,
        investigation_id=investigation_id,
        doc_version=document.doc_version,
        model_name=identity.model_name,
        model_revision=identity.model_revision,
        document_text=document.text,
        vector=vector,
    )
    if not inserted:
        # A concurrent writer stored the row between the check and the insert.
        stored_text = embedding_store.fetch_stored_document_text(conn, embedding_id)
        if stored_text is None:
            raise RuntimeError(
                "insert reported an existing embedding, but no row was found "
                f"for embedding_id {embedding_id!r}"
            )
        return _existing_row_outcome(
            investigation_id, embedding_id, stored_text, document.text, token_usage,
        )

    return EmbeddingOutcome(
        investigation_id=investigation_id,
        status=STATUS_INSERTED,
        embedding_id=embedding_id,
        token_usage=token_usage,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def embed_investigation(
    conn: Any,
    provider: EmbeddingProvider,
    investigation_id: str,
) -> EmbeddingOutcome:
    """
    Build, embed, and persist the incident document of one investigation.

    Parameters
    ----------
    conn
        Open psycopg connection for the incident_retrieval role.  The caller
        owns the connection lifecycle; this function does NOT close it.  The
        function commits the current transaction when it returns and rolls it
        back on any error.
    provider
        Embedding provider.  Its identity supplies model_name and
        model_revision for the stored row.
    investigation_id
        Primary key of the investigation in public.rca_investigations.

    Returns
    -------
    EmbeddingOutcome
        status is 'inserted', 'already_present', 'not_eligible', or
        'text_mismatch'.

    Raises
    ------
    InvestigationNotFoundError
        investigation_id does not exist.
    ValueError
        investigation_id is not a non-empty str; or the stored investigation
        or evidence data is rejected by the document builder; or the provider
        rejects its input or its backend's output.
    RuntimeError
        The provider's dimension does not match the embedding column; the
        document's doc_version is not DOC_VERSION; or the model could not be
        loaded.
    psycopg.Error
        On any database error.

    The transaction is rolled back before any exception propagates.
    """
    if not isinstance(investigation_id, str) or investigation_id.strip() == "":
        raise ValueError("investigation_id must be a non-empty str")

    try:
        outcome = _run(conn, provider, investigation_id)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return outcome

"""
incident-retrieval/similarity_search.py

Phase 12.6: Semantic retrieval for one investigation.

Answers: "Which previous investigations look operationally similar to this
investigation?"  A similarity score describes how alike two incident
documents are.  It is not evidence about the cause of either incident, and
this module draws no conclusion from it.  The RCA analyzer remains the
authoritative evidence-based analysis.

Flow for one investigation_id:
  validate inputs -> fetch investigation -> fetch evidence -> derive signal ->
  build document -> eligibility -> identity guards -> query embedding_id ->
  stored-text check -> similarity query -> validate rows -> outcome

Query embedding
---------------
The query vector is the investigation's ALREADY STORED embedding for the
given model identity and DOC_VERSION.  Nothing is embedded here: no model is
loaded and no provider is called.  Before the stored embedding is used, its
stored document_text is compared with the canonical document built now, so a
stale embedding is never used as a query.

Outcomes (returned as RetrievalOutcome.status):
    ok                  matches holds the ranked results; it may be empty
    not_eligible        confidence is INSUFFICIENT_DATA; nothing queried
    query_not_embedded  no stored embedding for this investigation and
                        identity; nothing queried
    text_mismatch       the stored embedding's text differs from the
                        canonical document; nothing queried

Ranking
-------
Ranking is done by the database: cosine distance ASC, then investigation_id
ASC.  The order returned is preserved as-is; results are never re-sorted and
similarity is never rounded.  There is no similarity threshold.

top_k
-----
DEFAULT_TOP_K = 5, MIN_TOP_K = 1, MAX_TOP_K = 50.  A value outside that range,
or one that is not an int, raises ValueError; it is never clamped.

Read-only
---------
This module performs SELECTs only, through embedding_store.  It never
writes, never commits, and never rolls back: the caller owns the connection
and its transaction, including cleanup after an error.

This module contains no SQL and does not import a database driver.

Out of scope: embedding generation, persistence, backfill, thresholds,
presentation of historical context.

Public API:
    DEFAULT_TOP_K, MIN_TOP_K, MAX_TOP_K
    STATUS_OK, STATUS_NOT_ELIGIBLE, STATUS_QUERY_NOT_EMBEDDED,
    STATUS_TEXT_MISMATCH, RETRIEVAL_STATUSES
    SimilarInvestigation           — one ranked match (frozen dataclass)
    RetrievalOutcome               — result of one retrieval (frozen dataclass)
    find_similar_investigations()  — run retrieval for one investigation_id
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Optional, Sequence

import embedding_store
from embedding_pipeline import InvestigationNotFoundError
from embedding_provider import EmbeddingModelIdentity
from embedding_record import (
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
    compute_embedding_id,
)
from incident_document import DOC_VERSION, build_incident_document
from incident_signal import derive_signal


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TOP_K: int = 5
MIN_TOP_K: int = 1
MAX_TOP_K: int = 50

#: Retrieval ran; matches holds the ranked results (possibly none).
STATUS_OK: str = "ok"

#: The investigation is eligible but has no stored embedding for this
#: model identity and DOC_VERSION.
STATUS_QUERY_NOT_EMBEDDED: str = "query_not_embedded"

RETRIEVAL_STATUSES: frozenset[str] = frozenset({
    STATUS_OK,
    STATUS_NOT_ELIGIBLE,
    STATUS_QUERY_NOT_EMBEDDED,
    STATUS_TEXT_MISMATCH,
})

# Cosine similarity lies in [-1, 1].  Stored vectors are float4, so a value
# computed from them can fall outside by rounding error only.
_SIMILARITY_TOLERANCE: float = 1e-6


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SimilarInvestigation:
    """
    One historical investigation and its similarity to the query.

    similarity is raw cosine similarity (1.0 - cosine distance) between the
    two stored embeddings.  It measures document likeness only.
    """

    investigation_id: str
    similarity: float


@dataclass(frozen=True)
class RetrievalOutcome:
    """
    Outcome of one find_similar_investigations() call.

    Attributes
    ----------
    investigation_id
        The query investigation.
    status
        One of RETRIEVAL_STATUSES.
    embedding_id
        Identity of the query embedding; None when status is 'not_eligible'.
    top_k
        The requested maximum number of matches.
    matches
        Ranked matches, most similar first.  Empty unless status is 'ok';
        may also be empty when status is 'ok'.
    """

    investigation_id: str
    status: str
    embedding_id: Optional[str]
    top_k: int
    matches: tuple[SimilarInvestigation, ...]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_top_k(top_k: int) -> int:
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise ValueError(f"top_k must be int, got {type(top_k).__name__}")
    if not MIN_TOP_K <= top_k <= MAX_TOP_K:
        raise ValueError(
            f"top_k must be between {MIN_TOP_K} and {MAX_TOP_K}, got {top_k}"
        )
    return top_k


def _validated_matches(
    rows: Sequence[Any],
    investigation_id: str,
    top_k: int,
) -> tuple[SimilarInvestigation, ...]:
    """
    Check the rows returned by the similarity query and convert them.

    The order of rows is preserved.  Raises RuntimeError when the result
    cannot be trusted; a non-finite similarity means a stored embedding is
    corrupt (for example a zero vector).
    """
    if not isinstance(rows, (list, tuple)):
        raise RuntimeError(
            f"similarity query returned {type(rows).__name__}, expected a list"
        )
    if len(rows) > top_k:
        raise RuntimeError(
            f"similarity query returned {len(rows)} rows for top_k={top_k}"
        )

    matches: list[SimilarInvestigation] = []
    seen: set[str] = set()
    for position, row in enumerate(rows):
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            raise RuntimeError(
                f"similarity row {position} is malformed: expected "
                "(investigation_id, similarity)"
            )
        match_id, similarity = row

        if not isinstance(match_id, str) or match_id.strip() == "":
            raise RuntimeError(
                f"similarity row {position} has an invalid investigation_id"
            )
        if match_id == investigation_id:
            raise RuntimeError(
                "similarity query returned the query investigation itself"
            )
        if match_id in seen:
            raise RuntimeError(
                f"similarity query returned investigation {match_id!r} twice"
            )

        if isinstance(similarity, bool) or not isinstance(similarity, (int, float)):
            raise RuntimeError(
                f"similarity for investigation {match_id!r} must be a real "
                f"number, got {type(similarity).__name__}"
            )
        if isinstance(similarity, float) and not math.isfinite(similarity):
            raise RuntimeError(
                f"similarity for investigation {match_id!r} is not finite; "
                "a stored embedding is corrupt"
            )
        if abs(similarity) > 1.0 + _SIMILARITY_TOLERANCE:
            raise RuntimeError(
                f"similarity for investigation {match_id!r} is outside "
                f"[-1, 1]: {similarity!r}"
            )

        seen.add(match_id)
        matches.append(
            SimilarInvestigation(investigation_id=match_id, similarity=float(similarity))
        )
    return tuple(matches)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def find_similar_investigations(
    conn: Any,
    identity: EmbeddingModelIdentity,
    investigation_id: str,
    *,
    top_k: int = DEFAULT_TOP_K,
) -> RetrievalOutcome:
    """
    Find stored investigations whose incident documents are most similar.

    Parameters
    ----------
    conn
        Open psycopg connection for the incident_retrieval role.  The caller
        owns the connection and its transaction.  This function only reads;
        it never commits, rolls back, or closes the connection, on success or
        on error.
    identity
        The model identity whose embeddings are compared.  Only embeddings
        with this model_name and model_revision, and DOC_VERSION, take part.
        No embedding is generated.
    investigation_id
        Primary key of the query investigation in public.rca_investigations.
    top_k
        Maximum number of matches, MIN_TOP_K..MAX_TOP_K.  Default DEFAULT_TOP_K.

    Returns
    -------
    RetrievalOutcome
        status is 'ok', 'not_eligible', 'query_not_embedded', or
        'text_mismatch'.  matches is ordered most similar first and excludes
        the query investigation.

    Raises
    ------
    InvestigationNotFoundError
        investigation_id does not exist.
    ValueError
        investigation_id is not a non-empty str; top_k is not an int in
        range; identity is not an EmbeddingModelIdentity; or the stored
        investigation or evidence data is rejected by the document builder.
    RuntimeError
        identity.dimension does not match the embedding column; the
        document's doc_version is not DOC_VERSION; or the similarity query
        returned a malformed row, a non-finite or out-of-range similarity,
        too many rows, a duplicate, or the query investigation itself.
    psycopg.Error
        On any database error.  It propagates unchanged; transaction cleanup
        is left to the caller.
    """
    # 1-2. Validate inputs
    if not isinstance(investigation_id, str) or investigation_id.strip() == "":
        raise ValueError("investigation_id must be a non-empty str")
    top_k = _validate_top_k(top_k)
    if not isinstance(identity, EmbeddingModelIdentity):
        raise ValueError(
            "identity must be an EmbeddingModelIdentity, "
            f"got {type(identity).__name__}"
        )

    # 3-4. Fetch investigation
    investigation = embedding_store.fetch_investigation(conn, investigation_id)
    if investigation is None:
        raise InvestigationNotFoundError(investigation_id)

    # 5. Fetch evidence
    evidence = embedding_store.fetch_evidence(conn, investigation_id)

    # 6-7. Derive signal and build the canonical document
    signal = derive_signal(investigation.anomaly_type, investigation.operation_name)
    document = build_incident_document(
        investigation, evidence, derived_signal=signal,
    )

    # 8. Eligibility
    if not document.eligible:
        return RetrievalOutcome(
            investigation_id=investigation_id,
            status=STATUS_NOT_ELIGIBLE,
            embedding_id=None,
            top_k=top_k,
            matches=(),
        )

    # 9-10. Identity guards
    if identity.dimension != embedding_store.EMBEDDING_COLUMN_DIMENSION:
        raise RuntimeError(
            f"identity dimension is {identity.dimension!r}; the embedding "
            f"column requires {embedding_store.EMBEDDING_COLUMN_DIMENSION}"
        )
    if document.doc_version != DOC_VERSION:
        raise RuntimeError(
            f"document doc_version is {document.doc_version!r}; "
            f"expected {DOC_VERSION!r}"
        )

    # 11. Query embedding identity
    embedding_id = compute_embedding_id(
        investigation_id,
        document.doc_version,
        identity.model_name,
        identity.model_revision,
    )

    # 12-14. The stored embedding must exist and describe the same document
    stored_text = embedding_store.fetch_stored_document_text(conn, embedding_id)
    if stored_text is None:
        return RetrievalOutcome(
            investigation_id=investigation_id,
            status=STATUS_QUERY_NOT_EMBEDDED,
            embedding_id=embedding_id,
            top_k=top_k,
            matches=(),
        )
    if stored_text != document.text:
        return RetrievalOutcome(
            investigation_id=investigation_id,
            status=STATUS_TEXT_MISMATCH,
            embedding_id=embedding_id,
            top_k=top_k,
            matches=(),
        )

    # 15. Rank stored embeddings against the stored query embedding
    rows = embedding_store.fetch_similar_investigations(
        conn,
        query_embedding_id=embedding_id,
        investigation_id=investigation_id,
        doc_version=document.doc_version,
        model_name=identity.model_name,
        model_revision=identity.model_revision,
        top_k=top_k,
    )

    # 16-17. Validate and return, preserving database order
    return RetrievalOutcome(
        investigation_id=investigation_id,
        status=STATUS_OK,
        embedding_id=embedding_id,
        top_k=top_k,
        matches=_validated_matches(rows, investigation_id, top_k),
    )

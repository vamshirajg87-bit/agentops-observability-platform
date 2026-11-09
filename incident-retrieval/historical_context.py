"""
incident-retrieval/historical_context.py

Phase 12.7: Historical context for one investigation.

Presents existing, authoritative RCA data next to the semantic retrieval
result: the current investigation, its retrieval status, and for each
historically similar investigation its raw similarity and a few fields
recorded by the RCA analyzer.

Historical similarity provides context only.  It does not prove that the
current incident has the same root cause as any historical investigation.
This module performs no analysis of its own: it does not reason about causes,
does not generate text, and does not interpret the similarity value.  The RCA
analyzer remains the authoritative evidence-based analysis.

Flow:
  find_similar_investigations() -> one batch fetch of investigation context
  for the current investigation and every match -> validate -> result

Retrieval is delegated entirely to similarity_search.find_similar_investigations();
its status, embedding_id, top_k, similarity values and match order are passed
through unchanged.

Similarity
----------
similarity is the raw cosine similarity returned by retrieval.  It is not
rounded, not bucketed, not compared with a threshold, and not a confidence.
"confidence" in this module always means the confidence the RCA analyzer
recorded for that investigation.

Fail closed
-----------
If the context of the current investigation or of any match cannot be read,
or the returned rows are duplicated, unexpected, or malformed, RuntimeError
is raised.  A match is never silently dropped.

Read-only
---------
SELECTs only, through embedding_store.  This module never writes, never
commits, never rolls back, and never closes the connection: the caller owns
the connection and its transaction.

This module contains no SQL and does not import a database driver.  No model
is loaded.

Public API:
    HISTORICAL_CONTEXT_DISCLAIMER  — fixed statement shown with every result
    InvestigationContext           — RCA fields of one investigation (frozen)
    HistoricalMatch                — one match: similarity + context (frozen)
    HistoricalContext              — result of one call (frozen)
    get_historical_context()       — build the context for one investigation_id
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional, Sequence

import embedding_store
import similarity_search
from embedding_provider import EmbeddingModelIdentity
from similarity_search import DEFAULT_TOP_K


HISTORICAL_CONTEXT_DISCLAIMER: str = (
    "Historical similarity provides context only. It does not prove that the "
    "current incident has the same root cause as any historical investigation."
)

_CONTEXT_FIELDS: tuple[str, ...] = (
    "investigation_id",
    "anomaly_type",
    "service_name",
    "operation_name",
    "confidence",
    "severity",
    "event_time",
    "summary",
    "limitations",
)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvestigationContext:
    """
    Fields of one investigation as recorded by the RCA analyzer.

    Every value is taken unchanged from public.rca_investigations.
    """

    investigation_id: str
    anomaly_type: str
    service_name: Optional[str]
    operation_name: Optional[str]
    confidence: str
    severity: str
    event_time: datetime
    summary: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class HistoricalMatch:
    """
    One historically similar investigation.

    similarity is the raw cosine similarity returned by retrieval, unchanged.
    It measures how alike two incident documents are, nothing more.
    """

    similarity: float
    investigation: InvestigationContext


@dataclass(frozen=True)
class HistoricalContext:
    """
    Outcome of one get_historical_context() call.

    Attributes
    ----------
    status
        The retrieval status, unchanged: 'ok', 'not_eligible',
        'query_not_embedded', or 'text_mismatch'.
    embedding_id
        Identity of the query embedding, unchanged; None when not eligible.
    top_k
        The requested maximum number of matches.
    current
        The investigation that was looked up.
    matches
        Historical matches in the order retrieval returned them.  Empty
        unless status is 'ok'; may also be empty when status is 'ok'.
    disclaimer
        HISTORICAL_CONTEXT_DISCLAIMER.
    """

    status: str
    embedding_id: Optional[str]
    top_k: int
    current: InvestigationContext
    matches: tuple[HistoricalMatch, ...]
    disclaimer: str


# ---------------------------------------------------------------------------
# Row validation
# ---------------------------------------------------------------------------

def _required_str(row: Mapping[str, Any], field: str, investigation_id: str) -> str:
    value = row[field]
    if not isinstance(value, str) or value.strip() == "":
        raise RuntimeError(
            f"investigation {investigation_id!r} has an invalid {field}"
        )
    return value


def _optional_str(
    row: Mapping[str, Any], field: str, investigation_id: str,
) -> Optional[str]:
    value = row[field]
    if value is not None and not isinstance(value, str):
        raise RuntimeError(
            f"investigation {investigation_id!r} has an invalid {field}"
        )
    return value


def _row_to_context(row: Any) -> InvestigationContext:
    """Validate one stored row and convert it; RuntimeError when malformed."""
    if not isinstance(row, Mapping):
        raise RuntimeError(
            f"investigation context row is malformed: got {type(row).__name__}"
        )
    if set(row) != set(_CONTEXT_FIELDS):
        raise RuntimeError(
            "investigation context row is malformed: unexpected set of fields"
        )

    investigation_id = row["investigation_id"]
    if not isinstance(investigation_id, str) or investigation_id.strip() == "":
        raise RuntimeError("investigation context row has an invalid investigation_id")

    event_time = row["event_time"]
    if not isinstance(event_time, datetime):
        raise RuntimeError(
            f"investigation {investigation_id!r} has an invalid event_time"
        )

    summary = row["summary"]
    if not isinstance(summary, str):
        raise RuntimeError(
            f"investigation {investigation_id!r} has an invalid summary"
        )

    limitations = row["limitations"]
    if not isinstance(limitations, (list, tuple)) or not all(
        isinstance(item, str) for item in limitations
    ):
        raise RuntimeError(
            f"investigation {investigation_id!r} has invalid limitations"
        )

    return InvestigationContext(
        investigation_id=investigation_id,
        anomaly_type=_required_str(row, "anomaly_type", investigation_id),
        service_name=_optional_str(row, "service_name", investigation_id),
        operation_name=_optional_str(row, "operation_name", investigation_id),
        confidence=_required_str(row, "confidence", investigation_id),
        severity=_required_str(row, "severity", investigation_id),
        event_time=event_time,
        summary=summary,
        limitations=tuple(limitations),
    )


def _contexts_by_id(
    rows: Any,
    current_id: str,
    match_ids: Sequence[str],
) -> dict[str, InvestigationContext]:
    """
    Index the fetched rows by investigation_id and check they are exactly the
    investigations that were asked for.
    """
    if not isinstance(rows, (list, tuple)):
        raise RuntimeError(
            f"investigation context query returned {type(rows).__name__}, "
            "expected a list"
        )

    expected = {current_id, *match_ids}
    contexts: dict[str, InvestigationContext] = {}
    for row in rows:
        context = _row_to_context(row)
        if context.investigation_id not in expected:
            raise RuntimeError(
                "investigation context query returned an unexpected "
                f"investigation: {context.investigation_id!r}"
            )
        if context.investigation_id in contexts:
            raise RuntimeError(
                "investigation context query returned investigation "
                f"{context.investigation_id!r} twice"
            )
        contexts[context.investigation_id] = context

    if current_id not in contexts:
        raise RuntimeError(
            f"context of the current investigation {current_id!r} is missing"
        )
    for match_id in match_ids:
        if match_id not in contexts:
            raise RuntimeError(
                f"context of historical investigation {match_id!r} is missing"
            )
    return contexts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def get_historical_context(
    conn: Any,
    identity: EmbeddingModelIdentity,
    investigation_id: str,
    *,
    top_k: int = DEFAULT_TOP_K,
) -> HistoricalContext:
    """
    Retrieve similar historical investigations and their recorded RCA context.

    Parameters
    ----------
    conn
        Open psycopg connection for the incident_retrieval role.  The caller
        owns the connection and its transaction.  This function only reads;
        it never commits, rolls back, or closes the connection, on success or
        on error.
    identity
        The model identity whose stored embeddings are compared.  No
        embedding is generated and no model is loaded.
    investigation_id
        Primary key of the current investigation.
    top_k
        Maximum number of matches; validated by retrieval.

    Returns
    -------
    HistoricalContext
        status, embedding_id and top_k are those of retrieval.  matches keeps
        retrieval's order and similarity values exactly.

    Raises
    ------
    InvestigationNotFoundError
        investigation_id does not exist.
    ValueError
        Invalid investigation_id, top_k or identity, or stored data rejected
        by the document builder (all raised by retrieval).
    RuntimeError
        Retrieval's own integrity checks failed; or the context of the
        current investigation or of a match is missing, duplicated,
        unexpected, or malformed.
    psycopg.Error
        On any database error.  It propagates unchanged; transaction cleanup
        is left to the caller.
    """
    outcome = similarity_search.find_similar_investigations(
        conn, identity, investigation_id, top_k=top_k,
    )

    match_ids = [match.investigation_id for match in outcome.matches]
    rows = embedding_store.fetch_investigation_contexts(
        conn, [investigation_id, *match_ids],
    )
    contexts = _contexts_by_id(rows, investigation_id, match_ids)

    return HistoricalContext(
        status=outcome.status,
        embedding_id=outcome.embedding_id,
        top_k=outcome.top_k,
        current=contexts[investigation_id],
        matches=tuple(
            HistoricalMatch(
                similarity=match.similarity,
                investigation=contexts[match.investigation_id],
            )
            for match in outcome.matches
        ),
        disclaimer=HISTORICAL_CONTEXT_DISCLAIMER,
    )

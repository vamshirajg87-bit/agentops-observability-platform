"""
incident-retrieval/embedding_store.py

Phase 12.5: Database access for embedding persistence.
Phase 12.6: Similarity query over stored embeddings.

This module holds every SQL statement of the component.  It reads the
investigation and evidence fields that the incident document needs, writes
one row to public.rca_investigation_embeddings, and ranks stored embeddings
by cosine similarity to one stored query embedding.

Role
----
All statements run as the incident_retrieval role (migration 011) and use
only what that role is granted:

    public.rca_investigations            SELECT on selected columns
    public.rca_evidence                  SELECT on selected columns
    public.rca_investigation_embeddings  INSERT, SELECT

Idempotency
-----------
embedding rows:  ON CONFLICT (investigation_id, doc_version, model_name,
                 model_revision) DO NOTHING

First-write-wins: an existing row is never overwritten.  No UPDATE, no DELETE.

Transactions
------------
Functions here never commit or roll back.  The caller owns the transaction
and supplies an open connection, which it also closes.

SQL safety
----------
All values are %(name)s bound parameters.  No string interpolation.  Explicit
column lists.  No SELECT *.

The embedding is bound as text in pgvector's input format and cast with
::vector.  embedded_at is not supplied; the column has DEFAULT NOW().

Similarity query
----------------
The query vector is a stored row, referenced by its embedding_id inside the
statement; no vector is sent from Python.  Candidates must share the query's
doc_version, model_name, and model_revision, and the query's own
investigation is excluded.

    cosine distance    = candidate.embedding <=> query.embedding
    cosine similarity  = 1.0 - cosine distance

Ordering is cosine distance ASC, then investigation_id ASC.  The search is
exact; there is no similarity threshold.

Investigation context (Phase 12.7)
----------------------------------
One batch SELECT returns the presentation fields of several investigations
at once, so historical context needs a single query rather than one per
match.  Rows come back ordered by investigation_id; callers that need another
order look rows up by id.

Public API:
    EMBEDDING_COLUMN_DIMENSION      — dimension of the embedding column (384)
    fetch_investigation()           — one investigation, or None
    fetch_evidence()                — its evidence rows, rank_position ASC
    fetch_stored_document_text()    — document_text of an embedding, or None
    insert_embedding()              — insert one row; True if inserted
    fetch_similar_investigations()  — ranked (investigation_id, similarity)
    fetch_investigation_contexts()  — presentation fields for a set of ids
    fetch_investigation_ids()       — every investigation_id, ascending

Investigation discovery (Phase 12.8)
------------------------------------
fetch_investigation_ids() lists every investigation, ordered by
investigation_id.  It applies no eligibility filter: whether an investigation
is embedded is decided by the document builder, not by SQL.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

import psycopg
import psycopg.rows

from embedding_record import format_vector_literal
from incident_document import EvidenceRow, InvestigationRow


#: public.rca_investigation_embeddings.embedding is vector(384).
EMBEDDING_COLUMN_DIMENSION: int = 384


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_SQL_FETCH_INVESTIGATION = """\
SELECT
    investigation_id,
    anomaly_type,
    service_name,
    operation_name,
    confidence
FROM public.rca_investigations
WHERE investigation_id = %(investigation_id)s
"""

_SQL_FETCH_EVIDENCE = """\
SELECT
    investigation_id,
    rank_position,
    evidence_type,
    evidence_score,
    span_name,
    service_name,
    status_code,
    error_type,
    tool_name,
    tool_status,
    agent_name,
    agent_operation,
    retrieval_result_count,
    retrieval_top_relevance_score,
    is_direct_subject,
    is_root_span,
    trace_duration_fraction
FROM public.rca_evidence
WHERE investigation_id = %(investigation_id)s
ORDER BY rank_position ASC
"""

_SQL_FETCH_STORED_DOCUMENT_TEXT = """\
SELECT
    document_text
FROM public.rca_investigation_embeddings
WHERE embedding_id = %(embedding_id)s
"""

# embedded_at is intentionally absent: the column has DEFAULT NOW() and is
# set by the database server.
_SQL_INSERT_EMBEDDING = """\
INSERT INTO public.rca_investigation_embeddings (
    embedding_id,
    investigation_id,
    doc_version,
    model_name,
    model_revision,
    document_text,
    embedding
) VALUES (
    %(embedding_id)s,
    %(investigation_id)s,
    %(doc_version)s,
    %(model_name)s,
    %(model_revision)s,
    %(document_text)s,
    %(embedding)s::vector
) ON CONFLICT (investigation_id, doc_version, model_name, model_revision) DO NOTHING"""

# c = candidate rows, q = the stored query row.
# The q join is constrained to the same (doc_version, model_name,
# model_revision) as the candidate, so embeddings produced under different
# document contracts or models are never compared.
_SQL_FETCH_SIMILAR_INVESTIGATIONS = """\
SELECT
    c.investigation_id,
    1.0 - (c.embedding <=> q.embedding) AS similarity
FROM public.rca_investigation_embeddings AS c
JOIN public.rca_investigation_embeddings AS q
  ON q.embedding_id = %(query_embedding_id)s
 AND q.investigation_id = %(investigation_id)s
 AND q.doc_version = c.doc_version
 AND q.model_name = c.model_name
 AND q.model_revision = c.model_revision
WHERE c.doc_version = %(doc_version)s
  AND c.model_name = %(model_name)s
  AND c.model_revision = %(model_revision)s
  AND c.investigation_id <> %(investigation_id)s
ORDER BY c.embedding <=> q.embedding ASC, c.investigation_id ASC
LIMIT %(top_k)s
"""

_SQL_FETCH_INVESTIGATION_CONTEXTS = """\
SELECT
    investigation_id,
    anomaly_type,
    service_name,
    operation_name,
    confidence,
    severity,
    event_time,
    summary,
    limitations
FROM public.rca_investigations
WHERE investigation_id = ANY(%(investigation_ids)s)
ORDER BY investigation_id ASC
"""

_SQL_FETCH_INVESTIGATION_IDS = """\
SELECT investigation_id
FROM public.rca_investigations
ORDER BY investigation_id ASC
"""


# ---------------------------------------------------------------------------
# Row mappers
# ---------------------------------------------------------------------------

def _row_to_investigation(row: dict[str, Any]) -> InvestigationRow:
    """Map a psycopg dict_row from public.rca_investigations."""
    return InvestigationRow(
        investigation_id=row["investigation_id"],
        anomaly_type=row["anomaly_type"],
        service_name=row["service_name"],
        operation_name=row["operation_name"],
        confidence=row["confidence"],
    )


def _row_to_evidence(row: dict[str, Any]) -> EvidenceRow:
    """Map a psycopg dict_row from public.rca_evidence."""
    return EvidenceRow(
        investigation_id=row["investigation_id"],
        rank_position=row["rank_position"],
        evidence_type=row["evidence_type"],
        evidence_score=row["evidence_score"],
        span_name=row["span_name"],
        service_name=row["service_name"],
        status_code=row["status_code"],
        error_type=row["error_type"],
        tool_name=row["tool_name"],
        tool_status=row["tool_status"],
        agent_name=row["agent_name"],
        agent_operation=row["agent_operation"],
        retrieval_result_count=row["retrieval_result_count"],
        retrieval_top_relevance_score=row["retrieval_top_relevance_score"],
        is_direct_subject=row["is_direct_subject"],
        is_root_span=row["is_root_span"],
        trace_duration_fraction=row["trace_duration_fraction"],
    )


# ---------------------------------------------------------------------------
# Public query functions
# ---------------------------------------------------------------------------

def fetch_investigation(
    conn: psycopg.Connection,
    investigation_id: str,
) -> Optional[InvestigationRow]:
    """
    Fetch one investigation by investigation_id.

    Returns None if investigation_id does not exist.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_INVESTIGATION, {"investigation_id": investigation_id})
        row = cur.fetchone()

    if row is None:
        return None
    return _row_to_investigation(row)


def fetch_evidence(
    conn: psycopg.Connection,
    investigation_id: str,
) -> list[EvidenceRow]:
    """
    Fetch all evidence rows of an investigation, ordered rank_position ASC.

    Returns an empty list if the investigation has no evidence.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_EVIDENCE, {"investigation_id": investigation_id})
        rows = cur.fetchall()

    return [_row_to_evidence(row) for row in rows]


def fetch_stored_document_text(
    conn: psycopg.Connection,
    embedding_id: str,
) -> Optional[str]:
    """
    Return the document_text stored for embedding_id.

    Returns None if no embedding row with that embedding_id exists.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_STORED_DOCUMENT_TEXT, {"embedding_id": embedding_id})
        row = cur.fetchone()

    if row is None:
        return None
    return row["document_text"]


def insert_embedding(
    conn: psycopg.Connection,
    *,
    embedding_id: str,
    investigation_id: str,
    doc_version: str,
    model_name: str,
    model_revision: str,
    document_text: str,
    vector: Sequence[float],
) -> bool:
    """
    Insert one embedding row; first-write-wins.

    Returns True if the row was inserted, False if a row with the same
    (investigation_id, doc_version, model_name, model_revision) already
    existed, in which case nothing is changed.

    Does not commit.

    Raises:
        ValueError     if vector does not have EMBEDDING_COLUMN_DIMENSION
                       elements or holds a non-numeric or non-finite value.
                       Raised before any SQL is executed.
        psycopg.Error  on any database error.
    """
    if len(vector) != EMBEDDING_COLUMN_DIMENSION:
        raise ValueError(
            f"vector must have {EMBEDDING_COLUMN_DIMENSION} elements, "
            f"got {len(vector)}"
        )
    params = {
        "embedding_id": embedding_id,
        "investigation_id": investigation_id,
        "doc_version": doc_version,
        "model_name": model_name,
        "model_revision": model_revision,
        "document_text": document_text,
        "embedding": format_vector_literal(vector),
    }
    with conn.cursor() as cur:
        cur.execute(_SQL_INSERT_EMBEDDING, params)
        return cur.rowcount == 1


def fetch_similar_investigations(
    conn: psycopg.Connection,
    *,
    query_embedding_id: str,
    investigation_id: str,
    doc_version: str,
    model_name: str,
    model_revision: str,
    top_k: int,
) -> list[tuple[Any, Any]]:
    """
    Rank stored embeddings by cosine similarity to one stored query embedding.

    The query vector is the row identified by query_embedding_id, which must
    belong to investigation_id.  Candidates share the given doc_version,
    model_name, and model_revision; investigation_id itself is excluded.

    Returns (investigation_id, similarity) pairs in database order: cosine
    distance ASC, then investigation_id ASC, at most top_k of them.  Returns
    an empty list when there is no other compatible embedding, or when the
    query row does not exist.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    params = {
        "query_embedding_id": query_embedding_id,
        "investigation_id": investigation_id,
        "doc_version": doc_version,
        "model_name": model_name,
        "model_revision": model_revision,
        "top_k": top_k,
    }
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_SIMILAR_INVESTIGATIONS, params)
        rows = cur.fetchall()

    return [(row["investigation_id"], row["similarity"]) for row in rows]


def fetch_investigation_contexts(
    conn: psycopg.Connection,
    investigation_ids: Sequence[str],
) -> list[dict[str, Any]]:
    """
    Fetch the presentation fields of several investigations in one query.

    Returns one dict per investigation found, with the keys
    investigation_id, anomaly_type, service_name, operation_name, confidence,
    severity, event_time, summary, limitations, ordered investigation_id ASC.
    Ids that do not exist are simply absent from the result; the caller
    decides whether that is an error.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    params = {"investigation_ids": list(investigation_ids)}
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_INVESTIGATION_CONTEXTS, params)
        rows = cur.fetchall()

    return [dict(row) for row in rows]


def fetch_investigation_ids(conn: psycopg.Connection) -> list[Any]:
    """
    List the investigation_id of every investigation, ordered ASC.

    No eligibility filter is applied; investigations that must not be
    embedded are included and are classified by the caller's pipeline.

    Read-only.  Does not commit or roll back.

    Raises:
        psycopg.Error  on any database error.
    """
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(_SQL_FETCH_INVESTIGATION_IDS)
        rows = cur.fetchall()

    return [row["investigation_id"] for row in rows]

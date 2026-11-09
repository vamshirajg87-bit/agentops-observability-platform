"""
incident-retrieval/embedding_backfill.py

Phase 12.8: Embedding backfill over existing investigations.

Runs the single-investigation pipeline (embedding_pipeline.embed_investigation)
for every investigation in the database, in investigation_id order.  The
pipeline itself is reused unchanged; this module only discovers the
investigations, calls it for each one, and records what happened.

Discovery
---------
Every investigation is discovered, with no eligibility filter.  Whether an
investigation is embedded is decided by the pipeline: an INSUFFICIENT_DATA
investigation is processed and reported as 'not_eligible'.

Statuses (BackfillResult.status):
    inserted         a new embedding row was stored
    already_present  the embedding already exists with the same text
    not_eligible     the investigation must not be embedded
    text_mismatch    an embedding exists with different text; left untouched
    failure          the pipeline raised ValueError or RuntimeError for this
                     investigation; the error is recorded

A backfill succeeded only when there is no 'failure' and no 'text_mismatch'.

Failure policy
--------------
ValueError and RuntimeError raised for one investigation are recorded and the
backfill continues with the next investigation.  Any other exception — a
database error in particular — and KeyboardInterrupt are not caught: they
stop the backfill immediately and propagate to the caller.

Transactions
------------
Each investigation is its own transaction, owned by embed_investigation():
it commits when it returns and rolls back before re-raising.  A failure never
undoes an earlier investigation.  The read-only discovery query is ended with
a rollback before the loop starts, so no transaction spans investigations.
This module never commits and never closes the connection.

Idempotency
-----------
A rerun stores nothing new: every investigation embedded earlier is reported
as 'already_present'.  The pipeline checks for the existing row before it
uses the model, so a rerun with nothing to do does not load the model.

Nothing is ever overwritten, updated, or deleted.

This module contains no SQL and does not import a database driver.

Public API:
    STATUS_FAILURE, BACKFILL_STATUSES
    BackfillResult         — what happened for one investigation (frozen)
    BackfillReport         — all results, with counts (frozen)
    backfill_embeddings()  — run the backfill
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

import embedding_pipeline
import embedding_store
from embedding_provider import EmbeddingProvider
from embedding_record import (
    EMBEDDING_STATUSES,
    STATUS_ALREADY_PRESENT,
    STATUS_INSERTED,
    STATUS_NOT_ELIGIBLE,
    STATUS_TEXT_MISMATCH,
)


#: The pipeline raised ValueError or RuntimeError for this investigation.
STATUS_FAILURE: str = "failure"

BACKFILL_STATUSES: frozenset[str] = frozenset(EMBEDDING_STATUSES | {STATUS_FAILURE})


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackfillResult:
    """
    What happened for one investigation.

    Attributes
    ----------
    investigation_id
        The investigation that was processed.
    status
        One of BACKFILL_STATUSES.
    embedding_id
        The embedding identity when the pipeline computed one; otherwise None.
    token_usage
        Token counts and truncation flag reported by the pipeline, or None.
    error
        "<ExceptionType>: <message>" when status is 'failure'; otherwise None.
    """

    investigation_id: Any
    status: str
    embedding_id: Optional[str]
    token_usage: Optional[Any]
    error: Optional[str]


@dataclass(frozen=True)
class BackfillReport:
    """
    Outcome of one backfill_embeddings() call.

    results holds one BackfillResult per discovered investigation, in the
    order they were processed (investigation_id ascending).
    """

    results: tuple[BackfillResult, ...]

    def count(self, status: str) -> int:
        """Number of results with the given status."""
        return sum(1 for result in self.results if result.status == status)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def inserted(self) -> int:
        return self.count(STATUS_INSERTED)

    @property
    def already_present(self) -> int:
        return self.count(STATUS_ALREADY_PRESENT)

    @property
    def not_eligible(self) -> int:
        return self.count(STATUS_NOT_ELIGIBLE)

    @property
    def text_mismatch(self) -> int:
        return self.count(STATUS_TEXT_MISMATCH)

    @property
    def failures(self) -> int:
        return self.count(STATUS_FAILURE)

    @property
    def succeeded(self) -> bool:
        """True when nothing failed and no stored text mismatched."""
        return self.failures == 0 and self.text_mismatch == 0


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _process(
    conn: Any,
    provider: EmbeddingProvider,
    investigation_id: Any,
) -> BackfillResult:
    """Run the pipeline for one investigation and record the outcome."""
    try:
        outcome = embedding_pipeline.embed_investigation(
            conn, provider, investigation_id,
        )
        if outcome.status not in EMBEDDING_STATUSES:
            raise RuntimeError(f"unknown pipeline status: {outcome.status!r}")
    except (ValueError, RuntimeError) as exc:
        return BackfillResult(
            investigation_id=investigation_id,
            status=STATUS_FAILURE,
            embedding_id=None,
            token_usage=None,
            error=f"{type(exc).__name__}: {exc}",
        )

    return BackfillResult(
        investigation_id=investigation_id,
        status=outcome.status,
        embedding_id=outcome.embedding_id,
        token_usage=outcome.token_usage,
        error=None,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def backfill_embeddings(
    conn: Any,
    provider: EmbeddingProvider,
    *,
    on_result: Optional[Callable[[BackfillResult], None]] = None,
) -> BackfillReport:
    """
    Embed and persist every investigation that does not have an embedding yet.

    Parameters
    ----------
    conn
        Open psycopg connection for the incident_retrieval role.  The caller
        owns the connection lifecycle; this function does NOT close it.  Each
        investigation is committed or rolled back by embed_investigation().
        The connection must not carry uncommitted work of the caller: the
        discovery transaction is ended with a rollback.
    provider
        Embedding provider.  It is used only for investigations that need a
        new embedding.
    on_result
        Optional callback invoked with each BackfillResult as soon as it is
        known, in processing order.

    Returns
    -------
    BackfillReport
        One result per investigation, in investigation_id order.

    Raises
    ------
    psycopg.Error
        On any database error, during discovery or for any investigation.
        The backfill stops; investigations processed earlier stay committed.
    KeyboardInterrupt
        Not caught; the backfill stops.

    ValueError and RuntimeError raised for a single investigation are not
    propagated; they are recorded as a 'failure' result.
    """
    investigation_ids = embedding_store.fetch_investigation_ids(conn)

    # End the read-only discovery transaction so that every investigation
    # runs in a transaction of its own.
    conn.rollback()

    results: list[BackfillResult] = []
    for investigation_id in investigation_ids:
        result = _process(conn, provider, investigation_id)
        results.append(result)
        if on_result is not None:
            on_result(result)

    return BackfillReport(results=tuple(results))

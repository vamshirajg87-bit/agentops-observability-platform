"""
rca-analyzer/rca_persist.py

Phase 11.5: Persistence boundary for RCA investigations and evidence.

Accepts fully-computed, scored, and ranked RCA results (RCAResult from
rca_models) and writes them atomically to:

    public.rca_investigations  — one row per (anomaly_id, analyzer_version)
    public.rca_evidence        — one row per span per investigation

Idempotency
-----------
investigation rows:  ON CONFLICT (investigation_id) DO NOTHING
evidence rows:       ON CONFLICT (investigation_id, span_id) DO NOTHING

First-write-wins: the first successful write is authoritative.  No UPDATE,
no DELETE, no UPSERT that overwrites.  A repeated call for the same
investigation is a safe no-op that leaves all existing data unchanged.

Partial-state repair
--------------------
If a prior write inserted the investigation row but some evidence rows
are missing (e.g., from manual intervention or an abnormal partial state),
a repeat call will skip the investigation row (conflict) and insert only
the missing evidence rows.  Existing evidence rows are left untouched.

Transaction semantics
---------------------
persist_investigation() owns exactly one logical transaction:
    BEGIN → INSERT investigation → INSERT evidence rows → COMMIT
    On any error: ROLLBACK, then re-raise

The caller supplies an open connection (via rca_db.connect()) and is
responsible for closing it after the call returns.  persist_investigation()
does NOT open or close the connection.

INSUFFICIENT_DATA
-----------------
Results with confidence == 'INSUFFICIENT_DATA' and an empty all_evidence
tuple are persisted normally.  The investigation row is inserted; zero
evidence rows are inserted.

SQL safety
----------
All values are %(name)s bound parameters.  No string interpolation.
No f-string SQL values.  Explicit column lists.  No SELECT *.
No UPDATE.  No DELETE.

No database access, no I/O beyond the supplied connection.

Public API:
    compute_investigation_id()  — pure: (anomaly_id, analyzer_version) → SHA-256 hex
    PersistenceResult           — frozen dataclass: outcome of one persist call
    persist_investigation()     — atomic investigation + evidence write
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import psycopg

from rca_models import RCAResult, SpanEvidence


# ---------------------------------------------------------------------------
# Investigation identity
# ---------------------------------------------------------------------------

def compute_investigation_id(anomaly_id: str, analyzer_version: str) -> str:
    """
    Deterministic 64-character SHA-256 hex investigation identity.

    Payload: UTF-8 encoding of "{anomaly_id}|{analyzer_version}".

    The "|" separator prevents ambiguous concatenation so that:
        ("ab", "c")  → "ab|c"   produces a different digest than
        ("a",  "bc") → "a|bc"

    Args:
        anomaly_id:       from public.anomaly_events.anomaly_id
        analyzer_version: from rca_version.RCA_ANALYZER_VERSION

    Returns:
        64 lowercase hexadecimal characters (full SHA-256 digest).
    """
    payload = f"{anomaly_id}|{analyzer_version}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

# investigated_at is intentionally absent: the column has DEFAULT NOW() and
# is set by the database server, not by the Python layer.
_INSERT_INVESTIGATION_SQL = """\
INSERT INTO public.rca_investigations (
    investigation_id,
    anomaly_id,
    analyzer_version,
    trace_id,
    subject_span_id,
    service_name,
    operation_name,
    event_time,
    trace_span_count,
    anomaly_type,
    observed_value,
    baseline_median,
    anomaly_score,
    severity,
    confidence,
    summary,
    limitations
) VALUES (
    %(investigation_id)s,
    %(anomaly_id)s,
    %(analyzer_version)s,
    %(trace_id)s,
    %(subject_span_id)s,
    %(service_name)s,
    %(operation_name)s,
    %(event_time)s,
    %(trace_span_count)s,
    %(anomaly_type)s,
    %(observed_value)s,
    %(baseline_median)s,
    %(anomaly_score)s,
    %(severity)s,
    %(confidence)s,
    %(summary)s,
    %(limitations)s
) ON CONFLICT (investigation_id) DO NOTHING"""

# id is intentionally absent: it is a BIGSERIAL column set by the database.
# status_message, start_time, end_time from SpanEvidence are not stored in
# rca_evidence and are therefore absent.
_INSERT_EVIDENCE_SQL = """\
INSERT INTO public.rca_evidence (
    investigation_id,
    span_id,
    parent_span_id,
    span_name,
    service_name,
    duration_ms,
    status_code,
    error_type,
    error_message,
    tool_name,
    tool_status,
    agent_name,
    agent_operation,
    retrieval_result_count,
    retrieval_top_relevance_score,
    is_root_span,
    is_error_span,
    is_direct_subject,
    depth,
    trace_duration_fraction,
    evidence_type,
    evidence_score,
    evidence_score_breakdown,
    explanation,
    rank_position
) VALUES (
    %(investigation_id)s,
    %(span_id)s,
    %(parent_span_id)s,
    %(span_name)s,
    %(service_name)s,
    %(duration_ms)s,
    %(status_code)s,
    %(error_type)s,
    %(error_message)s,
    %(tool_name)s,
    %(tool_status)s,
    %(agent_name)s,
    %(agent_operation)s,
    %(retrieval_result_count)s,
    %(retrieval_top_relevance_score)s,
    %(is_root_span)s,
    %(is_error_span)s,
    %(is_direct_subject)s,
    %(depth)s,
    %(trace_duration_fraction)s,
    %(evidence_type)s,
    %(evidence_score)s,
    %(evidence_score_breakdown)s,
    %(explanation)s,
    %(rank_position)s
) ON CONFLICT (investigation_id, span_id) DO NOTHING"""


# ---------------------------------------------------------------------------
# Parameter mapping (pure functions — no I/O)
# ---------------------------------------------------------------------------

def _investigation_params(result: RCAResult) -> dict:
    """
    Map RCAResult to INSERT parameter dict for public.rca_investigations.

    Columns not included:
        investigated_at  — DB DEFAULT NOW(); never supplied from Python.
        signal_name      — not in rca_investigations schema.
        detector_name    — not in rca_investigations schema.
        detector_version — not in rca_investigations schema.
        baseline_mad     — not in rca_investigations schema.
        baseline_n       — not in rca_investigations schema.
        detector_explanation — not in rca_investigations schema.
    """
    return {
        "investigation_id": result.investigation_id,
        "anomaly_id": result.anomaly_id,
        "analyzer_version": result.analyzer_version,
        "trace_id": result.trace_id,
        "subject_span_id": result.subject_span_id,
        "service_name": result.service_name,
        "operation_name": result.operation_name,
        "event_time": result.event_time,
        "trace_span_count": result.trace_span_count,
        "anomaly_type": result.anomaly_type,
        "observed_value": result.observed_value,
        "baseline_median": result.baseline_median,
        "anomaly_score": result.anomaly_score,
        "severity": result.severity,
        "confidence": result.confidence,
        "summary": result.summary,
        "limitations": list(result.limitations),  # tuple → list for TEXT[]
    }


def _evidence_params(
    investigation_id: str,
    evidence: SpanEvidence,
    rank_position: int,
) -> dict:
    """
    Map SpanEvidence to INSERT parameter dict for public.rca_evidence.

    rank_position is supplied externally as 1-based tuple index from
    the caller; it is not a field on SpanEvidence.

    Fields from SpanEvidence not mapped to DB:
        status_message — absent from rca_evidence table.
        start_time     — absent from rca_evidence table.
        end_time       — absent from rca_evidence table.
    """
    return {
        "investigation_id": investigation_id,
        "span_id": evidence.span_id,
        "parent_span_id": evidence.parent_span_id,
        "span_name": evidence.span_name,
        "service_name": evidence.service_name,
        "duration_ms": evidence.duration_ms,
        "status_code": evidence.status_code,
        "error_type": evidence.error_type,
        "error_message": evidence.error_message,
        "tool_name": evidence.tool_name,
        "tool_status": evidence.tool_status,
        "agent_name": evidence.agent_name,
        "agent_operation": evidence.agent_operation,
        "retrieval_result_count": evidence.retrieval_result_count,
        "retrieval_top_relevance_score": evidence.retrieval_top_relevance_score,
        "is_root_span": evidence.is_root_span,
        "is_error_span": evidence.is_error_span,
        "is_direct_subject": evidence.is_direct_subject,
        "depth": evidence.depth,
        "trace_duration_fraction": evidence.trace_duration_fraction,
        "evidence_type": evidence.evidence_type,
        "evidence_score": evidence.evidence_score,
        "evidence_score_breakdown": evidence.evidence_score_breakdown,
        "explanation": evidence.explanation,
        "rank_position": rank_position,
    }


# ---------------------------------------------------------------------------
# Return value
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PersistenceResult:
    """
    Outcome of one persist_investigation() call.

    Attributes
    ----------
    investigation_id
        The investigation's deterministic SHA-256 identity.
    investigation_inserted
        True  — investigation row was newly inserted.
        False — investigation_id already existed; row is unchanged.
    evidence_rows_inserted
        Number of evidence rows newly inserted this call.  May be less
        than len(result.all_evidence) when some rows already existed
        (partial-state repair path).
    """

    investigation_id: str
    investigation_inserted: bool
    evidence_rows_inserted: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _insert_investigation(conn: psycopg.Connection, result: RCAResult) -> bool:
    """Insert investigation row; return True if inserted, False if conflict."""
    params = _investigation_params(result)
    with conn.cursor() as cur:
        cur.execute(_INSERT_INVESTIGATION_SQL, params)
        return cur.rowcount == 1


def _insert_evidence_row(
    conn: psycopg.Connection,
    investigation_id: str,
    evidence: SpanEvidence,
    rank_position: int,
) -> bool:
    """Insert one evidence row; return True if inserted, False if conflict."""
    params = _evidence_params(investigation_id, evidence, rank_position)
    with conn.cursor() as cur:
        cur.execute(_INSERT_EVIDENCE_SQL, params)
        return cur.rowcount == 1


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def persist_investigation(
    conn: psycopg.Connection,
    result: RCAResult,
) -> PersistenceResult:
    """
    Atomically persist one RCA investigation and all its evidence spans.

    Writes to public.rca_investigations and public.rca_evidence in a
    single transaction.  Both tables use first-write-wins ON CONFLICT DO
    NOTHING semantics: existing rows are never overwritten.

    Parameters
    ----------
    conn
        Open psycopg connection for the rca_analyzer role.  The caller
        owns the connection lifecycle; this function does NOT close it.
        The function commits the current transaction on success and rolls
        it back on any error.

    result
        Fully computed RCAResult from Phase 11.4.  The all_evidence tuple
        order defines rank_position (1-based); the first element gets
        rank 1, the second gets rank 2, and so on.
        An empty all_evidence tuple (INSUFFICIENT_DATA) is valid.

    Returns
    -------
    PersistenceResult
        investigation_id, investigation_inserted, evidence_rows_inserted.

    Raises
    ------
    ValueError
        If result.investigation_id does not equal
        compute_investigation_id(result.anomaly_id, result.analyzer_version).
        Raised before any cursor is opened, any SQL is executed, and any
        transaction is started.  No commit, no rollback.
    psycopg.Error
        On any database error.  The transaction is rolled back before the
        exception propagates to the caller.
    """
    expected_id = compute_investigation_id(
        result.anomaly_id,
        result.analyzer_version,
    )
    if result.investigation_id != expected_id:
        raise ValueError(
            "RCAResult investigation_id does not match "
            "anomaly_id and analyzer_version"
        )

    try:
        investigation_inserted = _insert_investigation(conn, result)
        evidence_count = 0
        for rank, ev in enumerate(result.all_evidence, start=1):
            if _insert_evidence_row(conn, result.investigation_id, ev, rank):
                evidence_count += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return PersistenceResult(
        investigation_id=result.investigation_id,
        investigation_inserted=investigation_inserted,
        evidence_rows_inserted=evidence_count,
    )

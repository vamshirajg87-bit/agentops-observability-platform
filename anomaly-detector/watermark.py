"""
anomaly-detector/watermark.py

Checkpoint persistence for the Phase 10.5 anomaly detector runner.

Each (signal_path, service_name, operation_name) detection group has one
checkpoint row in public.anomaly_detector_runs.  The checkpoint_at column
holds the query_end of the last successfully committed runner invocation for
that group — not the query_start, which is always computed dynamically.

Public API
----------
    read_checkpoint()   — return the stored checkpoint_at, or None if absent
    write_checkpoint()  — forward-only UPSERT of checkpoint_at

Connection ownership
--------------------
This module does NOT open, commit, rollback, or close any database connection.
The caller supplies the connection and owns its full lifecycle:

    conn = db.connect()
    checkpoint = read_checkpoint(conn, ...)
    # ... run detection ...
    write_checkpoint(conn, ..., checkpoint_at=new_boundary)
    conn.commit()   # caller's responsibility
    conn.close()    # caller's responsibility

The write_checkpoint call participates in whatever transaction the caller
manages.  The checkpoint and the anomaly INSERTs it covers must be committed
atomically; that commit belongs to the runner, not here.

Forward-only semantics
----------------------
write_checkpoint uses an UPSERT with a WHERE clause on the conflict update:

    WHERE public.anomaly_detector_runs.checkpoint_at < EXCLUDED.checkpoint_at

This ensures:
  - First write inserts.
  - A newer checkpoint_at advances the stored value.
  - An identical checkpoint_at is a no-op (row unchanged).
  - An older checkpoint_at cannot rewind the stored value.

There is no rewind function.  Checkpoint resets needed for testing or operator
recovery must be performed by an admin role outside the anomaly_detector service.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import psycopg

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_READ_SQL = """\
SELECT checkpoint_at
FROM public.anomaly_detector_runs
WHERE signal_path    = %(signal_path)s
  AND service_name   = %(service_name)s
  AND operation_name = %(operation_name)s"""

_WRITE_SQL = """\
INSERT INTO public.anomaly_detector_runs
    (signal_path, service_name, operation_name, checkpoint_at, updated_at)
VALUES
    (%(signal_path)s, %(service_name)s, %(operation_name)s, %(checkpoint_at)s, NOW())
ON CONFLICT (signal_path, service_name, operation_name)
DO UPDATE SET
    checkpoint_at = EXCLUDED.checkpoint_at,
    updated_at    = NOW()
WHERE public.anomaly_detector_runs.checkpoint_at < EXCLUDED.checkpoint_at"""


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def read_checkpoint(
    conn: psycopg.Connection,
    signal_path: str,
    service_name: str,
    operation_name: Optional[str] = None,
) -> Optional[datetime]:
    """
    Return the stored checkpoint_at for the given detection group, or None.

    Args:
        conn:           Active psycopg connection (caller-owned lifecycle).
        signal_path:    Signal path key (e.g. 'trace_latency').
        service_name:   Service name for the detection group.
        operation_name: Operation name; None is normalised to '' (canonical
                        representation for paths that carry no operation_name).

    Returns:
        checkpoint_at as a timezone-aware datetime if a checkpoint row exists,
        or None if no checkpoint has been written for this group yet.
    """
    op = operation_name if operation_name is not None else ""
    params = {
        "signal_path": signal_path,
        "service_name": service_name,
        "operation_name": op,
    }
    with conn.cursor() as cur:
        cur.execute(_READ_SQL, params)
        row = cur.fetchone()
    return None if row is None else row[0]


def write_checkpoint(
    conn: psycopg.Connection,
    signal_path: str,
    service_name: str,
    operation_name: Optional[str],
    checkpoint_at: datetime,
) -> None:
    """
    Persist or advance the checkpoint for the given detection group.

    Uses a forward-only UPSERT: the stored checkpoint_at only moves forward.
    An identical or older checkpoint_at value produces no database mutation.

    Args:
        conn:           Active psycopg connection (caller-owned lifecycle).
        signal_path:    Signal path key (e.g. 'trace_latency').
        service_name:   Service name for the detection group.
        operation_name: Operation name; None is normalised to '' (canonical
                        representation for paths that carry no operation_name).
        checkpoint_at:  The query_end of the successfully committed run.
                        Must be timezone-aware.
    """
    if checkpoint_at.tzinfo is None:
        raise ValueError(
            f"checkpoint_at must be timezone-aware; got naive datetime {checkpoint_at!r}. "
            "A checkpoint represents an absolute processing boundary and must be an "
            "unambiguous instant. Attach a timezone (e.g. datetime.timezone.utc) before "
            "calling write_checkpoint()."
        )
    if checkpoint_at.utcoffset() is None:
        raise ValueError(
            f"checkpoint_at.tzinfo is set but utcoffset() returned None "
            f"(tzinfo={checkpoint_at.tzinfo!r}). The timezone object does not resolve to "
            "an unambiguous UTC offset. Use a concrete timezone such as datetime.timezone.utc "
            "or a pytz/zoneinfo zone that carries a deterministic offset."
        )
    op = operation_name if operation_name is not None else ""
    params = {
        "signal_path": signal_path,
        "service_name": service_name,
        "operation_name": op,
        "checkpoint_at": checkpoint_at,
    }
    with conn.cursor() as cur:
        cur.execute(_WRITE_SQL, params)

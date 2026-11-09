"""
anomaly-detector/anomaly_repository.py

Deterministic anomaly ID generation, AnomalyEvent → DB parameter mapping,
and INSERT-only persistence for public.anomaly_events.

Public API:
    compute_anomaly_id()    — pure function: AnomalyEvent → 64-char SHA-256 hex
    anomaly_to_db_params()  — pure function: AnomalyEvent → INSERT parameter dict
    AnomalyRepository       — INSERT-only persistence wrapper around psycopg conn

Rerun semantics
---------------
A rerun may recompute different baseline statistics, anomaly_score, severity,
or explanation for the same logical event.  Because anomaly_id is derived from
logical event identity only (not from result fields), ON CONFLICT DO NOTHING
ensures the FIRST persisted observation wins.  The existing row is never
overwritten.  If detector-run history is needed in future, model it as a
separate run/evaluation table rather than mutating anomaly_events.

No checkpoint semantics
-----------------------
anomaly_events records detected anomalies.  It does NOT prove that
non-anomalous observations were evaluated.  Processing checkpoints and
watermarks are separate concerns out of scope for Phase 10.

Connection ownership
--------------------
AnomalyRepository does NOT create, commit, or close the supplied connection.
The caller owns the full lifecycle:
    conn = db.connect()
    repo = AnomalyRepository(conn)
    repo.save(event)
    conn.commit()   # caller's responsibility
    conn.close()    # caller's responsibility
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import psycopg

from detector.anomaly_types import AnomalyEvent

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_INSERT_SQL = """\
INSERT INTO public.anomaly_events (
    anomaly_id,
    anomaly_type,
    signal_name,
    detector_name,
    detector_version,
    trace_id,
    span_id,
    service_name,
    operation_name,
    observed_value,
    event_time,
    baseline_median,
    baseline_mad,
    baseline_n,
    baseline_window_start,
    baseline_window_end,
    anomaly_score,
    severity,
    explanation
) VALUES (
    %(anomaly_id)s,
    %(anomaly_type)s,
    %(signal_name)s,
    %(detector_name)s,
    %(detector_version)s,
    %(trace_id)s,
    %(span_id)s,
    %(service_name)s,
    %(operation_name)s,
    %(observed_value)s,
    %(event_time)s,
    %(baseline_median)s,
    %(baseline_mad)s,
    %(baseline_n)s,
    %(baseline_window_start)s,
    %(baseline_window_end)s,
    %(anomaly_score)s,
    %(severity)s,
    %(explanation)s
) ON CONFLICT (anomaly_id) DO NOTHING"""


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

#: Identity fields, in fixed order, used to compute anomaly_id.
#:
#: Logical event identity — fields that identify WHICH event occurred:
#:   detector_name    which detector class produced the event
#:   detector_version which version of that detector (version change = different contract)
#:   anomaly_type     the category of anomaly
#:   signal_name      the specific signal being monitored
#:   service_name     which service
#:   operation_name   which operation (includes error_type for tool_failure events)
#:   trace_id         which trace
#:   span_id          which span (None for trace-level LatencyDetector events)
#:   observed_at      UTC-normalized ISO-8601 timestamp of the original observation
#:
#: Fields deliberately excluded from identity (describe detection result, not the event):
#:   observed_value, baseline_median, baseline_mad, baseline_n,
#:   baseline_window_start, baseline_window_end, anomaly_score, severity, explanation
#:
#: Excluded fields may differ between reruns as the baseline window shifts; including
#: them would produce a new anomaly_id for the same logical event on rerun.
_IDENTITY_FIELDS = (
    "detector_name",
    "detector_version",
    "anomaly_type",
    "signal_name",
    "service_name",
    "operation_name",
    "trace_id",
    "span_id",
)


def compute_anomaly_id(event: AnomalyEvent) -> str:
    """
    Compute a deterministic 64-character SHA-256 hex anomaly ID.

    Identity is derived from the logical event fields listed in _IDENTITY_FIELDS
    plus observed_at (UTC-normalized).  Result fields (score, severity, baseline,
    explanation) are excluded so that rerun stability is preserved.

    Canonical encoding: compact JSON array of the identity values in fixed order,
    UTF-8 encoded.  None values encode as JSON null, which is distinct from "".
    observed_at is normalized to UTC via .astimezone(timezone.utc) before
    .isoformat() to ensure timezone-equivalent instants produce identical IDs.

    Args:
        event: AnomalyEvent produced by a Phase 10.3 detector.

    Returns:
        64 lowercase hexadecimal characters (full SHA-256 digest).

    Raises:
        ValueError: if event.observed_at is timezone-naive or has no defined UTC offset.
    """
    if event.observed_at.tzinfo is None or event.observed_at.utcoffset() is None:
        raise ValueError(
            f"observed_at must be timezone-aware with a defined UTC offset; "
            f"got: {event.observed_at!r}"
        )
    utc_ts = event.observed_at.astimezone(timezone.utc).isoformat()

    identity = [
        event.detector_name,
        event.detector_version,
        event.anomaly_type,
        event.signal_name,
        event.service_name,
        event.operation_name,
        event.trace_id,
        event.span_id,
        utc_ts,
    ]

    canonical = json.dumps(identity, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# DB parameter mapping
# ---------------------------------------------------------------------------

def anomaly_to_db_params(event: AnomalyEvent) -> dict[str, Any]:
    """
    Map an AnomalyEvent to the INSERT parameter dict for public.anomaly_events.

    Column mapping:
        AnomalyEvent.observed_at  → event_time   (field rename; no type change)
        AnomalyEvent.severity     → severity      (Severity enum → .value string)
        (computed)                → anomaly_id    (via compute_anomaly_id)
        (omitted)                 → detected_at   (DB DEFAULT NOW(); never from Python)

    No type coercions applied.  None values remain None.  Zero numeric values
    are preserved.  Timezone-aware datetime objects are passed through as-is
    for psycopg3 to handle TIMESTAMPTZ binding.

    Args:
        event: AnomalyEvent produced by a Phase 10.3 detector.

    Returns:
        Dict mapping %(name)s parameter names to values for _INSERT_SQL.

    Raises:
        ValueError: if event.observed_at is timezone-naive (propagated from
                    compute_anomaly_id).
    """
    return {
        "anomaly_id": compute_anomaly_id(event),
        "anomaly_type": event.anomaly_type,
        "signal_name": event.signal_name,
        "detector_name": event.detector_name,
        "detector_version": event.detector_version,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "service_name": event.service_name,
        "operation_name": event.operation_name,
        "observed_value": event.observed_value,
        "event_time": event.observed_at,
        "baseline_median": event.baseline_median,
        "baseline_mad": event.baseline_mad,
        "baseline_n": event.baseline_n,
        "baseline_window_start": event.baseline_window_start,
        "baseline_window_end": event.baseline_window_end,
        "anomaly_score": event.anomaly_score,
        "severity": event.severity.value,
        "explanation": event.explanation,
    }


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class AnomalyRepository:
    """
    INSERT-only repository for public.anomaly_events.

    Idempotency
    -----------
    Duplicate anomaly_ids are silently ignored via ON CONFLICT (anomaly_id) DO NOTHING.
    The first persisted row wins; reruns do not overwrite it.  save() returns False
    when the row already exists, True when it is newly inserted.

    Connection lifecycle
    --------------------
    The caller supplies the connection and is responsible for:
        conn.commit()  — after saving one or more events
        conn.close()   — when the connection is no longer needed

    AnomalyRepository does not commit, rollback, or close the supplied connection.
    save() participates in whatever transaction the caller manages.

    No SELECT before INSERT
    -----------------------
    The uniqueness constraint on anomaly_id is the sole idempotency mechanism.
    No SELECT-before-INSERT existence check is performed; that would be a TOCTOU
    race under concurrent writers.
    """

    def __init__(self, conn: psycopg.Connection) -> None:
        self._conn = conn

    def save(self, event: AnomalyEvent) -> bool:
        """
        Persist an AnomalyEvent to public.anomaly_events.

        Executes INSERT ... ON CONFLICT (anomaly_id) DO NOTHING.

        Args:
            event: AnomalyEvent to persist.

        Returns:
            True  — the row was inserted (new anomaly event).
            False — anomaly_id already existed; existing row is unchanged.

        Raises:
            ValueError: if event.observed_at is timezone-naive.
            psycopg.Error: for any other database error.
        """
        params = anomaly_to_db_params(event)
        with self._conn.cursor() as cur:
            cur.execute(_INSERT_SQL, params)
            return cur.rowcount == 1

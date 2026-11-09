"""
anomaly-detector/runner.py

Production runner that drives per-group anomaly detection above the existing
AnomalyOrchestrator layer.

Responsibilities
----------------
Configuration iteration → connection lifecycle → checkpoint read →
window computation → orchestrator dispatch → checkpoint write →
transaction commit/rollback → connection replacement → per-group/run results.

AnomalyOrchestrator already owns: query, row mapping, candidate/history split,
detector invocation, and anomaly persistence.  This module does not duplicate
those responsibilities.

Single-runner concurrency contract
------------------------------------
SINGLE-RUNNER ONLY.  No two invocations of run_all_groups should process the
same configured groups concurrently.  The forward-only checkpoint and
deterministic anomaly IDs provide idempotency for reruns (at-least-once
evaluation is safe), but do NOT make the runner generally concurrency-safe
under simultaneous execution.  No advisory locking or distributed locking is
implemented.

Three-boundary window model
-----------------------------
query_end     — captured once as a UTC wall-clock instant before the group
                loop; every group in the run uses the same query_end.

First run (no prior checkpoint):
    candidate_after = query_end  -  initial_lookback_hours
    history_start   = candidate_after  -  history_days_for(signal_path)

Subsequent run:
    candidate_after = prior_checkpoint  -  overlap_minutes
    history_start   = candidate_after  -  history_days_for(signal_path)

Passed to the orchestrator for each group:
    window_start    = history_start       (SQL fetch lower bound)
    window_end      = query_end           (SQL fetch upper bound)
    candidate_after = candidate_after     (candidate eligibility cutoff)

SQL fetch interval:      [history_start, query_end)
Candidate interval:      [candidate_after, query_end)
Checkpoint after commit: query_end

Transaction contract
---------------------
Each group is processed in its own database transaction (autocommit=False):

    read_checkpoint()       — participates in the group transaction
    → window computation
    → orchestrator.run_*()  — anomaly INSERTs are NOT committed here
    → write_checkpoint()    — NOT committed here
    → conn.commit()         — ALL of the above commit atomically

If any step before commit raises, conn.rollback() is attempted and the group
result carries status="error".  The checkpoint does not advance on error.

Uncertain commit outcome
-------------------------
If conn.commit() raises, the durable outcome is UNKNOWN from the application
perspective.  The runner records status="uncertain" and does not advance the
checkpoint.  Future reruns are safe because anomaly IDs are deterministic
(ON CONFLICT DO NOTHING) and checkpoint writes are forward-only.

Connection factory / replacement
----------------------------------
The caller supplies connect_fn.  The runner owns every connection it creates.
If a connection becomes unusable (rollback fails after any error), the runner
closes the dead connection best-effort and calls connect_fn() again.  A new
AnomalyRepository and AnomalyOrchestrator are constructed from the replacement
connection.  If reconnection fails, the run terminates early and
RunResult.completed_all_groups is False.

Public API
----------
    RunGroupResult    — frozen dataclass; result for one detection group
    RunResult         — frozen dataclass; result for the full run
    run_all_groups    — entry point
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import psycopg

from anomaly_repository import AnomalyRepository
from orchestrator import AnomalyOrchestrator, OrchestrationResult
from run_config import GroupConfig, RunConfig
from watermark import read_checkpoint, write_checkpoint


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunGroupResult:
    """
    Immutable result for one (signal_path, service_name, operation_name) group.

    Window fields
    -------------
    history_start and candidate_after are None only when failure occurred
    before window computation (e.g. read_checkpoint raised).  query_end is
    always populated because it is captured before the group loop.

    Count semantics
    ---------------
    candidate_count and anomaly_events_* reflect the orchestrator's reported
    totals.  For status "uncertain" or "error" these counts are NOT guaranteed
    to be durable in the database — the underlying transaction may not have
    committed.

    Status semantics
    ----------------
    "ok"        — commit returned successfully; checkpoint_advanced=True;
                  new_checkpoint=query_end.
    "uncertain" — commit raised; checkpoint_advanced=False; new_checkpoint=None;
                  durable outcome is unknown; counts are preserved from the
                  orchestrator result when available.
    "error"     — failure before confirmed commit; checkpoint_advanced=False;
                  new_checkpoint=None.
    """
    signal_path: str
    service_name: str
    operation_name: str

    history_start: Optional[datetime]
    candidate_after: Optional[datetime]
    query_end: datetime

    candidate_count: int
    anomaly_events_emitted: int
    anomaly_events_inserted: int
    anomaly_events_duplicate: int

    prior_checkpoint: Optional[datetime]
    new_checkpoint: Optional[datetime]

    checkpoint_advanced: bool

    duration_ms: float

    status: Literal["ok", "uncertain", "error"]
    error: Optional[str]


@dataclass(frozen=True)
class RunResult:
    """
    Immutable result for a complete run_all_groups invocation.

    Aggregate count semantics
    -------------------------
    total_candidates and total_anomalies_* are summed across all attempted
    group results, including groups whose transaction status is "uncertain" or
    "error".  These are observation/detection attempt totals, NOT
    guaranteed-durable database totals.

    Invariant: groups_ok + groups_uncertain + groups_error == groups_attempted.

    groups_attempted reflects only groups that were actually started.  Groups
    never reached due to an early terminal connection failure are not
    fabricated.

    Early-termination fields
    -------------------------
    completed_all_groups=False means the run stopped early because a
    replacement connection could not be obtained.  terminal_error carries the
    reason string.  group_results contains only the groups that were attempted.
    """
    run_start: datetime
    run_end: datetime

    groups_attempted: int
    groups_ok: int
    groups_uncertain: int
    groups_error: int

    total_candidates: int
    total_anomalies_emitted: int
    total_anomalies_inserted: int
    total_anomalies_duplicate: int

    group_results: tuple[RunGroupResult, ...]

    completed_all_groups: bool
    terminal_error: Optional[str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_all_groups(
    config: RunConfig,
    connect_fn: Callable[[], psycopg.Connection],
    *,
    now: Optional[datetime] = None,
) -> RunResult:
    """
    Process every configured detection group, committing each atomically.

    Args:
        config:     Validated runner configuration (from load_config).
        connect_fn: Callable returning a new psycopg.Connection with
                    autocommit=False.  Called once at startup; called again
                    whenever a dead connection must be replaced.  If the
                    initial call raises, the exception propagates immediately
                    and no group results are fabricated.
        now:        Deterministic query_end injection for tests.  Must be
                    timezone-aware if provided; normalised to UTC internally.
                    Production callers omit this parameter.

    Returns:
        RunResult summarising all attempted groups.

    Raises:
        Exception: propagated from the initial connect_fn() call.
        ValueError: if now is a naive datetime or its utcoffset() is None.
    """
    query_end = _resolve_query_end(now)
    run_start = datetime.now(timezone.utc)

    # Initial connection — fail loudly; caller receives the raw exception.
    conn = connect_fn()
    repository = AnomalyRepository(conn)
    orchestrator = AnomalyOrchestrator(conn, repository)

    group_results: list[RunGroupResult] = []
    completed_all_groups = True
    terminal_error: Optional[str] = None

    for group in config.groups:
        t0 = time.perf_counter()
        orch_result: Optional[OrchestrationResult] = None
        commit_attempted = False
        prior_checkpoint: Optional[datetime] = None
        candidate_after: Optional[datetime] = None
        history_start: Optional[datetime] = None

        try:
            prior_checkpoint = read_checkpoint(
                conn,
                group.signal_path,
                group.service_name,
                group.operation_name,
            )
            candidate_after = _compute_candidate_after(prior_checkpoint, query_end, config)
            history_days = orchestrator.history_days_for(group.signal_path)
            history_start = _compute_history_start(candidate_after, history_days)

            orch_result = _dispatch(
                orchestrator, group, history_start, query_end, candidate_after
            )

            write_checkpoint(
                conn,
                group.signal_path,
                group.service_name,
                group.operation_name,
                query_end,
            )

            commit_attempted = True
            conn.commit()

            duration_ms = (time.perf_counter() - t0) * 1000.0
            group_results.append(RunGroupResult(
                signal_path=group.signal_path,
                service_name=group.service_name,
                operation_name=group.operation_name,
                history_start=history_start,
                candidate_after=candidate_after,
                query_end=query_end,
                candidate_count=orch_result.processed_observations,
                anomaly_events_emitted=orch_result.detected_anomalies,
                anomaly_events_inserted=orch_result.inserted_anomalies,
                anomaly_events_duplicate=orch_result.duplicate_anomalies,
                prior_checkpoint=prior_checkpoint,
                new_checkpoint=query_end,
                checkpoint_advanced=True,
                duration_ms=duration_ms,
                status="ok",
                error=None,
            ))

        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            # commit_attempted distinguishes uncertain (commit raised) from
            # error (failure before commit was attempted).
            status: Literal["ok", "uncertain", "error"] = (
                "uncertain" if commit_attempted else "error"
            )

            rollback_failed = False
            try:
                conn.rollback()
            except Exception:
                rollback_failed = True

            group_results.append(RunGroupResult(
                signal_path=group.signal_path,
                service_name=group.service_name,
                operation_name=group.operation_name,
                history_start=history_start,
                candidate_after=candidate_after,
                query_end=query_end,
                candidate_count=(
                    orch_result.processed_observations if orch_result is not None else 0
                ),
                anomaly_events_emitted=(
                    orch_result.detected_anomalies if orch_result is not None else 0
                ),
                anomaly_events_inserted=(
                    orch_result.inserted_anomalies if orch_result is not None else 0
                ),
                anomaly_events_duplicate=(
                    orch_result.duplicate_anomalies if orch_result is not None else 0
                ),
                prior_checkpoint=prior_checkpoint,
                new_checkpoint=None,
                checkpoint_advanced=False,
                duration_ms=duration_ms,
                status=status,
                error=str(exc),
            ))

            if rollback_failed:
                # Connection is dead.  Close best-effort and replace it.
                try:
                    conn.close()
                except Exception:
                    pass

                try:
                    conn = connect_fn()
                    repository = AnomalyRepository(conn)
                    orchestrator = AnomalyOrchestrator(conn, repository)
                except Exception as reconnect_exc:
                    completed_all_groups = False
                    terminal_error = (
                        f"Replacement connection failed after group "
                        f"({group.signal_path!r}, {group.service_name!r}): "
                        f"{reconnect_exc}"
                    )
                    break

    # Close the final active connection.  A double-close of a dead connection
    # (already closed during rollback_failed handling) is caught and ignored.
    try:
        conn.close()
    except Exception:
        pass

    run_end = datetime.now(timezone.utc)

    n_ok = sum(1 for r in group_results if r.status == "ok")
    n_uncertain = sum(1 for r in group_results if r.status == "uncertain")
    n_error = sum(1 for r in group_results if r.status == "error")

    return RunResult(
        run_start=run_start,
        run_end=run_end,
        groups_attempted=len(group_results),
        groups_ok=n_ok,
        groups_uncertain=n_uncertain,
        groups_error=n_error,
        total_candidates=sum(r.candidate_count for r in group_results),
        total_anomalies_emitted=sum(r.anomaly_events_emitted for r in group_results),
        total_anomalies_inserted=sum(r.anomaly_events_inserted for r in group_results),
        total_anomalies_duplicate=sum(r.anomaly_events_duplicate for r in group_results),
        group_results=tuple(group_results),
        completed_all_groups=completed_all_groups,
        terminal_error=terminal_error,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_query_end(now: Optional[datetime]) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError(
            f"now must be a timezone-aware datetime; got a naive datetime: {now!r}. "
            "Attach a timezone (e.g. datetime.timezone.utc) before calling "
            "run_all_groups()."
        )
    if now.utcoffset() is None:
        raise ValueError(
            f"now.tzinfo is set but utcoffset() returned None "
            f"(tzinfo={now.tzinfo!r}). "
            "Use a concrete timezone such as datetime.timezone.utc."
        )
    return now.astimezone(timezone.utc)


def _compute_candidate_after(
    prior_checkpoint: Optional[datetime],
    query_end: datetime,
    config: RunConfig,
) -> datetime:
    if prior_checkpoint is None:
        return query_end - timedelta(hours=config.initial_lookback_hours)
    return prior_checkpoint - timedelta(minutes=config.overlap_minutes)


def _compute_history_start(candidate_after: datetime, history_days: int) -> datetime:
    return candidate_after - timedelta(days=history_days)


def _dispatch(
    orchestrator: AnomalyOrchestrator,
    group: GroupConfig,
    history_start: datetime,
    query_end: datetime,
    candidate_after: datetime,
) -> OrchestrationResult:
    sp = group.signal_path
    if sp == "trace_latency":
        return orchestrator.run_trace_latency(
            group.service_name,
            group.operation_name,
            history_start,
            query_end,
            candidate_after=candidate_after,
        )
    if sp == "agent_latency":
        return orchestrator.run_agent_latency(
            group.service_name,
            group.operation_name,
            history_start,
            query_end,
            candidate_after=candidate_after,
        )
    if sp == "tool_latency":
        return orchestrator.run_tool_latency(
            group.service_name,
            history_start,
            query_end,
            candidate_after=candidate_after,
        )
    if sp == "retrieval":
        return orchestrator.run_retrieval(
            group.service_name,
            history_start,
            query_end,
            candidate_after=candidate_after,
        )
    if sp == "error_rate":
        return orchestrator.run_error_rate(
            group.service_name,
            group.operation_name,
            history_start,
            query_end,
            candidate_after=candidate_after,
        )
    if sp == "tool_failure":
        return orchestrator.run_tool_failure(
            group.service_name,
            history_start,
            query_end,
            candidate_after=candidate_after,
        )
    raise ValueError(
        f"Unknown signal_path {sp!r}; valid paths: "
        f"{sorted(['agent_latency', 'error_rate', 'retrieval', 'tool_failure', 'tool_latency', 'trace_latency'])}"
    )

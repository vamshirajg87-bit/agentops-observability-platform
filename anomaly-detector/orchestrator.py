"""
anomaly-detector/orchestrator.py

Application-service layer connecting Phase 10.4C telemetry queries and record
mapping, Phase 10.3 concrete detectors, and Phase 10.4D anomaly persistence.

One call to a run_* method:
    1. Fetches telemetry rows for the requested window via a query function.
    2. Maps each row to the typed detector record.
    3. For every candidate record as current, calls detector.detect(current, history)
       where history = {records with start_time strictly less than current.start_time}.
    4. Persists each produced AnomalyEvent via AnomalyRepository.save().
    5. Returns a deterministic OrchestrationResult summary.

History rule
------------
    history = [r for r in records if r.start_time < current.start_time]

Records with identical start_time are contemporaneous; neither appears in the
other's history.  SQL ORDER BY tie-breakers (trace_id, span_id) govern
iteration order only and are never used to establish temporal precedence.

candidate_after (Phase 10.5)
----------------------------
All run_* methods accept an optional keyword argument candidate_after.

When supplied, records fetched from [window_start, window_end) are split:

    history-only  : start_time < candidate_after
    candidates    : start_time >= candidate_after

History-only records contribute to baselines but are never passed as current
to detector.detect().  This allows the runner to widen window_start to include
baseline context without re-evaluating already-processed observations.

When candidate_after is None (the default), all records are candidates and
behavior is identical to the locked Phase 10.4E implementation.

No scheduling, checkpointing, watermarks, or runner behavior is implemented
here.  Those concerns belong to Phase 10.5.

Connection / transaction ownership
-----------------------------------
AnomalyOrchestrator does NOT commit, rollback, or close the supplied
connection.  The caller owns the full lifecycle:
    conn = db.connect()
    repo = AnomalyRepository(conn)
    orch = AnomalyOrchestrator(conn, repo)
    result = orch.run_trace_latency(...)
    conn.commit()   # caller's responsibility
    conn.close()    # caller's responsibility
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import psycopg

from anomaly_repository import AnomalyRepository
from detector.anomaly_types import AnomalyEvent, ErrorDetectorConfig
from detector.config import DetectorConfig
from detector.error_rate_detector import ErrorRateDetector
from detector.latency_detector import LatencyDetector
from detector.retrieval_detector import RetrievalQualityDetector
from detector.tool_failure_detector import ToolFailureDetector
from record_mapper import (
    row_to_error_record,
    row_to_retrieval_record,
    row_to_span_latency_record,
    row_to_tool_record,
    row_to_trace_latency_record,
)
from telemetry_queries import (
    fetch_agent_latency_history,
    fetch_error_rate_history,
    fetch_retrieval_history,
    fetch_tool_failure_history,
    fetch_tool_latency_history,
    fetch_trace_latency_history,
)


@dataclass(frozen=True)
class OrchestrationResult:
    """
    Immutable summary of one orchestration invocation.

    Invariant: inserted_anomalies + duplicate_anomalies == detected_anomalies
    processed_observations counts candidate records only (start_time >= candidate_after
    when candidate_after is supplied; all records otherwise).
    """
    processed_observations: int
    detected_anomalies: int
    inserted_anomalies: int
    duplicate_anomalies: int


class AnomalyOrchestrator:
    """
    Deterministic orchestration layer for one telemetry signal path per call.

    Each run_* method executes the full pipeline for its signal path and returns
    an OrchestrationResult.  The same window may be run multiple times safely:
    duplicate AnomalyEvents are silently skipped by the repository's
    ON CONFLICT DO NOTHING semantics.
    """

    def __init__(
        self,
        conn: psycopg.Connection,
        repository: AnomalyRepository,
        *,
        trace_latency_config: Optional[DetectorConfig] = None,
        agent_latency_config: Optional[DetectorConfig] = None,
        tool_latency_config: Optional[DetectorConfig] = None,
        retrieval_relevance_config: Optional[DetectorConfig] = None,
        retrieval_count_config: Optional[DetectorConfig] = None,
        error_rate_config: Optional[ErrorDetectorConfig] = None,
        tool_failure_config: Optional[ErrorDetectorConfig] = None,
    ) -> None:
        self._conn = conn
        self._repository = repository
        # Three independent LatencyDetector instances — trace, agent, and tool
        # latency operate at different grains and may require different practical
        # deviation floors in production.
        self._trace_latency_detector = LatencyDetector(trace_latency_config)
        self._agent_latency_detector = LatencyDetector(agent_latency_config)
        self._tool_latency_detector = LatencyDetector(tool_latency_config)
        self._retrieval_detector = RetrievalQualityDetector(
            retrieval_relevance_config, retrieval_count_config
        )
        self._error_rate_detector = ErrorRateDetector(error_rate_config)
        self._tool_failure_detector = ToolFailureDetector(tool_failure_config)

    # ------------------------------------------------------------------
    # Public run methods — one per signal path
    # ------------------------------------------------------------------

    def run_trace_latency(
        self,
        service_name: str,
        operation_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        rows = fetch_trace_latency_history(
            self._conn,
            service_name=service_name,
            operation_name=operation_name,
            window_start=window_start,
            window_end=window_end,
        )
        return self._orchestrate(
            rows, row_to_trace_latency_record, self._trace_latency_detector,
            candidate_after=candidate_after,
        )

    def run_agent_latency(
        self,
        service_name: str,
        operation_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        rows = fetch_agent_latency_history(
            self._conn,
            service_name=service_name,
            operation_name=operation_name,
            window_start=window_start,
            window_end=window_end,
        )
        return self._orchestrate(
            rows, row_to_span_latency_record, self._agent_latency_detector,
            candidate_after=candidate_after,
        )

    def run_tool_latency(
        self,
        service_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        rows = fetch_tool_latency_history(
            self._conn,
            service_name=service_name,
            window_start=window_start,
            window_end=window_end,
        )
        return self._orchestrate(
            rows, row_to_span_latency_record, self._tool_latency_detector,
            candidate_after=candidate_after,
        )

    def run_retrieval(
        self,
        service_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        rows = fetch_retrieval_history(
            self._conn,
            service_name=service_name,
            window_start=window_start,
            window_end=window_end,
        )
        return self._orchestrate(
            rows, row_to_retrieval_record, self._retrieval_detector,
            candidate_after=candidate_after,
        )

    def run_error_rate(
        self,
        service_name: str,
        operation_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        rows = fetch_error_rate_history(
            self._conn,
            service_name=service_name,
            operation_name=operation_name,
            window_start=window_start,
            window_end=window_end,
        )
        return self._orchestrate(
            rows, row_to_error_record, self._error_rate_detector,
            candidate_after=candidate_after,
        )

    def run_tool_failure(
        self,
        service_name: str,
        window_start: datetime,
        window_end: datetime,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        rows = fetch_tool_failure_history(
            self._conn,
            service_name=service_name,
            window_start=window_start,
            window_end=window_end,
        )
        return self._orchestrate(
            rows, row_to_tool_record, self._tool_failure_detector,
            candidate_after=candidate_after,
        )

    # ------------------------------------------------------------------
    # Public query methods
    # ------------------------------------------------------------------

    def history_days_for(self, signal_path: str) -> int:
        """
        Return the configured baseline_window_days for the detector used by
        signal_path.  The runner uses this to compute how far before
        evaluation_start it must query in order to supply sufficient baseline
        context to each candidate observation.

        For 'retrieval', returns the maximum of the relevance and count
        detector configs because both signals must have full baseline coverage.

        Raises ValueError for unknown signal_path values so that callers fail
        loudly rather than silently querying an insufficient history window.
        """
        _table = {
            "trace_latency": self._trace_latency_detector.config.baseline_window_days,
            "agent_latency": self._agent_latency_detector.config.baseline_window_days,
            "tool_latency":  self._tool_latency_detector.config.baseline_window_days,
            "retrieval": max(
                self._retrieval_detector.relevance_config.baseline_window_days,
                self._retrieval_detector.count_config.baseline_window_days,
            ),
            "error_rate":    self._error_rate_detector.config.baseline_window_days,
            "tool_failure":  self._tool_failure_detector.config.baseline_window_days,
        }
        if signal_path not in _table:
            raise ValueError(
                f"unknown signal_path {signal_path!r}; "
                f"valid paths: {sorted(_table)}"
            )
        return _table[signal_path]

    # ------------------------------------------------------------------
    # Private orchestration core
    # ------------------------------------------------------------------

    def _orchestrate(
        self,
        rows: list[dict[str, Any]],
        mapper: Callable[[Mapping[str, Any]], Any],
        detector: Any,
        *,
        candidate_after: Optional[datetime] = None,
    ) -> OrchestrationResult:
        """
        Map rows to records, evaluate candidates against prior-timestamp history,
        persist produced anomalies, and return a summary.

        History contract: history = [r for r in records if r.start_time < current.start_time]
        Records with equal start_time are contemporaneous; neither is in the other's history.

        candidate_after: when set, records with start_time < candidate_after contribute
        to baselines but are never passed as current to detector.detect().  Records
        with start_time >= candidate_after are candidates.  When None, all records are
        candidates — identical to locked Phase 10.4E behavior.
        processed_observations counts candidates only.
        """
        records = [mapper(row) for row in rows]

        candidates = (
            records
            if candidate_after is None
            else [r for r in records if r.start_time >= candidate_after]
        )

        detected = 0
        inserted = 0
        duplicate = 0

        for current in candidates:
            history = [r for r in records if r.start_time < current.start_time]
            events: list[AnomalyEvent] = detector.detect(current, history)
            detected += len(events)
            for event in events:
                if self._repository.save(event):
                    inserted += 1
                else:
                    duplicate += 1

        return OrchestrationResult(
            processed_observations=len(candidates),
            detected_anomalies=detected,
            inserted_anomalies=inserted,
            duplicate_anomalies=duplicate,
        )

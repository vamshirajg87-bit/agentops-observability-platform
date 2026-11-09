from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .severity import Severity


@dataclass(frozen=True)
class AnomalyEvent:
    """
    Immutable, self-auditable anomaly record.

    Every field needed to reconstruct the detection decision is present so that
    callers can log, deduplicate, or replay without contacting the detector again.
    No database IDs, UUIDs, or persistence logic live here; those belong to
    Phase 10.4.
    """
    anomaly_type: str           # "latency" | "retrieval_quality" | "error_rate" | "tool_failure"
    signal_name: str            # e.g. "duration_ms", "retrieval_top_relevance_score"
    detector_name: str          # class name of the producing detector
    detector_version: str       # "1.0"

    # Subject identity
    trace_id: Optional[str]
    span_id: Optional[str]
    service_name: Optional[str]
    operation_name: Optional[str]   # group key in human-readable form

    # Signal evidence
    observed_value: float
    observed_at: datetime

    # Baseline evidence (all present or all None for error-rate signals)
    baseline_median: Optional[float]
    baseline_mad: Optional[float]
    baseline_n: Optional[int]
    baseline_window_start: Optional[datetime]
    baseline_window_end: Optional[datetime]

    # Score evidence
    anomaly_score: Optional[float]  # modified z-score for continuous; rate_ratio for error; None for zero-MAD

    # Verdict
    severity: Severity

    # Human-readable evidence (no causal claims)
    explanation: str


# ---------------------------------------------------------------------------
# Input record types
# These are plain frozen dataclasses populated by Phase 10.4 from the mart
# queries.  Field names match the mart column names where applicable.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LatencyRecord:
    """One latency observation; can represent a trace, agent span, tool span, or retrieval span."""
    trace_id: str
    span_id: Optional[str]      # None for trace-level records
    service_name: str
    operation_name: str         # group key; e.g. "trace", "research/plan", "tool.execute"
    duration_ms: float
    start_time: datetime
    is_error: bool              # derived from status_code='ERROR'


@dataclass(frozen=True)
class RetrievalRecord:
    """One retrieval span observation."""
    trace_id: str
    span_id: str
    service_name: str
    retrieval_top_relevance_score: Optional[float]  # None when not instrumented
    retrieval_result_count: Optional[int]           # 0 is valid; None means absent
    start_time: datetime
    is_error: bool


@dataclass(frozen=True)
class ErrorRecord:
    """One span observation used for error-rate analysis."""
    trace_id: str
    span_id: str
    service_name: str
    operation_name: str     # span_name; used as the group key
    is_error: bool
    error_type: Optional[str]   # populated on ERROR spans
    start_time: datetime


@dataclass(frozen=True)
class ToolRecord:
    """One tool.execute span observation.  tool_name is absent (NULL on error spans)."""
    trace_id: str
    span_id: str
    service_name: str
    is_error: bool
    error_type: Optional[str]   # populated on ERROR spans; None on successful spans
    start_time: datetime


# ---------------------------------------------------------------------------
# Config for error-rate detectors
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ErrorDetectorConfig:
    """
    Configuration shared by ErrorRateDetector and ToolFailureDetector.

    recent_window_hours
        Defines the "recent" period: [current.start_time - hours, current.start_time).
    baseline_window_days
        Total lookback window: [current.start_time - days, current.start_time - hours).
    persistence_k
        Number of consecutive tail observations that must all be errors for the
        is_persistent flag to fire.  Applied to the entire observation history
        (not limited to the baseline window).
    """
    recent_window_hours: int = 24
    baseline_window_days: int = 7
    persistence_k: int = 5
    min_sample_for_info: int = 10
    min_sample_for_warning: int = 30

    def __post_init__(self) -> None:
        if self.recent_window_hours < 1:
            raise ValueError("recent_window_hours must be >= 1")
        if self.baseline_window_days < 1:
            raise ValueError("baseline_window_days must be >= 1")
        if self.persistence_k < 1:
            raise ValueError("persistence_k must be >= 1")
        if self.min_sample_for_info < 1:
            raise ValueError("min_sample_for_info must be >= 1")
        if self.min_sample_for_warning < self.min_sample_for_info:
            raise ValueError(
                "min_sample_for_warning must be >= min_sample_for_info"
            )

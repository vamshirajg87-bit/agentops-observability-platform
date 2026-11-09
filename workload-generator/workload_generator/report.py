"""
workload_generator/report.py

Metrics of a PLAN, as a text summary and as JSON.

A PlanReport describes what was planned and nothing else: no count of
completed requests, no span count, no throughput, no measured latency.

An ExecutionReport is a separate thing, produced only when a plan was really
executed.  It holds what the driver itself did and observed, including what
its local exporter returned.  It makes no statement about anything
downstream of that exporter.

Standard library only.  This module knows nothing of how a plan is executed.

Public API:
    PlanReport
    build_report()      Plan -> PlanReport
    plan_digest()       one SHA-256 over every planned request
    request_row()       one planned request as plain JSON-ready data
    format_summary()    the text printed after planning
    ExecutionReport, OUTCOMES, RUN_STATUSES
    format_execution()  the text printed after execution
    combined_dict()     plan report + execution report as one mapping
    write_report()      report(s) -> JSON file
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from . import __version__
from .personas import Persona
from .plan import Plan, PlannedFault, PlannedRequest
from .scenarios import Scenario

REPORT_KIND: str = "workload-plan"
REPORT_VERSION: int = 1

#: Planned requests shown in the text summary.
SAMPLE_SIZE: int = 5
_QUERY_WIDTH: int = 48


def _fault_row(fault: Optional[PlannedFault]) -> Optional[dict[str, str]]:
    if fault is None:
        return None
    return {
        "target": fault.target.value,
        "error_type": fault.error_type,
        "error_message": fault.error_message,
    }


def request_row(request: PlannedRequest) -> dict[str, Any]:
    """One planned request as plain data, with a fixed set of keys."""
    return {
        "request_index": request.request_index,
        "request_id": request.request_id,
        "session_id": request.session_id,
        "persona": request.persona.value,
        "scenario": request.scenario.value,
        "query": request.query,
        "arrival_offset_seconds": request.arrival_offset_seconds,
        "latency_ms": {
            "tool": request.latency.tool_ms,
            "retrieval": request.latency.retrieval_ms,
            "synthesis": request.latency.synthesis_ms,
        },
        "fault": _fault_row(request.fault),
        "retries": [
            {
                "attempt": retry.attempt,
                "request_id": retry.request_id,
                "backoff_seconds": retry.backoff_seconds,
                "fault": _fault_row(retry.fault),
            }
            for retry in request.retries
        ],
        "episode_id": request.episode_id,
        "retrieval_effect": (
            request.retrieval_effect.value if request.retrieval_effect is not None else None
        ),
    }


def plan_digest(plan: Plan) -> str:
    """
    SHA-256 over every planned request in order.  Two plans with the same
    digest are the same plan; it is what a repeated run is compared by.
    """
    digest = hashlib.sha256()
    for request in plan.requests:
        line = json.dumps(request_row(request), sort_keys=True, separators=(",", ":"))
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


@dataclass(frozen=True)
class PlanReport:
    """
    planned_requests is the number of first submissions and equals
    requested_traces.  planned_retries is the number of client
    resubmissions on top of them.  planned_duration_seconds is the arrival
    offset of the last first submission.
    """

    run_id: str
    seed: int
    mode: str
    scenario: str
    persona: str
    requested_traces: int
    planned_requests: int
    planned_retries: int
    planned_submissions: int
    planned_duration_seconds: float
    requested_rate: float
    concurrency: int
    max_duration_seconds: float
    sessions: int
    scenario_distribution: Mapping[str, int]
    persona_distribution: Mapping[str, int]
    planned_fault_distribution: Mapping[str, int]
    episodes: tuple[Mapping[str, Any], ...]
    plan_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "report": REPORT_KIND,
            "report_version": REPORT_VERSION,
            "generator_version": __version__,
            # Nothing in this report was measured: no request was sent.
            "executed": False,
            "run_id": self.run_id,
            "seed": self.seed,
            "mode": self.mode,
            "scenario": self.scenario,
            "persona": self.persona,
            "requested_traces": self.requested_traces,
            "planned_requests": self.planned_requests,
            "planned_retries": self.planned_retries,
            "planned_submissions": self.planned_submissions,
            "planned_duration_seconds": self.planned_duration_seconds,
            "requested_rate": self.requested_rate,
            "concurrency": self.concurrency,
            "max_duration_seconds": self.max_duration_seconds,
            "sessions": self.sessions,
            "scenario_distribution": dict(self.scenario_distribution),
            "persona_distribution": dict(self.persona_distribution),
            "planned_fault_distribution": dict(self.planned_fault_distribution),
            "episodes": [dict(episode) for episode in self.episodes],
            "plan_digest": self.plan_digest,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"


def _counts(names: Sequence[str], values: Sequence[str]) -> dict[str, int]:
    """Occurrences of each name, in vocabulary order, zeros left out."""
    found = {name: 0 for name in names}
    for value in values:
        found[value] += 1
    return {name: count for name, count in found.items() if count}


def build_report(plan: Plan, *, concurrency: int, max_duration_seconds: float) -> PlanReport:
    requests = plan.requests
    config = plan.config

    faults: dict[str, int] = {}
    for request in requests:
        for fault in (request.fault, *(retry.fault for retry in request.retries)):
            if fault is not None:
                faults[fault.error_type] = faults.get(fault.error_type, 0) + 1

    episodes = tuple(
        {
            "episode_id": episode.episode_id,
            "scenario": episode.scenario.value,
            "start_index": episode.start_index,
            "end_index": episode.end_index,
            "requests": episode.length,
            "affected_requests": sum(
                1 for request in requests[episode.start_index:episode.end_index]
                if request.scenario is not Scenario.NORMAL
            ),
        }
        for episode in plan.episodes
    )

    retries = plan.planned_retries
    return PlanReport(
        run_id=config.run_id,
        seed=config.seed,
        mode=config.mode,
        scenario=config.scenario.value,
        persona=config.persona.value if config.persona is not None else "mix",
        requested_traces=config.traces,
        planned_requests=len(requests),
        planned_retries=retries,
        planned_submissions=len(requests) + retries,
        planned_duration_seconds=plan.planned_duration_seconds,
        requested_rate=float(config.rate),
        concurrency=concurrency,
        max_duration_seconds=float(max_duration_seconds),
        sessions=plan.session_count,
        scenario_distribution=_counts(
            [scenario.value for scenario in Scenario],
            [request.scenario.value for request in requests],
        ),
        persona_distribution=_counts(
            [persona.value for persona in Persona],
            [request.persona.value for request in requests],
        ),
        planned_fault_distribution=dict(sorted(faults.items())),
        episodes=episodes,
        plan_digest=plan_digest(plan),
    )


def _distribution_lines(title: str, counts: Mapping[str, int], total: int) -> list[str]:
    lines = [f"{title}:"]
    if not counts:
        lines.append("  (none)")
    for name, count in counts.items():
        share = 100.0 * count / total if total else 0.0
        lines.append(f"  {name:<20} {count:>8}  {share:5.1f}%")
    return lines


def _sample_line(request: PlannedRequest) -> str:
    query = request.query if request.query else "(empty request)"
    if len(query) > _QUERY_WIDTH:
        query = query[:_QUERY_WIDTH - 3] + "..."
    fault = f"  fault={request.fault.error_type}" if request.fault else ""
    retries = f"  retries={len(request.retries)}" if request.retries else ""
    retrieval = (
        f"  retrieval={request.retrieval_effect.value}" if request.retrieval_effect else ""
    )
    return (
        f"  #{request.request_index:<6} +{request.arrival_offset_seconds:>10.3f}s  "
        f"{request.persona.value:<18} {request.scenario.value:<18} "
        f"{query}{fault}{retries}{retrieval}"
    )


def format_summary(
    report: PlanReport,
    sample: Sequence[PlannedRequest] = (),
    *,
    plan_only: bool = True,
) -> str:
    """
    The text printed after planning.  Never one line per planned request.

    plan_only is False when the plan is about to be executed; the heading
    then says so instead of saying that nothing was sent.
    """
    heading = (
        "PLAN ONLY - nothing was executed and nothing was sent."
        if plan_only else
        "PLAN - about to be executed; the execution report follows."
    )
    mode_note = "recorded; nothing is executed without --send" if plan_only else "executing"
    lines = [
        heading,
        "",
        f"run id              {report.run_id}",
        f"seed                {report.seed}",
        f"mode                {report.mode} ({mode_note})",
        f"scenario            {report.scenario}",
        f"persona             {report.persona}",
        f"requested traces    {report.requested_traces}",
        f"planned requests    {report.planned_requests}",
        f"planned retries     {report.planned_retries} (client resubmissions)",
        f"planned submissions {report.planned_submissions}",
        f"sessions            {report.sessions}",
        f"rate                {report.requested_rate:g} requests/second",
        f"concurrency         {report.concurrency}",
        f"planned duration    {report.planned_duration_seconds:.3f} seconds "
        f"(limit {report.max_duration_seconds:g})",
        f"plan digest         {report.plan_digest}",
        "",
    ]
    lines += _distribution_lines(
        "scenario distribution", report.scenario_distribution, report.planned_requests,
    )
    lines += _distribution_lines(
        "persona distribution", report.persona_distribution, report.planned_requests,
    )
    lines.append("planned failures by error type (first submissions and retries):")
    if not report.planned_fault_distribution:
        lines.append("  (none)")
    for error_type, count in report.planned_fault_distribution.items():
        lines.append(f"  {error_type:<20} {count:>8}")
    lines.append(f"episodes: {len(report.episodes)}")
    for episode in report.episodes:
        lines.append(
            f"  {episode['episode_id']:<28} requests "
            f"{episode['start_index']}..{episode['end_index'] - 1}  "
            f"affected {episode['affected_requests']} of {episode['requests']}"
        )
    if sample:
        lines.append(f"first {len(sample)} planned requests:")
        lines += [_sample_line(request) for request in sample]
    return "\n".join(lines) + "\n"


#: Outcome of one execution attempt, in the order they are reported.  Only the
#: first two are outcomes of the WORKLOAD; the next three mean the generator
#: or the platform did not do what the plan describes.
OUTCOMES: tuple[str, ...] = (
    "expected_success",
    "expected_failure",
    "unexpected_failure",
    "missing_failure",
    "reach_failure",
    "not_started",
)

RUN_STATUSES: tuple[str, ...] = (
    "completed",
    "stopped_integrity",
    "deadline_reached",
    "export_failed",
)

#: Integrity problems listed in a report; the count is always complete.
MAX_PROBLEMS_LISTED: int = 10


@dataclass(frozen=True)
class ExecutionReport:
    """
    What the driver did with a plan, as far as the driver itself can know.

    spans_exported_successfully counts spans for which the local exporter
    returned success.  That is the exporter's own result; it says nothing
    about what a collector, Kafka or a database did with them afterwards.
    Nothing here is a statement about stored rows or detected anomalies.

    attempts maps every name in OUTCOMES to a count.  problems holds the
    first integrity problems as text.
    """

    endpoint: str
    started: str
    finished: str
    elapsed_seconds: float
    planned_requests: int
    planned_retries: int
    planned_submissions: int
    started_requests: int
    not_started_requests: int
    attempts: Mapping[str, int]
    executed_attempts: int
    executed_retries: int
    late_starts: int
    max_start_lag_seconds: float
    mean_start_lag_seconds: float
    achieved_submission_rate: float
    spans_ended: int
    spans_exported_successfully: int
    export_failures: int
    flush_ok: bool
    run_status: str
    problems: tuple[str, ...] = ()
    #: Diagnostic only: per-request start lags of the started first attempts,
    #: built by the execution driver after the run.  None when not
    #: recorded.  Nothing in the late-start count depends on it.
    start_lags: Optional[Mapping[str, Any]] = None

    def __post_init__(self) -> None:
        if self.run_status not in RUN_STATUSES:
            raise ValueError(f"unknown run status {self.run_status!r}")
        if tuple(self.attempts) != OUTCOMES:
            raise ValueError("attempts must hold exactly the known outcomes, in order")

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed": True,
            "endpoint": self.endpoint,
            "started": self.started,
            "finished": self.finished,
            "elapsed_seconds": self.elapsed_seconds,
            "planned_requests": self.planned_requests,
            "planned_retries": self.planned_retries,
            "planned_submissions": self.planned_submissions,
            "started_requests": self.started_requests,
            "not_started_requests": self.not_started_requests,
            "attempts": dict(self.attempts),
            "executed_attempts": self.executed_attempts,
            "executed_retries": self.executed_retries,
            "late_starts": self.late_starts,
            "max_start_lag_seconds": self.max_start_lag_seconds,
            "mean_start_lag_seconds": self.mean_start_lag_seconds,
            "achieved_submission_rate": self.achieved_submission_rate,
            "spans_ended": self.spans_ended,
            "spans_exported_successfully": self.spans_exported_successfully,
            "export_failures": self.export_failures,
            "flush_ok": self.flush_ok,
            "run_status": self.run_status,
            "problems": list(self.problems),
            "start_lags": None if self.start_lags is None else {
                **self.start_lags,
                "entries": [list(entry) for entry in self.start_lags["entries"]],
            },
        }


def format_execution(execution: ExecutionReport) -> str:
    """The text printed after a plan was executed."""
    lines = [
        "EXECUTION - what this driver did. Nothing here says what a collector,",
        "Kafka or a database did with the telemetry afterwards.",
        "",
        f"run status          {execution.run_status}",
        f"endpoint            {execution.endpoint}",
        f"started             {execution.started}",
        f"finished            {execution.finished}",
        f"elapsed             {execution.elapsed_seconds:.3f} seconds",
        f"planned submissions {execution.planned_submissions} "
        f"({execution.planned_requests} requests + {execution.planned_retries} retries)",
        f"started requests    {execution.started_requests}",
        f"not started         {execution.not_started_requests} requests",
        f"executed attempts   {execution.executed_attempts} "
        f"(of which client retries: {execution.executed_retries})",
        "attempts by outcome:",
    ]
    for name in OUTCOMES:
        lines.append(f"  {name:<20} {execution.attempts[name]:>8}")
    lines += [
        f"late starts         {execution.late_starts} "
        f"(max lag {execution.max_start_lag_seconds:.3f} s, "
        f"mean lag {execution.mean_start_lag_seconds:.3f} s)",
        f"achieved rate       {execution.achieved_submission_rate:.3f} attempts/second",
        f"spans ended         {execution.spans_ended}",
        f"spans exported      {execution.spans_exported_successfully} "
        "(local exporter reported success)",
        f"export failures     {execution.export_failures}",
        f"flush ok            {'yes' if execution.flush_ok else 'NO'}",
    ]
    if execution.problems:
        lines.append("integrity problems (first ones):")
        lines += [f"  {problem}" for problem in execution.problems]
    return "\n".join(lines) + "\n"


def combined_dict(report: PlanReport, execution: ExecutionReport) -> dict[str, Any]:
    """The plan report with what was executed added under "execution"."""
    data = report.to_dict()
    data["executed"] = True
    data["execution"] = execution.to_dict()
    return data


def write_report(
    report: PlanReport, path: Path, execution: Optional[ExecutionReport] = None,
) -> Path:
    """
    Write the report as JSON to a NEW file and return its path.  With an
    execution report, the file holds both.

    Raises:
        FileExistsError    the path already exists; nothing is overwritten.
        FileNotFoundError  the directory of the path does not exist.
    """
    path = Path(path)
    if not path.parent.is_dir():
        raise FileNotFoundError(f"directory does not exist: {path.parent}")
    text = (
        report.to_json() if execution is None
        else json.dumps(combined_dict(report, execution), indent=2) + "\n"
    )
    # "x": fails rather than replaces.
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path

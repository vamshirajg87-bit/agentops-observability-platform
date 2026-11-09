"""
workload_generator/scenarios.py

The scenario vocabulary of the workload generator, and where in a plan each
scenario's abnormal traffic falls.

A scenario here is planning metadata only.  It says which step of the demo
agent is meant to be affected, how (slower, failing, timing out), with which
error type, and over which part of the run.  Nothing in this module waits,
raises an injected failure or touches the demo application; a later phase
reads this metadata and acts on it.

What can be affected is limited to what the demo agent really has:

    tool.execute         the one tool call
    retrieval.search     the document lookup
    research.synthesize  the step that builds the answer

The agent calls no language model and records no model, provider or token
data, so no scenario refers to any of those.  Failures are planned on the
tool call only: it is the only step whose error type the existing
instrumentation records.

Episodes
--------
Abnormal traffic is never spread evenly.  It is planned in episodes: runs of
consecutive requests.  A single-incident scenario has healthy traffic first,
one episode, then recovery.  RECURRING_INCIDENT has two episodes of the same
failure with healthy traffic between them.  MIXED_PRODUCTION has several
short episodes of different kinds that together cover about 5% of the run.

Standard library only.

Public API:
    Scenario, Target, RetrievalEffect, ScenarioSpec, Episode
    SPECS                       scenario -> spec
    MIXED_ABNORMAL_SCENARIOS    what a mixed-production episode may be
    plan_episodes()             the episodes of one plan
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

from .rng import Draw


class Scenario(Enum):
    NORMAL = "normal"
    SLOW_TOOL = "slow-tool"
    SLOW_SYNTHESIS = "slow-synthesis"
    API_500 = "api-500"
    API_429 = "api-429"
    TIMEOUT = "timeout"
    RETRY_STORM = "retry-storm"
    RETRIEVAL_LATENCY = "retrieval-latency"
    REPEATED_FAILURE = "repeated-failure"
    RECURRING_INCIDENT = "recurring-incident"
    RETRIEVAL_QUALITY = "retrieval-quality"
    MIXED_PRODUCTION = "mixed-production"


class Target(Enum):
    """The step of the demo agent a scenario acts on; values are span names."""

    TOOL = "tool.execute"
    RETRIEVAL = "retrieval.search"
    SYNTHESIS = "research.synthesize"


class RetrievalEffect(Enum):
    """
    What is planned to happen to the RESULT of the document lookup.  The
    question asked is never changed.

    DROP_BEST_MATCH  the best-matching document is missing from the result,
                     as with a stale or incomplete index.  What remains is
                     returned as it is, with its real scores; a result of
                     one document becomes empty.
    """

    DROP_BEST_MATCH = "drop-best-match"


# Error types a planned tool failure may carry.  ERROR_UNAVAILABLE is the
# failure the demo agent already has; the others are what a generator-owned
# wrapper around the tool will raise in a later phase.
ERROR_UNAVAILABLE: str = "ToolExecutionError"
ERROR_SERVER: str = "UpstreamServerError"
ERROR_RATE_LIMIT: str = "RateLimitError"
ERROR_TIMEOUT: str = "ToolTimeoutError"

ERROR_MESSAGES: Mapping[str, str] = {
    ERROR_UNAVAILABLE: (
        "External service unavailable: "
        "connection refused to metadata.example.internal"
    ),
    ERROR_SERVER: "Upstream service returned HTTP 500",
    ERROR_RATE_LIMIT: "Upstream service returned HTTP 429: rate limit exceeded",
    ERROR_TIMEOUT: "Tool call exceeded the 5000 ms time limit",
}

#: How long a timed-out tool call is planned to take before it fails.
TIMEOUT_MS: float = 5000.0


@dataclass(frozen=True)
class ScenarioSpec:
    """
    What one scenario plans for a request it affects.

    target            step acted on; None when no step is changed
    latency_factor    range the target's planned latency is multiplied by
    fixed_latency_ms  planned latency of the target, replacing its baseline
    fault_latency_ms  range of the target's latency when it fails quickly
    error_type        error the target is planned to fail with
    client_retries    the client resubmits a failed request
    retrieval_effect  what happens to the result of the document lookup; the
                      request itself, question included, is not changed
    intensity         share of the requests inside an episode that are
                      affected
    windows           episodes as (start, end) fractions of the plan
    """

    scenario: Scenario
    description: str
    target: Optional[Target] = None
    latency_factor: Optional[tuple[float, float]] = None
    fixed_latency_ms: Optional[float] = None
    fault_latency_ms: Optional[tuple[float, float]] = None
    error_type: Optional[str] = None
    client_retries: bool = False
    retrieval_effect: Optional[RetrievalEffect] = None
    intensity: float = 1.0
    windows: tuple[tuple[float, float], ...] = ()


_ONE_INCIDENT: tuple[tuple[float, float], ...] = ((0.50, 0.80),)

SPECS: Mapping[Scenario, ScenarioSpec] = {
    Scenario.NORMAL: ScenarioSpec(
        scenario=Scenario.NORMAL,
        description="healthy traffic: baseline latency, no failure",
    ),
    Scenario.SLOW_TOOL: ScenarioSpec(
        scenario=Scenario.SLOW_TOOL,
        description="the tool call answers, but several times slower",
        target=Target.TOOL,
        latency_factor=(6.0, 12.0),
        windows=_ONE_INCIDENT,
    ),
    Scenario.SLOW_SYNTHESIS: ScenarioSpec(
        scenario=Scenario.SLOW_SYNTHESIS,
        description="the answer-building step is several times slower",
        target=Target.SYNTHESIS,
        latency_factor=(6.0, 12.0),
        windows=_ONE_INCIDENT,
    ),
    Scenario.API_500: ScenarioSpec(
        scenario=Scenario.API_500,
        description="the tool's upstream service answers with a server error",
        target=Target.TOOL,
        error_type=ERROR_SERVER,
        intensity=0.8,
        windows=_ONE_INCIDENT,
    ),
    Scenario.API_429: ScenarioSpec(
        scenario=Scenario.API_429,
        description="the tool's upstream service rejects calls as rate limited",
        target=Target.TOOL,
        fault_latency_ms=(15.0, 60.0),
        error_type=ERROR_RATE_LIMIT,
        intensity=0.6,
        windows=_ONE_INCIDENT,
    ),
    Scenario.TIMEOUT: ScenarioSpec(
        scenario=Scenario.TIMEOUT,
        description="the tool call runs into its time limit and fails",
        target=Target.TOOL,
        fixed_latency_ms=TIMEOUT_MS,
        error_type=ERROR_TIMEOUT,
        intensity=0.5,
        windows=_ONE_INCIDENT,
    ),
    Scenario.RETRY_STORM: ScenarioSpec(
        scenario=Scenario.RETRY_STORM,
        description=(
            "transient tool failures that the CLIENT answers by resubmitting "
            "the request in the same session; the agent itself never retries"
        ),
        target=Target.TOOL,
        error_type=ERROR_SERVER,
        client_retries=True,
        intensity=0.7,
        windows=_ONE_INCIDENT,
    ),
    Scenario.RETRIEVAL_LATENCY: ScenarioSpec(
        scenario=Scenario.RETRIEVAL_LATENCY,
        description="the document lookup is many times slower",
        target=Target.RETRIEVAL,
        latency_factor=(8.0, 15.0),
        windows=_ONE_INCIDENT,
    ),
    Scenario.REPEATED_FAILURE: ScenarioSpec(
        scenario=Scenario.REPEATED_FAILURE,
        description="the same tool failure on every request for a while",
        target=Target.TOOL,
        error_type=ERROR_UNAVAILABLE,
        windows=_ONE_INCIDENT,
    ),
    Scenario.RECURRING_INCIDENT: ScenarioSpec(
        scenario=Scenario.RECURRING_INCIDENT,
        description=(
            "one failure pattern twice, with healthy traffic between, so "
            "that the second resembles the first"
        ),
        target=Target.TOOL,
        error_type=ERROR_SERVER,
        intensity=0.8,
        windows=((0.25, 0.40), (0.70, 0.85)),
    ),
    Scenario.RETRIEVAL_QUALITY: ScenarioSpec(
        scenario=Scenario.RETRIEVAL_QUALITY,
        description=(
            "the document lookup answers the same questions with its best "
            "match missing: no failure, but fewer and weaker results. "
            "Visible in telemetry; not necessarily raised as an anomaly"
        ),
        target=Target.RETRIEVAL,
        retrieval_effect=RetrievalEffect.DROP_BEST_MATCH,
        intensity=0.8,
        windows=_ONE_INCIDENT,
    ),
    Scenario.MIXED_PRODUCTION: ScenarioSpec(
        scenario=Scenario.MIXED_PRODUCTION,
        description=(
            "mostly healthy traffic with a few short abnormal episodes of "
            "different kinds, about 5% of all requests"
        ),
    ),
}

#: What an episode of MIXED_PRODUCTION may be.  RECURRING_INCIDENT is left
#: out: it is a pattern across two episodes, not a kind of episode.
MIXED_ABNORMAL_SCENARIOS: tuple[Scenario, ...] = (
    Scenario.SLOW_TOOL,
    Scenario.SLOW_SYNTHESIS,
    Scenario.API_500,
    Scenario.API_429,
    Scenario.TIMEOUT,
    Scenario.RETRY_STORM,
    Scenario.RETRIEVAL_LATENCY,
    Scenario.REPEATED_FAILURE,
    Scenario.RETRIEVAL_QUALITY,
)

#: Target share of abnormal requests in MIXED_PRODUCTION.
MIXED_ABNORMAL_SHARE: float = 0.05
#: Requests per mixed-production episode the planner aims for.
MIXED_EPISODE_LENGTH: int = 8
#: Leading share of a mixed-production plan that is always healthy, so that
#: an abnormal episode has ordinary traffic before it.
MIXED_LEAD_SHARE: float = 0.10


@dataclass(frozen=True)
class Episode:
    """
    A run of consecutive requests, [start_index, end_index), in which a
    scenario applies.  Each request inside is affected with probability
    intensity.
    """

    episode_id: str
    scenario: Scenario
    start_index: int
    end_index: int
    intensity: float

    def __contains__(self, request_index: object) -> bool:
        return (
            isinstance(request_index, int)
            and self.start_index <= request_index < self.end_index
        )

    @property
    def length(self) -> int:
        return self.end_index - self.start_index


def _episode_id(number: int, scenario: Scenario) -> str:
    return f"ep{number:02d}-{scenario.value}"


def _window_episodes(spec: ScenarioSpec, total: int) -> tuple[Episode, ...]:
    episodes = []
    previous_end = 0
    for number, (start_share, end_share) in enumerate(spec.windows, start=1):
        start = max(int(total * start_share), previous_end)
        end = min(max(int(total * end_share), start + 1), total)
        if start >= end:
            continue
        episodes.append(Episode(
            episode_id=_episode_id(number, spec.scenario),
            scenario=spec.scenario,
            start_index=start,
            end_index=end,
            intensity=spec.intensity,
        ))
        previous_end = end
    return tuple(episodes)


def _mixed_episodes(total: int, seed: int) -> tuple[Episode, ...]:
    budget = int(round(total * MIXED_ABNORMAL_SHARE))
    if budget < 1:
        return ()
    count = max(1, int(round(budget / MIXED_EPISODE_LENGTH)))
    lead = int(total * MIXED_LEAD_SHARE)
    slot = (total - lead) // count
    if slot < 1:
        return ()

    episodes = []
    for number in range(count):
        # The budget is shared out as evenly as whole requests allow.
        length = budget // count + (1 if number < budget % count else 0)
        length = min(length, slot)
        if length < 1:
            continue
        draw = Draw(seed, "mixed-episode", number)
        slot_start = lead + number * slot
        start = slot_start + draw.index(slot - length + 1)
        scenario = draw.choice(MIXED_ABNORMAL_SCENARIOS)
        episodes.append(Episode(
            episode_id=_episode_id(number + 1, scenario),
            scenario=scenario,
            start_index=start,
            end_index=start + length,
            # Every request of a mixed episode is abnormal, which keeps the
            # abnormal share of the whole plan at the target.
            intensity=1.0,
        ))
    return tuple(episodes)


def plan_episodes(scenario: Scenario, total: int, seed: int) -> tuple[Episode, ...]:
    """
    The episodes of a plan of `total` requests, in order and not overlapping.

    Raises:
        ValueError  total is below 1.
    """
    if total < 1:
        raise ValueError("a plan holds at least one request")
    if scenario is Scenario.MIXED_PRODUCTION:
        return _mixed_episodes(total, seed)
    return _window_episodes(SPECS[scenario], total)

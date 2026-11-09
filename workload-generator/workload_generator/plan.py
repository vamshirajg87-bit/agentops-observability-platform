"""
workload_generator/plan.py

The plan data model and the planner.

build_plan() turns a PlanConfig into a Plan: an ordered tuple of planned
requests.  It is pure: it reads no clock, no environment and no file, waits
for nothing and sends nothing.  A plan describes what is INTENDED; what later
happens when a plan is executed is recorded elsewhere.

Reproducibility
---------------
The same PlanConfig always gives the same Plan.

    seed     decides everything about the traffic: sessions, queries,
             arrival times, latencies, episodes, failures, retries
    run_id   decides the identifiers only (request and session ids)

So two runs with the same seed and different run ids plan the same traffic
under different identifiers, and a run can be repeated exactly by passing
both again.  Concurrency and other execution settings are not inputs of the
planner at all.

How a plan is built
-------------------
1. Sessions.  Sessions start one after another with exponentially distributed
   gaps, now and then a much longer quiet gap.  Each session has a persona,
   a number of requests and its own gaps between them; an automation client
   sends its requests almost at once.  Sessions overlap in time.
2. Order.  All requests are ordered by their time; that order is the request
   index.
3. Rate.  Times are scaled so that the plan as a whole has the requested
   average rate.  The bursts and gaps keep their shape.
4. Scenario.  Episodes are laid over the ordered requests; each request gets
   its planned latencies and, inside an episode, what the scenario intends.

Retries are CLIENT resubmissions: a planned retry is a new request by the
same client in the same session, sent after a backoff.  The demo agent has
no retry of its own and none is planned for it.

Standard library only.

Public API:
    PlanConfig, Plan, PlannedRequest, PlannedLatency, PlannedFault,
    PlannedRetry
    build_plan()
    validate_run_id(), RUN_ID_PATTERN
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NamedTuple, Optional

from .personas import (
    MIX,
    MIX_WEIGHTS,
    PROFILES,
    Persona,
    session_queries,
)
from .rng import Draw, derive_hex
from .scenarios import (
    ERROR_MESSAGES,
    SPECS,
    Episode,
    RetrievalEffect,
    Scenario,
    ScenarioSpec,
    Target,
    plan_episodes,
)

#: Lower-case letters, digits and hyphens; 4 to 40 characters; starts and
#: ends with a letter or digit.
RUN_ID_PATTERN: str = r"[a-z0-9][a-z0-9-]{2,38}[a-z0-9]"
_RUN_ID_RE = re.compile(RUN_ID_PATTERN)

MODES: tuple[str, ...] = ("real", "synthetic")

# Baseline latency of each step, as the median in milliseconds and the sigma
# of a log-normal distribution.  The demo agent itself answers in well under
# a millisecond; these are what a later phase adds to make a request take a
# believable time.
_BASELINE_MS: dict[Target, tuple[float, float]] = {
    Target.TOOL: (120.0, 0.35),
    Target.RETRIEVAL: (45.0, 0.30),
    Target.SYNTHESIS: (60.0, 0.30),
}
#: Share of healthy tool calls that are much slower than usual.
_TAIL_PROBABILITY: float = 0.02
_TAIL_FACTOR: float = 3.0

#: Share of session starts that follow a quiet period, and how much longer
#: that gap is.
_QUIET_PROBABILITY: float = 0.08
_QUIET_FACTOR: float = 6.0

_RETRY_RANGE: tuple[int, int] = (1, 3)
_RETRY_BASE_BACKOFF_SECONDS: float = 0.5
_RETRY_JITTER: tuple[float, float] = (0.8, 1.2)
#: Probability that the last planned resubmission of a request succeeds.
_RETRY_RECOVERY_PROBABILITY: float = 0.5


def validate_run_id(run_id: str) -> str:
    """
    Returns run_id unchanged.

    Raises:
        ValueError  run_id is not a string matching RUN_ID_PATTERN.
    """
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError(
            "run id must be 4 to 40 lower-case letters, digits or hyphens "
            "and must start and end with a letter or digit"
        )
    return run_id


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlanConfig:
    """
    Everything a plan depends on.  persona None means the default mix.
    mode is recorded with the plan; it does not change the planned traffic.
    """

    seed: int
    run_id: str
    scenario: Scenario
    traces: int
    rate: float
    persona: Optional[Persona] = None
    mode: str = "real"

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        validate_run_id(self.run_id)
        if not isinstance(self.scenario, Scenario):
            raise ValueError("scenario must be a Scenario")
        if self.persona is not None and not isinstance(self.persona, Persona):
            raise ValueError("persona must be a Persona or None")
        if isinstance(self.traces, bool) or not isinstance(self.traces, int) or self.traces < 1:
            raise ValueError("traces must be a positive integer")
        if isinstance(self.rate, bool) or not isinstance(self.rate, (int, float)):
            raise ValueError("rate must be a number")
        if not 0.0 < self.rate < float("inf"):
            raise ValueError("rate must be positive and finite")
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {', '.join(MODES)}")


@dataclass(frozen=True, slots=True)
class PlannedLatency:
    """Planned duration of the three steps that take time, in milliseconds."""

    tool_ms: float
    retrieval_ms: float
    synthesis_ms: float


@dataclass(frozen=True, slots=True)
class PlannedFault:
    """A failure the given step is planned to end with."""

    target: Target
    error_type: str
    error_message: str


@dataclass(frozen=True, slots=True)
class PlannedRetry:
    """
    One planned CLIENT resubmission of a failed request: the same query in
    the same session, as a new request, backoff_seconds after the previous
    attempt failed.  fault is what this attempt is planned to fail with, or
    None when it is planned to succeed.
    """

    attempt: int
    request_id: str
    backoff_seconds: float
    fault: Optional[PlannedFault]


@dataclass(frozen=True, slots=True)
class PlannedRequest:
    """
    One request a client is planned to send.

    scenario is what applies to THIS request: NORMAL unless the request is
    inside an episode and affected by it.  episode_id is set for every
    request inside an episode, affected or not.

    persona is the profile of the session the request belongs to, and the
    query always comes from that persona's pool: no scenario changes what a
    user asks.  retrieval_effect is what is planned to happen to the RESULT
    of the document lookup for this request, or None.
    """

    request_index: int
    request_id: str
    session_id: str
    persona: Persona
    scenario: Scenario
    query: str
    arrival_offset_seconds: float
    latency: PlannedLatency
    fault: Optional[PlannedFault] = None
    retries: tuple[PlannedRetry, ...] = ()
    episode_id: Optional[str] = None
    retrieval_effect: Optional[RetrievalEffect] = None


@dataclass(frozen=True)
class Plan:
    config: PlanConfig
    requests: tuple[PlannedRequest, ...]
    episodes: tuple[Episode, ...]
    session_count: int

    @property
    def planned_retries(self) -> int:
        return sum(len(request.retries) for request in self.requests)

    @property
    def planned_duration_seconds(self) -> float:
        """Arrival offset of the last request; retries are not counted."""
        return self.requests[-1].arrival_offset_seconds if self.requests else 0.0


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class _Arrival(NamedTuple):
    moment: float
    session: int
    position: int
    persona: Persona
    query: str


def _identifier(prefix: str, config: PlanConfig, kind: str, key: object) -> str:
    """The same shape the demo application uses: prefix + 32 hex characters."""
    return prefix + derive_hex(config.seed, config.run_id, kind, key)[:32]


def _plan_arrivals(config: PlanConfig) -> list[_Arrival]:
    """Requests of as many sessions as are needed, ordered by time."""
    arrivals: list[_Arrival] = []
    session_start = 0.0
    session = 0
    while len(arrivals) < config.traces:
        draw = Draw(config.seed, "session", session)
        persona = config.persona or draw.weighted(MIX, MIX_WEIGHTS)
        profile = PROFILES[persona]
        length = draw.integer(*profile.session_length)
        if session > 0:
            gap = draw.exponential(1.0)
            if draw.uniform() < _QUIET_PROBABILITY:
                gap *= _QUIET_FACTOR
            session_start += gap
        moment = session_start
        for position, query in enumerate(session_queries(persona, length, draw)):
            if position > 0:
                moment += draw.exponential(profile.think_gap)
            arrivals.append(_Arrival(moment, session, position, persona, query))
        session += 1
    # The last session is cut where the requested number is reached.
    del arrivals[config.traces:]
    arrivals.sort(key=lambda arrival: (arrival.moment, arrival.session, arrival.position))
    return arrivals


def _offsets(arrivals: list[_Arrival], rate: float) -> list[float]:
    """Arrival offsets in seconds: first at 0, average rate as requested."""
    count = len(arrivals)
    if count == 1:
        return [0.0]
    first = arrivals[0].moment
    span = arrivals[-1].moment - first
    duration = (count - 1) / rate
    if span <= 0.0:
        return [round(index / rate, 6) for index in range(count)]
    scale = duration / span
    return [round((arrival.moment - first) * scale, 6) for arrival in arrivals]


def _fault(spec: ScenarioSpec) -> Optional[PlannedFault]:
    if spec.error_type is None or spec.target is None:
        return None
    return PlannedFault(
        target=spec.target,
        error_type=spec.error_type,
        error_message=ERROR_MESSAGES[spec.error_type],
    )


def _plan_retries(
    config: PlanConfig, index: int, fault: PlannedFault, draw: Draw,
) -> tuple[PlannedRetry, ...]:
    count = draw.integer(*_RETRY_RANGE)
    retries = []
    for attempt in range(1, count + 1):
        backoff = (
            _RETRY_BASE_BACKOFF_SECONDS * 2 ** (attempt - 1) * draw.between(*_RETRY_JITTER)
        )
        recovers = attempt == count and draw.uniform() < _RETRY_RECOVERY_PROBABILITY
        retries.append(PlannedRetry(
            attempt=attempt,
            request_id=_identifier("req_", config, "retry", f"{index}.{attempt}"),
            backoff_seconds=round(backoff, 3),
            fault=None if recovers else fault,
        ))
    return tuple(retries)


def _plan_request(
    config: PlanConfig,
    index: int,
    arrival: _Arrival,
    offset: float,
    episode: Optional[Episode],
) -> PlannedRequest:
    draw = Draw(config.seed, "request", index)

    durations = {
        target: draw.lognormal(median, sigma)
        for target, (median, sigma) in _BASELINE_MS.items()
    }
    if draw.uniform() < _TAIL_PROBABILITY:
        durations[Target.TOOL] *= _TAIL_FACTOR

    affected = episode is not None and draw.uniform() < episode.intensity
    scenario = episode.scenario if affected and episode is not None else Scenario.NORMAL
    spec = SPECS[scenario]

    if spec.target is not None:
        if spec.latency_factor is not None:
            durations[spec.target] *= draw.between(*spec.latency_factor)
        if spec.fault_latency_ms is not None:
            durations[spec.target] = draw.between(*spec.fault_latency_ms)
        if spec.fixed_latency_ms is not None:
            durations[spec.target] = spec.fixed_latency_ms

    fault = _fault(spec)
    retries: tuple[PlannedRetry, ...] = ()
    if fault is not None and spec.client_retries:
        retries = _plan_retries(config, index, fault, draw)

    return PlannedRequest(
        request_index=index,
        request_id=_identifier("req_", config, "request", index),
        session_id=_identifier("sess_", config, "session", arrival.session),
        persona=arrival.persona,
        scenario=scenario,
        query=arrival.query,
        arrival_offset_seconds=offset,
        latency=PlannedLatency(
            tool_ms=round(durations[Target.TOOL], 3),
            retrieval_ms=round(durations[Target.RETRIEVAL], 3),
            synthesis_ms=round(durations[Target.SYNTHESIS], 3),
        ),
        fault=fault,
        retries=retries,
        episode_id=episode.episode_id if episode is not None else None,
        retrieval_effect=spec.retrieval_effect,
    )


def build_plan(config: PlanConfig) -> Plan:
    """
    Plan config.traces requests.

    The result depends on config and on nothing else.
    """
    arrivals = _plan_arrivals(config)
    offsets = _offsets(arrivals, config.rate)
    episodes = plan_episodes(config.scenario, config.traces, config.seed)

    episode_of: dict[int, Episode] = {}
    for episode in episodes:
        for index in range(episode.start_index, episode.end_index):
            episode_of[index] = episode

    requests = tuple(
        _plan_request(config, index, arrival, offsets[index], episode_of.get(index))
        for index, arrival in enumerate(arrivals)
    )
    return Plan(
        config=config,
        requests=requests,
        episodes=episodes,
        session_count=len({arrival.session for arrival in arrivals}),
    )

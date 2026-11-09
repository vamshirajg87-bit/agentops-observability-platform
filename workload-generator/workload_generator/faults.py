"""
workload_generator/faults.py

Phase 14.3C: Generator-owned fault injection.

Carries out, inside the generator's own process, what a plan intends for one
execution attempt: how long each step takes, whether the tool call fails,
and whether the document lookup returns a degraded result.  The demo
application's files are not changed.  While an injector is installed, three
of its functions are replaced in memory by wrappers that call the originals:

    the tool call           <tool module>.run_tool
    the document lookup     <retrieval module>.retrieve
    the answer-building     <instrumentation module>.research_synthesize_node
    step

The third is the reference the instrumentation module itself imported; it is
the name looked up when the step runs.  All three wrappers run inside the
span the application already creates for the step, so the added time and the
raised error appear in the telemetry the application already emits.

The planner decides WHAT happens; this module only does it.  It draws no
random number and makes no scenario decision.

One set of wrappers, one context per attempt
--------------------------------------------
installed() replaces the three functions ONCE, for the whole run, and puts
the originals back when the run ends.  It is not entered per request:
installing and removing per request would be unsafe as soon as two requests
are in flight.

applied(effects) makes one attempt's effects current for the code it
encloses.  They are held in a context variable, so two attempts running at
the same time each see their own.  Outside applied() the wrappers call the
originals and do nothing else: no pause, no failure, no change.

Known assumption: the wrappers see the effects because the application's
graph runs its steps in the context of the caller.  That was observed for
LangGraph 1.2.11 and the application's linear graph.  Should it change, the
wrappers would be reached without effects and inject nothing; applied()
therefore yields a Reach that records which wrappers an attempt reached
under its effects, and Reach.problems() says what is missing.

Waiting
-------
Latency is applied by calling a `pause` function given to the injector by
its caller, with seconds as its argument.  This module does not import a
clock and never waits on its own.  The planned latencies are workload
simulation assumptions; they are not measurements, benchmarks or objectives.

Failures
--------
A planned failure is raised from the tool wrapper in place of the tool call.
Three kinds are defined here.  The fourth, ToolExecutionError, is the
application's own exception class, taken from the tool module the caller
supplied; it is not defined again.

Standard library only.  Nothing of the demo application is imported here;
its modules are handed in by the caller.

Public API:
    InjectedFault, UpstreamServerError, RateLimitError, ToolTimeoutError
    FaultInstallError
    Effects, Attempt, Reach
    effects_of(), attempts()
    FaultInjector
"""

from __future__ import annotations

import math
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterator, NamedTuple, Optional

from .plan import PlannedFault, PlannedLatency, PlannedRequest
from .scenarios import (
    ERROR_RATE_LIMIT,
    ERROR_SERVER,
    ERROR_TIMEOUT,
    ERROR_UNAVAILABLE,
    RetrievalEffect,
    Target,
)

#: Called with a number of seconds; returns when that time has passed.
Pause = Callable[[float], None]

# Function replaced, and the function of the same module that calls it by
# name.  The caller is checked at installation: if it no longer refers to
# the function by that name, replacing the name would change nothing.
_TOOL_FUNCTION, _TOOL_CALLER = "run_tool", "tool_agent_node"
_RETRIEVAL_FUNCTION, _RETRIEVAL_CALLER = "retrieve", "retrieval_node"
_SYNTHESIS_FUNCTION, _SYNTHESIS_CALLER = (
    "research_synthesize_node", "instrumented_research_synthesize",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class InjectedFault(RuntimeError):
    """A failure the generator raised on purpose, as the plan intends."""


class UpstreamServerError(InjectedFault):
    """The tool's upstream service answered with a server error."""


class RateLimitError(InjectedFault):
    """The tool's upstream service rejected the call as rate limited."""


class ToolTimeoutError(InjectedFault):
    """The tool call ran into its time limit."""


class FaultInstallError(RuntimeError):
    """The wrappers cannot be installed, or effects cannot be applied."""


_GENERATOR_ERRORS: dict[str, type[InjectedFault]] = {
    ERROR_SERVER: UpstreamServerError,
    ERROR_RATE_LIMIT: RateLimitError,
    ERROR_TIMEOUT: ToolTimeoutError,
}


# ---------------------------------------------------------------------------
# Effects and attempts (pure)
# ---------------------------------------------------------------------------

def _milliseconds(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value) or value < 0.0:
        raise ValueError(f"{name} must be finite and not negative")


@dataclass(frozen=True)
class Effects:
    """
    What one execution attempt is intended to experience.

    The three latencies are how long each step is planned to take.  fault is
    the failure the tool call is planned to end with, or None.
    retrieval_effect is what happens to the result of the document lookup,
    or None.
    """

    tool_ms: float
    retrieval_ms: float
    synthesis_ms: float
    fault: Optional[PlannedFault] = None
    retrieval_effect: Optional[RetrievalEffect] = None

    def __post_init__(self) -> None:
        _milliseconds("tool_ms", self.tool_ms)
        _milliseconds("retrieval_ms", self.retrieval_ms)
        _milliseconds("synthesis_ms", self.synthesis_ms)
        if self.fault is not None:
            if not isinstance(self.fault, PlannedFault):
                raise ValueError("fault must be a PlannedFault or None")
            if self.fault.target is not Target.TOOL:
                # The only step whose error type the application records.
                raise ValueError("a fault can only be planned on the tool call")
        if self.retrieval_effect is not None and not isinstance(
            self.retrieval_effect, RetrievalEffect,
        ):
            raise ValueError("retrieval_effect must be a RetrievalEffect or None")


def _effects(
    latency: PlannedLatency,
    fault: Optional[PlannedFault],
    retrieval_effect: Optional[RetrievalEffect],
) -> Effects:
    return Effects(
        tool_ms=latency.tool_ms,
        retrieval_ms=latency.retrieval_ms,
        synthesis_ms=latency.synthesis_ms,
        fault=fault,
        retrieval_effect=retrieval_effect,
    )


def effects_of(request: PlannedRequest) -> Effects:
    """The effects of a planned request's first submission."""
    return _effects(request.latency, request.fault, request.retrieval_effect)


@dataclass(frozen=True)
class Attempt:
    """
    One submission of a planned request.

    attempt 0 is the request itself.  Every later attempt is a CLIENT
    resubmission: a new request with its own request id, in the same session,
    with the same query, sent backoff_seconds after the previous attempt
    failed.  The agent itself never retries.
    """

    attempt: int
    request_id: str
    session_id: str
    query: str
    backoff_seconds: float
    effects: Effects


def attempts(request: PlannedRequest) -> tuple[Attempt, ...]:
    """
    The submissions planned for one request, in order: the request, then each
    planned client retry.

    Pure: nothing is executed, nothing waits, and no random number is drawn.
    A retry keeps the request's planned latencies and retrieval effect; only
    its planned failure is its own.
    """
    planned = [Attempt(
        attempt=0,
        request_id=request.request_id,
        session_id=request.session_id,
        query=request.query,
        backoff_seconds=0.0,
        effects=effects_of(request),
    )]
    for retry in request.retries:
        planned.append(Attempt(
            attempt=retry.attempt,
            request_id=retry.request_id,
            session_id=request.session_id,
            query=request.query,
            backoff_seconds=retry.backoff_seconds,
            effects=_effects(request.latency, retry.fault, request.retrieval_effect),
        ))
    return tuple(planned)


# ---------------------------------------------------------------------------
# Bookkeeping of one attempt
# ---------------------------------------------------------------------------

class Reach:
    """
    How often each wrapper was reached while one attempt's effects were
    current.  Bookkeeping of the generator only; it is not telemetry.
    """

    __slots__ = ("tool", "retrieval", "synthesis")

    def __init__(self) -> None:
        self.tool = 0
        self.retrieval = 0
        self.synthesis = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "tool": self.tool, "retrieval": self.retrieval, "synthesis": self.synthesis,
        }

    @staticmethod
    def expected(effects: Effects) -> dict[str, int]:
        """
        What a complete attempt reaches: every step once, except that the
        answer-building step never runs when the tool call fails.
        """
        return {
            "tool": 1,
            "retrieval": 1,
            "synthesis": 0 if effects.fault is not None else 1,
        }

    def problems(self, effects: Effects) -> tuple[str, ...]:
        """
        One line per wrapper that was not reached as often as a complete
        attempt reaches it.  Empty when the attempt went as intended.
        """
        expected = self.expected(effects)
        return tuple(
            f"{name}: reached {count} time(s), expected {expected[name]}"
            for name, count in self.as_dict().items()
            if count != expected[name]
        )

    def __repr__(self) -> str:
        return f"Reach(tool={self.tool}, retrieval={self.retrieval}, synthesis={self.synthesis})"


class _Active(NamedTuple):
    injector: "FaultInjector"
    effects: Effects
    reach: Reach


#: The effects of the attempt running in the current context, if any.
_ACTIVE: ContextVar[Optional[_Active]] = ContextVar(
    "workload_generator_active_effects", default=None,
)

#: Set on every wrapper, so that a second installation over the first is seen.
_WRAPPER_MARK: str = "_workload_generator_wrapper"


# ---------------------------------------------------------------------------
# Injector
# ---------------------------------------------------------------------------

class FaultInjector:
    """
    Applies planned effects to the demo application's three steps.

    tool, retrieval and instrumentation are the application's modules (or
    objects with the same attributes) that hold the functions to wrap:

        tool             run_tool, tool_agent_node, ToolExecutionError
        retrieval        retrieve, retrieval_node
        instrumentation  research_synthesize_node,
                         instrumented_research_synthesize

    pause is called with seconds whenever a step is planned to take time.
    """

    def __init__(
        self,
        *,
        tool: Any,
        retrieval: Any,
        instrumentation: Any,
        pause: Pause,
    ) -> None:
        if not callable(pause):
            raise FaultInstallError("pause must be callable")
        self._tool = tool
        self._retrieval = retrieval
        self._instrumentation = instrumentation
        self._pause = pause
        self._installed = False
        self._tool_failure: Optional[type[BaseException]] = None

    @property
    def is_installed(self) -> bool:
        return self._installed

    # -- installation -------------------------------------------------------

    @staticmethod
    def _original(owner: Any, function: str, caller: str) -> Callable[..., Any]:
        """
        The function to wrap, after checking that wrapping it will have an
        effect.

        Raises:
            FaultInstallError  naming what is not as expected.
        """
        original = getattr(owner, function, None)
        if not callable(original):
            raise FaultInstallError(
                f"{function} is missing or not callable; the demo application "
                "is not structured as this injector expects"
            )
        if getattr(original, _WRAPPER_MARK, False):
            raise FaultInstallError(f"{function} is already wrapped by an injector")
        calling = getattr(owner, caller, None)
        code = getattr(calling, "__code__", None)
        if code is None:
            raise FaultInstallError(
                f"{caller} is missing; the demo application is not structured "
                "as this injector expects"
            )
        if function not in code.co_names:
            raise FaultInstallError(
                f"{caller} does not call {function} by name; replacing it "
                "would change nothing"
            )
        return original

    def _tool_failure_class(self) -> type[BaseException]:
        failure = getattr(self._tool, ERROR_UNAVAILABLE, None)
        if not (isinstance(failure, type) and issubclass(failure, Exception)):
            raise FaultInstallError(
                f"the tool module has no exception class named {ERROR_UNAVAILABLE}"
            )
        return failure

    @contextmanager
    def installed(self) -> Iterator["FaultInjector"]:
        """
        Replace the three functions for the duration of the block and put the
        originals back afterwards, whatever happens inside.

        Raises:
            FaultInstallError  already installed, or the application is not
                               structured as expected; nothing was replaced.
        """
        if self._installed:
            raise FaultInstallError("this injector is already installed")

        # Everything is checked before anything is replaced.
        targets = (
            (self._tool, _TOOL_FUNCTION, _TOOL_CALLER, self._wrap_tool),
            (self._retrieval, _RETRIEVAL_FUNCTION, _RETRIEVAL_CALLER, self._wrap_retrieval),
            (self._instrumentation, _SYNTHESIS_FUNCTION, _SYNTHESIS_CALLER,
             self._wrap_synthesis),
        )
        originals = [
            (owner, function, self._original(owner, function, caller), wrap)
            for owner, function, caller, wrap in targets
        ]
        self._tool_failure = self._tool_failure_class()

        self._installed = True
        try:
            for owner, function, original, wrap in originals:
                wrapper = wrap(original)
                setattr(wrapper, _WRAPPER_MARK, True)
                setattr(owner, function, wrapper)
            yield self
        finally:
            for owner, function, original, _ in originals:
                setattr(owner, function, original)
            self._installed = False
            self._tool_failure = None

    # -- one attempt --------------------------------------------------------

    @contextmanager
    def applied(self, effects: Effects) -> Iterator[Reach]:
        """
        Make `effects` current for the block, in this context only, and yield
        the Reach that records which wrappers the block reached.

        Raises:
            FaultInstallError  the injector is not installed, effects are
                               already applied in this context, or the
                               planned failure is of an unknown kind; nothing
                               was applied.
        """
        if not isinstance(effects, Effects):
            raise FaultInstallError("effects must be an Effects")
        if not self._installed:
            raise FaultInstallError("effects cannot be applied: the injector is not installed")
        if _ACTIVE.get() is not None:
            raise FaultInstallError("effects are already applied in this context")
        if effects.fault is not None:
            self._exception(effects.fault)          # refuse an unknown kind now

        reach = Reach()
        token = _ACTIVE.set(_Active(self, effects, reach))
        try:
            yield reach
        finally:
            _ACTIVE.reset(token)

    def _current(self) -> Optional[_Active]:
        active = _ACTIVE.get()
        if active is None or active.injector is not self:
            return None
        return active

    def _exception(self, fault: PlannedFault) -> BaseException:
        """The exception a planned failure is raised as."""
        if fault.error_type == ERROR_UNAVAILABLE:
            if self._tool_failure is None:
                raise FaultInstallError("the injector is not installed")
            return self._tool_failure(fault.error_message)
        kind = _GENERATOR_ERRORS.get(fault.error_type)
        if kind is None:
            raise FaultInstallError(f"unknown planned failure {fault.error_type!r}")
        return kind(fault.error_message)

    # -- wrappers -----------------------------------------------------------

    def _wrap_tool(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def run_tool(query: str) -> Any:
            active = self._current()
            if active is None:
                return original(query)
            active.reach.tool += 1
            self._pause(active.effects.tool_ms / 1000.0)
            if active.effects.fault is not None:
                # The planned time passes first, then the call fails; the
                # tool itself is not called.
                raise self._exception(active.effects.fault)
            return original(query)

        return run_tool

    def _wrap_retrieval(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def retrieve(query: str) -> Any:
            active = self._current()
            if active is None:
                return original(query)
            active.reach.retrieval += 1
            self._pause(active.effects.retrieval_ms / 1000.0)
            # Always the query as it was asked.
            result = original(query)
            if active.effects.retrieval_effect is RetrievalEffect.DROP_BEST_MATCH:
                # A new list without the first, best-matching entry; the
                # remaining entries are the same objects with their own
                # scores, and the original list is left as it was.
                return list(result[1:])
            return result

        return retrieve

    def _wrap_synthesis(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def research_synthesize_node(state: Any) -> Any:
            active = self._current()
            if active is None:
                return original(state)
            active.reach.synthesis += 1
            self._pause(active.effects.synthesis_ms / 1000.0)
            return original(state)

        return research_synthesize_node

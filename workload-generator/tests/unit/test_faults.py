"""
workload-generator/tests/unit/test_faults.py

Unit tests for faults.py.

Test inventory:
    WF01  Effects and attempts (pure mapping from the plan)
    WF02  Installation lifecycle
    WF03  Applying effects: lifecycle and pass-through
    WF04  Tool wrapper: latency and failures
    WF05  Retrieval wrapper: latency and the degraded result
    WF06  Synthesis wrapper
    WF07  Whole attempts per scenario, and wrapper reach
    WF08  Concurrency: 32 attempts at once
    WF09  Guards: nothing waits, nothing is contacted, nothing is changed

The wrappers are exercised against the demo application's real, pure tool,
retrieval and research functions, called through its real node functions.
The agent graph is not run, no span is created and nothing is sent.  Time
never passes: `pause` is a recorder that returns at once.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import sys
import threading
import types
from pathlib import Path

import pytest

from workload_generator import faults
from workload_generator.faults import (
    Attempt,
    Effects,
    FaultInjector,
    FaultInstallError,
    InjectedFault,
    RateLimitError,
    Reach,
    ToolTimeoutError,
    UpstreamServerError,
    attempts,
    effects_of,
)
from workload_generator.personas import Persona
from workload_generator.plan import (
    PlanConfig,
    PlannedFault,
    PlannedLatency,
    PlannedRequest,
    build_plan,
)
from workload_generator.scenarios import (
    ERROR_MESSAGES,
    ERROR_RATE_LIMIT,
    ERROR_SERVER,
    ERROR_TIMEOUT,
    ERROR_UNAVAILABLE,
    RetrievalEffect,
    Scenario,
    Target,
)

_REPO = Path(__file__).resolve().parents[3]
_DEMO = _REPO / "demo-app"


def _demo_hashes() -> dict[str, str]:
    return {
        path.relative_to(_DEMO).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(_DEMO.rglob("*.py"))
    }


# Taken before any test of this module runs; compared at the very end.
_DEMO_BEFORE = _demo_hashes()

_ONE_RESULT = "What is Apache Kafka?"
_THREE_RESULTS = "How do producers and consumers exchange event data?"
_NO_RESULT = "How do I bake sourdough bread?"


class Recorder:
    """A pause that returns at once and remembers what it was asked for."""

    def __init__(self) -> None:
        self.seconds: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.seconds.append(seconds)


@pytest.fixture(scope="module")
def demo():
    """The demo application's pure modules, as the driver will hand them in."""
    sys.path.insert(0, str(_DEMO))
    try:
        from agents import research, retrieval, tool_agent
    finally:
        sys.path.remove(str(_DEMO))

    # The instrumentation module pulls in telemetry exporters; a stand-in with
    # the same two names and the REAL node function is all the injector needs.
    instrumentation = types.SimpleNamespace()
    instrumentation.research_synthesize_node = research.research_synthesize_node

    def instrumented_research_synthesize(state):
        return instrumentation.research_synthesize_node(state)

    instrumentation.instrumented_research_synthesize = instrumented_research_synthesize

    originals = (
        tool_agent.run_tool, retrieval.retrieve, instrumentation.research_synthesize_node,
    )
    yield types.SimpleNamespace(
        tool=tool_agent, retrieval=retrieval, research=research,
        instrumentation=instrumentation, originals=originals,
    )
    # Whatever a test did, the real modules are left as they were found.
    assert (
        tool_agent.run_tool, retrieval.retrieve, instrumentation.research_synthesize_node,
    ) == originals


def _injector(demo, pause=None) -> FaultInjector:
    return FaultInjector(
        tool=demo.tool, retrieval=demo.retrieval, instrumentation=demo.instrumentation,
        pause=pause if pause is not None else Recorder(),
    )


def _effects(**overrides) -> Effects:
    values = dict(tool_ms=120.0, retrieval_ms=45.0, synthesis_ms=60.0)
    values.update(overrides)
    return Effects(**values)


def _fault(error_type: str) -> PlannedFault:
    return PlannedFault(Target.TOOL, error_type, ERROR_MESSAGES[error_type])


def _plan(scenario: Scenario, traces: int = 1000, **overrides):
    values = dict(seed=42, run_id="fault-tests", scenario=scenario, traces=traces, rate=10.0)
    values.update(overrides)
    return build_plan(PlanConfig(**values))


def _first(plan, scenario: Scenario) -> PlannedRequest:
    return next(r for r in plan.requests if r.scenario is scenario)


def _run_steps(demo, query: str) -> dict:
    """The three steps in the order the agent runs them, through its real nodes."""
    state = {
        "user_request": query,
        "retrieval_query": demo.research._derive_retrieval_query(query),
    }
    state.update(demo.retrieval.retrieval_node(state))
    state.update(demo.tool.tool_agent_node(state))
    state.update(demo.instrumentation.instrumented_research_synthesize(state))
    return state


def _summary(chunks) -> tuple[int, float | None]:
    """(result count, top score) exactly as the existing instrumentation derives them."""
    return len(chunks), max((chunk.relevance_score for chunk in chunks), default=None)


# ---------------------------------------------------------------------------
# WF01  Effects and attempts
# ---------------------------------------------------------------------------

class TestEffectsAndAttempts:

    def test_effects_of_a_normal_request_are_its_planned_latencies(self):
        request = _plan(Scenario.NORMAL).requests[0]
        effects = effects_of(request)
        assert (effects.tool_ms, effects.retrieval_ms, effects.synthesis_ms) == (
            request.latency.tool_ms, request.latency.retrieval_ms,
            request.latency.synthesis_ms,
        )
        assert effects.fault is None and effects.retrieval_effect is None

    @pytest.mark.parametrize("scenario", list(Scenario))
    def test_effects_carry_exactly_what_the_plan_holds(self, scenario):
        for request in _plan(scenario, traces=400).requests:
            effects = effects_of(request)
            assert dataclasses.astuple(request.latency) == (
                effects.tool_ms, effects.retrieval_ms, effects.synthesis_ms,
            )
            assert effects.fault is request.fault
            assert effects.retrieval_effect is request.retrieval_effect

    def test_effects_are_immutable(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            _effects().tool_ms = 1.0  # type: ignore[misc]

    @pytest.mark.parametrize("overrides", [
        {"tool_ms": -1.0}, {"retrieval_ms": float("nan")}, {"synthesis_ms": float("inf")},
        {"tool_ms": "120"}, {"tool_ms": True}, {"fault": "UpstreamServerError"},
        {"retrieval_effect": "drop-best-match"},
        {"fault": PlannedFault(Target.RETRIEVAL, ERROR_SERVER, "x")},
        {"fault": PlannedFault(Target.SYNTHESIS, ERROR_SERVER, "x")},
    ])
    def test_invalid_effects_are_rejected(self, overrides):
        with pytest.raises(ValueError):
            _effects(**overrides)

    def test_zero_latency_is_allowed(self):
        assert _effects(tool_ms=0, retrieval_ms=0.0, synthesis_ms=0).tool_ms == 0

    def test_a_request_without_retries_is_one_attempt(self):
        request = _plan(Scenario.API_500).requests[0]
        (only,) = attempts(request)
        assert only == Attempt(
            attempt=0, request_id=request.request_id, session_id=request.session_id,
            query=request.query, backoff_seconds=0.0, effects=effects_of(request),
        )

    def test_attempts_of_a_retry_storm_request(self):
        plan = _plan(Scenario.RETRY_STORM)
        checked = 0
        for request in plan.requests:
            planned = attempts(request)
            assert len(planned) == 1 + len(request.retries)
            first, *later = planned
            assert first.attempt == 0 and first.backoff_seconds == 0.0
            assert first.request_id == request.request_id
            assert first.effects.fault is request.fault
            for attempt, retry in zip(later, request.retries):
                checked += 1
                assert attempt.attempt == retry.attempt >= 1
                # Its own request id; the same session and the same question.
                assert attempt.request_id == retry.request_id != request.request_id
                assert attempt.session_id == request.session_id
                assert attempt.query == request.query
                assert attempt.backoff_seconds == retry.backoff_seconds > 0.0
                # Planned to fail or to succeed, as the plan says.
                assert attempt.effects.fault is retry.fault
                # The applicable planned latencies are the request's.
                assert dataclasses.astuple(request.latency) == (
                    attempt.effects.tool_ms, attempt.effects.retrieval_ms,
                    attempt.effects.synthesis_ms,
                )
        assert checked > 300

    def test_attempts_are_in_order_with_unique_request_ids(self):
        for request in _plan(Scenario.RETRY_STORM).requests:
            planned = attempts(request)
            assert [a.attempt for a in planned] == list(range(len(planned)))
            assert len({a.request_id for a in planned}) == len(planned)

    def test_a_recovering_retry_has_no_fault(self):
        plan = _plan(Scenario.RETRY_STORM)
        last = [attempts(r)[-1] for r in plan.requests if r.retries]
        outcomes = {a.effects.fault is None for a in last}
        assert outcomes == {True, False}

    def test_attempts_is_pure_and_repeatable(self):
        request = next(r for r in _plan(Scenario.RETRY_STORM).requests if len(r.retries) == 3)
        assert attempts(request) == attempts(request)
        assert isinstance(attempts(request), tuple)

    def test_an_attempt_carries_no_telemetry_attribute(self):
        names = {field.name for field in dataclasses.fields(Attempt)}
        assert names == {
            "attempt", "request_id", "session_id", "query", "backoff_seconds", "effects",
        }

    def test_retries_keep_the_retrieval_effect_of_their_request(self):
        base = _plan(Scenario.NORMAL).requests[0]
        request = dataclasses.replace(
            _first(_plan(Scenario.RETRY_STORM), Scenario.RETRY_STORM),
            retrieval_effect=RetrievalEffect.DROP_BEST_MATCH, latency=base.latency,
        )
        assert {a.effects.retrieval_effect for a in attempts(request)} == {
            RetrievalEffect.DROP_BEST_MATCH
        }


# ---------------------------------------------------------------------------
# WF02  Installation
# ---------------------------------------------------------------------------

class TestInstallation:

    def test_wrappers_are_installed_inside_and_originals_restored_after(self, demo):
        injector = _injector(demo)
        assert not injector.is_installed
        with injector.installed() as entered:
            assert entered is injector and injector.is_installed
            assert demo.tool.run_tool is not demo.originals[0]
            assert demo.retrieval.retrieve is not demo.originals[1]
            assert demo.instrumentation.research_synthesize_node is not demo.originals[2]
        assert not injector.is_installed
        assert (
            demo.tool.run_tool, demo.retrieval.retrieve,
            demo.instrumentation.research_synthesize_node,
        ) == demo.originals

    def test_originals_are_restored_after_an_exception(self, demo):
        injector = _injector(demo)
        with pytest.raises(KeyError):
            with injector.installed():
                raise KeyError("boom")
        assert not injector.is_installed
        assert demo.tool.run_tool is demo.originals[0]
        assert demo.retrieval.retrieve is demo.originals[1]
        assert demo.instrumentation.research_synthesize_node is demo.originals[2]

    def test_exactly_the_three_functions_are_replaced(self, demo):
        modules = {"tool": demo.tool, "retrieval": demo.retrieval, "research": demo.research}
        before = {
            (label, name): getattr(module, name)
            for label, module in modules.items()
            for name in dir(module) if not name.startswith("__")
        }
        with _injector(demo).installed():
            changed = sorted(
                key for key, value in before.items()
                if getattr(modules[key[0]], key[1]) is not value
            )
        assert changed == [("retrieval", "retrieve"), ("tool", "run_tool")]
        # The third is the instrumentation's own reference; the research
        # module's function is left alone.
        assert demo.research.research_synthesize_node is demo.originals[2]

    def test_one_stable_set_of_wrappers_for_the_whole_run(self, demo):
        injector = _injector(demo)
        with injector.installed():
            wrappers = (demo.tool.run_tool, demo.retrieval.retrieve)
            for _ in range(5):
                with injector.applied(_effects()):
                    _run_steps(demo, _ONE_RESULT)
                assert (demo.tool.run_tool, demo.retrieval.retrieve) == wrappers

    def test_double_install_is_refused(self, demo):
        injector = _injector(demo)
        with injector.installed():
            with pytest.raises(FaultInstallError, match="already installed"):
                with injector.installed():
                    pass
            # The refused attempt removed nothing.
            assert injector.is_installed
            assert demo.tool.run_tool is not demo.originals[0]
        assert demo.tool.run_tool is demo.originals[0]

    def test_a_second_injector_over_the_first_is_refused(self, demo):
        with _injector(demo).installed():
            with pytest.raises(FaultInstallError, match="already wrapped"):
                with _injector(demo).installed():
                    pass
        assert demo.tool.run_tool is demo.originals[0]

    def test_an_injector_can_be_installed_again_after_it_was_removed(self, demo):
        injector = _injector(demo)
        for _ in range(3):
            with injector.installed():
                assert injector.is_installed
        assert demo.tool.run_tool is demo.originals[0]

    @pytest.mark.parametrize("module, name", [
        ("tool", "run_tool"), ("retrieval", "retrieve"),
        ("instrumentation", "research_synthesize_node"),
    ])
    @pytest.mark.parametrize("value", ["missing", None, "not callable", 42])
    def test_a_missing_or_non_callable_target_is_refused(self, demo, module, name, value):
        parts = {
            "tool": types.SimpleNamespace(**vars(demo.tool)),
            "retrieval": types.SimpleNamespace(**vars(demo.retrieval)),
            "instrumentation": types.SimpleNamespace(**vars(demo.instrumentation)),
        }
        if value == "missing":
            delattr(parts[module], name)
        else:
            setattr(parts[module], name, value)
        injector = FaultInjector(pause=Recorder(), **parts)
        with pytest.raises(FaultInstallError, match=f"{name} is missing or not callable"):
            with injector.installed():
                pass
        assert not injector.is_installed
        # Nothing was replaced anywhere, not even the targets checked earlier.
        for part, original in zip(("tool", "retrieval"), demo.originals):
            if part != module:
                target = "run_tool" if part == "tool" else "retrieve"
                assert getattr(parts[part], target) is original

    @pytest.mark.parametrize("module, caller", [
        ("tool", "tool_agent_node"), ("retrieval", "retrieval_node"),
        ("instrumentation", "instrumented_research_synthesize"),
    ])
    def test_a_missing_calling_function_is_refused(self, demo, module, caller):
        parts = {
            "tool": types.SimpleNamespace(**vars(demo.tool)),
            "retrieval": types.SimpleNamespace(**vars(demo.retrieval)),
            "instrumentation": types.SimpleNamespace(**vars(demo.instrumentation)),
        }
        delattr(parts[module], caller)
        with pytest.raises(FaultInstallError, match=f"{caller} is missing"):
            with FaultInjector(pause=Recorder(), **parts).installed():
                pass

    def test_a_caller_that_no_longer_uses_the_name_is_refused(self, demo):
        tool = types.SimpleNamespace(**vars(demo.tool))
        tool.tool_agent_node = lambda state: {"tool_result": None}
        injector = FaultInjector(
            tool=tool, retrieval=demo.retrieval, instrumentation=demo.instrumentation,
            pause=Recorder(),
        )
        with pytest.raises(FaultInstallError, match="does not call run_tool by name"):
            with injector.installed():
                pass
        assert demo.retrieval.retrieve is demo.originals[1]

    def test_a_tool_module_without_its_exception_class_is_refused(self, demo):
        tool = types.SimpleNamespace(**vars(demo.tool))
        del tool.ToolExecutionError
        injector = FaultInjector(
            tool=tool, retrieval=demo.retrieval, instrumentation=demo.instrumentation,
            pause=Recorder(),
        )
        with pytest.raises(FaultInstallError, match="no exception class named"):
            with injector.installed():
                pass
        assert demo.retrieval.retrieve is demo.originals[1]

    def test_pause_must_be_callable(self, demo):
        with pytest.raises(FaultInstallError, match="pause must be callable"):
            FaultInjector(
                tool=demo.tool, retrieval=demo.retrieval,
                instrumentation=demo.instrumentation, pause=0.1,  # type: ignore[arg-type]
            )

    def test_pause_has_no_default(self):
        import inspect
        parameter = inspect.signature(FaultInjector.__init__).parameters["pause"]
        assert parameter.default is inspect.Parameter.empty
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY

    def test_the_real_modules_have_the_structure_the_injector_checks(self, demo):
        assert "run_tool" in demo.tool.tool_agent_node.__code__.co_names
        assert "retrieve" in demo.retrieval.retrieval_node.__code__.co_names
        instrumentation = (_DEMO / "observability" / "instrumentation.py").read_text(
            encoding="utf-8",
        )
        assert "def instrumented_research_synthesize(state" in instrumentation
        assert "return research_synthesize_node(state)" in instrumentation
        assert issubclass(demo.tool.ToolExecutionError, Exception)


# ---------------------------------------------------------------------------
# WF03  Applying effects
# ---------------------------------------------------------------------------

class TestApplying:

    def test_without_effects_the_wrappers_pass_straight_through(self, demo):
        pause = Recorder()
        expected = _run_steps(demo, _THREE_RESULTS)
        with _injector(demo, pause).installed():
            assert _run_steps(demo, _THREE_RESULTS) == expected
            assert demo.retrieval.retrieve("kafka") == demo.originals[1]("kafka")
        assert pause.seconds == []                       # no pause, no effect at all

    def test_effects_apply_only_inside_the_block(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed():
            with injector.applied(_effects()):
                _run_steps(demo, _ONE_RESULT)
            inside = list(pause.seconds)
            _run_steps(demo, _ONE_RESULT)
            assert pause.seconds == inside == [0.045, 0.12, 0.06]

    def test_effects_are_reset_after_an_exception(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed():
            with pytest.raises(UpstreamServerError):
                with injector.applied(_effects(fault=_fault(ERROR_SERVER))):
                    _run_steps(demo, _ONE_RESULT)
            pause.seconds.clear()
            # The next call in the same thread is unaffected.
            assert _run_steps(demo, _ONE_RESULT)["tool_result"].status == "success"
            assert pause.seconds == []
            assert faults._ACTIVE.get() is None

    def test_effects_are_reset_after_an_unrelated_exception(self, demo):
        injector = _injector(demo)
        with injector.installed():
            with pytest.raises(ZeroDivisionError):
                with injector.applied(_effects()):
                    1 / 0
            assert faults._ACTIVE.get() is None

    def test_applying_needs_an_installed_injector(self, demo):
        injector = _injector(demo)
        with pytest.raises(FaultInstallError, match="not installed"):
            with injector.applied(_effects()):
                pass
        with injector.installed():
            pass
        with pytest.raises(FaultInstallError, match="not installed"):
            with injector.applied(_effects()):
                pass

    def test_nested_effects_in_one_context_are_refused(self, demo):
        injector = _injector(demo)
        with injector.installed():
            with injector.applied(_effects()):
                with pytest.raises(FaultInstallError, match="already applied"):
                    with injector.applied(_effects()):
                        pass
                # The outer effects are still the current ones.
                assert faults._ACTIVE.get().effects == _effects()
            assert faults._ACTIVE.get() is None

    def test_an_unknown_planned_failure_is_refused_before_anything_runs(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        unknown = PlannedFault(Target.TOOL, "SomethingElseError", "x")
        with injector.installed():
            with pytest.raises(FaultInstallError, match="unknown planned failure"):
                with injector.applied(_effects(fault=unknown)):
                    raise AssertionError("the block must not run")
            assert faults._ACTIVE.get() is None and pause.seconds == []

    def test_effects_must_be_effects(self, demo):
        injector = _injector(demo)
        with injector.installed():
            with pytest.raises(FaultInstallError, match="must be an Effects"):
                with injector.applied({"tool_ms": 1}):  # type: ignore[arg-type]
                    pass

    def test_effects_do_not_leak_between_consecutive_requests(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed():
            with pytest.raises(RateLimitError):
                with injector.applied(_effects(tool_ms=30.0, fault=_fault(ERROR_RATE_LIMIT))):
                    _run_steps(demo, _ONE_RESULT)
            with injector.applied(
                _effects(retrieval_effect=RetrievalEffect.DROP_BEST_MATCH)
            ):
                degraded = _run_steps(demo, _THREE_RESULTS)
            with injector.applied(_effects(tool_ms=7.0)):
                healthy = _run_steps(demo, _THREE_RESULTS)
        assert len(degraded["retrieved_context"]) == 2
        assert len(healthy["retrieved_context"]) == 3    # no leftover degradation
        assert healthy["tool_result"].status == "not_found"   # and no leftover fault
        assert pause.seconds == [0.045, 0.03, 0.045, 0.12, 0.06, 0.045, 0.007, 0.06]


# ---------------------------------------------------------------------------
# WF04  Tool wrapper
# ---------------------------------------------------------------------------

class TestTool:

    def test_normal_pauses_the_planned_time_then_returns_the_real_result(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        expected = demo.originals[0]("apache kafka")
        with injector.installed(), injector.applied(_effects(tool_ms=137.5)):
            result = demo.tool.tool_agent_node({"retrieval_query": "apache kafka"})
        assert result == {"tool_result": expected}
        assert pause.seconds == [0.1375]

    def test_the_query_reaches_the_real_tool_unchanged(self, demo):
        seen = []
        tool = types.SimpleNamespace(**vars(demo.tool))
        tool.run_tool = lambda query: seen.append(query) or demo.originals[0](query)
        tool.tool_agent_node = lambda state: {"tool_result": tool.run_tool(state["q"])}
        injector = FaultInjector(
            tool=tool, retrieval=demo.retrieval, instrumentation=demo.instrumentation,
            pause=Recorder(),
        )
        with injector.installed(), injector.applied(_effects()):
            tool.tool_agent_node({"q": "Is Postgres a system of record?"})
        assert seen == ["Is Postgres a system of record?"]

    @pytest.mark.parametrize("error_type, kind, message", [
        (ERROR_SERVER, UpstreamServerError, "Upstream service returned HTTP 500"),
        (ERROR_RATE_LIMIT, RateLimitError,
         "Upstream service returned HTTP 429: rate limit exceeded"),
        (ERROR_TIMEOUT, ToolTimeoutError, "Tool call exceeded the 5000 ms time limit"),
    ])
    def test_generator_owned_failures(self, demo, error_type, kind, message):
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(
            _effects(tool_ms=80.0, fault=_fault(error_type))
        ):
            with pytest.raises(InjectedFault) as excinfo:
                demo.tool.tool_agent_node({"retrieval_query": "apache kafka"})
        assert type(excinfo.value) is kind
        assert str(excinfo.value) == message
        assert type(excinfo.value).__name__ == error_type
        # The planned time passes first; then the call fails.
        assert pause.seconds == [0.08]

    def test_the_real_tool_is_not_called_when_a_failure_is_planned(self, demo):
        calls = []
        tool = types.SimpleNamespace(**vars(demo.tool))
        tool.run_tool = lambda query: calls.append(query)
        tool.tool_agent_node = lambda state: {"tool_result": tool.run_tool(state["q"])}
        injector = FaultInjector(
            tool=tool, retrieval=demo.retrieval, instrumentation=demo.instrumentation,
            pause=Recorder(),
        )
        with injector.installed(), injector.applied(_effects(fault=_fault(ERROR_SERVER))):
            with pytest.raises(UpstreamServerError):
                tool.tool_agent_node({"q": "kafka"})
        assert calls == []

    def test_api_500_as_planned(self, demo):
        request = _first(_plan(Scenario.API_500), Scenario.API_500)
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(effects_of(request)):
            with pytest.raises(UpstreamServerError, match="^Upstream service returned HTTP 500$"):
                demo.tool.run_tool("kafka")
        assert pause.seconds == [request.latency.tool_ms / 1000.0]

    def test_api_429_as_planned_fails_fast(self, demo):
        request = _first(_plan(Scenario.API_429), Scenario.API_429)
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(effects_of(request)):
            with pytest.raises(RateLimitError) as excinfo:
                demo.tool.run_tool("kafka")
        assert str(excinfo.value) == "Upstream service returned HTTP 429: rate limit exceeded"
        assert 0.015 <= pause.seconds[0] <= 0.060

    def test_timeout_asks_for_five_seconds_and_does_not_wait(self, demo):
        import time
        request = _first(_plan(Scenario.TIMEOUT), Scenario.TIMEOUT)
        pause = Recorder()
        injector = _injector(demo, pause)
        started = time.perf_counter()
        with injector.installed(), injector.applied(effects_of(request)):
            with pytest.raises(ToolTimeoutError) as excinfo:
                demo.tool.run_tool("kafka")
        elapsed = time.perf_counter() - started
        assert pause.seconds == [5.0]
        assert str(excinfo.value) == "Tool call exceeded the 5000 ms time limit"
        assert elapsed < 1.0                             # nothing really waited

    def test_repeated_failure_raises_the_demo_applications_own_class(self, demo):
        request = _first(_plan(Scenario.REPEATED_FAILURE), Scenario.REPEATED_FAILURE)
        injector = _injector(demo)
        with injector.installed(), injector.applied(effects_of(request)):
            with pytest.raises(Exception) as excinfo:
                demo.tool.tool_agent_node({"retrieval_query": "apache kafka"})
        assert type(excinfo.value) is demo.tool.ToolExecutionError
        assert not isinstance(excinfo.value, InjectedFault)
        assert type(excinfo.value).__name__ == ERROR_UNAVAILABLE == "ToolExecutionError"

    def test_repeated_failure_has_the_signature_of_the_built_in_failure(self, demo):
        with pytest.raises(demo.tool.ToolExecutionError) as native:
            demo.originals[0](demo.tool.FAIL_TRIGGER)
        request = _first(_plan(Scenario.REPEATED_FAILURE), Scenario.REPEATED_FAILURE)
        injector = _injector(demo)
        with injector.installed(), injector.applied(effects_of(request)):
            with pytest.raises(demo.tool.ToolExecutionError) as injected:
                # The user's own question, not the built-in trigger word.
                demo.tool.run_tool("apache kafka")
        assert type(injected.value) is type(native.value)
        assert str(injected.value) == str(native.value)

    def test_the_tool_exception_class_is_not_defined_again(self):
        source = Path(faults.__file__).read_text(encoding="utf-8")
        classes = [
            node.name for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ClassDef)
        ]
        assert "ToolExecutionError" not in classes
        assert {"InjectedFault", "UpstreamServerError", "RateLimitError",
                "ToolTimeoutError"} <= set(classes)

    def test_exception_hierarchy(self):
        assert InjectedFault.__bases__ == (RuntimeError,)
        for kind in (UpstreamServerError, RateLimitError, ToolTimeoutError):
            assert kind.__bases__ == (InjectedFault,)
        assert not issubclass(FaultInstallError, InjectedFault)

    def test_every_planned_error_type_can_be_raised(self, demo):
        injector = _injector(demo)
        with injector.installed():
            for error_type in ERROR_MESSAGES:
                with pytest.raises(Exception) as excinfo:
                    with injector.applied(_effects(fault=_fault(error_type))):
                        demo.tool.run_tool("kafka")
                assert type(excinfo.value).__name__ == error_type
                assert str(excinfo.value) == ERROR_MESSAGES[error_type]

    def test_repeated_failure_signature_is_stable_across_the_window(self, demo):
        plan = _plan(Scenario.REPEATED_FAILURE)
        (episode,) = plan.episodes
        signatures = set()
        injector = _injector(demo)
        with injector.installed():
            for request in plan.requests[episode.start_index:episode.end_index]:
                with pytest.raises(demo.tool.ToolExecutionError) as excinfo:
                    with injector.applied(effects_of(request)):
                        demo.tool.run_tool("kafka")
                signatures.add((type(excinfo.value).__name__, str(excinfo.value)))
        assert len(signatures) == 1

    def test_recurring_incident_has_one_signature_in_both_episodes(self, demo):
        plan = _plan(Scenario.RECURRING_INCIDENT)
        first, second = plan.episodes
        assert first.end_index < second.start_index      # separated in the plan
        injector = _injector(demo)
        per_episode = []
        with injector.installed():
            for episode in (first, second):
                signatures = set()
                for request in plan.requests[episode.start_index:episode.end_index]:
                    if request.fault is None:
                        continue
                    with pytest.raises(UpstreamServerError) as excinfo:
                        with injector.applied(effects_of(request)):
                            demo.tool.run_tool("kafka")
                    signatures.add((
                        request.fault.target.value, type(excinfo.value).__name__,
                        str(excinfo.value),
                    ))
                per_episode.append(signatures)
        assert per_episode[0] == per_episode[1] == {
            ("tool.execute", "UpstreamServerError", "Upstream service returned HTTP 500"),
        }


# ---------------------------------------------------------------------------
# WF05  Retrieval wrapper
# ---------------------------------------------------------------------------

class TestRetrieval:

    def test_normal_pauses_then_returns_the_real_result_itself(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(_effects(retrieval_ms=52.25)):
            result = demo.retrieval.retrieve("producers consumers exchange event data")
        assert result == demo.originals[1]("producers consumers exchange event data")
        assert pause.seconds == [0.05225]

    def _spy(self, demo):
        """A retrieval module whose real retrieve() records what it is asked."""
        asked, returned = [], []
        retrieval = types.SimpleNamespace(**vars(demo.retrieval))

        def retrieve(query):
            asked.append(query)
            result = demo.originals[1](query)
            returned.append(result)
            return result

        def retrieval_node(state):
            return {"retrieved_context": retrieval.retrieve(state["retrieval_query"])}

        retrieval.retrieve, retrieval.retrieval_node = retrieve, retrieval_node
        injector = FaultInjector(
            tool=demo.tool, retrieval=retrieval, instrumentation=demo.instrumentation,
            pause=Recorder(),
        )
        return injector, retrieval, asked, returned

    @pytest.mark.parametrize("query, before, after", [
        ("producers consumers exchange event data", 3, 2),
        ("apache kafka", 1, 0),
        ("bake sourdough bread", 0, 0),
    ])
    def test_drop_best_match(self, demo, query, before, after):
        injector, retrieval, asked, returned = self._spy(demo)
        with injector.installed(), injector.applied(
            _effects(retrieval_effect=RetrievalEffect.DROP_BEST_MATCH)
        ):
            result = retrieval.retrieval_node({"retrieval_query": query})["retrieved_context"]
        # The real lookup was asked exactly the original query, once.
        assert asked == [query]
        (original,) = returned
        assert len(original) == before and len(result) == after
        # What remains are the same objects, in the same order.
        assert len(result) == len(original[1:])
        assert all(kept is source for kept, source in zip(result, original[1:]))
        # The original list was not changed.
        assert len(original) == before and result is not original

    def test_remaining_scores_are_the_real_ones(self, demo):
        injector, retrieval, _, returned = self._spy(demo)
        query = "producers consumers exchange event data"
        healthy = demo.originals[1](query)
        with injector.installed(), injector.applied(
            _effects(retrieval_effect=RetrievalEffect.DROP_BEST_MATCH)
        ):
            result = retrieval.retrieve(query)
        assert [c.relevance_score for c in result] == [c.relevance_score for c in healthy[1:]]
        assert [c.document_id for c in result] == [c.document_id for c in healthy[1:]]
        assert [c.content for c in result] == [c.content for c in healthy[1:]]
        # The best match is the one that is gone.
        assert healthy[0].document_id not in {c.document_id for c in result}

    def test_no_score_is_ever_written(self):
        source = Path(faults.__file__).read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        for word in ("relevance_score", "model_copy", "RetrievedChunk", "score ="):
            assert word not in code.split('"""', 2)[2]

    @pytest.mark.parametrize("query, healthy, degraded", [
        ("how do producers and consumers exchange event data", (3, 0.625), (2, 0.25)),
        ("apache kafka", (1, 1.0), (0, None)),
        ("bake sourdough bread", (0, None), (0, None)),
    ])
    def test_existing_telemetry_fields_can_represent_the_degradation(
        self, demo, query, healthy, degraded,
    ):
        # (count, top score) as the existing instrumentation computes them:
        # the top score is simply absent when nothing was retrieved.
        injector = _injector(demo)
        with injector.installed():
            with injector.applied(_effects()):
                assert _summary(demo.retrieval.retrieve(query)) == healthy
            with injector.applied(
                _effects(retrieval_effect=RetrievalEffect.DROP_BEST_MATCH)
            ):
                assert _summary(demo.retrieval.retrieve(query)) == degraded

    def test_the_degraded_result_is_a_valid_result_for_the_agent(self, demo):
        injector = _injector(demo)
        with injector.installed(), injector.applied(
            _effects(retrieval_effect=RetrievalEffect.DROP_BEST_MATCH)
        ):
            state = _run_steps(demo, _THREE_RESULTS)
            empty = _run_steps(demo, _ONE_RESULT)
        assert len(state["retrieved_context"]) == 2 and state["synthesized_answer"]
        # With nothing retrieved the agent still answers, from the tool alone.
        assert empty["retrieved_context"] == [] and empty["synthesized_answer"]
        assert empty["tool_result"].status == "success"

    def test_retrieval_quality_as_planned_keeps_the_users_question(self, demo):
        plan = _plan(Scenario.RETRIEVAL_QUALITY, persona=Persona.RESEARCH_SESSION)
        normal = _plan(Scenario.NORMAL, persona=Persona.RESEARCH_SESSION)
        injector, retrieval, asked, _ = self._spy(demo)
        checked = 0
        with injector.installed():
            for request in plan.requests[500:560]:
                if request.retrieval_effect is None:
                    continue
                checked += 1
                assert request.query == normal.requests[request.request_index].query
                derived = demo.research._derive_retrieval_query(request.query)
                healthy = demo.originals[1](derived)
                asked.clear()
                with injector.applied(effects_of(request)):
                    result = retrieval.retrieve(derived)
                assert asked == [derived]
                assert len(result) == max(len(healthy) - 1, 0)
        assert checked > 30

    def test_latency_only_requests_do_not_degrade_the_result(self, demo):
        request = _first(_plan(Scenario.RETRIEVAL_LATENCY), Scenario.RETRIEVAL_LATENCY)
        assert request.retrieval_effect is None
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(effects_of(request)):
            result = demo.retrieval.retrieve("producers consumers exchange event data")
        assert len(result) == 3
        assert pause.seconds == [request.latency.retrieval_ms / 1000.0]
        assert pause.seconds[0] > 0.2                    # many times the 45 ms baseline


# ---------------------------------------------------------------------------
# WF06  Synthesis wrapper
# ---------------------------------------------------------------------------

class TestSynthesis:

    def test_normal_pauses_then_returns_the_real_answer(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        state = {
            "user_request": _ONE_RESULT,
            "retrieved_context": demo.originals[1]("apache kafka"),
            "tool_result": demo.originals[0]("apache kafka"),
        }
        expected = demo.originals[2](state)
        with injector.installed(), injector.applied(_effects(synthesis_ms=64.0)):
            result = demo.instrumentation.instrumented_research_synthesize(state)
        assert result == expected and result["synthesized_answer"]
        assert pause.seconds == [0.064]

    def test_the_instrumentation_reference_is_what_gets_replaced(self, demo):
        with _injector(demo).installed():
            assert demo.instrumentation.research_synthesize_node is not demo.originals[2]
            # Not the research module's own function: replacing that would
            # not be seen by the instrumentation, which holds its own name.
            assert demo.research.research_synthesize_node is demo.originals[2]

    def test_slow_synthesis_as_planned(self, demo):
        request = _first(_plan(Scenario.SLOW_SYNTHESIS), Scenario.SLOW_SYNTHESIS)
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(effects_of(request)):
            _run_steps(demo, _ONE_RESULT)
        retrieval_s, tool_s, synthesis_s = pause.seconds
        assert synthesis_s == request.latency.synthesis_ms / 1000.0 > 0.2
        assert retrieval_s < 0.15 and tool_s < 0.6       # the others keep their baseline


# ---------------------------------------------------------------------------
# WF07  Whole attempts and wrapper reach
# ---------------------------------------------------------------------------

class TestAttemptsAndReach:

    def test_normal_request_changes_no_result_and_pauses_its_baseline(self, demo):
        request = _plan(Scenario.NORMAL).requests[0]
        untouched = _run_steps(demo, request.query)
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(effects_of(request)) as reach:
            state = _run_steps(demo, request.query)
        assert state == untouched
        assert pause.seconds == [
            request.latency.retrieval_ms / 1000.0, request.latency.tool_ms / 1000.0,
            request.latency.synthesis_ms / 1000.0,
        ]
        assert reach.as_dict() == {"tool": 1, "retrieval": 1, "synthesis": 1}
        assert reach.problems(effects_of(request)) == ()

    @pytest.mark.parametrize("scenario, slowed", [
        (Scenario.SLOW_TOOL, 1), (Scenario.SLOW_SYNTHESIS, 2), (Scenario.RETRIEVAL_LATENCY, 0),
    ])
    def test_a_latency_scenario_enlarges_one_pause_only(self, demo, scenario, slowed):
        affected = _first(_plan(scenario), scenario)
        baseline = _plan(Scenario.NORMAL).requests[affected.request_index]
        seconds = {}
        for name, request in (("affected", affected), ("baseline", baseline)):
            pause = Recorder()
            injector = _injector(demo, pause)
            with injector.installed(), injector.applied(effects_of(request)):
                _run_steps(demo, request.query)
            seconds[name] = pause.seconds
        for position in range(3):
            if position == slowed:
                assert seconds["affected"][position] > 5 * seconds["baseline"][position]
            else:
                assert seconds["affected"][position] == seconds["baseline"][position]

    def test_a_failing_attempt_never_reaches_the_answer_step(self, demo):
        effects = _effects(fault=_fault(ERROR_SERVER))
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed():
            with pytest.raises(UpstreamServerError):
                with injector.applied(effects) as reach:
                    _run_steps(demo, _ONE_RESULT)
        assert reach.as_dict() == {"tool": 1, "retrieval": 1, "synthesis": 0}
        assert reach.problems(effects) == ()             # exactly what a failure reaches
        assert pause.seconds == [0.045, 0.12]

    def test_reach_expectation(self):
        assert Reach.expected(_effects()) == {"tool": 1, "retrieval": 1, "synthesis": 1}
        assert Reach.expected(_effects(fault=_fault(ERROR_TIMEOUT))) == {
            "tool": 1, "retrieval": 1, "synthesis": 0,
        }

    def test_an_attempt_that_reaches_nothing_is_reported(self, demo):
        # What would happen if the application stopped calling the wrapped
        # names, or ran its steps outside the caller's context.
        injector = _injector(demo)
        with injector.installed(), injector.applied(_effects()) as reach:
            pass
        assert reach.problems(_effects()) == (
            "tool: reached 0 time(s), expected 1",
            "retrieval: reached 0 time(s), expected 1",
            "synthesis: reached 0 time(s), expected 1",
        )

    def test_a_step_run_outside_the_context_is_not_counted(self, demo):
        pause = Recorder()
        injector = _injector(demo, pause)
        outcome = {}
        with injector.installed(), injector.applied(_effects()) as reach:
            # A plain thread does not inherit the context variable.
            thread = threading.Thread(
                target=lambda: outcome.update(result=demo.tool.run_tool("apache kafka")),
            )
            thread.start()
            thread.join()
        assert outcome["result"].status == "success"     # passed through, unaffected
        assert pause.seconds == [] and reach.tool == 0
        assert "tool: reached 0 time(s), expected 1" in reach.problems(_effects())

    def test_a_wrapper_reached_twice_is_reported(self, demo):
        injector = _injector(demo)
        with injector.installed(), injector.applied(_effects()) as reach:
            _run_steps(demo, _ONE_RESULT)
            demo.tool.run_tool("apache kafka")
        assert reach.problems(_effects()) == ("tool: reached 2 time(s), expected 1",)

    def test_reach_is_per_attempt(self, demo):
        injector = _injector(demo)
        with injector.installed():
            with injector.applied(_effects()) as first:
                _run_steps(demo, _ONE_RESULT)
            with injector.applied(_effects()) as second:
                demo.retrieval.retrieve("apache kafka")
        assert first is not second
        assert first.as_dict() == {"tool": 1, "retrieval": 1, "synthesis": 1}
        assert second.as_dict() == {"tool": 0, "retrieval": 1, "synthesis": 0}

    def test_reach_is_bookkeeping_not_telemetry(self):
        assert Reach.__slots__ == ("tool", "retrieval", "synthesis")
        source = Path(faults.__file__).read_text(encoding="utf-8")
        for word in ("set_attribute", "span", "agentops.workload"):
            assert word not in source.split('"""', 2)[2]

    def test_a_retry_storm_request_runs_as_separate_attempts(self, demo):
        request = next(
            r for r in _plan(Scenario.RETRY_STORM).requests
            if len(r.retries) == 3 and r.retries[-1].fault is None
        )
        pause = Recorder()
        injector = _injector(demo, pause)
        outcomes, backoffs = [], []
        with injector.installed():
            for attempt in attempts(request):
                backoffs.append(attempt.backoff_seconds)
                try:
                    with injector.applied(attempt.effects) as reach:
                        _run_steps(demo, attempt.query)
                    outcomes.append("ok")
                except UpstreamServerError:
                    outcomes.append("failed")
                assert reach.problems(attempt.effects) == ()
        assert outcomes == ["failed", "failed", "failed", "ok"]
        assert backoffs[0] == 0.0 and backoffs[1] < backoffs[2] < backoffs[3]
        # Each failing attempt paused retrieval and tool; the last all three.
        assert len(pause.seconds) == 2 + 2 + 2 + 3

    @pytest.mark.parametrize("seed", [1, 42])
    def test_a_mixed_plan_is_carried_out_exactly_as_planned(self, demo, seed):
        plan = _plan(Scenario.MIXED_PRODUCTION, traces=2000, seed=seed, rate=50.0)
        injector = _injector(demo)
        seen = set()
        with injector.installed():
            for request in plan.requests:
                if request.scenario is Scenario.NORMAL and request.request_index % 25:
                    continue
                seen.add(request.scenario)
                effects = effects_of(request)
                derived = demo.research._derive_retrieval_query(
                    request.query or "No request was provided.",
                )
                healthy = demo.originals[1](derived)
                try:
                    with injector.applied(effects) as reach:
                        state = _run_steps(demo, request.query or "No request was provided.")
                    raised = None
                except Exception as exc:  # noqa: BLE001 - compared with the plan below
                    raised = exc
                # Failure exactly when planned, and of the planned type.
                if request.fault is None:
                    assert raised is None
                    expected = healthy[1:] if request.retrieval_effect else healthy
                    assert state["retrieved_context"] == expected
                else:
                    assert type(raised).__name__ == request.fault.error_type
                    assert str(raised) == request.fault.error_message
                assert reach.problems(effects) == ()
        assert len(seen) >= 5


# ---------------------------------------------------------------------------
# WF08  Concurrency
# ---------------------------------------------------------------------------

_THREADS = 32


class TestConcurrency:

    def _kind(self, index: int) -> str:
        return ("normal", "fault", "degraded", "fault")[index % 4]

    def test_thirty_two_attempts_at_once_stay_isolated(self, demo):
        # Every pause blocks until all threads are inside the same wrapper,
        # so the attempts are certain to overlap.  No clock is involved.
        retrieval_gate = threading.Barrier(_THREADS)
        tool_gate = threading.Barrier(_THREADS)
        local = threading.local()
        recorded: dict[int, list[float]] = {}
        lock = threading.Lock()

        def pause(seconds: float) -> None:
            step = getattr(local, "step", 0)
            local.step = step + 1
            with lock:
                recorded.setdefault(local.index, []).append(seconds)
            if step == 0:
                retrieval_gate.wait(timeout=60)
            elif step == 1:
                tool_gate.wait(timeout=60)

        errors = (ERROR_SERVER, ERROR_RATE_LIMIT, ERROR_TIMEOUT, ERROR_UNAVAILABLE)
        injector = _injector(demo, pause)
        results: dict[int, tuple] = {}
        start = threading.Barrier(_THREADS)

        def worker(index: int) -> None:
            local.index = index
            kind = self._kind(index)
            effects = _effects(
                tool_ms=1000.0 + index, retrieval_ms=2000.0 + index,
                synthesis_ms=3000.0 + index,
                fault=_fault(errors[index % len(errors)]) if kind == "fault" else None,
                retrieval_effect=(
                    RetrievalEffect.DROP_BEST_MATCH if kind == "degraded" else None
                ),
            )
            start.wait(timeout=60)
            try:
                with injector.applied(effects) as reach:
                    state = _run_steps(demo, _THREE_RESULTS)
                results[index] = ("ok", len(state["retrieved_context"]), reach.as_dict())
            except Exception as exc:  # noqa: BLE001 - recorded and checked below
                results[index] = (type(exc).__name__, str(exc), reach.as_dict())

        with injector.installed():
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(_THREADS)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=120)
            assert not any(thread.is_alive() for thread in threads)

        assert sorted(results) == list(range(_THREADS))
        assert not retrieval_gate.broken and not tool_gate.broken
        for index in range(_THREADS):
            kind = self._kind(index)
            outcome = results[index]
            if kind == "fault":
                error_type = errors[index % len(errors)]
                assert outcome[:2] == (error_type, ERROR_MESSAGES[error_type])
                assert outcome[2] == {"tool": 1, "retrieval": 1, "synthesis": 0}
                assert recorded[index] == [(2000.0 + index) / 1000.0, (1000.0 + index) / 1000.0]
            else:
                assert outcome[0] == "ok"
                assert outcome[1] == (2 if kind == "degraded" else 3)
                assert outcome[2] == {"tool": 1, "retrieval": 1, "synthesis": 1}
                # Each attempt paused its OWN three latencies and no other's.
                assert recorded[index] == [
                    (2000.0 + index) / 1000.0, (1000.0 + index) / 1000.0,
                    (3000.0 + index) / 1000.0,
                ]
        kinds = [self._kind(i) for i in range(_THREADS)]
        assert kinds.count("normal") == 8 and kinds.count("degraded") == 8
        assert kinds.count("fault") == 16

    def test_a_context_copy_carries_the_effects_with_it(self, demo):
        # How a pool that copies the caller's context would run a step.
        import contextvars
        pause = Recorder()
        injector = _injector(demo, pause)
        with injector.installed(), injector.applied(_effects(tool_ms=9.0)) as reach:
            context = contextvars.copy_context()
            outcome = {}
            thread = threading.Thread(
                target=lambda: outcome.update(
                    result=context.run(demo.tool.run_tool, "apache kafka"),
                ),
            )
            thread.start()
            thread.join()
        assert outcome["result"].status == "success"
        assert pause.seconds == [0.009] and reach.tool == 1

    def test_effects_of_one_thread_are_invisible_in_another(self, demo):
        injector = _injector(demo)
        inside, release = threading.Event(), threading.Event()
        seen = {}

        def holder() -> None:
            with injector.applied(_effects(fault=_fault(ERROR_SERVER))):
                inside.set()
                release.wait(timeout=60)

        with injector.installed():
            thread = threading.Thread(target=holder)
            thread.start()
            assert inside.wait(timeout=60)
            # A failure is current in the other thread; here nothing is.
            seen["active"] = faults._ACTIVE.get()
            seen["result"] = demo.tool.run_tool("apache kafka")
            release.set()
            thread.join(timeout=60)
        assert seen["active"] is None and seen["result"].status == "success"

    def test_effects_of_another_injector_are_ignored(self, demo):
        first = _injector(demo)
        other_tool = types.SimpleNamespace(**vars(demo.tool))
        other_retrieval = types.SimpleNamespace(**vars(demo.retrieval))
        other_instrumentation = types.SimpleNamespace(**vars(demo.instrumentation))
        other_tool.tool_agent_node = lambda state: other_tool.run_tool(state)
        other_retrieval.retrieval_node = lambda state: other_retrieval.retrieve(state)
        other_instrumentation.instrumented_research_synthesize = (
            lambda state: other_instrumentation.research_synthesize_node(state)
        )
        pause = Recorder()
        second = FaultInjector(
            tool=other_tool, retrieval=other_retrieval,
            instrumentation=other_instrumentation, pause=pause,
        )
        with first.installed(), second.installed():
            with first.applied(_effects(fault=_fault(ERROR_SERVER))):
                # The second injector's wrapper sees effects that are not its own.
                assert other_tool.run_tool("apache kafka").status == "success"
        assert pause.seconds == []


# ---------------------------------------------------------------------------
# WF09  Guards
# ---------------------------------------------------------------------------

def _imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
    return found


def _calls(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            function = node.func
            found.add(function.id if isinstance(function, ast.Name) else getattr(
                function, "attr", "",
            ))
    return found


_FAULTS = Path(faults.__file__)


class TestGuards:

    def test_imports_are_the_standard_library_and_the_plan_model(self):
        assert _imports(_FAULTS) == {
            "__future__", "math", "contextlib", "contextvars", "dataclasses", "typing",
            ".plan", ".scenarios",
        }

    @pytest.mark.parametrize("module", [
        "time", "random", "secrets", "datetime", "threading", "asyncio", "subprocess",
        "socket", "http", "urllib", "requests", "psycopg", "confluent_kafka",
        "opentelemetry", "docker", "os", "agents", "observability", "graph", "langgraph",
        "state", "schemas",
    ])
    def test_forbidden_module_is_not_imported(self, module):
        assert not any(
            name.lstrip(".").split(".")[0] == module for name in _imports(_FAULTS)
        )

    def test_importing_faults_loads_no_demo_or_telemetry_module(self):
        import subprocess
        code = (
            "import sys, workload_generator.faults;"
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in "
            "('agents','observability','graph','langgraph','opentelemetry',"
            "'confluent_kafka','psycopg','pydantic','docker','requests'));"
            "print(bad)"
        )
        import os
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=_FAULTS.parents[1], capture_output=True,
            text=True,
            env={**{k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH")},
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "[]"

    def test_nothing_waits_and_nothing_is_contacted(self):
        calls = _calls(_FAULTS)
        for name in ("sleep", "run", "Popen", "system", "connect", "create_connection",
                     "urlopen", "Producer", "Consumer", "invoke", "getenv", "open",
                     "start_as_current_span", "set_attribute", "export"):
            assert name not in calls, name

    def test_waiting_is_only_ever_the_injected_pause(self):
        source = _FAULTS.read_text(encoding="utf-8")
        assert source.count("self._pause(") == 3         # one per wrapper
        assert "import time" not in source and "time.sleep" not in source

    def test_no_random_decision_is_made_here(self):
        # Every name the code uses; prose in docstrings is not code.
        names = set()
        for node in ast.walk(ast.parse(_FAULTS.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.alias):
                names.add(node.name)
        for word in ("random", "Random", "Draw", "uniform", "choice", "shuffle", "seed",
                     "randint", "Scenario", "SPECS", "plan_episodes"):
            assert word not in names, word

    def test_the_fault_layer_does_not_know_scenarios(self):
        # It reads effects; which scenario produced them is the planner's affair.
        assert not hasattr(faults, "Scenario") and not hasattr(faults, "SPECS")

    def test_no_environment_file_or_endpoint(self):
        source = _FAULTS.read_text(encoding="utf-8")
        for word in ("os.environ", "localhost", "4317", "9092", "5432", "http://",
                     "https://", "sys.path", "demo-app", "demo_app"):
            assert word not in source, word

    def test_no_retry_or_workload_telemetry_attribute_is_introduced(self):
        # Every module but the execution driver sets no span attribute at all.
        # The driver sets the approved root-span attributes and nothing about
        # retries or attempts.
        for path in _FAULTS.parent.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            if path.name == "real_driver.py":
                for word in ("agentops.retry", "retry_attempt", "workload.attempt",
                             "workload.retry"):
                    assert word not in text, (path.name, word)
                continue
            for word in ("agentops.workload", "agentops.retry", "retry_attempt",
                         "set_attribute"):
                assert word not in text, (path.name, word)

    def test_the_command_still_refuses_to_send(self, capsys):
        from workload_generator import cli
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--send"])
        assert excinfo.value.code == 2
        assert "--send is not available" in capsys.readouterr().err

    def test_demo_application_files_are_unchanged_by_these_tests(self, demo):
        assert _demo_hashes() == _DEMO_BEFORE
        assert len(_DEMO_BEFORE) >= 8

    def test_the_real_modules_are_left_unwrapped(self, demo):
        assert (
            demo.tool.run_tool, demo.retrieval.retrieve,
            demo.instrumentation.research_synthesize_node,
        ) == demo.originals
        for function in (demo.tool.run_tool, demo.retrieval.retrieve):
            assert not getattr(function, faults._WRAPPER_MARK, False)
        assert faults._ACTIVE.get() is None

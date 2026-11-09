"""
workload-generator/tests/integration/test_real_driver.py

Offline integration tests for real_driver.py.

What is real here: the demo application's compiled agent graph, its
instrumentation, the fault injector, and the driver with its own tracer
provider and batching span processor.

What is not: the exporter is an in-memory one, the reachability check is a
recorder, and time is a counter that only advances when something "waits".
No collector, no Kafka, no database, no Docker, no network; an automatic
fixture fails any test that tries to open a TCP connection.

Test inventory:
    RD01  Endpoint and environment checks
    RD02  Outcome classification
    RD03  The production path, with every boundary replaced
    RD04  Healthy trace
    RD05  Failed trace
    RD06  Retrieval quality and slow synthesis
    RD07  Root span attributes
    RD08  Client retries
    RD09  Concurrency
    RD10  Integrity: the run stops
    RD11  Arrival schedule and deadline
    RD12  Export accounting
    RD13  Lifecycle: everything is put back
    RD14  Real waiting appears in the existing spans
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import socket
import sys
import threading
import time
import types
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from workload_generator import real_driver
from workload_generator.faults import (
    Effects,
    RateLimitError,
    UpstreamServerError,
    attempts,
)
from workload_generator.personas import Persona
from workload_generator.plan import Plan, PlanConfig, PlannedFault, build_plan
from workload_generator.real_driver import (
    Demo,
    DriverError,
    Endpoint,
    EndpointError,
    Outcome,
    classify,
    execute,
    otel_environment_names,
    parse_endpoint,
    run_real,
)
from workload_generator.report import OUTCOMES
from workload_generator.scenarios import (
    ERROR_MESSAGES,
    ERROR_SERVER,
    RetrievalEffect,
    Scenario,
    Target,
)

_REPO = Path(__file__).resolve().parents[3]
_DEMO_DIR = _REPO / "demo-app"
_ENDPOINT_TEXT = "http://localhost:14317"

_HEALTHY = [
    "agentops.request", "supervisor.start", "research.plan", "retrieval.search",
    "tool.execute", "research.synthesize", "supervisor.finalize",
]
_FAILED = _HEALTHY[:5]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test in this module may open a TCP connection."""
    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to open a network connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    for name in [n for n in __import__("os").environ if n.upper().startswith("OTEL_")]:
        monkeypatch.delenv(name)


@pytest.fixture(scope="module")
def demo() -> Demo:
    """The demo application, loaded the way the driver loads it."""
    sys.path.insert(0, str(_DEMO_DIR))
    try:
        loaded = real_driver.load_demo()
    finally:
        sys.path.remove(str(_DEMO_DIR))
    return loaded


class FakeTime:
    """A clock that advances only when something asks to wait."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.now = 1000.0
        self.waits: list[float] = []

    def clock(self) -> float:
        with self._lock:
            return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0.0
        with self._lock:
            self.now += seconds
            self.waits.append(seconds)


def _exporter():
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    return InMemorySpanExporter()


def _plan(scenario: Scenario = Scenario.NORMAL, traces: int = 40, **overrides) -> Plan:
    values = dict(seed=42, run_id="driver-tests", scenario=scenario, traces=traces, rate=20.0)
    values.update(overrides)
    return build_plan(PlanConfig(**values))


def _subset(plan: Plan, requests) -> Plan:
    """A plan of the given requests only, all arriving at once."""
    requests = tuple(dataclasses.replace(r, arrival_offset_seconds=0.0) for r in requests)
    return Plan(
        config=plan.config, requests=requests, episodes=(),
        session_count=len({r.session_id for r in requests}),
    )


def _execute(plan: Plan, demo: Demo, *, exporter=None, fake=None, concurrency: int = 1,
             max_duration: float = 86_400.0, **kwargs):
    exporter = exporter if exporter is not None else _exporter()
    fake = fake if fake is not None else FakeTime()
    report = execute(
        plan, demo=demo, span_exporter=exporter, endpoint="in-memory",
        concurrency=concurrency, max_duration_seconds=max_duration,
        pause=fake.sleep, clock=fake.clock, **kwargs,
    )
    return report, exporter, fake


def _traces(exporter) -> dict[int, list]:
    grouped = defaultdict(list)
    for span in exporter.get_finished_spans():
        grouped[span.get_span_context().trace_id].append(span)
    return grouped


def _names(spans) -> list[str]:
    return [span.name for span in sorted(spans, key=lambda s: s.start_time)]


def _root(spans):
    (root,) = [span for span in spans if span.name == "agentops.request"]
    return root


def _span(spans, name: str):
    (found,) = [span for span in spans if span.name == name]
    return found


def _parents_ok(spans) -> bool:
    root = _root(spans)
    ids = {span.get_span_context().span_id for span in spans}
    return root.parent is None and all(
        span is root or (span.parent is not None and span.parent.span_id in ids)
        for span in spans
    )


def _by_request_id(exporter) -> dict[str, list]:
    return {
        _root(spans).attributes["agentops.request_id"]: spans
        for spans in _traces(exporter).values()
    }


def _planned_attempts(plan: Plan) -> dict[str, tuple]:
    """request id -> (planned request, attempt), for every planned submission."""
    return {
        attempt.request_id: (request, attempt)
        for request in plan.requests for attempt in attempts(request)
    }


def _clean(report) -> None:
    """A run that did exactly what was planned and exported everything."""
    assert report.run_status == "completed", report.problems
    assert report.problems == ()
    for name in ("unexpected_failure", "missing_failure", "reach_failure", "not_started"):
        assert report.attempts[name] == 0
    assert report.flush_ok and report.export_failures == 0
    assert report.spans_ended == report.spans_exported_successfully > 0


# ---------------------------------------------------------------------------
# RD01  Endpoint and environment
# ---------------------------------------------------------------------------

class TestEndpointAndEnvironment:

    def test_a_valid_loopback_endpoint(self):
        assert parse_endpoint(_ENDPOINT_TEXT) == Endpoint(
            url=_ENDPOINT_TEXT, host="localhost", port=14317, is_loopback=True,
        )

    def test_an_endpoint_error_is_a_driver_error(self):
        assert issubclass(EndpointError, DriverError)
        with pytest.raises(DriverError):
            parse_endpoint("http://localhost:4317")

    @pytest.mark.parametrize("value", [None, 14317, b"http://localhost:14317"])
    def test_a_non_text_endpoint_is_refused(self, value):
        with pytest.raises(EndpointError):
            parse_endpoint(value)  # type: ignore[arg-type]

    def test_remote_needs_the_flag_and_is_marked(self):
        with pytest.raises(EndpointError, match="--allow-remote-endpoint"):
            parse_endpoint("http://collector.example.com:14317")
        endpoint = parse_endpoint("http://collector.example.com:14317", allow_remote=True)
        assert endpoint.is_loopback is False

    def test_the_flag_does_not_unlock_the_refused_ports(self):
        for port in (4317, 4318):
            with pytest.raises(EndpointError, match=f"port {port} is refused"):
                parse_endpoint(f"http://localhost:{port}", allow_remote=True)

    def test_credentials_are_never_repeated_in_the_error(self):
        with pytest.raises(EndpointError) as excinfo:
            parse_endpoint("http://someuser:hunter2@localhost:14317")
        assert "hunter2" not in str(excinfo.value) and "someuser" not in str(excinfo.value)

    def test_environment_names_only(self):
        environ = {
            "PATH": "x", "OTEL_SDK_DISABLED": "true", "otel_lowercase": "1",
            "OTEL_EXPORTER_OTLP_HEADERS": "authorization=SECRET", "NOT_OTEL_X": "1",
        }
        names = otel_environment_names(environ)
        assert names == ("OTEL_EXPORTER_OTLP_HEADERS", "OTEL_SDK_DISABLED", "otel_lowercase")
        assert "SECRET" not in repr(names) and "true" not in names

    def test_a_clean_environment_has_no_names(self):
        assert otel_environment_names({"PATH": "x", "HOME": "y"}) == ()
        assert otel_environment_names() == ()            # this process, see the fixture

    def test_the_real_reachability_check_reports_an_unreachable_endpoint(self, monkeypatch):
        # The socket call is replaced: nothing is contacted.
        def refused(address, timeout):
            assert address == ("localhost", 14317) and timeout == 3.0
            raise ConnectionRefusedError("refused")

        monkeypatch.setattr(socket, "create_connection", refused)
        with pytest.raises(DriverError, match="nothing is reachable at localhost:14317"):
            real_driver.check_reachable("localhost", 14317)

    def test_the_real_reachability_check_closes_its_connection(self, monkeypatch):
        closed = []
        connection = types.SimpleNamespace(close=lambda: closed.append(True))
        monkeypatch.setattr(socket, "create_connection", lambda address, timeout: connection)
        assert real_driver.check_reachable("127.0.0.1", 14317) is None
        assert closed == [True]


# ---------------------------------------------------------------------------
# RD02  Classification
# ---------------------------------------------------------------------------

def _fault_effects(error_type: str = ERROR_SERVER) -> Effects:
    return Effects(1.0, 1.0, 1.0, fault=PlannedFault(
        Target.TOOL, error_type, ERROR_MESSAGES[error_type],
    ))


_NO_FAULT = Effects(1.0, 1.0, 1.0)


class TestClassification:

    def test_success_as_planned(self):
        assert classify(_NO_FAULT, None, ()) == (Outcome.EXPECTED_SUCCESS, "")

    def test_failure_as_planned(self):
        raised = UpstreamServerError(ERROR_MESSAGES[ERROR_SERVER])
        assert classify(_fault_effects(), raised, ()) == (Outcome.EXPECTED_FAILURE, "")

    def test_an_unplanned_failure(self):
        outcome, detail = classify(_NO_FAULT, RuntimeError("boom"), ())
        assert outcome is Outcome.UNEXPECTED_FAILURE
        assert detail == "no failure was planned; raised RuntimeError: boom"

    def test_a_planned_failure_that_did_not_happen(self):
        outcome, detail = classify(_fault_effects(), None, ())
        assert outcome is Outcome.MISSING_FAILURE
        assert detail == "planned UpstreamServerError; nothing raised"

    @pytest.mark.parametrize("raised", [
        RateLimitError(ERROR_MESSAGES[ERROR_SERVER]),            # wrong type
        UpstreamServerError("some other message"),               # wrong message
        RuntimeError(ERROR_MESSAGES[ERROR_SERVER]),
    ])
    def test_a_different_failure_than_planned_is_unexpected(self, raised):
        outcome, detail = classify(_fault_effects(), raised, ())
        assert outcome is Outcome.UNEXPECTED_FAILURE
        assert detail.startswith("planned UpstreamServerError; raised ")

    @pytest.mark.parametrize("effects, raised", [
        (_NO_FAULT, None),
        (_fault_effects(), UpstreamServerError(ERROR_MESSAGES[ERROR_SERVER])),
        (_NO_FAULT, RuntimeError("x")),
    ])
    def test_a_reach_problem_outranks_everything(self, effects, raised):
        outcome, detail = classify(effects, raised, ("tool: reached 0 time(s), expected 1",))
        assert outcome is Outcome.REACH_FAILURE
        assert detail.startswith("tool: reached 0 time(s), expected 1 (")

    def test_outcome_vocabulary_matches_the_report(self):
        assert tuple(outcome.value for outcome in Outcome) == OUTCOMES
        assert real_driver.WORKLOAD_OUTCOMES == {
            Outcome.EXPECTED_SUCCESS, Outcome.EXPECTED_FAILURE,
        }
        assert real_driver.INTEGRITY_OUTCOMES == {
            Outcome.UNEXPECTED_FAILURE, Outcome.MISSING_FAILURE, Outcome.REACH_FAILURE,
        }
        assert Outcome.NOT_STARTED not in (
            real_driver.WORKLOAD_OUTCOMES | real_driver.INTEGRITY_OUTCOMES
        )


# ---------------------------------------------------------------------------
# RD03  The production path, every boundary replaced
# ---------------------------------------------------------------------------

class TestProductionPath:

    def _run(self, demo, order, **overrides):
        fake = FakeTime()
        exporter = _exporter()
        kwargs = dict(
            endpoint=parse_endpoint(_ENDPOINT_TEXT), concurrency=2, max_duration_seconds=600.0,
            reachability=lambda host, port: order.append(("reach", host, port)),
            demo_loader=lambda: order.append(("demo",)) or demo,
            exporter_factory=lambda endpoint: order.append(("exporter", endpoint.url)) or exporter,
            pause=fake.sleep, clock=fake.clock,
        )
        kwargs.update(overrides)
        return run_real(_plan(traces=10), **kwargs), exporter

    def test_reachability_then_demo_then_exporter_then_execution(self, demo):
        order = []
        report, exporter = self._run(demo, order)
        assert order == [("reach", "localhost", 14317), ("demo",), ("exporter", _ENDPOINT_TEXT)]
        _clean(report)
        assert report.endpoint == _ENDPOINT_TEXT
        assert len(_traces(exporter)) == 10

    def test_an_unreachable_endpoint_executes_nothing(self, demo):
        order = []

        def unreachable(host, port):
            raise DriverError("nothing is reachable")

        with pytest.raises(DriverError, match="nothing is reachable"):
            self._run(demo, order, reachability=unreachable)
        assert order == []                               # demo not loaded, no exporter built

    def test_otel_variables_refuse_the_run_before_anything_else(self, demo, monkeypatch):
        monkeypatch.setenv("OTEL_SDK_DISABLED", "true-SECRET")
        order = []
        with pytest.raises(DriverError) as excinfo:
            self._run(demo, order)
        assert "OTEL_SDK_DISABLED" in str(excinfo.value)
        assert "true-SECRET" not in str(excinfo.value)
        assert order == []

    def test_production_defaults_are_the_real_ones(self):
        import inspect
        defaults = {
            name: parameter.default
            for name, parameter in inspect.signature(run_real).parameters.items()
        }
        assert defaults["reachability"] is real_driver.check_reachable
        assert defaults["demo_loader"] is real_driver.load_demo
        assert defaults["exporter_factory"] is real_driver.build_otlp_exporter
        assert defaults["pause"] is time.sleep and defaults["clock"] is time.monotonic

    def test_the_otlp_exporter_is_built_with_explicit_settings(self, monkeypatch):
        # The exporter class is replaced: no channel is created.
        import grpc
        from opentelemetry.exporter.otlp.proto.grpc import trace_exporter
        built = {}
        monkeypatch.setattr(
            trace_exporter, "OTLPSpanExporter", lambda **kwargs: built.update(kwargs) or "x",
        )
        assert real_driver.build_otlp_exporter(parse_endpoint(_ENDPOINT_TEXT)) == "x"
        assert built == {
            "endpoint": _ENDPOINT_TEXT, "insecure": True, "timeout": 10.0,
            "compression": grpc.Compression.NoCompression,
        }

    def test_a_missing_demo_application_is_a_clear_refusal(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def no_graph(name, *args, **kwargs):
            if name == "graph":
                raise ImportError("No module named 'graph'", name="graph")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_graph)
        with pytest.raises(DriverError) as excinfo:
            real_driver.load_demo()
        message = str(excinfo.value)
        assert "the demo application cannot be imported" in message and "graph" in message
        assert "PYTHONPATH" in message


# ---------------------------------------------------------------------------
# RD04  Healthy trace
# ---------------------------------------------------------------------------

class TestHealthyTrace:

    @pytest.fixture(scope="class")
    def run(self, demo):
        plan = _plan(Scenario.NORMAL, traces=12)
        report, exporter, fake = _execute(plan, demo)
        return plan, report, exporter, fake

    def test_the_run_is_clean(self, run):
        plan, report, _, _ = run
        _clean(report)
        assert report.attempts["expected_success"] == 12
        assert report.started_requests == 12 and report.executed_attempts == 12
        assert report.executed_retries == 0 and report.not_started_requests == 0

    def test_one_trace_of_seven_spans_per_request(self, run):
        _, report, exporter, _ = run
        traces = _traces(exporter)
        assert len(traces) == 12
        for spans in traces.values():
            assert _names(spans) == _HEALTHY
            assert _parents_ok(spans)
        assert report.spans_ended == report.spans_exported_successfully == 12 * 7

    def test_every_healthy_span_has_status_unset_and_is_internal(self, run):
        for span in run[2].get_finished_spans():
            assert span.status.status_code.name == "UNSET"
            assert span.kind.name == "INTERNAL"
            assert not span.events

    def test_children_are_direct_children_of_the_root(self, run):
        for spans in _traces(run[2]).values():
            root_id = _root(spans).get_span_context().span_id
            assert all(s.parent.span_id == root_id for s in spans if s is not _root(spans))

    def test_resource_and_scope_are_the_demo_applications(self, run):
        for span in run[2].get_finished_spans():
            assert span.resource.attributes["service.name"] == "agentops-demo-app"
            assert span.instrumentation_scope.name == "agentops.demo"

    def test_the_existing_child_attributes_are_untouched(self, run):
        for spans in _traces(run[2]).values():
            tool = _span(spans, "tool.execute")
            assert tool.attributes["agent.name"] == "tool_agent"
            assert tool.attributes["tool.name"] == "technology_info_service"
            assert tool.attributes["tool.status"] in ("success", "not_found")
            retrieval = _span(spans, "retrieval.search")
            assert retrieval.attributes["gen_ai.operation.name"] == "retrieval"
            assert "retrieval.result_count" in retrieval.attributes
            for name in _HEALTHY[1:]:
                assert not [k for k in _span(spans, name).attributes if "workload" in k]

    def test_the_planned_baseline_latency_was_asked_for(self, run):
        plan, _, _, fake = run
        expected = sorted(
            round(value / 1000.0, 9)
            for request in plan.requests
            for value in dataclasses.astuple(request.latency)
        )
        waited = sorted(round(w, 9) for w in fake.waits)
        # Every planned latency is among the waits (the rest are arrival waits).
        remaining = Counter(waited)
        remaining.subtract(Counter(expected))
        assert all(count >= 0 for count in remaining.values())

    def test_no_span_was_printed(self, demo, capsys):
        _execute(_plan(traces=3), demo)
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""


# ---------------------------------------------------------------------------
# RD05  Failed trace
# ---------------------------------------------------------------------------

class TestFailedTrace:

    @pytest.mark.parametrize("scenario, error_type", [
        (Scenario.API_500, "UpstreamServerError"),
        (Scenario.API_429, "RateLimitError"),
        (Scenario.TIMEOUT, "ToolTimeoutError"),
        (Scenario.REPEATED_FAILURE, "ToolExecutionError"),
        (Scenario.RECURRING_INCIDENT, "UpstreamServerError"),
    ])
    def test_a_planned_tool_failure(self, demo, scenario, error_type):
        plan = _plan(scenario, traces=40)
        failing = [r for r in plan.requests if r.fault is not None]
        assert failing
        report, exporter, _ = _execute(plan, demo)
        _clean(report)
        assert report.attempts["expected_failure"] == len(failing)
        assert report.attempts["expected_success"] == 40 - len(failing)

        traces = _by_request_id(exporter)
        message = ERROR_MESSAGES[error_type]
        for request in plan.requests:
            spans = traces[request.request_id]
            assert _parents_ok(spans)
            if request.fault is None:
                assert _names(spans) == _HEALTHY
                continue
            # Five spans: the answer-building steps never ran.
            assert _names(spans) == _FAILED
            tool = _span(spans, "tool.execute")
            assert tool.status.status_code.name == "ERROR"
            assert tool.status.description == f"{error_type}: {message}"
            assert tool.attributes["error.type"] == error_type
            assert tool.attributes["error.message"] == message
            assert "tool.name" not in tool.attributes     # as the demo application behaves
            assert [event.name for event in tool.events] == ["exception"]
            root = _root(spans)
            assert root.status.status_code.name == "ERROR"
            assert root.status.description == f"{error_type}: {message}"
            assert "error.type" not in root.attributes
            assert [event.name for event in root.events] == ["exception"]
            for name in ("supervisor.start", "research.plan", "retrieval.search"):
                assert _span(spans, name).status.status_code.name == "UNSET"

    def test_a_planned_failure_is_a_workload_result_not_a_generator_failure(self, demo):
        plan = _plan(Scenario.REPEATED_FAILURE, traces=20)
        report, _, _ = _execute(plan, demo)
        assert report.run_status == "completed"
        assert report.attempts["expected_failure"] == 6
        assert real_driver.exit_code(report) == 0

    def test_a_timeout_asks_for_five_seconds_of_waiting(self, demo):
        plan = _plan(Scenario.TIMEOUT, traces=20)
        failing = [r for r in plan.requests if r.fault is not None]
        _, _, fake = _execute(plan, demo)
        assert fake.waits.count(5.0) == len(failing) > 0


# ---------------------------------------------------------------------------
# RD06  Retrieval quality and slow synthesis
# ---------------------------------------------------------------------------

class TestRetrievalQualityAndSlowSynthesis:

    def test_retrieval_quality_keeps_the_query_and_degrades_the_result(self, demo):
        plan = _plan(Scenario.RETRIEVAL_QUALITY, traces=60, persona=Persona.RESEARCH_SESSION)
        normal = _plan(Scenario.NORMAL, traces=60, persona=Persona.RESEARCH_SESSION)
        seen = []
        proxy = types.SimpleNamespace(
            invoke=lambda state: seen.append(
                (state["request_id"], state["user_request"])
            ) or demo.app.invoke(state),
        )
        report, exporter, _ = _execute(plan, dataclasses.replace(demo, app=proxy))
        _clean(report)
        baseline, baseline_exporter, _ = _execute(normal, demo)
        _clean(baseline)

        degraded_traces = _by_request_id(exporter)
        healthy_traces = _by_request_id(baseline_exporter)
        asked = dict(seen)
        degraded = [r for r in plan.requests if r.retrieval_effect is not None]
        assert len(degraded) > 5
        for request in plan.requests:
            # The question sent to the agent is the user's own, in every case.
            assert asked[request.request_id] == request.query
            assert request.query == normal.requests[request.request_index].query
            spans = degraded_traces[request.request_id]
            assert _names(spans) == _HEALTHY             # still seven spans, no error
            assert {s.status.status_code.name for s in spans} == {"UNSET"}
            now = _span(spans, "retrieval.search").attributes
            before = _span(
                healthy_traces[request.request_id], "retrieval.search",
            ).attributes
            if request.retrieval_effect is RetrievalEffect.DROP_BEST_MATCH:
                assert now["retrieval.result_count"] == max(
                    before["retrieval.result_count"] - 1, 0,
                )
                if now["retrieval.result_count"] == 0:
                    assert "retrieval.top_relevance_score" not in now
                else:
                    assert now["retrieval.top_relevance_score"] <= (
                        before["retrieval.top_relevance_score"]
                    )
            else:
                assert dict(now) == dict(before)

    def test_slow_synthesis_reaches_the_synthesis_wrapper_through_the_graph(self, demo):
        plan = _plan(Scenario.SLOW_SYNTHESIS, traces=40)
        slow = [r for r in plan.requests if r.scenario is Scenario.SLOW_SYNTHESIS]
        assert slow
        report, exporter, fake = _execute(plan, demo)
        # A wrapper that was not reached would have stopped the run.
        _clean(report)
        for request in slow:
            assert round(request.latency.synthesis_ms / 1000.0, 9) in {
                round(w, 9) for w in fake.waits
            }
            # Six to twelve times a baseline whose median is 60 ms.
            assert request.latency.synthesis_ms > 150.0
        assert all(_names(spans) == _HEALTHY for spans in _traces(exporter).values())

    @pytest.mark.parametrize("scenario", [Scenario.SLOW_TOOL, Scenario.RETRIEVAL_LATENCY])
    def test_other_latency_scenarios_run_clean(self, demo, scenario):
        report, exporter, _ = _execute(_plan(scenario, traces=30), demo)
        _clean(report)
        assert report.attempts["expected_success"] == 30
        assert len(_traces(exporter)) == 30


# ---------------------------------------------------------------------------
# RD07  Root span attributes
# ---------------------------------------------------------------------------

class TestRootAttributes:

    def test_existing_and_workload_attributes(self, demo):
        plan = _plan(Scenario.MIXED_PRODUCTION, traces=200, rate=50.0)
        report, exporter, _ = _execute(plan, demo)
        _clean(report)
        traces = _by_request_id(exporter)
        assert set(traces) == {r.request_id for r in plan.requests}
        for request in plan.requests:
            attributes = dict(_root(traces[request.request_id]).attributes)
            assert attributes == {
                "gen_ai.operation.name": "invoke_workflow",
                "agentops.request_id": request.request_id,
                "agentops.session_id": request.session_id,
                "agentops.schema_version": "1.0",
                "agentops.workload.run_id": "driver-tests",
                "agentops.workload.mode": "real",
                "agentops.workload.scenario": request.scenario.value,
                "agentops.workload.persona": request.persona.value,
            }
        assert len({r.scenario for r in plan.requests}) >= 2

    def test_the_query_is_not_recorded_anywhere(self, demo):
        plan = _plan(traces=10)
        _, exporter, _ = _execute(plan, demo)
        queries = {r.query for r in plan.requests if r.query}
        for span in exporter.get_finished_spans():
            for value in span.attributes.values():
                assert value not in queries
            assert not [k for k in span.attributes if "query" in k or "input" in k]

    def test_no_retry_or_attempt_attribute_exists(self, demo):
        plan = _plan(Scenario.RETRY_STORM, traces=40)
        _, exporter, _ = _execute(plan, demo)
        for span in exporter.get_finished_spans():
            assert not [k for k in span.attributes if "retry" in k or "attempt" in k]

    def test_workload_attributes_are_on_the_root_only(self, demo):
        _, exporter, _ = _execute(_plan(traces=6), demo)
        for span in exporter.get_finished_spans():
            has = [k for k in span.attributes if k.startswith("agentops.workload.")]
            assert bool(has) == (span.name == "agentops.request")

    def test_root_span_matches_the_demo_applications_own(self):
        main = (_DEMO_DIR / "main.py").read_text(encoding="utf-8")
        assert f'start_as_current_span("{real_driver.ROOT_SPAN_NAME}")' in main
        for text in (real_driver.ATTR_OPERATION, real_driver.ROOT_OPERATION,
                     real_driver.ATTR_REQUEST_ID, real_driver.ATTR_SESSION_ID,
                     real_driver.ATTR_SCHEMA_VERSION):
            assert f'"{text}"' in main
        assert f'SCHEMA_VERSION = "{real_driver.SCHEMA_VERSION}"' in main
        tracing = (_DEMO_DIR / "observability" / "tracing.py").read_text(encoding="utf-8")
        assert f'SERVICE_NAME = "{real_driver.SERVICE_NAME}"' in tracing
        assert f'get_tracer("{real_driver.TRACER_NAME}")' in (
            _DEMO_DIR / "observability" / "instrumentation.py"
        ).read_text(encoding="utf-8")

    def test_the_state_given_to_the_graph_has_the_demo_applications_shape(self, demo):
        states = []
        proxy = types.SimpleNamespace(
            invoke=lambda state: states.append(dict(state)) or demo.app.invoke(state),
        )
        plan = _plan(traces=3)
        _execute(plan, dataclasses.replace(demo, app=proxy))
        for state, request in zip(states, plan.requests):
            assert state == {
                "request_id": request.request_id, "session_id": request.session_id,
                "user_request": request.query, "retrieval_query": None,
                "retrieved_context": None, "tool_result": None,
                "synthesized_answer": None, "final_response": None,
            }
        main = (_DEMO_DIR / "main.py").read_text(encoding="utf-8")
        for key in states[0]:
            assert f'"{key}":' in main


# ---------------------------------------------------------------------------
# RD08  Client retries
# ---------------------------------------------------------------------------

class TestRetries:

    @pytest.fixture(scope="class")
    def run(self, demo):
        plan = _plan(Scenario.RETRY_STORM, traces=60)
        report, exporter, fake = _execute(plan, demo)
        return plan, report, exporter, fake

    def test_every_planned_attempt_was_executed(self, run):
        plan, report, _, _ = run
        _clean(report)
        assert plan.planned_retries > 0
        assert report.executed_retries == report.planned_retries == plan.planned_retries
        assert report.executed_attempts == report.planned_submissions == 60 + plan.planned_retries

    def test_one_trace_per_attempt_with_its_own_planned_request_id(self, run):
        plan, _, exporter, _ = run
        planned = _planned_attempts(plan)
        traces = _by_request_id(exporter)
        assert set(traces) == set(planned)
        assert len(_traces(exporter)) == len(planned)
        # Distinct traces, not spans of one trace.
        trace_ids = [s[0].get_span_context().trace_id for s in traces.values()]
        assert len(set(trace_ids)) == len(trace_ids)

    def test_a_retry_shares_the_session_and_nothing_else(self, run):
        plan, _, exporter, _ = run
        traces = _by_request_id(exporter)
        checked = 0
        for request in plan.requests:
            if not request.retries:
                continue
            roots = [_root(traces[a.request_id]) for a in attempts(request)]
            assert {r.attributes["agentops.session_id"] for r in roots} == {request.session_id}
            assert len({r.attributes["agentops.request_id"] for r in roots}) == len(roots)
            assert len({r.get_span_context().trace_id for r in roots}) == len(roots)
            assert {r.attributes["agentops.workload.scenario"] for r in roots} == {"retry-storm"}
            checked += 1
        assert checked > 5

    def test_each_attempt_ends_as_planned(self, run):
        plan, _, exporter, _ = run
        traces = _by_request_id(exporter)
        recovered = 0
        for request, attempt in _planned_attempts(plan).values():
            spans = traces[attempt.request_id]
            if attempt.effects.fault is None:
                assert _names(spans) == _HEALTHY
                recovered += attempt.attempt > 0
            else:
                assert _names(spans) == _FAILED
                assert _span(spans, "tool.execute").attributes["error.type"] == (
                    "UpstreamServerError"
                )
        assert recovered > 0                             # some last retries succeed

    def test_attempts_of_one_request_run_in_order_after_their_backoff(self, demo):
        plan = _plan(Scenario.RETRY_STORM, traces=60)
        request = next(r for r in plan.requests if len(r.retries) == 3)
        order = []
        proxy = types.SimpleNamespace(
            invoke=lambda state: order.append(state["request_id"]) or demo.app.invoke(state),
        )
        report, _, fake = _execute(_subset(plan, [request]), dataclasses.replace(demo, app=proxy))
        assert order == [a.request_id for a in attempts(request)]
        for retry in request.retries:
            assert retry.backoff_seconds in fake.waits
        assert report.executed_retries == 3 and report.run_status == "completed"


# ---------------------------------------------------------------------------
# RD09  Concurrency
# ---------------------------------------------------------------------------

class TestConcurrency:

    def test_sixteen_workers_overlap_and_nothing_crosses(self, demo):
        workers = 16
        plan = _plan(Scenario.MIXED_PRODUCTION, traces=400, rate=200.0, seed=7)
        gate = threading.Barrier(workers)
        counted = {"calls": 0, "in_flight": 0, "peak": 0}
        lock = threading.Lock()

        def invoke(state):
            with lock:
                counted["calls"] += 1
                number = counted["calls"]
                counted["in_flight"] += 1
                counted["peak"] = max(counted["peak"], counted["in_flight"])
            try:
                if number <= workers:
                    # The first sixteen calls wait for each other: they are
                    # certain to be inside the graph at the same time.
                    gate.wait(timeout=60)
                return demo.app.invoke(state)
            finally:
                with lock:
                    counted["in_flight"] -= 1

        report, exporter, _ = _execute(
            plan, dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
            concurrency=workers,
        )
        assert not gate.broken and counted["peak"] == workers
        _clean(report)
        assert report.executed_attempts == report.planned_submissions

        planned = _planned_attempts(plan)
        traces = _by_request_id(exporter)
        assert set(traces) == set(planned)
        for request_id, (request, attempt) in planned.items():
            spans = traces[request_id]
            root = _root(spans)
            assert _parents_ok(spans)
            # Each trace carries its own request's attributes ...
            assert root.attributes["agentops.session_id"] == request.session_id
            assert root.attributes["agentops.workload.scenario"] == request.scenario.value
            assert root.attributes["agentops.workload.persona"] == request.persona.value
            # ... and its own request's planned effect, nobody else's.
            if attempt.effects.fault is not None:
                assert _names(spans) == _FAILED
                assert _span(spans, "tool.execute").attributes["error.type"] == (
                    attempt.effects.fault.error_type
                )
            else:
                assert _names(spans) == _HEALTHY
        assert {r.scenario for r in plan.requests} > {Scenario.NORMAL}

    def test_concurrency_never_exceeds_the_limit(self, demo):
        counted = {"in_flight": 0, "peak": 0}
        lock = threading.Lock()

        def invoke(state):
            with lock:
                counted["in_flight"] += 1
                counted["peak"] = max(counted["peak"], counted["in_flight"])
            try:
                return demo.app.invoke(state)
            finally:
                with lock:
                    counted["in_flight"] -= 1

        report, _, _ = _execute(
            _plan(traces=120, rate=500.0),
            dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
            concurrency=3,
        )
        _clean(report)
        assert 1 <= counted["peak"] <= 3

    @pytest.mark.parametrize("concurrency", [0, -1, True, 2.5])
    def test_invalid_concurrency_is_rejected_before_anything_runs(self, demo, concurrency):
        with pytest.raises(ValueError):
            _execute(_plan(traces=2), demo, concurrency=concurrency)
        assert not getattr(demo.tool.run_tool, "_workload_generator_wrapper", False)


# ---------------------------------------------------------------------------
# RD10  Integrity
# ---------------------------------------------------------------------------

def _steps(demo: Demo, state: dict) -> dict:
    """The three wrapped steps in order, without the graph."""
    state = dict(state, retrieval_query=state["user_request"] or "x")
    state.update(demo.retrieval.retrieval_node(state))
    state.update(demo.tool.tool_agent_node(state))
    state.update(demo.instrumentation.instrumented_research_synthesize(state))
    return state


class TestIntegrity:

    def _stopped(self, report, outcome: str):
        assert report.run_status == "stopped_integrity"
        assert real_driver.exit_code(report) == 3
        assert report.attempts[outcome] == 1
        assert sum(report.attempts[name] for name in (
            "unexpected_failure", "missing_failure", "reach_failure",
        )) == 1
        assert len(report.problems) == 1 and f": {outcome}: " in report.problems[0]

    def test_a_wrapper_that_is_not_reached_stops_the_run(self, demo):
        calls = []

        def invoke(state):
            calls.append(state["request_id"])
            if len(calls) == 4:
                return {"final_response": "answered without the agent's steps"}
            return demo.app.invoke(state)

        plan = _plan(traces=30)
        report, exporter, _ = _execute(
            plan, dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
        )
        self._stopped(report, "reach_failure")
        assert "tool: reached 0 time(s), expected 1" in report.problems[0]
        assert report.problems[0].startswith("request 3 attempt 0 (req_")
        # Three clean requests, the fourth is the problem, nothing after it.
        assert calls == [r.request_id for r in plan.requests[:4]]
        assert report.attempts["expected_success"] == 3
        assert report.attempts["not_started"] == 26
        assert report.started_requests == 4 and report.not_started_requests == 26
        # What ran was still exported.
        assert report.flush_ok and report.spans_ended == report.spans_exported_successfully
        assert len(_traces(exporter)) == 4

    def test_an_unplanned_failure_stops_the_run(self, demo):
        calls = []

        def invoke(state):
            calls.append(1)
            result = _steps(demo, state)
            if len(calls) == 2:
                raise RuntimeError("the platform broke")
            return result

        report, _, _ = _execute(
            _plan(traces=20), dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
        )
        self._stopped(report, "unexpected_failure")
        assert "no failure was planned; raised RuntimeError: the platform broke" in (
            report.problems[0]
        )
        assert len(calls) == 2 and report.attempts["not_started"] == 18

    def test_a_planned_failure_that_does_not_happen_stops_the_run(self, demo):
        def invoke(state):
            state = dict(state, retrieval_query=state["user_request"] or "x")
            state.update(demo.retrieval.retrieval_node(state))
            try:
                state.update(demo.tool.tool_agent_node(state))
            except Exception:  # noqa: BLE001 - an agent that swallows its tool failure
                return state
            state.update(demo.instrumentation.instrumented_research_synthesize(state))
            return state

        plan = _plan(Scenario.API_500, traces=40)
        first_failing = next(r for r in plan.requests if r.fault is not None)
        report, _, _ = _execute(
            plan, dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
        )
        self._stopped(report, "missing_failure")
        assert "planned UpstreamServerError; nothing raised" in report.problems[0]
        assert report.problems[0].startswith(f"request {first_failing.request_index} ")
        assert report.attempts["expected_success"] == first_failing.request_index
        assert report.attempts["not_started"] == 40 - first_failing.request_index - 1

    def test_remaining_retries_are_not_sent_after_a_deviation(self, demo):
        plan = _plan(Scenario.RETRY_STORM, traces=60)
        request = next(r for r in plan.requests if len(r.retries) == 3)
        calls = []

        def invoke(state):
            calls.append(state["request_id"])
            return _steps(demo, state)       # succeeds although a failure is planned?

        # The tool wrapper raises as planned, so make the deviation explicit:
        # an agent that swallows the failure on the second attempt.
        def swallowing(state):
            calls.append(state["request_id"])
            if len(calls) == 2:
                state = dict(state, retrieval_query=state["user_request"] or "x")
                state.update(demo.retrieval.retrieval_node(state))
                try:
                    demo.tool.tool_agent_node(state)
                except Exception:  # noqa: BLE001
                    pass
                return state
            return demo.app.invoke(state)

        report, _, _ = _execute(
            _subset(plan, [request]),
            dataclasses.replace(demo, app=types.SimpleNamespace(invoke=swallowing)),
        )
        planned = attempts(request)
        assert calls == [planned[0].request_id, planned[1].request_id]
        assert report.attempts == {
            "expected_success": 0, "expected_failure": 1, "unexpected_failure": 0,
            "missing_failure": 1, "reach_failure": 0, "not_started": 2,
        }
        assert report.run_status == "stopped_integrity" and report.executed_retries == 1

    def test_running_work_finishes_and_new_work_does_not_start(self, demo):
        release = threading.Event()
        entered = threading.Event()
        calls = []
        lock = threading.Lock()

        def invoke(state):
            with lock:
                calls.append(state["request_id"])
                number = len(calls)
            if number == 1:
                entered.set()
                assert release.wait(timeout=60)          # still running when #2 deviates
                return demo.app.invoke(state)
            if number == 2:
                assert entered.wait(timeout=60)
                try:
                    return {"final_response": "no steps"}
                finally:
                    release.set()
            return demo.app.invoke(state)

        plan = _plan(traces=40, rate=500.0)
        report, exporter, _ = _execute(
            plan, dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
            concurrency=2,
        )
        assert report.run_status == "stopped_integrity"
        assert report.attempts["reach_failure"] == 1
        # The request that was already running completed normally.
        assert report.attempts["expected_success"] >= 1
        assert plan.requests[0].request_id in _by_request_id(exporter)
        assert _names(_by_request_id(exporter)[plan.requests[0].request_id]) == _HEALTHY
        assert report.attempts["not_started"] >= 35
        assert sum(report.attempts.values()) == 40

    def test_problems_listed_are_bounded(self):
        from workload_generator.report import MAX_PROBLEMS_LISTED
        assert MAX_PROBLEMS_LISTED == 10


# ---------------------------------------------------------------------------
# RD11  Arrival schedule and deadline
# ---------------------------------------------------------------------------

class TestScheduleAndDeadline:

    def test_no_request_starts_before_its_planned_arrival(self, demo):
        fake = FakeTime()
        starts = {}
        proxy = types.SimpleNamespace(
            invoke=lambda state: starts.setdefault(
                state["request_id"], fake.clock(),
            ) and demo.app.invoke(state),
        )
        plan = _plan(traces=40, rate=2.0)
        report, _, _ = _execute(plan, dataclasses.replace(demo, app=proxy), fake=fake)
        _clean(report)
        for request in plan.requests:
            assert starts[request.request_id] >= 1000.0 + request.arrival_offset_seconds - 1e-9

    def test_a_run_with_spare_capacity_has_no_late_start(self, demo):
        # One request every two seconds, each taking about a quarter of a
        # second: a worker is always free when the next one is due.  Here
        # only the dispatcher's waiting moves the clock, as if the workers'
        # short waits overlapped the two-second gaps (the plain fake clock
        # would add them on top).
        class ArrivalTime(FakeTime):
            def sleep(self, seconds: float) -> None:
                if not threading.current_thread().name.startswith("workload"):
                    super().sleep(seconds)

        plan = _plan(traces=20)
        spaced = Plan(
            config=plan.config,
            requests=tuple(
                dataclasses.replace(request, arrival_offset_seconds=2.0 * index)
                for index, request in enumerate(plan.requests)
            ),
            episodes=(), session_count=plan.session_count,
        )
        report, _, fake = _execute(spaced, demo, concurrency=2, fake=ArrivalTime())
        _clean(report)
        assert report.late_starts == 0
        assert report.max_start_lag_seconds == 0.0 and report.mean_start_lag_seconds == 0.0
        assert report.elapsed_seconds >= 38.0            # the plan's duration, in fake time

    def test_saturation_makes_requests_start_late_not_disappear(self, demo):
        # 100 requests a second with one worker: far more than it can take.
        plan = _plan(traces=60, rate=100.0)
        report, exporter, _ = _execute(plan, demo, concurrency=1)
        _clean(report)
        assert report.attempts["expected_success"] == 60 and len(_traces(exporter)) == 60
        assert report.late_starts > 40
        assert report.max_start_lag_seconds > 5.0
        assert 0.0 < report.mean_start_lag_seconds < report.max_start_lag_seconds
        # The requested rate was not achieved, and the report shows it.
        assert report.achieved_submission_rate < 10.0

    def test_requests_run_in_plan_order_with_one_worker(self, demo):
        order = []
        proxy = types.SimpleNamespace(
            invoke=lambda state: order.append(state["request_id"]) or demo.app.invoke(state),
        )
        plan = _plan(traces=25)
        _execute(plan, dataclasses.replace(demo, app=proxy))
        assert order == [r.request_id for r in plan.requests]

    def test_no_request_starts_after_the_deadline(self, demo):
        # A 30-second plan with a 5-second limit.
        plan = _plan(traces=60, rate=2.0)
        report, exporter, fake = _execute(plan, demo, max_duration=5.0)
        assert report.run_status == "deadline_reached"
        assert real_driver.exit_code(report) == 5
        started = report.started_requests
        assert 5 <= started <= 14 and report.not_started_requests == 60 - started
        assert report.attempts["not_started"] == 60 - started
        assert report.attempts["expected_success"] == started
        # Only requests planned before the deadline ran, and all of them were exported.
        assert set(_by_request_id(exporter)) == {r.request_id for r in plan.requests[:started]}
        assert all(r.arrival_offset_seconds < 5.0 for r in plan.requests[:started])
        assert report.flush_ok and report.spans_ended == report.spans_exported_successfully
        assert report.problems == ()

    def test_an_attempt_already_running_at_the_deadline_finishes(self, demo):
        # One request whose tool call "takes" ten seconds, with a 2-second limit.
        request = _plan(traces=1).requests[0]
        slow = dataclasses.replace(
            request, latency=dataclasses.replace(request.latency, tool_ms=10_000.0),
        )
        report, exporter, _ = _execute(
            _subset(_plan(traces=1), [slow]), demo, max_duration=2.0,
        )
        assert report.attempts["expected_success"] == 1
        assert _names(next(iter(_traces(exporter).values()))) == _HEALTHY
        assert report.elapsed_seconds > 10.0 and report.run_status == "completed"

    def test_no_retry_starts_after_the_deadline(self, demo):
        plan = _plan(Scenario.RETRY_STORM, traces=60)
        request = next(r for r in plan.requests if len(r.retries) == 3)
        # The first attempt fits; the backoffs carry the next ones past the limit.
        limit = request.latency.retrieval_ms / 1000.0 + request.latency.tool_ms / 1000.0 + 0.6
        report, _, _ = _execute(_subset(plan, [request]), demo, max_duration=limit)
        assert report.run_status == "deadline_reached"
        assert report.attempts["expected_failure"] >= 1
        assert report.attempts["not_started"] >= 1
        assert report.attempts["expected_failure"] + report.attempts["not_started"] == 4
        assert report.started_requests == 1 and report.not_started_requests == 0

    @pytest.mark.parametrize("limit", [0, -1.0])
    def test_the_limit_must_be_positive(self, demo, limit):
        with pytest.raises(ValueError):
            _execute(_plan(traces=2), demo, max_duration=limit)

    def test_timestamps_and_elapsed_come_from_the_injected_clocks(self, demo):
        moments = iter([
            datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 6, 12, 0, 30, tzinfo=timezone.utc),
        ])
        report, _, fake = _execute(_plan(traces=10, rate=5.0), demo, now=lambda: next(moments))
        assert report.started == "2026-10-06T12:00:00+00:00"
        assert report.finished == "2026-10-06T12:00:30+00:00"
        assert report.elapsed_seconds == round(fake.now - 1000.0, 3) > 1.7
        assert report.achieved_submission_rate == pytest.approx(
            10 / (fake.now - 1000.0), abs=0.001,
        )


# ---------------------------------------------------------------------------
# RD12  Export accounting
# ---------------------------------------------------------------------------

def _failing_exporter(result_name: str = "FAILURE", fail_every: int = 1, raises: bool = False):
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class Failing(SpanExporter):
        def __init__(self) -> None:
            self.calls = 0
            self.accepted = 0
            self.shut_down = False

        def export(self, spans):
            self.calls += 1
            if self.calls % fail_every == 0:
                if raises:
                    raise RuntimeError("exporter broke")
                return getattr(SpanExportResult, result_name)
            self.accepted += len(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            self.shut_down = True

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    return Failing()


class TestExportAccounting:

    def test_everything_exported(self, demo):
        report, exporter, _ = _execute(_plan(traces=30), demo)
        assert report.spans_ended == report.spans_exported_successfully == 210
        assert report.export_failures == 0 and report.flush_ok
        assert len(exporter.get_finished_spans()) == 210

    def test_an_exporter_that_reports_failure_fails_the_run(self, demo):
        exporter = _failing_exporter()
        report, _, _ = _execute(_plan(traces=10), demo, exporter=exporter)
        assert report.run_status == "export_failed" and real_driver.exit_code(report) == 4
        assert report.spans_ended == 70 and report.spans_exported_successfully == 0
        assert report.export_failures == exporter.calls >= 1
        # The workload itself went as planned; only the export did not.
        assert report.attempts["expected_success"] == 10 and report.problems == ()

    def test_an_exporter_that_raises_is_counted_as_a_failure(self, demo):
        exporter = _failing_exporter(raises=True)
        report, _, _ = _execute(_plan(traces=10), demo, exporter=exporter)
        assert report.run_status == "export_failed"
        assert report.export_failures >= 1 and report.spans_exported_successfully == 0

    def test_partly_failed_export_is_not_reported_as_complete(self, demo):
        # Small batches, every second export call fails.
        exporter = _failing_exporter(fail_every=2)
        report, _, _ = _execute(_plan(traces=40), demo, exporter=exporter, max_queue_size=16)
        assert report.run_status == "export_failed"
        assert report.export_failures >= 1
        assert report.spans_exported_successfully == exporter.accepted < report.spans_ended

    def test_the_exporter_is_shut_down_at_the_end(self, demo):
        exporter = _failing_exporter(fail_every=10 ** 9)
        report, _, _ = _execute(_plan(traces=5), demo, exporter=exporter)
        assert exporter.shut_down and report.run_status == "completed"

    def test_the_queue_has_a_fixed_ceiling_not_derived_from_the_plan(self, demo):
        assert real_driver.MAX_QUEUE_SIZE == 8192
        assert real_driver.MAX_EXPORT_BATCH_SIZE == 512
        source = Path(real_driver.__file__).read_text(encoding="utf-8")
        assert "max_queue_size: int = MAX_QUEUE_SIZE" in source
        for size in (0, -5, 8193, True, 2.0):
            with pytest.raises(ValueError):
                _execute(_plan(traces=2), demo, max_queue_size=size)

    def test_the_report_makes_no_downstream_claim(self, demo):
        report, _, _ = _execute(_plan(traces=5), demo)
        for key in report.to_dict():
            for word in ("collector", "accepted", "kafka", "stored", "persisted", "rows"):
                assert word not in key


# ---------------------------------------------------------------------------
# RD13  Lifecycle
# ---------------------------------------------------------------------------

class _Abort(BaseException):
    """Not an Exception: the driver must not treat it as a workload result."""


class TestLifecycle:

    def _originals(self, demo):
        return (
            demo.tool.run_tool, demo.retrieval.retrieve,
            demo.instrumentation.research_synthesize_node, demo.instrumentation._tracer,
        )

    def test_everything_is_put_back_after_a_clean_run(self, demo):
        before = self._originals(demo)
        _execute(_plan(traces=5), demo)
        assert self._originals(demo) == before
        assert not getattr(demo.tool.run_tool, "_workload_generator_wrapper", False)

    def test_everything_is_put_back_after_a_stopped_run(self, demo):
        before = self._originals(demo)
        proxy = types.SimpleNamespace(invoke=lambda state: {})
        report, _, _ = _execute(_plan(traces=5), dataclasses.replace(demo, app=proxy))
        assert report.run_status == "stopped_integrity"
        assert self._originals(demo) == before

    def test_everything_is_put_back_and_flushed_after_an_abort(self, demo):
        before = self._originals(demo)
        exporter = _exporter()
        calls = []

        def invoke(state):
            calls.append(1)
            if len(calls) == 3:
                raise _Abort()
            return demo.app.invoke(state)

        with pytest.raises(_Abort):
            _execute(
                _plan(traces=10),
                dataclasses.replace(demo, app=types.SimpleNamespace(invoke=invoke)),
                exporter=exporter,
            )
        assert self._originals(demo) == before
        # Nothing was started after the abort ...
        assert len(calls) == 3
        # ... and the two requests that completed were flushed before it surfaced.
        complete = [s for s in _traces(exporter).values() if len(s) == 7]
        assert len(complete) == 2

    def test_an_error_while_applying_effects_stops_new_work(self, demo):
        # A planned failure of a kind the injector does not know: a defect in
        # the plan, not a workload result.  It must surface, not be recorded
        # as an outcome, and nothing may be started after it.
        plan = _plan(traces=10)
        broken = dataclasses.replace(
            plan.requests[2],
            fault=PlannedFault(Target.TOOL, "NoSuchFailureError", "x"),
        )
        requests = (*plan.requests[:2], broken, *plan.requests[3:])
        calls = []
        proxy = types.SimpleNamespace(
            invoke=lambda state: calls.append(1) or demo.app.invoke(state),
        )
        from workload_generator.faults import FaultInstallError
        with pytest.raises(FaultInstallError, match="unknown planned failure"):
            _execute(_subset(plan, requests), dataclasses.replace(demo, app=proxy))
        assert len(calls) == 2
        assert not getattr(demo.tool.run_tool, "_workload_generator_wrapper", False)

    def test_the_tracer_is_bound_only_during_the_run(self, demo):
        original = demo.instrumentation._tracer
        during = []
        proxy = types.SimpleNamespace(
            invoke=lambda state: during.append(demo.instrumentation._tracer)
            or demo.app.invoke(state),
        )
        _execute(_plan(traces=2), dataclasses.replace(demo, app=proxy))
        assert all(tracer is not original for tracer in during) and len(during) == 2
        assert demo.instrumentation._tracer is original

    def test_the_process_wide_provider_is_never_registered(self, demo):
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        _execute(_plan(traces=3), demo)
        assert not isinstance(trace.get_tracer_provider(), TracerProvider)
        assert type(trace.get_tracer_provider()).__name__ == "ProxyTracerProvider"

    def test_the_demo_applications_own_telemetry_setup_is_never_called(self, demo):
        sys.path.insert(0, str(_DEMO_DIR))
        try:
            from observability import tracing
        finally:
            sys.path.remove(str(_DEMO_DIR))
        _execute(_plan(traces=3), demo)
        assert tracing._tracing_configured is False

    def test_two_runs_in_one_process_do_not_share_spans(self, demo):
        _, first, _ = _execute(_plan(traces=4, run_id="run-one"), demo)
        _, second, _ = _execute(_plan(traces=6, run_id="run-two"), demo)
        runs = lambda exporter: {
            _root(spans).attributes["agentops.workload.run_id"]
            for spans in _traces(exporter).values()
        }
        assert runs(first) == {"run-one"} and len(_traces(first)) == 4
        assert runs(second) == {"run-two"} and len(_traces(second)) == 6

    def test_no_worker_or_exporter_thread_outlives_the_run(self, demo):
        before = threading.active_count()
        _execute(_plan(traces=20, rate=200.0), demo, concurrency=8)
        deadline = time.monotonic() + 10.0
        while threading.active_count() > before and time.monotonic() < deadline:
            time.sleep(0.01)
        assert threading.active_count() <= before

    def test_a_module_without_a_tracer_is_refused_before_anything_runs(self, demo):
        stripped = types.SimpleNamespace(**{
            k: v for k, v in vars(demo.instrumentation).items() if k != "_tracer"
        })
        with pytest.raises(DriverError, match="has no _tracer"):
            _execute(_plan(traces=2), dataclasses.replace(demo, instrumentation=stripped))
        assert not getattr(demo.tool.run_tool, "_workload_generator_wrapper", False)

    def test_demo_application_files_are_not_touched(self, demo):
        import hashlib
        before = {
            path: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(_DEMO_DIR.rglob("*.py"))
        }
        _execute(_plan(Scenario.MIXED_PRODUCTION, traces=60), demo, concurrency=4)
        after = {
            path: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(_DEMO_DIR.rglob("*.py"))
        }
        assert before == after and len(before) >= 10


# ---------------------------------------------------------------------------
# RD14  Real waiting
# ---------------------------------------------------------------------------

class TestRealWaiting:

    def test_injected_time_appears_in_the_existing_span_durations(self, demo):
        """
        The one test that really waits: one request, about 0.15 seconds in
        all.  It shows that planned latency becomes span duration; it is not
        a measurement of anything.
        """
        request = _plan(traces=1).requests[0]
        planned = dataclasses.replace(
            request,
            latency=dataclasses.replace(
                request.latency, tool_ms=40.0, retrieval_ms=25.0, synthesis_ms=80.0,
            ),
        )
        exporter = _exporter()
        report = execute(
            _subset(_plan(traces=1), [planned]), demo=demo, span_exporter=exporter,
            endpoint="in-memory", concurrency=1, max_duration_seconds=60.0,
            pause=time.sleep, clock=time.monotonic,
        )
        _clean(report)
        (spans,) = _traces(exporter).values()
        milliseconds = lambda name: (
            _span(spans, name).end_time - _span(spans, name).start_time
        ) / 1e6
        # At least the planned time (minus timer granularity), and not wildly more.
        for name, planned_ms in (
            ("tool.execute", 40.0), ("retrieval.search", 25.0), ("research.synthesize", 80.0),
        ):
            assert planned_ms - 5.0 <= milliseconds(name) <= planned_ms + 400.0, name
        assert milliseconds("agentops.request") >= 140.0
        assert 0.1 <= report.elapsed_seconds < 5.0


# ---------------------------------------------------------------------------
# RD15  Start-lag diagnostic (observational only)
# ---------------------------------------------------------------------------

def _result(index, attempt=0, outcome=None, lag=0.0):
    outcome = real_driver.Outcome.EXPECTED_SUCCESS if outcome is None else outcome
    return real_driver.AttemptResult(index, attempt, f"req_{index}_{attempt}", outcome, "", lag)


class TestStartLagDiagnostic:

    def test_complete_series_in_request_order(self):
        plan = _plan(traces=6)
        results = [_result(i, lag=0.01 * i) for i in (4, 0, 5, 2, 1, 3)]  # completion order
        lags = real_driver.build_start_lags(plan, results)
        assert lags["complete"] is True and lags["truncated_reason"] is None
        assert lags["expected"] == lags["recorded"] == 6 and lags["limit"] == 10000
        assert [entry[0] for entry in lags["entries"]] == [0, 1, 2, 3, 4, 5]
        for index, offset, lag in lags["entries"]:
            assert offset == round(plan.requests[index].arrival_offset_seconds, 6)
            assert lag == round(0.01 * index, 6)

    def test_order_is_deterministic(self):
        plan = _plan(traces=8)
        results = [_result(i, lag=0.001 * i) for i in range(8)]
        first = real_driver.build_start_lags(plan, results)
        second = real_driver.build_start_lags(plan, list(reversed(results)))
        assert first == second

    def test_failed_first_attempts_in_retries_and_unstarted_out(self):
        plan = _plan(traces=4)
        results = [
            _result(0),
            _result(1, outcome=real_driver.Outcome.EXPECTED_FAILURE, lag=0.2),
            _result(1, attempt=1, lag=None),                       # a client retry
            _result(2, outcome=real_driver.Outcome.UNEXPECTED_FAILURE, lag=0.05),
            _result(3, outcome=real_driver.Outcome.NOT_STARTED, lag=None),
        ]
        lags = real_driver.build_start_lags(plan, results)
        assert [entry[0] for entry in lags["entries"]] == [0, 1, 2]
        assert lags["expected"] == 3 and lags["complete"] is True

    def test_overflow_keeps_the_first_entries(self):
        plan = _plan(traces=10)
        results = [_result(i, lag=0.001) for i in reversed(range(10))]
        lags = real_driver.build_start_lags(plan, results, limit=4)
        assert [entry[0] for entry in lags["entries"]] == [0, 1, 2, 3]
        assert lags["recorded"] == 4 and lags["expected"] == 10
        assert lags["complete"] is False and lags["truncated_reason"] == "limit"

    @pytest.mark.parametrize("bad", [None, float("nan"), float("inf"), -0.001, "0.1", True])
    def test_missing_or_malformed_lag(self, bad):
        plan = _plan(traces=3)
        lags = real_driver.build_start_lags(plan, [_result(0), _result(1, lag=bad), _result(2)])
        assert [entry[0] for entry in lags["entries"]] == [0, 2]
        assert lags["complete"] is False
        assert lags["truncated_reason"] == "missing or invalid start lag"
        assert lags["expected"] == 3 and lags["recorded"] == 2

    def test_duplicate_index(self):
        plan = _plan(traces=3)
        lags = real_driver.build_start_lags(plan, [_result(0), _result(1), _result(1, lag=0.5)])
        assert [entry[0] for entry in lags["entries"]] == [0, 1]
        assert lags["complete"] is False and "duplicate request index" in lags["truncated_reason"]

    def test_unknown_request_index(self):
        plan = _plan(traces=2)
        lags = real_driver.build_start_lags(plan, [_result(0), _result(7)])
        assert lags["complete"] is False
        assert "missing or invalid planned offset" in lags["truncated_reason"]

    def test_no_started_request(self):
        plan = _plan(traces=2)
        lags = real_driver.build_start_lags(
            plan, [_result(0, outcome=real_driver.Outcome.NOT_STARTED, lag=None)])
        assert lags == {"limit": 10000, "expected": 0, "recorded": 0, "complete": True,
                        "truncated_reason": None, "entries": []}

    def test_a_run_reports_a_complete_series_consistent_with_its_counts(self, demo):
        plan = _plan(traces=60, rate=100.0)              # saturated: many late starts
        report, _, _ = _execute(plan, demo, concurrency=1)
        _clean(report)
        lags = report.start_lags
        assert lags["complete"] is True and lags["expected"] == report.started_requests == 60
        late = sum(1 for _, _, lag in lags["entries"] if lag > real_driver.LATE_START_SECONDS)
        assert late == report.late_starts
        assert max(lag for _, _, lag in lags["entries"]) == pytest.approx(
            report.max_start_lag_seconds, abs=0.001)

    def test_late_start_accounting_is_unchanged(self, demo):
        # The same run, its counts taken with and without the diagnostic.
        plan = _plan(traces=40, rate=50.0)
        report, _, _ = _execute(plan, demo, concurrency=1)
        without = dataclasses.replace(report, start_lags=None)
        for name in ("late_starts", "max_start_lag_seconds", "mean_start_lag_seconds",
                     "started_requests", "not_started_requests", "run_status"):
            assert getattr(without, name) == getattr(report, name)

    def test_spare_capacity_gives_zero_lags(self, demo):
        class ArrivalTime(FakeTime):
            def sleep(self, seconds: float) -> None:
                if not threading.current_thread().name.startswith("workload"):
                    super().sleep(seconds)

        plan = _plan(traces=10)
        spaced = Plan(
            config=plan.config,
            requests=tuple(dataclasses.replace(r, arrival_offset_seconds=2.0 * i)
                           for i, r in enumerate(plan.requests)),
            episodes=(), session_count=plan.session_count,
        )
        report, _, _ = _execute(spaced, demo, concurrency=2, fake=ArrivalTime())
        assert report.start_lags["complete"] is True
        assert [entry[2] for entry in report.start_lags["entries"]] == [0.0] * 10
        assert [entry[1] for entry in report.start_lags["entries"]] == [2.0 * i for i in range(10)]

    def test_json_round_trip(self, demo):
        report, _, _ = _execute(_plan(traces=5), demo)
        data = json.loads(json.dumps(report.to_dict()))
        assert data["start_lags"] == report.to_dict()["start_lags"]
        assert data["start_lags"]["entries"] == [list(e) for e in report.start_lags["entries"]]

    def test_dispatcher_untouched(self):
        source = inspect.getsource(real_driver._dispatch)
        assert "start_lags" not in source and "build_start_lags" not in source

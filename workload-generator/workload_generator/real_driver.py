"""
workload_generator/real_driver.py

Phase 14.3D: The REAL driver.

Executes a plan through the demo application's own compiled agent graph, with
the application's own instrumentation, and exports the resulting spans by
OTLP gRPC to one explicitly named collector endpoint:

    PlannedRequest -> attempts() -> FaultInjector -> graph -> spans -> OTLP

The driver decides nothing about the traffic.  Which request runs when, what
is slow, what fails and what is retried were all decided by the planner; the
driver carries the plan out, checks every attempt against it, and reports
what it did.

What is and is not changed
--------------------------
No file of the demo application is changed.  For the duration of one run,
four names inside its already imported modules are rebound in this process
and put back afterwards: the three functions the fault injector wraps, and
the tracer of the instrumentation module.

The tracer provider belongs to the driver and is NOT registered as the
process-wide provider.  The instrumentation module reads its module-level
tracer each time a step runs; while a run is in progress that name refers to
the driver's tracer, so the application's spans and the driver's root span
come from one provider and form one trace.  The application's own telemetry
setup is never called: no console output, no direct Kafka export.

One way out
-----------
The only thing this module sends anywhere is spans, to the endpoint it was
given.  There is no default endpoint.  It opens no database connection and
uses no Kafka client.  Environment variables are read for one purpose only:
to refuse to run when any OpenTelemetry (OTEL_*) variable is set, because
such variables can silently disable or alter an explicitly configured
provider.

What the report can claim
-------------------------
The driver knows how many spans ended and for how many its local exporter
returned success.  It does not know, and never says, what a collector, Kafka
or a database did with them.

Integrity
---------
An attempt that fails as planned is a result of the workload.  An attempt
that does something the plan does not describe (an unplanned failure, a
planned failure that did not happen, a fault wrapper that was not reached)
is an integrity problem: no further work is started, running work finishes,
spans are flushed, and the run is reported as stopped.

Imports
-------
Only the standard library is imported when this module is loaded.  The
OpenTelemetry packages and the demo application are imported inside the
functions that need them, so that the checks which refuse a run can happen
first.

Public API:
    DriverError, EndpointError
    Endpoint, parse_endpoint()
    otel_environment_names()
    check_reachable()
    Demo, load_demo()
    Outcome, AttemptResult, classify()
    build_otlp_exporter()
    execute()        plan + demo + span exporter -> ExecutionReport
    run_real()       the production path: reachability, demo, OTLP, execute
    exit_code()
"""

from __future__ import annotations

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterator, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from .faults import Attempt, Effects, FaultInjector, attempts
from .plan import Plan, PlannedRequest
from .report import MAX_PROBLEMS_LISTED, OUTCOMES, ExecutionReport

SERVICE_NAME: str = "agentops-demo-app"
TRACER_NAME: str = "agentops.demo"

# The root span of a request, exactly as the demo application creates it.
ROOT_SPAN_NAME: str = "agentops.request"
ROOT_OPERATION: str = "invoke_workflow"
SCHEMA_VERSION: str = "1.0"
ATTR_OPERATION: str = "gen_ai.operation.name"
ATTR_REQUEST_ID: str = "agentops.request_id"
ATTR_SESSION_ID: str = "agentops.session_id"
ATTR_SCHEMA_VERSION: str = "agentops.schema_version"

# Added by the generator, on the root span only.
ATTR_RUN_ID: str = "agentops.workload.run_id"
ATTR_MODE: str = "agentops.workload.mode"
ATTR_SCENARIO: str = "agentops.workload.scenario"
ATTR_PERSONA: str = "agentops.workload.persona"
MODE_REAL: str = "real"

LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
#: The ports the platform's own collector publishes.  Refused during Phase
#: 14.3, so that generated telemetry cannot reach the normal stack by
#: accident.
REFUSED_PORTS: frozenset[int] = frozenset({4317, 4318})

REACHABILITY_TIMEOUT_SECONDS: float = 3.0
EXPORT_TIMEOUT_SECONDS: float = 10.0
FLUSH_TIMEOUT_MILLIS: int = 30_000

#: Spans waiting to be exported.  A fixed ceiling chosen for smoke-sized and
#: small runs; it is not derived from the size of the plan.  A full queue
#: makes the span processor drop spans, which this driver reports as an
#: export failure (spans ended != spans exported).  Tuning for large runs is
#: not done here.
MAX_QUEUE_SIZE: int = 8192
MAX_EXPORT_BATCH_SIZE: int = 512
SCHEDULE_DELAY_MILLIS: int = 500

#: A request counts as started late when it begins this long after its
#: planned arrival.
LATE_START_SECONDS: float = 0.1

EXIT_COMPLETED: int = 0
EXIT_STOPPED_INTEGRITY: int = 3
EXIT_EXPORT_FAILED: int = 4
EXIT_DEADLINE_REACHED: int = 5

_EXIT_CODES: dict[str, int] = {
    "completed": EXIT_COMPLETED,
    "stopped_integrity": EXIT_STOPPED_INTEGRITY,
    "export_failed": EXIT_EXPORT_FAILED,
    "deadline_reached": EXIT_DEADLINE_REACHED,
}

Clock = Callable[[], float]
Pause = Callable[[float], None]
Reachability = Callable[[str, int], None]


class DriverError(RuntimeError):
    """The run cannot start, or its telemetry cannot be set up."""


class EndpointError(DriverError):
    """The endpoint is not one this driver may send to."""


# ---------------------------------------------------------------------------
# Endpoint and environment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Endpoint:
    """An endpoint that passed parse_endpoint()."""

    url: str
    host: str
    port: int
    is_loopback: bool


def parse_endpoint(text: str, *, allow_remote: bool = False) -> Endpoint:
    """
    Validate an OTLP gRPC endpoint of the form http://host:port.

    Raises:
        EndpointError  malformed, a refused port, or not loopback without
                       allow_remote.  The message never repeats credentials.
    """
    if not isinstance(text, str) or text.strip() == "":
        raise EndpointError("the endpoint is empty")
    if text != text.strip() or any(character.isspace() for character in text):
        raise EndpointError("the endpoint must not contain whitespace")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise EndpointError("the endpoint is not a valid http://host:port") from None
    if parts.scheme != "http":
        raise EndpointError(
            "the endpoint must start with http:// (OTLP gRPC without TLS)"
        )
    if "@" in parts.netloc:
        raise EndpointError("the endpoint must not contain credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise EndpointError("the endpoint must be http://host:port and nothing more")
    host = parts.hostname
    if not host:
        raise EndpointError("the endpoint has no host")
    if port is None:
        raise EndpointError("the endpoint must name its port explicitly")
    if port in REFUSED_PORTS:
        raise EndpointError(
            f"port {port} is refused: it is a port the platform's own collector "
            "publishes, and generated telemetry may only go to an isolated stack"
        )
    is_loopback = host in LOOPBACK_HOSTS
    if not is_loopback and not allow_remote:
        raise EndpointError(
            "the endpoint is not on this machine (localhost, 127.0.0.1 or ::1); "
            "a remote endpoint needs --allow-remote-endpoint"
        )
    shown = f"[{host}]" if ":" in host else host
    return Endpoint(url=f"http://{shown}:{port}", host=host, port=port, is_loopback=is_loopback)


def otel_environment_names(environ: Optional[Mapping[str, str]] = None) -> tuple[str, ...]:
    """
    The NAMES of the environment variables that start with OTEL_, sorted.
    Values are never returned.
    """
    source = os.environ if environ is None else environ
    return tuple(sorted(name for name in source if name.upper().startswith("OTEL_")))


def check_reachable(host: str, port: int) -> None:
    """
    One TCP connection to the endpoint, closed at once.

    Raises:
        DriverError  nothing accepts connections there.
    """
    try:
        connection = socket.create_connection((host, port), REACHABILITY_TIMEOUT_SECONDS)
    except OSError as exc:
        raise DriverError(
            f"nothing is reachable at {host}:{port} ({type(exc).__name__}); "
            "nothing was executed"
        ) from None
    connection.close()


# ---------------------------------------------------------------------------
# The demo application
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Demo:
    """
    What the driver needs of the demo application: its compiled graph and
    the three modules whose names are rebound during a run.
    """

    app: Any
    tool: Any
    retrieval: Any
    instrumentation: Any


def load_demo() -> Demo:
    """
    Import the demo application.  Its directory has to be on the import path
    already (PYTHONPATH), as for the stream processor and the storage
    consumer; this function does not change the path.

    Raises:
        DriverError  the application or one of its packages is not importable.
    """
    try:
        import graph
        from agents import retrieval, tool_agent
        from observability import instrumentation
    except ImportError as exc:
        raise DriverError(
            "the demo application cannot be imported "
            f"({type(exc).__name__}: {exc.name or 'unknown module'}); put its "
            "directory on PYTHONPATH and install its requirements"
        ) from None
    return Demo(
        app=graph.app, tool=tool_agent, retrieval=retrieval, instrumentation=instrumentation,
    )


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------

class Outcome(Enum):
    EXPECTED_SUCCESS = "expected_success"
    EXPECTED_FAILURE = "expected_failure"
    UNEXPECTED_FAILURE = "unexpected_failure"
    MISSING_FAILURE = "missing_failure"
    REACH_FAILURE = "reach_failure"
    NOT_STARTED = "not_started"


#: Outcomes of the workload itself.  Every other outcome of an executed
#: attempt is an integrity problem.
WORKLOAD_OUTCOMES: frozenset[Outcome] = frozenset({
    Outcome.EXPECTED_SUCCESS, Outcome.EXPECTED_FAILURE,
})
INTEGRITY_OUTCOMES: frozenset[Outcome] = frozenset({
    Outcome.UNEXPECTED_FAILURE, Outcome.MISSING_FAILURE, Outcome.REACH_FAILURE,
})

assert tuple(outcome.value for outcome in Outcome) == OUTCOMES


@dataclass(frozen=True)
class AttemptResult:
    """What became of one planned attempt.  start_lag_seconds is set on the
    first attempt of a request that was started."""

    request_index: int
    attempt: int
    request_id: str
    outcome: Outcome
    detail: str = ""
    start_lag_seconds: Optional[float] = None


def classify(
    effects: Effects,
    raised: Optional[BaseException],
    reach_problems: tuple[str, ...],
) -> tuple[Outcome, str]:
    """
    Compare what an attempt did with what was planned for it.

    A planned failure is recognised by the type name and the message of the
    exception that was raised.  A wrapper that was not reached as planned
    outranks everything else: the attempt's telemetry cannot be trusted.
    """
    described = "nothing raised" if raised is None else (
        f"raised {type(raised).__name__}: {raised}"
    )
    if reach_problems:
        return Outcome.REACH_FAILURE, "; ".join(reach_problems) + f" ({described})"
    fault = effects.fault
    if fault is None:
        if raised is None:
            return Outcome.EXPECTED_SUCCESS, ""
        return Outcome.UNEXPECTED_FAILURE, f"no failure was planned; {described}"
    if raised is None:
        return Outcome.MISSING_FAILURE, f"planned {fault.error_type}; nothing raised"
    if type(raised).__name__ == fault.error_type and str(raised) == fault.error_message:
        return Outcome.EXPECTED_FAILURE, ""
    return Outcome.UNEXPECTED_FAILURE, f"planned {fault.error_type}; {described}"


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------

class _Counters:
    """Span accounting of one run; updated from several threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.spans_ended = 0
        self.spans_exported_successfully = 0
        self.export_failures = 0

    def ended(self) -> None:
        with self._lock:
            self.spans_ended += 1

    def exported(self, count: int, success: bool) -> None:
        with self._lock:
            if success:
                self.spans_exported_successfully += count
            else:
                self.export_failures += 1


@dataclass(frozen=True)
class _Telemetry:
    provider: Any
    tracer: Any
    counters: _Counters


def build_otlp_exporter(endpoint: Endpoint) -> Any:
    """
    The OTLP gRPC span exporter for one validated endpoint.  Every setting
    that has a parameter is given explicitly.  Constructing it sends nothing.
    """
    from grpc import Compression
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    return OTLPSpanExporter(
        endpoint=endpoint.url,
        insecure=True,
        timeout=EXPORT_TIMEOUT_SECONDS,
        compression=Compression.NoCompression,
    )


def _build_telemetry(span_exporter: Any, max_queue_size: int) -> _Telemetry:
    """
    A provider of the driver's own, not registered process-wide, with a
    batching processor in front of the given exporter and exact counts of
    spans ended and spans the exporter reported as exported.
    """
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider, sampling
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        SpanExporter,
        SpanExportResult,
    )

    counters = _Counters()

    class CountingExporter(SpanExporter):
        def export(self, spans):  # type: ignore[no-untyped-def]
            try:
                result = span_exporter.export(spans)
            except Exception:  # noqa: BLE001 - an exporter that raises has failed
                counters.exported(len(spans), False)
                return SpanExportResult.FAILURE
            counters.exported(len(spans), result is SpanExportResult.SUCCESS)
            return result

        def shutdown(self) -> None:
            span_exporter.shutdown()

        def force_flush(self, timeout_millis: int = FLUSH_TIMEOUT_MILLIS) -> bool:
            return span_exporter.force_flush(timeout_millis)

    class EndCounter(SpanProcessor):
        def on_end(self, span) -> None:  # type: ignore[no-untyped-def]
            counters.ended()

    provider = TracerProvider(
        resource=Resource.create({"service.name": SERVICE_NAME}),
        sampler=sampling.ALWAYS_ON,
    )
    provider.add_span_processor(EndCounter())
    provider.add_span_processor(BatchSpanProcessor(
        CountingExporter(),
        max_queue_size=max_queue_size,
        schedule_delay_millis=SCHEDULE_DELAY_MILLIS,
        max_export_batch_size=min(MAX_EXPORT_BATCH_SIZE, max_queue_size),
        export_timeout_millis=FLUSH_TIMEOUT_MILLIS,
    ))
    return _Telemetry(
        provider=provider, tracer=provider.get_tracer(TRACER_NAME), counters=counters,
    )


@contextmanager
def _bound_tracer(instrumentation: Any, tracer: Any) -> Iterator[None]:
    """
    Make the instrumentation module create its spans with `tracer` for the
    block, and give it back its own tracer afterwards, whatever happens.

    Raises:
        DriverError  the module has no tracer to rebind.
    """
    if not hasattr(instrumentation, "_tracer"):
        raise DriverError(
            "the instrumentation module has no _tracer; the demo application "
            "is not structured as this driver expects"
        )
    original = instrumentation._tracer
    instrumentation._tracer = tracer
    try:
        yield
    finally:
        instrumentation._tracer = original


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _state(attempt: Attempt) -> dict[str, Any]:
    """The initial state, in the shape the demo application's own entry point uses."""
    return {
        "request_id": attempt.request_id,
        "session_id": attempt.session_id,
        "user_request": attempt.query,
        "retrieval_query": None,
        "retrieved_context": None,
        "tool_result": None,
        "synthesized_answer": None,
        "final_response": None,
    }


class _Run:
    """The state of one execution: what was done, and whether to go on."""

    def __init__(
        self,
        plan: Plan,
        demo: Demo,
        telemetry: _Telemetry,
        injector: FaultInjector,
        clock: Clock,
        pause: Pause,
        deadline: float,
    ) -> None:
        self.plan = plan
        self.demo = demo
        self.tracer = telemetry.tracer
        self.injector = injector
        self.clock = clock
        self.pause = pause
        self.deadline = deadline
        self.stop = threading.Event()
        self.deadline_reached = threading.Event()
        self._lock = threading.Lock()
        self.results: list[AttemptResult] = []

    def record(self, result: AttemptResult) -> None:
        with self._lock:
            self.results.append(result)

    def _skip(self, request: PlannedRequest, remaining: tuple[Attempt, ...], why: str) -> None:
        for attempt in remaining:
            self.record(AttemptResult(
                request.request_index, attempt.attempt, attempt.request_id,
                Outcome.NOT_STARTED, why,
            ))

    def skip_request(self, request: PlannedRequest, why: str) -> None:
        self._skip(request, attempts(request), why)

    def _attempt(self, request: PlannedRequest, attempt: Attempt) -> tuple[Outcome, str]:
        raised: Optional[BaseException] = None
        with self.injector.applied(attempt.effects) as reach:
            try:
                with self.tracer.start_as_current_span(ROOT_SPAN_NAME) as span:
                    span.set_attribute(ATTR_OPERATION, ROOT_OPERATION)
                    span.set_attribute(ATTR_REQUEST_ID, attempt.request_id)
                    span.set_attribute(ATTR_SESSION_ID, attempt.session_id)
                    span.set_attribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION)
                    span.set_attribute(ATTR_RUN_ID, self.plan.config.run_id)
                    span.set_attribute(ATTR_MODE, MODE_REAL)
                    span.set_attribute(ATTR_SCENARIO, request.scenario.value)
                    span.set_attribute(ATTR_PERSONA, request.persona.value)
                    self.demo.app.invoke(_state(attempt))
            except Exception as exc:  # noqa: BLE001 - compared with the plan below
                raised = exc
        return classify(attempt.effects, raised, reach.problems(attempt.effects))

    def run_request(self, request: PlannedRequest, start_lag: float) -> None:
        """
        Every planned attempt of one request, one after another.  start_lag
        is how long after its planned arrival the request was handed to a
        worker.
        """
        planned = attempts(request)
        for position, attempt in enumerate(planned):
            if self.stop.is_set():
                self._skip(request, planned[position:], "the run was stopped")
                return
            if attempt.attempt > 0:
                # The client waits before it submits again.
                self.pause(attempt.backoff_seconds)
                if self.stop.is_set():
                    self._skip(request, planned[position:], "the run was stopped")
                    return
            if self.clock() >= self.deadline:
                self.deadline_reached.set()
                self._skip(request, planned[position:], "the deadline was reached")
                return
            lag = start_lag if attempt.attempt == 0 else None
            outcome, detail = self._attempt(request, attempt)
            self.record(AttemptResult(
                request.request_index, attempt.attempt, attempt.request_id, outcome, detail,
                lag,
            ))
            if outcome in INTEGRITY_OUTCOMES:
                # Nothing further is started: not for this request, not for any.
                self.stop.set()
                self._skip(request, planned[position + 1:], "an earlier attempt deviated")
                return


def _dispatch(run: _Run, concurrency: int, start: float) -> None:
    """
    Start each request at its planned arrival time, at most `concurrency` at
    once.  A request whose turn comes while every worker is busy starts late;
    it is not dropped and nothing is started early.
    """
    slots = threading.BoundedSemaphore(concurrency)

    def worker(request: PlannedRequest, start_lag: float) -> None:
        try:
            run.run_request(request, start_lag)
        except BaseException:
            # Not a workload result (those are recorded, not raised): a
            # defect or an interruption.  Nothing further is started.
            run.stop.set()
            raise
        finally:
            slots.release()

    requests = run.plan.requests
    submitted = 0
    with ThreadPoolExecutor(
        max_workers=concurrency, thread_name_prefix="workload",
    ) as pool:
        futures = []
        try:
            for request in requests:
                if run.stop.is_set():
                    break
                target = start + request.arrival_offset_seconds
                if target >= run.deadline:
                    run.deadline_reached.set()
                    break
                delay = target - run.clock()
                if delay > 0.0:
                    run.pause(delay)
                # Waits while every worker is busy, so no backlog builds up.
                slots.acquire()
                if run.stop.is_set() or run.clock() >= run.deadline:
                    if not run.stop.is_set():
                        run.deadline_reached.set()
                    slots.release()
                    break
                # Measured here, when a worker is free for the request: the
                # time it had to wait for capacity beyond its planned arrival.
                start_lag = max(0.0, run.clock() - target)
                futures.append(pool.submit(worker, request, start_lag))
                submitted += 1
        except BaseException:
            # Interrupted while dispatching: running work finishes, no retry
            # and no new request is started.
            run.stop.set()
            raise
        for future in futures:
            # A worker never raises for a workload result; anything that does
            # get here is a defect and must not be lost.
            future.result()

    why = "the run was stopped" if run.stop.is_set() else "the deadline was reached"
    for request in requests[submitted:]:
        run.skip_request(request, why)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


#: At most this many entries in the start-lag diagnostic of one run.
START_LAG_LIMIT: int = 10000


def _finite_nonnegative(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and value == value and value != float("inf") and value >= 0.0)


def build_start_lags(
    plan: Plan, results: Sequence[AttemptResult], *, limit: int = START_LAG_LIMIT,
) -> dict[str, Any]:
    """
    Diagnostic only: [request_index, planned_offset_s, start_lag_s] for the
    first attempt of every started request (failed ones included; retries
    and requests never started left out), in request-index order.

    Built from the results the run already recorded, after it ended: no
    clock is read and nothing in the dispatcher or the workers changes.  The
    late-start count does not depend on it.  An entry whose lag or planned
    offset is missing or invalid, or whose request index repeats, is left
    out and named in truncated_reason; beyond `limit` entries the first ones
    are kept and truncated_reason is "limit".
    """
    offsets = {request.request_index: request.arrival_offset_seconds
               for request in plan.requests}
    started = sorted(
        (r for r in results if r.attempt == 0 and r.outcome is not Outcome.NOT_STARTED),
        key=lambda r: r.request_index,
    )
    reasons: list[str] = []
    seen: set[int] = set()
    entries: list[list[Any]] = []
    for result in started:
        index = result.request_index
        if index in seen:
            reasons.append("duplicate request index")
            continue
        seen.add(index)
        if not _finite_nonnegative(result.start_lag_seconds):
            reasons.append("missing or invalid start lag")
            continue
        offset = offsets.get(index)
        if not _finite_nonnegative(offset):
            reasons.append("missing or invalid planned offset")
            continue
        entries.append([index, round(offset, 6), round(result.start_lag_seconds, 6)])
    if len(entries) > limit:
        entries = entries[:limit]
        reasons.append("limit")
    reasons = list(dict.fromkeys(reasons))
    complete = not reasons and len(entries) == len(started)
    return {
        "limit": limit, "expected": len(started), "recorded": len(entries),
        "complete": complete,
        "truncated_reason": None if complete else ("; ".join(reasons) or "incomplete"),
        "entries": entries,
    }


def _report(
    plan: Plan,
    results: list[AttemptResult],
    telemetry: _Telemetry,
    *,
    endpoint: str,
    started: datetime,
    finished: datetime,
    elapsed: float,
    flush_ok: bool,
    stopped: bool,
    deadline_reached: bool,
) -> ExecutionReport:
    counts = {name: 0 for name in OUTCOMES}
    for result in results:
        counts[result.outcome.value] += 1
    executed = [r for r in results if r.outcome is not Outcome.NOT_STARTED]
    first = [r for r in results if r.attempt == 0]
    lags = [r.start_lag_seconds for r in first if r.start_lag_seconds is not None]
    counters = telemetry.counters

    integrity = [r for r in executed if r.outcome in INTEGRITY_OUTCOMES]
    integrity.sort(key=lambda r: (r.request_index, r.attempt))
    problems = tuple(
        f"request {r.request_index} attempt {r.attempt} ({r.request_id}): "
        f"{r.outcome.value}: {r.detail}"
        for r in integrity[:MAX_PROBLEMS_LISTED]
    )

    export_ok = (
        flush_ok
        and counters.export_failures == 0
        and counters.spans_ended == counters.spans_exported_successfully
    )
    if stopped or integrity:
        status = "stopped_integrity"
    elif not export_ok:
        status = "export_failed"
    elif deadline_reached:
        status = "deadline_reached"
    else:
        status = "completed"

    return ExecutionReport(
        endpoint=endpoint,
        started=started.isoformat(timespec="seconds"),
        finished=finished.isoformat(timespec="seconds"),
        elapsed_seconds=round(elapsed, 3),
        planned_requests=len(plan.requests),
        planned_retries=plan.planned_retries,
        planned_submissions=len(plan.requests) + plan.planned_retries,
        started_requests=sum(1 for r in first if r.outcome is not Outcome.NOT_STARTED),
        not_started_requests=sum(1 for r in first if r.outcome is Outcome.NOT_STARTED),
        attempts=counts,
        executed_attempts=len(executed),
        executed_retries=sum(1 for r in executed if r.attempt > 0),
        late_starts=sum(1 for lag in lags if lag > LATE_START_SECONDS),
        max_start_lag_seconds=round(max(lags), 3) if lags else 0.0,
        mean_start_lag_seconds=round(sum(lags) / len(lags), 3) if lags else 0.0,
        achieved_submission_rate=round(len(executed) / elapsed, 3) if elapsed > 0 else 0.0,
        spans_ended=counters.spans_ended,
        spans_exported_successfully=counters.spans_exported_successfully,
        export_failures=counters.export_failures,
        flush_ok=flush_ok,
        run_status=status,
        problems=problems,
        start_lags=build_start_lags(plan, results),
    )


def execute(
    plan: Plan,
    *,
    demo: Demo,
    span_exporter: Any,
    endpoint: str,
    concurrency: int,
    max_duration_seconds: float,
    pause: Pause,
    clock: Clock,
    now: Callable[[], datetime] = _utc_now,
    max_queue_size: int = MAX_QUEUE_SIZE,
) -> ExecutionReport:
    """
    Execute a plan and return what was done.

    span_exporter receives the spans; endpoint is only the text shown for it
    in the report.  pause is called with seconds whenever the plan calls for
    waiting (arrival times, planned latencies, retry backoffs); clock returns
    monotonic seconds.  Both are given by the caller, so that tests can run
    without waiting.

    Whatever happens, the spans are flushed, the provider is shut down, and
    the demo application's functions and tracer are put back.

    Raises:
        DriverError  telemetry cannot be set up, or the demo application is
                     not structured as expected; nothing was executed.
        ValueError   an argument is out of range.
    """
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError("concurrency must be a positive integer")
    if not max_duration_seconds > 0:
        raise ValueError("max_duration_seconds must be positive")
    if isinstance(max_queue_size, bool) or not isinstance(max_queue_size, int) or not (
        1 <= max_queue_size <= MAX_QUEUE_SIZE
    ):
        raise ValueError(f"max_queue_size must be between 1 and {MAX_QUEUE_SIZE}")

    telemetry = _build_telemetry(span_exporter, max_queue_size)
    injector = FaultInjector(
        tool=demo.tool, retrieval=demo.retrieval, instrumentation=demo.instrumentation,
        pause=pause,
    )
    flush_ok = False
    started = now()
    start = clock()
    run = _Run(
        plan, demo, telemetry, injector, clock, pause, start + max_duration_seconds,
    )
    try:
        with _bound_tracer(demo.instrumentation, telemetry.tracer), injector.installed():
            _dispatch(run, concurrency, start)
    finally:
        # Always: nothing a run produced may be left unflushed, and the
        # provider's worker thread must not outlive the run.
        try:
            flush_ok = bool(telemetry.provider.force_flush(FLUSH_TIMEOUT_MILLIS))
        finally:
            telemetry.provider.shutdown()
    elapsed = clock() - start
    return _report(
        plan, run.results, telemetry,
        endpoint=endpoint, started=started, finished=now(), elapsed=elapsed,
        flush_ok=flush_ok, stopped=run.stop.is_set(),
        deadline_reached=run.deadline_reached.is_set(),
    )


def run_real(
    plan: Plan,
    *,
    endpoint: Endpoint,
    concurrency: int,
    max_duration_seconds: float,
    reachability: Reachability = check_reachable,
    demo_loader: Callable[[], Demo] = load_demo,
    exporter_factory: Callable[[Endpoint], Any] = build_otlp_exporter,
    pause: Pause = time.sleep,
    clock: Clock = time.monotonic,
) -> ExecutionReport:
    """
    The production path: refuse if OpenTelemetry variables are set, check
    that the endpoint accepts connections, load the demo application, build
    the OTLP exporter and execute.  Nothing is executed unless every step
    before execution succeeds.

    Raises:
        DriverError  the run was refused or could not be set up.
    """
    names = otel_environment_names()
    if names:
        raise DriverError(
            "OpenTelemetry environment variables are set and could alter the "
            "run: " + ", ".join(names)
        )
    reachability(endpoint.host, endpoint.port)
    demo = demo_loader()
    return execute(
        plan,
        demo=demo,
        span_exporter=exporter_factory(endpoint),
        endpoint=endpoint.url,
        concurrency=concurrency,
        max_duration_seconds=max_duration_seconds,
        pause=pause,
        clock=clock,
    )


def exit_code(execution: ExecutionReport) -> int:
    """The process exit code for a finished run."""
    return _EXIT_CODES[execution.run_status]

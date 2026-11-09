"""
workload-generator/run_e2e.py

Small end-to-end test of the workload generator on the same separate,
disposable stack as run_smoke.py, carried through to the anomaly detector:

    REAL driver -> OTLP -> collector -> Kafka -> stream processor
        -> canonical Kafka topic -> storage consumer -> PostgreSQL
        -> analytics refresh (dbt) -> anomaly detector -> anomaly_events

Three workloads are sent, one after the other, with one request in flight
at a time so that spans are stored in the order they were planned:

    f-warm-002   normal             30 requests   history for the detectors
    f-slow-002   slow-tool          40 requests   12 slow tool calls
    f-fail-002   repeated-failure   40 requests   12 failed tool calls

Then the analytics models are rebuilt with the sanctioned refresh, the
existing anomaly detector runs twice with detector_config.json, and its
rows are reconciled with the plans:

    exact     the failure path: which requests are reported, by which
              detector, with which severity; and that a second detector run
              inserts nothing
    bounded   the latency path: real durations carry overhead, so the test
              asks for at least 10 of the 12 slow requests per signal and at
              most 3 healthy requests per signal

It only ORCHESTRATES.  The stack, the readiness checks, the execution and
reconciliation of a stage and the cleanup are run_smoke.py's, imported and
unchanged.  The detector's algorithms and thresholds are the existing ones;
detector_config.json only selects which of its groups run.

The first failure stops the run; nothing is retried or adjusted.  Cleanup
always runs.

    python workload-generator/run_e2e.py                      # prints the plan and exits; nothing runs
    python workload-generator/run_e2e.py --expect-head <40-hex> [--approved-tree <manifest>
            --approved-tree-sha256 <64-hex>] --preflight      # reads only: repository and resources
    python workload-generator/run_e2e.py --expect-head <40-hex> [--approved-tree <manifest>
            --approved-tree-sha256 <64-hex>] --execute --confirm "<phrase>"

A live run needs --execute, the full expected HEAD and the confirmation phrase printed by the plan (with the
real HEAD in it).  A dirty working tree is accepted only when it is exactly the one an operator-approved
manifest describes; otherwise the strict check of run_smoke applies.  The resource preflight runs before
anything is created.  Cleanup is contained to this run's own project; the result states, separately,
workload acceptance, Docker and process cleanup, workspace retention and protected-resource verification.

Exit codes:
    0  everything reconciled, cleanup was verified and the protected resources are unchanged
       (a workspace retained by policy on Windows does not change this)
    1  anything else
    2  a usage error: nothing was started
    130  cleanup was interrupted (Ctrl-C): never a success; manual review of the project's resources is required

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_smoke as smoke  # noqa: E402
from run_smoke import Checks, SmokeFailure, Stage, say, section  # noqa: E402

DETECTOR_CONFIG: str = "workload-generator/detector_config.json"
REFRESH_SERVICE: str = "analytics-refresh"
REFRESH_PROFILE: str = "analytics-refresh"

#: What may differ from the commit while these files are under review.
ALLOWED_CHANGES: frozenset[str] = frozenset({
    "?? workload-generator/detector_config.json",
    "?? workload-generator/run_e2e.py",
    " M workload-generator/tests/unit/test_cli.py",
})

#: One request in flight at a time: spans are stored in planned order, which
#: the exact failure expectations below depend on.
CONCURRENCY: int = 1

# Seconds.
T_DRAIN: float = 120.0
T_REFRESH: float = 300.0
T_DETECTOR: float = 120.0

#: The one Docker engine this harness may use (Phase 14.7, Step 3), and the protected objects that must exist on
#: it before anything is created.  Changing the engine means changing, and reviewing, this constant.
PINNED_ENGINE = smoke.EnginePin(
    context="desktop-linux",
    endpoint="npipe:////./pipe/dockerDesktopLinuxEngine",
    engine_id="14136b17-759d-4fa3-b3a8-51411d61f7d8",
    required_containers=(
        ("agentops-mvp-workers-postgres-1",
         "509fe585c0591886047a869f198fe47d4a2b36dda9eb10a90195d50d9fdd51a4", "agentops-mvp-workers-postgres-data"),
        ("agentops-mvp-workers-viewer-1",
         "94774118be5faad84f24f01fc33f44ca49c55bf8317b19da43b318a882b4710e", ""),
        ("agentops-pipetest-postgres-1",
         "57ac9ee8ff8bc234ef0c1cecce146b91cf50158e0db53d04ce2365304f510ca8", "agentops-pipetest-pgdata"),
    ),
    required_volumes=smoke.PROTECTED_VOLUME_NAMES,
)

WARM = Stage(
    run_id="f-warm-002", scenario="normal", traces=30, max_duration=60,
    digest_prefix="7a58209c592ddb3e",
    successes=30, failures=0, failing_indexes=(),
    spans=210, trace_sizes={"7": 30}, status={"UNSET": 210},
    error_spans={}, error_types={}, scenario_roots={"normal": 30},
)
SLOW = Stage(
    run_id="f-slow-002", scenario="slow-tool", traces=40, max_duration=90,
    digest_prefix="82cb25d0b6292938",
    successes=40, failures=0, failing_indexes=(),
    spans=280, trace_sizes={"7": 40}, status={"UNSET": 280},
    error_spans={}, error_types={}, scenario_roots={"normal": 28, "slow-tool": 12},
)
FAIL = Stage(
    run_id="f-fail-002", scenario="repeated-failure", traces=40, max_duration=90,
    digest_prefix="db61f197d0da884a",
    successes=28, failures=12, failing_indexes=tuple(range(20, 32)),
    spans=256, trace_sizes={"7": 28, "5": 12}, status={"UNSET": 232, "ERROR": 24},
    error_spans={smoke.ROOT_SPAN: 12, smoke.TOOL_SPAN: 12},
    error_types={"ToolExecutionError": 12},
    scenario_roots={"normal": 28, "repeated-failure": 12},
)
STAGES: tuple[Stage, ...] = (WARM, SLOW, FAIL)

TOTAL_REQUESTS: int = sum(stage.traces for stage in STAGES)
TOTAL_SPANS: int = sum(stage.spans for stage in STAGES)
FAILED_TRACES: int = FAIL.failures
#: Indexes of the slow requests of the slow-tool run.
SLOW_INDEXES: tuple[int, ...] = tuple(range(20, 32))

# The detector's own rules, restated only as what this workload must produce.
#: An error is reported as INFO when it is the first of its group, and as
#: CRITICAL when it completes this many consecutive errors.
PERSISTENCE: int = 5
FAILURE_ERROR_TYPE: str = "ToolExecutionError"
FAILURE_EVENTS: int = 1 + (FAIL.failures - (PERSISTENCE - 1))

MIN_SLOW_FLAGGED: int = 10
MAX_HEALTHY_FLAGGED: int = 3

GROUPS: tuple[tuple[str, str], ...] = (
    ("trace_latency", smoke.ROOT_SPAN),
    ("tool_latency", ""),
    ("error_rate", smoke.ROOT_SPAN),
    ("tool_failure", ""),
)


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------

def planned_requests(stage: Stage) -> list[dict[str, Any]]:
    """
    The requests of a stage as the generator's own planner orders them:
    index, request id, planned scenario, and whether the tool call is
    planned to fail.  Computed by the generator's code; nothing is planned
    here.
    """
    assert smoke.RUN.python is not None
    code = (
        "import json\n"
        "from workload_generator.plan import PlanConfig, build_plan\n"
        "from workload_generator.scenarios import Scenario\n"
        f"plan = build_plan(PlanConfig(seed={smoke.SEED}, run_id={stage.run_id!r},"
        f" scenario=Scenario({stage.scenario!r}), traces={stage.traces},"
        f" rate={float(smoke.RATE)!r}, persona=None, mode='real'))\n"
        "print(json.dumps([{'index': r.request_index, 'request_id': r.request_id,"
        " 'scenario': r.scenario.value, 'failing': r.fault is not None,"
        " 'retries': len(r.retries)} for r in plan.requests]))\n"
    )
    return json.loads(smoke.checked(
        [str(smoke.RUN.python), "-c", code], cwd=smoke.REPO / "workload-generator",
        timeout=smoke.T_COMMAND, what="planned requests", env=smoke.host_environment(),
    ))


def check_plans(plans: Mapping[str, Sequence[Mapping[str, Any]]]) -> None:
    """The plans are the approved ones before anything is sent."""
    checks = Checks()
    checks.equal("requests in all", sum(len(plan) for plan in plans.values()), TOTAL_REQUESTS)
    checks.equal("planned retries in all",
                 sum(r["retries"] for plan in plans.values() for r in plan), 0)
    checks.equal("slow-tool requests",
                 tuple(r["index"] for r in plans[SLOW.run_id] if r["scenario"] == "slow-tool"),
                 SLOW_INDEXES)
    checks.equal("repeated-failure requests",
                 tuple(r["index"] for r in plans[FAIL.run_id] if r["failing"]),
                 FAIL.failing_indexes)
    checks.equal("failing requests outside the failure run",
                 sum(r["failing"] for run_id, plan in plans.items()
                     if run_id != FAIL.run_id for r in plan), 0)
    checks.equal("spans expected in all", TOTAL_SPANS, 746)
    checks.finish("plans")


def expected_failure_events(plan: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """
    request id -> severity the detectors' rules give the failing requests of
    one run, taken in planned order with no error before them: the first is
    INFO, the next ones are not reported, and from the one that completes
    PERSISTENCE consecutive errors on, each is CRITICAL.
    """
    failing = [r for r in sorted(plan, key=lambda r: r["index"]) if r["failing"]]
    expected = {}
    for position, request in enumerate(failing, start=1):
        if position == 1:
            expected[request["request_id"]] = "INFO"
        elif position >= PERSISTENCE:
            expected[request["request_id"]] = "CRITICAL"
    return expected


# ---------------------------------------------------------------------------
# Analytics refresh
# ---------------------------------------------------------------------------

def refresh_command(*args: str) -> list[str]:
    """A Compose command for the refresh service, which belongs to a profile."""
    return smoke.compose_command("--profile", REFRESH_PROFILE, *args)


def build_refresh_image() -> None:
    """Built before any traffic, so that the detector runs soon after it."""
    section("analytics refresh image")
    smoke.RUN.compose_used = True
    build = smoke.run(refresh_command("build", REFRESH_SERVICE), timeout=smoke.T_BUILD,
                      what="compose build analytics-refresh")
    smoke.write_log("build-refresh.log", build.stdout + build.stderr)
    if build.returncode != 0:
        raise SmokeFailure("building the refresh image failed:\n"
                           + "\n".join((build.stdout + build.stderr).splitlines()[-10:]))
    say("built")


def ledger_fingerprint() -> str:
    return smoke.psql(
        "SELECT count(*) || ' steps, ' || md5(string_agg(position || ':' || step || ':' "
        "|| checksum, ',' ORDER BY position)) FROM agentops_bootstrap.ledger"
    )


def refresh_analytics() -> None:
    """The sanctioned refresh: it refuses any database the bootstrap has not
    completed, rebuilds the models, re-applies and verifies the grants."""
    section("analytics refresh")
    smoke.check_host_processes()
    before = ledger_fingerprint()
    result = smoke.run(refresh_command("run", "--rm", "-T", REFRESH_SERVICE),
                       timeout=T_REFRESH, what="analytics refresh")
    output = result.stdout + result.stderr
    smoke.write_log("analytics-refresh.log", output)
    say(f"analytics-refresh exit code {result.returncode}")
    for line in output.strip().splitlines()[-4:]:
        say("  " + line[:200])
    if result.returncode != 0:
        raise SmokeFailure("the analytics refresh failed")
    checks = Checks()
    checks.equal("ledger unchanged by the refresh", ledger_fingerprint(), before)
    checks.equal("ledger steps", before.split(" ")[0], str(smoke.LEDGER_STEPS))
    found = json.loads(smoke.psql(
        "SELECT json_build_object("
        "'stg_spans', (SELECT count(*) FROM analytics.stg_telemetry_spans),"
        "'traces', (SELECT count(*) FROM analytics.mart_trace_metrics),"
        "'request_traces', (SELECT count(*) FROM analytics.mart_trace_metrics"
        f" WHERE root_service_name = '{smoke.SERVICE_NAME}' AND root_span_name = '{smoke.ROOT_SPAN}'),"
        "'error_traces', (SELECT count(*) FROM analytics.mart_trace_metrics WHERE has_error),"
        "'trace_spans', (SELECT coalesce(sum(span_count), 0) FROM analytics.mart_trace_metrics),"
        "'tool_spans', (SELECT count(*) FROM analytics.stg_telemetry_spans"
        f" WHERE span_name = '{smoke.TOOL_SPAN}'),"
        "'anomaly_rows', (SELECT count(*) FROM public.anomaly_events),"
        "'checkpoints', (SELECT count(*) FROM public.anomaly_detector_runs))"
    ))
    checks.equal("analytics.stg_telemetry_spans rows", found["stg_spans"], TOTAL_SPANS)
    checks.equal("analytics.mart_trace_metrics traces", found["traces"], TOTAL_REQUESTS)
    checks.equal("traces rooted at the request span", found["request_traces"], TOTAL_REQUESTS)
    checks.equal("traces with has_error", found["error_traces"], FAILED_TRACES)
    checks.equal("spans counted by the trace mart", found["trace_spans"], TOTAL_SPANS)
    checks.equal("tool.execute spans", found["tool_spans"], TOTAL_REQUESTS)
    checks.equal("anomaly_events rows before the detector", found["anomaly_rows"], 0)
    checks.equal("detector checkpoints before the detector", found["checkpoints"], 0)
    checks.finish("analytics refresh")


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

_GROUP_LINE = re.compile(r"\[(\w+) / ([^/\]]+?) / ([^\]]*)\]\s*$")
_FIELD_LINE = re.compile(r"\s(\w+)\s*: (.*)$")


def parse_detector_log(text: str) -> tuple[list[dict[str, str]], dict[str, str]]:
    """
    (groups, summary) from the detector's log: one dict of its printed fields
    per group, in order, each with signal_path / service_name /
    operation_name; and the fields printed after "run complete".
    """
    groups: list[dict[str, str]] = []
    summary: dict[str, str] = {}
    target: Optional[dict[str, str]] = None
    for line in text.splitlines():
        header = _GROUP_LINE.search(line)
        if header:
            target = {"signal_path": header.group(1), "service_name": header.group(2),
                      "operation_name": header.group(3)}
            groups.append(target)
            continue
        if line.rstrip().endswith("run complete"):
            target = summary
            continue
        field = _FIELD_LINE.search(line)
        if field and target is not None:
            target[field.group(1)] = field.group(2).strip()
    return groups, summary


def run_detector(label: str) -> tuple[list[dict[str, str]], dict[str, str]]:
    """One pass of the existing detector, as its own role, on the isolated
    database."""
    assert smoke.RUN.python is not None
    result = smoke.run(
        [str(smoke.RUN.python), "main.py", "--config", str(smoke.REPO / DETECTOR_CONFIG)],
        cwd=smoke.REPO / "anomaly-detector", timeout=T_DETECTOR, what=f"detector {label}",
        env=smoke.host_environment(
            ANOMALY_DETECTOR_DB_HOST="127.0.0.1",
            ANOMALY_DETECTOR_DB_PORT=str(smoke.POSTGRES_PORT),
            ANOMALY_DETECTOR_DB_NAME="agentops",
            ANOMALY_DETECTOR_DB_USER="anomaly_detector",
            ANOMALY_DETECTOR_DB_PASSWORD=smoke.RUN.generated["ANOMALY_DETECTOR_DB_PASSWORD"],
        ),
    )
    output = result.stdout + result.stderr
    smoke.write_log(f"detector-{label}.log", output)
    wrong = smoke._WRONG_STACK.search(output)
    if wrong:
        raise SmokeFailure(f"detector {label}: mentions the normal stack's port {wrong.group(1)}")
    say(f"detector exit code {result.returncode}")
    if result.returncode != 0:
        raise SmokeFailure(f"detector {label} failed:\n" + "\n".join(output.splitlines()[-12:]))
    groups, summary = parse_detector_log(output)
    for group in groups:
        say("  %-13s %-17s status %s, candidates %s, emitted %s, inserted %s, duplicate %s" % (
            group["signal_path"], group["operation_name"] or "-", group.get("status"),
            group.get("candidates"), group.get("emitted"), group.get("inserted"),
            group.get("duplicate")))
    return groups, summary


def check_detector_run(
    groups: Sequence[Mapping[str, str]], summary: Mapping[str, str], checks: Checks,
) -> None:
    """What holds for every detector pass."""
    checks.equal("groups, in configured order",
                 [(g["signal_path"], g["operation_name"]) for g in groups], list(GROUPS))
    checks.equal("service of every group", sorted({g["service_name"] for g in groups}),
                 [smoke.SERVICE_NAME])
    checks.equal("group statuses", sorted({g.get("status") for g in groups}), ["ok"])
    checks.equal("checkpoints advanced",
                 sorted({g.get("checkpoint_advanced") for g in groups}), ["True"])
    checks.equal("groups attempted / ok / uncertain / error",
                 [summary.get("groups_attempted"), summary.get("groups_ok"),
                  summary.get("groups_uncertain"), summary.get("groups_error")],
                 [str(len(GROUPS)), str(len(GROUPS)), "0", "0"])
    checks.equal("completed all groups", summary.get("completed_all_groups"), "True")
    checks.equal("totals equal the sum of the groups",
                 [int(summary.get(name, -1)) for name in
                  ("total_candidates", "total_emitted", "total_inserted", "total_duplicate")],
                 [sum(int(g.get(name, 0)) for g in groups) for name in
                  ("candidates", "emitted", "inserted", "duplicate")])


_EVENTS_SQL = """
WITH roots AS (
    SELECT trace_id::text AS trace_id,
           coalesce(request_id, attributes->>'agentops.request_id') AS request_id,
           attributes->>'agentops.workload.run_id' AS run_id,
           attributes->>'agentops.workload.scenario' AS scenario,
           status_code = 'ERROR' AS root_error
    FROM telemetry_spans
    WHERE parent_span_id IS NULL AND attributes ? 'agentops.workload.run_id'
)
SELECT json_build_object(
  'rows', (SELECT count(*) FROM public.anomaly_events),
  'checkpoints', (SELECT count(*) FROM public.anomaly_detector_runs),
  'events', (SELECT coalesce(json_agg(json_build_object(
      'anomaly_type', a.anomaly_type, 'signal_name', a.signal_name,
      'detector_name', a.detector_name, 'severity', a.severity,
      'service_name', a.service_name, 'operation_name', a.operation_name,
      'span', a.span_id IS NOT NULL, 'run_id', r.run_id, 'scenario', r.scenario,
      'request_id', r.request_id, 'root_error', r.root_error)), '[]')
    FROM public.anomaly_events a LEFT JOIN roots r ON r.trace_id = a.trace_id)
)
"""


def read_anomalies() -> dict[str, Any]:
    """Every anomaly row with the workload request its trace belongs to."""
    return json.loads(smoke.psql(_EVENTS_SQL))


def reconcile_anomalies(
    events: Sequence[Mapping[str, Any]],
    plans: Mapping[str, Sequence[Mapping[str, Any]]],
    checks: Checks,
) -> None:
    """
    Compare the stored anomaly rows with the plans.  Pure: it reads nothing.

    The failure path is exact.  The latency path is bounded, because the
    durations the detector scores are measured, not planned.
    """
    run_ids = sorted(plans)
    checks.equal("events outside the workload's traces",
                 sum(1 for e in events if e["run_id"] not in run_ids), 0)
    checks.equal("service of every event", sorted({e["service_name"] for e in events}, key=str),
                 [smoke.SERVICE_NAME])
    checks.equal("anomaly types", sorted({e["anomaly_type"] for e in events}),
                 ["error_rate", "latency", "tool_failure"])

    # -- failures: exact ---------------------------------------------------
    expected = expected_failure_events(plans[FAIL.run_id])
    failing_ids = {r["request_id"] for r in plans[FAIL.run_id] if r["failing"]}
    checks.equal("failure events expected per detector", len(expected), FAILURE_EVENTS)
    for anomaly_type, detector, operation in (
        ("tool_failure", "ToolFailureDetector", f"{smoke.TOOL_SPAN}/{FAILURE_ERROR_TYPE}"),
        ("error_rate", "ErrorRateDetector", smoke.ROOT_SPAN),
    ):
        found = [e for e in events if e["anomaly_type"] == anomaly_type]
        checks.equal(f"{anomaly_type} events", len(found), FAILURE_EVENTS)
        checks.equal(f"{anomaly_type} run ids", sorted({e["run_id"] for e in found}, key=str),
                     [FAIL.run_id])
        checks.equal(f"{anomaly_type} detector / operation",
                     sorted({(e["detector_name"], e["operation_name"]) for e in found}, key=str),
                     [(detector, operation)])
        checks.equal(f"{anomaly_type} request -> severity equals the expected mapping",
                     {e["request_id"]: e["severity"] for e in found} == expected, True)
        checks.equal(f"{anomaly_type} severities",
                     smoke._tally(e["severity"] for e in found),
                     smoke._tally(expected.values()))
        checks.equal(f"{anomaly_type} events on requests not planned to fail",
                     sum(1 for e in found if e["request_id"] not in failing_ids), 0)
        checks.equal(f"{anomaly_type} events on traces that did not fail",
                     sum(1 for e in found if not e["root_error"]), 0)
    reported = {
        anomaly_type: sorted(
            (e["request_id"] for e in events if e["anomaly_type"] == anomaly_type), key=str,
        )
        for anomaly_type in ("tool_failure", "error_rate")
    }
    checks.equal("tool_failure and error_rate report the same requests",
                 reported["tool_failure"], reported["error_rate"])

    # -- latency: bounded --------------------------------------------------
    slow_ids = {r["request_id"] for r in plans[SLOW.run_id] if r["scenario"] == "slow-tool"}
    latency = [e for e in events if e["anomaly_type"] == "latency"]
    checks.equal("latency detector / signal",
                 sorted({(e["detector_name"], e["signal_name"]) for e in latency}),
                 [("LatencyDetector", "duration_ms")])
    checks.equal("latency events on failed traces",
                 sum(1 for e in latency if e["root_error"]), 0)
    checks.equal("latency events on requests planned to fail",
                 sum(1 for e in latency if e["request_id"] in failing_ids), 0)
    for name, operation, has_span in (
        ("trace_latency", smoke.ROOT_SPAN, False),
        ("tool_latency", smoke.TOOL_SPAN, True),
    ):
        found = [e for e in latency if e["operation_name"] == operation]
        checks.equal(f"{name} events are {'span' if has_span else 'trace'} level",
                     sorted({e["span"] for e in found}), [has_span])
        on_slow = {e["request_id"] for e in found if e["request_id"] in slow_ids}
        on_healthy = [e for e in found if e["request_id"] not in slow_ids]
        checks.true(f"{name}: slow requests flagged, at least {MIN_SLOW_FLAGGED} of "
                    f"{len(slow_ids)}", len(on_slow) >= MIN_SLOW_FLAGGED, len(on_slow))
        checks.true(f"{name}: healthy requests flagged, at most {MAX_HEALTHY_FLAGGED}",
                    len(on_healthy) <= MAX_HEALTHY_FLAGGED, len(on_healthy))
        checks.equal(f"{name}: at most one event per request",
                     len(found), len({e["request_id"] for e in found}))
        say(f"           {name} severities on slow requests: "
            f"{smoke._tally(e['severity'] for e in found if e['request_id'] in slow_ids)}; "
            f"healthy requests flagged by run: "
            f"{smoke._tally(e['run_id'] for e in on_healthy)}")
    checks.equal("latency events of other operations",
                 sum(1 for e in latency
                     if e["operation_name"] not in (smoke.ROOT_SPAN, smoke.TOOL_SPAN)), 0)
    above_info = sum(1 for e in latency
                     if e["request_id"] in slow_ids and e["severity"] != "INFO")
    checks.true("latency events above INFO on slow requests, at least 1",
                above_info >= 1, above_info)


def detect_and_reconcile(plans: Mapping[str, Sequence[Mapping[str, Any]]]) -> None:
    section("anomaly detector: first run")
    groups, summary = run_detector("run-1")
    stored = read_anomalies()
    checks = Checks()
    check_detector_run(groups, summary, checks)
    checks.equal("candidates of every group", [g.get("candidates") for g in groups],
                 [str(TOTAL_REQUESTS)] * len(GROUPS))
    checks.equal("prior checkpoints", sorted({g.get("prior_checkpoint") for g in groups}),
                 ["None"])
    checks.equal("inserted equals emitted", summary.get("total_inserted"),
                 summary.get("total_emitted"))
    checks.equal("duplicates", summary.get("total_duplicate"), "0")
    checks.equal("anomaly_events rows equal the inserted total", stored["rows"],
                 int(summary.get("total_inserted", -1)))
    checks.equal("detector checkpoints", stored["checkpoints"], len(GROUPS))
    emitted = {g["signal_path"]: int(g.get("emitted", -1)) for g in groups}
    by_path = {
        "trace_latency": sum(1 for e in stored["events"] if e["anomaly_type"] == "latency"
                             and e["operation_name"] == smoke.ROOT_SPAN),
        "tool_latency": sum(1 for e in stored["events"] if e["anomaly_type"] == "latency"
                            and e["operation_name"] == smoke.TOOL_SPAN),
        "error_rate": sum(1 for e in stored["events"] if e["anomaly_type"] == "error_rate"),
        "tool_failure": sum(1 for e in stored["events"] if e["anomaly_type"] == "tool_failure"),
    }
    checks.equal("rows per signal path equal what each group emitted", by_path, emitted)
    checks.finish("detector run 1")

    section("anomaly reconciliation")
    checks = Checks()
    reconcile_anomalies(stored["events"], plans, checks)
    checks.finish("anomaly reconciliation")

    section("anomaly detector: second run")
    groups, summary = run_detector("run-2")
    again = read_anomalies()
    checks = Checks()
    check_detector_run(groups, summary, checks)
    checks.equal("inserted", summary.get("total_inserted"), "0")
    checks.equal("every emitted event is a duplicate", summary.get("total_duplicate"),
                 summary.get("total_emitted"))
    checks.equal("anomaly_events rows unchanged", again["rows"], stored["rows"])
    checks.equal("anomaly rows identical to the first run",
                 sorted(json.dumps(e, sort_keys=True) for e in again["events"])
                 == sorted(json.dumps(e, sort_keys=True) for e in stored["events"]), True)
    checks.equal("detector checkpoints", again["checkpoints"], len(GROUPS))
    say(f"  emitted again {summary.get('total_emitted')} of "
        f"{stored['rows']} (only observations inside the overlap are evaluated again)")
    checks.finish("detector run 2")


# ---------------------------------------------------------------------------
# Optional stage: RCA investigation, then the existing Trace Viewer (opt in: --with-rca-viewer)
# ---------------------------------------------------------------------------

RCA_ANALYZER_DIR: str = "rca-analyzer"
VIEWER_DIR: str = "trace-viewer"
#: Added to the harness virtual environment by this stage only (the ranges of trace-viewer/requirements.txt);
#: the Viewer is exercised in-process through its own ASGI app, so no server is started and no port is opened.
VIEWER_EXTRA_REQUIREMENTS: tuple[str, ...] = ("fastapi>=0.115.0,<0.116.0", "httpx>=0.28.0,<0.29.0")
T_RCA: float = 120.0
T_VIEWER: float = 120.0
ANOMALY_ID_RE = re.compile(r"[0-9a-f]{64}")
RCA_RESULT_RE = re.compile(r"investigation_id=(\S+) confidence=(\S+) evidence=(\d+) inserted=(True|False)")
VIEWER_REPORT_PREFIX: str = "VIEWER_REPORT "

#: Run inside the harness virtual environment, in the Viewer's directory, as a short-lived process: the Viewer's
#: own FastAPI app is driven through Starlette's in-process test client (no socket, no server).  Argument order:
#: anomaly id, investigation id, an anomaly without an investigation, the trace id.  It prints one JSON line.
VIEWER_PROBE: str = r"""
import json, sys
sys.path.insert(0, ".")
from fastapi.testclient import TestClient
import app as viewer
anomaly_id, investigation_id, missing_id, trace_id = sys.argv[1:5]

def span_ids(nodes, found):
    for node in nodes:
        found.append(node["span"]["span_id"])
        span_ids(node["children"], found)
    return found

def call(client, path):
    response = client.get(path)
    try:
        body = response.json()
    except ValueError:
        body = None
    return {"status": response.status_code, "body": body}

report = {}
with TestClient(viewer.app, base_url="http://127.0.0.1:8000") as client:
    report["ready"] = call(client, "/api/health/ready")
    report["traces"] = call(client, "/api/traces?limit=1")
    report["anomalies"] = call(client, "/api/anomalies?limit=1")
    report["anomaly"] = call(client, "/api/anomalies/" + anomaly_id)
    report["anomaly_rca"] = call(client, "/api/anomalies/" + anomaly_id + "/rca")
    report["rca"] = call(client, "/api/rca/" + investigation_id)
    report["missing_rca"] = call(client, "/api/anomalies/" + missing_id + "/rca")
    detail = call(client, "/api/traces/" + trace_id)
    body = detail["body"] or {}
    report["trace"] = {"status": detail["status"], "span_count": body.get("span_count"),
                       "span_ids": span_ids(body.get("roots", []) + body.get("orphans", [])
                                            + body.get("cycle_members", []), [])}
print("%s" + json.dumps(report))
""" % VIEWER_REPORT_PREFIX


def require_disposable_database() -> None:
    """Fail closed unless every connection setting this stage will use is the disposable stack's."""
    if smoke.PROJECT != "agentops-workload-smoke" or smoke.POSTGRES_PORT != 15432:
        raise SmokeFailure("the RCA and Viewer stage is bound to agentops-workload-smoke on 127.0.0.1:15432")
    for name in ("RCA_ANALYZER_DB_PASSWORD", "TRACE_VIEWER_DB_PASSWORD"):
        if not smoke.RUN.generated.get(name):
            raise SmokeFailure(f"the generated credential {name} is missing")
    if smoke.psql("SELECT current_database()") != "agentops":
        raise SmokeFailure("the isolated database did not identify itself as 'agentops'")


def _db_environment(prefix: str, user: str) -> dict[str, str]:
    return {
        f"{prefix}_DB_HOST": "127.0.0.1",
        f"{prefix}_DB_PORT": str(smoke.POSTGRES_PORT),
        f"{prefix}_DB_NAME": "agentops",
        f"{prefix}_DB_USER": user,
        f"{prefix}_DB_PASSWORD": smoke.RUN.generated[f"{prefix}_DB_PASSWORD"],
    }


def install_viewer_dependencies() -> None:
    """The two packages the in-process Viewer probe needs that the harness's other components do not."""
    assert smoke.RUN.python is not None
    result = smoke.run(
        [str(smoke.RUN.python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
         *VIEWER_EXTRA_REQUIREMENTS],
        timeout=smoke.T_VENV, what="pip install (Trace Viewer probe)")
    smoke.write_log("pip-install-viewer.log", result.stdout + result.stderr)
    if result.returncode != 0:
        raise SmokeFailure("pip install (Trace Viewer probe): exit %d\n%s" % (
            result.returncode, smoke.redact_tail(result.stdout + result.stderr, 2000)))


def _single_value(sql: str, what: str) -> str:
    value = smoke.psql(sql)
    if not value or "\n" in value:
        raise SmokeFailure(f"{what}: expected exactly one value, got {value!r}")
    return value


def select_rca_anomaly() -> dict[str, Any]:
    """The first CRITICAL tool_failure anomaly in a fixed order (event time, then id); read-only."""
    row = smoke.psql(
        "SELECT json_build_object('anomaly_id', anomaly_id, 'trace_id', trace_id, 'span_id', span_id, "
        "'severity', severity, 'anomaly_type', anomaly_type) FROM public.anomaly_events "
        "WHERE anomaly_type = 'tool_failure' AND upper(severity) = 'CRITICAL' "
        "ORDER BY event_time, anomaly_id LIMIT 1")
    if not row:
        raise SmokeFailure("no CRITICAL tool_failure anomaly exists to investigate")
    anomaly = json.loads(row)
    if not ANOMALY_ID_RE.fullmatch(str(anomaly.get("anomaly_id"))):
        raise SmokeFailure("the selected anomaly id is not a 64-character lowercase hexadecimal value")
    if not anomaly.get("trace_id") or not anomaly.get("span_id"):
        raise SmokeFailure("the selected anomaly has no trace or span to investigate")
    return anomaly


def select_uninvestigated_anomaly(excluding: str) -> str:
    """An anomaly with no investigation (fixed order), for the Viewer's 404 check."""
    value = smoke.psql(
        "SELECT a.anomaly_id FROM public.anomaly_events a WHERE a.anomaly_id <> '%s' AND NOT EXISTS "
        "(SELECT 1 FROM public.rca_investigations r WHERE r.anomaly_id = a.anomaly_id) "
        "ORDER BY a.event_time, a.anomaly_id LIMIT 1" % excluding)
    if not ANOMALY_ID_RE.fullmatch(value):
        raise SmokeFailure("no anomaly without an investigation exists for the 404 check")
    return value


def run_rca(label: str, anomaly_id: str) -> dict[str, Any]:
    """One run of the existing rca-analyzer CLI as its own role; returns what it reported."""
    assert smoke.RUN.python is not None
    result = smoke.run(
        [str(smoke.RUN.python), "main.py", "--anomaly-id", anomaly_id],
        cwd=smoke.REPO / RCA_ANALYZER_DIR, timeout=T_RCA, what=f"rca analyzer {label}",
        env=smoke.host_environment(**_db_environment("RCA_ANALYZER", "rca_analyzer")))
    output = result.stdout + result.stderr
    smoke.write_log(f"rca-{label}.log", output)
    wrong = smoke._WRONG_STACK.search(output)
    if wrong:
        raise SmokeFailure(f"rca analyzer {label}: mentions the normal stack's port {wrong.group(1)}")
    say(f"rca analyzer {label}: exit code {result.returncode}")
    if result.returncode != 0:
        raise SmokeFailure(f"rca analyzer {label} failed:\n" + "\n".join(output.splitlines()[-12:]))
    match = RCA_RESULT_RE.search(output)
    if match is None:
        raise SmokeFailure(f"rca analyzer {label}: its result line was not found")
    return {"investigation_id": match.group(1), "evidence": int(match.group(3)),
            "inserted": match.group(4) == "True"}


def read_rca_rows(anomaly_id: str) -> dict[str, Any]:
    """The investigation and evidence rows for one anomaly, read as the owner."""
    row = smoke.psql(
        "SELECT json_build_object("
        "'investigations', (SELECT count(*) FROM public.rca_investigations WHERE anomaly_id = '%(a)s'), "
        "'investigation_id', (SELECT min(investigation_id) FROM public.rca_investigations "
        "WHERE anomaly_id = '%(a)s'), "
        "'evidence', (SELECT count(*) FROM public.rca_evidence e JOIN public.rca_investigations r "
        "ON r.investigation_id = e.investigation_id WHERE r.anomaly_id = '%(a)s'))" % {"a": anomaly_id})
    return json.loads(row)


def check_rca_rows(first: Mapping[str, Any], second: Mapping[str, Any], before: Mapping[str, Any],
                   after: Mapping[str, Any]) -> list[str]:
    """Pure.  The analyzer runs (first, second) and the row counts after each (before, after)."""
    problems: list[str] = []
    if first.get("investigation_id") != second.get("investigation_id"):
        problems.append("the two analyzer runs reported different investigation ids")
    if second.get("inserted") is not False:
        problems.append("the second analyzer run inserted an investigation (not idempotent)")
    if before.get("investigations") != 1:
        problems.append(f"expected exactly one investigation, found {before.get('investigations')}")
    if not isinstance(before.get("evidence"), int) or before["evidence"] < 1:
        problems.append("the investigation has no evidence rows")
    if before.get("investigation_id") != first.get("investigation_id"):
        problems.append("the stored investigation id differs from the one the analyzer reported")
    if dict(before) != dict(after):
        problems.append(f"the second run changed the rows: {dict(before)} -> {dict(after)}")
    return problems


def run_viewer_probe(anomaly_id: str, investigation_id: str, missing_id: str, trace_id: str) -> dict[str, Any]:
    """The Viewer's own app, in a short-lived process of the harness environment: no server, no socket."""
    assert smoke.RUN.python is not None
    result = smoke.run(
        [str(smoke.RUN.python), "-c", VIEWER_PROBE, anomaly_id, investigation_id, missing_id, trace_id],
        cwd=smoke.REPO / VIEWER_DIR, timeout=T_VIEWER, what="trace viewer probe",
        env=smoke.host_environment(**_db_environment("TRACE_VIEWER", "trace_viewer_reader")))
    output = result.stdout + result.stderr
    smoke.write_log("viewer-probe.log", output)
    wrong = smoke._WRONG_STACK.search(output)
    if wrong:
        raise SmokeFailure(f"trace viewer probe: mentions the normal stack's port {wrong.group(1)}")
    say(f"trace viewer probe: exit code {result.returncode}")
    if result.returncode != 0:
        raise SmokeFailure("trace viewer probe failed:\n" + "\n".join(output.splitlines()[-12:]))
    lines = [line for line in result.stdout.splitlines() if line.startswith(VIEWER_REPORT_PREFIX)]
    if len(lines) != 1:
        raise SmokeFailure("trace viewer probe: its report was not found")
    try:
        return json.loads(lines[0][len(VIEWER_REPORT_PREFIX):])
    except ValueError:
        raise SmokeFailure("trace viewer probe: its report is not valid JSON") from None


def check_viewer_report(report: Mapping[str, Any], *, anomaly: Mapping[str, Any], investigation_id: str,
                        evidence_rows: int, expected_traces: int, expected_anomalies: int) -> list[str]:
    """Pure.  What the Viewer returned against what the database and the analyzer said."""
    problems: list[str] = []

    def part(name: str) -> Mapping[str, Any]:
        value = report.get(name)
        return value if isinstance(value, dict) else {}

    def body(name: str) -> Mapping[str, Any]:
        value = part(name).get("body")
        return value if isinstance(value, dict) else {}

    for name, want in (("ready", 200), ("traces", 200), ("anomalies", 200), ("anomaly", 200),
                       ("anomaly_rca", 200), ("rca", 200), ("missing_rca", 404), ("trace", 200)):
        if part(name).get("status") != want:
            problems.append(f"{name}: HTTP {part(name).get('status')}, expected {want}")
    if problems:
        return problems
    if not body("ready").get("status"):
        problems.append("ready: no status in the response")
    if body("traces").get("total") != expected_traces:
        problems.append(f"traces: total {body('traces').get('total')}, expected {expected_traces}")
    if body("anomalies").get("total") != expected_anomalies:
        problems.append(f"anomalies: total {body('anomalies').get('total')}, expected {expected_anomalies} "
                        "(is this the isolated database?)")
    detail = body("anomaly")
    for key in ("anomaly_id", "trace_id", "span_id"):
        if detail.get(key) != anomaly[key]:
            problems.append(f"anomaly: {key} differs from the database")
    rca = body("anomaly_rca")
    if rca != body("rca"):
        problems.append("/api/rca/{investigation_id} does not match /api/anomalies/{anomaly_id}/rca")
    for key, want in (("investigation_id", investigation_id), ("anomaly_id", anomaly["anomaly_id"]),
                      ("trace_id", anomaly["trace_id"]), ("subject_span_id", anomaly["span_id"]),
                      ("anomaly_type", "tool_failure")):
        if rca.get(key) != want:
            problems.append(f"rca: {key} is {rca.get(key)!r}, expected {want!r}")
    if str(rca.get("severity", "")).upper() != "CRITICAL":
        problems.append("rca: the severity is not CRITICAL")
    evidence = rca.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        problems.append("rca: no evidence in the response")
        return problems
    omitted = rca.get("omitted_evidence") or 0
    if len(evidence) + omitted != evidence_rows:
        problems.append(f"rca: {len(evidence)} evidence rows (+{omitted} omitted), the database has {evidence_rows}")
    spans = {item.get("span_id") for item in evidence}
    trace = part("trace")
    trace_spans = set(trace.get("span_ids") or [])
    if not spans <= trace_spans:
        problems.append("rca: evidence refers to spans that are not in the investigated trace")
    if anomaly["span_id"] not in trace_spans:
        problems.append("trace: the anomaly's span is not in the trace")
    if anomaly["span_id"] not in spans:
        problems.append("rca: the anomaly's span is not among the evidence")
    elif not any(item.get("is_direct_subject") for item in evidence if item.get("span_id") == anomaly["span_id"]):
        problems.append("rca: the anomaly's span is not marked as the direct subject")
    return problems


def rca_and_viewer() -> None:
    """Optional stage: a fresh anomaly -> RCA (twice) -> evidence -> the Trace Viewer, on the disposable
    database only."""
    section("RCA investigation and Trace Viewer")
    require_disposable_database()
    anomaly = select_rca_anomaly()
    anomaly_id = anomaly["anomaly_id"]
    say(f"selected CRITICAL tool_failure anomaly {anomaly_id[:12]}... (trace {anomaly['trace_id'][:8]}...)")

    first = run_rca("first", anomaly_id)
    before = read_rca_rows(anomaly_id)
    second = run_rca("second", anomaly_id)
    after = read_rca_rows(anomaly_id)
    say(f"investigations {before.get('investigations')}, evidence rows {before.get('evidence')}; "
        f"second run inserted: {second['inserted']}")
    problems = check_rca_rows(first, second, before, after)
    if problems:
        raise SmokeFailure("RCA: " + "; ".join(problems))

    missing = select_uninvestigated_anomaly(anomaly_id)
    expected_traces = int(_single_value("SELECT count(*) FROM analytics.int_trace_spans", "trace count"))
    expected_anomalies = int(_single_value("SELECT count(*) FROM public.anomaly_events", "anomaly count"))
    if expected_traces != TOTAL_REQUESTS:
        raise SmokeFailure(f"the database holds {expected_traces} traces, expected {TOTAL_REQUESTS}")
    report = run_viewer_probe(anomaly_id, str(first["investigation_id"]), missing, str(anomaly["trace_id"]))
    problems = check_viewer_report(
        report, anomaly=anomaly, investigation_id=str(first["investigation_id"]),
        evidence_rows=int(before["evidence"]), expected_traces=expected_traces,
        expected_anomalies=expected_anomalies)
    if problems:
        raise SmokeFailure("Trace Viewer: " + "; ".join(problems))
    say(f"Trace Viewer: ready, {expected_traces} traces, {expected_anomalies} anomalies, RCA and evidence "
        "consistent with the database and the trace, an uninvestigated anomaly returns 404")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def configure_harness() -> None:
    """The D3 harness, unchanged on disk, with this test's values in place of
    its own: its stages, one request in flight, a longer drain allowance for
    the larger runs, and the files of this test as the allowed changes."""
    smoke.STAGES = STAGES
    smoke.CONCURRENCY = CONCURRENCY
    smoke.T_DRAIN = T_DRAIN
    smoke.ALLOWED_UNTRACKED = ALLOWED_CHANGES


#: The phrase an operator types (or pastes) to authorize one live run.  It names the disposable project and
#: the full commit, so a phrase for one commit cannot authorize a run at another.
CONFIRMATION_PREFIX: str = "AUTHORIZE-LIVE-E2E"


def confirmation_phrase(expect_head: str) -> str:
    return f"{CONFIRMATION_PREFIX} {smoke.PROJECT} {expect_head}"


def _python_supported() -> bool:
    return sys.version_info[:2] == (3, 13)


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


def plan_text(expect_head: Optional[str], with_rca_viewer: bool = False) -> str:
    """What a live run would do, and what authorizes it.  Pure: it runs, reads and creates nothing, and it holds
    no secret."""
    head = expect_head or "<full 40-character HEAD>"
    ports = f"127.0.0.1:{smoke.OTLP_PORT} (OTLP gRPC), 127.0.0.1:{smoke.KAFKA_PORT} (Kafka), " \
            f"127.0.0.1:{smoke.POSTGRES_PORT} (PostgreSQL)"
    stages = "; ".join(f"{s.run_id}: {s.traces} {s.scenario} requests ({s.spans} spans)" for s in STAGES)
    images = ", ".join(sorted(smoke.PROJECT_IMAGES))
    optional = [
        "Optional stage       --with-rca-viewer: after the anomaly detector, one CRITICAL tool_failure anomaly "
        "is investigated twice by rca-analyzer/main.py (as rca_analyzer) and the existing Trace Viewer app is "
        "exercised in-process (as trace_viewer_reader) through a short-lived process of the harness virtual "
        "environment.  fastapi and httpx are added to that environment.  No server, no extra port; the only "
        f"database is the disposable one on 127.0.0.1:{smoke.POSTGRES_PORT}; the only writes are the "
        "investigation and evidence rows.",
    ] if with_rca_viewer else []
    return "\n".join([
        "run_e2e: NOTHING WAS RUN.  This is the plan; no live step happens without every item under 'authorization'.",
        "",
        f"Compose project      {smoke.PROJECT} (disposable; never 'agentops', never an accepted or PR-02 project)",
        f"Host ports           {ports}",
        f"Docker resources     containers kafka, kafka-init, postgres, db-bootstrap, otel-collector and one "
        f"analytics-refresh run; network {smoke.PROJECT}_agentops-net; volumes {smoke.PROJECT}_kafka-data, "
        f"{smoke.PROJECT}_postgres-data",
        f"Docker engine        pinned: context {PINNED_ENGINE.context}, engine id {PINNED_ENGINE.engine_id}; "
        f"{len(PINNED_ENGINE.required_containers)} protected containers and {len(PINNED_ENGINE.required_volumes)} "
        "protected volumes must exist with their approved identities before anything is created",
        f"Images built         {images}",
        "Network downloads    pip install of the pinned workload-generator, stream-processor and storage-consumer "
        "requirements into a new virtual environment; apt and pip inside the image builds (dbt, pgvector, "
        "postgresql-client); whether the builds also contact a registry for the base images is not established",
        "Host processes       the stream processor and the storage consumer (from the new virtual environment), "
        "the workload driver and the anomaly detector",
        f"Workload stages      {stages}; {TOTAL_REQUESTS} requests and {TOTAL_SPANS} spans in all",
        "Database writes      a NEW isolated PostgreSQL volume only: the bootstrap ledger "
        f"({smoke.LEDGER_STEPS} steps), telemetry_spans rows, the dbt models, anomaly_events and detector "
        "checkpoints.  No existing database is addressed.",
        "Cleanup policy      this run's own project only: processes this run started, then one project-scoped "
        "compose down of containers, networks and volumes after every object is shown to be the project's, then "
        "the project's own images by exact reference.  Nothing is removed by comparing inventories; objects "
        "that cannot be proven the project's are left for manual review.  On Windows the temporary workspace "
        "(logs, reports, virtual environment, the environment file of test-only generated credentials) is "
        "RETAINED, listed, and never deleted recursively.",
        "Resource preflight   before anything is created: available memory at least "
        f"{smoke.GATE_MIN_AVAILABLE_MIB} MiB by WMI and by counter, free disk at least {smoke.GATE_MIN_FREE_DISK_GIB} "
        "GiB (temporary and Docker storage), committed memory below 70 %, paging file below 5 %, Pages/sec "
        "twelve one-second samples (two discarded; fail when two of the ten exceed 100), Docker engine memory at "
        "least 3.5 GiB, AC power, the three ports free, no object of the project present.  One sampling "
        "session; no repeat.",
        "",
        "authorization (all required for a live run):",
        f"  --execute --expect-head {head} --confirm \"{CONFIRMATION_PREFIX} {smoke.PROJECT} {head}\"",
        "  --approved-tree <manifest.json> --approved-tree-sha256 <64 hex>   (when the working tree is dirty)",
        "  a passing resource preflight, protected-resource snapshot and port check",
        "  --preflight (with --expect-head) runs the repository and resource checks only and starts nothing",
        "  --with-rca-viewer (needs --execute) adds the optional RCA and Trace Viewer stage",
        *optional,
    ])


def argument_problem(args: argparse.Namespace) -> Optional[str]:
    """Why these arguments cannot be used, or None.  Pure; checked before anything runs or is read."""
    if args.expect_head is not None and not smoke.FULL_COMMIT_RE.fullmatch(args.expect_head):
        return "--expect-head must be a full 40-character lowercase commit"
    if (args.approved_tree is None) != (args.approved_tree_sha256 is None):
        return "--approved-tree and --approved-tree-sha256 must be given together"
    if args.approved_tree_sha256 is not None and not smoke.SHA256_HEX_RE.fullmatch(args.approved_tree_sha256):
        return "--approved-tree-sha256 must be 64 hexadecimal characters"
    if args.execute and args.preflight:
        return "--execute and --preflight cannot be combined"
    if (args.execute or args.preflight) and args.expect_head is None:
        return "--execute and --preflight need --expect-head"
    if getattr(args, "with_rca_viewer", False) and not args.execute:
        return "--with-rca-viewer needs --execute"
    if args.execute and args.confirm != confirmation_phrase(args.expect_head):
        return "--execute needs --confirm with the exact confirmation phrase shown by the plan"
    return None


def e2e(expect_head: Optional[str], approved: Optional[smoke.ApprovedTree] = None,
        with_rca_viewer: bool = False) -> None:
    # Read-only first: the repository, then the resources.  Nothing is created, started or written before both
    # have passed.
    smoke.check_repository(expect_head, approved)
    if not (smoke.REPO / DETECTOR_CONFIG).is_file():
        raise SmokeFailure(f"missing {DETECTOR_CONFIG}")
    smoke.run_resource_gate(pin=PINNED_ENGINE)
    smoke.record_docker_state()
    smoke.record_protected_state(pin=PINNED_ENGINE)
    smoke.create_workspace_secured()
    smoke.create_virtual_environment()
    if with_rca_viewer:
        install_viewer_dependencies()
    smoke.check_render()

    section("plans")
    plans = {stage.run_id: planned_requests(stage) for stage in STAGES}
    check_plans(plans)

    smoke.start_kafka()
    smoke.create_topics()
    smoke.track_project_identities("after Kafka")
    smoke.start_postgres()
    smoke.run_bootstrap()
    smoke.track_project_identities("after the database")
    build_refresh_image()
    smoke.start_collector()
    smoke.track_project_identities("after the collector")
    smoke.start_host_services()
    offsets = smoke.check_baseline()
    for stage in STAGES:
        # A stage that does not reconcile raises; nothing after it runs.
        offsets = smoke.run_stage(stage, offsets)
        smoke.check_normal_stack(f"after {stage.run_id}")
    smoke.check_totals(offsets)

    refresh_analytics()
    smoke.track_project_identities("after the analytics refresh")
    detect_and_reconcile(plans)
    smoke.check_host_processes()
    smoke.check_normal_stack("after the detector")
    if with_rca_viewer:
        rca_and_viewer()
        smoke.check_normal_stack("after the RCA and Viewer stage")


def remove_profile_resources() -> None:
    """The refresh service belongs to a profile, which a plain `down` leaves
    out; this one includes it, so that its image is removed with the rest."""
    if not (smoke.RUN.compose_used and smoke.RUN.env_file is not None
            and smoke.RUN.env_file.is_file()):
        return
    down = smoke.run(
        refresh_command("down", "--volumes", "--rmi", "local", "--remove-orphans"),
        timeout=smoke.T_DOWN, what="compose down",
    )
    say(f"compose --profile {REFRESH_PROFILE} down --volumes --rmi local --remove-orphans: "
        f"exit {down.returncode}")


def result_lines(passed: bool, outcome: smoke.CleanupOutcome) -> list[str]:
    """The four independent parts of the result.  Pure."""
    if outcome.workspace_retained:
        workspace = f"yes, by policy ({outcome.workspace_path}): {outcome.workspace_reason}"
    elif outcome.workspace_status == "deleted":
        workspace = f"no ({outcome.workspace_reason or 'deleted'})"
    else:
        workspace = f"NO - {outcome.workspace_status}: {outcome.workspace_reason}"
    lines = [
        f"workload acceptance: {'PASSED' if passed else 'FAILED'}",
        f"docker and process cleanup verified: {'yes' if outcome.verified else 'NO'}",
        f"workspace retained: {workspace}",
        f"protected resources unchanged: {'yes' if outcome.protected_ok else 'NO'}",
    ]
    if outcome.interrupted:
        lines.append("cleanup interrupted: YES - manual review required; the remaining cleanup steps did not run")
    return lines


def exit_code(passed: bool, outcome: smoke.CleanupOutcome) -> int:
    """0 only for an accepted workload, a verified cleanup and unchanged protected resources.  A workspace
    retained by policy does not change it; a refused or failed workspace is a cleanup problem and does.  An
    interrupted cleanup is never a success and exits 130, the conventional status of an interrupt."""
    if outcome.interrupted:
        return 130
    return 0 if passed and outcome.verified and outcome.protected_ok else 1


def preflight_only(expect_head: Optional[str], approved: Optional[smoke.ApprovedTree]) -> int:
    """The repository and resource checks, and nothing else: no workspace, no Docker change, no workload."""
    try:
        smoke.check_repository(expect_head, approved)
        if not (smoke.REPO / DETECTOR_CONFIG).is_file():
            raise SmokeFailure(f"missing {DETECTOR_CONFIG}")
        smoke.run_resource_gate(pin=PINNED_ENGINE)
    except SmokeFailure as failure:
        section("FAILURE")
        say(str(failure))
        say("preflight: FAILED (nothing was started or changed)")
        return 1
    say("preflight: PASSED (nothing was started or changed)")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_e2e",
        description="Small end-to-end test of the workload generator, through to the "
                    "anomaly detector, on a disposable stack.  Without --execute it only prints its plan.",
    )
    parser.add_argument("--expect-head", default=None, metavar="COMMIT",
                        help="the full 40-character commit HEAD must equal (needed with --execute and --preflight)")
    parser.add_argument("--approved-tree", default=None, metavar="MANIFEST",
                        help="operator-approved JSON manifest of the dirty working tree (outside the repository)")
    parser.add_argument("--approved-tree-sha256", default=None, metavar="SHA256",
                        help="the SHA-256 of that manifest file, supplied by the operator")
    parser.add_argument("--preflight", action="store_true",
                        help="check the repository and the resources only; start nothing")
    parser.add_argument("--execute", action="store_true",
                        help="run the live test (needs --confirm and --expect-head)")
    parser.add_argument("--with-rca-viewer", action="store_true",
                        help="also run the optional RCA investigation and Trace Viewer stage (needs --execute)")
    parser.add_argument("--confirm", default=None, metavar="PHRASE",
                        help="the exact confirmation phrase shown by the plan")
    args = parser.parse_args(argv)
    problem = argument_problem(args)
    if problem is not None:
        parser.error(problem)
    if not (args.execute or args.preflight):
        print(plan_text(args.expect_head, True) if args.with_rca_viewer else plan_text(args.expect_head))
        return 0
    if not _python_supported():
        parser.error("run_e2e needs Python 3.13")
    _reconfigure_streams()
    configure_harness()

    approved: Optional[smoke.ApprovedTree] = None
    if args.approved_tree is not None:
        try:
            approved = smoke.load_approved_tree(args.approved_tree, args.approved_tree_sha256)
        except SmokeFailure as failure:
            say(f"the approved-tree manifest was refused: {failure}")
            say("nothing was started or changed")
            return 1
    smoke.CONTAINED.reset()
    if args.preflight:
        return preflight_only(args.expect_head, approved)

    passed = False
    try:
        if args.with_rca_viewer:
            e2e(args.expect_head, approved, with_rca_viewer=True)
        else:
            e2e(args.expect_head, approved)
        passed = True
    except SmokeFailure as failure:
        section("FAILURE")
        say(str(failure))
    except KeyboardInterrupt:
        section("FAILURE")
        say("interrupted")
    except Exception as exc:  # anything unforeseen is a failure, and is cleaned up too
        section("FAILURE")
        say(f"{type(exc).__name__}: {exc}")
    try:
        outcome = smoke.cleanup_contained(profiles=(REFRESH_PROFILE,))
    except KeyboardInterrupt:
        # cleanup_contained reports its own interruptions; this covers one that arrives outside it.  It is
        # reported and exits 130, never swallowed and never a success.
        outcome = smoke.CleanupOutcome(
            problems=["cleanup was interrupted before it could report; its state is unknown and any resource of "
                      "the project that remains is left for manual review"],
            protected_problems=["the protected resources were not re-checked because cleanup was interrupted"],
            interrupted=True)
    except Exception as exc:
        outcome = smoke.CleanupOutcome(problems=[f"cleanup could not be completed ({type(exc).__name__})"])
    for problem_text in outcome.problems:
        say(f"CLEANUP PROBLEM: {problem_text}")

    section("result")
    for line in result_lines(passed, outcome):
        say(line)
    return exit_code(passed, outcome)


if __name__ == "__main__":
    sys.exit(main())

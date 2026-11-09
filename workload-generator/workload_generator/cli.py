"""
workload_generator/cli.py

Command-line entry point of the workload generator.

Without --send the command PLANS ONLY: it builds a plan from its arguments,
prints a summary and, when asked, writes the plan report as JSON.  It
contacts nothing, imports nothing beyond the standard library, and reads no
environment variable and no configuration file.

    python -m workload_generator --scenario mixed-production --traces 100 \\
        --rate 5 --seed 42

With --send and --mode real the plan is executed through the demo agent and
its telemetry is exported to the endpoint named with --endpoint:

    python -m workload_generator --scenario api-500 --traces 20 --rate 2 \\
        --seed 42 --send --endpoint http://localhost:14317

--send is refused, and nothing is executed, when

    --mode is synthetic         synthetic execution is not implemented; the
                                command never falls back to another mode
    any OTEL_* variable is set  such variables can disable or alter the
                                telemetry of the run; their names are shown,
                                never their values
    --endpoint is missing       there is no default endpoint
    the endpoint is refused     not http://host:port, port 4317 or 4318, or
                                not on this machine without
                                --allow-remote-endpoint

Safety limits, for planning and execution alike:

    traces        at least 1; more than 10,000 needs --allow-large; never
                  more than 1,000,000 (a plan is held in memory)
    rate          more than 0, at most 10,000 requests per second
    concurrency   1 to 64
    max duration  the plan must fit in it (default 15 minutes); during
                  execution no request is started after it

Exit codes:
    0  planned; or executed exactly as planned and exported
    2  invalid arguments or a refused request (nothing was executed)
    3  execution stopped: an attempt did something the plan does not describe
    4  the spans could not all be exported
    5  the deadline was reached before every request was started

This module itself uses the standard library only.  The execution driver is
loaded only when --send is given.

Public API:
    main()
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, TextIO

from .personas import Persona
from .plan import MODES, PlanConfig, build_plan, validate_run_id
from .report import (
    SAMPLE_SIZE,
    build_report,
    format_execution,
    format_summary,
    write_report,
)
from .scenarios import Scenario

DEFAULT_MODE: str = "real"
DEFAULT_SCENARIO: str = Scenario.NORMAL.value
DEFAULT_PERSONA: str = "mix"
DEFAULT_TRACES: int = 100
DEFAULT_RATE: float = 5.0
DEFAULT_CONCURRENCY: int = 4
DEFAULT_SEED: int = 0
DEFAULT_MAX_DURATION: str = "15m"

#: Above this, --allow-large is required.
LARGE_TRACES: int = 10_000
#: Never planned in one run, with or without --allow-large: every planned
#: request is an object in memory (roughly half a kilobyte), and a plan this
#: size already takes several hundred megabytes.
ABSOLUTE_MAX_TRACES: int = 1_000_000
MAX_RATE: float = 10_000.0
MAX_CONCURRENCY: int = 64
MAX_SEED: int = 2 ** 63 - 1

_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)([smh]?)")
_DURATION_UNITS = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0}

MODE_REAL: str = "real"

EXIT_OK: int = 0
EXIT_REFUSED: int = 2

_SEND_REFUSED_SYNTHETIC = (
    "--send is not available for --mode synthetic: synthetic execution is not "
    "implemented. Nothing was sent, and the command does not fall back to "
    "another mode."
)
_SEND_REFUSED_NO_ENDPOINT = (
    "--send is not available without --endpoint: there is no default "
    "endpoint. Name the collector of an isolated stack, for example "
    "--endpoint http://localhost:14317."
)
_SEND_REFUSED_ENVIRONMENT = (
    "--send is not available while OpenTelemetry environment variables are "
    "set, because they can disable or alter the telemetry of the run. Unset: "
)
_ENDPOINT_WITHOUT_SEND = (
    "--endpoint and --allow-remote-endpoint are only used with --send; "
    "without --send nothing is sent anywhere"
)


def _parse_duration(text: str) -> float:
    """Seconds from '90', '90s', '15m' or '2h'."""
    match = _DURATION_RE.fullmatch(text.strip().lower())
    if match is None:
        raise ValueError("expected a number optionally followed by s, m or h")
    return float(match.group(1)) * _DURATION_UNITS[match.group(2)]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workload_generator",
        description=(
            "Plan a realistic workload for the AgentOps demo agent. "
            "Without --send nothing is executed and nothing is sent."
        ),
    )
    parser.add_argument(
        "--mode", choices=MODES, default=DEFAULT_MODE,
        help="how the plan is executed with --send; only real can be executed "
             "(default: real)",
    )
    parser.add_argument(
        "--scenario", choices=[scenario.value for scenario in Scenario],
        default=DEFAULT_SCENARIO, help="default: normal",
    )
    parser.add_argument(
        "--persona", choices=[DEFAULT_PERSONA, *(persona.value for persona in Persona)],
        default=DEFAULT_PERSONA, help="one traffic profile, or the default mix",
    )
    parser.add_argument(
        "--traces", type=int, default=DEFAULT_TRACES,
        help=f"requests to plan (default: {DEFAULT_TRACES})",
    )
    parser.add_argument(
        "--rate", type=float, default=DEFAULT_RATE,
        help=f"average requests per second (default: {DEFAULT_RATE:g})",
    )
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
        help=f"requests in flight at once, 1-{MAX_CONCURRENCY} "
             f"(default: {DEFAULT_CONCURRENCY}); does not change the plan",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_SEED,
        help=f"decides the planned traffic (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--run-id", default=None,
        help="decides the identifiers; random when not given, always printed",
    )
    parser.add_argument(
        "--max-duration", default=DEFAULT_MAX_DURATION,
        help="longest plan accepted, e.g. 90s, 15m, 2h (default: 15m)",
    )
    parser.add_argument(
        "--allow-large", action="store_true",
        help=f"permit planning more than {LARGE_TRACES:,} requests",
    )
    parser.add_argument(
        "--send", action="store_true",
        help="execute the plan and export its telemetry; needs --mode real "
             "and --endpoint",
    )
    parser.add_argument(
        "--endpoint", default=None, metavar="URL",
        help="with --send: the OTLP gRPC collector to export to, as "
             "http://host:port; no default; ports 4317 and 4318 are refused",
    )
    parser.add_argument(
        "--allow-remote-endpoint", action="store_true",
        help="with --send: permit an endpoint that is not on this machine",
    )
    parser.add_argument(
        "--report", default=None, metavar="PATH",
        help="also write the report as JSON to a new file",
    )
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    runner: Optional[Callable[..., Any]] = None,
) -> int:
    """
    runner replaces the production execution path (reachability check, demo
    application, OTLP exporter); it is called as
    runner(plan, endpoint=..., concurrency=..., max_duration_seconds=...)
    and returns an ExecutionReport.  It is used only with --send.
    """
    out = sys.stdout if stdout is None else stdout
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Everything that refuses execution is checked first, before any plan is
    # built and before any telemetry package is imported.
    endpoint = None
    driver = None
    if args.send:
        if args.mode != MODE_REAL:
            parser.error(_SEND_REFUSED_SYNTHETIC)
        # Loading the driver imports the standard library only.
        from . import real_driver as driver
        names = driver.otel_environment_names()
        if names:
            parser.error(_SEND_REFUSED_ENVIRONMENT + ", ".join(names))
        if args.endpoint is None:
            parser.error(_SEND_REFUSED_NO_ENDPOINT)
        try:
            endpoint = driver.parse_endpoint(
                args.endpoint, allow_remote=args.allow_remote_endpoint,
            )
        except driver.EndpointError as exc:
            parser.error(f"--endpoint: {exc}")
    elif args.endpoint is not None or args.allow_remote_endpoint:
        parser.error(_ENDPOINT_WITHOUT_SEND)

    if args.traces < 1:
        parser.error("--traces must be at least 1")
    if args.traces > ABSOLUTE_MAX_TRACES:
        parser.error(
            f"--traces must not exceed {ABSOLUTE_MAX_TRACES:,}: a plan is held in memory"
        )
    if args.traces > LARGE_TRACES and not args.allow_large:
        parser.error(
            f"--traces above {LARGE_TRACES:,} requires --allow-large"
        )
    # "not (0 < x <= limit)" also rejects nan.
    if not 0.0 < args.rate <= MAX_RATE:
        parser.error(f"--rate must be more than 0 and at most {MAX_RATE:g}")
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        parser.error(f"--concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not 0 <= args.seed <= MAX_SEED:
        parser.error("--seed must be a non-negative integer")

    try:
        max_duration = _parse_duration(args.max_duration)
    except ValueError as exc:
        parser.error(f"--max-duration: {exc}")
    if not 0.0 < max_duration < float("inf"):
        parser.error("--max-duration must be positive")

    planned_duration = (args.traces - 1) / args.rate
    if planned_duration > max_duration:
        parser.error(
            f"{args.traces} requests at {args.rate:g} per second take "
            f"{planned_duration:.0f} seconds, more than --max-duration "
            f"({max_duration:g} seconds); lower --traces, raise --rate or "
            "raise --max-duration"
        )

    run_id = args.run_id if args.run_id is not None else secrets.token_hex(6)
    try:
        validate_run_id(run_id)
    except ValueError as exc:
        parser.error(f"--run-id: {exc}")

    report_path: Optional[Path] = None
    if args.report is not None:
        report_path = Path(args.report)
        if report_path.exists():
            parser.error(f"--report: {report_path} already exists; nothing is overwritten")
        if not report_path.parent.is_dir():
            parser.error(f"--report: directory does not exist: {report_path.parent}")

    config = PlanConfig(
        seed=args.seed,
        run_id=run_id,
        scenario=Scenario(args.scenario),
        traces=args.traces,
        rate=args.rate,
        persona=None if args.persona == DEFAULT_PERSONA else Persona(args.persona),
        mode=args.mode,
    )
    plan = build_plan(config)
    report = build_report(
        plan, concurrency=args.concurrency, max_duration_seconds=max_duration,
    )

    if endpoint is None or driver is None:
        out.write(format_summary(report, plan.requests[:SAMPLE_SIZE]))
        if report_path is not None:
            write_report(report, report_path)
            out.write(f"plan report written to {report_path}\n")
        return EXIT_OK

    out.write(format_summary(report, plan.requests[:SAMPLE_SIZE], plan_only=False))
    out.flush()
    execute_plan = runner if runner is not None else driver.run_real
    try:
        execution = execute_plan(
            plan, endpoint=endpoint, concurrency=args.concurrency,
            max_duration_seconds=max_duration,
        )
    except driver.DriverError as exc:
        # Refused or not set up: nothing was executed.
        sys.stderr.write(f"{parser.prog}: error: {exc}\n")
        return EXIT_REFUSED
    out.write("\n" + format_execution(execution))
    if report_path is not None:
        write_report(report, report_path, execution)
        out.write(f"report written to {report_path}\n")
    return driver.exit_code(execution)

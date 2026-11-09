#!/usr/bin/env python3
"""
scripts/agentops_mvp_workers.py

Seeding and read-only status for the ISOLATED worker project (docker/mvp-workers/compose.yml, Compose
project "agentops-mvp-workers"), which is never the MVP stack (project "agentops-mvp").

Three commands:

    plan         print the intended sequence of steps; nothing is run
    status       read-only: the row counts of the four tables and the ids of the anomalies found so far
    seed-spans   write the spans-only dataset (agentops_mvp_demo.spans_only_sql) into the EMPTY
                 telemetry table of the isolated database.  Without --execute it only says what it
                 would do.

What it will and will not touch
  - The one container it can address is the fixed name agentops-mvp-workers-postgres-1.  No argument,
    environment variable or file can change that name, and the module refuses to load if the name, the
    project, the volume or the network ever equals one of the protected MVP names.
  - Before any query it reads the container's identity (Compose project label, dedicated data volume,
    no published port) and refuses unless all three match exactly.
  - Before writing, it reads the bootstrap ledger (exactly the 18 expected steps) and counts the rows of
    public.telemetry_spans; any row at all means nothing is written.  The script it sends also refuses
    inside its own transaction if the table is not empty.
  - It writes only public.telemetry_spans.  It never writes anomalies, investigations or evidence: the
    detector and the analyzer do that.
  - It uses no password: it reaches PostgreSQL through "docker exec ... psql" on the container's local
    socket.  It never reads a credential file, never prints the output of a command, and builds every
    command as an argument list (no shell).  It refuses to run when DOCKER_HOST is set.

Standard library plus agentops_mvp_demo.  Nothing here has been run against a real engine.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Optional, Sequence, TextIO

import agentops_mvp_demo as demo

PROJECT_NAME = "agentops-mvp-workers"
POSTGRES_CONTAINER = "agentops-mvp-workers-postgres-1"
VOLUME_NAME = "agentops-mvp-workers-postgres-data"
NETWORK_NAME = "agentops-mvp-workers-net"
DATA_DESTINATION = "/var/lib/postgresql/data"
COMPOSE_FILE = "docker/mvp-workers/compose.yml"

#: names of the running MVP stack and of the older stacks; this module must never be able to name them
PROTECTED_NAMES = ("agentops", "agentops-mvp", "agentops-mvp-postgres-1", "agentops-mvp-postgres-data",
                   "agentops-mvp_mvp-net", "agentops-postgres", "agentops-mvp-viewer-1")
if {PROJECT_NAME, POSTGRES_CONTAINER, VOLUME_NAME, NETWORK_NAME} & set(PROTECTED_NAMES):
    raise RuntimeError("the isolated project must not share a name with a protected resource")

HOURS_BACK_MIN, HOURS_BACK_MAX, HOURS_BACK_DEFAULT = 4, 20, 6
TIMEOUT_SECONDS = 120
EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2

_EXPECTED_FACTS = f"{PROJECT_NAME}|postgres|true|volume:{VOLUME_NAME}:{DATA_DESTINATION};"
_FACTS_FORMAT = (
    '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|'
    '{{.State.Running}}|{{range .Mounts}}{{.Type}}:{{.Name}}:{{.Destination}};{{end}}|{{json .HostConfig.PortBindings}}')

TELEMETRY_COUNT_SQL = "SELECT count(*) FROM public.telemetry_spans"
COUNTS_SQL = "SELECT " + " || '|' || ".join(f"(SELECT count(*) FROM public.{t})" for t in demo.TABLES)
ANOMALY_IDS_SQL = "SELECT anomaly_id FROM public.anomaly_events ORDER BY event_time, anomaly_id"
_FIXED_READS = frozenset({TELEMETRY_COUNT_SQL, COUNTS_SQL, ANOMALY_IDS_SQL, demo.LEDGER_SQL})


class WorkersError(Exception):
    """A refusal or failure with a fixed message; never carries command output."""

    def __init__(self, message: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""


Runner = Callable[[Sequence[str], Mapping[str, str], bytes], CommandResult]

PLAN = f"""\
Isolated worker project {PROJECT_NAME}: intended sequence (NOTHING IS RUN BY THIS COMMAND)
  0. a credentials file of this project, not the MVP's (scripts/agentops_mvp.py init-credentials --credentials-file <path>)
  1. docker compose -p {PROJECT_NAME} -f {COMPOSE_FILE} --env-file <file> up -d --build postgres db-bootstrap
  2. agentops_mvp_workers.py status                 read-only: the bootstrapped database is empty
  3. agentops_mvp_workers.py seed-spans --execute   the spans-only dataset into public.telemetry_spans
  4. docker compose -p {PROJECT_NAME} -f {COMPOSE_FILE} --env-file <file> run --rm --no-deps anomaly-detector
  5. agentops_mvp_workers.py status                 the anomaly ids the detector wrote
  6. docker compose -p {PROJECT_NAME} -f {COMPOSE_FILE} --env-file <file> run --rm --no-deps rca-analyzer --anomaly-id <id>
  7. agentops_mvp_workers.py status                 the investigation and its evidence
The running {PROTECTED_NAMES[1]} stack is never named, started, stopped or written by any step.
"""


# ---------------------------------------------------------------------------
# Command builders (pure)
# ---------------------------------------------------------------------------

def container_facts_argv(docker: str) -> list[str]:
    return [docker, "inspect", "--type", "container", "--format", _FACTS_FORMAT, POSTGRES_CONTAINER]


def psql_read_argv(docker: str, sql: str) -> list[str]:
    if sql not in _FIXED_READS:
        raise WorkersError("that query is not one of the fixed queries", EXIT_USAGE)
    return [docker, "exec", "-e", "PGOPTIONS=-cdefault_transaction_read_only=on", POSTGRES_CONTAINER,
            "psql", "-U", "agentops", "-d", "agentops", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql]


def psql_write_argv(docker: str) -> list[str]:
    """The script arrives on standard input; one transaction; stop at the first error."""
    return [docker, "exec", "-i", POSTGRES_CONTAINER,
            "psql", "-U", "agentops", "-d", "agentops", "-X", "-q", "--single-transaction",
            "-v", "ON_ERROR_STOP=1", "-f", "-"]


def hours_back(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not HOURS_BACK_MIN <= value <= HOURS_BACK_MAX:
        raise WorkersError(f"--hours-back must be a whole number from {HOURS_BACK_MIN} to {HOURS_BACK_MAX}", EXIT_USAGE)
    return value


def base_time_for(now: datetime, back_hours: int) -> datetime:
    """The start of the dataset: back_hours before now, so that it ends before now and, within the
    detector's 24 hour first-run lookback, is all candidate data."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise WorkersError("the clock must be timezone-aware", EXIT_USAGE)
    return now.astimezone(timezone.utc) - timedelta(hours=hours_back(back_hours))


# ---------------------------------------------------------------------------
# Execution (every call goes through the injected runner)
# ---------------------------------------------------------------------------

def _query(run: Runner, argv: Sequence[str], env: Mapping[str, str], what: str) -> str:
    try:
        result = run(argv, env, b"")
    except Exception:  # noqa: BLE001 - type only, never the output
        raise WorkersError(f"{what} could not be read") from None
    if result.returncode != 0:
        raise WorkersError(f"{what} could not be read")
    return result.stdout.decode("utf-8", "replace")


def verify_target(run: Runner, docker: str, env: Mapping[str, str]) -> None:
    """Refuse unless the container is the isolated project's database: its label, its data volume, no ports."""
    facts = _query(run, container_facts_argv(docker), env, "the database container's identity").strip()
    head, _, ports = facts.rpartition("|")
    if head != _EXPECTED_FACTS or ports.strip() not in ("{}", "null"):
        raise WorkersError("the database container is not the isolated worker project's database "
                           "(project label, dedicated data volume or published ports differ)")
    try:
        ledger = demo.parse_ledger(_query(run, psql_read_argv(docker, demo.LEDGER_SQL), env, "the bootstrap ledger"))
    except ValueError:
        raise WorkersError("the bootstrap ledger could not be read") from None
    if not demo.ledger_matches(ledger):
        raise WorkersError(f"the bootstrap ledger is not the expected {len(demo.EXPECTED_LEDGER_STEPS)} steps "
                           f"({len(ledger)} rows found)")


def _spans_count(run: Runner, docker: str, env: Mapping[str, str]) -> int:
    text = _query(run, psql_read_argv(docker, TELEMETRY_COUNT_SQL), env, "the telemetry row count").strip()
    if not text.isdigit():
        raise WorkersError("the telemetry row count could not be read")
    return int(text)


def status(run: Runner, docker: str, env: Mapping[str, str]) -> str:
    verify_target(run, docker, env)
    counts = demo.parse_counts(_query(run, psql_read_argv(docker, COUNTS_SQL), env, "the table row counts"))
    if counts is None:
        raise WorkersError("the table row counts could not be read")
    ids = [line.strip() for line in _query(run, psql_read_argv(docker, ANOMALY_IDS_SQL), env, "the anomaly ids").splitlines()
           if line.strip()]
    if not all(len(i) == 64 and all(c in "0123456789abcdef" for c in i) for i in ids):
        raise WorkersError("the anomaly ids could not be read")
    lines = [f"project {PROJECT_NAME}: " + ", ".join(f"{t} {counts[t]}" for t in demo.TABLES)]
    lines += [f"  anomaly {i}" for i in ids] or ["  no anomalies yet"]
    lines.append("  read only; nothing was changed")
    return "\n".join(lines)


def seed_spans(run: Runner, seed_run: Runner, docker: str, env: Mapping[str, str], base_time: datetime,
               execute: bool) -> str:
    verify_target(run, docker, env)
    found = _spans_count(run, docker, env)
    if found:
        raise WorkersError(f"not seeding: public.telemetry_spans already holds {found} rows; nothing was changed")
    expected = demo.spans_only_expected_count()
    first, last = demo.spans_only_extent(base_time)
    summary = (f"{expected} spans, {first.isoformat()} to {last.isoformat()}, label {demo.SPANS_ONLY_LABEL}, "
               "public.telemetry_spans only")
    if not execute:
        return f"dry run: would write {summary}\n  nothing was written (add --execute)"
    script = demo.spans_only_sql(base_time).encode("utf-8")
    try:
        result = seed_run(psql_write_argv(docker), env, script)
    except Exception:  # noqa: BLE001
        raise WorkersError("the seed failed or timed out; the transaction was not committed, or its result is unknown; "
                           "run status") from None
    if result.returncode != 0:
        raise WorkersError("the seed failed; the single transaction was rolled back; nothing was cleaned up")
    after = _spans_count(run, docker, env)
    if after != expected:
        raise WorkersError(f"the seed finished but public.telemetry_spans holds {after} rows, not {expected}")
    return f"wrote {summary}\n  verified: {after} rows; no anomaly, investigation or evidence row was written"


# ---------------------------------------------------------------------------
# Process plumbing
# ---------------------------------------------------------------------------

_ENV_KEYS = ("PATH", "SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA")


def child_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """A small environment for the container tool: no DOCKER_*, COMPOSE_* or credential names are passed on."""
    return {k: environ[k] for k in _ENV_KEYS if k in environ}


def default_runner(argv: Sequence[str], env: Mapping[str, str], input_bytes: bytes) -> CommandResult:
    completed = subprocess.run(list(argv), input=input_bytes or None, env=dict(env), capture_output=True,
                               timeout=TIMEOUT_SECONDS, check=False, shell=False)
    return CommandResult(completed.returncode, completed.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentops_mvp_workers.py",
                                     description="Seeding and read-only status for the isolated worker project.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print the intended sequence; runs nothing")
    sub.add_parser("status", help="read-only counts and anomaly ids of the isolated database")
    seed = sub.add_parser("seed-spans", help="write the spans-only dataset into the empty telemetry table")
    seed.add_argument("--hours-back", type=int, default=HOURS_BACK_DEFAULT, metavar="N",
                      help=f"start the dataset N hours before now ({HOURS_BACK_MIN} to {HOURS_BACK_MAX}, "
                           f"default {HOURS_BACK_DEFAULT})")
    seed.add_argument("--execute", action="store_true", help="really write; without it only a dry run")
    return parser


def main(argv: Optional[Sequence[str]] = None, *, environ: Optional[Mapping[str, str]] = None,
         run: Optional[Runner] = None, seed_run: Optional[Runner] = None,
         now: Optional[Callable[[], datetime]] = None, docker: Optional[str] = None,
         out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    environ = os.environ if environ is None else environ
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exit_:
        return int(exit_.code or 0) if exit_.code in (0, None) else EXIT_USAGE
    if args.command == "plan":
        print(PLAN, file=out, end="")
        return EXIT_OK
    try:
        if "DOCKER_HOST" in environ:
            raise WorkersError("DOCKER_HOST is set; refusing to use a possibly remote engine", EXIT_USAGE)
        tool = docker if docker is not None else shutil.which("docker")
        if not tool:
            raise WorkersError("the container command-line tool was not found")
        env = child_environment(environ)
        runner = run or default_runner
        if args.command == "status":
            print(status(runner, tool, env), file=out)
        else:
            base = base_time_for((now or (lambda: datetime.now(timezone.utc)))(), args.hours_back)
            print(seed_spans(runner, seed_run or runner, tool, env, base, args.execute), file=out)
        return EXIT_OK
    except WorkersError as error:
        print(f"error: {error}", file=err)
        return error.exit_code
    except Exception as error:  # noqa: BLE001
        print(f"error: internal ({type(error).__name__})", file=err)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())

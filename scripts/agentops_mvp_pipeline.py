#!/usr/bin/env python3
"""
scripts/agentops_mvp_pipeline.py

Host-side runner that connects the existing anomaly detector to the existing RCA analyzer.  It orchestrates
only: it changes no worker, no migration, no database role and no existing script.

TARGETS.  The runner works on one of exactly two fixed targets (a closed registry; no project, compose file,
container, volume or network name can be supplied by a user):

    accepted   the accepted Phase 14.7 MVP (Compose project agentops-mvp-workers).  PROTECTED: it can be
               checked with a dry run, and --execute is permanently refused for it.
    pipetest   a disposable validation environment (Compose project agentops-pipetest,
               docker/mvp-workers-pipetest/compose.yml).  The only target --execute can ever run on.

Commands

    plan                  print the intended sequence; nothing is run
    run                   DRY RUN (the default): read-only checks of the target, then a report of what a
                          run would do.  No worker container is started and no lock is taken.
    run --execute         the real workflow, pipetest only (it needs a separate, explicit authorization to
                          be used):

        1. refuse unless the target passes the identity checks and no one-off worker container is running
        2. take an exclusive host lock, then check for one-off worker containers again
        3. run the anomaly detector once (exit 0 is the only success; anything else stops the run
           before RCA)
        4. discover the anomalies that have no RCA investigation (one fixed read-only query)
        5. run the RCA analyzer once per pending anomaly, one after the other
        6. read the pending set again and report anything that does not add up

    Options: --target {accepted,pipetest} (default accepted), --credentials-file PATH (required),
    --execute, --max-anomalies N (default 25, 1 to 100).

What it will and will not do
  - Every command is an argument list; nothing goes through a shell.  Nothing is retried.
  - The credentials file is never opened, read or printed.  Its path is checked (outside the repository,
    not a link, not the MVP's own file; for pipetest it must sit under a directory named agentops-pipetest)
    and handed to Docker Compose only as --env-file.
  - A target passes verification only by EXACT equality with its registry entry (Compose project and service
    labels, ownership label, container name, volume and mount destination, network, no extra mount, not
    privileged, no published port, volume and network labels, the 18-step ledger).  A name that merely
    contains "pipetest" passes nothing.
  - Database reads go through "docker exec ... psql" on the target's container, over its local socket, with a
    read-only session default, and only the fixed queries below.  The runner writes nothing to the database.
  - A timeout or an interrupt never removes, stops or restarts a container.  A worker container that
    outlived its client is found by the next run's check and that run refuses to start.
  - Messages come from a fixed vocabulary.  Command output, passwords and the credentials path are never
    printed.

Exit codes
    0    success (nothing left to do or everything processed and verified)
    1    internal error or a final check that could not be read
    2    usage error or a safety refusal (target, credentials location, detector configuration, --execute
         on the accepted target)
    3    the detector stage did not succeed (RCA was not run)
    4    the RCA stage did not complete cleanly (failures, a stop, or a result that did not add up)
    5    another run holds the lock, or a one-off worker container is running
    130  interrupted

Standard library plus agentops_mvp, agentops_mvp_demo, agentops_mvp_lifecycle and agentops_mvp_workers.
Nothing here has been run against a real engine.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Optional, Sequence, TextIO

import agentops_mvp as creds
import agentops_mvp_demo as demo
import agentops_mvp_lifecycle as lifecycle
import agentops_mvp_workers as workers

# ---------------------------------------------------------------------------
# Targets: a closed registry
# ---------------------------------------------------------------------------

DETECTOR_SERVICE = "anomaly-detector"
RCA_SERVICE = "rca-analyzer"
DATA_DESTINATION = workers.DATA_DESTINATION

#: Label every resource of the disposable environment carries; a resource without it is not that environment.
PIPETEST_LABEL = "agentops.pipetest"


@dataclass(frozen=True)
class Target:
    key: str
    project: str
    compose_file: str
    postgres_container: str
    volume: str
    network: str
    ownership_label: str              # label key (container, volume and network) that proves ownership
    executable: bool                  # may --execute ever run on it?
    credentials_parent: Optional[str]  # required name of the directory above "agentops-mvp/", or None


_ACCEPTED = Target(
    key="accepted", project=workers.PROJECT_NAME, compose_file=workers.COMPOSE_FILE,
    postgres_container=workers.POSTGRES_CONTAINER, volume=workers.VOLUME_NAME, network=workers.NETWORK_NAME,
    ownership_label="agentops.mvp-workers", executable=False, credentials_parent=None)

_PIPETEST = Target(
    key="pipetest", project="agentops-pipetest", compose_file="docker/mvp-workers-pipetest/compose.yml",
    postgres_container="agentops-pipetest-postgres-1", volume="agentops-pipetest-pgdata",
    network="agentops-pipetest-net", ownership_label=PIPETEST_LABEL, executable=True,
    credentials_parent="agentops-pipetest")

#: The only targets.  Read-only mapping; the command line can only choose a key of it.
TARGETS: Mapping[str, Target] = MappingProxyType({_ACCEPTED.key: _ACCEPTED, _PIPETEST.key: _PIPETEST})
DEFAULT_TARGET = _ACCEPTED.key


def _check_registry() -> None:
    """Import-time proof that the registry cannot name a protected resource or let two targets overlap."""
    protected = set(workers.PROTECTED_NAMES)
    seen: dict[str, str] = {}
    for target in TARGETS.values():
        names = (target.project, target.postgres_container, target.volume, target.network)
        if target.key != "accepted" and set(names) & protected:
            raise RuntimeError("a disposable target must not share a name with a protected resource")
        for name in names:
            if name in seen and seen[name] != target.key:
                raise RuntimeError("two targets share a name")
            seen[name] = target.key
    if TARGETS["accepted"].executable or not TARGETS["pipetest"].executable:
        raise RuntimeError("only the disposable target may be executable")
    for other in ("agentops-mvp-workers", "agentops-mvp-workers-postgres-1", "agentops-mvp-workers-postgres-data",
                  "agentops-mvp-workers-net"):
        if other in (_PIPETEST.project, _PIPETEST.postgres_container, _PIPETEST.volume, _PIPETEST.network):
            raise RuntimeError("the disposable target names an accepted resource")


_check_registry()

# ---------------------------------------------------------------------------
# Fixed vocabulary
# ---------------------------------------------------------------------------

#: Signals whose detector queries read analytics VIEWS (always current).  The others read dbt mart TABLES
#: that only an analytics refresh rebuilds; this runner does not refresh, so it refuses them.  Both targets
#: use the worker images' own baked copy of docker/mvp-workers/detector_config.json.
VIEW_SIGNALS = frozenset({"tool_latency", "error_rate", "tool_failure"})
MART_SIGNALS = frozenset({"trace_latency", "agent_latency", "retrieval"})
DETECTOR_CONFIG = "docker/mvp-workers/detector_config.json"

LOCK_NAME = "pipeline.lock"

DEFAULT_MAX_ANOMALIES = 25
MAX_ANOMALIES_LIMIT = 100
DIAGNOSTIC_LIMIT = 25
MAX_CONSECUTIVE_RCA_FAILURES = 3

READ_TIMEOUT_SECONDS = 60.0
DETECTOR_TIMEOUT_SECONDS = 900.0
RCA_TIMEOUT_SECONDS = 300.0

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_DETECTOR = 3
EXIT_RCA = 4
EXIT_BUSY = 5
EXIT_INTERRUPTED = 130

_ID_RE = re.compile(r"[0-9a-f]{64}")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}")

DETECTOR_MESSAGES = {
    1: "failed or uncertain (a group failed or its commit outcome is unknown)",
    2: "ended early",
    3: "configuration error",
    4: "database startup failure",
    130: "interrupted",
}
RCA_MESSAGES = {
    1: "anomaly not found or unexpected error",
    2: "source data integrity error",
    3: "configuration error",
    4: "database error",
    130: "interrupted",
}
#: Exit codes of the RCA analyzer that say the problem is not about one anomaly: stop the whole stage.
RCA_SYSTEMIC_CODES = frozenset({3, 4})

# ---------------------------------------------------------------------------
# Fixed read-only queries
# ---------------------------------------------------------------------------


def pending_sql(limit: int) -> str:
    """Anomalies that have no RCA investigation of any analyzer version, oldest first.  The only value
    placed into the text is a bounded whole number."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ANOMALIES_LIMIT:
        raise PipelineError(f"--max-anomalies must be a whole number from 1 to {MAX_ANOMALIES_LIMIT}", EXIT_USAGE)
    return ("SELECT a.anomaly_id FROM public.anomaly_events AS a "
            "WHERE NOT EXISTS (SELECT 1 FROM public.rca_investigations AS i WHERE i.anomaly_id = a.anomaly_id) "
            f"ORDER BY a.event_time, a.anomaly_id LIMIT {limit}")


#: Report only: investigations that should have evidence and have none.  Never triggers an action.
NO_EVIDENCE_SQL = ("SELECT i.anomaly_id FROM public.rca_investigations AS i "
                   "WHERE i.confidence <> 'INSUFFICIENT_DATA' "
                   "AND NOT EXISTS (SELECT 1 FROM public.rca_evidence AS e WHERE e.investigation_id = i.investigation_id) "
                   f"ORDER BY i.investigated_at, i.anomaly_id LIMIT {DIAGNOSTIC_LIMIT}")

ALLOWED_READS = frozenset({pending_sql(n) for n in range(1, MAX_ANOMALIES_LIMIT + 1)}
                          | {NO_EVIDENCE_SQL, demo.LEDGER_SQL})


class PipelineError(Exception):
    """A refusal or failure with a fixed message; never carries command output or a secret."""

    def __init__(self, message: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class StageTimeout(Exception):
    """A command did not finish in time.  Whatever it started may still be running."""


#: Runs one command and returns its result.  Signature: (argv, env, timeout_seconds).
Runner = Callable[[Sequence[str], Mapping[str, str], float], workers.CommandResult]

PLAN = f"""\
Pipeline for a fixed target (NOTHING IS RUN BY THIS COMMAND)
  targets  accepted  {_ACCEPTED.project}: protected; dry run only, --execute is always refused
           pipetest  {_PIPETEST.project}: the disposable environment, {_PIPETEST.compose_file}
  checks   the target passes the exact identity checks (container, labels, volume and mount, network,
           no published port, the 18-step bootstrap ledger) and no one-off worker container is running
  lock     (--execute only) an exclusive host lock next to the credentials file, then the check again
  1. docker compose -p <project> -f <compose file> --env-file <file> run --rm -T --no-deps {DETECTOR_SERVICE}
           exit 0 is the only success; anything else stops the run before RCA
  2. one read-only query: anomalies with no RCA investigation (oldest first, at most --max-anomalies)
  3. docker compose -p <project> -f <compose file> --env-file <file> run --rm -T --no-deps {RCA_SERVICE} --anomaly-id <id>
           once per pending anomaly, one after the other; no retries
  4. the pending query again, and a report of anything that does not add up
Without --execute, 'run' stops after the checks and the first read and starts no worker.
Not done: analytics refresh (detector signals must be view-based), alerting, scheduling, retries.
"""


# ---------------------------------------------------------------------------
# Command construction (pure)
# ---------------------------------------------------------------------------

def compose_run_argv(docker: str, repo_root: Path, credentials: str, service: str, target: Target,
                     extra: Sequence[str] = ()) -> list[str]:
    if service not in (DETECTOR_SERVICE, RCA_SERVICE):
        raise PipelineError("that service is not one of the two workers", EXIT_USAGE)
    _require_registered(target)
    return [docker, "compose", "-p", target.project, "-f", str(Path(repo_root) / target.compose_file),
            "--env-file", credentials, "run", "--rm", "-T", "--no-deps", service, *extra]


def rca_argv(docker: str, repo_root: Path, credentials: str, anomaly_id: str, target: Target) -> list[str]:
    if not _ID_RE.fullmatch(anomaly_id):
        raise PipelineError("an anomaly id is not 64 lowercase hexadecimal characters", EXIT_FAILED)
    return compose_run_argv(docker, repo_root, credentials, RCA_SERVICE, target, ["--anomaly-id", anomaly_id])


def read_argv(docker: str, sql: str, target: Target) -> list[str]:
    if sql not in ALLOWED_READS:
        raise PipelineError("that query is not one of the fixed queries", EXIT_USAGE)
    _require_registered(target)
    return [docker, "exec", "-e", "PGOPTIONS=-cdefault_transaction_read_only=on", target.postgres_container,
            "psql", "-U", "agentops", "-d", "agentops", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql]


def workers_ps_argv(docker: str, target: Target) -> list[str]:
    """Running one-off containers of the target's project (any worker run, ours or a hand-started one)."""
    _require_registered(target)
    return [docker, "ps", "--quiet", "--no-trunc",
            "--filter", f"label=com.docker.compose.project={target.project}",
            "--filter", "label=com.docker.compose.oneoff=True"]


def _require_registered(target: Target) -> None:
    """A Target value that is not the registry's own entry is never used to build a command."""
    if TARGETS.get(getattr(target, "key", None)) is not target:
        raise PipelineError("that target is not one of the fixed targets", EXIT_USAGE)


# --- the disposable target's identity probes (read-only inspections) ---

_FACTS_PARTS = (
    "{{.Name}}", '{{index .Config.Labels "com.docker.compose.project"}}',
    '{{index .Config.Labels "com.docker.compose.service"}}', '{{index .Config.Labels "%s"}}',
    "{{.State.Running}}", "{{.HostConfig.Privileged}}",
    "{{range .Mounts}}{{.Type}}:{{.Name}}:{{.Destination}};{{end}}",
    "{{range $k, $v := .NetworkSettings.Networks}}{{$k}};{{end}}", "{{json .HostConfig.PortBindings}}")


def container_probe_argv(docker: str, target: Target) -> list[str]:
    _require_registered(target)
    fmt = "|".join(_FACTS_PARTS) % target.ownership_label
    return [docker, "inspect", "--type", "container", "--format", fmt, target.postgres_container]


def expected_container_facts(target: Target) -> str:
    """What the probe must print, in full, for the target's PostgreSQL container (ports are checked apart)."""
    return (f"/{target.postgres_container}|{target.project}|postgres|true|true|false|"
            f"volume:{target.volume}:{DATA_DESTINATION};|{target.network};")


def volume_probe_argv(docker: str, target: Target) -> list[str]:
    _require_registered(target)
    fmt = '{{.Name}}|{{index .Labels "%s"}}|{{.Driver}}|{{json .Options}}' % target.ownership_label
    return [docker, "volume", "inspect", "--format", fmt, target.volume]


def expected_volume_facts(target: Target) -> tuple[str, ...]:
    return (f"{target.volume}|true|local|null", f"{target.volume}|true|local|{{}}")


def network_probe_argv(docker: str, target: Target) -> list[str]:
    _require_registered(target)
    fmt = '{{.Name}}|{{index .Labels "%s"}}|{{.Driver}}|{{.Internal}}' % target.ownership_label
    return [docker, "network", "inspect", "--format", fmt, target.network]


def expected_network_facts(target: Target) -> str:
    return f"{target.network}|true|bridge|false"


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def check_credentials_path(path: str, environ: Mapping[str, str], repo_root: Path, platform_name: str,
                           home: str, target: Target) -> str:
    """Refuse an unsafe credentials location; return the absolute path.  The file is not opened."""
    try:
        absolute = creds.check_location(path, repo_root, environ)
        mvp_default = creds.default_credentials_path(environ, platform_name, home)
    except creds.CredentialError as error:
        raise PipelineError(str(error), EXIT_USAGE) from None
    if os.path.normcase(os.path.realpath(absolute)) == os.path.normcase(os.path.realpath(mvp_default)):
        raise PipelineError("the credentials file is the MVP's own; use the isolated project's file", EXIT_USAGE)
    if target.credentials_parent is not None:
        # <parent>/agentops-mvp/credentials.env: the file has to be made for this target, in its own tree
        parent = os.path.basename(os.path.dirname(os.path.dirname(absolute)))
        if parent != target.credentials_parent:
            raise PipelineError(f"the credentials file for the {target.key} target must be under a directory "
                                f"named {target.credentials_parent}", EXIT_USAGE)
    return absolute


def check_detector_config(text: str) -> None:
    """Refuse a detector configuration that needs an analytics refresh (or that is not understood)."""
    try:
        data = json.loads(text)
    except ValueError:
        raise PipelineError("the detector configuration is not valid JSON", EXIT_USAGE) from None
    groups = data.get("groups") if isinstance(data, dict) else None
    if not isinstance(groups, list) or not groups:
        raise PipelineError("the detector configuration has no groups", EXIT_USAGE)
    for group in groups:
        signal = group.get("signal_path") if isinstance(group, dict) else None
        if signal in MART_SIGNALS:
            raise PipelineError("the detector configuration uses a signal that needs an analytics refresh, "
                                "which this runner does not run", EXIT_USAGE)
        if signal not in VIEW_SIGNALS:
            raise PipelineError("the detector configuration names an unknown signal", EXIT_USAGE)


def _reader(run: Runner) -> Callable[[Sequence[str], Mapping[str, str], bytes], workers.CommandResult]:
    """Adapt a runner to the three-argument form the existing target check calls."""
    return lambda argv, env, _input: run(argv, env, READ_TIMEOUT_SECONDS)


def _inspect_text(run: Runner, argv: Sequence[str], env: Mapping[str, str], what: str) -> str:
    try:
        result = run(argv, env, READ_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001 - any failure to read an identity is a refusal, like the accepted target's
        raise PipelineError(f"{what} could not be read", EXIT_USAGE) from None
    if result.returncode != 0:
        raise PipelineError(f"{what} could not be read", EXIT_USAGE)
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise PipelineError(f"{what} could not be read", EXIT_USAGE) from None


def _verify_disposable(run: Runner, docker: str, env: Mapping[str, str], target: Target) -> None:
    """Exact-equality identity checks for the disposable target.  No check looks at a substring."""
    facts = _inspect_text(run, container_probe_argv(docker, target), env, "the database container's identity")
    head, _, ports = facts.rpartition("|")
    if head != expected_container_facts(target) or ports.strip() not in ("{}", "null"):
        raise PipelineError(f"the database container is not the {target.key} target (project, service, ownership "
                            "label, state, privileges, mounts, network or published ports differ)", EXIT_USAGE)
    volume = _inspect_text(run, volume_probe_argv(docker, target), env, "the data volume's identity")
    if volume not in expected_volume_facts(target):
        raise PipelineError(f"the data volume is not the {target.key} target's (name, ownership label, driver or "
                            "options differ)", EXIT_USAGE)
    network = _inspect_text(run, network_probe_argv(docker, target), env, "the network's identity")
    if network != expected_network_facts(target):
        raise PipelineError(f"the network is not the {target.key} target's (name, ownership label or driver "
                            "differ)", EXIT_USAGE)
    ledger_text = _inspect_text(run, read_argv(docker, demo.LEDGER_SQL, target), env, "the bootstrap ledger")
    try:
        ledger = demo.parse_ledger(ledger_text)
    except ValueError:
        raise PipelineError("the bootstrap ledger could not be read", EXIT_USAGE) from None
    if not demo.ledger_matches(ledger):
        raise PipelineError(f"the bootstrap ledger is not the expected {len(demo.EXPECTED_LEDGER_STEPS)} steps",
                            EXIT_USAGE)


def verify_target(run: Runner, docker: str, env: Mapping[str, str], target: Target) -> None:
    """The target's identity check.  The accepted target keeps the existing check, unchanged."""
    _require_registered(target)
    if target.key == "accepted":
        try:
            workers.verify_target(_reader(run), docker, env)
        except workers.WorkersError as error:
            raise PipelineError(str(error), EXIT_USAGE) from None
        return
    _verify_disposable(run, docker, env, target)


def require_no_workers(run: Runner, docker: str, env: Mapping[str, str], target: Target) -> None:
    try:
        result = run(workers_ps_argv(docker, target), env, READ_TIMEOUT_SECONDS)
    except (StageTimeout, OSError):
        raise PipelineError("the running worker containers could not be checked", EXIT_USAGE) from None
    if result.returncode != 0:
        raise PipelineError("the running worker containers could not be checked", EXIT_USAGE)
    try:
        lines = [line.strip() for line in result.stdout.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError:
        raise PipelineError("the running worker containers could not be checked", EXIT_USAGE) from None
    if not all(_CONTAINER_ID_RE.fullmatch(line) for line in lines):
        raise PipelineError("the running worker containers could not be checked", EXIT_USAGE)
    if lines:
        raise PipelineError(f"a one-off worker container of the {target.key} target is running", EXIT_BUSY)


def read_ids(run: Runner, docker: str, env: Mapping[str, str], sql: str, limit: int, what: str,
             target: Target) -> list[str]:
    """Run one fixed read-only query that returns anomaly ids, one per line; validate every one."""
    try:
        result = run(read_argv(docker, sql, target), env, READ_TIMEOUT_SECONDS)
    except (StageTimeout, OSError):
        raise PipelineError(f"{what} could not be read", EXIT_FAILED) from None
    if result.returncode != 0:
        raise PipelineError(f"{what} could not be read", EXIT_FAILED)
    try:
        ids = [line.strip() for line in result.stdout.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError:
        raise PipelineError(f"{what} could not be read", EXIT_FAILED) from None
    if len(ids) > limit or len(set(ids)) != len(ids) or not all(_ID_RE.fullmatch(i) for i in ids):
        raise PipelineError(f"{what} could not be read", EXIT_FAILED)
    return ids


# ---------------------------------------------------------------------------
# Running a worker
# ---------------------------------------------------------------------------

def default_runner(argv: Sequence[str], env: Mapping[str, str], timeout: float) -> workers.CommandResult:
    """The only place that starts a process.  No shell, no input; the output is kept and never printed."""
    try:
        completed = subprocess.run(list(argv), env=dict(env), stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired:
        raise StageTimeout from None
    return workers.CommandResult(completed.returncode, completed.stdout)


def run_worker(run: Runner, argv: Sequence[str], env: Mapping[str, str],
               timeout: float) -> tuple[Optional[int], Optional[str]]:
    """(exit code, None) or (None, "timeout" | "launch").  Never retries and never cleans up."""
    try:
        return run(argv, env, timeout).returncode, None
    except StageTimeout:
        return None, "timeout"
    except OSError:
        return None, "launch"


@dataclass
class Progress:
    target: str = ""
    detector: str = "not run"
    pending_at_start: Optional[int] = None
    investigated: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    not_attempted: int = 0
    stopped: Optional[str] = None
    remaining: Optional[list[str]] = None
    inconsistent: list[str] = field(default_factory=list)
    no_evidence: Optional[int] = None
    note: list[str] = field(default_factory=list)


def _summary(progress: Progress) -> str:
    lines = [f"pipeline summary (target {progress.target})", f"  detector: {progress.detector}"]
    if progress.pending_at_start is not None:
        lines.append(f"  pending at start of the RCA stage: {progress.pending_at_start}")
    lines.append(f"  investigated: {len(progress.investigated)}")
    lines += [f"    {i}" for i in progress.investigated]
    lines.append(f"  failed: {len(progress.failed)}")
    lines += [f"    {i}: {reason}" for i, reason in progress.failed]
    if progress.not_attempted:
        lines.append(f"  not attempted: {progress.not_attempted}")
    if progress.stopped:
        lines.append(f"  stopped: {progress.stopped}")
    if progress.remaining is not None:
        lines.append(f"  still pending after the run (at most the limit is read): {len(progress.remaining)}")
    if progress.inconsistent:
        lines.append(f"  INCONSISTENT (exit 0 but still pending): {len(progress.inconsistent)}")
        lines += [f"    {i}" for i in progress.inconsistent]
    if progress.no_evidence is not None:
        lines.append(f"  investigations without evidence that are not INSUFFICIENT_DATA: {progress.no_evidence}")
    lines += [f"  note: {n}" for n in progress.note]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The workflow
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Context:
    run: Runner
    docker: str
    env: Mapping[str, str]
    repo_root: Path
    credentials: str
    max_anomalies: int
    target: Target
    detector_timeout: float = DETECTOR_TIMEOUT_SECONDS
    rca_timeout: float = RCA_TIMEOUT_SECONDS


def refuse_if_not_executable(target: Target) -> None:
    _require_registered(target)
    if not target.executable:
        raise PipelineError("the accepted MVP is protected and can never be the target of --execute; "
                            "use --target pipetest", EXIT_USAGE)


def _detector_stage(ctx: Context, progress: Progress) -> bool:
    code, problem = run_worker(
        ctx.run, compose_run_argv(ctx.docker, ctx.repo_root, ctx.credentials, DETECTOR_SERVICE, ctx.target),
        ctx.env, ctx.detector_timeout)
    if problem == "timeout":
        progress.detector = "timed out; its container may still be running; nothing was cleaned up"
        return False
    if problem == "launch":
        progress.detector = "not started: the container tool could not be run"
        return False
    if code == 0:
        progress.detector = "succeeded (exit 0)"
        return True
    progress.detector = f"unsuccessful (exit {code}): " + DETECTOR_MESSAGES.get(code, "unexpected exit code")
    return False


def _rca_stage(ctx: Context, pending: list[str], progress: Progress) -> None:
    consecutive = 0
    for position, anomaly_id in enumerate(pending):
        code, problem = run_worker(ctx.run, rca_argv(ctx.docker, ctx.repo_root, ctx.credentials, anomaly_id,
                                                     ctx.target), ctx.env, ctx.rca_timeout)
        if problem == "timeout":
            progress.failed.append((anomaly_id, "timed out; its container may still be running"))
            progress.stopped = "an RCA run timed out; nothing was cleaned up and nothing was retried"
            progress.not_attempted = len(pending) - position - 1
            return
        if problem == "launch":
            progress.failed.append((anomaly_id, "the container tool could not be run"))
            progress.stopped = "the container tool could not be run"
            progress.not_attempted = len(pending) - position - 1
            return
        if code == 0:
            progress.investigated.append(anomaly_id)
            consecutive = 0
            continue
        progress.failed.append((anomaly_id, f"exit {code}: " + RCA_MESSAGES.get(code, "unexpected exit code")))
        consecutive += 1
        if code == 130:
            progress.stopped = "an RCA run was interrupted"
        elif code in RCA_SYSTEMIC_CODES:
            progress.stopped = "a configuration or database failure; the stage was stopped"
        elif consecutive >= MAX_CONSECUTIVE_RCA_FAILURES:
            progress.stopped = f"{MAX_CONSECUTIVE_RCA_FAILURES} consecutive RCA failures"
        if progress.stopped:
            progress.not_attempted = len(pending) - position - 1
            return


def _locked_workflow(ctx: Context, lock_factory: Callable[[str], object], progress: Progress) -> int:
    refuse_if_not_executable(ctx.target)                    # a second, independent guard behind main()'s
    lock_path = os.path.join(os.path.dirname(ctx.credentials), LOCK_NAME)
    try:
        lock = lock_factory(lock_path)
        with lock:  # type: ignore[attr-defined]
            # the second look for conflicting workers, now that no other run can be starting one
            require_no_workers(ctx.run, ctx.docker, ctx.env, ctx.target)
            if not _detector_stage(ctx, progress):
                return EXIT_DETECTOR
            verify_target(ctx.run, ctx.docker, ctx.env, ctx.target)
            pending = read_ids(ctx.run, ctx.docker, ctx.env, pending_sql(ctx.max_anomalies),
                               ctx.max_anomalies, "the pending anomalies", ctx.target)
            progress.pending_at_start = len(pending)
            _rca_stage(ctx, pending, progress)
            try:
                progress.remaining = read_ids(ctx.run, ctx.docker, ctx.env, pending_sql(ctx.max_anomalies),
                                              ctx.max_anomalies, "the final pending set", ctx.target)
            except PipelineError:
                progress.note.append("the final pending set could not be read")
                return EXIT_RCA
            progress.inconsistent = [i for i in progress.investigated if i in progress.remaining]
            try:
                progress.no_evidence = len(read_ids(ctx.run, ctx.docker, ctx.env, NO_EVIDENCE_SQL,
                                                    DIAGNOSTIC_LIMIT, "the evidence check", ctx.target))
            except PipelineError:
                progress.note.append("the evidence check could not be read")
            if progress.failed or progress.stopped or progress.inconsistent:
                return EXIT_RCA
            return EXIT_OK
    except lifecycle.LockHeldError:
        raise PipelineError("another pipeline run holds the lock; nothing was started", EXIT_BUSY) from None
    except lifecycle.LifecycleError:
        raise PipelineError("the lock could not be taken; nothing was started", EXIT_USAGE) from None


def execute_workflow(ctx: Context, lock_factory: Callable[[str], object], out: TextIO) -> int:
    """Run the workflow and ALWAYS print what was done, whichever way it ended."""
    progress = Progress(target=ctx.target.key)
    try:
        code = _locked_workflow(ctx, lock_factory, progress)
    except KeyboardInterrupt:
        progress.stopped = "interrupted; no container was stopped or cleaned up"
        code = EXIT_INTERRUPTED
    except PipelineError as error:
        progress.note.append(str(error))
        code = error.exit_code
    except Exception as error:  # noqa: BLE001 - type only, never the message
        progress.note.append(f"internal error ({type(error).__name__})")
        code = EXIT_FAILED
    print(_summary(progress), file=out)
    return code


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _bounded(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not a whole number") from None
    if not 1 <= number <= MAX_ANOMALIES_LIMIT:
        raise argparse.ArgumentTypeError(f"must be from 1 to {MAX_ANOMALIES_LIMIT}")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentops_mvp_pipeline.py",
                                     description="Detector then RCA for a fixed target.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print the intended sequence; runs nothing")
    run = sub.add_parser("run", help="dry run by default; --execute runs the workers (pipetest only)")
    run.add_argument("--target", choices=tuple(TARGETS), default=DEFAULT_TARGET,
                     help="a fixed target; 'accepted' is protected and can only be dry-run")
    run.add_argument("--credentials-file", metavar="PATH", required=True,
                     help="the target's credentials file (never read; handed to Compose)")
    run.add_argument("--execute", action="store_true", help="really run the detector and the RCA analyzer")
    run.add_argument("--max-anomalies", type=_bounded, default=DEFAULT_MAX_ANOMALIES, metavar="N",
                     help=f"at most N anomalies per run (1 to {MAX_ANOMALIES_LIMIT}, default {DEFAULT_MAX_ANOMALIES})")
    return parser


def main(argv: Optional[Sequence[str]] = None, *, environ: Optional[Mapping[str, str]] = None,
         run: Optional[Runner] = None, docker: Optional[str] = None, out: Optional[TextIO] = None,
         err: Optional[TextIO] = None, lock_factory: Optional[Callable[[str], object]] = None,
         repo_root: Optional[Path] = None, home: Optional[str] = None, platform_name: Optional[str] = None,
         file_exists: Optional[Callable[[str], bool]] = None,
         detector_config_text: Optional[str] = None) -> int:
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
        target = TARGETS[args.target]
        if args.execute:
            refuse_if_not_executable(target)             # before anything else is looked at
        if "DOCKER_HOST" in environ:
            raise PipelineError("DOCKER_HOST is set; refusing to use a possibly remote engine", EXIT_USAGE)
        tool = docker if docker is not None else shutil.which("docker")
        if not tool:
            raise PipelineError("the container command-line tool was not found", EXIT_USAGE)
        root = Path(repo_root) if repo_root is not None else creds.repository_root()
        credentials = check_credentials_path(args.credentials_file, environ, root,
                                             platform_name or os.name,
                                             home if home is not None else os.path.expanduser("~"), target)
        if detector_config_text is None:
            try:
                detector_config_text = (root / DETECTOR_CONFIG).read_text(encoding="utf-8")
            except OSError:
                raise PipelineError("the detector configuration could not be read", EXIT_USAGE) from None
        check_detector_config(detector_config_text)
        pending_sql(args.max_anomalies)
        env = workers.child_environment(environ)
        runner = run or default_runner
        verify_target(runner, tool, env, target)
        require_no_workers(runner, tool, env, target)
        if not args.execute:
            pending = read_ids(runner, tool, env, pending_sql(args.max_anomalies), args.max_anomalies,
                               "the pending anomalies", target)
            lines = [f"dry run: the target is {target.key} ({target.project}); no one-off worker container is running",
                     f"  a run would start the anomaly detector once, then investigate up to {args.max_anomalies} "
                     "pending anomalies one after the other",
                     f"  pending now (before the detector runs): {len(pending)}"]
            lines += [f"    {i}" for i in pending]
            lines.append("  nothing was started and no lock was taken; add --execute to run"
                         if target.executable else
                         "  nothing was started and no lock was taken; this target can never be executed")
            print("\n".join(lines), file=out)
            return EXIT_OK
        if not (file_exists or os.path.isfile)(credentials):
            raise PipelineError("the credentials file was not found", EXIT_USAGE)
        ctx = Context(runner, tool, env, root, credentials, args.max_anomalies, target)
        return execute_workflow(ctx, lock_factory or lifecycle.ExclusiveLock, out)
    except PipelineError as error:
        print(f"error: {error}", file=err)
        return error.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=err)
        return EXIT_INTERRUPTED
    except Exception as error:  # noqa: BLE001 - type only, never the message
        print(f"error: internal ({type(error).__name__})", file=err)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())

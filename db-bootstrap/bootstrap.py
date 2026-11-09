"""
db-bootstrap/bootstrap.py

Phase 14.2: Fresh-database bootstrap.

Turns a completely empty PostgreSQL database into the schema, roles and
analytics objects the platform needs, by applying the existing migrations and
the existing dbt project in the one order that works on an empty database:

    ledger -> 001 -> dbt run -> 002 ... 014 -> post-dbt grants -> verify
          -> complete -> upgrades (015 ...)

dbt has to run after 001 and before 002: migrations 002, 003, 005 and 008
grant on objects that only dbt creates.  For that first run to be possible
the dbt models must not need a role that a later migration creates; their
grant hooks are conditional on the role for this reason.  This program
changes no migration and no dbt model.

Base bootstrap and upgrades
---------------------------
The base plan ends with the "complete" marker: the schema, roles and analytics
objects were built and verified.  Migrations added later are listed in
_UPGRADES and follow the marker, one ledger row each, so the rows of a database
that was already complete stay valid and such a database simply resumes at the
first upgrade it has not recorded.  The marker therefore means "the base
bootstrap is complete", not "the whole plan is".  The database is COMPLETE
only when every step of the whole plan, upgrades included, is recorded; the
analytics refresh and the services that wait for this program rely on that.

Before the base bootstrap is marked complete, every grant the migrations make on
the analytics schema is checked.  post_dbt_grants.sql restores the part of
them that a later dbt run removes and nothing else restores.

Ledger
------
The migrations fail when they are run twice, on purpose.  This program
therefore records what it applied in agentops_bootstrap.ledger: one row per
step, in order, with the SHA-256 of the step's file.  A migration and its
ledger row are written in ONE transaction, so a step is either applied and
recorded or neither.

States
------
Before anything is changed, the database is classified:

    EMPTY          no ledger and none of the objects this program creates
    PARTIAL_VALID  the ledger holds a strict prefix of the steps, every
                   checksum matches, and the objects in the database are
                   exactly those of the recorded steps
    COMPLETE       every step of the plan is recorded: the base steps, the
                   "complete" marker and every upgrade
    INCOMPATIBLE   anything else

EMPTY starts from the beginning.  PARTIAL_VALID resumes at the first step
that is not recorded.  COMPLETE changes nothing.  INCOMPATIBLE changes
nothing and fails; this includes a database that already holds the platform's
objects but no ledger: such a database was not built by this program and is
never adopted.

Credentials
-----------
Every password comes from the environment.  None is written into a command
line, a statement text of this program, a log line or an error message.  The
administrator password reaches psql through PGPASSWORD; a role password
reaches a migration through psql's \\getenv.  Output of child processes is
shown only after every known password has been removed from it.

Standard library only.  psql and dbt are run as child processes.

Public API:
    BootstrapState, Classification, DbState, Step, Config
    ConfigError, DatabaseError, IncompatibleError, StepError
    build_plan(), classify(), load_config(), file_checksum()
    parse_analytics_grants(), intended_analytics_grants()
    parse_state_output(), parse_facts_output()
    PsqlExecutor            — the side effects
    run_bootstrap()         — the whole procedure
    main()                  — command-line entry point
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXIT_OK: int = 0
EXIT_INTERNAL: int = 1
EXIT_USAGE: int = 2
EXIT_CONFIGURATION: int = 3
EXIT_DATABASE: int = 4
EXIT_INCOMPATIBLE: int = 5
EXIT_STEP_FAILED: int = 6

LEDGER_SCHEMA: str = "agentops_bootstrap"
LEDGER_TABLE: str = "ledger"

#: The migrations name this database and this owner role literally
#: (GRANT CONNECT ON DATABASE agentops, ALTER DEFAULT PRIVILEGES FOR ROLE
#: agentops), so the bootstrap can only target exactly these.
REQUIRED_DATABASE: str = "agentops"
REQUIRED_OWNER: str = "agentops"

ANALYTICS_SCHEMA: str = "analytics"

KIND_SQL: str = "sql"
KIND_DBT: str = "dbt"
KIND_COMPLETE: str = "complete"

STEP_DBT: str = "dbt_run"
STEP_GRANTS: str = "post_dbt_grants.sql"
STEP_COMPLETE: str = "complete"

#: Checksum recorded for a step that has no file of its own.
NO_CHECKSUM: str = "-"

_ENV_HOST = "BOOTSTRAP_DB_HOST"
_ENV_PORT = "BOOTSTRAP_DB_PORT"
_ENV_NAME = "BOOTSTRAP_DB_NAME"
_ENV_ADMIN_USER = "BOOTSTRAP_DB_ADMIN_USER"
_ENV_ADMIN_PASSWORD = "BOOTSTRAP_DB_ADMIN_PASSWORD"
_ENV_MIGRATIONS_DIR = "BOOTSTRAP_MIGRATIONS_DIR"
_ENV_DBT_PROJECT_DIR = "BOOTSTRAP_DBT_PROJECT_DIR"
_ENV_WORK_DIR = "BOOTSTRAP_WORK_DIR"

#: Database role -> the environment variable that holds its password.  These
#: are the names the runtime services already read, so one value per role
#: serves both its creation and its use.
ROLE_PASSWORD_ENV: Mapping[str, str] = {
    "grafana_reader": "GF_DATASOURCE_AGENTOPS_PASSWORD",
    "trace_viewer_reader": "TRACE_VIEWER_DB_PASSWORD",
    "anomaly_detector": "ANOMALY_DETECTOR_DB_PASSWORD",
    "rca_analyzer": "RCA_ANALYZER_DB_PASSWORD",
    "incident_retrieval": "INCIDENT_RETRIEVAL_DB_PASSWORD",
    "alert_evaluator": "ALERT_EVALUATOR_DB_PASSWORD",
    "alert_notifier": "ALERT_NOTIFIER_DB_PASSWORD",
}

APPLICATION_ROLES: tuple[str, ...] = tuple(ROLE_PASSWORD_ENV)

#: Role attributes no application role may have.
ELEVATED_ROLE_ATTRIBUTES: tuple[str, ...] = (
    "rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls",
)

_DBT_RELATIONS: tuple[str, ...] = (
    "stg_telemetry_spans",
    "int_trace_spans",
    "mart_trace_metrics",
    "mart_agent_metrics",
    "mart_tool_metrics",
    "mart_retrieval_metrics",
    "mart_error_events",
)


def _role(name: str) -> str:
    return f"role:{name}"


def _table(name: str) -> str:
    return f"table:public.{name}"


_DBT_SENTINELS: tuple[str, ...] = (
    f"schema:{ANALYTICS_SCHEMA}",
    *(f"relation:{ANALYTICS_SCHEMA}.{name}" for name in _DBT_RELATIONS),
)

# file name, the objects that prove it was applied, and the psql variables it
# needs (psql variable -> database role whose password it is).
_MIGRATIONS: tuple[tuple[str, tuple[str, ...], Mapping[str, str]], ...] = (
    ("001_create_telemetry_spans.sql", (_table("telemetry_spans"),), {}),
    ("002_create_grafana_reader.sql", (_role("grafana_reader"),),
     {"grafana_reader_password": "grafana_reader"}),
    ("003_create_trace_viewer_reader.sql", (_role("trace_viewer_reader"),),
     {"trace_viewer_reader_password": "trace_viewer_reader"}),
    ("004_create_anomaly_events.sql", (_table("anomaly_events"),), {}),
    ("005_create_anomaly_detector_role.sql", (_role("anomaly_detector"),),
     {"anomaly_detector_password": "anomaly_detector"}),
    ("006_create_anomaly_detector_runs.sql", (_table("anomaly_detector_runs"),), {}),
    ("007_create_rca_tables.sql",
     (_table("rca_investigations"), _table("rca_evidence")), {}),
    ("008_create_rca_analyzer_role.sql", (_role("rca_analyzer"),),
     {"rca_analyzer_password": "rca_analyzer"}),
    # A column grant only: it leaves no object of its own behind.
    ("009_grant_rca_evidence_conflict_select.sql", (), {}),
    ("010_create_rca_investigation_embeddings.sql",
     ("extension:vector", _table("rca_investigation_embeddings")), {}),
    ("011_create_incident_retrieval_role.sql", (_role("incident_retrieval"),),
     {"incident_retrieval_password": "incident_retrieval"}),
    ("012_create_alert_tables.sql",
     (_table("alert_policies"), _table("alert_decisions"),
      _table("alert_delivery_attempts"), _table("alert_delivery_outcomes")), {}),
    ("013_create_alert_evaluator_role.sql", (_role("alert_evaluator"),),
     {"alert_evaluator_password": "alert_evaluator"}),
    ("014_create_alert_notifier_role.sql", (_role("alert_notifier"),),
     {"alert_notifier_password": "alert_notifier"}),
)

#: Migrations added after the base bootstrap, in the order they are applied.
#: They follow the "complete" marker (see the module docstring), so a database
#: that was complete before an upgrade existed resumes at it and nothing else.
#: Same shape as _MIGRATIONS.  An entry is final once any database has applied
#: it: its file is checksummed in the ledger.
_UPGRADES: tuple[tuple[str, tuple[str, ...], Mapping[str, str]], ...] = (
    # Read-only grants (SELECT on three tables, USAGE on schema public) to
    # trace_viewer_reader.  It creates no object and needs no password.
    ("015_grant_trace_viewer_anomaly_rca_read.sql", (), {}),
)

#: Every migration file the bootstrap knows: the base ones, then the upgrades.
MIGRATION_FILES: tuple[str, ...] = tuple(
    name for name, _, _ in _MIGRATIONS + _UPGRADES
)

#: dbt runs after this migration and before the next one.
DBT_AFTER_MIGRATION: str = "001_create_telemetry_spans.sql"

_IDENTIFIER_RE = re.compile(r"[a-z_][a-z0-9_]*")
_STEP_NAME_RE = re.compile(r"[a-z0-9_.]+")
_CHECKSUM_RE = re.compile(r"[0-9a-f]{64}|-")
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]*")

#: Values that are obviously the example text, not a chosen password.
_PLACEHOLDER_WORDS: frozenset[str] = frozenset({
    "changeme", "change-me", "change_me", "password", "placeholder", "example",
    "secret", "todo", "xxx", "none", "null",
})

_PSQL_TIMEOUT_SECONDS: int = 300
_DBT_TIMEOUT_SECONDS: int = 1800


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class BootstrapError(Exception):
    """Base class.  Messages never hold a password or a connection string."""

    exit_code: int = EXIT_INTERNAL


class ConfigError(BootstrapError):
    """The environment or the files this program needs are not usable."""

    exit_code = EXIT_CONFIGURATION


class DatabaseError(BootstrapError):
    """The database could not be reached or inspected.  Nothing was changed."""

    exit_code = EXIT_DATABASE


class IncompatibleError(BootstrapError):
    """The database is not one this program may change.  Nothing was changed."""

    exit_code = EXIT_INCOMPATIBLE


class StepError(BootstrapError):
    """A step failed.  It was not recorded; earlier steps stay recorded."""

    exit_code = EXIT_STEP_FAILED


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """
    One step of the bootstrap.

    sentinels are the objects whose presence shows the step was applied.
    atomic is False for dbt: it creates its objects one by one, so some of
    them may exist although the step is not recorded; it is safe to repeat.
    psql_variables maps a psql variable to the environment variable holding
    its value.
    """

    name: str
    kind: str
    checksum: str
    sentinels: tuple[str, ...] = ()
    atomic: bool = True
    path: Optional[Path] = None
    psql_variables: Mapping[str, str] = field(default_factory=dict)


def file_checksum(data: bytes) -> str:
    """
    SHA-256 of a file's content with line endings normalised to LF, so that a
    Windows checkout and a Linux checkout of the same file agree.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    normalised = bytes(data).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalised).hexdigest()


def _read_checksum(path: Path) -> str:
    try:
        return file_checksum(path.read_bytes())
    except OSError as exc:
        raise ConfigError(
            f"cannot read {path.name} ({type(exc).__name__})"
        ) from None


def build_plan(migrations_dir: Path, grants_file: Path) -> tuple[Step, ...]:
    """
    The ordered steps, with the checksum of every file as it is on disk now.

    Order: the base migrations (dbt after 001), the post-dbt grants, the
    "complete" marker, then the upgrades.

    Raises:
        ConfigError  a migration is missing, an unknown migration is present,
                     or a file cannot be read.
    """
    migrations_dir = Path(migrations_dir)
    if not migrations_dir.is_dir():
        raise ConfigError("the migrations directory does not exist")
    present = sorted(p.name for p in migrations_dir.glob("*.sql"))
    missing = [name for name in MIGRATION_FILES if name not in present]
    unknown = [name for name in present if name not in MIGRATION_FILES]
    if missing:
        raise ConfigError(f"migration file(s) missing: {', '.join(missing)}")
    if unknown:
        # A migration this program does not know cannot be ordered or verified.
        raise ConfigError(
            f"migration file(s) unknown to the bootstrap: {', '.join(unknown)}"
        )
    grants_file = Path(grants_file)
    if not grants_file.is_file():
        raise ConfigError("the post-dbt grants file does not exist")

    steps: list[Step] = []
    def sql_step(name, sentinels, variables) -> Step:
        path = migrations_dir / name
        return Step(
            name=name,
            kind=KIND_SQL,
            checksum=_read_checksum(path),
            sentinels=sentinels,
            path=path,
            psql_variables={
                variable: ROLE_PASSWORD_ENV[role]
                for variable, role in variables.items()
            },
        )

    for name, sentinels, variables in _MIGRATIONS:
        steps.append(sql_step(name, sentinels, variables))
        if name == DBT_AFTER_MIGRATION:
            steps.append(Step(
                name=STEP_DBT,
                kind=KIND_DBT,
                checksum=NO_CHECKSUM,
                sentinels=_DBT_SENTINELS,
                atomic=False,
            ))
    steps.append(Step(
        name=STEP_GRANTS,
        kind=KIND_SQL,
        checksum=_read_checksum(grants_file),
        path=grants_file,
    ))
    steps.append(Step(name=STEP_COMPLETE, kind=KIND_COMPLETE, checksum=NO_CHECKSUM))
    for name, sentinels, variables in _UPGRADES:
        steps.append(sql_step(name, sentinels, variables))
    return tuple(steps)


def all_sentinels(plan: Sequence[Step]) -> tuple[str, ...]:
    """Every object the bootstrap looks for, in plan order."""
    return tuple(sentinel for step in plan for sentinel in step.sentinels)


# ---------------------------------------------------------------------------
# State classification (pure)
# ---------------------------------------------------------------------------

class BootstrapState(Enum):
    EMPTY = "EMPTY"
    PARTIAL_VALID = "PARTIAL_VALID"
    COMPLETE = "COMPLETE"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass(frozen=True)
class DbState:
    """
    What was observed in the database.

    ledger_rows holds (position, step, checksum).  sentinels_present holds
    the names from all_sentinels() that exist.  elevated_roles holds
    "<role>:<attribute>" for every application role with an attribute it
    must not have.
    """

    ledger_schema_exists: bool = False
    ledger_table_exists: bool = False
    ledger_rows: tuple[tuple[int, str, str], ...] = ()
    sentinels_present: frozenset[str] = frozenset()
    elevated_roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Classification:
    """
    state, a fixed-vocabulary reason, and the index of the next step to run
    (None unless the state is EMPTY or PARTIAL_VALID).
    """

    state: BootstrapState
    reason: str
    next_index: Optional[int] = None


def _incompatible(reason: str) -> Classification:
    return Classification(BootstrapState.INCOMPATIBLE, reason)


def classify(state: DbState, plan: Sequence[Step]) -> Classification:
    """
    Classify the database.  Pure: reads nothing and changes nothing.

    Anything that is not clearly EMPTY, a consistent prefix, or COMPLETE is
    INCOMPATIBLE.
    """
    known = set(all_sentinels(plan))
    present = set(state.sentinels_present) & known

    if not state.ledger_table_exists:
        if state.ledger_schema_exists:
            return _incompatible("the ledger schema exists without its table")
        if state.ledger_rows:
            return _incompatible("ledger rows were reported without a ledger table")
        if present:
            return _incompatible(
                "objects of the platform exist but there is no ledger: "
                + ", ".join(sorted(present))
            )
        return Classification(BootstrapState.EMPTY, "no ledger and no objects", 0)

    rows = sorted(state.ledger_rows)
    if len(rows) > len(plan):
        return _incompatible("the ledger holds more steps than the plan")
    for index, (position, name, checksum) in enumerate(rows):
        step = plan[index]
        if position != index + 1:
            return _incompatible(
                f"ledger positions are not 1..n without gaps (at row {index + 1})"
            )
        if name != step.name:
            return _incompatible(
                f"ledger step {index + 1} is not the expected step {step.name}"
            )
        if checksum != step.checksum:
            return _incompatible(f"checksum mismatch for recorded step {step.name}")

    recorded = len(rows)
    expected = {s for step in plan[:recorded] for s in step.sentinels}
    missing = expected - present
    if missing:
        return _incompatible(
            "objects of recorded steps are missing: " + ", ".join(sorted(missing))
        )
    unexpected = present - expected
    if unexpected and recorded < len(plan):
        following = plan[recorded]
        # dbt is not atomic: its objects may exist before the step is recorded.
        if not following.atomic:
            unexpected -= set(following.sentinels)
    if unexpected:
        return _incompatible(
            "objects of steps that are not recorded exist: "
            + ", ".join(sorted(unexpected))
        )

    if recorded == len(plan):
        return Classification(BootstrapState.COMPLETE, "every step is recorded")
    return Classification(
        BootstrapState.PARTIAL_VALID,
        f"{recorded} of {len(plan)} steps are recorded",
        recorded,
    )


# ---------------------------------------------------------------------------
# Analytics grants (pure)
# ---------------------------------------------------------------------------

_GRANT_SELECT_RE = re.compile(
    r"GRANT\s+SELECT\s+ON\s+(?P<objects>[a-z0-9_.,\s]+?)\s+TO\s+(?P<role>[a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)
_GRANT_USAGE_RE = re.compile(
    r"GRANT\s+USAGE\s+ON\s+SCHEMA\s+(?P<schema>[a-z_][a-z0-9_]*)\s+TO\s+"
    r"(?P<role>[a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)


def _sql_statements(sql: str) -> list[str]:
    """Statements of a SQL text, comments removed, whitespace collapsed."""
    lines = [line.split("--", 1)[0] for line in sql.splitlines()]
    return [
        " ".join(statement.split())
        for statement in "\n".join(lines).split(";")
        if statement.strip()
    ]


def parse_analytics_grants(sql: str) -> frozenset[tuple[str, str, str]]:
    """
    The grants on the analytics schema and its relations found in a SQL
    text, as (privilege, object, role).

        ("USAGE",  "schema:analytics",              "<role>")
        ("SELECT", "analytics.<relation>",          "<role>")

    Statements about anything else are ignored.  Grants through default
    privileges are not grants on an object and are not returned.
    """
    found: set[tuple[str, str, str]] = set()
    for statement in _sql_statements(sql):
        usage = _GRANT_USAGE_RE.fullmatch(statement)
        if usage and usage.group("schema").lower() == ANALYTICS_SCHEMA:
            found.add(("USAGE", f"schema:{ANALYTICS_SCHEMA}", usage.group("role").lower()))
            continue
        select = _GRANT_SELECT_RE.fullmatch(statement)
        if select:
            for item in select.group("objects").split(","):
                name = item.strip().lower()
                if name.startswith(f"{ANALYTICS_SCHEMA}."):
                    found.add(("SELECT", name, select.group("role").lower()))
    return frozenset(found)


def statement_kinds(sql: str) -> frozenset[str]:
    """The leading two words of every statement, upper-cased."""
    return frozenset(
        " ".join(statement.split()[:2]).upper() for statement in _sql_statements(sql)
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Config:
    """
    Everything the bootstrap needs.  repr() never shows a password.
    """

    host: str
    port: int
    dbname: str
    admin_user: str
    admin_password: str = field(repr=False)
    role_passwords: Mapping[str, str] = field(repr=False)
    migrations_dir: Path
    dbt_project_dir: Path
    grants_file: Path
    work_dir: Optional[Path] = None

    def secrets(self) -> tuple[str, ...]:
        """Every password, longest first, for removing them from output."""
        values = {self.admin_password, *self.role_passwords.values()}
        return tuple(sorted((v for v in values if v), key=len, reverse=True))


def _is_placeholder(value: str) -> bool:
    text = value.strip()
    if text == "":
        return True
    if text.startswith("<") and text.endswith(">"):
        return True
    return text.lower() in _PLACEHOLDER_WORDS


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_config(
    environ: Mapping[str, str], *, require_role_passwords: bool = True,
) -> Config:
    """
    Read the configuration from an environment mapping.

    require_role_passwords is True for the bootstrap, which creates the
    application roles.  A program that creates no role passes False: the
    role passwords are then neither required nor read, and role_passwords
    is empty.

    Raises:
        ConfigError  naming the variable, never its value.
    """
    def required(name: str) -> str:
        value = environ.get(name)
        if value is None or value.strip() == "":
            raise ConfigError(f"environment variable {name} is not set")
        return value

    host = required(_ENV_HOST)
    port_text = required(_ENV_PORT)
    try:
        port = int(port_text)
    except ValueError:
        raise ConfigError(f"environment variable {_ENV_PORT} must be an integer") from None
    if not 1 <= port <= 65535:
        raise ConfigError(f"environment variable {_ENV_PORT} is not a valid port")

    dbname = required(_ENV_NAME)
    admin_user = required(_ENV_ADMIN_USER)
    if dbname != REQUIRED_DATABASE:
        raise ConfigError(
            f"{_ENV_NAME} must be {REQUIRED_DATABASE!r}: the migrations name "
            "that database"
        )
    if admin_user != REQUIRED_OWNER:
        raise ConfigError(
            f"{_ENV_ADMIN_USER} must be {REQUIRED_OWNER!r}: the migrations name "
            "that owner role"
        )

    role_names = tuple(ROLE_PASSWORD_ENV.values()) if require_role_passwords else ()
    passwords: dict[str, str] = {}
    for name in (_ENV_ADMIN_PASSWORD, *role_names):
        value = required(name)
        if _is_placeholder(value):
            raise ConfigError(
                f"environment variable {name} still holds a placeholder"
            )
        if "\n" in value or "\r" in value or "\x00" in value:
            raise ConfigError(
                f"environment variable {name} must be a single line"
            )
        passwords[name] = value

    root = _repo_root()
    migrations_dir = Path(
        environ.get(_ENV_MIGRATIONS_DIR) or root / "storage-consumer" / "migrations"
    )
    dbt_project_dir = Path(environ.get(_ENV_DBT_PROJECT_DIR) or root / "analytics")
    work_dir = environ.get(_ENV_WORK_DIR)
    return Config(
        host=host,
        port=port,
        dbname=dbname,
        admin_user=admin_user,
        admin_password=passwords[_ENV_ADMIN_PASSWORD],
        role_passwords={env_name: passwords[env_name] for env_name in role_names},
        migrations_dir=migrations_dir,
        dbt_project_dir=dbt_project_dir,
        grants_file=Path(__file__).resolve().parent / "post_dbt_grants.sql",
        work_dir=Path(work_dir) if work_dir else None,
    )


# ---------------------------------------------------------------------------
# Child processes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


#: (argv, env, stdin text, timeout seconds) -> ProcessResult
Runner = Callable[[Sequence[str], Mapping[str, str], Optional[str], int], ProcessResult]


def run_process(
    argv: Sequence[str],
    env: Mapping[str, str],
    stdin: Optional[str],
    timeout: int,
) -> ProcessResult:
    """
    Run one child process: an argument list, never a shell, with exactly the
    environment given.

    Raises:
        StepError  the program is not installed or did not finish in time.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - argument list, shell=False
            list(argv),
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(env),
            shell=False,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise StepError(f"the program {argv[0]!r} is not installed") from None
    except subprocess.TimeoutExpired:
        raise StepError(f"{argv[0]} did not finish within {timeout} seconds") from None
    return ProcessResult(completed.returncode, completed.stdout, completed.stderr)


def sanitize(text: str, secrets: Sequence[str]) -> str:
    """text with every known password replaced by ***."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def _tail(text: str, lines: int = 15) -> str:
    kept = [line for line in text.splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


def _base_env(environ: Mapping[str, str]) -> dict[str, str]:
    """The few variables a child process needs to start at all."""
    return {
        name: environ[name]
        for name in ("PATH", "SYSTEMROOT", "TEMP", "TMP")
        if name in environ
    }


def _psql_path_literal(path: Path) -> str:
    """A file path as a psql meta-command argument."""
    text = Path(path).resolve().as_posix()
    if any(ch in text for ch in ("'", "\\", "\n", "\r")):
        raise ConfigError("a file path holds a character psql cannot be given")
    return f"'{text}'"


def _check_step_values(position: int, name: str, checksum: str) -> None:
    if isinstance(position, bool) or not isinstance(position, int) or position < 1:
        raise ValueError("position must be an integer >= 1")
    if _STEP_NAME_RE.fullmatch(name) is None:
        raise ValueError("step name holds an unexpected character")
    if _CHECKSUM_RE.fullmatch(checksum) is None:
        raise ValueError("checksum is not a SHA-256 digest")


def ledger_insert_sql(position: int, name: str, checksum: str) -> str:
    """The INSERT that records one step.  Its values are validated first."""
    _check_step_values(position, name, checksum)
    return (
        f"INSERT INTO {LEDGER_SCHEMA}.{LEDGER_TABLE} (position, step, checksum) "
        f"VALUES ({position}, '{name}', '{checksum}');"
    )


_LEDGER_DDL: str = f"""\
CREATE SCHEMA {LEDGER_SCHEMA};
CREATE TABLE {LEDGER_SCHEMA}.{LEDGER_TABLE} (
    position    INTEGER      NOT NULL,
    step        TEXT         NOT NULL,
    checksum    TEXT         NOT NULL,
    applied_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT pk_bootstrap_ledger PRIMARY KEY (position),
    CONSTRAINT uq_bootstrap_ledger_step UNIQUE (step),
    CONSTRAINT chk_bootstrap_ledger_position CHECK (position >= 1)
);
"""

_FACTS_SQL: str = """\
SELECT 'database=' || current_database();
SELECT 'user=' || current_user;
SELECT 'superuser=' || rolsuper::text FROM pg_roles WHERE rolname = current_user;
SELECT 'vector_available=' || EXISTS (
    SELECT 1 FROM pg_available_extensions WHERE name = 'vector'
)::text;
"""


def _name_list(names: Sequence[str]) -> str:
    for name in names:
        if _IDENTIFIER_RE.fullmatch(name) is None:
            raise ValueError("an object name holds an unexpected character")
    return ", ".join(f"'{name}'" for name in names)


def state_sql(plan: Sequence[Step]) -> str:
    """The read-only statements whose output parse_state_output() reads."""
    sentinels = all_sentinels(plan)
    roles = [s.split(":", 1)[1] for s in sentinels if s.startswith("role:")]
    tables = [s.split(".", 1)[1] for s in sentinels if s.startswith("table:public.")]
    relations = [
        s.split(".", 1)[1] for s in sentinels
        if s.startswith(f"relation:{ANALYTICS_SCHEMA}.")
    ]
    elevated = " UNION ALL ".join(
        f"SELECT 'elevated:' || rolname || ':{attribute}' FROM pg_roles "
        f"WHERE rolname IN ({_name_list(APPLICATION_ROLES)}) AND {attribute}"
        for attribute in ELEVATED_ROLE_ATTRIBUTES
    )
    return f"""\
SELECT 'ledger_schema' WHERE EXISTS (
    SELECT 1 FROM pg_namespace WHERE nspname = '{LEDGER_SCHEMA}');
SELECT 'ledger_table' WHERE to_regclass('{LEDGER_SCHEMA}.{LEDGER_TABLE}') IS NOT NULL;
SELECT 'sentinel:role:' || rolname FROM pg_roles
    WHERE rolname IN ({_name_list(roles)});
SELECT 'sentinel:table:public.' || tablename FROM pg_tables
    WHERE schemaname = 'public' AND tablename IN ({_name_list(tables)});
SELECT 'sentinel:schema:{ANALYTICS_SCHEMA}' WHERE EXISTS (
    SELECT 1 FROM pg_namespace WHERE nspname = '{ANALYTICS_SCHEMA}');
SELECT 'sentinel:relation:{ANALYTICS_SCHEMA}.' || c.relname
    FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = '{ANALYTICS_SCHEMA}' AND c.relkind IN ('r', 'v', 'm')
      AND c.relname IN ({_name_list(relations)});
SELECT 'sentinel:extension:vector' WHERE EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'vector');
{elevated};
"""


_LEDGER_ROWS_SQL: str = (
    f"SELECT 'row:' || position || ':' || step || ':' || checksum "
    f"FROM {LEDGER_SCHEMA}.{LEDGER_TABLE} ORDER BY position;\n"
)


def parse_facts_output(text: str) -> dict[str, str]:
    """key=value lines of the preflight query."""
    facts: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.strip().partition("=")
        if separator:
            facts[key] = value
    return facts


def parse_state_output(state_text: str, rows_text: str = "") -> DbState:
    """
    Build a DbState from the output of state_sql() and of the ledger query.

    Raises:
        DatabaseError  a line is not one this program asked for.
    """
    schema = table = False
    sentinels: set[str] = set()
    elevated: set[str] = set()
    for raw in state_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "ledger_schema":
            schema = True
        elif line == "ledger_table":
            table = True
        elif line.startswith("sentinel:"):
            sentinels.add(line[len("sentinel:"):])
        elif line.startswith("elevated:"):
            elevated.add(line[len("elevated:"):])
        else:
            raise DatabaseError("the state query returned an unexpected line")

    rows: list[tuple[int, str, str]] = []
    for raw in rows_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) != 4 or parts[0] != "row" or not parts[1].isdigit():
            raise DatabaseError("the ledger query returned an unexpected line")
        rows.append((int(parts[1]), parts[2], parts[3]))
    return DbState(
        ledger_schema_exists=schema,
        ledger_table_exists=table,
        ledger_rows=tuple(rows),
        sentinels_present=frozenset(sentinels),
        elevated_roles=frozenset(elevated),
    )


def grants_check_sql(grants: frozenset[tuple[str, str, str]]) -> str:
    """One line 'missing:<privilege>:<object>:<role>' per grant that is absent."""
    statements = []
    for privilege, target, role in sorted(grants):
        if _IDENTIFIER_RE.fullmatch(role) is None:
            raise ValueError("a role name holds an unexpected character")
        if privilege == "USAGE":
            schema = target.split(":", 1)[1]
            if _IDENTIFIER_RE.fullmatch(schema) is None:
                raise ValueError("a schema name holds an unexpected character")
            check = f"has_schema_privilege('{role}', '{schema}', 'USAGE')"
        elif privilege == "SELECT":
            schema, _, relation = target.partition(".")
            if not all(_IDENTIFIER_RE.fullmatch(part) for part in (schema, relation)):
                raise ValueError("a relation name holds an unexpected character")
            check = f"has_table_privilege('{role}', '{schema}.{relation}', 'SELECT')"
        else:
            raise ValueError("unknown privilege")
        statements.append(
            f"SELECT 'missing:{privilege}:{target}:{role}' WHERE NOT {check};"
        )
    return "\n".join(statements) + "\n"


class PsqlExecutor:
    """
    The side effects of the bootstrap, through psql and dbt.

    Every statement that changes the database runs in one transaction with
    stop-on-error.  Reads run in a read-only session.
    """

    def __init__(
        self,
        config: Config,
        *,
        runner: Runner = run_process,
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config = config
        self._runner = runner
        self._environ = dict(os.environ if environ is None else environ)
        self._work_dir: Optional[Path] = None

    # -- psql ---------------------------------------------------------------

    def _psql_argv(self, *, transaction: bool) -> list[str]:
        # No password and no value from the environment appears here.
        argv = [
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--set", "ON_ERROR_STOP=1",
            "--host", self._config.host,
            "--port", str(self._config.port),
            "--username", self._config.admin_user,
            "--dbname", self._config.dbname,
            "--no-password",
        ]
        if transaction:
            argv.append("--single-transaction")
        argv += ["--file", "-"]
        return argv

    def _psql_env(
        self, *, read_only: bool, extra: Optional[Mapping[str, str]] = None,
    ) -> dict[str, str]:
        env = _base_env(self._environ)
        env["PGPASSWORD"] = self._config.admin_password
        env["PGCONNECT_TIMEOUT"] = "10"
        env["PGAPPNAME"] = "agentops-db-bootstrap"
        env["PGCLIENTENCODING"] = "UTF8"
        if read_only:
            env["PGOPTIONS"] = "-c default_transaction_read_only=on"
        env.update(extra or {})
        return env

    def _psql(
        self,
        script: str,
        *,
        read_only: bool,
        transaction: bool,
        extra_env: Optional[Mapping[str, str]] = None,
    ) -> ProcessResult:
        return self._runner(
            self._psql_argv(transaction=transaction),
            self._psql_env(read_only=read_only, extra=extra_env),
            script,
            _PSQL_TIMEOUT_SECONDS,
        )

    def _failure_detail(self, result: ProcessResult) -> str:
        return sanitize(_tail(result.stderr or result.stdout), self._config.secrets())

    def _read(self, script: str, what: str) -> str:
        result = self._psql(script, read_only=True, transaction=False)
        if result.returncode != 0:
            raise DatabaseError(
                f"could not read {what} (psql exit {result.returncode})\n"
                + self._failure_detail(result)
            )
        return result.stdout

    # -- reads --------------------------------------------------------------

    def read_facts(self) -> dict[str, str]:
        return parse_facts_output(self._read(_FACTS_SQL, "the server's identity"))

    def read_state(self, plan: Sequence[Step]) -> DbState:
        state_text = self._read(state_sql(plan), "the database state")
        rows_text = ""
        if "ledger_table" in {line.strip() for line in state_text.splitlines()}:
            rows_text = self._read(_LEDGER_ROWS_SQL, "the ledger")
        return parse_state_output(state_text, rows_text)

    def missing_grants(self, grants: frozenset[tuple[str, str, str]]) -> list[str]:
        if not grants:
            return []
        output = self._read(grants_check_sql(grants), "the granted privileges")
        return [
            line.strip()[len("missing:"):]
            for line in output.splitlines() if line.strip().startswith("missing:")
        ]

    # -- writes -------------------------------------------------------------

    def _write(
        self, script: str, step: str, extra_env: Optional[Mapping[str, str]] = None,
    ) -> None:
        result = self._psql(
            script, read_only=False, transaction=True, extra_env=extra_env,
        )
        if result.returncode != 0:
            raise StepError(
                f"step {step} failed and was rolled back "
                f"(psql exit {result.returncode})\n" + self._failure_detail(result)
            )

    def init_ledger(self) -> None:
        self._write(_LEDGER_DDL, "ledger")

    def apply_sql(self, step: Step, position: int) -> None:
        """Apply one SQL file and record it, in one transaction."""
        if step.kind != KIND_SQL or step.path is None:
            raise ValueError("apply_sql needs a SQL step")
        lines = []
        extra_env: dict[str, str] = {}
        for variable, env_name in sorted(step.psql_variables.items()):
            if _IDENTIFIER_RE.fullmatch(variable) is None:
                raise ValueError("a psql variable name holds an unexpected character")
            if _ENV_NAME_RE.fullmatch(env_name) is None:
                raise ValueError("an environment variable name is not valid")
            # psql reads the value itself; it is never part of this script.
            lines.append(f"\\getenv {variable} {env_name}")
            extra_env[env_name] = self._config.role_passwords[env_name]
        lines.append(f"\\i {_psql_path_literal(step.path)}")
        lines.append(ledger_insert_sql(position, step.name, step.checksum))
        self._write("\n".join(lines) + "\n", step.name, extra_env)

    def apply_unrecorded(self, path: Path, name: str) -> None:
        """
        Apply one SQL file in one transaction and record nothing.

        For a file that is safe to repeat and needs no psql variable.  The
        ledger is not read and not written.  name is used in the error only.

        Raises:
            StepError  the file failed; its transaction was rolled back.
        """
        if _STEP_NAME_RE.fullmatch(name) is None:
            raise ValueError("a step name holds an unexpected character")
        self._write(f"\\i {_psql_path_literal(path)}\n", name)

    def record_step(self, step: Step, position: int) -> None:
        """Record a step that has no SQL file of its own."""
        self._write(
            ledger_insert_sql(position, step.name, step.checksum) + "\n", step.name,
        )

    # -- dbt ----------------------------------------------------------------

    def _prepare_work_dir(self) -> Path:
        if self._work_dir is None:
            base = self._config.work_dir
            if base is None:
                base = Path(tempfile.mkdtemp(prefix="agentops-bootstrap-"))
            base.mkdir(parents=True, exist_ok=True)
            self._work_dir = base
        return self._work_dir

    def run_dbt(self) -> None:
        """
        Run `dbt run` on the analytics project as the owner role.

        The profile is the repository's own example, copied into a private
        directory; it takes every value from the environment.
        """
        project = self._config.dbt_project_dir
        example = project / "profiles.yml.example"
        if not example.is_file():
            raise ConfigError("the dbt profile example does not exist")
        work = self._prepare_work_dir()
        profiles = work / "profiles"
        profiles.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(example, profiles / "profiles.yml")

        env = _base_env(self._environ)
        env.update({
            "DBT_PG_HOST": self._config.host,
            "DBT_PG_PORT": str(self._config.port),
            "DBT_PG_DATABASE": self._config.dbname,
            "DBT_PG_USER": self._config.admin_user,
            "DBT_PG_PASSWORD": self._config.admin_password,
            "DBT_PG_SCHEMA": ANALYTICS_SCHEMA,
            "HOME": str(work),
            # No outbound connection from the bootstrap.
            "DBT_SEND_ANONYMOUS_USAGE_STATS": "False",
            "DO_NOT_TRACK": "1",
            "DBT_USE_COLORS": "False",
        })
        argv = [
            "dbt", "run",
            "--project-dir", str(project),
            "--profiles-dir", str(profiles),
            "--target-path", str(work / "target"),
            "--log-path", str(work / "logs"),
        ]
        result = self._runner(argv, env, None, _DBT_TIMEOUT_SECONDS)
        if result.returncode != 0:
            raise StepError(
                f"step {STEP_DBT} failed (dbt exit {result.returncode})\n"
                + sanitize(_tail(result.stdout or result.stderr), self._config.secrets())
            )


# ---------------------------------------------------------------------------
# Procedure
# ---------------------------------------------------------------------------

def check_facts(facts: Mapping[str, str]) -> None:
    """
    Refuse a server this program must not change.

    Raises:
        IncompatibleError  naming the failed check.
    """
    if facts.get("database") != REQUIRED_DATABASE:
        raise IncompatibleError(f"the database is not named {REQUIRED_DATABASE!r}")
    if facts.get("user") != REQUIRED_OWNER:
        raise IncompatibleError(f"the session role is not {REQUIRED_OWNER!r}")
    if facts.get("superuser") != "true":
        raise IncompatibleError(
            "the session role is not a superuser; the vector extension needs one"
        )
    if facts.get("vector_available") != "true":
        raise IncompatibleError(
            "the vector extension is not installed in this PostgreSQL image"
        )


def intended_analytics_grants(plan: Sequence[Step]) -> frozenset[tuple[str, str, str]]:
    """
    Every grant on the analytics schema and its relations that the migrations
    make.  This is the privilege matrix a finished database must have,
    whichever mechanism restores a grant after dbt rebuilds a relation.

    Raises:
        ConfigError  a migration file cannot be read.
    """
    found: set[tuple[str, str, str]] = set()
    for step in plan:
        if step.kind != KIND_SQL or step.name == STEP_GRANTS or step.path is None:
            continue
        try:
            text = step.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(
                f"cannot read {step.path.name} ({type(exc).__name__})"
            ) from None
        found |= parse_analytics_grants(text)
    return frozenset(found)


def verify(
    executor,
    plan: Sequence[Step],
    intended_grants: frozenset[tuple[str, str, str]],
) -> None:
    """
    Check the finished database before it is marked complete.

    intended_grants is the full analytics privilege matrix of the
    migrations, from intended_analytics_grants().

    Raises:
        StepError  naming what is missing or wrong.
    """
    state = executor.read_state(plan)
    missing = sorted(set(all_sentinels(plan)) - set(state.sentinels_present))
    if missing:
        raise StepError("verification failed: missing " + ", ".join(missing))
    if state.elevated_roles:
        raise StepError(
            "verification failed: application role with an elevated attribute: "
            + ", ".join(sorted(state.elevated_roles))
        )
    absent = executor.missing_grants(intended_grants)
    if absent:
        raise StepError(
            "verification failed: analytics grant missing: " + ", ".join(sorted(absent))
        )


def run_bootstrap(
    executor,
    plan: Sequence[Step],
    intended_grants: frozenset[tuple[str, str, str]],
    *,
    report: Callable[[str], None] = print,
) -> BootstrapState:
    """
    Bring the database to the complete state, or leave it untouched.

    intended_grants is checked before the database is marked complete.

    Returns the state the database was found in.

    Raises:
        DatabaseError      the database could not be inspected.
        IncompatibleError  the database must not be changed; nothing was done.
        StepError          a step failed; it was not recorded.
    """
    check_facts(executor.read_facts())
    found = classify(executor.read_state(plan), plan)
    report(f"database state: {found.state.value} ({found.reason})")

    if found.state is BootstrapState.INCOMPATIBLE:
        raise IncompatibleError(found.reason)
    if found.state is BootstrapState.COMPLETE:
        report("already initialized; nothing to do")
        return found.state

    if found.state is BootstrapState.EMPTY:
        report("creating the ledger")
        executor.init_ledger()
    else:
        report(f"resuming at step {found.next_index + 1}: {plan[found.next_index].name}")

    for index in range(found.next_index, len(plan)):
        step = plan[index]
        position = index + 1
        report(f"step {position}/{len(plan)}: {step.name}")
        if step.kind == KIND_SQL:
            executor.apply_sql(step, position)
        elif step.kind == KIND_DBT:
            executor.run_dbt()
            present = executor.read_state(plan).sentinels_present
            missing = sorted(set(step.sentinels) - set(present))
            if missing:
                raise StepError("dbt did not create: " + ", ".join(missing))
            executor.record_step(step, position)
        elif step.kind == KIND_COMPLETE:
            verify(executor, plan, intended_grants)
            executor.record_step(step, position)
        else:
            raise ValueError(f"unknown step kind {step.kind!r}")

    report("bootstrap complete")
    return found.state


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Initialize an empty AgentOps PostgreSQL database: migrations, "
            "dbt models and roles, in the required order. Configuration comes "
            "from the environment. A database that is already complete is "
            "left unchanged; one this program did not build is refused."
        ),
    )
    return parser.parse_args(argv)


def _error(message: str) -> None:
    sys.stderr.write(f"error: {message}\n")


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    runner: Runner = run_process,
) -> int:
    _parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        config = load_config(environment)
        plan = build_plan(config.migrations_dir, config.grants_file)
        executor = PsqlExecutor(config, runner=runner, environ=environment)
        run_bootstrap(executor, plan, intended_analytics_grants(plan))
    except BootstrapError as exc:
        _error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - last line of containment
        # Only the type: a message could quote a value.
        _error(f"internal: {type(exc).__name__}")
        return EXIT_INTERNAL
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

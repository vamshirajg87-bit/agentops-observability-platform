"""
db-bootstrap/tests/unit/test_analytics_refresh.py

Unit tests for analytics_refresh.py and the two additions it needs in
bootstrap.py.

No Docker, no PostgreSQL, no dbt, no network.  The plan is built from the
real migration files and the real grants file; the database is a small
in-memory stand-in, and child processes are replaced by a function.

Test inventory:
    AR01  Only a COMPLETE database is refreshed
    AR02  Order and failures: dbt -> grants -> verification
    AR03  The bootstrap's record is never written and must not change
    AR04  apply_unrecorded
    AR05  Configuration: owner password only
    AR06  Entry point
    AR07  Module boundaries
    AR08  Image
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

import analytics_refresh
import bootstrap
from analytics_refresh import run_refresh
from bootstrap import (
    BootstrapState,
    ConfigError,
    DbState,
    IncompatibleError,
    ProcessResult,
    PsqlExecutor,
    StepError,
    build_plan,
    classify,
    load_config,
)


_REPO = Path(__file__).resolve().parents[3]
_MIGRATIONS = _REPO / "storage-consumer" / "migrations"
_GRANTS = _REPO / "db-bootstrap" / "post_dbt_grants.sql"
_DOCKERFILE = _REPO / "docker" / "bootstrap" / "Dockerfile"

_PLAN = build_plan(_MIGRATIONS, _GRANTS)
_INTENDED = bootstrap.intended_analytics_grants(_PLAN)
_DBT_SENTINELS = next(step.sentinels for step in _PLAN if step.name == "dbt_run")

_ROLE_VARIABLES = list(bootstrap.ROLE_PASSWORD_ENV.values())

# Invented for these tests; none is a real credential.
_ADMIN_SECRET = "TESTONLY-admin-4b8d"
_ROLE_SECRETS = {
    name: f"TESTONLY-{index}-role-2a6f" for index, name in enumerate(_ROLE_VARIABLES)
}

_GOOD_FACTS = {
    "database": "agentops", "user": "agentops", "superuser": "true",
    "vector_available": "true",
}


def _state(count: int, **overrides) -> DbState:
    """The database exactly as it is after `count` recorded steps."""
    values = dict(
        ledger_schema_exists=True,
        ledger_table_exists=True,
        ledger_rows=tuple(
            (index + 1, step.name, step.checksum)
            for index, step in enumerate(_PLAN[:count])
        ),
        sentinels_present=frozenset(
            s for step in _PLAN[:count] for s in step.sentinels
        ),
    )
    values.update(overrides)
    return DbState(**values)


_COMPLETE = _state(len(_PLAN))
_LEGACY = DbState(sentinels_present=_COMPLETE.sentinels_present)


class FakeDatabase:
    """An in-memory stand-in for the executor."""

    def __init__(self, state: DbState = _COMPLETE, *, facts=None) -> None:
        self.state = state
        self.facts = dict(_GOOD_FACTS if facts is None else facts)
        self.calls: list[str] = []
        self.fail_at: str | None = None
        self.missing: list[str] = []
        self.after_dbt: DbState | None = None
        self.after_grants: DbState | None = None

    # -- reads ----------------------------------------------------------------
    def read_facts(self):
        self.calls.append("read_facts")
        return dict(self.facts)

    def read_state(self, plan):
        self.calls.append("read_state")
        return self.state

    def missing_grants(self, grants):
        self.calls.append("missing_grants")
        self.grants_checked = grants
        return list(self.missing)

    # -- the two things a refresh may do --------------------------------------
    def run_dbt(self):
        self.calls.append("dbt")
        if self.fail_at == "dbt":
            raise StepError("step dbt_run failed (dbt exit 1)")
        if self.after_dbt is not None:
            self.state = self.after_dbt

    def apply_unrecorded(self, path, name):
        self.calls.append(f"grants:{name}")
        self.grants_path = path
        if self.fail_at == "grants":
            raise StepError(f"step {name} failed and was rolled back (psql exit 3)")
        if self.after_grants is not None:
            self.state = self.after_grants

    # -- what a refresh must never do ----------------------------------------
    def init_ledger(self):
        raise AssertionError("the refresh created the ledger")

    def apply_sql(self, step, position):
        raise AssertionError("the refresh applied a recorded step")

    def record_step(self, step, position):
        raise AssertionError("the refresh recorded a step")

    @property
    def actions(self) -> list[str]:
        return [c for c in self.calls if c == "dbt" or c.startswith("grants:")]


def _run(db: FakeDatabase) -> list[str]:
    lines: list[str] = []
    run_refresh(db, _PLAN, _INTENDED, report=lines.append)
    return lines


# ---------------------------------------------------------------------------
# AR01  Only a COMPLETE database is refreshed
# ---------------------------------------------------------------------------

class TestCompleteRequirement:

    def test_complete_database_is_refreshed(self):
        db = FakeDatabase()
        lines = _run(db)
        assert db.actions == ["dbt", "grants:post_dbt_grants.sql"]
        assert lines == [
            "database state: COMPLETE (every step is recorded)",
            "step 1/3: dbt run",
            "step 2/3: post_dbt_grants.sql",
            "step 3/3: verify analytics privileges",
            "analytics refresh complete",
        ]

    def test_empty_database_is_refused_before_dbt(self):
        db = FakeDatabase(DbState())
        with pytest.raises(IncompatibleError) as excinfo:
            _run(db)
        assert str(excinfo.value) == (
            "the database is not initialized; the database bootstrap has to "
            "finish first"
        )
        assert db.actions == []
        assert db.calls == ["read_facts", "read_state"]

    @pytest.mark.parametrize("count", [1, 2, 3, 9, len(_PLAN) - 1])
    def test_unfinished_bootstrap_is_refused_before_dbt(self, count):
        db = FakeDatabase(_state(count))
        assert classify(db.state, _PLAN).state is BootstrapState.PARTIAL_VALID
        with pytest.raises(IncompatibleError) as excinfo:
            _run(db)
        assert str(excinfo.value) == (
            "the database bootstrap has not finished; it has to finish first "
            f"({count} of {len(_PLAN)} steps are recorded)"
        )
        assert db.actions == []

    def test_base_complete_database_is_refused_until_the_upgrade_is_applied(self):
        """17 rows: built and verified before 015 existed, 015 not yet applied."""
        upgrade = "015_grant_trace_viewer_anomaly_rca_read.sql"
        base_rows = [step.name for step in _PLAN].index(upgrade)
        assert _PLAN[base_rows - 1].name == "complete"
        db = FakeDatabase(_state(base_rows))
        assert classify(db.state, _PLAN).state is BootstrapState.PARTIAL_VALID
        with pytest.raises(IncompatibleError) as excinfo:
            _run(db)
        assert str(excinfo.value) == (
            "the database bootstrap has not finished; it has to finish first "
            f"({base_rows} of {len(_PLAN)} steps are recorded)"
        )
        assert db.actions == []

    def test_refresh_is_allowed_once_the_upgrade_is_recorded(self):
        db = FakeDatabase(_state(len(_PLAN)))
        assert classify(db.state, _PLAN).state is BootstrapState.COMPLETE
        _run(db)
        assert db.actions == ["dbt", "grants:post_dbt_grants.sql"]

    def test_database_without_ledger_is_refused_before_dbt(self):
        db = FakeDatabase(_LEGACY)
        with pytest.raises(IncompatibleError, match="there is no ledger"):
            _run(db)
        assert db.actions == []

    @pytest.mark.parametrize("state", [
        _state(len(_PLAN), ledger_rows=_COMPLETE.ledger_rows[:-1] + (
            (len(_PLAN), "complete", "f" * 64),)),
        _state(len(_PLAN), sentinels_present=frozenset(
            _COMPLETE.sentinels_present - {"role:grafana_reader"})),
        DbState(ledger_schema_exists=True),
    ])
    def test_other_incompatible_states_are_refused_before_dbt(self, state):
        assert classify(state, _PLAN).state is BootstrapState.INCOMPATIBLE
        db = FakeDatabase(state)
        with pytest.raises(IncompatibleError):
            _run(db)
        assert db.actions == []

    @pytest.mark.parametrize("fact, value", [
        ("database", "other"), ("user", "postgres"), ("superuser", "false"),
        ("vector_available", "false"),
    ])
    def test_wrong_server_is_refused_before_the_state_is_read(self, fact, value):
        db = FakeDatabase(facts={**_GOOD_FACTS, fact: value})
        with pytest.raises(IncompatibleError):
            _run(db)
        assert db.calls == ["read_facts"]

    def test_refusals_use_the_incompatible_exit_code(self):
        assert IncompatibleError.exit_code == bootstrap.EXIT_INCOMPATIBLE == 5

    def test_state_is_decided_by_the_bootstrap_classifier(self):
        source = inspect.getsource(analytics_refresh)
        assert "bootstrap.classify(before, plan)" in source
        assert "def classify" not in source


# ---------------------------------------------------------------------------
# AR02  Order and failures
# ---------------------------------------------------------------------------

class TestOrderAndFailures:

    def test_order_is_dbt_then_grants_then_verification(self):
        db = FakeDatabase()
        _run(db)
        assert db.calls == [
            "read_facts", "read_state",              # refuse or accept
            "dbt", "grants:post_dbt_grants.sql",
            "read_state", "missing_grants",          # verification
            "read_state",                            # the record, again
        ]

    def test_grants_file_is_the_one_of_the_plan(self):
        db = FakeDatabase()
        _run(db)
        assert db.grants_path == _GRANTS

    def test_verification_checks_the_full_intended_matrix(self):
        db = FakeDatabase()
        _run(db)
        assert db.grants_checked == _INTENDED
        assert len(_INTENDED) > len(bootstrap.parse_analytics_grants(
            _GRANTS.read_text(encoding="utf-8")))

    def test_dbt_failure_stops_before_the_grants(self):
        db = FakeDatabase()
        db.fail_at = "dbt"
        with pytest.raises(StepError) as excinfo:
            _run(db)
        assert db.actions == ["dbt"]
        assert "missing_grants" not in db.calls
        assert str(excinfo.value) == (
            "step dbt_run failed (dbt exit 1)\n"
            "the analytics grants were not re-applied; correct the cause and "
            "run the refresh again"
        )

    def test_grants_failure_stops_before_verification(self):
        db = FakeDatabase()
        db.fail_at = "grants"
        lines: list[str] = []
        with pytest.raises(StepError, match="rolled back"):
            run_refresh(db, _PLAN, _INTENDED, report=lines.append)
        assert db.actions == ["dbt", "grants:post_dbt_grants.sql"]
        assert "missing_grants" not in db.calls
        assert "analytics refresh complete" not in lines

    def test_missing_grant_fails_and_is_named(self):
        db = FakeDatabase()
        db.missing = ["SELECT:analytics.int_trace_spans:trace_viewer_reader"]
        lines: list[str] = []
        with pytest.raises(StepError) as excinfo:
            run_refresh(db, _PLAN, _INTENDED, report=lines.append)
        assert str(excinfo.value) == (
            "verification failed: analytics grant missing: "
            "SELECT:analytics.int_trace_spans:trace_viewer_reader"
        )
        assert "analytics refresh complete" not in lines

    def test_relation_missing_after_dbt_fails(self):
        db = FakeDatabase()
        db.after_dbt = _state(len(_PLAN), sentinels_present=frozenset(
            _COMPLETE.sentinels_present - {"relation:analytics.mart_tool_metrics"}))
        with pytest.raises(StepError) as excinfo:
            _run(db)
        assert str(excinfo.value) == (
            "verification failed: missing relation:analytics.mart_tool_metrics"
        )

    def test_elevated_application_role_fails(self):
        db = FakeDatabase(_state(
            len(_PLAN), elevated_roles=frozenset({"rca_analyzer:rolsuper"})))
        with pytest.raises(StepError, match="elevated attribute: rca_analyzer:rolsuper"):
            _run(db)

    def test_failures_use_the_step_exit_code(self):
        assert StepError.exit_code == bootstrap.EXIT_STEP_FAILED == 6

    def test_verification_is_the_bootstrap_one(self):
        source = inspect.getsource(analytics_refresh)
        assert "bootstrap.verify(executor, plan, intended_grants)" in source
        assert "def verify" not in source

    def test_repeated_refresh_succeeds_every_time(self):
        db = FakeDatabase()
        for _ in range(3):
            assert _run(db)[-1] == "analytics refresh complete"
        assert db.actions == ["dbt", "grants:post_dbt_grants.sql"] * 3
        assert db.state == _COMPLETE

    def test_plan_without_a_grants_step_is_a_programming_error(self):
        db = FakeDatabase()
        plan = tuple(step for step in _PLAN if step.name != "post_dbt_grants.sql")
        with pytest.raises(ValueError):
            run_refresh(db, plan, _INTENDED, report=lambda line: None)
        assert db.calls == []


# ---------------------------------------------------------------------------
# AR03  The bootstrap's record
# ---------------------------------------------------------------------------

class TestLedger:

    def test_record_is_identical_after_a_successful_refresh(self):
        db = FakeDatabase()
        before = db.state.ledger_rows
        _run(db)
        assert db.state.ledger_rows == before
        assert classify(db.state, _PLAN).state is BootstrapState.COMPLETE

    @pytest.mark.parametrize("changed", [
        _state(len(_PLAN), ledger_rows=_COMPLETE.ledger_rows[:-1]),
        _state(len(_PLAN), ledger_rows=_COMPLETE.ledger_rows + (
            (len(_PLAN) + 1, "extra", "-"),)),
        _state(len(_PLAN), ledger_rows=_COMPLETE.ledger_rows[:-1] + (
            (len(_PLAN), "complete", "0" * 64),)),
        _state(len(_PLAN), ledger_table_exists=False),
    ])
    @pytest.mark.parametrize("moment", ["after_dbt", "after_grants"])
    def test_changed_record_fails_the_refresh(self, changed, moment):
        db = FakeDatabase()
        setattr(db, moment, changed)
        lines: list[str] = []
        with pytest.raises(StepError) as excinfo:
            run_refresh(db, _PLAN, _INTENDED, report=lines.append)
        assert str(excinfo.value) == "the bootstrap record changed during the refresh"
        assert "analytics refresh complete" not in lines

    def test_no_recording_method_is_ever_called(self):
        # FakeDatabase raises AssertionError from each of them.
        for state in (_COMPLETE, DbState(), _state(4), _LEGACY):
            db = FakeDatabase(state)
            try:
                _run(db)
            except bootstrap.BootstrapError:
                pass
            assert set(db.calls) <= {
                "read_facts", "read_state", "missing_grants", "dbt",
                "grants:post_dbt_grants.sql",
            }

    @pytest.mark.parametrize("word", [
        "init_ledger", "apply_sql", "record_step", "ledger_insert_sql",
        "_LEDGER_DDL", "_write", "INSERT", "CREATE", "ALTER", "DROP", "GRANT ",
    ])
    def test_source_names_no_recording_or_changing_operation(self, word):
        assert word not in inspect.getsource(analytics_refresh)

    def test_only_two_changing_methods_are_called_on_the_executor(self):
        tree = ast.parse(inspect.getsource(analytics_refresh))
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "executor"
        }
        assert called == {
            "read_facts", "read_state", "run_dbt", "apply_unrecorded",
        }


# ---------------------------------------------------------------------------
# AR04  apply_unrecorded
# ---------------------------------------------------------------------------

class Recorder:
    """Stands in for run_process and keeps every call."""

    def __init__(self, responses=None) -> None:
        self.calls: list[tuple[list[str], dict[str, str], str | None, int]] = []
        self.responses = list(responses or [])

    def __call__(self, argv, env, stdin, timeout):
        self.calls.append((list(argv), dict(env), stdin, timeout))
        if self.responses:
            return self.responses.pop(0)
        return ProcessResult(0, "", "")


def _environ(**overrides) -> dict[str, str]:
    """What the analytics-refresh service is given: no role password."""
    env = {
        "BOOTSTRAP_DB_HOST": "db.internal",
        "BOOTSTRAP_DB_PORT": "5432",
        "BOOTSTRAP_DB_NAME": "agentops",
        "BOOTSTRAP_DB_ADMIN_USER": "agentops",
        "BOOTSTRAP_DB_ADMIN_PASSWORD": _ADMIN_SECRET,
        "PATH": "/usr/bin",
    }
    env.update(overrides)
    return {key: value for key, value in env.items() if value is not None}


def _executor(tmp_path, responses=None):
    recorder = Recorder(responses)
    env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"))
    config = load_config(env, require_role_passwords=False)
    return PsqlExecutor(config, runner=recorder, environ=env), recorder


class TestApplyUnrecorded:

    def test_script_is_the_file_and_nothing_else(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.apply_unrecorded(_GRANTS, "post_dbt_grants.sql")
        ((_, _, stdin, _),) = recorder.calls
        assert stdin == f"\\i '{_GRANTS.resolve().as_posix()}'\n"

    def test_script_holds_no_ledger_statement(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.apply_unrecorded(_GRANTS, "post_dbt_grants.sql")
        ((_, _, stdin, _),) = recorder.calls
        for word in ("INSERT", "ledger", "agentops_bootstrap", "getenv"):
            assert word not in stdin

    def test_one_transaction_that_stops_on_the_first_error(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.apply_unrecorded(_GRANTS, "post_dbt_grants.sql")
        ((argv, env, _, timeout),) = recorder.calls
        assert argv[0] == "psql"
        assert "--single-transaction" in argv
        assert argv[argv.index("--set") + 1] == "ON_ERROR_STOP=1"
        assert "--no-psqlrc" in argv and "--no-password" in argv
        assert argv[-2:] == ["--file", "-"]
        assert "PGOPTIONS" not in env
        assert timeout > 0

    def test_password_is_in_the_environment_only(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.apply_unrecorded(_GRANTS, "post_dbt_grants.sql")
        ((argv, env, stdin, _),) = recorder.calls
        assert all(_ADMIN_SECRET not in argument for argument in argv)
        assert _ADMIN_SECRET not in stdin
        assert env["PGPASSWORD"] == _ADMIN_SECRET
        assert set(env) == {
            "PATH", "PGPASSWORD", "PGCONNECT_TIMEOUT", "PGAPPNAME", "PGCLIENTENCODING",
        }

    def test_failure_is_a_step_error_with_sanitized_detail(self, tmp_path):
        executor, _ = _executor(tmp_path, [ProcessResult(
            3, "", f'ERROR: role "x" does not exist {_ADMIN_SECRET}',
        )])
        with pytest.raises(StepError) as excinfo:
            executor.apply_unrecorded(_GRANTS, "post_dbt_grants.sql")
        assert str(excinfo.value) == (
            "step post_dbt_grants.sql failed and was rolled back (psql exit 3)\n"
            'ERROR: role "x" does not exist ***'
        )

    def test_it_is_the_existing_write_path(self):
        source = inspect.getsource(PsqlExecutor.apply_unrecorded)
        assert "self._write(" in source
        assert "ledger_insert_sql" not in source and "self._runner" not in source

    @pytest.mark.parametrize("name", ["bad name", "a;b", "", "A"])
    def test_unexpected_name_is_rejected_before_any_process(self, tmp_path, name):
        executor, recorder = _executor(tmp_path)
        with pytest.raises(ValueError):
            executor.apply_unrecorded(_GRANTS, name)
        assert recorder.calls == []

    def test_unusable_path_is_rejected_before_any_process(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        with pytest.raises(ConfigError):
            executor.apply_unrecorded(tmp_path / "it's.sql", "post_dbt_grants.sql")
        assert recorder.calls == []

    def test_grants_file_itself_only_grants_select(self):
        kinds = bootstrap.statement_kinds(_GRANTS.read_text(encoding="utf-8"))
        assert kinds == {"GRANT SELECT"}


# ---------------------------------------------------------------------------
# AR05  Configuration
# ---------------------------------------------------------------------------

class TestConfiguration:

    def test_owner_password_alone_is_enough(self):
        config = load_config(_environ(), require_role_passwords=False)
        assert config.admin_password == _ADMIN_SECRET
        assert dict(config.role_passwords) == {}
        assert config.secrets() == (_ADMIN_SECRET,)

    def test_role_passwords_are_not_read_even_when_present(self):
        config = load_config(
            {**_environ(), **_ROLE_SECRETS}, require_role_passwords=False,
        )
        assert dict(config.role_passwords) == {}
        assert set(config.secrets()) == {_ADMIN_SECRET}

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_owner_password_is_still_required(self, value):
        with pytest.raises(ConfigError) as excinfo:
            load_config(
                _environ(BOOTSTRAP_DB_ADMIN_PASSWORD=value), require_role_passwords=False,
            )
        assert str(excinfo.value) == (
            "environment variable BOOTSTRAP_DB_ADMIN_PASSWORD is not set"
        )

    @pytest.mark.parametrize("value", ["<password>", "change-me", "password"])
    def test_owner_placeholder_is_still_rejected(self, value):
        with pytest.raises(ConfigError, match="still holds a placeholder"):
            load_config(
                _environ(BOOTSTRAP_DB_ADMIN_PASSWORD=value), require_role_passwords=False,
            )

    @pytest.mark.parametrize("name", [
        "BOOTSTRAP_DB_HOST", "BOOTSTRAP_DB_PORT", "BOOTSTRAP_DB_NAME",
        "BOOTSTRAP_DB_ADMIN_USER",
    ])
    def test_connection_settings_are_still_required(self, name):
        with pytest.raises(ConfigError, match=name):
            load_config(_environ(**{name: None}), require_role_passwords=False)

    def test_database_and_owner_names_are_still_fixed(self):
        with pytest.raises(ConfigError, match="BOOTSTRAP_DB_NAME"):
            load_config(_environ(BOOTSTRAP_DB_NAME="other"), require_role_passwords=False)
        with pytest.raises(ConfigError, match="BOOTSTRAP_DB_ADMIN_USER"):
            load_config(
                _environ(BOOTSTRAP_DB_ADMIN_USER="postgres"), require_role_passwords=False,
            )

    @pytest.mark.parametrize("name", _ROLE_VARIABLES)
    def test_default_still_requires_every_role_password(self, name):
        full = {**_environ(), **_ROLE_SECRETS}
        assert dict(load_config(full).role_passwords) == _ROLE_SECRETS
        without = {key: value for key, value in full.items() if key != name}
        for call in (
            lambda: load_config(without),
            lambda: load_config(without, require_role_passwords=True),
        ):
            with pytest.raises(ConfigError) as excinfo:
                call()
            assert str(excinfo.value) == f"environment variable {name} is not set"

    def test_default_of_the_keyword_is_true_and_it_is_keyword_only(self):
        parameter = inspect.signature(load_config).parameters["require_role_passwords"]
        assert parameter.default is True
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY

    def test_bootstrap_entry_point_does_not_pass_the_keyword(self):
        assert "require_role_passwords" not in inspect.getsource(bootstrap.main)
        assert "load_config(environment)" in inspect.getsource(bootstrap.main)

    def test_refresh_entry_point_passes_false(self):
        assert (
            "bootstrap.load_config(environment, require_role_passwords=False)"
            in inspect.getsource(analytics_refresh.main)
        )


# ---------------------------------------------------------------------------
# AR06  Entry point
# ---------------------------------------------------------------------------

def _lines(state: DbState) -> tuple[str, str]:
    lines = []
    if state.ledger_schema_exists:
        lines.append("ledger_schema")
    if state.ledger_table_exists:
        lines.append("ledger_table")
    lines += [f"sentinel:{name}" for name in sorted(state.sentinels_present)]
    rows = [f"row:{p}:{n}:{c}" for p, n, c in state.ledger_rows]
    return "\n".join(lines) + "\n", "\n".join(rows) + "\n"


class SimulatedServer:
    """
    Stands in for psql and dbt as child processes of the real executor.
    Only two changing calls are accepted: dbt, and the grants file alone in
    one transaction.  Anything else fails the test.
    """

    def __init__(self, state: DbState = _COMPLETE) -> None:
        self.state = state
        self.writes: list[str] = []
        self.calls: list[tuple[list[str], dict[str, str], str | None]] = []
        self.dbt_result = ProcessResult(0, "Completed successfully", "")
        self.grants_result = ProcessResult(0, "", "")
        self.missing_output = ""
        self.facts_result = ProcessResult(
            0, "database=agentops\nuser=agentops\nsuperuser=true\nvector_available=true\n", "",
        )

    def __call__(self, argv, env, stdin, timeout):
        self.calls.append((list(argv), dict(env), stdin))
        text = stdin or ""
        if argv[0] == "dbt":
            self.writes.append("dbt")
            return self.dbt_result
        assert argv[0] == "psql"
        if "--single-transaction" not in argv:
            assert env.get("PGOPTIONS") == "-c default_transaction_read_only=on"
            if "current_database()" in text:
                return self.facts_result
            if "'ledger_schema'" in text:
                return ProcessResult(0, _lines(self.state)[0], "")
            if text.startswith("SELECT 'row:'"):
                return ProcessResult(0, _lines(self.state)[1], "")
            if "SELECT 'missing:" in text:
                return ProcessResult(0, self.missing_output, "")
            raise AssertionError("unexpected read")
        assert text == f"\\i '{_GRANTS.resolve().as_posix()}'\n", "unexpected write"
        self.writes.append("grants")
        return self.grants_result


def _main(server, tmp_path, **overrides) -> int:
    env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"), **overrides)
    return analytics_refresh.main([], environ=env, runner=server)


class TestMain:

    def test_complete_database_exits_zero(self, capsys, tmp_path):
        server = SimulatedServer()
        assert _main(server, tmp_path) == 0
        assert server.writes == ["dbt", "grants"]
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out.splitlines() == [
            "database state: COMPLETE (every step is recorded)",
            "step 1/3: dbt run",
            "step 2/3: post_dbt_grants.sql",
            "step 3/3: verify analytics privileges",
            "analytics refresh complete",
        ]

    def test_second_run_is_the_same(self, capsys, tmp_path):
        server = SimulatedServer()
        assert _main(server, tmp_path) == 0
        assert _main(server, tmp_path) == 0
        assert server.writes == ["dbt", "grants", "dbt", "grants"]

    def test_runs_without_any_role_password(self, capsys, tmp_path):
        server = SimulatedServer()
        assert _main(server, tmp_path) == 0
        for _argv, env, _stdin in server.calls:
            assert not set(env) & set(_ROLE_VARIABLES)

    def test_role_passwords_in_the_environment_reach_no_child(self, capsys, tmp_path):
        server = SimulatedServer()
        assert _main(server, tmp_path, **_ROLE_SECRETS) == 0
        for argv, env, stdin in server.calls:
            for secret in _ROLE_SECRETS.values():
                assert secret not in env.values()
                assert all(secret not in a for a in argv) and secret not in (stdin or "")

    def test_empty_database_exits_five_and_runs_nothing(self, capsys, tmp_path):
        server = SimulatedServer(DbState())
        assert _main(server, tmp_path) == 5
        assert server.writes == []
        assert len(server.calls) == 2
        captured = capsys.readouterr()
        assert captured.out == "database state: EMPTY (no ledger and no objects)\n"
        assert captured.err == (
            "error: the database is not initialized; the database bootstrap has "
            "to finish first\n"
        )

    def test_unfinished_bootstrap_exits_five_and_runs_nothing(self, capsys, tmp_path):
        server = SimulatedServer(_state(6))
        assert _main(server, tmp_path) == 5
        assert server.writes == []
        assert "has not finished" in capsys.readouterr().err

    def test_database_without_ledger_exits_five_and_runs_nothing(self, capsys, tmp_path):
        server = SimulatedServer(_LEGACY)
        assert _main(server, tmp_path) == 5
        assert server.writes == []
        assert capsys.readouterr().err.startswith(
            "error: objects of the platform exist but there is no ledger:"
        )

    def test_missing_owner_password_exits_three_before_any_process(self, capsys, tmp_path):
        server = SimulatedServer()
        assert _main(server, tmp_path, BOOTSTRAP_DB_ADMIN_PASSWORD=None) == 3
        assert server.calls == []
        assert capsys.readouterr().err == (
            "error: environment variable BOOTSTRAP_DB_ADMIN_PASSWORD is not set\n"
        )

    def test_unreachable_database_exits_four(self, capsys, tmp_path):
        server = SimulatedServer()
        server.facts_result = ProcessResult(2, "", "psql: error: connection refused")
        assert _main(server, tmp_path) == 4
        assert server.writes == []
        assert "could not read the server's identity" in capsys.readouterr().err

    def test_dbt_failure_exits_six_without_the_grants(self, capsys, tmp_path):
        server = SimulatedServer()
        server.dbt_result = ProcessResult(
            1, f"Database Error in model x\n  password={_ADMIN_SECRET}", "",
        )
        assert _main(server, tmp_path) == 6
        assert server.writes == ["dbt"]
        err = capsys.readouterr().err
        assert err.startswith("error: step dbt_run failed (dbt exit 1)\n")
        assert "the analytics grants were not re-applied" in err
        assert _ADMIN_SECRET not in err and "password=***" in err

    def test_grants_failure_exits_six(self, capsys, tmp_path):
        server = SimulatedServer()
        server.grants_result = ProcessResult(3, "", "ERROR: permission denied")
        assert _main(server, tmp_path) == 6
        captured = capsys.readouterr()
        assert "step post_dbt_grants.sql failed and was rolled back" in captured.err
        assert "analytics refresh complete" not in captured.out

    def test_missing_grant_exits_six(self, capsys, tmp_path):
        server = SimulatedServer()
        server.missing_output = "missing:SELECT:analytics.stg_telemetry_spans:rca_analyzer\n"
        assert _main(server, tmp_path) == 6
        captured = capsys.readouterr()
        assert captured.err == (
            "error: verification failed: analytics grant missing: "
            "SELECT:analytics.stg_telemetry_spans:rca_analyzer\n"
        )
        assert "analytics refresh complete" not in captured.out

    def test_unexpected_error_is_reported_by_type_only(self, capsys, tmp_path):
        def runner(argv, env, stdin, timeout):
            raise RuntimeError(f"boom {_ADMIN_SECRET}")

        env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"))
        assert analytics_refresh.main([], environ=env, runner=runner) == 1
        assert capsys.readouterr().err == "error: internal: RuntimeError\n"

    def test_no_output_argv_or_script_ever_holds_the_password(self, capsys, tmp_path):
        server = SimulatedServer()
        assert _main(server, tmp_path) == 0
        captured = capsys.readouterr()
        assert _ADMIN_SECRET not in captured.out and _ADMIN_SECRET not in captured.err
        assert len(server.calls) >= 8
        for argv, _env, stdin in server.calls:
            assert all(_ADMIN_SECRET not in a for a in argv)
            assert _ADMIN_SECRET not in (stdin or "")

    def test_dbt_runs_as_the_owner_with_the_password_in_its_environment(
        self, capsys, tmp_path,
    ):
        server = SimulatedServer()
        assert _main(server, tmp_path) == 0
        ((argv, env, stdin),) = [c for c in server.calls if c[0][0] == "dbt"]
        assert argv[:2] == ["dbt", "run"]
        assert env["DBT_PG_USER"] == "agentops"
        assert env["DBT_PG_PASSWORD"] == _ADMIN_SECRET
        assert stdin is None

    def test_needs_no_argument_and_takes_no_option(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            analytics_refresh.main(["--force"], environ=_environ(), runner=SimulatedServer())
        assert excinfo.value.code == 2
        with pytest.raises(SystemExit) as excinfo:
            analytics_refresh.main(["refresh"], environ=_environ(), runner=SimulatedServer())
        assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# AR07  Module boundaries
# ---------------------------------------------------------------------------

class TestModuleBoundaries:

    def test_imports_only_the_standard_library_and_bootstrap(self):
        tree = ast.parse(inspect.getsource(analytics_refresh))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module.split(".")[0])
        assert imported == {"__future__", "argparse", "os", "sys", "typing", "bootstrap"}

    def test_starts_no_process_and_sends_no_statement_of_its_own(self):
        source = inspect.getsource(analytics_refresh)
        for word in ("subprocess", "psql", "SELECT", "PGPASSWORD", "getenv"):
            assert word not in source

    def test_environment_is_never_printed(self):
        source = inspect.getsource(analytics_refresh)
        for word in ("print(os.environ", "print(env", "printenv", "pprint"):
            assert word not in source

    def test_no_adoption_and_no_option(self):
        source = inspect.getsource(analytics_refresh).lower()
        for word in ("--force", "--adopt", "--resume", "baseline", "add_argument"):
            assert word not in source

    def test_exit_codes_are_the_bootstrap_ones(self):
        source = inspect.getsource(analytics_refresh)
        assert re.findall(r"\bEXIT_[A-Z_]+ *(?::|=)", source) == []
        assert "exc.exit_code" in source


# ---------------------------------------------------------------------------
# AR08  Image
# ---------------------------------------------------------------------------

class TestImage:

    def test_dockerfile_copies_both_programs_and_the_grants_file(self):
        raw = _DOCKERFILE.read_text(encoding="utf-8").replace("\r\n", "\n")
        text = " ".join(raw.replace("\\\n", " ").split())
        assert (
            "COPY db-bootstrap/bootstrap.py db-bootstrap/analytics_refresh.py "
            "db-bootstrap/post_dbt_grants.sql db-bootstrap/"
        ) in text

    def test_default_entry_point_is_still_the_bootstrap(self):
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert 'ENTRYPOINT ["python", "/opt/agentops/db-bootstrap/bootstrap.py"]' in text
        assert text.count("ENTRYPOINT") == 1

    def test_refresh_module_sits_next_to_the_bootstrap(self):
        assert Path(analytics_refresh.__file__).parent == Path(bootstrap.__file__).parent

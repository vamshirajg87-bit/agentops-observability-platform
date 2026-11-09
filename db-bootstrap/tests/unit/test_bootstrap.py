"""
db-bootstrap/tests/unit/test_bootstrap.py

Unit tests for bootstrap.py.

No Docker, no PostgreSQL, no dbt, no network.  The plan is built from the
real migration files and the real grants file on disk; the database is a
small in-memory stand-in, and child processes are replaced by a recording
function.

Test inventory:
    BS01  Plan: order, dbt position, files, sentinels
    BS02  Checksums: line endings
    BS03  State classification
    BS04  Procedure: empty, resume, complete, incompatible, failures
    BS05  Verification and role expectations
    BS06  Configuration and credentials
    BS07  Child processes: argument lists, environments, scripts
    BS08  Output parsing
    BS09  Post-dbt grants: drift protection
    BS10  Entry point
    BS11  Module boundaries
    BS12  dbt grant hooks do not need the role to exist
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import re
from pathlib import Path

import pytest

import bootstrap
from bootstrap import (
    BootstrapState,
    Classification,
    Config,
    ConfigError,
    DatabaseError,
    DbState,
    IncompatibleError,
    ProcessResult,
    PsqlExecutor,
    StepError,
    build_plan,
    classify,
    file_checksum,
    load_config,
    parse_analytics_grants,
    parse_facts_output,
    parse_state_output,
    run_bootstrap,
)


_REPO = Path(__file__).resolve().parents[3]
_MIGRATIONS = _REPO / "storage-consumer" / "migrations"
_ANALYTICS = _REPO / "analytics"
_GRANTS = _REPO / "db-bootstrap" / "post_dbt_grants.sql"

_PLAN = build_plan(_MIGRATIONS, _GRANTS)
_NAMES = [step.name for step in _PLAN]
_GRANTS_SQL = _GRANTS.read_text(encoding="utf-8")
# Every analytics grant the migrations make: what verification checks.
_INTENDED = bootstrap.intended_analytics_grants(_PLAN)

_EXPECTED_ORDER = [
    "001_create_telemetry_spans.sql",
    "dbt_run",
    "002_create_grafana_reader.sql",
    "003_create_trace_viewer_reader.sql",
    "004_create_anomaly_events.sql",
    "005_create_anomaly_detector_role.sql",
    "006_create_anomaly_detector_runs.sql",
    "007_create_rca_tables.sql",
    "008_create_rca_analyzer_role.sql",
    "009_grant_rca_evidence_conflict_select.sql",
    "010_create_rca_investigation_embeddings.sql",
    "011_create_incident_retrieval_role.sql",
    "012_create_alert_tables.sql",
    "013_create_alert_evaluator_role.sql",
    "014_create_alert_notifier_role.sql",
    "post_dbt_grants.sql",
    "complete",
    # An upgrade: it follows the base marker (see bootstrap's _UPGRADES).
    "015_grant_trace_viewer_anomaly_rca_read.sql",
]

_UPGRADE = "015_grant_trace_viewer_anomaly_rca_read.sql"
# The ledger of a database the bootstrap completed before 015 existed.
_BASE_ROWS = 17

_ROLES = [
    "grafana_reader", "trace_viewer_reader", "anomaly_detector", "rca_analyzer",
    "incident_retrieval", "alert_evaluator", "alert_notifier",
]

_PASSWORD_VARIABLES = [
    "GF_DATASOURCE_AGENTOPS_PASSWORD", "TRACE_VIEWER_DB_PASSWORD",
    "ANOMALY_DETECTOR_DB_PASSWORD", "RCA_ANALYZER_DB_PASSWORD",
    "INCIDENT_RETRIEVAL_DB_PASSWORD", "ALERT_EVALUATOR_DB_PASSWORD",
    "ALERT_NOTIFIER_DB_PASSWORD",
]

# Invented for these tests; none is a real credential.
_ADMIN_SECRET = "TESTONLY-admin-7f3a"
_ROLE_SECRETS = {
    name: f"TESTONLY-{index}-role-9c1e" for index, name in enumerate(_PASSWORD_VARIABLES)
}
_ALL_SECRETS = [_ADMIN_SECRET, *_ROLE_SECRETS.values()]


def _environ(**overrides) -> dict[str, str]:
    env = {
        "BOOTSTRAP_DB_HOST": "db.internal",
        "BOOTSTRAP_DB_PORT": "5432",
        "BOOTSTRAP_DB_NAME": "agentops",
        "BOOTSTRAP_DB_ADMIN_USER": "agentops",
        "BOOTSTRAP_DB_ADMIN_PASSWORD": _ADMIN_SECRET,
        **_ROLE_SECRETS,
        "PATH": "/usr/bin",
    }
    env.update(overrides)
    return {key: value for key, value in env.items() if value is not None}


def _config(tmp_path=None) -> Config:
    env = _environ()
    if tmp_path is not None:
        env["BOOTSTRAP_WORK_DIR"] = str(tmp_path / "work")
    return load_config(env)


def _sentinels_through(count: int) -> frozenset[str]:
    return frozenset(s for step in _PLAN[:count] for s in step.sentinels)


def _rows_through(count: int) -> tuple[tuple[int, str, str], ...]:
    return tuple(
        (index + 1, step.name, step.checksum) for index, step in enumerate(_PLAN[:count])
    )


def _state(count: int, **overrides) -> DbState:
    """The database exactly as it is after `count` recorded steps."""
    values = dict(
        ledger_schema_exists=True,
        ledger_table_exists=True,
        ledger_rows=_rows_through(count),
        sentinels_present=_sentinels_through(count),
    )
    values.update(overrides)
    return DbState(**values)


_INDEX = {name: index for index, name in enumerate(_NAMES)}


# ---------------------------------------------------------------------------
# BS01  Plan
# ---------------------------------------------------------------------------

class TestPlan:

    def test_exact_order(self):
        assert _NAMES == _EXPECTED_ORDER

    def test_dbt_runs_after_001_and_before_002(self):
        assert _INDEX["dbt_run"] == _INDEX["001_create_telemetry_spans.sql"] + 1
        assert _INDEX["dbt_run"] + 1 == _INDEX["002_create_grafana_reader.sql"]

    def test_migrations_are_in_numeric_order(self):
        numbers = [int(name[:3]) for name in _NAMES if name[:3].isdigit()]
        assert numbers == list(range(1, 16))

    def test_every_migration_on_disk_is_in_the_plan_and_nothing_else(self):
        on_disk = sorted(path.name for path in _MIGRATIONS.glob("*.sql"))
        assert on_disk == sorted(bootstrap.MIGRATION_FILES)
        assert len(on_disk) == 15

    def test_grants_then_marker_then_upgrades_come_last(self):
        assert _NAMES[-3:] == ["post_dbt_grants.sql", "complete", _UPGRADE]
        assert _INDEX["complete"] == _BASE_ROWS - 1
        assert _NAMES[:_BASE_ROWS] == _EXPECTED_ORDER[:_BASE_ROWS]

    def test_base_plan_is_what_it_was_before_the_upgrade(self):
        """A database completed before 015 existed holds exactly these rows."""
        assert _NAMES[:_BASE_ROWS] == [
            "001_create_telemetry_spans.sql", "dbt_run",
            *[n for n in _NAMES[2:15]], "post_dbt_grants.sql", "complete",
        ]
        assert [int(n[:3]) for n in _NAMES[:15] if n[:3].isdigit()] == list(range(1, 15))

    def test_upgrade_step_is_a_plain_sql_step_with_no_variable_or_object(self):
        step = _PLAN[_INDEX[_UPGRADE]]
        assert step.kind == "sql" and step.atomic
        assert step.sentinels == () and dict(step.psql_variables) == {}
        assert step.path.is_file()
        assert step.checksum == bootstrap.file_checksum(step.path.read_bytes())

    def test_kinds(self):
        kinds = {step.name: step.kind for step in _PLAN}
        assert kinds["dbt_run"] == "dbt"
        assert kinds["complete"] == "complete"
        assert all(
            kind == "sql" for name, kind in kinds.items()
            if name not in ("dbt_run", "complete")
        )

    def test_only_dbt_is_not_atomic(self):
        assert [step.name for step in _PLAN if not step.atomic] == ["dbt_run"]

    def test_dbt_objects_are_those_the_later_migrations_grant_on(self):
        dbt = _PLAN[_INDEX["dbt_run"]]
        relations = {s.split(".", 1)[1] for s in dbt.sentinels if s.startswith("relation:")}
        assert "schema:analytics" in dbt.sentinels
        granted = set()
        for number in ("002", "003", "005", "008"):
            (path,) = _MIGRATIONS.glob(f"{number}_*.sql")
            granted |= set(re.findall(r"analytics\.([a-z_]+)", "\n".join(
                line.split("--")[0] for line in path.read_text(encoding="utf-8").splitlines()
            )))
        assert granted <= relations
        # And dbt really builds exactly these models.
        models = {path.stem for path in (_ANALYTICS / "models").rglob("*.sql")}
        assert relations == models

    def test_psql_variables_match_the_migration_files(self):
        for step in _PLAN:
            if step.kind != "sql" or step.name == "post_dbt_grants.sql":
                continue
            text = "\n".join(
                line.split("--")[0]
                for line in step.path.read_text(encoding="utf-8").splitlines()
            )
            assert set(re.findall(r":'([a-z_]+)'", text)) == set(step.psql_variables), step.name

    def test_each_role_password_variable_is_used_by_exactly_one_migration(self):
        used = [env for step in _PLAN for env in step.psql_variables.values()]
        assert sorted(used) == sorted(_PASSWORD_VARIABLES)
        assert dict(bootstrap.ROLE_PASSWORD_ENV) == dict(zip(_ROLES, _PASSWORD_VARIABLES))

    def test_role_sentinels_are_the_seven_application_roles(self):
        roles = [
            s.split(":", 1)[1] for s in bootstrap.all_sentinels(_PLAN) if s.startswith("role:")
        ]
        assert sorted(roles) == sorted(_ROLES)
        assert sorted(bootstrap.APPLICATION_ROLES) == sorted(_ROLES)

    def test_table_sentinels_are_created_by_their_migration(self):
        for step in _PLAN:
            for sentinel in step.sentinels:
                if not sentinel.startswith("table:public."):
                    continue
                table = sentinel.split(".", 1)[1]
                text = step.path.read_text(encoding="utf-8")
                assert re.search(
                    rf"CREATE TABLE (IF NOT EXISTS )?(public\.)?{table}\b", text,
                ), (step.name, table)

    def test_files_and_checksums(self):
        for step in _PLAN:
            if step.kind == "sql":
                assert step.path.is_file()
                assert re.fullmatch(r"[0-9a-f]{64}", step.checksum)
            else:
                assert step.path is None and step.checksum == "-"

    def test_missing_migration_is_rejected(self, tmp_path):
        for path in list(_MIGRATIONS.glob("*.sql"))[:-1]:
            (tmp_path / path.name).write_bytes(path.read_bytes())
        with pytest.raises(ConfigError, match="missing"):
            build_plan(tmp_path, _GRANTS)

    def test_unknown_migration_is_rejected(self, tmp_path):
        for path in _MIGRATIONS.glob("*.sql"):
            (tmp_path / path.name).write_bytes(path.read_bytes())
        (tmp_path / "016_something_new.sql").write_text("SELECT 1;", encoding="utf-8")
        with pytest.raises(ConfigError, match="unknown to the bootstrap"):
            build_plan(tmp_path, _GRANTS)

    def test_missing_directory_or_grants_file_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError):
            build_plan(tmp_path / "absent", _GRANTS)
        with pytest.raises(ConfigError):
            build_plan(_MIGRATIONS, tmp_path / "absent.sql")

    def test_migrations_hold_no_transaction_control(self):
        # Each file is applied inside one transaction with its ledger row.
        for path in _MIGRATIONS.glob("*.sql"):
            for line in path.read_text(encoding="utf-8").splitlines():
                code = line.split("--")[0].strip().upper()
                assert not re.match(r"(BEGIN|COMMIT|ROLLBACK|START TRANSACTION)\b", code), path.name
                assert not code.startswith("\\"), path.name


# ---------------------------------------------------------------------------
# BS02  Checksums
# ---------------------------------------------------------------------------

class TestChecksum:

    def test_crlf_lf_and_cr_give_the_same_checksum(self):
        lf = b"CREATE TABLE t (\n    a INT\n);\n"
        assert file_checksum(lf) == file_checksum(lf.replace(b"\n", b"\r\n"))
        assert file_checksum(lf) == file_checksum(lf.replace(b"\n", b"\r"))

    def test_is_sha256_of_the_lf_form(self):
        assert file_checksum(b"a\r\nb\r\n") == hashlib.sha256(b"a\nb\n").hexdigest()

    def test_content_change_changes_the_checksum(self):
        assert file_checksum(b"SELECT 1;\n") != file_checksum(b"SELECT 2;\n")
        assert file_checksum(b"SELECT 1;\n") != file_checksum(b"SELECT 1;\n\n")

    def test_real_migration_is_the_same_in_both_checkouts(self):
        data = (_MIGRATIONS / "012_create_alert_tables.sql").read_bytes()
        lf = data.replace(b"\r\n", b"\n")
        assert file_checksum(lf) == file_checksum(lf.replace(b"\n", b"\r\n"))
        assert _PLAN[_INDEX["012_create_alert_tables.sql"]].checksum == file_checksum(lf)

    def test_text_is_rejected(self):
        with pytest.raises(TypeError):
            file_checksum("SELECT 1;")


# ---------------------------------------------------------------------------
# BS03  State classification
# ---------------------------------------------------------------------------

def _incompatible(state: DbState) -> str:
    result = classify(state, _PLAN)
    assert result.state is BootstrapState.INCOMPATIBLE
    assert result.next_index is None
    return result.reason


class TestClassification:

    def test_empty(self):
        assert classify(DbState(), _PLAN) == Classification(
            BootstrapState.EMPTY, "no ledger and no objects", 0,
        )

    def test_ledger_only_resumes_at_the_first_step(self):
        result = classify(_state(0), _PLAN)
        assert (result.state, result.next_index) == (BootstrapState.PARTIAL_VALID, 0)

    @pytest.mark.parametrize("count", range(1, len(_EXPECTED_ORDER)))
    def test_every_valid_prefix_resumes_at_the_next_step(self, count):
        result = classify(_state(count), _PLAN)
        assert result.state is BootstrapState.PARTIAL_VALID
        assert result.next_index == count
        assert result.reason == f"{count} of {len(_PLAN)} steps are recorded"

    def test_complete(self):
        result = classify(_state(len(_PLAN)), _PLAN)
        assert result == Classification(BootstrapState.COMPLETE, "every step is recorded")

    def test_all_base_steps_but_the_marker_is_not_complete(self):
        result = classify(_state(_INDEX["complete"]), _PLAN)
        assert result.state is BootstrapState.PARTIAL_VALID
        assert _PLAN[result.next_index].name == "complete"

    def test_base_complete_database_is_not_complete_until_the_upgrade_is_recorded(self):
        result = classify(_state(_BASE_ROWS), _PLAN)
        assert result.state is BootstrapState.PARTIAL_VALID
        assert result.next_index == _BASE_ROWS
        assert _PLAN[result.next_index].name == _UPGRADE
        assert result.reason == f"{_BASE_ROWS} of {len(_PLAN)} steps are recorded"

    # -- objects without a ledger --------------------------------------------

    def test_fully_populated_database_without_ledger_is_incompatible(self):
        reason = _incompatible(DbState(sentinels_present=_sentinels_through(len(_PLAN))))
        assert "no ledger" in reason

    @pytest.mark.parametrize("sentinel", [
        "table:public.telemetry_spans", "role:grafana_reader", "schema:analytics",
        "relation:analytics.mart_trace_metrics", "extension:vector",
        "table:public.alert_decisions",
    ])
    def test_one_object_without_ledger_is_incompatible(self, sentinel):
        assert sentinel in _incompatible(DbState(sentinels_present=frozenset({sentinel})))

    def test_ledger_schema_without_table_is_incompatible(self):
        assert "without its table" in _incompatible(DbState(ledger_schema_exists=True))

    def test_rows_without_a_table_are_incompatible(self):
        _incompatible(DbState(ledger_rows=_rows_through(1)))

    # -- ledger defects --------------------------------------------------------

    def test_checksum_mismatch(self):
        rows = list(_rows_through(5))
        rows[2] = (3, rows[2][1], "0" * 64)
        reason = _incompatible(_state(5, ledger_rows=tuple(rows)))
        assert reason == "checksum mismatch for recorded step 002_create_grafana_reader.sql"

    def test_changed_migration_file_is_a_checksum_mismatch(self, tmp_path):
        for path in _MIGRATIONS.glob("*.sql"):
            (tmp_path / path.name).write_bytes(path.read_bytes())
        target = tmp_path / "004_create_anomaly_events.sql"
        target.write_bytes(target.read_bytes() + b"\n-- edited after it was applied\n")
        plan = build_plan(tmp_path, _GRANTS)
        result = classify(_state(len(_PLAN)), plan)
        assert result.state is BootstrapState.INCOMPATIBLE
        assert "004_create_anomaly_events.sql" in result.reason

    def test_steps_out_of_order(self):
        rows = list(_rows_through(4))
        rows[1], rows[2] = (2, rows[2][1], rows[2][2]), (3, rows[1][1], rows[1][2])
        reason = _incompatible(_state(4, ledger_rows=tuple(rows)))
        assert reason == "ledger step 2 is not the expected step dbt_run"

    def test_skipped_step(self):
        rows = [row for row in _rows_through(6) if row[0] != 3]
        assert "positions" in _incompatible(_state(6, ledger_rows=tuple(rows)))

    def test_positions_not_starting_at_one(self):
        rows = tuple((p + 1, n, c) for p, n, c in _rows_through(3))
        assert "positions" in _incompatible(_state(3, ledger_rows=rows))

    def test_unknown_step_name(self):
        rows = list(_rows_through(3))
        rows[2] = (3, "999_not_a_step.sql", rows[2][2])
        assert "not the expected step" in _incompatible(_state(3, ledger_rows=tuple(rows)))

    def test_more_rows_than_steps(self):
        rows = _rows_through(len(_PLAN)) + ((len(_PLAN) + 1, "extra", "-"),)
        assert "more steps" in _incompatible(_state(len(_PLAN), ledger_rows=rows))

    def test_marker_without_all_steps(self):
        rows = _rows_through(3) + ((4, "complete", "-"),)
        _incompatible(_state(3, ledger_rows=rows))

    # -- sentinels disagree with the ledger -------------------------------------

    @pytest.mark.parametrize("name", [
        "001_create_telemetry_spans.sql", "dbt_run", "005_create_anomaly_detector_role.sql",
        "010_create_rca_investigation_embeddings.sql", "012_create_alert_tables.sql",
        "014_create_alert_notifier_role.sql",
    ])
    def test_missing_object_of_a_recorded_step(self, name):
        step = _PLAN[_INDEX[name]]
        lost = step.sentinels[0]
        state = _state(len(_PLAN), sentinels_present=_sentinels_through(len(_PLAN)) - {lost})
        reason = _incompatible(state)
        assert reason == f"objects of recorded steps are missing: {lost}"

    def test_object_of_a_later_atomic_step(self):
        state = _state(3, sentinels_present=_sentinels_through(3) | {"role:alert_notifier"})
        reason = _incompatible(state)
        assert reason == "objects of steps that are not recorded exist: role:alert_notifier"

    def test_object_of_the_next_atomic_step(self):
        # 002 is next; its role already exists: a half-applied migration
        # cannot look like this, so something else created it.
        state = _state(2, sentinels_present=_sentinels_through(2) | {"role:grafana_reader"})
        _incompatible(state)

    def test_dbt_objects_before_dbt_is_recorded_are_accepted(self):
        # dbt creates its relations one by one and can be repeated.
        some = {"schema:analytics", "relation:analytics.stg_telemetry_spans"}
        state = _state(1, sentinels_present=_sentinels_through(1) | some)
        result = classify(state, _PLAN)
        assert (result.state, result.next_index) == (BootstrapState.PARTIAL_VALID, 1)
        assert _PLAN[result.next_index].name == "dbt_run"

    def test_dbt_objects_are_not_accepted_any_earlier(self):
        state = _state(0, sentinels_present=frozenset({"schema:analytics"}))
        _incompatible(state)

    def test_objects_the_bootstrap_does_not_know_are_ignored(self):
        state = _state(2, sentinels_present=_sentinels_through(2) | {"table:public.other"})
        assert classify(state, _PLAN).state is BootstrapState.PARTIAL_VALID

    def test_classification_is_pure(self):
        state = _state(4)
        assert classify(state, _PLAN) == classify(state, _PLAN)
        assert state == _state(4)

    def test_every_single_defect_of_a_complete_database_is_incompatible(self):
        full = _state(len(_PLAN))
        for sentinel in full.sentinels_present:
            broken = _state(len(_PLAN), sentinels_present=full.sentinels_present - {sentinel})
            assert classify(broken, _PLAN).state is BootstrapState.INCOMPATIBLE, sentinel
        for index in range(len(_PLAN)):
            rows = list(full.ledger_rows)
            if _PLAN[index].checksum == "-":
                continue
            rows[index] = (rows[index][0], rows[index][1], "f" * 64)
            broken = _state(len(_PLAN), ledger_rows=tuple(rows))
            assert classify(broken, _PLAN).state is BootstrapState.INCOMPATIBLE, index


# ---------------------------------------------------------------------------
# BS04  Procedure
# ---------------------------------------------------------------------------

_GOOD_FACTS = {
    "database": "agentops", "user": "agentops", "superuser": "true",
    "vector_available": "true",
}


class FakeDatabase:
    """An in-memory stand-in for the executor: it only tracks what exists."""

    def __init__(self, state: DbState = DbState(), *, facts=None) -> None:
        self.schema = state.ledger_schema_exists
        self.table = state.ledger_table_exists
        self.rows = list(state.ledger_rows)
        self.sentinels = set(state.sentinels_present)
        self.elevated = set(state.elevated_roles)
        self.facts = dict(_GOOD_FACTS if facts is None else facts)
        self.calls: list[str] = []
        self.fail_at: str | None = None
        self.dbt_creates: tuple[str, ...] | None = None
        self.missing: list[str] = []

    # -- reads ----------------------------------------------------------------
    def read_facts(self):
        return dict(self.facts)

    def read_state(self, plan):
        return DbState(
            self.schema, self.table, tuple(self.rows), frozenset(self.sentinels),
            frozenset(self.elevated),
        )

    def missing_grants(self, grants):
        self.grants_checked = grants
        return list(self.missing)

    # -- writes ---------------------------------------------------------------
    def init_ledger(self):
        self.calls.append("init_ledger")
        assert not self.schema and not self.table
        self.schema = self.table = True

    def apply_sql(self, step, position):
        self.calls.append(f"sql:{step.name}")
        if self.fail_at == step.name:
            # One transaction: neither the objects nor the ledger row exist.
            raise StepError(f"step {step.name} failed and was rolled back")
        self.sentinels |= set(step.sentinels)
        self.rows.append((position, step.name, step.checksum))

    def run_dbt(self):
        self.calls.append("dbt")
        created = _PLAN[_INDEX["dbt_run"]].sentinels
        if self.dbt_creates is not None:
            created = self.dbt_creates
        self.sentinels |= set(created)
        if self.fail_at == "dbt_run":
            raise StepError("step dbt_run failed")

    def record_step(self, step, position):
        self.calls.append(f"record:{step.name}")
        if self.fail_at == f"record:{step.name}":
            raise StepError(f"step {step.name} failed and was rolled back")
        self.rows.append((position, step.name, step.checksum))

    @property
    def mutations(self) -> list[str]:
        return list(self.calls)


_FULL_RUN = (
    ["init_ledger", "sql:001_create_telemetry_spans.sql", "dbt", "record:dbt_run"]
    + [f"sql:{name}" for name in _EXPECTED_ORDER[2:16]]
    + ["record:complete", f"sql:{_UPGRADE}"]
)


def _run(db: FakeDatabase):
    lines: list[str] = []
    found = run_bootstrap(db, _PLAN, _INTENDED, report=lines.append)
    return found, lines


class TestProcedure:

    def test_empty_database_runs_every_step_in_order(self):
        db = FakeDatabase()
        found, lines = _run(db)
        assert found is BootstrapState.EMPTY
        assert db.calls == _FULL_RUN
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.COMPLETE
        assert lines[0] == "database state: EMPTY (no ledger and no objects)"
        assert lines[-1] == "bootstrap complete"

    def test_ledger_rows_are_written_in_plan_order(self):
        db = FakeDatabase()
        _run(db)
        assert [row[1] for row in db.rows] == _EXPECTED_ORDER
        assert [row[0] for row in db.rows] == list(range(1, len(_PLAN) + 1))
        assert db.rows == list(_rows_through(len(_PLAN)))

    def test_second_run_is_a_no_op(self):
        db = FakeDatabase()
        _run(db)
        before = db.read_state(_PLAN)
        db.calls.clear()
        found, lines = _run(db)
        assert found is BootstrapState.COMPLETE
        assert db.mutations == []
        assert db.read_state(_PLAN) == before
        assert lines[-1] == "already initialized; nothing to do"

    @pytest.mark.parametrize("count", range(0, len(_EXPECTED_ORDER)))
    def test_valid_partial_state_resumes_at_the_next_step(self, count):
        db = FakeDatabase(_state(count))
        found, lines = _run(db)
        assert found is BootstrapState.PARTIAL_VALID
        # Exactly the tail of a full run: no ledger creation, nothing repeated.
        expected = [call for call in _FULL_RUN if call != "init_ledger"]
        first = _EXPECTED_ORDER[count]
        start = expected.index("dbt") if first == "dbt_run" else next(
            i for i, call in enumerate(expected) if call.endswith(first)
        )
        assert db.calls == expected[start:]
        assert f"resuming at step {count + 1}: {first}" in lines
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.COMPLETE

    @pytest.mark.parametrize("state", [
        DbState(sentinels_present=_sentinels_through(len(_EXPECTED_ORDER))),
        DbState(sentinels_present=frozenset({"role:grafana_reader"})),
        DbState(ledger_schema_exists=True),
        _state(5, ledger_rows=_rows_through(4) + ((5, "x", "-"),)),
        _state(6, sentinels_present=_sentinels_through(5)),
        _state(3, sentinels_present=_sentinels_through(9)),
    ])
    def test_incompatible_state_changes_nothing(self, state):
        db = FakeDatabase(state)
        before = db.read_state(_PLAN)
        with pytest.raises(IncompatibleError):
            _run(db)
        assert db.mutations == []
        assert db.read_state(_PLAN) == before

    def test_incompatible_error_carries_the_failed_invariant(self):
        db = FakeDatabase(DbState(sentinels_present=frozenset({"role:rca_analyzer"})))
        with pytest.raises(IncompatibleError) as excinfo:
            _run(db)
        assert str(excinfo.value) == (
            "objects of the platform exist but there is no ledger: role:rca_analyzer"
        )
        assert excinfo.value.exit_code == bootstrap.EXIT_INCOMPATIBLE

    @pytest.mark.parametrize("name", [
        "001_create_telemetry_spans.sql", "002_create_grafana_reader.sql",
        "010_create_rca_investigation_embeddings.sql", "014_create_alert_notifier_role.sql",
        "post_dbt_grants.sql",
    ])
    def test_failed_sql_step_is_not_recorded_and_stops_the_run(self, name):
        db = FakeDatabase()
        db.fail_at = name
        with pytest.raises(StepError):
            _run(db)
        assert db.calls[-1] == f"sql:{name}"
        assert [row[1] for row in db.rows] == _EXPECTED_ORDER[:_INDEX[name]]
        # The database is a valid prefix: the next run resumes at the same step.
        result = classify(db.read_state(_PLAN), _PLAN)
        assert (result.state, result.next_index) == (
            BootstrapState.PARTIAL_VALID, _INDEX[name],
        )

    def test_run_after_a_failed_step_resumes_and_completes(self):
        db = FakeDatabase()
        db.fail_at = "007_create_rca_tables.sql"
        with pytest.raises(StepError):
            _run(db)
        db.fail_at = None
        db.calls.clear()
        found, _ = _run(db)
        assert found is BootstrapState.PARTIAL_VALID
        assert db.calls[0] == "sql:007_create_rca_tables.sql"
        assert "init_ledger" not in db.calls and "dbt" not in db.calls
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.COMPLETE

    def test_failed_dbt_is_not_recorded_and_can_be_repeated(self):
        db = FakeDatabase()
        db.fail_at = "dbt_run"
        db.dbt_creates = ("schema:analytics", "relation:analytics.stg_telemetry_spans")
        with pytest.raises(StepError):
            _run(db)
        assert "record:dbt_run" not in db.calls
        assert [row[1] for row in db.rows] == ["001_create_telemetry_spans.sql"]
        result = classify(db.read_state(_PLAN), _PLAN)
        assert (result.state, _PLAN[result.next_index].name) == (
            BootstrapState.PARTIAL_VALID, "dbt_run",
        )
        db.fail_at, db.dbt_creates = None, None
        db.calls.clear()
        _run(db)
        assert db.calls[:2] == ["dbt", "record:dbt_run"]

    def test_dbt_that_creates_too_little_is_not_recorded(self):
        db = FakeDatabase()
        db.dbt_creates = ("schema:analytics",)
        with pytest.raises(StepError, match="dbt did not create"):
            _run(db)
        assert "record:dbt_run" not in db.calls
        assert "sql:002_create_grafana_reader.sql" not in db.calls

    def test_no_migration_after_002_runs_before_dbt(self):
        db = FakeDatabase()
        _run(db)
        dbt_at = db.calls.index("dbt")
        assert db.calls[:dbt_at] == ["init_ledger", "sql:001_create_telemetry_spans.sql"]

    def test_dbt_runs_exactly_once(self):
        db = FakeDatabase()
        _run(db)
        assert db.calls.count("dbt") == 1

    @pytest.mark.parametrize("facts, text", [
        ({**_GOOD_FACTS, "database": "postgres"}, "database is not named"),
        ({**_GOOD_FACTS, "user": "someone"}, "session role"),
        ({**_GOOD_FACTS, "superuser": "false"}, "superuser"),
        ({**_GOOD_FACTS, "vector_available": "false"}, "vector extension"),
        ({}, "database is not named"),
    ])
    def test_unsuitable_server_is_refused_before_anything_is_read_or_changed(
        self, facts, text,
    ):
        db = FakeDatabase(facts=facts)
        with pytest.raises(IncompatibleError, match=text):
            _run(db)
        assert db.mutations == []


# ---------------------------------------------------------------------------
# BS05  Verification and role expectations
# ---------------------------------------------------------------------------

class TestVerification:

    def test_marker_is_written_only_after_verification(self):
        db = FakeDatabase()
        _run(db)
        # The marker is the last base step; the upgrade follows it.
        assert db.calls[-2:] == ["record:complete", f"sql:{_UPGRADE}"]
        # The whole matrix of the migrations is checked, not only the part
        # the grants file restores.
        assert db.grants_checked == _INTENDED == _EXPECTED_GRANTS
        assert parse_analytics_grants(_GRANTS_SQL) < db.grants_checked

    def test_missing_grant_blocks_the_marker(self):
        db = FakeDatabase()
        db.missing = ["SELECT:analytics.mart_trace_metrics:anomaly_detector"]
        with pytest.raises(StepError, match="analytics grant missing"):
            _run(db)
        assert "record:complete" not in db.calls
        assert f"sql:{_UPGRADE}" not in db.calls
        result = classify(db.read_state(_PLAN), _PLAN)
        assert _PLAN[result.next_index].name == "complete"

    def test_elevated_application_role_blocks_the_marker(self):
        db = FakeDatabase()
        db.elevated = {"alert_notifier:rolsuper"}
        with pytest.raises(StepError, match="elevated attribute: alert_notifier:rolsuper"):
            _run(db)
        assert "record:complete" not in db.calls

    def test_missing_object_at_the_end_blocks_the_marker(self):
        db = FakeDatabase(_state(_INDEX["complete"]))
        db.sentinels.discard("extension:vector")
        # Found before anything runs: the ledger and the objects disagree.
        with pytest.raises(IncompatibleError):
            _run(db)
        assert db.mutations == []

    def test_no_application_role_may_be_elevated(self):
        assert bootstrap.ELEVATED_ROLE_ATTRIBUTES == (
            "rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls",
        )
        sql = bootstrap.state_sql(_PLAN)
        for attribute in bootstrap.ELEVATED_ROLE_ATTRIBUTES:
            assert f"AND {attribute}" in sql
        for role in _ROLES:
            assert f"'{role}'" in sql

    def test_migrations_create_only_plain_login_roles(self):
        for path in _MIGRATIONS.glob("*.sql"):
            text = "\n".join(
                line.split("--")[0] for line in path.read_text(encoding="utf-8").splitlines()
            )
            for statement in re.findall(r"CREATE ROLE[^;]*;", text, re.DOTALL):
                words = " ".join(statement.split())
                assert re.fullmatch(
                    r"CREATE ROLE [a-z_]+ WITH LOGIN PASSWORD :'[a-z_]+';", words,
                ), words

    def test_ledger_is_granted_to_nobody(self):
        assert "GRANT" not in bootstrap._LEDGER_DDL.upper()
        assert "agentops_bootstrap" not in _GRANTS_SQL


# ---------------------------------------------------------------------------
# BS06  Configuration and credentials
# ---------------------------------------------------------------------------

_REQUIRED = [
    "BOOTSTRAP_DB_HOST", "BOOTSTRAP_DB_PORT", "BOOTSTRAP_DB_NAME",
    "BOOTSTRAP_DB_ADMIN_USER", "BOOTSTRAP_DB_ADMIN_PASSWORD", *_PASSWORD_VARIABLES,
]


class TestConfiguration:

    def test_complete_environment(self):
        config = load_config(_environ())
        assert (config.host, config.port, config.dbname, config.admin_user) == (
            "db.internal", 5432, "agentops", "agentops",
        )
        assert config.admin_password == _ADMIN_SECRET
        assert dict(config.role_passwords) == _ROLE_SECRETS
        assert config.migrations_dir == _MIGRATIONS
        assert config.dbt_project_dir == _ANALYTICS
        assert config.grants_file == _GRANTS

    @pytest.mark.parametrize("name", _REQUIRED)
    def test_each_required_variable_missing(self, name):
        with pytest.raises(ConfigError) as excinfo:
            load_config(_environ(**{name: None}))
        assert str(excinfo.value) == f"environment variable {name} is not set"

    @pytest.mark.parametrize("name", _REQUIRED)
    @pytest.mark.parametrize("value", ["", "   ", "\t"])
    def test_each_required_variable_empty(self, name, value):
        with pytest.raises(ConfigError, match=name):
            load_config(_environ(**{name: value}))

    @pytest.mark.parametrize("name", ["BOOTSTRAP_DB_ADMIN_PASSWORD", *_PASSWORD_VARIABLES])
    @pytest.mark.parametrize("value", [
        "<password>", "<set-me>", "change-me", "CHANGEME", "Change_Me", "password",
        "placeholder", "example", "secret", "TODO", " change-me ",
    ])
    def test_placeholder_password_is_rejected(self, name, value):
        with pytest.raises(ConfigError) as excinfo:
            load_config(_environ(**{name: value}))
        assert str(excinfo.value) == f"environment variable {name} still holds a placeholder"

    @pytest.mark.parametrize("value", ["two\nlines", "carriage\rreturn", "nul\x00byte"])
    def test_multi_line_password_is_rejected(self, value):
        with pytest.raises(ConfigError, match="single line"):
            load_config(_environ(BOOTSTRAP_DB_ADMIN_PASSWORD=value))

    @pytest.mark.parametrize("port", ["abc", "5432.0", "0", "70000", "-1"])
    def test_invalid_port(self, port):
        with pytest.raises(ConfigError, match="BOOTSTRAP_DB_PORT"):
            load_config(_environ(BOOTSTRAP_DB_PORT=port))

    def test_database_and_owner_names_are_fixed_by_the_migrations(self):
        with pytest.raises(ConfigError, match="BOOTSTRAP_DB_NAME"):
            load_config(_environ(BOOTSTRAP_DB_NAME="other"))
        with pytest.raises(ConfigError, match="BOOTSTRAP_DB_ADMIN_USER"):
            load_config(_environ(BOOTSTRAP_DB_ADMIN_USER="postgres"))
        text = (_MIGRATIONS / "002_create_grafana_reader.sql").read_text(encoding="utf-8")
        assert "GRANT CONNECT ON DATABASE agentops" in text
        assert "FOR ROLE agentops" in text

    def test_no_error_message_ever_holds_a_value(self):
        for name in _REQUIRED:
            for value in (None, "", "<password>", "bad\nvalue"):
                try:
                    load_config(_environ(**{name: value}))
                except ConfigError as exc:
                    for secret in _ALL_SECRETS:
                        assert secret not in str(exc)

    def test_repr_hides_every_password(self):
        text = repr(load_config(_environ()))
        for secret in _ALL_SECRETS:
            assert secret not in text
        assert "db.internal" in text

    def test_secrets_lists_every_password_longest_first(self):
        secrets = load_config(_environ()).secrets()
        assert set(secrets) == set(_ALL_SECRETS)
        assert list(secrets) == sorted(secrets, key=len, reverse=True)

    def test_directories_can_be_overridden(self, tmp_path):
        config = load_config(_environ(
            BOOTSTRAP_MIGRATIONS_DIR=str(tmp_path / "m"),
            BOOTSTRAP_DBT_PROJECT_DIR=str(tmp_path / "a"),
            BOOTSTRAP_WORK_DIR=str(tmp_path / "w"),
        ))
        assert (config.migrations_dir, config.dbt_project_dir, config.work_dir) == (
            tmp_path / "m", tmp_path / "a", tmp_path / "w",
        )

    def test_no_password_is_written_in_the_module(self):
        source = inspect.getsource(bootstrap)
        # Every text assigned to a name that mentions a password is the NAME
        # of an environment variable, never a value.
        tree = ast.parse(source)
        checked = 0
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            value = node.value
            if (
                any("PASSWORD" in name.upper() for name in names)
                and isinstance(value, ast.Constant) and isinstance(value.value, str)
            ):
                assert re.fullmatch(r"[A-Z][A-Z0-9_]*", value.value), value.value
                checked += 1
        assert checked >= 1
        for env_name in bootstrap.ROLE_PASSWORD_ENV.values():
            assert re.fullmatch(r"[A-Z][A-Z0-9_]*", env_name)


# ---------------------------------------------------------------------------
# BS07  Child processes
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


def _executor(tmp_path, responses=None):
    recorder = Recorder(responses)
    env = _environ()
    env["BOOTSTRAP_WORK_DIR"] = str(tmp_path / "work")
    env["UNRELATED_SECRET"] = "TESTONLY-unrelated"
    executor = PsqlExecutor(load_config(env), runner=recorder, environ=env)
    return executor, recorder


def _assert_no_secret_in_argv_or_script(recorder: Recorder) -> None:
    for argv, _env, stdin, _timeout in recorder.calls:
        for secret in [*_ALL_SECRETS, "TESTONLY-unrelated"]:
            assert all(secret not in argument for argument in argv)
            assert stdin is None or secret not in stdin


class TestChildProcesses:

    def test_every_sql_step_keeps_passwords_out_of_argv_and_script(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        for position, step in enumerate(_PLAN, start=1):
            if step.kind == "sql":
                executor.apply_sql(step, position)
        assert len(recorder.calls) == 16
        _assert_no_secret_in_argv_or_script(recorder)

    def test_sql_step_is_one_transaction_with_its_ledger_row(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        step = _PLAN[_INDEX["002_create_grafana_reader.sql"]]
        executor.apply_sql(step, 3)
        ((argv, env, stdin, timeout),) = recorder.calls
        assert argv[0] == "psql"
        assert "--single-transaction" in argv
        assert argv[argv.index("--set") + 1] == "ON_ERROR_STOP=1"
        assert "--no-psqlrc" in argv and "--no-password" in argv
        assert argv[-2:] == ["--file", "-"]
        assert not any(flag in argv for flag in ("-a", "-e", "--echo-all", "--echo-queries"))
        lines = stdin.splitlines()
        assert lines[0] == "\\getenv grafana_reader_password GF_DATASOURCE_AGENTOPS_PASSWORD"
        assert lines[1] == f"\\i '{step.path.resolve().as_posix()}'"
        assert lines[2] == (
            "INSERT INTO agentops_bootstrap.ledger (position, step, checksum) "
            f"VALUES (3, '002_create_grafana_reader.sql', '{step.checksum}');"
        )
        assert len(lines) == 3
        assert timeout > 0

    def test_sql_step_gets_only_its_own_role_password(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        for position, step in enumerate(_PLAN, start=1):
            if step.kind == "sql":
                executor.apply_sql(step, position)
        for (argv, env, stdin, _), step in zip(
            recorder.calls, [s for s in _PLAN if s.kind == "sql"],
        ):
            allowed = set(step.psql_variables.values())
            present = {name for name in _PASSWORD_VARIABLES if name in env}
            assert present == allowed, step.name
            assert env["PGPASSWORD"] == _ADMIN_SECRET
            assert "PGOPTIONS" not in env
            assert "UNRELATED_SECRET" not in env
            assert "BOOTSTRAP_DB_ADMIN_PASSWORD" not in env

    def test_environment_is_built_from_scratch(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.init_ledger()
        ((_, env, _, _),) = recorder.calls
        assert set(env) == {
            "PATH", "PGPASSWORD", "PGCONNECT_TIMEOUT", "PGAPPNAME", "PGCLIENTENCODING",
        }

    def test_reads_use_a_read_only_session_and_no_transaction_flag(self, tmp_path):
        executor, recorder = _executor(tmp_path, [
            ProcessResult(0, "database=agentops\nuser=agentops\n", ""),
            ProcessResult(0, "ledger_schema\nledger_table\n", ""),
            ProcessResult(0, "", ""),
            ProcessResult(0, "", ""),
        ])
        executor.read_facts()
        executor.read_state(_PLAN)
        executor.missing_grants(parse_analytics_grants(_GRANTS_SQL))
        assert len(recorder.calls) == 4
        for argv, env, stdin, _ in recorder.calls:
            assert env["PGOPTIONS"] == "-c default_transaction_read_only=on"
            assert "--single-transaction" not in argv
            assert re.search(
                r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|GRANT|TRUNCATE)\b", stdin,
                re.IGNORECASE,
            ) is None
        _assert_no_secret_in_argv_or_script(recorder)

    def test_ledger_rows_are_read_only_when_the_table_exists(self, tmp_path):
        executor, recorder = _executor(tmp_path, [ProcessResult(0, "", "")])
        state = executor.read_state(_PLAN)
        assert len(recorder.calls) == 1
        assert state == DbState()

    def test_state_is_parsed_from_psql_output(self, tmp_path):
        executor, _ = _executor(tmp_path, [
            ProcessResult(0, "ledger_schema\nledger_table\nsentinel:table:public.telemetry_spans\n", ""),
            ProcessResult(0, f"row:1:{_PLAN[0].name}:{_PLAN[0].checksum}\n", ""),
        ])
        state = executor.read_state(_PLAN)
        assert state == _state(1)
        assert classify(state, _PLAN).next_index == 1

    def test_ledger_creation_is_one_transaction(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.init_ledger()
        ((argv, _, stdin, _),) = recorder.calls
        assert "--single-transaction" in argv
        assert "CREATE SCHEMA agentops_bootstrap;" in stdin
        assert "CREATE TABLE agentops_bootstrap.ledger" in stdin
        assert "IF NOT EXISTS" not in stdin

    def test_record_step_writes_only_the_ledger_row(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.record_step(_PLAN[_INDEX["dbt_run"]], 2)
        ((argv, _, stdin, _),) = recorder.calls
        assert "--single-transaction" in argv
        assert stdin == (
            "INSERT INTO agentops_bootstrap.ledger (position, step, checksum) "
            "VALUES (2, 'dbt_run', '-');\n"
        )

    def test_failed_write_raises_and_reports_without_passwords(self, tmp_path):
        leak = f"ERROR: something about {_ADMIN_SECRET} and {_ROLE_SECRETS['RCA_ANALYZER_DB_PASSWORD']}"
        executor, _ = _executor(tmp_path, [ProcessResult(3, "", leak)])
        with pytest.raises(StepError) as excinfo:
            executor.apply_sql(_PLAN[_INDEX["008_create_rca_analyzer_role.sql"]], 9)
        message = str(excinfo.value)
        assert "008_create_rca_analyzer_role.sql failed and was rolled back" in message
        assert "psql exit 3" in message
        for secret in _ALL_SECRETS:
            assert secret not in message
        assert "ERROR: something about *** and ***" in message

    def test_failed_read_is_a_database_error(self, tmp_path):
        executor, _ = _executor(tmp_path, [ProcessResult(2, "", "could not connect")])
        with pytest.raises(DatabaseError, match="psql exit 2"):
            executor.read_facts()

    def test_dbt_run(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        executor.run_dbt()
        ((argv, env, stdin, timeout),) = recorder.calls
        work = tmp_path / "work"
        assert argv == [
            "dbt", "run",
            "--project-dir", str(_ANALYTICS),
            "--profiles-dir", str(work / "profiles"),
            "--target-path", str(work / "target"),
            "--log-path", str(work / "logs"),
        ]
        assert stdin is None
        assert "test" not in argv and "build" not in argv
        assert env["DBT_PG_PASSWORD"] == _ADMIN_SECRET
        assert (env["DBT_PG_USER"], env["DBT_PG_DATABASE"], env["DBT_PG_SCHEMA"]) == (
            "agentops", "agentops", "analytics",
        )
        assert env["DBT_SEND_ANONYMOUS_USAGE_STATS"] == "False"
        assert not any(name in env for name in _PASSWORD_VARIABLES)
        assert "PGPASSWORD" not in env and "UNRELATED_SECRET" not in env
        _assert_no_secret_in_argv_or_script(recorder)
        # The profile is the repository's example, copied and unchanged.
        copied = (work / "profiles" / "profiles.yml").read_bytes()
        assert copied == (_ANALYTICS / "profiles.yml.example").read_bytes()
        assert _ADMIN_SECRET.encode() not in copied

    def test_dbt_does_not_write_into_the_project(self, tmp_path):
        executor, recorder = _executor(tmp_path)
        before = sorted(p.name for p in _ANALYTICS.iterdir())
        executor.run_dbt()
        assert sorted(p.name for p in _ANALYTICS.iterdir()) == before
        argv = recorder.calls[0][0]
        assert str(tmp_path) in argv[argv.index("--target-path") + 1]
        assert str(tmp_path) in argv[argv.index("--log-path") + 1]

    def test_failed_dbt_raises_without_passwords(self, tmp_path):
        executor, _ = _executor(tmp_path, [
            ProcessResult(1, f"Database Error: password {_ADMIN_SECRET} rejected", ""),
        ])
        with pytest.raises(StepError) as excinfo:
            executor.run_dbt()
        assert "dbt exit 1" in str(excinfo.value)
        assert _ADMIN_SECRET not in str(excinfo.value)

    def test_run_process_uses_an_argument_list_and_no_shell(self):
        source = inspect.getsource(bootstrap.run_process)
        assert "shell=False" in source
        assert "shell=True" not in inspect.getsource(bootstrap)
        tree = ast.parse(inspect.getsource(bootstrap))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
        ]
        assert [call.func.attr for call in calls] == ["run"]
        assert "os.system" not in inspect.getsource(bootstrap)

    def test_missing_program_is_a_step_error(self):
        with pytest.raises(StepError, match="is not installed"):
            bootstrap.run_process(
                ["agentops-no-such-program-xyz"], {"PATH": ""}, None, 5,
            )

    def test_sanitize(self):
        text = f"a {_ADMIN_SECRET} b {_ADMIN_SECRET}"
        assert bootstrap.sanitize(text, [_ADMIN_SECRET]) == "a *** b ***"
        assert bootstrap.sanitize("nothing here", ["", "x" * 9]) == "nothing here"

    @pytest.mark.parametrize("position, name, checksum", [
        (0, "001_a.sql", "a" * 64), (True, "001_a.sql", "a" * 64),
        (1, "001_a.sql'; DROP TABLE x; --", "a" * 64), (1, "001 a.sql", "a" * 64),
        (1, "001_a.sql", "xyz"), (1, "001_a.sql", "a" * 63), (1, "001_a.sql", "'"),
    ])
    def test_ledger_values_are_validated_before_they_become_sql(
        self, position, name, checksum,
    ):
        with pytest.raises(ValueError):
            bootstrap.ledger_insert_sql(position, name, checksum)

    def test_path_with_a_quote_is_refused(self, tmp_path):
        with pytest.raises(ConfigError):
            bootstrap._psql_path_literal(tmp_path / "it's.sql")


# ---------------------------------------------------------------------------
# BS08  Output parsing
# ---------------------------------------------------------------------------

class TestParsing:

    def test_facts(self):
        text = "database=agentops\nuser=agentops\nsuperuser=true\nvector_available=false\n\n"
        assert parse_facts_output(text) == {
            "database": "agentops", "user": "agentops", "superuser": "true",
            "vector_available": "false",
        }

    def test_state(self):
        state = parse_state_output(
            "ledger_schema\nledger_table\nsentinel:role:grafana_reader\n"
            "sentinel:relation:analytics.int_trace_spans\nelevated:rca_analyzer:rolsuper\n\n",
            "row:2:dbt_run:-\nrow:1:001_create_telemetry_spans.sql:" + "a" * 64 + "\n",
        )
        assert state.ledger_schema_exists and state.ledger_table_exists
        assert state.sentinels_present == {
            "role:grafana_reader", "relation:analytics.int_trace_spans",
        }
        assert state.elevated_roles == {"rca_analyzer:rolsuper"}
        assert sorted(state.ledger_rows) == [
            (1, "001_create_telemetry_spans.sql", "a" * 64), (2, "dbt_run", "-"),
        ]

    def test_empty_output_is_an_empty_database(self):
        assert parse_state_output("", "") == DbState()

    @pytest.mark.parametrize("state_text, rows_text", [
        ("something else\n", ""),
        ("", "row:x:001:abc\n"),
        ("", "row:1:001\n"),
        ("", "nonsense\n"),
    ])
    def test_unexpected_lines_fail_closed(self, state_text, rows_text):
        with pytest.raises(DatabaseError):
            parse_state_output(state_text, rows_text)

    def test_state_query_names_every_sentinel(self):
        sql = bootstrap.state_sql(_PLAN)
        for sentinel in bootstrap.all_sentinels(_PLAN):
            assert sentinel.split(":", 1)[1].split(".")[-1] in sql, sentinel
        assert sql.upper().count("SELECT") >= 7

    def test_grants_check_covers_every_grant(self):
        sql = bootstrap.grants_check_sql(_INTENDED)
        assert len(_INTENDED) == 16
        assert sql.count("SELECT 'missing:") == 16
        assert sql.count("has_schema_privilege") == 4
        assert sql.count("has_table_privilege") == 12


# ---------------------------------------------------------------------------
# BS09  Post-dbt grants
# ---------------------------------------------------------------------------

_GRANT_MIGRATIONS = ("002", "003", "005", "008")

# Written out by hand from the four migrations.
_EXPECTED_GRANTS = {
    *(("USAGE", "schema:analytics", role) for role in (
        "grafana_reader", "trace_viewer_reader", "anomaly_detector", "rca_analyzer",
    )),
    *(("SELECT", f"analytics.{name}", "grafana_reader") for name in (
        "mart_trace_metrics", "mart_agent_metrics", "mart_tool_metrics",
        "mart_retrieval_metrics", "mart_error_events",
    )),
    ("SELECT", "analytics.stg_telemetry_spans", "trace_viewer_reader"),
    ("SELECT", "analytics.int_trace_spans", "trace_viewer_reader"),
    *(("SELECT", f"analytics.{name}", "anomaly_detector") for name in (
        "stg_telemetry_spans", "mart_trace_metrics", "mart_agent_metrics",
        "mart_retrieval_metrics",
    )),
    ("SELECT", "analytics.stg_telemetry_spans", "rca_analyzer"),
}


def _migration_grants() -> frozenset:
    found = set()
    for number in _GRANT_MIGRATIONS:
        (path,) = _MIGRATIONS.glob(f"{number}_*.sql")
        found |= parse_analytics_grants(path.read_text(encoding="utf-8"))
    return frozenset(found)


class TestIntendedMatrix:
    """The full analytics privilege matrix of the migrations."""

    def test_equals_the_list_written_by_hand(self):
        assert _migration_grants() == _EXPECTED_GRANTS
        assert _INTENDED == _EXPECTED_GRANTS
        assert len(_EXPECTED_GRANTS) == 16

    def test_no_other_migration_grants_on_analytics(self):
        for path in _MIGRATIONS.glob("*.sql"):
            if path.name[:3] in _GRANT_MIGRATIONS:
                continue
            assert parse_analytics_grants(path.read_text(encoding="utf-8")) == frozenset(), path.name

    def test_each_role_has_exactly_its_own_relations(self):
        by_role: dict[str, set[str]] = {}
        for privilege, target, role in _INTENDED:
            if privilege == "SELECT":
                by_role.setdefault(role, set()).add(target.split(".", 1)[1])
        assert by_role == {
            "grafana_reader": {
                "mart_trace_metrics", "mart_agent_metrics", "mart_tool_metrics",
                "mart_retrieval_metrics", "mart_error_events",
            },
            "trace_viewer_reader": {"stg_telemetry_spans", "int_trace_spans"},
            "anomaly_detector": {
                "stg_telemetry_spans", "mart_trace_metrics", "mart_agent_metrics",
                "mart_retrieval_metrics",
            },
            "rca_analyzer": {"stg_telemetry_spans"},
        }

    def test_three_application_roles_never_read_analytics(self):
        roles = {role for _, _, role in _INTENDED}
        assert roles == {
            "grafana_reader", "trace_viewer_reader", "anomaly_detector", "rca_analyzer",
        }

    def test_the_grants_file_itself_is_not_a_source_of_the_matrix(self):
        # Adding a grant to the file must not widen what verification accepts.
        assert bootstrap.STEP_GRANTS == "post_dbt_grants.sql"
        source = inspect.getsource(bootstrap.intended_analytics_grants)
        assert "step.name == STEP_GRANTS" in source


# Written out by hand: what a dbt run removes and nothing else restores,
# as measured on a real database in Phase 14.2C2.
_EXPECTED_RESTORED = {
    ("SELECT", "analytics.stg_telemetry_spans", "trace_viewer_reader"),
    ("SELECT", "analytics.int_trace_spans", "trace_viewer_reader"),
    ("SELECT", "analytics.stg_telemetry_spans", "anomaly_detector"),
    ("SELECT", "analytics.stg_telemetry_spans", "rca_analyzer"),
}


def _default_privilege_roles() -> set[str]:
    """Roles that get SELECT on every new analytics relation by default."""
    roles = set()
    for path in _MIGRATIONS.glob("*.sql"):
        for statement in bootstrap._sql_statements(path.read_text(encoding="utf-8")):
            match = re.fullmatch(
                r"ALTER DEFAULT PRIVILEGES FOR ROLE agentops IN SCHEMA analytics "
                r"GRANT SELECT ON TABLES TO ([a-z_]+)",
                statement,
            )
            if match:
                roles.add(match.group(1))
    return roles


def _hook_grants() -> set[tuple[str, str, str]]:
    """Grants the dbt models re-issue themselves when they are rebuilt."""
    found = set()
    for path in (_ANALYTICS / "models").rglob("*.sql"):
        for role in re.findall(
            r"grant_select_if_role_exists\(this, '([a-z_]+)'\)",
            path.read_text(encoding="utf-8"),
        ):
            found.add(("SELECT", f"analytics.{path.stem}", role))
    return found


class TestPostDbtGrants:

    def test_file_is_exactly_what_nothing_else_restores(self):
        # Derived from the three sources: the migrations' grants, minus the
        # role covered by default privileges, minus the dbt hook grants.  The
        # schema itself is never replaced, so USAGE needs no restoring.
        derived = {
            grant for grant in _INTENDED
            if grant[0] == "SELECT"
            and grant[2] not in _default_privilege_roles()
            and grant not in _hook_grants()
        }
        assert parse_analytics_grants(_GRANTS_SQL) == derived

    def test_file_equals_the_list_written_by_hand(self):
        assert parse_analytics_grants(_GRANTS_SQL) == _EXPECTED_RESTORED
        assert len(_EXPECTED_RESTORED) == 4

    def test_file_is_a_strict_subset_of_the_migrations_grants(self):
        assert parse_analytics_grants(_GRANTS_SQL) < _migration_grants()

    def test_the_three_mechanisms_cover_the_whole_matrix_without_overlap(self):
        selects = {grant for grant in _INTENDED if grant[0] == "SELECT"}
        by_default = {g for g in selects if g[2] in _default_privilege_roles()}
        by_hook = _hook_grants()
        by_file = set(parse_analytics_grants(_GRANTS_SQL))
        assert by_default | by_hook | by_file == selects
        assert not by_default & by_hook
        assert not by_default & by_file
        assert not by_hook & by_file
        assert (len(by_default), len(by_hook), len(by_file)) == (5, 3, 4)

    def test_sources_of_the_derivation(self):
        assert _default_privilege_roles() == {"grafana_reader"}
        assert _hook_grants() == {
            ("SELECT", "analytics.mart_trace_metrics", "anomaly_detector"),
            ("SELECT", "analytics.mart_agent_metrics", "anomaly_detector"),
            ("SELECT", "analytics.mart_retrieval_metrics", "anomaly_detector"),
        }

    def test_file_restores_only_grants_on_views(self):
        views = set()
        for path in (_ANALYTICS / "models").rglob("*.sql"):
            if "materialized='view'" in path.read_text(encoding="utf-8"):
                views.add(f"analytics.{path.stem}")
        assert views == {"analytics.stg_telemetry_spans", "analytics.int_trace_spans"}
        assert {target for _, target, _ in parse_analytics_grants(_GRANTS_SQL)} == views

    def test_file_holds_nothing_but_those_grants(self):
        assert bootstrap.statement_kinds(_GRANTS_SQL) == {"GRANT SELECT"}
        statements = bootstrap._sql_statements(_GRANTS_SQL)
        assert len(statements) == 4
        # Every statement is one of the parsed grants: nothing is left over.
        reparsed = set()
        for statement in statements:
            parsed = parse_analytics_grants(statement + ";")
            assert len(parsed) == 1, statement
            reparsed |= parsed
        assert reparsed == _EXPECTED_RESTORED

    @pytest.mark.parametrize("word", [
        "ALTER", "DEFAULT PRIVILEGES", "ALL ", "PUBLIC", "WITH GRANT OPTION", "CREATE",
        "DROP", "REVOKE", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "OWNER", "SUPERUSER",
        "ROLE ", "PASSWORD", "public.", "agentops_bootstrap", "USAGE", "grafana_reader",
        "mart_",
    ])
    def test_file_broadens_nothing(self, word):
        code = "\n".join(line.split("--")[0] for line in _GRANTS_SQL.splitlines())
        assert word not in code

    def test_only_the_three_roles_that_read_views_appear(self):
        roles = {role for _, _, role in parse_analytics_grants(_GRANTS_SQL)}
        assert roles == {"trace_viewer_reader", "anomaly_detector", "rca_analyzer"}
        code = "\n".join(line.split("--")[0] for line in _GRANTS_SQL.splitlines())
        for role in ("incident_retrieval", "alert_evaluator", "alert_notifier"):
            assert role not in code

    def test_drift_is_detected_in_both_directions(self):
        extra = _GRANTS_SQL + "\nGRANT SELECT ON analytics.mart_error_events TO rca_analyzer;\n"
        assert parse_analytics_grants(extra) != _EXPECTED_RESTORED
        assert not parse_analytics_grants(extra) <= _migration_grants()
        fewer = _GRANTS_SQL.replace(
            "GRANT SELECT ON analytics.int_trace_spans TO trace_viewer_reader;", "",
        )
        assert fewer != _GRANTS_SQL
        assert parse_analytics_grants(fewer) != _EXPECTED_RESTORED

    def test_parser_ignores_what_is_not_an_analytics_object_grant(self):
        sql = """
            GRANT SELECT ON public.anomaly_events TO rca_analyzer;
            GRANT SELECT (anomaly_id) ON public.anomaly_events TO anomaly_detector;
            ALTER DEFAULT PRIVILEGES FOR ROLE agentops IN SCHEMA analytics
                GRANT SELECT ON TABLES TO grafana_reader;
            GRANT USAGE ON SCHEMA public TO rca_analyzer;
            -- GRANT SELECT ON analytics.hidden TO nobody;
            GRANT INSERT ON public.rca_evidence TO rca_analyzer;
        """
        assert parse_analytics_grants(sql) == frozenset()

    def test_parser_reads_lists_case_and_spacing(self):
        sql = "grant  select on\n analytics.a ,\n analytics.b\n to some_role ;"
        assert parse_analytics_grants(sql) == {
            ("SELECT", "analytics.a", "some_role"), ("SELECT", "analytics.b", "some_role"),
        }

    def test_grants_step_is_checksummed_like_a_migration(self):
        step = _PLAN[_INDEX["post_dbt_grants.sql"]]
        assert step.checksum == file_checksum(_GRANTS.read_bytes())
        assert step.psql_variables == {} and step.sentinels == ()


# ---------------------------------------------------------------------------
# BS10  Entry point
# ---------------------------------------------------------------------------

def _scripted(state_lines: str, rows: str = ""):
    """A runner that answers the three reads and accepts every write."""
    calls: list[tuple[list[str], str | None]] = []

    def runner(argv, env, stdin, timeout):
        calls.append((list(argv), stdin))
        text = stdin or ""
        if "current_database()" in text:
            return ProcessResult(
                0, "database=agentops\nuser=agentops\nsuperuser=true\nvector_available=true\n", "",
            )
        if "'ledger_schema'" in text:
            return ProcessResult(0, state_lines, "")
        if text.startswith("SELECT 'row:'"):
            return ProcessResult(0, rows, "")
        return ProcessResult(0, "", "")

    runner.calls = calls
    return runner


def _state_lines(state: DbState) -> tuple[str, str]:
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
    Stands in for psql and dbt as child processes: it reads the scripts the
    real executor sends and keeps the objects and ledger rows they would
    create.  A failing write changes nothing, as one transaction would.
    """

    def __init__(self, fail_on: str | None = None) -> None:
        self.schema = self.table = False
        self.rows: list[tuple[int, str, str]] = []
        self.sentinels: set[str] = set()
        self.writes: list[str] = []
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail_on = fail_on

    def state(self) -> DbState:
        return DbState(self.schema, self.table, tuple(self.rows), frozenset(self.sentinels))

    def __call__(self, argv, env, stdin, timeout):
        self.calls.append((list(argv), stdin))
        text = stdin or ""
        if argv[0] == "dbt":
            self.writes.append("dbt")
            self.sentinels |= set(_PLAN[_INDEX["dbt_run"]].sentinels)
            return ProcessResult(0, "Completed successfully", "")
        if "--single-transaction" not in argv:
            assert env.get("PGOPTIONS") == "-c default_transaction_read_only=on"
            if "current_database()" in text:
                return ProcessResult(
                    0,
                    "database=agentops\nuser=agentops\nsuperuser=true\n"
                    "vector_available=true\n",
                    "",
                )
            if "'ledger_schema'" in text:
                return ProcessResult(0, _state_lines(self.state())[0], "")
            if text.startswith("SELECT 'row:'"):
                return ProcessResult(0, _state_lines(self.state())[1], "")
            if "SELECT 'missing:" in text:
                return ProcessResult(0, "", "")
            raise AssertionError("unexpected read")

        # A write: one transaction.
        if "CREATE SCHEMA agentops_bootstrap" in text:
            self.writes.append("ledger")
            self.schema = self.table = True
            return ProcessResult(0, "", "")
        inserted = re.search(r"VALUES \((\d+), '([^']+)', '([^']+)'\);", text)
        assert inserted, "a write without a ledger row"
        position, name, checksum = int(inserted.group(1)), inserted.group(2), inserted.group(3)
        if name == self.fail_on:
            return ProcessResult(3, "", "ERROR: simulated failure")
        step = _PLAN[_INDEX[name]]
        if step.kind == "sql":
            assert f"\\i '{step.path.resolve().as_posix()}'" in text
            # psql would fail if a variable the file needs were not provided.
            for env_name in step.psql_variables.values():
                assert env.get(env_name)
            self.sentinels |= set(step.sentinels)
        self.rows.append((position, name, checksum))
        self.writes.append(name)
        return ProcessResult(0, "", "")


# ---------------------------------------------------------------------------
# BS12  Upgrades after the base marker (migration 015)
# ---------------------------------------------------------------------------

class TestUpgrade:

    def _existing(self) -> FakeDatabase:
        """A database the bootstrap completed before 015 existed: 17 rows."""
        return FakeDatabase(_state(_BASE_ROWS))

    # -- fresh database -------------------------------------------------------

    def test_fresh_database_runs_the_base_plan_then_015(self):
        db = FakeDatabase()
        found, _ = _run(db)
        assert found is BootstrapState.EMPTY
        assert db.calls[-2:] == ["record:complete", f"sql:{_UPGRADE}"]
        assert db.rows[_BASE_ROWS - 1][:2] == (_BASE_ROWS, "complete")
        assert db.rows[_BASE_ROWS][:2] == (_BASE_ROWS + 1, _UPGRADE)
        assert len(db.rows) == len(_PLAN) == _BASE_ROWS + 1
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.COMPLETE

    # -- previously completed database ----------------------------------------

    def test_existing_complete_database_is_not_complete_until_015(self):
        found = classify(self._existing().read_state(_PLAN), _PLAN)
        assert found.state is BootstrapState.PARTIAL_VALID
        assert _PLAN[found.next_index].name == _UPGRADE

    def test_existing_17_row_ledger_resumes_at_015_only(self):
        db = self._existing()
        base_rows = list(db.rows)
        found, lines = _run(db)
        assert found is BootstrapState.PARTIAL_VALID
        # Nothing but 015: no ledger creation, no dbt, no earlier migration,
        # no second marker, no verification of the base.
        assert db.calls == [f"sql:{_UPGRADE}"]
        assert db.rows[:_BASE_ROWS] == base_rows          # historical rows untouched
        assert db.rows[_BASE_ROWS] == (
            _BASE_ROWS + 1, _UPGRADE, _PLAN[_INDEX[_UPGRADE]].checksum)
        assert f"resuming at step {_BASE_ROWS + 1}: {_UPGRADE}" in lines
        assert lines[-1] == "bootstrap complete"
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.COMPLETE

    def test_015_is_applied_exactly_once(self):
        db = self._existing()
        _run(db)
        db.calls.clear()
        found, lines = _run(db)
        assert found is BootstrapState.COMPLETE
        assert db.mutations == []
        assert lines[-1] == "already initialized; nothing to do"
        assert [row[1] for row in db.rows].count(_UPGRADE) == 1

    # -- crash and restart ----------------------------------------------------

    def test_failed_015_on_an_existing_database_changes_nothing_and_retries(self):
        db = self._existing()
        before = (list(db.rows), set(db.sentinels))
        db.fail_at = _UPGRADE
        with pytest.raises(StepError, match="rolled back"):
            _run(db)
        assert (list(db.rows), set(db.sentinels)) == before
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.PARTIAL_VALID

        db.fail_at = None
        db.calls.clear()
        _run(db)
        assert db.calls == [f"sql:{_UPGRADE}"]
        assert classify(db.read_state(_PLAN), _PLAN).state is BootstrapState.COMPLETE

    def test_crash_between_the_marker_and_015_on_a_fresh_database_resumes_at_015(self):
        db = FakeDatabase()
        db.fail_at = _UPGRADE
        with pytest.raises(StepError):
            _run(db)
        assert [row[1] for row in db.rows] == _EXPECTED_ORDER[:_BASE_ROWS]
        db.fail_at = None
        db.calls.clear()
        found, _ = _run(db)
        assert found is BootstrapState.PARTIAL_VALID
        assert db.calls == [f"sql:{_UPGRADE}"]
        assert [row[1] for row in db.rows] == _EXPECTED_ORDER

    def test_failed_marker_never_lets_015_run(self):
        db = FakeDatabase(_state(_INDEX["complete"]))
        db.missing = ["SELECT:analytics.mart_trace_metrics:anomaly_detector"]
        with pytest.raises(StepError):
            _run(db)
        assert f"sql:{_UPGRADE}" not in db.calls

    # -- refusals -------------------------------------------------------------

    def test_changed_015_checksum_is_refused(self):
        rows = _rows_through(len(_PLAN))[:-1] + ((len(_PLAN), _UPGRADE, "0" * 64),)
        db = FakeDatabase(_state(len(_PLAN), ledger_rows=rows))
        with pytest.raises(
            IncompatibleError, match=f"checksum mismatch for recorded step {_UPGRADE}",
        ):
            _run(db)
        assert db.mutations == []

    def test_015_recorded_in_place_of_the_marker_is_refused(self):
        rows = _rows_through(_INDEX["complete"]) + (
            (_BASE_ROWS, _UPGRADE, _PLAN[_INDEX[_UPGRADE]].checksum),)
        db = FakeDatabase(_state(_BASE_ROWS, ledger_rows=rows))
        with pytest.raises(IncompatibleError, match="not the expected step complete"):
            _run(db)
        assert db.mutations == []

    def test_unknown_step_after_015_is_refused(self):
        rows = _rows_through(len(_PLAN)) + (
            (len(_PLAN) + 1, "016_something_new.sql", "0" * 64),)
        db = FakeDatabase(_state(len(_PLAN), ledger_rows=rows))
        with pytest.raises(IncompatibleError, match="more steps than the plan"):
            _run(db)
        assert db.mutations == []

    def test_unknown_migration_file_is_still_refused(self, tmp_path):
        for path in _MIGRATIONS.glob("*.sql"):
            (tmp_path / path.name).write_bytes(path.read_bytes())
        (tmp_path / "016_something_new.sql").write_text("SELECT 1;", encoding="utf-8")
        with pytest.raises(ConfigError, match="unknown to the bootstrap"):
            build_plan(tmp_path, _GRANTS)

    def test_missing_015_file_is_refused(self, tmp_path):
        for path in _MIGRATIONS.glob("*.sql"):
            if path.name != _UPGRADE:
                (tmp_path / path.name).write_bytes(path.read_bytes())
        with pytest.raises(ConfigError, match=f"missing: {_UPGRADE}"):
            build_plan(tmp_path, _GRANTS)

    def test_015_does_not_change_the_analytics_matrix(self):
        assert _INTENDED == _EXPECTED_GRANTS
        text = _PLAN[_INDEX[_UPGRADE]].path.read_text(encoding="utf-8")
        assert parse_analytics_grants(text) == frozenset()

    # -- through the real executor -------------------------------------------

    def test_existing_database_through_the_real_executor_applies_only_015(
        self, capsys, tmp_path,
    ):
        runner = SimulatedServer()
        runner.schema = runner.table = True
        runner.rows = list(_rows_through(_BASE_ROWS))
        runner.sentinels = set(_sentinels_through(_BASE_ROWS))
        env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"))
        assert bootstrap.main([], environ=env, runner=runner) == 0
        assert runner.writes == [_UPGRADE]
        assert [row[1] for row in runner.rows] == _EXPECTED_ORDER
        assert f"resuming at step {_BASE_ROWS + 1}: {_UPGRADE}" in capsys.readouterr().out

        runner.writes.clear()
        assert bootstrap.main([], environ=env, runner=runner) == 0
        assert runner.writes == []


class TestMain:

    def test_complete_database_exits_zero_and_writes_nothing(self, capsys):
        runner = _scripted(*_state_lines(_state(len(_PLAN))))
        assert bootstrap.main([], environ=_environ(), runner=runner) == 0
        out = capsys.readouterr().out
        assert "database state: COMPLETE" in out
        assert "already initialized; nothing to do" in out
        assert all("--single-transaction" not in argv for argv, _ in runner.calls)
        assert len(runner.calls) == 3

    def test_populated_database_without_ledger_exits_five_and_writes_nothing(self, capsys):
        legacy = DbState(sentinels_present=_sentinels_through(len(_PLAN)))
        runner = _scripted(*_state_lines(legacy))
        assert bootstrap.main([], environ=_environ(), runner=runner) == 5
        captured = capsys.readouterr()
        assert "database state: INCOMPATIBLE" in captured.out
        assert captured.err.startswith(
            "error: objects of the platform exist but there is no ledger:"
        )
        assert all("--single-transaction" not in argv for argv, _ in runner.calls)
        assert len(runner.calls) == 2

    def test_missing_configuration_exits_three_before_any_process(self, capsys):
        runner = _scripted("")
        env = _environ(ALERT_NOTIFIER_DB_PASSWORD=None)
        assert bootstrap.main([], environ=env, runner=runner) == 3
        assert runner.calls == []
        assert capsys.readouterr().err == (
            "error: environment variable ALERT_NOTIFIER_DB_PASSWORD is not set\n"
        )

    def test_unreachable_database_exits_four(self, capsys):
        def runner(argv, env, stdin, timeout):
            return ProcessResult(2, "", "psql: error: connection refused")

        assert bootstrap.main([], environ=_environ(), runner=runner) == 4
        assert "could not read the server's identity" in capsys.readouterr().err

    def test_failed_step_exits_six(self, capsys):
        base = _scripted(*_state_lines(_state(3)))

        def runner(argv, env, stdin, timeout):
            if "--single-transaction" in argv:
                return ProcessResult(3, "", "ERROR: relation does not exist")
            return base(argv, env, stdin, timeout)

        assert bootstrap.main([], environ=_environ(), runner=runner) == 6
        err = capsys.readouterr().err
        assert "step 003_create_trace_viewer_reader.sql failed and was rolled back" in err

    def test_unexpected_error_is_reported_by_type_only(self, capsys):
        def runner(argv, env, stdin, timeout):
            raise RuntimeError(f"boom {_ADMIN_SECRET}")

        assert bootstrap.main([], environ=_environ(), runner=runner) == 1
        assert capsys.readouterr().err == "error: internal: RuntimeError\n"

    def test_empty_database_end_to_end_through_the_real_executor(self, capsys, tmp_path):
        runner = SimulatedServer()
        env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"))
        assert bootstrap.main([], environ=env, runner=runner) == 0

        # The simulated server ends exactly as a complete database.
        assert classify(runner.state(), _PLAN).state is BootstrapState.COMPLETE
        assert [row[1] for row in runner.rows] == _EXPECTED_ORDER
        assert runner.writes == (
            ["ledger", "001_create_telemetry_spans.sql", "dbt", "dbt_run"]
            + _EXPECTED_ORDER[2:16] + ["complete", _UPGRADE]
        )
        out = capsys.readouterr()
        assert out.err == ""
        assert out.out.splitlines()[0] == "database state: EMPTY (no ledger and no objects)"
        assert out.out.splitlines()[-1] == "bootstrap complete"

        # A second run finds it complete and writes nothing.
        runner.writes.clear()
        assert bootstrap.main([], environ=env, runner=runner) == 0
        assert runner.writes == []
        assert "already initialized; nothing to do" in capsys.readouterr().out

    def test_no_output_ever_holds_a_password(self, capsys, tmp_path):
        runner = SimulatedServer()
        env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"))
        assert bootstrap.main([], environ=env, runner=runner) == 0
        captured = capsys.readouterr()
        for secret in _ALL_SECRETS:
            assert secret not in captured.out and secret not in captured.err
        assert len(runner.calls) > 20
        for argv, stdin in runner.calls:
            for secret in _ALL_SECRETS:
                assert all(secret not in a for a in argv) and secret not in (stdin or "")

    def test_failure_in_the_middle_then_resume_through_the_real_executor(
        self, capsys, tmp_path,
    ):
        runner = SimulatedServer(fail_on="010_create_rca_investigation_embeddings.sql")
        env = _environ(BOOTSTRAP_WORK_DIR=str(tmp_path / "work"))
        assert bootstrap.main([], environ=env, runner=runner) == 6
        assert [row[1] for row in runner.rows] == _EXPECTED_ORDER[:10]
        assert "extension:vector" not in runner.sentinels
        capsys.readouterr()

        runner.fail_on = None
        runner.writes.clear()
        assert bootstrap.main([], environ=env, runner=runner) == 0
        assert runner.writes == _EXPECTED_ORDER[10:16] + ["complete", _UPGRADE]
        assert "resuming at step 11: 010_create_rca_investigation_embeddings.sql" in (
            capsys.readouterr().out
        )

    def test_takes_no_option(self):
        with pytest.raises(SystemExit) as excinfo:
            bootstrap.main(["--force"], environ=_environ(), runner=_scripted(""))
        assert excinfo.value.code == 2

    def test_exit_codes(self):
        assert (
            bootstrap.EXIT_OK, bootstrap.EXIT_INTERNAL, bootstrap.EXIT_USAGE,
            bootstrap.EXIT_CONFIGURATION, bootstrap.EXIT_DATABASE,
            bootstrap.EXIT_INCOMPATIBLE, bootstrap.EXIT_STEP_FAILED,
        ) == (0, 1, 2, 3, 4, 5, 6)


# ---------------------------------------------------------------------------
# BS11  Module boundaries
# ---------------------------------------------------------------------------

class TestModuleBoundaries:

    def test_standard_library_only(self):
        tree = ast.parse(inspect.getsource(bootstrap))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module.split(".")[0])
        assert imported == {
            "__future__", "argparse", "hashlib", "os", "re", "shutil", "subprocess",
            "sys", "tempfile", "dataclasses", "enum", "pathlib", "typing",
        }

    def test_environment_is_never_printed(self):
        source = inspect.getsource(bootstrap)
        for word in ("print(os.environ", "print(env", "printenv", "pprint"):
            assert word not in source

    def test_no_destructive_statement_in_the_program(self):
        # Every statement text this program itself sends.
        statements = "\n".join([
            bootstrap._LEDGER_DDL,
            bootstrap._FACTS_SQL,
            bootstrap._LEDGER_ROWS_SQL,
            bootstrap.state_sql(_PLAN),
            bootstrap.grants_check_sql(parse_analytics_grants(_GRANTS_SQL)),
            bootstrap.ledger_insert_sql(1, "001_a.sql", "a" * 64),
        ])
        assert re.search(
            r"\b(DROP|TRUNCATE|DELETE|ALTER|REVOKE|UPDATE|GRANT)\b", statements,
            re.IGNORECASE,
        ) is None
        # The only objects it creates itself are the ledger schema and table.
        assert re.findall(r"\bCREATE (\w+)", statements) == ["SCHEMA", "TABLE"]

    def test_no_adoption_of_an_existing_database(self):
        source = inspect.getsource(bootstrap).lower()
        for word in ("--force", "--adopt", "--resume", "baseline"):
            assert word not in source


# ---------------------------------------------------------------------------
# BS12  dbt grant hooks do not need the role to exist
# ---------------------------------------------------------------------------
#
# On an empty database dbt runs before migration 005 creates anomaly_detector,
# and 005 grants on the tables dbt builds.  A hook that grants unconditionally
# makes that first run impossible.

_MACRO = _ANALYTICS / "macros" / "grant_select_if_role_exists.sql"
_HOOKED_MODELS = ("mart_trace_metrics", "mart_agent_metrics", "mart_retrieval_metrics")
_HOOK = "post_hook=\"{{ grant_select_if_role_exists(this, 'anomaly_detector') }}\""


def _model_text(name: str) -> str:
    (path,) = (_ANALYTICS / "models").rglob(f"{name}.sql")
    return path.read_text(encoding="utf-8")


def _macro_body() -> str:
    """The macro without its leading comment block."""
    text = _MACRO.read_text(encoding="utf-8")
    return text[text.index("{% macro"):]


class TestConditionalGrantHooks:

    @pytest.mark.parametrize("name", _HOOKED_MODELS)
    def test_the_three_marts_grant_through_the_macro(self, name):
        text = _model_text(name)
        assert text.count("post_hook") == 1
        assert _HOOK in text
        assert "materialized='table'" in text

    def test_no_model_grants_unconditionally(self):
        for path in (_ANALYTICS / "models").rglob("*.sql"):
            text = path.read_text(encoding="utf-8")
            assert re.search(r"\bGRANT\b", text, re.IGNORECASE) is None, path.name

    def test_only_those_three_models_have_a_hook(self):
        hooked = sorted(
            path.stem for path in (_ANALYTICS / "models").rglob("*.sql")
            if "hook" in path.read_text(encoding="utf-8")
        )
        assert hooked == sorted(_HOOKED_MODELS)

    def test_hooked_models_are_exactly_the_marts_migration_005_grants_on(self):
        (path,) = _MIGRATIONS.glob("005_*.sql")
        granted = {
            target.split(".", 1)[1]
            for privilege, target, role in parse_analytics_grants(
                path.read_text(encoding="utf-8")
            )
            if privilege == "SELECT" and role == "anomaly_detector"
            and target.startswith("analytics.mart_")
        }
        assert granted == set(_HOOKED_MODELS)

    def test_macro_checks_that_the_role_exists_before_granting(self):
        body = " ".join(_macro_body().split())
        assert (
            "IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{ role }}') THEN "
            "EXECUTE 'GRANT SELECT ON {{ relation }} TO {{ role }}'; END IF;"
        ) in body
        assert body.count("GRANT") == 1

    @pytest.mark.parametrize("word", [
        "CREATE", "PUBLIC", "EXCEPTION", "WITH GRANT OPTION", "ALL ", "ALTER", "DROP",
        "REVOKE", "INSERT", "UPDATE", "DELETE", "OWNER", "SUPERUSER",
    ])
    def test_macro_does_nothing_else(self, word):
        # In particular it never creates the role, never grants to PUBLIC, and
        # has no handler that would swallow an error.  Only the statement it
        # sends is examined, not the template code around it.
        body = _macro_body()
        statement = body[body.index("DO $grant$"):body.rindex("$grant$")]
        assert "BEGIN" in statement and "END IF;" in statement
        assert word not in statement.upper()

    def test_macro_accepts_only_a_plain_role_identifier(self):
        body = _macro_body()
        assert "modules.re.fullmatch('[a-z_][a-z0-9_]*', role)" in body
        assert "exceptions.raise_compiler_error" in body

    def test_macro_takes_the_relation_and_the_role(self):
        assert "{% macro grant_select_if_role_exists(relation, role) %}" in _macro_body()
        assert _macro_body().rstrip().endswith("{% endmacro %}")

    def test_the_only_macro_is_this_one(self):
        assert sorted(p.name for p in (_ANALYTICS / "macros").iterdir()) == [
            "grant_select_if_role_exists.sql",
        ]

    def test_bootstrap_image_copies_the_macros(self):
        dockerfile = (_REPO / "docker" / "bootstrap" / "Dockerfile").read_text(encoding="utf-8")
        assert "COPY analytics/macros analytics/macros" in dockerfile

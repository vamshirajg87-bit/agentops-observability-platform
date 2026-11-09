"""
scripts/tests/test_agentops_mvp_workers.py

Offline tests of the isolated worker project (B3J-420): docker/mvp-workers/compose.yml,
docker/workers/Dockerfile, docker/mvp-workers/detector_config.json and
scripts/agentops_mvp_workers.py.

Nothing real is ever run: the files are read as text or YAML, and every container command of the
script goes to a fake engine that records it.  No Docker, no database, no network, no process.

    W01  The Compose file: names, no published port, credential isolation
    W02  The worker image
    W03  The detector configuration
    W04  Compatibility of the detector's SQL with the generated telemetry (static)
    W05  The script: it can only address the isolated database
    W06  The script's behaviour on a fake engine
"""

from __future__ import annotations

import ast
import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentops_mvp_demo as demo  # noqa: E402
import agentops_mvp_workers as workers  # noqa: E402

_REPO = Path(workers.__file__).resolve().parents[1]
_COMPOSE = _REPO / "docker" / "mvp-workers" / "compose.yml"
_MVP_COMPOSE = _REPO / "docker" / "mvp" / "compose.yml"
_DOCKERFILE = _REPO / "docker" / "workers" / "Dockerfile"
_CONFIG = _REPO / "docker" / "mvp-workers" / "detector_config.json"
_CANARY = "LEAK-CANARY-9f8e7d6c5b4a-0123456789"
_NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)

#: sha256 of docker/mvp/compose.yml (line endings normalised to LF) as of B3J-424: the MVP stack's file is not edited
_MVP_COMPOSE_SHA256 = "2573c9f9bc20f177c03f531fadef86f16f6d2806733f046636094349f5e65f5d"

_EIGHT = ("POSTGRES_PASSWORD", "GF_DATASOURCE_AGENTOPS_PASSWORD", "TRACE_VIEWER_DB_PASSWORD",
          "ANOMALY_DETECTOR_DB_PASSWORD", "RCA_ANALYZER_DB_PASSWORD", "INCIDENT_RETRIEVAL_DB_PASSWORD",
          "ALERT_EVALUATOR_DB_PASSWORD", "ALERT_NOTIFIER_DB_PASSWORD")


def _load(path):
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _references(value) -> set[str]:
    """Every ${NAME...} substitution inside a loaded YAML value."""
    return set(re.findall(r"\$\{([A-Z0-9_]+)", json.dumps(value)))


# ---------------------------------------------------------------------------
# W01  The Compose file
# ---------------------------------------------------------------------------

class TestCompose:

    def test_project_network_and_volume_names(self):
        doc = _load(_COMPOSE)
        assert doc["name"] == workers.PROJECT_NAME == "agentops-mvp-workers"
        assert doc["networks"]["workers-net"]["name"] == workers.NETWORK_NAME == "agentops-mvp-workers-net"
        assert doc["volumes"]["postgres-data"]["name"] == workers.VOLUME_NAME == "agentops-mvp-workers-postgres-data"
        assert set(doc["networks"]) == {"workers-net"} and set(doc["volumes"]) == {"postgres-data"}

    def test_nothing_is_shared_with_the_mvp_stack(self):
        mine, theirs = _load(_COMPOSE), _load(_MVP_COMPOSE)
        assert mine["name"] != theirs["name"]
        assert {n["name"] for n in mine["volumes"].values()}.isdisjoint({n["name"] for n in theirs["volumes"].values()})
        assert not {n.get("name") for n in mine["networks"].values()} & {n.get("name") for n in theirs["networks"].values()}
        assert "agentops-mvp-postgres-data" not in _COMPOSE.read_text(encoding="utf-8").replace(
            "agentops-mvp-workers-postgres-data", "")

    def test_the_backend_services_publish_no_port_and_nothing_names_a_container(self):
        doc = _load(_COMPOSE)
        for name, service in doc["services"].items():
            assert "container_name" not in service and "image" not in service, name
            assert "network_mode" not in service and "privileged" not in service, name
            assert service["networks"] == ["workers-net"], name
            if name != "viewer":
                assert "ports" not in service and "expose" not in service, name

    def test_the_viewer_is_the_only_service_that_publishes_and_only_on_loopback_8001(self):
        doc = _load(_COMPOSE)
        published = {n: s["ports"] for n, s in doc["services"].items() if "ports" in s}
        assert published == {"viewer": ["127.0.0.1:8001:8000"]}
        assert "expose" not in doc["services"]["viewer"]
        # the MVP's own viewer keeps 8000; this one must never collide with it
        assert "127.0.0.1:8000:8000" in _MVP_COMPOSE.read_text(encoding="utf-8")
        assert not any(":8000:" in port for port in doc["services"]["viewer"]["ports"])

    def test_the_services_are_the_expected_ones(self):
        doc = _load(_COMPOSE)
        assert set(doc["services"]) == {"postgres", "db-bootstrap", "anomaly-detector", "rca-analyzer", "viewer"}

    def test_the_profiles_are_exactly_the_expected_ones(self):
        doc = _load(_COMPOSE)
        assert {n for n, s in doc["services"].items() if s.get("profiles") == ["workers"]} == {"anomaly-detector", "rca-analyzer"}
        assert {n for n, s in doc["services"].items() if s.get("profiles") == ["viewer"]} == {"viewer"}
        assert "profiles" not in doc["services"]["postgres"] and "profiles" not in doc["services"]["db-bootstrap"]

    def test_the_detector_gets_only_its_own_password(self):
        service = _load(_COMPOSE)["services"]["anomaly-detector"]
        assert _references(service) == {"ANOMALY_DETECTOR_DB_PASSWORD"}
        assert {k for k in service["environment"] if "PASSWORD" in k} == {"ANOMALY_DETECTOR_DB_PASSWORD"}

    def test_the_analyzer_gets_only_its_own_password(self):
        service = _load(_COMPOSE)["services"]["rca-analyzer"]
        assert _references(service) == {"RCA_ANALYZER_DB_PASSWORD"}
        assert {k for k in service["environment"] if "PASSWORD" in k} == {"RCA_ANALYZER_DB_PASSWORD"}

    def test_postgres_gets_only_the_owner_password(self):
        assert _references(_load(_COMPOSE)["services"]["postgres"]) == {"POSTGRES_PASSWORD"}

    def test_the_viewer_gets_only_its_own_password(self):
        service = _load(_COMPOSE)["services"]["viewer"]
        assert _references(service) == {"TRACE_VIEWER_DB_PASSWORD"}
        assert {k for k in service["environment"] if "PASSWORD" in k} == {"TRACE_VIEWER_DB_PASSWORD"}
        assert not _references(service) & (set(_EIGHT) - {"TRACE_VIEWER_DB_PASSWORD"})

    def test_only_the_one_shot_bootstrap_gets_all_eight(self):
        doc = _load(_COMPOSE)
        assert _references(doc["services"]["db-bootstrap"]) == set(_EIGHT)
        for name in ("postgres", "anomaly-detector", "rca-analyzer", "viewer"):
            assert len(_references(doc["services"][name])) == 1, name

    def test_no_env_file_and_no_mount_reaches_any_service(self):
        for name, service in _load(_COMPOSE)["services"].items():
            assert "env_file" not in service, name
            if name != "postgres":
                assert "volumes" not in service, name           # the workers see no host path and no credential file
        assert "--env-file" in _COMPOSE.read_text(encoding="utf-8")   # documented as the substitution source only

    def test_workers_and_viewer_are_hardened_and_never_restart(self):
        for name in ("anomaly-detector", "rca-analyzer", "viewer"):
            service = _load(_COMPOSE)["services"][name]
            assert service["restart"] == "no" and service["read_only"] is True
            assert service["cap_drop"] == ["ALL"] and "no-new-privileges:true" in service["security_opt"]
            assert service["tmpfs"] == ["/tmp"]

    def test_the_workers_and_viewer_wait_for_a_complete_bootstrap_and_need_nothing_else(self):
        for name in ("anomaly-detector", "rca-analyzer", "viewer"):
            depends = _load(_COMPOSE)["services"][name]["depends_on"]
            assert set(depends) == {"postgres", "db-bootstrap"}, name
            assert depends["postgres"]["condition"] == "service_healthy"
            assert depends["db-bootstrap"]["condition"] == "service_completed_successfully"

    def test_the_workers_connect_as_their_own_roles_to_the_isolated_database(self):
        doc = _load(_COMPOSE)["services"]
        assert doc["anomaly-detector"]["environment"]["ANOMALY_DETECTOR_DB_USER"] == "anomaly_detector"
        assert doc["rca-analyzer"]["environment"]["RCA_ANALYZER_DB_USER"] == "rca_analyzer"
        for name, prefix in (("anomaly-detector", "ANOMALY_DETECTOR"), ("rca-analyzer", "RCA_ANALYZER")):
            env = doc[name]["environment"]
            assert env[f"{prefix}_DB_HOST"] == "postgres" and env[f"{prefix}_DB_NAME"] == "agentops"

    def test_the_detector_uses_the_baked_in_configuration_and_the_analyzer_has_no_default_target(self):
        doc = _load(_COMPOSE)["services"]
        assert doc["anomaly-detector"]["command"] == ["--config", "/opt/agentops/config/detector_config.json"]
        assert doc["anomaly-detector"]["entrypoint"] == ["python", "main.py"]
        assert "command" not in doc["rca-analyzer"] and doc["rca-analyzer"]["entrypoint"] == ["python", "main.py"]

    def test_the_documented_commands_use_the_project_name_the_file_and_no_deps(self):
        text = _COMPOSE.read_text(encoding="utf-8")
        for line in re.findall(r"^#\s+docker compose .*$", text, re.M):
            assert "-p agentops-mvp-workers -f docker/mvp-workers/compose.yml" in line
        assert text.count("run --rm --no-deps") == 2
        assert text.count("--profile viewer up -d --build --no-deps viewer") == 1

    def test_the_viewer_is_built_from_the_existing_viewer_dockerfile_with_the_repository_context(self):
        service = _load(_COMPOSE)["services"]["viewer"]
        assert service["build"] == {"context": "../..", "dockerfile": "docker/trace-viewer/Dockerfile"}
        assert (_REPO / "docker" / "trace-viewer" / "Dockerfile").is_file() and "image" not in service
        # an unset tag means Compose names the image <project>-<service>: agentops-mvp-workers-viewer

    def test_the_viewer_connects_to_the_isolated_database_as_the_read_only_role(self):
        env = _load(_COMPOSE)["services"]["viewer"]["environment"]
        assert env == {
            "TRACE_VIEWER_DB_HOST": "postgres", "TRACE_VIEWER_DB_PORT": "5432", "TRACE_VIEWER_DB_NAME": "agentops",
            "TRACE_VIEWER_DB_USER": "trace_viewer_reader",
            "TRACE_VIEWER_DB_PASSWORD": "${TRACE_VIEWER_DB_PASSWORD:?TRACE_VIEWER_DB_PASSWORD must be set}"}

    def test_the_viewer_keeps_the_mvp_viewers_non_secret_settings_and_health_check(self):
        mine = _load(_COMPOSE)["services"]["viewer"]
        theirs = _load(_MVP_COMPOSE)["services"]["viewer"]
        assert mine["environment"] == theirs["environment"]
        assert mine["healthcheck"] == theirs["healthcheck"]
        assert "/api/health'" in mine["healthcheck"]["test"][-1] and "ready" not in mine["healthcheck"]["test"][-1]
        assert mine["build"]["dockerfile"] == theirs["build"]["dockerfile"]

    def test_the_viewer_is_on_the_isolated_network_only(self):
        doc = _load(_COMPOSE)
        assert doc["services"]["viewer"]["networks"] == ["workers-net"]
        assert doc["networks"]["workers-net"]["name"] == workers.NETWORK_NAME
        text = _COMPOSE.read_text(encoding="utf-8")
        assert "mvp-net" not in text.replace("agentops-mvp-workers-net", "") and "external" not in text

    def test_the_viewer_needs_no_kafka_detector_or_analyzer(self):
        doc = _load(_COMPOSE)
        assert set(doc["services"]["viewer"]["depends_on"]) == {"postgres", "db-bootstrap"}
        assert not {n for n in doc["services"] if "kafka" in n or "collector" in n}

    def test_the_original_mvp_compose_is_unchanged(self):
        import hashlib
        data = _MVP_COMPOSE.read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(data).hexdigest() == _MVP_COMPOSE_SHA256
        doc = _load(_MVP_COMPOSE)
        assert doc["name"] == "agentops-mvp" and set(doc["services"]) == {"postgres", "db-bootstrap", "viewer"}
        assert doc["services"]["viewer"]["ports"] == ["127.0.0.1:8000:8000"]
        assert "8001" not in data.decode("utf-8") and "mvp-workers" not in data.decode("utf-8")


# ---------------------------------------------------------------------------
# W02  The worker image
# ---------------------------------------------------------------------------

class TestImage:
    TEXT = _DOCKERFILE.read_text(encoding="utf-8")

    def test_psycopg_is_pinned_like_the_viewers(self):
        wanted = re.search(r"psycopg\[binary\][^\s]*", (_REPO / "trace-viewer" / "requirements.txt").read_text(encoding="utf-8"))
        assert wanted and f'"{wanted.group(0)}"' in self.TEXT

    def test_it_copies_the_workers_source_and_the_configuration(self):
        for source in re.findall(r"^COPY (\S+) ", self.TEXT, re.M):
            assert list(_REPO.glob(source)), source
        assert "anomaly-detector/detector" in self.TEXT and "rca-analyzer/*.py" in self.TEXT

    def test_every_local_import_of_the_workers_is_in_the_image(self):
        for folder in ("anomaly-detector", "rca-analyzer"):
            modules = {p.stem for p in (_REPO / folder).glob("*.py")}
            for path in (_REPO / folder).glob("*.py"):
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    names = [a.name.split(".")[0] for a in node.names] if isinstance(node, ast.Import) else \
                        [node.module.split(".")[0]] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
                    for name in names:
                        local = (_REPO / folder / name).exists() or (_REPO / folder / f"{name}.py").exists()
                        if local:
                            assert name in modules or (_REPO / folder / name).is_dir(), (path.name, name)

    def test_it_runs_unprivileged_and_holds_no_credential(self):
        assert re.search(r"^USER worker$", self.TEXT, re.M)
        assert "PASSWORD" not in self.TEXT.replace("It holds no credential", "") and "ENV " in self.TEXT
        assert not re.search(r"^ENV .*(PASSWORD|SECRET|TOKEN)", self.TEXT, re.M)

    def test_the_build_context_does_not_exclude_what_it_copies(self):
        ignore = (_REPO / ".dockerignore").read_text(encoding="utf-8")
        for name in ("anomaly-detector", "rca-analyzer", "docker/mvp-workers"):
            assert not re.search(rf"^/?{re.escape(name)}/?\s*$", ignore, re.M), name


# ---------------------------------------------------------------------------
# W03  The detector configuration
# ---------------------------------------------------------------------------

class TestDetectorConfig:

    def _run_config(self):
        path = str(_REPO / "anomaly-detector")
        if path not in sys.path:
            sys.path.append(path)
        import run_config
        return run_config

    def test_it_loads_with_the_real_loader(self):
        config = self._run_config().load_config(_CONFIG)
        groups = {(g.signal_path, g.service_name, g.operation_name) for g in config.groups}
        assert groups == {("tool_latency", "agentops-demo-app", ""), ("tool_failure", "agentops-demo-app", "")}   # "" = no operation

    def test_the_lookback_covers_the_latest_start_the_seed_command_allows(self):
        config = self._run_config().load_config(_CONFIG)
        assert config.initial_lookback_hours > workers.HOURS_BACK_MAX
        assert config.initial_lookback_hours >= 24

    def test_only_signals_that_read_the_staging_view_are_configured(self):
        assert {g["signal_path"] for g in json.loads(_CONFIG.read_text(encoding="utf-8"))["groups"]} == {"tool_latency", "tool_failure"}


# ---------------------------------------------------------------------------
# W04  The detector's SQL against the generated telemetry (static)
# ---------------------------------------------------------------------------

def _sql_constant(name: str) -> str:
    tree = ast.parse((_REPO / "anomaly-detector" / "telemetry_queries.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(name)


def _selected(sql: str) -> list[str]:
    return [c.strip() for c in sql.split("FROM")[0].replace("SELECT", "").split(",") if c.strip()]


def _view_columns() -> set[str]:
    text = (_REPO / "analytics" / "models" / "staging" / "stg_telemetry_spans.sql").read_text(encoding="utf-8")
    body = text.split("select", 1)[1].split("from {{", 1)[0]
    body = re.sub(r"--[^\n]*", "", body)
    columns = set()
    for item in (part.strip() for part in body.split(",")):
        if not item:
            continue
        alias = re.search(r"\bas\s+(\w+)\s*$", item, re.S)
        columns.add(alias.group(1) if alias else item.split()[-1])
    return columns


def _table_columns() -> set[str]:
    text = (_REPO / "storage-consumer" / "migrations" / "001_create_telemetry_spans.sql").read_text(encoding="utf-8")
    body = text.split("CREATE TABLE telemetry_spans (", 1)[1].split("\n);", 1)[0]
    return {m.group(1) for m in re.finditer(r"^\s{4}([a-z_]+)\s+[A-Z]", body, re.M)}


class TestSqlCompatibility:

    def test_the_generated_rows_match_the_table_exactly(self):
        assert set(demo.COLUMNS["telemetry_spans"]) == _table_columns() - {"id"}

    @pytest.mark.parametrize("name", ["_SQL_TOOL_LATENCY", "_SQL_TOOL_FAILURE"])
    def test_every_selected_column_is_a_column_of_the_staging_view(self, name):
        sql = _sql_constant(name)
        assert "FROM analytics.stg_telemetry_spans" in sql
        assert set(_selected(sql)) <= _view_columns()

    def test_the_view_reads_the_table_the_generator_fills(self):
        text = (_REPO / "analytics" / "models" / "staging" / "stg_telemetry_spans.sql").read_text(encoding="utf-8")
        assert "source('agentops', 'telemetry_spans')" in text
        sources = (_REPO / "analytics" / "models" / "staging" / "_sources.yml").read_text(encoding="utf-8")
        assert "telemetry_spans" in sources and "schema" in sources
        assert "is_error_span" in _view_columns() and "status_code = 'ERROR'" in text

    def test_the_view_does_not_filter_or_drop_rows(self):
        text = (_REPO / "analytics" / "models" / "staging" / "stg_telemetry_spans.sql").read_text(encoding="utf-8").lower()
        assert " where " not in text and "group by" not in text and "limit" not in text and "distinct" not in text

    def test_the_tool_queries_filter_only_on_things_the_generated_rows_satisfy(self):
        for name in ("_SQL_TOOL_LATENCY", "_SQL_TOOL_FAILURE"):
            sql = _sql_constant(name)
            assert "WHERE span_name    = 'tool.execute'" in sql and "service_name = %(service_name)s" in sql
            assert "is_error_span =" not in sql and "tool_name" not in sql.split("WHERE")[1]
        rows = demo.spans_only_rows(_NOW - timedelta(hours=6))
        tools = [r for r in rows if r["span_name"] == "tool.execute"]
        assert len(tools) == 38 and {r["service_name"] for r in tools} == {"agentops-demo-app"}
        errors = [r for r in tools if r["status_code"] == "ERROR"]
        assert len(errors) == 1 and errors[0]["error_type"] == demo.ERROR_TYPE and errors[0]["tool_name"] is None

    def test_timestamps_fall_inside_the_first_run_window_for_every_allowed_start(self):
        for back in (workers.HOURS_BACK_MIN, workers.HOURS_BACK_DEFAULT, workers.HOURS_BACK_MAX):
            first, last = demo.spans_only_extent(workers.base_time_for(_NOW, back))
            assert _NOW - timedelta(hours=24) <= first and last <= _NOW, back

    def test_the_trace_ids_fit_the_char_columns(self):
        assert all(len(r["trace_id"]) == 32 and len(r["span_id"]) == 16 for r in demo.spans_only_rows(_NOW))


# ---------------------------------------------------------------------------
# W05  The script can only address the isolated database
# ---------------------------------------------------------------------------

class TestScriptScope:
    SOURCE = Path(workers.__file__).read_text(encoding="utf-8")

    def test_the_names_are_disjoint_from_the_protected_ones(self):
        assert not {workers.PROJECT_NAME, workers.POSTGRES_CONTAINER, workers.VOLUME_NAME, workers.NETWORK_NAME} \
            & set(workers.PROTECTED_NAMES)
        assert workers.POSTGRES_CONTAINER == f"{workers.PROJECT_NAME}-postgres-1"

    def test_the_mvp_container_name_appears_only_in_the_protected_list(self):
        assert self.SOURCE.count('"agentops-mvp-postgres-1"') == 1

    def test_every_issued_command_names_only_the_isolated_container(self):
        for argv in (workers.container_facts_argv("docker"), workers.psql_write_argv("docker"),
                     workers.psql_read_argv("docker", workers.COUNTS_SQL)):
            assert argv.count(workers.POSTGRES_CONTAINER) == 1
            assert argv[1] in ("inspect", "exec")
            # "agentops" itself is the database and owner role inside the isolated container, so it is not a name to forbid
            assert not any(p in argv for p in ("agentops-mvp-postgres-1", "agentops-mvp", "agentops-postgres"))

    def test_reads_are_read_only_sessions_and_only_fixed_queries(self):
        argv = workers.psql_read_argv("docker", workers.TELEMETRY_COUNT_SQL)
        assert "PGOPTIONS=-cdefault_transaction_read_only=on" in argv
        with pytest.raises(workers.WorkersError):
            workers.psql_read_argv("docker", "DELETE FROM public.telemetry_spans")
        with pytest.raises(workers.WorkersError):
            workers.psql_read_argv("docker", workers.TELEMETRY_COUNT_SQL + "; DROP TABLE x")

    def test_the_one_write_is_a_single_transaction_from_standard_input(self):
        argv = workers.psql_write_argv("docker")
        assert "--single-transaction" in argv and argv[-2:] == ["-f", "-"] and "-c" not in argv
        assert "ON_ERROR_STOP=1" in argv

    def test_no_shell_no_credential_file_no_compose_command(self):
        tree = ast.parse(self.SOURCE)
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert node.value.value is False
        assert "credentials.env" not in self.SOURCE and "--env-file" not in self.SOURCE.replace("--env-file <file>", "")
        constants = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert not constants & {"up", "down", "build", "kill", "rm", "stop", "start", "pull", "prune", "volume", "network"}

    def test_only_telemetry_spans_is_ever_written(self):
        sql = demo.spans_only_sql(_NOW)
        assert set(re.findall(r"public\.(\w+)", sql)) == {"telemetry_spans"}

    def test_the_environment_given_to_the_container_tool_is_small(self):
        env = workers.child_environment({"PATH": "p", "DOCKER_HOST": "tcp://x", "COMPOSE_PROJECT_NAME": "agentops-mvp",
                                         "POSTGRES_PASSWORD": _CANARY, "SystemRoot": "r"})
        assert env == {"PATH": "p", "SystemRoot": "r"}

    @pytest.mark.parametrize("value", [0, 3, 21, -1, True, 6.0, "6", None])
    def test_hours_back_is_bounded(self, value):
        with pytest.raises(workers.WorkersError):
            workers.hours_back(value)

    def test_the_base_time_is_before_now_and_naive_clocks_are_refused(self):
        assert workers.base_time_for(_NOW, 6) == _NOW - timedelta(hours=6)
        with pytest.raises(workers.WorkersError):
            workers.base_time_for(datetime(2026, 10, 26, 12, 0), 6)


# ---------------------------------------------------------------------------
# W06  Behaviour on a fake engine
# ---------------------------------------------------------------------------

class FakeEngine:
    """Answers the script's commands from a small model and records every one of them."""

    def __init__(self, *, facts=None, ledger=None, spans=0, anomalies=(), write_code=0, after_spans=None,
                 raise_on=None, leak=False):
        self.calls: list[tuple[list[str], bytes, dict]] = []
        self.facts = facts if facts is not None else (workers._EXPECTED_FACTS + "|{}")
        self.ledger = ledger if ledger is not None else "\n".join(f"{i + 1}|{s}" for i, s in enumerate(demo.EXPECTED_LEDGER_STEPS))
        self.spans, self.anomalies, self.write_code = spans, list(anomalies), write_code
        self.after_spans = after_spans if after_spans is not None else demo.spans_only_expected_count()
        self.raise_on, self.leak, self.written = raise_on, leak, False

    def __call__(self, argv, env, input_bytes):
        self.calls.append((list(argv), input_bytes, dict(env)))
        verb = argv[1]
        if self.raise_on == verb:
            raise OSError(_CANARY)
        if verb == "inspect":
            return workers.CommandResult(0, self.facts.encode())
        if "-f" in argv:
            self.written = True
            return workers.CommandResult(self.write_code, (_CANARY if self.leak else "").encode())
        sql = argv[argv.index("-c") + 1]
        if sql == demo.LEDGER_SQL:
            return workers.CommandResult(0, self.ledger.encode())
        if sql == workers.TELEMETRY_COUNT_SQL:
            return workers.CommandResult(0, str(self.after_spans if self.written else self.spans).encode())
        if sql == workers.COUNTS_SQL:
            return workers.CommandResult(0, f"{self.spans}|{len(self.anomalies)}|0|0".encode())
        if sql == workers.ANOMALY_IDS_SQL:
            return workers.CommandResult(0, "\n".join(self.anomalies).encode())
        raise AssertionError(sql)

    def writes(self):
        return [c for c in self.calls if "-f" in c[0]]


def _run(argv, engine, environ=None):
    out, err = io.StringIO(), io.StringIO()
    code = workers.main(argv, environ=environ if environ is not None else {"PATH": "p", "POSTGRES_PASSWORD": _CANARY},
                        run=engine, now=lambda: _NOW, docker="docker", out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class TestBehaviour:

    def test_plan_prints_the_sequence_and_runs_nothing(self):
        engine = FakeEngine()
        code, out, _ = _run(["plan"], engine)
        assert code == 0 and engine.calls == []
        assert "NOTHING IS RUN" in out and "--no-deps anomaly-detector" in out and "rca-analyzer --anomaly-id" in out

    def test_status_reports_counts_and_anomaly_ids_read_only(self):
        ids = ["a" * 64, "b" * 64]
        engine = FakeEngine(spans=264, anomalies=ids)
        code, out, _ = _run(["status"], engine)
        assert code == 0 and "telemetry_spans 264, anomaly_events 2" in out and ("a" * 64) in out
        assert not engine.writes() and all(c[0][1] in ("inspect", "exec") for c in engine.calls)

    def test_a_dry_run_reads_but_never_writes(self):
        engine = FakeEngine()
        code, out, _ = _run(["seed-spans"], engine)
        assert code == 0 and "dry run" in out and "264 spans" in out and not engine.writes()

    def test_execute_writes_the_spans_only_script_once_and_verifies_it(self):
        engine = FakeEngine()
        code, out, _ = _run(["seed-spans", "--execute"], engine)
        assert code == 0 and "wrote 264 spans" in out
        (argv, stdin, _env), = engine.writes()
        assert argv == workers.psql_write_argv("docker")
        assert stdin == demo.spans_only_sql(_NOW - timedelta(hours=6)).encode()
        assert set(re.findall(rb"public\.(\w+)", stdin)) == {b"telemetry_spans"}

    def test_hours_back_moves_the_dataset(self):
        engine = FakeEngine()
        _run(["seed-spans", "--execute", "--hours-back", "10"], engine)
        assert engine.writes()[0][1] == demo.spans_only_sql(_NOW - timedelta(hours=10)).encode()

    @pytest.mark.parametrize("argv", [["seed-spans", "--hours-back", "3"], ["seed-spans", "--hours-back", "21"],
                                      ["seed-spans", "--hours-back", "x"], ["bogus"], []])
    def test_bad_usage_exits_2_and_touches_nothing(self, argv):
        engine = FakeEngine()
        code, _, _ = _run(argv, engine)
        assert code == 2 and engine.calls == []

    @pytest.mark.parametrize("facts", [
        "agentops-mvp|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{}",
        "agentops-mvp-workers|postgres|true|volume:agentops-mvp-postgres-data:/var/lib/postgresql/data;|{}",
        "agentops-mvp-workers|postgres|true|volume:agentops-mvp-workers-postgres-data:/var/lib/postgresql/data;|"
        '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]}',
        "agentops-mvp-workers|postgres|false|volume:agentops-mvp-workers-postgres-data:/var/lib/postgresql/data;|{}",
        "agentops-mvp-workers|viewer|true|volume:agentops-mvp-workers-postgres-data:/var/lib/postgresql/data;|{}",
        "", "garbage",
    ])
    def test_any_other_container_is_refused_before_anything_else(self, facts):
        engine = FakeEngine(facts=facts)
        for argv in (["status"], ["seed-spans", "--execute"]):
            code, _, err = _run(argv, engine)
            assert code == 1 and "isolated worker project" in err
        assert [c[0][1] for c in engine.calls] == ["inspect", "inspect"] and not engine.writes()

    def test_a_wrong_ledger_is_refused(self):
        engine = FakeEngine(ledger="1|001_create_telemetry_spans.sql")
        code, _, err = _run(["seed-spans", "--execute"], engine)
        assert code == 1 and "ledger" in err and not engine.writes()

    @pytest.mark.parametrize("rows", [1, 96, 264, 5000])
    def test_a_nonempty_telemetry_table_is_never_written(self, rows):
        engine = FakeEngine(spans=rows)
        code, _, err = _run(["seed-spans", "--execute"], engine)
        assert code == 1 and f"already holds {rows} rows" in err and not engine.writes()

    def test_a_failed_write_reports_a_rollback_and_cleans_nothing_up(self):
        engine = FakeEngine(write_code=3, leak=True)
        code, out, err = _run(["seed-spans", "--execute"], engine)
        assert code == 1 and "rolled back" in err and _CANARY not in out + err
        assert engine.calls[-1][0] == workers.psql_write_argv("docker")      # nothing was issued after the failure

    def test_a_wrong_count_after_the_write_is_reported(self):
        engine = FakeEngine(after_spans=100)
        code, _, err = _run(["seed-spans", "--execute"], engine)
        assert code == 1 and "100 rows, not 264" in err

    @pytest.mark.parametrize("verb", ["inspect", "exec"])
    def test_a_failing_command_never_leaks_its_output(self, verb):
        engine = FakeEngine(raise_on=verb)
        code, out, err = _run(["status"], engine)
        assert code == 1 and _CANARY not in out + err

    def test_docker_host_set_refuses_without_running_anything(self):
        engine = FakeEngine()
        code, _, err = _run(["status"], engine, environ={"PATH": "p", "DOCKER_HOST": "tcp://10.0.0.5:2375"})
        assert code == 2 and "DOCKER_HOST" in err and engine.calls == []

    def test_no_credential_or_engine_variable_reaches_the_container_tool(self):
        engine = FakeEngine()
        _run(["status"], engine, environ={"PATH": "p", "POSTGRES_PASSWORD": _CANARY, "COMPOSE_PROJECT_NAME": "agentops-mvp",
                                           "DOCKER_CONTEXT": "x"})
        for argv, stdin, env in engine.calls:
            assert env == {"PATH": "p"} and _CANARY not in " ".join(argv)

    def test_every_issued_command_addresses_only_the_isolated_container(self):
        engine = FakeEngine(spans=0)
        _run(["seed-spans", "--execute"], engine)
        for argv, _, _ in engine.calls:
            assert argv[0] == "docker" and argv[1] in ("inspect", "exec")
            assert argv.count(workers.POSTGRES_CONTAINER) == 1
            assert "agentops-mvp-postgres-1" not in argv

"""
db-bootstrap/tests/unit/test_compose_contract.py

Contract tests for the Compose integration of the database bootstrap
(Phase 14.2).

They read docker-compose.yml, .env.example, .gitignore and the two override
files as text.  No Docker, no database, no network, and no YAML library: a
service block is cut out by its indentation, which is enough for the checks
made here.

Test inventory:
    CC01  No credential is written in the Compose file
    CC02  PostgreSQL: password source and TCP health check
    CC03  db-bootstrap service
    CC04  Grafana waits for the bootstrap and requires its administrator password
    CC05  .env.example
    CC06  Legacy-database override example and ignore rule
    CC07  Validation override
    CC08  analytics-refresh service
    CC09  Published ports of the main file are bound to the loopback address
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import bootstrap


_REPO = Path(__file__).resolve().parents[3]
_COMPOSE = _REPO / "docker-compose.yml"
_ENV_EXAMPLE = _REPO / ".env.example"
_GITIGNORE = _REPO / ".gitignore"
_LEGACY = _REPO / "docker" / "compose.legacy-database.example.yml"
_VALIDATION = _REPO / "docker" / "bootstrap" / "compose.main-validation.override.yml"

_ROLE_VARIABLES = [
    "GF_DATASOURCE_AGENTOPS_PASSWORD",
    "TRACE_VIEWER_DB_PASSWORD",
    "ANOMALY_DETECTOR_DB_PASSWORD",
    "RCA_ANALYZER_DB_PASSWORD",
    "INCIDENT_RETRIEVAL_DB_PASSWORD",
    "ALERT_EVALUATOR_DB_PASSWORD",
    "ALERT_NOTIFIER_DB_PASSWORD",
]
# The Grafana administrator login is a Grafana account, not a database role, so it is
# not one of the role variables above; it follows them in .env.example.
_GRAFANA_ADMIN_VARIABLE = "GF_SECURITY_ADMIN_PASSWORD"
_REQUIRED_VARIABLES = ["POSTGRES_PASSWORD", *_ROLE_VARIABLES, _GRAFANA_ADMIN_VARIABLE]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _code(text: str) -> str:
    """The text without comment lines and trailing comments."""
    lines = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(re.sub(r"\s+#.*$", "", line))
    return "\n".join(lines)


def _service(text: str, name: str) -> str:
    """The block of one service of a Compose file, comments removed."""
    lines = _code(text).splitlines()
    try:
        start = lines.index(f"  {name}:")
    except ValueError:
        raise AssertionError(f"service {name} not found") from None
    block = []
    for line in lines[start + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= 2:
            break
        block.append(line)
    return "\n".join(block)


def _section(block: str, key: str) -> str:
    """The lines nested under `key:` inside a service block."""
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"{key}:" or line.strip().startswith(f"{key}: "):
            indent = len(line) - len(line.lstrip())
            nested = []
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                nested.append(following)
            return "\n".join([line, *nested])
    return ""


_COMPOSE_TEXT = _text(_COMPOSE)
_POSTGRES = _service(_COMPOSE_TEXT, "postgres")
_BOOTSTRAP = _service(_COMPOSE_TEXT, "db-bootstrap")
_GRAFANA = _service(_COMPOSE_TEXT, "grafana")


def _environment(block: str) -> dict[str, str]:
    values = {}
    for line in _section(block, "environment").splitlines()[1:]:
        key, separator, value = line.strip().partition(":")
        if separator:
            values[key.strip()] = value.strip()
    return values


# ---------------------------------------------------------------------------
# CC01  No credential is written in the Compose file
# ---------------------------------------------------------------------------

class TestNoCredentialInCompose:

    def test_every_password_value_is_a_variable_reference(self):
        found = re.findall(r"^\s*([A-Z_]*PASSWORD[A-Z_]*):\s*(.*)$", _code(_COMPOSE_TEXT), re.M)
        # postgres 1, db-bootstrap 8, analytics-refresh 1, grafana 2
        assert len(found) == 12
        for name, value in found:
            assert re.fullmatch(r"\$\{[A-Z_]+(:[?-][^}]*)?\}", value), name

    def test_no_literal_admin_password(self):
        assert re.search(
            r"^\s*POSTGRES_PASSWORD:\s*[^$\s]", _code(_COMPOSE_TEXT), re.M,
        ) is None
        assert _environment(_POSTGRES)["POSTGRES_PASSWORD"].startswith("${POSTGRES_PASSWORD:?")

    def test_no_default_value_stands_in_for_a_password(self):
        # ":-" may only supply the EMPTY string, which the bootstrap rejects.
        for default in re.findall(r"\$\{[A-Z_]*PASSWORD[A-Z_]*:-([^}]*)\}", _COMPOSE_TEXT):
            assert default == ""

    def test_no_credential_bearing_url(self):
        assert re.search(r"://[^/\s:@]+:[^/\s:@]+@", _COMPOSE_TEXT) is None


# ---------------------------------------------------------------------------
# CC02  PostgreSQL
# ---------------------------------------------------------------------------

class TestPostgres:

    def test_password_comes_from_the_required_variable(self):
        value = _environment(_POSTGRES)["POSTGRES_PASSWORD"]
        assert re.fullmatch(r"\$\{POSTGRES_PASSWORD:\?[^}]+\}", value)

    def test_database_and_owner_are_the_names_the_migrations_use(self):
        environment = _environment(_POSTGRES)
        assert environment["POSTGRES_DB"] == bootstrap.REQUIRED_DATABASE
        assert environment["POSTGRES_USER"] == bootstrap.REQUIRED_OWNER

    def test_health_check_is_over_tcp(self):
        health = _section(_POSTGRES, "healthcheck")
        assert (
            'test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -p 5432 -U agentops -d agentops"]'
        ) in health

    def test_health_check_timing(self):
        health = _section(_POSTGRES, "healthcheck")
        for line in ("interval: 3s", "timeout: 3s", "retries: 20", "start_period: 10s"):
            assert line in health

    def test_data_volume_is_unchanged(self):
        assert "- postgres-data:/var/lib/postgresql/data" in _POSTGRES
        assert "container_name: agentops-postgres" in _POSTGRES


# ---------------------------------------------------------------------------
# CC03  db-bootstrap
# ---------------------------------------------------------------------------

class TestBootstrapService:

    def test_built_from_the_bootstrap_dockerfile_at_the_repository_root(self):
        build = _section(_BOOTSTRAP, "build")
        assert "context: ." in build
        assert "dockerfile: docker/bootstrap/Dockerfile" in build
        assert (_REPO / "docker" / "bootstrap" / "Dockerfile").is_file()

    def test_waits_for_a_healthy_postgres(self):
        depends = " ".join(_section(_BOOTSTRAP, "depends_on").split())
        assert depends == "depends_on: postgres: condition: service_healthy"

    def test_restart_is_disabled(self):
        assert 'restart: "no"' in _BOOTSTRAP

    @pytest.mark.parametrize("key", [
        "ports", "container_name", "volumes", "command", "entrypoint", "profiles",
        "privileged", "env_file",
    ])
    def test_has_none_of(self, key):
        assert re.search(rf"^\s*{key}:", _BOOTSTRAP, re.M) is None

    def test_connection_target(self):
        environment = _environment(_BOOTSTRAP)
        assert environment["BOOTSTRAP_DB_HOST"] == "postgres"
        assert environment["BOOTSTRAP_DB_PORT"] == '"5432"'
        assert environment["BOOTSTRAP_DB_NAME"] == "agentops"
        assert environment["BOOTSTRAP_DB_ADMIN_USER"] == "agentops"

    def test_admin_password_is_the_postgres_password_variable(self):
        value = _environment(_BOOTSTRAP)["BOOTSTRAP_DB_ADMIN_PASSWORD"]
        assert re.fullmatch(r"\$\{POSTGRES_PASSWORD:\?[^}]+\}", value)
        assert "BOOTSTRAP_DB_ADMIN_PASSWORD" not in _text(_ENV_EXAMPLE)

    @pytest.mark.parametrize("name", _ROLE_VARIABLES)
    def test_every_role_password_is_passed_under_its_own_name(self, name):
        value = _environment(_BOOTSTRAP)[name]
        assert re.fullmatch(rf"\$\{{{name}(:[?-][^}}]*)?\}}", value)

    def test_role_variables_are_exactly_those_the_bootstrap_reads(self):
        passed = {
            name for name in _environment(_BOOTSTRAP)
            if name.endswith("PASSWORD") and name != "BOOTSTRAP_DB_ADMIN_PASSWORD"
        }
        assert passed == set(bootstrap.ROLE_PASSWORD_ENV.values()) == set(_ROLE_VARIABLES)

    def test_environment_holds_nothing_else(self):
        assert set(_environment(_BOOTSTRAP)) == {
            "BOOTSTRAP_DB_HOST", "BOOTSTRAP_DB_PORT", "BOOTSTRAP_DB_NAME",
            "BOOTSTRAP_DB_ADMIN_USER", "BOOTSTRAP_DB_ADMIN_PASSWORD", *_ROLE_VARIABLES,
        }

    def test_on_the_platform_network(self):
        assert "- agentops-net" in _section(_BOOTSTRAP, "networks")


# ---------------------------------------------------------------------------
# CC04  Grafana
# ---------------------------------------------------------------------------

class TestGrafana:

    def test_waits_for_postgres_and_for_the_bootstrap(self):
        depends = " ".join(_section(_GRAFANA, "depends_on").split())
        assert depends == (
            "depends_on: postgres: condition: service_healthy "
            "db-bootstrap: condition: service_completed_successfully"
        )

    def test_password_is_required(self):
        value = _environment(_GRAFANA)["GF_DATASOURCE_AGENTOPS_PASSWORD"]
        assert re.fullmatch(r"\$\{GF_DATASOURCE_AGENTOPS_PASSWORD:\?[^}]+\}", value)

    def test_gets_only_its_own_two_passwords(self):
        assert list(_environment(_GRAFANA)) == [
            "GF_DATASOURCE_AGENTOPS_PASSWORD", "GF_SECURITY_ADMIN_PASSWORD",
        ]

    def test_nothing_else_about_grafana_changed(self):
        assert "container_name: agentops-grafana" in _GRAFANA
        assert '- "127.0.0.1:3000:3000"' in _GRAFANA
        assert "image: grafana/grafana:13.2.2" in _GRAFANA

    def test_only_grafana_depends_on_the_bootstrap_so_far(self):
        waiting = [
            name for name in ("kafka", "otel-collector", "kafka-init", "postgres", "grafana")
            if "db-bootstrap" in _service(_COMPOSE_TEXT, name)
        ]
        assert waiting == ["grafana"]

    def test_administrator_password_is_required_from_the_environment(self):
        value = _environment(_GRAFANA)["GF_SECURITY_ADMIN_PASSWORD"]
        assert re.fullmatch(r"\$\{GF_SECURITY_ADMIN_PASSWORD:\?[^}]+\}", value)

    def test_administrator_and_datasource_passwords_are_separate_variables(self):
        environment = _environment(_GRAFANA)
        assert "GF_DATASOURCE_AGENTOPS_PASSWORD" not in environment["GF_SECURITY_ADMIN_PASSWORD"]
        assert "GF_SECURITY_ADMIN_PASSWORD" not in environment["GF_DATASOURCE_AGENTOPS_PASSWORD"]
        assert re.fullmatch(
            r"\$\{GF_DATASOURCE_AGENTOPS_PASSWORD:\?[^}]+\}",
            environment["GF_DATASOURCE_AGENTOPS_PASSWORD"],
        )

    def test_port_stays_bound_to_the_loopback_address(self):
        mappings = re.findall(r'^\s*- ("[^"]*")\s*$', _section(_GRAFANA, "ports"), re.M)
        assert mappings == ['"127.0.0.1:3000:3000"']

    def test_no_tracked_configuration_opens_access_or_removes_the_administrator(self):
        forbidden = (
            "GF_AUTH_ANONYMOUS", "auth.anonymous", "GF_AUTH_DISABLE_LOGIN_FORM",
            "GF_SECURITY_DISABLE_INITIAL_ADMIN_CREATION", "disable_initial_admin_creation",
        )
        # Only configuration Grafana itself reads: its Compose service and the provisioning
        # and settings files.  Documentation, the dashboards (their JSON is panel content)
        # and unrelated files are not scanned.
        grafana_dir = _REPO / "grafana"
        configuration = sorted(
            path for path in grafana_dir.rglob("*")
            if path.is_file() and path.suffix in (".yml", ".yaml", ".ini")
            and path.relative_to(grafana_dir).parts[0] != "dashboards"
        )
        assert configuration, "no Grafana configuration file was found to scan"
        texts = [_GRAFANA] + [path.read_text(encoding="utf-8") for path in configuration]
        for text in texts:
            for name in forbidden:
                assert name.lower() not in text.lower(), name


# ---------------------------------------------------------------------------
# CC05  .env.example
# ---------------------------------------------------------------------------

def _assignments(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, separator, value = line.partition("=")
            assert separator, line
            values[name.strip()] = value
    return values


class TestEnvExample:

    def test_names_exactly_the_required_variables(self):
        assert list(_assignments(_text(_ENV_EXAMPLE))) == _REQUIRED_VARIABLES

    def test_every_value_is_empty(self):
        assert set(_assignments(_text(_ENV_EXAMPLE)).values()) == {""}

    def test_an_unedited_copy_can_start_nothing(self):
        # Compose stops on the two required variables; the bootstrap refuses
        # every empty one.
        environ = {
            "BOOTSTRAP_DB_HOST": "postgres", "BOOTSTRAP_DB_PORT": "5432",
            "BOOTSTRAP_DB_NAME": "agentops", "BOOTSTRAP_DB_ADMIN_USER": "agentops",
            "BOOTSTRAP_DB_ADMIN_PASSWORD": _assignments(_text(_ENV_EXAMPLE))["POSTGRES_PASSWORD"],
            **{name: _assignments(_text(_ENV_EXAMPLE))[name] for name in _ROLE_VARIABLES},
        }
        with pytest.raises(bootstrap.ConfigError, match="is not set"):
            bootstrap.load_config(environ)

    def test_every_variable_compose_requires_is_documented(self):
        referenced = set(re.findall(r"\$\{([A-Z_]+)", _COMPOSE_TEXT))
        assert referenced == set(_REQUIRED_VARIABLES)
        assert referenced <= set(_assignments(_text(_ENV_EXAMPLE)))

    def test_no_secret_like_content(self):
        text = _text(_ENV_EXAMPLE)
        assert re.search(r"://[^/\s:@]+:[^/\s:@]+@", text) is None
        # No assignment has anything after its "=" on the same line.
        assert re.search(r"(?i)(password|token|secret|key)[ \t]*=[ \t]*\S", text) is None
        assert text.isascii()

    def test_later_variables_are_documented_but_not_active(self):
        text = _text(_ENV_EXAMPLE)
        for name in ("PG_PASSWORD", "DBT_PG_PASSWORD", "ALERTING_E2E_ADMIN_PASSWORD",
                     "INCIDENT_RETRIEVAL_E2E_ADMIN_PASSWORD"):
            assert name in text
            assert name not in _assignments(text)

    def test_post_dbt_rule_is_stated(self):
        assert "post_dbt_grants.sql" in _text(_ENV_EXAMPLE)

    def test_grafana_administrator_password_has_an_empty_placeholder(self):
        assignments = _assignments(_text(_ENV_EXAMPLE))
        assert assignments["GF_SECURITY_ADMIN_PASSWORD"] == ""
        assert "GF_SECURITY_ADMIN_PASSWORD" not in _ROLE_VARIABLES


# ---------------------------------------------------------------------------
# CC06  Legacy-database override example and ignore rule
# ---------------------------------------------------------------------------

class TestLegacyOverride:

    def test_local_override_file_is_ignored_by_git(self):
        assert "docker-compose.override.yml" in _text(_GITIGNORE).splitlines()

    def test_no_local_override_is_tracked_or_shipped(self):
        assert not (_REPO / "docker-compose.override.yml").exists()

    def test_tracked_example_exists_outside_the_auto_loaded_name(self):
        assert _LEGACY.is_file()
        assert _LEGACY.name != "docker-compose.override.yml"
        assert _LEGACY.parent != _REPO

    def test_example_disables_the_bootstrap_through_a_profile(self):
        block = _service(_text(_LEGACY), "db-bootstrap")
        assert re.fullmatch(r'\s*profiles: \["[a-z-]+"\]', block.strip("\n"))
        # The profile is not one the main file ever activates.
        (profile,) = re.findall(r'profiles: \["([a-z-]+)"\]', block)
        assert profile not in _COMPOSE_TEXT

    def test_example_makes_grafana_wait_for_postgres_only(self):
        depends = " ".join(_section(_service(_text(_LEGACY), "grafana"), "depends_on").split())
        assert depends == "depends_on: !override postgres: condition: service_healthy"

    def test_example_touches_nothing_else(self):
        code = _code(_text(_LEGACY))
        services = re.findall(r"^  ([a-z-]+):$", code, re.M)
        assert services == ["db-bootstrap", "grafana"]
        for word in ("PASSWORD", "environment", "volumes", "image", "ports", "command"):
            assert word not in code

    def test_example_says_what_it_is_for(self):
        text = _text(_LEGACY)
        for phrase in (
            "TEMPORARY", "no bootstrap", "DO NOT use it for a new clone",
            "must never be committed", "Remove docker-compose.override.yml",
        ):
            assert phrase in " ".join(text.split()), phrase


# ---------------------------------------------------------------------------
# CC07  Validation override
# ---------------------------------------------------------------------------

class TestValidationOverride:

    def test_exists_and_is_marked_validation_only(self):
        assert _VALIDATION.is_file()
        assert "VALIDATION ONLY" in _text(_VALIDATION)

    @pytest.mark.parametrize("name", ["postgres", "grafana"])
    def test_removes_fixed_name_and_published_ports(self, name):
        block = _service(_text(_VALIDATION), name)
        assert "container_name: !reset null" in block
        assert "ports: !reset []" in block

    def test_touches_only_those_two_services(self):
        code = _code(_text(_VALIDATION))
        assert re.findall(r"^  ([a-z-]+):$", code, re.M) == ["postgres", "grafana"]
        for word in ("PASSWORD", "volumes", "external", "environment", "image"):
            assert word not in code

    def test_bootstrap_needs_no_override_because_it_has_no_fixed_name(self):
        assert "container_name" not in _BOOTSTRAP and "ports" not in _BOOTSTRAP


# ---------------------------------------------------------------------------
# CC08  analytics-refresh
# ---------------------------------------------------------------------------

_REFRESH = _service(_COMPOSE_TEXT, "analytics-refresh")
_REFRESH_PROGRAM = "/opt/agentops/db-bootstrap/analytics_refresh.py"


class TestAnalyticsRefreshService:

    def test_belongs_to_its_own_profile_so_up_does_not_start_it(self):
        assert 'profiles: ["analytics-refresh"]' in _REFRESH
        # No other service is in a profile, and nothing activates this one.
        assert _code(_COMPOSE_TEXT).count("profiles:") == 1
        assert "COMPOSE_PROFILES" not in _COMPOSE_TEXT
        assert "COMPOSE_PROFILES" not in _text(_ENV_EXAMPLE)

    def test_no_service_depends_on_it(self):
        for name in ("kafka", "otel-collector", "kafka-init", "postgres", "db-bootstrap",
                     "grafana"):
            assert "analytics-refresh" not in _service(_COMPOSE_TEXT, name)

    def test_built_exactly_like_the_bootstrap_image(self):
        assert _section(_REFRESH, "build") == _section(_BOOTSTRAP, "build")

    def test_entry_point_is_the_refresh_program(self):
        assert f'entrypoint: ["python", "{_REFRESH_PROGRAM}"]' in _REFRESH
        assert (_REPO / "db-bootstrap" / "analytics_refresh.py").is_file()

    def test_waits_for_a_healthy_postgres_only(self):
        depends = " ".join(_section(_REFRESH, "depends_on").split())
        assert depends == "depends_on: postgres: condition: service_healthy"
        assert "db-bootstrap" not in _REFRESH.replace(_REFRESH_PROGRAM, "")

    def test_restart_is_disabled(self):
        assert 'restart: "no"' in _REFRESH

    @pytest.mark.parametrize("key", [
        "ports", "container_name", "volumes", "command", "privileged", "env_file",
        "image",
    ])
    def test_has_none_of(self, key):
        assert re.search(rf"^\s*{key}:", _REFRESH, re.M) is None

    def test_connection_target_is_the_bootstrap_one(self):
        refresh, boot = _environment(_REFRESH), _environment(_BOOTSTRAP)
        for name in ("BOOTSTRAP_DB_HOST", "BOOTSTRAP_DB_PORT", "BOOTSTRAP_DB_NAME",
                     "BOOTSTRAP_DB_ADMIN_USER", "BOOTSTRAP_DB_ADMIN_PASSWORD"):
            assert refresh[name] == boot[name]

    def test_owner_password_is_the_only_credential(self):
        environment = _environment(_REFRESH)
        assert set(environment) == {
            "BOOTSTRAP_DB_HOST", "BOOTSTRAP_DB_PORT", "BOOTSTRAP_DB_NAME",
            "BOOTSTRAP_DB_ADMIN_USER", "BOOTSTRAP_DB_ADMIN_PASSWORD",
        }
        assert re.fullmatch(
            r"\$\{POSTGRES_PASSWORD:\?[^}]+\}", environment["BOOTSTRAP_DB_ADMIN_PASSWORD"],
        )

    @pytest.mark.parametrize("name", _ROLE_VARIABLES)
    def test_no_application_role_password_is_passed(self, name):
        assert name not in _REFRESH

    def test_given_environment_is_enough_for_the_refresh_and_not_for_the_bootstrap(self):
        environ = {
            "BOOTSTRAP_DB_HOST": "postgres", "BOOTSTRAP_DB_PORT": "5432",
            "BOOTSTRAP_DB_NAME": "agentops", "BOOTSTRAP_DB_ADMIN_USER": "agentops",
            "BOOTSTRAP_DB_ADMIN_PASSWORD": "TESTONLY-owner-51c7",
        }
        assert set(environ) == set(_environment(_REFRESH))
        config = bootstrap.load_config(environ, require_role_passwords=False)
        assert dict(config.role_passwords) == {}
        with pytest.raises(bootstrap.ConfigError, match="is not set"):
            bootstrap.load_config(environ)

    def test_on_the_platform_network(self):
        assert "- agentops-net" in _section(_REFRESH, "networks")

    def test_needs_no_validation_override(self):
        assert "analytics-refresh" not in _code(_text(_VALIDATION))
        assert "analytics-refresh" not in _code(_text(_LEGACY))

    def test_command_is_documented_and_direct_dbt_is_discouraged(self):
        text = " ".join(_text(_ENV_EXAMPLE).replace("#", " ").split())
        assert "docker compose run --rm analytics-refresh" in text
        assert "Do not run dbt directly against a platform database" in text
        assert "docker compose run --rm analytics-refresh" in _COMPOSE_TEXT


# ---------------------------------------------------------------------------
# CC09  Published ports of the main file
# ---------------------------------------------------------------------------

# Every host port the main file publishes, with the exact mapping it must use.
_LOOPBACK_PORTS = {
    "kafka": ['"127.0.0.1:9092:9092"'],
    "otel-collector": ['"127.0.0.1:4317:4317"', '"127.0.0.1:4318:4318"'],
    "postgres": ['"127.0.0.1:5432:5432"'],
    "grafana": ['"127.0.0.1:3000:3000"'],
}


class TestPublishedPorts:

    def test_all_five_published_ports_are_bound_to_the_loopback_address(self):
        found = {
            name: re.findall(
                r'^\s*- ("[^"]*")\s*$', _section(_service(_COMPOSE_TEXT, name), "ports"), re.M,
            )
            for name in _LOOPBACK_PORTS
        }
        assert found == _LOOPBACK_PORTS


# ---------------------------------------------------------------------------
# CC10  OpenTelemetry Collector debug exporter
# ---------------------------------------------------------------------------

_COLLECTOR_CONFIG = _REPO / "collector" / "otel-collector-config.yaml"


class TestCollectorDebugExporter:
    """Static text checks of the collector configuration; the collector is not run."""

    def _config(self) -> str:
        return _code(_text(_COLLECTOR_CONFIG))

    def test_collector_config_file_exists(self):
        assert _COLLECTOR_CONFIG.is_file()

    def test_debug_exporter_uses_basic_verbosity(self):
        debug = _section(_section(self._config(), "exporters"), "debug")
        assert re.findall(r"^\s*verbosity:\s*(\S+)\s*$", debug, re.M) == ["basic"]

    def test_detailed_verbosity_is_not_configured(self):
        assert not re.search(r"verbosity:\s*detailed", self._config())

    def test_traces_pipeline_keeps_debug_and_kafka_exporters(self):
        traces = _section(_section(self._config(), "pipelines"), "traces")
        assert re.findall(r"^\s*exporters:\s*\[(.*)\]\s*$", traces, re.M) == ["debug, kafka"]

    def test_kafka_exporter_settings_are_unchanged(self):
        kafka = _section(_section(self._config(), "exporters"), "kafka")
        assert "- agentops-kafka:29092" in kafka
        assert "topic: agentops.telemetry.otlp.traces" in kafka
        assert "encoding: otlp_proto" in kafka
        assert "partition_traces_by_id: true" in kafka

    def test_otlp_receiver_keeps_grpc_and_http_endpoints(self):
        otlp = _section(_section(self._config(), "receivers"), "otlp")
        assert "endpoint: 0.0.0.0:4317" in _section(otlp, "grpc")
        assert "endpoint: 0.0.0.0:4318" in _section(otlp, "http")

    def test_no_processors_are_configured(self):
        config = self._config()
        assert not re.search(r"^\s*processors:", config, re.M)

    def test_collector_config_is_mounted_read_only(self):
        volumes = _section(_service(_COMPOSE_TEXT, "otel-collector"), "volumes")
        assert (
            "- ./collector/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro"
            in volumes
        )

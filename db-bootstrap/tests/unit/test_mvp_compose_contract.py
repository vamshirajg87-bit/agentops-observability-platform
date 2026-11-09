"""
db-bootstrap/tests/unit/test_mvp_compose_contract.py

Static contract tests for docker/mvp/compose.yml, the dedicated fresh-database
stack of the AgentOps MVP viewer (Stage 1 skeleton).

The Compose file is read as text.  No Docker, no database, no network and no
required YAML library: like the other Compose contract tests, a service block is cut
out by its indentation.  One extra structural test uses PyYAML when it is installed
and is skipped otherwise.

Test inventory:
    MV01  Dedicated project identity, exactly three services, no container names
    MV02  Separate data volume; no reference to any other stack or volume
    MV03  PostgreSQL: image build, no published port, scram, health check
    MV04  Credentials: required variables, no defaults, no literals, no trust
    MV05  Bootstrap: image, ordering, migration 015 reachable, variables complete
    MV06  Viewer: image, loopback-only binding, hardening, health check, ordering
    MV07  Network, restart and override rules; nothing destructive is defined
    MV08  Nothing outside the authorized scope was created (no env file)
    MV09  Structure checked with a YAML parser (skipped without PyYAML)
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

import bootstrap

_REPO = Path(__file__).resolve().parents[3]
_COMPOSE = _REPO / "docker" / "mvp" / "compose.yml"
_MVP_DIR = _COMPOSE.parent

_ROLE_VARIABLES = [
    "GF_DATASOURCE_AGENTOPS_PASSWORD",
    "TRACE_VIEWER_DB_PASSWORD",
    "ANOMALY_DETECTOR_DB_PASSWORD",
    "RCA_ANALYZER_DB_PASSWORD",
    "INCIDENT_RETRIEVAL_DB_PASSWORD",
    "ALERT_EVALUATOR_DB_PASSWORD",
    "ALERT_NOTIFIER_DB_PASSWORD",
]
_REQUIRED_VARIABLES = ["POSTGRES_PASSWORD", *_ROLE_VARIABLES]


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


def _service_names(code: str) -> list[str]:
    lines = code.splitlines()
    start = lines.index("services:")
    names = []
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith(" "):
            break
        match = re.fullmatch(r"  ([a-z][a-z0-9-]*):", line)
        if match:
            names.append(match.group(1))
    return names


def _service(code: str, name: str) -> str:
    """The block of one service, comments removed."""
    lines = code.splitlines()
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
    """The lines nested under `key:` inside a block (the key line included)."""
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


def _environment(block: str) -> dict[str, str]:
    values = {}
    for line in _section(block, "environment").splitlines()[1:]:
        key, separator, value = line.strip().partition(":")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _scalar(block: str, key: str) -> str | None:
    match = re.search(rf"^\s{{4}}{re.escape(key)}:\s*(.+?)\s*$", block, re.M)
    return match.group(1) if match else None


def _top(code: str, key: str) -> str:
    """The lines nested under a top-level key (volumes, networks), key line included."""
    lines = code.splitlines()
    start = lines.index(f"{key}:")
    nested = []
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith(" "):
            break
        nested.append(line)
    return "\n".join([lines[start], *nested])


def _list_items(section: str) -> list[str]:
    return [line.strip()[2:].strip().strip('"') for line in section.splitlines()[1:] if line.strip().startswith("- ")]


TEXT = _text(_COMPOSE)
CODE = _code(TEXT)
POSTGRES = _service(CODE, "postgres")
BOOTSTRAP = _service(CODE, "db-bootstrap")
VIEWER = _service(CODE, "viewer")


# ---------------------------------------------------------------------------
# MV01  Project identity, services, container names
# ---------------------------------------------------------------------------

class TestIdentity:

    def test_dedicated_project_name(self):
        assert re.search(r"^name: agentops-mvp$", CODE, re.M)
        assert len(re.findall(r"^name:", CODE, re.M)) == 1

    def test_exactly_the_three_services(self):
        assert _service_names(CODE) == ["postgres", "db-bootstrap", "viewer"]

    def test_no_container_name_anywhere(self):
        assert "container_name" not in CODE

    def test_stands_alone(self):
        for key in ("extends:", "include:", "profiles:", "x-"):
            assert key not in CODE, key
        assert not re.search(r"^\s*-?\s*(\.\./)?docker-compose[^\s]*\.ya?ml", CODE, re.M)

    def test_no_image_tag_is_set(self):
        # Without "image:", Compose names each built image after the project and service,
        # so no tag of another stack can be reused or overwritten.
        assert not re.search(r"^\s+image:", CODE, re.M)


# ---------------------------------------------------------------------------
# MV02  Volume and references to other stacks
# ---------------------------------------------------------------------------

class TestVolumeAndReferences:

    def test_volume_has_the_dedicated_name(self):
        volumes = _top(CODE, "volumes")
        assert "  postgres-data:" in volumes
        assert re.search(r"^\s{4}name: agentops-mvp-postgres-data$", volumes, re.M)

    def test_volume_is_project_owned_not_external(self):
        assert "external" not in CODE
        assert 'agentops.mvp: "true"' in CODE

    def test_only_postgres_mounts_it_at_the_data_directory(self):
        assert _list_items(_section(POSTGRES, "volumes")) == ["postgres-data:/var/lib/postgresql/data"]
        assert _section(BOOTSTRAP, "volumes") == ""
        assert _section(VIEWER, "volumes") == ""
        assert len(re.findall(r"postgres-data:/", CODE)) == 1

    @pytest.mark.parametrize("forbidden", [
        "agentops_postgres-data",        # the other PostgreSQL data volume
        "agentops-postgres",             # the other PostgreSQL container
        "legacy-demo",                   # the other demo workflow
        "agentops-legacy",
        "docker-compose.yml",            # the main Compose file
        "compose.pipeline",
        "compose.trace-viewer",
        "grafana/",                      # the Grafana image
        "agentops-grafana",
        "kafka",
    ])
    def test_no_reference_to_another_stack(self, forbidden):
        assert forbidden not in TEXT.lower(), forbidden

    def test_the_volume_name_appears_and_is_not_a_legacy_name(self):
        assert TEXT.count("agentops-mvp-postgres-data") >= 1
        assert re.findall(r"name: (\S*postgres\S*)", CODE) == ["agentops-mvp-postgres-data"]


# ---------------------------------------------------------------------------
# MV03  PostgreSQL
# ---------------------------------------------------------------------------

class TestPostgres:

    def test_built_from_the_project_postgres_dockerfile(self):
        build = _section(POSTGRES, "build")
        assert "context: ../.." in build
        assert "dockerfile: docker/postgres/Dockerfile" in build
        assert (_REPO / "docker" / "postgres" / "Dockerfile").is_file()
        assert (_MVP_DIR / "../.." / "docker" / "postgres" / "Dockerfile").resolve().is_file()

    def test_publishes_no_port_of_any_kind(self):
        for key in ("ports:", "expose:", "network_mode:"):
            assert key not in POSTGRES, key
        assert "5432:" not in CODE.replace('"5432"', "").replace("PORT: ", "")

    def test_database_and_owner_are_the_names_the_migrations_use(self):
        env = _environment(POSTGRES)
        assert env["POSTGRES_DB"] == bootstrap.REQUIRED_DATABASE == "agentops"
        assert env["POSTGRES_USER"] == bootstrap.REQUIRED_OWNER == "agentops"

    def test_password_comes_from_the_required_variable(self):
        env = _environment(POSTGRES)
        assert env["POSTGRES_PASSWORD"] == "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"

    def test_tcp_connections_use_scram_not_the_trust_default(self):
        env = _environment(POSTGRES)
        assert env["POSTGRES_INITDB_ARGS"] == '"--auth-host=scram-sha-256"'
        assert "POSTGRES_HOST_AUTH_METHOD" not in CODE
        assert "trust" not in CODE.lower()

    def test_health_check_is_over_tcp_and_bounded(self):
        health = _section(POSTGRES, "healthcheck")
        assert 'test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -p 5432 -U agentops -d agentops"]' in health
        interval = int(re.search(r"interval: (\d+)s", health).group(1))
        timeout = int(re.search(r"timeout: (\d+)s", health).group(1))
        retries = int(re.search(r"retries: (\d+)", health).group(1))
        start = int(re.search(r"start_period: (\d+)s", health).group(1))
        assert (interval, timeout) == (3, 3)
        assert 1 <= retries <= 30
        assert start + retries * (interval + timeout) <= 180  # worst case, seconds

    def test_on_the_project_network_only(self):
        assert _list_items(_section(POSTGRES, "networks")) == ["mvp-net"]


# ---------------------------------------------------------------------------
# MV04  Credentials
# ---------------------------------------------------------------------------

class TestCredentials:

    def test_every_password_value_is_a_required_variable_reference(self):
        for block in (POSTGRES, BOOTSTRAP, VIEWER):
            for key, value in _environment(block).items():
                if "PASSWORD" in key:
                    assert re.fullmatch(r"\$\{[A-Z_]+:\?[A-Za-z_ ]+\}", value), (key, value)

    def test_no_password_variable_has_a_default(self):
        assert ":-" not in CODE
        assert not re.search(r"\$\{[A-Z_]+-", CODE)

    def test_each_reference_names_its_own_variable(self):
        for block in (POSTGRES, BOOTSTRAP, VIEWER):
            for key, value in _environment(block).items():
                match = re.fullmatch(r"\$\{([A-Z_]+):\?([A-Z_]+) must be set\}", value)
                if match:
                    assert match.group(1) == match.group(2)
                    assert key in {match.group(1), "BOOTSTRAP_DB_ADMIN_PASSWORD"}

    def test_no_literal_password_or_credential_bearing_url(self):
        for key, value in {**_environment(POSTGRES), **_environment(BOOTSTRAP), **_environment(VIEWER)}.items():
            if "PASSWORD" in key:
                assert value.startswith("${"), key
        assert not re.search(r"://[^\s/:@]+:[^\s/@]+@", CODE)
        assert not re.search(r"(?i)\b(secret|token|api[_-]?key)\b\s*:", CODE)

    def test_no_placeholder_or_example_value(self):
        for word in ("changeme", "change-me", "password123", "example", "placeholder", "secret", "demo-unused"):
            assert word not in CODE.lower(), word

    def test_no_trust_authentication_is_configured(self):
        assert "trust" not in CODE.lower()
        assert "POSTGRES_HOST_AUTH_METHOD" not in TEXT
        assert "pg_hba" not in TEXT.lower()


# ---------------------------------------------------------------------------
# MV05  Bootstrap
# ---------------------------------------------------------------------------

class TestBootstrap:

    def test_reuses_the_bootstrap_dockerfile_at_the_repository_root(self):
        build = _section(BOOTSTRAP, "build")
        assert "context: ../.." in build
        assert "dockerfile: docker/bootstrap/Dockerfile" in build
        assert (_REPO / "docker" / "bootstrap" / "Dockerfile").is_file()

    def test_waits_for_a_healthy_postgres(self):
        depends = _section(BOOTSTRAP, "depends_on")
        assert "postgres:" in depends and "condition: service_healthy" in depends

    def test_one_shot_and_not_restarted(self):
        assert _scalar(BOOTSTRAP, "restart") == '"no"'
        for key in ("command:", "entrypoint:", "ports:", "volumes:", "privileged:"):
            assert key not in BOOTSTRAP, key

    def test_connection_target_is_the_project_database(self):
        env = _environment(BOOTSTRAP)
        assert env["BOOTSTRAP_DB_HOST"] == "postgres"
        assert env["BOOTSTRAP_DB_PORT"] == '"5432"'
        assert env["BOOTSTRAP_DB_NAME"] == "agentops"
        assert env["BOOTSTRAP_DB_ADMIN_USER"] == "agentops"
        assert env["BOOTSTRAP_DB_ADMIN_PASSWORD"] == "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"

    def test_every_role_password_the_bootstrap_requires_is_supplied(self):
        env = _environment(BOOTSTRAP)
        required = set(bootstrap.ROLE_PASSWORD_ENV.values())
        assert required == set(_ROLE_VARIABLES)
        assert required <= set(env)
        for name in required:
            assert env[name] == f"${{{name}:?{name} must be set}}", name

    def test_exactly_the_documented_variables_are_used(self):
        used = set(re.findall(r"\$\{([A-Z_]+):\?", CODE))
        assert used == set(_REQUIRED_VARIABLES)
        header = TEXT[:TEXT.index("name: agentops-mvp")]
        for name in _REQUIRED_VARIABLES:
            assert name in header, name

    def test_migration_015_is_part_of_what_the_bootstrap_applies(self):
        name = "015_grant_trace_viewer_anomaly_rca_read.sql"
        assert name in bootstrap.MIGRATION_FILES
        assert (_REPO / "storage-consumer" / "migrations" / name).is_file()
        dockerfile = _text(_REPO / "docker" / "bootstrap" / "Dockerfile")
        assert "COPY storage-consumer/migrations storage-consumer/migrations" in dockerfile
        assert bootstrap.MIGRATION_FILES[-1] == name  # the post-marker upgrade, after 014


# ---------------------------------------------------------------------------
# MV06  Viewer
# ---------------------------------------------------------------------------

class TestViewer:

    def test_reuses_the_trace_viewer_dockerfile(self):
        build = _section(VIEWER, "build")
        assert "context: ../.." in build
        assert "dockerfile: docker/trace-viewer/Dockerfile" in build
        dockerfile = _text(_REPO / "docker" / "trace-viewer" / "Dockerfile")
        assert re.search(r"^USER viewer$", dockerfile, re.M)  # non-root

    def test_only_published_port_is_loopback_8000(self):
        assert _list_items(_section(VIEWER, "ports")) == ["127.0.0.1:8000:8000"]
        published = re.findall(r"^\s+- \"?([0-9.:]+:[0-9]+)\"?$", CODE, re.M)
        assert published == ["127.0.0.1:8000:8000"]
        assert not re.search(r"0\.0\.0\.0|\[::\]", CODE)

    def test_database_connection_uses_the_read_only_role_and_a_required_password(self):
        env = _environment(VIEWER)
        assert env["TRACE_VIEWER_DB_HOST"] == "postgres"
        assert env["TRACE_VIEWER_DB_PORT"] == '"5432"'
        assert env["TRACE_VIEWER_DB_NAME"] == "agentops"
        assert env["TRACE_VIEWER_DB_USER"] == "trace_viewer_reader"
        assert env["TRACE_VIEWER_DB_PASSWORD"] == "${TRACE_VIEWER_DB_PASSWORD:?TRACE_VIEWER_DB_PASSWORD must be set}"
        assert set(env) == {"TRACE_VIEWER_DB_HOST", "TRACE_VIEWER_DB_PORT", "TRACE_VIEWER_DB_NAME",
                            "TRACE_VIEWER_DB_USER", "TRACE_VIEWER_DB_PASSWORD"}

    def test_waits_for_postgres_and_for_the_bootstrap_to_finish_successfully(self):
        depends = _section(VIEWER, "depends_on")
        assert re.search(r"postgres:\n\s+condition: service_healthy", depends)
        assert re.search(r"db-bootstrap:\n\s+condition: service_completed_successfully", depends)

    def test_security_restrictions(self):
        assert _scalar(VIEWER, "read_only") == "true"
        assert _list_items(_section(VIEWER, "tmpfs")) == ["/tmp"]
        assert _list_items(_section(VIEWER, "cap_drop")) == ["ALL"]
        assert _list_items(_section(VIEWER, "security_opt")) == ["no-new-privileges:true"]
        for key in ("privileged:", "cap_add:", "user:", "pid:", "ipc:", "network_mode:", "devices:",
                    "volumes:", "volumes_from:", "sysctls:", "extra_hosts:", "userns_mode:"):
            assert key not in VIEWER, key

    def test_health_check_uses_the_database_free_route_and_is_bounded(self):
        health = _section(VIEWER, "healthcheck")
        assert "http://127.0.0.1:8000/api/health" in health
        assert 'test: ["CMD", "python", "-c",' in health
        interval = int(re.search(r"interval: (\d+)s", health).group(1))
        timeout = int(re.search(r"timeout: (\d+)s", health).group(1))
        retries = int(re.search(r"retries: (\d+)", health).group(1))
        start = int(re.search(r"start_period: (\d+)s", health).group(1))
        assert 1 <= retries <= 10
        assert start + retries * (interval + timeout) <= 180

    def test_not_restarted_automatically(self):
        assert _scalar(VIEWER, "restart") == '"no"'


# ---------------------------------------------------------------------------
# MV07  Network, restart policy, overrides, nothing destructive
# ---------------------------------------------------------------------------

class TestProjectScope:

    def test_one_private_bridge_network_owned_by_the_project(self):
        networks = _top(CODE, "networks")
        assert "  mvp-net:" in networks and "driver: bridge" in networks
        assert "external" not in networks and "name:" not in networks
        assert "internal: true" not in networks  # a published port needs a routable network

    def test_every_service_joins_only_that_network(self):
        for block in (POSTGRES, BOOTSTRAP, VIEWER):
            assert _list_items(_section(block, "networks")) == ["mvp-net"]

    def test_no_service_has_a_restart_policy_other_than_no(self):
        assert re.findall(r"^\s+restart:\s*(.+)$", CODE, re.M) == ['"no"', '"no"', '"no"']

    def test_no_command_or_entrypoint_override_anywhere(self):
        for key in ("command:", "entrypoint:", "privileged:", "init:", "pull_policy:"):
            assert key not in CODE, key

    def test_nothing_that_deletes_or_resets_data_is_defined(self):
        lowered = CODE.lower()
        for word in ("down -v", "--volumes", "volume rm", "prune", "rm -rf", "dropdb", "drop database",
                     "drop schema", "truncate", "reset", "initdb --force"):
            assert word not in lowered, word
        # a data volume, not a bind mount of a host directory
        assert not re.search(r"^\s+- [./~][^\s]*:/", CODE, re.M)

    def test_no_secrets_or_host_files_are_mounted(self):
        for block in (POSTGRES, BOOTSTRAP, VIEWER):
            assert "/var/run/docker.sock" not in block
            assert "env_file" not in block
        assert "env_file" not in CODE


# ---------------------------------------------------------------------------
# MV08  Scope: nothing else was created
# ---------------------------------------------------------------------------

class TestScope:

    def test_the_mvp_directory_holds_only_the_compose_file(self):
        assert sorted(p.name for p in _MVP_DIR.iterdir()) == ["compose.yml"]

    def test_no_env_file_exists_for_the_stack(self):
        # only the files that already existed: the ignored local .env and the template
        assert {p.name for p in _REPO.glob(".env*")} <= {".env", ".env.example"}
        assert list(_REPO.glob("mvp.env*")) == [] and list(_REPO.glob("*.mvp")) == []
        assert not (_REPO / ".env.mvp").exists()
        assert not any(_MVP_DIR.glob("*env*"))

    def test_docker_build_context_excludes_environment_files(self):
        ignore = _text(_REPO / ".dockerignore")
        assert re.search(r"^\.env$", ignore, re.M) and re.search(r"^\.env\.\*$", ignore, re.M)


# ---------------------------------------------------------------------------
# MV09  Structure, with a YAML parser when one is installed
# ---------------------------------------------------------------------------

def test_structure_with_a_yaml_parser():
    if os.environ.get("CI", "").lower() in ("true", "1"):
        import yaml        # in CI the parser is required (uvicorn[standard] installs PyYAML); never skip silently
    else:
        yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(TEXT)
    assert data["name"] == "agentops-mvp"
    assert list(data["services"]) == ["postgres", "db-bootstrap", "viewer"]
    assert data["volumes"]["postgres-data"]["name"] == "agentops-mvp-postgres-data"
    assert data["networks"]["mvp-net"] == {"driver": "bridge"}
    for service in data["services"].values():
        assert "container_name" not in service and "image" not in service and service["restart"] == "no"
        assert service["networks"] == ["mvp-net"]
    assert "ports" not in data["services"]["postgres"] and "ports" not in data["services"]["db-bootstrap"]
    assert data["services"]["viewer"]["ports"] == ["127.0.0.1:8000:8000"]
    assert data["services"]["viewer"]["read_only"] is True
    assert data["services"]["viewer"]["depends_on"] == {
        "postgres": {"condition": "service_healthy"},
        "db-bootstrap": {"condition": "service_completed_successfully"},
    }
    assert data["services"]["db-bootstrap"]["depends_on"] == {"postgres": {"condition": "service_healthy"}}
    assert data["services"]["postgres"]["volumes"] == ["postgres-data:/var/lib/postgresql/data"]
    for service in ("postgres", "db-bootstrap", "viewer"):
        for key, value in (data["services"][service].get("environment") or {}).items():
            if "PASSWORD" in key:
                assert str(value).startswith("${") and ":?" in str(value), key

"""
db-bootstrap/tests/unit/test_pipeline_compose_contract.py

Static contract of the containerized ingestion pipeline: docker/pipeline/Dockerfile
and docker/compose.pipeline.yml.  Nothing here starts a container, builds an
image or reads a credential; it reads the files and the two services' sources.

Each test covers one distinct invariant:

    PC01  the overlay adds the two services, with project-scoped images, and changes nothing else
    PC02  both services use the internal Kafka listener and the internal database name
    PC03  startup waits on services that exist, with the right conditions
    PC04  the only secret is a required reference to the existing variable
    PC05  the image is Python 3.13 slim Bookworm, unprivileged, with no credential
    PC06  the image takes exactly the three shared demo-app files and no demo dependency
    PC07  every runtime module of both services, and every shared module they import,
          is in the image; no test file is
    PC08  each service's working directory and command exist in the image layout
    PC09  the disposable integration-test wrapper cannot name the live project, reuse a
          project's objects, or prune anything
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_OVERLAY = _REPO / "docker" / "compose.pipeline.yml"
_DOCKERFILE = _REPO / "docker" / "pipeline" / "Dockerfile"
_BASE = _REPO / "docker-compose.yml"
_ENV_EXAMPLE = _REPO / ".env.example"

_SERVICES = ("stream-processor", "storage-consumer")
_SHARED = ("demo-app/schemas/telemetry.py", "demo-app/observability/__init__.py",
           "demo-app/observability/normalization.py")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _code(path: Path) -> str:
    """The file without comment lines."""
    return "\n".join(line for line in _text(path).splitlines() if not line.lstrip().startswith("#"))


def _services(text: str) -> dict[str, str]:
    """name -> block, for the two-space-indented entries under the top-level services key."""
    match = re.search(r"^services:\n(.*?)(?=^\S|\Z)", text, re.S | re.M)
    assert match, "no services section"
    blocks: dict[str, str] = {}
    current = None
    for line in match.group(1).splitlines():
        head = re.fullmatch(r"  ([a-z][a-z0-9-]*):", line)
        if head:
            current = head.group(1)
            blocks[current] = ""
        elif current is not None:
            blocks[current] += line + "\n"
    return blocks


def _dockerfile_instructions() -> list[tuple[str, str]]:
    joined = re.sub(r"\\\n\s*", " ", _text(_DOCKERFILE))
    found = []
    for line in joined.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keyword, _, rest = line.partition(" ")
            found.append((keyword.upper(), rest.strip()))
    return found


def _copies() -> list[tuple[list[str], str]]:
    """(sources, destination) of every COPY instruction."""
    out = []
    for keyword, rest in _dockerfile_instructions():
        if keyword == "COPY":
            parts = rest.split()
            out.append((parts[:-1], parts[-1]))
    return out


def _copied_sources() -> list[str]:
    return [src for sources, _ in _copies() for src in sources]


_OVERLAY_TEXT = _code(_OVERLAY)
_OVERLAY_SERVICES = _services(_OVERLAY_TEXT)


def test_PC01_the_overlay_adds_the_two_services_and_changes_nothing_else():
    assert sorted(_OVERLAY_SERVICES) == sorted(_SERVICES)
    assert set(re.findall(r"^([A-Za-z_-][\w-]*):", _OVERLAY_TEXT, re.M)) == {
        "x-pipeline-build", "services"}                   # no networks, volumes or secrets sections
    base_services = set(_services(_text(_BASE)))
    assert not set(_SERVICES) & base_services             # it adds; it overrides nothing
    for name, block in _OVERLAY_SERVICES.items():
        for forbidden in ("ports:", "container_name:", "volumes:", "profiles:", "privileged:",
                          "network_mode:", "expose:"):
            assert forbidden not in block, (name, forbidden)
        assert "agentops-net" in block                    # the platform network of the main file
        # No fixed image tag: images are named after the Compose project, so a second
        # project cannot share, overwrite or leave behind another project's image.
        assert not re.search(r"^    image:", block, re.M), name
        assert "<<: *pipeline_build" in block, name


def test_PC02_both_services_use_the_internal_kafka_listener_and_database_name():
    assert not re.search(r"localhost|127\.0\.0\.1|:9092\b", _OVERLAY_TEXT)
    for name, block in _OVERLAY_SERVICES.items():
        assert 'KAFKA_BOOTSTRAP_SERVERS: "agentops-kafka:29092"' in block, name
    advertised = re.search(r'KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://(agentops-kafka:29092)', _text(_BASE))
    assert advertised, "the main file no longer advertises the internal listener"
    block = _OVERLAY_SERVICES["storage-consumer"]
    assert 'PG_HOST: "postgres"' in block and 'PG_PORT: "5432"' in block
    assert 'PG_DATABASE: "agentops"' in block and 'PG_USER: "agentops"' in block
    assert "PG_HOST" not in _OVERLAY_SERVICES["stream-processor"]   # it never touches PostgreSQL


@pytest.mark.parametrize("name", _SERVICES)
def test_PC03_startup_waits_on_existing_services_with_the_right_conditions(name):
    block = _OVERLAY_SERVICES[name]
    base = _services(_text(_BASE))
    waits = dict(re.findall(r"^      ([a-z][a-z0-9-]*):\n        condition: (\w+)", block, re.M))
    expected = {"kafka-init": "service_completed_successfully",
                "db-bootstrap": "service_completed_successfully"}
    if name == "storage-consumer":
        expected["postgres"] = "service_healthy"
    assert waits == expected
    assert set(waits) <= set(base)                        # every name is a service of the main file
    assert "healthcheck:" in base["postgres"]             # service_healthy needs one
    assert "restart: unless-stopped" in block


def test_PC04_the_only_secret_is_a_required_reference_to_the_existing_variable():
    references = re.findall(r"\$\{[^}]*\}", _OVERLAY_TEXT)
    assert references == ["${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set in .env}"]
    assert "PG_PASSWORD: ${POSTGRES_PASSWORD:?" in _OVERLAY_SERVICES["storage-consumer"]
    assert "${POSTGRES_PASSWORD:?" in _text(_BASE)       # the variable the main file already requires
    assert re.search(r"^POSTGRES_PASSWORD=", _text(_ENV_EXAMPLE), re.M)
    for assignment in re.findall(r"^\s+([A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY)[A-Z_]*):\s*(.*)$",
                                 _OVERLAY_TEXT, re.M):
        assert assignment[1].startswith("${"), assignment   # never a literal value
    assert "PG_PASSWORD" not in _OVERLAY_SERVICES["stream-processor"]


def test_PC05_the_image_is_python_313_slim_bookworm_unprivileged_and_credential_free():
    instructions = _dockerfile_instructions()
    froms = [rest for keyword, rest in instructions if keyword == "FROM"]
    assert froms == ["python:3.13-slim-bookworm"]
    users = [rest for keyword, rest in instructions if keyword == "USER"]
    assert users and users[-1] not in ("root", "0")
    assert instructions[-1][0] == "USER"                  # nothing runs as root after it
    assert not any(keyword == "ENV" and re.search(r"(?i)password|secret|token|api[_-]?key", rest)
                   for keyword, rest in instructions)
    assert not any(keyword in ("ARG", "ADD") for keyword, _ in instructions)
    installs = [rest for keyword, rest in instructions if keyword == "RUN" and "pip install" in rest]
    assert len(installs) == 1
    assert "-r stream-processor/requirements.txt" in installs[0]
    assert "-r storage-consumer/requirements.txt" in installs[0]
    assert (_REPO / "stream-processor" / "requirements.txt").is_file()
    assert (_REPO / "storage-consumer" / "requirements.txt").is_file()


def test_PC06_the_image_takes_exactly_the_shared_demo_app_files_and_no_demo_dependency():
    from_demo = sorted(src for src in _copied_sources() if src.startswith("demo-app"))
    assert from_demo == sorted(_SHARED)
    assert all(src != "." and not src.endswith("/") for src in _copied_sources())
    for src in _SHARED:
        assert (_REPO / src).is_file(), src
    imports = "\n".join(_text(_REPO / src) for src in _SHARED)
    assert not re.search(r"^\s*(?:from|import)\s+(?:langgraph|opentelemetry)", imports, re.M)
    installed = "\n".join(rest for keyword, rest in _dockerfile_instructions()
                          if keyword in ("RUN", "COPY"))
    for unwanted in ("langgraph", "opentelemetry-sdk", "opentelemetry-api", "exporter-otlp",
                     "demo-app/requirements.txt"):
        assert unwanted not in installed, unwanted
    path = [rest for keyword, rest in _dockerfile_instructions() if keyword == "ENV"
            and "PYTHONPATH" in rest]
    assert path and "PYTHONPATH=/opt/agentops/demo-app" in path[0]


def test_PC07_every_runtime_module_and_shared_import_of_both_services_is_in_the_image():
    copied = set(_copied_sources())
    runtime = []
    for directory in _SERVICES:
        for module in sorted((_REPO / directory).glob("*.py")):
            if module.name != "conftest.py":
                runtime.append(f"{directory}/{module.name}")
    assert runtime and not any("test" in name for name in runtime)
    assert set(runtime) == {src for src in copied if src.startswith(_SERVICES)
                            and src.endswith(".py")}, "a module is missing from, or extra in, the image"
    assert not any("/tests/" in src or "migrations" in src or "conftest" in src for src in copied)
    # Every package the services import from demo-app must come with the image.
    shared_imports = set()
    for name in runtime:
        shared_imports |= set(re.findall(r"^\s*(?:from|import)\s+(schemas|observability)\b",
                                         _text(_REPO / name), re.M))
    assert shared_imports == {"schemas", "observability"}
    assert any(src.startswith("demo-app/schemas/") for src in copied)
    assert any(src.startswith("demo-app/observability/") for src in copied)


@pytest.mark.parametrize("name", _SERVICES)
def test_PC08_each_services_working_directory_and_command_exist_in_the_image_layout(name):
    block = _OVERLAY_SERVICES[name]
    assert f"working_dir: /opt/agentops/{name}\n" in block
    assert 'command: ["python", "main.py"]' in block
    assert f"{name}/main.py" in _copied_sources()
    workdir = [rest for keyword, rest in _dockerfile_instructions() if keyword == "WORKDIR"]
    assert workdir == ["/opt/agentops"]                   # the service directories sit below it
    destinations = [dest for _, dest in _copies()]
    assert f"{name}/" in destinations or f"{name}/requirements.txt" in destinations


def _wrapper():
    """workload-generator/run_pipeline_it.py, imported without running anything."""
    import importlib.util
    import sys
    path = _REPO / "workload-generator" / "run_pipeline_it.py"
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location("run_pipeline_it", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["run_pipeline_it"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(path.parent))


def test_PC09_the_wrapper_cannot_name_the_live_project_reuse_objects_or_prune():
    wrapper = _wrapper()
    smoke_failure = sys.modules["run_smoke"].SmokeFailure
    good = wrapper.new_project_name()
    assert good.startswith("agentops-pipeline-it-") and good != "agentops"
    wrapper.validate_project_name(good, ["abc1234 something-else running"])
    for bad in ("agentops", "agentops-workload-smoke", "agentops-pipeline-it-", "x" + good,
                good.upper(), good + "-2", "agentops-pipeline-it-zzzzzzzz"):
        with pytest.raises(smoke_failure):
            wrapper.validate_project_name(bad, [])
    with pytest.raises(smoke_failure):                       # a name Docker already carries
        wrapper.validate_project_name(good, [f"deadbeef {good}-postgres-1 running"])
    assert wrapper.new_project_name() != wrapper.new_project_name()
    stream, storage = wrapper.group_ids(good)
    assert stream != storage and stream.startswith(good) and storage.startswith(good)
    assert not {stream, storage} & {"agentops-stream-processor", "agentops-storage-consumer",
                                    "d3-stream-processor", "d3-storage-consumer"}
    text = wrapper.test_override_text(good)
    assert f'CONSUMER_GROUP_ID: "{stream}"' in text and f'CONSUMER_GROUP_ID: "{storage}"' in text
    # The only files it accepts, untracked or committed, are the five approved ones, all
    # inside the repository; the approved base is a full commit id, not "the" approved HEAD.
    assert wrapper.APPROVED_FILES == (
        "db-bootstrap/tests/unit/test_pipeline_compose_contract.py",
        "docker/compose.pipeline.yml", "docker/pipeline/Dockerfile",
        "workload-generator/run_pipeline_it.py",
        "workload-generator/tests/unit/test_pipeline_it_network.py")
    assert wrapper.EXPECTED_STATE == {f"?? {p}" for p in wrapper.APPROVED_FILES}
    assert all((_REPO / p).is_file() for p in wrapper.APPROVED_FILES)
    assert re.fullmatch(r"[0-9a-f]{40}", wrapper.BASE_COMMIT) and wrapper.EXPECTED_BRANCH
    source = (_REPO / "workload-generator" / "run_pipeline_it.py").read_text(encoding="utf-8")
    code = "\n".join(line.split("#")[0] for line in source.splitlines())
    # As a Docker argument (a quoted token), never a prune, a forced removal or a global listing
    # of every project's objects for deletion; the docstring may say the word.
    assert not re.search(r'"(?:prune|system|rm|rmi|--force|--all)"', code)
    assert '"-p", T.project' in code and '"--volumes"' in code and '"--rmi", "local"' in code
    assert "docker-compose.override" not in code

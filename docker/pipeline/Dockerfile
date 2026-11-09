# docker/pipeline/Dockerfile
#
# One image for the two processing services of the ingestion path: the stream
# processor (raw OTLP topic -> canonical topic) and the storage consumer
# (canonical topic -> PostgreSQL).  The Compose overlay docker/compose.pipeline.yml
# starts each from this image with its own working directory and command.
#
# Build from the repository root:
#   docker build -f docker/pipeline/Dockerfile -t agentops-pipeline .
#
# What it holds
#   - the two services' own modules, copied file by file (their tests are not),
#   - the runtime packages pinned in their two requirements.txt files,
#   - and the three demo-app files both services import, and nothing else of
#     demo-app: schemas/telemetry.py and observability/normalization.py (with
#     its package marker).  Neither imports LangGraph or OpenTelemetry, so
#     neither is installed.
#
# What it does not hold: any credential.  Every password and address is
# supplied through the environment when the container runs.
#
# Both manifests also pin pytest, which the services do not use at run time.
# It is installed because the manifests are reused unchanged.
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/agentops

# Runtime dependencies, from the repository's own pinned manifests.  One pip
# command so that the two files are resolved together.
COPY stream-processor/requirements.txt stream-processor/requirements.txt
COPY storage-consumer/requirements.txt storage-consumer/requirements.txt
RUN python -m pip install \
      -r stream-processor/requirements.txt \
      -r storage-consumer/requirements.txt

# The shared canonical-event contract.  Both services import it from a
# "schemas" and an "observability" package found on PYTHONPATH.
COPY demo-app/schemas/telemetry.py demo-app/schemas/telemetry.py
COPY demo-app/observability/__init__.py demo-app/observability/__init__.py
COPY demo-app/observability/normalization.py demo-app/observability/normalization.py

# The services.  Their modules import each other by bare name, so each runs
# from its own directory (the Compose overlay sets working_dir).
COPY stream-processor/canonicalizer.py stream-processor/config.py \
     stream-processor/deduplicator.py stream-processor/dlq.py \
     stream-processor/main.py stream-processor/otlp_decoder.py \
     stream-processor/processor.py stream-processor/publisher.py \
     stream-processor/
COPY storage-consumer/__init__.py storage-consumer/config.py \
     storage-consumer/consumer.py storage-consumer/main.py \
     storage-consumer/repository.py storage-consumer/timing.py \
     storage-consumer/

ENV PYTHONPATH=/opt/agentops/demo-app

# Run unprivileged.
RUN useradd --create-home --uid 10001 pipeline
USER pipeline

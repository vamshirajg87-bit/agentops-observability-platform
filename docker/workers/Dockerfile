# docker/workers/Dockerfile
#
# The anomaly detector and the RCA analyzer, for the isolated worker project
# (docker/mvp-workers/compose.yml).  Both are one-shot command-line programs that
# need only psycopg; their source is copied as it is, nothing is rewritten here.
#
# It holds no credential: each worker receives only its own database password,
# through the environment, when its container runs.  The detector's run
# configuration for the isolated project is baked in at /opt/agentops/config.
#
# Build from the repository root (Compose does this):
#   docker build -f docker/workers/Dockerfile .

FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# The same pin as trace-viewer/requirements.txt (a test keeps the two equal).
RUN python -m pip install "psycopg[binary]>=3.1,<4.0"

WORKDIR /opt/agentops

COPY anomaly-detector/*.py anomaly-detector/
COPY anomaly-detector/detector anomaly-detector/detector
COPY rca-analyzer/*.py rca-analyzer/
COPY docker/mvp-workers/detector_config.json config/detector_config.json

RUN useradd --create-home --uid 10001 worker
USER worker

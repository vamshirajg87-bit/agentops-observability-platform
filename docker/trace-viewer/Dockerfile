# docker/trace-viewer/Dockerfile
#
# The trace viewer: the FastAPI application with the trace, anomaly and RCA
# read endpoints and its static web UI.  The Compose overlay
# docker/compose.trace-viewer.yml runs it.
#
# Build from the repository root:
#   docker build -f docker/trace-viewer/Dockerfile -t agentops-trace-viewer .
#
# What it holds
#   - the application modules and static files, copied one by one (its tests
#     are not),
#   - and the runtime packages from trace-viewer/requirements.txt.
#
# What it does not hold: any credential.  The database host, name, role and
# password are supplied through TRACE_VIEWER_DB_* environment variables when the
# container runs.
#
# The manifest also pins pytest and httpx, which the application does not use at
# run time.  They are installed because the manifest is reused unchanged, as the
# pipeline image does.
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/agentops/trace-viewer

COPY trace-viewer/requirements.txt requirements.txt
RUN python -m pip install -r requirements.txt

# The application modules import each other by bare name, so the application
# runs from this directory.
COPY trace-viewer/app.py trace-viewer/db.py trace-viewer/queries.py \
     trace-viewer/reconstruction.py trace-viewer/anomaly_queries.py \
     ./
COPY trace-viewer/static static

# Run unprivileged.
RUN useradd --create-home --uid 10001 viewer
USER viewer

# Inside the container the server listens on all interfaces so that the
# published port can reach it; the Compose overlay publishes that port on the
# loopback address of the host only.
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

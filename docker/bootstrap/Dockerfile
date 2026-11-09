# docker/bootstrap/Dockerfile
#
# One-shot database bootstrap image (Phase 14.2).
#
# Holds psql, dbt, the migrations, the analytics project, the bootstrap
# program and the analytics refresh program, which a service selects with its
# own entry point.  It holds no credential: every password is supplied through
# the environment when the container runs.
#
# Build from the repository root:
#   docker build -f docker/bootstrap/Dockerfile -t agentops-db-bootstrap .

# Python 3.11 is the version analytics/requirements.txt was verified with in
# a container.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DBT_SEND_ANONYMOUS_USAGE_STATS=False \
    DO_NOT_TRACK=1

# psql: the migrations take their role passwords as psql variables.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agentops

# dbt, from the repository's own pinned requirements.
COPY analytics/requirements.txt analytics/requirements.txt
RUN python -m pip install -r analytics/requirements.txt

# The analytics project, the migrations and the bootstrap program.  The
# layout mirrors the repository, which is how the program finds them.
COPY analytics/dbt_project.yml analytics/profiles.yml.example analytics/
COPY analytics/models analytics/models
COPY analytics/macros analytics/macros
COPY analytics/tests analytics/tests
COPY storage-consumer/migrations storage-consumer/migrations
COPY db-bootstrap/bootstrap.py db-bootstrap/analytics_refresh.py \
     db-bootstrap/post_dbt_grants.sql db-bootstrap/

# Run unprivileged.  dbt writes its target, logs and profile copy here, never
# into the project.
RUN useradd --create-home --uid 10001 bootstrap \
 && mkdir -p /var/lib/agentops-bootstrap \
 && chown bootstrap:bootstrap /var/lib/agentops-bootstrap
ENV BOOTSTRAP_WORK_DIR=/var/lib/agentops-bootstrap
USER bootstrap

ENTRYPOINT ["python", "/opt/agentops/db-bootstrap/bootstrap.py"]

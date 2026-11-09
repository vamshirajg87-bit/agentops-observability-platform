# Setup and operations

This guide is **Windows-first** and **source-derived**. Every command and value below was read from files in this
repository. Only the paths marked *live-validated* were run end to end, and only through the pinned harness
described in [Using the end-to-end harness](#using-the-end-to-end-harness). There is **no validated one-command
startup**: the sequence under [Starting the stack](#starting-the-stack) is assembled from the Compose files'
own instructions and has not been run as a whole.

Labels used here:

- **Live-validated**: ran in the Phase 14.7 runs.
- **Source-derived, unverified**: taken from repository files; not run as written.

## Prerequisites

| Item | Requirement | Source |
|---|---|---|
| Operating system | Windows 11 was the development and validation environment; this is an **operator-recorded detail** that no repository file or private evidence independently verifies. Separately, the development repository configured its offline test suites for Linux (Ubuntu) CI; that CI workflow is deferred from the initial public release, so no CI result is claimed. The full pipeline has not been validated on Linux | CI workflow not included in this release |
| Python | **3.13** for the host components and the live harnesses (the harness refuses another version). The bootstrap image uses Python 3.11 deliberately, because the dbt packages were verified with it | [docker/bootstrap/Dockerfile](../docker/bootstrap/Dockerfile), [workload-generator/run_e2e.py](../workload-generator/run_e2e.py) |
| Docker | Docker Desktop with Compose v2 (as the Viewer README's prerequisites state). The Phase 14.7 runs were made on Docker Desktop 4.89.0 with Docker Engine 29.7.2 on WSL2; these versions are **operator-recorded environment details** that neither the repository nor the private evidence records (the private transcripts record only the approved engine id). No minimum version is stated in the repository | [docker/trace-viewer/README.md](../docker/trace-viewer/README.md) (Compose v2 only) |
| Python packages | One `requirements.txt` per component; all pinned or range-bound | [demo-app/requirements.txt](../demo-app/requirements.txt), [stream-processor/requirements.txt](../stream-processor/requirements.txt), [storage-consumer/requirements.txt](../storage-consumer/requirements.txt), [trace-viewer/requirements.txt](../trace-viewer/requirements.txt), [analytics/requirements.txt](../analytics/requirements.txt) |
| Network | The first build and `pip install` download images and packages | n/a |

### Hardware and memory

The repository states no product minimum. What exists are the **harness gates**, which are safety thresholds
for the live E2E on a laptop, not guarantees:

- host available memory of at least 4096 MiB, a Docker engine with at least 3.5 GiB, and at least 20 GiB free disk
  for the temporary and Docker storage;
- the private Phase 14.7 transcripts report a Docker engine memory of 4919 MiB and roughly 4 GiB of it available when each
  run started. That is an observation from those runs, not a requirement. The transcripts do not record the
  host's total RAM;
- the historical Phase 14.4 benchmark documents describe their own test machine as a 16 GB laptop with Docker
  Desktop limited to 4 CPUs and about 5.2 GB ([benchmarks/RESULTS.md](../benchmarks/RESULTS.md), line 38). That
  is a description of that earlier work, not a specification for Phase 14.7 or a universal minimum.

During the development session the operator observed that Docker Desktop's Resource Saver can stop the VM when it
is idle and that host sleep stops containers. These are session observations; the private Phase 14.7 evidence
does not demonstrate them. Treat them as operational guidance: keep the host awake during a run and check the
state of the stack before assuming data was lost. The benchmark documents separately record that host memory fell
during longer runs ([benchmarks/README.md](../benchmarks/README.md), section 11).

## Configuration

### Credentials

Copy [.env.example](../.env.example) to `.env` (git-ignored) and give every variable a different value on one
line, without quotes. Nothing in the template is a usable credential, and Compose refuses to start without the
three variables it requires.

| Variable | Used by |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL owner role `agentops`; bootstrap; `analytics-refresh`; the optional storage-consumer container |
| `GF_DATASOURCE_AGENTOPS_PASSWORD` | role `grafana_reader` |
| `TRACE_VIEWER_DB_PASSWORD` | role `trace_viewer_reader` |
| `ANOMALY_DETECTOR_DB_PASSWORD` | role `anomaly_detector` |
| `RCA_ANALYZER_DB_PASSWORD` | role `rca_analyzer` |
| `INCIDENT_RETRIEVAL_DB_PASSWORD`, `ALERT_EVALUATOR_DB_PASSWORD`, `ALERT_NOTIFIER_DB_PASSWORD` | the roles of the same names |
| `GF_SECURITY_ADMIN_PASSWORD` | Grafana administrator (separate from the database role) |

The bootstrap creates each database role with the value given when the database is **first** bootstrapped.
Changing a value later does not change an existing database. Processes you start on the host do not read `.env`:
export what they need in their own shell (for example `PG_PASSWORD`, which must equal `POSTGRES_PASSWORD`, for a
host-run storage consumer).

### Ports

All published ports are bound to the loopback address.

| Port | Service | File |
|---|---|---|
| 127.0.0.1:4317 and 4318 | OTLP gRPC and HTTP (Collector) | [docker-compose.yml](../docker-compose.yml) |
| 127.0.0.1:9092 | Kafka (host listener) | [docker-compose.yml](../docker-compose.yml) |
| 127.0.0.1:5432 | PostgreSQL | [docker-compose.yml](../docker-compose.yml) |
| 127.0.0.1:3000 | Grafana | [docker-compose.yml](../docker-compose.yml) |
| 127.0.0.1:8000 | Trace Viewer (overlay) | [docker/compose.trace-viewer.yml](../docker/compose.trace-viewer.yml) |

The live E2E harness uses a different disposable set (127.0.0.1:14317, 19092 and 15432) so that it never touches
a running stack. Loopback binding limits where a connection can come from; it is **not** authentication.

## Components

### Kafka

The `kafka` and `kafka-init` services in [docker-compose.yml](../docker-compose.yml) start a single broker and
create the topics `agentops.telemetry.otlp.traces`, `agentops.telemetry.spans` and `agentops.telemetry.dlq`
with three partitions each and replication factor 1.

### PostgreSQL bootstrap and migrations

The `db-bootstrap` service ([db-bootstrap/bootstrap.py](../db-bootstrap/bootstrap.py)) turns an empty database
into the full schema: 15 migrations from [storage-consumer/migrations/](../storage-consumer/migrations/), one dbt
run between migration 001 and 002, post-dbt grants, a `complete` marker and then migration 015, recorded in a
ledger (18 steps in all). It refuses a database that has platform objects but no ledger (exit code 5) and never
adopts one. *Live-validated* on a fresh database.

### Stream processor and storage consumer

- *Live-validated*: both run as host processes from a Python 3.13 virtual environment, started by the harness.
- *Source-derived, unverified*: the container form, [docker/compose.pipeline.yml](../docker/compose.pipeline.yml).
  Its header records one earlier run that reconciled ingestion but whose overall result was FAIL for a
  mis-specified assertion, and says to treat the stack as unverified beyond that run. In this form the storage
  consumer connects as the PostgreSQL **owner** role, which is acceptable for local development only.

### dbt analytics

Rebuild the models only with the refresh service, which runs dbt, re-applies
[db-bootstrap/post_dbt_grants.sql](../db-bootstrap/post_dbt_grants.sql) and verifies the grants:

```powershell
docker compose run --rm analytics-refresh
```

Do not run dbt directly against a platform database: the grants would be missing. This command is quoted from
[.env.example](../.env.example); the harness runs the same service on its disposable project (*live-validated*).

### Anomaly detector

A one-shot command. Export `ANOMALY_DETECTOR_DB_PASSWORD` (and the host or port, if not the defaults), then:

```powershell
python anomaly-detector/main.py --config anomaly-detector/runner_config.json
```

Running it twice inserts nothing the second time. *Live-validated* (via the harness, with
[workload-generator/detector_config.json](../workload-generator/detector_config.json)); the command above is
source-derived.

### RCA analyzer

Pick a 64-character anomaly id (from the Viewer or its API), export `RCA_ANALYZER_DB_PASSWORD`, then:

```powershell
python rca-analyzer/main.py --anomaly-id <64-character id>
```

Exit codes: 0 success, 1 anomaly not found, 2 source-data integrity error, 3 configuration error, 4 database
error. *Live-validated* (Step 5F).

### Trace Viewer

[docker/compose.trace-viewer.yml](../docker/compose.trace-viewer.yml) adds it to the main stack, and
[docker/trace-viewer/README.md](../docker/trace-viewer/README.md) has the demonstration steps. The API accepts
requests only for the hosts `127.0.0.1` and `localhost` (add exact names with `TRACE_VIEWER_ALLOWED_HOSTS`). The
Viewer API was *live-validated in-process*; the standalone overlay was **not** started in the validation.

### Workload

`python -m workload_generator` plans a workload and, only with `--send` and an explicit `--endpoint`, runs it
through the demo agent. Read the module header in
[workload-generator/workload_generator/cli.py](../workload-generator/workload_generator/cli.py) for the exact
arguments and the conditions under which a send is refused. The harness passes, for example, `--mode real
--scenario normal --traces 30 --rate 2 --seed 42 --concurrency 1`.

## Starting the stack

*Source-derived, unverified as a sequence.* From the repository root, with your `.env` in place:

1. Start the services (the Viewer overlay's own instructions):

   ```powershell
   docker compose -f docker-compose.yml -f docker/compose.pipeline.yml -f docker/compose.trace-viewer.yml up -d --build
   ```

   `docker compose ... config` shows the resolved configuration without starting anything. The pipeline overlay
   and the Viewer overlay both wait for `db-bootstrap` to finish successfully.
2. Send a workload to the Collector with `python -m workload_generator ... --send --endpoint ...`.
3. Run `docker compose run --rm analytics-refresh` once data is stored.
4. Run the anomaly detector, then the RCA analyzer for a chosen anomaly.
5. Open `http://127.0.0.1:8000/`.

The Viewer README states that its overlay cannot be used with a database that has no bootstrap ledger.

## Shutting down

*Source-derived, unverified.*

- Stop containers and keep the data: `docker compose -f docker-compose.yml ... down` with the same `-f` files
  you started with.
- `down --volumes` **also deletes the database and Kafka volumes**. Never run it against a stack whose data you
  need.
- Host processes you started yourself (stream processor, storage consumer) stop with Ctrl+C. The harness stops
  its own processes and removes only its own project's resources.

## Using the end-to-end harness

[workload-generator/run_e2e.py](../workload-generator/run_e2e.py) (built on
[run_smoke.py](../workload-generator/run_smoke.py)) is a **validation tool, not an installer**. It is pinned to
one Docker context and engine id, to a set of protected containers and volumes that must exist, and to a specific
Git branch and an operator-approved manifest of the working tree. On another machine it refuses to run until
that code is edited deliberately. It checks resources before it creates anything, runs in a disposable Compose
project, and cleans up only that project.

- Plan only (prints, runs nothing): `python workload-generator/run_e2e.py`
- Read-only preflight: add `--expect-head <40-hex> --preflight`, plus the approved-tree arguments when the tree
  is not clean
- Live run: `--execute --confirm "<phrase printed by the plan>"`; `--with-rca-viewer` adds the RCA and Viewer stage

Do not bypass or weaken its gates (memory, disk, ports, engine identity, protected resources). A failed gate
means the machine is not ready.

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Compose stops naming a variable | A required password is empty | Set it in `.env` |
| `db-bootstrap` exits with code 5 | Database has platform objects but no ledger | Use a fresh database; the bootstrap never adopts one |
| `analytics-refresh` is refused | The ledger is not complete (migration 015 missing) | Rebuild and rerun `db-bootstrap` |
| Viewer shows no anomaly or RCA data | Role lacks migration 015 grants, or nothing was detected yet | Check the ledger; run the refresh and the detector |
| Viewer returns an error for a request | Host header is not `127.0.0.1` or `localhost` | Use those names, or set `TRACE_VIEWER_ALLOWED_HOSTS` |
| RCA analyzer exit 1 | Anomaly id not found | Use an id from `public.anomaly_events` |
| Harness preflight fails on memory | Host or VM below a gate | Free memory and re-run once; do not edit the gate |
| Containers vanish after sleep | Docker Desktop restarted | Restart the stack; check volumes before assuming data loss |

## Security and secrets

- Keep `.env` and any `credentials.env` out of version control (both are git-ignored).
- The Trace Viewer has **no authentication**; do not change its loopback binding.
- Kafka and OTLP accept unauthenticated local connections; PostgreSQL and Grafana rely on their own credentials.
- Each application role has only the grants it needs; the Viewer role is read-only.
- The Collector's `debug` exporter can print span attributes to container logs; the committed level is `basic`.
  Do not raise it casually.
- The harness writes generated, test-only passwords to a temporary environment file and retains its workspace.
  Treat any retained workspace as private. See [VALIDATION-AND-ACCEPTANCE.md](VALIDATION-AND-ACCEPTANCE.md).
- Masking in harness logs knows only the values the harness generated. It does not catch other secrets.

## Portability notes

- Windows mechanisms are used by the harness (permission tools, memory counters, the Docker named pipe).
- The harness hard-codes protected paths and a Docker engine id.
- The validated implementation is included in this prepared release candidate. Git initialization, the initial
  commit, and public publication remain pending separate approval.
- A CI workflow is deferred from the initial public release. The live harnesses need Docker and were never
  intended to run in CI.

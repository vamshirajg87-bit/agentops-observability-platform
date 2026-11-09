# Trace viewer — local Docker demonstration

The trace viewer serves the trace list, the **Anomalies** tab and the **RCA panel**
(`trace-viewer/`) on `http://127.0.0.1:8000/`. It is a local demonstration, not a
deployment: the viewer has no authentication and is reachable from this machine only.

Status:

- The image was built from `docker/trace-viewer/Dockerfile` (B3J-140).
- The viewer was run from that image against the existing legacy database in isolated
  temporary containers; the API smoke test and an interactive browser check both passed
  (B3J-141, B3J-142). See [Verified legacy-database demo](#verified-legacy-database-demo).
- `legacy-demo.ps1` (below) completed a live start, status, API-check and stop cycle
  against the legacy database **twice**, each time with its containers and network cleaned
  up afterwards: B3J-149B for the original script version (hash prefix `8016cc23`) and
  B3J-152 for the current, revised version (hash prefix `db6eb55a`). Failure cleanup,
  Ctrl+C interruption, the refusal paths and repeated runs have **not** been live-verified.
  See [Repeatable legacy demo](#repeatable-legacy-demo-legacy-demops1).
- The Compose overlay `docker/compose.trace-viewer.yml` itself has only been validated with
  `docker compose config`. It has not been started, and it cannot be used unchanged with
  a database that has no bootstrap ledger (see below).

## Files

| File | Purpose |
|---|---|
| `docker/trace-viewer/Dockerfile` | The image: application modules, static files, pinned packages, unprivileged user, no credentials. |
| `docker/compose.trace-viewer.yml` | Overlay with one service, `trace-viewer`, published on `127.0.0.1:8000` only. |
| `storage-consumer/migrations/015_grant_trace_viewer_anomaly_rca_read.sql` | Gives `trace_viewer_reader` SELECT on `anomaly_events`, `rca_investigations` and `rca_evidence`. |

## What has and has not been validated

| Viewer form | Status |
|---|---|
| **In-process Viewer API** (this directory's `trace-viewer/app.py`, driven with Starlette's test client) | **Validated** in Phase 14.7 Step 5F against a disposable database, as the read-only `trace_viewer_reader` role. No server was started and no port was published. Results are listed under [Phase 14.7 Step 5F result](#phase-147-step-5f-result). This covers the API, not the container image, the Compose overlay or the browser UI. |
| **Accepted MVP Viewer** (a separate, protected Compose project; see `docker/mvp-workers/compose.yml`, loopback port 8001) | Exists and was observed running and healthy during Phase 14.7. It was not modified, and it is not the overlay described below. |
| **Standalone Compose overlay** (`docker/compose.trace-viewer.yml`) | **Not independently live-validated.** It has only been checked with `docker compose config`. It was not started in Phase 14.7, and nothing here claims that it starts successfully. |

## Prerequisites

1. Docker with Compose v2, run from the repository root.
2. A `.env` (copy `.env.example`, never commit it) with a value for at least
   `POSTGRES_PASSWORD`, `GF_DATASOURCE_AGENTOPS_PASSWORD`, `GF_SECURITY_ADMIN_PASSWORD` and
   **`TRACE_VIEWER_DB_PASSWORD`**. The bootstrap creates `trace_viewer_reader` with that
   password, so set it **before** the database is first bootstrapped. Also set
   `ANOMALY_DETECTOR_DB_PASSWORD` and `RCA_ANALYZER_DB_PASSWORD` if you will run the
   detector and the analyzer (step 4).

   `GF_SECURITY_ADMIN_PASSWORD` is the Grafana administrator login. It is a different
   credential from `GF_DATASOURCE_AGENTOPS_PASSWORD`, which is the `grafana_reader` database
   password. Compose refuses to start until it has a nonempty value, and it belongs only in
   the local, untracked `.env`: never commit it or paste it into logs. It sets the
   administrator password when Grafana first creates its state; it does not reset the
   administrator of an existing Grafana volume, which must be preserved (changing that
   password is a separate procedure).
3. **Migration 015 applied.** How depends on how the database was built; see below.

### Migration 015 and the bootstrap

`db-bootstrap` is the supported way to build a database. B3J-130C registered migration 015
in `db-bootstrap/bootstrap.py` as a **post-marker upgrade** (`_UPGRADES`): the plan is the
17 base steps (001, dbt, 002 to 014, the post-dbt grants and the `complete` marker) followed
by 015 as step 18. The base order and checksums are unchanged, and the bootstrap still
refuses any migration file it does not know.

| Database | What `db-bootstrap` does |
|---|---|
| **Fresh** (empty) | Runs the base plan, records `complete`, then applies 015 automatically. |
| **Already bootstrapped** (valid 17-step ledger, built before 015 existed) | Classifies it as partly complete and **resumes at 015 only**: nothing earlier is re-run. A second run changes nothing. |
| **Legacy** (platform objects but **no ledger**, for example built by hand) | **Incompatible**: it never adopts such a database, exits with code 5 and changes nothing. |

The `complete` marker means "the base bootstrap is complete". The database counts as
complete (and `analytics-refresh` accepts it) only once 015 is also recorded. The
bootstrap image copies `bootstrap.py` and the migrations at build time, so `db-bootstrap`
must be rebuilt to pick up 015. These bootstrap paths are covered by unit tests; they have
not been run against a live database.

For a legacy database, 015 cannot go through the bootstrap. The demo below applied its four
grants by hand, under explicit approval, and recorded that outside the database.

## Run

```
docker compose -f docker-compose.yml -f docker/compose.pipeline.yml \
               -f docker/compose.trace-viewer.yml up -d --build
```

Open `http://127.0.0.1:8000/`. The Traces tab works once telemetry has been stored.
`docker compose ... config` shows the resolved configuration without starting anything.

**This overlay depends on `db-bootstrap`** (`depends_on: db-bootstrap:
service_completed_successfully`). On a legacy database with no ledger, `db-bootstrap`
exits with code 5, so the viewer never starts. The overlay **cannot be used unchanged with
a ledger-less legacy database**. It is meant for a fresh or bootstrap-managed database.

## Verified legacy-database demo

The viewer was verified against the existing, ledger-less legacy database as follows. This
is a record of a **local demonstration**, not a deployment procedure, a production
configuration or an authentication model.

| Step | Result |
|---|---|
| B3J-134 | A custom-format dump and a globals-only dump (no role password hashes) were taken from a temporary container on the existing data volume, verified with `pg_restore --list` and SHA256, and stored outside the repository and OneDrive. |
| B3J-136 | The four grants of migration 015 were applied **by hand** in one transaction, with a check that rolls back on failure. No bootstrap ledger was created. An evidence note was written beside the backup. |
| B3J-139 | The two `SELECT` grants on `analytics.int_trace_spans` and `analytics.stg_telemetry_spans` were restored for `trace_viewer_reader`. The dbt rebuild of the views most likely removed them (as `post_dbt_grants.sql` describes); a later dbt run removes them again. |
| B3J-141 | The API smoke test passed: health, traces, anomalies, RCA, 404 and 422 handling, and the static dashboard files. |
| B3J-142 | Interactive browser verification passed: traces, anomaly details, RCA confidence, limitations and ranked evidence, related-trace navigation, execution tree and span details. |
| B3J-143 | The temporary containers and network were removed. The original container, the data volume, the images, the backups and the evidence notes were kept. |
| B3J-148 | `legacy-demo.ps1` was written to repeat this arrangement with guards (see below) and covered by 76 static tests. |
| B3J-149B | One live `start`, `status`, API-check and `stop` cycle of the **original** script version (hash prefix `8016cc23`) passed, run with the one-process `-ExecutionPolicy Bypass` option. Cleanup left no demo resources, and the original container, volume, images, backups and evidence were preserved. |
| B3J-151 | The start cleanup moved into a `finally` block (so it is also attempted on Ctrl+C), the execution-policy and interruption limits were documented, and an ineffective test assertion was fixed (92 static tests). |
| B3J-152 | One live `start`, `status`, API-check and `stop` cycle of the **current, revised** script version (hash prefix `db6eb55a`) passed, run with the plain `powershell -NoProfile -File` command and no execution-policy option. Same cleanup and preservation results as B3J-149B. |

How it was isolated: temporary containers, not Compose. A temporary PostgreSQL container
used the existing image and data volume on a private network and published **only**
`127.0.0.1:8000`; PostgreSQL's own port was never published. The viewer container shared that
container's network namespace and connected over loopback as `trace_viewer_reader`. The
viewer ran non-root with a read-only root file system, a `tmpfs` at `/tmp`, all capabilities
dropped and `no-new-privileges`.

Authentication in that arrangement was PostgreSQL's **local trust** rule for loopback
connections, with a non-secret placeholder in place of a password. That is acceptable only
inside a throwaway, single-machine, loopback-only demonstration. It does not exercise a real
password, and no role or password was changed. A shared or persistent setup needs a real
password and an authentication layer in front of the API, neither of which exists yet.

## Repeatable legacy demo (`legacy-demo.ps1`)

`docker/trace-viewer/legacy-demo.ps1` repeats the isolated legacy-database demo above with
guards, for Windows PowerShell 5.1 and Docker Desktop. It is the supported way to run the
viewer against the ledger-less database (the Compose overlay cannot be used there).

Run these from the repository root, in Windows PowerShell:

```
powershell -NoProfile -File docker/trace-viewer/legacy-demo.ps1 start      # add -Open to open the browser
powershell -NoProfile -File docker/trace-viewer/legacy-demo.ps1 status     # read-only report
powershell -NoProfile -File docker/trace-viewer/legacy-demo.ps1 stop
```

**If PowerShell refuses to run the script** (a "running scripts is disabled on this system"
or signature error), your execution policy blocks it. You can allow it for **that one
process only** by adding `-ExecutionPolicy Bypass` to the same command:

```
powershell -NoProfile -ExecutionPolicy Bypass -File docker/trace-viewer/legacy-demo.ps1 start
```

That option lasts only for the process it is given to. It does not change any stored
policy, and nothing here needs one changed: do not change the machine-wide or the
per-user execution policy for this script. If the policy is set by Group Policy (your
organization), the option has no effect and you should ask whoever manages the policy
rather than work around it. The live test in B3J-149B used the one-process option; the live
test in B3J-152 used the plain command without it and succeeded on this machine, whose
user-level policy already allows local scripts. That does not show the plain command works
under a stricter policy.

**Status of the script:** it is covered by static guard tests (including a PowerShell 5.1
parse that does not run it) and it has **two successful live cycles on one machine**, each
a single `start`, then `status`, then the four HTTP checks (`/api/health`,
`/api/traces?limit=1`, `/api/anomalies?limit=1` and `/`, all answering 200 with 9 traces and
2 anomalies), then `stop`, without `-Open`:

- **B3J-149B** ran the original script version (hash prefix `8016cc23`), using the
  one-process `-ExecutionPolicy Bypass` option.
- **B3J-152** ran the **current** script version (hash prefix `db6eb55a`), the one this
  README describes, using the plain `powershell -NoProfile -File` command.

After each, no demo container, network or published port remained, and the original
container, the database volume, the images, the backup and the evidence notes were intact.
The two runs were on the same machine and each was a normal, uninterrupted lifecycle.

**Not live-verified.** The failure cleanup, interruption (Ctrl+C) cleanup, the refusal
paths, the `-Open` switch and repeated runs have only been checked statically, not live. The
current version's `finally`-based cleanup has only been exercised on the success path, where
it removes nothing; no interruption or failure was triggered on purpose. Each live run still
needs its own authorization.

What it uses: the containers `agentops-legacy-demo-pg` and `agentops-legacy-demo-viewer`,
the private network `agentops-legacy-demo-net`, and the label `agentops.demo=legacy-viewer`.

**`start`** refuses, changing nothing, unless all of these hold: Docker responds; no demo
resource already exists; the original `agentops-postgres` container exists and is stopped;
the `agentops_postgres-data` volume exists and no running container uses it; the image
`agentops-trace-viewer:local` exists (the script never builds it); at least one non-empty
`*.dump` backup exists under `%LOCALAPPDATA%\agentops-backups` (there is no way to skip this
check); host port 8000 is free; and nothing listens on host port 5432. It then creates the
network, starts a PostgreSQL container from the **original container's exact image id** on
the existing volume, and starts the viewer in that container's network namespace (non-root,
read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped,
`no-new-privileges`, no restart policy). Only the literal `127.0.0.1:8000:8000` mapping is
published; PostgreSQL's port is never published. The script then verifies Docker's port
mappings (it tears down at once if they are anything else), waits for PostgreSQL and the
viewer with fixed time limits, and checks `/api/health`, `/api/traces?limit=1`,
`/api/anomalies?limit=1` and `/`. It prints the URL and a short browser checklist. If any
step fails, or the start is interrupted, it removes only the resources that invocation
created (see "If a start is interrupted" below).

**`stop`** removes only the two demo containers and the network, and only after checking
each one's exact name and label. It stops the viewer first, then PostgreSQL with a time
limit. It refuses when ownership is ambiguous or an unrelated container uses the demo, and it
never deletes volumes, images, backups or evidence. Afterwards it verifies that the original
container is still stopped, the database volume is present and port 8000 is free.

**If a start is interrupted.** The cleanup of a start runs in a `finally` block, so it is
attempted both when a step fails and when you press Ctrl+C. It removes only the resources
that this invocation itself created, each after an exact-name and label check, and never
anything that existed before. A pre-existing resource with a demo name makes `start` refuse
before it creates anything. It is **best effort and cannot be guaranteed** when:

- the PowerShell process is killed (Task Manager, `Stop-Process`, closing the terminal
  window) or the machine loses power or crashes: no cleanup code runs;
- Docker Desktop stops or restarts in the middle of a start;
- you interrupt a second time while the cleanup itself is running;
- the interrupt arrives in the instant after a `docker run` has created a container but
  before the script has recorded it as its own (it is deliberately not removed by guesswork).

After any of these, run `status` and then `stop`. `stop` removes only exact-name, labelled
demo resources and refuses when ownership is ambiguous. Until it has run, a new `start`
refuses. An interrupted or failed start is never retried automatically.

**Safety limits you should know about**

- The PostgreSQL data volume is mounted **read-write**, because PostgreSQL cannot start
  without that. Starting and stopping PostgreSQL rewrites some of its own files (the
  process-id file, a shutdown checkpoint, the WAL position). This demo therefore does **not**
  guarantee that the database files stay byte-for-byte unchanged. The script runs no SQL and
  the viewer's role is read-only, but take a backup first, which is why `start` requires one.
- Authentication is PostgreSQL's local **trust** rule for loopback connections inside the
  shared network namespace, with a random throwaway password value generated for each start
  and never printed or stored. This is a local demonstration, **not a security model** and
  not a production deployment: the API has no authentication and must stay on loopback.
- The analytics view grants for `trace_viewer_reader` are removed by any dbt run; a `503`
  from the data endpoints usually means they need restoring (see B3J-139 above).

## Demonstration

1. **Telemetry.** Send traces through the collector so the pipeline stores them
   (the `workload-generator/` package produces them; its exact invocation is not covered
   here and has not been verified for this demo). The Traces tab then lists them.
2. **Analytics models.** `docker compose run --rm analytics-refresh` rebuilds the dbt
   views the viewer and the detector read.
3. **Anomaly detection (host).** The detector is a one-shot command. With
   `ANOMALY_DETECTOR_DB_PASSWORD` exported in your shell and `ANOMALY_DETECTOR_DB_HOST`
   left at its default (`localhost`; the main stack publishes PostgreSQL on port 5432):
   `python anomaly-detector/main.py --config anomaly-detector/runner_config.json`
4. **RCA (host).** Pick an anomaly id from the Anomalies tab or from the API, with
   `RCA_ANALYZER_DB_PASSWORD` exported:
   `python rca-analyzer/main.py --anomaly-id <64-character id>`
5. **View.** Reload the Anomalies tab, open an anomaly, read the RCA panel, and use
   *View related trace* to go to the trace.

Useful checks: `GET /api/health` (no database), `GET /api/anomalies?limit=5`,
`GET /api/anomalies/{id}/rca` (404 when no investigation exists).

## Phase 14.7 Step 5F result

In Step 5F the end-to-end harness (`workload-generator/run_e2e.py --with-rca-viewer`) selected one CRITICAL
`tool_failure` anomaly from its disposable database, ran `rca-analyzer/main.py` twice, and then called the Viewer
in-process. The recorded outcome (`step-5F/viewer-probe.log` in the local, private evidence archive described in
[docs/VALIDATION-AND-ACCEPTANCE.md](../../docs/VALIDATION-AND-ACCEPTANCE.md)):

- `GET /api/health/ready` returned 200.
- `/api/traces` reported 110 traces and `/api/anomalies` reported 42 anomalies.
- `GET /api/anomalies/{id}/rca` and `GET /api/rca/{investigation_id}` returned identical bodies: one
  investigation (confidence HIGH) with five evidence rows and none omitted.
- Every evidence span was present in `GET /api/traces/{trace_id}`, and the anomaly's own span was among the
  evidence and marked as the direct subject.
- `GET /api/anomalies/{id}/rca` for an anomaly with no investigation returned 404.
- A second analyzer run inserted nothing.

This validates the API's behaviour on a small synthetic dataset. It does not validate the browser interface, the
container image or the Compose overlay.

## What `observed_value` means

The anomaly schema has no unit column, and no comment documents one. The unit depends on
`signal_name`, as set by the detectors in `anomaly-detector/detector/`:

| `signal_name` | `anomaly_type` | `observed_value` | Basis |
|---|---|---|---|
| `duration_ms` | `latency` | milliseconds | The signal is named `duration_ms`; its source columns are `trace_duration_ms` and `duration_ms`, and the trace one is computed as epoch seconds × 1000. |
| `retrieval_top_relevance_score` | `retrieval_quality` | unitless relevance score | The scale (for example 0 to 1) was not verified. |
| `retrieval_result_count` | `retrieval_quality` | a count of results | Count semantics follow from the signal name. |
| `error_rate` | `error_rate` | **not a rate: always `1.0`** | The detector sets `observed_value=1.0` for each error span. |
| `tool_error_rate` | `tool_failure` | **not a rate: always `1.0`** | Same, in the tool-failure detector. |

The Anomalies tab shows the bare number. It should show the unit from `signal_name`
(and not present `1.0` as a rate); that is a small follow-up in `trace-viewer/static/app.js`,
not done in this task. The latency unit is an inference from names and code, not from a
schema contract.

## Security notes

- `127.0.0.1:8000:8000` is the only published port. Do not widen it: there is no
  authentication, and anomaly and RCA text (`error_message`, `explanation`, `summary`)
  is served as stored.
- The viewer connects as `trace_viewer_reader`, which has SELECT only. Migration 015 adds
  SELECT on exactly three tables and `USAGE` on schema `public`.
- No password is written in any file here. `compose.trace-viewer.yml` refuses to start
  without `TRACE_VIEWER_DB_PASSWORD` in your environment or `.env`.
- The main stack's own ports (PostgreSQL 5432, Kafka, OTLP, Grafana) are published by
  `docker-compose.yml` on `127.0.0.1` only, so they are reachable from this machine only.
  That restricts where a connection can come from; it is not authentication. Kafka and
  OTLP accept unauthenticated connections from any local process, and PostgreSQL and
  Grafana rely on their own credentials. This task does not change this.
- **Collector debug logging.** The OpenTelemetry Collector
  (`collector/otel-collector-config.yaml`) keeps a `debug` exporter next to the Kafka
  exporter. At `verbosity: detailed` that exporter can print span attributes, including
  free text such as error messages, to the container logs, and the collector applies no
  filtering or redaction first. The committed level is `basic` to reduce that exposure.
  Kafka delivery is configured by its own exporter and does not depend on the debug
  exporter. `detailed` logging must not be enabled casually on sensitive workloads; it
  needs a separate review. This change does not redact telemetry (attributes still reach
  Kafka and PostgreSQL unchanged), does not remove logs that were already written, and has
  not been validated at runtime: no collector was started or recreated.

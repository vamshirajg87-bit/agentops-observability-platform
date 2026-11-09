# Validation and acceptance

This document records what was validated in Phase 14.7, what the published figures rest on, and what remains
unproven. The figures are the project owner's **reported historical validation outcomes** from two accepted local
runs. The underlying evidence is private and is not distributed with this repository, so a reader cannot
independently reproduce these figures from a fresh clone (see [Evidence archive](#evidence-archive)). The document
distinguishes results recorded in log files that the owner archived and hashed locally from **reported results**
(observed during a run, but with no archived snapshot).

## Scope of the acceptance

Phase 14.7 ran the full pipeline twice on a disposable Docker Compose project named `agentops-workload-smoke`,
using the live harness [workload-generator/run_e2e.py](../workload-generator/run_e2e.py):

| Run | Date (UTC) | Duration | Stages | Harness exit code |
|---|---|---|---|---|
| **Step 4F** | 2026-11-08, 04:13:02 to 04:18:34 | about 5.5 minutes | workload, Kafka, PostgreSQL, dbt, anomaly detection | 0 |
| **Step 5F** | 2026-11-08, 05:43:02 to 05:48:37 | about 5.5 minutes | the same, plus RCA and Trace Viewer (`--with-rca-viewer`) | 0 |

The Step 4F start and end times are preserved in its privately retained transcript (its `EXECUTION START` and
`EXECUTION END` lines). The Step 5F start and end times were taken from session records made around the run. The
retained Step 5F transcript does not preserve them; it corroborates only the approximate duration (the harness's
own elapsed time of 335 seconds, about 5.6 minutes) and, through the detector and analyzer log stamps in local
time, an end time consistent with a five-hour offset from UTC. Its last line records harness exit code 0.

An earlier live attempt failed at the harness's own workspace-permission check (Python 3.13 gives a new temporary
directory an extra OWNER RIGHTS entry). This is an **unarchived session observation**: the transcript of that
attempt was deliberately not included in the private evidence archive, so nothing in the archive demonstrates it.
The harness was corrected, and 4F and 5F are the successful runs after that. One preflight before 5F was refused
on a host-memory gate and was repeated once after memory was freed; the gate was not changed. Both preflight
results are in the owner's private archive.

## Results

The same workload ran in both runs: three stages of one request at a time, planned from a fixed seed.

| Stage | Requests | Spans | Scenario |
|---|---|---|---|
| `f-warm-002` | 30 | 210 | normal |
| `f-slow-002` | 40 | 280 | 12 slow-tool requests |
| `f-fail-002` | 40 | 256 | 12 repeated-failure requests |
| **Total** | **110** | **746** | |

Recorded in the owner's private harness transcripts, per stage: zero consumer lag on both consumer groups, zero DLQ records,
the exporter-reported span counts equal to the canonical topic records and the rows stored, and the request ids
equal to the plan.

| Check | Result | Source (private, not distributed) |
|---|---|---|
| Persisted spans | 746 (traces: 110) | transcripts; analytics refresh section |
| dbt refresh | 746 staged spans, 110 traces, 12 with errors, ledger unchanged at 18 steps | transcripts |
| Anomaly events | 42: 12 trace-latency, 12 tool-latency, 9 error-rate, 9 tool-failure | `detector-run-1.log` |
| Detector idempotency | second run inserted 0 and reported 42 duplicates, rows unchanged | `detector-run-2.log` |
| Tool-failure severities | 8 CRITICAL, 1 INFO | transcripts, anomaly reconciliation |
| RCA investigation (Step 5F only) | one investigation, five evidence rows, confidence HIGH | `step-5F/rca-first.log` |
| RCA idempotency | second run `inserted=False`, same investigation id, row counts unchanged | `step-5F/rca-second.log` |
| Viewer (in-process, Step 5F) | readiness 200; 110 traces; 42 anomalies; anomaly-to-RCA and investigation-detail routes identical; evidence spans all in the trace; the anomaly's span marked as the direct subject; an uninvestigated anomaly returned 404 | `step-5F/viewer-probe.log` |
| Contained cleanup | no project containers, networks, volumes or images left; Docker inventories identical before and after | transcripts |
| Protected isolation | the accepted PostgreSQL, accepted Viewer and the PR-02 PostgreSQL, and the four protected volumes, reported unchanged | transcripts |

How the Viewer was checked: the stage drives the Viewer's own FastAPI application in a short-lived process with
Starlette's test client, using the read-only `trace_viewer_reader` role against the disposable database. No
server was started and no extra port was published.

### Reported, not independently archived

- The accepted Viewer's data after the 5F run (38 traces, 2 anomalies, as before) was read live at the time. Only
  the "before" baselines were archived.
- The accepted local Viewer dataset (38 traces, 2 anomalies, and one HIGH-confidence RCA investigation with five
  evidence rows) is a **different dataset** from the E2E runs above (110 traces, 746 spans, 42 anomalies). The
  project owner checked it manually in a browser. The two datasets' counts must not be combined, and the browser
  screenshots are not part of this repository.
- Per-stage Kafka lag and DLQ figures appear in the transcripts; they were not re-measured afterwards.

## Evidence archive

The validation evidence was collected during the accepted local end-to-end runs and was retained **privately by
the project owner**, outside this repository. The original evidence archive **remains private and is not
distributed with the public repository**; it cannot be inspected from here. It holds the per-run logs and
reports, both harness transcripts, preflight results, protected-resource baselines and both approved-tree
manifests. It is not published because the logs contain local file-system paths and machine-specific identifiers,
and altering them would break their recorded hashes. Log and transcript names that appear in the tables above
describe the private archive's contents; they are not files in this repository.

The archive was hash-listed (SHA-256) when it was created, and the project owner can verify its integrity
locally. A reader of this repository cannot reproduce that check or independently confirm the figures. The
published results are **reported historical validation outcomes, not independently reproducible evidence from a
fresh clone**, and should be read as the project owner's recorded results. The generated credentials, the virtual
environments and the environment file were excluded from the archive.

## Offline tests

The development repository configured a CI workflow to install the component requirements on Python 3.13 and run
each component's suite in its own pytest process: alerting, rca-analyzer, anomaly-detector, trace-viewer,
incident-retrieval, stream-processor, storage-consumer, db-bootstrap, scripts and workload-generator. That
workflow is **deferred from the initial public release** and is not included, and no CI result is claimed. Run
each suite locally in its own process in the same way. Live suites are opt-in and off, and the live harnesses
need Docker. Two tests in `workload-generator/tests/unit/test_commit_batching_it.py` that inspect the CI
workflow adapt to its absence in this release candidate: one skips explicitly and one omits the workflow from
its file checks. In a later local verification of a copy of this release candidate (Windows, Python 3.13.7, one
pytest process per component, no Docker or network), the first of these tests passed and the second skipped with
its stated reason. The same verification ran the component unit suites with no failures or errors (15,601 passed,
34 skipped, 6 deselected); the integration suites, benchmark tests and live harnesses were not run, and the repository-hygiene
tests that need a Git repository were skipped because the copy had none. This is a local result, not a CI result.

## Residual-risk register

Classifications are conservative: nothing is marked resolved without evidence.

| Risk | Status | Detail |
|---|---|---|
| Wider test-suite results: 25 failures and 159 errors | **DEFERRED, cause unknown** | Seen when running the whole workload-generator unit directory under an isolation guard. Several failures were subprocess calls the guard blocks and one was a missing `psycopg` in the test environment; the `test_faults` and `test_personas` errors were not diagnosed. No baseline run exists, so none of them can yet be tied to or cleared of any change. These counts come from an earlier, broader test execution made under a different scope and environment (the whole workload-generator unit directory under an isolation guard). They are preserved as recorded. A later local verification of a copy of this release candidate ran the offline unit suites, one pytest process per component, with 15,601 passed, 34 skipped, 6 deselected, 0 failures and 0 errors (see [Offline tests](#offline-tests)). That later run used a different scope and environment, so it neither resolves nor invalidates the earlier failures and errors |
| Process-tree termination fallback | **ACCEPTED LIMITATION** | Never exercised: both runs stopped their host processes normally |
| Log masking and truncation | **ACCEPTED LIMITATION** | Masking replaces only the credentials the harness generated; other secrets would not be masked. No generated value was found in any archived file |
| Kafka exact-count sensitivity | **ACCEPTED LIMITATION** | The harness compares exact counts; a redelivered record would fail a run rather than be tolerated |
| Windows-specific, machine-pinned E2E | **ACCEPTED LIMITATION** | The harness depends on Windows permission and memory mechanisms, a Docker engine id, protected resource names and a branch name |
| Initial publication pending | **OPEN** | The validated implementation is included in this prepared release candidate. Git initialization, the initial commit, and public publication remain pending separate approval. The validated runs were made on the development working tree; this candidate has been edited only in documentation and the one test adjustment described above |
| Retained disposable credentials | **DEFERRED** | The live harness writes generated, test-only credentials to temporary files and retains its workspace. Treat any retained workspace as private. This release makes no claim that such workspaces have been deleted or that the credentials have been rotated |
| Scope of RCA validation | **ACCEPTED LIMITATION** | One anomaly was investigated in the live run |
| Components outside the runs | **ACCEPTED LIMITATION** | Grafana, alerting, incident retrieval and the standalone Viewer overlay were not part of the live validation |
| No OpenInference | **NOT IMPLEMENTED** | Referenced nowhere in the repository |

## What this does and does not establish

This is **successful end-to-end validation of a local MVP**: with the stated inputs, the pipeline produced the
expected counts, detected the expected anomalies, investigated one of them without duplication, presented it
consistently through the Viewer API, and cleaned up after itself without disturbing protected resources.

It is **not** a production-readiness certification. It does not cover authentication, multi-host deployment,
failure modes beyond those in the limited recovery study, sustained load, other operating systems, or the
components listed above. The benchmark and recovery work
([benchmarks/RESULTS.md](../benchmarks/RESULTS.md),
[workload-generator/PHASE-14.5-FAILURE-RECOVERY.md](../workload-generator/PHASE-14.5-FAILURE-RECOVERY.md)) is
limited by its own stated scope.

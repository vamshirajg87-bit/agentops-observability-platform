# AgentOps Intelligence Platform

A local observability and diagnosis pipeline for AI-agent workloads. It collects OpenTelemetry traces from an
agent, moves them through Kafka into PostgreSQL, models them with dbt, flags anomalies, produces a
root-cause-analysis (RCA) investigation with ranked evidence for a chosen anomaly, and shows the result in a
read-only Trace Viewer.

**Status: a validated local MVP, exercised with synthetic workloads.** It is not a production-ready or
commercial platform, and nothing here claims production readiness, production-scale throughput, scalability or
a measured RCA accuracy. The Trace Viewer is a local, unauthenticated tool; it is not a hosted public showcase,
and no public demo exists. See [Limitations](#limitations) before relying on any part of it.

## The problem

Agent runs fail or slow down in ways that are hard to see from logs alone: a tool call errors repeatedly, a step
takes far longer than usual, a trace is incomplete. This project asks a narrow, testable question: given
telemetry from an agent, can a small pipeline of ordinary components detect that something is wrong, point at
the span responsible, and present the evidence next to the trace? The workload is synthetic and deterministic,
so every result can be checked against a plan.

## Architecture in one picture

```text
Synthetic agent / workload -> OpenTelemetry -> OTLP Collector -> Kafka -> stream processing / storage
    -> PostgreSQL + dbt -> anomaly detection -> RCA investigation and evidence -> Trace Viewer
```

Details, source files and a component-status matrix are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Component status

| Component | Implemented | Included in the successful end-to-end runs |
|---|---|---|
| Synthetic workload ([workload-generator/](workload-generator/), [demo-app/](demo-app/)) | yes | yes |
| OpenTelemetry instrumentation and OTLP Collector ([collector/](collector/)) | yes | yes |
| Kafka, stream processor, storage consumer ([stream-processor/](stream-processor/), [storage-consumer/](storage-consumer/)) | yes | yes |
| PostgreSQL bootstrap and dbt ([db-bootstrap/](db-bootstrap/), [analytics/](analytics/)) | yes | yes |
| Anomaly detector ([anomaly-detector/](anomaly-detector/)) | yes | yes |
| RCA analyzer ([rca-analyzer/](rca-analyzer/)) | yes | yes (Step 5F) |
| Trace Viewer API ([trace-viewer/](trace-viewer/)) | yes | yes, in-process (Step 5F) |
| Standalone Viewer Compose overlay, Grafana, alerting, incident retrieval | yes | **no** |

"Implemented" means the code and its offline tests exist. "Included in the successful end-to-end runs" means it
ran in the Phase 14.7 live validation described in
[docs/VALIDATION-AND-ACCEPTANCE.md](docs/VALIDATION-AND-ACCEPTANCE.md).

**OpenInference is not implemented.** The repository contains no OpenInference dependency or reference. Spans are
produced with the OpenTelemetry SDK and carry `gen_ai.*` and `agentops.*` attributes.

## Validation status

Phase 14.7 ran the whole chain twice on a disposable Docker Compose project, each time ending in a verified
cleanup. Each run sent 110 synthetic requests, stored 746 spans, detected 42 anomaly events and re-ran the
detector without inserting duplicates. The second run also investigated one CRITICAL tool-failure anomaly
(five evidence rows, repeated without duplication) and checked it through the Trace Viewer API. These are
reported historical results from the project owner's accepted local runs. The underlying evidence archive is
private and is not distributed with this repository, so the figures cannot be reproduced from a fresh clone. The
residual-risk register is in [docs/VALIDATION-AND-ACCEPTANCE.md](docs/VALIDATION-AND-ACCEPTANCE.md).

The accepted local Viewer dataset (38 traces, 2 anomalies, one HIGH-confidence RCA investigation with five
evidence rows) is a different dataset from these end-to-end runs; its counts are not combined with theirs.

This is successful end-to-end validation of a local MVP on one pinned Windows and Docker Desktop environment. It
is not a certification of production readiness.

## Getting started

[docs/SETUP-AND-OPERATIONS.md](docs/SETUP-AND-OPERATIONS.md) lists prerequisites, configuration, ports, startup
and shutdown, and troubleshooting. There is no validated one-command start. Several setup paths there are
source-derived and labelled unverified. The live end-to-end harness
([workload-generator/run_e2e.py](workload-generator/run_e2e.py)) is pinned to a specific machine and is not an
installer.

## Limitations

- **Security.** Everything is for a single machine. Published ports are bound to `127.0.0.1`, which restricts
  where a connection can come from but is not authentication. The Trace Viewer has no authentication. In the
  optional pipeline overlay the storage consumer connects as the PostgreSQL owner role.
- **Portability.** The validated workflow is Windows-first. The live end-to-end harness
  ([workload-generator/run_e2e.py](workload-generator/run_e2e.py)) is pinned to the original developer machine's
  Docker engine, protected containers and volumes, Git branch and approved-tree manifest. It is included to
  document how the validation was done, and it refuses to run elsewhere until that code is edited deliberately.
  The retained E2E validation harness is machine-pinned and is not a portable fresh-clone installer.
  A CI workflow is deferred from the initial public release, so no CI result is claimed.
- **Source state.** The validated implementation is provided as a clean public-release source tree on the `main`
  branch, without importing the development repository's Git history. Local validation does not establish that a
  public GitHub release has been published.
- **Scale.** The benchmark and recovery work ([benchmarks/](benchmarks/),
  [workload-generator/PHASE-14.5-FAILURE-RECOVERY.md](workload-generator/PHASE-14.5-FAILURE-RECOVERY.md)) covers
  small synthetic workloads on one laptop and supports no production-capacity claim.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): pipeline, components, source files and status
- [docs/SETUP-AND-OPERATIONS.md](docs/SETUP-AND-OPERATIONS.md): environment, startup, shutdown, troubleshooting
- [docs/VALIDATION-AND-ACCEPTANCE.md](docs/VALIDATION-AND-ACCEPTANCE.md): Phase 14.7 results and residual risks
- [docker/trace-viewer/README.md](docker/trace-viewer/README.md): the Trace Viewer demonstration
- [.env.example](.env.example): the credential template (every value is intentionally empty)

## License

AgentOps-owned source code is licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE). Third-party
dependencies and model weights are not covered by that license and keep their own licenses; see
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for the reviewed inventory and its limitations.

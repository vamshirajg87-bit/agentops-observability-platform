# Pipeline benchmark (Phase 14.4)

This directory holds the benchmark of the AgentOps telemetry pipeline. It measures what a single, disposable copy of
the pipeline does under a generated workload, and it records the result as audited evidence. It is a **measurement and
safety harness**, not a capacity certificate: read [RESULTS.md](RESULTS.md) for what the stored runs do and do not
show.

**Status.** **Phase 14.4: CLOSED — October 17, 2026, with explicit deferrals.** **Phase 14.5 (failure-recovery validation): CLOSED WITH
DOCUMENTED DEFERRALS.** S1-S5 live PASS; S6 deferred (offline-tested, live inconclusive, host-blocked); the C04
cooperative-sticky rebalance test still FAILS and that configuration is unsupported. See
[PHASE-14.5-FAILURE-RECOVERY.md](../workload-generator/PHASE-14.5-FAILURE-RECOVERY.md). Phase 14.6 has not started.
Repetition 10 is reserved, unregistered and unclaimed. The Phase 14.4 closure record, with the accepted scope, is at
the end of [RESULTS.md](RESULTS.md).

The explicit deferrals are: SMALL at 25, 50 and 100 requests/s; MEDIUM, LARGE and STRESS; sustained capacity and soak
testing; generator-only calibration; AppContainer / Job Object isolation; integration of the hash-chained evidence
store; live validation of the host-memory checkpoint and of the CPU and memory stop rules; a controlled comparison of
consumer commit strategies; CI integration (GitHub Actions CI is intentionally deferred from the initial public
release); and an off-device backup. Generator calibration, process-level isolation
and the evidence store are committed but disabled (section 12).

Everything stated here was checked against the source in this directory (`run_benchmark.py`, `metrics.py`,
`ladder.json`) and `workload-generator/run_smoke.py`. Where the source and its own comments disagree, this file says so
([Known documentation drift](#13-known-documentation-drift)).

## 1. What is benchmarked

```
REAL workload -> OTLP -> collector -> Kafka raw -> stream processor
    -> Kafka canonical -> storage consumer -> PostgreSQL
    (-> analytics refresh -> anomaly detector, levels that allow it)
```

One **cell** is one (level, rate, concurrency, repetition) on a **fresh isolated stack**: a separate Compose project
(`agentops-workload-smoke`) with loopback ports 14317 (OTLP), 19092 (Kafka) and 15432 (PostgreSQL), a temporary
virtual environment, and generated throwaway credentials. The stream processor and the storage consumer run as host
processes. A cell:

1. checks the repository (expected HEAD, clean tree, empty index), the disk floor, the ports and the Docker state;
2. collects a machine baseline (including the Docker engine's CPU and memory allocation);
3. starts the stack, then runs a **warm-up** run (its own run id, excluded from every number);
4. **host-memory checkpoint** (section 5), then a clock probe;
5. starts the samplers and runs the **measured** run, with exact reconciliation, drain and settle;
6. reads the offsets, the driver report and the database, and runs the analytics refresh and the detector where the
   level allows it;
7. always cleans up, verifies the cleanup, writes one JSON result and a ledger entry.

Nothing is retried. A failed or stopped cell is evidence, not an error to repair.

## 2. The ladder (`ladder.json`)

`ladder.json` holds **targets and limits only**; it is pinned by a hash in `run_benchmark.py`
(`APPROVED_LADDER_SHA256`), so changing it makes every live run refuse.

| Level | Requests | Spans | Rates (requests/s) | Live allowed | Refresh and detector |
|---|---|---|---|---|---|
| SMOKE | 100 | 700 | 5, 10 | yes | yes |
| SMALL | 1,000 | 7,000 | 10, 25, 50, 100 | yes | yes |
| MEDIUM | 10,000 | 70,000 | 50, 100, 200 | **no** | yes |
| LARGE | 100,000 | 700,000 | 100, 200 | **no** | no (the detector is quadratic in history) |
| STRESS | 500,000 | 3,500,000 | 200 | **no** | no |

Defaults: scenario `normal`, seed 42, concurrency 32, warm-up 30 s of traffic (requests = rate × 30), at least 10 s
measured, 3 repetitions when planning, drain limit 120 s, settle 6 s, sample interval 10 s, cell budget 3,600 s. A
cell's measured duration is requests ÷ rate (SMALL at 10/s: 100 s).

Each request produces 7 spans. In this repository **only 13 cells are approved to run live** (below); every other
cell, including SMALL at 25, 50 and 100 requests/s and all of MEDIUM, LARGE and STRESS, is refused.

## 3. Plan mode and live mode

Without `--live` the program only **plans**: it validates the ladder, prints the cells, run ids, durations and where
results would go, and touches nothing.

```
venv\Scripts\python.exe benchmarks\run_benchmark.py --level SMALL --rate 10 --repetition 9
```

Flags (from `argparse` in `main`): `--config`, `--level` (required; one of the five levels), `--rate` (repeatable),
`--repetitions` or `--repetition N` (mutually exclusive; N is 1-10 and required with `--live`), `--concurrency`,
`--output-dir`, `--warmup-requests`, `--expect-head`, `--authorize`, `--live`. `--output-dir` must be outside the
repository, and a live run accepts only the canonical directory, `<temp>\agentops-benchmarks`.

A **live** run needs all of these, and refuses before starting anything if one is missing or wrong:

```
venv\Scripts\python.exe benchmarks\run_benchmark.py --level SMALL --rate 10 --repetition N ^
    --warmup-requests 300 --live --authorize bm-small-r0010-c32-repN --expect-head <full 40-character HEAD>
```

- `--authorize` must equal the cell's id and be one of the approved cells; `--repetition` and `--warmup-requests` must
  match the approval; exactly one cell may be planned;
- `--expect-head` must be the full SHA of the commit that is checked out, on a named branch, with a clean working tree
  and an empty index;
- the cell's registered configuration must agree across its independent approval tables (below).

Live runs are authorized one at a time by the project's review process. Do not run one without that authorization.

### Approved cells and single use

`APPROVED_LIVE_CELLS` lists 13 cells: `bm-smoke-r0005-c32-rep2` to `rep5` and `bm-small-r0010-c32-rep1` to `rep9`.
`rep10` is **not registered**; the planner accepts repetitions 1-10, so rep10 is the last number it accepts. A cell is
registered in seven independent structures (`APPROVED_LIVE_CELLS`, `APPROVED_DIAGNOSTIC_INTERVALS`,
`APPROVED_COMMIT_BATCHING`, `COMMIT_BATCHING_CELLS`, `COMPARABILITY_REFERENCES`, `CELL_LIMITATIONS`,
`DIAGNOSTIC_TIMING_CELLS`), and a live run is refused unless they agree.

Each cell is **single use**. The harness takes ownership of the output directory and writes, in
`<temp>\agentops-benchmarks`:

- `ACTIVE_RUN`, while a cell is running;
- `ledger\<id>.started` (the claim: configuration, expected HEAD, branch) and `ledger\<id>.done` (the result path and
  SHA-256, the verdict, whether cleanup was verified);
- `CLEANUP_UNVERIFIED`, if cleanup could not be verified. Live runs stay blocked until someone inspects Docker and
  removes it by hand.

A cell that was claimed can never run again, whatever its outcome. Results go outside the repository
(`<id>-<timestamp>.json`), plus a `<id>-consumer-timing.jsonl` sidecar for the timing-diagnostic cells.

## 4. Operator preflight

Some of this is enforced by code and some is **operator policy** the code cannot check. Do not treat the second list as
enforced.

**Enforced by the harness**
- expected HEAD, branch, clean tree and empty index, before any claim;
- the free-disk floor (10 GiB) and a projected need (2 × the planning estimate);
- the three loopback ports free; the normal Docker stack recorded before and checked unchanged after the cell;
- the effective configuration matching the approved one, and the ladder hash;
- the keep-awake request (section 7), made before the claim; a refusal ends the run with no repetition consumed.

**Operator policy (not enforced)**
- AC power connected (two readings, at least 15 s apart, both Online); the laptop has entered Modern Standby while on
  battery (seen in the Windows event log, outside the benchmark evidence);
- host **available memory of at least 4,000 MiB** at the three readings taken about 15 s apart. This floor is
  **provisional**: both VALID runs on the current configuration started above about 3.7 GB, and the review after rep9
  judged the earlier 3,072 MiB minimum too thin (a policy judgement based on one monitored run, not a measured limit);
- Windows session unlocked; no benchmark, smoke, consumer or stream-processor process running;
- Docker Desktop with **4 CPUs and 5,157,535,744 bytes** (the configuration of reps 5-9); the harness records
  whatever the engine reports, and comparability notes are attached to the result;
- the MVP containers healthy and the legacy `agentops-postgres` container stopped. The harness must never start, stop
  or recreate them.

## 5. Host-memory checkpoint (`host_memory_checkpoint`)

Between the warm-up and the measured run, the harness takes **three** readings of the host's available physical memory
(`GlobalMemoryStatusEx`) about 0.25 s apart and compares the **smallest** with a provisional threshold of
**2,048 MiB (2,147,483,648 bytes)**.

- A reading is valid only as a whole, non-negative byte count. A failure, `None`, bool, float (including NaN and
  infinity), string or negative value makes that reading unavailable, never 0.
- Exactly at the threshold passes; one byte below stops.
- **Any** unavailable reading stops the cell (the memory could not be verified).
- A stop is a controlled `_Stop`: no measured traffic, normal cleanup, verdict **STOPPED**, and the repetition is
  **spent**, because the cell was already claimed.
- Two observation-only readings (before the stack starts, and once it is ready) are recorded and never stop a run.
- The evidence is under `metrics.resources.host_memory_checkpoint_*` and is cross-checked against the verdict and the
  stop reasons by `metrics.validate_result`.
- The checkpoint is a **safety stop before load**. It is separate from the post-run resource rules below.
- It is **offline-tested but not live-validated**: its tests use injected readers. Its real memory reader has run live
  (as part of the host sampler), but the checkpoint itself has not been exercised in a live cell.

## 6. Resource sampling, coverage and stop rules

All resource rules are **judged after the measured run**; a running stage is never interrupted.

Sampling (interval 10 s configured, about 12 s observed because each `docker stats` call takes about 2 s):
- **Docker**: CPU and memory of the benchmark's own containers, one tick per `docker stats` call;
- **Host** (Windows): CPU and working set of the benchmark-owned storage consumer and stream processor (a venv
  launcher, when present, is a separate `:launcher` entry), host available memory, whole-host CPU, and free disk space
  of the repository's volume. These are observations only and feed no stop rule.

Rules (thresholds from `ladder.json`):
- **Docker CPU**: the containers' CPU is added per complete tick and divided by the recorded Docker NCPU; the cell is
  STOPPED when it stays at or above **99.5% for 60 s** over consecutive usable ticks (a failed or incomplete tick, or a
  gap above twice the interval, breaks the run);
- **Docker memory**: STOPPED when any one container is above **90%** of its reported limit, or when the containers'
  summed memory in one tick exceeds 90% of the recorded Docker `MemTotal`. A tick missing a container gives only a
  lower bound, which counts only when it already exceeds the limit;
- **Lag**: STOPPED when raw or canonical Kafka lag grows across **6** consecutive samples;
- **Disk**: STOPPED below the floor or the projected need;
- **Coverage**: the Docker samples must give at least 5 usable ticks for each of CPU and memory, cover at least 80% of
  the sampler's window, start and end within 2 × the interval of the window's edges, and have no gap above 3 × the
  interval. Otherwise the result is **INVALID** (an integrity gate), not STOPPED. A missing observation is never read
  as zero.

## 7. Windows keep-awake and host interruption

Before the claim the harness asks Windows to stay awake with `SetThreadExecutionState` using
`ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED` (`0x80000003`), reads the aggregate state back, and releases
the request in a `finally`. It changes no persistent power setting. The result records the acquisition and read-back,
the session lock state and idle time at the start and end, and any Kernel-Power events 506/507 (Modern Standby entry
and exit) in the run's window. If a standby is suspected, the **platform throughput and persistence latency claims are
withdrawn**; the verdict and the other claims follow the evidence as usual.

## 8. Cleanup and evidence integrity

- Cleanup always runs: samplers, host processes, the timing-sidecar capture, the refresh profile, then the whole stack
  (`compose down --volumes --rmi local --remove-orphans`) and the temporary directory. It is **verified**: no smoke
  containers, networks, volumes or images left, and the normal Docker state identical to before.
- A cell whose cleanup is not verified writes `CLEANUP_UNVERIFIED` and keeps `ACTIVE_RUN`.
- `.done` records the SHA-256 of the result file. **Never edit, move or delete** a result, a sidecar or a ledger file;
  doing so breaks the single-use guarantee and the audit trail.
- Every number carries its kind: MEASURED, DERIVED, OBSERVATION or NOT_MEASURED (with a reason). A value that is
  unavailable is NOT_MEASURED, never 0.
- Result validation (`metrics.validate_result`) is strict, and results written before a field existed stay valid
  without it (older results simply lack the newer optional blocks).

## 9. How to read a verdict

| Verdict | Meaning |
|---|---|
| VALID | Every integrity gate passed and no stop rule fired. Reconciliation: spans ended, exported, canonical, stored and distinct all match the plan; no missing, no duplicates; DLQ 0. |
| INVALID | An integrity gate failed or was never evaluated (including the harness failing, or inadequate resource sampling). The numbers cannot be trusted. |
| STOPPED | A stop rule ended or condemned the run (lag growth, resource limits, cell budget, the host-memory checkpoint, an unverified cleanup). |
| GENERATOR_BOUND | Complete and correct, but the load source could not keep the requested rate (more than 5% of requests started late). It describes the generator, **never** the platform's capacity. |

Precedence: INVALID > STOPPED > GENERATOR_BOUND > VALID. The result's `claims` block says which kinds of statement the
evidence allows (`platform_throughput`, `persistence_latency`, `span_volume_handled`, `no_loss_for_this_run`,
`load_source_limit_only`); it never contains claim text. **A VALID verdict is not a capacity result.**

## 10. Offline testing

The tests start no process, socket, container or database and send no telemetry; several tests prove that. The real
Windows host-resource API is blocked in the benchmark tests, and the D3 harness modules cannot be imported by them.

```
venv\Scripts\python.exe -B -m pytest benchmarks -q -p no:cacheprovider
venv\Scripts\python.exe -B -m pytest workload-generator\tests -q -p no:cacheprovider
set PYTHONPATH=<repo>\demo-app && venv\Scripts\python.exe -B -m pytest storage-consumer\tests\unit -q -p no:cacheprovider
```

The **B3J-301 verification snapshot** (the code later committed as B3J-302) gave 3,453 passed and 3 skipped (a POSIX
path-case rule and two symbolic-link tests) for `benchmarks`, 1,612 passed for the workload generator, and 651 passed
for the storage consumer's unit tests. These are point-in-time counts and **will not stay current as tests change**;
rerun the commands for today's numbers. The storage-consumer suite needs `PYTHONPATH` set to `demo-app` (as the
development repository's CI step did), and only its `tests\unit` directory is meant to run offline. GitHub Actions CI
is intentionally deferred from the initial public release: no CI workflow is included, no CI result is claimed, and
no benchmark CI step exists. These suites run locally.

## 11. Known laptop limitations and prohibited actions

**Limitations**
- One machine and one Docker Desktop VM. The earlier results (22-CPU engine, 8,168,574,976 bytes) and the current ones
  (4 CPUs, 5,157,535,744 bytes) are not directly comparable.
- Host available memory fell by about 1.66 GiB across a SMALL-10 cell on a 16 GB laptop (see RESULTS.md); the cause is
  unattributed.
- Docker sampling at about 12 s cannot see a spike shorter than the interval; summed container memory is not exactly
  the VM's physical use; the MVP containers share the Docker VM and are not counted.
- Resource enforcement is after the fact, except the single memory checkpoint before load.
- The laptop entered Modern Standby during one run (SMALL-10 rep7), according to the review of that run
  (see RESULTS.md, where this is labelled a review conclusion; rep7's own result holds no host diagnostics).

**Prohibited**
- Running any live cell without the project's explicit authorization, rerunning or retrying a claimed cell, or
  bypassing a guard (`--live` gates, expected HEAD, the ledger).
- Editing, moving or deleting benchmark evidence or the ledger.
- Starting, stopping or recreating the MVP containers (`agentops-mvp-postgres-1`, `agentops-mvp-viewer-1`,
  `agentops-mvp-db-bootstrap-1`) or the legacy `agentops-postgres`.
- Changing Windows power settings, or locking or sleeping the session during a run.
- Registering a new cell, or changing `ladder.json`, thresholds or approvals, outside a reviewed change.

## 12. Deferred modules (committed, gated off, not used by the live harness)

Four more modules sit in this directory: `calibrate_generator.py`, `appcontainer_preflight.py`, `win32_job.py` and
`evidence_store.py`. Together they are the start of (a) a **generator-only calibration** and (b) a stricter,
**process-level isolation** path with an immutable evidence record. They are committed and have offline tests, but they
are **disabled, have never been run against the host, and are not imported by `run_benchmark.py` or `metrics.py`**.
Nothing in [RESULTS.md](RESULTS.md) depends on them. **No generator calibration has been run:** there is no calibration
result in the evidence store, and no `agentops-calibration` output directory exists on the machine where the benchmarks
ran.

| Module | Intended purpose | Enabled or gated | Used by the live harness | Tested offline | Unverified or deferred |
|---|---|---|---|---|---|
| `calibrate_generator.py` | "Condition A" calibration: how far the workload generator's own request starts lag behind their planned times with **no platform running**. It reuses the real driver scheduling with an in-memory span exporter, on SMOKE-shaped traffic (seed 42, warm-up 25 and measured 100 requests, 5 requests/s, concurrency 32). It also has an isolation probe (`--probe`) for a Windows AppContainer child. | **Gated off.** `EXECUTION_ENABLED = False`, `APPROVED_CALIBRATIONS` empty, `PROBE_ENABLED = False`, `APPROVED_PROBES` empty, `AUTHORIZED_APPCONTAINER_SID = None`, `AUTHORIZED_PROFILE_PREFLIGHT_SHA256 = None`. A run would also need a full expected HEAD and a series token. | No. | `tests/test_calibration.py` (234 test functions): children, launchers, observations, clocks and the driver are fakes; no process or socket. | Never executed; no calibration result exists. AppContainer denial of loopback traffic is untested on the host, and the compatibility of CPython, the venv packages and the demo with an AppContainer is explicitly **not assumed**. A staged copy has no `.git` directory, but the harness reads HEAD from it, so a staged probe cannot start until that is solved. |
| `appcontainer_preflight.py` | Read-only planner for the future AppContainer staging environment: injectable host-inventory collectors, pure functions that turn an inventory into a dry-run staging plan with a recommendation that stays NO-GO unless every prerequisite is independently verified, and identity helpers (manifest digests, authorization-context schema). | **Gated off.** `HOST_INVENTORY_ENABLED = False`; the real collectors refuse before touching the host. | No. | `tests/test_appcontainer_preflight.py` (135 test functions) with fake host data only. | Real host inventory has never been collected; no AppContainer profile, ACL change or staging has been performed. |
| `win32_job.py` | A fail-closed Windows Job Object backend for the future staged AppContainer child: exactly one unnamed job with kill-on-close and a one-process limit, membership checks, and creation-attribute planning. | **Gated off.** Native calls need the calibration harness authorization, which is closed. Termination is refused while the lifecycle policy is design-only, and `JOB_LIST_CREATION_INTEGRATED = False`, so the proof that a child joined the job at creation cannot be minted. | No ("nothing calls it"). | `tests/test_win32_job.py` (148 test functions) with a fake kernel32 and fake handles. | Real job objects have never been created; the launcher has no `JOB_LIST` integration. |
| `evidence_store.py` | An offline, **hash-chained, immutable evidence record** for the future isolated runs: record schema, chain verification, recovery classification, and a writer that works only through an injected file-system interface. A Windows adapter exists for it. | **Gated off.** The Windows adapter can be built only with `EVIDENCE_WRITES_ENABLED` true (it is `False`) and a sealed authorization from the closed harness gates. | No. The live harness does not import it. | `tests/test_evidence_store.py` (107 test functions) with an in-memory fake file system and fault injection. | Never wrote to a real file system. By its own statement, a hash chain detects deleted, reordered, truncated or altered records but is **not authentication**, and "verified written" is not a claim of crash durability. |

The test-function counts are the counts at the commit that added this section and, like the other counts in this file,
will drift.

### What is active, and what is not

- **Isolation that is active:** the disposable Docker Compose project `agentops-workload-smoke`, with loopback-only
  ports, a temporary virtual environment, generated throwaway credentials, and a verified teardown (README section 8).
  The stream processor and storage consumer run as **ordinary host processes** started by the harness; they are not
  sandboxed and their network access is not restricted. **The AppContainer and Job Object path is not enabled** and
  provides no isolation today.
- **Evidence integrity that is active:** each run writes one JSON result that is validated against a strict schema, and
  `ledger/<id>.done` records that file's SHA-256 together with the verdict and the cleanup verification. This protects
  against accidental changes to a result file, but not against a deliberate one: the result and the ledger sit in the
  same directory, and anyone able to write there could change both. **The hash-chained evidence store is not
  used**, so no run's evidence is chained, anchored or tamper-evident beyond that hash.
- **Generator timing that is recorded:** each live result carries the scheduler's own start-lag statistics for that run
  (late starts, maximum and mean start lag). These come from the benchmark runs themselves, with the platform running.
  They are not a calibration, and generator-only start-lag has never been measured separately.

### Closure scope

Generator calibration, process-level (AppContainer / Job Object) isolation and integration of the hash-chained evidence
store are **explicitly deferred from the Phase 14.4 closure scope**. They are not abandoned, and enabling any of them is
a separate reviewed code change plus its own authorization (the workflow is described in the docstring of
`calibrate_generator.py`). Phase 14.4 was closed on 2026-10-17 with these items among its explicit deferrals (see the
closure record in [RESULTS.md](RESULTS.md)); this section changes no result or performance claim.

## 13. Known documentation drift

These are inaccuracies in existing source text, not behaviour; they are recorded here rather than silently fixed (the
code, the ladder and the command line were not changed for this document):
- **`LIVE_ENABLED = True` is the actual code state.** The module docstring of `run_benchmark.py` ("Live execution is
  DISABLED in this version") and the `--live` help text ("disabled in this version") are **stale**. Live runs are
  possible, but only for the approved cells and only through the gates above.
- **`--allow-large` is not implemented.** The note on the LARGE level in `ladder.json` refers to that flag, but the
  current command line defines no such option. The reference is documentation drift. It is **not** an authorization or
  a route to run larger cells: LARGE, STRESS and MEDIUM are `live_allowed: false` and are not in the approved list, so
  they are refused.

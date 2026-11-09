# Benchmark results summary (Phase 14.4)

This file summarizes the benchmark evidence stored on the development laptop up to **SMALL-10 repetition 9**
(2026-10-17). It is a reading of the stored result files and ledger, not a new measurement, and it does not replace
them. The authoritative records are the JSON results, the `.started`/`.done` ledger entries and the timing sidecars in
`<temp>\agentops-benchmarks` (outside the repository). Methodology, safety rules and the meaning of the verdicts are in
[README.md](README.md).

**Status.** **Phase 14.4: CLOSED — October 17, 2026, with explicit deferrals** (the closure record is at the end of
this file). **Phase 14.5 (failure-recovery validation): CLOSED WITH DOCUMENTED DEFERRALS.** S1-S5 live PASS; S6
deferred (offline-tested, live inconclusive, host-blocked); the C04 cooperative-sticky rebalance test still FAILS and
that configuration is unsupported. See [PHASE-14.5-FAILURE-RECOVERY.md](../workload-generator/PHASE-14.5-FAILURE-RECOVERY.md).
Phase 14.6 has not started. Repetition 10 is reserved, unregistered and unclaimed.

**How statements are labelled.** Three kinds of statement appear, and the difference matters:
- **[Recorded]**: read directly from a stored result file or ledger entry (the numbers in the tables are of this kind
  unless a note says otherwise);
- **[Review]**: a conclusion reached in a later engineering review step, supported by evidence that is *not* all stored
  in the result files (the Windows event log, timing analyses, a recomputation). It is cited, but not proven by the
  result it is attached to;
- **[Unresolved]**: a hypothesis or an open question; no cause is claimed.

**Read this first.** These runs show that, on one laptop, at **5 and 10 requests/s for 100 requests and 1,000
requests**, the pipeline persisted every span it was given without loss or duplication in the runs recorded as VALID.
They do **not** establish production capacity, a throughput ceiling, behaviour at any higher rate, or behaviour over
long durations. See [Limits on what these results show](#limits-on-what-these-results-show).

## 1. Two configurations, not one

| | Reps run on the 22-CPU engine | Reps run on the current engine |
|---|---|---|
| Cells | SMOKE-5 reps 1-5, SMALL-10 reps 1-4 | SMALL-10 reps 5-9 |
| Docker engine | 22 CPUs, 8,168,574,976 bytes (8,168,583,168 in SMOKE rep1-3) | **4 CPUs, 5,157,535,744 bytes** |
| Offset commits | one Kafka commit per message (these results predate batching) | rep6: per message; reps 7-9: batched, 100 messages or 1.0 s |
| Host-resource observations | none | only rep9 (rep8 has a host-interruption block, no resource series) |

Throughput and latency from the two columns are **not directly comparable**; each later result carries a limitation
saying so. The "current" configuration is a 16 GB laptop with Docker Desktop limited to 4 CPUs and about 5.2 GB.

## 2. SMOKE-5: 100 requests at 5 requests/s (700 spans)

| Cell | Start (UTC) | Verdict | Requests/s | Persistence p50 / p95 / p99 (ms) | Notes |
|---|---|---|---|---|---|
| rep1 | 2026-10-08 17:42 | VALID | 5.01 | 949 / 1,585 / 1,696 | Predates the single-use ledger: a result file exists, no `.started`/`.done` |
| rep2 | 2026-10-08 19:01 | **GENERATOR_BOUND** | 4.97 | 724 / 1,373 / 1,634 | 10.0% of requests started late (> 5%): describes the load source, not the platform |
| rep3 | 2026-10-08 20:57 | VALID | 5.01 | 639 / 1,018 / 1,239 | |
| rep4 | 2026-10-11 05:45 | VALID | 5.01 | 860 / 1,523 / 1,660 | |
| rep5 | 2026-10-11 14:27 | VALID | 5.01 | 641 / 1,135 / 1,266 | |

All five reconciled exactly (700 spans ended, canonical, stored and distinct; DLQ 0); canonical lag peaked at 0.
SMOKE is a small functional load. It does not establish anything about higher rates.

## 3. SMALL-10: 1,000 requests at 10 requests/s (7,000 spans)

Every SMALL-10 run was planned for 7,000 spans over 100 s of measured traffic, after a 300-request warm-up.

| Cell | Start (UTC) | Engine | Commits | Verdict | Req/s | Spans persisted/s | Persistence p50 / p95 / p99 (ms) | Canonical lag max | Late starts |
|---|---|---|---|---|---|---|---|---|---|
| rep1 | 10-11 15:53 | 22 CPU | per msg | VALID | 9.98 | 68.2 | 1,205 / 3,186 / 3,520 | 277 | 0 |
| rep2 | 10-11 17:29 | 22 CPU | per msg | VALID | 9.98 | 68.7 | 1,109 / 3,066 / 3,782 | 208 | 6 (0.6%) |
| rep3 | 10-11 20:32 | 22 CPU | per msg | VALID | 9.98 | 68.6 | 1,009 / 2,909 / 3,327 | 235 | 0 |
| rep4 | 10-12 04:38 | 22 CPU | per msg | VALID | 9.98 | 65.3 | 2,670 / 6,625 / 7,563 | 406 | 0 |
| rep5 | 10-15 20:38 | 4 CPU | per msg | **INVALID** | none | none | none | none | none |
| rep6 | 10-15 21:40 | 4 CPU | per msg | **STOPPED** | 9.98 | 64.6 | 3,418 / 7,322 / 8,673 | 379 | 0 |
| rep7 | 10-16 18:05 | 4 CPU | batched | **GENERATOR_BOUND** | 5.25 | 29.5 | 470 / 48,551 / 48,946 | 1,977 | 277 (27.7%) |
| rep8 | 10-16 20:12 | 4 CPU | batched | VALID | 9.98 | 70.3 | 385 / 639 / 771 | 71 | 0 |
| rep9 | 10-17 04:23 | 4 CPU | batched | VALID | 9.98 | 70.3 | 385 / 640 / 732 | 84 | 0 |

For rep1-4 and rep6 the consumer block is absent, which by the schema means one commit per message. Request latency
(root span duration, which includes planned simulated waits) stayed at about 480-500 ms p99 in every run that has it.

### Runs that are not capacity evidence

- **rep5, INVALID.** The harness failed its own evidence check before any load: the ledger of the isolated stack was not
  complete with the 17 steps the harness then expected (`SmokeFailure`). No metric exists. It is a harness defect,
  recorded as such.
- **rep6, STOPPED.**
  - *[Recorded]* Canonical lag grew across 6 consecutive samples (the stop reason), all claims are withdrawn, and the
    cell used one Kafka commit per message on the 4-CPU engine (its result has no consumer block).
  - *[Review]* The engineering review that followed (the consumer timing analysis, B3J-247, and the batching design
    steps, B3J-256 to B3J-258) attributed the lag growth to the serial storage consumer, whose per-message synchronous
    commit took a large share of each cycle, and added batched commits as an opt-in diagnostic. This diagnosis is **not
    recorded in rep6's result**, and it was not isolated by a controlled experiment: the later batched runs also
    differ in other respects.
- **rep7, GENERATOR_BOUND.**
  - *[Recorded]* 27.7% of requests started late (277 late starts), 5.25 requests/s were achieved, persistence p99 was
    about 49 s, and the largest gap between consecutive ingested spans was about 156 s. Rep7 recorded **no**
    host-interruption diagnostics: it ran before the keep-awake guard and the host block existed, so its result file
    contains no standby record and no Kernel-Power query.
  - *[Review]* The root-cause review after rep7 (B3J-265) matched Windows Kernel-Power events 506/507 (Modern Standby
    entry and exit) in the Windows System event log to the run's time window, which is why the cell is described as
    interrupted by a Windows Modern Standby transition. Those event-log entries live in Windows, not in the benchmark
    evidence. The explanation was then carried into the registered limitation text of rep8 (B3J-277/278), which is the
    in-repository statement of it. The keep-awake guard and the host diagnostics were added afterwards (B3J-267/268,
    B3J-276).
  - The numbers describe the interrupted load source and the stalled laptop, not the platform.

## 4. Reps 8 and 9 in detail

Both ran with the keep-awake guard and with the opt-in consumer batching of **100 messages or 1.0 s**, with the
consumer timing sidecar enabled at 5 s windows (9,100 messages observed over 41 windows each: the 2,100 warm-up and
7,000 measured messages).

| | Rep8 | Rep9 |
|---|---|---|
| Verdict | VALID | VALID |
| Spans ended / exported / canonical / stored / distinct | 7,000 each | 7,000 each |
| Missing, duplicates, DLQ | 0, 0, 0 | 0, 0, 0 |
| Requests/s, late starts, max start lag | 9.98, 0, 0.026 s | 9.98, 0, 0.027 s |
| Spans generated/s, persisted/s | 69.86, 70.33 | 69.86, 70.31 |
| Request p50 / p95 / p99 (ms) | 241.5 / 340.7 / 482.3 | 241.8 / 340.7 / 478.3 |
| Persistence p50 / p95 / p99 / max (ms) | 385.3 / 638.6 / 770.6 / 862.2 | 385.4 / 640.1 / 731.9 / 881.0 |
| Ingest gap max (ms), gaps > 100 ms | 4,549, 155 | 4,080, 158 |
| Canonical lag samples (records) | 0 0 0 10 71 69 23 31 0 0 | 0 0 0 38 5 34 25 84 0 0 |
| Raw lag max | 0 | 0 |
| Commit calls (messages per commit) | 118 (77.1) | 120 (75.8) |
| Analytics refresh | 6.0 s | 6.0 s |
| Host interruption (Kernel-Power 506/507 in the run window) | none; query ok | none; query ok |
| Result SHA-256 | `577108270d3d545d78a3fb2fe50e8468b8d7d705c53aad0c5d0349b5a9709bd9` | `036cc1738da90a937b3a742221aa13689bf1f5b403fbeedb7819fb472488ad64` |

**Resource observations.** The two reps were judged under **different rules**: rep8 ran before the Docker aggregate
CPU/memory rules, the coverage gate and the host-resource sampler existed; rep9 ran with them. Rep8 stays VALID under
its original rules and is not reclassified. *[Review]* A recomputation of rep8's recorded Docker series under the newer
rules (B3J-287; the calculation is not stored in any result) gives a peak of about 46% of the 4 Docker CPUs and at most
about 14.7% of the VM's memory, with no saturation.

| Observation | Rep8 | Rep9 |
|---|---|---|
| Kafka container CPU peak (percent of one core) | 182.85 | 180.89 |
| Kafka container memory peak | 625.9 MiB | 713.0 MiB |
| Docker aggregate CPU peak (percent of the 4 CPUs) | 46.0 (recomputed) | 46.46 |
| Docker aggregate memory peak | at most 757.4 MB (sum of peaks) | 850.8 MB, 16.5% of the VM |
| Docker coverage | not applicable | 11 of 11 ticks, 92.6% of the window, longest gap 12.1 s |
| Storage consumer CPU / working set peaks | not recorded | 5.6% / 48.5 MB |
| Stream processor CPU / working set peaks | not recorded | 4.1% / 39.7 MB |
| Host CPU peak | not recorded | 10.9% |
| Host available memory minimum | not recorded | **2,675.2 MiB** |
| Free disk minimum | not recorded | about 711.7 GiB |

Rep8 and rep9 agree closely, with differences within what two single runs can show. Neither result supports a
statement about variance beyond that.

## 5. Host-memory decline (unresolved)

*[Recorded]* Rep9 recorded host available memory (16,085.4 MiB installed). The first row is an operator reading from
the preflight, not a value in the result file:

| When | Available |
|---|---|
| Operator reading, 04:22:43Z (before the run) | 4,336.1 MiB |
| First sampler reading, 04:26:20Z (start of the measured stage) | 2,975.9 MiB |
| Last sampler reading, 04:28:20Z | 2,675.2 MiB (the minimum) |

*[Recorded]* About **1.36 GiB** disappeared between the operator reading and the first sample, during stack start-up
and warm-up, which no sampler covered, and a further 301 MiB during the measured stage (a steady, nearly monotonic
decline). The host processes grew by about 2 MiB and the Docker containers' reported memory by about 380 MiB over the
stage.

*[Unresolved]* The decline is **not attributed** to a process or subsystem, and the similar size of Docker's figure is a
correlation of two coarse series, not evidence of cause. *[Review]* With the same consumption, a start at the
earlier 3,072 MiB floor would end near 1.4 GiB (a projection, not a measurement); hence the provisional 4,000 MiB
operator floor and the 2,048 MiB post-warm-up checkpoint (README sections 4 and 5).

## 6. The host-memory checkpoint

Committed after rep9 (B3J-302). It is **offline-tested but not live-validated**: its tests use injected readers and
the result validator. Its real memory reader has run live as part of the host sampler, but the checkpoint itself has not
run in a live cell, so no stored result contains checkpoint evidence. Its first live
exercise would also record the host's memory before the stack starts and when it is ready.

## 7. Opt-in consumer batching

Batching (`CONSUMER_COMMIT_BATCH_MESSAGES`, `CONSUMER_COMMIT_INTERVAL_SECONDS`) is an **opt-in diagnostic** of the
storage consumer, enabled only for the registered cells rep7, rep8 and rep9 (100 messages or 1.0 s). It is not the
consumer's default. Across the stored runs, persistence p99 was 3.3-7.6 s with one commit per message (22-CPU reps 1-4)
and 8.7 s on the 4-CPU engine (rep6), against 0.73-0.77 s with batching on the 4-CPU engine (reps 8-9). These differ in
both commit mode and engine allocation, so the improvement is **not** a controlled comparison.

## Limits on what these results show

- **Sample size.** Nine SMALL-10 and five SMOKE-5 runs, two regimes, one machine. The spread inside the 22-CPU regime
  alone (persistence p99 3.3 s to 7.6 s) shows run-to-run variation above a factor of two. No confidence intervals or
  significance tests are computed or implied.
- **Rate and duration.** The highest rate ever executed is 10 requests/s (about 70 spans/s) for 100 s. SMALL at 25, 50
  and 100 requests/s, and MEDIUM, LARGE and STRESS, have **never run**; they are not live-allowed.
- **Capacity.** No ceiling has been found; VALID at 10 requests/s says nothing about 25. Rep9's Kafka container reached
  181% of a 400% CPU budget at 10 requests/s.
- **Soak.** The measured stage of every run lasted at most 100 s. Whole cells took about 4 to 8 minutes (SMOKE rep4
  took about 49 minutes end to end, with the same 20 s of measured traffic). Nothing longer has been run.
- **Default consumer on the small engine.** The consumer's default (per-message commits) was STOPPED on the 4-CPU
  engine (rep6). Batching is untested as a default.
- **Resource enforcement** is post-run, apart from the single pre-load memory checkpoint, which has not run live.
- **Comparisons.** Compare only within a regime, and read the limitations each result carries. Do not compare reps 1-4
  with reps 8-9.
- **Interrupted, stopped and invalid runs** (SMOKE rep2, SMALL rep5, rep6, rep7) are not evidence of capacity.

## Cell and repetition state

Ledger: 26 files (13 cells, `.started` and `.done` each); no `ACTIVE_RUN`, no `CLEANUP_UNVERIFIED`. Each cell's `.done`
records its verdict and `cleanup_verified: true`. **Repetition 10 is reserved: unregistered and unclaimed.** The planner
accepts repetitions 1-10 only, so rep10 is the last it accepts.

## Verified evidence archive

*[Recorded]* On **2026-10-17 (UTC)** a verified archival copy of the benchmark evidence was made, because the active
evidence store lives in the Windows temporary directory.

| | |
|---|---|
| Archive directory | `benchmark-evidence-20261017-194753-464292Z` |
| Base location | `%LOCALAPPDATA%\agentops-backups` |
| Evidence files | 44 (14 result files, 4 consumer timing sidecars, and the 26 ledger files: 13 `.started` and 13 `.done`) |
| Evidence bytes | 1,488,892 |
| `MANIFEST.json` SHA-256 | `00e7dff5b9af8e894b630c7791a65be31f72f959c373fbbadb17c741e8ed41bb` |

- Each archived file's SHA-256 was checked against the original, and all 44 matched, with sizes and modification times
  preserved. The archive holds a manifest (`MANIFEST.json`, with every file's path, size and SHA-256), its checksum
  (`MANIFEST.sha256`) and a README stating what the archive is.
- The active evidence store was not changed by the copy: its files, sizes, hashes and modification times are the same as
  before.
- The archive is a **copy**. It is **not** the active evidence store and **not** a replacement ledger; the single-use
  claim ledger exists only in the active store, and archived files must never be restored into it to recreate or
  release a claim.
- It protects against loss through temporary-file cleanup or accidental deletion of the temporary directory. It sits on
  the **same disk** as the original, so it does **not** protect against disk failure, theft or a machine reset.
- **No off-device backup has been made or verified.**
- The archive was made at repository commit `2482ed58e6732cb3053b7f2516b9b967b243667c`. Its files contain local paths
  and the local account name, so they should not be shared without deciding that is acceptable; this document records
  none of those paths.

This section changes none of the results, interpretations, performance claims or closure classifications in this file.

## Phase 14.4 Closure Criteria and Deferrals

**Phase 14.4: CLOSED — October 17, 2026, with explicit deferrals.**

*Closure record.* The phase was closed on 2026-10-17 on the project's review, with the deferrals in section 3 kept
explicit. Phase 14.5 is **planned and has not started**; closing Phase 14.4 does not start it. Repetition 10 remains
reserved, unregistered and unclaimed.

**Accepted scope of the closure:**
- an isolated benchmark harness;
- strict evidence validation and single-use claims;
- verified cleanup and a verified evidence archive;
- offline-tested safety mechanisms, some of which were also exercised in live runs;
- recorded VALID SMOKE runs at 5 requests/s (4 of the 5 SMOKE runs; the fifth is recorded GENERATOR_BOUND);
- recorded VALID SMALL runs at 10 requests/s (6 of the 9 SMALL-10 runs; reps 5, 6 and 7 are recorded INVALID, STOPPED
  and GENERATOR_BOUND).

Every result classification and recorded measurement in this file is unchanged by the closure, and no capacity or
scaling statement is made. The sections below are the supporting analysis.

### 1. Completed engineering deliverables
- The benchmark harness: plan and live modes, exact-id and exact-HEAD authorization, single-use claims and ledger,
  evidence kept outside the repository, schema validation, verified cleanup, and the pinned ladder.
- The metrics layer with explicit kinds and NOT_MEASURED semantics, reconciliation (loss and duplicates), clock-skew
  checks, lag and late-start rules, and the four verdicts with their precedence.
- Resource and host safety: Docker CPU/memory aggregates with coverage rules, the host-resource sampler, keep-awake
  and Modern Standby diagnostics, and the post-warm-up host-memory checkpoint with evidence cross-checks.
- A consumer bottleneck identified in engineering review (serial per-message commit; see rep6 above) and an opt-in
  batching mitigation.
- An offline test suite (3,453 benchmark tests passed, 3 skipped, in the B3J-301 verification snapshot; a point-in-time
  count, not a standing guarantee) and the documents in this directory.

### 2. Validated limited workload claims
Each applies only to the stated configuration and run, and only to runs recorded VALID:
- SMOKE-5 (4 of 5 runs): 700 spans persisted per run with no loss or duplication.
- SMALL-10 on the 22-CPU engine (reps 1-4): 7,000 spans per run persisted with no loss or duplication; persistence p99
  3.3-7.6 s.
- SMALL-10 on the 4-CPU/5.2 GB engine with batched commits (reps 8-9): 7,000 spans per run persisted with no loss or
  duplication at 70 spans/s; persistence p99 0.73-0.77 s; no host interruption.

### 3. Explicit deferrals
These objectives are **not** part of what the closure accepts:
- SMALL at 25, 50 and 100 requests/s, and any throughput ceiling or saturation point.
- MEDIUM, LARGE and STRESS.
- Sustained capacity and soak (long-duration) testing.
- Behaviour of the consumer's default configuration on a small engine (rep6 was STOPPED), and a controlled comparison
  of consumer commit strategies.
- Generator-only calibration.
- AppContainer / Job Object process-level isolation.
- Integration of the hash-chained evidence store.
- Live validation of the host-memory checkpoint and of the CPU and memory stop rules (only the lag-growth stop has
  fired in a live cell), and the cause of the host-memory decline.
- CI integration: GitHub Actions CI is intentionally deferred from the initial public release, so no CI workflow is
  included and no CI result is claimed. There is no benchmark step in CI, and the suites run locally.
- An off-device backup of the evidence: the verified archive is on the same disk as the original.

### 4. Evidence needed to revisit these
- A larger or dedicated machine (or runner) with a recorded engine allocation, so higher rates are not limited by a
  16 GB laptop; the SMALL 25/50/100 cells registered one at a time with their own review.
- Several repetitions per rate in the same regime, to say anything about variance.
- For MEDIUM and above: a disk budget, a decision on the detector's cost, and a separate authorization.
- Memory attribution: host memory readings at stack start-up, readiness and after warm-up (the checkpoint's observation
  points), or an external trace of the Docker VM.
- A decision on whether batching becomes the consumer's default, with a controlled comparison.
- For calibration, process-level isolation and the evidence store: enabling the gated modules is a reviewed code change
  plus its own authorization (README section 12).
- For CI integration: a workflow change under its own authorization (GitHub Actions CI is intentionally deferred
  from the initial public release).
- For an off-device backup: a destination chosen by the owner of the evidence, then the same verified copy.

### 5. Why production-capacity claims are unsupported
The rate and duration are small; no limit was found; the two regimes differ in engine and consumer mode; the
sample is a handful of single runs on one laptop; the failed, stopped and interrupted runs are unexplained load
conditions, not capacity data; and the resource observations are coarse (about 12 s sampling, post-run judgments).

### Closure decision
Phase 14.4 is **closed with explicit deferrals**. The closure records sections 1-3 as written, treats the SMOKE-5 and
SMALL-10 statements as the only workload claims, and does not claim capacity. It did not include any higher-rate
testing. If a capacity or scaling claim is needed later, the deferred objectives are open work that needs the larger
machine and the authorizations listed in section 4; they are not part of this closure. Repetition 10 stays reserved,
unregistered and unclaimed, and Phase 14.5 is planned and has not started.

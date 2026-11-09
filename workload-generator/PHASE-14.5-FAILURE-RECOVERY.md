# Phase 14.5: failure-recovery and shutdown validation (limited closure draft)

**Status: DRAFT. Phase 14.5 is pending ChatGPT review and explicit closure approval. It is not closed by this document.**

This file records what the isolated shutdown and failure-recovery harness
([run_shutdown_it.py](run_shutdown_it.py)) has and has not shown about the ingestion path (OTLP raw topic, stream
processor, canonical topic, storage consumer, PostgreSQL). It was written on 2026-10-19 from the stored evidence files,
the harness run logs and the accepted review steps B3J-341 to B3J-404. It records results; it does not re-run or
relabel them. Verdicts are quoted as the harness recorded them, including failed and inconclusive attempts.

The sibling record for the preceding phase is [../benchmarks/RESULTS.md](../benchmarks/RESULTS.md) (Phase 14.4).

## 1. Scope and recommendation

**Scope.** Does the pipeline lose data, or advance a Kafka offset past work that is not durable, when a service is
stopped gracefully or killed? Everything was run in disposable Compose projects named `agentops-shutdown-it-<8 hex>`
with remapped ports, never against the protected MVP or legacy containers and volumes.

**Recommendation (not a decision).** Phase 14.5 can be closed *in a limited way*, with the deferrals listed in
section 11, on these grounds:

- graceful stops (S1 to S4) and a forced storage-consumer crash with replay (S5) have live PASS results against a real
  Kafka broker and a real PostgreSQL;
- the one live attempt at the stream-processor crash case (S6) was INCONCLUSIVE and the redesigned case has not been
  run live because the host fails the memory gate;
- the C04 cooperative-sticky rebalance test FAILED and is kept as a failure, with an unsupported-configuration
  restriction (section 7).

Not every failure-recovery scenario is validated. Section 5 separates what has live evidence from what is modeled or
untested.

## 2. Results by case (S1 to S5)

All live runs: one machine, Windows 11 with Docker Desktop on WSL 2, one Kafka broker (`apache/kafka:4.1.0`), three
partitions per topic. Each case ran once to a PASS unless this table says otherwise. A single PASS does not establish
that a different timing of the same fault is safe.

| Case | What was done | Harness commit | Project | Recorded result |
|---|---|---|---|---|
| S1 | Graceful SIGTERM of both services while idle | not recorded in the log | `7dbafcde` | **PASS**, stop 1.37 s, cleanup verified |
| S2 | Graceful stop of the stream processor under load | `1d181d3` | `90d67e27` | **PASS**: 519 messages committed at stop, 0 duplicate copies, stop 0.39 s, cleanup verified |
| S3 | Graceful stop of the storage consumer under load | `8466564` | `bd0205bd` | **PASS**: 0 persisted-but-uncommitted, stop 0.43 s, cleanup verified |
| S4 | Graceful stop with commit batching (50 messages) | `8789897` | `2bf1845b` | **PASS**: batching exercised, 0 persisted-but-uncommitted, stop 0.41 s, cleanup verified |
| S5 | SIGKILL of the storage consumer (batch 500), restart, replay | `ce46b2f` | `ea2cdc48` | **PASS**: see section 4 |

Attempts that did not pass, kept as recorded:

| Attempt | Harness commit | Project | Recorded result | Reason (from the evidence) |
|---|---|---|---|---|
| Earlier S2 attempt 1 | `9f43fc8` | `326e7fd9` | **FAIL** | The harness could not obtain a stable description of the consumer group |
| Earlier S2 attempt 2 | `9460a5c` | `092a142d` | **FAIL** | Same cause: the group description was incomplete after 11 attempts in 31 s |
| S4 attempt 1 | `9bd49ad` | `a5e97758` | **INCONCLUSIVE** (overall **FAIL**) | The stop could not be issued inside the persistence window; the run also recorded cleanup as **not verified** (one network object counted as missing or changed: the default bridge, which Docker recreates on its own). Corrected later by a harness change that proves the window and a verified-default-bridge cleanup policy |

**Evidence limitations for S1 to S5.**
- S1: only the harness's stdout log is stored. There is no JSON evidence file, and the log does not name the commit it
  ran at.
- S2, S3, S5: each has a single run. S2 ran at harness commit B3J-351 (`1d181d3`) and S3 at B3J-357 (`8466564`); both
  predate the later hardening steps B3J-363 and B3J-373.
- The three S4/S5 run logs (`s4_run.log`, `s4_run2.log`, `s5_run.log`) were captured as stdout files; the evidence
  JSON is the authoritative record.
- None of the S1 to S5 results shows behaviour at a different kill timing, a larger workload or a different machine.

**S4 attempt 1 and its cleanup marker.** The original S4 attempt (project `a5e97758`, harness `9bd49ad`) ended
INCONCLUSIVE with cleanup recorded as **not verified**: its message was "1 existing networks object(s) missing or
changed", and the object was the Docker default bridge, which Docker Desktop recreated on its own. The harness left its
blocking marker `CLEANUP_UNVERIFIED`. The marker was later resolved in two separate steps:
- **B3J-374** was a read-only reconciliation. It found no disposable resource of that project left (0 containers,
  networks, volumes and images), all protected resources unchanged, and the evidence files intact.
- **B3J-375** was an explicit, single-purpose authorization to delete exactly one verified file: the 50-byte
  `CLEANUP_UNVERIFIED` marker (SHA-256 `bead1543ddc07668c31ce85dff1b2414f7e5d03466b49e3f0197686226e76b7c`). Its identity,
  size and hash were checked immediately before deletion, and nothing else was deleted. The file no longer exists, so
  this hash is taken from the B3J-374/B3J-375 reports and cannot be re-verified against a file.
- The original S4 evidence files (`a5e97758` pre-cleanup and final) were not changed. Removing the marker **did not
  change that attempt's INCONCLUSIVE verdict and did not retroactively verify its cleanup**; the recorded cleanup status
  stays "not verified".
- Removing any future `CLEANUP_UNVERIFIED` marker always requires its own separate, explicit authorization. The harness
  never deletes it.

## 3. S6: stream-processor SIGKILL and republication

**Classification: OFFLINE-TESTED, LIVE INCONCLUSIVE, HOST-BLOCKED, DEFERRED. S6 is not a PASS and no live proof of
republication exists.**

What S6 asks: kill the stream processor between publishing spans to the canonical topic and committing the source
offset; after a restart, the source messages are read again, their spans are published a second time, the storage
consumer absorbs the duplicates, and PostgreSQL holds exactly one row per expected identity.

History, in order:
1. **B3J-391 (`d43e0ce`)** added the case offline: a case-specific kill table (S5 may kill only the storage consumer,
   S6 only the stream processor), kill-target verification, frozen-state analysis, duplicate-straddle accounting and
   cleanup. The original workload was 600 messages of 10 spans.
2. **B3J-392** read-only preflight: ready (memory 4,461 to 4,510 MiB).
3. **B3J-393**: one live attempt, 2026-10-19, project `416e480f`. The SIGKILL was valid (exit 137, OOM false, no
   restart, no graceful-shutdown lines, attributed to the single authorized kill). The frozen state had no span of an
   uncommitted source message on the canonical topic: committed offsets 65 and 190 with partition 2 uncommitted, and
   2,550 canonical records equal to exactly 255 committed messages of 10 spans. The kill landed at a message boundary,
   so there was nothing to republish. **Verdict INCONCLUSIVE** (overall HOLD). Cleanup was verified, protected
   resources were unchanged. No PASS is claimed.
4. **B3J-394** timing analysis: a read-only reconstruction found 1.74 s between the last progress reading and the
   death of the container. The cycle of at most about 10.1 ms per message is **derived, not directly measured**: 172
   messages were committed between the last progress reading and the freeze, in at most 1.74 s. On that basis the
   harness could not aim a kill inside one message. The progress reading itself (a Kafka CLI call) took about 2 s.
   Whether the kill was simply unlucky or the processor was idle at that instant is not established by the evidence.
5. **B3J-395/396 (`d2826a5`)** offline redesign: 60 messages of 500 spans (30,000 identities; a 500-span message
   measured 33,541 bytes, below the producer's 1,000,000-byte default), the full kill-target and neighbour
   verification moved before the progress wait, and a mandatory single `docker inspect` of the verified container IDs
   immediately before the kill. The harness unit suite has 695 passing tests and the workload-generator suite 2,307.
6. **B3J-397 and B3J-400** preflights for a second live attempt both failed the memory gate (1,794 and 2,500 MiB
   available, against a required 4,096 MiB). The memory gate is not new to S6: it had already blocked the corrected
   live S4 attempt at **B3J-376** (harness preflight 3,991 MiB, before any Docker command). **B3J-398, 399, 401, 402 and
   403** diagnostics found available memory of approximately 1.8 to 2.9 GiB whenever the WSL virtual machine was running
   and near 4.8 to 5.4 GiB when it was not. B3J-403 started only an Ubuntu distribution once: available memory fell to
   3,050 MiB at startup and settled near 4,200 MiB with a 624 MiB virtual machine, which is not the state a live run
   needs (Docker engine and stack running). The cause of the memory pattern is not established.

No second live S6 attempt has been made.

## 4. S5: 112 predicted and 112 observed replay conflicts

S5 (project `ea2cdc48`, harness `ce46b2f`) killed the storage consumer with SIGKILL while it was batching 500
messages per commit, then restarted it. From the frozen state (committed destination offsets per partition and the
canonical topic after the kill) the harness predicted, before restarting, that the restarted consumer would read 3,000
canonical records, insert 2,888 and hit 112 conflicts. The restarted consumer's own final timing summary reported
**messages 3,000, inserted 2,888, conflicts 112**, six commits, and the final PostgreSQL rows matched the expected
identities with no missing, unexpected or duplicate rows. The predicted replay range was offsets [972, 1,084) on
canonical partition 1 (112 records); the ranges on partitions 0 and 2 were empty. This is real Kafka and PostgreSQL
evidence that a duplicate redelivery of already-stored spans is absorbed by `UNIQUE(trace_id, span_id)` with
`ON CONFLICT DO NOTHING`. It is a single run.

## 5. Live versus modeled evidence, by guarantee

| Guarantee | Evidence | Limits |
|---|---|---|
| Both services stop within the grace period on SIGTERM when idle | Live (S1) | One run; no JSON evidence |
| The stream processor finishes the message in hand and commits only after all its spans are acknowledged, on a graceful stop | Live (S2) plus unit tests | One run |
| The storage consumer does not commit an offset ahead of the database on a graceful stop | Live (S3) plus unit tests | One run |
| Batched commits are flushed on a graceful stop | Live (S4) | One run, batch 50 |
| A killed storage consumer replays and PostgreSQL absorbs the duplicates | Live (S5); live forced-kill observations C07b in the batching integration runs (real consumer, real PostgreSQL; replay accounting verified in two runs, 38 and 5 conflicts equal to the predicted replays) | Single S5 run |
| A killed stream processor republishes uncommitted source messages, and the downstream stages converge | **Modeled and offline only** (S6 harness simulation; restart-convergence and cross-component replay tests B3J-318, 321, 324). **No live proof** | S6 live INCONCLUSIVE; redesign not run live |
| No unsafe source or destination commit under the tested faults | Live for S2 to S5; none observed | Only the tested kill timings |
| Cleanup removes only the disposable project and leaves protected resources unchanged | Live for every run recorded here **except the original S4 attempt** (`a5e97758`), whose cleanup was recorded as not verified (section 2) | Verified-default-bridge policy introduced after that attempt |
| Exactly-once delivery | **Not claimed** | See section 8 |

## 6. Batching integration runs and the C04 failure

Three runs of the separate batching integration harness (`bit-e33dc272`, `bit-99f34ba4`, `bit-ae63ad79`) are archived.
**All three have overall verdict FAIL**, because **C04 (cooperative rebalance) FAILED in every run**: a commit after an
incremental revoke failed with `ILLEGAL_GENERATION` and the consumer halted. No unsafe commit was recorded.

- Run `bit-e33dc272` also failed C07a, C09 and C10 (a test-code TypeError and an idle-flush assertion).
- The git HEAD of each run was not recorded; the archive manifest infers it from timing. That is an inference.
- C03 (eager rebalance) and C08 (PostgreSQL idempotency) passed in all three runs.

## 7. Unsupported configuration: cooperative-sticky with commit batching

Because C04 failed and has not been fixed or re-tested, **a consumer using the cooperative-sticky assignor together
with commit batching is not a supported or validated configuration.** No Kafka partition assignor is explicitly
configured in the stream-processor or storage-consumer code; the client library default applies, which is assumed to
be eager and was not verified at runtime in this audit. Batching is opt-in (`CONSUMER_COMMIT_BATCH_MESSAGES` greater
than 1). The failure ended in a halt, not in data loss, in the recorded runs; that is an observation, not a guarantee.

## 8. Delivery semantics and explicit non-claims

The pipeline is **at-least-once**. A source offset is committed only after the work for that message is durable; after
a crash the work is read again, so a canonical-topic record or a database write may be repeated. PostgreSQL's
`UNIQUE(trace_id, span_id)` with `ON CONFLICT DO NOTHING` is the idempotency backstop that makes repeated storage
writes harmless.

This phase does **not** claim: exactly-once delivery; correctness under broker or PostgreSQL outage; behaviour with
more than one consumer per group; behaviour under poison messages and dead-letter handling during failure; correctness
of a stream-processor crash in the commit window; throughput or capacity.

## 9. Other scenarios not tested

- Kafka broker outage and recovery.
- PostgreSQL outage and recovery during consumption.
- Poison messages and the dead-letter topic under failure.
- Multi-member consumer groups and rebalances under load.
- Network partitions and slow-broker behaviour.
- The effective runtime message-size limits of the broker and topics. The 500-span S6 message (33,541 bytes) relies on
  the documented Kafka 4.1.0 and librdkafka defaults, which were not read from a running broker.
- Any run on hardware other than this development laptop.

## 10. Evidence index

Read-only hashes taken on 2026-10-19; sizes in bytes. The evidence archive is a byte-for-byte copy made by B3J-388
(`phase-14.5-failure-evidence-20261019-013125Z`, under `%LOCALAPPDATA%\agentops-backups`). Active copies are in
`%TEMP%\agentops-shutdown-it-evidence`. The two S6 files and the S6 run log postdate the archive and are **not in it**.

Archive control files: `MANIFEST.json` (30,082 bytes, SHA-256
`7220948bdc7526f5b1e7a3e623a4a1762a4c423c5843e3cf5da657ccd6f4e167`, 61 files listed), `README-ARCHIVE.txt` (2,219 bytes,
`381f35e15dba7e3403aef7ed3fa9f0bf9d7c705d2ff3dcb7603bc326fac52048`). The archive holds 64 files: the **61
manifest-listed evidence files** (re-hashed in the last preflight: 0 mismatches) plus the manifest, its checksum file
(`MANIFEST.sha256`, which matches `MANIFEST.json`) and the README, which the manifest does not list.

| Project | File | Size | SHA-256 | In archive |
|---|---|---|---|---|
| `326e7fd9` | pre-cleanup | 633 | `6978e1268da86f3f1d38d4b12be3a6d87382a98046c8ad4a42f7db17e51c5ef9` | yes |
| `326e7fd9` | final | 3,194 | `9cef643114eb12f0f7b76a2b4c15f5ff44fc5a8f9005bd9aa3e306bc49ea556e` | yes |
| `092a142d` | pre-cleanup | 3,071 | `4289fd4e7dd981bbb92b4de8fd26165b0184467fdf0ee538222009565774b61b` | yes |
| `092a142d` | final | 5,632 | `df0a07f78767c8d7c89ba28c352b892ac6d8ab896aa87ba1aa7465f3b9466ca7` | yes |
| `90d67e27` (S2) | pre-cleanup | 3,400 | `e2f4ae7ea028889f222ab297ca4dec030afcde2696653c4dd3d7ce2a6c3e65b4` | yes |
| `90d67e27` (S2) | final | 5,961 | `b7c575b7cc0f5de56394b5c8823fb17acc8f1e0e6e64f443d5680e6519eac314` | yes |
| `bd0205bd` (S3) | pre-cleanup | 4,670 | `04cc97ac344f97fa8524bb4415ed367262bb98b0864c1783d1ed1d5d6f3041cb` | yes |
| `bd0205bd` (S3) | final | 7,231 | `0c1520b74bfb66c098b98e45c55e856e2a55838bc89553f121319416444aa6da` | yes |
| `a5e97758` (S4 attempt 1) | pre-cleanup | 5,614 | `d1cbc22b64ad5a006d718ef9b08814a69f7b4aa8e7ea4663895e28e5fd7ee361` | yes |
| `a5e97758` (S4 attempt 1) | final | 8,254 | `d0cdd536a50d458ce1d0d5282089335d7cfe9ccf76d26de2aeb3dd743b97d95e` | yes |
| `2bf1845b` (S4) | pre-cleanup | 10,019 | `46ed14ee6f281788602edc04381b52222f150d4940d23c2fb793186faf824a55` | yes |
| `2bf1845b` (S4) | final | 18,787 | `b6f8e6e3c084c14670da4faec6135c57cf8bf1379fcac84990098802e28e0465` | yes |
| `ea2cdc48` (S5) | pre-cleanup | 12,808 | `8763290f68718f006d2c899c8914ceb5af2cb3443128f00b44faf19e2cd1a4b7` | yes |
| `ea2cdc48` (S5) | final | 21,576 | `0a3d43b0d3d66d2bb640aa81fb83e85710030aea15059629efe4978bba8f5f38` | yes |
| `416e480f` (S6) | pre-cleanup | 5,711 | `61596d29bec6b1bcc027de1b418968a74377b7a91ab0e3d56476a282bdba4caf` | **no** (active store only) |
| `416e480f` (S6) | final | 14,479 | `90d976ba515da4d2e4d4249b818dfa50077c8aa643a11332b262fcb754c43e23` | **no** (active store only) |

Run logs and other records:

| Record | Size | SHA-256 | Location |
|---|---|---|---|
| `s4_run.log` | 2,082 | `09292e306edc9c8860a21b5ce6c13fc00216975a251ce67d43f1600010459635` | archive |
| `s4_run2.log` | 1,903 | `3827e18523ff47bf004cc23d1add63e130a2704cb6d14d27a0b8ffeb7b0c899b` | archive |
| `s5_run.log` | 1,928 | `a044370fd619ca1120d3a5ef03babba0c9b22fa603d305907aae74829704d386` | archive |
| S1 `b343b_run.log` | 1,147 | `a0faa359e84583f8cdde6ea0372c6c9908816eb0e1ecd0978d5234a75151e0de` | `s1-shutdown-evidence-20261019-001810Z` (separate archive) |
| S6 run log `s6_run.log` | 1,837 | `bae516348f419f254155e6064385c1aaba403f0d355b8818cfd98a90abba6c1f` | session scratchpad only, **not archived** |
| Batching run `bit-e33dc272` `verdict.json` | 1,011 | `9999fd8159a89e9c3f3e16257e9e8afd8f3722f92600c6af11aefd8931544c4d` | archive |
| Batching run `bit-99f34ba4` `verdict.json` | 824 | `8d778fc1fd0b45966260f172c046d442d9c27f9433877992f2b76d8b9e69695e` | archive |
| Batching run `bit-ae63ad79` `verdict.json` | 870 | `2eac453ef7cf8595e22a20e4bef80191f6d6a59215dc1bbb8f49ab465a1e1e7e` | archive |
| Benchmark evidence archive `MANIFEST.json` | 11,129 | `00e7dff5b9af8e894b630c7791a65be31f72f959c373fbbadb17c741e8ed41bb` | `benchmark-evidence-20261017-194753-464292Z` (Phase 14.4; 47 files) |

Not available: the Claude Code transcript that holds the reasoning behind the review steps (about 161 MB, referenced
by path and line numbers in the B3J-387 report, not copied). The full text of the accepted B3J review reports is not
stored in this repository. Harness commits for S1 and for the batching runs were not recorded by their harnesses.

## 11. Deferred-validation register

| ID | Item | Current status | Blocker | Proposed acceptance criteria |
|---|---|---|---|---|
| D1 | S6: live stream-processor crash and republication | Offline-tested; one live INCONCLUSIVE; redesign not run live | Host memory gate (available memory below 4,096 MiB with the WSL VM running) | One authorized run of the committed harness that ends PASS: one verified SIGKILL, a positive published-but-uncommitted set, observed republication matching the prediction, duplicates attributed to the straddle, PostgreSQL rows exactly one per identity, final offsets at the ends, verified cleanup |
| D2 | C04 cooperative-sticky rebalance with batching | FAILED in three runs | None technical; a decision to fix or to document as unsupported | Either an explicitly approved fix or validation plan followed by **at least three consecutive successful cooperative-sticky integration runs**, each with no unsafe commit and verified cleanup, or this document's unsupported-configuration restriction kept in the operator documentation |
| D3 | Kafka broker outage and recovery | Not run | Test design; host memory | A disposable-project test where the broker is interrupted and restored, ending with no missing identity and no offset ahead of durable work |
| D4 | PostgreSQL outage and recovery | Not run | Same | The same, for the database |
| D5 | Poison messages and dead-letter under failure | Not run live | Test design | A malformed message reaches the DLQ and the offset advances only afterwards; valid messages are unaffected |
| D6 | Multi-member consumer groups | Not run | Host memory; test design | Two members, forced rebalance under load, no loss and no unsafe commit |
| D7 | Effective Kafka message limits | Assumed from documented defaults | Needs a running broker | Read `message.max.bytes` of the broker and topics at the start of a live run and record it in the evidence |
| D8 | Repeat of S2, S3, S5 at other kill timings | One run each | Host memory | At least two further independent runs per case with PASS, or an accepted decision that single runs suffice |
| D9 | Machine memory margin | Harness preflights failed the memory gate at B3J-376 (3,991 MiB, before S4), B3J-397 (1,794 MiB) and B3J-400 (2,500 MiB) | Host | Three consecutive fresh readings of at least 4,096 MiB with the Docker engine VM running, measured by the harness preflight |

## 12. Safety principles used throughout

- **One authorized action per step**, each reviewed before the next. A live run is executed once and never retried
  automatically, whatever the result.
- **Disposable projects only.** Names must match `agentops-shutdown-it-<8 hex>`; the project `agentops` is refused.
  The protected containers and volumes (`agentops-mvp-*`, `agentops-postgres` and their volumes) are never started or
  modified and their databases are never accessed; only their container metadata is read, and their IDs, states,
  restart counts, network attachments and mounts are compared before and after every run.
- **One kill.** The only destructive command is `docker compose kill -s SIGKILL <service>` for the one service the case
  may kill (S5: storage consumer; S6: stream processor), only after the container's ID, Compose project and service
  labels, name, restart policy `no`, running state, exclusion from the protected set and the neighbouring services'
  states are verified, and with the container ID re-checked immediately before the kill. A bare `docker kill`, a host
  process kill or an engine signal is never used.
- **Fail-closed cleanup.** Teardown removes only the project's own containers, volumes, networks and images. If any
  object is missing, changed or left behind, a `CLEANUP_UNVERIFIED` marker blocks further runs and the evidence is kept.
  The harness never deletes the marker; clearing it needs a separate, explicit authorization (section 2).
  A Docker-recreated default bridge is treated as informational only when it is positively verified.
- **Evidence is preserved, not edited.** Pre-cleanup and final evidence files are written before and after teardown;
  failed and inconclusive runs stay in the archive with their original verdicts.
- **Host safety.** A run starts only if memory, disk, Docker allocation, AC power and port checks pass; no
  configuration is changed to make a gate pass.

## 13. Status

**Phase 14.5 is pending ChatGPT review and explicit closure approval.** This draft does not close the phase, does not
claim that all failure-recovery scenarios are validated, and does not change any recorded verdict. It also does not
update [../benchmarks/README.md](../benchmarks/README.md) or [../benchmarks/RESULTS.md](../benchmarks/RESULTS.md). Their
status lines (README.md lines 8 to 9, RESULTS.md line 10) still say that Phase 14.5 "is planned and has not started";
those two statements are out of date and need a separate, authorized edit after any closure approval. The same words
inside the dated 2026-10-17 Phase 14.4 closure record in RESULTS.md (lines 235 and 308) were true when written and are
historical; they are to stay unchanged.

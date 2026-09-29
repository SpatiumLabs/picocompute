# Selective Bursting and RL Env-Building Loop (Design Spike)

**Date**: 2026-09-29
**Status**: Spike complete, design only, no implementation, no LPOP
**Strategy**: [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
**Consistency**: [ADR-0007](../adr/0007-snapshot-resume-fork-consistency-model.md)
**Candidate revision**: `00123ae`
**Profile**: Firecracker on `lab-64vcpu`, dedicated tenancy, `MIX-AGENT-V1`
**Default posture**: no bursting, no env-building loop, no quota change

## Executive Summary

This note is a design spike only. It produces eligibility rules, sync-cost
shape, shed behavior, and leakage controls for two tracks, plus the harness
inputs a later measurement track needs. It sets no LPOP, changes no defaults,
adds no code, and authorizes no build.

Context from the referenced external designs: DSec 3.4 bursts above 80%
on-prem util by offloading cloud-eligible tasks whose deps sit inside a synced
30TB deduped set covering about 70% of container tasks, to cloud VMs that reuse
the same EROFS read path, where about 200 VMs absorb about 30% of peak
overflow. DSec 6.1 builds reusable environments with incremental snapshots on
the same infra, with builder/runtime account separation and writable-layer
scrubbing before pack.

Pico today has cell-loss drills and LPOP gates but no bursting design, and it
has fork/base snapshots but no agent-driven env-building loop with leakage
controls. This spike closes the design gap only.

Sequencing constraint: both tracks are sequenced after verification-gated
on-demand reads. Bursting full images repeats the eager-pull failure mode
(full fetch before admit, cache thrash under burst, verification bypass
pressure). Burst capacity must reuse the same on-demand read path that serves
the base fleet. No burst design graduates without that prerequisite holding on
the candidate profile.

**Overall verdict**: the eligibility classifier shape, the hot-set sync policy
shape, the same-read-path requirement, the shed/shift semantics, and the
checkpoint-to-environment flow below are internally consistent with ADR-0012
and ADR-0007 and are ready to drive harness parameters. Every rate, byte
count, and latency number below is either a DSec-shaped input awaiting
measurement or an explicit placeholder. Promotion of any mechanism to an
implementation track requires the P1/P2 evidence in section 5.

## 1. Selective-Burst Design

### 1.1 Eligibility classifier (image-dep closure)

A create request is burst-eligible only when its full image-dep closure is a
subset of the synced hot set. The closure is computed from trusted metadata
before scheduling, never from guest-reported state.

Closure inputs:

- root bundle digest plus selected variant digest from the scheduler decision
- manifest component digests (rootfs, kernel, init, guest-agent) per the
  guest image contract
- composable environment layer digests (base, workspace seed, toolkits) plus
  the composition digest, when the manifest carries an environment composition
- declared snapshot reference (base snapshot digest and lineage) for
  restore/fork creates, validated against readiness, lineage, retention, and
  revocation state

Eligibility rules:

- eligible only when every closure digest is present in the hot-set index at
  the current sync epoch, with signature, promotion, and revocation evidence
  fresh per host verification policy
- ineligible when any closure member is unpinned, unsigned, unverified,
  revoked, or outside the hot-set index (fail closed to on-prem placement or
  typed reject, never silent fallback to eager full pull on burst capacity)
- ineligible when the request needs a capability the burst pool does not
  declare (backend family/version, CPU template/features, machine/device
  model, protocol range, mount classes, snapshot profile)
- ineligible when tenant policy, workload class, isolation floor, data
  classification, or current policy epoch forbids off-prem placement
- warm-snapshot restores are eligible only on exact source-bundle plus exact
  variant plus backend-bound compatibility; cross-backend restore stays
  rejected on burst capacity exactly as on base capacity
- the classifier output (eligible/ineligible plus reason code plus closure
  digest list plus sync epoch) rides the placement span, the scheduler
  response, and the audit event so later S-SPIKE-CREATE analysis can separate
  shed-by-policy from shed-by-capacity

The classifier is a pure function over digests and policy. It owns no network
fetch, no mutation, and no placement override. Schedulers call it before
filtering burst candidates; hosts re-evaluate closure membership at admit
because the hot set may have advanced between schedule and boot.

### 1.2 Hot-set sync policy and sync costs

The hot set is the deduped subset of image and layer content that burst
capacity pre-syncs. It is the only content burst hosts may serve without a
cold-fetch penalty. Everything outside it stays on-prem.

Sync policy:

- membership is by content digest (layer blobs, rootfs chunks, kernel/init
  artifacts), not by tag; tags are discovery aliases only
- the sync controller publishes a versioned hot-set index (digest list, byte
  sizes, sync epoch, source registry revision) that both schedulers and burst
  hosts consume
- burst hosts verify each synced blob against its descriptor digest and size
  before caching, and re-check revocation plus promotion freshness inside the
  configured offline window; stale or revoked entries become unavailable for
  new admits, not silently served
- eviction on burst hosts prefers coldest closure members first and never
  serves a wrong digest, skips verification, or leaks a tenant layer across
  tenants (class-A on violation, same as ST-CACHE rules)
- sync runs continuously at low priority, not inline on the burst admit path;
  a burst admit that arrives before its closure finishes syncing is
  ineligible for this epoch and sheds per section 1.4

Sync-cost shape (inputs for later measurement, not claims):

- total bytes after dedup: sum of unique closure bytes in the hot set, not
  sum over images; dedup ratio is measured per corpus (shared base plus
  shared toolkits dominate the saving)
- steady-state churn bytes per hour: new layer revision rate times mean
  layer size times dedup miss ratio
- burst-headroom bandwidth: churn plus initial fill divided by the refill
  deadline the operator sets for the next burst window
- verification cost: signature plus digest plus evidence-freshness checks per
  blob, recorded as p50/p95/p99 by blob size tier
- storage cost: hot-set bytes times replica count across burst hosts plus
  cell-cache bytes, with headroom per the cache sizing rule

DSec-shaped reference points carried as hypotheses: a 30TB-order deduped set
can cover a majority of container-task closures, and a low-hundreds VM-order
burst pool can absorb roughly a third of peak overflow. Both stay
placeholders until P1/P2 reports replace them with candidate-profile numbers.

### 1.3 Same-read-path requirement on burst capacity

Burst hosts must expose the same verification-gated on-demand read path as
base hosts, with identical ordering and identical failure semantics.

Required sameness:

- verify-then-serve ordering: digest plus production attestation plus
  revocation check completes before any byte is served; network or registry
  failure never permits unverified cache use
- chunk-addressed fetch keyed by digest plus chunk index (or equivalent
  content addressing for the container path), so evicting one digest cannot
  surface another digest bytes
- identical telemetry labels (`hit`/`miss`/`evicted` by tier, verify latency,
  overlay latency) so S-CACHE-COLD/S-CACHE-WARM/S-CACHE-THRASH analysis can
  compare burst hosts against base hosts without relabeling
- identical admission errors: cold miss stays Safe when boots succeed or fail
  closed with `reason=image` or verification deny; unsigned/unpinned served
  bytes stay class-A even when boots succeed
- no eager-pull mode on the burst admit path; where an eager path exists for
  tooling it is disabled by config on burst hosts and its use emits a
  distinct audit event

Rationale: the burst pool exists to absorb the overflow that on-prem cannot
fit. If burst hosts pull full images eagerly, the burst itself becomes the
cache-thrash and prepare-latency knee the design was meant to avoid.

### 1.4 Shed/shift semantics consistent with cell-loss and recovery drills

Burst capacity is modeled as ordinary schedulable cells with health states,
not as a special overflow queue. Shift and shed reuse the ST-CELL vocabulary.

Behavior:

- below the on-prem warning zone, all eligible and ineligible work stays
  on-prem; burst cells idle or serve steady low-priority fill
- above about 80% on-prem util (tunable threshold, measured per profile),
  eligible creates shift to burst cells while ineligible creates stay on-prem
  and contend for remaining on-prem headroom
- beyond combined warning-zone capacity, excess sheds with typed
  `rejected`/`unavailable` outcomes carrying proposed reason codes
  (`policy-ineligible`, `closure-not-synced`, `burst-unavailable`,
  `no-capacity`); timeouts rising with rejects is class-A, never clean shed.
  These code strings are proposals for the future track, not current
  proto or scheduler vocabulary.
- burst-cell loss is handled as S-FAIL-CELL: regional placement stops
  selecting the failed burst cell, in-flight work on that cell fences per
  host-agent fencing rules, cleanup plus quarantine completes, and surviving
  cells stay inside SLO at reduced capacity; no split-brain metadata and no
  orphan resources left for manual host mutation
- recovery follows S-RECOVER: the restored burst domain resumes placement
  without hand-edited inventory, backlog drains inside audit-lag bounds, and
  the report records pre-failure LPOP restoration explicitly
- admission math stays honest: scheduler advertised burst capacity versus
  measured admits must sit inside the documented error band; large divergence
  is class-A for production candidacy

No silent fallback is permitted at any step: backend selection, isolation
floor, credential mode, network policy, and snapshot profile must not change
because the request moved to burst capacity.

## 2. Env-Building Loop

### 2.1 Checkpoint-to-reusable-environment flow on snapshot/fork primitives

The loop turns one agent-prepared sandbox into a reusable environment that
later sandboxes can boot or fork from, using only the ADR-0007 primitives.

Proposed flow:

1. An agent drives a builder sandbox to the desired state (packages installed,
   repos checked out, caches warmed, service ports probed locally).
2. The agent invokes a standardized quiesce hook (flush filesystems, stop
   background writers, drop ephemeral listeners) and then requests a
   `filesystem`-profile fork snapshot; `memory`-profile capture is out of
   scope for reusable environments in this spike.
3. `sandboxd` installs the operation fence, drains admitted execs to terminal
   state, and fails closed on busy/timeout without auto-cancel.
4. The workspace implementation flushes and freezes, creates the immutable
   copy-on-write point, and `snapshot-agent` verifies completeness plus
   exclusion evidence before the snapshot manager commits `ready` metadata.
5. The scrub stage (section 2.3) runs against the staged layers before pack.
6. The pack stage produces an incremental layer (changed files only) against
   the declared parent composition, with fresh digests and lineage, then
   registers a new environment composition (parent plus new layer) for
   validation.
7. The quality stage (section 2.4) boots the new composition through the
   normal boot plus handshake path and promotes only on pass.
8. Parent and child lifecycle stay independent after fork per ADR-0007; a
   child boot failure never rolls back the source sandbox or the committed
   fork point.

Every step reuses existing consistency guarantees: cooperative quiescence,
fail-closed capture, atomic publication (`ready` or nothing restorable),
typed compatibility failures, and lineage records (source sandbox, source
snapshot, child identity, fork operation, purpose, profile, timestamps,
policy decision).

### 2.2 Builder/runtime account separation

Builder and runtime principals are distinct by construction.

Rules:

- builder sandboxes run under a builder account with a builder-only policy
  (egress limited to declared package registries plus version-control hosts,
  no production secret issuance, no port exposure, short lease lifetimes)
- the builder account cannot mint runtime credentials and cannot approve its
  own promotion; promotion requires the release policy path with required
  approver roles
- the disposable builder terminates after capture per the base-snapshot
  disposition pattern; the reusable artifact itself carries no builder
  authority (no sessions, leases, tokens, boot secrets, network flows)
- runtime restores run under the consuming tenant account at the current
  policy epoch with fresh boot identity, fresh protocol session, rebuilt
  network resources from current policy, and freshly issued credentials;
  lineage grants no capability increase
- audit separates builder events (build, quiesce, capture, scrub, pack,
  quality) from runtime events (restore, fork, boot, exec) by account plus
  operation identity so a later review can trace any runtime environment to
  its builder run

### 2.3 Residual/secret scrubbing before pack

Scrubbing proves that platform-issued authority is absent before any layer is
packed. It does not make an untrusted workload forget data it already
observed; workload-copied secrets in ordinary persistent files remain tenant
data governed by classification and retention policy.

Scrub checklist enforced before pack (each item produces evidence, any failure
fails the pack closed):

- `/run/pico/secrets` and direct credential channels: excluded, revoked,
  detached, proven absent
- `/run/pico/tmp`, ephemeral mounts, scratch disks, host staging paths:
  excluded and recreated empty or reported unavailable
- host/guest protocol sessions, boot secrets, operation handles, stream
  connections: excluded and invalidated
- access leases, bearer tokens, runtime credentials, secret-broker state:
  excluded and scheduled for post-readiness reissuance only
- network namespaces, interfaces, host addresses, NAT state, connection
  tracking, DNS cache, active flows, port exposure: excluded and rebuilt from
  current policy at runtime boot
- host-local process, cgroup, socket, and helper identities: excluded as
  runtime authority
- shell history, editor swap files, package-manager caches holding
  credential-bearing URLs, and cloud-metadata responses: matched by an
  explicit denylist plus assignment-shaped scan over the staged diff, with
  hits failing the pack and naming the path (never the value) in the report
- unclassified mounts or devices: capture-ineligible until classified

The scrub report (paths checked, ruleset revision, pass/fail per rule, diff
digest) is bound to the packed layer digest so a promotion decision keyed on
that digest also pins the scrub evidence it reviewed.

### 2.4 Quality check plus standardized export hooks

No packed environment becomes bootable by policy until it passes the quality
gate through standardized hooks.

Quality gate:

- schema plus digest integrity over the new composition and all referenced
  layers
- filesystem policy (ownership, modes, no setuid/setgid surprises, no
  prohibited devices, package inventory matches declared SBOM inputs)
- mount-contract check (required classes, paths, persistence, snapshot
  exclusions complete and non-conflicting)
- backend boot check: each declared backend profile boots the exact new
  composition and reaches the authenticated handshake within budget
- smoke exec: a declared smoke command (test harness entrypoint) runs to
  success inside the booted child with bounded output captured to the report
- secret rescan of the packed bytes with the same ruleset revision as the
  pre-pack scrub

Standardized export hooks (proposed stable interface, backend-neutral,
unimplemented in this change):

- `prepare`: declares parent composition, requested layer name, and build
  intent; returns a staged diff handle
- `quiesce`: runs the bounded application hooks and returns the quiesce
  receipt consumed by capture
- `scrub`: runs the section 2.3 checklist and returns the scrub report
- `pack`: produces the incremental layer plus lineage against the parent
- `verify`: runs the quality gate and returns the quality report
- `publish`: registers the new composition for promotion review without
  mutating any released layer

Hook failures are typed and identify the stage plus the mismatched dimension
without exposing secret values. Retries use the same operation identity and
never create a second logical layer.

## 3. Harness Inputs Recorded For Later

No measurements are claimed in this spike. The following DSec-shaped inputs
are recorded so a later harness track can parameterize mixes and scenarios
without re-deriving them.

| Input | Shape to encode | Notes |
|---|---|---|
| 32K-batch bursts | offered-load generator profile: 32K creates in one batch window against the burst-eligible closure | Measures S-SPIKE-CREATE shed path on combined on-prem plus burst capacity; records offered/admitted/completed plus reject-reason histogram; generator bottleneck attestation required |
| LS/BE latency budgets | latency-service-class mix: latency-sensitive baseline plus best-effort burst fill, with per-class exec p99 bands | Reuses the measured-overcommit track class plumbing; confirms burst fill does not move the LS saturation knee earlier |
| Long-lived low-CPU sessions | WP-SESSION-heavy soak at warning-zone density with periodic exec | Detects fd/cgroup/mount/audit-backlog leaks that only appear when burst survivors persist after the spike drains |
| Low-fanout corpora | image working set with a small closure count and high per-closure reuse | Sizes the hot set and the dedup ratio honestly; high-fanout corpora would understate sync cost and overstate hit rate |

Each input maps to existing scenario IDs (S-SPIKE-CREATE, S-NOISY,
S-SOAK-ACTIVE, S-CACHE-THRASH, S-FAIL-CELL/S-RECOVER) and must appear in the
P1/P2 runbook in section 5, not as a separate pass/fail track.

## 4. Non-Goals (Explicit)

- No implementation in this change: no scheduler classifier code, no sync
  controller, no hook runtime, no proto or route changes.
- No Fn/GPU paths: function-cold-start and GPU-device handling are untouched
  and must not be inferred from this note.
- No bursting of full images: any design that fetches full images inline on
  the burst admit path is rejected by section 1.3.
- No `memory`-profile reusable environments: process-memory preservation
  stays capability-gated per ADR-0007 and is out of scope for the loop in
  section 2.
- No cross-backend restore and no cold-boot-as-resume relabeling: restore
  compatibility stays fail-closed per ADR-0007 on burst capacity.
- No quota, LPOP, packing-number, cache-size, or cost-number changes: all
  capacity and cost documents stay untouched until P1/P2 reports exist.
- No new isolation backend and no Kubernetes-specific topology: the burst pool
  is ordinary cells under the existing backend-selection and placement rules.
- No production-secret or tenant-data use in any later measurement: synthetic
  load only, per ADR-0012.

## 5. Evidence Required Before Any Build (Gating Plan Per ADR-0012)

Warning zone caps any future LPOP for every scenario below. Saturation must
not break isolation, cleanup, or audit (class-A even when some creates
succeed). Profile for all runs: one production-shaped host (P1) per backend
first, then one production-shaped cell (P2); no regional claim before P3.

| Scenario | Gate question | Pass bar for the future track |
|---|---|---|
| S-CACHE-COLD/S-CACHE-WARM/S-CACHE-THRASH on burst hosts | Does the same-read-path requirement hold under cold, warm, and thrash? | Closure-hit boots match base-host behavior; eviction never serves wrong digest, skips verification, or leaks tenant layers; `hit`/`miss`/`evicted` series comparable across pools |
| S-SPIKE-CREATE with 32K-batch profile | Does eligible overflow shift while excess sheds cleanly? | Rejects are `rejected`/`unavailable` with reason codes, not timeouts; no eager full pull on burst admits; error ratio returns to the soak envelope within 15 minutes |
| S-RAMP-ACTIVE plus S-NOISY with LS/BE mix | Does burst fill preserve LS headroom? | LS warning-max unchanged versus LS-only baseline; LS exec p99 stays inside the diagnostic band under burst-backed noisy neighbor |
| S-SOAK-ACTIVE with long-lived low-CPU sessions | Does the post-burst footprint leak? | No leak in sandboxes, fds, overlay mounts, netns, audit backlog, or disk; heartbeats fresh for the stage duration |
| S-RAMP-RESTORE/S-SPIKE-RESTORE for env-boot | Do packed environments boot and fork inside budget? | Boot plus handshake plus smoke exec meet the candidate thresholds; partial cleanup is a bad restore event |
| S-FAIL-CELL/S-RECOVER over burst cells | Does burst loss look like cell loss? | Placement stops on the failed burst cell, no split-brain metadata, orphans reconciled, recovery to pre-failure LPOP without manual host mutation |

P1 runbook order: (1) confirm verification-gated on-demand reads on the
candidate profile; (2) characterize hot-set bytes, dedup ratio, churn, and
verify latency per closure tier; (3) run the 32K-batch spike against combined
capacity with classifier reason codes on; (4) run the LS/BE noisy-neighbor
comparison; (5) run the long-lived soak; (6) run the low-fanout thrash. Only
mechanisms inside SLO plus class-A invariants graduate to implementation
follow-ups.

## 6. Findings

| Class | Code | Detail |
|---|---|---|
| C | `spike_sets_no_lpop` | Design spike: `proposed_lpop` is `none`; all DSec numbers are hypotheses awaiting P1/P2 |
| C | `sync_costs_unmeasured` | Hot-set bytes, dedup ratio, churn, bandwidth, and verify-latency shape need P1 characterization |
| C | `classifier_unwired` | Eligibility rules have no executable seam in this change; scheduler plus host admit wiring is future work |
| C | `loop_unbuilt` | Checkpoint-to-environment flow plus hooks plus scrub plus quality gate are specified but unimplemented |

No class-A or class-B findings in this change: docs-only spikes cannot break
isolation, cleanup, audit, or SLO accounting, and they change no defaults.

## 7. Follow-Up Work (Evidence-Blocked, Described Without Tracker References)

Implementation follow-ups open only for mechanisms inside SLO plus class-A
invariants after P1/P2. Until then they stay blocked on evidence:

- P1/P2 measurement runs for section 5 on the candidate profile and image
  corpus.
- Executable eligibility classifier plus hot-set index plus scheduler and
  host-admit wiring, behind a default-off policy gate.
- Burst-cell topology plus health plus placement integration reusing the
  cell-loss and recovery machinery.
- Standardized env-building hooks plus scrub plus pack plus quality gate
  integrated with the snapshot manager and image pipeline promotion path.
- Cost and capacity plan inputs (hot-set bytes, hit rate, prepare latency,
  surviving burst capacity) consumed only from P2+ reports.

## 8. Acceptance Mapping

| Requested spike item | This note |
|---|---|
| Selective-burst design: eligibility classifier (image-dep closure) | Section 1.1 rules plus reason-coded audit trail |
| Selective-burst design: hot-set sync policy | Section 1.2 policy plus cost shape |
| Selective-burst design: same-read-path requirement on burst capacity | Section 1.3 verify-then-serve sameness |
| Selective-burst design: shed/shift semantics consistent with cell-loss and recovery drills | Section 1.4 shift/shed plus failure and recovery behavior |
| Env-building loop: checkpoint-to-reusable-environment flow on snapshot/fork primitives | Section 2.1 staged flow on ADR-0007 guarantees |
| Env-building loop: builder versus runtime account separation | Section 2.2 account, policy, and audit separation |
| Env-building loop: residual/secret scrubbing before pack | Section 2.3 checklist plus bound evidence |
| Env-building loop: quality check plus standardized export hooks | Section 2.4 gate plus six-hook interface |
| Harness inputs: 32K-batch bursts, LS/BE latency budgets, long-lived low-CPU sessions, low-fanout corpora | Section 3 recorded inputs mapped to scenario IDs |
| Design notes with eligibility rules, sync costs, shed behavior, leakage controls | Sections 1 and 2 |
| Explicit non-goals and evidence required before any build | Sections 4 and 5 |
| No Fn/GPU | Section 4 non-goals, untouched elsewhere |

## Appendix A: Reproducibility

Docs-only change. No Rust code, no new dependencies, no proto changes, so the
misuse-resistance checklist does not apply.

```bash
git status --short
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Existing suites covering the prerequisite and neighboring paths (must stay
green, unchanged by this note):

```bash
cargo nextest run -p pico-core --lib image_cache
cargo nextest run -p pico-core --lib capacity
cargo nextest run -p pico-core --lib availability
cargo nextest run -p pico-core --lib restore_capacity
```

# ADR-0012: Production Scale Validation Strategy

**Status**: Proposed
**Date**: 2026-09-04
**Milestone**: M0 - Scale Validation ADR
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0009](0009-observability-and-reliability-signals.md),
[production readiness model](../security/production-readiness.md),
[SLO and error-budget policy](../observability/slo-error-budget-policy.md)

## Context

PicoCompute is designed for high churn: short-lived agent sandboxes, warm
restore, fork, and bounded network exposure. Architecture section 14.1
records design targets of 10k external API RPS, 500k active sandboxes, and
50k creates/min. Those numbers are not production guarantees.

 requires G-14 evidence:
SLOs and rollout limits must come from measured candidate behavior under
expected load and failure scenarios.
sets the SLO catalog, 30-day budgets, burn alerts, and freeze rules.
Without a validation strategy, later harness work can:

- measure host density while missing control-plane, audit, or cache knees
- treat architecture targets as launch blockers, or treat unmeasured
  quotas as safe
- pass a green create/destroy loop that hides isolation, cleanup, or
  audit-loss failures
- extrapolate a single-host result to a region

This ADR defines what scale means, which environments and scenarios produce
evidence, how results map to G-14, and which failures block a launch stage.
It does not implement the load harness, set host density defaults, size
cells, or produce cost numbers. Those are follow-up work.

## Decision

PicoCompute validates production scale against an **exact deployment profile**
using phased environments, named workload mixes, and a **launch proven
operating point (LPOP)**.

1. Architecture 14.1 numbers are design targets. They do not admit traffic
   and do not pass G-14 by themselves.
2. Each launch stage publishes an LPOP: the maximum measured rate, active
   count, and concurrency at which the candidate meets user-facing
   SLOs (projected over 30 days from the test window), all class-A safety
   invariants, and the stage headroom rule.
3. Production and public-beta quotas must be less than or equal to the
   LPOP. Unproven architecture headroom stays a follow-up, not a launch
   claim.
4. Evidence is profile-scoped. A Firecracker dedicated-tenancy result does
   not authorize gVisor, shared-host, or a different host/image/kernel.
5. Load is synthetic and tenant-safe. Real tenant data, credentials, or
   production audit stores are never inputs.
6. Admission must fail closed beyond the LPOP. Saturation that queues
   forever, silently weakens isolation, drops audit events, or skips
   cleanup is a class-A failure even if some creates succeed.

 is the shared harness. Later issues consume this strategy; they do
not redefine pass/fail.

### Principles

1. **Measure the path that will serve users.** Local smoke proves the
   harness. Only production-shaped hosts, images, backends, and telemetry
   may set an LPOP.
2. **Separate reliability from capacity.** judges error ratio and
   latency share. This ADR judges whether those SLOs hold at a stated load
   and whether safety invariants hold when load or a failure domain breaks.
3. **Do not hide rejects.** Quota, policy, and `unavailable` admission
   denials are expected near saturation. They are excluded from
   availability SLIs per, but the report must show they are the
   intended shed path, not timeouts, retries, or host overcommit.
4. **No silent fallback.** Backend selection, isolation floor, and
   credential mode must not change under pressure.
5. **Pipelines are part of the system.** Audit and required telemetry must
   keep up or fail closed. A lifecycle SLO that looks healthy while audit
   drops or SLO series go stale is a class-A miss.
6. **Extrapolation is explicit and bounded.** Host density may inform cell
   packing only after a cell test shows the cell control plane is not the
   knee. Control-plane RPS, metadata-store write rate, and regional
   scheduler behavior cannot be inferred from host tests.

## Scale Targets

Every target is a measured axis. Each axis has a primary question, required
scenarios, and the issue that produces the numbers.

| ID | Target | Primary question | Primary scenarios | Producing issue |
|---|---|---|---|---|
| ST-API | External API request rate | Can the regional API admit, authorize, and reject at the intended RPS without burning SLO-API or SLO-API-LAT? | S-RAMP-API, S-SPIKE-API, S-SOAK-MIX | |
| ST-CREATE | Sandbox creation rate | Can create/boot complete at the intended rate with SLO-CREATE and SLO-BOOT intact, and with clean `unavailable` beyond capacity? | S-RAMP-CREATE, S-SPIKE-CREATE, S-SOAK-MIX | |
| ST-ACTIVE | Active sandbox count | What host/cell/region density stays inside safe pressure and SLO-EXEC/SLO-BOOT before saturation? | S-RAMP-ACTIVE, S-SOAK-ACTIVE, S-NOISY | |
| ST-EXEC | Exec concurrency | How many concurrent platform execs per host/cell keep SLO-EXEC and do not burn boot/restore via contention? | S-RAMP-EXEC, S-NOISY, S-SOAK-MIX | |
| ST-RESTORE | Snapshot restore throughput and latency | Can restore/fork meet SLO-RESTORE and SLO-RESTORE-LAT/SLO-FORK-LAT under concurrent restore, including restore storms? | S-RAMP-RESTORE, S-SPIKE-RESTORE, S-SOAK-RESTORE | |
| ST-CACHE | Image/rootfs cache behavior | Do cold-miss, warm-hit, eviction, and promotion keep boot/restore successful without supply-chain bypass? | S-CACHE-COLD, S-CACHE-WARM, S-CACHE-THRASH | |
| ST-CELL | Cell and host availability | Does one cell or host loss shed, drain, and recover without orphan resources or SLO collapse in remaining capacity? | S-FAIL-HOST, S-FAIL-CELL, S-RECOVER | |
| ST-PIPE | Audit and observability pipeline throughput | Do audit durable delivery and required SLO series keep pipeline SLOs at the lifecycle LPOP? | S-RAMP-PIPE, S-SOAK-MIX, S-PIPE-BACKPRESSURE | |

Architecture design targets remain the long-range planning numbers for
. They are class-C gaps until an LPOP reaches them.

## Launch Proven Operating Point

An LPOP is a versioned tuple for one deployment profile and launch stage:

- region, cell count, host shape, kernel, backend, guest image, and config
  revision
- admitted API RPS (ST-API)
- create/min (ST-CREATE)
- active sandboxes (ST-ACTIVE)
- concurrent execs (ST-EXEC)
- restore/fork per second (ST-RESTORE)
- cache working set and expected hit rate (ST-CACHE)
- surviving capacity after one cell loss (ST-CELL)
- audit and telemetry lag at that load (ST-PIPE)
- mix IDs used to produce the numbers
- measured error ratio per `slo` label
- headroom remaining vs saturation knee
- report ID and artifact digest

Quotas, rate limits, and rollout caps must be less than or equal to
this tuple. Raising a quota requires a new LPOP, not an inference.

### Stage minima

| Stage | Minimum environment | Headroom | Soak | Failure drills |
|---|---|---|---|---|
| Private preview | One production-shaped cell, dedicated tenancy, allowlisted tenants | LPOP leaves >= 50% unused cell capacity vs saturation knee | >= 24h at preview LPOP | Host drain and quarantine. Cell loss optional. |
| Public limited beta | >= 2 cells in one region, production-shaped hosts | LPOP covers published beta quotas with >= 25% unused regional capacity | >= 24h at beta LPOP | Host drain/quarantine plus one-cell unavailability. |
| Production | Regional candidate matching production topology and failure domains | LPOP covers committed quotas with >= 25% unused regional capacity and surviving-cell capacity after one cell loss | >= 72h at production LPOP | Host, cell, restore-storm, cache-thrash, and audit-backpressure. |

Preview may use a lower LPOP than architecture targets. Public beta and
production may not exceed their LPOP. Remaining user-facing error budget
rules in still apply at review time (`>= 25%` remaining or a current
exception; no fast-burn page).

## Validation Phases

| Phase | Name | Environment | Purpose | May set LPOP? |
|---|---|---|---|---|
| P0 | Local/CI smoke | Developer machine or CI | Harness, report schema, mix wiring, tiny create/exec/destroy | No |
| P1 | Host characterization | One production-shaped host | Find per-host knees for active, exec, restore, cache | No (input to cell tests) |
| P2 | Cell validation | One production-shaped cell | Confirm cell control plane, packing, soak, host failure | Preview LPOP only |
| P3 | Regional candidate | >= 2 cells, production topology | Control plane, scheduler, multi-cell restore/cache, cell loss | Beta and production LPOP |
| P4 | G-14 evidence bundle | Same as the stage candidate | Immutable report, SLO projection, capacity outputs, owner sign-off | Yes, the stage LPOP |

P0 failures block harness rollout, not a product launch. P1 results never
authorize regional quotas. Skipping P2 and claiming a production LPOP from
P3 without host/cell knees is invalid: the report cannot explain the
saturation mode.

## Environments and Limitations

| Environment | Shape | Allowed claims | Hard limits |
|---|---|---|---|
| Local/CI | Single process or nested VM, reduced images | Harness correctness | Not production-shaped. No density, RPS, or SLO claim. |
| Lab host | Production SKU, kernel, VMM, guest image | Per-host density and latency knees | No cell-controller, scheduler, or regional API claim. |
| Lab cell | Production hosts plus cell control plane | Preview LPOP, cell packing, host-loss | Single failure domain. No regional API or multi-cell claim. |
| Staging region | Production-like control plane, >= 2 cells, synthetic tenants | Beta/production LPOP | Synthetic load only. Shared production audit/telemetry backends only if isolated by environment label. |
| Production canary | Exact production profile, tightly capped tenants | Confirmation of staging LPOP, not discovery | Discovery ramps belong in staging. Canary only confirms. |

Limitations that must appear on every report:

- Hardware, kernel, VMM, and image drift from the candidate profile.
- Whether IPv6, snapshots, fork, port-forward, or a backend were disabled.
- Metadata-store, registry, snapshot-storage, and egress-gateway SKUs vs
  production.
- Trace sampling and metric cardinality vs production policy.
- Any load-generator bottleneck (client RPS, auth token minting, image
  pull bandwidth).

If the generator is the knee, the run is invalid for LPOP.

## Workload Profiles and Traffic Mix

Profiles are harness parameters. They are not extra lifecycle states.

| Profile ID | Shape | Why it exists |
|---|---|---|
| WP-SHORT | Create, one exec, destroy | Dominant agent tool-step |
| WP-SESSION | Long-lived sandbox, periodic exec | Idle density and fd/cgroup leak |
| WP-RESTORE | Warm restore then exec | Snapshot path |
| WP-FORK | Fork from a running or snapshotted parent | Clone burst |
| WP-NET | Egress, DNS, optional port-forward | Network-agent and lease path |
| WP-COLD | Create/boot with cold image/rootfs | Cache miss and prepare |

Default mix for LPOP soaks (`MIX-AGENT-V1`):

| Profile | Share of creates or occupied slots |
|---|---:|
| WP-SHORT | 50% |
| WP-SESSION | 20% |
| WP-RESTORE | 15% |
| WP-FORK | 5% |
| WP-NET | 7% |
| WP-COLD | 3% |

A stage review may use a documented narrower mix when a capability is
disabled (`not_applicable` on G-10/G-07). It may not use a friendlier mix
to hide a enabled path. Specialized mixes (`MIX-RESTORE-STORM`,
`MIX-CACHE-MISS`, `MIX-EXEC-HEAVY`) are for targeted scenarios, not for
the LPOP soak unless the product is actually that shape.

Traffic models:

| Model | Definition |
|---|---|
| Steady | Constant arrival at the target rate |
| Ramp | Stepwise increase, hold at each step until latency and error ratio stabilize |
| Spike | Abrupt 2x-3x of the current LPOP for a fixed window |
| Soak | Steady at LPOP for the stage duration |
| Recovery | Failure injection while holding pre-failure offered load, then restore the domain |

Offered load includes traffic that will be rejected. Reports record offered
vs admitted vs completed.

## Scenario Catalog

Scenarios are the unit of evidence. Each has a target axis, phase, mix, and
pass rule. encodes them; later issues may add parameters but not
weaken class-A rules.

### Ramp, soak, spike

| ID | Axis | What runs | Pass |
|---|---|---|---|
| S-RAMP-API | ST-API | Read-heavy plus create admission ramp on regional API | Knee identified. Beyond knee, rejects are `rejected`/`unavailable`, not timeouts. Projected SLO-API holds at the chosen LPOP step. |
| S-RAMP-CREATE | ST-CREATE | MIX-AGENT-V1 create/boot ramp | Same, for SLO-CREATE and SLO-BOOT. Scheduler capacity matches measured admits. |
| S-RAMP-ACTIVE | ST-ACTIVE | Fill hosts with WP-SESSION, then exec | Safe/warning/saturation zones. Warning is the LPOP cap. Saturation does not break isolation or cleanup. |
| S-RAMP-EXEC | ST-EXEC | Concurrent execs on a fixed active set | SLO-EXEC holds at LPOP. Boot/restore p99 does not cross latency thresholds solely from exec contention. |
| S-RAMP-RESTORE | ST-RESTORE | Concurrent warm restore/fork | SLO-RESTORE and restore/fork latency SLOs hold at LPOP. Partial cleanup is a bad restore event. |
| S-RAMP-PIPE | ST-PIPE | Lifecycle mix while measuring audit lag and SLO series freshness | SLO-AUDIT, SLO-AUDIT-LAG, SLO-TELEMETRY hold at the lifecycle LPOP. |
| S-SOAK-MIX | several | MIX-AGENT-V1 at LPOP for stage duration | No leak in sandboxes, fds, overlay mounts, netns, audit backlog, or disk. Error ratio stays inside the 30-day projection. |
| S-SOAK-ACTIVE | ST-ACTIVE | WP-SESSION at warning-zone density | Same leak rule. Host heartbeats stay inside SLO-HOST diagnostic thresholds. |
| S-SOAK-RESTORE | ST-RESTORE | Steady restore/fork at restore LPOP | No snapshot-store backlog growth, no lineage mix-up, no secret material in artifacts. |
| S-SPIKE-API | ST-API | 2x-3x API offered load for 5-10 min | Shed without cascade. No fast-burn equivalent in the spike window after spike ends. |
| S-SPIKE-CREATE | ST-CREATE | Create burst at 2x-3x LPOP | Admission shed. No host overcommit, no silent backend change. |
| S-SPIKE-RESTORE | ST-RESTORE | Restore storm from one popular snapshot | Throughput caps; latency SLO may degrade only if admitted restore stays inside budget or excess is rejected. |

### Cache

| ID | Axis | What runs | Pass |
|---|---|---|---|
| S-CACHE-COLD | ST-CACHE | WP-COLD against empty host/cell cache | Boots succeed or fail with `reason=image` or verification deny. No unsigned or unpinned pull. Prepare latency is reported; it does not have to match warm LPOP. |
| S-CACHE-WARM | ST-CACHE | Repeat boots of the candidate image | Hit rate and boot SLO meet the warm LPOP. |
| S-CACHE-THRASH | ST-CACHE | Working set larger than cache | Eviction does not serve the wrong digest, skip verification, or leak tenant layers. Misses may slow boot; they may not corrupt isolation. |

### Failure and recovery

| ID | Axis | What runs | Pass |
|---|---|---|---|
| S-FAIL-HOST | ST-CELL | Drain or kill one host under MIX-AGENT-V1 | Placement stops. Workloads on that host fence. Cleanup/quarantine completes. Remaining hosts stay inside SLO at reduced capacity. |
| S-FAIL-CELL | ST-CELL | Mark one cell unavailable under regional load | Regional API sheds or shifts only to remaining cells. No split-brain metadata. Orphans are reconciled. Surviving LPOP still meets stage headroom. |
| S-NOISY | ST-ACTIVE, ST-EXEC | One tenant-class mix saturates CPU/net on a shared host | If shared-host is enabled, noisy neighbor is not excluded from SLOs (network contention). If dedicated tenancy, the noisy load cannot land on another tenant's host. |
| S-PIPE-BACKPRESSURE | ST-PIPE | Induce audit or telemetry backlog at LPOP | Audit fail-closed on security-sensitive mutations. Required SLO series go stale and alert; they are not reported as 100% success. |
| S-RECOVER | ST-CELL, ST-PIPE | Restore the failed domain, drain backlog | Recovery to pre-failure LPOP without manual host mutation. Backlog drains inside SLO-AUDIT-LAG once healthy. |

### Mapping completeness

| Target | Scenarios that must appear in the stage evidence bundle |
|---|---|
| ST-API | S-RAMP-API, S-SPIKE-API, S-SOAK-MIX |
| ST-CREATE | S-RAMP-CREATE, S-SPIKE-CREATE, S-SOAK-MIX |
| ST-ACTIVE | S-RAMP-ACTIVE, S-SOAK-ACTIVE, S-NOISY |
| ST-EXEC | S-RAMP-EXEC, S-NOISY, S-SOAK-MIX |
| ST-RESTORE | S-RAMP-RESTORE, S-SPIKE-RESTORE, S-SOAK-RESTORE |
| ST-CACHE | S-CACHE-COLD, S-CACHE-WARM, S-CACHE-THRASH |
| ST-CELL | S-FAIL-HOST, S-FAIL-CELL (preview may skip S-FAIL-CELL), S-RECOVER |
| ST-PIPE | S-RAMP-PIPE, S-PIPE-BACKPRESSURE, S-SOAK-MIX |

Disabled capabilities are `not_applicable` with admission proof they cannot
run. Missing scenarios for enabled capabilities are `blocked`.

## Success Criteria

A scenario passes only if all of the following hold for the candidate
profile.

### SLO and error-budget

Use definitions. During a test window of duration `W`, compute
error ratio on terminal valid events. Project a 30-day ratio by treating
`W` as representative. That projection is a launch gate, not a substitute
for live 30-day burn at review.

| Check | Rule |
|---|---|
| User-facing availability | Projected ratio meets SLO-API (or create proxy), SLO-CREATE, SLO-BOOT, SLO-EXEC, SLO-DESTROY, and any enabled suspend/resume/fork/restore SLO. |
| Latency | Once histogram buckets exist, SLO-*-LAT success share meets target at LPOP. Until then, p99 panels are diagnostic and cannot pass a latency SLO, but a p99 that exceeds the future threshold is at least class-B. |
| Pipeline | SLO-AUDIT holds. Dead-letter or drop is class-A. Missing `pico:slo:*` is class-A (unknown, not healthy). |
| Rejects | Client `rejected`/`conflict`/`canceled` stay excluded. `unavailable` at saturation is success of the shed path if it is the majority terminal non-success and timeouts do not rise with it. |
| Live review | still records no `PicoComputeSloBurnFast`, remaining user-facing budget `>= 25%` or a current exception, and no `PicoComputeSloTelemetryStale`. |

A short spike may spend budget. After the spike, error ratio must return to
the soak envelope within 15 minutes or the spike is class-A.

### Safety invariants (always class-A)

These fail the run even when SLOs are green:

- Isolation floor or backend changes under load.
- Cross-tenant placement when the profile is dedicated tenancy.
- Snapshot or workspace containing credentials or undeclared secret state.
- Destroy/cleanup leaving overlays, netns, cgroups, leases, or addresses
  that can be reused unsafely.
- Audit event loss, mutation success without durable enqueue, or integrity
  gap.
- Unsigned, unpinned, or unverified image served from cache.
- Load-generator or operator action that required unapproved host mutation
  to recover.

### Capacity honesty

- Saturation knee is recorded (rate or count where goodput stops rising or
  error ratio leaves the SLO envelope).
- LPOP is at or below the warning zone, not the knee.
- Scheduler advertised capacity vs measured admits is within the
  report's documented error band; large divergence is class-A for
  production (wrong admission math).

## Failure Classes

| Class | Meaning | Launch effect | Typical examples |
|---|---|---|---|
| A | Blocks the requested stage | Gate `blocked` until fixed and retested on the same profile | SLO projection miss at intended quota; audit drop; isolation/cleanup break; silent fallback; stale telemetry; cell loss that orphans work; generator-invalid run used as evidence |
| B | Does not block if quota is capped below the issue | Follow-up issue required; records the cap | Efficiency (low packing); warm cache below design hit rate while boots still pass; diagnostic p99 above architecture target but inside SLO; cost higher than hoped |
| C | Design-target gap | Tracked for; not a G-14 miss | LPOP at 2k RPS vs 10k design; 20k active vs 500k design, if stage quotas stay inside LPOP |

Class-B items cannot waive a class-A invariant. An exception follows
/ fail-closed rules and cannot convert missing independent
validation into a pass.

## Capacity Model Outputs

Every P2+ report that may set an LPOP must emit inputs needs. The
model is not this ADR; the ADR requires the measurements to exist.

| Output | Source |
|---|---|
| Safe/warning/saturation density per host SKU and backend | S-RAMP-ACTIVE, S-SOAK-ACTIVE |
| Creates/min per host and per cell | S-RAMP-CREATE |
| Admitted API RPS and shed behavior | S-RAMP-API, S-SPIKE-API |
| Exec concurrency per host | S-RAMP-EXEC |
| Restore/fork per second and storage bandwidth | S-RAMP-RESTORE, S-SPIKE-RESTORE |
| Cache size vs hit rate vs prepare latency | S-CACHE-* |
| Surviving capacity after one host/cell loss | S-FAIL-HOST, S-FAIL-CELL |
| Audit events/s and max lag at LPOP | S-RAMP-PIPE |
| Headroom policy used (25% or 50%) | Stage table |
| Confidence and unknowns | Environment limitations |

Reports that omit these for an enabled path cannot feed or
capacity caps.

## Launch Readiness Report

 defines the artifact schema. This ADR defines the required content.
Reports are immutable, content-addressed, and linked from the G-14 evidence
record.

Required fields:

- `report_id`, artifact digest, harness version, scenario IDs, mix ID
- exact deployment-profile identifier and candidate git/config revision
- environment inventory (region, cells, host SKUs, kernel, VMM, images)
- offered, admitted, and completed rates per operation
- outcome and reason histograms using ADR-0009 taxonomy (or the documented
  implemented `event=` labels until instrumentation converges)
- `slo` error ratios, projected 30-day budget spend, and whether
  latency SLOs were budgeted or diagnostic
- resource-pressure series (CPU, memory, cgroup, disk, fds, net)
- audit enqueue/delivery/dead-letter/lag and telemetry freshness
- saturation knee, warning zone, proposed LPOP tuple
- class-A/B/C findings with follow-up issue IDs
- limitations and invalidation triggers (same as evidence freshness)
- owners: SRE (reliability), Runtime, Control Plane, Security

Format: machine-readable JSON (or JSON Lines per scenario) plus a short
Markdown summary. Dashboards are supporting views, not the record of
record. A screenshot without the JSON artifact is not evidence.

P0 CI may keep only JSON and a JUnit wrapper. P2+ stage evidence requires
the full bundle retained for the profile review window.

## Ownership

| Concern | Authority |
|---|---|
| This strategy, scenario catalog, and class-A/B/C rules | SRE with Runtime, Control Plane, and Security approval |
| Harness implementation and report schema | SRE, with Control Plane for API load |
| Host/cell density numbers | Runtime and SRE via |
| Cell unavailability drills | SRE and Control Plane via |
| Snapshot pressure numbers | Runtime and Storage via |
| Image cache numbers | Image Pipeline and Runtime via |
| Cost, cell size, and rollout caps from measurements | SRE |
| Live SLO freeze at rollout | SRE and |
| Isolation, audit, and supply-chain invariants under load | Security, independent of the team that ran the generator |

SRE may refuse an LPOP that the producing team claims. Security may fail a
green SLO run on a class-A invariant.

## Consequences

### Positive

- Harness work has a fixed catalog instead of inventing pass/fail later.
- Launch quotas track measured LPOPs, not architecture aspirations.
- Safety and audit stay in the scale path instead of being "functional
  tests only".
- and receive explicit numeric outputs and failure classes.
- Preview can launch small without pretending 500k active is proven.

### Negative

- Staging must look like production for any LPOP claim, which costs hosts
  and time (24h-72h soaks).
- Disabled features need admission proof, not just skipped tests.
- Instrumentation gaps (API metrics, histogram buckets) keep some latency
  SLOs diagnostic, so early LPOPs are availability-heavy.
- Multi-cell failure drills are operationally expensive and can block
  production even when density looks fine.

## Rejected Alternatives

### Treat architecture 14.1 as the launch gate

**Rejected**: Forcing 10k RPS/500k active before preview delays useful
restricted launch and invites unsafe overclaim if tests never reach those
numbers. Design targets remain planning inputs.

### Single synthetic create/destroy benchmark as G-14

**Rejected**: That mix misses session leaks, restore storms, cache thrash,
cell loss, and pipeline backpressure. Those are distinct knees.

### Production canary as the first scale test

**Rejected**: Discovery ramps on production spend error budget and can
orphan tenant work. Staging finds the LPOP; canary only confirms.

### Derive regional capacity from one host

**Rejected**: Cell controllers, regional metadata, schedulers, registries,
and audit stores have different saturation modes.

### SLO-only pass/fail without safety class-A

**Rejected**: A platform can meet create success while dropping audit,
skipping verification, or leaking netns. G-14 would then fight G-06/G-08
G-10/G-11/G-12.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Encode phases, mixes, scenarios, and the immutable report schema |
| | Measure ST-ACTIVE/ST-EXEC density and calibrate scheduler capacity |
| | Run S-FAIL-HOST, S-FAIL-CELL, S-RECOVER |
| | Run restore/fork pressure scenarios |
| | Run cache cold/warm/thrash scenarios |
| | Convert report outputs into host/cell/cache/cost/headroom caps |
| | Control-plane integrated readiness, including ST-API and ST-PIPE |
| | Consume LPOP, class findings, and freeze status in the checklist |

## References

- [ARCHITECTURE.md](..../ARCHITECTURE.md) section 14
- [Production readiness model](../security/production-readiness.md) gate G-14
- [SLO and error-budget policy](../observability/slo-error-budget-policy.md)
- [ADR-0009](0009-observability-and-reliability-signals.md)
- [Scheduling and capacity runbook](../runbooks/scheduling-capacity.md)
- [Image prepare and cache runbook](../runbooks/image-cache.md)

## Required Review

The ADR remains `Proposed` until all four roles
approve the phases, target-to-scenario map, LPOP rules, and class-A/B/C
split:

- SRE owner
- Runtime owner
- Control Plane owner
- Security owner

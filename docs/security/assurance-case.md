# PicoCompute Security Assurance Case

**Status**: Proposed
**Date**: 2026-09-17
**Milestone**: M5 - Security Production Review
**Linear**: 89
**Normative posture**:
[ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Risk model**: [PicoCompute threat model](threat-model.md)
**Readiness gates**:
[PicoCompute production readiness model](production-readiness.md)
**Side-channel assessment**:
[side-channel and covert-channel risk assessment](side-channel-assessment.md)

## Purpose

This document is the traceable security assurance case for PicoCompute. It maps
production security claims to current evidence, records what is proven, what
is partial, and what is missing, and gives the rollout checklist (67) a
single G-17 artifact to consume.

It summarizes evidence. It does not replace the reviews, tests, reports,
dashboards, drills, and approvals that produce that evidence.

## Verdict

No launch stage is approved by this case. The 2026-06-11 readiness baseline
marks every area `blocked`, the backend report rates supported paths as
preview rather than production, and the claims below carry open gaps. Do not
use this document as launch approval.

## Method

Each claim uses Claim-Argument-Evidence:

- **Claim**: a falsifiable statement scoped to an exact deployment profile.
  Approval for one profile never authorizes a different backend, hardware
  class, image, credential mode, snapshot mode, workload class, or
  tenant-sharing model.
- **Argument**: why the listed evidence would support the claim if current.
- **Evidence**: a named ADR, test suite, report, dashboard, runbook, drill,
  or CI job with a path and a how-to-run command where applicable.
- **Disposition**: `supported`, `partial`, or `missing`.

Rules applied throughout:

- Issue completion, code presence, an owner statement, or a green test from
  another profile is not sufficient evidence.
- Evidence must name the tested revision, the exact profile, the owner, and
  an expiry or revalidation trigger before it can move a gate to `pass`.
- A claim with any `missing` evidence stays `missing`. A claim with only
  partial coverage stays `partial`. No claim below is `supported` for a
  public shared-host production profile at the time of writing.
- Gap follow-ups name remaining work, not the issue that produced the
  current evidence. Done issues are cited in evidence tables. Open issues,
  accepted-risk IDs, and the section 8 follow-up list are the only valid
  follow-up targets.

## Freshness and Invalidation

This case is a snapshot of repository state on 2026-09-17. It expires on the
earliest of: a material backend, networking, snapshot, credential, host
kernel/VMM, image, protocol, audit/SLO, or tenant-sharing change; a failed
drill or incident; or a new critical/high advisory. Revalidation follows the
[review checklist](#9-review-checklist) and the freshness rules in the
[production readiness model](production-readiness.md#evidence-freshness).

## C-01 Sandbox Isolation Boundaries Hold for Supported Backends

**Claim**: For the exact backend, host image, kernel, VMM version, seccomp
profile, and workload class under review, a tenant workload cannot escape
its sandbox, access another tenant, reach platform sockets, or silently
receive a weaker backend.

**Related risks**: R-03, R-05, R-13, R-14.
**Related gates**: G-01, G-04, G-05, G-15.
**Disposition**: `missing`.

### Argument

Isolation holds only if backend selection never weakens the floor, host
confinement is installed before untrusted execution, negative boundary
tests pin the floor, and live enforcement evidence covers the exact host
and VMM. Policy and config tests alone do not prove enforcement.

### Evidence

| Evidence | Type | Location and how to run | Coverage |
|---|---|---|---|
| Workload-class isolation floors | ADR | [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md), [ADR-0004](../adr/0004-default-isolation-backend-strategy.md) | Defines Firecracker default for public untrusted, QEMU as only public fallback, gVisor as opt-in trusted fast path. Both Proposed. |
| Backend selection policy | Test | `../../crates/pico-core/src/backend_selection/tests.rs`, `cargo nextest run -p pico-core --lib backend_selection` | Workload class to floor mapping, no silent downgrade fixtures. |
| Isolation boundary suite | Test | `../../crates/pico-runtime/tests/isolation.rs`, `cargo nextest run -p pico-runtime --test isolation` | Filesystem, process, network, resource, credential, data-sharing, backend checks against mock paths. Live probes are stubbed unless `live_boundary_tests` is set. |
| Backend conformance suite | Test | `../../crates/pico-runtime/tests/conformance.rs`, `cargo nextest run -p pico-runtime --test conformance` | Lifecycle contract across adapters. |
| Seccomp and capability profiles | Config and test | `../../crates/pico-seccomp/profiles/`, `../../crates/pico-seccomp/src/lib.rs` | Per-component profiles for host-agent, sandboxd, guest-agent, Firecracker, QEMU, gVisor, network-agent. |
| cgroup v2 controls | Test and doc | `../../crates/pico-core/src/cgroups.rs`, `../observability/cgroup-metrics.md` | Path safety, CPU list formatting, pressure metric basis. |
| CPU isolation units | Test | `../../crates/pico-core/src/cpu_isolation/tests.rs` | Dedicated cores and SMT sibling exclusion logic used by RR-06c reasoning. |
| Backend readiness report | Report | [backend readiness](../robustness/backend-prod-readiness-report.md), `cargo nextest run -p pico-runtime --test conformance` plus isolation and lib suites | 2026-09-10 verdict: preview for Firecracker/QEMU, preview with policy restriction for gVisor, evaluation-only for Cloud Hypervisor/Kata, rejected for RemoteFirecracker. 207 tests pass. |
| Live boot evidence | Procedure, samples, and CI | [live-boot evidence](../robustness/live-boot-evidence/README.md), `scripts/live-boot-evidence.sh`, `.github/workflows/live-boot-evidence.yaml`, `../../crates/pico-runtime/tests/live_boot.rs` | Ignored-by-default live walks (schema `live-boot-evidence/1` with source revision, host image, kernel, VMM versions, digests, transport). Recorded passes: Firecracker on Ubuntu 24.04 aarch64 with KVM; QEMU on the same Linux host over vsock with QMP stop/cont; QEMU on macOS hvf via the serial fallback. Current evidence comes from per-revision CI artifacts and collector reruns. Wiring the same runs into self-hosted CI (per-revision bundles on every run instead of manual collector runs) is still pending. |
| Privileged helper inventory | Doc | [privileged helpers](privileged-helpers.md) | Per-backend helper tables and namespace model. |
| Side-channel assessment | Assessment | [side-channel assessment](side-channel-assessment.md) | Backend comparison and RR-06a/b/c placement limits. Design-level; live cache/timing probes are stubbed. |

### Gaps

| Gap | Follow-up |
|---|---|
| Live VMM enforcement is not in CI. Isolation suite validates policy and config on mock paths. 134 (Done) produced a Darwin/arm64 sample, not a Linux KVM production host. | 138 Linux KVM live-boot CI evidence |
| Backend report is Draft and rates supported paths as preview, with TCP host path and fail-open selection gates noted as blockers. 92 (Done) is the evidence source. | 141 remaining 92 report blockers |
| ADR-0004 and ADR-0006 remain Proposed. | Owner approval track for M0 posture |
| Shared-host cross-tenant placement has no approved profile. | RR-06 / G-15; dedicated tenancy fallback |

## C-02 Credentials Are Short-Lived, Scoped, and Excluded From Persistent Artifacts

**Claim**: Runtime credentials are mediated where possible, otherwise
short-lived and narrowly scoped, bound to policy epoch and lease, revoked
on policy change, lease expiry, destroy, resume, and fork, redacted from
telemetry, and never persisted into snapshot artifacts.

**Related risks**: R-10, R-11, R-16.
**Related gates**: G-09, G-10, G-12.
**Disposition**: `missing`.

### Argument

The claim holds only if issuance is authorized and scoped, enforcement
rejects stale and misbound leases before side effects, revocation is
explicit and audited (including on destroy), redaction is tested, and
snapshot capture provably excludes secret mounts. Destroy auto-revokes
all active leases for the sandbox with `ResourceRemoved` between the
`Destroying` commit and `Destroyed`, carrying the destroying operation
identity onto each `LeaseRevoked` event (140).

### Evidence

| Evidence | Type | Location and how to run | Coverage |
|---|---|---|---|
| Credential snapshot exclusion suite | Test | `../../crates/pico-core/tests/credential_snapshot_exclusion.rs`, `cargo nextest run -p pico-core --test credential_snapshot_exclusion` | Secret mounts ephemeral, exclusion receipts, restore refresh, fork inheritance, misplaced-credential negative fixture, audit redaction. |
| Secrets broker suite | Test | `../../crates/pico-core/tests/secrets_broker.rs`, `cargo nextest run -p pico-core --test secrets_broker` | Mock and HTTP broker fetch/deny, snapshot exclusion, issuance redaction. HTTP path needs the `secrets-http` feature. |
| Lease scope suite | Test | `../../crates/pico-core/tests/secrets_lease_scope.rs`, `cargo nextest run -p pico-core --test secrets_lease_scope` | CredentialAccess lease scope and stale policy epoch rejection. |
| Host-agent secrets integration | Test | `../../crates/pico-host-agent/tests/secrets_integration.rs`, `cargo nextest run -p pico-host-agent --test secrets_integration` | Coordinator revoke path with audit. |
| Destroy-path lease revoke | Test | `../../crates/pico-core/tests/control_plane_readiness.rs` (`destroy_revokes_all_sandbox_leases`, `concurrent_destroy_and_lease_use_is_fail_closed`), `cargo nextest run -p pico-core --test control_plane_readiness` | Destroy revokes all sandbox leases with `ResourceRemoved`, no lease validates after `Destroyed`, revokes carry destroying operation identity, race is fail-closed; foreign-sandbox leases survive. 140 supersedes the 91 report exception for the destroy-revoke gap. |
| Host-agent destroy revoke-all | Test | `../../crates/pico-host-agent/src/secrets.rs` (`revoke_all_for_sandbox_revokes_every_lease_with_operation_identity`), `cargo nextest run -p pico-host-agent --lib secrets`; destroy wiring in `../../crates/pico-host-agent/src/tests.rs` (`destroy_revokes_all_known_credential_leases`) | Coordinator revokes every known lease for the sandbox on destroy with operation identity. |
| sandboxd secrets and DNS ownership | Test | `../../crates/pico-sandboxd/tests/secrets_dns.rs`, `cargo nextest run -p pico-sandboxd --test secrets_dns` | Secrets inject and DNS attach ownership. |
| Credential policy units | Test | `../../crates/pico-core/src/snapshot/credential_policy.rs` | Policy allow/deny units. |
| Isolation credential checks | Test | `../../crates/pico-runtime/src/isolation/credentials.rs` via the isolation suite | Production mount exclusion assertions. |

### Gaps

| Gap | Follow-up |
|---|---|
| HTTP broker coverage is feature-gated and not part of the default evidence bundle. 83 (Done) is the broker implementation source. | 139 default-bundle HTTP broker evidence |
| Application memory can still contain tenant-copied secrets that exclusion rules cannot classify. | RR-03 |

## C-03 Network Exposure Is Policy-Controlled, Time-Bound, and Auditable

**Claim**: Every sandbox network path starts isolated, each egress/DNS/ingress
exception is bound to current policy and a lease with expiry, revocation
takes effect promptly, cleanup leaves no stale mapping, and every decision
is auditable without exposing tenant data through labels.

**Related risks**: R-10, R-12, R-15.
**Related gates**: G-07, G-11, G-12.
**Disposition**: `partial`.

### Argument

The claim needs default-deny enforcement, lease-bound ingress, policy DNS,
anti-spoofing, revocation and restart behavior, reconciliation to a known
safe state, and tenant-safe metrics and audit events.

### Evidence

| Evidence | Type | Location and how to run | Coverage |
|---|---|---|---|
| Networking model | ADR | [ADR-0005](../adr/0005-per-sandbox-networking-model.md) | Per-sandbox routed networking with deny-by-default enforcement. Proposed. |
| Egress policy suite | Test | `../../crates/pico-network-agent/tests/egress_integration.rs`, `cargo nextest run -p pico-network-agent --test egress_integration` | Allow/deny CIDR, RFC1918/CGNAT protection, NAT, lease identity, cleanup idempotency. |
| Reconciliation suite | Test | `../../crates/pico-network-agent/tests/reconciliation_integration.rs`, `cargo nextest run -p pico-network-agent --test reconciliation_integration` | Stale object cleanup and receipt-based reconcile. |
| eBPF policy path | Test | `../../crates/pico-network-agent/tests/ebpf_integration.rs`, `cargo nextest run -p pico-network-agent --test ebpf_integration` | eBPF enforcement path. |
| sandboxd network pipeline | Test | `../../crates/pico-sandboxd/tests/network.rs`, `cargo nextest run -p pico-sandboxd --test network` | Pipeline ownership. |
| Network isolation defaults | Test | `../../crates/pico-runtime/src/isolation/network.rs` via the isolation suite | Default `network_isolated` assertion. |
| Runbooks and dashboards | Ops | [networking](../runbooks/networking.md), [dns](../runbooks/dns.md), `../../o11y/networking.json`, `../../o11y/dns.json` | Response paths and tenant-safe panels. Validated in CI by `scripts/validate-o11y-dashboards.sh`. |
| Networking readiness report | Report | [network readiness](../robustness/network-prod-readiness-report.md), `cargo nextest run -p pico-network-agent --lib --tests` | 2026-09-23 Draft. 280 tests pass across network-agent (237), sandboxd network (5), host-agent port-forward (22), and edge (16). Pins provisioning identity, egress/DNS, lease-bound ingress, resume/fork decisions, reconciliation, and metrics. Live Linux attachment, IPv6, and owner approval remain open. |

### Gaps

| Gap | Follow-up |
|---|---|
| Live Linux namespace, TAP, nftables, and NAT attachment is not in the default suite. `fork_network` device creation is untested off a privileged host. | Linux host network walk under the readiness report section 10 |
| IPv6 guest networking is disabled. DNS answers IPv6 sources with `NXDOMAIN`. | Equivalent IPv6 controls before dual-stack |
| ADR-0005 remains Proposed. The readiness report is Draft pending Networking, Runtime, Platform, and SRE approval. | Owner approval track |
| `pico-edge` allows a request when `require_lease` is false and no lease header is present. Pingora reload, body limits, and WebSocket drain are not covered by the edge unit tests. | Production edge config requires leases; proxy-lifecycle tests |

## C-04 Snapshot and Fork Behavior Does Not Leak Excluded State

**Claim**: Snapshot capture quiesces, revokes, zeroizes, detaches, and
excludes declared secret and runtime state; artifacts are encrypted,
integrity-checked, tenant- and lineage-bound; restore and fork issue fresh
identity, network, protocol, lease, and credential authority; retention and
deletion are enforced.

**Related risks**: R-16, R-17, R-18.
**Related gates**: G-08, G-10, G-11.
**Disposition**: `missing`.

### Argument

Exclusion must be proven by artifact scans and negative fixtures, not by
policy text. Encryption and integrity must be tested, restore must reject
tampered or stale artifacts, and fork must preserve lineage binding while
issuing independent authority.

### Evidence

| Evidence | Type | Location and how to run | Coverage |
|---|---|---|---|
| Consistency model | ADR | [ADR-0007](../adr/0007-snapshot-resume-fork-consistency-model.md) | Snapshot, resume, and fork semantics. Proposed. |
| Credential exclusion suite | Test | `../../crates/pico-core/tests/credential_snapshot_exclusion.rs` | Exclusion receipts and fork credential policy. Shared with C-02. |
| Encryption and integrity suite | Test | `../../crates/pico-core/tests/snapshot_encryption_robustness.rs`, `cargo nextest run -p pico-core --test snapshot_encryption_robustness` | Encryption, integrity, stale digest after key-ref change. |
| Fork units | Test | `../../crates/pico-core/src/snapshot/cow/fork/tests.rs`, `cargo nextest run -p pico-core --lib snapshot` | Fork depth and independent child workspace behavior. |
| Image validation | Test | `../../crates/pico-image/tests/validation_static.rs`, `../../crates/pico-image/tests/pipeline.rs` | Empty `excluded_mount_classes` fails; manifests pin `secret` and `runtime_tmp` exclusion. |
| Image readiness report | Report | [image readiness](../robustness/image-prod-readiness-report.md), `cargo nextest run -p pico-image --lib --tests` | 2026-09-23 Draft. 249 tests pass. Pins manifest schema, mount exclusions, host rejection of unsigned and mismatched artifacts, and warm-snapshot lineage. OCI referrers, vulnerability scanning, promotion attestations, and owner approval remain open. |
| Snapshot runbook | Ops | [snapshot-fork](../runbooks/snapshot-fork.md), `../../o11y/snapshot-fork.json` | Response path. The runbook records that `HostAgent::restore_from_snapshot` stays fail-closed. |

### Gaps

| Gap | Follow-up |
|---|---|
| No integrated snapshot readiness report exists. Retention, deletion, restore, and fork evidence is spread across suites. | 143 G-10 snapshot readiness report |
| `HostAgent::restore_from_snapshot` remains fail-closed (`snapshot restore via sandboxd is not implemented yet`). | 143 host-agent restore path |
| ADR-0007 remains Proposed. | Owner approval track |

## C-05 Lifecycle State Cannot Be Advanced by Stale or Misbound Decisions

**Claim**: Lifecycle transitions are authorized, fresh, correctly bound to
tenant/sandbox/operation/policy/lease/boot/lineage identity, fenced
against stale actors, idempotent on retry, convergent under concurrency,
and ordered in audit.

**Related risks**: R-01, R-04, R-07, R-08.
**Related gates**: G-03, G-06, G-11, G-12.
**Disposition**: `partial`.

### Argument

Lifecycle safety needs typed identity binding, fencing epochs, policy epoch
checks, optimistic concurrency with single-winner semantics, protocol
replay/reflection resistance, and audit ordering that survives retry and
restart.

### Evidence

| Evidence | Type | Location and how to run | Coverage |
|---|---|---|---|
| Ownership and state model | ADR | [ADR-0001](../adr/0001-control-plane-ownership-lifecycle-state-model.md), [ADR-0011](../adr/0011-sandboxd-process-boundary-and-host-ingress.md) | Control-plane ownership, lifecycle authority, sandboxd split. ADR-0011 is Accepted; ADR-0001 is Proposed. |
| Protocol contract | ADR | [ADR-0003](../adr/0003-host-guest-agent-protocol-contract.md) | Authenticated bounded host/guest protocol. Accepted pending final owner approval. |
| Control-plane readiness | Test and report | `../../crates/pico-core/tests/control_plane_readiness.rs`, [control-plane report](../control-plane/prod-readiness-report.md), `cargo nextest run -p pico-core --test control_plane_readiness` | 46 tests across lifecycle contract, retry/concurrency, time/identity binding, policy/quota, leases, schedulers, audit, degradation, scheduler-on-create, and stale-operation convergence. |
| Create-path placement | Test | `../../crates/pico-core/src/create.rs`, `cargo nextest run -p pico-core --test control_plane_readiness create_path` | Regional plus cell placement on the create path with persisted placement, typed rejections in traces and audit, trace/operation/key correlation, quota release on reject, and best-effort audit degradation. |
| Stale-operation convergence | Test | `../../crates/pico-core/src/metadata.rs` (`commit_with_operation`), `../../crates/pico-core/src/create.rs` (`IdempotencyStore`), `cargo nextest run -p pico-core --test control_plane_readiness commit_with_operation`, `create_idempotent` | Operation-identity commit with `StaleOperation` construction, idempotent replay without version move, same-key conflict detection, and partition retry converging to one outcome. |
| Fencing units | Test | `../../crates/pico-core/src/identity/fencing.rs`, `cargo nextest run -p pico-core --lib fencing` | Newer-epoch takeover and stale-token rejection. |
| sandboxd supervisor stale rejection | Test | `../../crates/pico-sandboxd/tests/supervisor.rs`, `cargo nextest run -p pico-sandboxd --test supervisor` | Stale fencing token and stale policy epoch rejected before runtime side effects. |
| Protocol robustness | Test and report | `../../crates/pico-guest-protocol/tests/robustness.rs`, `../../crates/pico-guest-protocol/tests/compat_fixtures.rs`, `../../crates/pico-guest-protocol/tests/protocol.rs`, `../../crates/pico-guest-protocol/tests/grpc_stack.rs`, `../../crates/pico-guest-protocol/tests/session.rs`, [protocol report](../robustness/guest-agent-proto-prod-readiness-report.md) | Framing, handshake, binding, replay/reflection, stale policy epoch detection, v1.0/v1.5 compatibility, plus gRPC-stack backpressure/deadline (slow consumer with memory ceiling, deadline teardown without leak, oversize rejection before allocation) over TCP loopback and Unix socket, and bounded host buffering (`OutputLimitExceeded`/`FileTooLarge`). |
| Misuse-resistance checklist | Process | [misuse-resistance checklist](../robustness/misuse-resistance-checklist.md) | Required review before new RPCs. |
| Audit ordering and correlation | Test | `../../crates/pico-core/tests/audit_ordering.rs`, `../../crates/pico-core/tests/audit_correlation.rs` | HLC ordering including fencing tokens, correlation IDs. |

### Gaps

| Gap | Follow-up |
|---|---|
| Core scheduler-on-create and stale-operation plumbing landed in 142; API wiring of `CreateOrchestrator` and a durable cross-restart operation log remain. 91 (Done) was the prior evidence source. | 142 follow-up for API seam and durable store |
| Protocol report is Draft. | Owner approval track |

## C-06 Operators Can Detect, Respond to, and Recover From Critical Failures

**Claim**: Required metrics, traces, redacted logs, and durable audit events
are complete, current, tenant-safe, and queryable; every launch-critical
signal has an owner, dashboard, alert, and tested response; SLOs and error
budgets gate rollout; and quarantine, drain, rebuild, rollback, and incident
paths are exercised.

**Related risks**: R-02, R-06, R-09, R-15, R-19, R-20.
**Related gates**: G-12, G-13, G-14, G-16.
**Disposition**: `missing`.

### Argument

Detection needs instrumentation conformance, freshness, cardinality bounds,
and redaction. Response needs runbooks with severity, first checks,
mitigation, escalation, and rollback. Recovery needs quarantine, restart,
revocation, rollback, and evidence preservation, all verified by drills.

### Evidence

| Evidence | Type | Location and how to run | Coverage |
|---|---|---|---|
| Signal contract | ADR | [ADR-0009](../adr/0009-observability-and-reliability-signals.md) | Signal schemas, correlation, cardinality, redaction, audit, dashboard, and alert contract. Proposed. |
| Scale validation strategy | ADR | [ADR-0012](../adr/0012-production-scale-validation-strategy.md) | LPOP and scenario validation basis for G-14. Proposed. |
| SLO and error-budget policy | Policy | [SLO policy](../observability/slo-error-budget-policy.md), `../../o11y/slo-error-budget.json`, `../../o11y/rules/pico-recording-rules.yaml` | Measurable SLIs, 30-day windows, burn alerts, freeze rules. Proposed. |
| Audit pipeline suites | Test | `../../crates/pico-core/tests/audit_pipeline.rs`, `audit_contract.rs`, `audit_correlation.rs`, `audit_ordering.rs`, `audit_dead_letter.rs`, `audit_retry.rs`, `audit_schema_compat.rs` | Policy-to-lease chain, redaction, query, retention, ordering, dead-letter, retry, forward compatibility. |
| Runbook index | Ops | [runbook index](../runbooks/README.md) | Coverage map from failure mode to runbook and alert category, plus host-mutation policy. |
| Lifecycle and capacity runbooks | Ops | [control-plane](../runbooks/control-plane.md), [lifecycle-operations](../runbooks/lifecycle-operations.md), [scheduling-capacity](../runbooks/scheduling-capacity.md), [host-health](../runbooks/host-health.md), [host-quarantine](../runbooks/host-quarantine.md), [audit-telemetry](../runbooks/audit-telemetry.md), [slo-error-budget](../runbooks/slo-error-budget.md), [cleanup-reconciliation](../runbooks/cleanup-reconciliation.md) | Severity, first checks, mitigation, escalation, rollback per area. |
| Boot quarantine drill | Drill | [boot non-ready and quarantine drill](../runbooks/drills/boot-non-ready-and-quarantine.md) | Tabletop with image/network/backend/protocol non-ready injects plus quarantine. Result table is still empty. |
| Dashboards | Ops | `../../o11y/*.json` provisioned by `../../o11y/provisioning/dashboards.yml`, validated by `scripts/validate-o11y-dashboards.sh` | Twelve Grafana dashboards under the `PicoCompute` folder with tenant-safe dimensions. |
| Quarantine and availability units | Test | `../../crates/pico-core/src/availability/tests.rs`, `../../crates/pico-core/src/host_quarantine/tests.rs` | Inventory staleness and quarantine overlay behavior. |
| Restart acceptance | Test | `../../crates/pico-host-agent/tests/restart_acceptance.rs`, `../../crates/pico-host-agent/tests/binary_restart_acceptance.rs`, `../../crates/pico-sandboxd/tests/restart_acceptance.rs` | Host-agent and sandboxd restart paths. Binary restart is a CI job in `../../.github/workflows/test.yaml`. |
| Tracing and cgroup docs | Doc | [distributed tracing](../observability/distributed-tracing.md), [cgroup metrics](../observability/cgroup-metrics.md) | Sampling, correlation, and contention visibility basis. |
| Dependency policy gate | CI job and policy | `../../deny.toml`, `../../.github/workflows/deny.yaml`, [dependency policy](dependency-policy.md), `cargo deny check` | License, advisory, source, and banned-crate policy with reviewed exceptions. |
| Coverage bundle with threshold verdict | CI job, config, collector, and threshold doc | [coverage threshold](coverage-threshold.md), `../../.config/coverage.json`, `../../scripts/coverage.sh`, `../../.github/workflows/coverage.yaml`, `cargo llvm-cov nextest --workspace --all-features` | Line floors for workspace plus `pico-core`, `pico-runtime`, `pico-guest-protocol`, and `pico-network-agent`; region coverage warn-only; revision-pinned bundle (`coverage.json`, `lcov.info`, `gate.json`, `meta.json`, `summary.md`) uploaded as `coverage-bundle-<sha>`. Below-threshold fails the job and blocks `G-16`. |

### Gaps

| Gap | Follow-up |
|---|---|
| SLO policy is Proposed and `pico:slo:*` queries are provisional until measured candidate behavior justifies tightening. 85 (Done) defined the policy. | 144 G-14 LPOP evidence against live `pico:slo:*` queries |
| Drill result table is empty and no incident tabletop is recorded. | 146 dated drill and tabletop results |
| Dependency-policy gate is configured (`deny.toml` plus CI); coverage threshold is defined with a revision-pinned candidate bundle per candidate revision (see coverage threshold doc). | Coverage ratchet plus owner approval; cite the attached bundle for the candidate revision |
| Fuzz and property evidence is absent: no `cargo-fuzz` corpus and no `proptest` coverage for lifecycle, protocol, or snapshot invariants. | 147 fuzz and property tests |

## 7 Evidence Matrix

`S` marks primary evidence for the claim. `+` marks supporting evidence.

| Evidence | C-01 isolation | C-02 credentials | C-03 network | C-04 snapshot/fork | C-05 lifecycle | C-06 detect/recover |
|---|---|---|---|---|---|---|
| ADR-0006 posture | S | S | S | S | S | + |
| Threat model R-01/R-20 with FMEA | + | + | + | + | S | S |
| Production readiness G-01/G-17 | S | S | S | S | S | S |
| ADR-0004 backend strategy | S |  |  |  | + |  |
| ADR-0001/ADR-0011 lifecycle |  |  |  |  | S | + |
| ADR-0003 protocol |  |  |  | + | S |  |
| ADR-0005 networking |  |  | S |  |  | + |
| ADR-0007 snapshot model |  | S |  | S |  |  |
| ADR-0009 signals |  |  | + |  | + | S |
| ADR-0012 scale validation |  |  |  |  |  | S |
| Isolation suite `isolation.rs` | S | + | + |  |  |  |
| Conformance suite `conformance.rs` | S |  |  |  | + |  |
| Backend selection units | S |  |  |  | + |  |
| Seccomp profiles | S |  |  |  |  |  |
| cgroup and CPU isolation units | S |  |  |  |  | + |
| Backend readiness report | S |  |  |  | + |  |
| Live boot evidence | S |  |  |  |  |  |
| `credential_snapshot_exclusion.rs` |  | S |  | S |  |  |
| `secrets_broker.rs`, `secrets_lease_scope.rs` |  | S |  | + | + |  |
| `snapshot_encryption_robustness.rs` |  | + |  | S |  |  |
| Image validation suites |  |  |  | S |  |  |
| Egress/reconciliation/eBPF suites |  |  | S |  |  | + |
| `control_plane_readiness.rs` and report |  | + |  |  | S | + |
| Protocol robustness/compat suites and report |  |  |  |  | S |  |
| Audit pipeline suites |  | + | + |  | + | S |
| SLO policy, rules, dashboards |  |  | + |  |  | S |
| Runbooks and quarantine drill | + |  | + | + | + | S |
| CI: nextest, Clippy, RustSec, Semgrep, cargo-deny | + | + | + | + | + | S |
| Coverage bundle with threshold verdict | + | + | + | + | + | S |

## 8 Accepted-Risk Register

This register operationalizes the residual risks from the
[threat model](threat-model.md#residual-risk-register) and the
[side-channel RR-06a/b/c entries](side-channel-assessment.md#accepted-risk-register).
It does not duplicate their analysis. Every entry below is `not_accepted`
for a public shared-host production profile until the stated conditions
close. Dedicated tenancy is the compensating fallback, not acceptance of
shared-host exposure.

| ID | Scope | Compensating controls | Status | Next review | Follow-up |
|---|---|---|---|---|---|
| RR-01 unknown VMM/kernel/firmware/hardware escape | Exact patched VM profile | Emergency drain, revoke, rebuild, patch capability; host quarantine | `not_accepted` | Before any production approval; on new advisory or patch | 149 patch/rebuild exercise |
| RR-02 workload exfiltrates a visible credential during its lifetime | Direct-delivery credential modes | Mediation preference, narrow scope, short lifetime, downstream enforcement | `not_accepted` | Before enabling direct delivery for a new workload class | Policy owner approval; RR-02 stays not accepted |
| RR-03 tenant-copied secrets in application memory escape classification | Snapshot-capable profiles | Snapshot policy, classification, retention, tenant notice, encryption | `not_accepted` | Before enabling snapshot capture for a new data class | 143 G-10 snapshot readiness report |
| RR-04 authorized egress reaches a compromised service or carries an application-layer channel | Egress-enabled profiles | Destination policy, downstream AuthZ, narrow credentials, monitoring | `not_accepted` | Before opening a new egress class | [network readiness report](../robustness/network-prod-readiness-report.md) section 3; downstream AuthZ remains open |
| RR-05 compromised control plane or insider acts within granted authority | All profiles | Separation of duties, least privilege, independent audit, review, recovery | `not_accepted` | Continuous; at each access-model change | Audit pipeline and access review |
| RR-06 shared hardware timing/contention/cache/covert channels | Shared-host profiles | Dedicated tenancy until the exact profile has evidence and explicit acceptance | `not_accepted` | Before any shared-host approval | Side-channel G-15 conditions |
| RR-06a L3 cache timing on microVM backends | Firecracker/QEMU shared hosts | Non-overlapping CPU pinning, SMT sibling exclusion | `not_accepted` | 2027-01-01 or before public beta | SC-IMPL-01, SC-IMPL-02 |
| RR-06b metric and telemetry inference | Shared hosts | `shared_host_metric_redaction`, per-tenant aggregation, rate limits | `not_accepted` | 2027-01-01 or before public beta | SC-IMPL-06 |
| RR-06c gVisor cross-tenant co-location | gVisor shared hosts | Prohibited for v1; dedicated tenancy plus Trusted Fast-Path restriction | `not_accepted` | 2027-01-01 | SC-IMPL-01, SC-IMPL-02 |
| RR-07 build, signing, registry, and vulnerability-data trust | Release artifacts | Key protection, separated duties, digest pinning, revocation monitoring, rebuild capability | `not_accepted` | Before promoting a new artifact pipeline | [image readiness report](../robustness/image-prod-readiness-report.md) section 11; OCI referrers, vulnerability scanning, and promotion attestations remain open |
| RR-08 regional/provider/organizational failure beyond tested recovery | Launch tier | Launch tier definition, recovery objectives, owner coverage, drills, accepted outage/data-loss limits | `not_accepted` | Before production approval; after each drill | Scale validation and incident exercises |

Acceptance for one profile never authorizes another profile and never
survives a material architecture, hardware, runtime, kernel, or threat
change.

### Follow-up issues

Every gap below is owned by an open follow-up issue related to 89.
Done issues that produced current evidence are named in the evidence
tables, not here. Each item stays `missing` evidence until its owner
lands and this case cites the new evidence.

Remaining after Done evidence:

- 138: Linux KVM live-boot CI evidence for Firecracker and QEMU on a
  production host profile. 134 produced a Darwin/arm64 sample only
  (C-01).
- 141: remaining 92 report blockers: TCP host path, fail-open
  selection gates, and preview-to-production promotion (C-01).
- 140: destroy-path lease revoke so destroy cannot leave a valid
  credential lease (C-02). 91 pinned the exception.
- 139: default-bundle HTTP broker evidence without the `secrets-http`
  feature gate (C-02).
- 143: host-agent snapshot restore path replacing the fail-closed
  `HostAgent::restore_from_snapshot` stub, plus an integrated G-10
  snapshot readiness report (C-04).
- 142: core scheduler-on-create and stale-operation plumbing landed;
  follow-up is API wiring of `CreateOrchestrator` and a durable
  cross-restart operation log (C-05). 91 pinned the prior exceptions.
- 144: G-14 LPOP evidence against live `pico:slo:*` queries (C-06).
- 146: dated boot/quarantine drill results and an incident tabletop
  (C-06).
- 149: patch/rebuild exercise for RR-01.

Tooling:

- 147: `cargo-fuzz` targets for protocol framing, handshake, and
  boundary-sensitive parsers, plus `proptest` coverage for lifecycle,
  protocol, and snapshot invariants (R-07 evidence).
- Coverage threshold definition with a revision-pinned candidate bundle
  landed (see coverage threshold doc); ratchet plus owner approval remain.

## 9 Review Checklist

Use this checklist for the dry-run assurance review, for link verification,
and after every major backend, networking, snapshot, or credential change.

### Dry run

- [ ] Freeze the candidate source revision, artifact digests, configuration,
  and exact deployment profile.
- [ ] For each claim C-01 through C-06, open every evidence link and rerun
  the listed `cargo nextest` command for the candidate revision.
- [ ] Mark each claim `supported`, `partial`, or `missing`. Any `partial`
  or `missing` blocks the affected production profile.
- [ ] Confirm disabled capabilities cannot be admitted or enabled through
  fallback, operator override, stale state, or configuration drift.
- [ ] Run at least one adversarial and one independent-failure scenario from
  each applicable threat-model risk tree.
- [ ] Confirm every RR entry has scope, compensating controls, status, next
  review, and follow-up. No silent acceptance.
- [ ] Record residual risks, exceptions, compensating controls, owners,
  expiry, and rollback behavior.
- [ ] Obtain subsystem approvals, then independent Security and SRE
  approval. Architecture approval is required for public beta and
  production.

### Link and evidence verification

- [ ] Every relative link in claim evidence tables C-01 through C-06 and
  in the evidence matrix resolves from this file.
- [ ] Every `cargo nextest` command names a suite that exists.
- [ ] Every report cited shows its date and status without overstating it
  (Draft stays Draft, preview stays preview, Proposed stays Proposed).
- [ ] No claim cites tool availability as passing evidence. Attached
  candidate results are required.
- [ ] The drill entry links dated results once the tabletop is executed.
  The empty result table is a gap until then.

### Re-review triggers

Re-run the affected claim review when any of these change:

- backend, launcher, VMM version, device profile, or security profile
- host kernel, host image, firmware, microcode, or hardware class
- guest image, guest agent, protocol, mount, or device profile
- network, DNS, egress, ingress, lease, or IPv6 policy
- credential broker, token scope, delivery, rotation, or revocation
- snapshot format, capture, exclusion, retention, deletion, restore, or fork
- workload class, tenant-sharing, data-classification, or admission rule
- telemetry, audit, alert, runbook, SLO, or incident-response contract
- new critical/high advisory, security incident, failed drill, or
  evidence-integrity failure

### Approval

This case remains Proposed until Security and architecture owners approve
the claim mapping, the risk register, and the review procedure, with SRE
approval for C-06:

- [ ] Security owner
- [ ] Architecture owner
- [ ] SRE owner (C-06 and drill evidence)

## Maintenance

The Security owner maintains claim identifiers and this risk register.
Component owners maintain linked controls and evidence. 67 consumes the
approved gate records from this case as its G-17 input; this case never
approves a rollout by itself.

## References

- [ADR-0001](../adr/0001-control-plane-ownership-lifecycle-state-model.md)
- [ADR-0002](../adr/0002-host-runtime-lifecycle-orchestration.md)
- [ADR-0003](../adr/0003-host-guest-agent-protocol-contract.md)
- [ADR-0004](../adr/0004-default-isolation-backend-strategy.md)
- [ADR-0005](../adr/0005-per-sandbox-networking-model.md)
- [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
- [ADR-0007](../adr/0007-snapshot-resume-fork-consistency-model.md)
- [ADR-0008](../adr/0008-guest-image-format-and-build-pipeline.md)
- [ADR-0009](../adr/0009-observability-and-reliability-signals.md)
- [ADR-0011](../adr/0011-sandboxd-process-boundary-and-host-ingress.md)
- [ADR-0012](../adr/0012-production-scale-validation-strategy.md)
- [PicoCompute threat model](threat-model.md)
- [PicoCompute production readiness model](production-readiness.md)
- [Side-channel assessment](side-channel-assessment.md)
- [Privileged helpers](privileged-helpers.md)
- [Control-plane readiness report](../control-plane/prod-readiness-report.md)
- [Backend readiness report](../robustness/backend-prod-readiness-report.md)
- [Protocol readiness report](../robustness/guest-agent-proto-prod-readiness-report.md)
- [Misuse-resistance checklist](../robustness/misuse-resistance-checklist.md)
- [Live-boot evidence](../robustness/live-boot-evidence/README.md)
- [SLO and error-budget policy](../observability/slo-error-budget-policy.md)
- [Cgroup metrics](../observability/cgroup-metrics.md)
- [Distributed tracing](../observability/distributed-tracing.md)
- [Runbook index](../runbooks/README.md)
- [Boot non-ready and quarantine drill](../runbooks/drills/boot-non-ready-and-quarantine.md)
- [Coverage threshold and candidate bundle](coverage-threshold.md)

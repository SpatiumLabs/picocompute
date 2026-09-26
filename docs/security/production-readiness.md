# PicoCompute Production Readiness Model

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M5 - Security Production Review
**Normative posture**:
[ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md)
**Risk model**: [PicoCompute threat model](threat-model.md)
**Side-channel assessment**:
[side-channel and covert-channel risk assessment](side-channel-assessment.md)
**Signal model**:
[ADR-0009](../adr/0009-observability-and-reliability-signals.md)
**Scale validation**:
[ADR-0012](../adr/0012-production-scale-validation-strategy.md)

## Purpose

This document defines how PicoCompute decides whether an exact deployment profile
may serve private-preview, public limited-beta, or production workloads. It
turns the mandatory controls in ADR-0006 and the risks in the threat model into
blocking launch gates, evidence requirements, owner responsibilities, and
stage-specific thresholds.

This model is the source of truth for readiness criteria. Implementation issues
remain the source of truth for delivery state, validation reports remain the
source of truth for test results, and
 remains the final rollout
checklist.

This document cannot lower an ADR-0006 isolation floor or hard invariant. When
documents conflict, the stricter requirement applies until Security and
architecture review updates the normative sources.

## Readiness Unit

Readiness applies to an exact deployment profile, not to PicoCompute in general.
Every review records:

- workload class and supported use cases
- tenant-sharing and data-classification assumptions
- region, cell, host image, hardware class, and kernel
- runtime backend, launcher, VMM version, and security profile
- guest image, guest-agent version, and protocol range
- network, DNS, egress, ingress, and IPv6 policy
- credential delivery mode and downstream authorization assumptions
- workspace, snapshot, fork, cache, retention, and deletion behavior
- enabled lifecycle and API capabilities
- source revision, release artifact digests, and configuration revision

Approval for one profile does not authorize a different backend, hardware
class, image, credential mode, snapshot mode, workload class, or tenant-sharing
model.

## Gate Semantics

Every mandatory gate has one of these states:

| State | Meaning |
|---|---|
| `pass` | Current retained evidence covers the exact candidate profile and all required owners approved it. |
| `blocked` | Evidence is missing, failing, stale, incomplete, or does not cover the exact candidate profile. |
| `not_applicable` | The capability is disabled and the review records how admission and configuration prevent its use. |
| `expired` | Previously accepted evidence crossed its review date or an invalidation trigger occurred. The state is blocking. |

An unknown or unrecorded state is `blocked`. Issue completion, code presence,
an owner statement, or a green test from another profile is not sufficient
evidence.

### Evidence Record

Each gate record contains:

- stable gate identifier
- exact deployment-profile identifier and candidate revision
- evidence links and immutable report identifiers
- pass, fail, skipped, and unresolved result summary
- accountable owner and required reviewers
- review time and explicit expiry or revalidation trigger
- open risks, limitations, exceptions, and compensating controls
- follow-up issue for every unresolved item

Evidence without an owner, exact scope, and expiry or revalidation trigger is
stale and blocks the affected profile.

### Evidence Freshness

Evidence remains current only while it describes the deployed bytes,
configuration, infrastructure, and operating assumptions. The responsible
owner assigns a review date when producing the evidence. A fixed global
freshness period is not a substitute for profile-specific review.

The following changes invalidate affected evidence immediately:

- source, dependency, build toolchain, or release configuration change
- host kernel, host image, firmware, microcode, hardware, or VMM change
- guest image, guest agent, protocol, mount, or device-profile change
- network, DNS, egress, ingress, lease, or IPv6 policy change
- credential broker, token scope, delivery, rotation, or revocation change
- snapshot format, capture, exclusion, retention, deletion, restore, or fork
  change
- workload class, tenant-sharing, data-classification, or admission change
- telemetry, audit, alert, runbook, SLO, or incident-response contract change
- new critical or high vulnerability, security incident, failed drill, or
  evidence-integrity failure

CI results are valid only for the tested revision and declared environment.
Operational dashboards and alerts must be live and within their freshness
objectives at the time of review. Exercises and accepted-risk records require
an explicit next-review date.

### Exceptions

Exceptions are fail-closed and cannot:

- lower the public-untrusted isolation floor
- waive an ADR-0006 hard invariant
- allow ambient platform or non-expiring credentials
- bypass tenant separation, protected-destination policy, or evidence for the
  exact deployed profile
- convert missing independent validation into a passing gate

A permitted exception records exact scope, owner, reason, compensating
controls, expiry, rollback plan, audit record, and Security approval. Expired
exceptions block admission and rollout.

## Launch Stages

### Private Preview

Private preview is restricted to named, allowlisted tenants and approved
workloads. It requires:

- dedicated tenancy for tenant workloads, with no cross-tenant shared-host
  placement
- explicit supported-use-case and data-classification review
- admission controls that prevent disabled backends, features, snapshot modes,
  network paths, and credential modes
- all ADR-0006 hard invariants applicable to the enabled feature set
- current lifecycle, cleanup, tenant-separation, credential, and network
  validation for the selected profile
- bounded quota, capacity, and blast radius
- named operational and security contacts, rollback procedure, and evidence
  preservation path
- Security and SRE approval, plus every owner of an enabled subsystem

Features without passing evidence remain disabled. Private-preview status does
not authorize public untrusted workloads.

### Public Limited Beta

Public limited beta permits public untrusted workloads under strict quota,
feature, region, and capacity limits. It requires:

- every private-preview gate
- every ADR-0006 hard invariant for the complete public profile
- public-untrusted placement through an approved Firecracker profile, with
  QEMU only as the approved VM fallback and no container downgrade
- approval for the exact
  shared-host profile, or enforced dedicated tenancy
- integrated readiness reports for control plane, backend, protocol,
  networking, image supply chain, credentials, snapshot behavior, cleanup, and
  audit delivery
- strict quota, rate, concurrency, exposure, and rollout controls
- production-shaped dashboards, actionable alerts, runbooks, rollback, and
  incident escalation for every enabled capability
- measured provisional reliability and capacity limits based on the candidate
  profile
- Security, SRE, architecture, Runtime, Control Plane, and affected subsystem
  approval

Public beta cannot use an incomplete security gate as a learning experiment.
Incomplete optional capabilities remain disabled and `not_applicable`.

### Production

Production requires every public-beta gate plus:

- approved SLOs, SLIs, error-budget policy, and multi-window burn alerts
  ([slo-error-budget-policy](../observability/slo-error-budget-policy.md))
- validated capacity, cell-failure, snapshot-load, image-cache, cost, and
  headroom models
- complete service and component dashboards with defined missing-data behavior
- durable audit delivery, retention, integrity monitoring, and query support
- reviewed runbooks, rollback procedures, host rebuild procedures, and
  incident exercises
- a current [security assurance case](assurance-case.md) and accepted-risk register
- production support ownership and escalation coverage
- an approved production rollout checklist
  with staged rollout and rollback criteria
- Security, SRE, architecture, Runtime, Control Plane, Networking,
  Observability, Image Pipeline, Storage, Release, and Product approval

Production remains blocked while any mandatory gate is `blocked` or `expired`.

## Mandatory Gate Matrix

| Gate | Requirement | Minimum retained evidence | Blocking owners | Primary references |
|---|---|---|---|---|
| `G-01` Profile and workload contract | The exact profile, supported use cases, disabled capabilities, tenant-sharing model, and data classes are documented and enforced by admission. | Versioned profile manifest, admission tests, supported-backend matrix, and reviewed limitations. | Product, Architecture, Security | [ADR-0004](../adr/0004-default-isolation-backend-strategy.md), [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md), |
| `G-02` Threat and risk posture | Trust boundaries, critical and high risks, hard invariants, and residual risks cover the candidate profile. | Approved ADR-0006, threat-model review, current residual-risk records, and no unowned critical or high risk. | Security | |
| `G-03` Identity, policy, and control plane | Authentication, authorization, quota, leases, lifecycle state, fencing, scheduling, retries, and audit binding fail closed. | Integrated control-plane report with stale, replay, concurrency, degradation, and recovery results. | Control Plane, Security, SRE | [ADR-0001](../adr/0001-control-plane-ownership-lifecycle-state-model.md), |
| `G-04` Host and runtime isolation | The launcher, identities, namespaces, seccomp, capabilities, devices, mounts, sockets, cgroups, patch state, and privileged helpers meet the selected isolation floor. | Component profiles, negative boundary tests, lifecycle smoke tests, resource-exhaustion tests, and exact host/runtime inventory. | Runtime, Security | [ADR-0002](../adr/0002-host-runtime-lifecycle-orchestration.md), |
| `G-05` Backend selection and conformance | Backend selection is deterministic, never silently weakens isolation, and every enabled adapter satisfies the common contract. | Selection-policy fixtures, backend conformance report, supported capability matrix, diagnostics, and cleanup results. | Runtime, Architecture, Security | [ADR-0004](../adr/0004-default-isolation-backend-strategy.md), |
| `G-06` Host and guest protocol | Authentication, version negotiation, replay resistance, message bounds, streams, deadlines, reconnect, quiesce, and restore behavior are validated. | Compatibility fixtures, integration suite, robustness corpus, and backend transport report. | Runtime, Security | [ADR-0003](../adr/0003-host-guest-agent-protocol-contract.md), |
| `G-07` Network isolation and exposure | Namespace, anti-spoofing, default-deny egress, policy DNS, protected destinations, lease-bound ingress, IPv6, lifecycle, and cleanup controls pass. | Integrated network report with allow, deny, revocation, restart, restore, fork, cleanup, and metric evidence. | Networking, Security, Runtime | [ADR-0005](../adr/0005-per-sandbox-networking-model.md), [network readiness report](../robustness/network-prod-readiness-report.md) |
| `G-08` Image supply chain | Production artifacts are immutable, reproducible, digest-pinned, signed, vulnerability-reviewed, compatible, promoted, and verified again at the host. | Build provenance, SBOM, signature, vulnerability report, validation results, promotion record, and host rejection tests. | Image Pipeline, Runtime, Security | [ADR-0008](../adr/0008-guest-image-format-and-build-pipeline.md), [image readiness report](../robustness/image-prod-readiness-report.md) |
| `G-09` Credential safety | Credentials are mediated where possible and otherwise short-lived, scoped, protected, rotated, revoked, redacted, and non-persistent. | Broker authorization, scope, lifetime, delivery, denial, rotation, revocation, cleanup, and redaction tests. | Security, Control Plane, Runtime | [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md), |
| `G-10` Snapshot, fork, and data handling | Capture, storage, retention, deletion, restore, and fork preserve tenant and lineage binding while excluding stale authority and declared secret state. | Quiesce and exclusion receipts, artifact scans, encryption and integrity tests, compatibility results, retention and deletion evidence, and fresh-authority tests. | Storage, Runtime, Security | [ADR-0007](../adr/0007-snapshot-resume-fork-consistency-model.md), |
| `G-11` Cleanup and reconciliation | Crash, retry, restart, partial failure, orphan, quarantine, absence proof, and delayed reuse behavior reach a known safe state. | Destroy and network reconciliation reports, orphan scans, quarantine tests, and identity and address non-reuse evidence. | Runtime, Networking, Control Plane, SRE | |
| `G-12` Audit and operational telemetry | Required metrics, traces, redacted logs, and durable audit events are complete, current, tenant-safe, and queryable. | Instrumentation conformance, telemetry freshness, cardinality, redaction, audit delivery, replay, retention, and integrity reports. | Observability, Control Plane, Security, SRE | [ADR-0009](../adr/0009-observability-and-reliability-signals.md), |
| `G-13` Dashboards, alerts, and runbooks | Every launch-critical signal has an owner, dashboard, alert behavior, and tested operational response. | Dashboard review, alert routing and missing-data tests, [runbook index](../runbooks/README.md), [boot non-ready and quarantine drill](../runbooks/drills/boot-non-ready-and-quarantine.md), tabletop results, and stale-owner checks. | SRE, Observability, subsystem owners | |
| `G-14` Reliability, scale, and capacity | SLOs and rollout limits are based on measured candidate behavior under expected load and failure scenarios. | [SLO policy](../observability/slo-error-budget-policy.md), live `pico:slo:*` queries, burn-alert tests, [ADR-0012](../adr/0012-production-scale-validation-strategy.md) LPOP and scenario reports, capacity and headroom model, cell-failure results, and cost limits. must record no fast-burn page, remaining user-facing budget >= 25% or a current exception, and fresh telemetry. | SRE, Control Plane, Runtime, Product | [ADR-0012](../adr/0012-production-scale-validation-strategy.md), |
| `G-15` Side-channel and tenant-sharing posture | Shared resources and observability do not create an unreviewed multi-tenant exposure. | assessment for the exact profile and accepted-risk record, or enforcement evidence for dedicated tenancy. | Security, Runtime, SRE | |
| `G-16` Vulnerability and incident response | Dependency and artifact advisories are actionable, emergency drain and rebuild work, credentials can be revoked, rollback is tested, and incidents preserve evidence. | Advisory reports, static-analysis reports, revision-pinned coverage bundle with threshold verdict ([coverage threshold](coverage-threshold.md)), patch and rebuild exercise, credential-revocation exercise, rollback test, and incident tabletop. | Security, SRE, Runtime, Release | [ADR-0006](../adr/0006-production-security-posture-for-sandbox-isolation.md), |
| `G-17` Assurance and rollout decision | Claims map to current evidence, accepted risks are explicit, and staged rollout and rollback criteria are approved. | Assurance case, accepted-risk register, this gate review, final checklist, approver record, and rollout decision. | Security, SRE, Architecture, Product | [assurance case](assurance-case.md) |

## Owner Matrix

| Owner | Accountable readiness areas | Required approval |
|---|---|---|
| Security | Threat model, hard invariants, credentials, supply chain, side channels, vulnerability response, residual risk | Every launch stage |
| SRE | Reliability, capacity, dashboards, alerts, runbooks, rollback, incidents, support coverage | Every launch stage |
| Architecture | Workload classes, profile boundaries, ADR consistency, material exceptions | Public beta and production |
| Control Plane | Identity, policy, quota, leases, lifecycle state, scheduling, audit creation | Any stage enabling those paths |
| Runtime | Host process boundaries, VMMs, guest protocol, cgroups, cleanup, snapshot execution | Any stage running tenant workloads |
| Networking | Namespace, DNS, egress, ingress, leases, IPv4 and IPv6, network cleanup | Any stage enabling networking |
| Image Pipeline and Release | Build reproducibility, manifests, signatures, provenance, promotion, patch and rebuild | Any stage booting released artifacts |
| Storage | Workspace, snapshot, cache, retention, deletion, lineage, integrity | Any stage enabling persistent or captured state |
| Observability | Signal schemas, export, redaction, cardinality, dashboards, audit transport | Public beta and production |
| Product | Supported use cases, tenant communication, rollout limits, accepted service constraints | Production and public-beta scope |

Security and SRE approval are mandatory and independent. A subsystem owner
cannot self-approve independent validation evidence for a critical boundary.

## Evidence-Producing Tooling

Tool availability means PicoCompute can produce evidence. It does not mean the
current candidate has passed. A launch review links immutable results for the
candidate revision.

| Evidence source | Repository implementation | Readiness use | Baseline state |
|---|---|---|---|
| Rust formatting and Clippy | [GitHub test workflow](../../.github/workflows/test.yaml) | Compile-time quality and lint policy for the workspace | Configured; candidate result must be attached |
| `cargo-nextest` | [nextest configuration](../../.config/nextest.toml) and GitHub test workflow | Unit and integration test execution, failure output, and CI JUnit evidence | Configured; candidate result must be attached |
| Coverage gate (`cargo-llvm-cov`) | [Coverage threshold](coverage-threshold.md), [thresholds](../../.config/coverage.json), [collector](../../scripts/coverage.sh), [coverage workflow](../../.github/workflows/coverage.yaml) | Line-coverage floors plus revision-pinned candidate bundle for `G-16` with `G-17` assurance input | Blocking on PR plus `main`; below-threshold fails the job and blocks `G-16`; bundle uploads as `coverage-bundle-<sha>` |
| RustSec audit | [security audit workflow](../../.github/workflows/audit.yaml) and [audit policy](../../.cargo/audit.toml) | Dependency advisory evidence and reviewed advisory exceptions | Configured on `main` and schedule; candidate result and ignored-advisory review required |
| Semgrep | [Semgrep workflow](../../.github/workflows/semgrep.yaml) | Static-analysis evidence for Rust changes | Configured; findings require disposition |
| Dependabot | [Dependabot configuration](../../.github/dependabot.yml) | Dependency and GitHub Actions update intake | Configured; update intake is not vulnerability-response proof |
| Structured `tracing` | Workspace `tracing` dependencies and current component instrumentation | Local diagnostic evidence and basis for and | Partial; shared schema, redaction, completeness, and production export are not proven |
| `cargo-deny` | [`deny.toml`](../../deny.toml), [dependency-policy workflow](../../.github/workflows/deny.yaml), and [dependency policy](dependency-policy.md) | License, advisory, source, and banned-crate policy evidence | Configured on PR, `main`, and weekly schedule; candidate result and exception review required |
| Metrics and OpenTelemetry | ADR-0009 contract; no production metrics or OpenTelemetry SDK/export implementation | Objective readiness signals, SLO queries, traces, dashboards, and alert inputs | Missing and blocking for public beta and production |

 does not add runtime dependencies or a machine-readable gate schema.
Future automation may encode these gates with `serde`, `serde_json`, or `toml`
after the human review contract is stable.

## Baseline Review - 2026-06-11

The initial baseline uses repository state and Linear issue state available on
June 11, 2026. It is a gap assessment, not launch approval.

| Area | Current evidence | Missing evidence | Gate result |
|---|---|---|---|
| Security posture and risk | and are `Done`; ADR-0006 and the threat model exist | Both documents remain `Proposed`; required owner approvals and the assurance case are incomplete | `blocked` |
| Signal architecture | is `Done`; ADR-0009 defines the contract; structured `tracing` exists | ADR-0009 remains `Proposed`; metrics, OpenTelemetry export, durable audit, dashboards, alerts, SLOs, and runbooks are incomplete | `blocked` |
| CI and dependency checks | Formatting, Clippy, nextest, smoke, coverage, benchmark, RustSec, Semgrep, and Dependabot are configured | No candidate evidence bundle, no `cargo-deny`, no defined coverage threshold, and the benchmark job is non-blocking | `blocked` |
| Runtime isolation and resources | Architecture contracts exist |, and are in `Backlog` | `blocked` |
| Credentials and snapshots | ADR-0006 and ADR-0007 define expected behavior | and are in `Backlog`; integrated exclusion, retention, deletion, restore, and fork evidence is absent | `blocked` |
| Side-channel posture | Dedicated tenancy is the documented fallback | assessment is `Proposed`; implementation issues (SC-IMPL-01 through SC-IMPL-08) remain in `Backlog`; shared-host public multi-tenancy is prohibited until they are complete | `blocked` for shared hosts |
| Integrated subsystem readiness | through define report requirements |, and are in `Backlog` | `blocked` |
| Reliability and operations | ADR-0009 defines required signals and actions |, scale validation, and capacity planning are in `Backlog` | `blocked` |
| Assurance and rollout | This model defines readiness gates | and are in `Backlog`; no approval record or rollout decision exists | `blocked` |

**Baseline decision**: no launch stage is approved. Public limited beta and
production are blocked. Private preview is also blocked until one exact,
dedicated-tenancy profile passes every applicable hard-invariant, lifecycle,
cleanup, network, credential, and operational-safety gate.

## Missing-Gate Work List

The current gaps are already represented by existing Linear work:

| Gap | Follow-up |
|---|---|
| Seccomp, capabilities, runtime identities, namespaces, filesystem, devices, sockets, helpers, and cgroups | |
| Cross-boundary and cleanup validation | |
| Credential mediation, revocation, redaction, and snapshot exclusion | |
| Snapshot metadata, encryption, integrity, retention, deletion, restore, and fork evidence | |
| Metrics, logs, traces, durable audit, dashboards, and alerts | |
| Runbooks, SLOs, incident exercises, and dependency-policy evidence | |
| Load, failure, cache, snapshot, capacity, headroom, and cost validation | |
| Control-plane, backend, protocol, network, and image integrated readiness | |
| Shared-host multi-tenant assessment | |
| Assurance case and final rollout checklist | [assurance case](assurance-case.md) plus 67 checklist |

## Readiness Review Procedure

1. Freeze the candidate source revision, artifact digests, configuration, and
   exact deployment profile.
2. Collect the gate records and immutable evidence for that candidate.
3. Mark every gate `pass`, `blocked`, `not_applicable`, or `expired`.
4. Verify disabled capabilities cannot be admitted or enabled through fallback,
   operator override, stale state, or configuration drift.
5. Run at least one adversarial and one independent-failure scenario from each
   applicable threat-model risk tree.
6. Record residual risks, exceptions, compensating controls, owners, expiry,
   and rollback behavior.
7. Obtain subsystem approvals, then independent Security and SRE approval.
8. Record a stage decision: approve, approve with narrower scope, or block.
9. For production, transfer the approved evidence into and execute the
   staged rollout and rollback criteria.

## Approval

This document remains `Proposed` until both owners approve the readiness
semantics, stage thresholds, gate matrix, baseline disposition, and review
procedure:

- Security owner
- SRE owner

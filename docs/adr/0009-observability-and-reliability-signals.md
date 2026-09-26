# ADR-0009: Observability and Reliability Signals

**Status**: Proposed
**Date**: 2026-06-11
**Milestone**: M0 - Telemetry Model ADR
**Depends on**:
[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md),
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md),
[ADR-0005](0005-per-sandbox-networking-model.md)

## Context

PicoCompute operations cross the regional API, policy and quota services,
schedulers, cell controllers, host agents, `sandboxd`, runtime adapters,
guest agents, and image, network, snapshot, and metrics agents. Operators
must be able to answer:

- whether the platform is meeting its reliability objectives
- where a lifecycle operation spent time or failed
- whether a host is safe to receive new work
- whether resource pressure, cleanup drift, or dependency health is reducing
  capacity
- which policy, lease, network, credential, snapshot, image, or operator
  decision affected a sandbox
- whether the telemetry and audit systems themselves are complete and current

Metrics, traces, logs, and audit events serve different purposes. Metrics
provide bounded aggregate behavior. Traces explain one distributed operation.
Logs provide local diagnostic detail. Audit events are durable security and
control evidence. Treating any one signal as a substitute for the others
would either lose operational detail or weaken audit guarantees.

[ADR-0001](0001-control-plane-ownership-lifecycle-state-model.md) requires
atomic lifecycle state and audit writes in the regional metadata store.
[ADR-0002](0002-host-runtime-lifecycle-orchestration.md) makes `host-agent`
the host health reporter and `metrics-agent` the telemetry transport rather
than the health authority.
[ADR-0005](0005-per-sandbox-networking-model.md) requires bounded network
metrics, metadata-only flow logs, durable security-relevant audit events, and
tenant-safe correlation.

The current repository has structured `tracing` calls and a versioned audit
event type, but no complete cross-service telemetry contract. The current
asynchronous PostgreSQL audit sink can also reject an event when its channel
is full. That behavior is acceptable for a prototype but does not satisfy the
production audit guarantee selected here.

This ADR defines signal semantics, identity, cardinality, redaction,
propagation, delivery, dashboards, alerts, and readiness behavior. It does
not select a hosted observability vendor, retention duration, dashboard
product, paging product, Rust crate layout, or final SLO target values.

## Decision

PicoCompute adopts an **OpenTelemetry-first operational telemetry model using
OpenTelemetry APIs, OTLP export, W3C Trace Context, structured JSON logs, and
a separate durable audit plane**.

The operational signals share one versioned PicoCompute semantic convention:

- canonical operation, phase, outcome, and reason values
- common resource identity for service, deployment, region, cell, host, and
  backend
- trace and operation correlation across trusted internal boundaries
- bounded attributes suitable for aggregate metrics and SLO queries
- explicit redaction and tenant-isolation rules

Audit events reuse safe correlation fields and the same outcome taxonomy, but
they are not exported through the best-effort telemetry path. They use
versioned domain schemas, durable outboxes, at-least-once delivery,
event-identity deduplication, and explicit ordering evidence.

OpenTelemetry is an instrumentation and transport contract, not an
authorization source. Trace context, baggage, log attributes, and collector
enrichment never grant access, select a tenant, identify a sandbox for a
mutation, or override typed request fields.

### Signal Roles

| Signal | Primary question | Reliability contract |
|---|---|---|
| Metrics | Is the system healthy and meeting its objectives? | Every admitted operation contributes to bounded counters and latency distributions. Export loss is measured and alertable. |
| Traces | Where did one distributed operation spend time or fail? | Context propagates across trusted boundaries. Sampling may reduce successful traces but never changes operation behavior. |
| Structured logs | What local diagnostic event explains this outcome? | Platform logs use a documented JSON schema and source-side allowlist redaction. Workload logs use a separate pipeline and access policy. |
| Audit events | Who or what made or enforced a security-sensitive or authoritative decision? | Events are versioned, immutable, unsampled, durably enqueued, delivered at least once, and deduplicated by event ID. |
| Validation reports | Does a release or deployment profile have current readiness evidence? | Reports are immutable evidence linked to the exact artifact, profile, environment, and test revision. |
| Dashboards | What is the current service-level and component-level state? | Queries use stable metrics and bounded dimensions, with explicit missing-data behavior. |
| Alerts | Which condition requires automated action or human response? | Every alert maps to an owner, severity, dashboard, and runbook category. |

### Canonical Semantic Taxonomy

The following values are shared by metrics, spans, logs, audit events,
dashboards, validation reports, and alerts. Implementations use stable
lowercase snake-case wire values.

Lifecycle `operation` values are:

- `create`
- `exec`
- `suspend`
- `resume`
- `fork`
- `restore`
- `destroy`

Supporting operation values are:

- `image_prepare`
- `network_setup`
- `snapshot_capture`
- `placement`
- `reconcile`
- `cleanup`

Lifecycle `phase` values are:

- `api_admission`
- `policy`
- `quota`
- `regional_schedule`
- `cell_schedule`
- `host_prepare`
- `image_prepare`
- `network_prepare`
- `runtime_prepare`
- `runtime_start`
- `guest_boot`
- `guest_handshake`
- `ready_commit`
- `snapshot_capture`
- `snapshot_restore`
- `cleanup`
- `metadata_commit`

Terminal `outcome` values are:

- `success`
- `rejected`
- `conflict`
- `timeout`
- `canceled`
- `unavailable`
- `failed`

The initial bounded `reason` values are:

- `none`
- `invalid_request`
- `authentication_failed`
- `policy_denied`
- `quota_exceeded`
- `state_conflict`
- `lease_invalid`
- `lease_expired`
- `lease_revoked`
- `no_capacity`
- `assignment_stale`
- `host_degraded`
- `host_draining`
- `host_unsafe`
- `image_unavailable`
- `image_verification_failed`
- `network_policy_denied`
- `network_setup_failed`
- `runtime_unsupported`
- `runtime_prepare_failed`
- `runtime_start_failed`
- `guest_unreachable`
- `guest_not_ready`
- `protocol_error`
- `snapshot_busy`
- `snapshot_incompatible`
- `snapshot_capture_failed`
- `snapshot_restore_failed`
- `cleanup_incomplete`
- `dependency_unavailable`
- `deadline_exceeded`
- `canceled_by_caller`
- `internal_error`

`success` uses `reason=none`. Every non-success outcome uses one non-`none`
reason. Raw error strings, exception text, paths, commands, tenant values, and
dependency messages never become taxonomy values.

Adding or changing a value requires semantic-convention review because it
changes aggregation, dashboards, alerts, SLO queries, and audit consumers.
Unknown future values are preserved by versioned readers. Older aggregate
queries group them under a query-only `other` bucket without rewriting stored
signals. Producers do not invent service-local synonyms.

### Resource and Correlation Identity

OpenTelemetry resource attributes identify the emitting process and its
deployment:

| Attribute | Requirement |
|---|---|
| `service.name` | Required stable component name |
| `service.version` | Required release version or source revision |
| `service.instance.id` | Required process or instance identity |
| `deployment.environment.name` | Required deployment environment |
| `cloud.region` or `pico.region` | Required region |
| `pico.cell.id` | Required for cell-scoped services |
| `host.id` | Required for host-scoped services |
| `pico.backend` | Required when one backend is selected |

Metric export configuration filters resource attributes before they become
time-series dimensions. In particular, `service.instance.id` and `host.id`
do not become metric dimensions except for the explicitly host-scoped
instruments below.

Operation correlation fields are:

- `trace_id`: W3C trace identity for one distributed diagnostic trace
- `span_id`: one timed operation within a trace
- `request_id`: one transmission attempt
- `operation_id`: stable identity for one logical side-effecting operation
- `tenant_id`: tenant ownership
- `sandbox_id`: sandbox identity
- `policy_decision_id`: authoritative policy decision correlation
- `lease_id`: access-lease correlation

Correlation fields are permitted in protected traces, platform logs, and
audit records according to access policy. They are prohibited as metric
attributes.

Public `traceparent` and `tracestate` values are untrusted input. Services
validate syntax and size before use. A service may start a new internal trace
linked to the incoming context when a trust-boundary policy requires it.
`tracestate` contains no PicoCompute tenant, principal, sandbox, lease, policy, or
credential data and is stripped before calls to untrusted external systems.

PicoCompute does not propagate tenant data through public OpenTelemetry baggage.
Trusted internal RPC schemas carry required operation and authorization
identity in typed, authenticated fields. Trace context provides diagnostic
correlation only.

### Metrics Contract

Metric instruments use OpenTelemetry names and base units. Prometheus or
another backend may translate dots and units during export, but the
instrumentation name and meaning remain stable.

| Instrument | Type | Unit | Required bounded attributes |
|---|---|---|---|
| `pico.api.request.duration` | Histogram | `s` | `operation`, `outcome`, `reason`, `region` |
| `pico.api.request.count` | Counter | `{request}` | `operation`, `outcome`, `reason`, `region` |
| `pico.lifecycle.operation.duration` | Histogram | `s` | `operation`, `outcome`, `reason`, `region`, `backend`, `workload_class` |
| `pico.lifecycle.phase.duration` | Histogram | `s` | `operation`, `phase`, `outcome`, `reason`, `region`, `backend` |
| `pico.lifecycle.operation.count` | Counter | `{operation}` | `operation`, `outcome`, `reason`, `region`, `backend`, `workload_class` |
| `pico.scheduler.placement.duration` | Histogram | `s` | `scheduler_scope`, `outcome`, `reason`, `region`, `cell`, `backend` |
| `pico.scheduler.placement.count` | Counter | `{placement}` | `scheduler_scope`, `outcome`, `reason`, `region`, `cell`, `backend` |
| `pico.host.health` | Gauge | `1` | `health_state`, `reason`, `region`, `cell`, `host_id` |
| `pico.host.cpu.capacity` | Gauge | `{cpu}` | `state`, `region`, `cell`, `host_id` |
| `pico.host.memory.capacity` | Gauge | `By` | `state`, `region`, `cell`, `host_id` |
| `pico.host.sandbox.capacity` | Gauge | `{sandbox}` | `state`, `region`, `cell`, `host_id` |
| `pico.host.resource.utilization` | Gauge | `1` | `resource`, `region`, `cell`, `host_id` |
| `pico.runtime.operation.duration` | Histogram | `s` | `operation`, `outcome`, `reason`, `backend`, `region` |
| `pico.runtime.operation.count` | Counter | `{operation}` | `operation`, `outcome`, `reason`, `backend`, `region` |
| `pico.image.prepare.duration` | Histogram | `s` | `outcome`, `reason`, `backend`, `cache_result`, `region` |
| `pico.image.prepare.count` | Counter | `{operation}` | `outcome`, `reason`, `backend`, `cache_result`, `region` |
| `pico.network.operation.duration` | Histogram | `s` | `operation`, `outcome`, `reason`, `direction`, `region` |
| `pico.network.decision.count` | Counter | `{decision}` | `action`, `reason`, `direction`, `protocol`, `destination_class`, `region` |
| `pico.network.traffic` | Counter | `By` | `action`, `direction`, `protocol`, `region`, `cell` |
| `pico.network.packet.count` | Counter | `{packet}` | `action`, `direction`, `protocol`, `region`, `cell` |
| `pico.snapshot.operation.duration` | Histogram | `s` | `operation`, `profile`, `outcome`, `reason`, `backend`, `cache_result`, `region` |
| `pico.snapshot.operation.count` | Counter | `{operation}` | `operation`, `profile`, `outcome`, `reason`, `backend`, `cache_result`, `region` |
| `pico.cleanup.operation.duration` | Histogram | `s` | `resource_class`, `outcome`, `reason`, `region`, `cell` |
| `pico.cleanup.pending` | Gauge | `{resource}` | `resource_class`, `age_bucket`, `region`, `cell` |
| `pico.reconciliation.finding.count` | Counter | `{finding}` | `resource_class`, `finding`, `action`, `region`, `cell` |
| `pico.audit.delivery.count` | Counter | `{event}` | `event_class`, `outcome`, `reason`, `region`, `producer` |
| `pico.audit.delivery.lag` | Histogram | `s` | `event_class`, `region`, `producer` |
| `pico.audit.outbox.pending` | Gauge | `{event}` | `event_class`, `age_bucket`, `region`, `producer` |
| `pico.telemetry.export.count` | Counter | `{item}` | `signal`, `outcome`, `reason`, `region`, `exporter` |
| `pico.telemetry.export.lag` | Histogram | `s` | `signal`, `region`, `exporter` |
| `pico.telemetry.queue.utilization` | Gauge | `1` | `signal`, `region`, `exporter` |
| `pico.telemetry.cardinality.overflow.count` | Counter | `{measurement}` | `instrument`, `region`, `service.name` |

Histogram boundaries are configured centrally by instrument family and
include the architecture latency targets without creating service-local
bucket sets. SLO queries use histogram distributions, not client-calculated
quantiles.

The allowed metric dimensions are bounded enums or controlled deployment
identities:

- `operation`, `phase`, `outcome`, and `reason`
- `service.name`, `region`, `cell`, and deployment environment
- `backend`, `workload_class`, `health_state`, and `resource`
- `direction`, `protocol`, `destination_class`, and policy `action`
- `profile`, `cache_result`, `resource_class`, `finding`, and `age_bucket`
- `signal`, `producer`, and `exporter`

The following values are never metric attributes:

- tenant, principal, sandbox, request, operation, trace, span, lease, policy
  decision, audit event, snapshot, image digest, or task identifiers
- IP addresses, ports, domain names, paths, commands, arguments, error strings,
  user agents, or arbitrary headers
- user-provided labels, image tags, environment values, or workload content

`host_id` is allowed only on host-scoped health, capacity, pressure, and
diagnostic instruments. Service-level dashboards and SLOs aggregate away
`host_id`. Per-host metrics have bounded fleet retention and are not joined
with tenant identity.

Each instrument has a hard limit of 2,000 active attribute combinations per
collection cycle after attribute filtering. Overflow measurements aggregate
under the OpenTelemetry `otel.metric.overflow=true` attribute and increment
`pico.telemetry.cardinality.overflow.count`. Any overflow is a telemetry
contract violation, creates an alert, and blocks production-readiness approval
until the offending attributes are corrected.

### Trace Contract

W3C Trace Context propagates across:

1. public API admission
2. authentication, policy, and quota decisions
3. regional and cell scheduling
4. host-agent lifecycle admission
5. `sandboxd` orchestration steps
6. image, network, snapshot, and privileged-helper calls
7. runtime adapter calls
8. authenticated host/guest protocol calls
9. authoritative metadata commit and audit enqueue

Root span names use `pico.<operation>`. Internal span names use the
component and phase, such as `scheduler.regional_schedule`,
`host.image_prepare`, `runtime.runtime_start`, and
`guest.guest_handshake`.

Every span records:

- canonical `operation`, `phase`, `outcome`, and `reason`
- safe resource attributes
- `operation_id` and `sandbox_id` only in the protected trace store
- deadlines and retry attempt number as bounded numeric attributes
- selected backend and lifecycle state when known

Span status is `OK` only for `outcome=success`. Rejections, conflicts, and
cancellations retain their typed outcome and reason without being rewritten
as internal failures. Exception messages, stack traces, command text, raw
protocol payloads, and guest output are not recorded by default.

Retries remain part of the logical operation. Synchronous retries are child
spans under the operation. Work resumed asynchronously after the initiating
request uses a span link to the prior trace and preserves `operation_id` in
the trusted request schema. Batch and reconciliation work uses span links
rather than inventing a false single parent.

Every admitted lifecycle operation creates or continues a recording internal
trace regardless of an untrusted caller's sampled flag. In-scope lifecycle
roots use a parent-based always-on recording policy to a local collector.
Collectors route all spans for one trace to the same tail-sampling decision
point. Tail sampling then retains:

- every failed, rejected, conflict, timeout, canceled, or unavailable
  lifecycle trace
- every trace slower than the operation-specific threshold
- every security-relevant policy, lease, credential, network, image,
  snapshot, or operator trace
- every trace involving `host_unsafe`, host quarantine, cleanup ambiguity,
  audit pipeline failure, or telemetry pipeline failure
- a configurable representative sample of other successful traces

Sampling never applies to audit events. Sampling decisions and dropped-span
counts are telemetry pipeline metrics. Emergency diagnostic sampling changes
are time-bound, authorized, audited, and cannot enable prohibited attributes.

### Structured Log Contract

Platform services emit UTF-8 JSON records compatible with the OpenTelemetry
log data model. Every record contains:

- timestamp and observed timestamp
- severity text and normalized severity number
- event name and stable message template
- `service.name`, `service.version`, and `service.instance.id`
- region, cell, and host identity where applicable
- trace ID and span ID when a span exists
- operation ID, request ID, tenant ID, and sandbox ID when authorized for the
  platform log store
- operation, phase, lifecycle state, backend, outcome, and reason when
  applicable
- component and source location
- `redacted=true` and `redacted_fields` when source-side policy removes data

The coordinator that owns a lifecycle operation emits exactly one
`operation_terminal` record at `ERROR` for a terminal non-success outcome.
The record includes the typed outcome, reason, owner, and correlation IDs.
Subordinate components may emit diagnostic warnings or errors, but they do
not emit duplicate terminal records for the same operation.

Platform logs, guest-agent platform logs, guest console output, and workload
stdout or stderr use separate streams, storage classes, access policies, and
retention controls. Workload output is never promoted into platform logs,
span events, metric attributes, or audit details.

Instrumentation uses a source-side allowlist. The following data is
prohibited from all operational telemetry and audit payloads:

- credentials, tokens, private keys, signatures, boot secrets, or lease
  bearer material
- commands, arguments, environment names or values, process titles, or shell
  fragments
- request or response bodies, user payloads, file contents, guest output, or
  memory contents
- full URLs, query strings, arbitrary headers, cookies, domain names, or
  unclassified IP addresses
- host-local paths, workspace paths, image registry credentials, or snapshot
  blob locations
- raw dependency errors or debug representations that may include any
  prohibited value

Safe typed reason codes and controlled resource classes replace raw values.
Hashing is not an automatic substitute because small or predictable identity
spaces can be reversed. Collector allowlist, filter, and redaction processors
provide defense in depth, but source-side prevention is mandatory.

Redaction failures, schema failures, and platform/workload stream mixing are
security findings. The pipeline drops the prohibited field or record, emits a
safe redaction-failure metric and audit event when required, and never exports
the unsafe payload for diagnosis.

### Durable Audit Plane

Audit events are security and control records, not logs. They are versioned,
immutable, unsampled domain events with this common envelope:

| Field | Requirement |
|---|---|
| `schema_version` | Required positive integer |
| `event_id` | Required globally unique immutable identity |
| `event_kind` | Required bounded event taxonomy |
| `hlc_timestamp` | Required causal ordering evidence |
| `recorded_at` | Required UTC wall-clock display time |
| `producer` | Required service identity |
| `tenant_id` | Required for tenant-owned decisions |
| `sandbox_id` | Required for sandbox-scoped decisions |
| `operation_id` | Required for side-effecting operations |
| `request_id` | Required when one request attempt initiated the event |
| `trace_id` | Optional diagnostic correlation |
| `principal` | Required when a principal initiated or approved the action |
| `service` | Required committing or enforcing service |
| `action` | Required bounded action |
| `outcome` and `reason` | Required canonical terminal result |
| `policy_decision_id` | Required for policy-governed decisions |
| `lease_id` | Required for lease lifecycle or enforcement events |
| `epoch` and `fencing_token` | Required when stale-writer protection applies |
| `details` | Versioned event-specific typed payload with no raw user content |

Audit event classes include:

- lifecycle transitions
- policy and quota decisions
- scheduler placement and backend selection
- access lease issue, renewal, denial, enforcement, expiry, and revocation
- runtime and host-health outcomes
- network policy, DNS, egress, and port-exposure enforcement
- credential issue, denial, revocation, and delivery mode
- image verification, promotion, rejection, and revocation
- snapshot creation, restore, fork, exclusion, and integrity outcomes
- cleanup ambiguity, quarantine, reconciliation, and operator action
- telemetry redaction, audit delivery, and production-readiness decisions

Delivery guarantees are:

1. Authoritative control-plane state and its audit event are committed in the
   same metadata transaction as required by ADR-0001.
2. A compute-plane security-sensitive or mutating operation durably appends
   its audit event to a local outbox or operation ledger before reporting
   success upstream.
3. Producers retry delivery with bounded exponential backoff and preserve the
   original event ID.
4. Consumers implement idempotent insertion by `event_id`; delivery is
   at-least-once, not exactly-once.
5. HLC timestamps, operation IDs, epochs, fencing tokens, and event-specific
   sequence values preserve causal and per-operation ordering. PicoCompute does
   not claim a global total order across unrelated operations.
6. Exhausted deliveries enter a durable dead-letter state without deleting
   the source outbox record. Dead-letter state is queryable, alertable, and
   requires explicit replay or reviewed disposition.
7. Outbox age, backlog, retries, dead letters, duplicates, and end-to-end
   delivery lag are measured.

A full queue, unavailable sink, serialization failure, or delivery gap must
never silently drop an audit event. If the event is required to authorize,
commit, or attest a security-sensitive or authoritative mutation, failure to
durably enqueue it fails the mutation or prevents its success acknowledgement.

Audit degradation affects readiness:

- regional audit commit failure blocks affected authoritative mutations
- host audit outbox unavailability makes the host `degraded` or `unsafe`
  according to the affected operation class
- sustained backlog blocks new security-sensitive mutations before local
  durable capacity is exhausted
- detected loss, corruption, or unexplained sequence gaps are page-level
  security and reliability incidents

 defines concrete storage, retention periods, query APIs, replay tools,
and migration mechanics without weakening these guarantees.

### Production-Readiness Signal Matrix

| Readiness area | Metrics | Traces and logs | Audit evidence | Dashboard and alert requirement |
|---|---|---|---|---|
| API | request count, availability, and latency | admission trace and terminal log | authentication and policy decision where applicable | availability, latency, and multi-window burn alerts |
| Lifecycle | operation and phase count, success, and latency | complete create, exec, suspend, resume, fork, restore, and destroy traces | lifecycle transitions and terminal operation events | latency, failure, timeout, and stuck-operation views |
| Scheduling | placement count, latency, rejection, and capacity | regional and cell placement spans | placement, backend selection, and rejection decision | no-capacity, stale-capacity, and placement-failure alerts |
| Host health | health state, capacity, pressure, and heartbeat freshness | host health transition logs and diagnostic traces | disable, drain, quarantine, and operator action | host degradation, drain, quarantine, and stale heartbeat alerts |
| Runtime and guest | prepare, boot, handshake, exec, and runtime outcomes | adapter and guest protocol spans with one terminal owner log | runtime outcome and protocol security events | backend and guest non-ready views |
| Networking | setup latency, policy decisions, traffic, DNS, lease, and cleanup outcomes | network setup and enforcement traces, metadata-only flow logs | policy, lease, exposure, and enforcement events | setup, protected-destination, DNS, and cleanup alerts |
| Images | prepare latency, cache result, verification, and rejection | image prepare and verification spans | image verification, promotion, rejection, and revocation | cache, verification, stale evidence, and supply-chain alerts |
| Snapshots | capture, restore, fork, cache, compatibility, and exclusion outcomes | snapshot lifecycle traces and typed failure logs | creation, restore, fork, integrity, and exclusion events | restore SLO, incompatibility, exclusion, and integrity alerts |
| Cleanup and reconciliation | pending age, cleanup latency, orphan, drift, and ambiguity counts | reconciliation traces and resource-class logs | cleanup ambiguity, quarantine, and reviewed disposition | backlog, drift, orphan, and quarantine alerts |
| Security | bounded deny and revocation counts | protected traces and redacted platform logs | policy, lease, credential, network, image, snapshot, and operator events | security-event and evidence-gap alerts |
| Audit pipeline | enqueue, delivery, retry, lag, backlog, dead-letter, and sequence-gap signals | pipeline diagnostic traces and safe logs | audit delivery and disposition events | backlog, lag, dead-letter, loss, and corruption pages |
| Telemetry pipeline | export success, lag, queue use, sampling, redaction, and cardinality overflow | exporter and collector diagnostics | redaction-policy and readiness decisions | missing data, exporter failure, overflow, and freshness alerts |

No readiness area may rely on logs alone. A production gate identifies the
metric or durable event used for objective evaluation and links traces and
logs for diagnosis.

### Dashboards and SLO Categories

Service-level dashboards aggregate by these bounded dimensions:

- deployment environment and region
- cell for capacity and failure-domain views
- service and component
- operation, phase, outcome, and reason
- backend and workload class
- host health state and resource class
- network direction, action, protocol, and destination class
- snapshot profile and cache result

Dashboards do not expose tenant or sandbox dimensions. Authorized diagnostic
tools pivot from a trace or audit event to protected tenant and sandbox
records instead of adding those identities to aggregate metrics.

Required dashboard groups are:

- control-plane API and admission
- lifecycle operations and phase latency
- scheduling and regional capacity
- host health, pressure, drain, and quarantine
- runtime backend and guest readiness
- image preparation and cache behavior
- networking, DNS, egress, and exposure
- snapshot, resume, restore, and fork
- cleanup and reconciliation
- audit and telemetry pipeline health
- SLO status and error-budget burn

 sets numeric objectives and error-budget policy in
[slo-error-budget-policy](../observability/slo-error-budget-policy.md) for:

- control-plane availability and latency
- lifecycle operation success and latency
- host control-loop and reconciliation freshness
- snapshot restore success and latency
- audit event durable-delivery health
- required telemetry freshness

### Alert Categories and Operational Action

Alerts use stable categories rather than service-local names:

| Category | Typical action |
|---|---|
| `slo_burn` | Page or ticket according to multi-window burn severity |
| `regional_lifecycle_failure` | Page the owning control-plane or runtime team |
| `capacity_exhaustion` | Page or ticket, apply admission or rollout controls |
| `host_degradation` | Stop placement or drain according to health state |
| `host_quarantine` | Quarantine immediately and page |
| `cleanup_drift` | Stop unsafe deletion, drain or quarantine, investigate receipts |
| `resource_pressure` | Stop placement, shed load, or drain before isolation is at risk |
| `audit_delivery_failure` | Block affected mutations and page SRE and Security |
| `audit_integrity_gap` | Treat as a security incident and page immediately |
| `telemetry_delivery_failure` | Page when required readiness signals are stale or missing |
| `cardinality_overflow` | Stop rollout of the offending instrumentation and remediate |
| `security_event` | Apply the event-specific security response and preserve evidence |

Every page-capable alert includes region, cell or host when applicable,
category, bounded reason, first-seen and last-seen time, dashboard link,
runbook category, and owning team. Alerts never include raw tenant content,
credentials, commands, or workload output.

### Ownership and Enforcement Boundaries

| Concern | Authority |
|---|---|
| PicoCompute semantic convention and schema versions | Observability owners with SRE and Security review |
| Lifecycle operation, phase, outcome, and reason taxonomy | Control-plane, Runtime, and Observability owners |
| Instrumentation at a component boundary | Owning component team |
| Metric views, cardinality filters, and histogram configuration | Observability owners |
| Trace propagation and sampling policy | Observability owners with Security review |
| Source log fields and redaction | Owning component team under Security policy |
| Collector transformation and export | `metrics-agent` and observability platform |
| Host health decision | `host-agent`; telemetry transport cannot override it |
| Authoritative audit event creation | Service that commits or enforces the decision |
| Audit schema, delivery, retention, and query policy | Control Plane, SRE, and Security owners |
| SLO targets and error-budget policy | SRE and service owners through |
| Alert severity and runbook action | SRE and owning service team |

Instrumentation failure does not change the functional result of a read-only
operation unless a production gate explicitly requires the signal. Audit
failure does change the admissibility or acknowledgement of authoritative and
security-sensitive mutations as defined above.

## Consequences

### Positive

- One semantic convention supports metrics, traces, logs, audit correlation,
  dashboards, alerts, validation, and SLO queries.
- OpenTelemetry and OTLP avoid binding instrumentation to one storage vendor.
- Metric labels remain tenant-safe and operationally bounded.
- Tail sampling preserves important traces without requiring every successful
  trace to be stored.
- Source-side redaction prevents collectors from becoming the first security
  boundary.
- Durable audit delivery remains independent of telemetry sampling, queue
  pressure, and exporter availability.
- Audit and telemetry health become observable production dependencies rather
  than hidden support systems.
- Production readiness maps each claim to objective aggregate signals and
  durable evidence.

### Negative

- Every component must adopt and maintain shared schemas and taxonomy.
- Tail sampling requires collector capacity and delayed sampling decisions.
- Protected trace, log, and audit stores require separate access controls and
  retention policies.
- The 2,000-series instrument limit requires active cardinality review and
  may aggregate overflow during instrumentation defects.
- Durable compute-plane audit outboxes add local storage, replay, migration,
  and backpressure complexity.
- Security-sensitive mutations can become unavailable when their audit
  evidence cannot be durably recorded.
- Cross-signal schema changes require coordinated rollout and compatibility
  testing.

## Rejected Alternatives

### Metrics-First with Sampled Traces

Metrics would be the primary contract and traces would be added only around
selected slow paths.

**Rejected**: Aggregate metrics are necessary for SLOs but do not preserve the
causal boundaries needed to diagnose lifecycle operations spanning the
control plane, host, runtime, and guest. Adding traces later would allow
operation, phase, and reason taxonomies to diverge.

### Event-Log-First with Derived Metrics

Every operational occurrence would be written as an event, and metrics and
traces would be derived from the event stream.

**Rejected**: High-volume operational events are expensive to retain and do
not naturally provide metric aggregation or distributed span semantics.
Making one event pipeline authoritative for both diagnostics and security
evidence also couples production audit durability to observability volume.

### Vendor-Specific Instrumentation

Services would use one observability vendor's SDK, propagation format,
queries, and agent-specific attributes.

**Rejected**: The vendor would become part of every component interface and
make instrumentation, migration, testing, and multi-environment operation
dependent on one backend. OpenTelemetry provides the required neutral API and
transport contract while allowing backend-specific storage and query layers.

### One Pipeline for Logs and Audit Events

Audit events would be emitted as structured logs and retained by the log
backend.

**Rejected**: Log sampling, queue overflow, mutable processing, retention, and
best-effort export do not satisfy authoritative audit ordering, durability,
deduplication, and mutation-gating requirements. Audit records remain a
separate durable domain-event plane.

### High-Cardinality Metric Labels for Direct Debugging

Tenant, sandbox, operation, trace, lease, host, or policy-decision IDs would
be attached to metrics to simplify drill-down.

**Rejected**: Unbounded identities multiply time series, expose tenant
correlation in aggregate stores, and make system cost depend on workload
identity. Metrics use bounded dimensions; traces, logs, and audit records
provide protected correlation.

## Follow-Up Implementation Issues

| Issue | Relationship to this ADR |
|---|---|
| | Implement lifecycle metrics, histogram views, outcome taxonomy, and initial trace propagation |
| | Implement structured platform logs, source-side redaction, stream separation, and terminal operation records |
| | Implement complete distributed tracing, W3C propagation, span links, and sampling policy |
| | Replace best-effort audit delivery with durable outboxes, query storage, retries, dead letters, integrity checks, and retention |
| | Build the required service-level and component-level dashboard groups |
| | Implement host degradation, drain, quarantine, pressure, cleanup, audit, and telemetry alert behavior |
| | Link every alert category and failure mode to operational runbooks in `docs/runbooks/` |
| | Set SLO targets, error-budget policy, burn alerts, and rollout gates in [slo-error-budget-policy](../observability/slo-error-budget-policy.md) |

## References

- [OpenTelemetry specification overview](https://opentelemetry.io/docs/specs/otel/overview)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv)
- [OpenTelemetry metrics SDK cardinality limits](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#cardinality-limits)
- [OpenTelemetry logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model)
- [OpenTelemetry trace SDK sampling](https://opentelemetry.io/docs/specs/otel/trace/sdk/#sampling)
- [OpenTelemetry guidance for sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data)
- [OpenTelemetry Protocol specification](https://opentelemetry.io/docs/specs/otlp)
- [W3C Trace Context](https://www.w3.org/TR/trace-context)
- [Prometheus metric and label naming](https://prometheus.io/docs/practices/naming)

## Required Review

The ADR remains `Proposed` until both roles approve
the telemetry model, tenant-safety rules, audit guarantees, and readiness
mapping:

- SRE owner
- Security owner

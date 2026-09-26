# Distributed Tracing for Lifecycle Operations

## Overview

Lifecycle operations cross API, host-agent, runtime adapter, and guest-agent
boundaries. Distributed tracing correlates spans across these boundaries so
operators can debug latency and outcomes end-to-end.

## Architecture

PicoCompute uses the OpenTelemetry protocol with OTLP gRPC export. The
`pico-telemetry` crate manages trace initialization, export, and span
context propagation.

```
Public API (traceparent in) -> host-agent -> runtime adapter -> guest-agent
                        |                   |
                        v                   v
                   Tower TraceLayer    GuestConnection injects
                   extracts W3C        TraceContext into
                   traceparent         RequestContext proto
```

## Trace boundaries

| Boundary | Propagation | Component |
|----------|------------|-----------|
| Public API request | W3C `traceparent` header extraction | `pico-api` middleware |
| Tenant policy / quota | Span created in `PolicyEnforcingAgent` | `pico-api` |
| Host-agent HTTP RPC | W3C `traceparent` extraction layer | `pico-host-agent` binary |
| Host-agent lifecycle | `#[tracing::instrument]` spans | `pico-host-agent` lib |
| Runtime adapter | `#[tracing::instrument]` on backend entry points | `pico-runtime` |
| Guest-agent protocol | `TraceContext` in `RequestContext` proto | `pico-guest-protocol` |
| Image preparation | `#[tracing::instrument]` on `RootfsBuilder::build` | `pico-image` |
| Network setup/teardown | `#[tracing::instrument]` on `NetworkAgent::provision` | `pico-network-agent` |
| Snapshot / restore | `#[tracing::instrument]` on `restore_from_snapshot` | `pico-host-agent` |
| Scheduler | Placeholder span on adapter selection | `pico-host-agent` |

## Span attributes

Only **bounded, tenant-safe attributes** are recorded on lifecycle spans:

- `sandbox_id` - sandbox identity
- `operation_id` - stable operation identity
- `tenant_id` - tenant identity
- `backend` - runtime class (firecracker, qemu, gvisor)
- `lifecycle_operation` - create, boot, exec, suspend, resume, fork, destroy, restore
- `outcome` - success, timeout, cancelled, policy_rejected, quota_rejected, placement_failed, runtime_failed, internal_error
- `reason` - typed reason code string
- `host_id` - compute host identity
- `cell_id` - cell identity
- `region` - cloud region

**Never** recorded: commands, arguments, environment variables, file paths,
stdout, stderr, credentials, or any tenant-supplied data. The attribute
allowlist is enforced via `pico_telemetry::trace_context::record_bounded_attr`
which panics in debug builds if an unbounded key is used.

## Outcome to span status mapping

Terminal lifecycle outcomes are mapped to OpenTelemetry span status:

| LifecycleOutcome | Span Status |
|-----------------|-------------|
| `Success` | `Status::Ok` |
| `InternalError` | `Status::Error("internal_error")` |
| `RuntimeFailed` | `Status::Error("runtime_failed")` |
| `Timeout` | `Status::Error("timeout")` |
| `Cancelled` | `Status::Error("cancelled")` |
| `PolicyRejected` | `Status::Error("policy_rejected")` |
| `QuotaRejected` | `Status::Error("quota_rejected")` |
| `PlacementFailed` | `Status::Error("placement_failed")` |

## Trace views

The following per-operation trace views are available in any OpenTelemetry
backend (Jaeger, Grafana Tempo, Datadog, etc.):

- **create** - spans from API `POST /v1/sandboxes` through prepare, boot, handshake, and ready
- **exec** - spans from API `POST /v1/sandboxes/{id}/exec` through operational guest protocol
- **suspend** - spans for the suspend flow including quiesce and backend checkpoint
- **resume** - spans for the resume flow including restore notification
- **fork** - spans for forking an existing sandbox (stub)
- **destroy** - spans for sandbox teardown including cgroup cleanup
- **restore** - spans for snapshot-based restore

## Sampling policy

The sampling rate is configured via `TracingSettings.sample_rate` (0.0-1.0),
backend by `Sampler::TraceIdRatioBased`. Default: **1.0** (always sample) when
OTLP export is enabled, **0.0** (never sample) when no endpoint is configured.

Sampling decisions are made at span creation time and propagate through the
`traceparent` header and `TraceContext` proto field so that all downstream
spans respect the same sampling decision.

## Trace context propagation contract

Components that participate in distributed tracing follow this contract:

1. **Incoming HTTP requests**: Extract `traceparent` and `tracestate` headers.
   If present, create the request span as a child of the incoming context.
2. **Internal RPC**: The operational guest protocol carries a `TraceContext`
   message inside the `RequestContext` protobuf. The caller injects the
   current span's trace ID, span ID, and flags; the callee extracts them.
3. **Log correlation**: Structured log records include `trace_id` and
   `span_id` fields when a span is active.

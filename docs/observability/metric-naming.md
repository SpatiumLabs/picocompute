# Metric naming and dashboard mapping

Which metric name each backend reads, and where the series is published from.
This exists because a single `grep` over the repository cannot answer either
question: names are declared as `const`s next to their recorder, and dashboards
reference the *Prometheus* spelling rather than the OpenTelemetry one.

## Adding a metric, or a label

Three rules, all enforced by the compiler rather than by review.

**Identity labels come from `Labels` only.** `Counter::inc`, `Gauge::set`, and
`Histogram::record` take a `&Labels`, not an attribute slice, so a call site
cannot hand-build a `sandbox_id`. Inside `Labels`, the identity keys
(`tenant_id`, `sandbox_id`) are `&'static str` and every other key is a
`PlainKey`; `Labels::with` accepts only `PlainKey`, so passing an identity key
there is a type error. That is what makes the redaction policy in
`pico-telemetry` the only path to an identity attribute.

**Caller-supplied label values go through an `Allowlist`.** `Allowlist::new` is
a `const fn` that requires the set's fallback to be a member of the set, so a
set missing its own `unknown` is a build error. Declare it as a `const` to get
the check at compile time:

```rust
const CACHE_RESULTS: Allowlist =
    Allowlist::new(&["hit", "miss", "evicted", "unknown"], "unknown");

// Bounded: an image digest passed in comes out as "unknown".
let label = CACHE_RESULTS.bound(cache_result);
```

`bound()` returns either the input or the set's own fallback, never anything
else. There is no release-mode relaxation of this.

**New attribute keys go in the `attr` module**, not inline at the call site, so
the set of label names a crate can emit is readable in one place. `PlainKey::new`
is `pub(crate)` for that reason.

The two identity policies are distinct, so pick the constructor that matches the
series rather than the one that seems convenient:

- `Labels::host()` - a host-level aggregate, never attributed.
- `Labels::tenant(tenant_id)` - gains `tenant_id` only under
  `shared_host_metric_redaction`, and never emits `sandbox_id`. Used by
  host-agent lifecycle series.
- `Labels::sandbox(sandbox_id, tenant_id)` - `sandbox_id` normally, substituted
  by `tenant_id` under redaction. Used by sandbox-scoped network and
  observability series.

A panel that selects on `sandbox_id` silently empties once redaction is enabled.
Panels for sandbox-scoped series must aggregate without a label filter.


## Name translation

Metrics are exported over OTLP gRPC. The collector translates the OTel name to
the Prometheus spelling by replacing `.` with `_`, and adds the metric-type
suffix for histograms and counters.

| OpenTelemetry name | Prometheus name |
| --- | --- |
| `pico.host.cpu.capacity` | `pico_host_cpu_capacity` |
| `network.interface.rx_bytes` | `network_interface_rx_bytes` |
| `pico_create_events_total` | `pico_create_events_total` (unchanged) |
| `pico_image_prepare_latency_seconds` | `pico_image_prepare_latency_seconds_bucket` (histogram) |

Two naming styles are in use, and both are deliberate:

- `pico_`-prefixed, for control-plane and host lifecycle series owned by
  `pico-host-agent` and `pico-core`. Long-established; the dashboards and
  recording rules were written against these names.
- `network.`-dotted, for series owned by `pico-network-agent`, following the
  OTel convention from ADR-0009. Translated to `network_` in Prometheus.

Do not "normalize" one style to the other. Renaming a series breaks every
dashboard panel and alert rule that reads it, and there is no dual-write here.

## Series map

`crate` is the recording crate. "dash" is the Grafana dashboard file in `o11y/`;
"rule" means `o11y/rules/pico-recording-rules.yaml`.

### Host lifecycle and capacity (`pico-host-agent`)

| Prometheus name | Type | dash | rule |
| --- | --- | --- | --- |
| `pico_create_events_total` | counter | control-plane, lifecycle-operations | yes |
| `pico_create_latency_seconds` | histogram | control-plane | - |
| `pico_prepare_events_total` | counter | image-cache, lifecycle-operations | yes |
| `pico_prepare_latency_seconds` | histogram | image-cache, lifecycle-operations | - |
| `pico_image_prepare_latency_seconds` | histogram | image-cache | - |
| `pico_boot_events_total` | counter | lifecycle-operations | yes |
| `pico_boot_latency_seconds` | histogram | lifecycle-operations | - |
| `pico_destroy_events_total` | counter | lifecycle-operations | yes |
| `pico_destroy_latency_seconds` | histogram | lifecycle-operations | - |
| `pico_fork_events_total` | counter | lifecycle-operations, snapshot-fork | yes |
| `pico_fork_latency_seconds` | histogram | lifecycle-operations, snapshot-fork | - |
| `pico_exec_events_total` | counter | lifecycle-operations | yes |
| `pico_exec_duration_seconds` | histogram | lifecycle-operations, scheduling-capacity | - |
| `pico_exec_output_bytes` | histogram | lifecycle-operations | - |
| `pico_quiesce_events_total` | counter | lifecycle-operations | yes |
| `pico_quiesce_duration_seconds` | histogram | runtime-backend | - |
| `pico_resume_notify_events_total` | counter | runtime-backend | - |
| `pico_resume_notify_duration_seconds` | histogram | runtime-backend | - |
| `pico_suspend_events_total` | counter | - | yes |
| `pico_suspend_latency_seconds` | histogram | runtime-backend | - |
| `pico_resume_events_total` | counter | snapshot-fork | yes |
| `pico_resume_latency_seconds` | histogram | runtime-backend, snapshot-fork | - |
| `pico_restore_events_total` | counter | snapshot-fork | yes |
| `pico_restore_latency_seconds` | histogram | snapshot-fork | - |
| `pico_host_sandbox_count` | gauge | host-health, scheduling-capacity | - |
| `pico_host_draining` | gauge | host-health | - |
| `pico_host_cpu_capacity` | gauge | - | - |
| `pico_host_memory_capacity` | gauge | - | - |
| `pico_host_sandbox_capacity` | gauge | - | - |
| `pico_host_resource_utilization` | gauge | - | - |
| `pico_host_health` | gauge | - | - |
| `pico_network_health_state` | gauge | runtime-backend | - |
| `pico_credential_issued_total` | counter | control-plane | yes |
| `pico_credential_denied_total` | counter | control-plane | yes |
| `pico_credential_refreshed_total` | counter | control-plane | yes |
| `pico_credential_revoked_total` | counter | control-plane | yes |
| `network_port_forward_endpoints_active` | gauge | - | - |
| `network_port_forward_connections_active` | gauge | - | - |
| `network_port_forward_expose_total` | counter | - | - |
| `network_port_forward_revoke_total` | counter | - | - |
| `network_port_forward_expired_total` | counter | - | - |
| `network_port_forward_denied_total` | counter | - | - |

### Cgroup pressure (`pico-host-agent`)

All host-level aggregates with no identity attribute. Fed by the periodic
`memory.events` / `cpu.stat` poller, which sums deltas across all sandboxes.

| Prometheus name | Type | dash | rule |
| --- | --- | --- | --- |
| `pico_cgroup_oom_events_total` | counter | host-health | yes |
| `pico_cgroup_memory_high_events_total` | counter | host-health | yes |
| `pico_cgroup_cpu_throttled_total` | counter | host-health | yes |
| `pico_cgroup_memory_pressure` | gauge | host-health, scheduling-capacity | - |
| `pico_cgroup_memory_pressure_read_errors_total` | counter | host-health | - |
| `pico_cgroup_setup_errors_total` | counter | host-health | yes |

`pico_cgroup_setup_errors_total` is registered but has no emitting call site,
so its panel reads a permanent zero. It is kept registered because the
`host-health` dashboard references the name; removing it would break the query
rather than fix the panel. Either wire up a caller reporting a host-aggregated
count, or drop the panel and the name together.

### Placement, GC, and CPU receipts (`pico-core`)

| Prometheus name | Type | dash | rule |
| --- | --- | --- | --- |
| `pico_placement_latency_seconds` | histogram | scheduling-capacity | - |
| `pico_placement_hosts_evaluated` | histogram | scheduling-capacity | - |
| `pico_placement_hosts_passed_constraints` | histogram | scheduling-capacity | - |
| `pico_gc_pass_duration_seconds` | histogram | cleanup-reconciliation | - |
| `pico_gc_orphans_detected` | counter | cleanup-reconciliation, scheduling-capacity | yes |
| `pico_gc_resources_removed` | counter | cleanup-reconciliation, scheduling-capacity | yes |
| `pico_gc_review_required` | counter | cleanup-reconciliation | yes |
| `pico_gc_cleanup_failed` | counter | cleanup-reconciliation | yes |
| `pico_cpu_receipts_restored` | counter | - | - |
| `pico_cpu_receipts_skipped` | counter | - | - |

### Snapshot and fork (`pico-core`)

| Prometheus name | Type | dash | rule |
| --- | --- | --- | --- |
| `pico_snapshot_cache_hits` | counter | image-cache, snapshot-fork | yes |
| `pico_snapshot_cache_misses` | counter | image-cache, snapshot-fork | yes |
| `pico_snapshot_eviction_count` | counter | image-cache | yes |
| `pico_snapshot_eviction_bytes` | counter | image-cache | yes |
| `pico_snapshot_gc_passes` | counter | snapshot-fork | - |
| `pico_snapshot_gc_deleted` | counter | snapshot-fork | - |
| `pico_snapshot_gc_bytes_freed` | counter | - | - |
| `pico_snapshot_gc_skipped_ref` | counter | snapshot-fork | - |
| `pico_snapshot_gc_skipped_retention` | counter | snapshot-fork | - |
| `pico_snapshot_gc_candidates` | gauge | snapshot-fork | - |
| `pico_snapshot_ref_registered` | counter | image-cache | - |
| `pico_snapshot_ref_deregistered` | counter | image-cache | - |
| `pico_fork_workspace_started` | counter | snapshot-fork | - |
| `pico_fork_workspace_completed` | counter | snapshot-fork | - |
| `pico_fork_workspace_failed` | counter | snapshot-fork | - |
| `pico_fork_shared_bytes` | gauge | snapshot-fork | - |
| `pico_fork_private_bytes` | gauge | snapshot-fork | - |

### Audit pipeline (`pico-core`)

| Prometheus name | Type | dash | rule |
| --- | --- | --- | --- |
| `pico_audit_delivery_count` | counter | audit-telemetry | yes |
| `pico_audit_delivery_lag` | histogram | audit-telemetry | yes |
| `pico_audit_outbox_pending` | gauge | audit-telemetry | - |

### Quarantine (`pico-core`)

| Prometheus name | Type | dash | rule |
| --- | --- | --- | --- |
| `pico_quarantine_alerts_fired_total` | counter | - | yes |
| `pico_quarantine_alerts_resolved_total` | counter | - | yes |
| `pico_quarantine_alerts_active` | gauge | scheduling-capacity | - |
| `pico_quarantine_hosts_quarantined` | gauge | scheduling-capacity | - |

### Networking (`pico-network-agent`)

Sandbox-scoped series carry `sandbox_id` on a dedicated host and `tenant_id` on
a shared host. Panels that aggregate with `sum(...)` or `rate(...)` without a
label filter work under both policies; a panel that selects on `sandbox_id`
silently empties once redaction is enabled.

| Prometheus name | Scope | dash |
| --- | --- | --- |
| `network_setup_started` / `_completed` / `_not_completed` | host | networking |
| `network_setup_duration_seconds` | host | networking |
| `network_objects_count` | host | - |
| `network_cleanup_removed` / `_absent` / `_completed` | host | networking |
| `network_rollback_completed` | host | - |
| `network_egress_allowed` / `_denied` | host | networking |
| `network_egress_setup_completed` / `_cleanup_completed` | host | - |
| `network_nat_setup_completed` | host | - |
| `network_nat_sessions` | sandbox | networking |
| `network_nat_active_entries` | sandbox | - |
| `network_bandwidth_limit_configured` | sandbox | networking |
| `network_bandwidth_setup_completed` / `_cleanup_completed` | host | - |
| `network_interface_rx_bytes` / `_tx_bytes` | sandbox | networking |
| `network_interface_rx_packets` / `_tx_packets` | sandbox | networking |
| `network_interface_allocation_succeeded` / `_incomplete` | host | - |
| `network_ratelimit_bandwidth_drops` | sandbox | - |
| `network_ratelimit_pps_drops` | sandbox | - |
| `network_ratelimit_connection_drops` | sandbox | - |
| `network_ratelimit_connection_rate_drops` | sandbox | - |
| `network_ratelimit_nat_drops` | sandbox | - |
| `network_ratelimit_active_connections` | sandbox | - |
| `network_ratelimit_bandwidth_limit_configured` | sandbox | - |
| `network_flow_egress_bytes` / `_egress_packets` | sandbox | - |
| `network_flow_tcp_syn_sent` / `_established` / `_fin_wait` / `_reset` / `_total` | sandbox | - |
| `network_flow_sampled_connections` / `_bytes` / `_duration_ms` | sandbox | - |
| `network_reconciliation_passes` | host | cleanup-reconciliation |
| `network_reconciliation_stale_objects` | host | cleanup-reconciliation |
| `network_reconciliation_cleaned` | host | cleanup-reconciliation |
| `network_reconciliation_review_required` | host | cleanup-reconciliation |
| `network_reconciliation_cleanup_failed` | host | cleanup-reconciliation |
| `network_reconciliation_health_state` | host | - |
| `network_suspend_completed` / `_duration_seconds` / `_connections_dropped` | host | networking |
| `network_resume_completed` / `_failed` / `_duration_seconds` | host | networking |
| `network_resume_policy_epoch_rejected` | host | - |
| `network_fork_completed` / `_failed` / `_duration_seconds` | host | networking |
| `network_fork_port_inheritance_blocked` | host | networking |

### DNS (`pico-network-agent`)

Host-scoped. The `domain` label carries the suffix class (`.com.example`), never
the queried name, and `reason` / `action` / `rcode` are closed allowlists that
normalize unrecognized input to `unknown`.

| Prometheus name | dash |
| --- | --- |
| `network_dns_queries_total` | dns |
| `network_dns_allowed` / `_denied` / `_failed` | dns |
| `network_dns_cache_hits` / `_cache_misses` | dns |
| `network_dns_policy_actions` | dns |
| `network_dns_query_domain` | dns |
| `network_dns_response_code` | dns |
| `network_dns_resolution_duration_seconds` | dns |
| `network_dns_registered_sandboxes` | dns |

### Observability backend (`pico-observability`)

| Prometheus name | Scope |
| --- | --- |
| `pico_ebpf_observability_enabled` | host |
| `pico_cpu_profile_available` | host |
| `pico_cpu_samples_total` | host |
| `pico_syscall_latency_seconds` | sandbox |
| `pico_observability_memory_usage_bytes` | sandbox |
| `pico_observability_memory_swap_bytes` | sandbox |
| `pico_observability_memory_pressure_avg10` | sandbox |
| `pico_observability_memory_oom_kills_total` | sandbox |
| `pico_observability_io_read_latency_seconds` | host |
| `pico_observability_io_write_latency_seconds` | host |
| `pico_observability_io_operations_total` | host |

## Series with no consumer

Registered and emitted, but not read by any dashboard or recording rule. Listed
so that removing one is a deliberate decision rather than a silent loss.

- `pico_host_cpu_capacity`, `pico_host_memory_capacity`,
  `pico_host_sandbox_capacity`, `pico_host_resource_utilization`,
  `pico_host_health`. The scheduling-capacity dashboard reads
  `pico_host_sandbox_count` instead of the `state`-labelled capacity gauges.
- All six `network_port_forward_*` series.
- `pico_cpu_receipts_restored`, `pico_cpu_receipts_skipped`.
- `pico_snapshot_gc_bytes_freed`.
- `network_nat_sessions` is read by networking, but `network_nat_active_entries`
  and the rate-limit and flow-telemetry series are not read by any panel.
- `pico_suspend_events_total` is read by a recording rule but by no panel.

## Keeping this file honest

When a metric name, label set, or recorder moves, update the table above in the
same change. The failure mode this guards against is a panel that keeps
rendering because the series still exists but now carries a different label, so
the query silently returns no data.

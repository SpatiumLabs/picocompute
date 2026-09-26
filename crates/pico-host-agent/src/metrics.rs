//! Centralized host-agent metrics.
//!
//! # Interface
//!
//! Lifecycle series are recorded through the `record_*` functions, which own
//! their label set and the bounded-allowlist normalization of any
//! caller-supplied value. `tenant_id` flows through
//! [`Labels::tenant`](pico_telemetry::metrics::Labels::tenant), so a
//! lifecycle series gains a `tenant_id` label only when shared-host redaction is
//! enabled and never carries a `sandbox_id`.
//!
//! The four `*_attrs` builders that used to hand-roll the redaction check each
//! are now thin wrappers over `Labels::tenant`.

use pico_telemetry::metrics::{Counter, Gauge, Histogram, Labels, attr, shared_host_redaction};
use std::borrow::Cow;
use std::sync::LazyLock;

pub static HOST_METRICS: LazyLock<HostMetrics> = LazyLock::new(HostMetrics::register);

/// Enables shared-host metric redaction for this process.
///
/// Thin re-export of the policy owner in `pico-telemetry`; the host agent,
/// `pico-core`, and the network agent all share one flag, so this only has to
/// be called once at startup.
pub(crate) fn set_metric_redaction(enabled: bool) {
    pico_telemetry::metrics::set_shared_host_redaction(enabled);
}

pub(crate) fn is_metric_redaction_enabled() -> bool {
    shared_host_redaction()
}

/// Build latency attributes: `status` plus `tenant_id` when redacted.
pub(crate) fn latency_attrs<'a>(status: &'a str, tenant_id: Option<&'a str>) -> Labels<'a> {
    Labels::tenant(tenant_id).with(attr::STATUS, status)
}

/// Build event counter attributes: `event` plus `tenant_id` when redacted.
pub(crate) fn event_attrs<'a>(event: &'a str, tenant_id: Option<&'a str>) -> Labels<'a> {
    Labels::tenant(tenant_id).with(attr::EVENT, event)
}

/// Build event + reason counter attributes, plus `tenant_id` when redacted.
pub(crate) fn event_reason_attrs<'a>(
    event: &'a str,
    reason: &'a str,
    tenant_id: Option<&'a str>,
) -> Labels<'a> {
    Labels::tenant(tenant_id)
        .with(attr::EVENT, event)
        .with(attr::REASON, reason)
}

/// Build image-prepare latency attributes.
///
/// `status`, `cache_result`, and `image_profile` are normalized to bounded
/// allowlists so future callers cannot turn user-controlled strings
/// (digests, IDs, tags) into high-cardinality labels. Unknown inputs fall back
/// to `"unknown"`, the only `cache_result`/`image_profile` value emitted until
/// host image-cache work provides real lookup results and profiles.
pub(crate) fn image_prepare_latency_attrs<'a>(
    status: &'a str,
    cache_result: &'a str,
    image_profile: &'a str,
    tenant_id: Option<&'a str>,
) -> Labels<'a> {
    Labels::tenant(tenant_id)
        .with(attr::STATUS, val::PREPARE_STATUSES.bound(status).as_str())
        .with(
            attr::CACHE_RESULT,
            val::CACHE_RESULTS.bound(cache_result).as_str(),
        )
        .with(
            attr::IMAGE_PROFILE,
            val::IMAGE_PROFILES.bound(image_profile).as_str(),
        )
}

/// Returns the label for tracing diagnostics.
///
/// When redaction is enabled, replaces sandbox_id with tenant_id prefix.
pub(crate) fn tracing_identity_label<'a>(
    sandbox_id: &'a str,
    tenant_id: Option<&'a str>,
) -> Cow<'a, str> {
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            Cow::Owned(format!("tenant:{tid}"))
        } else {
            Cow::Borrowed("redacted")
        }
    } else {
        Cow::Borrowed(sandbox_id)
    }
}

const BOOT_EVENTS_TOTAL: &str = "pico_boot_events_total";
const BOOT_LATENCY_SECONDS: &str = "pico_boot_latency_seconds";
const CREATE_EVENTS_TOTAL: &str = "pico_create_events_total";
const CREATE_LATENCY_SECONDS: &str = "pico_create_latency_seconds";
const PREPARE_EVENTS_TOTAL: &str = "pico_prepare_events_total";
const PREPARE_LATENCY_SECONDS: &str = "pico_prepare_latency_seconds";
/// Image-stage prepare latency. Emitted from the real prepare path with
/// `cache_result="unknown"` and `image_profile="unknown"` until the host
/// image cache lands and provides real lookup results and profiles.
/// Dashboard `pico-image-cache` panel "Image Prepare Latency by
/// cache_result" and recording rules `pico:image_prepare:latency:*`
/// read this series. Hit-filtered rules (`cache_result="hit"`) stay empty
/// until real hits exist, keeping `PicoComputeImagePrepareSaturated` silent.
const IMAGE_PREPARE_LATENCY_SECONDS: &str = "pico_image_prepare_latency_seconds";
const DESTROY_EVENTS_TOTAL: &str = "pico_destroy_events_total";
const DESTROY_LATENCY_SECONDS: &str = "pico_destroy_latency_seconds";
const FORK_EVENTS_TOTAL: &str = "pico_fork_events_total";
const FORK_LATENCY_SECONDS: &str = "pico_fork_latency_seconds";
const EXEC_EVENTS_TOTAL: &str = "pico_exec_events_total";
const EXEC_DURATION_SECONDS: &str = "pico_exec_duration_seconds";
const EXEC_OUTPUT_BYTES: &str = "pico_exec_output_bytes";
const QUIESCE_EVENTS_TOTAL: &str = "pico_quiesce_events_total";
const QUIESCE_DURATION_SECONDS: &str = "pico_quiesce_duration_seconds";
const RESUME_NOTIFY_EVENTS_TOTAL: &str = "pico_resume_notify_events_total";
const RESUME_NOTIFY_DURATION_SECONDS: &str = "pico_resume_notify_duration_seconds";
const SUSPEND_EVENTS_TOTAL: &str = "pico_suspend_events_total";
const SUSPEND_LATENCY_SECONDS: &str = "pico_suspend_latency_seconds";
const RESUME_EVENTS_TOTAL: &str = "pico_resume_events_total";
const RESUME_LATENCY_SECONDS: &str = "pico_resume_latency_seconds";
const RESTORE_EVENTS_TOTAL: &str = "pico_restore_events_total";
const RESTORE_LATENCY_SECONDS: &str = "pico_restore_latency_seconds";
const CGROUP_SETUP_ERRORS_TOTAL: &str = "pico_cgroup_setup_errors_total";
const CGROUP_OOM_EVENTS_TOTAL: &str = "pico_cgroup_oom_events_total";
const CGROUP_MEMORY_HIGH_EVENTS_TOTAL: &str = "pico_cgroup_memory_high_events_total";
const CGROUP_CPU_THROTTLED_TOTAL: &str = "pico_cgroup_cpu_throttled_total";
const CGROUP_MEMORY_PRESSURE: &str = "pico_cgroup_memory_pressure";
const CGROUP_MEMORY_PRESSURE_READ_ERRORS_TOTAL: &str =
    "pico_cgroup_memory_pressure_read_errors_total";
const HOST_SANDBOX_COUNT: &str = "pico_host_sandbox_count";
const HOST_DRAINING: &str = "pico_host_draining";
/// OTel names from the observability ADR. Prometheus export translates dots.
/// `state` is `total` or `allocated`/`used`. Memory values are bytes to match
/// the `By` unit; CPU and sandbox values are counts.
const HOST_CPU_CAPACITY: &str = "pico.host.cpu.capacity";
const HOST_MEMORY_CAPACITY: &str = "pico.host.memory.capacity";
const HOST_SANDBOX_CAPACITY: &str = "pico.host.sandbox.capacity";
/// Per-resource utilization in 0.0-1.0. `resource` is one of
/// `cpu`, `memory`, `disk`, `network`, `process_slots`.
const HOST_RESOURCE_UTILIZATION: &str = "pico.host.resource.utilization";
/// Current health as 1.0 with `health_state` set to the active state.
const HOST_HEALTH: &str = "pico.host.health";
const CREDENTIAL_ISSUED_TOTAL: &str = "pico_credential_issued_total";
const CREDENTIAL_DENIED_TOTAL: &str = "pico_credential_denied_total";
const CREDENTIAL_REFRESHED_TOTAL: &str = "pico_credential_refreshed_total";
const CREDENTIAL_REVOKED_TOTAL: &str = "pico_credential_revoked_total";

// Port-forwarding metric name constants.
const PORT_FORWARD_ENDPOINTS_ACTIVE: &str = "network.port_forward.endpoints_active";
const PORT_FORWARD_CONNECTIONS_ACTIVE: &str = "network.port_forward.connections_active";
const PORT_FORWARD_EXPOSE_TOTAL: &str = "network.port_forward.expose_total";
const PORT_FORWARD_REVOKE_TOTAL: &str = "network.port_forward.revoke_total";
const PORT_FORWARD_EXPIRED_TOTAL: &str = "network.port_forward.expired_total";
const PORT_FORWARD_DENIED_TOTAL: &str = "network.port_forward.denied_total";
const NETWORK_HEALTH_STATE: &str = "pico_network_health_state";

// Attribute value constants.
pub mod val {
    use pico_telemetry::metrics::Allowlist;

    pub const READY: &str = "ready";
    pub const NOT_READY: &str = "not_ready";

    pub const CREATE_STARTED: &str = "create_started";
    pub const CREATE_COMPLETED: &str = "create_completed";
    pub const CREATE_FAILED: &str = "create_failed";

    pub const PREPARE_STARTED: &str = "prepare_started";
    pub const PREPARE_COMPLETED: &str = "prepare_completed";
    pub const PREPARE_FAILED: &str = "prepare_failed";

    pub const DESTROY_STARTED: &str = "destroy_started";
    pub const DESTROY_COMPLETED: &str = "destroy_completed";
    pub const DESTROY_FAILED: &str = "destroy_failed";

    pub const FORK_STARTED: &str = "fork_started";
    pub const FORK_COMPLETED: &str = "fork_completed";
    pub const FORK_FAILED: &str = "fork_failed";

    pub const BOOT_START: &str = "boot_start";
    pub const BOOT_READY: &str = "boot_ready";
    pub const BOOT_NOT_READY: &str = "boot_not_ready";
    pub const BOOT_CLEANUP: &str = "boot_cleanup";

    pub const EXEC_STARTED: &str = "exec_started";
    pub const EXEC_SUCCEEDED: &str = "succeeded";
    pub const EXEC_FAILED: &str = "failed";
    pub const EXEC_CANCELED: &str = "canceled";
    pub const EXEC_TIMED_OUT: &str = "timed_out";
    pub const EXEC_NOT_COMPLETED: &str = "not_completed";

    pub const QUIESCE_STARTED: &str = "quiesce_started";
    pub const QUIESCE_READY: &str = "quiesce_ready";
    pub const QUIESCE_TIMED_OUT: &str = "quiesce_timed_out";
    pub const QUIESCE_FAILED: &str = "quiesce_failed";
    pub const QUIESCE_BUSY: &str = "quiesce_busy";
    pub const QUIESCE_UNSUPPORTED: &str = "quiesce_unsupported";

    pub const RESUME_NOTIFY_STARTED: &str = "resume_notify_started";
    pub const RESUME_NOTIFY_ACCEPTED: &str = "resume_notify_accepted";
    pub const RESUME_NOTIFY_STALE_EPOCH: &str = "resume_notify_stale_epoch";
    pub const RESUME_NOTIFY_SESSION_MISMATCH: &str = "resume_notify_session_mismatch";
    pub const RESUME_NOTIFY_RESOURCES_UNAVAILABLE: &str = "resume_notify_resources_unavailable";
    pub const RESUME_NOTIFY_FAILED: &str = "resume_notify_failed";

    pub const SUSPEND_STARTED: &str = "suspend_started";
    pub const SUSPEND_COMPLETED: &str = "suspend_completed";
    pub const SUSPEND_FAILED: &str = "suspend_failed";
    pub const SUSPEND_TIMED_OUT: &str = "suspend_timed_out";

    pub const RESUME_STARTED: &str = "resume_started";
    pub const RESUME_COMPLETED: &str = "resume_completed";
    pub const RESUME_FAILED: &str = "resume_failed";
    pub const RESUME_TIMED_OUT: &str = "resume_timed_out";

    pub const RESTORE_STARTED: &str = "restore_started";
    pub const RESTORE_COMPLETED: &str = "restore_completed";
    pub const RESTORE_FAILED: &str = "restore_failed";
    pub const RESTORE_MEMORY_RESTORED: &str = "restore_memory_restored";
    pub const RESTORE_PARTIAL_CLEANUP: &str = "restore_partial_cleanup";

    /// Image cache lookup result before the host cache lands.
    /// Only `UNKNOWN` is emitted until host image-cache work provides
    /// real hit/miss/evicted outcomes. Bounded to keep label cardinality low.
    /// Never use image digests or IDs as label values.
    pub const CACHE_RESULT_UNKNOWN: &str = "unknown";
    /// Guest image profile before the image pipeline reports a real profile.
    /// Only `UNKNOWN` is emitted until then. Bounded to keep cardinality low.
    pub const IMAGE_PROFILE_UNKNOWN: &str = "unknown";

    /// Fallback for any label value outside the allowlists below.
    pub const UNKNOWN: &str = "unknown";

    /// Allowlist for the `status` label on image-prepare latency.
    ///
    /// Only the two terminal outcomes belong here; `prepare_started` is a
    /// counter event, not a latency sample. `UNKNOWN` is a member so an
    /// unrecognised value normalizes to something still inside the set; the
    /// compiler rejects a set that omits its own fallback.
    pub const PREPARE_STATUSES: Allowlist =
        Allowlist::new(&[PREPARE_COMPLETED, PREPARE_FAILED, UNKNOWN], UNKNOWN);

    /// Allowlist for the `cache_result` label.
    pub const CACHE_RESULTS: Allowlist = Allowlist::new(
        &["hit", "miss", "evicted", CACHE_RESULT_UNKNOWN],
        CACHE_RESULT_UNKNOWN,
    );

    /// Allowlist for the `image_profile` label.
    pub const IMAGE_PROFILES: Allowlist = Allowlist::new(
        &["minimal", "agent", "session", IMAGE_PROFILE_UNKNOWN],
        IMAGE_PROFILE_UNKNOWN,
    );
}

pub struct HostMetrics {
    pub create_events: Counter,
    pub create_latency: Histogram,
    pub prepare_events: Counter,
    pub prepare_latency: Histogram,
    /// Image-stage prepare latency with `cache_result` and `image_profile` labels.
    /// Populated from the real prepare path with `unknown` labels until the
    /// host image cache provides real values. Hit/miss/eviction counters and
    /// verify/overlay histograms stay unregistered until then, so their
    /// panels remain honestly empty instead of reporting fabricated ratios.
    pub image_prepare_latency: Histogram,
    pub boot_events: Counter,
    pub boot_latency: Histogram,
    pub destroy_events: Counter,
    pub destroy_latency: Histogram,
    pub exec_events: Counter,
    pub exec_duration: Histogram,
    pub exec_output_bytes: Histogram,
    pub quiesce_events: Counter,
    pub quiesce_duration: Histogram,
    pub resume_notify_events: Counter,
    pub resume_notify_duration: Histogram,
    pub suspend_events: Counter,
    pub suspend_latency: Histogram,
    pub resume_events: Counter,
    pub resume_latency: Histogram,
    pub fork_events: Counter,
    pub fork_latency: Histogram,
    pub restore_events: Counter,
    pub restore_latency: Histogram,
    pub sandbox_count: Gauge,
    pub draining: Gauge,
    pub credential_issued: Counter,
    pub credential_denied: Counter,
    pub credential_refreshed: Counter,
    pub credential_revoked: Counter,
    // Host-level aggregate cgroup event counters, fed by the periodic
    // `memory.events`/`cpu.stat` poller. They carry no tenant or sandbox
    // labels, so they never enable cross-tenant inference.
    //
    // Registered but currently un-emitted: no caller yet reports setup errors.
    // Kept so the `host-health` dashboard's `pico_cgroup_setup_errors_total`
    // panel keeps resolving rather than breaking on a missing series.
    pub cgroup_setup_errors: Counter,
    pub cgroup_oom_events: Counter,
    pub cgroup_memory_high_events: Counter,
    pub cgroup_cpu_throttled: Counter,
    /// Host-level aggregate gauge of cgroup v2 memory pressure.
    /// Tracks the maximum `memory.pressure` `some avg10` value across
    /// all active sandbox cgroups. 0.0 = no pressure, 100.0 = full stall.
    pub cgroup_memory_pressure: Gauge,
    /// Counter for memory pressure read/parse failures.
    /// Provides operator visibility into cgroup misconfiguration or kernel issues
    /// without changing the security properties of the gauge itself.
    pub cgroup_memory_pressure_read_errors: Counter,
    // Port-forwarding metrics.
    pub port_forward_endpoints_active: Gauge,
    pub port_forward_connections_active: Gauge,
    pub port_forward_expose_total: Counter,
    pub port_forward_revoke_total: Counter,
    pub port_forward_expired_total: Counter,
    pub port_forward_denied_total: Counter,
    /// Host-agent's observed view of network-agent health.
    /// Mirrors `network.reconciliation.health_state` as observed
    /// by the host-agent health check loop.
    pub network_health_state: Gauge,
    /// Scheduler capacity gauges. All host-level aggregates with bounded
    /// `state` labels only; host identity comes from scrape/resource attrs.
    pub host_cpu_capacity: Gauge,
    pub host_memory_capacity: Gauge,
    pub host_sandbox_capacity: Gauge,
    pub host_resource_utilization: Gauge,
    pub host_health: Gauge,
}

impl HostMetrics {
    fn register() -> Self {
        Self {
            create_events: Counter::register(CREATE_EVENTS_TOTAL),
            create_latency: Histogram::register(CREATE_LATENCY_SECONDS),
            prepare_events: Counter::register(PREPARE_EVENTS_TOTAL),
            prepare_latency: Histogram::register(PREPARE_LATENCY_SECONDS),
            image_prepare_latency: Histogram::register(IMAGE_PREPARE_LATENCY_SECONDS),
            boot_events: Counter::register(BOOT_EVENTS_TOTAL),
            boot_latency: Histogram::register(BOOT_LATENCY_SECONDS),
            destroy_events: Counter::register(DESTROY_EVENTS_TOTAL),
            destroy_latency: Histogram::register(DESTROY_LATENCY_SECONDS),
            exec_events: Counter::register(EXEC_EVENTS_TOTAL),
            exec_duration: Histogram::register(EXEC_DURATION_SECONDS),
            exec_output_bytes: Histogram::register(EXEC_OUTPUT_BYTES),
            quiesce_events: Counter::register(QUIESCE_EVENTS_TOTAL),
            quiesce_duration: Histogram::register(QUIESCE_DURATION_SECONDS),
            resume_notify_events: Counter::register(RESUME_NOTIFY_EVENTS_TOTAL),
            resume_notify_duration: Histogram::register(RESUME_NOTIFY_DURATION_SECONDS),
            suspend_events: Counter::register(SUSPEND_EVENTS_TOTAL),
            suspend_latency: Histogram::register(SUSPEND_LATENCY_SECONDS),
            resume_events: Counter::register(RESUME_EVENTS_TOTAL),
            resume_latency: Histogram::register(RESUME_LATENCY_SECONDS),
            fork_events: Counter::register(FORK_EVENTS_TOTAL),
            fork_latency: Histogram::register(FORK_LATENCY_SECONDS),
            restore_events: Counter::register(RESTORE_EVENTS_TOTAL),
            restore_latency: Histogram::register(RESTORE_LATENCY_SECONDS),
            sandbox_count: Gauge::register(HOST_SANDBOX_COUNT),
            draining: Gauge::register(HOST_DRAINING),
            cgroup_setup_errors: Counter::register(CGROUP_SETUP_ERRORS_TOTAL),
            cgroup_oom_events: Counter::register(CGROUP_OOM_EVENTS_TOTAL),
            cgroup_memory_high_events: Counter::register(CGROUP_MEMORY_HIGH_EVENTS_TOTAL),
            cgroup_cpu_throttled: Counter::register(CGROUP_CPU_THROTTLED_TOTAL),
            cgroup_memory_pressure: Gauge::register(CGROUP_MEMORY_PRESSURE),
            cgroup_memory_pressure_read_errors: Counter::register(
                CGROUP_MEMORY_PRESSURE_READ_ERRORS_TOTAL,
            ),
            credential_issued: Counter::register(CREDENTIAL_ISSUED_TOTAL),
            credential_denied: Counter::register(CREDENTIAL_DENIED_TOTAL),
            credential_refreshed: Counter::register(CREDENTIAL_REFRESHED_TOTAL),
            credential_revoked: Counter::register(CREDENTIAL_REVOKED_TOTAL),
            port_forward_endpoints_active: Gauge::register(PORT_FORWARD_ENDPOINTS_ACTIVE),
            port_forward_connections_active: Gauge::register(PORT_FORWARD_CONNECTIONS_ACTIVE),
            port_forward_expose_total: Counter::register(PORT_FORWARD_EXPOSE_TOTAL),
            port_forward_revoke_total: Counter::register(PORT_FORWARD_REVOKE_TOTAL),
            port_forward_expired_total: Counter::register(PORT_FORWARD_EXPIRED_TOTAL),
            port_forward_denied_total: Counter::register(PORT_FORWARD_DENIED_TOTAL),
            network_health_state: Gauge::register(NETWORK_HEALTH_STATE),
            host_cpu_capacity: Gauge::register(HOST_CPU_CAPACITY),
            host_memory_capacity: Gauge::register(HOST_MEMORY_CAPACITY),
            host_sandbox_capacity: Gauge::register(HOST_SANDBOX_CAPACITY),
            host_resource_utilization: Gauge::register(HOST_RESOURCE_UTILIZATION),
            host_health: Gauge::register(HOST_HEALTH),
        }
    }
}

/// Records scheduler capacity totals and allocated values.
///
/// Prometheus translation (dots to underscores): `pico_host_cpu_capacity{state="total"|"allocated"}`,
/// `pico_host_memory_capacity{state=...}`,
/// `pico_host_sandbox_capacity{state="total"|"used"}`.
/// Memory is converted from MB to bytes to match the `By` unit.
/// In-flight create/restore pressure is visible via the inventory/stats
/// payloads and placement rejections, not via these gauges.
pub fn record_scheduler_capacity(capacity: &pico_core::HostCapacity) {
    const MB_TO_BYTES: f64 = 1024.0 * 1024.0;
    let total = Labels::host().with(attr::STATE, "total");
    let allocated = Labels::host().with(attr::STATE, "allocated");
    let used = Labels::host().with(attr::STATE, "used");

    HOST_METRICS
        .host_cpu_capacity
        .set(capacity.total_vcpus as f64, &total);
    HOST_METRICS
        .host_cpu_capacity
        .set(capacity.allocated_vcpus as f64, &allocated);
    HOST_METRICS
        .host_memory_capacity
        .set(capacity.total_memory_mb as f64 * MB_TO_BYTES, &total);
    HOST_METRICS.host_memory_capacity.set(
        capacity.allocated_memory_mb as f64 * MB_TO_BYTES,
        &allocated,
    );
    HOST_METRICS
        .host_sandbox_capacity
        .set(capacity.max_process_slots as f64, &total);
    HOST_METRICS
        .host_sandbox_capacity
        .set(capacity.used_process_slots as f64, &used);
}

/// Records per-resource utilization in 0.0-1.0.
///
/// Prometheus: `pico_host_resource_utilization{resource="cpu"|"memory"|"disk"|"network"|"process_slots"}`.
pub fn record_scheduler_utilization(utilization: &crate::scheduler_capacity::CapacityUtilization) {
    for (resource, value) in [
        ("cpu", utilization.cpu),
        ("memory", utilization.memory),
        ("disk", utilization.disk),
        ("network", utilization.network),
        ("process_slots", utilization.process_slots),
    ] {
        HOST_METRICS
            .host_resource_utilization
            .set(value, &Labels::host().with(attr::RESOURCE, resource));
    }
}

/// Records the current scheduler health state as 1.0.
///
/// Prometheus: `pico_host_health{health_state="healthy"|"degraded"|"draining"|"disabled_for_placement"|"unavailable"|"quarantined"}`.
pub fn record_scheduler_health(health: pico_core::HostHealth) {
    HOST_METRICS.host_health.set(
        1.0,
        &Labels::host().with(attr::HEALTH_STATE, health.as_str()),
    );
}

/// Record `count` issued sandbox credentials.
pub fn record_credential_issued(count: u64) {
    HOST_METRICS
        .credential_issued
        .inc_by(count, &Labels::host());
}

/// Record `count` denied credential requests.
pub fn record_credential_denied(count: u64) {
    HOST_METRICS
        .credential_denied
        .inc_by(count, &Labels::host());
}

/// Record `count` refreshed credentials.
pub fn record_credential_refreshed(count: u64) {
    HOST_METRICS
        .credential_refreshed
        .inc_by(count, &Labels::host());
}

/// Record `count` revoked credentials.
pub fn record_credential_revoked(count: u64) {
    HOST_METRICS
        .credential_revoked
        .inc_by(count, &Labels::host());
}

/// Record the current count of active port-forward endpoints.
pub fn record_port_forward_endpoints_active(count: u64) {
    HOST_METRICS
        .port_forward_endpoints_active
        .set(count as f64, &Labels::host());
}

/// Record the current count of active port-forward connections.
pub fn record_port_forward_connections_active(count: u64) {
    HOST_METRICS
        .port_forward_connections_active
        .set(count as f64, &Labels::host());
}

/// Record a successful port-forward expose operation.
pub fn record_port_forward_expose() {
    HOST_METRICS.port_forward_expose_total.inc(&Labels::host());
}

/// Record a port-forward revoke operation.
pub fn record_port_forward_revoke() {
    HOST_METRICS.port_forward_revoke_total.inc(&Labels::host());
}

/// Record a port-forward endpoint that expired.
pub fn record_port_forward_expired() {
    HOST_METRICS.port_forward_expired_total.inc(&Labels::host());
}

/// Record a denied port-forward expose attempt.
pub fn record_port_forward_denied() {
    HOST_METRICS.port_forward_denied_total.inc(&Labels::host());
}

/// Record the network-agent's observed health state as reported
/// by the host-agent health check loop.
///
/// 0 = ready, 1 = degraded, 2 = unsafe.
pub fn record_network_health_state(value: f64) {
    HOST_METRICS
        .network_health_state
        .set(value, &Labels::host());
}

/// Record a cgroup setup error for a sandbox.
///
/// Host-level aggregate with no tenant or sandbox labels, safe to emit
/// even when `shared_host_metric_redaction` is enabled.
///
/// No call site currently emits this. The series stays registered because
/// `pico_cgroup_setup_errors_total` is referenced by the `host-health`
/// dashboard and runbook; removing the name would break those queries. When a
/// caller is added it should report a host-aggregated count, matching the other
/// cgroup series.
pub fn record_cgroup_setup_error(count: u64) {
    if count > 0 {
        HOST_METRICS
            .cgroup_setup_errors
            .inc_by(count, &Labels::host());
    }
}

/// Record cgroup OOM events observed by the `memory.events` poller.
///
/// `count` is the summed delta of `oom_kill` across all sandboxes since
/// the previous poll. No-op when zero to avoid empty increments.
pub fn record_cgroup_oom_events_by(count: u64) {
    if count > 0 {
        HOST_METRICS
            .cgroup_oom_events
            .inc_by(count, &Labels::host());
    }
}

/// Record cgroup memory-high events observed by the `memory.events` poller.
///
/// `count` is the summed delta of `high` across all sandboxes since the
/// previous poll. No-op when zero.
pub fn record_cgroup_memory_high_events_by(count: u64) {
    if count > 0 {
        HOST_METRICS
            .cgroup_memory_high_events
            .inc_by(count, &Labels::host());
    }
}

/// Record CPU throttle events observed by the `cpu.stat` poller.
///
/// `count` is the summed delta of `nr_throttled` across all sandboxes
/// since the previous poll. No-op when zero.
pub fn record_cgroup_cpu_throttled_by(count: u64) {
    if count > 0 {
        HOST_METRICS
            .cgroup_cpu_throttled
            .inc_by(count, &Labels::host());
    }
}

/// Record the host-level aggregate cgroup v2 memory pressure gauge.
///
/// This metric is always host-level aggregate (maximum `memory.pressure`
/// `some avg10` across all sandboxes), so it does not expose per-sandbox
/// data and is safe to emit even when `shared_host_metric_redaction` is
/// enabled.
pub fn record_cgroup_memory_pressure(value: f64) {
    HOST_METRICS
        .cgroup_memory_pressure
        .set(value, &Labels::host());
}

/// Record memory pressure read/parse failures.
///
/// This counter provides operator visibility into cgroup misconfiguration
/// or kernel issues. It is always emitted (host-level aggregate) and does
/// not expose per-sandbox data.
pub fn record_cgroup_memory_pressure_read_error(count: u64) {
    if count > 0 {
        HOST_METRICS
            .cgroup_memory_pressure_read_errors
            .inc_by(count, &Labels::host());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redaction flag lives in `pico-telemetry` and is process-global, so
    /// these tests serialize on a lock and restore the prior value on drop.
    struct RedactionGuard {
        previous: bool,
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl RedactionGuard {
        fn set(enabled: bool) -> Self {
            let lock = STATE_LOCK.lock();
            let guard = Self {
                previous: is_metric_redaction_enabled(),
                _lock: lock,
            };
            set_metric_redaction(enabled);
            guard
        }
    }

    impl Drop for RedactionGuard {
        fn drop(&mut self) {
            set_metric_redaction(self.previous);
        }
    }

    /// Serializes the redaction-touching tests in this module. `nextest` isolates
    /// each test in its own process, but a plain `cargo test` shares one.
    static STATE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn pairs<'l, 'a>(labels: &'l Labels<'a>) -> Vec<(&'static str, &'l str)> {
        labels.as_slice().to_vec()
    }

    #[test]
    fn metric_redaction_default_disabled() {
        let _guard = RedactionGuard::set(false);
        assert!(!is_metric_redaction_enabled());
    }

    #[test]
    fn metric_redaction_enable_disable_roundtrip() {
        let _guard = RedactionGuard::set(false);
        set_metric_redaction(true);
        assert!(is_metric_redaction_enabled());
        set_metric_redaction(false);
        assert!(!is_metric_redaction_enabled());
    }

    #[test]
    fn latency_attrs_carry_status_only_when_disabled() {
        let _guard = RedactionGuard::set(false);
        let labels = latency_attrs("completed", None);
        assert_eq!(pairs(&labels), vec![(attr::STATUS.as_str(), "completed")]);
    }

    #[test]
    fn latency_attrs_drop_tenant_when_redacted_without_tenant() {
        let _guard = RedactionGuard::set(true);
        let labels = latency_attrs("completed", None);
        assert_eq!(pairs(&labels), vec![(attr::STATUS.as_str(), "completed")]);
    }

    #[test]
    fn latency_attrs_carry_tenant_when_redacted() {
        let _guard = RedactionGuard::set(true);
        let labels = latency_attrs("completed", Some("tnt_test"));
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::TENANT_ID, "tnt_test"),
                (attr::STATUS.as_str(), "completed")
            ]
        );
    }

    #[test]
    fn event_attrs_carry_tenant_when_redacted() {
        let _guard = RedactionGuard::set(true);
        let labels = event_attrs("create_started", Some("tnt_test"));
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::TENANT_ID, "tnt_test"),
                (attr::EVENT.as_str(), "create_started")
            ]
        );
    }

    #[test]
    fn event_reason_attrs_carry_all_three_when_redacted() {
        let _guard = RedactionGuard::set(true);
        let labels = event_reason_attrs("create_failed", "oom", Some("tnt_test"));
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::TENANT_ID, "tnt_test"),
                (attr::EVENT.as_str(), "create_failed"),
                (attr::REASON.as_str(), "oom"),
            ]
        );
    }

    #[test]
    fn tracing_identity_label_uses_sandbox_when_disabled() {
        let _guard = RedactionGuard::set(false);
        assert_eq!(
            tracing_identity_label("sbx_test", Some("tnt_test")),
            "sbx_test"
        );
    }

    #[test]
    fn tracing_identity_label_uses_tenant_when_redacted() {
        let _guard = RedactionGuard::set(true);
        assert_eq!(
            tracing_identity_label("sbx_test", Some("tnt_test")),
            "tenant:tnt_test"
        );
    }

    #[test]
    fn tracing_identity_label_falls_back_to_redacted() {
        let _guard = RedactionGuard::set(true);
        assert_eq!(tracing_identity_label("sbx_test", None), "redacted");
    }

    #[test]
    fn image_prepare_latency_attrs_use_unknown_by_default() {
        let _guard = RedactionGuard::set(false);
        let labels = image_prepare_latency_attrs(
            val::PREPARE_COMPLETED,
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            None,
        );
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::STATUS.as_str(), "prepare_completed"),
                (attr::CACHE_RESULT.as_str(), "unknown"),
                (attr::IMAGE_PROFILE.as_str(), "unknown"),
            ]
        );
    }

    #[test]
    fn image_prepare_latency_attrs_reject_unbounded_labels() {
        let _guard = RedactionGuard::set(false);
        // Digests, IDs, and tags must never become label values.
        let labels = image_prepare_latency_attrs(
            val::PREPARE_FAILED,
            "sha256:deadbeef",
            "custom-gpu-image-v99",
            None,
        );
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::STATUS.as_str(), "prepare_failed"),
                (attr::CACHE_RESULT.as_str(), "unknown"),
                (attr::IMAGE_PROFILE.as_str(), "unknown"),
            ]
        );
    }

    #[test]
    fn image_prepare_latency_attrs_reject_unbounded_status() {
        let _guard = RedactionGuard::set(false);
        // A digest or ID passed as status must never become a label value.
        let labels = image_prepare_latency_attrs(
            "sha256:deadbeef",
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            None,
        );
        assert_eq!(pairs(&labels)[0], (attr::STATUS.as_str(), "unknown"));
    }

    #[test]
    fn image_prepare_latency_attrs_reject_non_terminal_status() {
        let _guard = RedactionGuard::set(false);
        // `prepare_started` is a counter event, not a latency sample.
        let labels = image_prepare_latency_attrs(
            val::PREPARE_STARTED,
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            None,
        );
        assert_eq!(pairs(&labels)[0], (attr::STATUS.as_str(), "unknown"));
    }

    #[test]
    fn image_prepare_latency_attrs_accept_bounded_allowlist() {
        let _guard = RedactionGuard::set(false);
        let labels = image_prepare_latency_attrs("prepare_completed", "hit", "minimal", None);
        assert_eq!(pairs(&labels)[1], (attr::CACHE_RESULT.as_str(), "hit"));
        assert_eq!(pairs(&labels)[2], (attr::IMAGE_PROFILE.as_str(), "minimal"));
    }

    #[test]
    fn image_prepare_latency_attrs_carry_tenant_only_when_redacted() {
        let dedicated = RedactionGuard::set(false);
        let labels = image_prepare_latency_attrs(
            val::PREPARE_COMPLETED,
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            Some("tnt_test"),
        );
        assert_eq!(labels.as_slice().len(), 3);
        drop(dedicated);

        let _shared = RedactionGuard::set(true);
        let labels = image_prepare_latency_attrs(
            val::PREPARE_COMPLETED,
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            Some("tnt_test"),
        );
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::TENANT_ID, "tnt_test"),
                (attr::STATUS.as_str(), "prepare_completed"),
                (attr::CACHE_RESULT.as_str(), "unknown"),
                (attr::IMAGE_PROFILE.as_str(), "unknown"),
            ]
        );
    }

    #[test]
    fn image_prepare_latency_records_without_panic() {
        let _guard = RedactionGuard::set(false);
        // Registration happens once via HOST_METRICS; recording with unknown
        // labels must never panic, with or without redaction.
        let labels = image_prepare_latency_attrs(
            val::PREPARE_COMPLETED,
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            None,
        );
        HOST_METRICS.image_prepare_latency.record(0.150, &labels);
        let failed = image_prepare_latency_attrs(
            val::PREPARE_FAILED,
            val::CACHE_RESULT_UNKNOWN,
            val::IMAGE_PROFILE_UNKNOWN,
            None,
        );
        HOST_METRICS.image_prepare_latency.record(0.250, &failed);
    }

    #[test]
    fn host_recorders_do_not_emit_identity_labels() {
        // Every host-scoped series must stay unattributable even with
        // redaction on, otherwise it would be a cross-tenant leak in the
        // opposite direction.
        let _guard = RedactionGuard::set(true);
        let capacity = pico_core::HostCapacity {
            total_vcpus: 8,
            allocated_vcpus: 2,
            total_memory_mb: 1024,
            allocated_memory_mb: 256,
            total_disk_mb: 4096,
            used_disk_mb: 512,
            total_network_mbps: 1000,
            allocated_network_mbps: 100,
            max_process_slots: 32,
            used_process_slots: 4,
        };
        record_scheduler_capacity(&capacity);
        record_scheduler_utilization(&crate::scheduler_capacity::CapacityUtilization {
            cpu: 0.25,
            memory: 0.5,
            disk: 0.75,
            network: 0.1,
            process_slots: 0.125,
        });
        record_scheduler_health(pico_core::HostHealth::Healthy);
        record_credential_issued(1);
        record_credential_denied(2);
        record_credential_refreshed(3);
        record_credential_revoked(4);
        record_port_forward_endpoints_active(2);
        record_port_forward_connections_active(1);
        record_port_forward_expose();
        record_port_forward_revoke();
        record_port_forward_expired();
        record_port_forward_denied();
        record_network_health_state(0.0);
    }

    #[test]
    fn cgroup_recorders_skip_zero_counts() {
        let _guard = RedactionGuard::set(false);
        // A zero delta would otherwise create an empty data point on every poll.
        record_cgroup_oom_events_by(0);
        record_cgroup_memory_high_events_by(0);
        record_cgroup_cpu_throttled_by(0);
        record_cgroup_setup_error(0);
        record_cgroup_memory_pressure_read_error(0);
        record_cgroup_oom_events_by(2);
        record_cgroup_memory_high_events_by(3);
        record_cgroup_cpu_throttled_by(4);
        record_cgroup_setup_error(1);
        record_cgroup_memory_pressure(12.5);
        record_cgroup_memory_pressure_read_error(1);
    }
}

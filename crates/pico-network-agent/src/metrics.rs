//! Centralized network-agent metrics.
//!
//! # Interface
//!
//! Host-scoped series are recorded through the `record_*` functions, which own
//! their label set. Sandbox-scoped series go through [`record_sandbox_series`]
//! (and its siblings), which route identity through
//! [`Labels::sandbox`](pico_telemetry::metrics::Labels::sandbox) so the
//! shared-host redaction decision is applied in one place.
//!
//! Callers should not reach into [`NETWORK_METRICS`] fields to build their own
//! attribute slices. That was possible before, and 24 sandbox-scoped call sites
//! did exactly that, which is how raw `sandbox_id` labels ended up being
//! published on shared hosts where redaction was supposed to replace them with
//! `tenant_id`.

use pico_telemetry::metrics::{
    Counter, Gauge, Histogram, Labels, SHARED_HOST_LIMITER, attr, shared_host_redaction,
};
use std::sync::LazyLock;

pub static NETWORK_METRICS: LazyLock<NetworkMetrics> = LazyLock::new(NetworkMetrics::register);

// Metric name constants.
const SETUP_STARTED: &str = "network.setup.started";
const SETUP_COMPLETED: &str = "network.setup.completed";
const SETUP_NOT_COMPLETED: &str = "network.setup.not_completed";
const SETUP_DURATION_SECONDS: &str = "network.setup.duration_seconds";
const CLEANUP_REMOVED: &str = "network.cleanup.removed";
const CLEANUP_ABSENT: &str = "network.cleanup.absent";
const CLEANUP_COMPLETED: &str = "network.cleanup.completed";
const ROLLBACK_COMPLETED: &str = "network.rollback.completed";
const OBJECTS_COUNT: &str = "network.objects.count";
const EGRESS_ALLOWED: &str = "network.egress.allowed";
const EGRESS_DENIED: &str = "network.egress.denied";
const NAT_SESSIONS: &str = "network.nat.sessions";
const NAT_SETUP_COMPLETED: &str = "network.nat.setup_completed";
const NAT_ACTIVE_ENTRIES: &str = "network.nat.active_entries";
const EGRESS_SETUP_COMPLETED: &str = "network.egress.setup_completed";
const EGRESS_CLEANUP_COMPLETED: &str = "network.egress.cleanup_completed";

// Interface byte/packet counter metric name constants.
const INTERFACE_ALLOCATION_SUCCEEDED: &str = "network.interface.allocation_succeeded";
const INTERFACE_ALLOCATION_INCOMPLETE: &str = "network.interface.allocation_incomplete";
const INTERFACE_RX_BYTES: &str = "network.interface.rx_bytes";
const INTERFACE_TX_BYTES: &str = "network.interface.tx_bytes";
const INTERFACE_RX_PACKETS: &str = "network.interface.rx_packets";
const INTERFACE_TX_PACKETS: &str = "network.interface.tx_packets";

// Reconciliation metric name constants.
const RECONCILIATION_PASSES: &str = "network.reconciliation.passes";
const RECONCILIATION_PASS_DURATION_SECONDS: &str = "network.reconciliation.pass_duration_seconds";
const RECONCILIATION_STALE_OBJECTS: &str = "network.reconciliation.stale_objects";
const RECONCILIATION_CLEANED: &str = "network.reconciliation.cleaned";
const RECONCILIATION_REVIEW_REQUIRED: &str = "network.reconciliation.review_required";
const RECONCILIATION_CLEANUP_FAILED: &str = "network.reconciliation.cleanup_failed";
const RECONCILIATION_HEALTH_STATE: &str = "network.reconciliation.health_state";

// Lifecycle metric name constants.
const SUSPEND_COMPLETED: &str = "network.suspend.completed";
const SUSPEND_DURATION_SECONDS: &str = "network.suspend.duration_seconds";
const SUSPEND_CONNECTIONS_DROPPED: &str = "network.suspend.connections_dropped";

// Bandwidth shaping metric name constants.
const BANDWIDTH_SETUP_COMPLETED: &str = "network.bandwidth.setup_completed";
const BANDWIDTH_CLEANUP_COMPLETED: &str = "network.bandwidth.cleanup_completed";
const BANDWIDTH_LIMIT_CONFIGURED: &str = "network.bandwidth.limit_configured";

// Rate limit metric name constants.
const RATELIMIT_BANDWIDTH_DROPS: &str = "network.ratelimit.bandwidth_drops";
const RATELIMIT_PPS_DROPS: &str = "network.ratelimit.pps_drops";
const RATELIMIT_CONNECTION_DROPS: &str = "network.ratelimit.connection_drops";
const RATELIMIT_CONNECTION_RATE_DROPS: &str = "network.ratelimit.connection_rate_drops";
const RATELIMIT_NAT_DROPS: &str = "network.ratelimit.nat_drops";
const RATELIMIT_ACTIVE_CONNECTIONS: &str = "network.ratelimit.active_connections";
const RATELIMIT_BANDWIDTH_LIMIT_CONFIGURED: &str = "network.ratelimit.bandwidth_limit_configured";

const RESUME_COMPLETED: &str = "network.resume.completed";
const RESUME_FAILED: &str = "network.resume.failed";
const RESUME_POLICY_EPOCH_REJECTED: &str = "network.resume.policy_epoch_rejected";
const RESUME_DURATION_SECONDS: &str = "network.resume.duration_seconds";
const FORK_COMPLETED: &str = "network.fork.completed";
const FORK_FAILED: &str = "network.fork.failed";
const FORK_DURATION_SECONDS: &str = "network.fork.duration_seconds";
const FORK_PORT_INHERITANCE_BLOCKED: &str = "network.fork.port_inheritance_blocked";

const FLOW_EGRESS_BYTES: &str = "network.flow.egress_bytes";
const FLOW_EGRESS_PACKETS: &str = "network.flow.egress_packets";
const FLOW_TCP_SYN_SENT: &str = "network.flow.tcp.syn_sent";
const FLOW_TCP_ESTABLISHED: &str = "network.flow.tcp.established";
const FLOW_TCP_FIN_WAIT: &str = "network.flow.tcp.fin_wait";
const FLOW_TCP_RESET: &str = "network.flow.tcp.reset";
const FLOW_TCP_TOTAL: &str = "network.flow.tcp.total";
const FLOW_SAMPLED_CONNECTIONS: &str = "network.flow.sampled_connections";
const FLOW_SAMPLED_BYTES: &str = "network.flow.sampled_bytes";
const FLOW_SAMPLED_DURATION_MS: &str = "network.flow.sampled_duration_ms";

// Attribute value constants.
pub mod val {
    pub const MICROVM: &str = "microvm";
    pub const CONTAINER: &str = "container";
    pub const TAP: &str = "tap";
    pub const VETH: &str = "veth";
    pub const NAMESPACE: &str = "namespace";
    pub const ROUTE: &str = "route";
    pub const PROVISION_FAILURE: &str = "provision_failure";
    pub const ROUTE_ADD: &str = "route_add";
}

pub struct NetworkMetrics {
    pub setup: SetupMetrics,
    pub cleanup: CleanupMetrics,
    pub egress: EgressMetrics,
    pub nat: NatMetrics,
    pub bandwidth: BandwidthMetrics,
    pub lifecycle: LifecycleMetrics,
    pub reconciliation: ReconciliationMetrics,
    pub interface: InterfaceMetrics,
    pub ratelimit: RateLimitMetrics,
    pub flow: FlowTelemetryMetrics,
    pub objects: Gauge,
}

pub struct SetupMetrics {
    pub started: Counter,
    pub completed: Counter,
    pub not_completed: Counter,
    pub duration: Histogram,
}

pub struct CleanupMetrics {
    pub removed: Counter,
    pub absent: Counter,
    pub completed: Counter,
    pub rollback: Counter,
}

pub struct EgressMetrics {
    pub allowed: Counter,
    pub denied: Counter,
    pub setup_completed: Counter,
    pub cleanup_completed: Counter,
}

pub struct NatMetrics {
    pub sessions: Gauge,
    pub setup_completed: Counter,
    pub active_entries: Gauge,
}

pub struct BandwidthMetrics {
    pub setup_completed: Counter,
    pub cleanup_completed: Counter,
    pub limit_configured: Gauge,
}

/// Rate-limit hit counters.
pub struct RateLimitMetrics {
    pub bandwidth_drops: Counter,
    pub pps_drops: Counter,
    pub connection_drops: Counter,
    pub connection_rate_drops: Counter,
    pub nat_drops: Counter,
    pub active_connections: Gauge,
    pub bandwidth_limit_configured: Gauge,
}

/// Per-sandbox interface byte and packet counters.
///
/// Sourced from rtnetlink link stats where the backend supports them. Recorded
/// through [`record_interface_stats`], which applies the shared-host redaction
/// policy: `sandbox_id` normally, `tenant_id` when
/// `shared_host_metric_redaction` is on.
pub struct InterfaceMetrics {
    /// Cumulative received bytes on the sandbox interface.
    pub rx_bytes: Gauge,
    /// Cumulative transmitted bytes on the sandbox interface.
    pub tx_bytes: Gauge,
    /// Cumulative received packets on the sandbox interface.
    pub rx_packets: Gauge,
    /// Cumulative transmitted packets on the sandbox interface.
    pub tx_packets: Gauge,
    /// Successful interface allocation events.
    pub allocation_succeeded: Counter,
    /// Incomplete interface allocation events (provisioning failed mid-way).
    pub allocation_incomplete: Counter,
}

/// Reconciliation metrics for stale object detection and cleanup.
pub struct ReconciliationMetrics {
    /// Total number of reconciliation passes executed.
    pub passes: Counter,
    /// Duration of the most recent reconciliation pass.
    pub pass_duration: Histogram,
    /// Total number of stale objects detected.
    pub stale_objects: Counter,
    /// Number of stale objects successfully cleaned up.
    pub cleaned: Counter,
    /// Number of objects requiring operator review.
    pub review_required: Counter,
    /// Number of objects where cleanup failed.
    pub cleanup_failed: Counter,
    /// Current network health state (0=ready, 1=degraded, 2=unsafe).
    pub health_state: Gauge,
}

/// Lifecycle metrics for suspend, resume, and fork operations.
pub struct LifecycleMetrics {
    pub suspend_completed: Counter,
    pub suspend_duration: Histogram,
    pub suspend_connections_dropped: Counter,
    pub resume_completed: Counter,
    pub resume_failed: Counter,
    pub resume_policy_epoch_rejected: Counter,
    pub resume_duration: Histogram,
    pub fork_completed: Counter,
    pub fork_failed: Counter,
    pub fork_duration: Histogram,
    pub fork_port_inheritance_blocked: Counter,
}

pub struct FlowTelemetryMetrics {
    pub egress_bytes: Counter,
    pub egress_packets: Counter,
    pub tcp_syn_sent: Gauge,
    pub tcp_established: Gauge,
    pub tcp_fin_wait: Gauge,
    pub tcp_reset: Gauge,
    pub tcp_total: Gauge,
    pub sampled_connections: Counter,
    pub sampled_bytes: Counter,
    pub sampled_duration_ms: Histogram,
}

impl NetworkMetrics {
    fn register() -> Self {
        Self {
            setup: SetupMetrics {
                started: Counter::register(SETUP_STARTED),
                completed: Counter::register(SETUP_COMPLETED),
                not_completed: Counter::register(SETUP_NOT_COMPLETED),
                duration: Histogram::register(SETUP_DURATION_SECONDS),
            },
            cleanup: CleanupMetrics {
                removed: Counter::register(CLEANUP_REMOVED),
                absent: Counter::register(CLEANUP_ABSENT),
                completed: Counter::register(CLEANUP_COMPLETED),
                rollback: Counter::register(ROLLBACK_COMPLETED),
            },
            egress: EgressMetrics {
                allowed: Counter::register(EGRESS_ALLOWED),
                denied: Counter::register(EGRESS_DENIED),
                setup_completed: Counter::register(EGRESS_SETUP_COMPLETED),
                cleanup_completed: Counter::register(EGRESS_CLEANUP_COMPLETED),
            },
            nat: NatMetrics {
                sessions: Gauge::register(NAT_SESSIONS),
                setup_completed: Counter::register(NAT_SETUP_COMPLETED),
                active_entries: Gauge::register(NAT_ACTIVE_ENTRIES),
            },
            bandwidth: BandwidthMetrics {
                setup_completed: Counter::register(BANDWIDTH_SETUP_COMPLETED),
                cleanup_completed: Counter::register(BANDWIDTH_CLEANUP_COMPLETED),
                limit_configured: Gauge::register(BANDWIDTH_LIMIT_CONFIGURED),
            },
            ratelimit: RateLimitMetrics {
                bandwidth_drops: Counter::register(RATELIMIT_BANDWIDTH_DROPS),
                pps_drops: Counter::register(RATELIMIT_PPS_DROPS),
                connection_drops: Counter::register(RATELIMIT_CONNECTION_DROPS),
                connection_rate_drops: Counter::register(RATELIMIT_CONNECTION_RATE_DROPS),
                nat_drops: Counter::register(RATELIMIT_NAT_DROPS),
                active_connections: Gauge::register(RATELIMIT_ACTIVE_CONNECTIONS),
                bandwidth_limit_configured: Gauge::register(RATELIMIT_BANDWIDTH_LIMIT_CONFIGURED),
            },
            interface: InterfaceMetrics {
                rx_bytes: Gauge::register(INTERFACE_RX_BYTES),
                tx_bytes: Gauge::register(INTERFACE_TX_BYTES),
                rx_packets: Gauge::register(INTERFACE_RX_PACKETS),
                tx_packets: Gauge::register(INTERFACE_TX_PACKETS),
                allocation_succeeded: Counter::register(INTERFACE_ALLOCATION_SUCCEEDED),
                allocation_incomplete: Counter::register(INTERFACE_ALLOCATION_INCOMPLETE),
            },
            reconciliation: ReconciliationMetrics {
                passes: Counter::register(RECONCILIATION_PASSES),
                pass_duration: Histogram::register(RECONCILIATION_PASS_DURATION_SECONDS),
                stale_objects: Counter::register(RECONCILIATION_STALE_OBJECTS),
                cleaned: Counter::register(RECONCILIATION_CLEANED),
                review_required: Counter::register(RECONCILIATION_REVIEW_REQUIRED),
                cleanup_failed: Counter::register(RECONCILIATION_CLEANUP_FAILED),
                health_state: Gauge::register(RECONCILIATION_HEALTH_STATE),
            },
            lifecycle: LifecycleMetrics {
                suspend_completed: Counter::register(SUSPEND_COMPLETED),
                suspend_duration: Histogram::register(SUSPEND_DURATION_SECONDS),
                suspend_connections_dropped: Counter::register(SUSPEND_CONNECTIONS_DROPPED),
                resume_completed: Counter::register(RESUME_COMPLETED),
                resume_failed: Counter::register(RESUME_FAILED),
                resume_policy_epoch_rejected: Counter::register(RESUME_POLICY_EPOCH_REJECTED),
                resume_duration: Histogram::register(RESUME_DURATION_SECONDS),
                fork_completed: Counter::register(FORK_COMPLETED),
                fork_failed: Counter::register(FORK_FAILED),
                fork_duration: Histogram::register(FORK_DURATION_SECONDS),
                fork_port_inheritance_blocked: Counter::register(FORK_PORT_INHERITANCE_BLOCKED),
            },
            flow: FlowTelemetryMetrics {
                egress_bytes: Counter::register(FLOW_EGRESS_BYTES),
                egress_packets: Counter::register(FLOW_EGRESS_PACKETS),
                tcp_syn_sent: Gauge::register(FLOW_TCP_SYN_SENT),
                tcp_established: Gauge::register(FLOW_TCP_ESTABLISHED),
                tcp_fin_wait: Gauge::register(FLOW_TCP_FIN_WAIT),
                tcp_reset: Gauge::register(FLOW_TCP_RESET),
                tcp_total: Gauge::register(FLOW_TCP_TOTAL),
                sampled_connections: Counter::register(FLOW_SAMPLED_CONNECTIONS),
                sampled_bytes: Counter::register(FLOW_SAMPLED_BYTES),
                sampled_duration_ms: Histogram::register(FLOW_SAMPLED_DURATION_MS),
            },
            objects: Gauge::register(OBJECTS_COUNT),
        }
    }
}

// ── Host-scoped recorders ──
//
// These series aggregate across sandboxes, so they carry no identity
// attribute and are safe to publish on a shared host.

/// Records a network object provision start, by backend and kind.
pub fn record_setup_started(backend: &str, kind: &str) {
    NETWORK_METRICS.setup.started.inc(
        &Labels::host()
            .with(attr::BACKEND, backend)
            .with(attr::KIND, kind),
    );
}

/// Records a successful network object provision.
pub fn record_setup_completed(backend: &str, kind: &str, duration_secs: f64) {
    NETWORK_METRICS.setup.completed.inc(
        &Labels::host()
            .with(attr::BACKEND, backend)
            .with(attr::KIND, kind),
    );
    NETWORK_METRICS
        .setup
        .duration
        .record(duration_secs, &Labels::host());
}

/// Records a provision that did not complete, with the reason.
pub fn record_setup_not_completed(backend: &str, kind: &str, reason: &str) {
    let mut labels = Labels::host().with(attr::REASON, reason);
    if !backend.is_empty() {
        labels = labels.with(attr::BACKEND, backend);
    }
    if !kind.is_empty() {
        labels = labels.with(attr::KIND, kind);
    }
    NETWORK_METRICS.setup.not_completed.inc(&labels);
}

/// Records the number of live network objects of a kind.
pub fn record_object_count(kind: &str, count: usize) {
    NETWORK_METRICS
        .objects
        .set(count as f64, &Labels::host().with(attr::KIND, kind));
}

/// Records a network object that was present and removed.
pub fn record_cleanup_removed(kind: &str) {
    NETWORK_METRICS
        .cleanup
        .removed
        .inc(&Labels::host().with(attr::KIND, kind));
}

/// Records a cleanup for an object that was already absent.
pub fn record_cleanup_absent(kind: &str) {
    NETWORK_METRICS
        .cleanup
        .absent
        .inc(&Labels::host().with(attr::KIND, kind));
}

/// Records a completed network cleanup.
pub fn record_cleanup_completed() {
    NETWORK_METRICS.cleanup.completed.inc(&Labels::host());
}

/// Records a rolled-back provision.
pub fn record_rollback_completed() {
    NETWORK_METRICS.cleanup.rollback.inc(&Labels::host());
}

/// Records an egress rule provisioned.
pub fn record_egress_setup_completed() {
    NETWORK_METRICS.egress.setup_completed.inc(&Labels::host());
}

/// Records an egress rule removed.
pub fn record_egress_cleanup_completed() {
    NETWORK_METRICS
        .egress
        .cleanup_completed
        .inc(&Labels::host());
}

/// Records a NAT rule provisioned.
pub fn record_nat_setup_completed() {
    NETWORK_METRICS.nat.setup_completed.inc(&Labels::host());
}

/// Records an interface that was allocated successfully.
pub fn record_interface_allocated(backend: &str) {
    NETWORK_METRICS
        .interface
        .allocation_succeeded
        .inc(&Labels::host().with(attr::BACKEND, backend));
}

/// Records an interface allocation that failed part-way.
pub fn record_interface_allocation_incomplete(backend: &str) {
    NETWORK_METRICS
        .interface
        .allocation_incomplete
        .inc(&Labels::host().with(attr::BACKEND, backend));
}

/// Records a completed reconciliation pass.
///
/// Zero-valued outcome counters are skipped rather than incremented by zero, so
/// a clean pass does not create empty data points on the outcome series.
pub fn record_reconciliation_pass(duration_secs: f64, report: &ReconciliationReport) {
    let labels = Labels::host();
    NETWORK_METRICS
        .reconciliation
        .pass_duration
        .record(duration_secs, &labels);
    NETWORK_METRICS.reconciliation.passes.inc(&labels);

    for (counter, count) in [
        (
            &NETWORK_METRICS.reconciliation.stale_objects,
            report.stale_count,
        ),
        (
            &NETWORK_METRICS.reconciliation.cleaned,
            report.cleaned_count,
        ),
        (
            &NETWORK_METRICS.reconciliation.review_required,
            report.review_required,
        ),
        (
            &NETWORK_METRICS.reconciliation.cleanup_failed,
            report.cleanup_failed,
        ),
    ] {
        if count > 0 {
            counter.inc_by(count, &labels);
        }
    }

    NETWORK_METRICS
        .reconciliation
        .health_state
        .set(report.health.gauge(), &labels);
}

/// Network health, as reported by the reconciler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkHealth {
    Ready,
    Degraded,
    Unsafe,
}

impl NetworkHealth {
    /// The gauge value dashboards read: 0 = ready, 1 = degraded, 2 = unsafe.
    fn gauge(self) -> f64 {
        match self {
            Self::Ready => 0.0,
            Self::Degraded => 1.0,
            Self::Unsafe => 2.0,
        }
    }
}

/// Counts from a single reconciliation pass.
#[derive(Debug, Clone, Copy)]
pub struct ReconciliationReport {
    pub stale_count: u64,
    pub cleaned_count: u64,
    pub review_required: u64,
    pub cleanup_failed: u64,
    pub health: NetworkHealth,
}

impl Default for ReconciliationReport {
    /// A clean pass over a healthy network: nothing stale, nothing to do.
    fn default() -> Self {
        Self {
            stale_count: 0,
            cleaned_count: 0,
            review_required: 0,
            cleanup_failed: 0,
            health: NetworkHealth::Ready,
        }
    }
}

/// Records a suspend that dropped the given number of connections.
pub fn record_suspend(connections_dropped: u64, duration_secs: f64) {
    NETWORK_METRICS
        .lifecycle
        .suspend_connections_dropped
        .inc_by(connections_dropped, &Labels::host());
    NETWORK_METRICS
        .lifecycle
        .suspend_completed
        .inc(&Labels::host());
    NETWORK_METRICS
        .lifecycle
        .suspend_duration
        .record(duration_secs, &Labels::host());
}

/// Records a resume rejected because the policy epoch was stale.
pub fn record_resume_policy_epoch_rejected() {
    NETWORK_METRICS
        .lifecycle
        .resume_policy_epoch_rejected
        .inc(&Labels::host());
}

/// Records a failed resume.
pub fn record_resume_failed() {
    NETWORK_METRICS.lifecycle.resume_failed.inc(&Labels::host());
}

/// Records a successful resume.
pub fn record_resume_completed(duration_secs: f64) {
    NETWORK_METRICS
        .lifecycle
        .resume_completed
        .inc(&Labels::host());
    NETWORK_METRICS
        .lifecycle
        .resume_duration
        .record(duration_secs, &Labels::host());
}

/// Records a failed fork.
pub fn record_fork_failed() {
    NETWORK_METRICS.lifecycle.fork_failed.inc(&Labels::host());
}

/// Records a completed fork.
pub fn record_fork_completed(duration_secs: f64, port_inheritance_blocked: bool) {
    NETWORK_METRICS
        .lifecycle
        .fork_completed
        .inc(&Labels::host());
    NETWORK_METRICS
        .lifecycle
        .fork_duration
        .record(duration_secs, &Labels::host());
    if port_inheritance_blocked {
        NETWORK_METRICS
            .lifecycle
            .fork_port_inheritance_blocked
            .inc(&Labels::host());
    }
}

// ── Sandbox-scoped recorders ──
//
// These carry an identity attribute, so they go through `Labels::sandbox` and
// therefore honour `shared_host_metric_redaction`.

/// Identity of the sandbox a series is about, for the sandbox-scoped recorders.
#[derive(Debug, Clone, Copy)]
pub struct SandboxScope<'a> {
    pub sandbox_id: &'a str,
    pub tenant_id: Option<&'a str>,
}

impl<'a> SandboxScope<'a> {
    /// Builds a scope for a sandbox whose tenant is known.
    #[must_use]
    pub fn new(sandbox_id: &'a str, tenant_id: &'a str) -> Self {
        Self {
            sandbox_id,
            tenant_id: Some(tenant_id),
        }
    }

    /// Builds a scope for a sandbox with no tenant context available.
    #[must_use]
    pub fn without_tenant(sandbox_id: &'a str) -> Self {
        Self {
            sandbox_id,
            tenant_id: None,
        }
    }

    /// Builds a scope, applying the redaction policy when labels are requested.
    fn labels(self) -> Labels<'a> {
        Labels::sandbox(self.sandbox_id, self.tenant_id)
    }
}

/// Records the configured bandwidth limit for a sandbox interface.
pub fn record_bandwidth_limit_configured(scope: SandboxScope<'_>, if_name: &str, limit_bps: u64) {
    NETWORK_METRICS.bandwidth.limit_configured.set(
        limit_bps as f64,
        &scope.labels().with(attr::IF_NAME, if_name),
    );
}

/// Records a bandwidth limit applied to an existing interface.
pub fn record_bandwidth_setup_completed(if_name: &str) {
    NETWORK_METRICS
        .bandwidth
        .setup_completed
        .inc(&Labels::host().with(attr::IF_NAME, if_name));
}

/// Records a bandwidth limit removed from an interface.
pub fn record_bandwidth_cleanup_completed(if_name: &str) {
    NETWORK_METRICS
        .bandwidth
        .cleanup_completed
        .inc(&Labels::host().with(attr::IF_NAME, if_name));
}

/// Records the eBPF-configured rate limit for a sandbox.
pub fn record_ratelimit_configured(scope: SandboxScope<'_>, bandwidth_bps: u64) {
    NETWORK_METRICS
        .ratelimit
        .bandwidth_limit_configured
        .set(bandwidth_bps as f64, &scope.labels());
}

/// Records the active connection count for a sandbox.
pub fn record_ratelimit_active_connections(scope: SandboxScope<'_>, max_conns: u64) {
    NETWORK_METRICS
        .ratelimit
        .active_connections
        .set(max_conns as f64, &scope.labels());
}

/// Records the current active connection count for a sandbox.
pub fn record_active_connections(scope: SandboxScope<'_>, count: u64) {
    NETWORK_METRICS
        .ratelimit
        .active_connections
        .set(count as f64, &scope.labels());
}

/// Counts of drops observed by the eBPF rate limiter.
#[derive(Debug, Clone, Copy, Default)]
pub struct RateLimitDrops {
    pub bw_drops: u64,
    pub pps_drops: u64,
    pub conn_drops: u64,
    pub conn_rate_drops: u64,
    pub nat_drops: u64,
}

/// Records every drop counter the eBPF rate limiter reports.
pub fn record_ratelimit_drops(scope: SandboxScope<'_>, drops: &RateLimitDrops) {
    let labels = scope.labels();
    NETWORK_METRICS
        .ratelimit
        .bandwidth_drops
        .inc_by(drops.bw_drops, &labels);
    NETWORK_METRICS
        .ratelimit
        .pps_drops
        .inc_by(drops.pps_drops, &labels);
    NETWORK_METRICS
        .ratelimit
        .connection_drops
        .inc_by(drops.conn_drops, &labels);
    NETWORK_METRICS
        .ratelimit
        .connection_rate_drops
        .inc_by(drops.conn_rate_drops, &labels);
    NETWORK_METRICS
        .ratelimit
        .nat_drops
        .inc_by(drops.nat_drops, &labels);
}

/// Records the current active NAT entry count for a sandbox.
pub fn record_nat_active_entries(scope: SandboxScope<'_>, count: u64) {
    NETWORK_METRICS
        .nat
        .active_entries
        .set(count as f64, &scope.labels());
}

/// Records the current NAT session count for a sandbox.
pub fn record_nat_sessions(scope: SandboxScope<'_>, count: u64) {
    NETWORK_METRICS
        .nat
        .sessions
        .set(count as f64, &scope.labels());
}

/// Egress byte and packet counters for a sandbox.
#[derive(Debug, Clone, Copy, Default)]
pub struct EgressCounters {
    pub egress_bytes: u64,
    pub egress_packets: u64,
}

/// Records egress byte and packet counters.
pub fn record_egress_counters(scope: SandboxScope<'_>, counters: &EgressCounters) {
    let labels = scope.labels();
    NETWORK_METRICS
        .flow
        .egress_bytes
        .inc_by(counters.egress_bytes, &labels);
    NETWORK_METRICS
        .flow
        .egress_packets
        .inc_by(counters.egress_packets, &labels);
}

/// TCP connection state counts for a sandbox.
///
/// `u32` to match the eBPF counter width, widened to `f64` only at the gauge.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpStateCounts {
    pub syn_sent: u32,
    pub established: u32,
    pub fin_wait: u32,
    pub reset: u32,
    pub total: u32,
}

impl TcpStateCounts {
    /// Sets all five gauges under one shared label set, so the series stay
    /// consistent with each other.
    fn set(&self, labels: &Labels<'_>) {
        NETWORK_METRICS
            .flow
            .tcp_syn_sent
            .set(self.syn_sent as f64, labels);
        NETWORK_METRICS
            .flow
            .tcp_established
            .set(self.established as f64, labels);
        NETWORK_METRICS
            .flow
            .tcp_fin_wait
            .set(self.fin_wait as f64, labels);
        NETWORK_METRICS
            .flow
            .tcp_reset
            .set(self.reset as f64, labels);
        NETWORK_METRICS
            .flow
            .tcp_total
            .set(self.total as f64, labels);
    }
}

/// Records TCP state gauges from the eBPF flow sampler.
pub fn record_tcp_state(scope: SandboxScope<'_>, state: &TcpStateCounts) {
    state.set(&scope.labels());
}

/// Records TCP state gauges read from a counters map.
pub fn record_tcp_state_counts(scope: SandboxScope<'_>, counts: &TcpStateCounts) {
    counts.set(&scope.labels());
}

/// Records how many connections the flow sampler observed.
pub fn record_sampled_connections(scope: SandboxScope<'_>, count: u64) {
    NETWORK_METRICS
        .flow
        .sampled_connections
        .inc_by(count, &scope.labels());
}

/// Records bytes observed by the flow sampler.
pub fn record_sampled_bytes(scope: SandboxScope<'_>, bytes: u64) {
    NETWORK_METRICS
        .flow
        .sampled_bytes
        .inc_by(bytes, &scope.labels());
}

/// Records per-sandbox interface byte and packet counters from rtnetlink stats.
///
/// Labels use `sandbox_id`, `if_name`, and `backend` dimensions. All label
/// values are tenant-safe (deterministic hash-derived names, not
/// user-provided content).
///
/// When `shared_host_metric_redaction` is enabled, `sandbox_id` is replaced
/// with `tenant_id` and reporting is throttled to one emission per
/// [`SHARED_HOST_LIMITER`] window per key, because a per-sandbox counter's
/// update frequency is itself a cross-tenant side channel.
pub fn record_interface_stats(
    scope: SandboxScope<'_>,
    if_name: &str,
    backend: &str,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
) {
    let labels = scope
        .labels()
        .with(attr::IF_NAME, if_name)
        .with(attr::BACKEND, backend);

    if shared_host_redaction() {
        // Key on whatever identity the label actually carries, so the throttle
        // matches the series it is protecting.
        let key = labels
            .as_slice()
            .first()
            .map_or("unknown_tenant", |(_, v)| *v);
        if !SHARED_HOST_LIMITER.should_emit(key) {
            return;
        }
    }

    NETWORK_METRICS
        .interface
        .rx_bytes
        .set(rx_bytes as f64, &labels);
    NETWORK_METRICS
        .interface
        .tx_bytes
        .set(tx_bytes as f64, &labels);
    NETWORK_METRICS
        .interface
        .rx_packets
        .set(rx_packets as f64, &labels);
    NETWORK_METRICS
        .interface
        .tx_packets
        .set(tx_packets as f64, &labels);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes against other redaction-touching tests and restores the flag.
    ///
    /// Holds a shared lock because the flag is process-global: `nextest` gives
    /// every test its own process, but a plain `cargo test` shares one, so
    /// without the lock two tests flipping the flag can observe each other's
    /// value.
    struct RedactionGuard {
        previous: bool,
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl RedactionGuard {
        fn set(enabled: bool) -> Self {
            let lock = STATE_LOCK.lock();
            let guard = Self {
                previous: shared_host_redaction(),
                _lock: lock,
            };
            pico_telemetry::metrics::set_shared_host_redaction(enabled);
            guard
        }
    }

    /// Serializes the redaction-touching tests in this module.
    static STATE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    impl Drop for RedactionGuard {
        fn drop(&mut self) {
            pico_telemetry::metrics::set_shared_host_redaction(self.previous);
        }
    }

    fn scope<'a>(sandbox_id: &'a str, tenant_id: &'a str) -> SandboxScope<'a> {
        SandboxScope::new(sandbox_id, tenant_id)
    }

    fn tenantless<'a>(sandbox_id: &'a str) -> SandboxScope<'a> {
        SandboxScope::without_tenant(sandbox_id)
    }

    #[test]
    fn sandbox_scope_uses_sandbox_id_on_dedicated_hosts() {
        let _guard = RedactionGuard::set(false);
        let labels = scope("sbx_test", "tnt_test").labels();
        assert_eq!(labels.as_slice(), &[(attr::SANDBOX_ID, "sbx_test")]);
    }

    #[test]
    fn sandbox_scope_substitutes_tenant_under_redaction() {
        let _guard = RedactionGuard::set(true);
        let labels = scope("sbx_test", "tnt_test").labels();
        assert_eq!(labels.as_slice(), &[(attr::TENANT_ID, "tnt_test")]);
    }

    #[test]
    fn interface_stats_do_not_leak_sandbox_id_when_redacted() {
        let _guard = RedactionGuard::set(true);
        record_interface_stats(
            scope("sbx_secret", "tnt_test"),
            "cvx_if",
            val::MICROVM,
            100,
            200,
            10,
            20,
        );
    }

    #[test]
    fn interface_stats_emit_on_dedicated_hosts() {
        let _guard = RedactionGuard::set(false);
        record_interface_stats(
            tenantless("sbx_test"),
            "cvx_if",
            val::MICROVM,
            100,
            200,
            10,
            20,
        );
    }

    #[test]
    fn interface_stats_are_rate_limited_when_redacted() {
        let _guard = RedactionGuard::set(true);
        // A fresh tenant so the first call is not throttled by a sibling test.
        let scope = scope("sbx_rl", "tnt_rl_unique");
        assert!(SHARED_HOST_LIMITER.should_emit("tnt_rl_unique"));

        record_interface_stats(scope, "cvx_if", val::MICROVM, 100, 200, 10, 20);
        // The limiter was already charged above, so the recorder must skip.
        record_interface_stats(scope, "cvx_if", val::MICROVM, 200, 400, 20, 40);
    }

    #[test]
    fn host_recorders_do_not_panic() {
        record_setup_started(val::MICROVM, val::TAP);
        record_setup_completed(val::MICROVM, val::TAP, 0.01);
        record_setup_not_completed(val::MICROVM, val::TAP, val::PROVISION_FAILURE);
        record_setup_not_completed("", "", val::ROUTE_ADD);
        record_object_count(val::TAP, 3);
        record_cleanup_removed(val::TAP);
        record_cleanup_absent(val::TAP);
        record_cleanup_completed();
        record_rollback_completed();
        record_egress_setup_completed();
        record_egress_cleanup_completed();
        record_nat_setup_completed();
        record_interface_allocated(val::MICROVM);
        record_interface_allocation_incomplete(val::CONTAINER);
        record_bandwidth_setup_completed("cvx0");
        record_bandwidth_cleanup_completed("cvx0");
        record_resume_policy_epoch_rejected();
        record_resume_failed();
        record_resume_completed(0.5);
        record_suspend(4, 0.2);
        record_fork_failed();
        record_fork_completed(0.3, true);
        record_fork_completed(0.3, false);
    }

    #[test]
    fn reconciliation_recorder_does_not_panic() {
        let report = ReconciliationReport {
            stale_count: 2,
            cleaned_count: 1,
            review_required: 1,
            cleanup_failed: 0,
            health: NetworkHealth::Degraded,
        };
        record_reconciliation_pass(0.01, &report);
    }

    #[test]
    fn health_gauges_are_ordered_by_severity() {
        assert_eq!(NetworkHealth::Ready.gauge(), 0.0);
        assert_eq!(NetworkHealth::Degraded.gauge(), 1.0);
        assert_eq!(NetworkHealth::Unsafe.gauge(), 2.0);
    }

    #[test]
    fn sandbox_recorders_do_not_panic() {
        let _guard = RedactionGuard::set(false);
        let scope = scope("sbx_test", "tnt_test");
        record_bandwidth_limit_configured(scope, "cvx0", 1_000_000);
        record_ratelimit_configured(scope, 1_000_000);
        record_ratelimit_active_connections(scope, 64);
        record_active_connections(scope, 3);
        record_ratelimit_drops(
            scope,
            &RateLimitDrops {
                bw_drops: 1,
                pps_drops: 2,
                conn_drops: 3,
                conn_rate_drops: 4,
                nat_drops: 5,
            },
        );
        record_nat_active_entries(scope, 7);
        record_nat_sessions(scope, 2);
        record_egress_counters(
            scope,
            &EgressCounters {
                egress_bytes: 1000,
                egress_packets: 10,
            },
        );
        let tcp = TcpStateCounts {
            syn_sent: 1,
            established: 2,
            fin_wait: 3,
            reset: 4,
            total: 5,
        };
        record_tcp_state(scope, &tcp);
        record_tcp_state_counts(scope, &tcp);
        record_sampled_connections(scope, 1);
        record_sampled_bytes(scope, 2048);
    }
}

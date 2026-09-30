//! Core observability metrics.
//!
//! ## Snapshot cache metrics and shared-host redaction (SC-IMPL-04)
//!
//! Snapshot cache metrics (`pico_snapshot_cache_hits`, `pico_snapshot_cache_misses`,
//! `pico_snapshot_eviction_*`) are rate-limited on shared multi-tenant hosts to
//! prevent cross-tenant cache activity inference via high-frequency metric sampling.
//!
//! ### Rate-limiting strategy
//!
//! When `shared_host_metric_redaction` is enabled:
//! 1. Metrics are throttled to one emission per 60-second window per key, by
//!    [`RateLimiter`](pico_telemetry::metrics::RateLimiter).
//! 2. Key space uses a `{metric_type}:{tenant_id}` scheme. The current cache layer
//!    (`TieredCacheManager` / `CacheTierStore`) lacks tenant context, so all call sites
//!    pass `None` for `tenant_id`, collapsing to a single host-level key per metric type.
//!    This means the rate limiter applies per-host, not per-tenant.
//! 3. No `tenant_id` label is attached to the emitted OTel data points, because
//!    [`Labels::tenant`](pico_telemetry::metrics::Labels::tenant) drops the
//!    attribute when no tenant is supplied.
//!
//! This is a known limitation: if per-tenant (still rate-limited) visibility is needed,
//! `tenant_id` must be threaded through the cache tiering layer. For now, host-level
//! aggregation is the safer default---it prevents cross-tenant inference without leaking
//! tenancy boundaries through metric labels.
//!
//! On dedicated-tenancy hosts (redaction disabled), all metrics pass through without
//! rate-limiting, maintaining full per-host granularity.

use std::sync::LazyLock;

use pico_telemetry::metrics::{
    Counter, Gauge, Histogram, Labels, SHARED_HOST_LIMITER, shared_host_redaction,
};

pub static CORE_METRICS: LazyLock<CoreMetrics> = LazyLock::new(CoreMetrics::register);

/// Whether a shared-host throttle should be consulted for `prefix`.
///
/// On a dedicated host nothing is rate-limited, so the limiter is skipped
/// entirely rather than charged a lookup.
fn should_emit_snapshot_cache_metric(prefix: &str, tenant_id: Option<&str>) -> bool {
    if !shared_host_redaction() {
        return true;
    }
    // Collapses to a single host-level key while the cache tiering layer has no
    // tenant context to thread through.
    let key = match tenant_id {
        Some(tid) => [prefix, ":", tid].concat(),
        None => [prefix, ":", "host"].concat(),
    };
    SHARED_HOST_LIMITER.should_emit(&key)
}

/// Record a snapshot cache hit. Rate-limited on shared hosts.
///
/// `tenant_id` is optional. When `None` (current default from the cache tiering layer),
/// the rate-limiter key collapses to `"hit:host"` and no `tenant_id` label is attached.
pub fn record_snapshot_cache_hit(tenant_id: Option<&str>) {
    if !should_emit_snapshot_cache_metric("hit", tenant_id) {
        return;
    }
    CORE_METRICS
        .snapshot_cache_hits
        .inc(&Labels::tenant(tenant_id));
}

/// Record a snapshot cache miss. Rate-limited on shared hosts.
///
/// See `record_snapshot_cache_hit` for tenant context caveats.
pub fn record_snapshot_cache_miss(tenant_id: Option<&str>) {
    if !should_emit_snapshot_cache_metric("miss", tenant_id) {
        return;
    }
    CORE_METRICS
        .snapshot_cache_misses
        .inc(&Labels::tenant(tenant_id));
}

/// Record a snapshot eviction. Rate-limited on shared hosts.
///
/// See `record_snapshot_cache_hit` for tenant context caveats.
pub fn record_snapshot_eviction(tenant_id: Option<&str>, freed_bytes: u64) {
    if !should_emit_snapshot_cache_metric("evict", tenant_id) {
        return;
    }
    let labels = Labels::tenant(tenant_id);
    CORE_METRICS.snapshot_eviction_count.inc(&labels);
    CORE_METRICS
        .snapshot_eviction_bytes
        .inc_by(freed_bytes, &labels);
}

/// Records the service-class outcome of one cell placement admit.
///
/// Best-effort admits increment `pico_placement_be_admits_total`; the
/// subset that consumed overcommit budget beyond strict capacity also
/// increments `pico_placement_overcommit_admits_total`. Latency-sensitive
/// admits record nothing extra, so the LS path stays metric-identical
/// with the pre-class behavior. Host-level aggregates carry no identity
/// attribute.
pub fn record_placement_class(
    service_class: crate::overcommit::ServiceClass,
    overcommit_applied: bool,
) {
    if !service_class.is_best_effort() {
        return;
    }
    let labels = Labels::host();
    CORE_METRICS.placement_be_admits.inc(&labels);
    if overcommit_applied {
        CORE_METRICS.placement_overcommit_admits.inc(&labels);
    }
}

const PLACEMENT_LATENCY_SECONDS: &str = "pico_placement_latency_seconds";
const PLACEMENT_HOSTS_EVALUATED: &str = "pico_placement_hosts_evaluated";
const PLACEMENT_HOSTS_PASSED_CONSTRAINTS: &str = "pico_placement_hosts_passed_constraints";
const PLACEMENT_BE_ADMITS_TOTAL: &str = "pico_placement_be_admits_total";
const PLACEMENT_OVERCOMMIT_ADMITS_TOTAL: &str = "pico_placement_overcommit_admits_total";

const GC_PASS_DURATION_SECONDS: &str = "pico_gc_pass_duration_seconds";
const GC_ORPHANS_DETECTED: &str = "pico_gc_orphans_detected";
const GC_RESOURCES_REMOVED: &str = "pico_gc_resources_removed";
const GC_REVIEW_REQUIRED: &str = "pico_gc_review_required";
const GC_CLEANUP_FAILED: &str = "pico_gc_cleanup_failed";

const CPU_RECEIPTS_RESTORED: &str = "pico_cpu_receipts_restored";
const CPU_RECEIPTS_SKIPPED: &str = "pico_cpu_receipts_skipped";

const SNAPSHOT_CACHE_HITS: &str = "pico_snapshot_cache_hits";
const SNAPSHOT_CACHE_MISSES: &str = "pico_snapshot_cache_misses";
const SNAPSHOT_EVICTION_COUNT: &str = "pico_snapshot_eviction_count";
const SNAPSHOT_EVICTION_BYTES: &str = "pico_snapshot_eviction_bytes";
const SNAPSHOT_REF_REGISTERED: &str = "pico_snapshot_ref_registered";
const SNAPSHOT_REF_DEREGISTERED: &str = "pico_snapshot_ref_deregistered";
const SNAPSHOT_GC_PASSES: &str = "pico_snapshot_gc_passes";
const SNAPSHOT_GC_DELETED: &str = "pico_snapshot_gc_deleted";
const SNAPSHOT_GC_BYTES_FREED: &str = "pico_snapshot_gc_bytes_freed";
const SNAPSHOT_GC_SKIPPED_REF: &str = "pico_snapshot_gc_skipped_ref";
const SNAPSHOT_GC_SKIPPED_RETENTION: &str = "pico_snapshot_gc_skipped_retention";
const SNAPSHOT_GC_CANDIDATES: &str = "pico_snapshot_gc_candidates";

pub struct CoreMetrics {
    pub placement_latency: Histogram,
    pub hosts_evaluated: Histogram,
    pub hosts_passed: Histogram,
    /// Best-effort admits (host-level, gated by OvercommitPolicy).
    pub placement_be_admits: Counter,
    /// Best-effort admits that consumed overcommit budget beyond strict.
    pub placement_overcommit_admits: Counter,
    pub gc_pass_duration: Histogram,
    pub gc_orphans_detected: Counter,
    pub gc_resources_removed: Counter,
    pub gc_review_required: Counter,
    pub gc_cleanup_failed: Counter,
    pub cpu_receipts_restored: Counter,
    pub cpu_receipts_skipped: Counter,
    pub snapshot_cache_hits: Counter,
    pub snapshot_cache_misses: Counter,
    pub snapshot_eviction_count: Counter,
    pub snapshot_eviction_bytes: Counter,
    pub snapshot_ref_registered: Counter,
    pub snapshot_ref_deregistered: Counter,
    pub snapshot_gc_passes: Counter,
    pub snapshot_gc_deleted: Counter,
    pub snapshot_gc_bytes_freed: Counter,
    pub snapshot_gc_skipped_ref: Counter,
    pub snapshot_gc_skipped_retention: Counter,
    pub snapshot_gc_candidates: Gauge,
}

impl CoreMetrics {
    fn register() -> Self {
        Self {
            placement_latency: Histogram::register(PLACEMENT_LATENCY_SECONDS),
            hosts_evaluated: Histogram::register(PLACEMENT_HOSTS_EVALUATED),
            hosts_passed: Histogram::register(PLACEMENT_HOSTS_PASSED_CONSTRAINTS),
            placement_be_admits: Counter::register(PLACEMENT_BE_ADMITS_TOTAL),
            placement_overcommit_admits: Counter::register(PLACEMENT_OVERCOMMIT_ADMITS_TOTAL),
            gc_pass_duration: Histogram::register(GC_PASS_DURATION_SECONDS),
            gc_orphans_detected: Counter::register(GC_ORPHANS_DETECTED),
            gc_resources_removed: Counter::register(GC_RESOURCES_REMOVED),
            gc_review_required: Counter::register(GC_REVIEW_REQUIRED),
            gc_cleanup_failed: Counter::register(GC_CLEANUP_FAILED),
            cpu_receipts_restored: Counter::register(CPU_RECEIPTS_RESTORED),
            cpu_receipts_skipped: Counter::register(CPU_RECEIPTS_SKIPPED),
            snapshot_cache_hits: Counter::register(SNAPSHOT_CACHE_HITS),
            snapshot_cache_misses: Counter::register(SNAPSHOT_CACHE_MISSES),
            snapshot_eviction_count: Counter::register(SNAPSHOT_EVICTION_COUNT),
            snapshot_eviction_bytes: Counter::register(SNAPSHOT_EVICTION_BYTES),
            snapshot_ref_registered: Counter::register(SNAPSHOT_REF_REGISTERED),
            snapshot_ref_deregistered: Counter::register(SNAPSHOT_REF_DEREGISTERED),
            snapshot_gc_passes: Counter::register(SNAPSHOT_GC_PASSES),
            snapshot_gc_deleted: Counter::register(SNAPSHOT_GC_DELETED),
            snapshot_gc_bytes_freed: Counter::register(SNAPSHOT_GC_BYTES_FREED),
            snapshot_gc_skipped_ref: Counter::register(SNAPSHOT_GC_SKIPPED_REF),
            snapshot_gc_skipped_retention: Counter::register(SNAPSHOT_GC_SKIPPED_RETENTION),
            snapshot_gc_candidates: Gauge::register(SNAPSHOT_GC_CANDIDATES),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_telemetry::metrics::attr;

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
                previous: pico_telemetry::metrics::shared_host_redaction(),
                _lock: lock,
            };
            pico_telemetry::metrics::set_shared_host_redaction(enabled);
            guard
        }
    }

    impl Drop for RedactionGuard {
        fn drop(&mut self) {
            pico_telemetry::metrics::set_shared_host_redaction(self.previous);
        }
    }

    /// Serializes the redaction-touching tests in this module. `nextest` isolates
    /// each test in its own process, but a plain `cargo test` shares one.
    static STATE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn labels<'a>(set: Labels<'a>) -> Vec<(&'static str, &'a str)> {
        set.as_slice().to_vec()
    }

    #[test]
    fn dedicated_hosts_are_never_rate_limited() {
        let _guard = RedactionGuard::set(false);
        // The throttle is skipped entirely on a dedicated host, so repeated
        // calls for the same key all emit.
        for _ in 0..5 {
            assert!(should_emit_snapshot_cache_metric("hit", Some("tnt_test")));
        }
    }

    #[test]
    fn should_emit_first_call_returns_true() {
        let _guard = RedactionGuard::set(true);
        assert!(should_emit_snapshot_cache_metric("hit", Some("tnt_first")));
    }

    #[test]
    fn should_emit_second_call_within_interval_returns_false() {
        let _guard = RedactionGuard::set(true);
        assert!(should_emit_snapshot_cache_metric("hit", Some("tnt_rl")));
        assert!(!should_emit_snapshot_cache_metric("hit", Some("tnt_rl")));
    }

    #[test]
    fn should_emit_different_keys_are_independent() {
        // The limiter is a process-wide singleton, so each test claims its own
        // key space. A shared key would let one test consume the window another
        // test is asserting on.
        let _guard = RedactionGuard::set(true);
        assert!(should_emit_snapshot_cache_metric("hit", Some("tnt_a")));
        assert!(should_emit_snapshot_cache_metric("miss", Some("tnt_a")));
        assert!(should_emit_snapshot_cache_metric("hit", Some("tnt_b")));
        assert!(!should_emit_snapshot_cache_metric("hit", Some("tnt_a")));
        assert!(should_emit_snapshot_cache_metric("evict", Some("tnt_b")));
    }

    #[test]
    fn tenantless_keys_share_one_host_bucket() {
        // The cache tiering layer has no tenant context, so `None` must collapse
        // to a single per-host key rather than a fresh bucket per call. The key
        // space is this test's own, so the first call is guaranteed fresh.
        let _guard = RedactionGuard::set(true);
        assert!(should_emit_snapshot_cache_metric("tenantless-probe", None));
        assert!(!should_emit_snapshot_cache_metric("tenantless-probe", None));
    }

    #[test]
    fn record_snapshot_cache_hit_does_not_panic() {
        let _guard = RedactionGuard::set(false);
        record_snapshot_cache_hit(None);
        record_snapshot_cache_hit(Some("tnt_test"));
        pico_telemetry::metrics::set_shared_host_redaction(true);
        record_snapshot_cache_hit(None);
        record_snapshot_cache_hit(Some("tnt_test"));
    }

    #[test]
    fn record_snapshot_cache_miss_does_not_panic() {
        let _guard = RedactionGuard::set(false);
        record_snapshot_cache_miss(None);
        record_snapshot_cache_miss(Some("tnt_test"));
        pico_telemetry::metrics::set_shared_host_redaction(true);
        record_snapshot_cache_miss(None);
        record_snapshot_cache_miss(Some("tnt_test"));
    }

    #[test]
    fn record_snapshot_eviction_does_not_panic() {
        let _guard = RedactionGuard::set(false);
        record_snapshot_eviction(None, 1024);
        record_snapshot_eviction(Some("tnt_test"), 2048);
        pico_telemetry::metrics::set_shared_host_redaction(true);
        // Own key space: `tenantless-probe` is reserved for the bucket test.
        record_snapshot_eviction(None, 1024);
        record_snapshot_eviction(Some("tnt_evict"), 2048);
    }

    #[test]
    fn record_placement_class_does_not_panic_and_skips_ls() {
        use crate::overcommit::ServiceClass;
        let _guard = RedactionGuard::set(false);
        // LS records nothing extra (metric-identical with pre-class path).
        record_placement_class(ServiceClass::LatencySensitive, false);
        record_placement_class(ServiceClass::LatencySensitive, true);
        // BE records be admits, with overcommit subset.
        record_placement_class(ServiceClass::BestEffort, false);
        record_placement_class(ServiceClass::BestEffort, true);
    }

    #[test]
    fn snapshot_cache_labels_are_empty_on_dedicated_hosts() {
        let _guard = RedactionGuard::set(false);
        assert!(labels(Labels::tenant(Some("tnt_test"))).is_empty());
    }

    #[test]
    fn snapshot_cache_labels_carry_tenant_when_redacted() {
        let _guard = RedactionGuard::set(true);
        assert_eq!(
            labels(Labels::tenant(Some("tnt_test"))),
            vec![(attr::TENANT_ID, "tnt_test")]
        );
    }

    #[test]
    fn snapshot_cache_labels_stay_empty_when_redacted_without_tenant() {
        let _guard = RedactionGuard::set(true);
        assert!(labels(Labels::tenant(None)).is_empty());
    }
}

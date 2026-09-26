//! Tenant quota engine for resource admission control.
//!
//! Provides per-tenant quota limits and atomic usage counters.
//! Quota checks gate the Pending -> Scheduled transition.
//!
//! The check_create function uses an increment-first-then-validate pattern
//! to avoid TOCTOU races: counters are atomically incremented, validated
//! against limits, and rolled back if any limit is exceeded.

use hashbrown::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::identity::{PolicyDecisionId, TenantId};

/// Per-tenant quota limits.
#[derive(Debug, Clone, Copy)]
pub struct QuotaLimits {
    pub max_sandboxes: u32,
    pub max_vcpus: u32,
    pub max_memory_mb: u64,
    /// Per-sandbox egress bandwidth cap in bytes per second. None = unlimited.
    pub max_bandwidth_bps: Option<u64>,
    /// Per-sandbox maximum concurrent connections. None = unlimited.
    pub max_connections: Option<u32>,
    /// Per-sandbox maximum packets per second. None = unlimited.
    pub max_pps: Option<u32>,
}

/// Network rate-limit parameters derived from quota policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkLimits {
    pub bandwidth_bps: u64,
    pub max_connections: u32,
    pub max_pps: u32,
}

const DEFAULT_MAX_SANDBOXES: u32 = 10;
const DEFAULT_MAX_VCPUS: u32 = 20;
const DEFAULT_MAX_MEMORY_MB: u64 = 8192;

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            max_sandboxes: DEFAULT_MAX_SANDBOXES,
            max_vcpus: DEFAULT_MAX_VCPUS,
            max_memory_mb: DEFAULT_MAX_MEMORY_MB,
            max_bandwidth_bps: None,
            max_connections: None,
            max_pps: None,
        }
    }
}

/// Atomic per-tenant usage counters.
#[derive(Debug)]
pub struct QuotaCounters {
    pub current_sandboxes: AtomicU32,
    pub current_vcpus: AtomicU32,
    pub current_memory_mb: AtomicU64,
}

impl QuotaCounters {
    pub fn new() -> Self {
        Self {
            current_sandboxes: AtomicU32::new(0),
            current_vcpus: AtomicU32::new(0),
            current_memory_mb: AtomicU64::new(0),
        }
    }

    pub fn sandbox_count(&self) -> u32 {
        self.current_sandboxes.load(Ordering::Relaxed)
    }

    pub fn vcpu_usage(&self) -> u32 {
        self.current_vcpus.load(Ordering::Relaxed)
    }

    pub fn memory_usage_mb(&self) -> u64 {
        self.current_memory_mb.load(Ordering::Relaxed)
    }
}

impl Default for QuotaCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct QuotaDecision {
    pub decision_id: PolicyDecisionId,
    pub allowed: bool,
    pub resource: Option<String>,
    pub limit: u64,
    pub current: u64,
}

/// Engine that enforces per-tenant resource quotas.
#[derive(Debug)]
pub struct QuotaEngine {
    limits: RwLock<HashMap<TenantId, QuotaLimits>>,
    counters: RwLock<HashMap<TenantId, Arc<QuotaCounters>>>,
}

impl QuotaEngine {
    pub fn new() -> Self {
        Self {
            limits: RwLock::new(HashMap::new()),
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Set quota limits for a tenant.
    pub fn set_limits(&self, tenant_id: TenantId, limits: QuotaLimits) {
        self.limits.write().insert(tenant_id, limits);
    }

    fn get_or_create_counters(&self, tenant_id: &TenantId) -> Arc<QuotaCounters> {
        let mut counters = self.counters.write();
        Arc::clone(
            counters
                .entry(tenant_id.clone())
                .or_insert_with(|| Arc::new(QuotaCounters::new())),
        )
    }

    fn get_limits(&self, tenant_id: &TenantId) -> QuotaLimits {
        self.limits
            .read()
            .get(tenant_id)
            .copied()
            .unwrap_or_default()
    }

    /// Check whether creating a sandbox with the given vcpus and memory
    /// would exceed the tenant's quota. Returns `QuotaDecision`.
    ///
    /// Uses increment-first-then-validate to avoid TOCTOU races:
    /// counters are atomically incremented, validated against limits,
    /// and rolled back if any limit is exceeded.
    pub fn check_create(&self, tenant_id: &TenantId, vcpus: u32, memory_mb: u64) -> QuotaDecision {
        let limits = self.get_limits(tenant_id);
        let counters = self.get_or_create_counters(tenant_id);

        let prev_sandboxes = counters.current_sandboxes.fetch_add(1, Ordering::Relaxed);
        if prev_sandboxes >= limits.max_sandboxes {
            counters.current_sandboxes.fetch_sub(1, Ordering::Relaxed);
            return QuotaDecision {
                decision_id: PolicyDecisionId::generate(),
                allowed: false,
                resource: Some("sandboxes".into()),
                limit: limits.max_sandboxes as u64,
                current: prev_sandboxes as u64,
            };
        }

        let prev_vcpus = counters.current_vcpus.fetch_add(vcpus, Ordering::Relaxed);
        let new_vcpus = prev_vcpus + vcpus;
        if new_vcpus > limits.max_vcpus {
            counters.current_vcpus.fetch_sub(vcpus, Ordering::Relaxed);
            counters.current_sandboxes.fetch_sub(1, Ordering::Relaxed);
            return QuotaDecision {
                decision_id: PolicyDecisionId::generate(),
                allowed: false,
                resource: Some("vcpus".into()),
                limit: limits.max_vcpus as u64,
                current: prev_vcpus as u64,
            };
        }

        let prev_memory = counters
            .current_memory_mb
            .fetch_add(memory_mb, Ordering::Relaxed);
        let new_memory = prev_memory + memory_mb;
        if new_memory > limits.max_memory_mb {
            counters
                .current_memory_mb
                .fetch_sub(memory_mb, Ordering::Relaxed);
            counters.current_vcpus.fetch_sub(vcpus, Ordering::Relaxed);
            counters.current_sandboxes.fetch_sub(1, Ordering::Relaxed);
            return QuotaDecision {
                decision_id: PolicyDecisionId::generate(),
                allowed: false,
                resource: Some("memory_mb".into()),
                limit: limits.max_memory_mb,
                current: prev_memory,
            };
        }

        QuotaDecision {
            decision_id: PolicyDecisionId::generate(),
            allowed: true,
            resource: None,
            limit: 0,
            current: 0,
        }
    }

    /// Release resources when a sandbox is destroyed or fails.
    ///
    /// Uses saturating subtraction to prevent underflow from
    /// double-release calls.
    pub fn release(&self, tenant_id: &TenantId, vcpus: u32, memory_mb: u64) {
        if let Some(counters) = self.counters.read().get(tenant_id) {
            let curr = counters.current_sandboxes.load(Ordering::Relaxed);
            if curr > 0 {
                counters.current_sandboxes.fetch_sub(1, Ordering::Relaxed);
            }
            let v = counters.current_vcpus.load(Ordering::Relaxed);
            if v >= vcpus {
                counters.current_vcpus.fetch_sub(vcpus, Ordering::Relaxed);
            }
            let m = counters.current_memory_mb.load(Ordering::Relaxed);
            if m >= memory_mb {
                counters
                    .current_memory_mb
                    .fetch_sub(memory_mb, Ordering::Relaxed);
            }
        }
    }

    /// Read current counters for a tenant.
    pub fn get_counters(&self, tenant_id: &TenantId) -> (u32, u32, u64) {
        if let Some(counters) = self.counters.read().get(tenant_id) {
            (
                counters.sandbox_count(),
                counters.vcpu_usage(),
                counters.memory_usage_mb(),
            )
        } else {
            (0, 0, 0)
        }
    }

    /// Derive resolved network rate limits for a sandbox.
    ///
    /// Returns the effective limits by resolving overrides in order:
    /// per-sandbox override > tenant quota limit > unlimited (0).
    pub fn network_limits_for(
        &self,
        tenant_id: &TenantId,
        sandbox_overrides: Option<&NetworkLimits>,
    ) -> NetworkLimits {
        let tenant_limits = self.get_limits(tenant_id);

        let bandwidth_bps = sandbox_overrides
            .and_then(|o| {
                if o.bandwidth_bps == 0 {
                    None
                } else {
                    Some(o.bandwidth_bps)
                }
            })
            .or(tenant_limits.max_bandwidth_bps)
            .unwrap_or(0);

        let max_connections = sandbox_overrides
            .and_then(|o| {
                if o.max_connections == 0 {
                    None
                } else {
                    Some(o.max_connections)
                }
            })
            .or(tenant_limits.max_connections)
            .unwrap_or(0);

        let max_pps = sandbox_overrides
            .and_then(|o| {
                if o.max_pps == 0 {
                    None
                } else {
                    Some(o.max_pps)
                }
            })
            .or(tenant_limits.max_pps)
            .unwrap_or(0);

        NetworkLimits {
            bandwidth_bps,
            max_connections,
            max_pps,
        }
    }
}

impl Default for QuotaEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn quota_check_allows_when_under_limits() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();
        engine.set_limits(
            tid.clone(),
            QuotaLimits {
                max_sandboxes: 10,
                max_vcpus: 20,
                max_memory_mb: 8192,
                ..Default::default()
            },
        );

        let decision = engine.check_create(&tid, 2, 512);
        assert!(decision.allowed);

        let (s, v, m) = engine.get_counters(&tid);
        assert_eq!(s, 1);
        assert_eq!(v, 2);
        assert_eq!(m, 512);
    }

    #[test]
    fn quota_check_denies_when_sandboxes_exceeded() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();
        engine.set_limits(
            tid.clone(),
            QuotaLimits {
                max_sandboxes: 1,
                max_vcpus: 20,
                max_memory_mb: 8192,
                ..Default::default()
            },
        );

        let d1 = engine.check_create(&tid, 2, 512);
        assert!(d1.allowed);

        let d2 = engine.check_create(&tid, 2, 512);
        assert!(!d2.allowed);
        assert_eq!(d2.resource.as_deref(), Some("sandboxes"));
        assert_eq!(d2.limit, 1);
        assert_eq!(d2.current, 1);

        let (s, _, _) = engine.get_counters(&tid);
        assert_eq!(s, 1);
    }

    #[test]
    fn quota_check_denies_when_vcpus_exceeded() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();
        engine.set_limits(
            tid.clone(),
            QuotaLimits {
                max_sandboxes: 10,
                max_vcpus: 4,
                max_memory_mb: 8192,
                ..Default::default()
            },
        );

        let d1 = engine.check_create(&tid, 4, 512);
        assert!(d1.allowed);

        let d2 = engine.check_create(&tid, 1, 512);
        assert!(!d2.allowed);
        assert_eq!(d2.resource.as_deref(), Some("vcpus"));

        let (s, v, _) = engine.get_counters(&tid);
        assert_eq!(s, 1);
        assert_eq!(v, 4);
    }

    #[test]
    fn quota_check_denies_when_memory_exceeded() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();
        engine.set_limits(
            tid.clone(),
            QuotaLimits {
                max_sandboxes: 10,
                max_vcpus: 20,
                max_memory_mb: 1024,
                ..Default::default()
            },
        );

        let d1 = engine.check_create(&tid, 2, 1024);
        assert!(d1.allowed);

        let d2 = engine.check_create(&tid, 2, 128);
        assert!(!d2.allowed);
        assert_eq!(d2.resource.as_deref(), Some("memory_mb"));

        let (s, _, m) = engine.get_counters(&tid);
        assert_eq!(s, 1);
        assert_eq!(m, 1024);
    }

    #[test]
    fn quota_release_frees_resources() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();
        engine.set_limits(
            tid.clone(),
            QuotaLimits {
                max_sandboxes: 1,
                max_vcpus: 2,
                max_memory_mb: 512,
                ..Default::default()
            },
        );

        let d1 = engine.check_create(&tid, 2, 512);
        assert!(d1.allowed);

        engine.release(&tid, 2, 512);

        let (s, v, m) = engine.get_counters(&tid);
        assert_eq!(s, 0);
        assert_eq!(v, 0);
        assert_eq!(m, 0);

        let d2 = engine.check_create(&tid, 2, 512);
        assert!(d2.allowed);
    }

    #[test]
    fn quota_default_limits_for_unconfigured_tenant() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();

        let decision = engine.check_create(&tid, 2, 512);
        assert!(decision.allowed);

        let (s, v, m) = engine.get_counters(&tid);
        assert_eq!(s, 1);
        assert_eq!(v, 2);
        assert_eq!(m, 512);
    }

    #[test]
    fn double_release_does_not_underflow() {
        let engine = QuotaEngine::new();
        let tid = TenantId::generate();

        engine.check_create(&tid, 2, 512);

        engine.release(&tid, 2, 512);
        engine.release(&tid, 2, 512);
        engine.release(&tid, 2, 512);

        let (s, v, m) = engine.get_counters(&tid);
        assert_eq!(s, 0);
        assert_eq!(v, 0);
        assert_eq!(m, 0);
    }

    #[test]
    fn concurrent_creates_respect_quota_limits() {
        let engine = Arc::new(QuotaEngine::new());
        let tid = TenantId::generate();
        engine.set_limits(
            tid.clone(),
            QuotaLimits {
                max_sandboxes: 5,
                max_vcpus: 10,
                max_memory_mb: 5120,
                ..Default::default()
            },
        );

        let thread_count = 20;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = vec![];

        for _ in 0..thread_count {
            let engine = Arc::clone(&engine);
            let tid = tid.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                engine.check_create(&tid, 1, 256)
            }));
        }

        let decisions: Vec<QuotaDecision> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        let allowed_count = decisions.iter().filter(|d| d.allowed).count();
        assert_eq!(
            allowed_count, 5,
            "exactly 5 sandboxes should be allowed (limit is 5)"
        );

        let (s, _, _) = engine.get_counters(&tid);
        assert_eq!(s, 5);
    }
}

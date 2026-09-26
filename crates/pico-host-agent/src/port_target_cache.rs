//! Host-side cache of sandboxd port targets keyed by generation.
//!
//! The port proxy resolves upstream addresses only through this cache (fed by
//! Watch/List observations and GetPortTarget). Missing or generation-mismatched
//! entries fail closed. Invalidation writes a tombstone so a stale List or
//! GetPortTarget cannot repopulate dropped routes. Generation and host-boot
//! decisions are delegated to the shared core observation policy.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use pico_core::{CoherenceDecision, ObservationCoherence, ObservationEpoch};
use pico_sandboxd_proto::v1::{PortTarget, SandboxObservation, port_target};

/// Resolved upstream for one guest port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedPortTarget {
    /// Host-reachable TCP address for proxying.
    Tcp(SocketAddr),
    /// Backend owns exposure; host proxy must not bind a route.
    BackendManaged,
    /// Port cannot be exposed.
    Unsupported,
}

#[derive(Debug, Clone)]
struct PortEntry {
    generation: u64,
    target: CachedPortTarget,
}

#[derive(Debug, Default)]
struct CacheInner {
    /// Generation and host-boot guards shared with the host observation policy.
    coherence: ObservationCoherence,
    /// Port targets keyed by `(sandbox_id, guest_port)`.
    ports: HashMap<(String, u16), PortEntry>,
}

/// Shared observation-backed port target cache.
#[derive(Clone, Default)]
pub struct PortTargetCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl PortTargetCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached generation for a sandbox, if any.
    #[cfg(test)]
    #[must_use]
    fn generation(&self, sandbox_id: &str) -> Option<u64> {
        self.inner.read().coherence.generation(sandbox_id)
    }

    /// Looks up a TCP upstream when the cached generation still matches.
    ///
    /// Returns `None` for missing entries, generation mismatch, or non-TCP
    /// targets so the proxy fails closed.
    #[must_use]
    pub fn resolve_tcp(&self, sandbox_id: &str, guest_port: u16) -> Option<SocketAddr> {
        let guard = self.inner.read();
        let generation = guard.coherence.generation(sandbox_id)?;
        let entry = guard.ports.get(&(sandbox_id.to_string(), guest_port))?;
        if entry.generation != generation {
            return None;
        }
        match entry.target {
            CachedPortTarget::Tcp(addr) => Some(addr),
            CachedPortTarget::BackendManaged | CachedPortTarget::Unsupported => None,
        }
    }

    /// Drops cached routes and tombstones when sandboxd's process boot changes.
    pub fn note_host_boot_id(&self, host_boot_id: &str) {
        let mut guard = self.inner.write();
        if guard.coherence.note_host_boot_id(host_boot_id) {
            guard.ports.clear();
        }
    }

    /// Applies a full observation snapshot (Watch upsert or List reconcile).
    ///
    /// Older generations on the same host boot are ignored. A different
    /// `host_boot_id` is treated as a sandboxd restart and accepted.
    pub fn apply_observation(&self, observation: &SandboxObservation) {
        let mut guard = self.inner.write();
        let epoch = ObservationEpoch::new(observation.generation, observation.host_boot_id.clone());
        match guard.coherence.accept(&observation.sandbox_id, &epoch) {
            CoherenceDecision::Rejected => return,
            CoherenceDecision::Accepted => {}
            CoherenceDecision::AcceptedAfterBootChange => {
                // A boot change resets dependent route state.
                guard.ports.clear();
            }
        }
        install_observation(&mut guard, observation);
    }

    /// Records a GetPortTarget response when its generation is not stale.
    pub fn apply_get_port_target(
        &self,
        sandbox_id: &str,
        guest_port: u16,
        target: &PortTarget,
        generation: u64,
    ) {
        let mut guard = self.inner.write();
        let boot = guard
            .coherence
            .epoch(sandbox_id)
            .map(|epoch| epoch.host_boot_id.clone())
            .unwrap_or_else(|| guard.coherence.host_boot_id().to_string());
        let epoch = ObservationEpoch::new(generation, boot);
        match guard.coherence.accept(sandbox_id, &epoch) {
            CoherenceDecision::Rejected => return,
            CoherenceDecision::Accepted => {}
            CoherenceDecision::AcceptedAfterBootChange => {
                guard.ports.clear();
            }
        }
        let Some(decoded) = decode_port_target(target) else {
            return;
        };
        guard.ports.insert(
            (sandbox_id.to_string(), guest_port),
            PortEntry {
                generation,
                target: decoded,
            },
        );
    }

    /// Invalidates every cached route for one sandbox (resume/destroy/Watch remove).
    ///
    /// Writes a tombstone so a late List/GetPortTarget at or below the last
    /// accepted generation cannot restore the dropped routes.
    pub fn invalidate_sandbox(&self, sandbox_id: &str) {
        let mut guard = self.inner.write();
        invalidate_locked(&mut guard, sandbox_id);
    }

    /// Applies a ListSandboxes snapshot without wiping newer Watch state.
    ///
    /// Listed snapshots go through the monotonic/tombstone guard. Ids present
    /// in the cache but absent from the list are dropped only when they were
    /// not updated after this reconcile started.
    pub fn reconcile_from_list(&self, observations: &[SandboxObservation]) {
        if let Some(boot) = observations
            .iter()
            .map(|observation| observation.host_boot_id.as_str())
            .find(|boot| !boot.is_empty())
        {
            self.note_host_boot_id(boot);
        }

        let listed: HashSet<String> = observations
            .iter()
            .map(|observation| observation.sandbox_id.clone())
            .collect();
        let snapshot: HashMap<String, u64> = {
            let guard = self.inner.read();
            guard
                .coherence
                .tracked_epochs()
                .map(|(id, generation)| (id.to_string(), generation))
                .collect()
        };

        for observation in observations {
            self.apply_observation(observation);
        }

        let mut guard = self.inner.write();
        let stale: Vec<String> = guard
            .coherence
            .tracked_epochs()
            .filter(|(id, _)| !listed.contains(*id))
            .filter(|(id, generation)| snapshot.get(*id).copied() == Some(*generation))
            .map(|(id, _)| id.to_string())
            .collect();
        for id in stale {
            invalidate_locked(&mut guard, &id);
        }
    }
}

fn install_observation(guard: &mut CacheInner, observation: &SandboxObservation) {
    let sandbox_id = observation.sandbox_id.as_str();
    guard.ports.retain(|(sid, _), _| sid != sandbox_id);

    for port in &observation.ports {
        let Ok(guest_port) = u16::try_from(port.guest_port) else {
            continue;
        };
        if guest_port == 0 {
            continue;
        }
        if let Some(target) = decode_port_target(port) {
            guard.ports.insert(
                (sandbox_id.to_string(), guest_port),
                PortEntry {
                    generation: observation.generation,
                    target,
                },
            );
        }
    }
}

fn invalidate_locked(guard: &mut CacheInner, sandbox_id: &str) {
    guard.coherence.invalidate(sandbox_id);
    guard.ports.retain(|(sid, _), _| sid != sandbox_id);
}

fn decode_port_target(port: &PortTarget) -> Option<CachedPortTarget> {
    match port.target.as_ref()? {
        port_target::Target::TcpAddr(addr) => {
            let addr = SocketAddr::from_str(addr).ok()?;
            Some(CachedPortTarget::Tcp(addr))
        }
        port_target::Target::BackendManaged(true) => Some(CachedPortTarget::BackendManaged),
        port_target::Target::Unsupported(true) => Some(CachedPortTarget::Unsupported),
        port_target::Target::BackendManaged(false) | port_target::Target::Unsupported(false) => {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_sandboxd_proto::v1::{
        RuntimeType as ProtoRuntime, SandboxObservation, SandboxState as ProtoState,
    };

    fn observation(
        id: &str,
        generation: u64,
        ports: Vec<PortTarget>,
        host_boot_id: &str,
    ) -> SandboxObservation {
        SandboxObservation {
            sandbox_id: id.into(),
            observed_state: ProtoState::Running as i32,
            generation,
            host_boot_id: host_boot_id.into(),
            guest_boot_id: String::new(),
            backend: ProtoRuntime::Firecracker as i32,
            ports,
            ssh: None,
            policy_epoch: 1,
            assignment_fencing_token: "1.1".into(),
            updated_at: "t".into(),
        }
    }

    fn tcp_port(guest: u16, addr: &str) -> PortTarget {
        PortTarget {
            guest_port: u32::from(guest),
            target: Some(port_target::Target::TcpAddr(addr.into())),
        }
    }

    #[test]
    fn resolve_tcp_requires_matching_generation() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            3,
            vec![tcp_port(8080, "127.0.0.1:18080")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:18080".parse().unwrap())
        );

        cache.apply_get_port_target("sbx_a", 9090, &tcp_port(9090, "127.0.0.1:18081"), 4);
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);
    }

    #[test]
    fn newer_observation_drops_stale_routes() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![
                tcp_port(8080, "127.0.0.1:18080"),
                tcp_port(22, "127.0.0.1:22"),
            ],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            2,
            vec![tcp_port(8080, "10.0.0.2:8080")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("10.0.0.2:8080".parse().unwrap())
        );
        assert_eq!(cache.resolve_tcp("sbx_a", 22), None);
    }

    #[test]
    fn invalidate_sandbox_clears_routes() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![tcp_port(8080, "127.0.0.1:18080")],
            "boot",
        ));
        cache.invalidate_sandbox("sbx_a");
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);
        assert_eq!(cache.generation("sbx_a"), None);
    }

    #[test]
    fn stale_observation_is_ignored() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            5,
            vec![tcp_port(8080, "127.0.0.1:5")],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            2,
            vec![tcp_port(8080, "127.0.0.1:2")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:5".parse().unwrap())
        );
    }

    #[test]
    fn tombstone_rejects_stale_list_and_get_after_invalidate() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            4,
            vec![tcp_port(8080, "127.0.0.1:4")],
            "boot",
        ));
        cache.invalidate_sandbox("sbx_a");
        cache.apply_observation(&observation(
            "sbx_a",
            4,
            vec![tcp_port(8080, "127.0.0.1:4")],
            "boot",
        ));
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);

        cache.apply_get_port_target("sbx_a", 8080, &tcp_port(8080, "127.0.0.1:4"), 4);
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);

        cache.apply_observation(&observation(
            "sbx_a",
            5,
            vec![tcp_port(8080, "10.0.0.2:8080")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("10.0.0.2:8080".parse().unwrap())
        );
    }

    #[test]
    fn reconcile_from_list_does_not_wipe_newer_watch_state() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_keep",
            3,
            vec![tcp_port(80, "127.0.0.1:80")],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_gone",
            1,
            vec![tcp_port(22, "127.0.0.1:22")],
            "boot",
        ));
        cache.invalidate_sandbox("sbx_gone");

        cache.reconcile_from_list(&[
            observation("sbx_keep", 2, vec![tcp_port(80, "10.0.0.1:80")], "boot"),
            observation("sbx_gone", 1, vec![tcp_port(22, "127.0.0.1:22")], "boot"),
        ]);

        assert_eq!(
            cache.resolve_tcp("sbx_keep", 80),
            Some("127.0.0.1:80".parse().unwrap())
        );
        assert_eq!(cache.resolve_tcp("sbx_gone", 22), None);
    }

    #[test]
    fn reconcile_from_list_drops_absent_ids_not_updated_during_reconcile() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_live",
            1,
            vec![tcp_port(80, "127.0.0.1:80")],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_stale",
            1,
            vec![tcp_port(22, "127.0.0.1:22")],
            "boot",
        ));

        cache.reconcile_from_list(&[observation(
            "sbx_live",
            1,
            vec![tcp_port(80, "127.0.0.1:80")],
            "boot",
        )]);

        assert!(cache.resolve_tcp("sbx_live", 80).is_some());
        assert_eq!(cache.resolve_tcp("sbx_stale", 22), None);
        assert_eq!(cache.generation("sbx_stale"), None);
    }

    #[test]
    fn first_boot_observation_does_not_flush_existing_routes() {
        let cache = PortTargetCache::new();
        cache.apply_get_port_target("sbx_a", 8080, &tcp_port(8080, "127.0.0.1:18080"), 1);
        cache.apply_observation(&observation("sbx_b", 1, Vec::new(), "boot-x"));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:18080".parse().unwrap())
        );
    }

    #[test]
    fn boot_change_clears_routes_for_all_sandboxes() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            3,
            vec![tcp_port(8080, "127.0.0.1:18080")],
            "boot-old",
        ));
        cache.apply_observation(&observation(
            "sbx_b",
            4,
            vec![tcp_port(8080, "127.0.0.1:18081")],
            "boot-old",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![tcp_port(8080, "127.0.0.1:19080")],
            "boot-new",
        ));
        assert!(cache.resolve_tcp("sbx_a", 8080).is_some());
        assert_eq!(cache.resolve_tcp("sbx_b", 8080), None);
    }

    #[test]
    fn host_boot_id_change_resets_generation_floor() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            9,
            vec![tcp_port(8080, "127.0.0.1:9")],
            "boot-old",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![tcp_port(8080, "127.0.0.1:1")],
            "boot-new",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:1".parse().unwrap())
        );
        assert_eq!(cache.generation("sbx_a"), Some(1));
    }
}

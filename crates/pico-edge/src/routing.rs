//! Host-header–based routing for the edge gateway.
//!
//! Routes incoming requests to sandbox TCP backends based on:
//! - Host header pattern matching (e.g., `sandbox-id.example.com`) — **implemented**
//! - Default upstream fallback — **implemented**
//! - Path prefix matching — **future work**

use hashbrown::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

/// An upstream backend target for proxied traffic.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// TCP address of the host-agent port-forward endpoint (host:port).
    pub addr: String,
    /// Whether TLS should be used when connecting to the upstream.
    pub tls: bool,
    /// Maximum allowed concurrent connections for this upstream
    /// (future work — not yet enforced).
    pub max_connections: Option<usize>,
    /// Maximum requests per second for this upstream
    /// (future work — not yet enforced).
    pub max_rps: Option<u32>,
}

impl Upstream {
    /// Create a plain TCP upstream.
    pub fn tcp(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            tls: false,
            max_connections: None,
            max_rps: None,
        }
    }
}

/// Routing table that maps host header patterns to upstream backend addresses.
///
/// Thread-safe: uses `RwLock` for dynamic updates.
pub struct RoutingTable {
    /// Exact hostname to upstream mapping.
    exact: RwLock<HashMap<String, Arc<Upstream>>>,
    /// Fallback upstream for unmatched hosts.
    default_upstream: Arc<Upstream>,
}

impl RoutingTable {
    /// Create a new routing table with a default upstream.
    pub fn new(default_upstream: Upstream) -> Self {
        Self {
            exact: RwLock::new(HashMap::new()),
            default_upstream: Arc::new(default_upstream),
        }
    }

    /// Register a host-to-upstream mapping.
    pub fn register(&self, host: &str, upstream: Upstream) {
        self.exact
            .write()
            .insert(host.to_lowercase(), Arc::new(upstream));
    }

    /// Remove a host mapping.
    pub fn remove(&self, host: &str) {
        self.exact.write().remove(&host.to_lowercase());
    }

    /// Look up the upstream for a given host header.
    ///
    /// Falls back to the default upstream if no exact match is found.
    #[must_use]
    pub fn resolve(&self, host: Option<&str>) -> Arc<Upstream> {
        if let Some(host) = host {
            let lower = host.to_lowercase();
            // Strip port from host header if present
            let hostname = lower.split(':').next().unwrap_or(&lower);
            if let Some(upstream) = self.exact.read().get(hostname) {
                return Arc::clone(upstream);
            }
        }
        Arc::clone(&self.default_upstream)
    }

    /// Returns the number of registered host mappings.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.exact.read().len()
    }

    /// Returns true if the routing table has no registered host mappings.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.exact.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_exact_host_match() {
        let table = RoutingTable::new(Upstream::tcp("127.0.0.1:9999"));
        table.register("sandbox-abc.example.com", Upstream::tcp("10.0.0.1:8080"));

        let upstream = table.resolve(Some("sandbox-abc.example.com"));
        assert_eq!(upstream.addr, "10.0.0.1:8080");

        let upstream = table.resolve(Some("sandbox-abc.example.com:443"));
        assert_eq!(upstream.addr, "10.0.0.1:8080");
    }

    #[test]
    fn falls_back_to_default() {
        let table = RoutingTable::new(Upstream::tcp("127.0.0.1:9000"));
        let upstream = table.resolve(Some("unknown.example.com"));
        assert_eq!(upstream.addr, "127.0.0.1:9000");
    }

    #[test]
    fn falls_back_with_no_host_header() {
        let table = RoutingTable::new(Upstream::tcp("127.0.0.1:9000"));
        let upstream = table.resolve(None);
        assert_eq!(upstream.addr, "127.0.0.1:9000");
    }

    #[test]
    fn case_insensitive_matching() {
        let table = RoutingTable::new(Upstream::tcp("127.0.0.1:9000"));
        table.register("SandBox-AbC.example.com", Upstream::tcp("10.0.0.1:8080"));

        let upstream = table.resolve(Some("sandbox-abc.example.com"));
        assert_eq!(upstream.addr, "10.0.0.1:8080");
    }

    #[test]
    fn register_and_remove() {
        let table = RoutingTable::new(Upstream::tcp("127.0.0.1:9000"));
        table.register("test.example.com", Upstream::tcp("10.0.0.1:3000"));
        assert_eq!(table.len(), 1);

        table.remove("test.example.com");
        assert_eq!(table.len(), 0);

        let upstream = table.resolve(Some("test.example.com"));
        assert_eq!(upstream.addr, "127.0.0.1:9000");
    }
}

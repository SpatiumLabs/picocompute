//! TTL-bounded, policy-epoch-scoped DNS answer cache.
//!
//! Cache entries are keyed by (sandbox_id, qname, qtype, policy_epoch).
//! When a sandbox receives a new policy with a higher epoch, all entries
//! for the old epoch are invalidated by the epoch-mismatch check.
//! Entry TTL is capped to the minimum of the DNS answer TTL and the
//! policy validity window.

use hashbrown::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A cached DNS answer record.
#[derive(Debug, Clone)]
pub struct CachedAnswer {
    pub addresses: Vec<IpAddr>,
    pub record_type: String,
    pub cached_at: Instant,
    pub ttl: Duration,
}

impl CachedAnswer {
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) >= self.ttl
    }
}

/// A per-sandbox DNS answer cache.
///
/// Each entry is keyed by (qname, qtype, policy_epoch) so that a policy
/// update (epoch change) automatically invalidates all cached answers.
#[derive(Debug, Clone)]
pub struct DnsCache {
    entries: HashMap<CacheKey, CachedAnswer>,
    max_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    sandbox_id: String,
    qname: String,
    qtype: String,
    policy_epoch: u64,
}

impl DnsCache {
    /// Create a new cache with the given capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Look up a cached answer.
    ///
    /// Returns `None` when the entry is absent, expired, or the policy
    /// epoch does not match (implicitly invalidating old-epoch entries).
    #[must_use]
    pub fn get(
        &self,
        sandbox_id: &str,
        qname: &str,
        qtype: &str,
        policy_epoch: u64,
    ) -> Option<&CachedAnswer> {
        let key = CacheKey {
            sandbox_id: sandbox_id.into(),
            qname: qname.into(),
            qtype: qtype.into(),
            policy_epoch,
        };
        let entry = self.entries.get(&key)?;
        if entry.is_expired(Instant::now()) {
            return None;
        }
        Some(entry)
    }

    /// Insert a resolved answer into the cache.
    ///
    /// TTL is capped to a reasonable maximum to prevent stale answers
    /// from persisting indefinitely. If the cache is full, the oldest
    /// entry is evicted.
    pub fn insert(
        &mut self,
        sandbox_id: &str,
        qname: &str,
        qtype: &str,
        policy_epoch: u64,
        addresses: Vec<IpAddr>,
        dns_ttl: Duration,
    ) {
        let key = CacheKey {
            sandbox_id: sandbox_id.into(),
            qname: qname.into(),
            qtype: qtype.into(),
            policy_epoch,
        };
        let ttl = dns_ttl.min(Duration::from_secs(3600)); // max 1h cache
        let entry = CachedAnswer {
            addresses,
            record_type: qtype.into(),
            cached_at: Instant::now(),
            ttl,
        };
        if self.entries.len() >= self.max_entries {
            self.evict_one();
        }
        self.entries.insert(key, entry);
    }

    /// Evict the oldest entry (by insertion order approximation).
    ///
    /// NOTE: This is O(n) over all entries and evicts only one entry.
    /// With 10k capacity and frequent inserts, consider an LRU crate
    /// or linked-list ordering for production scale.
    fn evict_one(&mut self) {
        let oldest = self
            .entries
            .values()
            .min_by_key(|e| e.cached_at)
            .map(|e| e.cached_at);
        if let Some(oldest_time) = oldest {
            self.entries.retain(|_, v| v.cached_at != oldest_time);
        }
    }

    /// Remove all cache entries for a given sandbox.
    ///
    /// Called on sandbox destroy or DNS attachment teardown.
    pub fn remove_sandbox(&mut self, sandbox_id: &str) {
        self.entries.retain(|k, _| k.sandbox_id != sandbox_id);
    }

    /// Return the current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_and_miss() {
        let mut cache = DnsCache::new(100);
        let addrs = vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))];
        cache.insert(
            "sbx",
            "example.com",
            "A",
            1,
            addrs.clone(),
            Duration::from_secs(300),
        );

        let hit = cache.get("sbx", "example.com", "A", 1);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().addresses, addrs);

        let miss = cache.get("sbx", "example.com", "A", 2);
        assert!(miss.is_none()); // epoch mismatch
    }

    #[test]
    fn epoch_change_invalidates() {
        let mut cache = DnsCache::new(100);
        cache.insert(
            "sbx",
            "example.com",
            "A",
            1,
            vec![],
            Duration::from_secs(300),
        );
        assert!(cache.get("sbx", "example.com", "A", 1).is_some());
        assert!(cache.get("sbx", "example.com", "A", 2).is_none());
    }

    #[test]
    fn different_sandbox_no_cross_access() {
        let mut cache = DnsCache::new(100);
        cache.insert(
            "sbx_a",
            "example.com",
            "A",
            1,
            vec![],
            Duration::from_secs(300),
        );
        assert!(cache.get("sbx_a", "example.com", "A", 1).is_some());
        assert!(cache.get("sbx_b", "example.com", "A", 1).is_none());
    }

    #[test]
    fn remove_sandbox_clears_entries() {
        let mut cache = DnsCache::new(100);
        cache.insert("sbx_a", "a.com", "A", 1, vec![], Duration::from_secs(300));
        cache.insert("sbx_b", "b.com", "A", 1, vec![], Duration::from_secs(300));
        cache.remove_sandbox("sbx_a");
        assert!(cache.get("sbx_a", "a.com", "A", 1).is_none());
        assert!(cache.get("sbx_b", "b.com", "A", 1).is_some());
    }

    #[test]
    fn expired_entry_returns_none() {
        let mut cache = DnsCache::new(100);
        cache.insert(
            "sbx",
            "example.com",
            "A",
            1,
            vec![],
            Duration::from_nanos(1),
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("sbx", "example.com", "A", 1).is_none());
    }
}

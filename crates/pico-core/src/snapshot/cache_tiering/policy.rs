use serde::{Deserialize, Serialize};
use time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheTier {
    HostLocal,
    CellCache,
    RegionalObjectStore,
}

impl CacheTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostLocal => "host_local",
            Self::CellCache => "cell_cache",
            Self::RegionalObjectStore => "regional_object_store",
        }
    }
}

impl std::fmt::Display for CacheTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvictionPolicyKind {
    Lru,
    Lfu,
    SizeBased,
    TimeToLive,
}

impl EvictionPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lru => "lru",
            Self::Lfu => "lfu",
            Self::SizeBased => "size_based",
            Self::TimeToLive => "ttl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvictionPolicy {
    pub kind: EvictionPolicyKind,
    pub max_entries: Option<usize>,
    pub max_size_bytes: Option<u64>,
    pub max_age: Option<humantime_serde::DurationSerde>,
}

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DurationSerde(pub time::Duration);

    impl Serialize for DurationSerde {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_u64(self.0.whole_seconds() as u64)
        }
    }

    impl<'de> Deserialize<'de> for DurationSerde {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let secs: u64 = Deserialize::deserialize(deserializer)?;
            Ok(DurationSerde(time::Duration::seconds(secs as i64)))
        }
    }
}

impl EvictionPolicy {
    pub fn lru(max_entries: usize) -> Self {
        Self {
            kind: EvictionPolicyKind::Lru,
            max_entries: Some(max_entries),
            max_size_bytes: None,
            max_age: None,
        }
    }

    pub fn size_based(max_size_bytes: u64) -> Self {
        Self {
            kind: EvictionPolicyKind::SizeBased,
            max_entries: None,
            max_size_bytes: Some(max_size_bytes),
            max_age: None,
        }
    }

    pub fn ttl(max_age: Duration) -> Self {
        Self {
            kind: EvictionPolicyKind::TimeToLive,
            max_entries: None,
            max_size_bytes: None,
            max_age: Some(humantime_serde::DurationSerde(max_age)),
        }
    }

    pub fn lru_with_size(max_entries: usize, max_size_bytes: u64) -> Self {
        Self {
            kind: EvictionPolicyKind::Lru,
            max_entries: Some(max_entries),
            max_size_bytes: Some(max_size_bytes),
            max_age: None,
        }
    }
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        Self::lru(1000)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetentionPolicy {
    pub min_retention: humantime_serde::DurationSerde,
    pub max_retention: Option<humantime_serde::DurationSerde>,
    pub require_integrity_check: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            min_retention: humantime_serde::DurationSerde(Duration::hours(24)),
            max_retention: None,
            require_integrity_check: true,
        }
    }
}

impl RetentionPolicy {
    pub fn with_min_retention(seconds: i64) -> Self {
        Self {
            min_retention: humantime_serde::DurationSerde(Duration::seconds(seconds)),
            max_retention: None,
            require_integrity_check: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TieredCachePolicy {
    pub tier: CacheTier,
    pub eviction_policy: EvictionPolicy,
    pub max_capacity_bytes: u64,
    pub prewarm_enabled: bool,
}

impl TieredCachePolicy {
    pub fn host_local(max_capacity_bytes: u64, eviction_policy: EvictionPolicy) -> Self {
        Self {
            tier: CacheTier::HostLocal,
            eviction_policy,
            max_capacity_bytes,
            prewarm_enabled: false,
        }
    }

    pub fn cell_cache(max_capacity_bytes: u64, eviction_policy: EvictionPolicy) -> Self {
        Self {
            tier: CacheTier::CellCache,
            eviction_policy,
            max_capacity_bytes,
            prewarm_enabled: true,
        }
    }

    pub fn regional(max_capacity_bytes: u64, eviction_policy: EvictionPolicy) -> Self {
        Self {
            tier: CacheTier::RegionalObjectStore,
            eviction_policy,
            max_capacity_bytes,
            prewarm_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GcPolicy {
    pub retention_policy: RetentionPolicy,
    pub tier_policies: Vec<TieredCachePolicy>,
    pub max_concurrent_deletions: usize,
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self {
            retention_policy: RetentionPolicy::default(),
            tier_policies: vec![
                TieredCachePolicy::host_local(10 * 1024 * 1024 * 1024, EvictionPolicy::default()),
                TieredCachePolicy::cell_cache(100 * 1024 * 1024 * 1024, EvictionPolicy::default()),
                TieredCachePolicy::regional(1024 * 1024 * 1024 * 1024, EvictionPolicy::default()),
            ],
            max_concurrent_deletions: 4,
        }
    }
}

impl GcPolicy {
    pub fn policy_for_tier(&self, tier: CacheTier) -> Option<&TieredCachePolicy> {
        self.tier_policies.iter().find(|p| p.tier == tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_tier_as_str() {
        assert_eq!(CacheTier::HostLocal.as_str(), "host_local");
        assert_eq!(CacheTier::CellCache.as_str(), "cell_cache");
        assert_eq!(
            CacheTier::RegionalObjectStore.as_str(),
            "regional_object_store"
        );
    }

    #[test]
    fn eviction_policy_lru() {
        let policy = EvictionPolicy::lru(500);
        assert_eq!(policy.kind, EvictionPolicyKind::Lru);
        assert_eq!(policy.max_entries, Some(500));
        assert!(policy.max_size_bytes.is_none());
    }

    #[test]
    fn eviction_policy_size_based() {
        let policy = EvictionPolicy::size_based(1024 * 1024 * 1024);
        assert_eq!(policy.kind, EvictionPolicyKind::SizeBased);
        assert_eq!(policy.max_size_bytes, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn eviction_policy_lru_with_size() {
        let policy = EvictionPolicy::lru_with_size(100, 1024 * 1024 * 1024);
        assert_eq!(policy.kind, EvictionPolicyKind::Lru);
        assert_eq!(policy.max_entries, Some(100));
        assert_eq!(policy.max_size_bytes, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn retention_policy_defaults() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.min_retention.0, Duration::hours(24));
        assert!(policy.require_integrity_check);
        assert!(policy.max_retention.is_none());
    }

    #[test]
    fn gc_policy_finds_tier_policy() {
        let policy = GcPolicy::default();
        assert!(policy.policy_for_tier(CacheTier::HostLocal).is_some());
        assert!(policy.policy_for_tier(CacheTier::CellCache).is_some());
        assert!(
            policy
                .policy_for_tier(CacheTier::RegionalObjectStore)
                .is_some()
        );
    }

    #[test]
    fn eviction_policy_default_is_lru_1000() {
        let policy = EvictionPolicy::default();
        assert_eq!(policy.kind, EvictionPolicyKind::Lru);
        assert_eq!(policy.max_entries, Some(1000));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = EvictionPolicy::lru_with_size(500, 1024 * 1024 * 1024);
        let json = serde_json::to_string(&policy).unwrap();
        let back: EvictionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.kind, back.kind);
        assert_eq!(policy.max_entries, back.max_entries);
        assert_eq!(policy.max_size_bytes, back.max_size_bytes);
    }

    #[test]
    fn tiered_cache_policy_builders() {
        let policy = TieredCachePolicy::host_local(1024, EvictionPolicy::default());
        assert_eq!(policy.tier, CacheTier::HostLocal);
        assert_eq!(policy.max_capacity_bytes, 1024);
        assert!(!policy.prewarm_enabled);

        let policy = TieredCachePolicy::cell_cache(2048, EvictionPolicy::default());
        assert_eq!(policy.tier, CacheTier::CellCache);
        assert!(policy.prewarm_enabled);

        let policy = TieredCachePolicy::regional(4096, EvictionPolicy::default());
        assert_eq!(policy.tier, CacheTier::RegionalObjectStore);
        assert!(!policy.prewarm_enabled);
    }
}

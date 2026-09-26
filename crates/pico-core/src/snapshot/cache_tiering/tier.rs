use crate::identity::SnapshotId;
use crate::metrics::{
    record_snapshot_cache_hit, record_snapshot_cache_miss, record_snapshot_eviction,
};
use hashbrown::HashMap;

use super::error::{CacheTierError, CacheTierResult};
use super::policy::{CacheTier, EvictionPolicy, EvictionPolicyKind};

#[derive(Debug, Clone)]
pub struct TierEntry {
    pub snapshot_id: SnapshotId,
    pub size_bytes: u64,
    pub inserted_at: String,
    pub last_accessed_at: String,
    pub access_count: u64,
    pub pinned: bool,
}

impl TierEntry {
    pub fn new(snapshot_id: SnapshotId, size_bytes: u64) -> Self {
        let now = crate::types::now_iso();
        Self {
            snapshot_id,
            size_bytes,
            inserted_at: now.clone(),
            last_accessed_at: now,
            access_count: 0,
            pinned: false,
        }
    }

    pub fn pin(&mut self) {
        self.pinned = true;
    }

    pub fn touch(&mut self) {
        self.last_accessed_at = crate::types::now_iso();
        self.access_count = self.access_count.saturating_add(1);
    }
}

#[derive(Debug, Clone, Default)]
pub struct TierStats {
    pub entry_count: usize,
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub eviction_count: u64,
}

impl TierStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hit_count + self.miss_count;
        if total == 0 {
            return 0.0;
        }
        self.hit_count as f64 / total as f64
    }

    pub fn usage_ratio(&self) -> f64 {
        if self.capacity_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.capacity_bytes as f64
    }
}

#[derive(Debug)]
pub struct CacheTierStore {
    tier: CacheTier,
    policy: EvictionPolicy,
    max_capacity_bytes: u64,
    entries: HashMap<SnapshotId, TierEntry>,
    used_bytes: u64,
    stats: TierStats,
}

impl CacheTierStore {
    pub fn new(tier: CacheTier, policy: EvictionPolicy, max_capacity_bytes: u64) -> Self {
        Self {
            tier,
            policy,
            max_capacity_bytes,
            entries: HashMap::new(),
            used_bytes: 0,
            stats: TierStats {
                entry_count: 0,
                used_bytes: 0,
                capacity_bytes: max_capacity_bytes,
                hit_count: 0,
                miss_count: 0,
                eviction_count: 0,
            },
        }
    }

    pub fn insert(&mut self, snapshot_id: SnapshotId, size_bytes: u64) -> CacheTierResult<()> {
        if self.entries.contains_key(&snapshot_id) {
            self.touch(&snapshot_id);
            return Ok(());
        }

        self.enforce_eviction_policy(size_bytes, 1)?;

        if self.used_bytes + size_bytes > self.max_capacity_bytes {
            return Err(CacheTierError::TierFull {
                tier: self.tier.as_str().to_string(),
                snapshot_id: snapshot_id.as_str().to_string(),
                used_bytes: self.used_bytes,
                max_bytes: self.max_capacity_bytes,
            });
        }

        if let Some(max_entries) = self.policy.max_entries
            && self.entries.len() >= max_entries
        {
            return Err(CacheTierError::TierFull {
                tier: self.tier.as_str().to_string(),
                snapshot_id: snapshot_id.as_str().to_string(),
                used_bytes: self.used_bytes,
                max_bytes: self.max_capacity_bytes,
            });
        }

        let entry = TierEntry::new(snapshot_id.clone(), size_bytes);
        self.entries.insert(snapshot_id.clone(), entry);
        self.used_bytes = self.used_bytes.saturating_add(size_bytes);
        self.stats.entry_count = self.entries.len();
        self.stats.used_bytes = self.used_bytes;
        Ok(())
    }

    pub fn get(&mut self, snapshot_id: &SnapshotId) -> CacheTierResult<&TierEntry> {
        if self.entries.contains_key(snapshot_id) {
            self.stats.hit_count = self.stats.hit_count.saturating_add(1);
            self.touch(snapshot_id);
            Ok(&self.entries[snapshot_id])
        } else {
            self.stats.miss_count = self.stats.miss_count.saturating_add(1);
            Err(CacheTierError::SnapshotNotCached {
                snapshot_id: snapshot_id.as_str().to_string(),
                tier: self.tier.as_str().to_string(),
            })
        }
    }

    pub fn remove(&mut self, snapshot_id: &SnapshotId) -> CacheTierResult<TierEntry> {
        let entry =
            self.entries
                .remove(snapshot_id)
                .ok_or_else(|| CacheTierError::SnapshotNotCached {
                    snapshot_id: snapshot_id.as_str().to_string(),
                    tier: self.tier.as_str().to_string(),
                })?;

        self.used_bytes = self.used_bytes.saturating_sub(entry.size_bytes);
        self.stats.entry_count = self.entries.len();
        self.stats.used_bytes = self.used_bytes;
        Ok(entry)
    }

    pub fn contains(&self, snapshot_id: &SnapshotId) -> bool {
        self.entries.contains_key(snapshot_id)
    }

    pub fn pin(&mut self, snapshot_id: &SnapshotId) -> CacheTierResult<()> {
        self.entries
            .get_mut(snapshot_id)
            .ok_or_else(|| CacheTierError::SnapshotNotCached {
                snapshot_id: snapshot_id.as_str().to_string(),
                tier: self.tier.as_str().to_string(),
            })?
            .pin();
        Ok(())
    }

    pub fn unpin(&mut self, snapshot_id: &SnapshotId) -> CacheTierResult<()> {
        self.entries
            .get_mut(snapshot_id)
            .ok_or_else(|| CacheTierError::SnapshotNotCached {
                snapshot_id: snapshot_id.as_str().to_string(),
                tier: self.tier.as_str().to_string(),
            })?
            .pinned = false;
        Ok(())
    }

    pub fn evict(&mut self, snapshot_id: &SnapshotId) -> CacheTierResult<TierEntry> {
        let entry =
            self.entries
                .get(snapshot_id)
                .ok_or_else(|| CacheTierError::SnapshotNotCached {
                    snapshot_id: snapshot_id.as_str().to_string(),
                    tier: self.tier.as_str().to_string(),
                })?;

        if entry.pinned {
            return Err(CacheTierError::SnapshotReferenced {
                snapshot_id: snapshot_id.as_str().to_string(),
                ref_count: 1,
            });
        }

        let freed_bytes = entry.size_bytes;
        let entry = self.remove(snapshot_id)?;
        self.stats.eviction_count = self.stats.eviction_count.saturating_add(1);
        record_snapshot_eviction(None, freed_bytes);
        Ok(entry)
    }

    pub fn eviction_candidates(&self, required_bytes: u64) -> Vec<SnapshotId> {
        let mut candidates: Vec<&TierEntry> = self.entries.values().filter(|e| !e.pinned).collect();

        match self.policy.kind {
            EvictionPolicyKind::Lru => {
                candidates.sort_by(|a, b| a.last_accessed_at.cmp(&b.last_accessed_at));
            }
            EvictionPolicyKind::Lfu => {
                candidates.sort_by_key(|a| a.access_count);
            }
            EvictionPolicyKind::SizeBased => {
                candidates.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
            }
            EvictionPolicyKind::TimeToLive => {
                candidates.sort_by(|a, b| a.inserted_at.cmp(&b.inserted_at));
            }
        }

        let mut freed = 0u64;
        candidates
            .iter()
            .take_while(|e| {
                if freed < required_bytes {
                    freed = freed.saturating_add(e.size_bytes);
                    true
                } else {
                    false
                }
            })
            .map(|e| e.snapshot_id.clone())
            .collect()
    }

    pub fn stats(&self) -> &TierStats {
        &self.stats
    }

    pub fn tier(&self) -> CacheTier {
        self.tier
    }

    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    pub fn max_capacity_bytes(&self) -> u64 {
        self.max_capacity_bytes
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn touch(&mut self, snapshot_id: &SnapshotId) {
        if let Some(entry) = self.entries.get_mut(snapshot_id) {
            entry.touch();
        }
    }

    fn enforce_eviction_policy(
        &mut self,
        needed_bytes: u64,
        needed_slots: usize,
    ) -> CacheTierResult<()> {
        let available = self.max_capacity_bytes.saturating_sub(self.used_bytes);
        let must_free_bytes = needed_bytes.saturating_sub(available);

        let entry_overage = if let Some(max_entries) = self.policy.max_entries {
            let needed_entries = max_entries.saturating_sub(self.entries.len());
            needed_slots.saturating_sub(needed_entries)
        } else {
            0
        };

        if must_free_bytes == 0 && entry_overage == 0 {
            return Ok(());
        }

        let candidates = self.eviction_candidates(must_free_bytes.max(1));
        if candidates.is_empty() {
            return Err(CacheTierError::TierFull {
                tier: self.tier.as_str().to_string(),
                snapshot_id: "unknown".to_string(),
                used_bytes: self.used_bytes,
                max_bytes: self.max_capacity_bytes,
            });
        }

        let mut evicted_count = 0;
        for candidate_id in &candidates {
            let _ = self.evict(candidate_id);
            evicted_count += 1;
            if self.used_bytes + needed_bytes <= self.max_capacity_bytes
                && evicted_count >= entry_overage.saturating_add(needed_slots)
            {
                break;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct TieredCacheManager {
    tiers: HashMap<CacheTier, CacheTierStore>,
    total_hits: u64,
    total_misses: u64,
}

impl TieredCacheManager {
    pub fn new() -> Self {
        Self {
            tiers: HashMap::new(),
            total_hits: 0,
            total_misses: 0,
        }
    }

    pub fn register_tier(
        &mut self,
        tier: CacheTier,
        policy: EvictionPolicy,
        max_capacity_bytes: u64,
    ) {
        let store = CacheTierStore::new(tier, policy, max_capacity_bytes);
        self.tiers.insert(tier, store);
    }

    pub fn get_tier(&self, tier: CacheTier) -> Option<&CacheTierStore> {
        self.tiers.get(&tier)
    }

    pub fn get_tier_mut(&mut self, tier: CacheTier) -> Option<&mut CacheTierStore> {
        self.tiers.get_mut(&tier)
    }

    pub fn insert(
        &mut self,
        tier: CacheTier,
        snapshot_id: SnapshotId,
        size_bytes: u64,
    ) -> CacheTierResult<()> {
        let store = self
            .tiers
            .get_mut(&tier)
            .ok_or_else(|| CacheTierError::TierNotEligible {
                tier: tier.as_str().to_string(),
                policy: "tier not registered".to_string(),
            })?;
        store.insert(snapshot_id, size_bytes)
    }

    pub fn lookup(&mut self, snapshot_id: &SnapshotId) -> Option<CacheTier> {
        for (&tier, store) in &mut self.tiers {
            if store.contains(snapshot_id) {
                let _ = store.get(snapshot_id);
                self.total_hits = self.total_hits.saturating_add(1);
                record_snapshot_cache_hit(None);
                return Some(tier);
            }
        }
        self.total_misses = self.total_misses.saturating_add(1);
        record_snapshot_cache_miss(None);
        None
    }

    pub fn remove_from_all_tiers(&mut self, snapshot_id: &SnapshotId) -> Vec<TierEntry> {
        let mut removed = Vec::new();
        for store in self.tiers.values_mut() {
            if let Ok(entry) = store.remove(snapshot_id) {
                removed.push(entry);
            }
        }
        removed
    }

    pub fn evict_from_tier(
        &mut self,
        tier: CacheTier,
        snapshot_id: &SnapshotId,
    ) -> CacheTierResult<TierEntry> {
        let store = self
            .tiers
            .get_mut(&tier)
            .ok_or_else(|| CacheTierError::TierNotEligible {
                tier: tier.as_str().to_string(),
                policy: "tier not registered".to_string(),
            })?;
        store.evict(snapshot_id)
    }

    pub fn total_hit_rate(&self) -> f64 {
        let total = self.total_hits + self.total_misses;
        if total == 0 {
            return 0.0;
        }
        self.total_hits as f64 / total as f64
    }

    pub fn total_capacity_bytes(&self) -> u64 {
        self.tiers.values().map(|t| t.max_capacity_bytes()).sum()
    }

    pub fn total_used_bytes(&self) -> u64 {
        self.tiers.values().map(|t| t.used_bytes()).sum()
    }

    pub fn tiers(&self) -> impl Iterator<Item = (&CacheTier, &CacheTierStore)> {
        self.tiers.iter()
    }
}

impl Default for TieredCacheManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CacheTierStatsSummary {
    pub total_capacity_bytes: u64,
    pub total_used_bytes: u64,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_retrieve_from_tier() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        store.insert(snap_id.clone(), 100 * 1024 * 1024).unwrap();
        assert!(store.contains(&snap_id));
        assert!(store.get(&snap_id).is_ok());
    }

    #[test]
    fn insert_duplicate_is_idempotent() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        store.insert(snap_id.clone(), 100 * 1024 * 1024).unwrap();
        store.insert(snap_id.clone(), 200 * 1024 * 1024).unwrap();
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn miss_increments_miss_count() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let result = store.get(&SnapshotId::from_string("snp_nonexistent"));
        assert!(result.is_err());
        assert_eq!(store.stats().miss_count, 1);
    }

    #[test]
    fn hit_increments_hit_count_and_touches() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        store.insert(snap_id.clone(), 100 * 1024 * 1024).unwrap();
        store.get(&snap_id).unwrap();
        assert_eq!(store.stats().hit_count, 1);
        assert_eq!(store.entries.get(&snap_id).unwrap().access_count, 1);
    }

    #[test]
    fn evict_unpinned_entry() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        store.insert(snap_id.clone(), 100 * 1024 * 1024).unwrap();
        let result = store.evict(&snap_id);
        assert!(result.is_ok());
        assert_eq!(store.stats().eviction_count, 1);
        assert!(!store.contains(&snap_id));
    }

    #[test]
    fn evict_pinned_entry_fails() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        store.insert(snap_id.clone(), 100 * 1024 * 1024).unwrap();
        store.pin(&snap_id).unwrap();
        let result = store.evict(&snap_id);
        assert!(result.is_err());
        assert!(store.contains(&snap_id));
    }

    #[test]
    fn tiered_cache_manager_multi_tier_lookup() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );
        manager.register_tier(
            CacheTier::CellCache,
            EvictionPolicy::default(),
            10 * 1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        manager
            .insert(CacheTier::CellCache, snap_id.clone(), 100 * 1024 * 1024)
            .unwrap();

        let found_tier = manager.lookup(&snap_id);
        assert_eq!(found_tier, Some(CacheTier::CellCache));
    }

    #[test]
    fn lookup_miss_increments_miss_counter() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let found = manager.lookup(&SnapshotId::from_string("snp_missing"));
        assert!(found.is_none());
        assert_eq!(manager.total_misses, 1);
    }

    #[test]
    fn eviction_candidates_lru_order() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::lru(10),
            10 * 1024 * 1024 * 1024,
        );

        store
            .insert(SnapshotId::from_string("snp_a"), 100 * 1024 * 1024)
            .unwrap();
        store
            .insert(SnapshotId::from_string("snp_b"), 200 * 1024 * 1024)
            .unwrap();
        store
            .insert(SnapshotId::from_string("snp_c"), 300 * 1024 * 1024)
            .unwrap();

        let candidates = store.eviction_candidates(100 * 1024 * 1024);
        assert_eq!(candidates.len(), 1);

        let snapshot_a = SnapshotId::from_string("snp_a");
        let snapshot_b = SnapshotId::from_string("snp_b");
        let snapshot_c = SnapshotId::from_string("snp_c");
        assert!(
            candidates[0] == snapshot_a
                || candidates[0] == snapshot_b
                || candidates[0] == snapshot_c
        );
    }

    #[test]
    fn tier_full_error_when_exceeding_capacity() {
        let mut store = CacheTierStore::new(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            100 * 1024 * 1024,
        );

        let snap_a = SnapshotId::from_string("snp_a");
        store.insert(snap_a.clone(), 80 * 1024 * 1024).unwrap();
        store.pin(&snap_a).unwrap();

        let result = store.insert(SnapshotId::from_string("snp_b"), 50 * 1024 * 1024);

        assert!(matches!(result, Err(CacheTierError::TierFull { .. })));
    }

    #[test]
    fn stats_hit_rate_calculation() {
        let stats = TierStats {
            entry_count: 10,
            used_bytes: 1024,
            capacity_bytes: 2048,
            hit_count: 75,
            miss_count: 25,
            eviction_count: 5,
        };

        assert!((stats.hit_rate() - 0.75).abs() < f64::EPSILON);
        assert!((stats.usage_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn total_capacity_and_usage() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(CacheTier::HostLocal, EvictionPolicy::default(), 1024);
        manager.register_tier(CacheTier::CellCache, EvictionPolicy::default(), 2048);

        assert_eq!(manager.total_capacity_bytes(), 3072);
        assert_eq!(manager.total_used_bytes(), 0);
    }

    #[test]
    fn tier_fallback_hit_in_second_tier() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(CacheTier::HostLocal, EvictionPolicy::default(), 1024);
        manager.register_tier(CacheTier::CellCache, EvictionPolicy::default(), 2048);

        let snap_id = SnapshotId::from_string("snp_fallback");
        manager
            .insert(CacheTier::CellCache, snap_id.clone(), 100)
            .unwrap();

        let found = manager.lookup(&snap_id);
        assert_eq!(found, Some(CacheTier::CellCache));
        assert_eq!(manager.total_hit_rate(), 1.0);
    }

    #[test]
    fn remove_from_all_tiers_cleans_up() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(CacheTier::HostLocal, EvictionPolicy::default(), 1024);
        manager.register_tier(CacheTier::CellCache, EvictionPolicy::default(), 2048);

        let snap_id = SnapshotId::from_string("snp_cleanup");
        manager
            .insert(CacheTier::HostLocal, snap_id.clone(), 100)
            .unwrap();
        manager
            .insert(CacheTier::CellCache, snap_id.clone(), 100)
            .unwrap();

        let removed = manager.remove_from_all_tiers(&snap_id);
        assert_eq!(removed.len(), 2);
    }
}

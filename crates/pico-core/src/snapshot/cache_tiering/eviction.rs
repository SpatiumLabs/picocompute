use crate::identity::SnapshotId;

use super::error::CacheTierError;
use super::policy::CacheTier;
use super::reference::SnapshotRefTracker;
use super::tier::TieredCacheManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvictionOutcome {
    Evicted,
    SkippedReferenced,
    SkippedPinned,
    NotInTier,
    Error,
}

#[derive(Debug, Clone)]
pub struct EvictionResult {
    pub snapshot_id: SnapshotId,
    pub tier: CacheTier,
    pub outcome: EvictionOutcome,
    pub freed_bytes: u64,
}

impl EvictionResult {
    pub fn evicted(snapshot_id: SnapshotId, tier: CacheTier, freed_bytes: u64) -> Self {
        Self {
            snapshot_id,
            tier,
            outcome: EvictionOutcome::Evicted,
            freed_bytes,
        }
    }

    pub fn skipped(snapshot_id: SnapshotId, tier: CacheTier, outcome: EvictionOutcome) -> Self {
        Self {
            snapshot_id,
            tier,
            outcome,
            freed_bytes: 0,
        }
    }
}

pub struct EvictionEngine {
    manager: TieredCacheManager,
}

impl EvictionEngine {
    pub fn new(manager: TieredCacheManager) -> Self {
        Self { manager }
    }

    pub fn evict_from_tier(
        &mut self,
        tier: CacheTier,
        snapshot_id: &SnapshotId,
        ref_tracker: &SnapshotRefTracker,
    ) -> EvictionResult {
        if ref_tracker.is_referenced(snapshot_id) {
            return EvictionResult::skipped(
                snapshot_id.clone(),
                tier,
                EvictionOutcome::SkippedReferenced,
            );
        }

        self.do_evict_from_store(tier, snapshot_id)
    }

    pub fn enforce_policy(
        &mut self,
        tier: CacheTier,
        needed_bytes: u64,
        ref_tracker: &SnapshotRefTracker,
    ) -> Vec<EvictionResult> {
        let Some(store) = self.manager.get_tier(tier) else {
            return Vec::new();
        };

        let candidates = store.eviction_candidates(needed_bytes);
        let mut results = Vec::new();

        for candidate_id in &candidates {
            if ref_tracker.is_referenced(candidate_id) {
                results.push(EvictionResult::skipped(
                    candidate_id.clone(),
                    tier,
                    EvictionOutcome::SkippedReferenced,
                ));
                continue;
            }

            results.push(self.do_evict_from_store(tier, candidate_id));
        }

        results
    }

    fn do_evict_from_store(&mut self, tier: CacheTier, snapshot_id: &SnapshotId) -> EvictionResult {
        match self.manager.evict_from_tier(tier, snapshot_id) {
            Ok(entry) => EvictionResult::evicted(snapshot_id.clone(), tier, entry.size_bytes),
            Err(CacheTierError::SnapshotReferenced { .. }) => {
                EvictionResult::skipped(snapshot_id.clone(), tier, EvictionOutcome::SkippedPinned)
            }
            Err(CacheTierError::SnapshotNotCached { .. }) => {
                EvictionResult::skipped(snapshot_id.clone(), tier, EvictionOutcome::NotInTier)
            }
            Err(_) => EvictionResult::skipped(snapshot_id.clone(), tier, EvictionOutcome::Error),
        }
    }

    pub fn lookup(&mut self, snapshot_id: &SnapshotId) -> Option<CacheTier> {
        self.manager.lookup(snapshot_id)
    }

    pub fn insert(
        &mut self,
        tier: CacheTier,
        snapshot_id: SnapshotId,
        size_bytes: u64,
    ) -> super::error::CacheTierResult<()> {
        self.manager.insert(tier, snapshot_id, size_bytes)
    }

    pub fn total_capacity_bytes(&self) -> u64 {
        self.manager.total_capacity_bytes()
    }

    pub fn total_used_bytes(&self) -> u64 {
        self.manager.total_used_bytes()
    }

    pub fn total_hit_rate(&self) -> f64 {
        self.manager.total_hit_rate()
    }

    pub fn total_evicted_bytes(results: &[EvictionResult]) -> u64 {
        results
            .iter()
            .filter(|r| r.outcome == EvictionOutcome::Evicted)
            .map(|r| r.freed_bytes)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::super::policy::EvictionPolicy;
    use super::super::reference::ReferenceSource;
    use super::*;

    #[test]
    fn evict_unreferenced_snapshot_succeeds() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        manager
            .insert(CacheTier::HostLocal, snap_id.clone(), 100 * 1024 * 1024)
            .unwrap();

        let ref_tracker = SnapshotRefTracker::new();
        let mut engine = EvictionEngine::new(manager);

        let result = engine.evict_from_tier(CacheTier::HostLocal, &snap_id, &ref_tracker);
        assert_eq!(result.outcome, EvictionOutcome::Evicted);
        assert_eq!(result.freed_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn evict_referenced_snapshot_is_skipped() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_id = SnapshotId::from_string("snp_001");
        manager
            .insert(CacheTier::HostLocal, snap_id.clone(), 100 * 1024 * 1024)
            .unwrap();

        let mut ref_tracker = SnapshotRefTracker::new();
        ref_tracker.register(super::super::reference::SnapshotReference::new(
            snap_id.clone(),
            ReferenceSource::ActiveSandbox,
            "sbx_a".to_string(),
            None,
            None,
        ));

        let mut engine = EvictionEngine::new(manager);
        let result = engine.evict_from_tier(CacheTier::HostLocal, &snap_id, &ref_tracker);
        assert_eq!(result.outcome, EvictionOutcome::SkippedReferenced);
    }

    #[test]
    fn enforce_policy_skips_referenced_entries() {
        let mut manager = TieredCacheManager::new();
        manager.register_tier(
            CacheTier::HostLocal,
            EvictionPolicy::default(),
            1024 * 1024 * 1024,
        );

        let snap_a = SnapshotId::from_string("snp_a");
        let snap_b = SnapshotId::from_string("snp_b");
        let snap_c = SnapshotId::from_string("snp_c");

        manager
            .insert(CacheTier::HostLocal, snap_a.clone(), 200 * 1024 * 1024)
            .unwrap();
        manager
            .insert(CacheTier::HostLocal, snap_b.clone(), 200 * 1024 * 1024)
            .unwrap();
        manager
            .insert(CacheTier::HostLocal, snap_c.clone(), 200 * 1024 * 1024)
            .unwrap();

        let mut ref_tracker = SnapshotRefTracker::new();
        ref_tracker.register(super::super::reference::SnapshotReference::new(
            snap_a.clone(),
            ReferenceSource::ActiveSandbox,
            "sbx_1".to_string(),
            None,
            None,
        ));

        let mut engine = EvictionEngine::new(manager);
        let results = engine.enforce_policy(CacheTier::HostLocal, 600 * 1024 * 1024, &ref_tracker);

        let skipped: Vec<_> = results
            .iter()
            .filter(|r| r.outcome == EvictionOutcome::SkippedReferenced)
            .collect();
        assert!(!skipped.is_empty());
    }

    #[test]
    fn total_evicted_bytes_aggregates_correctly() {
        let results = vec![
            EvictionResult::evicted(SnapshotId::from_string("snp_a"), CacheTier::HostLocal, 100),
            EvictionResult::skipped(
                SnapshotId::from_string("snp_b"),
                CacheTier::HostLocal,
                EvictionOutcome::SkippedReferenced,
            ),
            EvictionResult::evicted(SnapshotId::from_string("snp_c"), CacheTier::HostLocal, 200),
        ];

        assert_eq!(EvictionEngine::total_evicted_bytes(&results), 300);
    }
}

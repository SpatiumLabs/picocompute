use crate::identity::SnapshotId;
use crate::snapshot::lineage::LineageGraph;

use super::error::CacheTierResult;
use super::gc::{CacheGarbageCollector, GcMode, SnapshotRecord};
use super::policy::{CacheTier, GcPolicy};
use super::reference::{ReferenceSource, SnapshotRefTracker};
use super::tier::{CacheTierStatsSummary, TieredCacheManager};

pub struct CacheIntegration {
    gc: CacheGarbageCollector,
}

impl CacheIntegration {
    pub fn new(policy: GcPolicy, manager: TieredCacheManager, lineage: LineageGraph) -> Self {
        let ref_tracker = SnapshotRefTracker::new();
        Self {
            gc: CacheGarbageCollector::new(policy, ref_tracker, manager, lineage),
        }
    }

    pub fn lookup_snapshot(&mut self, snapshot_id: &SnapshotId) -> Option<CacheTier> {
        self.gc.lookup_snapshot(snapshot_id)
    }

    pub fn cache_snapshot(
        &mut self,
        tier: CacheTier,
        snapshot_id: SnapshotId,
        size_bytes: u64,
    ) -> CacheTierResult<()> {
        self.gc.cache_snapshot(tier, snapshot_id, size_bytes)
    }

    pub fn register_reference(&mut self, snapshot_id: SnapshotId, holder_id: String) {
        self.gc
            .register_reference(snapshot_id, ReferenceSource::ActiveSandbox, holder_id);
    }

    pub fn deregister_holder(&mut self, holder_id: &str) {
        self.gc.deregister_holder(holder_id);
    }

    pub fn run_gc(
        &mut self,
        mode: GcMode,
        known_snapshots: &[SnapshotRecord],
    ) -> CacheTierResult<super::gc::GcRunStats> {
        self.gc.run_gc(mode, known_snapshots)
    }

    pub fn run_gc_dry_run(
        &mut self,
        known_snapshots: &[SnapshotRecord],
    ) -> CacheTierResult<super::gc::GcRunStats> {
        self.gc.run_gc_dry_run(known_snapshots)
    }

    pub fn is_snapshot_referenced(&self, snapshot_id: &SnapshotId) -> bool {
        self.gc.is_referenced(snapshot_id)
    }

    pub fn cache_stats(&self) -> CacheTierStatsSummary {
        self.gc.cache_stats()
    }
}

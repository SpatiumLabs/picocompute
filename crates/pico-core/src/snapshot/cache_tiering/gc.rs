use pico_telemetry::metrics::Labels;

use crate::identity::SnapshotId;
use crate::metrics::CORE_METRICS;
use crate::snapshot::lineage::LineageGraph;
use crate::snapshot::state::SnapshotState;
use time::OffsetDateTime;

use super::error::CacheTierResult;
use super::eviction::{EvictionEngine, EvictionOutcome};
use super::policy::{CacheTier, GcPolicy, RetentionPolicy};
use super::reference::{ReferenceSource, SnapshotRefTracker};
use super::tier::TieredCacheManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GcMode {
    DryRun,
    Delete,
}

impl GcMode {
    pub fn is_dry_run(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GcOutcome {
    Deleted,
    SkippedReferenced,
    SkippedRetention,
    SkippedTerminalState,
    SkippedIntegrityFail,
    DryRunCandidate,
}

#[derive(Debug, Clone)]
pub struct GcEntryResult {
    pub snapshot_id: SnapshotId,
    pub outcome: GcOutcome,
    pub tier: Option<CacheTier>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GcRunStats {
    pub total_candidates: usize,
    pub deleted: usize,
    pub skipped_referenced: usize,
    pub skipped_retention: usize,
    pub skipped_terminal: usize,
    pub skipped_integrity: usize,
    pub total_freed_bytes: u64,
    pub duration_secs: f64,
}

impl GcRunStats {
    pub fn deletion_rate(&self) -> f64 {
        if self.total_candidates == 0 {
            return 0.0;
        }
        self.deleted as f64 / self.total_candidates as f64
    }

    fn update(&mut self, result: &GcEntryResult) {
        match result.outcome {
            GcOutcome::Deleted => self.deleted += 1,
            GcOutcome::SkippedReferenced => self.skipped_referenced += 1,
            GcOutcome::SkippedRetention => self.skipped_retention += 1,
            GcOutcome::SkippedTerminalState => self.skipped_terminal += 1,
            GcOutcome::SkippedIntegrityFail => self.skipped_integrity += 1,
            GcOutcome::DryRunCandidate => {}
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub snapshot_id: SnapshotId,
    pub state: SnapshotState,
    pub created_at: String,
    pub parent_snapshot_id: Option<SnapshotId>,
    pub total_blob_size_bytes: u64,
}

pub struct CacheGarbageCollector {
    policy: GcPolicy,
    ref_tracker: SnapshotRefTracker,
    eviction_engine: EvictionEngine,
    lineage: LineageGraph,
}

impl CacheGarbageCollector {
    pub fn new(
        policy: GcPolicy,
        ref_tracker: SnapshotRefTracker,
        manager: TieredCacheManager,
        lineage: LineageGraph,
    ) -> Self {
        Self {
            policy,
            ref_tracker,
            eviction_engine: EvictionEngine::new(manager),
            lineage,
        }
    }

    pub fn run_gc(
        &mut self,
        mode: GcMode,
        known_snapshots: &[SnapshotRecord],
    ) -> CacheTierResult<GcRunStats> {
        let start = std::time::Instant::now();
        let mut stats = GcRunStats::default();
        let is_delete_mode = mode == GcMode::Delete;

        let candidates = self.find_gc_candidates(known_snapshots, &self.policy.retention_policy);
        stats.total_candidates = candidates.len();
        // Host-level aggregates: the GC tier has no tenant context, so these stay
        // unattributed rather than inventing a tenancy dimension.
        let labels = Labels::host();
        CORE_METRICS
            .snapshot_gc_candidates
            .set(stats.total_candidates as f64, &labels);

        for candidate in &candidates {
            let result = self.process_candidate(candidate, mode);
            stats.update(&result);

            if is_delete_mode {
                match result.outcome {
                    GcOutcome::Deleted => {
                        CORE_METRICS.snapshot_gc_deleted.inc(&labels);
                        CORE_METRICS
                            .snapshot_gc_bytes_freed
                            .inc_by(candidate.total_blob_size_bytes, &labels);
                    }
                    GcOutcome::SkippedReferenced => {
                        CORE_METRICS.snapshot_gc_skipped_ref.inc(&labels);
                    }
                    GcOutcome::SkippedRetention => {
                        CORE_METRICS.snapshot_gc_skipped_retention.inc(&labels);
                    }
                    _ => {}
                }
            }
        }

        stats.duration_secs = start.elapsed().as_secs_f64();

        match mode {
            GcMode::DryRun | GcMode::Delete => {
                CORE_METRICS.snapshot_gc_passes.inc(&labels);
            }
        }

        Ok(stats)
    }

    fn find_gc_candidates(
        &self,
        known_snapshots: &[SnapshotRecord],
        retention: &RetentionPolicy,
    ) -> Vec<SnapshotRecord> {
        known_snapshots
            .iter()
            .filter(|record| {
                !record.state.is_terminal()
                    && !self.ref_tracker.is_referenced(&record.snapshot_id)
                    && !self.has_live_descendants(&record.snapshot_id)
                    && self.retention_elapsed(record, retention)
            })
            .cloned()
            .collect()
    }

    fn process_candidate(&mut self, candidate: &SnapshotRecord, mode: GcMode) -> GcEntryResult {
        let snapshot_id = candidate.snapshot_id.clone();

        if mode == GcMode::DryRun {
            return GcEntryResult {
                snapshot_id,
                outcome: GcOutcome::DryRunCandidate,
                tier: None,
                reason: None,
            };
        }

        for tier_policy in &self.policy.tier_policies {
            let tier = tier_policy.tier;
            let result = self.eviction_engine.evict_from_tier(
                tier,
                &candidate.snapshot_id,
                &self.ref_tracker,
            );

            match result.outcome {
                EvictionOutcome::Evicted => {
                    return GcEntryResult {
                        snapshot_id,
                        outcome: GcOutcome::Deleted,
                        tier: Some(tier),
                        reason: Some(format!("evicted from {}", tier.as_str())),
                    };
                }
                EvictionOutcome::SkippedReferenced => {
                    return GcEntryResult {
                        snapshot_id,
                        outcome: GcOutcome::SkippedReferenced,
                        tier: Some(tier),
                        reason: Some("still referenced".to_string()),
                    };
                }
                EvictionOutcome::NotInTier => continue,
                EvictionOutcome::SkippedPinned | EvictionOutcome::Error => {
                    return GcEntryResult {
                        snapshot_id,
                        outcome: GcOutcome::SkippedIntegrityFail,
                        tier: Some(tier),
                        reason: Some("eviction blocked".to_string()),
                    };
                }
            }
        }

        GcEntryResult {
            snapshot_id,
            outcome: GcOutcome::Deleted,
            tier: None,
            reason: Some("not cached in any tier".to_string()),
        }
    }

    fn has_live_descendants(&self, snapshot_id: &SnapshotId) -> bool {
        self.lineage
            .descendants(snapshot_id)
            .iter()
            .any(|d| self.ref_tracker.is_referenced(&d.snapshot_id))
    }

    fn retention_elapsed(&self, record: &SnapshotRecord, retention: &RetentionPolicy) -> bool {
        let created = match OffsetDateTime::parse(
            &record.created_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(dt) => dt,
            Err(_) => return false,
        };

        OffsetDateTime::now_utc() - created >= retention.min_retention.0
    }

    pub fn register_reference(
        &mut self,
        snapshot_id: SnapshotId,
        source: ReferenceSource,
        holder_id: String,
    ) {
        let reference =
            super::reference::SnapshotReference::new(snapshot_id, source, holder_id, None, None);
        self.ref_tracker.register(reference);
        CORE_METRICS.snapshot_ref_registered.inc(&Labels::host());
    }

    pub fn deregister_reference(&mut self, snapshot_id: &SnapshotId, holder_id: &str) {
        self.ref_tracker.deregister(snapshot_id, holder_id);
        CORE_METRICS.snapshot_ref_deregistered.inc(&Labels::host());
    }

    pub fn deregister_holder(&mut self, holder_id: &str) {
        self.ref_tracker.deregister_all_for_holder(holder_id);
        CORE_METRICS.snapshot_ref_deregistered.inc(&Labels::host());
    }

    pub fn reference_count(&self, snapshot_id: &SnapshotId) -> u64 {
        self.ref_tracker.ref_count(snapshot_id)
    }

    pub fn is_referenced(&self, snapshot_id: &SnapshotId) -> bool {
        self.ref_tracker.is_referenced(snapshot_id)
    }

    pub fn retention_policy(&self) -> &RetentionPolicy {
        &self.policy.retention_policy
    }

    pub fn gc_policy(&self) -> &GcPolicy {
        &self.policy
    }

    pub fn run_gc_dry_run(
        &mut self,
        known_snapshots: &[SnapshotRecord],
    ) -> CacheTierResult<GcRunStats> {
        self.run_gc(GcMode::DryRun, known_snapshots)
    }

    pub fn lookup_snapshot(&mut self, snapshot_id: &SnapshotId) -> Option<CacheTier> {
        self.eviction_engine.lookup(snapshot_id)
    }

    pub fn cache_snapshot(
        &mut self,
        tier: CacheTier,
        snapshot_id: SnapshotId,
        size_bytes: u64,
    ) -> super::error::CacheTierResult<()> {
        self.eviction_engine.insert(tier, snapshot_id, size_bytes)
    }

    pub fn cache_stats(&self) -> super::tier::CacheTierStatsSummary {
        super::tier::CacheTierStatsSummary {
            total_capacity_bytes: self.eviction_engine.total_capacity_bytes(),
            total_used_bytes: self.eviction_engine.total_used_bytes(),
            hit_rate: self.eviction_engine.total_hit_rate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(id: &str, state: SnapshotState, age_hours: i64) -> SnapshotRecord {
        let created = OffsetDateTime::now_utc() - time::Duration::hours(age_hours);
        SnapshotRecord {
            snapshot_id: SnapshotId::from_string(id),
            state,
            created_at: created
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            parent_snapshot_id: None,
            total_blob_size_bytes: 100 * 1024 * 1024,
        }
    }

    fn make_gc(policy: GcPolicy) -> CacheGarbageCollector {
        let mut manager = TieredCacheManager::new();
        for tp in &policy.tier_policies {
            manager.register_tier(tp.tier, tp.eviction_policy.clone(), tp.max_capacity_bytes);
        }
        let ref_tracker = SnapshotRefTracker::new();
        let lineage = LineageGraph::default();
        CacheGarbageCollector::new(policy, ref_tracker, manager, lineage)
    }

    #[test]
    fn dry_run_finds_candidates() {
        let policy = GcPolicy {
            retention_policy: RetentionPolicy::with_min_retention(0),
            ..Default::default()
        };
        let mut gc = make_gc(policy);
        let records = vec![
            make_record("snp_a", SnapshotState::Ready, 48),
            make_record("snp_b", SnapshotState::Ready, 48),
        ];

        let stats = gc.run_gc(GcMode::DryRun, &records).unwrap();
        assert_eq!(stats.total_candidates, 2);
        assert_eq!(stats.deleted, 0);
    }

    #[test]
    fn gc_skips_terminal_state_snapshots() {
        let policy = GcPolicy {
            retention_policy: RetentionPolicy::with_min_retention(0),
            ..Default::default()
        };
        let mut gc = make_gc(policy);
        let records = vec![
            make_record("snp_a", SnapshotState::Deleted, 48),
            make_record("snp_b", SnapshotState::Failed, 48),
            make_record("snp_c", SnapshotState::Ready, 48),
        ];

        let stats = gc.run_gc(GcMode::DryRun, &records).unwrap();
        assert_eq!(stats.total_candidates, 1);
    }

    #[test]
    fn gc_skips_referenced_snapshots() {
        let policy = GcPolicy {
            retention_policy: RetentionPolicy::with_min_retention(0),
            ..Default::default()
        };
        let mut gc = make_gc(policy);
        gc.register_reference(
            SnapshotId::from_string("snp_a"),
            ReferenceSource::ActiveSandbox,
            "sbx_1".to_string(),
        );

        let records = vec![
            make_record("snp_a", SnapshotState::Ready, 48),
            make_record("snp_b", SnapshotState::Ready, 48),
        ];

        let stats = gc.run_gc(GcMode::DryRun, &records).unwrap();
        assert_eq!(stats.total_candidates, 1);
    }

    #[test]
    fn gc_respects_retention_period() {
        let policy = GcPolicy {
            retention_policy: RetentionPolicy::with_min_retention(3600),
            ..Default::default()
        };
        let mut gc = make_gc(policy);
        let records = vec![
            make_record("snp_recent", SnapshotState::Ready, 0),
            make_record("snp_old", SnapshotState::Ready, 48),
        ];

        let stats = gc.run_gc(GcMode::DryRun, &records).unwrap();
        assert_eq!(stats.total_candidates, 1);
    }

    #[test]
    fn gc_mode_is_dry_run() {
        assert!(GcMode::DryRun.is_dry_run());
        assert!(!GcMode::Delete.is_dry_run());
    }

    #[test]
    fn gc_run_stats_deletion_rate() {
        let stats = GcRunStats {
            total_candidates: 100,
            deleted: 75,
            ..Default::default()
        };
        assert!((stats.deletion_rate() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn gc_run_stats_zero_candidates() {
        let stats = GcRunStats::default();
        assert_eq!(stats.deletion_rate(), 0.0);
    }

    #[test]
    fn deregister_holder_removes_all_references() {
        let policy = GcPolicy::default();
        let mut gc = make_gc(policy);
        gc.register_reference(
            SnapshotId::from_string("snp_a"),
            ReferenceSource::ActiveSandbox,
            "sbx_1".to_string(),
        );
        gc.register_reference(
            SnapshotId::from_string("snp_b"),
            ReferenceSource::ActiveSandbox,
            "sbx_1".to_string(),
        );

        gc.deregister_holder("sbx_1");
        assert_eq!(gc.reference_count(&SnapshotId::from_string("snp_a")), 0);
        assert_eq!(gc.reference_count(&SnapshotId::from_string("snp_b")), 0);
    }

    #[test]
    fn gc_entry_result_displays_snapshot_id() {
        let result = GcEntryResult {
            snapshot_id: SnapshotId::from_string("snp_test"),
            outcome: GcOutcome::DryRunCandidate,
            tier: None,
            reason: None,
        };
        assert_eq!(result.snapshot_id, SnapshotId::from_string("snp_test"));
    }

    #[test]
    fn dry_run_never_deletes() {
        let policy = GcPolicy {
            retention_policy: RetentionPolicy::with_min_retention(0),
            ..Default::default()
        };
        let mut gc = make_gc(policy);
        gc.cache_snapshot(
            CacheTier::HostLocal,
            SnapshotId::from_string("snp_a"),
            100 * 1024 * 1024,
        )
        .unwrap();

        let records = vec![make_record("snp_a", SnapshotState::Ready, 48)];
        let stats = gc.run_gc_dry_run(&records).unwrap();

        assert_eq!(stats.total_candidates, 1);
        assert_eq!(stats.deleted, 0);
        assert!(
            gc.lookup_snapshot(&SnapshotId::from_string("snp_a"))
                .is_some()
        );
    }

    #[test]
    fn delete_mode_removes_from_cache() {
        let policy = GcPolicy {
            retention_policy: RetentionPolicy::with_min_retention(0),
            ..Default::default()
        };
        let mut gc = make_gc(policy);
        gc.cache_snapshot(
            CacheTier::HostLocal,
            SnapshotId::from_string("snp_a"),
            100 * 1024 * 1024,
        )
        .unwrap();

        let records = vec![make_record("snp_a", SnapshotState::Ready, 48)];
        let stats = gc.run_gc(GcMode::Delete, &records).unwrap();

        assert_eq!(stats.deleted, 1);
    }

    #[test]
    fn gc_entry_result_tracks_evicted_tier() {
        let result = GcEntryResult {
            snapshot_id: SnapshotId::from_string("snp_x"),
            outcome: GcOutcome::Deleted,
            tier: Some(CacheTier::CellCache),
            reason: Some("evicted from cell_cache".to_string()),
        };
        assert_eq!(result.tier, Some(CacheTier::CellCache));
        assert_eq!(result.outcome, GcOutcome::Deleted);
        assert!(result.reason.is_some());
    }
}

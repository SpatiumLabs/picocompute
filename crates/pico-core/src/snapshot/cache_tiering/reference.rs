use hashbrown::HashMap;

use crate::identity::{SandboxId, SnapshotId};
use crate::snapshot::purpose::LineageType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReferenceSource {
    ActiveSandbox,
    ImageWarmPool,
    ForkLineage,
    ExternalRestore,
}

impl ReferenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActiveSandbox => "active_sandbox",
            Self::ImageWarmPool => "image_warm_pool",
            Self::ForkLineage => "fork_lineage",
            Self::ExternalRestore => "external_restore",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SnapshotReference {
    pub snapshot_id: SnapshotId,
    pub source: ReferenceSource,
    pub holder_id: String,
    pub sandbox_id: Option<SandboxId>,
    pub lineage_type: Option<LineageType>,
    pub registered_at: String,
    pub last_accessed_at: String,
    pub access_count: u64,
}

impl SnapshotReference {
    pub fn new(
        snapshot_id: SnapshotId,
        source: ReferenceSource,
        holder_id: String,
        sandbox_id: Option<SandboxId>,
        lineage_type: Option<LineageType>,
    ) -> Self {
        let now = crate::types::now_iso();
        Self {
            snapshot_id,
            source,
            holder_id,
            sandbox_id,
            lineage_type,
            registered_at: now.clone(),
            last_accessed_at: now,
            access_count: 0,
        }
    }

    pub fn touch(&mut self) {
        self.last_accessed_at = crate::types::now_iso();
        self.access_count = self.access_count.saturating_add(1);
    }

    pub fn is_active_sandbox(&self) -> bool {
        self.source == ReferenceSource::ActiveSandbox
    }

    pub fn is_warm_pool(&self) -> bool {
        self.source == ReferenceSource::ImageWarmPool
    }

    pub fn is_fork_lineage(&self) -> bool {
        self.source == ReferenceSource::ForkLineage
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SnapshotRefTracker {
    references: HashMap<SnapshotId, Vec<SnapshotReference>>,
}

impl SnapshotRefTracker {
    pub fn new() -> Self {
        Self {
            references: HashMap::new(),
        }
    }

    pub fn register(&mut self, reference: SnapshotReference) {
        self.references
            .entry(reference.snapshot_id.clone())
            .or_default()
            .push(reference);
    }

    pub fn deregister(
        &mut self,
        snapshot_id: &SnapshotId,
        holder_id: &str,
    ) -> Option<SnapshotReference> {
        let refs = self.references.get_mut(snapshot_id)?;
        let idx = refs.iter().position(|r| r.holder_id == holder_id)?;
        Some(refs.remove(idx))
    }

    pub fn deregister_all_for_holder(&mut self, holder_id: &str) -> Vec<SnapshotReference> {
        let mut removed = Vec::new();
        for refs in self.references.values_mut() {
            refs.retain(|r| {
                if r.holder_id == holder_id {
                    removed.push(r.clone());
                    false
                } else {
                    true
                }
            });
        }
        self.references.retain(|_, refs| !refs.is_empty());
        removed
    }

    pub fn get_references(&self, snapshot_id: &SnapshotId) -> Vec<&SnapshotReference> {
        self.references
            .get(snapshot_id)
            .map(|refs| refs.iter().collect())
            .unwrap_or_default()
    }

    pub fn ref_count(&self, snapshot_id: &SnapshotId) -> u64 {
        self.references
            .get(snapshot_id)
            .map(|refs| refs.len() as u64)
            .unwrap_or(0)
    }

    pub fn is_referenced(&self, snapshot_id: &SnapshotId) -> bool {
        self.ref_count(snapshot_id) > 0
    }

    pub fn active_sandbox_snapshots(&self) -> Vec<&SnapshotReference> {
        self.refs_by_source(ReferenceSource::ActiveSandbox)
    }

    pub fn warm_pool_snapshots(&self) -> Vec<&SnapshotReference> {
        self.refs_by_source(ReferenceSource::ImageWarmPool)
    }

    pub fn fork_lineage_snapshots(&self) -> Vec<&SnapshotReference> {
        self.refs_by_source(ReferenceSource::ForkLineage)
    }

    fn refs_by_source(&self, source: ReferenceSource) -> Vec<&SnapshotReference> {
        self.references
            .values()
            .flatten()
            .filter(|r| r.source == source)
            .collect()
    }

    pub fn all_snapshot_ids(&self) -> Vec<&SnapshotId> {
        self.references.keys().collect()
    }

    pub fn total_references(&self) -> usize {
        self.references.values().map(|refs| refs.len()).sum()
    }

    pub fn unreferenced_snapshots<'a>(
        &self,
        all_known_snapshots: &'a [SnapshotId],
    ) -> Vec<&'a SnapshotId> {
        all_known_snapshots
            .iter()
            .filter(|id| !self.is_referenced(id))
            .collect()
    }

    pub fn touch_reference(&mut self, snapshot_id: &SnapshotId, holder_id: &str) -> bool {
        if let Some(refs) = self.references.get_mut(snapshot_id)
            && let Some(r) = refs.iter_mut().find(|r| r.holder_id == holder_id)
        {
            r.touch();
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ref(snap_id: &str, source: ReferenceSource, holder: &str) -> SnapshotReference {
        SnapshotReference::new(
            SnapshotId::from_string(snap_id),
            source,
            holder.to_string(),
            None,
            None,
        )
    }

    #[test]
    fn register_and_count_references() {
        let mut tracker = SnapshotRefTracker::new();
        let snap_id = SnapshotId::from_string("snp_001");

        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "sbx_a"));
        tracker.register(make_ref("snp_001", ReferenceSource::ForkLineage, "fork_b"));

        assert_eq!(tracker.ref_count(&snap_id), 2);
        assert!(tracker.is_referenced(&snap_id));
    }

    #[test]
    fn deregister_reduces_count() {
        let mut tracker = SnapshotRefTracker::new();
        let snap_id = SnapshotId::from_string("snp_001");

        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "sbx_a"));
        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "sbx_b"));

        tracker.deregister(&snap_id, "sbx_a");
        assert_eq!(tracker.ref_count(&snap_id), 1);

        tracker.deregister(&snap_id, "sbx_b");
        assert_eq!(tracker.ref_count(&snap_id), 0);
        assert!(!tracker.is_referenced(&snap_id));
    }

    #[test]
    fn deregister_all_for_holder_removes_bulk() {
        let mut tracker = SnapshotRefTracker::new();

        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "sbx_a"));
        tracker.register(make_ref("snp_002", ReferenceSource::ActiveSandbox, "sbx_a"));
        tracker.register(make_ref("snp_003", ReferenceSource::ActiveSandbox, "sbx_b"));

        let removed = tracker.deregister_all_for_holder("sbx_a");
        assert_eq!(removed.len(), 2);
        assert_eq!(tracker.ref_count(&SnapshotId::from_string("snp_001")), 0);
        assert_eq!(tracker.ref_count(&SnapshotId::from_string("snp_002")), 0);
        assert_eq!(tracker.ref_count(&SnapshotId::from_string("snp_003")), 1);
    }

    #[test]
    fn unreferenced_snapshots_finds_gc_candidates() {
        let mut tracker = SnapshotRefTracker::new();
        let known = vec![
            SnapshotId::from_string("snp_a"),
            SnapshotId::from_string("snp_b"),
            SnapshotId::from_string("snp_c"),
        ];

        tracker.register(make_ref("snp_a", ReferenceSource::ActiveSandbox, "sbx_1"));

        let unreferenced = tracker.unreferenced_snapshots(&known);
        assert_eq!(unreferenced.len(), 2);
    }

    #[test]
    fn touch_reference_updates_access_count() {
        let mut tracker = SnapshotRefTracker::new();
        let snap_id = SnapshotId::from_string("snp_001");

        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "sbx_a"));

        tracker.touch_reference(&snap_id, "sbx_a");
        tracker.touch_reference(&snap_id, "sbx_a");

        let refs = tracker.get_references(&snap_id);
        assert_eq!(refs[0].access_count, 2);
    }

    #[test]
    fn active_sandbox_snapshots_filter() {
        let mut tracker = SnapshotRefTracker::new();
        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "sbx_a"));
        tracker.register(make_ref(
            "snp_002",
            ReferenceSource::ImageWarmPool,
            "pool_a",
        ));

        let active = tracker.active_sandbox_snapshots();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].source, ReferenceSource::ActiveSandbox);
    }

    #[test]
    fn warm_pool_and_fork_lineage_filters() {
        let mut tracker = SnapshotRefTracker::new();
        tracker.register(make_ref(
            "snp_001",
            ReferenceSource::ImageWarmPool,
            "pool_a",
        ));
        tracker.register(make_ref("snp_002", ReferenceSource::ForkLineage, "fork_a"));
        tracker.register(make_ref("snp_003", ReferenceSource::ActiveSandbox, "sbx_a"));

        assert_eq!(tracker.warm_pool_snapshots().len(), 1);
        assert_eq!(tracker.fork_lineage_snapshots().len(), 1);
    }

    #[test]
    fn total_references_across_all_snapshots() {
        let mut tracker = SnapshotRefTracker::new();
        tracker.register(make_ref("snp_001", ReferenceSource::ActiveSandbox, "a"));
        tracker.register(make_ref("snp_001", ReferenceSource::ForkLineage, "b"));
        tracker.register(make_ref("snp_002", ReferenceSource::ImageWarmPool, "c"));

        assert_eq!(tracker.total_references(), 3);
    }
}

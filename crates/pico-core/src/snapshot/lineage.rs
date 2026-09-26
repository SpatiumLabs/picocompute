//! Snapshot lineage records.
//!
//! Supports parent/child traversal for snapshot lineage queries.
//! Per ADR-0007, every fork records source sandbox, source snapshot,
//! child sandbox, workspace reference, and fork operation identity.

use serde::{Deserialize, Serialize};

use crate::identity::OperationId;
use crate::identity::SandboxId;
use crate::identity::SnapshotId;

use super::profile::SnapshotProfile;
use super::purpose::{LineageType, SnapshotPurpose};

/// A single lineage edge connecting a snapshot to its parent.
///
/// Supports forward (parent to child) and reverse (child to parent)
/// traversal for lineage queries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotLineage {
    /// The snapshot this lineage record belongs to.
    pub snapshot_id: SnapshotId,
    /// The sandbox that owns this snapshot.
    pub sandbox_id: SandboxId,
    /// The parent snapshot ID (if any).
    #[serde(default)]
    pub parent_snapshot_id: Option<SnapshotId>,
    /// The parent sandbox ID for fork snapshots.
    #[serde(default)]
    pub parent_sandbox_id: Option<SandboxId>,
    /// Type of lineage relationship.
    pub lineage_type: LineageType,
    /// Snapshot purpose for this entry.
    pub purpose: SnapshotPurpose,
    /// State profile of this snapshot.
    pub profile: SnapshotProfile,
    /// Operation that created this snapshot.
    pub operation_id: OperationId,
    /// Workspace or layer reference for the child.
    #[serde(default)]
    pub workspace_ref: Option<String>,
    /// When this lineage entry was created (ISO 8601 UTC).
    pub created_at: String,
}

impl SnapshotLineage {
    /// True if this is a root snapshot with no parent.
    pub fn is_root(&self) -> bool {
        self.parent_snapshot_id.is_none()
    }

    /// True if this snapshot was created by a fork operation.
    pub fn is_fork(&self) -> bool {
        self.lineage_type == LineageType::Fork
    }

    /// True if this snapshot has a parent in the same sandbox.
    pub fn is_direct_child(&self) -> bool {
        self.lineage_type == LineageType::Direct
    }

    /// Returns whether this entry is a direct child (has a parent).
    ///
    /// See [`LineageGraph::ancestors`] for full chain depth traversal.
    pub fn is_child(&self) -> bool {
        !self.is_root()
    }
}

/// A collection of lineage entries for traversal queries.
///
/// Supports building a chain from a snapshot back to its root,
/// and finding all children of a given snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LineageGraph {
    /// All lineage edges, indexed by snapshot ID.
    pub edges: Vec<SnapshotLineage>,
}

impl LineageGraph {
    /// Returns all ancestors of a snapshot, ordered from nearest to root.
    pub fn ancestors(&self, snapshot_id: &SnapshotId) -> Vec<&SnapshotLineage> {
        let mut result = Vec::new();
        let mut current = snapshot_id.clone();
        while let Some(edge) = self.edges.iter().find(|e| e.snapshot_id == current) {
            if let Some(ref parent_id) = edge.parent_snapshot_id {
                result.push(edge);
                current = parent_id.clone();
            } else {
                result.push(edge);
                break;
            }
        }
        result
    }

    /// Returns all direct children of a snapshot.
    pub fn children(&self, parent_id: &SnapshotId) -> Vec<&SnapshotLineage> {
        self.edges
            .iter()
            .filter(|e| e.parent_snapshot_id.as_ref() == Some(parent_id))
            .collect()
    }

    /// Returns all descendants (children, grandchildren, etc.) of a snapshot.
    pub fn descendants(&self, root_id: &SnapshotId) -> Vec<&SnapshotLineage> {
        let mut result = Vec::new();
        let mut queue: Vec<SnapshotId> = vec![root_id.clone()];
        while let Some(parent) = queue.pop() {
            for child in self.children(&parent) {
                result.push(child);
                queue.push(child.snapshot_id.clone());
            }
        }
        result
    }

    /// Returns true if there is a lineage path from `ancestor` to `descendant`.
    pub fn is_descendant_of(&self, descendant: &SnapshotId, ancestor: &SnapshotId) -> bool {
        if descendant == ancestor {
            return true;
        }
        let mut current = descendant.clone();
        loop {
            let Some(edge) = self.edges.iter().find(|e| e.snapshot_id == current) else {
                return false;
            };
            match &edge.parent_snapshot_id {
                Some(parent) if parent == ancestor => return true,
                Some(parent) => current = parent.clone(),
                None => return false,
            }
        }
    }

    /// Returns true if there is a cycle in the lineage graph.
    ///
    /// Should always return false for valid data; this is a safety check.
    pub fn has_cycle(&self) -> bool {
        for edge in &self.edges {
            let mut visited: Vec<&SnapshotId> = vec![&edge.snapshot_id];
            let mut current = edge.parent_snapshot_id.as_ref();
            while let Some(id) = current {
                if visited.contains(&id) {
                    return true;
                }
                visited.push(id);
                current = self
                    .edges
                    .iter()
                    .find(|e| &e.snapshot_id == id)
                    .and_then(|e| e.parent_snapshot_id.as_ref());
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot_id(prefix: &str) -> SnapshotId {
        SnapshotId::from_string(format!("snp_{prefix}"))
    }

    fn make_sandbox_id(prefix: &str) -> SandboxId {
        SandboxId::from_string(format!("sbx_{prefix}"))
    }

    fn make_op_id(num: u8) -> OperationId {
        OperationId::from_string(format!("opr_test_{num:02}"))
    }

    fn make_edge(
        snap_id: &str,
        sandbox_id: &str,
        parent_snap: Option<&str>,
        parent_sandbox: Option<&str>,
        lineage_type: LineageType,
    ) -> SnapshotLineage {
        SnapshotLineage {
            snapshot_id: make_snapshot_id(snap_id),
            sandbox_id: make_sandbox_id(sandbox_id),
            parent_snapshot_id: parent_snap.map(make_snapshot_id),
            parent_sandbox_id: parent_sandbox.map(make_sandbox_id),
            lineage_type,
            purpose: SnapshotPurpose::Session,
            profile: SnapshotProfile::Filesystem,
            operation_id: make_op_id(1),
            workspace_ref: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn root_snapshot_has_no_parent() {
        let edge = make_edge("root", "sbx_a", None, None, LineageType::Root);
        assert!(edge.is_root());
        assert!(!edge.is_fork());
        assert!(!edge.is_child());
    }

    #[test]
    fn direct_child_has_parent() {
        let edge = make_edge("child", "sbx_a", Some("parent"), None, LineageType::Direct);
        assert!(!edge.is_root());
        assert!(edge.is_direct_child());
        assert!(edge.is_child());
    }

    #[test]
    fn fork_has_parent_and_different_sandbox() {
        let edge = make_edge(
            "fork_snap",
            "sbx_child",
            Some("source_snap"),
            Some("sbx_parent"),
            LineageType::Fork,
        );
        assert!(edge.is_fork());
        assert!(!edge.is_root());
    }

    #[test]
    fn ancestors_traversal() {
        let mut graph = LineageGraph::default();
        graph.edges.push(make_edge(
            "s3",
            "sbx_a",
            Some("s2"),
            None,
            LineageType::Direct,
        ));
        graph.edges.push(make_edge(
            "s2",
            "sbx_a",
            Some("s1"),
            None,
            LineageType::Direct,
        ));
        graph
            .edges
            .push(make_edge("s1", "sbx_a", None, None, LineageType::Root));

        let ancestors = graph.ancestors(&make_snapshot_id("s3"));
        // Should be: s3, s2, s1
        assert_eq!(ancestors.len(), 3);
        assert_eq!(ancestors[0].snapshot_id, make_snapshot_id("s3"));
        assert_eq!(ancestors[1].snapshot_id, make_snapshot_id("s2"));
        assert_eq!(ancestors[2].snapshot_id, make_snapshot_id("s1"));
    }

    #[test]
    fn children_query() {
        let mut graph = LineageGraph::default();
        let parent_id = make_snapshot_id("parent");
        graph.edges.push(make_edge(
            "child1",
            "sbx_a",
            Some("parent"),
            None,
            LineageType::Direct,
        ));
        graph.edges.push(make_edge(
            "child2",
            "sbx_b",
            Some("parent"),
            Some("sbx_a"),
            LineageType::Fork,
        ));
        graph.edges.push(make_edge(
            "unrelated",
            "sbx_c",
            None,
            None,
            LineageType::Root,
        ));

        let children = graph.children(&parent_id);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn descendants_traversal() {
        let mut graph = LineageGraph::default();
        graph.edges.push(make_edge(
            "c1a",
            "sbx_a",
            Some("root"),
            None,
            LineageType::Direct,
        ));
        graph.edges.push(make_edge(
            "c2a",
            "sbx_a",
            Some("c1a"),
            None,
            LineageType::Direct,
        ));
        graph.edges.push(make_edge(
            "c1b",
            "sbx_b",
            Some("root"),
            Some("sbx_a"),
            LineageType::Fork,
        ));
        graph.edges.push(make_edge(
            "c2b",
            "sbx_b",
            Some("c1b"),
            None,
            LineageType::Direct,
        ));

        let descendants = graph.descendants(&make_snapshot_id("root"));
        assert_eq!(descendants.len(), 4);
    }

    #[test]
    fn is_descendant_of() {
        let mut graph = LineageGraph::default();
        graph.edges.push(make_edge(
            "child",
            "sbx_a",
            Some("parent"),
            None,
            LineageType::Direct,
        ));
        graph
            .edges
            .push(make_edge("parent", "sbx_a", None, None, LineageType::Root));

        assert!(graph.is_descendant_of(&make_snapshot_id("child"), &make_snapshot_id("parent")));
        assert!(!graph.is_descendant_of(&make_snapshot_id("parent"), &make_snapshot_id("child")));
        assert!(graph.is_descendant_of(&make_snapshot_id("parent"), &make_snapshot_id("parent")));
    }

    #[test]
    fn has_cycle_no_cycle() {
        let mut graph = LineageGraph::default();
        graph.edges.push(make_edge(
            "s2",
            "sbx_a",
            Some("s1"),
            None,
            LineageType::Direct,
        ));
        graph
            .edges
            .push(make_edge("s1", "sbx_a", None, None, LineageType::Root));
        assert!(!graph.has_cycle());
    }

    #[test]
    fn has_cycle_detects_cycle() {
        let mut graph = LineageGraph::default();
        graph.edges.push(make_edge(
            "s1",
            "sbx_a",
            Some("s2"),
            None,
            LineageType::Direct,
        ));
        graph.edges.push(make_edge(
            "s2",
            "sbx_a",
            Some("s1"),
            None,
            LineageType::Direct,
        ));
        assert!(graph.has_cycle());
    }

    #[test]
    fn empty_graph_no_cycle() {
        let graph = LineageGraph::default();
        assert!(!graph.has_cycle());
    }

    #[test]
    fn lineage_serde_roundtrip() {
        let edge = make_edge("s1", "sbx_a", None, None, LineageType::Root);
        let json = serde_json::to_string(&edge).unwrap();
        let back: SnapshotLineage = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }
}

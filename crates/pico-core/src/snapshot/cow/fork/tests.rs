use super::*;
use std::sync::Arc;

use crate::identity::SandboxId;
use crate::snapshot::cow::{CowEngine, CowWorkspaceState};

fn make_test_sandbox() -> SandboxId {
    SandboxId::from_string("sbx_fork_test")
}

fn make_fork_manager() -> (Arc<ForkManager>, CowWorkspace) {
    let engine: Arc<dyn CowWorkspaceManager> = Arc::new(CowEngine::new());
    let manager = Arc::new(ForkManager::new(
        engine,
        ForkManager::default_max_fork_depth(),
    ));
    let root = manager
        .create_root_workspace(make_test_sandbox(), 4096)
        .expect("failed to create root workspace");
    (manager, root)
}

fn make_fork_request(
    parent_id: &WorkspaceId,
    child_sandbox: &str,
    overlay_size: u64,
) -> ForkRequest {
    ForkRequest {
        parent_workspace_id: parent_id.clone(),
        child_sandbox_id: SandboxId::from_string(child_sandbox),
        operation_id: OperationId::generate(),
        overlay_size_bytes: overlay_size,
    }
}

mod fork_production {
    use super::*;

    #[test]
    fn succeeds_with_valid_parent() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_child", 1024);

        let outcome = manager
            .fork_workspace(&request)
            .expect("fork should succeed");

        assert_eq!(outcome.result.parent_workspace_id, root.id);
        assert_eq!(outcome.result.shared_layer_count, 1);
        assert!(outcome.result.shared_bytes > 0);
        assert_eq!(
            outcome.child_workspace.parent_workspace_id,
            Some(root.id.clone())
        );
        assert_eq!(outcome.child_workspace.overlay_layer_count(), 1);
        assert!(outcome.child_workspace.is_active());
        assert!(outcome.parent_workspace.is_active());
    }

    #[test]
    fn child_receives_own_identity() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_child_identity", 256);

        let outcome = manager.fork_workspace(&request).unwrap();

        assert_ne!(outcome.child_workspace.id, root.id);
        assert_ne!(outcome.child_workspace.sandbox_id, root.sandbox_id);
        assert_eq!(
            outcome.child_workspace.sandbox_id,
            SandboxId::from_string("sbx_child_identity")
        );
        assert!(outcome.child_workspace.id.as_str().starts_with("wsp_"));
    }

    #[test]
    fn quota_tracks_shared_and_private_bytes() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_quota", 2048);

        let outcome = manager.fork_workspace(&request).unwrap();

        let quota = manager
            .compute_quota(&outcome.result.child_workspace_id)
            .unwrap();
        assert_eq!(quota.shared_bytes, 4096);
        assert_eq!(quota.private_bytes, 2048);
        assert_eq!(quota.total_bytes(), 6144);

        let parent_quota = manager.compute_quota(&root.id).unwrap();
        assert_eq!(parent_quota.shared_bytes, 4096);
        assert_eq!(parent_quota.private_bytes, 0);
    }

    #[test]
    fn parent_writes_diverge_safely_after_fork() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_div", 512);

        let outcome = manager.fork_workspace(&request).unwrap();

        // Verify child has independent overlay
        let child = manager
            .get_workspace(&outcome.result.child_workspace_id)
            .unwrap();
        let parent = manager.get_workspace(&root.id).unwrap();

        assert_eq!(child.layers[0].blob_ref, parent.layers[0].blob_ref);
        // Child overlay is independent
        assert_ne!(child.overlay_layer_count(), parent.overlay_layer_count());
    }

    #[test]
    fn from_non_active_parent_fails() {
        // Fork from a non-active parent should fail at the ForkManager level.
        // We test this by creating a root, freezing it via the concrete engine,
        // then attempting a fork through the ForkManager.
        let engine = Arc::new(CowEngine::new());
        let manager = ForkManager::new(
            Arc::<CowEngine>::clone(&engine),
            ForkManager::default_max_fork_depth(),
        );
        let root = manager
            .create_root_workspace(SandboxId::from_string("sbx_frozen"), 1024)
            .unwrap();

        // Freeze the workspace via low-level engine access
        {
            let mut guard = engine.workspaces.write();
            if let Some(ws) = guard.get_mut(&root.id) {
                ws.state = CowWorkspaceState::Frozen;
            }
        }

        let request = make_fork_request(&root.id, "sbx_child", 512);
        let result = manager.fork_workspace(&request);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "fork from non-active parent should fail"
        );
    }

    #[test]
    fn lineage_recorded_after_fork() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_lineage", 512);

        let _outcome = manager.fork_workspace(&request).unwrap();

        let children = manager.get_children(&root.id);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].parent_workspace_id, root.id);
        assert_eq!(children[0].shared_layer_count, 1);
        assert!(!children[0].created_at.is_empty());
    }

    #[test]
    fn forked_metadata_queryable_by_parent() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_queryable", 1024);

        let outcome = manager.fork_workspace(&request).unwrap();

        let children = manager.get_children(&root.id);
        let child = children
            .iter()
            .find(|l| l.child_workspace_id == outcome.result.child_workspace_id);
        assert!(
            child.is_some(),
            "forked child should be queryable by parent sandbox"
        );
    }

    #[test]
    fn forked_metadata_queryable_by_child() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_cq", 512);

        let outcome = manager.fork_workspace(&request).unwrap();

        let parent = manager.get_parent(&outcome.result.child_workspace_id);
        assert_eq!(parent, Some(root.id));
    }

    #[test]
    fn aggregate_quota_across_sandbox() {
        let (manager, root) = make_fork_manager();
        let same_sandbox = root.sandbox_id.clone();
        let _c1 = manager
            .fork_workspace(&make_fork_request(&root.id, same_sandbox.as_str(), 256))
            .unwrap();
        let _c2 = manager
            .fork_workspace(&make_fork_request(&root.id, same_sandbox.as_str(), 512))
            .unwrap();

        let agg = manager.aggregate_quota(&root.sandbox_id).unwrap();
        // 1 root + 2 children all in same sandbox, each with 4096 shared bytes
        assert_eq!(agg.total_shared_bytes, 4096 * 3);
        // Each child has overlay private bytes: 256 + 512 = 768
        assert!(agg.total_private_bytes >= 768);
    }

    #[test]
    fn deep_chain_shares_root_base_layer() {
        let (manager, root) = make_fork_manager();
        let f1 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_d1", 100))
            .unwrap();
        let f2 = manager
            .fork_workspace(&make_fork_request(
                &f1.result.child_workspace_id,
                "sbx_d2",
                200,
            ))
            .unwrap();
        let f3 = manager
            .fork_workspace(&make_fork_request(
                &f2.result.child_workspace_id,
                "sbx_d3",
                300,
            ))
            .unwrap();

        let c3 = manager
            .get_workspace(&f3.result.child_workspace_id)
            .unwrap();
        assert_eq!(c3.base_layer_count(), 1);
        assert_eq!(c3.overlay_layer_count(), 1);
        assert_eq!(c3.layers[0].blob_ref, root.layers[0].blob_ref);
    }
}

mod fork_depth_limits {
    use super::*;

    /// Helper: creates a ForkManager with a specific max_fork_depth.
    fn make_limited_manager(max_depth: u32) -> (Arc<ForkManager>, CowWorkspace) {
        let engine: Arc<dyn CowWorkspaceManager> = Arc::new(CowEngine::new());
        let manager = Arc::new(ForkManager::new(engine, max_depth));
        let root = manager
            .create_root_workspace(SandboxId::from_string("sbx_depth"), 4096)
            .expect("failed to create root workspace");
        (manager, root)
    }

    #[test]
    fn fork_at_depth_limit_succeeds() {
        // max_fork_depth=3 should allow a chain of depth 3 (root -> 1 -> 2 -> 3).
        let (manager, root) = make_limited_manager(3);

        let f1 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_d1", 100))
            .unwrap();
        let f2 = manager
            .fork_workspace(&make_fork_request(
                &f1.result.child_workspace_id,
                "sbx_d2",
                100,
            ))
            .unwrap();
        let _f3 = manager
            .fork_workspace(&make_fork_request(
                &f2.result.child_workspace_id,
                "sbx_d3",
                100,
            ))
            .unwrap();

        // Verify lineage records have correct fork depths
        let children_1 = manager.get_children(&root.id);
        assert_eq!(children_1[0].fork_depth, 1);

        let children_2 = manager.get_children(&f1.result.child_workspace_id);
        assert_eq!(children_2[0].fork_depth, 2);

        let children_3 = manager.get_children(&f2.result.child_workspace_id);
        assert_eq!(children_3[0].fork_depth, 3);

        // All three forks succeeded
        assert_eq!(manager.workspace_count(), 4); // root + 3 children
    }

    #[test]
    fn fork_beyond_depth_limit_fails() {
        // max_fork_depth=2 should reject a 3rd-deep fork (root -> 1 -> 2 -> REJECT).
        let (manager, root) = make_limited_manager(2);

        let f1 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_d1", 100))
            .unwrap();
        let f2 = manager
            .fork_workspace(&make_fork_request(
                &f1.result.child_workspace_id,
                "sbx_d2",
                100,
            ))
            .unwrap();

        // Third-deep fork should be rejected
        let result = manager.fork_workspace(&make_fork_request(
            &f2.result.child_workspace_id,
            "sbx_d3",
            100,
        ));
        let err = result.as_ref().unwrap_err();
        assert!(
            matches!(
                err,
                SnapshotError::ForkDepthExceeded {
                    max_depth: 2,
                    actual_depth: 3
                }
            ),
            "fork beyond max depth should fail with ForkDepthExceeded"
        );
        // Verify the exact error message (regression: max_depth must be redacted
        // from Display to avoid leaking the security control threshold).
        assert_eq!(
            err.to_string(),
            "fork depth exceeded: maximum depth exceeded (actual: 3)"
        );

        // Workspace count should still be 3 (root + 2 children, the third was rejected)
        assert_eq!(manager.workspace_count(), 3);
    }

    #[test]
    fn zero_max_depth_disables_check() {
        // max_fork_depth=0 should disable the check, allowing any depth.
        let (manager, root) = make_limited_manager(0);

        let f1 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_d1", 100))
            .unwrap();
        let f2 = manager
            .fork_workspace(&make_fork_request(
                &f1.result.child_workspace_id,
                "sbx_d2",
                100,
            ))
            .unwrap();
        let f3 = manager
            .fork_workspace(&make_fork_request(
                &f2.result.child_workspace_id,
                "sbx_d3",
                100,
            ))
            .unwrap();
        let _f4 = manager
            .fork_workspace(&make_fork_request(
                &f3.result.child_workspace_id,
                "sbx_d4",
                100,
            ))
            .unwrap();

        // All four forks succeeded
        assert_eq!(manager.workspace_count(), 5); // root + 4 children
        assert_eq!(
            manager.get_children(&f3.result.child_workspace_id)[0].fork_depth,
            4
        );
    }

    #[test]
    fn idempotent_fork_respected_after_depth_rejection() {
        // A failed depth check should not corrupt the idempotency registry
        // for unrelated operation IDs.
        let (manager, root) = make_limited_manager(1);

        // First fork succeeds (depth 1) — use a specific operation ID for idempotency.
        let op_id_1 = OperationId::generate();
        let req_1 = ForkRequest {
            parent_workspace_id: root.id.clone(),
            child_sandbox_id: SandboxId::from_string("sbx_d1"),
            operation_id: op_id_1.clone(),
            overlay_size_bytes: 100,
        };
        let f1 = manager.fork_workspace(&req_1).unwrap();

        // Second fork from the same root with a different operation ID
        // should succeed (different child, same depth 1).
        let op_id_1b = OperationId::generate();
        let req_1b = ForkRequest {
            parent_workspace_id: root.id.clone(),
            child_sandbox_id: SandboxId::from_string("sbx_d1b"),
            operation_id: op_id_1b,
            overlay_size_bytes: 100,
        };
        let _f1b = manager.fork_workspace(&req_1b).unwrap();
        assert_eq!(manager.workspace_count(), 3); // root + 2 children

        // Fork from the first child should be rejected (depth would be 2, max is 1)
        let op_id_2 = OperationId::generate();
        let req_2 = ForkRequest {
            parent_workspace_id: f1.result.child_workspace_id.clone(),
            child_sandbox_id: SandboxId::from_string("sbx_d2"),
            operation_id: op_id_2,
            overlay_size_bytes: 100,
        };
        let result = manager.fork_workspace(&req_2);
        assert!(
            matches!(result, Err(SnapshotError::ForkDepthExceeded { .. })),
            "should reject deep fork"
        );

        // Idempotent retry of the first fork with the same operation ID
        // should return the existing child (no new workspace).
        let retry = manager.fork_workspace(&req_1).unwrap();
        assert_eq!(
            retry.result.child_workspace_id,
            f1.result.child_workspace_id
        );
        assert_eq!(manager.workspace_count(), 3); // no new workspace created
    }

    #[test]
    fn fork_depth_reflects_in_lineage() {
        // Verify that fork_depth is correctly recorded in CowLineage records
        // and matches the expected depth from root.
        let (manager, root) = make_limited_manager(5);

        let f1 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_l1", 100))
            .unwrap();
        let f2 = manager
            .fork_workspace(&make_fork_request(
                &f1.result.child_workspace_id,
                "sbx_l2",
                100,
            ))
            .unwrap();
        let _f3 = manager
            .fork_workspace(&make_fork_request(
                &f2.result.child_workspace_id,
                "sbx_l3",
                100,
            ))
            .unwrap();

        // Check lineage depths via get_children
        let lineages_1 = manager.get_children(&root.id);
        assert_eq!(lineages_1.len(), 1);
        assert_eq!(lineages_1[0].fork_depth, 1);

        let lineages_2 = manager.get_children(&f1.result.child_workspace_id);
        assert_eq!(lineages_2.len(), 1);
        assert_eq!(lineages_2[0].fork_depth, 2);

        let lineages_3 = manager.get_children(&f2.result.child_workspace_id);
        assert_eq!(lineages_3.len(), 1);
        assert_eq!(lineages_3[0].fork_depth, 3);

        // Check all_lineages includes all records
        let all = manager.all_lineages();
        assert_eq!(all.len(), 3);
        assert!(all.iter().any(|l| l.fork_depth == 1));
        assert!(all.iter().any(|l| l.fork_depth == 2));
        assert!(all.iter().any(|l| l.fork_depth == 3));
    }
}

mod idempotency {
    use super::*;

    #[test]
    fn same_operation_id_returns_existing_child() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_idem", 1024);

        let outcome1 = manager
            .fork_workspace(&request)
            .expect("first fork should succeed");
        let outcome2 = manager
            .fork_workspace(&request)
            .expect("second fork should succeed (idempotent)");

        // Same child workspace returned
        assert_eq!(
            outcome1.result.child_workspace_id,
            outcome2.result.child_workspace_id
        );
        // Only one workspace was actually created
        assert_eq!(manager.workspace_count(), 2); // root + 1 child
    }

    #[test]
    fn idempotent_fork_preserves_workspace_count() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_idem2", 512);

        assert_eq!(manager.workspace_count(), 1); // root only

        let _first = manager.fork_workspace(&request).unwrap();
        assert_eq!(manager.workspace_count(), 2); // root + 1 child

        let _second = manager.fork_workspace(&request).unwrap();
        assert_eq!(manager.workspace_count(), 2); // still root + 1 child (no duplicate)
    }

    #[test]
    fn different_operation_ids_create_different_children() {
        let (manager, root) = make_fork_manager();

        let req1 = ForkRequest {
            parent_workspace_id: root.id.clone(),
            child_sandbox_id: SandboxId::from_string("sbx_d1"),
            operation_id: OperationId::generate(),
            overlay_size_bytes: 100,
        };
        let req2 = ForkRequest {
            parent_workspace_id: root.id.clone(),
            child_sandbox_id: SandboxId::from_string("sbx_d2"),
            operation_id: OperationId::generate(),
            overlay_size_bytes: 200,
        };

        let r1 = manager.fork_workspace(&req1).unwrap();
        let r2 = manager.fork_workspace(&req2).unwrap();

        assert_ne!(r1.result.child_workspace_id, r2.result.child_workspace_id);
        assert_eq!(manager.workspace_count(), 3); // root + 2 children
    }

    #[test]
    fn clear_idempotency_key_allows_new_fork() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_clear", 512);

        let _first = manager.fork_workspace(&request).unwrap();
        assert_eq!(manager.idempotency_key_count(), 1);

        manager.clear_idempotency_key(&request.operation_id);
        assert_eq!(manager.idempotency_key_count(), 0);

        // Workspace count unchanged (child still exists, idempotency key just removed)
        assert_eq!(manager.workspace_count(), 2);
    }

    #[test]
    fn concurrent_same_operation_id_second_gets_conflict() {
        // Simulate the TOCTOU scenario: a second caller with the same
        // operation_id races after the first reserves the slot but
        // before it completes.
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_race", 512);

        // Manually reserve the slot (simulates first caller winning the race)
        {
            let mut registry = manager.idempotency_registry.write();
            registry.insert(request.operation_id.clone(), None);
        }
        assert!(manager.is_fork_in_progress(&request.operation_id));

        // Second caller with same operation_id should get a conflict
        let result = manager.fork_workspace(&request);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "concurrent caller should get OperationConflict when fork is in progress"
        );

        // Clean up the reservation
        manager.clear_idempotency_key(&request.operation_id);
    }

    #[test]
    fn fork_failure_removes_reservation() {
        // When a fork fails after reserving the idempotency slot,
        // the reservation should be removed so a retry can proceed.
        // We need a concrete engine to freeze the workspace for this test.
        let engine = Arc::new(CowEngine::new());
        let manager = ForkManager::new(
            Arc::<CowEngine>::clone(&engine),
            ForkManager::default_max_fork_depth(),
        );
        let root = manager
            .create_root_workspace(SandboxId::from_string("sbx_fail_cleanup"), 4096)
            .unwrap();
        let request = make_fork_request(&root.id, "sbx_fail_cleanup", 512);

        // Manually sabotage the parent to force fork failure after reservation
        // The engine.fork_workspace will fail if parent is frozen.
        {
            let mut guard = engine.workspaces.write();
            if let Some(ws) = guard.get_mut(&root.id) {
                ws.state = CowWorkspaceState::Frozen;
            }
        }

        let result = manager.fork_workspace(&request);
        assert!(result.is_err());

        // Reservation should be cleaned up (no entry in registry)
        assert_eq!(manager.idempotency_key_count(), 0);
        assert!(!manager.is_fork_in_progress(&request.operation_id));
    }
}

mod cleanup_production {
    use super::*;

    #[test]
    fn clean_child_preserves_parent() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_cc", 256);
        let outcome = manager.fork_workspace(&request).unwrap();

        assert_eq!(manager.workspace_count(), 2);

        manager
            .clean_child_workspace(&outcome.result.child_workspace_id)
            .expect("clean child should succeed");

        assert_eq!(manager.workspace_count(), 1);
        assert!(manager.get_workspace(&root.id).is_ok());
        assert!(
            manager
                .get_workspace(&outcome.result.child_workspace_id)
                .is_err()
        );
    }

    #[test]
    fn clean_parent_with_active_children_fails() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_cp", 256);
        let _outcome = manager.fork_workspace(&request).unwrap();

        let result = manager.clean_parent_workspace(&root.id);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "deleting parent with active children should fail"
        );
        assert_eq!(manager.workspace_count(), 2);
    }

    #[test]
    fn clean_parent_after_children_removed_succeeds() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_cpas", 256);
        let outcome = manager.fork_workspace(&request).unwrap();

        manager
            .clean_child_workspace(&outcome.result.child_workspace_id)
            .unwrap();

        manager
            .clean_parent_workspace(&root.id)
            .expect("delete parent should succeed after children removed");

        assert_eq!(manager.workspace_count(), 0);
    }

    #[test]
    fn cleanup_does_not_delete_shared_layers() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_shared", 256);
        let outcome = manager.fork_workspace(&request).unwrap();

        let parent_base_blob = root.layers[0].blob_ref.clone();
        let child_base = outcome.child_workspace.layers[0].blob_ref.clone();
        // Both reference the same base blob
        assert_eq!(parent_base_blob, child_base);

        // Clean child - parent base layer should still exist
        manager
            .clean_child_workspace(&outcome.result.child_workspace_id)
            .unwrap();

        // Parent still accessible with its base layer intact
        let parent = manager.get_workspace(&root.id).unwrap();
        assert!(!parent.layers.is_empty());
        assert_eq!(parent.layers[0].blob_ref, parent_base_blob);
    }

    #[test]
    fn ref_count_tracks_shared_layers() {
        let (manager, root) = make_fork_manager();
        let base_blob = root.layers[0].blob_ref.clone();

        // After root creation, ref count should be 1
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(1));

        // Fork: child also shares the base layer
        let request = make_fork_request(&root.id, "sbx_ref", 256);
        let outcome = manager.fork_workspace(&request).unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(2));

        // Delete child: ref count should drop to 1
        manager
            .clean_child_workspace(&outcome.result.child_workspace_id)
            .unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(1));

        // Delete parent: ref count should drop to 0 (released)
        manager.clean_parent_workspace(&root.id).unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(0));
    }

    #[test]
    fn multiple_children_increase_ref_count() {
        let (manager, root) = make_fork_manager();
        let base_blob = root.layers[0].blob_ref.clone();

        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(1));

        let _c1 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_mc1", 100))
            .unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(2));

        let _c2 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_mc2", 200))
            .unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(3));

        let _c3 = manager
            .fork_workspace(&make_fork_request(&root.id, "sbx_mc3", 300))
            .unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(4));
    }

    #[test]
    fn sweep_released_removes_zero_ref_layers() {
        let (manager, root) = make_fork_manager();
        let base_blob = root.layers[0].blob_ref.clone();

        // Delete root directly (no children created) - ref count goes to 0
        manager.clean_parent_workspace(&root.id).unwrap();
        assert_eq!(manager.cleanup_tracker_ref_count(&base_blob), Some(0));
        assert_eq!(manager.released_layer_count(), 1);

        let swept = manager.sweep_released();
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0], base_blob);
        assert_eq!(manager.released_layer_count(), 0);
    }

    #[test]
    fn parent_cleanup_detects_child_in_different_sandbox() {
        // Children can be in a different sandbox than the parent.
        // The cleanup must catch this cross-sandbox case.
        let (manager, root) = make_fork_manager();
        let child_sandbox = SandboxId::from_string("sbx_other_sandbox");
        let request = make_fork_request(&root.id, child_sandbox.as_str(), 256);
        let outcome = manager.fork_workspace(&request).unwrap();

        // Child is in a different sandbox than the parent
        assert_ne!(outcome.child_workspace.sandbox_id, root.sandbox_id);

        // Parent cleanup should still detect and block because of active child
        let result = manager.clean_parent_workspace(&root.id);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "should detect child in different sandbox"
        );
        assert_eq!(manager.workspace_count(), 2);
    }
}

mod observability {
    use super::*;

    #[test]
    fn metrics_are_registered() {
        // COW_FORK_METRICS is lazily registered - accessing it proves registration
        let _ = &*crate::snapshot::cow::metrics::COW_FORK_METRICS;
    }

    #[test]
    fn fork_emits_started_and_completed_metrics() {
        // This test verifies the metrics calls don't panic.
        // Actual metric recording is verified in integration tests
        // against the OTLP exporter.
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_metrics", 512);

        // Should not panic
        let _outcome = manager.fork_workspace(&request).unwrap();
    }
}

mod integration {
    use super::*;

    #[test]
    fn full_fork_lifecycle() {
        let (manager, root) = make_fork_manager();

        // Fork creates child with quota tracking
        let req = make_fork_request(&root.id, "sbx_full", 1024);
        let outcome = manager.fork_workspace(&req).unwrap();

        // Child has independent identity
        let child_id = outcome.result.child_workspace_id.clone();
        let child = manager.get_workspace(&child_id).unwrap();
        assert!(child.is_active());
        assert_eq!(child.parent_workspace_id, Some(root.id.clone()));

        // Quota is correct
        let child_quota = manager.compute_quota(&child_id).unwrap();
        assert_eq!(child_quota.shared_bytes, 4096);
        assert_eq!(child_quota.private_bytes, 1024);

        // Lineage is queryable
        let children = manager.get_children(&root.id);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].child_workspace_id, child_id);

        let parent = manager.get_parent(&child_id);
        assert_eq!(parent, Some(root.id.clone()));

        // Workspaces listable by sandbox
        let workspaces = manager
            .list_workspaces(&SandboxId::from_string("sbx_full"))
            .unwrap();
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].id, child_id);

        // Child cleanup preserves parent
        manager.clean_child_workspace(&child_id).unwrap();
        assert!(manager.get_workspace(&root.id).is_ok());
        assert!(manager.get_workspace(&child_id).is_err());
    }

    #[test]
    fn retry_safety_full_cycle() {
        let (manager, root) = make_fork_manager();
        let request = make_fork_request(&root.id, "sbx_retry", 512);

        // First fork
        let first = manager.fork_workspace(&request).unwrap();
        let child_id = first.result.child_workspace_id.clone();

        // Retry with same request (idempotent)
        let retry = manager.fork_workspace(&request).unwrap();
        assert_eq!(retry.result.child_workspace_id, child_id);

        // Clean child
        manager.clean_child_workspace(&child_id).unwrap();

        // Clear idempotency key, then fork again with same request
        // (the key was consumed; clear it to allow a new fork)
        manager.clear_idempotency_key(&request.operation_id);
        let re_fork = manager.fork_workspace(&request).unwrap();
        assert_ne!(re_fork.result.child_workspace_id, child_id);

        // Clean up everything
        manager
            .clean_child_workspace(&re_fork.result.child_workspace_id)
            .unwrap();
        manager.clean_parent_workspace(&root.id).unwrap();
        assert_eq!(manager.workspace_count(), 0);
    }
}

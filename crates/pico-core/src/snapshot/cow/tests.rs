use super::*;
use std::sync::Arc;

fn make_test_sandbox() -> SandboxId {
    SandboxId::from_string("sbx_test_001")
}

fn make_engine_with_root(base_size: u64) -> (Arc<CowEngine>, CowWorkspace) {
    let engine = Arc::new(CowEngine::new());
    let ws = engine
        .create_root_workspace(make_test_sandbox(), base_size)
        .expect("failed to create root workspace");
    (engine, ws)
}

mod root_workspace {
    use super::*;

    #[test]
    fn has_single_base_layer() {
        let (_engine, root) = make_engine_with_root(1024);
        assert!(root.is_root());
        assert_eq!(root.layer_count(), 1);
        assert_eq!(root.base_layer_count(), 1);
        assert_eq!(root.overlay_layer_count(), 0);
        assert_eq!(root.layers[0].kind, LayerKind::Base);
        assert_eq!(root.layers[0].size_bytes, 1024);
        assert!(root.is_active());
    }

    #[test]
    fn total_size_matches_base_layer() {
        let (_engine, root) = make_engine_with_root(4096);
        assert_eq!(root.total_size_bytes(), 4096);
        assert_eq!(root.shared_size_bytes(), 4096);
        assert_eq!(root.private_size_bytes(), 0);
    }
}

mod fork {
    use super::*;

    #[test]
    fn creates_child_with_shared_base_layers() {
        let (engine, root) = make_engine_with_root(2048);
        let child_sandbox = SandboxId::from_string("sbx_child_001");

        let result = engine
            .fork_workspace(&root.id, child_sandbox.clone(), 512)
            .expect("fork should succeed");

        assert_eq!(result.parent_workspace_id, root.id);
        assert_eq!(result.shared_layer_count, 1);
        assert_eq!(result.shared_bytes, 2048);

        let child = engine
            .get_workspace(&result.child_workspace_id)
            .expect("child should exist");

        assert!(!child.is_root());
        assert_eq!(child.parent_workspace_id, Some(root.id.clone()));
        assert_eq!(child.sandbox_id, child_sandbox);
        assert_eq!(child.layer_count(), 2);
        assert_eq!(child.base_layer_count(), 1);
        assert_eq!(child.overlay_layer_count(), 1);
        assert_eq!(child.layers[0].kind, LayerKind::Base);
        assert_eq!(child.layers[1].kind, LayerKind::Overlay);
        assert_eq!(child.layers[0].blob_ref, root.layers[0].blob_ref);
        assert!(child.is_active());
    }

    #[test]
    fn from_non_active_workspace_fails() {
        let (engine, root) = make_engine_with_root(1024);
        {
            let mut guard = engine.workspaces.write();
            if let Some(ws) = guard.get_mut(&root.id) {
                ws.state = CowWorkspaceState::Frozen;
            }
        }

        let result = engine.fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 512);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "fork from non-active workspace should fail"
        );
    }

    #[test]
    fn from_nonexistent_workspace_fails() {
        let engine = CowEngine::new();
        let result = engine.fork_workspace(
            &WorkspaceId::from_string("wsp_nonexistent"),
            SandboxId::from_string("sbx_child"),
            512,
        );
        assert!(
            matches!(result, Err(SnapshotError::SnapshotNotFound { .. })),
            "fork from nonexistent workspace should fail"
        );
    }

    #[test]
    fn multiple_from_same_parent() {
        let (engine, root) = make_engine_with_root(1024);

        let child1 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c1"), 256)
            .expect("fork 1");
        let child2 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c2"), 512)
            .expect("fork 2");
        let child3 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c3"), 768)
            .expect("fork 3");

        assert_eq!(engine.workspace_count(), 4);

        let c1 = engine.get_workspace(&child1.child_workspace_id).unwrap();
        let c2 = engine.get_workspace(&child2.child_workspace_id).unwrap();
        let c3 = engine.get_workspace(&child3.child_workspace_id).unwrap();

        assert_eq!(c1.base_layer_count(), 1);
        assert_eq!(c2.base_layer_count(), 1);
        assert_eq!(c3.base_layer_count(), 1);
        assert_eq!(c1.layers[0].blob_ref, root.layers[0].blob_ref);
        assert_eq!(c2.layers[0].blob_ref, root.layers[0].blob_ref);
        assert_eq!(c3.layers[0].blob_ref, root.layers[0].blob_ref);

        assert_eq!(c1.overlay_layer_count(), 1);
        assert_eq!(c2.overlay_layer_count(), 1);
        assert_eq!(c3.overlay_layer_count(), 1);

        assert_ne!(c1.layers[1].blob_ref, c2.layers[1].blob_ref);
        assert_ne!(c2.layers[1].blob_ref, c3.layers[1].blob_ref);
    }

    #[test]
    fn deep_chain_shares_root_base_layer() {
        let (engine, root) = make_engine_with_root(1024);

        let f1 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_1"), 100)
            .unwrap();
        let f2 = engine
            .fork_workspace(&f1.child_workspace_id, SandboxId::from_string("sbx_2"), 200)
            .unwrap();
        let f2_child_id = f2.child_workspace_id.clone();
        let f3 = engine
            .fork_workspace(&f2_child_id, SandboxId::from_string("sbx_3"), 300)
            .unwrap();

        let c3 = engine.get_workspace(&f3.child_workspace_id).unwrap();

        assert_eq!(c3.layer_count(), 2);
        assert_eq!(c3.base_layer_count(), 1);
        assert_eq!(c3.overlay_layer_count(), 1);
        assert_eq!(c3.parent_workspace_id, Some(f2_child_id.clone()));
        assert_eq!(c3.layers[0].blob_ref, root.layers[0].blob_ref);

        assert_eq!(
            engine.get_workspace(&f1.child_workspace_id).unwrap().layers[0].blob_ref,
            root.layers[0].blob_ref
        );
        assert_eq!(
            engine.get_workspace(&f2_child_id).unwrap().layers[0].blob_ref,
            root.layers[0].blob_ref
        );
        assert_eq!(
            engine.get_workspace(&f3.child_workspace_id).unwrap().layers[0].blob_ref,
            root.layers[0].blob_ref
        );
    }
}

mod divergence {
    use super::*;

    #[test]
    fn parent_and_child_have_independent_state() {
        let (engine, root) = make_engine_with_root(2048);

        let result = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 0)
            .expect("fork should succeed");

        let child = engine
            .get_workspace(&result.child_workspace_id)
            .expect("child should exist");
        let parent = engine.get_workspace(&root.id).expect("parent should exist");

        assert_eq!(parent.layer_count(), 1);
        assert_eq!(child.layer_count(), 2);

        let child_overlay = &child.layers[1];
        assert_eq!(child_overlay.kind, LayerKind::Overlay);

        // Parent writes after fork do not affect child
        assert_eq!(child.layers[0].size_bytes, parent.layers[0].size_bytes);
    }
}

mod quota {
    use super::*;

    #[test]
    fn accounts_for_shared_and_private_bytes() {
        let (engine, root) = make_engine_with_root(2048);

        let root_quota = engine.compute_quota(&root.id).unwrap();
        assert_eq!(root_quota.shared_bytes, 2048);
        assert_eq!(root_quota.private_bytes, 0);
        assert_eq!(root_quota.total_bytes(), 2048);

        let result = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 512)
            .unwrap();

        let child_quota = engine.compute_quota(&result.child_workspace_id).unwrap();
        assert_eq!(child_quota.shared_bytes, 2048);
        assert_eq!(child_quota.private_bytes, 512);
        assert_eq!(child_quota.total_bytes(), 2560);
    }

    #[test]
    fn default_has_zero_bytes() {
        let q = WorkspaceQuota::default();
        assert_eq!(q.shared_bytes, 0);
        assert_eq!(q.private_bytes, 0);
        assert_eq!(q.total_bytes(), 0);
    }
}

mod cleanup_child_first {
    use super::*;

    #[test]
    fn delete_child_preserves_parent() {
        let (engine, root) = make_engine_with_root(1024);

        let result = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 256)
            .unwrap();

        assert_eq!(engine.workspace_count(), 2);

        engine
            .delete_child_workspace(&result.child_workspace_id)
            .expect("delete child should succeed");

        assert!(engine.get_workspace(&root.id).is_ok());
        assert_eq!(engine.workspace_count(), 1);
        assert!(matches!(
            engine.get_workspace(&result.child_workspace_id),
            Err(SnapshotError::SnapshotNotFound { .. })
        ));
    }

    #[test]
    fn delete_then_recreate_child() {
        let (engine, root) = make_engine_with_root(1024);

        let result = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 256)
            .unwrap();

        engine
            .delete_child_workspace(&result.child_workspace_id)
            .unwrap();

        let result2 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child2"), 512)
            .unwrap();

        let child2 = engine.get_workspace(&result2.child_workspace_id).unwrap();
        assert_eq!(child2.layers[0].blob_ref, root.layers[0].blob_ref);
        assert_eq!(child2.private_size_bytes(), 512);
    }

    #[test]
    fn delete_root_workspace_as_child_fails() {
        let (engine, root) = make_engine_with_root(1024);

        let result = engine.delete_child_workspace(&root.id);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "deleting root as child should fail"
        );
    }
}

mod cleanup_parent_first {
    use super::*;

    #[test]
    fn delete_parent_with_active_children_fails() {
        let (engine, root) = make_engine_with_root(1024);

        let _child = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 256)
            .unwrap();

        let result = engine.delete_parent_workspace(&root.id);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "deleting parent with active children should fail"
        );
        assert_eq!(engine.workspace_count(), 2);
    }

    #[test]
    fn delete_parent_after_children_removed_succeeds() {
        let (engine, root) = make_engine_with_root(1024);

        let child = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_child"), 256)
            .unwrap();

        engine
            .delete_child_workspace(&child.child_workspace_id)
            .unwrap();

        engine
            .delete_parent_workspace(&root.id)
            .expect("delete parent should succeed after children removed");

        assert_eq!(engine.workspace_count(), 0);
    }

    #[test]
    fn delete_nonexistent_workspace_fails() {
        let engine = CowEngine::new();
        let result = engine.delete_workspace(&WorkspaceId::from_string("wsp_nonexistent"));
        assert!(matches!(
            result,
            Err(SnapshotError::SnapshotNotFound { .. })
        ));
    }
}

mod lineage {
    use super::*;

    #[test]
    fn fork_records_lineage() {
        let (engine, root) = make_engine_with_root(1024);

        let _child = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c1"), 256)
            .unwrap();

        let children = engine.get_children(&root.id);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].parent_workspace_id, root.id);
        assert_eq!(children[0].shared_layer_count, 1);
    }

    #[test]
    fn get_parent_returns_correct_parent() {
        let (engine, root) = make_engine_with_root(1024);

        let child = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c1"), 256)
            .unwrap();

        let parent = engine.get_parent(&child.child_workspace_id);
        assert_eq!(parent, Some(root.id));
    }

    #[test]
    fn get_parent_for_root_returns_none() {
        let (engine, root) = make_engine_with_root(1024);
        assert_eq!(engine.get_parent(&root.id), None);
    }

    #[test]
    fn all_lineages_returns_all_records() {
        let (engine, root) = make_engine_with_root(1024);

        let _c1 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c1"), 100)
            .unwrap();
        let _c2 = engine
            .fork_workspace(&root.id, SandboxId::from_string("sbx_c2"), 200)
            .unwrap();

        let all = engine.all_lineages();
        assert_eq!(all.len(), 2);
    }
}

mod listing {
    use super::*;

    #[test]
    fn list_workspaces_filters_by_sandbox() {
        let engine = CowEngine::new();
        let sbx_a = SandboxId::from_string("sbx_a");
        let sbx_b = SandboxId::from_string("sbx_b");

        let _ws_a = engine.create_root_workspace(sbx_a.clone(), 1024).unwrap();
        let _ws_b = engine.create_root_workspace(sbx_b.clone(), 2048).unwrap();

        let a_workspaces = engine.list_workspaces(&sbx_a).unwrap();
        assert_eq!(a_workspaces.len(), 1);

        let b_workspaces = engine.list_workspaces(&sbx_b).unwrap();
        assert_eq!(b_workspaces.len(), 1);

        // list_all_workspaces returns all regardless of sandbox
        let all = engine.list_all_workspaces().unwrap();
        assert_eq!(all.len(), 2);
    }
}

mod serde {
    use super::*;

    #[test]
    fn cow_layer_serde_roundtrip() {
        let layer = CowLayer {
            layer_id: "layer_test_0".into(),
            kind: LayerKind::Base,
            blob_ref: "blob_base_test".into(),
            layer_index: 0,
            parent_blob_ref: None,
            size_bytes: 1024,
            digest: Some("blake3:abc".into()),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&layer).unwrap();
        let back: CowLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(layer, back);
    }

    #[test]
    fn cow_workspace_serde_roundtrip() {
        let (engine, root) = make_engine_with_root(1024);
        let ws = engine.get_workspace(&root.id).unwrap();
        let json = serde_json::to_string(&ws).unwrap();
        let back: CowWorkspace = serde_json::from_str(&json).unwrap();
        assert_eq!(ws.id, back.id);
        assert_eq!(ws.sandbox_id, back.sandbox_id);
        assert_eq!(ws.layers.len(), back.layers.len());
        assert_eq!(ws.parent_workspace_id, back.parent_workspace_id);
        assert_eq!(ws.state, back.state);
    }

    #[test]
    fn cow_lineage_serde_roundtrip() {
        let lineage = CowLineage {
            parent_workspace_id: WorkspaceId::from_string("wsp_parent"),
            child_workspace_id: WorkspaceId::from_string("wsp_child"),
            shared_layer_count: 3,
            fork_depth: 5,
            created_at: "2026-06-24T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&lineage).unwrap();
        let back: CowLineage = serde_json::from_str(&json).unwrap();
        assert_eq!(lineage, back);
    }

    #[test]
    fn workspace_quota_serde_roundtrip() {
        let quota = WorkspaceQuota {
            shared_bytes: 4096,
            private_bytes: 1024,
        };
        let json = serde_json::to_string(&quota).unwrap();
        let back: WorkspaceQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(quota, back);
    }
}

mod trait_impl {
    use super::*;

    #[test]
    fn full_lifecycle_through_workspace_manager_trait() {
        let engine = CowEngine::new();
        let sbx = SandboxId::from_string("sbx_trait_test");

        let ws = CowWorkspace::new_root(
            WorkspaceId::generate(),
            sbx.clone(),
            "blob_manual".into(),
            512,
        );
        engine.store_workspace(&ws).unwrap();

        let retrieved = engine.get_workspace(&ws.id).unwrap();
        assert_eq!(retrieved.id, ws.id);

        let list = engine.list_workspaces(&sbx).unwrap();
        assert_eq!(list.len(), 1);

        engine.delete_workspace(&ws.id).unwrap();
        assert!(engine.get_workspace(&ws.id).is_err());
    }

    #[test]
    fn list_all_workspaces_via_trait() {
        let engine = CowEngine::new();
        let sbx_a = SandboxId::from_string("sbx_a_all");
        let sbx_b = SandboxId::from_string("sbx_b_all");

        engine.create_root_workspace(sbx_a.clone(), 512).unwrap();
        engine.create_root_workspace(sbx_b.clone(), 512).unwrap();

        // Via trait
        let all: Vec<CowWorkspace> = engine.list_all_workspaces().unwrap();
        assert_eq!(all.len(), 2);

        let manager: &dyn CowWorkspaceManager = &engine;
        let all_trait: Vec<CowWorkspace> = manager.list_all_workspaces().unwrap();
        assert_eq!(all_trait.len(), 2);
    }
}

mod display {
    use super::*;

    #[test]
    fn layer_kind_as_str() {
        assert_eq!(LayerKind::Base.as_str(), "base");
        assert_eq!(LayerKind::Overlay.as_str(), "overlay");
    }

    #[test]
    fn workspace_state_as_str() {
        assert_eq!(CowWorkspaceState::Active.as_str(), "active");
        assert_eq!(CowWorkspaceState::Frozen.as_str(), "frozen");
        assert_eq!(CowWorkspaceState::Deleting.as_str(), "deleting");
        assert_eq!(CowWorkspaceState::Deleted.as_str(), "deleted");
    }
}

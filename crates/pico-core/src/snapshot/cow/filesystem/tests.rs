//! Tests for the filesystem COW engine.
//!
//! Covers fork, quota, lineage, cleanup, filesystem I/O, integrity
//! verification, and persistence across restarts.

use super::*;
use crate::identity::SandboxId;
use crate::snapshot::cow::{CowWorkspaceState, LayerKind};
use crate::snapshot::error::SnapshotError;
use tempfile::TempDir;

fn make_temp_engine() -> (CowFilesystemEngine, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let engine = CowFilesystemEngine::open(tmp.path()).expect("failed to open engine");
    (engine, tmp)
}

fn make_test_sandbox(name: &str) -> SandboxId {
    SandboxId::from_string(name)
}

fn make_engine_with_root(base_size: u64) -> (CowFilesystemEngine, CowWorkspace, TempDir) {
    let (engine, tmp) = make_temp_engine();
    let root = engine
        .create_root_workspace(make_test_sandbox("sbx_fs_test"), base_size)
        .expect("failed to create root");
    (engine, root, tmp)
}

// ── Root workspace ──

mod root_workspace {
    use super::*;

    #[test]
    fn create_root_has_single_base_layer() {
        let (_engine, root, _tmp) = make_engine_with_root(1024);
        assert!(root.is_root());
        assert_eq!(root.layer_count(), 1);
        assert_eq!(root.base_layer_count(), 1);
        assert_eq!(root.overlay_layer_count(), 0);
        assert_eq!(root.layers[0].kind, LayerKind::Base);
        assert_eq!(root.layers[0].size_bytes, 1024);
        assert!(root.is_active());
    }

    #[test]
    fn root_layer_has_digest() {
        let (_engine, root, _tmp) = make_engine_with_root(2048);
        assert!(root.layers[0].digest.is_some());
        assert_eq!(root.layers[0].digest.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn quota_matches_base_layer() {
        let (_engine, root, _tmp) = make_engine_with_root(4096);
        assert_eq!(root.total_size_bytes(), 4096);
        assert_eq!(root.shared_size_bytes(), 4096);
        assert_eq!(root.private_size_bytes(), 0);
    }

    #[test]
    fn create_multiple_roots_in_different_sandboxes() {
        let (engine, _tmp) = make_temp_engine();
        let r1 = engine
            .create_root_workspace(make_test_sandbox("sbx_a"), 1024)
            .unwrap();
        let r2 = engine
            .create_root_workspace(make_test_sandbox("sbx_b"), 2048)
            .unwrap();
        assert_ne!(r1.id, r2.id);
        assert_eq!(engine.workspace_count(), 2);
        assert_eq!(
            engine
                .list_workspaces(&make_test_sandbox("sbx_a"))
                .unwrap()
                .len(),
            1
        );
    }
}

// ── Fork ──

mod fork {
    use super::*;

    #[test]
    fn fork_creates_child_with_shared_base() {
        let (engine, root, _tmp) = make_engine_with_root(2048);
        let child_sandbox = make_test_sandbox("sbx_fork_child");

        let result = engine
            .fork_workspace(&root.id, child_sandbox.clone(), 512)
            .expect("fork should succeed");

        assert_eq!(result.parent_workspace_id, root.id);
        assert_eq!(result.shared_layer_count, 1);
        assert_eq!(result.shared_bytes, 2048);

        let child = engine.get_workspace(&result.child_workspace_id).unwrap();
        assert!(!child.is_root());
        assert_eq!(child.parent_workspace_id, Some(root.id.clone()));
        assert_eq!(child.sandbox_id, child_sandbox);
        assert_eq!(child.layer_count(), 2);
        assert_eq!(child.base_layer_count(), 1);
        assert_eq!(child.overlay_layer_count(), 1);
        assert_eq!(child.layers[0].kind, LayerKind::Base);
        assert_eq!(child.layers[1].kind, LayerKind::Overlay);
        assert_eq!(child.layers[0].blob_ref, root.layers[0].blob_ref);
        assert!(child.layers[1].digest.is_some());
    }

    #[test]
    fn fork_from_frozen_parent_fails() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        // Freeze the workspace
        {
            let mut guard = engine.workspaces.write();
            if let Some(ws) = guard.get_mut(&root.id) {
                ws.state = CowWorkspaceState::Frozen;
            }
        }

        let result = engine.fork_workspace(&root.id, make_test_sandbox("sbx_child"), 512);
        assert!(matches!(
            result,
            Err(SnapshotError::OperationConflict { .. })
        ));
    }

    #[test]
    fn fork_from_nonexistent_parent_fails() {
        let (engine, _tmp) = make_temp_engine();
        let result = engine.fork_workspace(
            &WorkspaceId::from_string("wsp_nonexistent"),
            make_test_sandbox("sbx_child"),
            512,
        );
        assert!(matches!(
            result,
            Err(SnapshotError::SnapshotNotFound { .. })
        ));
    }

    #[test]
    fn multiple_forks_from_same_parent() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        let c1 = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_c1"), 256)
            .unwrap();
        let c2 = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_c2"), 512)
            .unwrap();
        let c3 = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_c3"), 768)
            .unwrap();

        assert_eq!(engine.workspace_count(), 4);

        let child1 = engine.get_workspace(&c1.child_workspace_id).unwrap();
        let child2 = engine.get_workspace(&c2.child_workspace_id).unwrap();
        let child3 = engine.get_workspace(&c3.child_workspace_id).unwrap();

        // All share the same base layer blob
        assert_eq!(child1.layers[0].blob_ref, root.layers[0].blob_ref);
        assert_eq!(child2.layers[0].blob_ref, root.layers[0].blob_ref);
        assert_eq!(child3.layers[0].blob_ref, root.layers[0].blob_ref);

        // Overlays are independent
        assert_eq!(child1.overlay_layer_count(), 1);
        assert_eq!(child2.overlay_layer_count(), 1);
        assert_eq!(child3.overlay_layer_count(), 1);
        assert_ne!(child1.layers[1].blob_ref, child2.layers[1].blob_ref);
        assert_ne!(child2.layers[1].blob_ref, child3.layers[1].blob_ref);
    }

    #[test]
    fn deep_chain_shares_root_base() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        let f1 = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_d1"), 100)
            .unwrap();
        let f2 = engine
            .fork_workspace(&f1.child_workspace_id, make_test_sandbox("sbx_d2"), 200)
            .unwrap();
        let f3 = engine
            .fork_workspace(&f2.child_workspace_id, make_test_sandbox("sbx_d3"), 300)
            .unwrap();

        let c3 = engine.get_workspace(&f3.child_workspace_id).unwrap();
        assert_eq!(c3.base_layer_count(), 1);
        assert_eq!(c3.overlay_layer_count(), 1);
        assert_eq!(c3.layers[0].blob_ref, root.layers[0].blob_ref);
    }
}

// ── Filesystem I/O ──

mod filesystem_io {
    use super::*;

    #[test]
    fn write_and_read_file() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine
            .write_file(&root.id, "hello.txt", b"hello world")
            .unwrap();
        let content = engine.read_file(&root.id, "hello.txt").unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn write_to_child_does_not_affect_parent() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_iso"), 256)
            .unwrap();

        // Write to child
        engine
            .write_file(&child.child_workspace_id, "data.txt", b"child data")
            .unwrap();

        // Child can read it
        assert_eq!(
            engine
                .read_file(&child.child_workspace_id, "data.txt")
                .unwrap(),
            b"child data"
        );

        // Parent should NOT see it
        assert!(engine.read_file(&root.id, "data.txt").is_err());
    }

    #[test]
    fn child_reads_parent_file() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        // Write to parent (root) first
        engine
            .write_file(&root.id, "shared.txt", b"from parent")
            .unwrap();

        // Fork a child
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_inherit"), 256)
            .unwrap();

        // Child can read parent's file through union view
        let content = engine
            .read_file(&child.child_workspace_id, "shared.txt")
            .unwrap();
        assert_eq!(content, b"from parent");
    }

    #[test]
    fn cow_write_copies_up() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine
            .write_file(&root.id, "cow_test.txt", b"original")
            .unwrap();

        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_cow"), 256)
            .unwrap();

        // Child overwrites - this goes to the child's overlay layer
        engine
            .write_file(
                &child.child_workspace_id,
                "cow_test.txt",
                b"modified by child",
            )
            .unwrap();

        // Child sees modified version
        assert_eq!(
            engine
                .read_file(&child.child_workspace_id, "cow_test.txt")
                .unwrap(),
            b"modified by child"
        );

        // Parent still sees original (base layer unchanged)
        assert_eq!(
            engine.read_file(&root.id, "cow_test.txt").unwrap(),
            b"original"
        );
    }

    #[test]
    fn delete_file_whiteout() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine
            .write_file(&root.id, "to_delete.txt", b"delete me")
            .unwrap();

        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_del"), 256)
            .unwrap();

        // Delete in child
        engine
            .delete_file(&child.child_workspace_id, "to_delete.txt")
            .unwrap();

        // Child should not see the file
        assert!(
            engine
                .read_file(&child.child_workspace_id, "to_delete.txt")
                .is_err()
        );

        // Parent should still see it (base layer unchanged)
        assert_eq!(
            engine.read_file(&root.id, "to_delete.txt").unwrap(),
            b"delete me"
        );
    }

    #[test]
    fn file_exists_in_union_view() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine.write_file(&root.id, "exists.txt", b"yep").unwrap();

        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_ex"), 256)
            .unwrap();

        assert!(engine.file_exists(&root.id, "exists.txt").unwrap());
        assert!(
            engine
                .file_exists(&child.child_workspace_id, "exists.txt")
                .unwrap()
        );
        assert!(!engine.file_exists(&root.id, "nope.txt").unwrap());
    }

    #[test]
    fn list_directory_merges_layers() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine
            .write_file(&root.id, "base_file.txt", b"base")
            .unwrap();

        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_ls"), 256)
            .unwrap();

        engine
            .write_file(&child.child_workspace_id, "child_file.txt", b"child")
            .unwrap();

        let entries = engine
            .list_directory(&child.child_workspace_id, "/")
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();

        assert!(names.contains(&"base_file.txt"));
        assert!(names.contains(&"child_file.txt"));
    }

    #[test]
    fn list_directory_respects_whiteouts() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine
            .write_file(&root.id, "visible.txt", b"visible")
            .unwrap();
        engine
            .write_file(&root.id, "hidden.txt", b"hidden")
            .unwrap();

        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_white"), 256)
            .unwrap();

        engine
            .delete_file(&child.child_workspace_id, "hidden.txt")
            .unwrap();

        let entries = engine
            .list_directory(&child.child_workspace_id, "/")
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();

        assert!(names.contains(&"visible.txt"));
        assert!(!names.contains(&"hidden.txt"));
    }

    #[test]
    fn read_nonexistent_file_returns_error() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let result = engine.read_file(&root.id, "nope.txt");
        assert!(matches!(
            result,
            Err(SnapshotError::SnapshotNotFound { .. })
        ));
    }

    #[test]
    fn write_nested_path_creates_parent_dirs() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        engine
            .write_file(&root.id, "a/b/c/deep.txt", b"nested")
            .unwrap();

        let content = engine.read_file(&root.id, "a/b/c/deep.txt").unwrap();
        assert_eq!(content, b"nested");
    }

    #[test]
    fn workspace_root_returns_overlay_path() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let root_path = engine.workspace_root(&root.id).unwrap();
        assert!(root_path.exists());

        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_wr"), 256)
            .unwrap();
        let child_path = engine.workspace_root(&child.child_workspace_id).unwrap();
        assert!(child_path.exists());
        assert_ne!(root_path, child_path);
    }

    #[test]
    fn write_updates_layer_digest() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let orig_digest = root.layers[0].digest.clone();

        engine
            .write_file(&root.id, "new_file.txt", b"content")
            .unwrap();

        let updated = engine.get_workspace(&root.id).unwrap();
        let new_digest = updated.layers[0].digest.clone();
        assert_ne!(orig_digest, new_digest);
    }
}

// ── Quota ──

mod quota {
    use super::*;

    #[test]
    fn root_quota_allows_for_shared_and_private() {
        let (engine, root, _tmp) = make_engine_with_root(2048);

        let q = engine.compute_quota(&root.id).unwrap();
        assert_eq!(q.shared_bytes, 2048);
        assert_eq!(q.private_bytes, 0);
    }

    #[test]
    fn child_quota_accounts_for_shared_and_private() {
        let (engine, root, _tmp) = make_engine_with_root(2048);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_quota"), 512)
            .unwrap();

        let q = engine.compute_quota(&child.child_workspace_id).unwrap();
        assert_eq!(q.shared_bytes, 2048);
        assert_eq!(q.private_bytes, 512);
        assert_eq!(q.total_bytes(), 2560);
    }
}

// ── Cleanup ──

mod cleanup {
    use super::*;

    #[test]
    fn delete_child_preserves_parent() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_cc"), 256)
            .unwrap();

        assert_eq!(engine.workspace_count(), 2);

        engine
            .delete_child_workspace(&child.child_workspace_id)
            .unwrap();

        assert_eq!(engine.workspace_count(), 1);
        assert!(engine.get_workspace(&root.id).is_ok());
        assert!(engine.get_workspace(&child.child_workspace_id).is_err());
    }

    #[test]
    fn delete_parent_with_active_children_fails() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_cp"), 256)
            .unwrap();

        let result = engine.delete_parent_workspace(&root.id);
        assert!(matches!(
            result,
            Err(SnapshotError::OperationConflict { .. })
        ));
        assert_eq!(engine.workspace_count(), 2);
    }

    #[test]
    fn delete_parent_after_children_removed_succeeds() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_cp"), 256)
            .unwrap();

        engine
            .delete_child_workspace(&child.child_workspace_id)
            .unwrap();
        engine.delete_parent_workspace(&root.id).unwrap();

        assert_eq!(engine.workspace_count(), 0);
    }

    #[test]
    fn gc_ref_count_tracks_shared_layers() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let base_blob = root.layers[0].blob_ref.clone();

        // Root creation registers base layer
        assert_eq!(engine.gc_ref_count(&base_blob), Some(1));

        // Fork increments ref count
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_gc"), 256)
            .unwrap();
        assert_eq!(engine.gc_ref_count(&base_blob), Some(2));

        // Delete child decrements
        engine
            .delete_child_workspace(&child.child_workspace_id)
            .unwrap();
        assert_eq!(engine.gc_ref_count(&base_blob), Some(1));

        // Delete parent releases
        engine.delete_parent_workspace(&root.id).unwrap();
        assert_eq!(engine.gc_ref_count(&base_blob), Some(0));
    }

    #[test]
    fn sweep_released_deletes_layer_data() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let base_blob = root.layers[0].blob_ref.clone();

        // Delete root to release base layer
        engine.delete_parent_workspace(&root.id).unwrap();
        assert_eq!(engine.gc_ref_count(&base_blob), Some(0));
        assert_eq!(engine.released_layer_count(), 1);

        // Sweep removes the blob data
        let swept = engine.sweep_released().unwrap();
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0], base_blob);
        assert_eq!(engine.released_layer_count(), 0);

        // Verify blob data is gone
        assert!(!engine.root().join("data").join(&base_blob).exists());
    }

    #[test]
    fn delete_root_as_child_fails() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let result = engine.delete_child_workspace(&root.id);
        assert!(matches!(
            result,
            Err(SnapshotError::OperationConflict { .. })
        ));
    }

    #[test]
    fn delete_then_recreate_child() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child1 = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_dr"), 256)
            .unwrap();

        engine
            .delete_child_workspace(&child1.child_workspace_id)
            .unwrap();

        let child2 = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_dr2"), 512)
            .unwrap();

        let c2 = engine.get_workspace(&child2.child_workspace_id).unwrap();
        assert_eq!(c2.layers[0].blob_ref, root.layers[0].blob_ref);
        assert_eq!(c2.private_size_bytes(), 512);
    }

    #[test]
    fn parent_cleanup_detects_child_in_different_sandbox() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_other_sandbox"), 256)
            .unwrap();

        assert_ne!(child.child_workspace_id, root.id);

        let result = engine.delete_parent_workspace(&root.id);
        assert!(
            matches!(result, Err(SnapshotError::OperationConflict { .. })),
            "should detect child in different sandbox"
        );
    }
}

// ── Lineage ──

mod lineage {
    use super::*;

    #[test]
    fn fork_records_lineage() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let _child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_lin"), 256)
            .unwrap();

        let children = engine.get_children(&root.id);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].parent_workspace_id, root.id);
        assert_eq!(children[0].shared_layer_count, 1);
        assert!(!children[0].created_at.is_empty());
    }

    #[test]
    fn get_parent_returns_correct_parent() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_par"), 256)
            .unwrap();

        assert_eq!(engine.get_parent(&child.child_workspace_id), Some(root.id));
    }

    #[test]
    fn get_parent_for_root_returns_none() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        assert_eq!(engine.get_parent(&root.id), None);
    }

    #[test]
    fn all_lineages_includes_all_records() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_a"), 100)
            .unwrap();
        engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_b"), 200)
            .unwrap();

        assert_eq!(engine.all_lineages().len(), 2);
    }

    #[test]
    fn lineage_cleaned_on_child_delete() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let child = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_cl"), 256)
            .unwrap();

        assert_eq!(engine.all_lineages().len(), 1);

        engine
            .delete_child_workspace(&child.child_workspace_id)
            .unwrap();
        assert_eq!(engine.all_lineages().len(), 0);
    }
}

// ── Integrity ──

mod integrity {
    use super::*;

    #[test]
    fn verify_workspace_no_mismatches() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let mismatches = engine.verify_workspace_integrity(&root.id).unwrap();
        assert!(mismatches.is_empty());
    }

    #[test]
    fn verify_workspace_after_write() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        let mismatches_before = engine.verify_workspace_integrity(&root.id).unwrap();
        assert!(mismatches_before.is_empty());

        engine.write_file(&root.id, "test.txt", b"hello").unwrap();

        let mismatches_after = engine.verify_workspace_integrity(&root.id).unwrap();
        assert!(mismatches_after.is_empty());
    }

    #[test]
    fn verify_detects_tampered_layer() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        // Tamper with the layer data on disk (bypass the engine)
        let data_dir = engine.root().join("data").join(&root.layers[0].blob_ref);
        std::fs::write(data_dir.join("tampered.txt"), b"evil").unwrap();

        let mismatches = engine.verify_workspace_integrity(&root.id).unwrap();
        assert!(!mismatches.is_empty());
    }

    #[test]
    fn layer_digest_is_blake3_hex() {
        let (_engine, root, _tmp) = make_engine_with_root(1024);
        let digest = root.layers[0].digest.as_ref().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ── Persistence ──

mod persistence {
    use super::*;

    #[test]
    fn reopen_preserves_workspaces() {
        let tmp = TempDir::new().expect("tempdir");
        let root_id;

        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let root = engine
                .create_root_workspace(make_test_sandbox("sbx_persist"), 1024)
                .unwrap();
            root_id = root.id.clone();
            assert_eq!(engine.workspace_count(), 1);
        }

        // Reopen
        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            assert_eq!(engine.workspace_count(), 1);
            let loaded = engine.get_workspace(&root_id).unwrap();
            assert_eq!(loaded.sandbox_id, make_test_sandbox("sbx_persist"));
            assert_eq!(loaded.layer_count(), 1);
            assert!(loaded.layers[0].digest.is_some());
        }
    }

    #[test]
    fn reopen_preserves_lineages() {
        let tmp = TempDir::new().expect("tempdir");
        let root_id;
        let child_id;

        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let root = engine
                .create_root_workspace(make_test_sandbox("sbx_lin_p"), 1024)
                .unwrap();
            root_id = root.id.clone();

            let child = engine
                .fork_workspace(&root_id, make_test_sandbox("sbx_child_p"), 256)
                .unwrap();
            child_id = child.child_workspace_id.clone();

            assert_eq!(engine.all_lineages().len(), 1);
        }

        // Reopen
        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let lineages = engine.all_lineages();
            assert_eq!(lineages.len(), 1);
            assert_eq!(lineages[0].parent_workspace_id, root_id);
            assert_eq!(lineages[0].child_workspace_id, child_id);

            let parent = engine.get_parent(&child_id);
            assert_eq!(parent, Some(root_id));
        }
    }

    #[test]
    fn reopen_preserves_filesystem_data() {
        let tmp = TempDir::new().expect("tempdir");
        let root_id;

        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let root = engine
                .create_root_workspace(make_test_sandbox("sbx_fs_p"), 1024)
                .unwrap();
            root_id = root.id.clone();

            engine
                .write_file(&root_id, "data.txt", b"persisted content")
                .unwrap();

            let content = engine.read_file(&root_id, "data.txt").unwrap();
            assert_eq!(content, b"persisted content");
        }

        // Reopen
        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let content = engine.read_file(&root_id, "data.txt").unwrap();
            assert_eq!(content, b"persisted content");
        }
    }

    #[test]
    fn reopen_preserves_gc_state() {
        let tmp = TempDir::new().expect("tempdir");
        let blob_ref;

        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let root = engine
                .create_root_workspace(make_test_sandbox("sbx_gc_p"), 1024)
                .unwrap();
            blob_ref = root.layers[0].blob_ref.clone();
            assert_eq!(engine.gc_ref_count(&blob_ref), Some(1));
        }

        // Reopen
        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            assert_eq!(engine.gc_ref_count(&blob_ref), Some(1));
        }
    }

    #[test]
    fn reopen_preserves_multiple_workspaces_and_fork_tree() {
        let tmp = TempDir::new().expect("tempdir");
        let root_id;
        let c1_id;
        let c2_id;

        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            let root = engine
                .create_root_workspace(make_test_sandbox("sbx_tree"), 2048)
                .unwrap();
            root_id = root.id.clone();

            let c1 = engine
                .fork_workspace(&root_id, make_test_sandbox("sbx_branch1"), 100)
                .unwrap();
            c1_id = c1.child_workspace_id.clone();

            let c2 = engine
                .fork_workspace(&c1_id, make_test_sandbox("sbx_branch2"), 200)
                .unwrap();
            c2_id = c2.child_workspace_id.clone();

            engine
                .write_file(&c2_id, "leaf_data.txt", b"deep leaf")
                .unwrap();

            assert_eq!(engine.workspace_count(), 3);
        }

        // Reopen
        {
            let engine = CowFilesystemEngine::open(tmp.path()).unwrap();
            assert_eq!(engine.workspace_count(), 3);

            let c2 = engine.get_workspace(&c2_id).unwrap();
            assert_eq!(c2.parent_workspace_id, Some(c1_id.clone()));

            let content = engine.read_file(&c2_id, "leaf_data.txt").unwrap();
            assert_eq!(content, b"deep leaf");

            // Verify GC state
            let base_blob = engine.get_workspace(&root_id).unwrap().layers[0]
                .blob_ref
                .clone();
            assert_eq!(engine.gc_ref_count(&base_blob), Some(3));
        }
    }
}

// ── Trait implementation ──

mod trait_impl {
    use super::*;

    #[test]
    fn full_lifecycle_through_trait() {
        let (engine, _tmp) = make_temp_engine();
        let sbx = make_test_sandbox("sbx_trait_fs");

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

        let all = engine.list_all_workspaces().unwrap();
        assert_eq!(all.len(), 1);

        engine.delete_workspace(&ws.id).unwrap();
        assert!(engine.get_workspace(&ws.id).is_err());
    }

    #[test]
    fn trait_object_usage() {
        let (engine, _tmp) = make_temp_engine();
        let manager: &dyn CowWorkspaceManager = &engine;

        let root = engine
            .create_root_workspace(make_test_sandbox("sbx_trait_obj"), 1024)
            .unwrap();

        let retrieved = manager.get_workspace(&root.id).unwrap();
        assert_eq!(retrieved.id, root.id);

        let list = manager
            .list_workspaces(&make_test_sandbox("sbx_trait_obj"))
            .unwrap();
        assert_eq!(list.len(), 1);
    }
}

// ── Stress / Multi-fork ──

mod stress {
    use super::*;

    #[test]
    fn many_forks_from_same_root() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let n = 50;

        let mut child_ids = Vec::new();
        for i in 0..n {
            let child = engine
                .fork_workspace(&root.id, make_test_sandbox(&format!("sbx_many_{i}")), 64)
                .unwrap();
            child_ids.push(child.child_workspace_id);
        }

        assert_eq!(engine.workspace_count(), 1 + n as usize);

        // All children share the same base blob
        let base_blob = root.layers[0].blob_ref.clone();
        assert_eq!(engine.gc_ref_count(&base_blob), Some(1 + n as u32));

        // Delete all children
        for cid in &child_ids {
            engine.delete_child_workspace(cid).unwrap();
        }

        assert_eq!(engine.workspace_count(), 1);
        assert_eq!(engine.gc_ref_count(&base_blob), Some(1));
    }

    #[test]
    fn deep_fork_chain_then_cleanup() {
        let (engine, root, _tmp) = make_engine_with_root(1024);
        let depth = 20;

        let mut current_id = root.id.clone();
        let mut ids = vec![current_id.clone()];

        for i in 0..depth {
            let child = engine
                .fork_workspace(&current_id, make_test_sandbox(&format!("sbx_deep_{i}")), 10)
                .unwrap();
            current_id = child.child_workspace_id.clone();
            ids.push(current_id.clone());
        }

        assert_eq!(engine.workspace_count(), 1 + depth as usize);

        // Clean up from leaves to root
        for cid in ids.iter().skip(1).rev() {
            engine.delete_child_workspace(cid).unwrap();
        }
        engine.delete_parent_workspace(&ids[0]).unwrap();

        assert_eq!(engine.workspace_count(), 0);

        // Sweep everything
        let swept = engine.sweep_released().unwrap();
        assert!(!swept.is_empty());
    }
}

// ── Divergence ──

mod divergence {
    use super::*;

    #[test]
    fn sibling_workspaces_diverge_independently() {
        let (engine, root, _tmp) = make_engine_with_root(1024);

        // Write base data
        engine.write_file(&root.id, "base.txt", b"base").unwrap();

        let child_a = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_a"), 256)
            .unwrap();
        let child_b = engine
            .fork_workspace(&root.id, make_test_sandbox("sbx_b"), 256)
            .unwrap();

        // Child A modifies base file
        engine
            .write_file(&child_a.child_workspace_id, "base.txt", b"modified by A")
            .unwrap();
        // Child B creates a new file
        engine
            .write_file(&child_b.child_workspace_id, "only_b.txt", b"B's file")
            .unwrap();

        // A sees its own modification and base file
        assert_eq!(
            engine
                .read_file(&child_a.child_workspace_id, "base.txt")
                .unwrap(),
            b"modified by A"
        );
        assert!(
            engine
                .read_file(&child_a.child_workspace_id, "only_b.txt")
                .is_err()
        );

        // B sees original base file and its own new file
        assert_eq!(
            engine
                .read_file(&child_b.child_workspace_id, "base.txt")
                .unwrap(),
            b"base"
        );
        assert_eq!(
            engine
                .read_file(&child_b.child_workspace_id, "only_b.txt")
                .unwrap(),
            b"B's file"
        );

        // Root unchanged
        assert_eq!(engine.read_file(&root.id, "base.txt").unwrap(), b"base");
        assert!(engine.read_file(&root.id, "only_b.txt").is_err());
    }
}
